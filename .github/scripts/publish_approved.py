#!/usr/bin/env python3
"""Publish an owner-approved signed APK; never check out private source."""
from __future__ import annotations
import hashlib
import json
import os
import re
import subprocess
import tempfile
import urllib.error
import urllib.parse
import urllib.request
import zipfile
from pathlib import Path

API = "https://api.github.com"
ARTIFACT_NAME = "unsigned-release-candidate-"
APK_NAME = "app-release-unsigned.apk"


def required(name: str) -> str:
    value = os.environ.get(name, "").strip()
    if not value:
        raise RuntimeError(f"Missing required protected configuration: {name}")
    return value


def request(url: str, token: str | None = None, accept: str = "application/vnd.github+json", data=None, method=None):
    parsed = urllib.parse.urlsplit(url)
    if parsed.scheme != "https" or not parsed.hostname:
        raise RuntimeError("Refusing non-HTTPS or malformed URL")
    headers = {"Accept": accept, "User-Agent": "owner-release-publisher"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    if data is not None:
        headers["Content-Type"] = "application/json" if parsed.hostname == "api.github.com" else "application/vnd.android.package-archive"
    if parsed.hostname == "api.github.com":
        headers["X-GitHub-Api-Version"] = "2022-11-28"
    req = urllib.request.Request(url, data=data, method=method, headers=headers)
    # Never let urllib forward secrets to a redirect target.
    opener = urllib.request.build_opener(NoRedirect)
    try:
        with opener.open(req, timeout=300 if data else 60) as response:
            return response.read(), dict(response.headers)
    except urllib.error.HTTPError as exc:
        if exc.code in (301, 302, 303, 307, 308):
            location = exc.headers.get("Location", "")
            target = urllib.parse.urljoin(url, location)
            dest = urllib.parse.urlsplit(target)
            if (data is None and method in (None, "GET") and parsed.hostname == "api.github.com"
                    and dest.scheme == "https" and not dest.username and not dest.password
                    and dest.hostname and dest.hostname.endswith((".blob.core.windows.net", ".githubusercontent.com"))):
                return request(target, None, accept)
            if urllib.parse.urlsplit(target).hostname != parsed.hostname:
                raise RuntimeError("Cross-host redirect refused") from None
            raise RuntimeError("Redirect refused; use a direct HTTPS endpoint") from None
        raise


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def api_json(path: str, token: str, data=None, method=None):
    raw, _ = request(API + path, token, data=json.dumps(data).encode() if data is not None else None, method=method)
    return json.loads(raw)


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256(path: Path) -> str:
    return sha256_bytes(path.read_bytes())


def run(*cmd: str) -> str:
    # Avoid inheriting protected environment values in Android tooling.
    android_env = {key: os.environ[key] for key in ("ANDROID_HOME", "ANDROID_SDK_ROOT") if key in os.environ}
    return subprocess.check_output(cmd, text=True, stderr=subprocess.DEVNULL, env={"PATH": os.environ.get("PATH", ""), **android_env})


def isolated_apksigner(candidate: Path, root: Path) -> Path:
    """Sign using only the approved GitHub-hosted Android build-tools binary."""
    keystore_b64 = required("ANDROID_KEYSTORE_BASE64")
    keystore_password = required("ANDROID_KEYSTORE_PASSWORD")
    key_alias = required("ANDROID_KEY_ALIAS")
    key_password = required("ANDROID_KEY_PASSWORD")
    signer = Path(os.environ.get("ANDROID_HOME", "")) / "build-tools" / "36.0.0" / "apksigner"
    if not signer.is_file() or not os.access(signer, os.X_OK):
        raise RuntimeError("GitHub-hosted apksigner not found in pinned Android build-tools")
    keystore_data = b""
    try:
        import base64
        keystore_data = base64.b64decode(keystore_b64, validate=True)
    except (ValueError, TypeError):
        raise RuntimeError("Protected keystore is not valid base64") from None
    finally:
        keystore_b64 = ""
    keystore = root / "release.keystore"
    try:
        fd = os.open(keystore, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except BaseException:
        keystore_data = b""
        raise
    try:
        with os.fdopen(fd, "wb") as key_file:
            key_file.write(keystore_data)
    except BaseException:
        keystore.unlink(missing_ok=True)
        keystore_data = b""
        raise
    output = root / "signed.apk"
    env = {"PATH": os.environ.get("PATH", ""), "ANDROID_HOME": os.environ.get("ANDROID_HOME", ""), "ANDROID_SDK_ROOT": os.environ.get("ANDROID_SDK_ROOT", ""), "HOME": str(root)}
    signer_env = {**env, "ANDROID_KEYSTORE_PASSWORD": keystore_password, "ANDROID_KEY_ALIAS": key_alias, "ANDROID_KEY_PASSWORD": key_password}
    try:
        subprocess.run([str(signer), "sign", "--ks", str(keystore), "--ks-pass", "env:ANDROID_KEYSTORE_PASSWORD", "--ks-key-alias", key_alias, "--key-pass", "env:ANDROID_KEY_PASSWORD", "--out", str(output), str(candidate)], check=True, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, env=signer_env)
    except (subprocess.CalledProcessError, OSError):
        raise RuntimeError("Isolated apksigner failed") from None
    finally:
        # Remove decoded key material promptly; TemporaryDirectory cleans remaining files.
        keystore.unlink(missing_ok=True)
        keystore_data = b""
        keystore_password = key_alias = key_password = ""
        for name in ("ANDROID_KEYSTORE_PASSWORD", "ANDROID_KEY_ALIAS", "ANDROID_KEY_PASSWORD"):
            signer_env.pop(name, None)
    if not output.is_file():
        raise RuntimeError("Isolated apksigner produced no signed APK")
    return output


def verify_apk(path: Path, package: str, cert: str, *, previous=False) -> dict:
    badging = run("aapt", "dump", "badging", str(path))
    m = re.search(r"^package: name='([^']+)' versionCode='([^']+)' versionName='([^']*)'", badging, re.M)
    if not m or m.group(1) != package:
        raise RuntimeError("APK package identity/badging check failed")
    vcode, vname = int(m.group(2)), m.group(3)
    if vcode <= 0 or not vname or not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", vname):
        raise RuntimeError("APK version metadata invalid")
    if not previous and run("apkanalyzer", "manifest", "debuggable", str(path)).strip() != "false":
        raise RuntimeError("Debuggable APK rejected")
    cert_output = run("apksigner", "verify", "--print-certs", str(path))
    cm = re.search(r"Signer #1 certificate SHA-256 digest: ([0-9a-fA-F:]+)", cert_output)
    if not cm or cm.group(1).replace(":", "").lower() != cert.replace(":", "").lower():
        raise RuntimeError("APK signer fingerprint does not match protected approved fingerprint")
    return {"package": m.group(1), "versionCode": vcode, "versionName": vname}


def artifact_member(raw: bytes) -> bytes:
    import io
    with zipfile.ZipFile(io.BytesIO(raw)) as z:
        files = [n for n in z.namelist() if not n.endswith("/")]
        if files != [APK_NAME]:
            raise RuntimeError("Candidate artifact must contain exactly app-release-unsigned.apk")
        return z.read(APK_NAME)


def main():
    approval = required("APPROVAL_REF")
    if not re.fullmatch(r"[0-9a-fA-F]{64}", approval):
        raise RuntimeError("approval_ref must be a SHA-256 digest")
    repo, workflow, branch = (required(k) for k in ("SOURCE_REPOSITORY", "SOURCE_WORKFLOW", "SOURCE_BRANCH"))
    package, cert = required("EXPECTED_PACKAGE"), required("EXPECTED_CERT_SHA256")
    source_token, gh = required("SOURCE_READ_TOKEN"), required("GH_TOKEN")
    if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repo):
        raise RuntimeError("Invalid configured candidate repository")

    source_repo = urllib.parse.quote(repo, safe="/")
    runs = api_json(f"/repos/{source_repo}/actions/workflows/{urllib.parse.quote(workflow, safe='')}/runs?branch={urllib.parse.quote(branch, safe='')}&status=success&per_page=100", source_token)
    candidates = [r for r in runs.get("workflow_runs", []) if r.get("status") == "completed" and r.get("conclusion") == "success" and r.get("head_branch") == branch and r.get("head_sha", "")]
    candidates.sort(key=lambda r: r.get("run_number", 0), reverse=True)
    selected = None
    for runrec in candidates:
        arts = api_json(f"/repos/{source_repo}/actions/runs/{runrec['id']}/artifacts?per_page=100", source_token).get("artifacts", [])
        artifact = next((a for a in arts if a.get("name") == ARTIFACT_NAME + runrec["head_sha"] and not a.get("expired")), None)
        if artifact:
            selected = runrec, artifact
            break
    if not selected:
        raise RuntimeError("No successful unexpired unsigned-release-candidate artifact found")
    runrec, artifact = selected
    provenance = {"run_id": runrec["id"], "run_attempt": runrec.get("run_attempt"), "head_sha": runrec["head_sha"], "artifact_id": artifact["id"], "artifact_digest": artifact.get("digest")}
    approval_digest = sha256_bytes(json.dumps(provenance, sort_keys=True, separators=(",", ":")).encode())
    if not artifact.get("digest") or approval_digest.lower() != approval.lower():
        raise RuntimeError("Owner approval digest does not match selected candidate")
    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        raw, _ = request(artifact["archive_download_url"], source_token)
        if artifact["digest"].split(":")[-1].lower() != sha256_bytes(raw):
            raise RuntimeError("Downloaded candidate artifact digest mismatch")
        candidate_data = artifact_member(raw)
        candidate = root / APK_NAME
        candidate.write_bytes(candidate_data)
        # Public releases are authoritative: inspect only /releases/latest and download its sole APK asset by API URL.
        public_repo = urllib.parse.quote(os.environ["GITHUB_REPOSITORY"], safe="/")
        latest = api_json(f"/repos/{public_repo}/releases/latest", gh)
        apk_assets = [a for a in latest.get("assets", []) if a.get("content_type") == "application/vnd.android.package-archive" or a.get("name", "").lower().endswith(".apk")]
        if len(apk_assets) != 1:
            raise RuntimeError("Latest published release must contain exactly one APK asset")
        previous_data, _ = request(apk_assets[0]["url"], gh, "application/octet-stream")
        previous = root / "previous.apk"
        previous.write_bytes(previous_data)
        previous_info = verify_apk(previous, package, cert, previous=True)
        # Unsigned release candidate is intentionally unsigned; read metadata/debuggable independently.
        candidate_badging = run("aapt", "dump", "badging", str(candidate))
        cm = re.search(r"^package: name='([^']+)' versionCode='([^']+)' versionName='([^']*)'", candidate_badging, re.M)
        if not cm or cm.group(1) != package or int(cm.group(2)) <= previous_info["versionCode"] or not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", cm.group(3)):
            raise RuntimeError("Candidate package/version invalid or not newer than latest release APK")
        if run("apkanalyzer", "manifest", "debuggable", str(candidate)).strip() != "false":
            raise RuntimeError("Debuggable candidate APK rejected")
        signed_path = isolated_apksigner(candidate, root)
        info = verify_apk(signed_path, package, cert)
        if info != {"package": package, "versionCode": int(cm.group(2)), "versionName": cm.group(3)}:
            raise RuntimeError("Signer output package/version differs from original candidate")
        if sha256(signed_path) != sha256(candidate):
            # APK signing changes bytes; compare payload entries to ensure signed output preserves all original content.
            import zipfile
            with zipfile.ZipFile(candidate) as unsigned, zipfile.ZipFile(signed_path) as signed_zip:
                unsigned_files = {n: unsigned.read(n) for n in unsigned.namelist() if not n.startswith("META-INF/")}
                signed_files = {n: signed_zip.read(n) for n in signed_zip.namelist() if not n.startswith("META-INF/")}
            if unsigned_files != signed_files:
                raise RuntimeError("Signed APK content differs from original candidate")
        tag = "v" + info["versionName"]
        try:
            release = api_json(f"/repos/{public_repo}/releases/tags/{tag}", gh)
            raise RuntimeError("Target release already exists; refusing overwrite")
        except urllib.error.HTTPError as exc:
            if exc.code != 404:
                raise
        release = api_json(f"/repos/{public_repo}/releases", gh, {"tag_name": tag, "name": tag, "draft": True, "prerelease": False, "target_commitish": "main", "body": "Owner-approved signed release."}, "POST")
        upload_url = release["upload_url"].split("{", 1)[0] + "?name=zeitpunkte.apk"
        asset_raw, _ = request(upload_url, gh, "application/vnd.github+json", signed_path.read_bytes(), "POST")
        asset = json.loads(asset_raw)
        readback, _ = request(asset["url"], gh, "application/octet-stream")
        readback_path = root / "readback.apk"
        readback_path.write_bytes(readback)
        if sha256(readback_path) != sha256(signed_path):
            raise RuntimeError("Release asset readback differs from signed APK")
        verify_apk(readback_path, package, cert)
        published = api_json(f"/repos/{public_repo}/releases/{release['id']}", gh, {"draft": False}, "PATCH")
        if published.get("draft"):
            raise RuntimeError("Release did not publish")
        print(json.dumps({"published": True, "tag": tag, "versionCode": info["versionCode"], "sha256": sha256(readback_path)}, sort_keys=True))

if __name__ == "__main__":
    main()
