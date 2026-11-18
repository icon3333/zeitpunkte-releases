import importlib.util
import io
import unittest
import zipfile
from pathlib import Path

SCRIPT = Path(__file__).with_name("publish_approved.py")
spec = importlib.util.spec_from_file_location("publisher", SCRIPT)
p = importlib.util.module_from_spec(spec)
spec.loader.exec_module(p)


class PublisherTests(unittest.TestCase):
    def archive(self, files):
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as z:
            for name, data in files.items():
                z.writestr(name, data)
        return buf.getvalue()

    def test_extracts_producer_named_unsigned_apk(self):
        self.assertEqual(p.artifact_member(self.archive({p.APK_NAME: b"apk"})), b"apk")

    def test_rejects_old_and_wrong_artifact_layouts(self):
        for files in ({"candidate.apk": b"x"}, {p.APK_NAME: b"x", "extra": b"y"}):
            with self.subTest(files=files), self.assertRaises(RuntimeError):
                p.artifact_member(self.archive(files))

    def test_signing_has_no_external_signer_configuration(self):
        self.assertNotIn("SIGNER_URL", SCRIPT.read_text())
        self.assertNotIn("SIGNER_TOKEN", SCRIPT.read_text())

    def test_signer_uses_pinned_github_hosted_binary_and_bounded_environment(self):
        import os
        import tempfile
        from unittest import mock
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            sdk = root / "sdk"
            signer = sdk / "build-tools" / "36.0.0" / "apksigner"
            signer.parent.mkdir(parents=True)
            signer.write_text("#!/bin/sh\nexit 0\n")
            signer.chmod(0o700)
            candidate = root / "candidate.apk"
            candidate.write_bytes(b"candidate")
            with mock.patch.dict(os.environ, {"ANDROID_HOME": str(sdk), "ANDROID_KEYSTORE_BASE64": "a2V5", "ANDROID_KEYSTORE_PASSWORD": "secret-store", "ANDROID_KEY_ALIAS": "release", "ANDROID_KEY_PASSWORD": "secret-key", "UNRELATED_SECRET": "must-not-propagate"}, clear=True), mock.patch.object(p.subprocess, "run") as run:
                captured = {}
                def mock_sign(*args, **kwargs):
                    Path(kwargs["env"]["HOME"]).joinpath("signed.apk").write_bytes(b"signed")
                    captured.update(kwargs["env"])
                run.side_effect = mock_sign
                result = p.isolated_apksigner(candidate, root)
                self.assertEqual(result, root / "signed.apk")
                argv = run.call_args.args[0]
                self.assertEqual(argv[0], str(signer))
                self.assertIn("env:ANDROID_KEYSTORE_PASSWORD", argv)
                self.assertNotIn("secret-store", argv)
                self.assertNotIn("secret-key", argv)
                self.assertNotIn("UNRELATED_SECRET", captured)
                self.assertEqual(captured["ANDROID_KEYSTORE_PASSWORD"], "secret-store")
                self.assertFalse((root / "release.keystore").exists())
                self.assertEqual(run.call_args.kwargs["stdout"], p.subprocess.DEVNULL)
                self.assertEqual(run.call_args.kwargs["stderr"], p.subprocess.DEVNULL)
                self.assertEqual(run.call_args.kwargs["stdin"], p.subprocess.DEVNULL)

    def test_signer_rejects_missing_or_malformed_keystore_before_running(self):
        import os
        import tempfile
        from unittest import mock
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            sdk = root / "sdk"
            signer = sdk / "build-tools" / "36.0.0" / "apksigner"
            signer.parent.mkdir(parents=True)
            signer.write_text("")
            signer.chmod(0o700)
            with mock.patch.dict(os.environ, {"ANDROID_HOME": str(sdk)}, clear=True), mock.patch.object(p.subprocess, "run") as run:
                with self.assertRaisesRegex(RuntimeError, "ANDROID_KEYSTORE_BASE64"):
                    p.isolated_apksigner(root / "candidate.apk", root)
                run.assert_not_called()
                for key, value in {"ANDROID_KEYSTORE_BASE64": "%%%" , "ANDROID_KEYSTORE_PASSWORD": "x", "ANDROID_KEY_ALIAS": "a", "ANDROID_KEY_PASSWORD": "x"}.items():
                    os.environ[key] = value
                with self.assertRaisesRegex(RuntimeError, "valid base64"):
                    p.isolated_apksigner(root / "candidate.apk", root)
                run.assert_not_called()

    def test_keystore_creation_is_exclusive_and_mode_600(self):
        import os
        import tempfile
        from unittest import mock
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            sdk = root / "sdk"
            signer = sdk / "build-tools" / "36.0.0" / "apksigner"
            signer.parent.mkdir(parents=True)
            signer.write_text("")
            signer.chmod(0o700)
            candidate = root / "candidate.apk"
            candidate.write_bytes(b"candidate")
            keypath = root / "release.keystore"
            keypath.write_bytes(b"do not overwrite")
            with mock.patch.dict(os.environ, {"ANDROID_HOME": str(sdk), "ANDROID_KEYSTORE_BASE64": "a2V5", "ANDROID_KEYSTORE_PASSWORD": "p", "ANDROID_KEY_ALIAS": "a", "ANDROID_KEY_PASSWORD": "p"}, clear=True), mock.patch.object(p.subprocess, "run") as run:
                with self.assertRaises(FileExistsError):
                    p.isolated_apksigner(candidate, root)
                self.assertEqual(keypath.read_bytes(), b"do not overwrite")
                run.assert_not_called()
                keypath.unlink()
                def mock_sign(*args, **kwargs):
                    self.assertEqual(keypath.stat().st_mode & 0o777, 0o600)
                    Path(kwargs["env"]["HOME"], "signed.apk").write_bytes(b"signed")
                run.side_effect = mock_sign
                p.isolated_apksigner(candidate, root)
                self.assertFalse(keypath.exists())

    def test_apk_verification_subprocess_does_not_inherit_secrets_or_log_stderr(self):
        import os
        from unittest import mock
        with mock.patch.dict(os.environ, {"PATH": "/usr/bin", "ANDROID_HOME": "/sdk", "SOURCE_READ_TOKEN": "private", "GH_TOKEN": "private", "ANDROID_KEYSTORE_PASSWORD": "private"}, clear=True), mock.patch.object(p.subprocess, "check_output", return_value="ok") as check:
            self.assertEqual(p.run("apksigner", "verify", "sample.apk"), "ok")
            env = check.call_args.kwargs["env"]
            self.assertEqual(env, {"PATH": "/usr/bin", "ANDROID_HOME": "/sdk"})
            self.assertEqual(check.call_args.kwargs["stderr"], p.subprocess.DEVNULL)

    def test_request_does_not_follow_cross_host_redirect_with_auth(self):
        import unittest.mock
        class Redirect:
            headers = {"Location": "https://evil.example/steal"}
            code = 302
        with unittest.mock.patch.object(p.urllib.request, "build_opener") as opener:
            opener.return_value.open.side_effect = p.urllib.error.HTTPError("https://api.github.com/x", 302, "redirect", Redirect.headers, None)
            with self.assertRaises(RuntimeError):
                p.request("https://api.github.com/x", "secret")
            self.assertNotIn("secret", repr(opener.call_args))


    def test_latest_release_apk_selection_is_independent_of_filename(self):
        release = {"assets": [{"name": "zeitpunkte-0.1.0-pilot.apk", "url": "https://api.github.com/assets/1"}]}
        assets = [a for a in release["assets"] if a.get("content_type") == "application/vnd.android.package-archive" or a.get("name", "").lower().endswith(".apk")]
        self.assertEqual(len(assets), 1)

    def test_previous_release_must_have_one_apk(self):
        assets = [{"name": "zeitpunkte-0.1.0-pilot.apk", "url": "https://api.github.com/asset/1"}]
        self.assertEqual(len(assets), 1)
        self.assertTrue(assets[0]["name"].endswith(".apk"))
        self.assertNotEqual(assets[0]["name"], "zeitpunkte.apk")
        with self.assertRaises(RuntimeError):
            if len([]) != 1:
                raise RuntimeError("latest release has no APK")


if __name__ == "__main__":
    unittest.main()
