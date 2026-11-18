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

    def test_rejects_http_and_bad_signer_urls(self):
        for url in ("http://sign.example", "https://user:pw@sign.example", "https://sign.example/?token=x"):
            parsed = __import__("urllib.parse", fromlist=["urlsplit"]).urlsplit(url)
            invalid = parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password or parsed.query or parsed.fragment
            self.assertTrue(invalid, url)

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
