import base64
import importlib.util
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
import zipfile

os.environ.setdefault("XOP_API_TOKEN", "0123456789abcdef0123456789abcdef")
spec = importlib.util.spec_from_file_location("xop_server", Path(__file__).resolve().parents[1] / "api/server.py")
s = importlib.util.module_from_spec(spec)
spec.loader.exec_module(s)

def encoded(v):
    return base64.urlsafe_b64encode(json.dumps(v).encode()).decode().rstrip("=")

class ValidationTests(unittest.TestCase):
    def test_options(self):
        v = s.parse_options(encoded({"profile":"perf","protectSo":False,"trueVmpPrefixes":["Lcom/example/"]}))
        self.assertEqual(v["profile"], "perf")
        self.assertIn("--no-protect-so", s.cli_args(v, Path("a.apk"), Path("b.apk"), Path("/tmp")))
    def test_invalid_option(self):
        with self.assertRaisesRegex(ValueError, "XOP_OPTIONS_UNKNOWN"):
            s.parse_options(encoded({"shell":"rm -rf /"}))
    def test_so_name(self):
        s.parse_options(encoded({"soExclude":["libdemo.so"]}))
        with self.assertRaisesRegex(ValueError, "XOP_SO_EXCLUDE_INVALID"):
            s.parse_options(encoded({"soExclude":["libdemoXso"]}))
    def test_zip_safety(self):
        with tempfile.TemporaryDirectory() as d:
            f=Path(d)/"test.apk"
            with zipfile.ZipFile(f,"w") as z:
                z.writestr("AndroidManifest.xml",b"manifest")
                z.writestr("classes.dex",b"dex")
            s.apk_check(f)
            with self.assertRaisesRegex(ValueError,"XOP_OUTPUT_NOT_PROTECTED"):
                s.apk_check(f,output=True)
            with zipfile.ZipFile(f,"a") as z:
                z.writestr("assets/protector/config.json",b"{}")
            s.apk_check(f,output=True)
    def test_bad_entry(self):
        with tempfile.TemporaryDirectory() as d:
            f=Path(d)/"test.apk"
            with zipfile.ZipFile(f,"w") as z:
                z.writestr("AndroidManifest.xml",b"manifest")
                z.writestr("../escape",b"bad")
            with self.assertRaisesRegex(ValueError,"XOP_APK_UNSAFE_ENTRY"):
                s.apk_check(f)

if __name__ == "__main__":
    unittest.main()
