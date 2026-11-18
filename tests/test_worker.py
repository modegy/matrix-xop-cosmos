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
            # A single legacy-path file is NOT enough to prove protection.
            with self.assertRaisesRegex(ValueError,"XOP_OUTPUT_NOT_PROTECTED"):
                s.apk_check(f,output=True)
            with zipfile.ZipFile(f,"a") as z:
                z.writestr("assets/protector/dexes.zip",b"PDX1-legacy")
                z.writestr("assets/protector/code.bin",bytes((4, 0, 0, 0)))
            s.apk_check(f,output=True)

    def test_modegy_output_bundle(self):
        with tempfile.TemporaryDirectory() as d:
            f=Path(d)/"modegy.apk"
            with zipfile.ZipFile(f,"w") as z:
                z.writestr("AndroidManifest.xml",b"manifest")
                z.writestr("classes.dex",b"dex")
                z.writestr("assets/MODEGY_PROTECTION/MODEGY_DATA.zip",b"PDX1-ciphertext")
                z.writestr("assets/MODEGY_PROTECTION/MODEGY_CORE.vmp",bytes((4, 0, 0, 0)))
                z.writestr("assets/MODEGY_PROTECTION/MODEGY_POLICY.dat",b"nonce-and-gcm-ciphertext")
            s.apk_check(f,output=True)

    def test_modegy_partial_bundle_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            f=Path(d)/"invalid.apk"
            with zipfile.ZipFile(f,"w") as z:
                z.writestr("AndroidManifest.xml",b"manifest")
                z.writestr("assets/MODEGY_PROTECTION/MODEGY_DATA.zip",b"PDX1-ciphertext")
                z.writestr("assets/MODEGY_PROTECTION/MODEGY_CORE.vmp",bytes((4, 0, 0, 0)))
            with self.assertRaisesRegex(ValueError,"XOP_OUTPUT_NOT_PROTECTED"):
                s.apk_check(f,output=True)
    def test_unsigned_zip_trailing_removed_before_signing(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "unsigned.apk"
            with zipfile.ZipFile(p, "w") as z:
                z.writestr("AndroidManifest.xml", b"manifest")
                z.writestr("classes.dex", b"dex-content")
                z.writestr("assets/MODEGY_PROTECTION/MODEGY_DATA.zip", b"PDX1" + b"payload")
                z.writestr("assets/MODEGY_PROTECTION/MODEGY_CORE.vmp", bytes((4, 0, 0, 0)))
                z.writestr("assets/MODEGY_PROTECTION/MODEGY_POLICY.dat", b"encrypted-policy")
            clean = p.read_bytes()
            # Regression for the 4490 invalid bytes reported on MODEGY output.
            with p.open("ab") as out:
                out.write(b"\x00" * 1130 + b"PK\x03\x04" + b"Z" * 3356)
            self.assertEqual(p.stat().st_size, len(clean) + 4490)
            with self.assertRaisesRegex(ValueError, "XOP_OUTPUT_ZIP_TRAILING"):
                s.apk_check(p, output=True)
            self.assertEqual(s.normalize_unsigned_zip(p), 4490)
            self.assertEqual(p.read_bytes(), clean)
            s.apk_check(p, output=True)
            self.assertEqual(s.normalize_unsigned_zip(p), 0)

    def test_zip_comment_is_not_trailing_data(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "comment.apk"
            with zipfile.ZipFile(p, "w") as z:
                z.writestr("AndroidManifest.xml", b"manifest")
                z.comment = b"normal-zip-comment"
            self.assertEqual(s.normalize_unsigned_zip(p), 0)
            s.apk_check(p)

    def test_unsigned_zip_invalid_central_directory_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "corrupt.apk"
            with zipfile.ZipFile(p, "w") as z:
                z.writestr("AndroidManifest.xml", b"manifest")
            data = bytearray(p.read_bytes())
            eocd = data.rfind(b"PK\x05\x06")
            import struct
            struct.pack_into("<I", data, eocd + 16, 0xffffffff)
            p.write_bytes(data)
            with self.assertRaisesRegex(ValueError, "XOP_OUTPUT_ZIP_EOCD_INVALID"):
                s.normalize_unsigned_zip(p)

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
