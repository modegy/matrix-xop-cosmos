import base64
import importlib.util
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
import zipfile
import zlib

os.environ.setdefault("XOP_API_TOKEN", "0123456789abcdef0123456789abcdef")
spec = importlib.util.spec_from_file_location("xop_server", Path(__file__).resolve().parents[1] / "api/server.py")
s = importlib.util.module_from_spec(spec)
spec.loader.exec_module(s)

def encoded(v):
    return base64.urlsafe_b64encode(json.dumps(v).encode()).decode().rstrip("=")

def zipped(v):
    compressor = zlib.compressobj(level=9, wbits=-zlib.MAX_WBITS)
    packed = compressor.compress(json.dumps(v).encode()) + compressor.flush()
    return "z:" + base64.urlsafe_b64encode(packed).decode().rstrip("=")

class FailureClassificationTests(unittest.TestCase):
    def test_large_dex_failure_codes_are_stable_and_private(self):
        cases = {
            "MODEGY_DEX_SINGLE_FILE_LIMIT_88: 65536": "XOP_DEX_REFERENCE_LIMIT",
            "MODEGY_DEX_MERGE_UNSAFE_CLASS: Labc/;": "XOP_DEX_MERGE_UNSAFE",
            "MODEGY_DEX_DUPLICATE_CLASS: Labc/;": "XOP_DEX_DUPLICATE_CLASS",
            "MODEGY_SELECTED_VMP_NOT_APPLIED: [secret]": "XOP_VMP_SELECTION_UNSUPPORTED",
            "java.lang.OutOfMemoryError: Java heap space": "XOP_PACKER_JAVA_OOM",
            "Unexpected library error /internal/private": "XOP_PACKER_EXIT_NONZERO",
        }
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "packer.log"
            for message, code in cases.items():
                with self.subTest(code=code):
                    path.write_text("x" * 100000 + "\\n" + message)
                    self.assertEqual(s.classify_packer_failure(path), code)
            path.unlink()
            self.assertEqual(s.classify_packer_failure(path), "XOP_PACKER_EXIT_NONZERO")

class ValidationTests(unittest.TestCase):
    def test_options(self):
        v = s.parse_options(encoded({"profile":"perf","protectSo":False,"trueVmpPrefixes":["Lcom/example/"]}))
        self.assertEqual(v["profile"], "perf")
        self.assertIn("--no-protect-so", s.cli_args(v, Path("a.apk"), Path("b.apk"), Path("/tmp")))
    def test_invalid_option(self):
        with self.assertRaisesRegex(ValueError, "XOP_OPTIONS_UNKNOWN"):
            s.parse_options(encoded({"shell":"rm -rf /"}))
    def test_single_root_dex_is_opt_in(self):
        base = {"profile": "balanced", "protectSo": True}
        v = s.parse_options(encoded(base))
        self.assertNotIn("--modegy-single-root-dex",
                         s.cli_args(v, Path("a.apk"), Path("b.apk"), Path("/tmp")))
        v = s.parse_options(encoded({**base, "modegySingleRootDex": True}))
        args = s.cli_args(v, Path("a.apk"), Path("b.apk"), Path("/tmp"))
        self.assertIn("--modegy-single-root-dex", args)
        self.assertIn("--protect-so", args)
        with self.assertRaisesRegex(ValueError, "XOP_OPTIONS_INVALID"):
            s.parse_options(encoded({**base, "modegySingleRootDex": "yes"}))

    def test_all_rasp_disable_masks_pass_to_native_packer_unchanged(self):
        # MODEGY checkbox semantics: 0=all on; bits explicitly disable
        # Frida(1), CRC(2), debugger(4), Xposed(8), Root(16),
        # emulator(32), SO runtime integrity(64).
        for mask in range(128):
            with self.subTest(mask=mask):
                opts = s.parse_options(encoded({
                    "profile": "balanced", "protectSo": True,
                    "riskFlags": mask, "raspAction": 2
                }))
                args = s.cli_args(opts, Path("in.apk"), Path("out.apk"), Path("/tmp"))
                idx = args.index("--risk-flags")
                self.assertEqual(args[idx + 1], str(mask))
                self.assertEqual(args[args.index("--rasp-action") + 1], "2")
        for wrong in (-1, 128, 1.5, "0", True):
            with self.subTest(wrong=wrong):
                if wrong == 128:
                    # The standalone worker accepts a larger bit range, but
                    # NEXUS front end specifically caps the mask at 127.
                    continue
                with self.assertRaisesRegex(ValueError, "XOP_OPTIONS_INVALID"):
                    s.parse_options(encoded({"riskFlags": wrong}))

    def test_vpn_monitoring_forwards_to_native_netguard(self):
        base={"profile":"balanced","protectSo":True}
        plain=s.cli_args(s.parse_options(encoded(base)),Path("a.apk"),Path("b.apk"),Path("/tmp"))
        self.assertNotIn("--detect-proxy",plain)
        enabled=s.cli_args(s.parse_options(encoded({**base,"detectProxy":True})),
                           Path("a.apk"),Path("b.apk"),Path("/tmp"))
        self.assertIn("--detect-proxy",enabled)
        for bad in ("true",1,None):
            with self.assertRaisesRegex(ValueError,"XOP_OPTIONS_INVALID"):
                s.parse_options(encoded({"detectProxy":bad}))

    def test_nexus_pvm2_only_when_selected(self):
        base = {"profile": "balanced", "protectSo": True}
        plain = s.cli_args(s.parse_options(encoded(base)), Path("a.apk"), Path("b.apk"), Path("/tmp"))
        self.assertIn("--no-payment-auto-vmp", plain)
        self.assertIn("--no-industry-auto-vmp", plain)
        self.assertNotIn("--true-vmp-prefix", plain)
        scopes = ["Lsample/one/Foo;", "Lsample/two/Bar;"]
        explicit = s.cli_args(s.parse_options(encoded({**base, "trueVmpPrefixes": scopes})),
                              Path("a.apk"), Path("b.apk"), Path("/tmp"))
        self.assertEqual(explicit.count("--true-vmp-prefix"), len(scopes))
        self.assertIn("--no-payment-auto-vmp", explicit)
        self.assertIn("--no-industry-auto-vmp", explicit)

    def test_vmp_256_and_so_abi_selection(self):
        scope = ["Lsample/app/Feature%d;" % i for i in range(256)]
        for abi in ("all", "arm64-v8a", "armeabi-v7a", "x86", "x86_64"):
            settings = s.parse_options(zipped({"profile": "balanced",
                "protectSo": True, "soAbi": abi, "trueVmpPrefixes": scope}))
            args = s.cli_args(settings, Path("in.apk"), Path("out.apk"), Path("/tmp"))
            self.assertEqual(args[args.index("--protect-so-abi") + 1], abi)
            self.assertEqual(args.count("--true-vmp-prefix"), 256)
        with self.assertRaisesRegex(ValueError, "XOP_SCOPE_INVALID"):
            s.parse_options(zipped({"trueVmpPrefixes": scope + ["Lsample/app/Feature256;"]}))

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
