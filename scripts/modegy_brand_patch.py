#!/usr/bin/env python3
"""Brand the pinned upstream XopProtector runtime for an isolated MODEGYPRO experiment.

Operate ONLY on a fresh temporary upstream checkout. Never patch a deployed APK,
running container, user data, or signing key. Fails closed on upstream drift.
This renames identifiers and on-disk paths; it is NOT a cryptographic substitute.
"""
from __future__ import annotations

import re
import sys
import hashlib
import hmac
from pathlib import Path

OLD_PKG_DOT = "com.yqsh.protector.shell"
NEW_PKG_DOT = "com.modegypro.protection.shell"
OLD_PKG_PATH = "com/yqsh/protector/shell"
NEW_PKG_PATH = "com/modegypro/protection/shell"
ASSET_DIR = "MODEGY_PROTECTION"
NAMES = {
    "code.bin": "MODEGY_CORE.vmp",
    "dexes.zip": "MODEGY_DATA.zip",
    "config.json": "MODEGY_POLICY.dat",
    "sokeys.bin": "MODEGY_KEYS.dat",
    "netguard.json": "MODEGY_NET.dat",
    "so_text_diag.json": "MODEGY_SO_CHECK.dat",
    "size_report.json": "MODEGY_REPORT.dat",
    "res_mapping.txt": "MODEGY_RESOURCE.dat",
    "assets.map": "MODEGY_ASSETS.map",
}
CLASSES = {
    "ProxyApplication": "ModegyRuntime",
    "ProxyComponentFactory": "ModegyFactory",
    "JniBridge": "ModegyNativeBridge",
    "VmBridge": "ModegyVM",
    "DexMerger": "ModegyDexLoader",
    "StrEnc": "ModegyCodec",
    "ProtectorAssets": "ModegyAssets",
    "NativeLibDirRedirect": "ModegyLibRedirect",
}
EXTENSIONS = {".java", ".cpp", ".c", ".h", ".hpp", ".kt"}
ROLL_KEY, ROLL_PRIME = 0x5A, 0x1B

def renamed(s: str) -> str:
    s = s.replace(OLD_PKG_DOT, NEW_PKG_DOT).replace(OLD_PKG_PATH, NEW_PKG_PATH)
    s = s.replace("com.yqsh.protector.junkcode", "com.modegypro.protection.decoy")
    s = s.replace("com/yqsh/protector/junkcode", "com/modegypro/protection/decoy")
    s = s.replace("Lcom/yqsh/protector/", "Lcom/modegypro/protection/")
    for old, new in CLASSES.items():
        s = s.replace(old, new)
    for old, new in NAMES.items():
        s = s.replace(old, new)
    s = s.replace("assets/protector", "assets/" + ASSET_DIR)
    s = s.replace("code_cache/protector", "code_cache/" + ASSET_DIR)
    s = s.replace("/protector/", "/" + ASSET_DIR + "/")
    s = s.replace('"protector/"', '"' + ASSET_DIR + '/"')
    s = s.replace('"protector"', '"' + ASSET_DIR + '"')
    s = s.replace("libprotector.so", "libMODEGYPRO.so")
    s = s.replace("libprotector", "libMODEGYPRO")
    s = s.replace('System.loadLibrary("protector")',
                  'System.loadLibrary("MODEGYPRO")')
    return s

def decoded(raw: bytes) -> str | None:
    plain = bytes(b ^ (ROLL_KEY ^ (i * ROLL_PRIME & 255))
                  for i, b in enumerate(raw))
    try:
        return plain.decode("utf-8")
    except UnicodeDecodeError:
        return None

def encoded(s: str) -> bytes:
    return bytes(b ^ (ROLL_KEY ^ (i * ROLL_PRIME & 255))
                 for i, b in enumerate(s.encode("utf-8")))

# Existing shell constants are XOR-encoded, so plaintext-only substitution
# would leave runtime looking for the OLD names.
JAVA_ARRAY = re.compile(r"StrEnc\.d\(new byte\[\]\s*\{([^}]*)\}\s*\)", re.S)
def rewrite_java_arrays(s: str) -> str:
    def fix(m):
        values = [int(h, 16) for h in re.findall(r"0x([0-9a-fA-F]{2})", m.group(1))]
        if not values:
            return m.group(0)
        old = decoded(bytes(values))
        if old is None:
            return m.group(0)
        new = ASSET_DIR if old == "protector" else renamed(old)
        if new == old:
            return m.group(0)
        body = ", ".join("(byte)0x%02x" % b if b >= 128 else "0x%02x" % b
                         for b in encoded(new))
        return "StrEnc.d(new byte[]{" + body + "})"
    return JAVA_ARRAY.sub(fix, s)

# Obfuscated native strings also use a rolling XOR byte representation.
C_ENCODED = re.compile(r'"((?:\\x[0-9a-fA-F]{2}){3,})"')
def rewrite_cpp_literals(s: str) -> str:
    def fix(m):
        b = bytes(int(v, 16) for v in re.findall(r"\\x([0-9a-fA-F]{2})", m.group(1)))
        old = decoded(b)
        if old is None:
            return m.group(0)
        new = ASSET_DIR if old == "protector" else renamed(old)
        if new == old:
            return m.group(0)
        return '"' + "".join("\\x%02x" % x for x in encoded(new)) + '"'
    return C_ENCODED.sub(fix, s)

def patch_cryptographic_identity(root: Path) -> None:
    """Change BOTH endpoints of slot markers and HKDF labels, plus self-test fixtures."""
    def change(path: str, old: str, new: str):
        file = root / path
        src = file.read_text(encoding="utf-8")
        if src.count(old) != 1:
            raise RuntimeError("Upstream identity source changed: " + path + " " + old)
        file.write_text(src.replace(old, new), encoding="utf-8")

    java_key = "packer/src/main/java/com/yqsh/protector/packer/KeyLadder.java"
    cpp_master = "native/src/main/cpp/crypto/key_ladder.cpp"
    cpp_wrap = "native/src/main/cpp/crypto/section_decrypt.cpp"
    change(java_key,
           "'X', 'O', 'P', 'K', 'M', 'A', 'S', 'T', 'E', 'R'",
           "'M', 'G', 'P', 'R', 'M', 'A', 'S', 'T', 'E', 'R'")
    change(java_key,
           "'X', 'O', 'P', 'K', 'W', 'R', 'A', 'P'",
           "'M', 'G', 'P', 'R', 'W', 'R', 'A', 'P'")
    change(cpp_master,
           "0x58, 0x4f, 0x50, 0x4b, 0x4d, 0x41, 0x53, 0x54, 0x45, 0x52",
           "0x4d, 0x47, 0x50, 0x52, 0x4d, 0x41, 0x53, 0x54, 0x45, 0x52")
    change(cpp_wrap,
           "0x58, 0x4f, 0x50, 0x4b, 0x57, 0x52, 0x41, 0x50",
           "0x4d, 0x47, 0x50, 0x52, 0x57, 0x52, 0x41, 0x50")

    for rel in (
        java_key,
        cpp_master,
        "packer/src/test/java/com/yqsh/protector/packer/HkdfSha256Test.java",
    ):
        file = root / rel
        old = file.read_text(encoding="utf-8")
        new = old.replace("xop-", "mgp-")
        if new == old:
            raise RuntimeError("No HKDF domain-label replacement in " + rel)
        file.write_text(new, encoding="utf-8")

    for rel in (
        "packer/src/main/java/com/yqsh/protector/packer/SoSectionEncryptor.java",
        "packer/src/test/java/com/yqsh/protector/packer/KeyLadderTest.java",
    ):
        file = root / rel
        old = file.read_text(encoding="utf-8")
        new = old.replace("XOPKMASTER", "MGPRMASTER").replace("XOPKWRAP", "MGPRWRAP")
        if new == old:
            raise RuntimeError("No sentinel-label replacement in " + rel)
        file.write_text(new, encoding="utf-8")

    # Recompute SHA-256 HKDF fixture vectors; never silence the native self-test.
    master, cert = bytes(range(32)), bytes(range(32, 64))
    prk = hmac.new(cert, master, hashlib.sha256).digest()
    pkg = "com.yqsh.protectordemo"
    fixture = {}
    for kind, size in (("dex", 16), ("insn", 16), ("so", 16),
                       ("sowarm", 16), ("assets", 16), ("hmac", 32)):
        info = ("mgp-" + kind + "-v1" + pkg).encode("ascii")
        fixture[kind] = hmac.new(prk, info + b"\x01", hashlib.sha256).digest()[:size]

    native = root / "native/src/main/cpp/crypto/sha256.cpp"
    src = native.read_text(encoding="utf-8")
    def replace_native_array(name: str, values: bytes):
        nonlocal src
        pattern = re.compile(
            r"(static const uint8_t " + re.escape(name)
            + r"\[\d*\] PROT_RODATA = \{\s*)(.*?)(\s*\};)", re.S)
        def sub(m):
            return (m.group(1) + "\n        "
                    + ", ".join("0x%02x" % b for b in values)
                    + "\n    " + m.group(3).lstrip())
        src, cnt = pattern.subn(sub, src)
        if cnt != 1:
            raise RuntimeError("Native HKDF fixture changed: " + name)
    for kind, name in (("dex", "kInfoDex"), ("so", "kInfoSo"),
                       ("hmac", "kInfoHmac")):
        replace_native_array(name, ("mgp-" + kind + "-v1" + pkg).encode("ascii"))
    for kind, name in (("dex", "kDex16"), ("so", "kSo16"),
                       ("hmac", "kHmac32")):
        replace_native_array(name, fixture[kind])
    if "xop-" in src:
        src = src.replace("xop-", "mgp-")
    native.write_text(src, encoding="utf-8")

    # Update all existing Java golden tests with independently derived vectors.
    known = {
        "dex": "377ce3ca1ceb73aa0318643721a0a84a",
        "insn": "38e9face9f71e908b85c1e564efb4a89",
        "so": "5442b8e8c5ac63a13adfab1cb0385785",
        "sowarm": "3e8114e0448f162d290263d25c39feef",
        "assets": "86305d5b387e5431a8004e3c7bdfc645",
        "hmac": "91766823d4ae9feaa9d3f8ab390a2e3d504fade7afee6b9ffb11ec7eae5de688"
    }
    for rel in (
        "packer/src/test/java/com/yqsh/protector/packer/HkdfSha256Test.java",
        "packer/src/test/java/com/yqsh/protector/packer/KeyLadderTest.java",
    ):
        file = root / rel
        content = file.read_text(encoding="utf-8")
        for kind, oldhex in known.items():
            newhex = fixture[kind].hex()
            if oldhex in content:
                content = content.replace(oldhex, newhex)
            elif kind == "hmac":
                half = len(oldhex) // 2
                oldsplit = '"' + oldhex[:half] + '"\n                        + "' + oldhex[half:] + '"'
                newsplit = '"' + newhex[:half] + '"\n                        + "' + newhex[half:] + '"'
                content = content.replace(oldsplit, newsplit)
        file.write_text(content, encoding="utf-8")

    print("MODEGY key slot markers and per-APK HKDF domains patched in both packer and native")


def patch_tree(root: Path) -> None:
    if not (root / "packer/src/main/java/com/yqsh/protector/packer/PackerMain.java").is_file():
        raise RuntimeError("Not a verified XopProtector source tree")
    shell = root / "native/src/main/java/com/yqsh/protector/shell"
    if not shell.is_dir():
        raise RuntimeError("Unexpected upstream shell directory")
    touched = []
    for subtree in ("packer/src/main/java", "native/src/main/java", "native/src/main/cpp"):
        for p in (root / subtree).rglob("*"):
            if not p.is_file() or p.suffix not in EXTENSIONS or "external" in p.parts:
                continue
            old = p.read_text(encoding="utf-8")
            new = rewrite_java_arrays(old) if p.suffix == ".java" else old
            if p.suffix in {".cpp", ".c", ".h", ".hpp"}:
                new = rewrite_cpp_literals(new)
            new = renamed(new)
            if new != old:
                p.write_text(new, encoding="utf-8")
                touched.append(p.relative_to(root).as_posix())

    # bytehook links the upstream shadowhook dependency and also checks its
    # basename at runtime. Keep that string synchronized with the ELF rename
    # performed after exportShellFiles by the experimental workflow.
    bh_path = root / "native/src/main/cpp/external/bhook/bytehook/src/main/cpp/bh_const.h"
    bh = bh_path.read_text(encoding="utf-8")
    old_shadow = '#define BH_CONST_BASENAME_SHADOWHOOK         "libshadowhook.so"'
    if bh.count(old_shadow) != 1:
        raise RuntimeError("Upstream bytehook dependency basename changed")
    bh_path.write_text(bh.replace(old_shadow,
        '#define BH_CONST_BASENAME_SHADOWHOOK         "libMODEGY_PROTECTION.so"'),
        encoding="utf-8")

    # Build libMODEGYPRO.so directly from CMake, retaining exported entry points.
    cm = root / "native/src/main/cpp/CMakeLists.txt"
    source = cm.read_text(encoding="utf-8")
    source, count = re.subn(r"add_library\(protector SHARED", "add_library(MODEGYPRO SHARED", source)
    if count != 1:
        raise RuntimeError("Upstream native target changed")
    source = re.sub(r"(target_[a-z_]+\()protector\b", r"\1MODEGYPRO", source)
    source = source.replace("protector_apply_llvm_obf(protector)",
                            "protector_apply_llvm_obf(MODEGYPRO)")
    cm.write_text(source, encoding="utf-8")

    gradle = root / "native/build.gradle.kts"
    g = gradle.read_text(encoding="utf-8")
    if 'namespace = "com.yqsh.protector"' not in g:
        raise RuntimeError("Upstream native namespace changed")
    gradle.write_text(g.replace('namespace = "com.yqsh.protector"',
                                'namespace = "com.modegypro.protection"'), encoding="utf-8")

    # Relocate Java package and rename classes, including source file names.
    target_dir = root / "native/src/main/java/com/modegypro/protection/shell"
    target_dir.parent.mkdir(parents=True, exist_ok=True)
    shell.rename(target_dir)
    for old, new in CLASSES.items():
        a = target_dir / (old + ".java")
        if a.is_file():
            a.rename(target_dir / (new + ".java"))

    # Empty runtime debug report in APK is not needed by loader.
    packer = root / "packer/src/main/java/com/yqsh/protector/packer/PackerMain.java"
    p = packer.read_text(encoding="utf-8")
    expression = re.compile(
        r'\s*Files\.writeString\(new File\(assetsProtector, "MODEGY_REPORT\.dat"\)\.toPath\(\),'
        r'\s*reportPlaceholder,\s*StandardCharsets\.UTF_8\);')
    p, count = expression.subn("\n            // Keep size report beside output, not inside APK.", p)
    if count != 1:
        raise RuntimeError("APK-embedded diagnostic report changed")
    # Real authenticated encryption of the policy (nonce || ciphertext || GCM tag).
    # The per-APK assets AES key is already derived by the native key ladder
    # BEFORE runtime parses the configuration; retaining the HMAC after decrypt.
    old_write = ('Files.writeString(new File(assetsProtector, "MODEGY_POLICY.dat").toPath(), config,'
                 '\n                    StandardCharsets.UTF_8);')
    new_write = ('Files.write(new File(assetsProtector, "MODEGY_POLICY.dat").toPath(),'
                 '\n                    CryptoUtils.aesGcmEncrypt(assetsAesKey,'
                 ' config.getBytes(StandardCharsets.UTF_8)));')
    if p.count(old_write) != 1:
        raise RuntimeError("Expected policy writer unavailable")
    p = p.replace(old_write, new_write)
    packer.write_text(p, encoding="utf-8")

    # Runtime decrypts policy into memory with the same per-app key, checks the
    # GCM authentication tag, and only then verifies the existing config HMAC.
    engine = root / "native/src/main/cpp/runtime/engine.cpp"
    cpp = engine.read_text(encoding="utf-8")
    needle = '#include "crypto/key_ladder.h"'
    if cpp.count(needle) != 1:
        raise RuntimeError("Runtime key ladder include changed")
    cpp = cpp.replace(needle, needle + '\n#include "crypto/aes.h"')
    old_parse = '    parse_config_json(read_file(config_path));'
    new_parse = '''
    std::string encrypted_policy = read_file(config_path);
    if (encrypted_policy.size() <= 28 || state.config.assets_aes_key.size() != 16) {
        PLOGE("Encrypted policy missing or invalid");
        protector::risk::crash_exit();
        return;
    }
    std::string policy_plain(encrypted_policy.size() - 28, '\\0');
    if (!protector::crypto::aes128_gcm_decrypt(
            state.config.assets_aes_key.data(),
            reinterpret_cast<const uint8_t*>(encrypted_policy.data()),
            encrypted_policy.size(),
            reinterpret_cast<uint8_t*>(policy_plain.data()), policy_plain.size())) {
        PLOGE("Encrypted policy authentication failed");
        protector::risk::crash_exit();
        return;
    }
    parse_config_json(policy_plain);
    std::fill(policy_plain.begin(), policy_plain.end(), '\\0');'''.strip('\n')
    if cpp.count(old_parse) != 1:
        raise RuntimeError("Runtime config loader changed")
    cpp = cpp.replace(old_parse, new_parse)
    engine.write_text(cpp, encoding="utf-8")

    # The old hardcoded length is for '/dexes.zip'. Use new filename length.
    dex = root / "native/src/main/cpp/dex/dex_file.cpp"
    c = dex.read_text(encoding="utf-8")
    old = 'container.size() >= 10 && container.compare(container.size() - 10, 10, "/MODEGY_DATA.zip")'
    suffix_len = len("/" + NAMES["dexes.zip"])
    replacement = (f'container.size() >= {suffix_len} && '
                   f'container.compare(container.size() - {suffix_len}, {suffix_len}, "/MODEGY_DATA.zip")')
    if old not in c:
        raise RuntimeError("Expected hardcoded DEX archive suffix check missing")
    dex.write_text(c.replace(old, replacement), encoding="utf-8")

    patch_cryptographic_identity(root)

    # Reject any stale runtime path literals, but generic 'protector' namespaces
    # are source implementation details and are not automatically changed.
    critical = {
        'native/src/main/java/com/modegypro/protection/shell/ModegyRuntime.java',
        'native/src/main/java/com/modegypro/protection/shell/ModegyFactory.java',
        'native/src/main/cpp/runtime/engine.cpp',
        'native/src/main/cpp/dex/dex_file.cpp',
        'packer/src/main/java/com/yqsh/protector/packer/PackerMain.java',
    }
    for name in sorted(critical):
        body = (root / name).read_text(encoding="utf-8")
        if "assets/protector/" in body or '"code.bin"' in body:
            raise RuntimeError("Unpatched stale asset name in " + name)
    print("MODEGYPRO experiment patched first-party source files:", len(touched))
    print("Runtime lib: libMODEGYPRO.so")
    print("Code payload: assets/MODEGY_PROTECTION/MODEGY_CORE.vmp")
    print("Diagnostic report: excluded from packaged APK")
    print("Policy encrypted using per-APK AES-128-GCM; native also verifies original HMAC.")
    print("Shadowhook rename requires ELF SONAME/NEEDED patch and ABI checks after build.")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise SystemExit("Usage: python modegy_brand_patch.py /tmp/XopProtector")
    patch_tree(Path(sys.argv[1]).resolve())
