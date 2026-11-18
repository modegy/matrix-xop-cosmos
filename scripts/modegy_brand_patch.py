#!/usr/bin/env python3
"""Brand the pinned upstream XopProtector runtime for an isolated MODEGYPRO experiment.

Operate ONLY on a fresh temporary upstream checkout. Never patch a deployed APK,
running container, user data, or signing key. Fails closed on upstream drift.
This renames identifiers and on-disk paths; it is NOT a cryptographic substitute.
"""
from __future__ import annotations

import re
import sys
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
    packer.write_text(p, encoding="utf-8")

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
    print("Note: signed config/HMAC is NOT encrypted, and external shadowhook name unchanged.")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise SystemExit("Usage: python modegy_brand_patch.py /tmp/XopProtector")
    patch_tree(Path(sys.argv[1]).resolve())
