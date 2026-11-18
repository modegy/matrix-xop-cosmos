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
    "ApplicationReplacer": "Qm7A9R",
    "DexScanCompat": "Jv8A2C",
    "JunkClass": "T7mA2X",
    "ProtectorAssets": "ModegyAssets",
    "NativeLibDirRedirect": "ModegyLibRedirect",
}
EXTENSIONS = {".java", ".cpp", ".c", ".h", ".hpp", ".kt"}
ROLL_KEY, ROLL_PRIME = 0x5A, 0x1B

def renamed(s: str) -> str:
    # MUST run before the generic quoted "protector" asset-dir rewrite.
    # Otherwise System.loadLibrary("protector") incorrectly loads the renamed
    # shadowhook dependency (libMODEGY_PROTECTION.so), whose JNI_OnLoad fails.
    s = s.replace('System.loadLibrary("protector")',
                  'System.loadLibrary("MODEGYPRO")')
    s = s.replace(OLD_PKG_DOT, NEW_PKG_DOT).replace(OLD_PKG_PATH, NEW_PKG_PATH)
    s = s.replace("com.yqsh.protector.junkcode", "com.modegypro.protection.decoy")
    s = s.replace("com/yqsh/protector/junkcode", "com/modegypro/protection/decoy")
    s = s.replace("Lcom/yqsh/protector/", "Lcom/modegypro/protection/")
    for old, new in CLASSES.items():
        s = s.replace(old, new)
    for old, new in NAMES.items():
        s = s.replace(old, new)
    # Encrypted business assets must share the same relative path in packer and runtime.
    # The previous broad replacements skipped quoted "protector/aenc" (no terminal slash).
    s = s.replace("protector/aenc", ASSET_DIR + "/aenc")
    s = s.replace("assets/protector", "assets/" + ASSET_DIR)
    s = s.replace("code_cache/protector", "code_cache/" + ASSET_DIR)
    s = s.replace("/protector/", "/" + ASSET_DIR + "/")
    s = s.replace('"protector/"', '"' + ASSET_DIR + '/"')
    s = s.replace('"protector"', '"' + ASSET_DIR + '"')
    s = s.replace("libprotector.so", "libMODEGYPRO.so")
    s = s.replace("libprotector", "libMODEGYPRO")
    s = s.replace("[XOP-SO]", "[MODEGY-SO]")
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
    # The runtime SO guard uses a separate XOPKMASTER marker to locate the
    # writable master payload before computing the in-memory .bitcode HMAC.
    # If left unchanged, the matcher finds zero slots and deliberately exits
    # the app with "so_guard bitcode hmac fail: bind".
    change("native/src/main/cpp/risk/so_guard.cpp",
           "0x58, 0x4f, 0x50, 0x4b, 0x4d, 0x41, 0x53, 0x54, 0x45, 0x52",
           "0x4d, 0x47, 0x50, 0x52, 0x4d, 0x41, 0x53, 0x54, 0x45, 0x52")
    for rel in (cpp_master, "native/src/main/cpp/risk/so_guard.cpp"):
        content = (root / rel).read_text(encoding="utf-8")
        if "0x58, 0x4f, 0x50, 0x4b, 0x4d, 0x41, 0x53, 0x54, 0x45, 0x52" in content:
            raise RuntimeError("Legacy SO master marker retained in " + rel)
        if "0x4d, 0x47, 0x50, 0x52, 0x4d, 0x41, 0x53, 0x54, 0x45, 0x52" not in content:
            raise RuntimeError("MODEGY SO master marker missing in " + rel)
    print("Runtime .bitcode guard and packer key-slot magic synchronized")
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





def patch_strict_selected_vmp(root: Path) -> None:
    """Explicitly requested VMP must protect at least one method per scope."""
    p = root / "packer/src/main/java/com/yqsh/protector/packer/PackerMain.java"
    s = p.read_text(encoding="utf-8")
    def ch(old: str, new: str) -> None:
        nonlocal s
        if s.count(old) != 1:
            raise RuntimeError("Explicit VMP source drift " + old[:100])
        s = s.replace(old, new, 1)
    ch("    private final List<String> trueVmpPrefixes = new ArrayList<>();",
       "    private final List<String> trueVmpPrefixes = new ArrayList<>();\n"
       "    private final Set<String> admittedExplicitVmp = new HashSet<>();")
    ch("            pvm2Admission.reset();",
       "            pvm2Admission.reset();\n"
       "            admittedExplicitVmp.clear();")
    ch('            System.out.println(pvm2Admission.admissionLine());',
       '            if (!admittedExplicitVmp.containsAll(trueVmpPrefixes)) {\n'
       '                Set<String> unsupported = new LinkedHashSet<>(trueVmpPrefixes);\n'
       '                unsupported.removeAll(admittedExplicitVmp);\n'
       '                throw new IOException("MODEGY_SELECTED_VMP_NOT_APPLIED: " + unsupported);\n'
       '            }\n'
       '            System.out.println(pvm2Admission.admissionLine());')
    ch('            pvm2Admission.noteSuccess();',
       '            pvm2Admission.noteSuccess();\n'
       '            for (String requested : trueVmpPrefixes) {\n'
       '                if (typeDescriptor.startsWith(requested)) {\n'
       '                    admittedExplicitVmp.add(requested);\n'
       '                }\n'
       '            }')
    p.write_text(s, encoding="utf-8")
    print("Explicit True-VMP scope admission fails closed when no selected method was protected")


def patch_selected_runtime_rasp(root: Path) -> None:
    """Fix one-shot checks running before the authenticated runtime policy loads."""
    def change(path: str, old: str, new: str) -> None:
        p = root / path
        body = p.read_text(encoding="utf-8")
        if body.count(old) != 1:
            raise RuntimeError("MODEGY RASP upstream drift: " + path + " " + old[:90])
        p.write_text(body.replace(old, new, 1), encoding="utf-8")

    risk = "native/src/main/cpp/risk/risk.cpp"
    header = "native/src/main/cpp/risk/risk.h"
    engine = "native/src/main/cpp/runtime/engine.cpp"

    # init_protector() starts this thread in JNI_OnLoad, when risk_flags is
    # still 50 (Root/Emulator/CRC disabled). The original one-shot branch
    # permanently consumed Root/Emulator checks before config.json was parsed.
    # Do not delay the early continuous Frida/anti-debug checks.
    change(risk,
           "        if (!ran_one_shot) {\n            ran_one_shot = true;",
           "        if (!ran_one_shot && "
           "runtime_state().inited.load(std::memory_order_acquire)) {\n"
           "            ran_one_shot = true;")

    # Process-local LSPosed native bridge indicators, in addition to the
    # existing xposed/lsposed/edxposed names. This deliberately does NOT claim
    # to detect a manager installed but not injected into the target process.
    lsplant = "".join("\\x%02x" % b for b in encoded("lsplant"))
    liblspd = "".join("\\x%02x" % b for b in encoded("liblspd"))
    marker = '        if (strstr(line, OBSC_DECODE("\\x22\\x31\\x03\\x78\\x53\\xb9")) || // xposed'
    extra = ('        if (strstr(line, OBSC_DECODE("' + lsplant + '")) || // lsplant\n'
             '            strstr(line, OBSC_DECODE("' + liblspd + '")) || // liblspd\n'
             '            strstr(line, OBSC_DECODE("\\x22\\x31\\x03\\x78\\x53\\xb9")) || // xposed')
    change(risk, marker, extra)

    # Detect visible executable su entries from the process PATH and euid=0.
    # No shell is executed and no permissions are requested.
    root_start = "static bool root_binaries_found() {\n"
    root_check = r'''static bool root_binaries_found() {
    if (geteuid() == 0) return true;
    const char* path_env = getenv("PATH");
    while (path_env != nullptr && *path_env != '\0') {
        const char* end = strchr(path_env, ':');
        const size_t len = end != nullptr
                ? static_cast<size_t>(end - path_env) : strlen(path_env);
        if (len > 1 && len < PATH_MAX - 4 && path_env[0] == '/') {
            char path[PATH_MAX];
            memcpy(path, path_env, len);
            memcpy(path + len, "/su", 4);
            if (access(path, X_OK) == 0) return true;
        }
        if (end == nullptr) break;
        path_env = end + 1;
    }
'''
    change(risk, root_start, root_check)

    # A real JNI class check rather than the old comment pretending one
    # existed. The protected app's current native call provides JNIEnv.
    # Absence is normal; clear only our own ClassNotFound exception.
    change(header, "#include <cstdint>\n", "#include <cstdint>\n#include <jni.h>\n")
    change(header,
           "void scan_hooks_and_frida_now();",
           "void scan_hooks_and_frida_now();\n"
           "/** Process-visible XposedBridge class probe after verified config. */\n"
           "void scan_xposed_java_now(JNIEnv* env);")
    hook = "static void detect_xposed() {\n"
    probe = r'''void scan_xposed_java_now(JNIEnv* env) {
    if (env == nullptr) return;
    int flags = runtime_state().config.risk_flags.load(std::memory_order_acquire);
    if ((flags & FLAG_DISABLE_XPOSED_DETECT) != 0) return;
    jclass bridge = env->FindClass("de/robv/android/xposed/XposedBridge");
    if (bridge != nullptr) {
        env->DeleteLocalRef(bridge);
        CRASH_SEGV("xposed_bridge_class");
        return;
    }
    if (env->ExceptionCheck()) env->ExceptionClear();
}

static void detect_xposed() {
'''
    change(risk, hook, probe)

    sign_anchor = ('    if (!hex_equals_ci(cert_hex, state.config.app_sign_sha256)) {\n'
                   '        PLOGE("config cert mismatch");\n'
                   '        protector::risk::crash_abort();\n'
                   '        return;\n'
                   '    }\n')
    change(engine, sign_anchor,
           sign_anchor + '\n'
           '    // Selected Xposed/LSPosed check, with an app-native JNI environment.\n'
           '    protector::risk::scan_xposed_java_now(env);\n')
    print("MODEGY RASP checks: policy-gated one-shot, visible root and Xposed class probes")


def patch_modegy_dex_redivision(root: Path) -> None:
    """Opt-in, strict one-root-DEX composition; encrypted VMP stays separate."""
    def replace_one(path: str, old: str, new: str) -> None:
        p = root / path
        body = p.read_text(encoding="utf-8")
        if body.count(old) != 1:
            raise RuntimeError("Single-root-DEX source drift: " + path + ": " + old)
        p.write_text(body.replace(old, new, 1), encoding="utf-8")

    options = "packer/src/main/java/com/yqsh/protector/packer/ProtectOptions.java"
    packer = "packer/src/main/java/com/yqsh/protector/packer/PackerMain.java"
    replace_one(options,
                "    public boolean protectSo = true;",
                "    public boolean protectSo = true;\n"
                "    /** Optional merge of root shell/plain/decoy DEX; fail on unsafe output. */\n"
                "    public boolean modegySingleRootDex = false;")
    replace_one(packer,
                "    private boolean protectSo = true;",
                "    private boolean protectSo = true;\n"
                "    private boolean modegySingleRootDex = false;")
    replace_one(packer,
                "        protectSo = options.protectSo;",
                "        protectSo = options.protectSo;\n"
                "        modegySingleRootDex = options.modegySingleRootDex;")
    replace_one(packer,
                "        boolean protectSo = true;",
                "        boolean protectSo = true;\n"
                "        boolean modegySingleRootDexFlag = false;")
    replace_one(packer,
                '            } else if ("--no-protect-so".equals(args[i])) {\n'
                '                protectSo = false;',
                '            } else if ("--no-protect-so".equals(args[i])) {\n'
                '                protectSo = false;\n'
                '            } else if ("--modegy-single-root-dex".equals(args[i])) {\n'
                '                modegySingleRootDexFlag = true;')
    replace_one(packer,
                "        options.protectSo = protectSo;",
                "        options.protectSo = protectSo;\n"
                "        options.modegySingleRootDex = modegySingleRootDexFlag;")
    replace_one(packer,
                "            embedJunkCodeDex(unpack, work.toFile());",
                "            embedJunkCodeDex(unpack, work.toFile());\n"
                "            if (modegySingleRootDex) {\n"
                "                ModegyRootDexRedivision.merge(unpack);\n"
                "            }")
    for source, target in (
        ("ModegyRootDexRedivision.java",
         "packer/src/main/java/com/yqsh/protector/packer/ModegyRootDexRedivision.java"),
        ("ModegyRootDexRedivisionTest.java",
         "packer/src/test/java/com/yqsh/protector/packer/ModegyRootDexRedivisionTest.java"),
    ):
        p = Path(__file__).resolve().with_name(source)
        if not p.is_file():
            raise RuntimeError("MODEGY DEX merger source missing: " + str(p))
        dst = root / target
        if dst.exists():
            raise RuntimeError("MODEGY DEX merger already in upstream: " + target)
        dst.write_bytes(p.read_bytes())
    print("Opt-in MODEGY root DEX redivision included; keeps VMP archive encrypted")



def patch_runtime_identity_and_diagnostics(root: Path) -> None:
    """Synchronize decoy generation with the native loader; strip release details."""
    packer = root / "packer/src/main/java/com/yqsh/protector/packer/JunkCodeGenerator.java"
    payload = packer.read_text(encoding="utf-8")
    # patch_tree already rebrands packer sources. Verify both endpoints
    # rather than applying the rename for a second time.
    marker = 'BASE_CLASS_NAME = "com/modegypro/protection/decoy/T7mA2X"'
    if payload.count(marker) != 1:
        raise RuntimeError("Decoy generator/runtime rebrand mismatch")
    engine = root / "native/src/main/cpp/runtime/engine.cpp"
    current = engine.read_text(encoding="utf-8")
    if current.count('"com.modegypro.protection.decoy.T7mA2X"') != 1:
        raise RuntimeError("Native decoy resolver out of sync with generator")

    shell = root / "native/src/main/java/com/modegypro/protection/shell"
    for renamed_java in ("Qm7A9R.java", "Jv8A2C.java"):
        p = shell / renamed_java
        contents = p.read_text(encoding="utf-8")
        # Logging shell class names, runtime exceptions and paths makes
        # reverse-engineering easier and can expose exception contents.
        # Strip only complete standalone log statements; keep exception handling.
        pattern = re.compile(
            r"(?m)^[ \t]*Log\.(?:d|e|i|v|w)\(TAG,[\s\S]*?\);[ \t]*(?:\n|$)")
        contents, count = pattern.subn("", contents)
        if count < 5:
            raise RuntimeError("Unexpected Java logging structure " + renamed_java)
        contents = contents.replace("import android.util.Log;\n", "")
        contents = re.sub(
            r'(?m)^[ \t]*private static final String TAG = "protector\.[^"]+";[ \t]*\n',
            "", contents)
        if "Log." in contents or "protector.AppReplace" in contents or "protector.DexScan" in contents:
            raise RuntimeError("Sensitive Java diagnostic remains: " + renamed_java)
        p.write_text(contents, encoding="utf-8")

    # Rename selected non-framework shell helper entry points in all Java call
    # sites together. Avoid generic reflection/JNI method name rewriting.
    helper_names = {
        "findBusinessApplication": "n5V7qR",
        "markProvidersAlreadyInstalled": "u3D8wC",
        "reattach": "j8U5vE",
        "prefetchFacadeAsync": "k2X9aQ",
    }
    for p in shell.glob("*.java"):
        body = p.read_text(encoding="utf-8")
        for old_name, new_name in helper_names.items():
            body = re.sub(r"\\b" + old_name + r"\\b", new_name, body)
        p.write_text(body, encoding="utf-8")

    # The reattach return value is never consumed by the shell callers; keep
    # the actual operation inline but avoid a public mutable boolean success gate.
    app_helper = shell / "Qm7A9R.java"
    body = app_helper.read_text(encoding="utf-8")
    head1 = "public static boolean j8U5vE(Application real) {"
    head2 = "public static boolean j8U5vE(Application real, @Nullable Application proxyHint) {"
    if body.count(head1) != 1 or body.count(head2) != 1:
        raise RuntimeError("Application reattach signature changed")
    body = body.replace(head1, head1.replace("boolean", "void"))
    body = body.replace("return j8U5vE(real, null);", "j8U5vE(real, null);\n        return;")
    body = body.replace(head2, head2.replace("boolean", "void"))
    start = body.index(head2.replace("boolean", "void"))
    end = body.index("    /**\n     * Move Application-scoped callback", start)
    method = body[start:end]
    if method.count("return true;") != 1 or method.count("return false;") < 1:
        raise RuntimeError("Application reattach return structure changed")
    method = method.replace("return true;", "return;").replace("return false;", "return;")
    body = body[:start] + method + body[end:]

    # Selected reflection and facade strings use the existing ModegyCodec
    # rolling-XOR de-obfuscator. This hides literal names, not cryptographic
    # confidentiality; do not confuse it with per-APK AES-GCM.
    encoded_fields = (
        "mBoundApplication", "mAllApplications", "mInitialApplication",
        "mApplicationInfo", "mApplication", "mComponentCallbacks",
        "mActivityLifecycleCallbacks", "mCallbacksController",
        "mAssistCallbacks", "mLock",
    )
    for field in encoded_fields:
        value = '"' + field + '"'
        if value not in body: continue
        raw = encoded(field)
        bytes_java = ", ".join(
            "(byte)0x%02x" % b if b >= 128 else "0x%02x" % b for b in raw)
        body = body.replace(value, "ModegyCodec.d(new byte[]{" + bytes_java + "})")
    app_helper.write_text(body, encoding="utf-8")

    log_h = root / "native/src/main/cpp/common/log.h"
    contents = log_h.read_text(encoding="utf-8")
    old = ('// Keep PLOGE for crash forensics (only fires right before a crash).\n'
           '#define PLOGE(...) __android_log_print(ANDROID_LOG_ERROR, PROTECTOR_LOG_TAG, __VA_ARGS__)')
    if contents.count(old) != 1:
        raise RuntimeError("Native release log contract changed")
    log_h.write_text(contents.replace(old,
             '// No human-readable failure reasons in release logcat.\n'
             '#define PLOGE(...) ((void)0)'), encoding="utf-8")

    # The original release risk path writes the specific detector name
    # immediately before SIGILL / SIGSEGV.
    risk = root / "native/src/main/cpp/risk/risk.cpp"
    contents = risk.read_text(encoding="utf-8")
    for line in (
        '    __android_log_print(ANDROID_LOG_ERROR, "protector.risk", "sigill reason=%s", g_crash_reason);\n',
        '    __android_log_print(ANDROID_LOG_ERROR, "protector.risk", "sigsegv reason=%s", g_crash_reason);\n',
    ):
        if contents.count(line) != 1:
            raise RuntimeError("Native crash logging drift")
        contents = contents.replace(line, "")
    risk.write_text(contents, encoding="utf-8")

    # Matrix policy sets reportEnabled=false. The original file writer ignored
    # that flag and still wrote crash_reason.txt containing internal reasons.
    report = root / "native/src/main/cpp/report/threat_report.cpp"
    contents = report.read_text(encoding="utf-8")
    needle = 'void write_crash_reason(const char* reason, const char* kind) {\n'
    if contents.count(needle) != 1:
        raise RuntimeError("Crash reason output code drift")
    contents = contents.replace(needle,
        needle + '    if (!g_enabled.load(std::memory_order_acquire)) return;\n')
    report.write_text(contents, encoding="utf-8")
    # Prevent pre-policy failures from writing a reason file.
    contents = report.read_text(encoding="utf-8")
    state_flag = "static std::atomic_bool g_enabled{true};"
    if contents.count(state_flag) != 1:
        raise RuntimeError("Threat reporting default drift")
    report.write_text(contents.replace(state_flag,
        "static std::atomic_bool g_enabled{false};"), encoding="utf-8")
    print("Decoy generator verified; obfuscated Java shell, release diagnostics disabled")


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
    patch_modegy_dex_redivision(root)
    patch_selected_runtime_rasp(root)
    patch_strict_selected_vmp(root)
    patch_runtime_identity_and_diagnostics(root)

    # Fail the build if the app's JNI bridge or class-loader factory attempts
    # to call JNI_OnLoad in the shadowhook dependency instead of our runtime.
    for rel in ("ModegyNativeBridge.java", "ModegyFactory.java"):
        java = (target_dir / rel).read_text(encoding="utf-8")
        if 'System.loadLibrary("MODEGYPRO")' not in java:
            raise RuntimeError("Wrong JNI runtime library in " + rel)
        if 'System.loadLibrary("MODEGY_PROTECTION")' in java:
            raise RuntimeError("Accidental shadowhook JNI_OnLoad in " + rel)
    for java_file in target_dir.glob("*.java"):
        if 'System.loadLibrary("MODEGY_PROTECTION")' in java_file.read_text(encoding="utf-8"):
            raise RuntimeError("Unexpected explicit shadowhook load in " + java_file.name)
    print("JNI loader verified: System.loadLibrary(MODEGYPRO)")

    # Assert the packer and Android runtime use the same encrypted-assets namespace.
    # This catches the silent bug where the APK carries assets/protector/aenc/*.
    packer_assets = (root / "packer/src/main/java/com/yqsh/protector/packer/AssetsEncryptor.java").read_text(encoding="utf-8")
    reader_assets = (root / "native/src/main/java/com/modegypro/protection/shell/ModegyAssets.java").read_text(encoding="utf-8")
    if ('AENC_DIR = "' + ASSET_DIR + '/aenc"') not in packer_assets:
        raise RuntimeError("Encrypted asset writer still uses wrong folder")
    if ('AENC_PREFIX = "' + ASSET_DIR + '/aenc/"') not in reader_assets:
        raise RuntimeError("Encrypted asset reader still uses wrong folder")
    if 'protector/aenc' in packer_assets or 'protector/aenc' in reader_assets:
        raise RuntimeError("Legacy protector/aenc path remains in asset writer or reader")
    print("MODEGY encrypted asset reader/writer paths verified:", ASSET_DIR + "/aenc")

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
