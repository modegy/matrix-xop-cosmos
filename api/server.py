#!/usr/bin/env python3
"""Isolated XopProtector worker: NO Matrix, V4, database, or admin integration."""
import base64
import hashlib
import hmac
import json
import os
import queue
import re
import shutil
import signal
import struct
import subprocess
import threading
import time
import uuid
import zipfile
import zlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit

BASE = Path("/data/jobs")
PACKER = Path("/opt/xop/packer.jar")
SHELL = Path("/opt/xop/shell-files")
TOKEN = os.environ.get("XOP_API_TOKEN", "")
MAX_APK = int(os.environ.get("XOP_MAX_APK_MB", "128")) * 1024 * 1024
MAX_OUT = int(os.environ.get("XOP_MAX_OUTPUT_MB", "256")) * 1024 * 1024
TIMEOUT = int(os.environ.get("XOP_TIMEOUT_SECONDS", "900"))
TTL = int(os.environ.get("XOP_RETENTION_SECONDS", "3600"))
JAVA_HEAP_MB = int(os.environ.get("XOP_JAVA_HEAP_MB", "768"))
JOBS = {}
LOCK = threading.RLock()
QUEUE = queue.Queue(maxsize=3)
CAPACITY = threading.BoundedSemaphore(3)
HEX_ID = re.compile(r"^[0-9a-f]{32}$")
PREFIX = re.compile(r"^L(?:[A-Za-z_$][A-Za-z0-9_$]*/){1,16}(?:[A-Za-z_$][A-Za-z0-9_$]*;?)?$")
SO_NAME = re.compile(r"^lib[A-Za-z0-9_.+-]{1,100}\.so$")
ABIS = {"all", "armeabi-v7a", "arm64-v8a", "x86", "x86_64"}

def reject(code):
    raise ValueError(code)

def parse_options(encoded):
    if not encoded:
        return {"profile": "balanced", "protectSo": True}
    if len(encoded) > 8192:
        reject("XOP_OPTIONS_TOO_LARGE")
    try:
        compressed = encoded.startswith("z:")
        source = encoded[2:] if compressed else encoded
        if not re.fullmatch(r"[A-Za-z0-9_-]+", source):
            reject("XOP_OPTIONS_INVALID")
        packed = base64.urlsafe_b64decode(source + "=" * (-len(source) % 4))
        if compressed:
            decoder = zlib.decompressobj(-zlib.MAX_WBITS)
            raw = decoder.decompress(packed, 65537)
            if len(raw) > 65536 or decoder.unconsumed_tail or not decoder.eof or decoder.unused_data:
                reject("XOP_OPTIONS_INVALID")
        else:
            raw = packed
        if len(raw) > 65536:
            reject("XOP_OPTIONS_INVALID")
        value = json.loads(raw)
    except (ValueError, UnicodeError, zlib.error):
        reject("XOP_OPTIONS_INVALID")
    if not isinstance(value, dict):
        reject("XOP_OPTIONS_INVALID")
    allowed = {"profile", "protectSo", "modegySingleRootDex", "encryptAssets", "enableResProtect",
               "trueVmpPrefixes", "hollowPrefixes", "soMode", "soAbi",
               "soExclude", "riskFlags", "raspAction", "reportEnabled", "certSha256", "detectProxy"}
    if set(value) - allowed:
        reject("XOP_OPTIONS_UNKNOWN")
    if value.get("profile", "balanced") not in ("balanced", "perf", "industry", "aggressive", "max"):
        reject("XOP_PROFILE_INVALID")
    value.setdefault("profile", "balanced")
    for field in ("protectSo", "modegySingleRootDex", "encryptAssets", "enableResProtect", "reportEnabled", "detectProxy"):
        if field in value and type(value[field]) is not bool:
            reject("XOP_OPTIONS_INVALID")
    for field in ("trueVmpPrefixes", "hollowPrefixes"):
        items = value.get(field, [])
        if not isinstance(items, list) or len(items) > (256 if field == "trueVmpPrefixes" else 64) or any(
            not isinstance(x, str) or len(x) > 150 or not PREFIX.fullmatch(x) for x in items
        ):
            reject("XOP_SCOPE_INVALID")
        value[field] = list(dict.fromkeys(items))
    if value.get("soMode", "safe") not in ("safe", "aggressive", "max"):
        reject("XOP_SO_MODE_INVALID")
    if value.get("soAbi", "all") not in ABIS:
        reject("XOP_SO_ABI_INVALID")
    ex = value.get("soExclude", [])
    if not isinstance(ex, list) or len(ex) > 256 or any(
        not isinstance(x, str) or not SO_NAME.fullmatch(x) for x in ex
    ):
        reject("XOP_SO_EXCLUDE_INVALID")
    value["soExclude"] = list(dict.fromkeys(ex))
    for name, limit in (("riskFlags", 2147483647), ("raspAction", 2)):
        if name in value and (type(value[name]) is not int or not 0 <= value[name] <= limit):
            reject("XOP_OPTIONS_INVALID")
    if "certSha256" in value:
        cert = value["certSha256"]
        if not isinstance(cert, str) or not re.fullmatch(r"[0-9a-f]{64}", cert):
            reject("XOP_CERT_SHA256_INVALID")
    return value

def cli_args(options, src, dst, tmp):
    cmd = ["java", "-Xms64m", "-Xmx%dm" % JAVA_HEAP_MB, "-Djava.io.tmpdir=" + str(tmp),
           "-jar", str(PACKER), str(src), "-o", str(dst), "--shell-dir", str(SHELL),
           "--profile", options["profile"], "--json-progress",
           "--no-payment-auto-vmp", "--no-industry-auto-vmp",
           "--protect-so" if options.get("protectSo", True) else "--no-protect-so"]
    for key, flag in (("encryptAssets", "--encrypt-assets"),
                      ("enableResProtect", "--enable-res-protect"),
                      ("modegySingleRootDex", "--modegy-single-root-dex")):
        if options.get(key):
            cmd.append(flag)
    for key, flag in (("trueVmpPrefixes", "--true-vmp-prefix"), ("hollowPrefixes", "--hollow-prefix")):
        for scope in options.get(key, []):
            cmd.extend((flag, scope))
    for key, flag in (("soMode", "--protect-so-mode"), ("soAbi", "--protect-so-abi")):
        if key in options:
            cmd.extend((flag, options[key]))
    if options.get("soExclude"):
        cmd.extend(("--protect-so-exclude", ",".join(options["soExclude"])))
    for key, flag in (("riskFlags", "--risk-flags"), ("raspAction", "--rasp-action")):
        if key in options:
            cmd.extend((flag, str(options[key])))
    if "reportEnabled" in options:
        cmd.extend(("--report-enabled", "1" if options["reportEnabled"] else "0"))
    if options.get("detectProxy", False):
        cmd.append("--detect-proxy")
    if "certSha256" in options:
        cmd.extend(("--cert-sha256", options["certSha256"]))
    return cmd

def normalize_unsigned_zip(path):
    """Trim only unreferenced bytes after a structurally verified ZIP EOCD.

    The packer produces an UNSIGNED APK; stripping its trailing data before
    external signing is safe only after validating the central-directory bounds.
    Do not invoke on already signed APKs or user-supplied input files.
    """
    with path.open("r+b") as stream:
        size = stream.seek(0, os.SEEK_END)
        # EOCD can have up to 65535 bytes of comment. Permit a limited
        # trailing-data window; oversized/corrupt output fails closed.
        window = min(size, 22 + 65535 + 65535)
        stream.seek(size - window)
        tail = stream.read()
        idx = tail.rfind(b"PK\x05\x06")
        while idx >= 0:
            if len(tail) - idx >= 22:
                (sig, disk, cd_disk, on_disk, count, cd_size, cd_offset,
                 comment_size) = struct.unpack_from("<4sHHHHIIH", tail, idx)
                eocd = size - window + idx
                logical_end = eocd + 22 + comment_size
                # Only a complete, single-volume, non-Zip64 central directory
                # whose recorded end coincides with this EOCD is accepted.
                if (sig == b"PK\x05\x06" and disk == cd_disk == 0
                        and on_disk == count and 0 < count < 20001
                        and cd_offset != 0xffffffff and cd_size != 0xffffffff
                        and cd_offset + cd_size == eocd
                        and cd_offset + 4 <= size and logical_end <= size):
                    stream.seek(cd_offset)
                    if stream.read(4) == b"PK\x01\x02":
                        trailing = size - logical_end
                        if trailing:
                            stream.truncate(logical_end)
                            stream.flush()
                            os.fsync(stream.fileno())
                        return trailing
            idx = tail.rfind(b"PK\x05\x06", 0, idx)
    reject("XOP_OUTPUT_ZIP_EOCD_INVALID")

def apk_check(path, output=False):
    if output:
        # This must be a strict Android-installable ZIP end, not merely a
        # Python-readable archive with ignored bytes after its EOCD.
        with path.open("rb") as stream:
            size = stream.seek(0, os.SEEK_END)
            window = min(size, 22 + 65535 + 65535)
            stream.seek(size - window)
            tail = stream.read()
        idx = tail.rfind(b"PK\x05\x06")
        if idx < 0 or idx + 22 > len(tail):
            reject("XOP_OUTPUT_ZIP_EOCD_INVALID")
        comment_size = struct.unpack_from("<H", tail, idx + 20)[0]
        if size - window + idx + 22 + comment_size != size:
            reject("XOP_OUTPUT_ZIP_TRAILING")
    if not zipfile.is_zipfile(path):
        reject("XOP_APK_NOT_ZIP")
    with zipfile.ZipFile(path) as z:
        entries = z.infolist()
        if len(entries) > 20000:
            reject("XOP_APK_TOO_MANY_FILES")
        total = 0
        names = set()
        for entry in entries:
            name = entry.filename
            if (name.startswith("/") or "\\" in name or ".." in name.split("/")
                    or "\x00" in name or entry.flag_bits & 1):
                reject("XOP_APK_UNSAFE_ENTRY")
            total += entry.file_size
            if total > 1024 * 1024 * 1024:
                reject("XOP_APK_UNPACKED_TOO_LARGE")
            names.add(name)
        if "AndroidManifest.xml" not in names:
            reject("XOP_APK_NO_MANIFEST")
        if output:
            # Both layouts are produced by the pinned build variants.
            # Requiring a complete bundle prevents accepting a stray assets folder.
            bundles = (
                ("assets/protector/dexes.zip",
                 "assets/protector/code.bin",
                 "assets/protector/config.json"),
                ("assets/MODEGY_PROTECTION/MODEGY_DATA.zip",
                 "assets/MODEGY_PROTECTION/MODEGY_CORE.vmp",
                 "assets/MODEGY_PROTECTION/MODEGY_POLICY.dat"),
            )
            matched = next((bundle for bundle in bundles
                            if all(part in names for part in bundle)), None)
            if matched is None:
                reject("XOP_OUTPUT_NOT_PROTECTED")
            archive, code, policy = matched
            if z.getinfo(code).file_size < 4 or z.getinfo(policy).file_size == 0:
                reject("XOP_OUTPUT_NOT_PROTECTED")
            with z.open(archive) as stream:
                if stream.read(4) != b"PDX1":
                    reject("XOP_OUTPUT_NOT_PROTECTED")
        if z.testzip() is not None:
            reject("XOP_APK_CRC_INVALID")

def persist(job):
    fields = ("id", "status", "created", "updated", "sha256",
              "size", "error", "resultSha256", "resultSize")
    dst = BASE / job["id"] / "meta.json"
    tmp = dst.with_suffix(".tmp")
    tmp.write_text(json.dumps({key: job[key] for key in fields}, separators=(",", ":")))
    os.replace(tmp, dst)

def set_state(job, **updates):
    with LOCK:
        job.update(updates)
        job["updated"] = int(time.time())
        persist(job)

def classify_packer_failure(log_path):
    """Return stable non-sensitive codes, never a raw packer stack trace."""
    try:
        with log_path.open("rb") as stream:
            stream.seek(0, os.SEEK_END)
            stream.seek(max(0, stream.tell() - 65536))
            tail = stream.read(65536).decode("utf-8", errors="replace")
    except OSError:
        return "XOP_PACKER_EXIT_NONZERO"
    if "MODEGY_DEX_SINGLE_FILE_LIMIT_" in tail:
        return "XOP_DEX_REFERENCE_LIMIT"
    if "MODEGY_DEX_MERGE_UNSAFE_CLASS" in tail:
        return "XOP_DEX_MERGE_UNSAFE"
    if "MODEGY_DEX_DUPLICATE_CLASS" in tail:
        return "XOP_DEX_DUPLICATE_CLASS"
    if "MODEGY_SELECTED_VMP_NOT_APPLIED" in tail:
        return "XOP_VMP_SELECTION_UNSUPPORTED"
    if ("OutOfMemoryError" in tail or "GC overhead limit exceeded" in tail
            or "Java heap space" in tail):
        return "XOP_PACKER_JAVA_OOM"
    return "XOP_PACKER_EXIT_NONZERO"


def process_one(job_id):
    with LOCK:
        job = JOBS[job_id]
    folder = BASE / job_id
    output = folder / "output.apk"
    try:
        set_state(job, status="running")
        cmd = cli_args(job["options"], folder / "input.apk", output, folder)
        with (folder / "packer.log").open("wb") as log:
            child = subprocess.Popen(cmd, cwd=folder, stdout=log,
                                     stderr=subprocess.STDOUT, start_new_session=True,
                                     close_fds=True)
            try:
                exit_code = child.wait(timeout=TIMEOUT)
            except subprocess.TimeoutExpired:
                os.killpg(child.pid, signal.SIGKILL)
                child.wait()
                reject("XOP_PACKER_TIMEOUT")
        if exit_code:
            reject(classify_packer_failure(folder / "packer.log"))
        if not output.is_file() or not 1024 <= output.stat().st_size <= MAX_OUT:
            reject("XOP_OUTPUT_SIZE_INVALID")
        # Normalize only the worker-generated UNSIGNED APK, before hashing
        # or handing it to an external signer. Input APKs are never modified.
        normalize_unsigned_zip(output)
        apk_check(output, output=True)
        digest = hashlib.sha256()
        with output.open("rb") as f:
            for piece in iter(lambda: f.read(1024 * 1024), b""):
                digest.update(piece)
        set_state(job, status="succeeded", error="", resultSha256=digest.hexdigest(),
                  resultSize=output.stat().st_size)
    except ValueError as e:
        set_state(job, status="failed", error=str(e))
    except Exception:
        set_state(job, status="failed", error="XOP_PACKER_INTERNAL_ERROR")
    finally:
        CAPACITY.release()

def worker():
    while True:
        ident = QUEUE.get()
        try:
            process_one(ident)
        except Exception:
            with LOCK:
                if ident in JOBS:
                    set_state(JOBS[ident], status="failed", error="XOP_WORKER_INTERNAL_ERROR")
        finally:
            QUEUE.task_done()

def rehydrate():
    BASE.mkdir(parents=True, exist_ok=True)
    for folder in BASE.iterdir():
        if not folder.is_dir() or not HEX_ID.fullmatch(folder.name):
            continue
        try:
            job = json.loads((folder / "meta.json").read_text())
            if job["id"] != folder.name:
                continue
            job["options"] = {}
            if job["status"] in ("queued", "running"):
                job["status"] = "failed"
                job["error"] = "XOP_WORK_INTERRUPTED"
                job["updated"] = int(time.time())
                persist(job)
            JOBS[folder.name] = job
        except (OSError, ValueError, KeyError):
            continue

def cleanup_loop():
    while True:
        time.sleep(60)
        now = time.time()
        with LOCK:
            stale = [k for k, v in JOBS.items() if v["status"] in ("succeeded", "failed")
                     and now - v["updated"] > TTL]
            for ident in stale:
                JOBS.pop(ident, None)
                shutil.rmtree(BASE / ident, ignore_errors=True)

class Handler(BaseHTTPRequestHandler):
    server_version = "MatrixXop/1"
    protocol_version = "HTTP/1.1"
    def log_message(self, fmt, *args):
        print("%s %s" % (self.client_address[0], fmt % args), flush=True)
    def reply(self, status, body):
        raw = json.dumps(body, separators=(",", ":")).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(raw)
    def authorized(self):
        if not hmac.compare_digest(self.headers.get("Authorization", ""), "Bearer " + TOKEN):
            self.reply(401, {"code": "XOP_UNAUTHORIZED"})
            return False
        return True
    def do_GET(self):
        path = urlsplit(self.path).path
        if path == "/health":
            ready = PACKER.is_file() and (SHELL / "dex/classes.dex").is_file() and len(TOKEN) >= 32
            self.reply(200 if ready else 503, {"ready": ready, "worker": "xop"})
            return
        if not self.authorized():
            return
        parts = path.strip("/").split("/")
        if len(parts) not in (3, 4) or parts[:2] != ["v1", "jobs"] or not HEX_ID.fullmatch(parts[2]):
            self.reply(404, {"code": "NOT_FOUND"})
            return
        with LOCK:
            job = JOBS.get(parts[2])
            if job is None:
                self.reply(404, {"code": "XOP_JOB_NOT_FOUND"})
                return
            data = {k: job[k] for k in ("id", "status", "created", "updated", "sha256",
                                        "size", "error", "resultSha256", "resultSize")}
        if len(parts) == 3:
            self.reply(200, data)
            return
        if parts[3] != "apk" or data["status"] != "succeeded":
            self.reply(409, {"code": "XOP_RESULT_UNAVAILABLE"})
            return
        file = BASE / parts[2] / "output.apk"
        if not file.is_file():
            self.reply(410, {"code": "XOP_RESULT_EXPIRED"})
            return
        self.send_response(200)
        self.send_header("Content-Type", "application/vnd.android.package-archive")
        self.send_header("Content-Disposition", 'attachment; filename="protected.apk"')
        self.send_header("Content-Length", str(file.stat().st_size))
        self.send_header("X-Content-SHA256", data["resultSha256"])
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        try:
            with file.open("rb") as f:
                shutil.copyfileobj(f, self.wfile, 1024 * 1024)
        except (BrokenPipeError, ConnectionResetError):
            pass
    def do_POST(self):
        if not self.authorized():
            self.close_connection = True
            return
        if urlsplit(self.path).path != "/v1/jobs":
            self.reply(404, {"code": "NOT_FOUND"})
            return
        if self.headers.get("Content-Type", "").split(";", 1)[0] != "application/vnd.android.package-archive":
            self.reply(415, {"code": "XOP_CONTENT_TYPE_INVALID"})
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
            if not 1024 < length <= MAX_APK:
                reject("XOP_INPUT_SIZE_INVALID")
            options = parse_options(self.headers.get("X-XOP-Options", ""))
        except (ValueError, OverflowError) as e:
            self.reply(400, {"code": str(e) if str(e).startswith("XOP_") else "XOP_INPUT_INVALID"})
            self.close_connection = True
            return
        if not CAPACITY.acquire(blocking=False):
            self.reply(429, {"code": "XOP_QUEUE_FULL"})
            return
        ident = uuid.uuid4().hex
        folder = BASE / ident
        accepted = False
        try:
            folder.mkdir(mode=0o700)
            digest = hashlib.sha256()
            remaining = length
            self.connection.settimeout(120)
            with (folder / "input.apk").open("xb") as f:
                while remaining:
                    block = self.rfile.read(min(1024 * 1024, remaining))
                    if not block:
                        raise OSError("incomplete upload")
                    f.write(block)
                    digest.update(block)
                    remaining -= len(block)
            apk_check(folder / "input.apk")
            now = int(time.time())
            job = dict(id=ident, status="queued", created=now, updated=now,
                       sha256=digest.hexdigest(), size=length, error="",
                       resultSha256="", resultSize=0, options=options)
            with LOCK:
                JOBS[ident] = job
                persist(job)
                QUEUE.put_nowait(ident)
                accepted = True
        except (OSError, ValueError, zipfile.BadZipFile) as e:
            if not accepted:
                shutil.rmtree(folder, ignore_errors=True)
                CAPACITY.release()
            self.reply(400, {"code": str(e) if isinstance(e, ValueError) and str(e).startswith("XOP_")
                             else "XOP_INPUT_INVALID"})
            self.close_connection = True
            return
        self.reply(202, {"id": ident, "status": "queued", "statusPath": "/v1/jobs/" + ident})

def main():
    if len(TOKEN) < 32 or TOKEN.startswith("REPLACE_") or not 32 <= JAVA_HEAP_MB <= 4096 or not 60 <= TIMEOUT <= 3600:
        raise SystemExit("XOP configuration invalid: token, heap or timeout")
    rehydrate()
    threading.Thread(target=worker, daemon=True).start()
    threading.Thread(target=cleanup_loop, daemon=True).start()
    server = ThreadingHTTPServer(("0.0.0.0", 8761), Handler)
    server.daemon_threads = True
    print("Matrix XOP worker listening on 8761", flush=True)
    server.serve_forever(poll_interval=0.5)

if __name__ == "__main__":
    main()
