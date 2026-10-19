#!/usr/bin/env python3
"""Upload receiver for AoW Capture (standard library only).

    python aow_capture_receiver.py invite BigRaxFriend --url https://captures.example.com
    python aow_capture_receiver.py serve --port 8765 --decode-repo D:\\aow-pserver-development
    python aow_capture_receiver.py list
    python aow_capture_receiver.py revoke BigRaxFriend

Files land in <data>/inbox/<tester>/<name>.zip and are unpacked next to it
(<name>/<name>.pcapng + manifest.json + capture-log.txt). Every finished upload is
appended to <data>/index.jsonl. --decode-repo decodes each upload with
decode_upload.py into <name>/decoded/ (one at a time, in the background). --on-upload
runs an extra command per upload with {zip}, {dir}, {pcapng} and {tester} filled in
(already quoted; don't add quotes).
The --data folder may be a UNC path such as \\\\nas\\share\\aow_captures.
"""

import argparse
import base64
import hashlib
import json
import os
import queue
import re
import secrets
import shlex
import shutil
import subprocess
import sys
import threading
import time
import zipfile
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

INVITE_PREFIX = "AOWCAP1."
NAME_RE = re.compile(r"^[A-Za-z0-9._-]{1,120}\.zip$")
TESTER_RE = re.compile(r"^[A-Za-z0-9_-]{1,32}$")
MAX_CHUNK = 16 * 1024 * 1024


# ------------------------------------------------------------------ tokens

class Tokens:
    def __init__(self, data_dir):
        self.path = os.path.join(data_dir, "tokens.json")
        self.lock = threading.Lock()

    def _load(self):
        try:
            with open(self.path, "r", encoding="utf-8") as f:
                return json.load(f)
        except (OSError, ValueError):
            return {}

    def _save(self, data):
        tmp = self.path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
        os.replace(tmp, self.path)

    @staticmethod
    def _hash(token):
        return hashlib.sha256(token.encode()).hexdigest()

    def create(self, tester):
        token = secrets.token_urlsafe(24)
        with self.lock:
            data = self._load()
            data[self._hash(token)] = {"tester": tester, "created": int(time.time()), "revoked": False}
            self._save(data)
        return token

    def lookup(self, token):
        entry = self._load().get(self._hash(token or ""))
        if entry and not entry.get("revoked"):
            return entry["tester"]
        return None

    def revoke(self, tester):
        with self.lock:
            data = self._load()
            n = 0
            for entry in data.values():
                if entry["tester"] == tester and not entry.get("revoked"):
                    entry["revoked"] = True
                    n += 1
            self._save(data)
        return n

    def testers(self):
        return sorted({e["tester"] for e in self._load().values() if not e.get("revoked")})


# ------------------------------------------------------------------ storage

class Store:
    def __init__(self, data_dir, max_bytes, extract=True, hook=None, worker=None):
        self.data_dir = data_dir
        self.max_bytes = max_bytes
        self.extract = extract
        self.hook = hook
        self.worker = worker
        self.locks = {}
        self.glock = threading.Lock()
        for sub in ("inbox", "partial"):
            os.makedirs(os.path.join(data_dir, sub), exist_ok=True)

    def lock_for(self, key):
        with self.glock:
            return self.locks.setdefault(key, threading.Lock())

    def partial(self, tester, upload_id):
        d = os.path.join(self.data_dir, "partial", tester)
        os.makedirs(d, exist_ok=True)
        return os.path.join(d, upload_id + ".part"), os.path.join(d, upload_id + ".json")

    def find_done(self, tester, sha):
        idx = os.path.join(self.data_dir, "index.jsonl")
        try:
            with open(idx, "r", encoding="utf-8") as f:
                for line in f:
                    e = json.loads(line)
                    if e.get("tester") == tester and e.get("sha256") == sha:
                        return e
        except (OSError, ValueError):
            pass
        return None

    def finish(self, tester, meta, part_path):
        inbox = os.path.join(self.data_dir, "inbox", tester)
        os.makedirs(inbox, exist_ok=True)
        name = meta["filename"]
        dest = os.path.join(inbox, name)
        n = 2
        while os.path.exists(dest):
            dest = os.path.join(inbox, f"{name[:-4]}_{n}.zip")
            n += 1
        os.replace(part_path, dest)
        entry = {"received": datetime.now(timezone.utc).isoformat(timespec="seconds"),
                 "tester": tester, "file": os.path.relpath(dest, self.data_dir).replace("\\", "/"),
                 "size": meta["size"], "sha256": meta["sha256"]}
        out_dir, pcap = None, None
        if self.extract:
            try:
                out_dir, pcap, manifest = extract_zip(dest)
                entry["dir"] = os.path.relpath(out_dir, self.data_dir).replace("\\", "/")
                if manifest:
                    entry.update({k: manifest.get(k) for k in
                                  ("started", "duration_s", "note", "packets", "tool_version")})
                    entry["markers"] = len(manifest.get("markers") or [])
            except (zipfile.BadZipFile, OSError, ValueError) as e:
                entry["extract_error"] = str(e)
        with open(os.path.join(self.data_dir, "index.jsonl"), "a", encoding="utf-8") as f:
            f.write(json.dumps(entry, ensure_ascii=False) + "\n")
        print(f"[{entry['received']}] {tester}: {os.path.basename(dest)} ({meta['size']:,} bytes)", flush=True)
        if self.worker and out_dir and pcap:
            self.worker.submit(Job(dest, out_dir, pcap, tester))
        return entry


def extract_zip(zip_path):
    """Unpacks only flat, expected members; never trusts paths inside the zip."""
    out_dir = zip_path[:-4]
    os.makedirs(out_dir, exist_ok=True)
    pcap, manifest = None, None
    total = 0
    with zipfile.ZipFile(zip_path) as z:
        for info in z.infolist():
            base = os.path.basename(info.filename)
            if not base or base != info.filename or not re.match(r"^[A-Za-z0-9._-]+$", base):
                continue
            if not base.endswith((".pcapng", ".json", ".txt")):
                continue
            total += info.file_size
            if total > 8 * 1024 ** 3:
                raise ValueError("zip expands too large")
            target = os.path.join(out_dir, base)
            with z.open(info) as src, open(target, "wb") as dst:
                shutil.copyfileobj(src, dst)
            if base.endswith(".pcapng"):
                pcap = target
            elif base == "manifest.json":
                with open(target, "r", encoding="utf-8") as f:
                    manifest = json.load(f)
    return out_dir, pcap, manifest


class Job:
    def __init__(self, zip_path, out_dir, pcap, tester):
        self.zip, self.dir, self.pcap, self.tester = zip_path, out_dir, pcap, tester


class DecodeWorker(threading.Thread):
    """Runs the decoder (and an optional extra command) for one upload at a time.

    The decoder is tools/decode_upload.py from the --decode-repo checkout when it exists
    (so decoder fixes arrive with git pull, no restart), else the copy next to this file.
    Output goes to <dir>/decode.log; the result to <dir>/decode-status.json.

    Every few minutes it rescans the inbox and queues:
      - uploads with no decode-status.json (stopped mid-decode, or deleted to re-decode);
      - failed decodes older than the current decoder file (retried after a fix).
    """

    RESCAN_SECONDS = 300

    def __init__(self, repo=None, hook=None, pull=False, timeout=3600, data_dir=None):
        super().__init__(daemon=True, name="decode-worker")
        self.repo, self.hook, self.pull, self.timeout = repo, hook, pull, timeout
        self.data_dir = data_dir
        self.jobs = queue.Queue()
        self.queued = set()
        self.qlock = threading.Lock()
        self.last_pull = 0
        self.bundled = os.path.join(os.path.dirname(os.path.abspath(__file__)), "decode_upload.py")

    @property
    def decoder(self):
        if self.repo:
            p = os.path.join(self.repo, "tools", "decode_upload.py")
            if os.path.exists(p):
                return p
        return self.bundled

    def submit(self, job):
        with self.qlock:
            if job.dir in self.queued:
                return False
            self.queued.add(job.dir)
        self.jobs.put(job)
        return True

    def _needs_decode(self, d):
        status = os.path.join(d, "decode-status.json")
        if not os.path.exists(status):
            return True
        try:
            with open(status, encoding="utf-8") as f:
                ok = json.load(f).get("ok")
        except (OSError, ValueError):
            return True
        if ok:
            return False
        try:  # failed before: retry once the decoder has changed since
            return os.path.getmtime(self.decoder) > os.path.getmtime(status)
        except OSError:
            return False

    def backfill(self, data_dir=None):
        data_dir = data_dir or self.data_dir
        inbox = os.path.join(data_dir, "inbox")
        n = 0
        for tester in sorted(os.listdir(inbox)) if os.path.isdir(inbox) else []:
            tdir = os.path.join(inbox, tester)
            if not os.path.isdir(tdir):
                continue
            for name in sorted(os.listdir(tdir)):
                d = os.path.join(tdir, name)
                zp = d + ".zip"
                if not os.path.isdir(d) or not os.path.exists(zp) or not self._needs_decode(d):
                    continue
                pcaps = [f for f in os.listdir(d) if f.endswith(".pcapng")]
                if pcaps and self.submit(Job(zp, d, os.path.join(d, pcaps[0]), tester)):
                    n += 1
        if n:
            print(f"queued {n} upload(s) for decoding", flush=True)
        return n

    def _rescan_loop(self):
        while True:
            time.sleep(self.RESCAN_SECONDS)
            try:
                if self.pull and self.repo:
                    with open(os.devnull, "w") as devnull:
                        self._git_pull(devnull)
                self.backfill()
            except Exception as e:
                print("rescan failed:", e, flush=True)

    def start(self):
        super().start()
        if self.data_dir:
            threading.Thread(target=self._rescan_loop, daemon=True, name="decode-rescan").start()

    def _git_pull(self, log):
        if not (self.pull and self.repo) or time.time() - self.last_pull < 600:
            return
        self.last_pull = time.time()
        try:
            r = subprocess.run(["git", "-C", self.repo, "pull", "--ff-only", "-q"],
                               capture_output=True, text=True, timeout=120)
            log.write(f"$ git pull: {r.returncode} {r.stdout.strip()} {r.stderr.strip()}\n")
        except (OSError, subprocess.TimeoutExpired) as e:
            log.write(f"$ git pull failed: {e}\n")

    def _run(self, args, log, shell=False):
        log.write(f"$ {args if isinstance(args, str) else subprocess.list2cmdline(args)}\n")
        log.flush()
        env = dict(os.environ, PYTHONIOENCODING="utf-8")
        try:
            r = subprocess.run(args, stdout=log, stderr=subprocess.STDOUT, shell=shell,
                               timeout=self.timeout, env=env)
            return r.returncode
        except subprocess.TimeoutExpired:
            log.write("timed out\n")
            return -1
        except OSError as e:
            log.write(f"could not start: {e}\n")
            return -2

    def run(self):
        while True:
            job = self.jobs.get()
            started = time.time()
            status = {"started": datetime.now(timezone.utc).isoformat(timespec="seconds")}
            decoder = None
            try:
                with open(os.path.join(job.dir, "decode.log"), "a", encoding="utf-8") as log:
                    if self.repo:
                        self._git_pull(log)
                        decoder = self.decoder
                        status["decoder"] = decoder
                        status["decoder_rc"] = self._run(
                            [sys.executable, decoder, job.pcap, "--repo", self.repo], log)
                    if self.hook:
                        q = (lambda v: f'"{v}"') if os.name == "nt" else shlex.quote  # paths may contain spaces
                        cmd = self.hook.format(zip=q(job.zip), dir=q(job.dir), pcapng=q(job.pcap),
                                               tester=q(job.tester))
                        status["hook_rc"] = self._run(cmd if os.name == "nt" else shlex.split(cmd), log,
                                                      shell=(os.name == "nt"))
            except OSError as e:
                status["error"] = str(e)
            status["seconds"] = round(time.time() - started, 1)
            status["ok"] = not status.get("error") and all(
                status.get(k, 0) == 0 for k in ("decoder_rc", "hook_rc"))
            try:
                with open(os.path.join(job.dir, "decode-status.json"), "w", encoding="utf-8") as f:
                    json.dump(status, f, indent=2)
            except OSError:
                pass
            with self.qlock:
                self.queued.discard(job.dir)
            print(f"decoded {os.path.basename(job.dir)}: {'ok' if status['ok'] else 'FAILED'} "
                  f"({status['seconds']} s)", flush=True)


# ------------------------------------------------------------------ HTTP

def make_handler(tokens, store):
    class Handler(BaseHTTPRequestHandler):
        server_version = "AoWCaptureReceiver/1.0"

        def log_message(self, fmt, *args):
            pass  # quiet; finished uploads are printed by Store.finish

        def _json(self, code, payload):
            body = json.dumps(payload).encode()
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def _auth(self):
            h = self.headers.get("Authorization", "")
            tester = tokens.lookup(h[7:] if h.startswith("Bearer ") else "")
            if not tester:
                self._json(401, {"error": "unknown or revoked invite"})
            return tester

        def _body(self, limit):
            length = int(self.headers.get("Content-Length") or 0)
            if length < 0 or length > limit:
                return None
            data = b""
            while len(data) < length:
                chunk = self.rfile.read(min(1 << 20, length - len(data)))
                if not chunk:
                    break
                data += chunk
            return data

        def do_GET(self):
            path = urlparse(self.path).path
            if path == "/":
                self._json(200, {"service": "aow-capture-receiver"})
                return
            if path == "/api/v1/ping":
                tester = self._auth()
                if tester:
                    self._json(200, {"ok": True, "tester": tester, "max_bytes": store.max_bytes})
                return
            self._json(404, {"error": "not found"})

        def do_POST(self):
            if urlparse(self.path).path != "/api/v1/uploads":
                self._json(404, {"error": "not found"})
                return
            tester = self._auth()
            if not tester:
                return
            raw = self._body(64 * 1024)
            try:
                meta = json.loads(raw or b"")
                name, size, sha = meta["filename"], int(meta["size"]), meta["sha256"].lower()
            except (ValueError, KeyError, TypeError, AttributeError):
                self._json(400, {"error": "bad request"})
                return
            if not NAME_RE.match(name) or not re.fullmatch(r"[0-9a-f]{64}", sha):
                self._json(400, {"error": "bad file name or hash"})
                return
            if size <= 0 or size > store.max_bytes:
                self._json(413, {"error": f"file too large (max {store.max_bytes} bytes)"})
                return
            done = store.find_done(tester, sha)
            if done:
                self._json(200, {"id": sha[:32], "offset": size, "done": True, "stored": done["file"]})
                return
            upload_id = sha[:32]
            part, meta_path = store.partial(tester, upload_id)
            with store.lock_for((tester, upload_id)):
                with open(meta_path, "w", encoding="utf-8") as f:
                    json.dump({"filename": name, "size": size, "sha256": sha}, f)
                if not os.path.exists(part):
                    open(part, "wb").close()
                offset = os.path.getsize(part)
            self._json(200, {"id": upload_id, "offset": offset, "done": False})

        def do_PUT(self):
            url = urlparse(self.path)
            m = re.fullmatch(r"/api/v1/uploads/([0-9a-f]{32})", url.path)
            if not m:
                self._json(404, {"error": "not found"})
                return
            tester = self._auth()
            if not tester:
                return
            upload_id = m.group(1)
            try:
                offset = int(parse_qs(url.query).get("offset", ["-1"])[0])
            except ValueError:
                offset = -1
            part, meta_path = store.partial(tester, upload_id)
            if not os.path.exists(meta_path):
                self._json(404, {"error": "unknown upload; start again"})
                return
            data = self._body(MAX_CHUNK)
            if data is None:
                self._json(413, {"error": "chunk too large"})
                return
            with store.lock_for((tester, upload_id)):
                with open(meta_path, "r", encoding="utf-8") as f:
                    meta = json.load(f)
                current = os.path.getsize(part)
                if offset != current:
                    self._json(409, {"offset": current})
                    return
                if current + len(data) > meta["size"]:
                    self._json(400, {"error": "more data than announced"})
                    return
                with open(part, "ab") as f:
                    f.write(data)
                current += len(data)
                if current < meta["size"]:
                    self._json(200, {"offset": current, "done": False})
                    return
                h = hashlib.sha256()
                with open(part, "rb") as f:
                    for block in iter(lambda: f.read(1 << 20), b""):
                        h.update(block)
                if h.hexdigest() != meta["sha256"]:
                    os.remove(part)
                    os.remove(meta_path)
                    self._json(422, {"error": "checksum mismatch; upload restarted", "offset": 0})
                    return
                entry = store.finish(tester, meta, part)
                os.remove(meta_path)
            self._json(200, {"offset": current, "done": True, "stored": entry["file"]})

    return Handler


# ------------------------------------------------------------------ CLI

def make_invite(url, token, tester):
    raw = json.dumps({"url": url, "token": token, "tester": tester}, separators=(",", ":")).encode()
    return INVITE_PREFIX + base64.urlsafe_b64encode(raw).decode().rstrip("=")


def main(argv=None):
    ap = argparse.ArgumentParser(description="AoW Capture upload receiver")
    ap.add_argument("--data", default=os.environ.get("AOWCAP_DATA", "capture_inbox"),
                    help="storage folder (default ./capture_inbox)")
    sub = ap.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("serve")
    s.add_argument("--host", default="0.0.0.0")
    s.add_argument("--port", type=int, default=8765)
    s.add_argument("--max-mb", type=int, default=2048, help="largest accepted capture zip")
    s.add_argument("--no-extract", action="store_true")
    s.add_argument("--decode-repo", help="aow-pserver-development checkout: decode every upload with it")
    s.add_argument("--decode-pull", action="store_true", help="git pull --ff-only the repo before decoding")
    s.add_argument("--on-upload", help='extra command per upload, e.g. "python tools/analyze.py {pcapng}"')
    s.add_argument("--decode-timeout", type=int, default=3600)
    i = sub.add_parser("invite")
    i.add_argument("tester")
    i.add_argument("--url", required=True, help="public URL players upload to")
    r = sub.add_parser("revoke")
    r.add_argument("tester")
    sub.add_parser("list")
    sub.add_parser("testers")
    args = ap.parse_args(argv)

    os.makedirs(args.data, exist_ok=True)
    tokens = Tokens(args.data)

    if args.cmd == "invite":
        if not TESTER_RE.match(args.tester):
            ap.error("tester name: letters, digits, - and _ only (max 32)")
        token = tokens.create(args.tester)
        print(make_invite(args.url.rstrip("/"), token, args.tester))
        return 0
    if args.cmd == "revoke":
        print(f"Revoked {tokens.revoke(args.tester)} invite(s) for {args.tester}.")
        return 0
    if args.cmd == "testers":
        print("\n".join(tokens.testers()) or "(none)")
        return 0
    if args.cmd == "list":
        idx = os.path.join(args.data, "index.jsonl")
        if not os.path.exists(idx):
            print("(no uploads yet)")
            return 0
        with open(idx, "r", encoding="utf-8") as f:
            for line in f:
                e = json.loads(line)
                dec = ""
                if e.get("dir"):
                    try:
                        with open(os.path.join(args.data, e["dir"], "decode-status.json"), encoding="utf-8") as sf:
                            dec = " decoded" if json.load(sf).get("ok") else " DECODE-FAILED"
                    except (OSError, ValueError):
                        dec = " (not decoded)"
                print(f"{e['received']}  {e['tester']:<16} {e['size']:>12,}  {e['file']}{dec}"
                      + (f"  — {e['note'][:60]}" if e.get("note") else ""))
        return 0

    worker = None
    if args.decode_repo or args.on_upload:
        if args.decode_repo and not os.path.isdir(os.path.join(args.decode_repo, "tools")):
            ap.error(f"--decode-repo {args.decode_repo} is not an aow-pserver-development checkout")
        worker = DecodeWorker(args.decode_repo, args.on_upload, args.decode_pull, args.decode_timeout,
                              data_dir=args.data)
        worker.start()
        worker.backfill()
    store = Store(args.data, args.max_mb * 1024 * 1024, extract=not args.no_extract, worker=worker)
    server = ThreadingHTTPServer((args.host, args.port), make_handler(tokens, store))
    print(f"AoW Capture receiver on http://{args.host}:{args.port}  (data: {os.path.abspath(args.data)})",
          flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    return 0


if __name__ == "__main__":
    sys.exit(main())
