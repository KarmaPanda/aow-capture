"""A small stand-in for the upload receiver (which lives in the private
aow-capture-backend repo): just the upload protocol the client speaks.

GET  /api/v1/ping                      -> {"ok", "tester", "max_bytes"}
POST /api/v1/uploads {filename,size,sha256} -> {"id", "offset", "done"}
PUT  /api/v1/uploads/<id>?offset=N     -> {"offset", "done"} | 409 {"offset"}
"""

import hashlib
import json
import re
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse


class FakeReceiver:
    def __init__(self, max_bytes=50 * 1024 * 1024):
        self.tokens = {}         # token -> tester
        self.revoked = set()
        self.partial = {}        # (tester, id) -> {"meta":…, "data": bytearray}
        self.done = {}           # (tester, sha) -> stored name
        self.files = {}          # (tester, filename) -> bytes
        self.max_bytes = max_bytes
        self.lock = threading.Lock()
        self.srv = ThreadingHTTPServer(("127.0.0.1", 0), self._handler())
        self.url = f"http://127.0.0.1:{self.srv.server_address[1]}"

    def create(self, tester):
        token = hashlib.sha256(f"{tester}{len(self.tokens)}".encode()).hexdigest()[:24]
        self.tokens[token] = tester
        return token

    def revoke(self, tester):
        self.revoked |= {t for t, n in self.tokens.items() if n == tester}

    def start(self):
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()
        return self

    def stop(self):
        self.srv.shutdown()

    def _handler(rx):
        class H(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def _json(self, code, payload):
                body = json.dumps(payload).encode()
                self.send_response(code)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def _auth(self):
                h = self.headers.get("Authorization", "")
                token = h[7:] if h.startswith("Bearer ") else ""
                tester = rx.tokens.get(token) if token not in rx.revoked else None
                if not tester:
                    self._json(401, {"error": "unknown or revoked invite"})
                return tester

            def _body(self):
                return self.rfile.read(int(self.headers.get("Content-Length") or 0))

            def do_GET(self):
                if urlparse(self.path).path != "/api/v1/ping":
                    return self._json(404, {"error": "not found"})
                tester = self._auth()
                if tester:
                    self._json(200, {"ok": True, "tester": tester, "max_bytes": rx.max_bytes})

            def do_POST(self):
                tester = self._auth()
                if not tester:
                    return
                meta = json.loads(self._body())
                sha = meta["sha256"]
                with rx.lock:
                    if (tester, sha) in rx.done:
                        return self._json(200, {"id": sha[:32], "offset": meta["size"], "done": True,
                                                "stored": rx.done[(tester, sha)]})
                    p = rx.partial.setdefault((tester, sha[:32]), {"meta": meta, "data": bytearray()})
                    self._json(200, {"id": sha[:32], "offset": len(p["data"]), "done": False})

            def do_PUT(self):
                url = urlparse(self.path)
                m = re.fullmatch(r"/api/v1/uploads/([0-9a-f]{32})", url.path)
                tester = self._auth()
                if not tester:
                    return
                offset = int(parse_qs(url.query)["offset"][0])
                data = self._body()
                with rx.lock:
                    p = rx.partial.get((tester, m.group(1)))
                    if not p:
                        return self._json(404, {"error": "unknown upload; start again"})
                    if offset != len(p["data"]):
                        return self._json(409, {"offset": len(p["data"])})
                    p["data"] += data
                    meta = p["meta"]
                    if len(p["data"]) < meta["size"]:
                        return self._json(200, {"offset": len(p["data"]), "done": False})
                    if hashlib.sha256(p["data"]).hexdigest() != meta["sha256"]:
                        del rx.partial[(tester, m.group(1))]
                        return self._json(400, {"error": "checksum mismatch"})
                    stored = f"inbox/{tester}/{meta['filename']}"
                    rx.files[(tester, meta["filename"])] = bytes(p["data"])
                    rx.done[(tester, meta["sha256"])] = stored
                    del rx.partial[(tester, m.group(1))]
                    self._json(200, {"offset": meta["size"], "done": True, "stored": stored})
        return H
