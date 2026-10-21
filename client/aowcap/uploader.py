"""Resumable uploads to the capture receiver. Each zip has a sidecar '<zip>.upload.json'."""

import hashlib
import json
import os
import time
import urllib.error
import urllib.request

from . import APP_NAME, VERSION

CHUNK = 4 * 1024 * 1024


class UploadError(RuntimeError):
    pass


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for block in iter(lambda: f.read(1 << 20), b""):
            h.update(block)
    return h.hexdigest()


def state_path(zip_path):
    return zip_path + ".upload.json"


def read_state(zip_path):
    try:
        with open(state_path(zip_path), "r", encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError):
        return {"status": "local"}


def write_state(zip_path, **fields):
    st = read_state(zip_path)
    st.update(fields)
    with open(state_path(zip_path), "w", encoding="utf-8") as f:
        json.dump(st, f, indent=2)
    return st


class Client:
    def __init__(self, url, token, timeout=60):
        self.url = url.rstrip("/")
        self.token = token
        self.timeout = timeout

    def _req(self, method, path, body=None, ctype="application/json"):
        req = urllib.request.Request(self.url + path, data=body, method=method)
        req.add_header("Authorization", "Bearer " + self.token)
        req.add_header("User-Agent", f"{APP_NAME}/{VERSION}")
        if body is not None:
            req.add_header("Content-Type", ctype)
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                return resp.status, json.loads(resp.read() or b"{}")
        except urllib.error.HTTPError as e:
            try:
                payload = json.loads(e.read() or b"{}")
            except ValueError:
                payload = {}
            return e.code, payload
        except (urllib.error.URLError, OSError) as e:
            raise UploadError(f"Can't reach the upload server: {getattr(e, 'reason', e)}") from e

    def ping(self):
        status, data = self._req("GET", "/api/v1/ping")
        if status == 401:
            raise UploadError("The upload server rejected this invite code.")
        if status != 200:
            raise UploadError(f"Upload server error {status}: {data.get('error', '')}")
        return data

    def upload(self, zip_path, progress=None, retries=5):
        size = os.path.getsize(zip_path)
        st = read_state(zip_path)
        digest = st.get("sha256") or sha256_file(zip_path)
        write_state(zip_path, sha256=digest, status="uploading", size=size)
        meta = json.dumps({"filename": os.path.basename(zip_path), "size": size, "sha256": digest}).encode()
        status, data = self._req("POST", "/api/v1/uploads", meta)
        if status == 401:
            raise UploadError("The upload server rejected this invite code.")
        if status != 200:
            raise UploadError(f"Upload refused ({status}): {data.get('error', '')}")
        upload_id, offset = data["id"], int(data.get("offset", 0))
        if data.get("done"):
            write_state(zip_path, status="uploaded", uploaded_at=time.time(), stored=data.get("stored"))
            return data
        failures = 0
        with open(zip_path, "rb") as f:
            while offset < size:
                f.seek(offset)
                chunk = f.read(CHUNK)
                try:
                    status, data = self._req("PUT", f"/api/v1/uploads/{upload_id}?offset={offset}",
                                             chunk, "application/octet-stream")
                except UploadError:
                    failures += 1
                    if failures > retries:
                        write_state(zip_path, status="pending")
                        raise
                    time.sleep(min(30, 2 ** failures))
                    continue
                if status == 409:  # server has a different offset: resume from it
                    offset = int(data.get("offset", 0))
                    continue
                if status != 200:
                    write_state(zip_path, status="pending")
                    raise UploadError(f"Upload failed ({status}): {data.get('error', '')}")
                failures = 0
                offset = int(data["offset"])
                if progress:
                    progress(offset, size)
                if data.get("done"):
                    write_state(zip_path, status="uploaded", uploaded_at=time.time(),
                                stored=data.get("stored"))
                    return data
        raise UploadError("The server didn't confirm the finished upload.")


def new_upload_url(current, token, info, client_cls=None):
    """The upload server's answer to ping may name a new public address ("upload_url").
    Returns that address once it's confirmed to work with the same invite (and to belong
    to the same player), else None. Only https addresses are accepted."""
    new = (info.get("upload_url") or "").strip().rstrip("/")
    if not new or new == (current or "").rstrip("/") or not new.lower().startswith("https://"):
        return None
    try:
        there = (client_cls or Client)(new, token, timeout=20).ping()
    except UploadError:
        return None
    if there.get("tester") != info.get("tester"):
        return None
    return new
