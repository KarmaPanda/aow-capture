"""Self-update from GitHub Releases (public repo, no token needed).

A release is tagged vX.Y.Z and carries:
    AoWCapture.exe          the new build
    SHA256SUMS.txt          "<sha256>  AoWCapture.exe" (and the zip)

Flow:
  1. check()     GET /repos/<repo>/releases/latest; newer version + exe asset -> Update
  2. download()  to %LOCALAPPDATA%\\AoWCapture\\update\\, verified against SHA256SUMS.txt
  3. apply()     only when idle: rename the running exe to AoWCapture.old.exe (Windows allows
                 renaming a running exe), move the new one into place, start it with
                 --wait-pid <this pid> [--tray], and let this process exit.
  4. The new copy waits for the old pid to exit, deletes AoWCapture.old.exe and carries on.
"""

import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import time
import urllib.error
import urllib.request

from . import APP_NAME, VERSION
from .config import app_dir, applog

DEFAULT_REPO = "KarmaPanda/aow-capture"
API = "https://api.github.com"
EXE_ASSET = "AoWCapture.exe"
SUMS_ASSET = "SHA256SUMS.txt"


class UpdateError(RuntimeError):
    pass


def parse_version(text):
    m = re.search(r"(\d+)\.(\d+)\.(\d+)", text or "")
    return tuple(int(x) for x in m.groups()) if m else (0, 0, 0)


def is_frozen():
    return bool(getattr(sys, "frozen", False))


def current_exe():
    return os.path.abspath(sys.executable) if is_frozen() else None


def _get(url, timeout=30, accept="application/vnd.github+json"):
    req = urllib.request.Request(url, headers={"Accept": accept,
                                               "User-Agent": f"{APP_NAME}/{VERSION}"})
    try:
        return urllib.request.urlopen(req, timeout=timeout)
    except urllib.error.HTTPError as e:
        raise UpdateError(f"GitHub answered {e.code} for {url}") from e
    except (urllib.error.URLError, OSError) as e:
        raise UpdateError(f"Can't reach GitHub: {getattr(e, 'reason', e)}") from e


class Update:
    def __init__(self, version, tag, notes, exe_url, sums_url, page_url):
        self.version, self.tag, self.notes = version, tag, notes
        self.exe_url, self.sums_url, self.page_url = exe_url, sums_url, page_url
        self.path = None   # downloaded + verified exe

    @property
    def label(self):
        return ".".join(map(str, self.version))


class Updater:
    def __init__(self, repo=DEFAULT_REPO, api=API, current=VERSION, folder=None):
        self.repo, self.api = repo, api.rstrip("/")
        self.current = parse_version(current)
        self.folder = folder or os.path.join(app_dir(), "update")

    # ---------------------------------------------------------------- check / download
    def check(self):
        """Returns an Update when a newer release with an exe exists, else None."""
        with _get(f"{self.api}/repos/{self.repo}/releases/latest") as r:
            rel = json.load(r)
        if rel.get("draft") or rel.get("prerelease"):
            return None
        version = parse_version(rel.get("tag_name"))
        if version <= self.current:
            return None
        assets = {a.get("name"): a.get("browser_download_url") for a in rel.get("assets") or []}
        if EXE_ASSET not in assets or SUMS_ASSET not in assets:
            return None
        return Update(version, rel.get("tag_name"), rel.get("body") or "", assets[EXE_ASSET],
                      assets[SUMS_ASSET], rel.get("html_url"))

    def download(self, update, progress=None):
        os.makedirs(self.folder, exist_ok=True)
        with _get(update.sums_url, accept="application/octet-stream") as r:
            sums = r.read().decode("utf-8", "replace")
        expected = None
        for line in sums.splitlines():
            parts = line.strip().split()
            if len(parts) >= 2 and parts[-1].lstrip("*") == EXE_ASSET:
                expected = parts[0].lower()
        if not expected or not re.fullmatch(r"[0-9a-f]{64}", expected):
            raise UpdateError("The release has no checksum for AoWCapture.exe.")
        target = os.path.join(self.folder, f"AoWCapture-{update.label}.exe")
        if os.path.exists(target) and _sha256(target) == expected:
            update.path = target
            return target
        part = target + ".part"
        h = hashlib.sha256()
        done = 0
        with _get(update.exe_url, timeout=120, accept="application/octet-stream") as r, \
                open(part, "wb") as f:
            total = int(r.headers.get("Content-Length") or 0)
            for block in iter(lambda: r.read(1 << 16), b""):
                f.write(block)
                h.update(block)
                done += len(block)
                if progress and total:
                    progress(done, total)
        if h.hexdigest() != expected:
            os.remove(part)
            raise UpdateError("The downloaded update didn't match its checksum; it was deleted.")
        os.replace(part, target)
        update.path = target
        applog(f"Update {update.label} downloaded and verified")
        return target

    # ---------------------------------------------------------------- apply
    def apply(self, update, hidden=False):
        """Swap the running exe for the update and start it. The caller must then exit."""
        exe = current_exe()
        if not exe:
            raise UpdateError("Running from source; updates only apply to AoWCapture.exe.")
        if not update.path or not os.path.exists(update.path):
            raise UpdateError("The update hasn't been downloaded.")
        old = os.path.join(os.path.dirname(exe), "AoWCapture.old.exe")
        try:
            if os.path.exists(old):
                os.remove(old)
        except OSError:
            old = os.path.join(os.path.dirname(exe), f"AoWCapture.old-{int(time.time())}.exe")
        os.replace(exe, old)                 # a running exe can be renamed
        try:
            shutil.copy2(update.path, exe)
        except OSError:
            os.replace(old, exe)             # put the old one back
            raise
        args = [exe, "--wait-pid", str(os.getpid())] + (["--tray"] if hidden else [])
        flags = (0x00000008 | 0x00000200) if os.name == "nt" else 0  # DETACHED_PROCESS | NEW_PROCESS_GROUP
        # A one-file PyInstaller app must not hand its unpack folder to the new exe.
        env = {k: v for k, v in os.environ.items() if not k.startswith(("_PYI", "_MEIPASS"))}
        env["PYINSTALLER_RESET_ENVIRONMENT"] = "1"
        subprocess.Popen(args, close_fds=True, creationflags=flags, cwd=os.path.dirname(exe), env=env)
        applog(f"Updating {VERSION} -> {update.label}; restarting")


def _sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for block in iter(lambda: f.read(1 << 20), b""):
            h.update(block)
    return h.hexdigest()


def wait_for_pid(pid, timeout=30):
    """In the new copy: wait until the old process has exited."""
    try:
        import psutil
        psutil.Process(int(pid)).wait(timeout=timeout)
    except Exception:
        time.sleep(1)


def cleanup_after_update():
    """Delete AoWCapture.old*.exe and stale downloads next to / for the running exe."""
    exe = current_exe()
    if exe:
        folder = os.path.dirname(exe)
        for name in os.listdir(folder):
            if name.lower().startswith("aowcapture.old") and name.lower().endswith(".exe"):
                for _ in range(10):
                    try:
                        os.remove(os.path.join(folder, name))
                        break
                    except OSError:
                        time.sleep(0.5)
    upd = os.path.join(app_dir(), "update")
    if os.path.isdir(upd):
        for name in os.listdir(upd):
            if parse_version(name) <= parse_version(VERSION):
                try:
                    os.remove(os.path.join(upd, name))
                except OSError:
                    pass
