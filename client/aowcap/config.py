"""Settings: built-in defaults < defaults.json shipped next to the exe < the player's config."""

import base64
import json
import os
import sys

DEFAULTS = {
    # Who is recording: filled in from the upload server's answer for the invite code, and
    # only used in file names / manifests when there is an invite code.
    "tester_name": "",
    # Upload target, normally filled in from an invite code.
    "upload_url": "",
    "upload_token": "",
    "auto_upload": True,
    "auto_record": True,
    # Game detection: exe names to trust, plus any process that loads one of these DLLs.
    "process_names": [],
    "game_modules": ["fxnet2.dll"],
    # Only these count as official game servers. Traffic to anything else (other
    # servers, LAN, local programs) is never saved.
    "official_networks": ["148.153.0.0/16"],
    # Let Packet Monitor record only official_networks (much smaller raw files).
    "prefilter_networks": True,
    # Game sessions whose window title / launch args name another server are not recorded.
    # Any "Area-Server" title that names no official server already counts as another
    # server; private_servers lists extra names to treat that way.
    "official_servers": ["BlueDragon"],
    "private_servers": [],
    # Remote ports that are never game traffic (launcher, web, patcher).
    "ignore_ports": [80, 443, 8080],
    # If set, pktmon only records these ports (much smaller raw files, nothing else on the PC).
    # Fill in the official server ports in defaults.json before handing the tool out.
    "server_ports": [],
    # Ports always kept at save time even if the game's connection wasn't caught
    # (no effect on what pktmon records). Official game/config ports on 148.153.x.x.
    "known_ports": [2002, 2003, 2004, 4000],
    # Raw capture size limit in MB (pktmon file size). Only matters without server_ports.
    "raw_limit_mb": 4096,
    # Also record the game's link to a booster's local relay (ExitLag & co.) on 127.0.0.1.
    "capture_loopback": True,
    # Privacy rewriting of the saved capture.
    "anonymize_local": True,
    # Keep the unfiltered raw capture (debug only; contains all PC traffic).
    "keep_raw": False,
    "capture_dir": "",
    "consent_given": False,
    # While recording, save what's been captured so far as a part and upload it every N
    # minutes; recording carries on into the next part.
    "autosave": True,
    "autosave_minutes": 10,
    # Self-update from GitHub Releases; installs when nothing is being recorded or played.
    "auto_update": True,
    "update_repo": "KarmaPanda/aow-capture",
    # Tray: closing/minimizing the window keeps the tool running as a tray icon.
    "close_to_tray": True,
    "start_in_tray": False,
}

INVITE_PREFIX = "AOWCAP1."


def app_dir():
    base = os.environ.get("LOCALAPPDATA") or os.path.join(os.path.expanduser("~"), ".local", "share")
    path = os.path.join(base, "AoWCapture")
    os.makedirs(path, exist_ok=True)
    return path


def applog(msg):
    """Append to %LOCALAPPDATA%\\AoWCapture\\aowcap.log (kept even when nothing gets saved)."""
    try:
        path = os.path.join(app_dir(), "aowcap.log")
        if os.path.exists(path) and os.path.getsize(path) > 1_000_000:
            os.replace(path, path + ".1")
        from datetime import datetime
        with open(path, "a", encoding="utf-8") as f:
            f.write(f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')} {msg}\n")
    except OSError:
        pass


def default_capture_dir():
    return os.path.join(os.path.expanduser("~"), "Documents", "AoW Captures")


def _bundled_defaults_paths():
    paths = []
    if getattr(sys, "frozen", False):
        paths.append(os.path.join(os.path.dirname(sys.executable), "defaults.json"))
        meipass = getattr(sys, "_MEIPASS", None)
        if meipass:
            paths.append(os.path.join(meipass, "defaults.json"))
    paths.append(os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "defaults.json"))
    return paths


def _read_json(path):
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError):
        return {}


class Config(dict):
    def __init__(self, path=None):
        super().__init__(DEFAULTS)
        for p in _bundled_defaults_paths():
            if os.path.exists(p):
                self.update(_read_json(p))
                break
        self.path = path or os.path.join(app_dir(), "config.json")
        self.update(_read_json(self.path))
        if not self.get("capture_dir"):
            self["capture_dir"] = default_capture_dir()

    def save(self):
        tmp = self.path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(dict(self), f, indent=2)
        os.replace(tmp, self.path)

    @property
    def can_upload(self):
        return bool(self.get("upload_url") and self.get("upload_token"))

    @property
    def capture_name(self):
        """The player's name for file names and manifests: only with an invite code
        (the name comes from the upload server); "" otherwise."""
        return (self.get("tester_name") or "").strip() if self.can_upload else ""

    def apply_invite(self, code):
        info = parse_invite(code)
        self["upload_url"] = info["url"].rstrip("/")
        self["upload_token"] = info["token"]
        if info.get("tester"):
            self["tester_name"] = info["tester"]
        return info


def make_invite(url, token, tester):
    raw = json.dumps({"url": url, "token": token, "tester": tester}, separators=(",", ":")).encode()
    return INVITE_PREFIX + base64.urlsafe_b64encode(raw).decode().rstrip("=")


def parse_invite(code):
    code = "".join(code.split())
    if not code.startswith(INVITE_PREFIX):
        raise ValueError("That doesn't look like an AoW Capture invite code.")
    body = code[len(INVITE_PREFIX):]
    body += "=" * (-len(body) % 4)
    try:
        info = json.loads(base64.urlsafe_b64decode(body))
    except ValueError as e:
        raise ValueError("The invite code is damaged; copy it again.") from e
    if not info.get("url") or not info.get("token"):
        raise ValueError("The invite code is incomplete.")
    return info
