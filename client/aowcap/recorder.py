"""One capture from start to a finished, filtered zip."""

import ipaddress
import json
import os
import platform
import shutil
import tempfile
import threading
import time
import zipfile
from datetime import datetime

from . import APP_NAME, VERSION
from .config import applog
from .gameproc import FlowSet, FlowTracker, TCP
from .pcapng_filter import filter_capture
from .loopcap import LoopbackSniffer
from .pktmon import PktmonSession


VPN_WARNING = ("The game's connections were recorded but carried almost no data. This usually means a "
               "VPN or game booster carried the game's traffic in a way this tool can't see. Quit it "
               "fully (not just pause) and record again.")


def safe_name(text, fallback="player"):
    cleaned = "".join(c if c.isalnum() or c in "-_" else "_" for c in (text or "").strip())
    return cleaned[:32] or fallback


class Recorder:
    def __init__(self, cfg, watcher, log=print, session_factory=PktmonSession,
                 sniffer_factory=LoopbackSniffer):
        self.cfg = cfg
        self.watcher = watcher
        self.log = log
        self.session_factory = session_factory
        self.sniffer_factory = sniffer_factory
        self.sniffer = None
        self.session = None
        self.tracker = None
        self.flows = None
        self.markers = []
        self.started_at = None
        self.started_reason = None
        self.workdir = None
        self.lock = threading.Lock()
        self.log_lines = []
        self.warning = None
        self.servers_seen = {}
        self.skipped_private = False

    # -------------------------------------------------- state
    @property
    def recording(self):
        return self.session is not None

    def _log(self, msg):
        line = f"{datetime.now().strftime('%H:%M:%S')} {msg}"
        self.log_lines.append(line)
        applog(msg)
        self.log(msg)

    def elapsed(self):
        return time.time() - self.started_at if self.started_at else 0

    def raw_size(self):
        return self.session.raw_size() if self.session else 0

    def game_connections(self):
        return len(self.flows.remotes) if self.flows else 0

    # -------------------------------------------------- start / mark / stop
    def start(self, reason="manual"):
        with self.lock:
            if self.session:
                return
            self.log_lines = []
            self.servers_seen = {}   # "official"/"private" -> label
            self.workdir = tempfile.mkdtemp(prefix="aowcap_")
            ports = list(self.cfg.get("server_ports") or [])
            session = self.session_factory(self.workdir, ports, self.cfg.get("raw_limit_mb", 4096),
                                           log=self._log)
            session.start()
            self.session = session
            self.flows = FlowSet()
            self.tracker = FlowTracker(
                self.watcher, self.flows, self.cfg.get("ignore_ports", ()),
                on_new=lambda k: self._log(f"Game connection: {'TCP' if k[0] == TCP else 'UDP'} {k[1]}:{k[2]}"))
            self.tracker.start()
            self.sniffer = None
            if self.sniffer_factory and self.cfg.get("capture_loopback", True):
                sn = self.sniffer_factory(os.path.join(self.workdir, "loopback.pcapng"), self.flows,
                                          log=self._log)
                if sn.start_capture():
                    self.sniffer = sn
            self.markers = []
            self.started_at = time.time()
            self.started_reason = reason
            self._log(f"Recording started ({reason}).")

    def note_server(self, kind, label):
        """The app reports which server the game client is on (window title / launch args)."""
        if kind and kind not in self.servers_seen and self.recording:
            self.servers_seen[kind] = label
            self._log(f"Game server: {label} ({kind})")

    @property
    def private_session(self):
        return "private" in getattr(self, "servers_seen", {})

    def official_remote(self, remote, relay_ports=()):
        proto, ip, port = remote
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return False
        if addr.is_loopback:
            return proto == TCP and port in relay_ports
        return any(addr in ipaddress.ip_network(n) for n in self.cfg.get("official_networks") or [])

    def add_marker(self, text):
        if not self.recording or not text.strip():
            return
        self.markers.append({"t": round(self.elapsed(), 3), "unix": round(time.time(), 3),
                             "text": text.strip()[:500]})
        self._log(f"Marker: {text.strip()}")

    def abort(self):
        """Stop without saving (used on exit when the user chose not to keep it)."""
        with self.lock:
            if self.tracker:
                self.tracker.stop()
            if self.sniffer:
                self.sniffer.stop()
            if self.session:
                self.session.stop()
                self.session.discard_raw()
            self._reset()

    def _reset(self):
        if self.workdir:
            shutil.rmtree(self.workdir, ignore_errors=True)
        self.session = self.tracker = self.sniffer = None
        self.started_at = None
        self.workdir = None

    def stop(self, note="", progress=None):
        """Stops, filters and zips. Returns the zip path, or None when nothing game-related was seen."""
        with self.lock:
            if not self.session:
                return None
            session, tracker, flows, sniffer = self.session, self.tracker, self.flows, self.sniffer
            started, reason, markers = self.started_at, self.started_reason, list(self.markers)
            ended = time.time()
            self.warning = None
            self.skipped_private = False
            tracker.poll_once()
            tracker.stop()
            self._log("Stopping capture…")
            if progress:
                progress("Stopping Packet Monitor…")
            session.stop()
            if sniffer:
                sniffer.stop()
            try:
                if self.private_session:
                    self._log(f"The game was on a private server ({self.servers_seen['private']}); "
                              "nothing saved.")
                    self.skipped_private = True
                    return None
                remotes, local_ips = flows.snapshot()
                relay_ports = set(sniffer.ports) if sniffer and sniffer.packets else set()
                remotes |= {(TCP, "127.0.0.1", port) for port in relay_ports}
                dropped = {r for r in remotes if not self.official_remote(r, relay_ports)}
                if dropped:
                    self._log("Ignored non-official connections: "
                              + ", ".join(f"{ip}:{port}" for _, ip, port in sorted(dropped)))
                remotes -= dropped
                keep_ports = set(self.cfg.get("server_ports") or []) | set(self.cfg.get("known_ports") or [])
                if not remotes and not keep_ports:
                    self._log("No game connections were seen; nothing saved.")
                    return None
                if progress:
                    progress("Converting…")
                raw = session.convert()
                if progress:
                    progress("Keeping only game traffic…")
                stamp = datetime.fromtimestamp(started).strftime("%Y%m%d_%H%M%S")
                base = f"official_{stamp}_{safe_name(self.cfg.get('tester_name'))}"
                filtered = os.path.join(self.workdir, base + ".pcapng")
                inputs = [raw]
                if sniffer and sniffer.packets:
                    inputs.append(sniffer.path)
                stats = filter_capture(inputs, filtered, remotes, local_ips, keep_ports,
                                       anonymize=self.cfg.get("anonymize_local", True),
                                       dedupe=(not session.nics_only) or len(inputs) > 1,
                                       app=f"{APP_NAME} {VERSION}",
                                       allowed_nets=self.cfg.get("official_networks") or None)
                self._log(f"Kept {stats['packets_out']} of {stats['packets_in']} packets"
                          + (f" ({stats['duplicates']} duplicates dropped)" if stats["duplicates"] else ""))
                if stats["packets_out"] == 0:
                    if remotes:  # the game connected, yet nothing was captured: tunnelled
                        self.warning = VPN_WARNING
                        self._log("The game connected but no packets were captured. " + VPN_WARNING)
                    else:
                        self._log("No game traffic was recorded; nothing saved.")
                    return None
                if stats["tcp_payload_bytes"] < 2048:
                    self.warning = VPN_WARNING
                    self._log("Warning: game connections carried almost no data. " + VPN_WARNING)
                manifest = {
                    "tool": APP_NAME, "tool_version": VERSION,
                    "tester": self.cfg.get("tester_name", ""),
                    "note": (note or "").strip()[:4000],
                    "started": datetime.fromtimestamp(started).astimezone().isoformat(timespec="seconds"),
                    "ended": datetime.fromtimestamp(ended).astimezone().isoformat(timespec="seconds"),
                    "started_unix": round(started, 3), "duration_s": round(ended - started, 1),
                    "start_reason": reason,
                    "markers": markers,
                    "game": self.watcher.exe_version(),
                    "server_endpoints": [e for e in flows.to_manifest()
                                         if (TCP if e["proto"] == "tcp" else 17, e["ip"], e["port"]) in remotes]
                                        + [{"proto": "tcp", "ip": "127.0.0.1", "port": p, "first_seen": 0}
                                           for p in sorted(relay_ports)
                                           if not any(e["ip"] == "127.0.0.1" and e["port"] == p
                                                      for e in flows.to_manifest())],
                    "server_ports_filter": sorted(keep_ports),
                    "game_server": self.servers_seen.get("official"),
                    "official_networks": self.cfg.get("official_networks"),
                    "loopback": sniffer.summary() if sniffer else None,
                    "packets": stats["packets_out"], "packets_seen": stats["packets_in"],
                    "tcp_payload_bytes": stats["tcp_payload_bytes"],
                    "warning": self.warning,
                    "duplicates_dropped": stats["duplicates"],
                    "anonymized": bool(self.cfg.get("anonymize_local", True)),
                    "os": f"{platform.system()} {platform.release()} ({platform.version()})",
                }
                out_dir = self.cfg["capture_dir"]
                os.makedirs(out_dir, exist_ok=True)
                zip_path = os.path.join(out_dir, base + ".zip")
                n = 2
                while os.path.exists(zip_path):
                    zip_path = os.path.join(out_dir, f"{base}_{n}.zip")
                    n += 1
                if progress:
                    progress("Saving…")
                tmp_zip = zip_path + ".part"
                with zipfile.ZipFile(tmp_zip, "w", zipfile.ZIP_DEFLATED, compresslevel=6) as z:
                    z.write(filtered, base + ".pcapng")
                    z.writestr("manifest.json", json.dumps(manifest, indent=2, ensure_ascii=False))
                    z.writestr("capture-log.txt", "\n".join(self.log_lines) + "\n")
                os.replace(tmp_zip, zip_path)
                if self.cfg.get("keep_raw"):
                    shutil.copy(raw, zip_path[:-4] + ".RAW-ALL-TRAFFIC.pcapng")
                self._log(f"Saved {os.path.basename(zip_path)}")
                return zip_path
            finally:
                session.discard_raw()
                self._reset()
