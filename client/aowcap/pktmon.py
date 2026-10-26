"""Thin wrapper over Windows' built-in Packet Monitor (pktmon.exe, Windows 10 2004+ / 11).

No driver install is needed (unlike Npcap), but it must run as administrator.
"""

import os
import shutil
import subprocess
import time

CREATE_NO_WINDOW = 0x08000000


class PktmonError(RuntimeError):
    pass


def pktmon_path():
    found = shutil.which("pktmon")
    if found:
        return found
    root = os.environ.get("SystemRoot", r"C:\Windows")
    for sub in ("System32", "Sysnative"):
        p = os.path.join(root, sub, "pktmon.exe")
        if os.path.exists(p):
            return p
    return None


def _run(args, check=True, timeout=300):
    exe = pktmon_path()
    if not exe:
        raise PktmonError("pktmon.exe was not found. Windows 10 version 2004 or newer is required.")
    kwargs = {}
    if os.name == "nt":
        kwargs["creationflags"] = CREATE_NO_WINDOW
    proc = subprocess.run([exe, *args], capture_output=True, text=True, errors="replace",
                          timeout=timeout, **kwargs)
    out = (proc.stdout or "") + (proc.stderr or "")
    if check and proc.returncode != 0:
        raise PktmonError(f"pktmon {' '.join(args)} failed ({proc.returncode}): {out.strip()}")
    return out


class PktmonSession:
    """One recording: start -> [rotate ...] -> stop -> convert each piece to pcapng.

    rotate() starts a new raw file while recording continues, so a finished piece can be
    saved and uploaded. It first asks ETW to switch pktmon's output file in place
    (`logman update trace <session> -o <file> -ets`, no gap); if that isn't possible it
    restarts pktmon (a gap of about a second, logged).
    """

    def __init__(self, workdir, ports=(), raw_limit_mb=4096, log=print, all_components=False, nets=()):
        """all_components: record at every layer of the network stack, not just the
        network cards. Needed with ExitLag's NDIS mode (and similar drivers), which
        encrypt the game's packets below Windows' TCP/IP: the plain packets only exist
        above that driver. Duplicates across layers are removed at save.

        nets: address ranges (CIDR) to record, e.g. the official servers'. Packet Monitor
        then only writes packets to or from them, so the raw file stays small; everything
        else would be dropped at save anyway. Ignored if this Windows can't filter so."""
        self.workdir = workdir
        self.all_components = all_components
        self.ports = [int(p) for p in ports]
        self.nets = [str(n) for n in nets or ()]
        self.raw_limit_mb = int(raw_limit_mb)
        self.log = log
        self.seq = 0
        self.etl = os.path.join(workdir, "raw0.etl")
        self.nics_only = False
        self.running = False
        self.last_gap = None      # seconds lost by the last rotate (None = gapless)
        self._etw_name = None

    def start(self):
        os.makedirs(self.workdir, exist_ok=True)
        cleanup()  # a crashed earlier run may have left a session or filters behind
        for i, port in enumerate(self.ports):
            _run(["filter", "add", f"AOWCAP{i}", "-p", str(port)])
        if self.nets:
            try:
                for i, net in enumerate(self.nets):
                    _run(["filter", "add", f"AOWCAPNET{i}", "-i", net])
                self.log(f"Capture filter: {', '.join(self.nets)}"
                         + (f" and ports {', '.join(map(str, self.ports))}" if self.ports else ""))
                return self._start_capture(self.etl)
            except PktmonError as e:
                self.log(f"Packet Monitor can't filter by address here ({e}); recording all traffic.")
                _run(["filter", "remove"], check=False)
                for i, port in enumerate(self.ports):
                    _run(["filter", "add", f"AOWCAP{i}", "-p", str(port)])
        if self.ports:
            self.log(f"Capture filter: ports {', '.join(map(str, self.ports))}")
        else:
            self.log("No capture filter: recording all traffic, game traffic is filtered out at save.")
        self._start_capture(self.etl)

    def _start_capture(self, etl):
        base = ["start", "--capture", "--pkt-size", "0", "--file-name", etl,
                "--file-size", str(self.raw_limit_mb)]
        if self.all_components:
            _run(base)
            self.nics_only = False
            return self._started()
        try:
            _run(base + ["--comp", "nics"])
            self.nics_only = True
        except PktmonError as e:
            self.log(f"'--comp nics' not supported, recording every component ({e})")
            _run(base)
            self.nics_only = False
        self._started()

    def _started(self):
        self.running = True

    def stop(self):
        if self.running:
            _run(["stop"], check=False)
            self.running = False
        _run(["filter", "remove"], check=False)

    def raw_size(self):
        try:
            return os.path.getsize(self.etl)
        except OSError:
            return 0

    # ---------------------------------------------------------------- rotation
    def _etw_session(self):
        if self._etw_name:
            return self._etw_name
        try:
            out = subprocess.run(["logman", "query", "-ets"], capture_output=True, text=True,
                                 errors="replace", timeout=30,
                                 creationflags=CREATE_NO_WINDOW if os.name == "nt" else 0).stdout
        except (OSError, subprocess.TimeoutExpired):
            return None
        for line in out.splitlines():
            name = line.strip().split("  ")[0].strip()
            if name.lower().startswith("pktmon"):
                self._etw_name = name
                return name
        return None

    def rotate(self):
        """Switches recording to a new raw file; returns the finished file's path."""
        old = self.etl
        self.seq += 1
        new = os.path.join(self.workdir, f"raw{self.seq}.etl")
        name = self._etw_session()
        if name:
            try:
                r = subprocess.run(["logman", "update", "trace", name, "-o", new, "-ets"],
                                   capture_output=True, text=True, errors="replace", timeout=30,
                                   creationflags=CREATE_NO_WINDOW if os.name == "nt" else 0)
                if r.returncode == 0:
                    self.etl = new
                    self.last_gap = None
                    return old
                self.log(f"logman couldn't switch files ({(r.stdout + r.stderr).strip()[:200]}); "
                         "restarting Packet Monitor instead")
            except (OSError, subprocess.TimeoutExpired) as e:
                self.log(f"logman failed ({e}); restarting Packet Monitor instead")
        t0 = time.time()
        _run(["stop"], check=False)
        self.running = False
        self._start_capture(new)          # filters stay in place across stop/start
        self.etl = new
        self.last_gap = round(time.time() - t0, 2)
        self.log(f"Switched files by restarting Packet Monitor (gap ~{self.last_gap} s)")
        return old

    # ---------------------------------------------------------------- conversion
    def convert(self, etl=None):
        etl = etl or self.etl
        out = os.path.splitext(etl)[0] + ".pcapng"
        if not os.path.exists(etl):
            raise PktmonError("pktmon produced no capture file.")
        last = None
        for attempt in range(4):  # a just-switched file may still be closing
            try:
                try:
                    _run(["etl2pcap", etl, "--out", out])
                except PktmonError:
                    _run(["pcapng", etl, "-o", out])
                if os.path.exists(out):
                    return out
            except PktmonError as e:
                last = e
            time.sleep(1 + attempt)
        raise PktmonError(f"Converting the capture to pcapng failed. {last or ''}")

    def discard(self, etl):
        for p in (etl, os.path.splitext(etl)[0] + ".pcapng"):
            try:
                os.remove(p)
            except OSError:
                pass

    def discard_raw(self):
        for name in os.listdir(self.workdir) if os.path.isdir(self.workdir) else []:
            if name.startswith("raw") and name.endswith((".etl", ".pcapng")):
                try:
                    os.remove(os.path.join(self.workdir, name))
                except OSError:
                    pass


def cleanup():
    """Stop any running pktmon session and clear filters. Safe to call any time."""
    try:
        _run(["stop"], check=False, timeout=120)
        _run(["filter", "remove"], check=False, timeout=60)
    except (PktmonError, OSError, subprocess.TimeoutExpired):
        pass
