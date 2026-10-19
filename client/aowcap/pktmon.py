"""Thin wrapper over Windows' built-in Packet Monitor (pktmon.exe, Windows 10 2004+ / 11).

No driver install is needed (unlike Npcap), but it must run as administrator.
"""

import os
import shutil
import subprocess

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
    """One recording: start -> stop -> convert to pcapng."""

    def __init__(self, workdir, ports=(), raw_limit_mb=4096, log=print):
        self.workdir = workdir
        self.ports = [int(p) for p in ports]
        self.raw_limit_mb = int(raw_limit_mb)
        self.log = log
        self.etl = os.path.join(workdir, "raw.etl")
        self.pcapng = os.path.join(workdir, "raw.pcapng")
        self.nics_only = False
        self.running = False

    def start(self):
        os.makedirs(self.workdir, exist_ok=True)
        cleanup()  # a crashed earlier run may have left a session or filters behind
        for i, port in enumerate(self.ports):
            _run(["filter", "add", f"AOWCAP{i}", "-p", str(port)])
        if self.ports:
            self.log(f"Capture filter: ports {', '.join(map(str, self.ports))}")
        else:
            self.log("No server ports configured: recording all traffic, game traffic is filtered out at save.")
        base = ["start", "--capture", "--pkt-size", "0", "--file-name", self.etl,
                "--file-size", str(self.raw_limit_mb)]
        try:
            _run(base + ["--comp", "nics"])
            self.nics_only = True
        except PktmonError as e:
            self.log(f"'--comp nics' not supported, recording every component ({e})")
            _run(base)
            self.nics_only = False
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

    def convert(self):
        if not os.path.exists(self.etl):
            raise PktmonError("pktmon produced no capture file.")
        try:
            _run(["etl2pcap", self.etl, "--out", self.pcapng])
        except PktmonError:
            _run(["pcapng", self.etl, "-o", self.pcapng])
        if not os.path.exists(self.pcapng):
            raise PktmonError("Converting the capture to pcapng failed.")
        return self.pcapng

    def discard_raw(self):
        for p in (self.etl, self.pcapng):
            try:
                os.remove(p)
            except OSError:
                pass


def cleanup():
    """Stop any running pktmon session and clear filters. Safe to call any time."""
    try:
        _run(["stop"], check=False, timeout=120)
        _run(["filter", "remove"], check=False, timeout=60)
    except (PktmonError, OSError, subprocess.TimeoutExpired):
        pass
