"""Diagnostics report for "it isn't capturing" problems.

Run with the game running (logged in) and ExitLag/VPN as the player normally uses it:
    AoWCapture.exe --diagnose        or the "Diagnostics…" button in the window

Writes AoWCapture-diagnostics.txt on the Desktop and opens it. Nothing is uploaded.
Contains no passwords or invite tokens; the game's launch arguments are reduced to the
server name.
"""

import os
import platform
import socket
import struct
import time
from datetime import datetime

from . import APP_NAME, VERSION
from .config import Config, app_dir
from .gameproc import (GameWatcher, classify_server, is_loopback, process_cmdline, psutil,
                       tunnel_listen_ports, tunnel_processes, window_titles)
from .pktmon import pktmon_path


def _admin():
    if os.name != "nt":
        return os.geteuid() == 0 if hasattr(os, "geteuid") else None
    try:
        import ctypes
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return None


def _listeners():
    """{port: (pid, name)} for every listening TCP socket."""
    out = {}
    if psutil is None:
        return out
    try:
        names = {p.pid: p.info.get("name") for p in psutil.process_iter(["name"])}
        for c in psutil.net_connections(kind="tcp"):
            if c.status == psutil.CONN_LISTEN and c.laddr:
                out.setdefault(c.laddr.port, (c.pid, names.get(c.pid, "?"), c.laddr.ip))
    except Exception as e:
        out["error"] = str(e)
    return out


def _loopback_probe(ports, seconds=4.0):
    """Open the loopback raw socket the recorder uses and count what it sees."""
    if os.name != "nt":
        return "not Windows"
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
        s.bind(("127.0.0.1", 0))
        s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        s.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
        s.settimeout(0.25)
    except OSError as e:
        return f"FAILED to open: {e}"
    total = tcp = relay = relay_bytes = 0
    end = time.time() + seconds
    try:
        while time.time() < end:
            try:
                pkt = s.recv(65535)
            except socket.timeout:
                continue
            total += 1
            if len(pkt) >= 24 and pkt[0] >> 4 == 4 and pkt[9] == 6:
                tcp += 1
                ihl = (pkt[0] & 15) * 4
                sp, dp = struct.unpack("!HH", pkt[ihl:ihl + 4])
                if sp in ports or dp in ports:
                    relay += 1
                    relay_bytes += len(pkt)
    finally:
        try:
            s.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
            s.close()
        except OSError:
            pass
    return (f"{total} loopback packets in {seconds:.0f} s ({tcp} TCP); "
            f"{relay} on relay ports ({relay_bytes} bytes)")


def report():
    cfg = Config()
    L = []
    add = L.append
    add(f"{APP_NAME} {VERSION} diagnostics, {datetime.now().astimezone().isoformat(timespec='seconds')}")
    add(f"OS: {platform.platform()}  admin: {_admin()}  pktmon: {pktmon_path()}")
    add(f"Config: capture_loopback={cfg.get('capture_loopback', True)} "
        f"auto_record={cfg.get('auto_record')} official_networks={cfg.get('official_networks')} "
        f"official_servers={cfg.get('official_servers')} private_servers={cfg.get('private_servers')} "
        f"upload={'yes' if cfg.can_upload else 'no invite code'}")
    add("")

    tun = tunnel_processes()
    add("Boosters / VPNs running:")
    if not tun:
        add("  none found")
    for pid, label in sorted(tun.items()):
        exe = ""
        try:
            exe = psutil.Process(pid).exe()
        except Exception:
            pass
        add(f"  {label}: pid {pid} {exe}")
    relays = tunnel_listen_ports()
    add(f"Relay ports the recorder would use: {sorted(relays) or 'NONE'}")
    add("")

    listeners = _listeners()
    w = GameWatcher(cfg.get("process_names", ()), cfg.get("game_modules", ()))
    pids = w.refresh()
    add(f"Game processes: {w.describe() or 'NONE FOUND'}")
    for pid in sorted(pids):
        titles = window_titles(pid)
        args = [a for a in process_cmdline(pid)[1:] if "-" in a and len(a) < 80 and "=" not in a]
        add(f"  pid {pid}: titles={titles} server-like args={args}")
        add(f"    classified as: {classify_server(titles + args, cfg.get('official_servers') or (), cfg.get('private_servers') or ())}")
        try:
            conns = psutil.Process(pid).net_connections(kind="inet")
        except Exception as e:
            add(f"    connections: error {e}")
            continue
        for c in conns:
            if not c.raddr:
                continue
            note = ""
            if is_loopback(c.raddr.ip):
                owner = listeners.get(c.raddr.port)
                note = f"  <- local listener: {owner[1]} (pid {owner[0]}, on {owner[2]})" if owner else \
                    "  <- local listener: unknown"
                if c.raddr.port in relays:
                    note += "  [relay: recorded]"
            add(f"    {'TCP' if int(c.type) == 1 else 'UDP'} {c.laddr.ip}:{c.laddr.port} -> "
                f"{c.raddr.ip}:{c.raddr.port} {c.status}{note}")
    add(f"  overall: {w.server_identity(cfg.get('official_servers') or (), cfg.get('private_servers') or ())}")
    add("")
    add("Loopback capture test: " + _loopback_probe(set(relays)))
    add("")

    log = os.path.join(app_dir(), "aowcap.log")
    add("Last log lines:")
    try:
        with open(log, encoding="utf-8", errors="replace") as f:
            L.extend("  " + line.rstrip() for line in f.readlines()[-60:])
    except OSError:
        add("  (no log yet)")
    return "\n".join(L) + "\n"


def write_and_open():
    text = report()
    desk = os.path.join(os.path.expanduser("~"), "Desktop")
    path = os.path.join(desk if os.path.isdir(desk) else app_dir(), "AoWCapture-diagnostics.txt")
    with open(path, "w", encoding="utf-8") as f:
        f.write(text)
    if os.name == "nt":
        try:
            os.startfile(path)
        except OSError:
            pass
    return path
