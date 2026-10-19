"""Finds the running game client and records which network connections belong to it."""

import ipaddress
import os
import threading
import time

try:
    import psutil
except ImportError:  # the tests can run without it
    psutil = None

TCP, UDP = 6, 17


def is_loopback(ip):
    try:
        return ipaddress.ip_address(norm_ip(ip)).is_loopback
    except ValueError:
        return False


def norm_ip(ip):
    """'::ffff:1.2.3.4' -> '1.2.3.4'; IPv6 in canonical form."""
    try:
        addr = ipaddress.ip_address(ip.split("%")[0])
    except ValueError:
        return ip
    if addr.version == 6 and addr.ipv4_mapped:
        return str(addr.ipv4_mapped)
    return str(addr)


class FlowSet:
    """The game's connections seen during a capture."""

    def __init__(self):
        self.remotes = set()       # (proto, remote_ip, remote_port)
        self.local_ips = set()
        self.first_seen = {}       # (proto, rip, rport) -> unix time
        self.lock = threading.Lock()

    def add(self, proto, lip, lport, rip, rport):
        key = (proto, norm_ip(rip), int(rport))
        with self.lock:
            if key not in self.remotes:
                self.remotes.add(key)
                self.first_seen[key] = time.time()
            if lip:
                self.local_ips.add(norm_ip(lip))
            return key

    def snapshot(self):
        with self.lock:
            return set(self.remotes), set(self.local_ips)

    def to_manifest(self):
        with self.lock:
            return [{"proto": "tcp" if p == TCP else "udp", "ip": ip, "port": port,
                     "first_seen": round(self.first_seen.get((p, ip, port), 0), 3)}
                    for (p, ip, port) in sorted(self.remotes)]


def _connections(proc):
    fn = getattr(proc, "net_connections", None) or proc.connections
    return fn(kind="inet")


class GameWatcher:
    """Polls for game processes (by exe name or by a loaded game DLL)."""

    def __init__(self, process_names=(), modules=("fxnet2.dll",)):
        self.process_names = {n.lower() for n in process_names}
        self.modules = {m.lower() for m in modules}
        self._checked = {}   # pid -> (create_time, is_game)
        self.pids = set()
        self.exe_names = {}  # pid -> exe name
        self.exe_paths = {}

    def _is_game(self, proc):
        name = (proc.info.get("name") or "").lower()
        if name in self.process_names:
            return True
        if not self.modules:
            return False
        try:
            for m in proc.memory_maps(grouped=True):
                if os.path.basename(m.path).lower() in self.modules:
                    return True
            return False
        except (psutil.AccessDenied, psutil.NoSuchProcess, OSError, NotImplementedError):
            pass
        # Fallback when modules can't be listed: a game DLL next to the exe.
        exe = proc.info.get("exe") or ""
        if exe:
            folder = os.path.dirname(exe)
            return any(os.path.exists(os.path.join(folder, m)) for m in self.modules)
        return False

    def refresh(self):
        if psutil is None:
            return self.pids
        found, live = set(), set()
        for proc in psutil.process_iter(["pid", "name", "exe", "create_time"]):
            pid, ctime = proc.info["pid"], proc.info.get("create_time")
            live.add(pid)
            cached = self._checked.get(pid)
            if cached and cached[0] == ctime:
                is_game = cached[1]
            else:
                try:
                    is_game = self._is_game(proc)
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    is_game = False
                self._checked[pid] = (ctime, is_game)
            if is_game:
                found.add(pid)
                self.exe_names[pid] = proc.info.get("name") or "?"
                self.exe_paths[pid] = proc.info.get("exe") or ""
        for pid in list(self._checked):
            if pid not in live:
                self._checked.pop(pid, None)
        self.pids = found
        return found

    def describe(self):
        if not self.pids:
            return None
        return ", ".join(f"{self.exe_names.get(p, '?')} (pid {p})" for p in sorted(self.pids))

    def server_identity(self, official_names=("BlueDragon",), private_names=("AOW_EMU",)):
        """("official"|"private"|None, label) for the running game client(s)."""
        verdicts = []
        for pid in sorted(self.pids):
            texts = window_titles(pid) + [a for a in process_cmdline(pid)[1:] if "-" in a]
            verdicts.append(classify_server(texts, official_names, private_names))
        for kind in ("private", "official"):  # any private client wins
            for v in verdicts:
                if v[0] == kind:
                    return v
        return None, None

    def exe_version(self):
        """File version of the game exe, for the manifest (Windows only)."""
        for pid in self.pids:
            path = self.exe_paths.get(pid)
            if path:
                v = file_version(path)
                if v:
                    return {"exe": os.path.basename(path), "version": v}
        return None


class FlowTracker(threading.Thread):
    """Every 250 ms, records the game processes' connections into a FlowSet."""

    def __init__(self, watcher, flows, ignore_ports=(), on_new=None, interval=0.25):
        super().__init__(daemon=True, name="flow-tracker")
        self.watcher = watcher
        self.flows = flows
        self.ignore_ports = {int(p) for p in ignore_ports}
        self.on_new = on_new
        self.interval = interval
        self._stop = threading.Event()

    def stop(self):
        self._stop.set()

    def poll_once(self):
        if psutil is None:
            return
        per_pid = {}
        for pid in list(self.watcher.pids):
            try:
                per_pid[pid] = _connections(psutil.Process(pid))
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        # The game's own local ports: a loopback connection to one of them is the game
        # talking to itself (a socket pair), not a server or a booster's local relay.
        own_ports = {c.laddr.port for conns in per_pid.values() for c in conns if c.laddr}
        for pid, conns in per_pid.items():
            for c in conns:
                if not c.raddr:
                    continue
                rport = c.raddr.port
                if is_loopback(c.raddr.ip) and rport in own_ports:
                    continue
                if rport in self.ignore_ports:
                    continue
                proto = TCP if int(c.type) == 1 else UDP  # socket.SOCK_STREAM == 1
                before = len(self.flows.remotes)
                key = self.flows.add(proto, c.laddr.ip if c.laddr else None,
                                     c.laddr.port if c.laddr else 0, c.raddr.ip, rport)
                if self.on_new and len(self.flows.remotes) > before:
                    self.on_new(key)

    def run(self):
        while not self._stop.is_set():
            try:
                self.poll_once()
            except Exception:  # never let a psutil hiccup kill the capture
                pass
            self._stop.wait(self.interval)


TUNNEL_APPS = {"exitlag": "ExitLag", "noping": "NoPing", "wtfast": "WTFast", "gearup": "GearUP",
               "mudfish": "Mudfish", "haste": "Haste", "openvpn": "OpenVPN", "nordvpn": "NordVPN",
               "expressvpn": "ExpressVPN", "protonvpn": "ProtonVPN", "surfshark": "Surfshark",
               "lagofast": "LagoFast", "pingzapper": "PingZapper"}


def _tunnel_label(name):
    name = (name or "").lower()
    for key, label in TUNNEL_APPS.items():
        if name.startswith(key):
            return label
    return None


def tunnel_apps_running():
    """Game boosters / VPNs that tunnel game traffic."""
    return sorted(set(tunnel_processes().values()))


def tunnel_listen_ports():
    """{port: app label} for TCP ports booster/VPN apps listen on locally (e.g. ExitLag's relay)."""
    if psutil is None:
        return {}
    pids = tunnel_processes()
    if not pids:
        return {}
    ports = {}
    try:
        conns = psutil.net_connections(kind="tcp")
    except (psutil.AccessDenied, OSError):
        return {}
    for c in conns:
        # A relay may listen on 127.0.0.1 or on all interfaces (0.0.0.0 / ::); either way the
        # game reaches it through 127.0.0.1.
        if (c.pid in pids and c.status == psutil.CONN_LISTEN and c.laddr
                and (is_loopback(c.laddr.ip) or c.laddr.ip in ("0.0.0.0", "::"))):
            ports[c.laddr.port] = pids[c.pid]
    return ports


def tunnel_processes():
    """{pid: app label} for booster/VPN processes, matched by exe name or install folder
    (ExitLag's helper processes don't all start with "exitlag", but live in its folder)."""
    if psutil is None:
        return {}
    pids = {}
    for proc in psutil.process_iter(["pid", "name", "exe"]):
        lbl = _tunnel_label(proc.info.get("name"))
        if not lbl:
            exe = (proc.info.get("exe") or "").lower().replace("/", "\\")
            for key, label in TUNNEL_APPS.items():
                if f"\\{key}\\" in exe:
                    lbl = label
                    break
        if lbl:
            pids[proc.info["pid"]] = lbl
    return pids


# ------------------------------------------------------------------ which server is the game on?
# The NA client's window title is "Age of Wushu   {Area}-{Server}", taken from fxgame's
# argv[4] (official: "Launch-BlueDragon"; our launcher's private server: e.g.
# "AOW_EMU-AOW_EMU"). Used to keep private-server / emulator sessions out of captures.

def window_titles(pid):
    """Titles of the visible top-level windows owned by pid (Windows only)."""
    if os.name != "nt":
        return []
    import ctypes
    from ctypes import wintypes
    user32 = ctypes.windll.user32
    titles = []
    proto = ctypes.WINFUNCTYPE(wintypes.BOOL, wintypes.HWND, wintypes.LPARAM)

    def cb(hwnd, _):
        owner = wintypes.DWORD()
        user32.GetWindowThreadProcessId(hwnd, ctypes.byref(owner))
        if owner.value == pid and user32.IsWindowVisible(hwnd):
            n = user32.GetWindowTextLengthW(hwnd)
            if n:
                buf = ctypes.create_unicode_buffer(n + 1)
                user32.GetWindowTextW(hwnd, buf, n + 1)
                titles.append(buf.value)
        return True
    try:
        user32.EnumWindows(proto(cb), 0)
    except Exception:
        pass
    return titles


def process_cmdline(pid):
    if psutil is None:
        return []
    try:
        return psutil.Process(pid).cmdline()
    except (psutil.NoSuchProcess, psutil.AccessDenied, OSError):
        return []


def classify_server(texts, official_names=("BlueDragon",), private_names=("AOW_EMU",)):
    """texts: window titles + command-line args of the game.

    Returns ("official", label), ("private", label) or (None, None) when unknown.
    A "{Area}-{Server}" label that names no official server counts as private.
    """
    official = [n.lower() for n in official_names]
    private = [n.lower() for n in private_names]
    label = None
    for t in texts:
        low = (t or "").lower()
        if any(n in low for n in private):
            return "private", t.strip()
        if any(n in low for n in official):
            return "official", t.strip()
        m = None
        if low.startswith("age of wushu"):
            rest = t[len("age of wushu"):].strip()
            m = rest if "-" in rest else None
        if m:
            label = m
    if label:
        return "private", label
    return None, None


def file_version(path):
    if os.name != "nt":
        return None
    try:
        import ctypes
        from ctypes import wintypes
        ver = ctypes.windll.version
        size = ver.GetFileVersionInfoSizeW(path, None)
        if not size:
            return None
        buf = ctypes.create_string_buffer(size)
        if not ver.GetFileVersionInfoW(path, 0, size, buf):
            return None
        ptr = ctypes.c_void_p()
        length = wintypes.UINT()
        if not ver.VerQueryValueW(buf, "\\", ctypes.byref(ptr), ctypes.byref(length)):
            return None
        info = ctypes.cast(ptr, ctypes.POINTER(ctypes.c_uint32 * 13)).contents
        ms, ls = info[2], info[3]
        return f"{ms >> 16}.{ms & 0xFFFF}.{ls >> 16}.{ls & 0xFFFF}"
    except Exception:
        return None
