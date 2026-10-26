import ipaddress
import json
import os
import struct
import sys
import threading
import zipfile

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "client"))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from aowcap import pcapng_filter as pf  # noqa: E402
from aowcap.config import Config, make_invite, parse_invite  # noqa: E402
from aowcap.gameproc import FlowSet  # noqa: E402
from aowcap.recorder import Recorder  # noqa: E402
from aowcap.uploader import Client, read_state  # noqa: E402
from fake_receiver import FakeReceiver  # noqa: E402

LOCAL = "192.168.1.50"
SERVER = "148.153.10.20"
OTHER = "142.250.1.1"


def csum(data):
    if len(data) % 2:
        data += b"\0"
    s = sum(struct.unpack("!%dH" % (len(data) // 2), data))
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return (~s) & 0xFFFF


def tcp_packet(src, dst, sport, dport, payload=b"", ttl=64):
    s, d = ipaddress.ip_address(src).packed, ipaddress.ip_address(dst).packed
    tcp = struct.pack("!HHIIBBHHH", sport, dport, 1, 0, 5 << 4, 0x18, 65535, 0, 0) + payload
    pseudo = s + d + struct.pack("!BBH", 0, 6, len(tcp))
    tcp = tcp[:16] + struct.pack("!H", csum(pseudo + tcp)) + tcp[18:]
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(tcp), 1, 0, ttl, 6, 0, s, d)
    ip = ip[:10] + struct.pack("!H", csum(ip)) + ip[12:]
    eth = bytes.fromhex("aabbccddeeff") + bytes.fromhex("112233445566") + b"\x08\x00"
    return eth + ip + tcp


def write_pcapng(path, packets):
    """packets: list of (ts_us, bytes). Includes a hostname option and an NRB to make sure they're dropped."""
    with open(path, "wb") as f:
        body = struct.pack("<IHHq", pf.BOM, 1, 0, -1) + pf._opt(2, b"PLAYER-PC") + pf._opt(3, b"Windows 11")
        body += struct.pack("<HH", 0, 0)
        f.write(pf._block(pf.SHB, body))
        idb = struct.pack("<HHI", 1, 0, 0) + pf._opt(2, b"\\Device\\NPF_{SECRET}") + struct.pack("<HH", 0, 0)
        f.write(pf._block(pf.IDB, idb))
        f.write(pf._block(4, b"\x00" * 8))  # name resolution block
        for ts, data in packets:
            f.write(pf.epb_block(0, ts, data, len(data)))


def read_packets(path):
    out = []
    with open(path, "rb") as f:
        for endian, btype, body in pf.read_blocks(f):
            if btype == pf.EPB:
                cap = struct.unpack("<I", body[12:16])[0]
                out.append(body[20:20 + cap])
            else:
                out.append((btype, body))
    return out


def sample(tmp_path, dup=False):
    pkts = [
        (1_000_000, tcp_packet(LOCAL, SERVER, 50001, 2003, b"\x01" * 3000)),
        (1_000_100, tcp_packet(SERVER, LOCAL, 2003, 50001, b"\x02" * 100)),
        (1_000_200, tcp_packet(LOCAL, OTHER, 50002, 443, b"secret web")),
        (1_000_300, tcp_packet(OTHER, LOCAL, 443, 50002, b"secret reply")),
    ]
    if dup:
        pkts.append((1_000_101, pkts[1][1]))
    raw = tmp_path / "raw.pcapng"
    write_pcapng(raw, pkts)
    return raw


def test_filter_keeps_game_only_and_strips_identity(tmp_path):
    raw = sample(tmp_path)
    out = tmp_path / "out.pcapng"
    st = pf.filter_capture(str(raw), str(out), {(6, SERVER, 2003)}, {LOCAL})
    assert st["packets_in"] == 4 and st["packets_out"] == 2
    assert st["tcp_payload_bytes"] == 3100
    blob = out.read_bytes()
    for leak in (b"PLAYER-PC", b"Windows 11", b"SECRET", b"secret", bytes.fromhex("112233445566"),
                 ipaddress.ip_address(LOCAL).packed):
        assert leak not in blob
    pkts = [p for p in read_packets(out) if isinstance(p, bytes)]
    for p in pkts:
        ip = p[14:34]
        assert csum(ip) == 0  # IPv4 header checksum still valid
        tcp = p[34:]
        pseudo = ip[12:16] + ip[16:20] + struct.pack("!BBH", 0, 6, len(tcp))
        assert csum(pseudo + tcp) == 0  # TCP checksum still valid
        assert SERVER.encode() not in p and ipaddress.ip_address(SERVER).packed in p
    assert pkts[0][26:30] == ipaddress.ip_address("10.0.0.2").packed


def test_filter_by_port_and_dedupe(tmp_path):
    raw = sample(tmp_path, dup=True)
    out = tmp_path / "out.pcapng"
    st = pf.filter_capture(str(raw), str(out), set(), set(), keep_ports={2003}, dedupe=True)
    assert st["packets_out"] == 2 and st["duplicates"] == 1


def test_no_anonymize_keeps_bytes(tmp_path):
    raw = sample(tmp_path)
    out = tmp_path / "out.pcapng"
    pf.filter_capture(str(raw), str(out), {(6, SERVER, 2003)}, {LOCAL}, anonymize=False)
    pkts = [p for p in read_packets(out) if isinstance(p, bytes)]
    assert pkts[0] == tcp_packet(LOCAL, SERVER, 50001, 2003, b"\x01" * 3000)


def test_invite_roundtrip():
    code = make_invite("https://x.example", "tok", "Bob")
    assert parse_invite(code) == {"url": "https://x.example", "token": "tok", "tester": "Bob"}
    with pytest.raises(ValueError):
        parse_invite("hello")


class FakeSession:
    def __init__(self, workdir, ports, limit, log=print, all_components=False):
        self.workdir, self.nics_only = workdir, True
        self.src = None
        self.etl = "raw0.etl"
        self.last_gap = None
        self.rotations = 0

    def rotate(self):
        self.rotations += 1
        old, self.etl = self.etl, f"raw{self.rotations}.etl"
        return old

    def discard(self, etl):
        pass

    def start(self):
        pass

    def stop(self):
        pass

    def raw_size(self):
        return 0

    def convert(self, etl=None):
        return self.src

    def discard_raw(self):
        pass


class FakeWatcher:
    pids = set()

    def exe_version(self):
        return {"exe": "fxgame.exe", "version": "1.0.0.401"}


@pytest.mark.parametrize("invite", [True, False])
def test_recorder_end_to_end(tmp_path, monkeypatch, invite):
    raw = sample(tmp_path)
    cfg = Config(path=str(tmp_path / "cfg.json"))
    cfg.update(capture_dir=str(tmp_path / "caps"), tester_name="Bob Smith", known_ports=[])
    if invite:  # the name only goes on captures that have somewhere to go
        cfg.update(upload_url="https://example.invalid", upload_token="t")
    sessions = []

    def factory(*a, **k):
        s = FakeSession(*a, **k)
        s.src = str(raw)
        sessions.append(s)
        return s
    rec = Recorder(cfg, FakeWatcher(), log=lambda m: None, session_factory=factory)
    rec.start("test")
    rec.flows.note_client(4321, "fxgame.exe", 1.0, ["Age of Wushu   Launch-BlueDragon"])
    rec.flows.add(6, LOCAL, 50001, "::ffff:" + SERVER, 2003, pid=4321)
    rec.flows.add(6, LOCAL, 50009, OTHER, 443, pid=4321)          # not game traffic: not listed
    rec.add_marker("opened cultivation")
    path = rec.stop("note here")
    base = os.path.basename(path)
    assert base.startswith("official_")
    with zipfile.ZipFile(path) as z:
        names = z.namelist()
        man = json.loads(z.read("manifest.json"))
    if invite:
        assert base.endswith("_Bob_Smith.zip") and man["tester"] == "Bob Smith"
    else:
        assert "Bob" not in base and man["tester"] == ""
        assert base == f"official_{rec.session_id}.zip"
    assert any(n.endswith(".pcapng") for n in names)
    assert man["note"] == "note here" and man["markers"][0]["text"] == "opened cultivation"
    assert man["server_endpoints"][0]["ip"] == SERVER and man["warning"] is None
    (client,) = man["clients"]
    assert client["id"] == "client1" and client["pid"] == 4321
    assert [(c["local_port"], c["ip"], c["port"]) for c in client["connections"]] == [(50001, SERVER, 2003)]


def test_recorder_warns_on_empty_payload(tmp_path):
    pkts = [(1, tcp_packet(LOCAL, SERVER, 50001, 2003)), (2, tcp_packet(SERVER, LOCAL, 2003, 50001))]
    raw = tmp_path / "raw.pcapng"
    write_pcapng(raw, pkts)
    cfg = Config(path=str(tmp_path / "cfg.json"))
    cfg.update(capture_dir=str(tmp_path / "caps"), tester_name="Bob")

    def factory(*a, **k):
        s = FakeSession(*a, **k)
        s.src = str(raw)
        return s
    rec = Recorder(cfg, FakeWatcher(), log=lambda m: None, session_factory=factory)
    rec.start()
    path = rec.stop()
    assert path and rec.warning and "booster" in rec.warning


@pytest.fixture
def server(monkeypatch):
    for k in ("HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy"):
        monkeypatch.delenv(k, raising=False)
    monkeypatch.setenv("no_proxy", "*")
    rx = FakeReceiver().start()
    yield rx
    rx.stop()


def make_zip(tmp_path, name="official_20261015_003000_Bob.zip", size=9_000_000):
    p = tmp_path / name
    with zipfile.ZipFile(p, "w", zipfile.ZIP_STORED) as z:
        z.writestr(name[:-4] + ".pcapng", os.urandom(size))
        z.writestr("manifest.json", json.dumps({"note": "hi", "markers": [{"t": 1}], "packets": 5}))
        z.writestr("../evil.txt", "nope")
    return p


def test_upload_resume_and_extract(server, tmp_path, monkeypatch):
    rx = server
    token = rx.create("Bob")
    z = make_zip(tmp_path)
    client = Client(rx.url, token)
    assert client.ping()["tester"] == "Bob"

    # Simulate a dropped connection after the first chunk, then resume.
    import aowcap.uploader as up
    calls = {"n": 0}
    real = Client._req

    def flaky(self, method, path, body=None, ctype="application/json"):
        if method == "PUT":
            calls["n"] += 1
            if calls["n"] == 2:
                raise up.UploadError("network down")
        return real(self, method, path, body, ctype)
    monkeypatch.setattr(Client, "_req", flaky)
    monkeypatch.setattr(up.time, "sleep", lambda s: None)
    res = client.upload(str(z))
    assert res["done"] and read_state(str(z))["status"] == "uploaded"
    assert calls["n"] >= 3   # it really was sent in chunks, one of which failed
    assert rx.files[("Bob", z.name)] == z.read_bytes()

    # Re-uploading the same file is a no-op.
    os.remove(str(z) + ".upload.json")
    assert client.upload(str(z))["done"]
    assert len(rx.files) == 1


def test_bad_token_and_revoke(server, tmp_path):
    rx = server
    from aowcap.uploader import UploadError
    with pytest.raises(UploadError):
        Client(rx.url, "nope").ping()
    t = rx.create("Eve")
    assert Client(rx.url, t).ping()["tester"] == "Eve"
    rx.revoke("Eve")
    with pytest.raises(UploadError):
        Client(rx.url, t).ping()


def raw_ip(pkt_eth):
    return pkt_eth[14:]


def test_loopback_relay_kept_and_not_anonymized(tmp_path):
    # NIC capture (game + web) plus a loopback capture of the game's link to a local relay
    nic = sample(tmp_path)
    lo = tmp_path / "lo.pcapng"
    game = raw_ip(tcp_packet("127.0.0.1", "127.0.0.1", 59523, 55616, b"\xce\x3b" * 50))
    other = raw_ip(tcp_packet("127.0.0.1", "127.0.0.1", 49355, 6329, b"\x17\x03\x03 tls"))
    with open(lo, "wb") as f:
        f.write(pf.shb_block("x"))
        f.write(pf.idb_block(pf.LINK_RAW, 65535, None))
        for i, p in enumerate([game, other, game]):  # 3rd = duplicate within 5 ms
            f.write(pf.epb_block(0, 2_000_000 + i, p, len(p)))
    out = tmp_path / "out.pcapng"
    st = pf.filter_capture([str(nic), str(lo)], str(out), {(6, SERVER, 2003), (6, "127.0.0.1", 55616)},
                           {LOCAL}, dedupe=True)
    pkts = [p for p in read_packets(out) if isinstance(p, bytes)]
    assert st["packets_out"] == 3 and st["duplicates"] == 1
    assert game in pkts and other not in pkts  # loopback packet kept byte-for-byte


def test_tracker_skips_game_socket_pair():
    from aowcap import gameproc
    from types import SimpleNamespace as NS
    A = lambda ip, port: NS(ip=ip, port=port)
    conns = [NS(laddr=A("127.0.0.1", 62574), raddr=A("127.0.0.1", 62573), type=1),
             NS(laddr=A("127.0.0.1", 62573), raddr=A("127.0.0.1", 62574), type=1),
             NS(laddr=A("127.0.0.1", 60353), raddr=A("127.0.0.1", 55616), type=1)]

    class P:
        def __init__(self, pid):
            pass

        def net_connections(self, kind):
            return conns
    real = gameproc.psutil
    gameproc.psutil = NS(Process=P, NoSuchProcess=Exception, AccessDenied=Exception)
    try:
        flows = FlowSet()
        gameproc.FlowTracker(NS(pids={1}), flows).poll_once()
    finally:
        gameproc.psutil = real
    assert flows.remotes == {(6, "127.0.0.1", 55616)}


def test_classify_server():
    from aowcap.gameproc import classify_server
    assert classify_server(["Age of Wushu   Launch-BlueDragon"]) == ("official", "Age of Wushu   Launch-BlueDragon")
    assert classify_server(["Age of Wushu   Local-TestServer"])[0] == "private"
    assert classify_server(["Age of Wushu   Karma-PandaWorld"])[0] == "private"  # names no official server
    assert classify_server(["x.exe", "Launch-BlueDragon"])[0] == "official"        # from launch args
    assert classify_server(["Age of Wushu"]) == (None, None)                         # not known yet
    assert classify_server([]) == (None, None)


def test_other_server_and_local_traffic_never_saved(tmp_path):
    # official game traffic + a local server on loopback + another public server on game ports
    pkts = [
        (1, tcp_packet(LOCAL, SERVER, 50001, 2003, b"\x01" * 3000)),
        (2, tcp_packet(SERVER, LOCAL, 2003, 50001, b"\x02" * 100)),
        (3, tcp_packet(LOCAL, "203.0.113.9", 50003, 2003, b"private")),
        (4, tcp_packet("203.0.113.9", LOCAL, 2003, 50003, b"private")),
        (5, tcp_packet("127.0.0.1", "127.0.0.1", 50004, 19061, b"loc")),
    ]
    raw = tmp_path / "raw.pcapng"
    write_pcapng(raw, pkts)
    out = tmp_path / "out.pcapng"
    st = pf.filter_capture(str(raw), str(out), set(), {LOCAL}, keep_ports={2002, 2003, 2004, 4000},
                           allowed_nets=["148.153.0.0/16"])
    assert st["packets_out"] == 2
    assert b"private" not in out.read_bytes() and b"loc" not in out.read_bytes()


def test_recorder_drops_private_session_and_non_official_remotes(tmp_path):
    raw = sample(tmp_path)
    cfg = Config(path=str(tmp_path / "cfg.json"))
    cfg.update(capture_dir=str(tmp_path / "caps"), tester_name="Bob")

    def factory(*a, **k):
        s = FakeSession(*a, **k)
        s.src = str(raw)
        return s
    rec = Recorder(cfg, FakeWatcher(), log=lambda m: None, session_factory=factory, sniffer_factory=None)
    # 1) remotes outside the official range are ignored; the official one is kept
    rec.start()
    rec.flows.add(6, LOCAL, 50001, SERVER, 2003)
    rec.flows.add(6, "127.0.0.1", 60000, "127.0.0.1", 19061)   # a local server
    rec.flows.add(6, LOCAL, 50009, "203.0.113.9", 2003)       # another public server
    rec.note_server("official", "Age of Wushu   Launch-BlueDragon")
    path = rec.stop()
    with zipfile.ZipFile(path) as z:
        man = json.loads(z.read("manifest.json"))
    assert [e["ip"] for e in man["server_endpoints"]] == [SERVER]
    assert man["game_server"].endswith("Launch-BlueDragon")
    # 2) a session the game showed as another server is not saved at all
    rec.start()
    rec.flows.add(6, LOCAL, 50001, SERVER, 2003)
    rec.note_server("private", "Local-TestServer")
    assert rec.stop() is None and rec.skipped_private


def test_tunnel_processes_match_install_folder(monkeypatch):
    from aowcap import gameproc
    from types import SimpleNamespace as NS
    procs = [NS(info={"pid": 1, "name": "ExitLag.exe", "exe": r"C:\Program Files\ExitLag\ExitLag.exe"}),
             NS(info={"pid": 2, "name": "elhelper.exe", "exe": r"C:\Program Files\ExitLag\bin\elhelper.exe"}),
             NS(info={"pid": 3, "name": "python.exe", "exe": r"C:\Python313\python.exe"})]
    monkeypatch.setattr(gameproc.psutil, "process_iter", lambda attrs=None: procs)
    assert gameproc.tunnel_processes() == {1: "ExitLag", 2: "ExitLag"}


@pytest.fixture
def fake_github(tmp_path, monkeypatch):
    """A local stand-in for api.github.com + release downloads."""
    import hashlib
    import http.server
    for k in ("HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy"):
        monkeypatch.delenv(k, raising=False)
    monkeypatch.setenv("no_proxy", "*")
    state = {"exe": b"MZ new build 0.9.0", "tag": "v0.9.0", "sums_override": None}

    class H(http.server.BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_GET(self):
            base = f"http://127.0.0.1:{self.server.server_address[1]}"
            if self.path.endswith("/releases/latest"):
                body = json.dumps({"tag_name": state["tag"], "body": "notes", "html_url": base,
                                   "assets": [{"name": "AoWCapture.exe", "browser_download_url": base + "/dl/exe"},
                                              {"name": "SHA256SUMS.txt", "browser_download_url": base + "/dl/sums"}]}).encode()
            elif self.path == "/dl/exe":
                body = state["exe"]
            elif self.path == "/dl/sums":
                digest = state["sums_override"] or hashlib.sha256(state["exe"]).hexdigest()
                body = f"{digest}  AoWCapture.exe\n".encode()
            else:
                self.send_response(404)
                self.end_headers()
                return
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{srv.server_address[1]}", state
    srv.shutdown()


def test_updater_check_download_verify(fake_github, tmp_path):
    from aowcap import updater
    api, state = fake_github
    u = updater.Updater("x/y", api=api, current="0.2.0", folder=str(tmp_path / "upd"))
    up = u.check()
    assert up and up.label == "0.9.0"
    path = u.download(up)
    assert open(path, "rb").read() == state["exe"]
    # same or older version: no update
    assert updater.Updater("x/y", api=api, current="0.9.0", folder=str(tmp_path / "u2")).check() is None
    # tampered download is rejected and deleted
    state["sums_override"] = "0" * 64
    u3 = updater.Updater("x/y", api=api, current="0.2.0", folder=str(tmp_path / "u3"))
    with pytest.raises(updater.UpdateError):
        u3.download(u3.check())
    assert not [f for f in os.listdir(tmp_path / "u3") if f.endswith(".exe")]


def test_updater_apply_swaps_exe(fake_github, tmp_path, monkeypatch):
    from aowcap import updater
    api, state = fake_github
    app_dir = tmp_path / "app"
    app_dir.mkdir()
    exe = app_dir / "AoWCapture.exe"
    exe.write_bytes(b"MZ old build")
    monkeypatch.setattr(updater.sys, "frozen", True, raising=False)
    monkeypatch.setattr(updater.sys, "executable", str(exe))
    started = []
    monkeypatch.setattr(updater.subprocess, "Popen", lambda args, **kw: started.append((args, kw)))
    u = updater.Updater("x/y", api=api, current="0.2.0", folder=str(tmp_path / "upd"))
    up = u.check()
    u.download(up)
    u.apply(up, hidden=True)
    assert exe.read_bytes() == state["exe"]
    assert (app_dir / "AoWCapture.old.exe").read_bytes() == b"MZ old build"
    args, kw = started[0]
    assert args[0] == str(exe) and "--wait-pid" in args and "--tray" in args
    assert kw["env"]["PYINSTALLER_RESET_ENVIRONMENT"] == "1"
    updater.cleanup_after_update()
    assert not (app_dir / "AoWCapture.old.exe").exists()


def test_threads_stop_cleanly(tmp_path, monkeypatch):
    """Regression: a thread attribute named _stop broke Thread.join() on Python 3.12."""
    import socket as _socket
    from aowcap import loopcap
    from aowcap.gameproc import FlowTracker

    class DummySock:
        def recv(self, n):
            raise _socket.timeout()

        def ioctl(self, *a):
            pass

        def close(self):
            pass
    sn = loopcap.LoopbackSniffer(str(tmp_path / "lo.pcapng"), None, log=lambda m: None)
    monkeypatch.setattr(sn, "_open", lambda: DummySock())
    monkeypatch.setattr(loopcap, "tunnel_listen_ports", lambda: {})
    assert sn.start_capture()
    sn.stop()
    assert not sn.is_alive()
    ft = FlowTracker(type("W", (), {"pids": set()})(), FlowSet(), interval=0.01)
    ft.start()
    ft.stop()
    ft.join(timeout=2)
    assert not ft.is_alive()


def test_autosave_parts_while_recording(tmp_path):
    raw = sample(tmp_path)
    cfg = Config(path=str(tmp_path / "cfg.json"))
    cfg.update(capture_dir=str(tmp_path / "caps"), tester_name="Bob")
    sessions = []

    def factory(*a, **k):
        s = FakeSession(*a, **k)
        s.src = str(raw)
        sessions.append(s)
        return s
    rec = Recorder(cfg, FakeWatcher(), log=lambda m: None, session_factory=factory, sniffer_factory=None)
    rec.start()
    rec.flows.add(6, LOCAL, 50001, SERVER, 2003)
    rec.add_marker("before first save")
    p1 = rec.checkpoint()
    assert rec.recording and sessions[0].rotations == 1          # still recording after the save
    rec.add_marker("after first save")
    p2 = rec.checkpoint()
    p3 = rec.stop("final note")
    names = [os.path.basename(p) for p in (p1, p2, p3)]
    assert [n.rsplit("_part", 1)[1] for n in names] == ["01.zip", "02.zip", "03.zip"]
    mans = []
    for p in (p1, p2, p3):
        with zipfile.ZipFile(p) as z:
            mans.append(json.loads(z.read("manifest.json")))
    assert [m["part"] for m in mans] == [1, 2, 3] and [m["final"] for m in mans] == [False, False, True]
    assert len({m["session_id"] for m in mans}) == 1
    assert [x["text"] for x in mans[0]["markers"]] == ["before first save"]
    assert [x["text"] for x in mans[1]["markers"]] == ["after first save"]
    assert mans[2]["note"] == "final note"


def test_single_save_has_no_part_suffix(tmp_path):
    raw = sample(tmp_path)
    cfg = Config(path=str(tmp_path / "cfg.json"))
    cfg.update(capture_dir=str(tmp_path / "caps"), tester_name="Bob")

    def factory(*a, **k):
        s = FakeSession(*a, **k)
        s.src = str(raw)
        return s
    rec = Recorder(cfg, FakeWatcher(), log=lambda m: None, session_factory=factory, sniffer_factory=None)
    rec.start()
    rec.flows.add(6, LOCAL, 50001, SERVER, 2003)
    assert "_part" not in os.path.basename(rec.stop())


def test_follows_upload_server_to_new_address(monkeypatch):
    from aowcap.uploader import new_upload_url
    for k in ("HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy"):
        monkeypatch.delenv(k, raising=False)
    monkeypatch.setenv("no_proxy", "*")
    new_rx = FakeReceiver().start()
    old_rx = FakeReceiver(public_url="https://new.example").start()
    try:
        token = old_rx.create("Bob")
        new_rx.tokens[token] = "Bob"           # same receiver behind both names

        class Routed(Client):                  # https://new.example -> the second fake
            def __init__(self, url, token, timeout=60):
                super().__init__(new_rx.url if url == "https://new.example" else url, token, timeout)
        info = Client(old_rx.url, token).ping()
        assert info["upload_url"] == "https://new.example"
        assert new_upload_url(old_rx.url, token, info, Routed) == "https://new.example"
        # nothing to do when it's the same address or none is announced
        assert new_upload_url("https://new.example/", token, info, Routed) is None
        assert new_upload_url(old_rx.url, token, {"tester": "Bob"}, Routed) is None
        # never moves to an address where the invite doesn't work or that isn't https
        new_rx.revoke("Bob")
        assert new_upload_url(old_rx.url, token, info, Routed) is None
        assert new_upload_url(old_rx.url, token, dict(info, upload_url="http://x.example"), Routed) is None
    finally:
        old_rx.stop()
        new_rx.stop()


def test_tracker_notes_which_client_made_each_connection(monkeypatch):
    """Two game clients on the same server: each connection is credited to its own client."""
    from aowcap import gameproc
    from types import SimpleNamespace as NS
    A = lambda ip, port: NS(ip=ip, port=port)
    per_pid = {11: [NS(laddr=A(LOCAL, 50001), raddr=A(SERVER, 2003), type=1)],
               22: [NS(laddr=A(LOCAL, 50002), raddr=A(SERVER, 2003), type=1),
                    NS(laddr=A(LOCAL, 50003), raddr=A(OTHER, 443), type=1)]}

    class P:
        def __init__(self, pid):
            self.pid = pid

        def net_connections(self, kind):
            return per_pid[self.pid]

        def create_time(self):
            return 1000.0 + self.pid
    monkeypatch.setattr(gameproc, "psutil", NS(Process=P, NoSuchProcess=Exception, AccessDenied=Exception))
    monkeypatch.setattr(gameproc, "window_titles", lambda pid: [f"Age of Wushu   Launch-BlueDragon #{pid}"])
    flows = FlowSet()
    tr = gameproc.FlowTracker(NS(pids={11, 22}, exe_names={11: "fxgame.exe", 22: "fxgame.exe"}), flows)
    tr.poll_once()
    tr.poll_once()
    clients = {c["pid"]: c for c in flows.clients_manifest(keep=lambda p, ip, port: ip == SERVER)}
    assert {c["id"] for c in clients.values()} == {"client1", "client2"}
    assert [(x["local_port"], x["ip"], x["port"]) for x in clients[11]["connections"]] == [(50001, SERVER, 2003)]
    assert [(x["local_port"], x["ip"], x["port"]) for x in clients[22]["connections"]] == [(50002, SERVER, 2003)]
    assert clients[22]["window_titles"] == ["Age of Wushu   Launch-BlueDragon #22"]
    assert clients[11]["created"] == 1011.0 and clients[11]["exe"] == "fxgame.exe"


def test_reused_local_port_goes_to_newer_client():
    flows = FlowSet()
    flows.note_client(1)
    flows.note_client(2)
    flows.add(6, LOCAL, 50001, SERVER, 2003, pid=1)
    flows.add(6, LOCAL, 50001, SERVER, 2003, pid=2)   # client 1 closed, port reused by client 2
    c = {x["pid"]: x["connections"] for x in flows.clients_manifest()}
    assert c[1] == [] and len(c[2]) == 1


class FakeSniffer:
    """Stands in for the ExitLag-relay recorder: a ready-made loopback capture."""
    src = None

    def __init__(self, path, flows, log=print):
        self.path, self.ports = FakeSniffer.src, {55616: "ExitLag"}
        self.packets = self.part_packets = 3

    def start_capture(self):
        return True

    def stop(self):
        pass

    def rotate(self):
        return None, 0

    def summary(self):
        return {"relays": [{"port": 55616, "app": "ExitLag"}]}


def test_official_client_recorded_next_to_one_on_another_server(tmp_path):
    """One client on the official server, one on another server, both through ExitLag too:
    only the official client's traffic, connections and details are saved."""
    OTHER_SRV = "203.0.113.9"
    big = b"\xce\x3b" * 600
    nic = tmp_path / "nic.pcapng"
    write_pcapng(nic, [
        (1_000_000, tcp_packet(LOCAL, SERVER, 50001, 2003, big)),        # official client
        (1_000_100, tcp_packet(SERVER, LOCAL, 2003, 50001, big)),
        (1_000_200, tcp_packet(LOCAL, OTHER_SRV, 50002, 2003, b"other")),  # other client, its server
        (1_000_300, tcp_packet(LOCAL, SERVER, 50005, 2003, b"other2")),    # other client -> official ip
    ])
    lo = tmp_path / "lo.pcapng"
    relay_official = raw_ip(tcp_packet("127.0.0.1", "127.0.0.1", 60001, 55616, b"relay-ok" * 20))
    relay_other = raw_ip(tcp_packet("127.0.0.1", "127.0.0.1", 60002, 55616, b"relay-other"))
    relay_unknown = raw_ip(tcp_packet("127.0.0.1", "127.0.0.1", 60003, 55616, b"relay-unknown"))
    with open(lo, "wb") as f:
        f.write(pf.shb_block("x"))
        f.write(pf.idb_block(pf.LINK_RAW, 65535, None))
        for i, p in enumerate([relay_official, relay_other, relay_unknown]):
            f.write(pf.epb_block(0, 2_000_000 + i * 100, p, len(p)))
    FakeSniffer.src = str(lo)

    class Watcher(FakeWatcher):
        excluded = None

        def exe_version(self, exclude=()):
            Watcher.excluded = set(exclude)
            return {"exe": "fxgame.exe", "version": "1.0.0.401"}

    cfg = Config(path=str(tmp_path / "cfg.json"))
    cfg.update(capture_dir=str(tmp_path / "caps"), known_ports=[])

    def factory(*a, **k):
        s = FakeSession(*a, **k)
        s.src = str(nic)
        return s
    rec = Recorder(cfg, Watcher(), log=lambda m: None, session_factory=factory, sniffer_factory=FakeSniffer)
    rec.start()
    rec.flows.note_client(1, "fxgame.exe", 1.0, ["Age of Wushu   Launch-BlueDragon"])
    rec.flows.note_client(2, "fxgame.exe", 2.0, ["Age of Wushu   Other-Server"])
    rec.flows.add(6, LOCAL, 50001, SERVER, 2003, pid=1)
    rec.flows.add(6, "127.0.0.1", 60001, "127.0.0.1", 55616, pid=1)
    rec.flows.add(6, LOCAL, 50002, OTHER_SRV, 2003, pid=2)
    rec.flows.add(6, LOCAL, 50005, SERVER, 2003, pid=2)
    rec.flows.add(6, "127.0.0.1", 60002, "127.0.0.1", 55616, pid=2)
    rec.note_clients({1: ("official", "Age of Wushu   Launch-BlueDragon"),
                      2: ("private", "Age of Wushu   Other-Server")})
    rec.note_clients({2: ("official", "flicker")})         # once ignored, always ignored
    assert rec.ignored_pids == {2} and not rec.private_session
    path = rec.stop()
    assert path, "the official client's session must be saved"
    with zipfile.ZipFile(path) as z:
        man = json.loads(z.read("manifest.json"))
        log = z.read("capture-log.txt").decode()
        pkts = [p for p in read_packets(io_bytes(z, path)) if isinstance(p, bytes)]
    payloads = b"".join(pkts)
    assert b"other" not in payloads and b"relay-other" not in payloads
    assert b"relay-unknown" not in payloads                 # relay link not owned by the official client
    assert b"relay-ok" in payloads and big in payloads
    assert len(pkts) == 3
    assert [c["pid"] for c in man["clients"]] == [1] and man["ignored_clients"] == 1
    ports = sorted(c["local_port"] for c in man["clients"][0]["connections"])
    assert ports == [50001, 60001]
    assert Watcher.excluded == {2}
    blob = json.dumps(man) + log
    assert OTHER_SRV not in blob and "Other-Server" not in blob


def io_bytes(z, path):
    """Extract the capture's .pcapng from the zip to a temp file next to it."""
    name = next(n for n in z.namelist() if n.endswith(".pcapng"))
    out = path + ".pcapng"
    with open(out, "wb") as f:
        f.write(z.read(name))
    return out


def test_only_other_server_clients_saves_nothing(tmp_path):
    raw = sample(tmp_path)
    cfg = Config(path=str(tmp_path / "cfg.json"))
    cfg.update(capture_dir=str(tmp_path / "caps"))

    def factory(*a, **k):
        s = FakeSession(*a, **k)
        s.src = str(raw)
        return s
    rec = Recorder(cfg, FakeWatcher(), log=lambda m: None, session_factory=factory, sniffer_factory=None)
    rec.start()
    rec.flows.add(6, LOCAL, 50001, SERVER, 2003, pid=7)
    rec.note_clients({7: ("private", "Age of Wushu   Other-Server")})
    assert rec.stop() is None and rec.skipped_private


def test_summarize_clients():
    from aowcap.gameproc import summarize_clients
    assert summarize_clients({1: ("private", "a"), 2: ("official", "b")}) == ("official", "b")
    assert summarize_clients({1: ("private", "a"), 2: (None, None)}) == ("private", "a")
    assert summarize_clients({}) == (None, None)
