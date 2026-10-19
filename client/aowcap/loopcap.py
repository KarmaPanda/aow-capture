"""Records the game's traffic to a booster's local relay (ExitLag and similar).

ExitLag points the game at a relay on 127.0.0.1 and encrypts from there, so on the
network card the game data is unreadable. On the loopback link it is still the plain
game stream. Windows' Packet Monitor doesn't see loopback, so this uses a raw socket
on 127.0.0.1 with SIO_RCVALL (the RawCap technique): no driver, admin rights only.

Only TCP packets to/from the relay's ports are kept, so nothing else that talks over
127.0.0.1 on the player's PC is written to disk.
"""

import os
import socket
import struct
import threading
import time

from .gameproc import tunnel_listen_ports
from .pcapng_filter import LINK_RAW, epb_block, idb_block, shb_block


class LoopbackSniffer(threading.Thread):
    def __init__(self, path, flows=None, log=print, refresh=1.0):
        super().__init__(daemon=True, name="loopback-sniffer")
        self.path = path
        self.flows = flows
        self.log = log
        self.refresh = refresh
        self.ports = {}          # port -> app label
        self.packets = 0
        self.error = None
        self._stop = threading.Event()
        self._sock = None

    # ------------------------------------------------ ports
    def _refresh_ports(self):
        # Only ports a known booster (ExitLag & co.) listens on. Anything else on
        # 127.0.0.1, such as a local private-server emulator, is never recorded.
        ports = dict(tunnel_listen_ports())
        new = set(ports) - set(self.ports)
        self.ports.update({p: ports[p] for p in new})  # cumulative: relays seen at any point
        for p in sorted(new):
            self.log(f"Recording the game's link to {ports[p]} on 127.0.0.1:{p}")

    def keep(self, pkt):
        if len(pkt) < 20 or pkt[0] >> 4 != 4 or pkt[9] != 6:
            return False
        ihl = (pkt[0] & 0x0F) * 4
        if len(pkt) < ihl + 4:
            return False
        sport, dport = struct.unpack("!HH", pkt[ihl:ihl + 4])
        return sport in self.ports or dport in self.ports

    # ------------------------------------------------ socket
    def _open(self):
        if os.name != "nt":
            raise OSError("loopback capture is Windows-only")
        s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
        s.bind(("127.0.0.1", 0))
        s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        s.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
        s.settimeout(0.25)
        return s

    def start_capture(self):
        try:
            self._sock = self._open()
        except OSError as e:
            self.error = str(e)
            self.log(f"Loopback capture unavailable ({e}); boosters like ExitLag can't be recorded.")
            return False
        self.start()
        return True

    def stop(self):
        self._stop.set()
        if self.is_alive():
            self.join(timeout=3)

    def run(self):
        last = 0
        with open(self.path, "wb") as out:
            out.write(shb_block("aow-capture loopback"))
            out.write(idb_block(LINK_RAW, 65535, None))  # microsecond timestamps
            while not self._stop.is_set():
                now = time.time()
                if now - last >= self.refresh:
                    try:
                        self._refresh_ports()
                    except Exception:
                        pass
                    last = now
                try:
                    pkt = self._sock.recv(65535)
                except socket.timeout:
                    continue
                except OSError as e:
                    self.error = str(e)
                    break
                if self.ports and self.keep(pkt):
                    out.write(epb_block(0, time.time_ns() // 1000, pkt, len(pkt)))
                    self.packets += 1
        try:
            self._sock.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
            self._sock.close()
        except OSError:
            pass

    def summary(self):
        return {"enabled": self.error is None, "error": self.error, "packets": self.packets,
                "relays": [{"port": p, "app": a} for p, a in sorted(self.ports.items())]}


