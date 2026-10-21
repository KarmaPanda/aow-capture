"""Streams a raw pcapng and keeps only the game's packets.

- Keeps a packet when its remote end (ip, port) belongs to the game, or its port is a
  configured server port.
- Writes a clean single-section pcapng: no host name, OS, adapter names or name
  resolution blocks from the original.
- Optional anonymizing: the player's MAC addresses and local IPs are replaced, with the
  IPv4/TCP/UDP checksums adjusted so they stay exactly as valid as they were.
- Optional de-duplication for pktmon captures that logged the same packet at several
  components.
"""

import hashlib
import ipaddress
import os
import struct

SHB, IDB, EPB, SPB, OPB = 0x0A0D0D0A, 0x00000001, 0x00000006, 0x00000003, 0x00000002
BOM = 0x1A2B3C4D
TCP, UDP = 6, 17

LINK_NULL, LINK_ETH, LINK_RAW, LINK_IPV4, LINK_IPV6 = 0, 1, 101, 228, 229


class PcapngError(ValueError):
    pass


# ---------------------------------------------------------------- reading

def _options(buf, endian):
    out, i = [], 0
    while i + 4 <= len(buf):
        code, length = struct.unpack(endian + "HH", buf[i:i + 4])
        if code == 0:
            break
        out.append((code, buf[i + 4:i + 4 + length]))
        i += 4 + length + (-length % 4)
    return out


def read_blocks(f):
    """Yields (endian, block_type, body)."""
    endian = "<"
    while True:
        head = f.read(8)
        if not head:
            return
        if len(head) < 8:
            raise PcapngError("truncated block header")
        btype = struct.unpack("<I", head[:4])[0]
        if btype == SHB:
            bom = f.read(4)
            endian = "<" if struct.unpack("<I", bom)[0] == BOM else ">"
            if struct.unpack(endian + "I", bom)[0] != BOM:
                raise PcapngError("bad byte-order magic")
            length = struct.unpack(endian + "I", head[4:8])[0]
            body = bom + f.read(length - 16)
            f.read(4)
        else:
            btype, length = struct.unpack(endian + "II", head)
            if length < 12:
                raise PcapngError("bad block length")
            body = f.read(length - 12)
            f.read(4)
        if len(body) < 0:
            raise PcapngError("truncated block")
        yield endian, btype, body


def _tsresol_ns(raw):
    """if_tsresol option byte -> nanoseconds per tick."""
    if raw is None:
        return 1000  # default: microseconds
    v = raw[0]
    if v & 0x80:
        return 1e9 / (2 ** (v & 0x7F))
    return 1e9 / (10 ** v)


# ---------------------------------------------------------------- writing

def _opt(code, value):
    return struct.pack("<HH", code, len(value)) + value + b"\0" * (-len(value) % 4)


def _block(btype, body):
    total = len(body) + 12
    return struct.pack("<II", btype, total) + body + struct.pack("<I", total)


def shb_block(app):
    body = struct.pack("<IHHq", BOM, 1, 0, -1) + _opt(4, app.encode()) + struct.pack("<HH", 0, 0)
    return _block(SHB, body)


def idb_block(linktype, snaplen, tsresol_raw):
    body = struct.pack("<HHI", linktype, 0, snaplen)
    if tsresol_raw is not None:
        body += _opt(9, tsresol_raw) + struct.pack("<HH", 0, 0)
    return _block(IDB, body)


def epb_block(ifid, ts, data, orig_len):
    body = struct.pack("<IIIII", ifid, ts >> 32, ts & 0xFFFFFFFF, len(data), orig_len)
    body += data + b"\0" * (-len(data) % 4)
    return _block(EPB, body)


# ---------------------------------------------------------------- packet parsing

def parse(linktype, data):
    """-> dict(l3_off, ver, proto, src, dst, sport, dport, l4_off) or None."""
    off = 0
    if linktype == LINK_ETH:
        if len(data) < 14:
            return None
        etype = struct.unpack("!H", data[12:14])[0]
        off = 14
        while etype in (0x8100, 0x88A8) and len(data) >= off + 4:
            etype = struct.unpack("!H", data[off + 2:off + 4])[0]
            off += 4
        if etype == 0x0800:
            ver = 4
        elif etype == 0x86DD:
            ver = 6
        else:
            return None
    elif linktype == LINK_NULL:
        if len(data) < 4:
            return None
        off = 4
        ver = data[4] >> 4 if len(data) > 4 else 0
    elif linktype in (LINK_RAW, LINK_IPV4, LINK_IPV6):
        ver = data[0] >> 4 if data else 0
    else:
        return None

    if ver == 4:
        if len(data) < off + 20:
            return None
        ihl = (data[off] & 0x0F) * 4
        proto = data[off + 9]
        frag = struct.unpack("!H", data[off + 6:off + 8])[0] & 0x1FFF
        if frag:
            return None  # non-first fragment: no ports
        src = ipaddress.IPv4Address(data[off + 12:off + 16])
        dst = ipaddress.IPv4Address(data[off + 16:off + 20])
        l4 = off + ihl
    elif ver == 6:
        if len(data) < off + 40:
            return None
        proto = data[off + 6]
        src = ipaddress.IPv6Address(data[off + 8:off + 24])
        dst = ipaddress.IPv6Address(data[off + 24:off + 40])
        l4 = off + 40
        while proto in (0, 43, 60) and len(data) >= l4 + 2:  # hop-by-hop, routing, dest opts
            proto, l4 = data[l4], l4 + (data[l4 + 1] + 1) * 8
        if proto == 44:
            return None
    else:
        return None

    if proto not in (TCP, UDP) or len(data) < l4 + 4:
        return None
    sport, dport = struct.unpack("!HH", data[l4:l4 + 4])
    return {"l3": off, "ver": ver, "proto": proto, "src": src, "dst": dst,
            "sport": sport, "dport": dport, "l4": l4}


def csum_adjust(csum, old, new):
    """RFC 1624 incremental checksum update for a 16-bit-aligned field change."""
    s = (~csum) & 0xFFFF
    for i in range(0, len(old), 2):
        s += (~int.from_bytes(old[i:i + 2], "big")) & 0xFFFF
        s += int.from_bytes(new[i:i + 2], "big")
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return (~s) & 0xFFFF


MAC_LOCAL = bytes.fromhex("020000000001")
MAC_REMOTE = bytes.fromhex("020000000002")


class Anonymizer:
    def __init__(self):
        self.map = {}

    def replacement(self, ip):
        if ip not in self.map:
            n = sum(1 for k in self.map if k.version == ip.version) + 2
            self.map[ip] = (ipaddress.IPv4Address(f"10.0.0.{n}") if ip.version == 4
                            else ipaddress.IPv6Address(f"fd00::{n:x}"))
        return self.map[ip]

    def rewrite(self, linktype, data, p, local_is_src):
        buf = bytearray(data)
        if linktype == LINK_ETH:
            buf[0:6] = MAC_REMOTE if local_is_src else MAC_LOCAL
            buf[6:12] = MAC_LOCAL if local_is_src else MAC_REMOTE
        old_ip = p["src"] if local_is_src else p["dst"]
        new_ip = self.replacement(old_ip)
        l3, l4 = p["l3"], p["l4"]
        if p["ver"] == 4:
            field = l3 + (12 if local_is_src else 16)
            hc = struct.unpack("!H", buf[l3 + 10:l3 + 12])[0]
            buf[l3 + 10:l3 + 12] = struct.pack("!H", csum_adjust(hc, old_ip.packed, new_ip.packed))
        else:
            field = l3 + (8 if local_is_src else 24)
        buf[field:field + len(old_ip.packed)] = new_ip.packed
        # TCP/UDP checksums cover the addresses through the pseudo-header.
        coff = l4 + (16 if p["proto"] == TCP else 6)
        if len(buf) >= coff + 2:
            c = struct.unpack("!H", buf[coff:coff + 2])[0]
            if not (p["proto"] == UDP and c == 0):  # UDP 0 = no checksum
                c = csum_adjust(c, old_ip.packed, new_ip.packed)
                if p["proto"] == UDP and c == 0:
                    c = 0xFFFF
                buf[coff:coff + 2] = struct.pack("!H", c)
        return bytes(buf)


# ---------------------------------------------------------------- the filter

def filter_capture(in_path, out_path, remotes, local_ips=(), keep_ports=(),
                   anonymize=True, dedupe=False, app="aow-capture", allowed_nets=None):
    """in_path: one path or a list (e.g. the NIC capture + the loopback capture).
    remotes: {(proto, ip_str, port)}; local_ips: {ip_str}; keep_ports: {port}.

    Returns stats {packets_in, packets_out, duplicates, bytes_out, first_ts_ns, last_ts_ns}.
    """
    remote_set = {(p, ipaddress.ip_address(ip), int(port)) for p, ip, port in remotes}
    locals_ = {ipaddress.ip_address(ip) for ip in local_ips}
    keep_ports = {int(p) for p in keep_ports}
    nets = [ipaddress.ip_network(n) for n in allowed_nets] if allowed_nets else None

    def allowed(ip):
        return nets is None or any(ip in n for n in nets)
    anon = Anonymizer() if anonymize else None

    stats = {"packets_in": 0, "packets_out": 0, "duplicates": 0, "bytes_out": 0, "tcp_payload_bytes": 0,
             "first_ts_ns": None, "last_ts_ns": None}
    in_ifaces = []           # per current section: (linktype, snaplen, tsresol_raw)
    section = -1
    out_ifaces = {}          # (section, ifid) -> out ifid
    recent = {}              # dedupe: digest -> ts_ns

    paths = [in_path] if isinstance(in_path, (str, bytes, os.PathLike)) else list(in_path)

    def blocks():
        for path in paths:
            with open(path, "rb") as fin:
                yield from read_blocks(fin)

    with open(out_path, "wb") as fout:
        fout.write(shb_block(app))
        for endian, btype, body in blocks():
            if btype == SHB:
                section += 1
                in_ifaces = []
                continue
            if btype == IDB:
                linktype, _, snaplen = struct.unpack(endian + "HHI", body[:8])
                opts = dict(_options(body[8:], endian))
                in_ifaces.append((linktype, snaplen, opts.get(9)))
                continue
            if btype != EPB:
                continue  # SPB/NRB/ISB/custom: dropped
            ifid, ts_hi, ts_lo, cap_len, orig_len = struct.unpack(endian + "IIIII", body[:20])
            data = body[20:20 + cap_len]
            stats["packets_in"] += 1
            if ifid >= len(in_ifaces):
                continue
            linktype, snaplen, tsres = in_ifaces[ifid]
            ts = (ts_hi << 32) | ts_lo
            ts_ns = int(ts * _tsresol_ns(tsres))

            p = parse(linktype, data)
            if p is None:
                continue
            remote_is_dst = (p["proto"], p["dst"], p["dport"]) in remote_set
            remote_is_src = (p["proto"], p["src"], p["sport"]) in remote_set
            if not (remote_is_dst or remote_is_src):
                if p["dport"] in keep_ports and p["sport"] not in keep_ports and allowed(p["dst"]):
                    remote_is_dst = True
                elif p["sport"] in keep_ports and p["dport"] not in keep_ports and allowed(p["src"]):
                    remote_is_src = True
                elif p["sport"] in keep_ports and p["dport"] in keep_ports and (
                        allowed(p["src"]) or allowed(p["dst"])):
                    remote_is_dst = allowed(p["dst"]) and (p["src"] in locals_ or not allowed(p["src"]))
                    remote_is_src = not remote_is_dst
                else:
                    continue
            if remote_is_dst and remote_is_src:  # odd: decide by known local IPs
                remote_is_src = p["dst"] in locals_
                remote_is_dst = not remote_is_src

            if dedupe:
                digest = hashlib.blake2b(data[p["l3"]:], digest_size=12).digest()
                prev = recent.get(digest)
                if prev is not None and abs(ts_ns - prev) < 5_000_000:
                    stats["duplicates"] += 1
                    continue
                recent[digest] = ts_ns
                if len(recent) > 4096:
                    cutoff = ts_ns - 50_000_000
                    recent = {k: v for k, v in recent.items() if v >= cutoff}

            if anon is not None and not (p["src"].is_loopback and p["dst"].is_loopback):
                data = anon.rewrite(linktype, data, p, local_is_src=remote_is_dst)

            key = (section, ifid)
            if key not in out_ifaces:
                out_ifaces[key] = len(out_ifaces)
                fout.write(idb_block(linktype, snaplen, tsres))
            fout.write(epb_block(out_ifaces[key], ts, data, orig_len))
            if p["proto"] == TCP and len(data) >= p["l4"] + 13:
                thl = (data[p["l4"] + 12] >> 4) * 4
                if p["ver"] == 4:
                    ip_end = p["l3"] + struct.unpack("!H", data[p["l3"] + 2:p["l3"] + 4])[0]
                else:
                    ip_end = p["l3"] + 40 + struct.unpack("!H", data[p["l3"] + 4:p["l3"] + 6])[0]
                stats["tcp_payload_bytes"] += max(0, min(ip_end, len(data)) - p["l4"] - thl)
            stats["packets_out"] += 1
            stats["bytes_out"] += len(data)
            if stats["first_ts_ns"] is None:
                stats["first_ts_ns"] = ts_ns
            stats["last_ts_ns"] = ts_ns
    return stats
