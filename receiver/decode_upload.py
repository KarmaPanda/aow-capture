#!/usr/bin/env python3
"""Decodes one uploaded capture on the server, without tshark.

    python decode_upload.py <capture.pcapng> --repo <aow-pserver-development checkout> [--out DIR]

Uses the project's own code from --repo (tools/pcapng_py.py for TCP reassembly,
server/aow_emu/protocol for FX framing, tools/decode_official_capture.timeline for
the opcode summary), so the output matches what decode_official_capture.py writes:

    <out>/<stamp>_stream<N>_c2s.bin / _s2c.bin   raw game wire bytes per direction
    <out>/<stamp>_stream<N>_timeline.txt         opcode summary (same format as the dev tool)
    <out>/<stamp>_timed.txt                      every frame with its time from the start,
                                                 the player's markers in between
    <out>/summary.json                           streams, frame counts, top opcodes

Streams to the official 148.153.0.0/16 range are decoded, plus streams to a booster's
local relay (ExitLag & co.) listed in the manifest as 127.0.0.1 endpoints: with a
booster on, that loopback link carries the plain game stream.
"""

import argparse
import collections
import importlib.util
import json
import os
import sys
import time


def load_repo(repo):
    repo = os.path.abspath(repo)
    for sub in ("server", "tools"):
        p = os.path.join(repo, sub)
        if not os.path.isdir(p):
            raise SystemExit(f"--repo {repo} has no {sub}/ folder")
        if p not in sys.path:
            sys.path.insert(0, p)

    def load(name, path):
        spec = importlib.util.spec_from_file_location(name, path)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        return mod
    pcapng_py = load("pcapng_py", os.path.join(repo, "tools", "pcapng_py.py"))
    decoder = load("decode_official_capture", os.path.join(repo, "tools", "decode_official_capture.py"))
    from aow_emu.protocol import custom_c2s, custom_messages
    return pcapng_py, decoder, custom_c2s, custom_messages


def install_segment_reader(pcapng_py, extra_servers):
    """Makes pcapng_py.streams() also treat extra (ip_bytes, port) endpoints as servers.

    pcapng_py.tcp_segments decides direction by the 148.153 prefix, which can't tell the
    two ends of a 127.0.0.1 <-> 127.0.0.1 connection apart; this uses ip + port instead.
    """
    import struct
    if not extra_servers:
        return
    original = pcapng_py.tcp_segments

    def tcp_segments(path, net=b"\x94\x99", *args, **kwargs):  # tolerate newer pcapng_py signatures
        for ts, lt, pkt in pcapng_py.read_pcapng(path):
            if lt == 1:
                et = struct.unpack_from(">H", pkt, 12)[0]
                o = 14
                while et == 0x8100:
                    et = struct.unpack_from(">H", pkt, o + 2)[0]
                    o += 4
                if et != 0x0800:
                    continue
                ip = pkt[o:]
            elif lt in (0, 108):
                ip = pkt[4:]
            elif lt in (101, 228):
                ip = pkt
            elif lt == 113:
                ip = pkt[16:]
            else:
                continue
            if len(ip) < 20 or ip[0] >> 4 != 4 or ip[9] != 6:
                continue
            ihl = (ip[0] & 15) * 4
            tot = struct.unpack_from(">H", ip, 2)[0]
            src, dst = ip[12:16], ip[16:20]
            tcp = ip[ihl:tot]
            sp, dp, seq = struct.unpack_from(">HHI", tcp, 0)
            doff = (tcp[12] >> 4) * 4
            flags, payload = tcp[13], tcp[doff:]
            if (src, sp) in extra_servers or src[:2] == net:
                yield ts, (dst, dp, src, sp), "S", seq, flags, payload
            elif (dst, dp) in extra_servers or dst[:2] == net:
                yield ts, (src, sp, dst, dp), "C", seq, flags, payload
    pcapng_py.tcp_segments = tcp_segments
    pcapng_py._original_tcp_segments = original


def ip_str(b):
    return ".".join(str(x) for x in b)


def describe(op, frame, direction, custom_c2s, custom_messages):
    if direction == "C2S" and op == 0x0A:
        try:
            msg, ok = custom_c2s.parse_client_activity_custom_message(frame)
        except Exception:
            return ""
        if ok and msg.values:
            mid = msg.message_id or 0
            name = custom_messages.CUSTOM_MSG_NAMES.get(mid, f"msg_{mid}")
            return f" custom id={mid} ({name}) args=" + ",".join(str(v) for v in msg.values[1:4])
    return ""


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("pcapng")
    ap.add_argument("--repo", required=True)
    ap.add_argument("--out")
    a = ap.parse_args(argv)

    t0 = time.time()
    pcapng_py, decoder, custom_c2s, custom_messages = load_repo(a.repo)
    capdir = os.path.dirname(os.path.abspath(a.pcapng))
    out = a.out or os.path.join(capdir, "decoded")
    os.makedirs(out, exist_ok=True)
    stamp = os.path.splitext(os.path.basename(a.pcapng))[0]

    manifest = {}
    mpath = os.path.join(capdir, "manifest.json")
    if os.path.exists(mpath):
        with open(mpath, encoding="utf-8") as f:
            manifest = json.load(f)

    relays = set()
    for ep in manifest.get("server_endpoints") or []:
        if ep.get("proto", "tcp") == "tcp" and str(ep.get("ip", "")).startswith("127."):
            relays.add((bytes(int(x) for x in ep["ip"].split(".")), int(ep["port"])))
    for r in (manifest.get("loopback") or {}).get("relays") or []:
        relays.add((b"\x7f\x00\x00\x01", int(r["port"])))
    install_segment_reader(pcapng_py, relays)

    streams = pcapng_py.streams(a.pcapng)
    rows = []
    for key, dd in streams.items():
        c_chunks, s_chunks = dd.get("C", []), dd.get("S", [])
        c2s = b"".join(d for _, d, _ in c_chunks if d)
        s2c = b"".join(d for _, d, _ in s_chunks if d)
        if not (c2s or s2c):
            continue
        rows.append({"key": key, "c": c_chunks, "s": s_chunks, "c2s": c2s, "s2c": s2c,
                     "gaps": sum(1 for _, d, _ in c_chunks + s_chunks if d is None)})
    if not rows:
        print("no game streams in this capture (no 148.153.x.x traffic"
              + (f", nor any on relay ports {sorted(p for _, p in relays)})" if relays else ", and no relay ports in manifest.json)"))
        with open(os.path.join(out, "summary.json"), "w", encoding="utf-8") as f:
            json.dump({"ok": False, "reason": "no game streams"}, f, indent=2)
        return 2
    rows.sort(key=lambda r: len(r["c2s"]) + len(r["s2c"]), reverse=True)  # game stream first

    first_ts = min(ts for r in rows for ts, _, _ in (r["c"] + r["s"])[:1])
    start_unix = manifest.get("started_unix") or first_ts
    summary = {"ok": True, "capture": os.path.basename(a.pcapng), "tester": manifest.get("tester"),
               "note": manifest.get("note"), "streams": []}
    timed = []
    for n, r in enumerate(rows):
        client_ip, cport, server_ip, sport = r["key"]
        label = f"stream{n}"
        base = os.path.join(out, f"{stamp}_{label}")
        with open(base + "_c2s.bin", "wb") as f:
            f.write(r["c2s"])
        with open(base + "_s2c.bin", "wb") as f:
            f.write(r["s2c"])
        with open(base + "_timeline.txt", "w", encoding="utf-8") as f:
            f.write(decoder.timeline(r["c2s"], f"{label} C2S {len(r['c2s'])}B") + "\n"
                    + decoder.timeline(r["s2c"], f"{label} S2C {len(r['s2c'])}B"))
        counts = {"C2S": collections.Counter(), "S2C": collections.Counter()}
        for direction, chunks in (("C2S", r["c"]), ("S2C", r["s"])):
            for ts, frame in pcapng_py.frames_with_ts(chunks):
                if not frame:
                    continue
                op = frame[0]
                counts[direction][op] += 1
                timed.append((ts, f"{label} {direction} op={op:#04x} len={len(frame) - 1}"
                                  + describe(op, frame, direction, custom_c2s, custom_messages)))
        summary["streams"].append({
            "stream": label, "server": f"{ip_str(server_ip)}:{sport}",
            "c2s_bytes": len(r["c2s"]), "s2c_bytes": len(r["s2c"]), "gaps": r["gaps"],
            "c2s_frames": sum(counts["C2S"].values()), "s2c_frames": sum(counts["S2C"].values()),
            "top_c2s": {f"{op:#04x}": c for op, c in counts["C2S"].most_common(10)},
            "top_s2c": {f"{op:#04x}": c for op, c in counts["S2C"].most_common(10)},
        })
        print(f"{label} {ip_str(server_ip)}:{sport} c2s={len(r['c2s'])}B s2c={len(r['s2c'])}B"
              + (f" gaps={r['gaps']}" if r["gaps"] else ""))

    for m in manifest.get("markers") or []:
        if m.get("unix"):
            timed.append((m["unix"], f"===== MARKER: {m.get('text', '')}"))
    timed.sort(key=lambda t: t[0])
    with open(os.path.join(out, f"{stamp}_timed.txt"), "w", encoding="utf-8") as f:
        f.write(f"# {stamp}  (times are seconds from the start of the recording)\n")
        for ts, line in timed:
            f.write(f"{ts - start_unix:+10.3f} {line}\n")

    summary["frames"] = sum(s["c2s_frames"] + s["s2c_frames"] for s in summary["streams"])
    summary["markers"] = len(manifest.get("markers") or [])
    summary["decode_seconds"] = round(time.time() - t0, 2)
    with open(os.path.join(out, "summary.json"), "w", encoding="utf-8") as f:
        json.dump(summary, f, indent=2, ensure_ascii=False)
    print(f"game stream = stream0, {summary['frames']} frames, {summary['decode_seconds']} s")
    return 0


if __name__ == "__main__":
    sys.exit(main())
