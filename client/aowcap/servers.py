"""Which game servers may be recorded besides the official one.

A server profile says how to recognise a game client that is on that server and what
of its traffic to keep:

    {"id": "example",                  # file names start with it: example_<date>_<time>.zip
     "name": "Example server",         # shown to the player and in the manifest
     "match": ["Example.org"],         # text in the game window title (or launch args)
     "networks": ["203.0.113.0/24"],   # optional: the server's address ranges
     "ports": [7000]}                  # optional: its game ports

Without "networks", the tool keeps the connections that client itself opened (web
ports 53/80/443/8080 excepted), learned while recording. With "networks", only traffic
to those ranges is kept, and Packet Monitor can be told to record just those.

Profiles come from config.json ("extra_servers") and from the upload server, which
sends its list when the tool checks in ("record_servers"; saved as "remote_servers").
"""

import ipaddress
import re

ID_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,23}$")
RESERVED = {"official", "private", "ignored"}
WEB_PORTS = {53, 80, 443, 8080}


def normalize(raw):
    """Validated profiles from untrusted input (config or the upload server)."""
    out, seen = [], set()
    for p in raw if isinstance(raw, list) else []:
        if not isinstance(p, dict):
            continue
        pid = str(p.get("id") or "").strip().lower()
        if not ID_RE.match(pid) or pid in RESERVED or pid in seen:
            continue
        match = [m.strip() for m in p.get("match") or [] if isinstance(m, str) and 4 <= len(m.strip()) <= 64][:8]
        if not match:
            continue
        nets = []
        for n in (p.get("networks") or [])[:16]:
            try:
                nets.append(str(ipaddress.ip_network(str(n), strict=False)))
            except ValueError:
                continue
        ports = [int(x) for x in (p.get("ports") or [])[:16]
                 if isinstance(x, int) or (isinstance(x, str) and x.isdigit())]
        ports = [x for x in ports if 0 < x < 65536]
        name = str(p.get("name") or pid).strip()[:48] or pid
        seen.add(pid)
        out.append({"id": pid, "name": name, "match": match, "networks": nets, "ports": ports})
    return out


def profiles(cfg):
    """Profiles from config.json first, then the upload server's (same id: config wins)."""
    local = normalize(cfg.get("extra_servers") or [])
    ids = {p["id"] for p in local}
    return local + [p for p in normalize(cfg.get("remote_servers") or []) if p["id"] not in ids]


def by_kind(kind, profs):
    """The profile for a kind "extra:<id>", or None."""
    if not kind or not kind.startswith("extra:"):
        return None
    pid = kind[6:]
    return next((p for p in profs if p["id"] == pid), None)


def in_networks(ip, networks):
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(addr in ipaddress.ip_network(n) for n in networks or ())
