"""pcap_summary: packet count, time range, protocols, top talkers, services."""
from __future__ import annotations

from collections import Counter
from datetime import UTC, datetime
from pathlib import Path

from .reader import iter_packets

MAX_KEYS = 100_000  # distinct addresses / pairs tracked; counts for the rest are lumped into `untracked_packets`

SERVICES = {20: "ftp-data", 21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns", 80: "http", 110: "pop3",
            123: "ntp", 143: "imap", 161: "snmp", 389: "ldap", 443: "https", 445: "smb", 465: "smtps",
            587: "submission", 993: "imaps", 995: "pop3s", 1433: "mssql", 3306: "mysql", 3389: "rdp",
            5432: "postgres", 8080: "http-alt", 8443: "https-alt"}


def _iso(ts: float) -> str:
    return datetime.fromtimestamp(ts, UTC).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def summarize(path: Path, top: int = 10) -> dict:
    n, first, last, nbytes = 0, None, None, 0
    protos, talkers, convs, svc, non_ip = Counter(), Counter(), Counter(), Counter(), 0
    untracked = 0
    for p in iter_packets(path):
        n += 1
        nbytes += p.length
        first = p.ts if first is None else min(first, p.ts)
        last = p.ts if last is None else max(last, p.ts)
        if p.proto is None:
            non_ip += 1
            continue
        protos[p.proto] += 1
        if p.src in talkers or len(talkers) < MAX_KEYS:
            talkers[p.src] += 1
        else:
            untracked += 1
        if (p.src, p.dst) in convs or len(convs) < MAX_KEYS:
            convs[(p.src, p.dst)] += 1
        if p.dport is not None:
            name = SERVICES.get(p.dport) or SERVICES.get(p.sport)
            if name:
                svc[f"{name}/{p.proto.lower()}"] += 1
    return {
        "packets": n, "bytes": nbytes, "non_ip_packets": non_ip,
        "first_packet": _iso(first) if first is not None else None,
        "last_packet": _iso(last) if last is not None else None,
        "duration_s": round(last - first, 6) if first is not None else 0,
        "protocols": dict(protos.most_common()),
        "top_sources": talkers.most_common(top),
        "top_conversations": [{"src": s, "dst": d, "packets": c} for (s, d), c in convs.most_common(top)],
        "services": dict(svc.most_common(top)),
        "untracked_packets": untracked,
    }
