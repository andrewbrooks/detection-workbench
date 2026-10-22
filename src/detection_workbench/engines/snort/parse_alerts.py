"""Parse Snort 3 alert_json output into normalized alerts and a summary."""
from __future__ import annotations

import json
from collections import Counter, defaultdict
from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path


def _datetime(seconds: int, timestamp: str) -> str:
    """`seconds` is the epoch second; `timestamp` has no year but carries the microseconds."""
    micro = 0
    if "." in timestamp:
        frac = timestamp.rsplit(".", 1)[1]
        micro = int((frac + "000000")[:6]) if frac.isdigit() else 0
    return datetime.fromtimestamp(seconds, UTC).strftime("%Y-%m-%dT%H:%M:%S.") + f"{micro:06d}Z"


def normalize(raw: dict, idx: int) -> dict:
    return {
        "alert_idx": idx, "datetime": _datetime(int(raw.get("seconds", 0)), str(raw.get("timestamp", ""))),
        "seconds": raw.get("seconds"), "pkt_num": raw.get("pkt_num"), "pkt_gen": raw.get("pkt_gen"),
        "proto": raw.get("proto"), "dir": raw.get("dir"), "src_ip": raw.get("src_addr"),
        "src_port": raw.get("src_port"), "dst_ip": raw.get("dst_addr"), "dst_port": raw.get("dst_port"),
        "service": raw.get("service"), "gid": raw.get("gid"), "sid": raw.get("sid"), "rev": raw.get("rev"),
        "msg": raw.get("msg"), "class": raw.get("class"), "priority": raw.get("priority"),
        "action": raw.get("action"), "b64_data": raw.get("b64_data", ""),
    }


def iter_alerts(path: Path, max_alerts: int) -> Iterator[dict]:
    """Stream normalized alerts; malformed lines are skipped (counted by the caller via idx gaps)."""
    idx = 0
    with Path(path).open() as f:
        for line in f:
            if idx >= max_alerts:
                return
            line = line.strip()
            if not line:
                continue
            try:
                yield normalize(json.loads(line), idx)
            except (json.JSONDecodeError, ValueError, TypeError):
                continue
            idx += 1


def parse_alert_file(path: Path, out_jsonl: Path, max_alerts: int) -> dict:
    """Write results/alerts.jsonl and return the summary dict (totals, by sid / src / dst)."""
    by_sid: Counter = Counter()
    msgs: dict = {}
    srcs: dict = defaultdict(Counter)
    dsts: dict = defaultdict(Counter)
    total, truncated = 0, False
    p = Path(path)
    if not p.exists():  # Snort writes no file when nothing fired
        out_jsonl.write_text("")
        return {"total": 0, "truncated": False, "by_sid": [], "top_sources": [], "top_destinations": []}
    with out_jsonl.open("w") as out:
        for a in iter_alerts(p, max_alerts):
            out.write(json.dumps(a, separators=(",", ":")) + "\n")
            key = (a["gid"], a["sid"], a["rev"])
            by_sid[key] += 1
            msgs[key] = a["msg"]
            srcs[key][a["src_ip"]] += 1
            dsts[key][a["dst_ip"]] += 1
            total += 1
    with p.open() as f:
        truncated = sum(1 for line in f if line.strip()) > total
    rows = []
    for key, n in by_sid.most_common():
        gid, sid, rev = key
        rows.append({"gid": gid, "sid": sid, "rev": rev, "msg": msgs[key], "count": n,
                     "distinct_sources": len(srcs[key]), "distinct_destinations": len(dsts[key]),
                     "top_source": srcs[key].most_common(1)[0][0],
                     "top_source_share": round(srcs[key].most_common(1)[0][1] / n, 4)})
    all_src, all_dst = Counter(), Counter()
    for c in srcs.values():
        all_src.update(c)
    for c in dsts.values():
        all_dst.update(c)
    return {"total": total, "truncated": truncated, "by_sid": rows,
            "top_sources": all_src.most_common(10), "top_destinations": all_dst.most_common(10)}
