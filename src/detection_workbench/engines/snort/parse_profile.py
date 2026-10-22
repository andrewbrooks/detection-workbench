"""Parse the `rule profile` table Snort prints to stdout at shutdown.

With 7-digit SIDs the gid and sid columns run together ("11000042" is gid 1, sid 1000042; `rev` is
its own column), so the split is resolved against the (gid, sid) pairs loaded from the rules file.
"""
from __future__ import annotations

import re

_HEADER = re.compile(r"^rule profile \(")
_RULE_SID = re.compile(r"\bsid\s*:\s*(\d+)\s*;")
COLUMNS = ("checks", "matches", "alerts", "time_us", "avg_check", "avg_match", "avg_non_match",
           "timeouts", "suspends")


def known_rules(rules_text: str) -> set[tuple[int, int]]:
    """(gid, sid) pairs of the loaded rules; text rules are always gid 1."""
    out = set()
    for line in rules_text.splitlines():
        s = _RULE_SID.search(line)
        if s and not line.lstrip().startswith("#"):
            out.add((1, int(s.group(1))))
    return out


def _split_gid_sid(blob: str, known: set[tuple[int, int]]) -> tuple[int, int] | None:
    hits = {(int(blob[:i]), int(blob[i:])) for i in range(1, len(blob))
            if not blob[i:].startswith("0") and (int(blob[:i]), int(blob[i:])) in known}
    return next(iter(hits)) if len(hits) == 1 else None


def parse_profile(stdout: str, rules_text: str = "") -> dict:
    known = known_rules(rules_text)
    rows, unresolved, in_table = [], 0, False
    for line in stdout.splitlines():
        if _HEADER.match(line):
            in_table = True
            continue
        if not in_table:
            continue
        if not line.strip():
            if rows or unresolved:
                break
            continue
        if line.startswith(("#", "=")):
            continue
        tok = line.split()
        if not all(re.fullmatch(r"[\d.]+", t) for t in tok):
            continue
        if len(tok) == 13:  # gid and sid merged into one token
            gs = _split_gid_sid(tok[1], known)
            if gs is None:
                unresolved += 1
                continue
            rank, rev, rest = tok[0], tok[2], tok[3:]
        elif len(tok) == 14:
            rank, gs, rev, rest = tok[0], (int(tok[1]), int(tok[2])), tok[3], tok[4:]
        else:
            continue
        row = {"rank": int(rank), "gid": gs[0], "sid": gs[1], "rev": int(rev)}
        row.update({name: int(v) for name, v in zip(COLUMNS, rest[:9], strict=True)})
        row["rule_time_pct"] = float(rest[9])
        rows.append(row)
    return {"rules": rows, "unresolved_rows": unresolved}
