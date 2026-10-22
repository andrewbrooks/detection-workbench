"""Workbench lint: rule-hygiene checks Snort itself does not make (it is silent about a missing sid).
Results carry source="workbench_lint" so they are never confused with Snort's own diagnostics."""
from __future__ import annotations

from collections import defaultdict

from .rules import parse_rules

HTTP_BUFFERS = {"http_uri", "http_raw_uri", "http_header", "http_raw_header", "http_method",
                "http_client_body", "http_cookie", "http_stat_code", "http_stat_msg"}


def lint_rules(text: str) -> list[dict]:
    out, seen = [], defaultdict(list)

    def add(r, sev, msg):
        out.append({"severity": sev, "line": r.line, "sid": r.sid, "error": msg, "plain": msg,
                    "source": "workbench_lint", "rule": r.text[:300]})

    for r in parse_rules(text):
        if not r.parsed:
            add(r, "error", "Could not parse the rule header and options; check the 'action proto src port -> dst port ( ... )' shape.")
            continue
        if r.sid is None:
            add(r, "error", "No sid. Snort 3 loads this rule silently without one; add 'sid:1000001;' (local sids start at 1,000,000).")
        else:
            seen[(r.gid, r.sid)].append(r)
            if r.sid < 1_000_000 and r.gid == 1:
                add(r, "warning", f"sid {r.sid} is below 1,000,000, the range reserved for Talos rules; use a local sid.")
        if r.rev is None:
            add(r, "warning", "No rev. Add 'rev:1;' and bump it on every edit so runs can be told apart.")
        if not r.msg:
            add(r, "warning", "No msg. Alerts will be unreadable without one.")
        http_bufs = [b for b in r.buffers if b in HTTP_BUFFERS]
        if http_bufs and r.proto != "http" and "http" not in r.services:
            add(r, "warning", f"Uses {http_bufs[0]} but the rule is neither 'alert http' nor has 'service:http;', so it may never be evaluated on HTTP traffic.")
        positive = [c for c in r.contents if not c.negated]
        if not positive:
            add(r, "warning", "No positive content, so there is no fast pattern: Snort must evaluate this rule on every packet in scope.")
        elif not any(c.fast_pattern for c in positive) and len(positive) > 1:
            add(r, "info", "Several contents and no explicit fast_pattern; put the most unique string first or mark it fast_pattern.")
        if positive and not r.buffers and all(not c.anchored for c in positive) and r.proto in ("tcp", "udp"):
            add(r, "info", "Content is not anchored with offset/depth (or distance/within); anchor it where the protocol allows.")
    for (gid, sid), rs in seen.items():
        for dup in rs[1:]:
            add(dup, "warning", f"Duplicate sid {gid}:{sid} (first defined on line {rs[0].line}); Snort keeps the first.")
    return sorted(out, key=lambda d: (d["line"], d["severity"]))
