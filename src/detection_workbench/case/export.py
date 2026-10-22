"""Case exports: Markdown report and Timesketch-ready CSV."""
from __future__ import annotations

import csv
import io
import json
from datetime import UTC, datetime
from pathlib import Path

from ..safety.paths import write_text_safely
from .store import CaseStore

TIMESKETCH_COLUMNS = [
    "message", "datetime", "timestamp_desc", "timestamp", "data_type", "case_id", "run_id",
    "finding_id", "gid", "sid", "rev", "msg", "src_ip", "src_port", "dst_ip", "dst_port",
    "proto", "pkt_num", "pkt_gen", "status",
]


def _md_cell(v) -> str:
    return str(v if v is not None else "").replace("|", "\\|").replace("\n", " ")


def _table(headers: list[str], rows: list[list]) -> str:
    if not rows:
        return "_none_\n"
    out = ["| " + " | ".join(headers) + " |", "|" + "---|" * len(headers)]
    out += ["| " + " | ".join(_md_cell(c) for c in r) + " |" for r in rows]
    return "\n".join(out) + "\n"


def _result(store: CaseStore, run: dict, key: str = "summary") -> dict | None:
    """A run's parsed result file, or None when it is absent or unreadable."""
    rel = (run.get("results") or {}).get(key)
    if not rel:
        return None
    try:
        return json.loads((store.root / "runs" / run["id"] / rel).read_text())
    except (OSError, ValueError):
        return None


def _oneline(text: str) -> str:
    """Collapse whitespace so a finding or note cannot start its own heading or break the list it sits in."""
    return " ".join(str(text).split())


def _short(text, n: int = 90) -> str:
    text = str(text)
    return text if len(text) <= n else text[: n - 1] + "…"


def _event_detail(e: dict) -> str:
    d = e.get("data") or {}
    t = e["type"]
    if t == "case.created":
        return d.get("title", "")
    if t == "evidence.registered":
        return _short(d.get("path", ""))
    if t == "run.recorded":
        return f"{d.get('kind')} → {d.get('status')}"
    if t in ("finding.added",):
        return _short(d.get("statement", ""))
    if t == "finding.updated":
        return f"status {d.get('status')}"
    if t == "decision.recorded":
        return d.get("kind", "")
    if t == "case.updated":
        return ", ".join(f"{k}={v}" for k, v in d.items())
    if t == "export.written":
        return f"{d.get('format')} → {Path(d.get('path', '')).name}"
    return ""


MAX_TIMELINE = 200
TOP_SIDS = 10
BAR_WIDTH = 10


def _bar(value: int, peak: int) -> str:
    """A fixed-width text bar, scaled to the largest value in the table; any non-zero value shows at least one block."""
    if peak <= 0 or value <= 0:
        return "░" * BAR_WIDTH
    filled = max(1, round(BAR_WIDTH * value / peak))
    return "█" * filled + "░" * (BAR_WIDTH - filled)


def _change(before: int, after: int) -> str:
    if before == after:
        return "no change"
    if before == 0:
        return f"+{after} (new)"
    return f"{(after - before) / before:+.0%}".replace("-", "−")


def _plural(n: int, word: str) -> str:
    return f"{n} {word}{'' if n == 1 else 's'}"


def _headline(s: dict, runs: list[dict], engine_runs: list[dict], store: CaseStore) -> str:
    parts = []
    if engine_runs:
        parts.append(_plural(len(engine_runs), "engine run"))
    if s["findings"]:
        by = {st: sum(1 for f in s["findings"] if f["status"] == st) for st in ("confirmed", "open", "dismissed")}
        parts.append(f"{_plural(len(s['findings']), 'finding')} ("
                     + ", ".join(f"{n} {st}" for st, n in by.items() if n) + ")")
    if s["decisions"]:
        by = {st: sum(1 for d in s["decisions"] if d["status"] == st) for st in ("proposed", "accepted", "rejected")}
        parts.append(f"{_plural(len(s['decisions']), 'decision')} ("
                     + ", ".join(f"{n} {st}" for st, n in by.items() if n) + ")")
    top = None  # noisiest SID across baseline runs (tuning runs are what-ifs, so they are left out)
    for r in engine_runs:
        if r.get("kind") == "tuning":
            continue
        for b in (_result(store, r) or {}).get("by_sid") or []:
            if top is None or b["count"] > top[0]["count"]:
                top = (b, r["id"])
    if top:
        parts.append(f"noisiest SID: {top[0]['sid']} ({_plural(top[0]['count'], 'alert')} in {top[1]})")
    return "> **At a glance:** " + (" · ".join(parts) if parts else "nothing recorded yet.")


def export_markdown(store: CaseStore) -> str:
    s = store.summary(recent_runs=10_000)
    runs = store.list_runs()
    engine_runs = [r for r in runs if r.get("kind") in ("run", "profile", "tuning")]
    o = [f"# {s['title']}", "",
         f"Case `{s['id']}` · status **{s['status']}** · created {s['created']} · updated {s['updated']}", ""]

    o += [_headline(s, runs, engine_runs, store), ""]
    o += ["## Summary", "", s["summary"] if s["summary"] else
          "_No analyst summary was recorded for this case._", ""]

    # ---- overview: what was examined and with what ----
    o += ["## Overview", ""]
    caps = [(r, _result(store, r)) for r in runs if r.get("kind") == "summary"]
    caps = [(r, d) for r, d in caps if d]
    if caps:
        rows = []
        for r, d in caps:
            ev = next((i["evidence_id"] for i in r.get("inputs", []) if i.get("evidence_id")), "")
            protos = ", ".join(f"{k} {v}" for k, v in (d.get("protocols") or {}).items())
            rows.append([ev, d.get("packets"), d.get("first_packet"), d.get("last_packet"), protos])
        o += ["**Captures**", "", _table(["evidence", "packets", "first packet", "last packet", "protocols"], rows)]
    engines = sorted({(r.get("engine"), r.get("engine_version"), r.get("backend")) for r in runs
                      if r.get("engine") not in (None, "dpkt")}, key=str)
    if engines:
        o += ["**Engines:** " + "; ".join(f"{e} {v or '?'} ({b})" for e, v, b in engines), ""]
    sets: dict = {}
    for r in runs:
        rl = r.get("rules")
        if rl and rl.get("sha256"):
            origin = (rl.get("evidence_id") or (f"derived from {rl['parent_run']}" if rl.get("parent_run") else None)
                      or ("inline" if rl.get("source") in (None, "validate", "run", "inline") else rl.get("source")))
            entry = sets.setdefault(rl["sha256"], {"origins": [], "runs": []})
            if origin not in entry["origins"]:
                entry["origins"].append(origin)
            entry["runs"].append(r["id"])
    if sets:
        rows = [[" · ".join(v["origins"]), sha[:16] + "…", ", ".join(v["runs"])] for sha, v in sets.items()]
        o += ["**Rule sets** (by hash)", "", _table(["origin", "sha256", "used in"], rows)]

    o += ["## Evidence", "", _table(
        ["id", "type", "path", "sha256", "size"],
        [[e["id"], e["type"], e["path"], e["sha256"], e["size"]] for e in s["evidence"]])]

    o += ["## Findings", ""]
    if not s["findings"]:
        o.append("_none_\n")
    for f in s["findings"]:
        o.append(f"- **{f['id']}** [{f['status']}] {_oneline(f['statement'])}  "
                 f"(runs: {', '.join(f['run_ids']) or '-'}; evidence: {', '.join(f['evidence_ids']) or '-'})")
    o.append("")

    # ---- results by run ----
    o += ["## Results by run", ""]
    shown = False
    # one scale for every table, so a bar means the same thing in the baseline run and in a tuned run
    peak = max((b["count"] for r in engine_runs for b in ((_result(store, r) or {}).get("by_sid") or [])[:TOP_SIDS]),
               default=0)
    for r in runs:
        if r.get("kind") == "validate":
            d = _result(store, r) or {}
            ne, nw, nl = len(d.get("errors", [])), len(d.get("warnings", [])), len(d.get("lint", []))
            o.append(f"### {r['id']} — validate: {'ok' if d.get('ok') else 'not ok'} "
                     f"({ne} error{'s' * (ne != 1)}, {nw} warning{'s' * (nw != 1)}, {nl} lint note{'s' * (nl != 1)})\n")
            for e in (d.get("errors") or [])[:10]:
                o.append(f"- line {e.get('line')}, sid {e.get('sid')}: {e.get('plain') or e.get('error')}")
            if d.get("errors"):
                o.append("")
            shown = True
        elif r in engine_runs:
            d = _result(store, r) or {}
            parent = f" · parent `{r['parent_run']}`" if r.get("parent_run") else ""
            trunc = " · **truncated at the parse limit**" if d.get("truncated") else ""
            o.append(f"### {r['id']} — {r['kind']}{parent}\n")
            o.append(f"{d.get('total', (r.get('totals') or {}).get('alerts', 0))} alerts · status {r.get('status')}{trunc}\n")
            shown_sids = (d.get("by_sid") or [])[:TOP_SIDS]
            rows = [[b["sid"], b["msg"], b["count"], _bar(b["count"], peak), b["distinct_sources"],
                     f"{b['top_source']} ({b['top_source_share']:.0%})"] for b in shown_sids]
            if rows:
                o.append(_table(["sid", "message", "alerts", "volume", "sources", "top source"], rows))
                more = len(d.get("by_sid") or []) - len(rows)
                if more > 0:
                    o.append(f"_…and {more} more SIDs in `runs/{r['id']}/results/summary.json`_\n")
            shown = True
    if not shown:
        o.append("_No engine runs recorded._\n")

    o += ["## Decisions", ""]
    if not s["decisions"]:
        o.append("_none_\n")
    for d in s["decisions"]:
        o.append(f"### {d['id']} — {d['kind']} ({d['status']})\n")
        o.append(f"{d['reason']}\n\nBefore `{d['before_run']}` → after `{d['after_run']}`\n")
        o.append(_table(["sid", "before", "after", "change"],
                        [[sid, c.get("before"), c.get("after"), _change(c.get("before", 0), c.get("after", 0))]
                         for sid, c in sorted(d["counts"].items())]))
        if d.get("counts_omitted"):
            o.append(f"_{_plural(d['counts_omitted'], 'unchanged SID')} not listed._\n")
        o.append(f"Change: `{json.dumps(d['change'], sort_keys=True)}`\n")

    # ---- caveats ----
    cav = []
    for r in engine_runs:
        d = _result(store, r) or {}
        sc = d.get("stream_caveats") or {}
        if sc.get("unacked_flows"):
            cav.append(f"**{r['id']}:** {sc['unacked_flows']} of {sc.get('tcp_flows', '?')} TCP flows carried data the "
                       f"peer never ACKed ({sc.get('one_sided_flows', 0)} one-sided). {sc.get('explanation') or ''}".strip())
        if d.get("truncated"):
            cav.append(f"**{r['id']}:** alerts were truncated at the parse limit, so counts are lower bounds.")
    for r in runs:
        if r.get("status") not in (None, "ok"):
            cav.append(f"**{r['id']}** ({r.get('kind')}) finished with status `{r.get('status')}`"
                       + (f": {_short(r.get('error_excerpt', ''), 160)}" if r.get("error_excerpt") else "."))
    cav.append("Results describe only the evidence registered in this case. One capture is one sample; "
               "they do not show how a rule behaves on other traffic.")
    if any(d.get("status") == "proposed" for d in s["decisions"]):
        cav.append("Decisions marked `proposed` have been tested on this evidence but not accepted by a person.")
    o += ["## Caveats", ""] + [f"- {c}" for c in cav] + [""]

    # ---- timeline ----
    ev = store.events()
    o += ["## Timeline", ""]
    rows = [[e["ts"], e["type"], e["ref"], _event_detail(e)] for e in ev[:MAX_TIMELINE]]
    o.append(_table(["time (UTC)", "event", "ref", "detail"], rows))
    if len(ev) > MAX_TIMELINE:
        o.append(f"_…{len(ev) - MAX_TIMELINE} more events in `events.jsonl`_\n")

    if s["notes"]:
        o += ["## Notes", ""] + [f"- ({n['author']}, {n['created']}) {_oneline(n['text'])}" for n in s["notes"]] + [""]
    o += ["## Appendix: runs", "", _table(
        ["id", "kind", "engine", "version", "backend", "status", "duration_s", "alerts"],
        [[r["id"], r.get("kind"), r.get("engine"), r.get("engine_version"), r.get("backend"),
          r.get("status"), r.get("duration_s"), (r.get("totals") or {}).get("alerts")] for r in runs])]
    return "\n".join(o)


def _iso(dt: str | None) -> str:
    return dt or datetime.now(UTC).isoformat()


def _csv_row(row: dict) -> dict:
    return {k: _csv_cell(v) for k, v in row.items()}


def _csv_cell(value):
    """Text beginning with = + - @ (or a control character) is read as a formula by spreadsheets; prefix it with a quote."""
    if isinstance(value, str) and value[:1] in ("=", "+", "-", "@", "\t", "\r"):
        return "'" + value
    return value


def export_timesketch_csv(store: CaseStore) -> str:
    """Alerts from every recorded run plus findings. Required columns: message, datetime, timestamp_desc."""
    cid = store.root.name
    buf = io.StringIO()
    w = csv.DictWriter(buf, fieldnames=TIMESKETCH_COLUMNS, extrasaction="ignore", lineterminator="\n")
    w.writeheader()
    for run in store.list_runs():
        rel = (run.get("results") or {}).get("alerts")
        if not rel:
            continue
        f = store.root / "runs" / run["id"] / rel
        if not f.is_file():
            continue
        for line in f.read_text().splitlines():
            a = json.loads(line)
            w.writerow(_csv_row({
                "message": f"[{a['gid']}:{a['sid']}:{a['rev']}] {a['msg']} "
                           f"{a['src_ip']}:{a['src_port']} -> {a['dst_ip']}:{a['dst_port']}",
                "datetime": a["datetime"], "timestamp_desc": "Snort alert", "data_type": "snort:alert",
                "case_id": cid, "run_id": run["id"], "gid": a["gid"], "sid": a["sid"], "rev": a["rev"],
                "msg": a["msg"], "src_ip": a["src_ip"], "src_port": a["src_port"], "dst_ip": a["dst_ip"],
                "dst_port": a["dst_port"], "proto": a["proto"], "pkt_num": a["pkt_num"],
                "pkt_gen": a["pkt_gen"]}))
    for f in store.summary()["findings"]:
        w.writerow(_csv_row({"message": f["statement"], "datetime": _iso(f["created"]),
                    "timestamp_desc": "Workbench finding", "data_type": "workbench:finding",
                    "case_id": cid, "finding_id": f["id"], "run_id": ",".join(f["run_ids"]),
                    "status": f["status"]}))
    return buf.getvalue()


def write_export(store: CaseStore, fmt: str, path: Path | None = None, overwrite: bool = False) -> Path:
    if fmt == "markdown":
        text, ext = export_markdown(store), ".md"
    elif fmt == "timesketch_csv":
        text, ext = export_timesketch_csv(store), ".csv"
    else:
        raise ValueError("format must be markdown or timesketch_csv")
    if path is None:
        path = store.root / "exports" / f"{store.root.name}-{fmt}{ext}"
        overwrite = True
    path = Path(path)
    if path.suffix != ext:
        raise ValueError(f"export path must end with {ext} (Timesketch rejects other names)")
    if path.exists() and not overwrite:
        raise FileExistsError(f"{path} exists; pass overwrite=true to replace it")
    write_text_safely(path, text, overwrite=overwrite)
    store.log_event("export.written", path.name, {"format": fmt, "path": str(path)})
    return path
