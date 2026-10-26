"""Workbench service: every MCP tool is a method here, so the logic is testable without MCP."""
from __future__ import annotations

import contextlib
import difflib
import json
import os
import re
import shutil
import tempfile
from collections import Counter
from pathlib import Path

from .case.export import write_export
from .case.model import EVIDENCE_TYPES, now
from .case.store import CaseError, CaseStore
from .config import Config
from .engines.base import EngineResult
from .engines.snort import changes as tuning_changes
from .engines.snort.config_gen import FILTER_TYPES, TuningError, render_filter
from .engines.snort.explain import explain_alert as _explain
from .engines.snort.plugin import SnortEngine, make_engine
from .engines.snort.rules import find_includes, find_rule, parse_rules
from .pcap.reader import PcapError
from .pcap.summary import summarize
from .runner.recorder import run_recorded
from .safety.paths import PathError, resolve_read, resolve_write, write_text_safely
from .safety.verified import copy_verified, fingerprint, read_checked, read_verified

MAX_SID_ROWS = 100       # SIDs listed in any one tool response; the full lists stay in the run's results files
MAX_DECISION_COUNTS = 200  # per-SID rows stored with a tuning decision before unchanged ones are trimmed
OFFLINE_REFUSAL = ("The workbench is offline-only: it reads registered pcap files and never captures from an "
                   "interface, runs inline, or touches a live sensor.")


class WorkbenchError(ValueError):
    """A problem the caller can fix; the message is safe to show."""


class Workbench:
    def __init__(self, cfg: Config, engine: SnortEngine | None = None):
        self.cfg = cfg
        self.engine = engine or make_engine(cfg)
        self.store: CaseStore | None = None

    # ---- helpers ----------------------------------------------------------
    @property
    def roots(self) -> list[Path]:
        return [*self.cfg.allowed_roots, self.cfg.case_dir]

    def _case(self) -> CaseStore:
        if self.store is None:
            raise WorkbenchError("No active case. Call create_case or open_case first.")
        return self.store

    def _wrap(self, fn, *a, **kw):
        try:
            return fn(*a, **kw)
        except (CaseError, PathError, PcapError, TuningError) as e:
            raise WorkbenchError(str(e)) from None

    def _evidence(self, evidence_id: str, want: set[str]) -> dict:
        """The registered record, checked for type. Content is verified when it is read (see _stage)."""
        ev = self._wrap(self._case().get_evidence, evidence_id)
        if ev["type"] not in want:
            raise WorkbenchError(f"{evidence_id} is type '{ev['type']}', expected one of {sorted(want)}")
        return ev

    def _stage(self, ev: dict, dest_dir: Path, name: str, max_bytes: int | None = None) -> Path:
        """Copy evidence into `dest_dir`, verifying its hash while reading, and return the copy. Engines work from this
        copy, so the file cannot be swapped between the check and the use. Callers delete `dest_dir` afterwards."""
        dest = dest_dir / name
        self._wrap(copy_verified, ev["path"], dest, ev["sha256"], self.roots, max_bytes or self.cfg.limits.max_input_bytes)
        return dest

    @contextlib.contextmanager
    def _staged(self, ev: dict, workdir: Path, name: str, max_bytes: int | None = None):
        """Stage evidence for the duration of a block; the copy is always removed."""
        d = Path(tempfile.mkdtemp(prefix="input-", dir=workdir))
        try:
            yield self._stage(ev, d, name, max_bytes)
        finally:
            shutil.rmtree(d, ignore_errors=True)

    @staticmethod
    def _capture_name(ev: dict) -> str:
        suffix = Path(ev["path"]).suffix.lower()
        return "capture" + (suffix if suffix in (".pcap", ".pcapng", ".cap") else ".pcap")

    def _rules(self, rules_id: str | None, rules_text: str | None) -> tuple[str, dict, list[dict]]:
        """-> (text, rules reference, run inputs)."""
        if bool(rules_id) == bool(rules_text):
            raise WorkbenchError("Give exactly one of rules_id (registered rules evidence) or rules_text.")
        if rules_id:
            ev = self._evidence(rules_id, {"rules"})
            data = self._wrap(read_verified, ev["path"], ev["sha256"], self.roots, self.cfg.limits.max_rules_bytes)
            text = data.decode(errors="replace")
            self._no_includes(text)
            return (text, {"source": "evidence", "evidence_id": rules_id},
                    [{"evidence_id": rules_id, "sha256": ev["sha256"], "mount": "cfg/rules.rules"}])
        self._no_includes(rules_text)
        return rules_text, {"source": "inline"}, []

    @staticmethod
    def _no_includes(text: str) -> None:
        lines = find_includes(text)
        if lines:
            raise WorkbenchError(
                f"Rule sets may not contain 'include' directives (line {lines[0]}): Snort would open the named file. "
                "Paste the rules into one self-contained file or rules_text.")

    def _tag_rules(self, res: EngineResult, ref: dict) -> None:
        if res.rules is not None:
            res.rules = {**res.rules, **ref}

    def _engine_ready(self) -> None:
        v = self.engine.version()
        if not v.available:
            raise WorkbenchError(f"Snort is not available: {v.detail}")

    # ---- case tools ----------------------------------------------------------
    def create_case(self, title: str) -> dict:
        if not title.strip():
            raise WorkbenchError("title is empty")
        self.store = CaseStore.create(self.cfg.case_dir, title.strip())
        return {"case_id": self.store.root.name, "path": str(self.store.root), "active": True}

    def open_case(self, case_id: str) -> dict:
        self.store = self._wrap(CaseStore.open, self.cfg.case_dir, case_id)
        return {"case_id": case_id, "active": True, **{k: v for k, v in self.store.summary(3).items()
                                                      if k in ("title", "status", "recent_runs")}}

    def list_cases(self) -> dict:
        return {"cases": CaseStore.list_cases(self.cfg.case_dir), "case_dir": str(self.cfg.case_dir),
                "active": self.store.root.name if self.store else None}

    def register_evidence(self, path: str, type: str | None = None, label: dict | None = None) -> dict:
        store = self._case()
        if type is not None and type not in EVIDENCE_TYPES:
            raise WorkbenchError(f"type must be one of {list(EVIDENCE_TYPES)} (or omitted to auto-detect)")
        if label is not None:
            ok = (isinstance(label, dict) and set(label) <= {"class", "technique"}
                  and all(isinstance(v, str) and len(v) <= 100 for v in label.values())
                  and label.get("class") in ("malicious", "benign"))
            if not ok:
                raise WorkbenchError("label must look like {\"class\": \"malicious\"|\"benign\", \"technique\": \"T1059.001\"}")
        p = self._wrap(resolve_read, path, self.roots, self.cfg.limits.max_input_bytes)
        fp = self._wrap(fingerprint, p, self.roots, self.cfg.limits.max_input_bytes)  # hashed from the open file, not by path
        return self._wrap(store.register_evidence, p, label, type, fp)

    def add_finding(self, statement: str, run_ids: list[str], evidence_ids: list[str] | None = None) -> dict:
        return self._wrap(self._case().add_finding, statement, run_ids, evidence_ids or [])

    def update_finding(self, finding_id: str, status: str | None = None, statement: str | None = None) -> dict:
        return self._wrap(self._case().update_finding, finding_id, status, statement)

    def add_note(self, text: str) -> dict:
        return self._wrap(self._case().add_note, text, "client")

    def update_case(self, summary: str | None = None, status: str | None = None) -> dict:
        return self._wrap(self._case().update_case, summary, status)

    def get_case(self) -> dict:
        return self._case().summary(recent_runs=10)

    def export_case(self, format: str = "markdown", path: str | None = None, overwrite: bool = False) -> dict:
        store = self._case()
        target = None
        if path:
            protected = {Path(e["path"]).resolve() for e in store.summary()["evidence"]}
            target = self._wrap(resolve_write, path, self.roots, overwrite, protected)
        try:
            out = write_export(store, format, target, overwrite=bool(target) and overwrite)
        except (ValueError, FileExistsError) as e:
            raise WorkbenchError(str(e)) from None
        return {"path": str(out), "format": format}

    # ---- status ------------------------------------------------------------------
    def get_status(self) -> dict:
        lim = self.cfg.limits
        return {
            "engines": [self.engine.status()],
            "allowed_roots": [str(r) for r in self.cfg.allowed_roots], "case_dir": str(self.cfg.case_dir),
            "limits": vars(lim), "offline_only": True,
            "active_case": self.store.root.name if self.store else None,
            "hint": None if self.cfg.allowed_roots else
            "allowed_roots is empty: only files inside the case directory can be registered. Add directories in config.toml.",
        }

    # ---- pcap summary ------------------------------------------------------------------
    def pcap_summary(self, evidence_id: str) -> dict:
        store = self._case()
        ev = self._evidence(evidence_id, {"pcap", "pcapng"})
        rid, run_dir = store.allocate_run()
        try:
            with self._staged(ev, run_dir, self._capture_name(ev)) as staged:
                data = self._wrap(summarize, staged)
        except BaseException:
            shutil.rmtree(run_dir, ignore_errors=True)
            raise
        (run_dir / "results" / "summary.json").write_text(json.dumps(data, indent=2) + "\n")
        t = now()
        store.record_run({"id": rid, "kind": "summary", "engine": "dpkt", "engine_version": None, "backend": "native",
                          "argv": [], "inputs": [{"evidence_id": evidence_id, "sha256": ev["sha256"], "mount": "pcap"}],
                          "rules": None, "config": None, "started": t, "finished": t, "duration_s": 0.0,
                          "exit_code": 0, "timed_out": False, "status": "ok", "error_excerpt": "",
                          "results": {"summary": "results/summary.json"}, "totals": {"packets": data["packets"]},
                          "parent_run": None})
        return {"run_id": rid, "evidence_id": evidence_id, **data}

    # ---- validate / run ------------------------------------------------------------------
    def validate_rules(self, rules_id: str | None = None, rules_text: str | None = None) -> dict:
        store = self._case()
        self._engine_ready()
        text, ref, inputs = self._rules(rules_id, rules_text)
        def work(ctx):
            res = self.engine.validate(ctx, text)
            self._tag_rules(res, ref)
            return res

        rid, res = self._wrap(run_recorded, store, self.engine, "validate", work, inputs)
        out = {"run_id": rid, "status": res.status, **res.payload}
        if res.error_excerpt:
            out["error_excerpt"] = res.error_excerpt
        return out

    def _do_run(self, kind: str, pcap_id: str, text: str, ref: dict, rinputs: list[dict], options: dict,
                parent: str | None = None) -> tuple[str, EngineResult]:
        store = self._case()
        self._engine_ready()
        ev = self._evidence(pcap_id, {"pcap", "pcapng"})
        inputs = [{"evidence_id": pcap_id, "sha256": ev["sha256"], "mount": "pcap"}] + rinputs

        def work(ctx):
            with self._staged(ev, ctx.run_dir, self._capture_name(ev)) as staged:
                res = self.engine.run(ctx, staged, text, options)
            self._tag_rules(res, ref)
            return res

        return run_recorded(store, self.engine, kind, work, inputs, parent_run=parent)

    def _run_payload(self, rid: str, res: EngineResult) -> dict:
        if res.status != "ok":
            return {"run_id": rid, "status": res.status, "error_excerpt": res.error_excerpt}
        s, cap = res.payload, self.cfg.limits.max_alerts_returned
        first = self._read_alerts(rid, cap)[0]
        out = {"run_id": rid, "status": "ok", "total_alerts": s["total"], "truncated_at_parse_limit": s["truncated"],
               "by_sid": [{k: r[k] for k in ("gid", "sid", "rev", "msg", "count", "distinct_sources",
                                              "distinct_destinations")} for r in s["by_sid"][:MAX_SID_ROWS]],
               "sids_total": len(s["by_sid"]),
               "first_alerts": first, "first_alerts_note": f"first {len(first)} of {s['total']} (use get_alerts to page)",
               "stream_caveats": s["stream_caveats"]}
        return out

    def run_pcap(self, pcap_id: str, rules_id: str | None = None, rules_text: str | None = None,
                 home_net: str | None = None, external_net: str | None = None, flush_one_sided: bool = False,
                 profile: bool = False) -> dict:
        text, ref, rinputs = self._rules(rules_id, rules_text)
        opts = {"home_net": home_net, "external_net": external_net, "flush_one_sided": flush_one_sided,
                "profile": profile, "filters": []}
        rid, res = self._wrap(self._do_run, "run", pcap_id, text, ref, rinputs, opts)
        return self._run_payload(rid, res)

    # ---- alerts ----------------------------------------------------------------------------
    def _run_files(self, run_id: str) -> tuple[dict, Path]:
        store = self._case()
        run = self._wrap(store.get_run, run_id)
        rel = (run.get("results") or {}).get("alerts")
        if not rel:
            raise WorkbenchError(f"{run_id} ({run['kind']}) has no alerts")
        return run, store.root / "runs" / run_id / rel

    @staticmethod
    def _iter_jsonl(path: Path):
        """Stream a results file line by line; large alert files are never read into memory whole."""
        with path.open() as fh:
            for line in fh:
                if line.strip():
                    yield json.loads(line)

    def _read_alerts(self, run_id: str, limit: int, offset: int = 0, sid: int | None = None, src: str | None = None,
                     dst: str | None = None, pkt_from: int | None = None, pkt_to: int | None = None):
        _, f = self._run_files(run_id)
        out, matched = [], 0
        for a in self._iter_jsonl(f):
            if sid is not None and a["sid"] != sid:
                continue
            if src and a["src_ip"] != src:
                continue
            if dst and a["dst_ip"] != dst:
                continue
            if pkt_from is not None and a["pkt_num"] < pkt_from:
                continue
            if pkt_to is not None and a["pkt_num"] > pkt_to:
                continue
            matched += 1
            if matched > offset and len(out) < limit:
                a.pop("b64_data", None)
                out.append(a)
        return out, matched

    def get_alerts(self, run_id: str, sid: int | None = None, src: str | None = None, dst: str | None = None,
                   pkt_from: int | None = None, pkt_to: int | None = None, offset: int = 0, limit: int = 50) -> dict:
        limit = max(1, min(limit, self.cfg.limits.max_alerts_returned))
        alerts, matched = self._read_alerts(run_id, limit, max(0, offset), sid, src, dst, pkt_from, pkt_to)
        return {"run_id": run_id, "matched": matched, "returned": len(alerts), "offset": offset, "alerts": alerts,
                "more": matched > offset + len(alerts)}

    def explain_alert(self, run_id: str, alert_idx: int) -> dict:
        store = self._case()
        run, f = self._run_files(run_id)
        alert = None
        for a in self._iter_jsonl(f):
            if a["alert_idx"] == alert_idx:
                alert = a
                break
        if alert is None:
            raise WorkbenchError(f"{run_id} has no alert_idx {alert_idx}")
        pcap_in = next((i for i in run["inputs"] if i["mount"] == "pcap"), None)
        if not pcap_in:
            raise WorkbenchError(f"{run_id} has no pcap input")
        ev = self._evidence(pcap_in["evidence_id"], {"pcap", "pcapng"})
        rules_text = (store.root / "runs" / run_id / "cfg" / "rules.rules").read_text(errors="replace")
        rule = find_rule(rules_text, alert["gid"], alert["sid"])
        with self._staged(ev, store.root, self._capture_name(ev)) as pcap:
            return self._wrap(_explain, rule, alert, pcap, self.cfg.limits.payload_display_bytes)

    # ---- profiling / tuning ------------------------------------------------------------------
    def profile_rules(self, pcap_id: str, rules_id: str | None = None, rules_text: str | None = None, top: int = 20) -> dict:
        text, ref, rinputs = self._rules(rules_id, rules_text)
        opts = {"profile": True, "filters": []}
        rid, res = self._wrap(self._do_run, "profile", pcap_id, text, ref, rinputs, opts)
        if res.status != "ok":
            return {"run_id": rid, "status": res.status, "error_excerpt": res.error_excerpt}
        prof = json.loads((self._case().root / "runs" / rid / res.results["profile"]).read_text())
        msgs = {(1, r.sid): r.msg for r in parse_rules(text)}
        rows = [{**r, "msg": msgs.get((r["gid"], r["sid"]))} for r in prof["rules"][:max(1, top)]]
        return {"run_id": rid, "status": "ok", "slowest": rows, "rules_profiled": len(prof["rules"]),
                "unresolved_rows": prof["unresolved_rows"], "total_alerts": res.payload["total"],
                "stream_caveats": res.payload["stream_caveats"]}

    def suggest_tuning_targets(self, run_id: str, top: int = 10) -> dict:
        run, _ = self._run_files(run_id)
        summary = json.loads((self._case().root / "runs" / run_id / run["results"]["summary"]).read_text())
        rows = []
        for r in summary["by_sid"][:max(1, top)]:
            hint = []
            if r["top_source_share"] >= 0.8 and r["count"] >= 20:
                hint.append(f"{r['top_source_share']:.0%} of hits come from {r['top_source']}")
            if r["distinct_sources"] >= 20:
                hint.append("many distinct sources: the rule is probably too broad")
            rows.append({"gid": r["gid"], "sid": r["sid"], "msg": r["msg"], "count": r["count"],
                         "distinct_sources": r["distinct_sources"], "distinct_destinations": r["distinct_destinations"],
                         "top_source": r["top_source"], "top_source_share": r["top_source_share"],
                         "observations": hint})
        return {"run_id": run_id, "total_alerts": summary["total"], "targets": rows,
                "note": "Ranked by count. One capture is one sample; prove any change with test_tuning."}

    def test_tuning(self, before_run_id: str, change: dict, reason: str) -> dict:
        store = self._case()
        before = self._wrap(store.get_run, before_run_id)
        if before["kind"] not in ("run", "profile", "tuning") or before["status"] != "ok":
            raise WorkbenchError(f"{before_run_id} is not a successful pcap run")
        pcap_in = next(i for i in before["inputs"] if i["mount"] == "pcap")
        rules_text = (store.root / "runs" / before_run_id / "cfg" / "rules.rules").read_text(errors="replace")
        opts = dict(before["config"]["options"])
        kind = change.get("kind")
        new_text, filters = rules_text, list(opts.get("filters") or [])
        if kind in FILTER_TYPES:
            self._wrap(render_filter, change)  # validate before running anything
            filters.append(change)
        elif kind == "rule_edit":
            sid, new_rule = change.get("sid"), change.get("rule")
            if not isinstance(sid, int) or not isinstance(new_rule, str) or len(new_rule.strip().splitlines()) != 1:
                raise WorkbenchError("rule_edit needs integer 'sid' and a single-line 'rule' string")
            target = find_rule(rules_text, 1, sid)
            if target is None:
                raise WorkbenchError(f"sid {sid} is not in the rule set of {before_run_id}")
            lines = rules_text.splitlines()
            lines[target.line - 1] = new_rule.strip()
            new_text = "\n".join(lines) + "\n"
        else:
            raise WorkbenchError(f"change.kind must be one of {list(FILTER_TYPES) + ['rule_edit']}")
        self._engine_ready()
        if new_text != rules_text:
            v = self.validate_rules(rules_text=new_text)
            if not v["ok"]:
                return {"applied": False, "reason": "the edited rule set does not validate", "validation": v}
        opts["filters"] = filters
        self._evidence(pcap_in["evidence_id"], {"pcap", "pcapng"})
        ref = {"source": "derived", "parent_run": before_run_id}
        rid, res = self._wrap(self._do_run, "tuning", pcap_in["evidence_id"], new_text, ref, [], opts, before_run_id)
        if res.status != "ok":
            return {"applied": False, "run_id": rid, "status": res.status, "error_excerpt": res.error_excerpt}
        b_sum = json.loads((store.root / "runs" / before_run_id / before["results"]["summary"]).read_text())
        a_sum = res.payload
        bc = {str(r["sid"]): r["count"] for r in b_sum["by_sid"]}
        ac = {str(r["sid"]): r["count"] for r in a_sum["by_sid"]}
        full = {sid: {"before": bc.get(sid, 0), "after": ac.get(sid, 0)} for sid in sorted(set(bc) | set(ac), key=int)}
        target_sid = str(change.get("sid"))
        collateral = [sid for sid, c in full.items() if sid != target_sid and c["before"] != c["after"]]
        counts, omitted = self._trim_counts(full, target_sid)
        decision = store.add_decision(kind, change, reason, before_run_id, rid, counts, counts_omitted=omitted)
        if kind == "rule_edit":
            old_rule = find_rule(rules_text, 1, change["sid"])
            d = tuning_changes.rule_diff(old_rule.text if old_rule else None, change["rule"])
            review = {"kind": "rule_edit", "diff": d["lines"], "checks": d["checks"]}
        else:
            review = {"kind": kind, "config_entry": tuning_changes.filter_snippet(change)}
        return {"applied": True, "decision_id": decision["id"], "before_run": before_run_id, "after_run": rid,
                "counts": counts, "counts_omitted": omitted, "total": {"before": b_sum["total"], "after": a_sum["total"]},
                "review": review, "other_sids_changed": collateral[:MAX_SID_ROWS], "other_sids_changed_total": len(collateral),
                "note": "Check that the alerts you want to keep (use get_alerts on the after run) still fire. "
                        "The decision is recorded as 'proposed'; only the analyst accepts or rejects it (update_decision).",
                "stream_caveats": a_sum["stream_caveats"]}

    def update_decision(self, decision_id: str, status: str) -> dict:
        """Record the analyst's decision on a tested change: accepted, rejected, or back to proposed."""
        d = self._wrap(self._case().update_decision, decision_id, status)
        return {"decision_id": d["id"], "kind": d["kind"], "status": d["status"], "history": d.get("history", []),
                "next": "export_tuning gives the rule or config text to apply" if d["status"] == "accepted" else None}

    def export_tuning(self, decision_ids: list[str] | None = None, path_prefix: str | None = None, overwrite: bool = False,
                      include_unaccepted: bool = False) -> dict:
        """Accepted tuning changes as text to apply: a rules fragment and a config snippet (optionally written to files)."""
        store = self._case()
        every = store.summary()["decisions"]
        if decision_ids:
            by_id = {d["id"]: d for d in every}
            missing = [i for i in decision_ids if i not in by_id]
            if missing:
                raise WorkbenchError(f"unknown decision(s): {', '.join(missing)}")
            chosen = [by_id[i] for i in decision_ids]
            pending = [d["id"] for d in chosen if d["status"] != "accepted"]
            if pending and not include_unaccepted:
                raise WorkbenchError(f"{', '.join(pending)} not accepted yet. Accept with update_decision once the analyst agrees, "
                                     "or pass include_unaccepted=true to preview.")
        else:
            chosen = [d for d in every if d["status"] == "accepted"]
            if not chosen:
                raise WorkbenchError("No accepted decisions to export. Accept one with update_decision after the analyst agrees.")
        built = tuning_changes.build_export(chosen)
        written = []
        if path_prefix:
            protected = {Path(e["path"]).resolve() for e in store.summary()["evidence"]}
            parts = [(".rules", built["rules"]), (".lua", built["config"])]
            targets = [(self._wrap(resolve_write, f"{path_prefix}{ext}", self.roots, overwrite, protected), text)
                       for ext, text in parts if text]
            for target, text in targets:  # every path is vetted before the first file is written
                try:
                    write_text_safely(target, text, overwrite)
                except FileExistsError:
                    raise WorkbenchError(f"{target} appeared while writing; nothing further was written") from None
                except PathError as e:
                    raise WorkbenchError(str(e)) from None
                written.append(str(target))
            store.log_event("export.written", Path(written[0]).name if written else "tuning", {"format": "tuning", "paths": written})
        unaccepted = [d["id"] for d in chosen if d["status"] != "accepted"]
        return {"decisions": built["included"], "rules": built["rules"][:50_000], "config": built["config"][:50_000],
                "written": written, "skipped": built["skipped"],
                "warning": f"{', '.join(unaccepted)} not accepted yet; this is a preview." if unaccepted else None,
                "how_to_apply": ["Replace the rules with the same sid in your rules file, then run validate_rules on the result.",
                                 "Merge each config table into the table of the same name in snort.lua."]}

    @staticmethod
    def _trim_counts(full: dict, target_sid: str) -> tuple[dict, int]:
        """Keep every changed SID, the target and the busiest unchanged ones; report how many unchanged rows were left out."""
        if len(full) <= MAX_DECISION_COUNTS:
            return full, 0
        keep = {sid for sid, c in full.items() if c["before"] != c["after"]} | {target_sid}
        room = max(0, MAX_DECISION_COUNTS - len(keep))
        unchanged = sorted((sid for sid in full if sid not in keep), key=lambda s: -full[s]["before"])
        keep |= set(unchanged[:room])
        return {sid: full[sid] for sid in sorted(keep, key=int) if sid in full}, len(full) - len(keep)

    def diff_runs(self, run_a: str, run_b: str, sample: int = 20) -> dict:
        """Alerts added, removed and changed between two runs. Alerts are matched on (gid, sid, packet, 5-tuple); only a
        compact record per alert is held, so memory stays proportional to the alert count, not the alert size."""
        fields = ("rev", "msg", "class", "priority")

        def load(rid):
            _, f = self._run_files(rid)
            total, seen = 0, {}
            for a in self._iter_jsonl(f):
                total += 1
                seen.setdefault((a["gid"], a["sid"], a["pkt_num"], a["src_ip"], a["src_port"], a["dst_ip"], a["dst_port"]),
                                tuple(a[x] for x in fields))
            return total, seen

        na, A = load(run_a)
        nb, B = load(run_b)
        added, removed = B.keys() - A.keys(), A.keys() - B.keys()
        changed = [k for k in A.keys() & B.keys() if A[k] != B[k]]

        def per_sid(keys):
            return [{"sid": s, "count": n} for s, n in Counter(k[1] for k in keys).most_common(MAX_SID_ROWS)]

        def brief(k, values):
            return {"sid": k[1], "pkt_num": k[2], "src_ip": k[3], "src_port": k[4], "dst_ip": k[5], "dst_port": k[6],
                    "msg": values[k][1]}

        def sampled(keys):
            return sorted(keys, key=lambda k: (k[2], k[1]))[:sample]

        return {"run_a": run_a, "run_b": run_b, "totals": {"a": na, "b": nb},
                "added": {"count": len(added), "by_sid": per_sid(added), "sample": [brief(k, B) for k in sampled(added)]},
                "removed": {"count": len(removed), "by_sid": per_sid(removed), "sample": [brief(k, A) for k in sampled(removed)]},
                "changed": {"count": len(changed),
                            "sample": [{"sid": k[1], "pkt_num": k[2], "from": dict(zip(fields, A[k], strict=True)),
                                        "to": dict(zip(fields, B[k], strict=True))} for k in sampled(changed)]}}

    # ---- rules files ------------------------------------------------------------------------------
    def write_rules_file(self, path: str, rules_text: str, overwrite: bool = False) -> dict:
        if len(rules_text.encode()) > self.cfg.limits.max_rules_bytes:
            raise WorkbenchError("rules_text is larger than max_rules_bytes")
        protected = ({Path(e["path"]).resolve() for e in self.store.summary()["evidence"]}
                     if self.store and overwrite else None)
        # Vet the location before touching the file: anything outside the allowed roots is refused
        # without being read, so a diff can never reveal a file the server may not read.
        target = self._wrap(resolve_write, path, self.roots, True, protected)
        if os.path.lexists(target) and not overwrite:
            # opened without following links and re-checked against the roots: a link that appeared after the
            # vetting above must not turn this diff into a way to read another file
            old = self._wrap(read_checked, target, self.roots, self.cfg.limits.max_rules_bytes).decode(errors="replace")
            diff = "".join(difflib.unified_diff(old.splitlines(True), rules_text.splitlines(True),
                                                str(target), "proposed", n=2))
            return {"written": False, "reason": f"{target} already exists; nothing was changed. "
                    "Choose a new name, or pass overwrite=true if you really mean to replace it.",
                    "diff": diff[:20000] or "(identical)"}
        try:
            write_text_safely(target, rules_text if rules_text.endswith("\n") else rules_text + "\n", overwrite)
        except FileExistsError:
            raise WorkbenchError(f"{target} appeared while writing; nothing was changed") from None
        except PathError as e:
            raise WorkbenchError(str(e)) from None
        return {"written": True, "path": str(target)}

    def convert_snort2(self, evidence_id: str) -> dict:
        store = self._case()
        self._engine_ready()
        if not self.engine.has_snort2lua():
            raise WorkbenchError("snort2lua is not available with this Snort install.")
        ev = self._evidence(evidence_id, {"rules", "log"})

        def work(ctx):
            suffix = Path(ev["path"]).suffix
            safe = suffix if re.fullmatch(r"\.[A-Za-z0-9]{1,8}", suffix) else ".conf"
            with self._staged(ev, ctx.run_dir, "source" + safe, self.cfg.limits.max_rules_bytes) as staged:
                return self.engine.convert(ctx, staged)

        rid, res = self._wrap(run_recorded, store, self.engine, "convert", work,
                              [{"evidence_id": evidence_id, "sha256": ev["sha256"], "mount": "source"}])
        run_dir = store.root / "runs" / rid
        out = run_dir / "out"
        converted = out / "converted.rules"
        text = converted.read_text(errors="replace") if converted.exists() else ""
        errs = out / "convert_errors.txt"
        return {"run_id": rid, "status": res.status, "converted_rules": text[:50000],
                "converted_rules_path": str(converted) if converted.exists() else None,
                "lua_config_path": str(out / "converted.lua") if (out / "converted.lua").exists() else None,
                "conversion_notes": errs.read_text(errors="replace")[:4000] if errs.exists() else "",
                "error_excerpt": res.error_excerpt,
                "note": "Converted output lives in the run directory. Review it, validate it with validate_rules, "
                        "then save with write_rules_file."}
