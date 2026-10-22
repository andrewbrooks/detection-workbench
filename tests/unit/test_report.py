"""update_case and the Markdown report's analysis sections (no Snort needed)."""
import json

import pytest

from detection_workbench.case.export import MAX_TIMELINE, export_markdown
from detection_workbench.case.model import MAX_SUMMARY_CHARS
from detection_workbench.case.store import CaseError, CaseStore


@pytest.fixture
def store(tmp_path):
    return CaseStore.create(tmp_path / "cases", "Report test")


def add_run(store, kind="run", summary=None, **extra):
    rid, d = store.allocate_run()
    results = {}
    if summary is not None:
        (d / "results" / "summary.json").write_text(json.dumps(summary))
        results["summary"] = "results/summary.json"
    doc = {"id": rid, "kind": kind, "engine": "snort", "engine_version": "3.10.0.0", "backend": "docker",
           "status": "ok", "results": results, "inputs": [], "rules": None, "totals": {}, **extra}
    store.record_run(doc)
    return rid


def sid_row(sid, msg, count, sources=3, top="10.0.0.1", share=0.9):
    return {"gid": 1, "sid": sid, "rev": 1, "msg": msg, "count": count, "distinct_sources": sources,
            "distinct_destinations": 1, "top_source": top, "top_source_share": share}


# ---- update_case ---------------------------------------------------------------
def test_update_case_sets_summary_and_status_and_logs(store):
    out = store.update_case(summary="Rule is too broad (f-0001).", status="closed")
    assert out["status"] == "closed" and set(out["changed"]) == {"summary_chars", "status"}
    s = store.summary()
    assert s["summary"] == "Rule is too broad (f-0001)." and s["status"] == "closed"
    ev = [e for e in store.events() if e["type"] == "case.updated"]
    assert len(ev) == 1 and ev[0]["data"] == {"summary_chars": 27, "status": "closed"}


def test_update_case_is_idempotent_and_partial(store):
    store.update_case(summary="a")
    assert store.update_case(summary="a")["changed"] == []
    assert store.update_case(status="closed")["summary"] == "a"
    assert len([e for e in store.events() if e["type"] == "case.updated"]) == 2


def test_update_case_validation(store):
    for kwargs in ({}, {"status": "archived"}, {"summary": "x" * (MAX_SUMMARY_CHARS + 1)}):
        with pytest.raises(CaseError):
            store.update_case(**kwargs)
    store.update_case(summary="x" * MAX_SUMMARY_CHARS)


# ---- report ------------------------------------------------------------------------
def test_empty_case_report_is_honest(store):
    md = export_markdown(store)
    assert "_No analyst summary was recorded for this case._" in md and "_No engine runs recorded._" in md
    assert "One capture is one sample" in md and "case.created" in md


def test_summary_comes_first_and_status_shows(store):
    store.update_case(summary="**Conclusion:** fix the rule.", status="closed")
    md = export_markdown(store)
    assert md.index("## Summary") < md.index("**Conclusion:** fix the rule.") < md.index("## Overview")
    assert "status **closed**" in md and "case.updated" in md


def test_results_by_run_table_and_overflow(store):
    rows = [sid_row(1000000 + i, f"rule {i}", 100 - i) for i in range(12)]
    rid = add_run(store, summary={"total": 1234, "truncated": False, "by_sid": rows, "stream_caveats": {}})
    md = export_markdown(store)
    assert f"### {rid} — run" in md and "1234 alerts" in md
    assert "| 1000000 | rule 0 | 100 | ██████████ | 3 | 10.0.0.1 (90%) |" in md
    assert "1000009" in md and "1000010" not in md  # top 10 only
    assert f"…and 2 more SIDs in `runs/{rid}/results/summary.json`" in md


def test_tuning_run_shows_parent_and_truncation(store):
    a = add_run(store, summary={"total": 5, "by_sid": [], "stream_caveats": {}})
    b = add_run(store, kind="tuning", parent_run=a, summary={"total": 2, "truncated": True, "by_sid": [], "stream_caveats": {}})
    md = export_markdown(store)
    assert f"### {b} — tuning · parent `{a}`" in md
    assert "2 alerts · status ok · **truncated at the parse limit**" in md
    assert f"**{b}:** alerts were truncated at the parse limit" in md


def test_stream_caveats_surface(store):
    caveat = {"tcp_flows": 5, "unacked_flows": 4, "one_sided_flows": 1, "explanation": "Service rules can miss here."}
    rid = add_run(store, summary={"total": 1, "by_sid": [sid_row(1, "x", 1)], "stream_caveats": caveat})
    clean = add_run(store, summary={"total": 1, "by_sid": [], "stream_caveats": {"tcp_flows": 2, "unacked_flows": 0}})
    md = export_markdown(store)
    cav = md[md.index("## Caveats"):md.index("## Timeline")]
    assert f"**{rid}:** 4 of 5 TCP flows carried data the peer never ACKed (1 one-sided). Service rules can miss here." in cav
    assert clean not in cav


def test_failed_run_and_proposed_decision_caveats(store):
    ok = add_run(store, summary={"total": 1, "by_sid": [], "stream_caveats": {}})
    bad = add_run(store, status="error", error_excerpt="boom: could not start")
    store.add_decision("suppress", {"sid": 1}, "r", ok, ok, {"1": {"before": 2, "after": 1}})
    md = export_markdown(store)
    assert f"**{bad}** (run) finished with status `error`: boom: could not start" in md
    assert "Decisions marked `proposed`" in md


def test_validate_run_listed(store):
    add_run(store, kind="validate", summary={"ok": False, "errors": [{"line": 2, "sid": 7, "plain": "bad option"}],
                                              "warnings": [], "lint": [{}]})
    md = export_markdown(store)
    assert "— validate: not ok (1 error, 0 warnings, 1 lint note)" in md and "- line 2, sid 7: bad option" in md


def test_overview_captures_engines_and_rule_sets(store):
    add_run(store, kind="summary", engine="dpkt", engine_version=None, backend="native",
            inputs=[{"evidence_id": "e-0001"}],
            summary={"packets": 13, "first_packet": "2023-11-14T22:13:20Z", "last_packet": "2023-11-14T22:13:20.12Z",
                     "protocols": {"TCP": 11, "UDP": 2}})
    a = add_run(store, summary={"total": 0, "by_sid": [], "stream_caveats": {}},
                rules={"source": "evidence", "evidence_id": "e-0002", "sha256": "ab" * 32})
    b = add_run(store, kind="tuning", parent_run=a, summary={"total": 0, "by_sid": [], "stream_caveats": {}},
                rules={"source": "derived", "parent_run": a, "sha256": "cd" * 32})
    md = export_markdown(store)
    ov = md[md.index("## Overview"):md.index("## Evidence")]
    assert "| e-0001 | 13 | 2023-11-14T22:13:20Z |" in ov and "TCP 11, UDP 2" in ov
    assert "**Engines:** snort 3.10.0.0 (docker)" in ov and "dpkt" not in ov.split("**Engines:**")[1].splitlines()[0]
    assert f"| e-0002 | {'ab' * 8}… | {a} |" in ov and f"| derived from {a} | {'cd' * 8}… | {b} |" in ov


def test_timeline_lists_events_in_order_and_caps(store):
    for i in range(MAX_TIMELINE + 10):
        store.add_note(f"n{i}")
    md = export_markdown(store)
    tl = md[md.index("## Timeline"):md.index("## Notes")]
    assert "| case.created |" in tl and tl.index("case.created") < tl.index("note.added")
    assert "11 more events in `events.jsonl`" in tl


def test_missing_or_corrupt_result_files_do_not_break_the_report(store):
    rid = add_run(store, summary={"total": 1, "by_sid": [], "stream_caveats": {}})
    (store.root / "runs" / rid / "results" / "summary.json").write_text("{not json")
    assert f"### {rid} — run" in export_markdown(store)


def test_identical_rule_set_hash_is_one_row_with_all_origins(store):
    sha = "ef" * 32
    a = add_run(store, kind="validate", summary={"ok": True}, rules={"source": "evidence", "evidence_id": "e-0002", "sha256": sha})
    b = add_run(store, summary={"total": 0, "by_sid": [], "stream_caveats": {}},
                rules={"source": "evidence", "evidence_id": "e-0002", "sha256": sha})
    c = add_run(store, kind="tuning", parent_run=b, summary={"total": 0, "by_sid": [], "stream_caveats": {}},
                rules={"source": "derived", "parent_run": b, "sha256": sha})
    ov = export_markdown(store)
    ov = ov[ov.index("**Rule sets**"):ov.index("## Evidence")]
    assert ov.count(f"{'ef' * 8}…") == 1 and f"| e-0002 · derived from {b} | {'ef' * 8}… | {a}, {b}, {c} |" in ov


# ---- bars, change column, headline --------------------------------------------------------
def test_bars_scale_to_the_largest_row_and_never_hide_a_nonzero_count():
    from detection_workbench.case.export import BAR_WIDTH, _bar
    assert _bar(100, 100) == "█" * BAR_WIDTH and _bar(50, 100) == "█████░░░░░"
    assert _bar(1, 1000) == "█" + "░" * (BAR_WIDTH - 1)  # tiny but non-zero still shows
    assert _bar(0, 100) == "░" * BAR_WIDTH and _bar(5, 0) == "░" * BAR_WIDTH
    assert all(len(_bar(v, 7)) == BAR_WIDTH for v in range(8))


def test_report_table_has_a_bar_per_row(store):
    rows = [sid_row(1, "big", 300), sid_row(2, "small", 3)]
    add_run(store, summary={"total": 303, "by_sid": rows, "stream_caveats": {}})
    md = export_markdown(store)
    assert "| 1 | big | 300 | ██████████ |" in md and "| 2 | small | 3 | █░░░░░░░░░ |" in md and "| volume |" in md


@pytest.mark.parametrize("before,after,text", [(315, 15, "−95%"), (6, 1, "−83%"), (4, 4, "no change"),
                                               (0, 3, "+3 (new)"), (2, 3, "+50%"), (5, 0, "−100%")])
def test_change_column(before, after, text):
    from detection_workbench.case.export import _change
    assert _change(before, after) == text


def test_headline_summarises_the_case(store):
    base = add_run(store, summary={"total": 320, "by_sid": [sid_row(7, "a", 315), sid_row(8, "b", 5)], "stream_caveats": {}})
    tune = add_run(store, kind="tuning", parent_run=base,
                   summary={"total": 1000, "by_sid": [sid_row(9, "huge-but-hypothetical", 999)], "stream_caveats": {}})
    f = store.add_finding("one", [base], [])
    store.add_finding("two", [base], [])
    store.update_finding(f["id"], status="confirmed")
    store.add_decision("suppress", {"sid": 7}, "r", base, tune, {"7": {"before": 315, "after": 15}})
    line = next(line for line in export_markdown(store).splitlines() if line.startswith("> **At a glance:**"))
    assert "2 engine runs" in line and "2 findings (1 confirmed, 1 open)" in line and "1 decision (1 proposed)" in line
    assert "noisiest SID: 7 (315 alerts in r-0001)" in line  # the tuning run's 999 is a what-if and is ignored


def test_headline_on_an_empty_case_and_position(store):
    md = export_markdown(store)
    assert "> **At a glance:** nothing recorded yet." in md
    assert md.index("At a glance") < md.index("## Summary")
    one = CaseStore.create(store.root.parent, "single")
    one.add_finding("only", [], [])
    assert "1 finding (1 open)" in export_markdown(one)


def test_decisions_table_shows_percentage_change(store):
    a = add_run(store, summary={"total": 1, "by_sid": [], "stream_caveats": {}})
    b = add_run(store, kind="tuning", parent_run=a, summary={"total": 1, "by_sid": [], "stream_caveats": {}})
    store.add_decision("suppress", {"sid": 1}, "why", a, b, {"1": {"before": 6, "after": 1}, "2": {"before": 2, "after": 2}})
    md = export_markdown(store)
    assert "| 1 | 6 | 1 | −83% |" in md and "| 2 | 2 | 2 | no change |" in md


def test_bars_share_one_scale_across_runs(store):
    base = add_run(store, summary={"total": 6, "by_sid": [sid_row(3, "syn", 6)], "stream_caveats": {}})
    add_run(store, kind="tuning", parent_run=base, summary={"total": 1, "by_sid": [sid_row(3, "syn", 1)], "stream_caveats": {}})
    md = export_markdown(store)
    assert "| 3 | syn | 6 | ██████████ |" in md
    assert "| 3 | syn | 1 | ██░░░░░░░░ |" in md  # 1 of the report-wide peak of 6, not a full-looking bar of its own
