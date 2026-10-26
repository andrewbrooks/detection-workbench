"""Rule diffs, config entries, accept/reject, and the exported rules/config text."""
import pytest

from detection_workbench.case.export import export_markdown
from detection_workbench.case.store import CaseError, CaseStore
from detection_workbench.config import Config
from detection_workbench.engines.snort.changes import (
    MAX_COMMENT,
    MAX_DIFF_LINES,
    MAX_LINE,
    build_export,
    checks_text,
    comment_text,
    filter_snippet,
    rule_checks,
    rule_diff,
)
from detection_workbench.engines.snort.config_gen import TuningError
from detection_workbench.engines.snort.rules import parse_rule
from detection_workbench.workbench import Workbench, WorkbenchError

OLD = ('alert http any any -> any any ( msg:"LOCAL noisy GET anything"; flow:to_server,established; http_method; '
       'content:"GET"; sid:1000042; rev:1; classtype:web-application-activity; )')
NEW = ('alert http any any -> any any ( msg:"LOCAL GET to /download"; flow:to_server,established; http_uri; '
       'content:"/download/",fast_pattern; sid:1000042; rev:2; classtype:web-application-activity; )')


# ---- rule_diff ------------------------------------------------------------------------------
def test_diff_is_option_by_option_with_unchanged_context():
    d = rule_diff(OLD, NEW)
    assert d["granularity"] == "option"
    assert d["lines"] == [
        "  alert http any any -> any any",
        '- msg:"LOCAL noisy GET anything"', '+ msg:"LOCAL GET to /download"',
        "  flow:to_server,established",
        "- http_method", '- content:"GET"', "+ http_uri", '+ content:"/download/",fast_pattern',
        "  sid:1000042",
        "- rev:1", "+ rev:2",
        "  classtype:web-application-activity",
    ]
    assert [c["level"] for c in d["checks"]] == ["ok", "ok", "ok"]
    assert checks_text(d["checks"]) == "sid unchanged · rev bumped (1 → 2) · has an explicit fast pattern"


def test_header_changes_are_shown_as_a_replaced_line():
    d = rule_diff(OLD, NEW.replace("alert http any any -> any any", "alert tcp any any -> any 80"))
    assert d["lines"][:2] == ["- alert http any any -> any any", "+ alert tcp any any -> any 80"]


def test_an_added_option_is_only_plus_lines():
    d = rule_diff(OLD, OLD.replace("sid:1000042;", "sid:1000042; detection_filter:track by_src,count 5,seconds 60;"))
    assert [x for x in d["lines"] if x[0] in "+-"] == ["+ detection_filter:track by_src,count 5,seconds 60"]


@pytest.mark.parametrize("new,level,text", [
    (OLD.replace('"GET"', '"POST"'), "warn", "rev not bumped (still 1)"),
    (NEW.replace("rev:2", "rev:0"), "warn", "rev lowered (1 → 0)"),
    (NEW.replace("sid:1000042", "sid:1000043"), "warn", "sid changed"),
    (OLD, "warn", "identical to before"),
    (NEW.replace(" rev:2;", ""), "warn", "rev is missing"),
    (NEW.replace('content:"/download/",fast_pattern;', ""), "warn", "no positive content"),
])
def test_rule_checks_flag_the_usual_mistakes(new, level, text):
    checks = rule_checks(parse_rule(OLD), parse_rule(new))
    assert any(c["level"] == level and text in c["text"] for c in checks), checks


def test_warnings_are_bold_in_the_report_line():
    line = checks_text(rule_checks(parse_rule(OLD), parse_rule(OLD.replace('"GET"', '"POST"'))))
    assert "**warning:** rev not bumped (still 1)" in line and line.startswith("sid unchanged")


def test_unparseable_or_missing_old_rule_falls_back_to_plain_lines():
    assert rule_diff(None, NEW) == {"lines": [f"+ {NEW}"], "granularity": "line", "checks": []}
    d = rule_diff("this is not a rule", NEW)
    assert d["granularity"] == "line" and d["lines"][0] == "- this is not a rule" and d["checks"] == []
    assert rule_diff(OLD, "garbage")["granularity"] == "line"


def test_diff_output_is_bounded():
    long_msg = 'msg:"' + "x" * 2000 + '"'
    d = rule_diff(OLD, OLD.replace('msg:"LOCAL noisy GET anything"', long_msg).replace("rev:1", "rev:2"))
    assert all(len(x) <= MAX_LINE for x in d["lines"]) and any(x.endswith("…") for x in d["lines"])
    many = "alert tcp any any -> any any ( " + " ".join(f"content:\"a{i}\";" for i in range(400)) + " sid:1; rev:1; )"
    d2 = rule_diff(many, many.replace("rev:1", "rev:2").replace('"a1"', '"b1"'))
    assert len(d2["lines"]) == MAX_DIFF_LINES + 1 and d2["lines"][-1].startswith("  … ")


# ---- config entries -------------------------------------------------------------------------
def test_filter_snippets():
    assert filter_snippet({"kind": "suppress", "sid": 7, "track": "by_src", "ip": "10.0.0.1"}) == (
        "-- add this entry to the suppress table in snort.lua\n"
        "suppress = { { gid = 1, sid = 7, track = 'by_src', ip = '10.0.0.1' } }")
    assert "event_filter = { { gid = 1, sid = 1000003, type = 'limit', track = 'by_src', count = 1, seconds = 60 } }" in filter_snippet(
        {"kind": "event_filter", "sid": 1000003, "type": "limit", "track": "by_src", "count": 1, "seconds": 60})
    assert "rate_filter = {" in filter_snippet({"kind": "rate_filter", "sid": 1, "track": "by_rule", "count": 5, "seconds": 1,
                                                 "new_action": "drop", "timeout": 4})


@pytest.mark.parametrize("bad", [{"kind": "suppress", "sid": 7, "track": "by_src", "ip": "x'; os.execute('id') --"},
                                 {"kind": "suppress", "sid": "7", "track": "by_src", "ip": "10.0.0.1"}, {"kind": "nope", "sid": 1}])
def test_filter_snippets_go_through_the_validated_renderer(bad):
    with pytest.raises(TuningError):
        filter_snippet(bad)


# ---- comments cannot break out ------------------------------------------------------------------
def test_comment_text_is_one_safe_line():
    assert comment_text("known\nscanner\r\n  host") == "known scanner host"
    assert comment_text("a\x00b\x1bc\x7fd") == "a b c d"
    out = comment_text("y" * 1000)
    assert len(out) == MAX_COMMENT and out.endswith("…")


# ---- build_export -------------------------------------------------------------------------------
def dec(i, change, reason="why", status="accepted"):
    return {"id": f"d-{i:04d}", "change": change, "reason": reason, "status": status}


F1 = {"kind": "event_filter", "sid": 1000003, "type": "limit", "track": "by_src", "count": 1, "seconds": 60}
F2 = {"kind": "suppress", "sid": 1000042, "track": "by_src", "ip": "10.0.4.20"}
F3 = {"kind": "event_filter", "sid": 1000044, "type": "both", "track": "by_dst", "count": 3, "seconds": 10}


def test_export_groups_filters_by_table_and_collects_rules():
    out = build_export([dec(1, F1, "volume"), dec(2, {"kind": "rule_edit", "sid": 1000042, "rule": NEW}, "anchor path"),
                        dec(3, F2, "known scanner"), dec(4, F3)])
    assert out["included"] == ["d-0001", "d-0002", "d-0003", "d-0004"] and out["skipped"] == []
    assert out["rules"].splitlines() == [
        "# Detection Workbench: accepted rule changes. Replace the rule with the same sid in your rules file.",
        "# d-0002: anchor path", NEW]
    cfg = out["config"].splitlines()
    assert cfg[0].startswith("-- Detection Workbench") and "event_filter = {" in cfg and "suppress = {" in cfg
    assert cfg.index("event_filter = {") < cfg.index("suppress = {")  # tables in name order
    block = cfg[cfg.index("event_filter = {"):cfg.index("}", cfg.index("event_filter = {")) + 1]
    assert block[1:] == ["    -- d-0001: volume",
                         "    { gid = 1, sid = 1000003, type = 'limit', track = 'by_src', count = 1, seconds = 60 },",
                         "    -- d-0004: why",
                         "    { gid = 1, sid = 1000044, type = 'both', track = 'by_dst', count = 3, seconds = 10 },", "}"]


def test_latest_edit_for_a_sid_wins_and_the_earlier_one_is_reported():
    first, second = NEW, NEW.replace("rev:2", "rev:3")
    out = build_export([dec(1, {"kind": "rule_edit", "sid": 1000042, "rule": first}),
                        dec(2, {"kind": "rule_edit", "sid": 1000042, "rule": second})])
    assert second in out["rules"] and first not in out["rules"]
    assert out["skipped"] == ["d-0001: superseded by d-0002 (same sid 1000042)"]


def test_unusable_stored_changes_are_skipped_with_a_reason_not_exported():
    out = build_export([dec(1, {"kind": "suppress", "sid": 1, "track": "by_src", "ip": "x'; os.execute('id') --"}),
                        dec(2, {"kind": "rule_edit", "sid": 1, "rule": "not a rule"}),
                        dec(3, {"kind": "mystery"}), dec(4, {})])
    assert out["rules"] == out["config"] == "" and out["included"] == []
    assert len(out["skipped"]) == 4 and all(s.startswith("d-000") for s in out["skipped"])


def test_a_hostile_reason_cannot_add_rules_or_config_lines():
    evil = 'x\nalert tcp any any -> any any ( msg:"injected"; sid:9; rev:1; )\n-- and more\r\nos.execute("id")'
    out = build_export([dec(1, {"kind": "rule_edit", "sid": 1000042, "rule": NEW}, evil), dec(2, F1, evil)])
    rule_lines = [ln for ln in out["rules"].splitlines() if ln and not ln.startswith("#")]
    assert rule_lines == [NEW]
    code_lines = [ln for ln in out["config"].splitlines() if ln.strip() and not ln.strip().startswith("--")]
    assert code_lines == ["event_filter = {", "    { gid = 1, sid = 1000003, type = 'limit', track = 'by_src', count = 1, seconds = 60 },", "}"]


def test_nothing_to_export_gives_empty_text():
    assert build_export([]) == {"rules": "", "config": "", "included": [], "skipped": []}


# ---- store: accept / reject ------------------------------------------------------------------------
@pytest.fixture
def store(tmp_path):
    return CaseStore.create(tmp_path / "cases", "tuning")


def make_run(store, rules_text=None, kind="run"):
    rid, d = store.allocate_run()
    if rules_text is not None:
        (d / "cfg" / "rules.rules").write_text(rules_text)
    store.record_run({"id": rid, "kind": kind, "status": "ok", "inputs": [], "results": {}})
    return rid


def add_decision(store, change, reason="why", before_rules=None):
    a, b = make_run(store, before_rules), make_run(store, None, "tuning")
    return store.add_decision(change["kind"], change, reason, a, b, {"1": {"before": 3, "after": 1}})


def test_new_decisions_carry_updated_and_history(store):
    d = add_decision(store, F1)
    assert d["status"] == "proposed" and d["history"] == [] and d["updated"] >= d["created"]


def test_accept_reject_and_reopen_are_recorded(store):
    d = add_decision(store, F1)
    acc = store.update_decision(d["id"], "accepted")
    assert acc["status"] == "accepted" and acc["history"][0]["from"] == "proposed" and acc["history"][0]["to"] == "accepted"
    store.update_decision(d["id"], "rejected")
    back = store.update_decision(d["id"], "proposed")
    assert [(h["from"], h["to"]) for h in back["history"]] == [("proposed", "accepted"), ("accepted", "rejected"),
                                                               ("rejected", "proposed")]
    ev = [e for e in store.events() if e["type"] == "decision.updated"]
    assert [e["data"]["status"] for e in ev] == ["accepted", "rejected", "proposed"]


def test_setting_the_same_status_changes_nothing(store):
    d = add_decision(store, F1)
    n = len(store.events())
    assert store.update_decision(d["id"], "proposed")["history"] == [] and len(store.events()) == n


def test_update_decision_validation_and_old_records(store):
    with pytest.raises(CaseError, match="status must be one of"):
        store.update_decision("d-0001", "approved")
    with pytest.raises(CaseError, match="unknown decision"):
        store.update_decision("d-0099", "accepted")
    d = add_decision(store, F1)
    import json
    p = store.root / "decisions.json"
    doc = json.loads(p.read_text())
    for key in ("history", "updated"):
        doc["items"][0].pop(key)  # a decision written before these fields existed
    p.write_text(json.dumps(doc))
    assert store.update_decision(d["id"], "accepted")["history"][0]["to"] == "accepted"
    assert store.get_decision(d["id"])["status"] == "accepted"


# ---- the report -------------------------------------------------------------------------------------
def test_report_shows_a_rule_diff_checks_and_status_history(store):
    d = add_decision(store, {"kind": "rule_edit", "sid": 1000042, "rule": NEW}, "anchor on the path",
                     before_rules=OLD + "\nalert udp any any -> any 53 ( msg:\"other\"; sid:5; rev:1; )\n")
    store.update_decision(d["id"], "accepted")
    md = export_markdown(store)
    sect = md[md.index("### d-0001"):md.index("## Caveats")]
    assert "### d-0001 — rule_edit (accepted)" in sect and "Status history: proposed → accepted" in sect
    assert "Rule diff (option by option):" in sect and "```diff\n  alert http any any -> any any\n" in sect
    assert "- rev:1\n+ rev:2" in sect and '+ content:"/download/",fast_pattern' in sect
    assert "Rule check: sid unchanged · rev bumped (1 → 2) · has an explicit fast pattern" in sect
    assert "Change: `" not in sect  # the raw record is only a fallback


def test_report_shows_the_config_entry_for_a_filter(store):
    add_decision(store, F1)
    sect = export_markdown(store)
    assert "Config entry:" in sect and "```lua\n-- add this entry to the event_filter table in snort.lua\nevent_filter = { { gid = 1," in sect


def test_report_falls_back_when_the_previous_rules_are_missing_or_the_change_is_unknown(store):
    add_decision(store, {"kind": "rule_edit", "sid": 1000042, "rule": NEW}, before_rules=None)
    add_decision(store, {"kind": "mystery", "sid": 1})
    md = export_markdown(store)
    assert "Rule (the previous version was not available to compare):" in md and f"+ {NEW}" in md
    assert 'Change: `{"kind": "mystery", "sid": 1}`' in md


def test_headline_counts_accepted_decisions(store):
    a, b = add_decision(store, F1), add_decision(store, F2)
    store.update_decision(a["id"], "accepted")
    store.update_decision(b["id"], "rejected")
    assert "2 decisions (1 proposed, 1 accepted, 1 rejected)" not in export_markdown(store)  # proposed is zero now
    assert "2 decisions (1 accepted, 1 rejected)" in export_markdown(store)


# ---- workbench: update_decision / export_tuning (no Snort needed) -----------------------------------------
class NoEngine:
    name = "snort"
    evidence_types = {"pcap"}

    def version(self):
        from detection_workbench.engines.base import EngineVersion
        return EngineVersion("snort", None, None, False, "test double")

    def has_snort2lua(self):
        return False


@pytest.fixture
def wb(tmp_path):
    root = tmp_path / "allowed"
    root.mkdir()
    w = Workbench(Config(case_dir=tmp_path / "cases", allowed_roots=(root.resolve(),)), engine=NoEngine())
    w.create_case("export")
    return w, root.resolve()


def test_update_decision_tool_result(wb):
    w, _ = wb
    d = add_decision(w.store, F1)
    out = w.update_decision(d["id"], "accepted")
    assert out["status"] == "accepted" and out["history"][0]["to"] == "accepted" and "export_tuning" in out["next"]
    assert w.update_decision(d["id"], "rejected")["next"] is None
    with pytest.raises(WorkbenchError, match="status must be one of"):
        w.update_decision(d["id"], "approved")


def test_export_needs_an_accepted_decision(wb):
    w, _ = wb
    with pytest.raises(WorkbenchError, match="No accepted decisions"):
        w.export_tuning()
    d = add_decision(w.store, F1)
    with pytest.raises(WorkbenchError, match="not accepted yet"):
        w.export_tuning([d["id"]])
    with pytest.raises(WorkbenchError, match="unknown decision"):
        w.export_tuning(["d-0099"])
    preview = w.export_tuning([d["id"]], include_unaccepted=True)
    assert "event_filter = {" in preview["config"] and "not accepted yet; this is a preview" in preview["warning"]


def test_export_defaults_to_every_accepted_decision_only(wb):
    w, _ = wb
    a = add_decision(w.store, F1)
    add_decision(w.store, F2)  # stays proposed, so it must not be exported
    c = add_decision(w.store, {"kind": "rule_edit", "sid": 1000042, "rule": NEW})
    for d in (a, c):
        w.update_decision(d["id"], "accepted")
    out = w.export_tuning()
    assert out["decisions"] == [a["id"], c["id"]] and "suppress" not in out["config"] and NEW in out["rules"]
    assert out["written"] == [] and out["warning"] is None and len(out["how_to_apply"]) == 2


def test_export_writes_files_inside_the_roots(wb, tmp_path):
    w, root = wb
    for change in (F1, {"kind": "rule_edit", "sid": 1000042, "rule": NEW}):
        w.update_decision(add_decision(w.store, change)["id"], "accepted")
    out = w.export_tuning(path_prefix=str(root / "tuning"))
    assert sorted(out["written"]) == sorted([str(root / "tuning.rules"), str(root / "tuning.lua")])
    assert (root / "tuning.rules").read_text() == out["rules"] and (root / "tuning.lua").read_text() == out["config"]
    assert any(e["type"] == "export.written" and e["data"].get("format") == "tuning" for e in w.store.events())


def test_export_writes_only_the_parts_that_exist(wb):
    w, root = wb
    w.update_decision(add_decision(w.store, F1)["id"], "accepted")
    out = w.export_tuning(path_prefix=str(root / "only-config"))
    assert out["written"] == [str(root / "only-config.lua")] and not (root / "only-config.rules").exists()


def test_export_refuses_before_writing_anything(wb, tmp_path):
    w, root = wb
    for change in (F1, {"kind": "rule_edit", "sid": 1000042, "rule": NEW}):
        w.update_decision(add_decision(w.store, change)["id"], "accepted")
    (root / "t.lua").write_text("mine")  # one of the two targets already exists
    with pytest.raises(WorkbenchError, match="already exists"):
        w.export_tuning(path_prefix=str(root / "t"))
    assert not (root / "t.rules").exists() and (root / "t.lua").read_text() == "mine"  # nothing partial was written
    assert w.export_tuning(path_prefix=str(root / "t"), overwrite=True)["written"]
    with pytest.raises(WorkbenchError, match="outside allowed_roots"):
        w.export_tuning(path_prefix=str(tmp_path / "elsewhere"))
    assert not (tmp_path / "elsewhere.rules").exists()


def test_export_never_writes_through_a_link_or_over_evidence(wb, tmp_path):
    w, root = wb
    w.update_decision(add_decision(w.store, F1)["id"], "accepted")
    victim = tmp_path / "victim.txt"
    victim.write_text("keep")
    (root / "ln.lua").symlink_to(victim)
    with pytest.raises(WorkbenchError):
        w.export_tuning(path_prefix=str(root / "ln"), overwrite=True)
    assert victim.read_text() == "keep"
    ev = root / "evidence.lua"
    ev.write_text("-- registered evidence")
    w.register_evidence(str(ev), type="log")
    with pytest.raises(WorkbenchError, match="evidence"):
        w.export_tuning(path_prefix=str(root / "evidence"), overwrite=True)
    assert ev.read_text() == "-- registered evidence"
