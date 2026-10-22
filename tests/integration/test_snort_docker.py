"""Opt-in: needs Docker (or native Snort 3). Run: DW_INTEGRATION=1 uv run pytest -q tests/integration"""
import os
import subprocess
import time
from pathlib import Path

import pytest

from detection_workbench.config import Config
from detection_workbench.runner.runner import RunContext, docker_argv, execute
from detection_workbench.workbench import Workbench, WorkbenchError

FIX = Path(__file__).parents[1] / "fixtures"

pytestmark = pytest.mark.integration
if not os.environ.get("DW_INTEGRATION"):
    pytest.skip("set DW_INTEGRATION=1 to run integration tests", allow_module_level=True)


@pytest.fixture(scope="module")
def engine_cfg(tmp_path_factory):
    return Config(case_dir=tmp_path_factory.mktemp("cases"), allowed_roots=(FIX.resolve(),))


@pytest.fixture
def wb(engine_cfg):
    w = Workbench(engine_cfg)
    if not w.engine.version().available:
        pytest.skip(f"Snort unavailable: {w.engine.version().detail}")
    w.create_case("integration")
    return w


def ev(wb, rel):
    return wb.register_evidence(str(FIX / rel))["id"]


def counts(res):
    return {r["sid"]: r["count"] for r in res["by_sid"]}


def test_status(wb):
    s = wb.get_status()["engines"][0]
    assert s["available"] and s["version"].startswith("3.") and s["backend"] in ("native", "docker")


def test_validate_good(wb):
    r = wb.validate_rules(rules_id=ev(wb, "rules/good.rules"))
    assert r["ok"] and r["errors"] == [] and r["status"] == "ok"
    assert any("fast pattern" in w["error"] for w in r["warnings"])


def test_validate_bad_reports_lines_and_unmasks_cascade(wb):
    r = wb.validate_rules(rules_id=ev(wb, "rules/bad.rules"))
    assert not r["ok"]
    by_line = {e["line"]: e for e in r["errors"]}
    assert "contnet" in by_line[2]["error"] and by_line[2]["sid"] == 1000011
    assert "pcre" in by_line[4]["error"] and by_line[4]["sid"] == 1000013  # hidden by the line-3 cascade in one pass
    assert "depth" in by_line[7]["error"]
    assert r["rechecked_individually"] and 3 in r["rechecked_individually"]
    assert any(d["source"] == "workbench_lint" and "No sid" in d["error"] and d["line"] == 5 for d in r["lint"])


def test_validate_inline_and_missing_sid_flag(wb):
    r = wb.validate_rules(rules_text='alert tcp any any -> any any ( msg:"x"; content:"abc"; rev:1; )')
    assert r["snort_ok"] and not r["ok"]  # Snort is silent about the missing sid; the workbench is not


def test_run_http_marker_sid_to_packet(wb):
    pcap, rules = ev(wb, "pcaps/http_marker.pcap"), ev(wb, "rules/good.rules")
    r = wb.run_pcap(pcap, rules_id=rules)
    assert r["status"] == "ok" and counts(r) == {1000003: 6, 1000002: 2, 1000001: 1}
    alerts = wb.get_alerts(r["run_id"])["alerts"]
    raw_syn = sorted(a["pkt_num"] for a in alerts if a["sid"] == 1000003)
    assert raw_syn == [3, 9, 10, 11, 12, 13]
    marker = next(a for a in alerts if a["sid"] == 1000001)
    assert marker["pkt_gen"] == "stream_tcp" and marker["pkt_num"] == 7  # flush trigger, not the request (6)
    assert r["stream_caveats"]["unacked_flows"] == 0
    run = wb.store.get_run(r["run_id"])
    assert run["engine"] == "snort" and run["status"] == "ok" and run["argv"] and run["inputs"][0]["sha256"]
    assert "--daq" in run["argv"] and run["argv"][run["argv"].index("--daq") + 1] == "pcap"


def test_explain_marker_alert(wb):
    r = wb.run_pcap(ev(wb, "pcaps/http_marker.pcap"), rules_id=ev(wb, "rules/good.rules"))
    idx = next(a["alert_idx"] for a in wb.get_alerts(r["run_id"], sid=1000001)["alerts"])
    ex = wb.explain_alert(r["run_id"], idx)
    assert ex["packet"]["data_packets"] == [6] and ex["contents"][0]["wire_reassembled"]["packets"][0]["pkt"] == 6


def test_flow_endings_and_flush_one_sided(wb):
    pcap, rules = ev(wb, "pcaps/flow_endings.pcap"), ev(wb, "rules/noisy.rules")
    base = wb.run_pcap(pcap, rules_id=rules)
    assert base["stream_caveats"]["unacked_flows"] == 4 and base["stream_caveats"]["explanation"]
    got = sorted(a["pkt_num"] for a in wb.get_alerts(base["run_id"], sid=1000001)["alerts"])
    assert got == [19]  # only the server-ACKed flow is inspected (docs/notes.md A6b)
    flushed = wb.run_pcap(pcap, rules_id=rules, flush_one_sided=True)
    got2 = sorted(a["pkt_num"] for a in wb.get_alerts(flushed["run_id"], sid=1000001)["alerts"])
    assert got2 == [19, 22]  # the one-sided flow is now inspected too


def test_noisy_tuning_loop_with_before_after(wb):
    pcap, rules = ev(wb, "pcaps/noisy.pcap"), ev(wb, "rules/noisy.rules")
    r = wb.run_pcap(pcap, rules_id=rules)
    top = wb.suggest_tuning_targets(r["run_id"])["targets"][0]
    assert top["sid"] == 1000042 and top["top_source"] == "10.0.4.20" and top["top_source_share"] > 0.9
    before = counts(r)[1000042]
    t = wb.test_tuning(r["run_id"], {"kind": "suppress", "sid": 1000042, "track": "by_src", "ip": "10.0.4.20"}, "known scanner")
    c = t["counts"]
    assert t["applied"] and c["1000042"]["before"] == before and 0 < c["1000042"]["after"] < before - 250
    assert c["1000001"] == {"before": 1, "after": 1} and t["other_sids_changed"] == []
    d = wb.store.summary()["decisions"][0]
    assert d["id"] == t["decision_id"] and d["before_run"] == r["run_id"] and d["after_run"] == t["after_run"]
    diff = wb.diff_runs(r["run_id"], t["after_run"])
    assert diff["added"]["count"] == 0 and diff["removed"]["count"] == before - c["1000042"]["after"]


def test_rule_edit_tuning(wb):
    pcap, rules = ev(wb, "pcaps/noisy.pcap"), ev(wb, "rules/noisy.rules")
    r = wb.run_pcap(pcap, rules_id=rules)
    new = 'alert http any any -> any any ( msg:"LOCAL noisy GET index"; flow:to_server,established; http_uri; content:"/index",fast_pattern; sid:1000042; rev:2; classtype:web-application-activity; )'
    t = wb.test_tuning(r["run_id"], {"kind": "rule_edit", "sid": 1000042, "rule": new}, "match only /index")
    assert t["applied"] and 0 < t["counts"]["1000042"]["after"] < 20
    bad = wb.test_tuning(r["run_id"], {"kind": "rule_edit", "sid": 1000042, "rule": new.replace("content:", "contnet:")}, "typo")
    assert bad["applied"] is False and not bad["validation"]["ok"]


def test_test_tuning_rejects_hostile_filter(wb):
    r = wb.run_pcap(ev(wb, "pcaps/http_marker.pcap"), rules_id=ev(wb, "rules/good.rules"))
    for ip in ("10.0.0.1'; os.execute('id') --", "evil"):
        with pytest.raises(WorkbenchError):
            wb.test_tuning(r["run_id"], {"kind": "suppress", "sid": 1000001, "track": "by_src", "ip": ip}, "x")
    with pytest.raises(WorkbenchError):
        wb.run_pcap(ev(wb, "pcaps/http_marker.pcap"), rules_id=ev(wb, "rules/good.rules"), home_net="x'; y='")


def test_profile(wb):
    p = wb.profile_rules(ev(wb, "pcaps/noisy.pcap"), rules_id=ev(wb, "rules/noisy.rules"), top=3)
    assert p["status"] == "ok" and p["unresolved_rows"] == 0 and p["slowest"][0]["sid"] == 1000042
    assert p["slowest"][0]["msg"].startswith("LOCAL noisy") and p["slowest"][0]["checks"] > 300


def test_every_run_lands_in_case_and_exports(wb, tmp_path):
    pcap = ev(wb, "pcaps/http_marker.pcap")
    wb.pcap_summary(pcap)
    r = wb.run_pcap(pcap, rules_id=ev(wb, "rules/good.rules"))
    f = wb.add_finding("marker fires on the request", [r["run_id"]], [pcap])
    kinds = [x["kind"] for x in wb.store.list_runs()]
    assert kinds == ["summary", "run"]
    types = [e["type"] for e in wb.store.events()]
    assert types.count("run.recorded") == 2 and "finding.added" in types
    wb.update_case(summary=f"Marker rule fires once ({f['id']}, {r['run_id']}).", status="closed")
    md = Path(wb.export_case("markdown")["path"]).read_text()
    assert f["id"] in md and "http_marker.pcap" in md and "status **closed**" in md
    assert md.index("## Summary") < md.index("Marker rule fires once") < md.index("## Overview")
    assert f"### {r['run_id']} — run" in md and "| 1000001 | WBTEST marker in URI | 1 |" in md and "## Caveats" in md
    csv = Path(wb.export_case("timesketch_csv")["path"]).read_text().splitlines()
    assert csv[0].startswith("message,datetime,timestamp_desc") and len(csv) == 1 + 9 + 1


def test_convert_snort2(wb):
    copy = FIX / "rules" / "_snort2_tmp.rules"  # inside allowed_roots; removed afterwards
    copy.write_text('alert tcp any any -> any 80 (msg:"old uri"; uricontent:"/admin"; nocase; sid:1000100; rev:1;)\n')
    try:
        e = ev(wb, "rules/_snort2_tmp.rules")
        out = wb.convert_snort2(e)
    finally:
        copy.unlink()
    assert out["status"] == "ok" and "http_uri" in out["converted_rules"]


def test_docker_timeout_kills_container(wb, tmp_path):
    if wb.engine.version().backend != "docker":
        pytest.skip("docker backend only")
    run_dir = tmp_path / "run"
    for d in ("cfg", "out"):
        (run_dir / d).mkdir(parents=True)
    ctx = RunContext(run_dir=run_dir, backend="docker", cfg=wb.cfg, etc_dir="/x", name="dw-timeout-test")
    argv = docker_argv(ctx, ["60"], binary="/bin/sleep")
    t0 = time.monotonic()
    raw = execute(argv, ctx, 2)
    assert raw.timed_out and time.monotonic() - t0 < 15
    time.sleep(1)
    ps = subprocess.run(["docker", "ps", "-q", "--filter", "name=dw-timeout-test"], capture_output=True, text=True)
    assert ps.stdout.strip() == ""


def test_no_live_capture_surface(wb):
    import inspect
    for name in ("run_pcap", "validate_rules", "test_tuning"):
        params = inspect.signature(getattr(wb, name)).parameters
        assert not {"interface", "iface", "daq", "inline", "lua", "args", "argv"} & set(params)


def test_real_captures_from_env(engine_cfg, tmp_path):
    """Real-world pcaps come from a directory the user names; nothing is committed. Skipped when unset."""
    d = os.environ.get("DW_REAL_PCAPS")
    if not d or not Path(d).expanduser().is_dir():
        pytest.skip("set DW_REAL_PCAPS to a directory of pcaps")
    root = Path(d).expanduser().resolve()
    pcaps = sorted(p for p in root.iterdir() if p.suffix in (".pcap", ".pcapng", ".cap"))[:3]
    if not pcaps:
        pytest.skip("no pcaps in DW_REAL_PCAPS")
    w = Workbench(Config(case_dir=tmp_path / "cases", allowed_roots=(root,)))
    if not w.engine.version().available:
        pytest.skip("Snort unavailable")
    w.create_case("real captures")
    rules = 'alert tcp any any -> any any ( msg:"LOCAL any SYN"; flags:S; sid:1000001; rev:1; )'
    for p in pcaps:
        e = w.register_evidence(str(p))["id"]
        s = w.pcap_summary(e)
        r = w.run_pcap(e, rules_text=rules)
        assert s["packets"] > 0 and r["status"] == "ok" and r["total_alerts"] >= 0
        assert wb_runs(w)[-1]["status"] == "ok"


def wb_runs(w):
    return w.store.list_runs()


def test_include_directive_is_refused_before_anything_runs(wb):
    before = len(wb.store.list_runs())
    with pytest.raises(WorkbenchError, match="include"):
        wb.validate_rules(rules_text="include /etc/passwd\n" + 'alert tcp any any -> any any ( msg:"x"; content:"a"; sid:1000001; rev:1; )')
    r = wb.run_pcap(ev(wb, "pcaps/http_marker.pcap"), rules_id=ev(wb, "rules/good.rules"))
    with pytest.raises(WorkbenchError, match="include"):
        wb.test_tuning(r["run_id"], {"kind": "rule_edit", "sid": 1000001, "rule": "include /etc/passwd"}, "x")
    assert len(wb.store.list_runs()) == before + 1  # only the legitimate run was recorded


def test_multi_line_rule_edit_is_refused(wb):
    r = wb.run_pcap(ev(wb, "pcaps/http_marker.pcap"), rules_id=ev(wb, "rules/good.rules"))
    for rule in ("a\nb", "a\r\nb", ""):
        with pytest.raises(WorkbenchError, match="single-line"):
            wb.test_tuning(r["run_id"], {"kind": "rule_edit", "sid": 1000001, "rule": rule}, "x")


def test_awkward_and_hostile_evidence_names_work_because_the_engine_sees_a_safe_copy(tmp_path):
    import shutil
    root = tmp_path / "in"
    root.mkdir()
    w = Workbench(Config(case_dir=tmp_path / "cases", allowed_roots=(root.resolve(),)))
    if w.engine.version().backend != "docker":
        pytest.skip("docker backend only")
    w.create_case("names")
    rid = w.register_evidence(shutil.copy(FIX / "rules/good.rules", root / "good.rules"))["id"]
    for name in ("my capture (1).pcap", "x:etc:rw,y\"z.pcap"):  # spaces/brackets, and characters that break `-v` specs
        cap = shutil.copy(FIX / "pcaps/http_marker.pcap", root / name)
        r = w.run_pcap(w.register_evidence(cap)["id"], rules_id=rid)
        assert r["status"] == "ok" and r["total_alerts"] == 9, name


def test_evidence_changed_after_registration_is_refused_and_staged_copies_are_removed(tmp_path):
    import shutil
    root = tmp_path / "in"
    root.mkdir()
    w = Workbench(Config(case_dir=tmp_path / "cases", allowed_roots=(root.resolve(),)))
    if not w.engine.version().available:
        pytest.skip("Snort unavailable")
    w.create_case("toctou")
    rules = w.register_evidence(shutil.copy(FIX / "rules/good.rules", root / "good.rules"))["id"]
    cap = shutil.copy(FIX / "pcaps/http_marker.pcap", root / "cap.pcap")
    pc = w.register_evidence(cap)["id"]
    ok = w.run_pcap(pc, rules_id=rules)
    assert ok["status"] == "ok"
    assert not list((w.store.root / "runs" / ok["run_id"]).glob("input-*")), "staged copy must be deleted after the run"
    n = len(w.store.list_runs())
    Path(cap).write_bytes(Path(cap).read_bytes() + b"\0")  # modified after registration
    for call in (lambda: w.run_pcap(pc, rules_id=rules), lambda: w.pcap_summary(pc), lambda: w.explain_alert(ok["run_id"], 0)):
        with pytest.raises(WorkbenchError, match="changed since it was registered"):
            call()
    assert len(w.store.list_runs()) == n  # nothing recorded for the refused attempts
    assert not list(w.store.root.rglob("input-*"))


def test_snort2_conf_include_lines_are_not_followed(tmp_path):
    root = tmp_path / "in"
    root.mkdir()
    w = Workbench(Config(case_dir=tmp_path / "cases", allowed_roots=(root.resolve(),)))
    if not w.engine.version().available or not w.engine.has_snort2lua():
        pytest.skip("snort2lua unavailable")
    w.create_case("includes")
    (root / "extra.rules").write_text('alert tcp any any -> any 80 (msg:"SHOULD-NOT-APPEAR"; content:"zzz"; sid:1000200; rev:1;)\n')
    conf = root / "old.conf"
    conf.write_text(f"var HOME_NET any\ninclude {root / 'extra.rules'}\nalert tcp any any -> any 80 (msg:\"direct\"; content:\"abc\"; sid:1000201; rev:1;)\n")
    out = w.convert_snort2(w.register_evidence(str(conf), type="log")["id"])
    # the include is not followed: its rule is absent, the directly written rule converts, and the notes name the skipped line
    assert out["status"] == "partial"
    assert "SHOULD-NOT-APPEAR" not in out["converted_rules"] and "1000200" not in out["converted_rules"]
    assert "1000201" in out["converted_rules"] and "extra.rules" in out["conversion_notes"]
