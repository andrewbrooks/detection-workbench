"""Bounds and robustness found in the production-readiness review."""
import json
import subprocess
from pathlib import Path

import pytest

from detection_workbench.case.export import export_markdown
from detection_workbench.config import Config, Limits, SnortConfig
from detection_workbench.engines.base import EngineResult
from detection_workbench.engines.snort import plugin as plugin_mod
from detection_workbench.engines.snort.parse_validate import ValidationReport
from detection_workbench.pcap import flows as flows_mod
from detection_workbench.pcap import summary as summary_mod
from detection_workbench.pcap.flows import analyze_streams
from detection_workbench.pcap.summary import summarize
from detection_workbench.runner.runner import RunContext, read_capped
from detection_workbench.workbench import MAX_DECISION_COUNTS, MAX_SID_ROWS, Workbench

FIX = Path(__file__).parents[1] / "fixtures"


# ---- engine detection ---------------------------------------------------------------
class Proc:
    def __init__(self, rc=0, out="", err=""):
        self.returncode, self.stdout, self.stderr = rc, out, err


SNORT3 = "   ,,_     -*> Snort++ <*-\n  o\"  )~   Version 3.10.0.0\n"


def engine(monkeypatch, *, native=None, docker=True, inspect=None, run=None, build=None, derived_exists=True,
           backend="auto"):
    """A SnortEngine whose `snort`/`docker` calls are scripted. `engine._calls` records every command that was run."""
    monkeypatch.setattr(plugin_mod.shutil, "which", lambda n: ("/usr/bin/" + n) if (
        (n == "snort" and native is not None) or (n == "docker" and docker)) else None)
    calls = []

    def fake_run(argv, **kw):
        calls.append((argv, kw))
        if Path(argv[0]).name == "snort":
            return Proc(0, native or "")
        if argv[1:3] == ["image", "inspect"]:
            if argv[3].startswith("detection-workbench/"):  # the derived image
                return Proc(0) if derived_exists else Proc(1, "", "Error: No such image")
            if isinstance(inspect, Exception):
                raise inspect
            return inspect or Proc(0)
        if argv[1] == "build":
            if isinstance(build, Exception):
                raise build
            return build or Proc(0)
        if isinstance(run, Exception):
            raise run
        return run or Proc(0, SNORT3)

    monkeypatch.setattr(plugin_mod.subprocess, "run", fake_run)
    e = plugin_mod.SnortEngine(Config(snort=SnortConfig(backend=backend)))
    e._calls = calls
    return e


def test_native_snort3_is_preferred(monkeypatch):
    v = engine(monkeypatch, native=SNORT3).version()
    assert v.available and v.backend == "native" and v.version == "3.10.0.0"


def test_native_snort2_falls_back_to_docker(monkeypatch):
    v = engine(monkeypatch, native="Version 2.9.20").version()
    assert v.backend == "docker" and v.available and "need 3.x" in v.detail


def test_no_docker_and_no_snort(monkeypatch):
    v = engine(monkeypatch, docker=False).version()
    assert not v.available and "docker is not installed" in v.detail


def test_daemon_down_is_not_reported_as_a_missing_image(monkeypatch):
    v = engine(monkeypatch, inspect=Proc(1, "", "Cannot connect to the Docker daemon at unix:///var/run/docker.sock.\n")).version()
    assert not v.available and "not usable" in v.detail and "daemon" in v.detail and "docker pull" not in v.detail


def test_missing_image_says_how_to_pull(monkeypatch):
    v = engine(monkeypatch, inspect=Proc(1, "", "Error: No such image: ciscotalos/snort3\n")).version()
    assert not v.available and "docker pull" in v.detail


@pytest.mark.parametrize("kwargs,text", [({"inspect": subprocess.TimeoutExpired("docker", 30)}, "did not respond"),
                                         ({"run": subprocess.TimeoutExpired("docker", 60)}, "did not respond"),
                                         ({"run": Proc(0, "garbage")}, "could not start Snort in the image as your user")])
def test_docker_hangs_and_garbage_do_not_crash(monkeypatch, kwargs, text):
    v = engine(monkeypatch, **kwargs).version()
    assert not v.available and text in v.detail


def test_unavailable_engine_is_looked_for_again_but_available_is_cached(monkeypatch):
    clock = {"t": 1000.0}
    monkeypatch.setattr(plugin_mod.time, "monotonic", lambda: clock["t"])
    e = engine(monkeypatch, inspect=Proc(1, "", "No such image"))
    assert not e.version().available
    monkeypatch.undo()  # the image is "pulled": replace the scripted world with one where it exists
    monkeypatch.setattr(plugin_mod.time, "monotonic", lambda: clock["t"])
    e2 = engine(monkeypatch)
    e2._version, e2._checked = e._version, e._checked
    clock["t"] += 5
    assert not e2.version().available  # too soon: cached
    clock["t"] += plugin_mod.RECHECK_UNAVAILABLE_AFTER_S
    assert e2.version().available and e2.version().backend == "docker"
    clock["t"] += 10_000
    assert e2.version().available and sum(1 for c in e2._calls if c[0][1] == "run") == 1  # success is cached


# ---- the derived image and running as the host user ------------------------------------------
def test_probe_runs_as_the_host_user_with_the_lockdown_flags_on_the_derived_image(monkeypatch):
    import os
    e = engine(monkeypatch)
    assert e.version().available
    argv = next(a for a, _ in e._calls if a[1] == "run")
    assert argv[argv.index("--user") + 1] == f"{os.getuid()}:{os.getgid()}"
    assert "--read-only" in argv and argv[argv.index("--cap-drop") + 1] == "ALL" and argv[argv.index("--network") + 1] == "none"
    image = argv[argv.index("-V") - 1]
    assert image == e._image and image.startswith("detection-workbench/snort3:")
    assert e.status()["docker_run_image"] == image


def test_derived_image_is_built_when_missing_without_network(monkeypatch):
    e = engine(monkeypatch, derived_exists=False)
    assert e.version().available
    argv, kw = next((a, k) for a, k in e._calls if a[1] == "build")
    assert argv[argv.index("--network") + 1] == "none" and argv[-1] == "-"
    assert kw["input"].startswith("FROM ciscotalos/snort3@sha256:") and "chmod o+x /home /home/snorty" in kw["input"]


def test_derived_image_is_not_rebuilt_when_present(monkeypatch):
    e = engine(monkeypatch, derived_exists=True)
    e.version()
    assert not any(a[1] == "build" for a, _ in e._calls)


def test_image_build_failure_is_explained(monkeypatch):
    v = engine(monkeypatch, derived_exists=False, build=Proc(1, "", "failed to solve: permission denied\nmore")).version()
    assert not v.available and "could not prepare the Docker image" in v.detail and "failed to solve" in v.detail


def test_snort_that_cannot_start_as_your_user_is_reported_with_the_uid(monkeypatch):
    import os
    v = engine(monkeypatch, run=Proc(126, "", "exec: stat /home/snorty/snort3/bin/snort: permission denied")).version()
    assert not v.available and f"as your user ({os.getuid()}:{os.getgid()})" in v.detail and "permission denied" in v.detail


# ---- bounded reads and the validation time budget -----------------------------------------
def test_read_capped(tmp_path):
    f = tmp_path / "out.txt"
    f.write_bytes(b"a" * 100 + b"\xff" * 10)
    assert read_capped(f, 50) == "a" * 50 and len(read_capped(f)) == 110
    assert read_capped(tmp_path / "missing") == ""


def test_cascade_rechecks_stop_when_the_time_budget_is_spent(tmp_path, monkeypatch):
    cfg = Config(limits=Limits(timeout_s=10))
    eng = plugin_mod.SnortEngine(cfg)
    ctx = RunContext(run_dir=tmp_path, backend="native", cfg=cfg, etc_dir="/x", name="dw-t")
    (tmp_path / "cfg").mkdir()
    rules = "\n".join(f'alert tcp any any -> any any ( msg:"r{i}"; content:"a"; sid:{1000000 + i}; rev:1; )' for i in range(1, 9))
    calls = []
    clock = {"t": 0.0}
    monkeypatch.setattr(plugin_mod.time, "monotonic", lambda: clock["t"])

    def fake_once(ctx_, name, label):
        calls.append(label)
        clock["t"] += 4.0  # each single-rule check "takes" 4 s of a 10 s budget
        for n in ("stdout.txt", "stderr.txt"):
            (tmp_path / n).write_text("")
        from detection_workbench.runner.runner import RawRun
        return RawRun(["x"], 0, False, 4.0, tmp_path / "stdout.txt", tmp_path / "stderr.txt", "native"), ["x"]

    monkeypatch.setattr(eng, "_validate_once", fake_once)
    errors = [{"severity": "error", "line": ln, "sid": 1, "error": "syntax error", "plain": "", "source": "snort", "rule": ""}
              for ln in (2, 5)]
    rep = ValidationReport(ok=False, errors=errors)
    out, done, extra, incomplete = eng._recheck_cascade(ctx, rep, rules)
    assert incomplete is True and len(calls) == 3 and done == [2, 3, 5]  # 4 candidate lines, stopped once over budget
    assert len(extra) == 3


# ---- response size and memory caps ---------------------------------------------------------
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
    w = Workbench(Config(case_dir=tmp_path / "cases", allowed_roots=(tmp_path.resolve(),)), engine=NoEngine())
    w.create_case("bounds")
    return w


def make_run(store, alerts, kind="run"):
    rid, d = store.allocate_run()
    with (d / "results" / "alerts.jsonl").open("w") as f:
        for i, a in enumerate(alerts):
            f.write(json.dumps({"alert_idx": i, "gid": 1, "rev": 1, "class": "none", "priority": 0, "msg": "m",
                                "src_port": 1, "dst_port": 2, "dst_ip": "10.0.0.2", **a}) + "\n")
    store.record_run({"id": rid, "kind": kind, "status": "ok", "inputs": [],
                      "results": {"alerts": "results/alerts.jsonl"}})
    return rid


def alert(sid, pkt, src="10.0.0.1", **kw):
    return {"sid": sid, "pkt_num": pkt, "src_ip": src, **kw}


def test_run_payload_lists_a_bounded_number_of_sids(wb):
    rid = make_run(wb.store, [alert(1, 1)])
    rows = [{"gid": 1, "sid": 1000000 + i, "rev": 1, "msg": "m", "count": 1000 - i, "distinct_sources": 1,
             "distinct_destinations": 1, "top_source": "a", "top_source_share": 1.0} for i in range(MAX_SID_ROWS + 50)]
    res = EngineResult(status="ok", argv=[], payload={"total": 5, "truncated": False, "by_sid": rows, "stream_caveats": {}})
    out = wb._run_payload(rid, res)
    assert len(out["by_sid"]) == MAX_SID_ROWS and out["sids_total"] == MAX_SID_ROWS + 50
    assert out["by_sid"][0]["count"] == 1000  # the busiest come first


def test_trim_counts_keeps_changes_target_and_busiest(wb):
    small = {"1": {"before": 2, "after": 1}}
    assert wb._trim_counts(small, "1") == (small, 0)
    big = {str(i): {"before": i, "after": i} for i in range(1, 1001)}
    big["500"] = {"before": 500, "after": 5}
    big["7"] = {"before": 7, "after": 6}
    kept, omitted = wb._trim_counts(big, "7")
    assert len(kept) == MAX_DECISION_COUNTS and omitted == 1000 - MAX_DECISION_COUNTS
    assert "500" in kept and "7" in kept and "1000" in kept and "1" not in kept  # changed, target, busiest unchanged
    assert list(kept) == sorted(kept, key=int)


def test_decision_records_and_report_shows_omitted_rows(wb):
    a, b = make_run(wb.store, []), make_run(wb.store, [], kind="tuning")
    wb.store.add_decision("suppress", {"sid": 1}, "why", a, b, {"1": {"before": 3, "after": 1}}, counts_omitted=42)
    assert wb.store.summary()["decisions"][0]["counts_omitted"] == 42
    assert "42 unchanged SIDs not listed" in export_markdown(wb.store)
    wb.store.add_decision("suppress", {"sid": 2}, "why", a, b, {"2": {"before": 3, "after": 1}})
    assert "counts_omitted" not in wb.store.summary()["decisions"][1]


def test_diff_runs_added_removed_changed_and_caps(wb):
    shared = [alert(10, 1), alert(11, 2), alert(12, 3, rev=1, msg="old")]
    a = make_run(wb.store, shared + [alert(99, 50), alert(99, 51)])
    b = make_run(wb.store, [alert(10, 1), alert(11, 2), alert(12, 3, rev=2, msg="new")]
                 + [alert(500 + i, 100 + i) for i in range(MAX_SID_ROWS + 30)])
    d = wb.diff_runs(a, b, sample=5)
    assert d["totals"] == {"a": 5, "b": 3 + MAX_SID_ROWS + 30}
    assert d["removed"]["count"] == 2 and d["removed"]["by_sid"] == [{"sid": 99, "count": 2}]
    assert d["added"]["count"] == MAX_SID_ROWS + 30 and len(d["added"]["by_sid"]) == MAX_SID_ROWS and len(d["added"]["sample"]) == 5
    assert d["changed"]["count"] == 1
    ch = d["changed"]["sample"][0]
    assert ch["sid"] == 12 and ch["from"]["msg"] == "old" and ch["to"] == {"rev": 2, "msg": "new", "class": "none", "priority": 0}
    assert [s["pkt_num"] for s in d["added"]["sample"]] == sorted(s["pkt_num"] for s in d["added"]["sample"])


def test_diff_of_identical_runs_is_empty(wb):
    a = make_run(wb.store, [alert(1, 1), alert(2, 2)])
    b = make_run(wb.store, [alert(1, 1), alert(2, 2)])
    d = wb.diff_runs(a, b)
    assert d["added"]["count"] == d["removed"]["count"] == d["changed"]["count"] == 0


def test_flow_tracking_is_capped(monkeypatch):
    monkeypatch.setattr(flows_mod, "MAX_FLOWS", 2)
    r = analyze_streams(FIX / "pcaps/flow_endings.pcap")  # five flows
    assert r["tcp_flows"] == 2 and r["flows_truncated"] is True
    monkeypatch.setattr(flows_mod, "MAX_FLOWS", 1000)
    assert analyze_streams(FIX / "pcaps/flow_endings.pcap")["flows_truncated"] is False


def test_summary_counters_are_capped(monkeypatch):
    monkeypatch.setattr(summary_mod, "MAX_KEYS", 1)
    s = summarize(FIX / "pcaps/noisy.pcap")
    assert len(s["top_sources"]) == 1 and s["untracked_packets"] > 0 and s["packets"] == 1910
    monkeypatch.setattr(summary_mod, "MAX_KEYS", 100_000)
    assert summarize(FIX / "pcaps/http_marker.pcap")["untracked_packets"] == 0
