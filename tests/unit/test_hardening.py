"""Input-handling hardening: rule includes, Docker mount specs, evidence metadata, text caps."""
import pytest

from detection_workbench.case.model import MAX_TEXT_CHARS
from detection_workbench.case.store import CaseError, CaseStore
from detection_workbench.config import Config
from detection_workbench.engines.snort.rules import find_includes
from detection_workbench.runner.runner import RunContext, docker_argv
from detection_workbench.safety.paths import PathError
from detection_workbench.workbench import Workbench, WorkbenchError

RULE = 'alert tcp any any -> any any ( msg:"x"; content:"a"; sid:1000001; rev:1; )'


# ---- include directives --------------------------------------------------------------
@pytest.mark.parametrize("text,lines", [
    ("include /etc/passwd\n" + RULE, [1]),
    (RULE + "\n  INCLUDE other.rules\n", [2]),
    ("# include nothing\n" + RULE, []),
    (RULE, []),
    ('alert tcp any any -> any any ( msg:"includes are fine in msg"; sid:2; rev:1; )', []),
    ("includes_not_a_directive", []),
])
def test_find_includes(text, lines):
    assert find_includes(text) == lines


@pytest.fixture
def wb(tmp_path):
    root = tmp_path / "allowed"
    root.mkdir()
    w = Workbench(Config(case_dir=tmp_path / "cases", allowed_roots=(root.resolve(),)))
    w.create_case("hardening")
    return w, root.resolve()


def test_rules_with_include_are_refused_inline_and_registered(wb):
    w, root = wb
    with pytest.raises(WorkbenchError, match="include.*line 1"):
        w._rules(None, "include /etc/passwd\n" + RULE)
    f = root / "r.rules"
    f.write_text(RULE + "\ninclude /etc/shadow\n")
    ev = w.register_evidence(str(f), type="rules")["id"]
    with pytest.raises(WorkbenchError, match="line 2"):
        w._rules(ev, None)
    f2 = root / "ok.rules"
    f2.write_text(RULE + "\n")
    assert w._rules(w.register_evidence(str(f2), type="rules")["id"], None)[1]["source"] == "evidence"


# ---- Docker mount specs ---------------------------------------------------------------
@pytest.fixture
def dctx(tmp_path):
    for d in ("cfg", "out"):
        (tmp_path / d).mkdir()
    return RunContext(run_dir=tmp_path, backend="docker", cfg=Config(), etc_dir="/x", name="dw-t")


@pytest.mark.parametrize("name", ["a:b.pcap", "x:/etc:rw.pcap", "a,b.pcap", 'q"uote.pcap', "new\nline.pcap", "tab\t.pcap"])
def test_unsafe_mount_paths_are_refused(dctx, tmp_path, name):
    with pytest.raises(PathError, match="cannot be mounted safely"):
        dctx.input_arg(tmp_path / name)


def test_safe_names_get_sanitized_targets(dctx, tmp_path):
    t = dctx.input_arg(tmp_path / "my capture (1).pcap")
    assert t == "/in/0/my_capture__1_.pcap" and dctx.input_arg(tmp_path / "my capture (1).pcap") == t


def test_native_backend_does_not_restrict_names(dctx, tmp_path):
    dctx.backend = "native"
    assert dctx.input_arg(tmp_path / "a:b.pcap").endswith("a:b.pcap")


def test_case_directory_with_colon_is_refused_for_docker(tmp_path):
    bad = tmp_path / "ca:ses" / "run"
    (bad / "cfg").mkdir(parents=True)
    (bad / "out").mkdir()
    ctx = RunContext(run_dir=bad, backend="docker", cfg=Config(), etc_dir="/x", name="dw-t")
    with pytest.raises(PathError):
        docker_argv(ctx, ["-V"])


# ---- evidence metadata ------------------------------------------------------------------
def test_register_evidence_validates_type_and_label(wb):
    w, root = wb
    f = root / "a.pcap"
    f.write_bytes(bytes.fromhex("d4c3b2a1") + b"\0" * 20)
    with pytest.raises(WorkbenchError, match="type must be one of"):
        w.register_evidence(str(f), type="exe")
    for bad in ({"class": "evil"}, {"class": "benign", "extra": "x"}, {"class": 5}, "benign", {"technique": "T1"}):
        with pytest.raises(WorkbenchError, match="label must look like"):
            w.register_evidence(str(f), label=bad)  # type: ignore[arg-type]
    item = w.register_evidence(str(f), label={"class": "malicious", "technique": "T1059.001"})
    assert item["label"] == {"class": "malicious", "technique": "T1059.001"} and item["type"] == "pcap"


def test_store_rejects_unknown_evidence_type(tmp_path):
    s = CaseStore.create(tmp_path / "c", "t")
    f = tmp_path / "x"
    f.write_text("x")
    with pytest.raises(CaseError):
        s.register_evidence(f, type_="bogus")


# ---- text size caps ----------------------------------------------------------------------
def test_text_fields_are_capped_and_non_empty(tmp_path):
    s = CaseStore.create(tmp_path / "c", "t")
    big = "x" * (MAX_TEXT_CHARS + 1)
    with pytest.raises(CaseError, match="longer than"):
        s.add_note(big)
    with pytest.raises(CaseError, match="longer than"):
        s.add_finding(big, [], [])
    with pytest.raises(CaseError, match="empty"):
        s.add_note("   ")
    with pytest.raises(CaseError, match="empty"):
        s.add_finding("", [], [])
    f = s.add_finding("ok", [], [])
    with pytest.raises(CaseError, match="longer than"):
        s.update_finding(f["id"], statement=big)
    s.add_note("x" * MAX_TEXT_CHARS)


def test_decision_reason_is_capped(tmp_path):
    s = CaseStore.create(tmp_path / "c", "t")
    rids = []
    for _ in range(2):
        rid, _d = s.allocate_run()
        s.record_run({"id": rid, "kind": "run", "status": "ok"})
        rids.append(rid)
    with pytest.raises(CaseError, match="longer than"):
        s.add_decision("suppress", {}, "r" * (MAX_TEXT_CHARS + 1), rids[0], rids[1], {})


# ---- streaming reads -----------------------------------------------------------------------
def test_iter_jsonl_streams_and_skips_blank_lines(tmp_path):
    f = tmp_path / "a.jsonl"
    f.write_text('{"a":1}\n\n{"a":2}\n   \n')
    assert [x["a"] for x in Workbench._iter_jsonl(f)] == [1, 2]


# ---- convert_snort2 never follows includes ---------------------------------------------------
def test_snort2lua_is_always_run_with_no_include_flag(tmp_path, monkeypatch):
    from detection_workbench.engines.snort import plugin as plugin_mod
    from detection_workbench.runner.runner import RawRun

    seen = {}

    def fake_execute(argv, ctx, timeout_s):
        seen["argv"] = argv
        (ctx.run_dir / "stdout.txt").write_text("")
        (ctx.run_dir / "stderr.txt").write_text("")
        return RawRun(argv, 0, False, 0.0, ctx.run_dir / "stdout.txt", ctx.run_dir / "stderr.txt", ctx.backend)

    monkeypatch.setattr(plugin_mod, "execute", fake_execute)
    eng = plugin_mod.SnortEngine(Config())
    monkeypatch.setattr(eng, "has_snort2lua", lambda: True)
    for backend in ("native", "docker"):
        ctx = RunContext(run_dir=tmp_path / backend, backend=backend, cfg=Config(), etc_dir="/x", name="dw-t")
        for d in ("cfg", "out"):
            (ctx.run_dir / d).mkdir(parents=True)
        src = tmp_path / "old.conf"
        src.write_text("include other.rules\n")
        monkeypatch.setattr(plugin_mod.shutil, "which", lambda _n: "/usr/bin/snort2lua")
        eng.convert(ctx, src)
        argv = seen["argv"]
        assert argv.count("-i") == 1
