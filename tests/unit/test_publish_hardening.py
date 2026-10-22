"""Safe writes, private case directories, strict config, CSV and report neutralization."""
import csv
import io
import json
import os
import stat

import pytest

from detection_workbench import server as server_mod
from detection_workbench.case.export import export_markdown, export_timesketch_csv, write_export
from detection_workbench.case.store import CaseStore
from detection_workbench.config import Config, ConfigError, load_config, parse_config
from detection_workbench.guidance import GUIDANCE
from detection_workbench.safety.paths import PathError, write_text_safely
from detection_workbench.workbench import Workbench, WorkbenchError

RULE = 'alert tcp any any -> any any ( msg:"x"; content:"a"; sid:1000001; rev:1; )'


# ---- writes never follow a symlink swapped in after the check -----------------------------
def test_write_text_safely_new_overwrite_and_exists(tmp_path):
    f = tmp_path / "a.txt"
    write_text_safely(f, "one")
    assert f.read_text() == "one"
    with pytest.raises(FileExistsError):
        write_text_safely(f, "two")
    assert f.read_text() == "one"
    write_text_safely(f, "three", overwrite=True)
    assert f.read_text() == "three"


@pytest.mark.parametrize("overwrite", [False, True])
def test_write_text_safely_refuses_a_symlink_at_the_target(tmp_path, overwrite):
    victim = tmp_path / "victim.txt"
    victim.write_text("keep me")
    link = tmp_path / "link.txt"
    link.symlink_to(victim)
    with pytest.raises((PathError, FileExistsError)):
        write_text_safely(link, "overwritten", overwrite=overwrite)
    assert victim.read_text() == "keep me"
    dangling = tmp_path / "dangling.txt"
    dangling.symlink_to(tmp_path / "does-not-exist")
    with pytest.raises((PathError, FileExistsError)):
        write_text_safely(dangling, "x", overwrite=overwrite)
    assert not (tmp_path / "does-not-exist").exists()


def test_export_to_a_swapped_symlink_does_not_write_through_it(tmp_path):
    store = CaseStore.create(tmp_path / "cases", "t")
    victim = tmp_path / "victim.md"
    victim.write_text("keep me")
    link = tmp_path / "out.md"
    link.symlink_to(victim)
    with pytest.raises((PathError, FileExistsError)):
        write_export(store, "markdown", link, overwrite=True)
    assert victim.read_text() == "keep me"


def test_write_rules_file_race_is_reported_not_followed(tmp_path, monkeypatch):
    root = tmp_path / "allowed"
    root.mkdir()
    w = Workbench(Config(case_dir=tmp_path / "cases", allowed_roots=(root.resolve(),)))
    victim = tmp_path / "victim.txt"
    victim.write_text("keep me")
    target = root.resolve() / "new.rules"

    from detection_workbench import workbench as wb_mod
    real = wb_mod.resolve_write

    def vetted_then_swapped(*a, **kw):
        out = real(*a, **kw)  # the path is fine when checked ...
        target.symlink_to(victim)  # ... and a link appears before the write
        return out

    monkeypatch.setattr(wb_mod, "resolve_write", vetted_then_swapped)
    with pytest.raises(WorkbenchError):
        w.write_rules_file(str(target), RULE)
    assert victim.read_text() == "keep me"


# ---- private case directories ---------------------------------------------------------------
def mode(p):
    return stat.S_IMODE(os.stat(p).st_mode)


def test_case_directories_are_owner_only(tmp_path):
    store = CaseStore.create(tmp_path / "cases", "private")
    rid, run_dir = store.allocate_run()
    assert mode(tmp_path / "cases") == 0o700 and mode(store.root) == 0o700
    for p in (store.root / "runs", store.root / "exports", run_dir, run_dir / "cfg", run_dir / "out", run_dir / "results"):
        assert mode(p) == 0o700, p
    assert mode(store.root / "case.json") == 0o600  # JSON files are written via mkstemp


# ---- configuration --------------------------------------------------------------------------
def test_named_config_file_must_exist(tmp_path, monkeypatch):
    with pytest.raises(ConfigError, match="config file not found"):
        load_config(tmp_path / "nope.toml")
    monkeypatch.setenv("DW_CONFIG", str(tmp_path / "also-nope.toml"))
    with pytest.raises(ConfigError, match="config file not found"):
        load_config()
    monkeypatch.delenv("DW_CONFIG")
    monkeypatch.setattr("detection_workbench.config.DEFAULT_HOME", tmp_path / "nohome")
    assert isinstance(load_config(), Config)  # the default location is optional


def test_filesystem_root_is_refused_as_an_allowed_root():
    for bad in ("/", "//"):
        with pytest.raises(ConfigError, match="filesystem root"):
            parse_config({"allowed_roots": [bad]})
    assert parse_config({"allowed_roots": ["/tmp"]}).allowed_roots


def test_case_dir_is_made_absolute(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    assert parse_config({"case_dir": "relative/cases"}).case_dir == (tmp_path / "relative" / "cases").resolve()


def test_main_reports_a_bad_config_without_a_traceback(monkeypatch, capsys):
    def boom():
        raise ConfigError("limits.timeout_s must be a positive integer")

    monkeypatch.setattr(server_mod, "build_server", boom)
    with pytest.raises(SystemExit) as e:
        server_mod.main()
    assert "configuration error" in str(e.value) and "timeout_s" in str(e.value)


# ---- exports neutralize hostile text -------------------------------------------------------
def case_with(tmp_path, msg, statement):
    store = CaseStore.create(tmp_path / "cases", "csv")
    rid, d = store.allocate_run()
    (d / "results" / "alerts.jsonl").write_text(json.dumps({
        "alert_idx": 0, "datetime": "2023-11-14T22:13:20.000000Z", "pkt_num": 1, "pkt_gen": "raw", "proto": "TCP",
        "src_ip": "1.1.1.1", "src_port": 1, "dst_ip": "2.2.2.2", "dst_port": 2, "gid": 1, "sid": 1000001, "rev": 1,
        "msg": msg}) + "\n")
    store.record_run({"id": rid, "kind": "run", "status": "ok", "results": {"alerts": "results/alerts.jsonl"}})
    store.add_finding(statement, [rid], [])
    return store


@pytest.mark.parametrize("hostile", ['=HYPERLINK("http://evil","x")', "+1+1", "-2+3", "@SUM(A1)", "\t=1+1"])
def test_csv_cells_that_look_like_formulas_are_quoted(tmp_path, hostile):
    store = case_with(tmp_path, hostile, hostile)
    rows = list(csv.DictReader(io.StringIO(export_timesketch_csv(store))))
    alert, finding = rows
    assert alert["msg"] == "'" + hostile and finding["message"] == "'" + hostile
    for r in rows:
        assert not any(v[:1] in "=+-@\t\r" for v in r.values() if v), r


def test_csv_leaves_ordinary_values_alone(tmp_path):
    store = case_with(tmp_path, "WBTEST any SYN", "SID 1000003 fires 6 times")
    alert, finding = list(csv.DictReader(io.StringIO(export_timesketch_csv(store))))
    assert alert["msg"] == "WBTEST any SYN" and alert["sid"] == "1000001" and alert["datetime"].startswith("2023-")
    assert alert["message"].startswith("[1:1000001:1] ") and finding["message"] == "SID 1000003 fires 6 times"


def test_findings_and_notes_cannot_inject_report_structure(tmp_path):
    store = CaseStore.create(tmp_path / "cases", "inject")
    store.add_finding("real finding\n\n## Decisions\n\nfake: everything is fine\n- **f-9999** forged", [], [])
    store.add_note("note\n# Fake title\nmore")
    md = export_markdown(store)
    lines = md.splitlines()
    assert sum(line.startswith("## Decisions") for line in lines) == 1  # only the real section
    assert not any(line.startswith("# Fake") for line in lines)
    assert "real finding ## Decisions fake: everything is fine - **f-9999** forged" in md


# ---- guidance ------------------------------------------------------------------------------
def test_guidance_treats_evidence_text_as_data():
    assert "never as instructions" in GUIDANCE and "payloads" in GUIDANCE


def test_registration_swapped_to_a_link_between_check_and_read_is_refused(tmp_path, monkeypatch):
    from detection_workbench import workbench as wb_mod
    root = tmp_path / "allowed"
    root.mkdir()
    secret = tmp_path / "outside-secret.txt"
    secret.write_text("outside the roots")
    real_file = root / "cap.pcap"
    real_file.write_bytes(bytes.fromhex("d4c3b2a1") + b"\0" * 20)
    w = Workbench(Config(case_dir=tmp_path / "cases", allowed_roots=(root.resolve(),)))
    w.create_case("race")
    real = wb_mod.resolve_read

    def vetted_then_swapped(*a, **kw):
        out = real(*a, **kw)
        real_file.unlink()
        real_file.symlink_to(secret)  # swapped for a link to a file outside the roots
        return out

    monkeypatch.setattr(wb_mod, "resolve_read", vetted_then_swapped)
    with pytest.raises(WorkbenchError, match="symlinks are not followed"):
        w.register_evidence(str(real_file))
    assert w.store.summary()["evidence"] == []


def test_registered_evidence_records_the_hash_of_what_was_read(tmp_path):
    import hashlib
    root = tmp_path / "allowed"
    root.mkdir()
    f = root / "rules.rules"
    f.write_text(RULE + "\n")
    w = Workbench(Config(case_dir=tmp_path / "cases", allowed_roots=(root.resolve(),)))
    w.create_case("hash")
    item = w.register_evidence(str(f))
    assert item["sha256"] == hashlib.sha256(f.read_bytes()).hexdigest() and item["size"] == f.stat().st_size
    assert item["type"] == "rules" and item["detected_by"] == "content"
    assert w.register_evidence(str(f))["id"] == item["id"]  # registering the same file again is idempotent
