import csv
import io
import json
import os
import stat

import pytest

from detection_workbench.case.export import TIMESKETCH_COLUMNS, export_markdown, export_timesketch_csv, write_export
from detection_workbench.case.model import SCHEMA_VERSION, SchemaError, check_version
from detection_workbench.case.store import CaseError, CaseStore
from detection_workbench.config import Config, ConfigError, load_config, parse_config


@pytest.fixture
def store(tmp_path):
    return CaseStore.create(tmp_path / "cases", "Noisy rule 1000042")


@pytest.fixture
def pcap(tmp_path):
    p = tmp_path / "a.pcap"
    p.write_bytes(bytes.fromhex("d4c3b2a1") + b"\0" * 20)
    return p


def test_config_defaults_outside_repo():
    c = Config()
    assert str(c.case_dir).endswith(".detection-workbench/cases")
    assert c.limits.timeout_s == 120 and c.limits.max_alerts_returned == 200


def test_config_rejects_unknown_and_bad(tmp_path):
    with pytest.raises(ConfigError):
        parse_config({"bogus": 1})
    with pytest.raises(ConfigError):
        parse_config({"limits": {"timeout_s": 0}})
    with pytest.raises(ConfigError):
        parse_config({"snort": {"backend": "podman"}})
    f = tmp_path / "c.toml"
    f.write_text('case_dir = "~/x"\n[limits]\ntimeout_s = 5\n')
    assert load_config(f).limits.timeout_s == 5


def test_create_layout_and_events(store):
    assert store.root.name.endswith("-noisy-rule-1000042")
    for n in ("case.json", "evidence.json", "findings.json", "decisions.json", "notes.json", "events.jsonl"):
        assert (store.root / n).is_file()
    ev = store.events()
    assert [e["type"] for e in ev] == ["case.created"] and ev[0]["seq"] == 1


def test_list_and_open(store, tmp_path):
    assert [c["id"] for c in CaseStore.list_cases(tmp_path / "cases")] == [store.root.name]
    assert CaseStore.open(tmp_path / "cases", store.root.name).root == store.root
    with pytest.raises(CaseError):
        CaseStore.open(tmp_path / "cases", "../x")


def test_same_title_gets_unique_id(tmp_path):
    a = CaseStore.create(tmp_path, "x")
    b = CaseStore.create(tmp_path, "x")
    assert a.root != b.root


def test_register_evidence_hash_type_dedupe(store, pcap):
    e = store.register_evidence(pcap)
    assert e["id"] == "e-0001" and e["type"] == "pcap" and len(e["sha256"]) == 64 and not e["copied"]
    assert store.register_evidence(pcap)["id"] == "e-0001"
    assert [x["type"] for x in store.summary()["evidence"]] == ["pcap"]


def test_rules_type_detection(store, tmp_path):
    r = tmp_path / "r.rules"
    r.write_text('alert tcp any any -> any 80 ( msg:"x"; sid:1000001; rev:1; )\n')
    assert store.register_evidence(r)["type"] == "rules"


def test_verify_evidence_detects_change(store, pcap):
    e = store.register_evidence(pcap)
    store.verify_evidence(e["id"])
    pcap.write_bytes(pcap.read_bytes() + b"x")
    with pytest.raises(CaseError, match="changed"):
        store.verify_evidence(e["id"])


def test_runs_immutable_and_readonly(store):
    rid, d = store.allocate_run()
    assert rid == "r-0001" and (d / "cfg").is_dir() and (d / "out").is_dir()
    store.record_run({"id": rid, "kind": "run", "status": "ok"})
    assert stat.S_IMODE(os.stat(d / "run.json").st_mode) == 0o444
    with pytest.raises(CaseError, match="immutable"):
        store.record_run({"id": rid, "kind": "run", "status": "error"})
    assert store.get_run(rid)["status"] == "ok"
    assert store.allocate_run()[0] == "r-0002"


def test_finding_lifecycle_and_refs(store):
    rid, _ = store.allocate_run()
    store.record_run({"id": rid, "kind": "run", "status": "ok"})
    with pytest.raises(CaseError):
        store.add_finding("x", ["r-9999"], [])
    with pytest.raises(CaseError):
        store.add_finding("x", [], ["e-9999"])
    f = store.add_finding("SID 1000042 fires 900 times", [rid], [])
    assert f["status"] == "open"
    f = store.update_finding(f["id"], status="confirmed")
    assert f["history"][0]["from"] == "open" and f["history"][0]["to"] == "confirmed"
    with pytest.raises(CaseError):
        store.update_finding(f["id"], status="maybe")
    with pytest.raises(CaseError):
        store.update_finding("f-0099", status="open")


def test_decision_and_note(store):
    a, _ = store.allocate_run(); store.record_run({"id": a, "kind": "run", "status": "ok"})
    b, _ = store.allocate_run(); store.record_run({"id": b, "kind": "tuning", "status": "ok"})
    d = store.add_decision("suppress", {"sid": 1}, "known scanner", a, b, {"1": {"before": 9, "after": 0}})
    assert d["id"] == "d-0001" and d["status"] == "proposed"
    assert store.add_note("hello", "user")["id"] == "n-0001"
    with pytest.raises(CaseError):
        store.add_note("x", "robot")


def test_events_append_only_and_monotonic(store, pcap):
    store.register_evidence(pcap)
    store.add_note("n")
    seqs = [e["seq"] for e in store.events()]
    assert seqs == sorted(seqs) == list(range(1, len(seqs) + 1))
    assert {"case.created", "evidence.registered", "note.added"} <= {e["type"] for e in store.events()}


def test_ids_survive_reopen(store, tmp_path):
    store.add_note("a")
    again = CaseStore.open(tmp_path / "cases", store.root.name)
    assert again.add_note("b")["id"] == "n-0002"


def test_schema_version_checks():
    with pytest.raises(SchemaError):
        check_version({}, "x")
    with pytest.raises(SchemaError, match="newer"):
        check_version({"schema_version": SCHEMA_VERSION + 1}, "x")
    assert check_version({"schema_version": SCHEMA_VERSION}, "x")["schema_version"] == SCHEMA_VERSION


def test_store_refuses_newer_schema(store):
    p = store.root / "notes.json"
    d = json.loads(p.read_text()); d["schema_version"] = 99
    p.write_text(json.dumps(d))
    with pytest.raises(SchemaError):
        store.add_note("x")


def _run_with_alerts(store):
    rid, d = store.allocate_run()
    (d / "results" / "alerts.jsonl").write_text(json.dumps({
        "alert_idx": 0, "datetime": "2023-11-14T22:13:20.050000Z", "seconds": 1700000000, "pkt_num": 6,
        "pkt_gen": "raw", "proto": "TCP", "dir": "C2S", "src_ip": "10.0.4.20", "src_port": 40000,
        "dst_ip": "203.0.113.5", "dst_port": 80, "service": "http", "gid": 1, "sid": 1000020, "rev": 1,
        "msg": "WBTEST, with comma | pipe", "class": "none", "priority": 0, "action": "allow",
        "b64_data": ""}) + "\n")
    store.record_run({"id": rid, "kind": "run", "engine": "snort", "status": "ok",
                      "results": {"alerts": "results/alerts.jsonl"}, "totals": {"alerts": 1}})
    return rid


def test_timesketch_csv(store):
    rid = _run_with_alerts(store)
    store.add_finding("one alert", [rid], [])
    rows = list(csv.DictReader(io.StringIO(export_timesketch_csv(store))))
    assert list(rows[0].keys()) == TIMESKETCH_COLUMNS
    assert {"message", "datetime", "timestamp_desc"} <= set(rows[0])
    a, f = rows
    assert a["timestamp_desc"] == "Snort alert" and a["datetime"].endswith("Z") and a["sid"] == "1000020"
    assert f["timestamp_desc"] == "Workbench finding" and f["datetime"] and f["message"] == "one alert"
    assert all(r["message"] and r["datetime"] and r["timestamp_desc"] for r in rows)


def test_markdown_report(store, pcap):
    e = store.register_evidence(pcap)
    rid = _run_with_alerts(store)
    store.add_finding("noisy", [rid], [e["id"]])
    md = export_markdown(store)
    for s in ("# Noisy rule 1000042", "## Evidence", e["sha256"], "## Findings", "noisy", "## Decisions",
              "## Appendix: runs", rid):
        assert s in md


def test_write_export_rules(store, tmp_path):
    p = write_export(store, "markdown")
    assert p.parent == store.root / "exports" and p.suffix == ".md"
    out = tmp_path / "t.csv"
    write_export(store, "timesketch_csv", out)
    with pytest.raises(FileExistsError):
        write_export(store, "timesketch_csv", out)
    write_export(store, "timesketch_csv", out, overwrite=True)
    with pytest.raises(ValueError, match="must end"):
        write_export(store, "timesketch_csv", tmp_path / "t.txt")
    assert "export.written" in {e["type"] for e in store.events()}
