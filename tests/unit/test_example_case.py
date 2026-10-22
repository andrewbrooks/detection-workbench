"""The committed example case must stay loadable, consistent and free of local paths."""
import re
from pathlib import Path

import pytest

from detection_workbench.case.model import sha256_file
from detection_workbench.case.store import CaseStore

ROOT = Path(__file__).parents[2]
CASES = sorted((ROOT / "docs" / "examples" / "case").glob("*/case.json"))


@pytest.fixture
def store():
    assert len(CASES) == 1, "expected exactly one committed example case"
    return CaseStore(CASES[0].parent)


def test_loads_with_current_schema(store):
    s = store.summary(recent_runs=10)
    assert s["title"].startswith("Example") and len(s["evidence"]) == 2
    assert s["status"] == "closed" and "r-0003" in s["summary"] and "r-0004" in s["summary"] and "f-0001" in s["summary"]
    assert [r["kind"] for r in store.list_runs()] == ["summary", "validate", "run", "tuning"]
    assert [f["status"] for f in s["findings"]] == ["confirmed", "open"]
    d = s["decisions"][0]
    assert d["before_run"] == "r-0003" and d["after_run"] == "r-0004" and d["counts"]["1000003"] == {"before": 6, "after": 1}


def test_references_resolve_and_events_are_ordered(store):
    ids = {r["id"] for r in store.list_runs()}
    for f in store.summary()["findings"]:
        assert set(f["run_ids"]) <= ids
    ev = store.events()
    assert [e["seq"] for e in ev] == list(range(1, len(ev) + 1))
    assert [e["ts"] for e in ev] == sorted(e["ts"] for e in ev)


def test_evidence_hashes_match_the_fixtures(store):
    for item in store.summary()["evidence"]:
        real = ROOT / item["path"].replace("<repo>/", "")
        assert real.is_file() and sha256_file(real) == item["sha256"]


def test_tuning_run_differs_by_one_config_line(store):
    a = (store.root / "runs/r-0003/cfg/snort.lua").read_text().splitlines()
    b = (store.root / "runs/r-0004/cfg/snort.lua").read_text().splitlines()
    assert [l for l in b if l not in a] == [l for l in b if l.startswith("event_filter")] and len(b) == len(a) + 1


def test_no_local_paths_committed(store):
    bad = re.compile(r"/home/(?!snorty)|/Users/|/root/|/tmp/(?!$)|C:\\\\")
    for p in store.root.rglob("*"):
        if p.is_file():
            text = p.read_text(errors="replace")
            for m in bad.finditer(text):
                if m.group(0).startswith("/tmp/"):
                    continue  # the container's tmpfs mount, not a host path
                pytest.fail(f"local path {m.group(0)!r} in {p.relative_to(store.root)}")
    assert not list(store.root.rglob(".lock"))


def test_writeup_embeds_the_current_example_report_and_csv(store):
    """scripts/make_example_case.py refreshes these blocks; this fails if they drift apart."""
    text = (ROOT / "docs" / "writeup.md").read_text()
    exports = store.root / "exports"
    report = next(exports.glob("*markdown.md")).read_text().rstrip("\n")
    csv_lines = next(exports.glob("*.csv")).read_text().splitlines()
    fence = "`" * 5
    assert fence + "markdown\n" + report + "\n" + fence in text
    assert "```csv\n" + "\n".join(csv_lines[:3] + csv_lines[-1:]) + "\n```" in text


def test_stable_case_id_matches_directory(store):
    assert store.root.name == "example-marker-rule-and-syn-scan-noise"
    assert store.summary()["id"] == store.root.name
