"""Parser tests against output recorded from real Snort 3.10.0.0 (see scripts/record_snort_outputs.py)."""
import json
from pathlib import Path

from detection_workbench.engines.snort.parse_alerts import normalize, parse_alert_file
from detection_workbench.engines.snort.parse_profile import parse_profile
from detection_workbench.engines.snort.parse_validate import parse_validation, plain_message

FIX = Path(__file__).parents[1] / "fixtures"
REC = FIX / "recorded"


def rec(name):
    return (REC / name).read_text()


# ---- validation --------------------------------------------------------------
def test_validate_good_has_only_a_warning():
    r = parse_validation(rec("validate_good.txt"), 0, (FIX / "rules/good.rules").read_text(), "good.rules")
    assert r.ok and not r.errors and r.summary_warnings == 1
    assert "fast pattern" in r.warnings[0]["error"] and r.warnings[0]["sid"] == 1000003


def test_validate_bad_reports_lines_and_sids():
    rules = (FIX / "rules/bad.rules").read_text()
    r = parse_validation(rec("validate_bad.txt"), 1, rules, "bad.rules")
    assert not r.ok
    by_line = {}
    for e in r.errors:
        by_line.setdefault(e["line"], []).append(e)
    assert by_line[2][0]["error"].startswith("unknown rule keyword: contnet") and by_line[2][0]["sid"] == 1000011
    assert by_line[7][0]["error"].startswith("'depth' must be in 3:65535") and by_line[7][0]["sid"] == 1000014
    assert {e["line"] for e in r.errors} == {2, 3, 4, 7}
    assert r.needs_individual_check == [3, 4]  # cascade candidates; line 4's pcre error was masked
    assert all(e["plain"] and e["source"] == "snort" for e in r.errors)
    assert "contnet" in by_line[2][0]["plain"]


def test_validate_ignores_other_files_and_fatal_summary():
    text = "ERROR: /cfg/validate.lua:3 boom\nERROR: /in/0/x.rules:1 unknown rule keyword: foo.\nFATAL: see prior 2 errors (0 warnings)\n"
    r = parse_validation(text, 1, "alert tcp any any -> any any ( foo:1; sid:5; )", "x.rules")
    assert [e["line"] for e in r.errors] == [1] and r.errors[0]["sid"] == 5


def test_validate_error_without_exit_zero_is_not_ok():
    assert not parse_validation("ERROR: a.rules:1 syntax error", 0, "x", "a.rules").ok


def test_plain_messages():
    assert "missing closing parenthesis" in plain_message("pcre2 compile of '(abc' failed at offset 4 : missing closing parenthesis")
    assert "within 3:65535" in plain_message("'depth' must be in 3:65535, inclusive")
    assert plain_message("something new") == "something new"


# ---- alerts ------------------------------------------------------------------
def test_normalize_datetime_uses_seconds_and_micros():
    raw = json.loads(rec("alerts_http_marker.jsonl").splitlines()[0])
    a = normalize(raw, 0)
    assert a["datetime"] == "2023-11-14T22:13:20.000000Z" and a["src_ip"] == "10.0.4.20" and a["sid"] == 1000002
    raw["timestamp"] = "11/14-22:13:20.050000"
    assert normalize(raw, 1)["datetime"].endswith(":20.050000Z")


def test_alert_file_http_marker(tmp_path):
    s = parse_alert_file(REC / "alerts_http_marker.jsonl", tmp_path / "a.jsonl", 1000)
    assert s["total"] == 9 and not s["truncated"]
    by = {r["sid"]: r for r in s["by_sid"]}
    assert by[1000001]["count"] == 1 and by[1000003]["count"] == 6 and by[1000002]["count"] == 2
    lines = [json.loads(x) for x in (tmp_path / "a.jsonl").read_text().splitlines()]
    assert [a["alert_idx"] for a in lines] == list(range(9))
    marker = next(a for a in lines if a["sid"] == 1000001)
    assert marker["pkt_gen"] == "stream_tcp" and marker["pkt_num"] == 7 and marker["service"] == "http"


def test_alert_file_noisy_summary_and_truncation(tmp_path):
    s = parse_alert_file(REC / "alerts_noisy.jsonl", tmp_path / "a.jsonl", 1000)
    noisy = next(r for r in s["by_sid"] if r["sid"] == 1000042)
    assert noisy["count"] > 300 and noisy["top_source"] == "10.0.4.20" and noisy["top_source_share"] > 0.9
    assert s["by_sid"][0]["sid"] == 1000042  # sorted by count
    t = parse_alert_file(REC / "alerts_noisy.jsonl", tmp_path / "b.jsonl", 10)
    assert t["total"] == 10 and t["truncated"]


def test_alert_file_missing_and_malformed(tmp_path):
    s = parse_alert_file(tmp_path / "nope.txt", tmp_path / "a.jsonl", 10)
    assert s["total"] == 0 and (tmp_path / "a.jsonl").read_text() == ""
    bad = tmp_path / "bad.txt"
    bad.write_text("not json\n" + rec("alerts_http_marker.jsonl").splitlines()[0] + "\n{broken\n")
    assert parse_alert_file(bad, tmp_path / "b.jsonl", 10)["total"] == 1


# ---- profile -----------------------------------------------------------------
def test_profile_splits_merged_gid_sid():
    rules = (FIX / "rules/noisy.rules").read_text()
    p = parse_profile(rec("profile_noisy.txt"), rules)
    assert p["unresolved_rows"] == 0
    top = p["rules"][0]
    assert (top["gid"], top["sid"], top["rev"]) == (1, 1000042, 1) and top["checks"] == 315 and top["alerts"] == 315
    assert top["rule_time_pct"] > 0 and top["rank"] == 1


def test_profile_without_rules_text_flags_unresolved():
    p = parse_profile(rec("profile_noisy.txt"))
    assert p["rules"] == [] and p["unresolved_rows"] >= 1


def test_profile_unmerged_columns():
    text = "rule profile (all, sorted by total_time)\n#  gid sid rev checks\n=\n1 1 5 1 10 2 2 9 1 1 1 0 0 0.5\n\n"
    r = parse_profile(text)["rules"][0]
    assert (r["gid"], r["sid"], r["checks"], r["time_us"]) == (1, 5, 10, 9)


def test_profile_other_tables_ignored():
    assert parse_profile(rec("profile_http_marker.txt"), (FIX / "rules/good.rules").read_text())["rules"]
