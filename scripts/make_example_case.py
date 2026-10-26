"""Build the committed example case in docs/examples/case/ from the synthetic fixtures.

Run: uv run scripts/make_example_case.py   (needs Docker with the pinned Snort image, or native Snort 3)

The case is produced by the real tools. Afterwards machine-specific absolute paths are rewritten to
placeholders (<repo>, ~/.detection-workbench/cases/...) so no local paths are committed. Hashes in the case
refer to the input files, not the JSON, so they stay valid.
"""
from __future__ import annotations

import shutil
import sys
import tempfile
from pathlib import Path

from detection_workbench.config import Config
from detection_workbench.workbench import Workbench

ROOT = Path(__file__).resolve().parents[1]
FIX = ROOT / "tests" / "fixtures"
DEST = ROOT / "docs" / "examples" / "case"
WRITEUP = ROOT / "docs" / "writeup.md"
STABLE_ID = "example-marker-rule-and-syn-scan-noise"  # the real id embeds the date; a fixed one keeps doc links valid
FENCE = "`" * 5


def build(case_dir: Path) -> Path:
    w = Workbench(Config(case_dir=case_dir, allowed_roots=(FIX.resolve(),)))
    if not w.engine.version().available:
        sys.exit(f"Snort unavailable: {w.engine.version().detail}")
    w.create_case("Example: marker rule and SYN-scan noise")
    pcap = w.register_evidence(str(FIX / "pcaps/http_marker.pcap"))["id"]
    rules = w.register_evidence(str(FIX / "rules/good.rules"))["id"]
    w.pcap_summary(pcap)
    w.validate_rules(rules_id=rules)
    before = w.run_pcap(pcap, rules_id=rules)
    f1 = w.add_finding("SID 1000001 (marker in URI) fires once, on the target request: data in packet 6, "
                       "alert reported on packet 7 (the flush trigger).", [before["run_id"]], [pcap, rules])
    w.update_finding(f1["id"], status="confirmed")
    t = w.test_tuning(before["run_id"],
                      {"kind": "event_filter", "sid": 1000003, "type": "limit", "track": "by_src",
                       "count": 1, "seconds": 60},
                      "SYN rule fires on every scan packet; volume, not presence, is the noise")
    w.add_finding(f"SID 1000003 fires {t['counts']['1000003']['before']} times from one scanner; a limit of one "
                  f"alert per source per minute leaves {t['counts']['1000003']['after']}.",
                  [before["run_id"], t["after_run"]], [pcap, rules])
    # the same noisy rule fixed from inside the rule instead of from the config: a second candidate to compare
    fixed_rule = ('alert tcp any any -> any any ( msg:"WBTEST any SYN"; flags:S; '
                  'detection_filter:track by_src,count 5,seconds 60; sid:1000003; rev:2; )')
    t2 = w.test_tuning(before["run_id"], {"kind": "rule_edit", "sid": 1000003, "rule": fixed_rule},
                       "Same effect from inside the rule, so the fix travels with the rule set instead of the sensor config")
    w.update_decision(t["decision_id"], "rejected")
    w.update_decision(t2["decision_id"], "accepted")
    w.export_tuning(path_prefix=str(w.store.root / "exports" / "accepted-tuning"))
    w.add_note("Synthetic capture bundled with the repository; results say nothing about production traffic.")
    c = t["counts"]
    w.update_case(
        summary=(
            f"**Question.** Does the marker rule fire on the target request, and which rule in this set is noisy?\n\n"
            f"**Findings.** The marker rule (sid 1000001) fires exactly once, on the request carrying "
            f"`WBTEST-MARKER-7731` ({f1['id']}, run {before['run_id']}). The only noisy rule is the SYN rule "
            f"(sid 1000003): {c['1000003']['before']} alerts, all from one scanner (10.0.4.20) sweeping five ports "
            f"on 10.0.9.9.\n\n"
            f"**Two candidate fixes, same result.** An `event_filter` limit of one alert per source per minute (run "
            f"{t['after_run']}, decision {t['decision_id']}) and a `detection_filter` written into the rule itself (run "
            f"{t2['after_run']}, decision {t2['decision_id']}) both take sid 1000003 from {c['1000003']['before']} to "
            f"{c['1000003']['after']} alerts and leave sids 1000001 and 1000002 unchanged.\n\n"
            f"**Decision.** {t['decision_id']} was rejected and {t2['decision_id']} accepted, because a fix inside the rule "
            f"travels with the rule set. The accepted rule is in `exports/accepted-tuning.rules`. The rule check notes that "
            f"sid 1000003 has no content to build a fast pattern on; that was already true before the edit.\n\n"
            f"**Limits.** One 13-packet synthetic capture. It shows the change works mechanically, not that a limit of "
            f"one per minute is right for production traffic."),
        status="closed")
    w.export_case("markdown")
    w.export_case("timesketch_csv")
    return w.store.root


def scrub(case_root: Path, replacements: list[tuple[str, str]]) -> None:
    for p in sorted(case_root.rglob("*")):
        if not p.is_file() or p.name == ".lock":
            continue
        try:
            text = p.read_text()
        except UnicodeDecodeError:
            continue
        new = text
        for a, b in replacements:
            new = new.replace(a, b)
        if new != text:
            mode = p.stat().st_mode
            p.chmod(mode | 0o200)
            p.write_text(new)
            p.chmod(mode)


def main() -> int:
    with tempfile.TemporaryDirectory() as td:
        built = build(Path(td) / "cases")
        old_id = built.name
        scrub(built, [(str(built), f"~/.detection-workbench/cases/{STABLE_ID}"), (str(ROOT), "<repo>"), (old_id, STABLE_ID)])
        (built / ".lock").unlink(missing_ok=True)
        for p in sorted(built.rglob("*"), key=lambda x: len(x.parts), reverse=True):
            if old_id in p.name:
                p.rename(p.with_name(p.name.replace(old_id, STABLE_ID)))
        if DEST.exists():
            shutil.rmtree(DEST)
        DEST.mkdir(parents=True)
        shutil.copytree(built, DEST / STABLE_ID)
    exports = DEST / STABLE_ID / "exports"
    csv_lines = next(exports.glob("*.csv")).read_text().splitlines()
    sync_writeup(next(exports.glob("*markdown.md")).read_text().rstrip("\n"), "\n".join(csv_lines[:3] + csv_lines[-1:]))
    print("wrote", DEST / STABLE_ID)
    return 0


def _replace_block(text: str, fence: str, lang: str, body: str) -> str:
    """Replace the body of the first ```lang block. Refuses to proceed if the old body looks like it spans
    other parts of the document (an unbalanced or empty block would otherwise swallow them)."""
    opener = fence + lang + "\n"
    start = text.index(opener) + len(opener)
    end = text.index("\n" + fence + "\n", start - 1)  # start - 1 so an empty block closes immediately
    old = text[start:end]
    if lang != "markdown" and "\n#" in "\n" + old:
        raise RuntimeError(f"refusing to replace a {lang} block that contains headings; the fences look unbalanced")
    if lang == "markdown" and not old.startswith("# "):
        raise RuntimeError("the embedded report block does not start with a title; the fences look unbalanced")
    return text[:start] + body + text[end:]


def sync_writeup(report: str, csv_excerpt: str) -> None:
    """The write-up embeds the example's exported report and CSV rows; refresh them so they cannot drift apart."""
    text = _replace_block(WRITEUP.read_text(), FENCE, "markdown", report)
    WRITEUP.write_text(_replace_block(text, "```", "csv", csv_excerpt))


if __name__ == "__main__":
    sys.exit(main())
