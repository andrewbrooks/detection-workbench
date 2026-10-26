# Example case

[`case/example-marker-rule-and-syn-scan-noise/`](case/example-marker-rule-and-syn-scan-noise) is a real case produced by the workbench's own tools, not written by hand. It is what you would find under `~/.detection-workbench/cases/` after a short session on the synthetic `http_marker.pcap` fixture:

1. register a pcap and a rule file, then `pcap_summary`
2. `validate_rules`, then `run_pcap` (9 alerts from 3 rules)
3. record a confirmed finding about the marker rule
4. `test_tuning` with an `event_filter` limit on the noisy SYN rule (sid 1000003: 6 alerts become 1; the other rules are unchanged)
5. `test_tuning` again with the same fix written into the rule (`detection_filter`): the edited rules are validated first, then run, with the same result
6. record the analyst's verdict with `update_decision` (the config option rejected, the rule edit accepted) and `export_tuning` the accepted rule
7. record a second finding, add a note, write the analysis with `update_case` (which also closes the case), and export a Markdown report and a Timesketch CSV

The format is described in [../case-schema.md](../case-schema.md). Regenerate it with `uv run scripts/make_example_case.py` (needs Docker with the pinned Snort image, or native Snort 3).

## What each file is

| Path | What it holds |
|---|---|
| `case.json` | Case id, title, status, the analyst summary, timestamps and the id counters |
| `evidence.json` | The registered pcap and rules file, each with its SHA-256, size and detected type. Files are referenced, never copied |
| `findings.json` | Statements tied to run ids, with status (`open`, `confirmed`, `dismissed`) and a change history |
| `decisions.json` | Each tuning change, its reason, the before and after run ids and the per-SID counts. Status is `proposed` until the analyst accepts or rejects it; every change of status is kept in `history` |
| `notes.json` | Free-text notes |
| `events.jsonl` | Append-only log of every change, in order |
| `exports/*.md` | The Markdown report: summary, overview, evidence, findings, per-run results, decisions (with a rule diff or the config entry), caveats, timeline, notes, run appendix |
| `exports/accepted-tuning.rules` | What `export_tuning` produced from the accepted decisions: the edited rule, ready to replace the rule with the same sid. Accepted filter changes would go to a matching `.lua` file |
| `exports/*.csv` | The Timesketch-ready CSV |
| `runs/r-0001/` | `pcap_summary`: parsed capture summary only, no engine process |
| `runs/r-0002/` | `validate_rules`: the generated validation config, the rules checked, Snort's output and the parsed result |
| `runs/r-0003/` | `run_pcap`: the baseline run |
| `runs/r-0004/` | `test_tuning`: the same pcap and rules with the `event_filter` applied, linked to r-0003 by `parent_run` |
| `runs/r-0005/` | `validate_rules` on the edited rule set, run automatically before the rule edit is tested |
| `runs/r-0006/` | `test_tuning` for the rule edit |

Inside an engine run:

| Path | What it holds |
|---|---|
| `run.json` | Engine and version, backend, the exact argument list, input hashes, rule-set and config hashes, timings, exit status and result pointers. Written once and never edited |
| `cfg/` | The generated `snort.lua` and the exact `rules.rules` that Snort ran |
| `out/alert_json.txt` | Snort's raw alert output |
| `results/` | Parsed alerts (`alerts.jsonl`, one per line) and `summary.json` |
| `stdout.txt`, `stderr.txt` | Captured process output (never returned wholesale by the tools) |

## Things to notice

- `runs/r-0004/cfg/snort.lua` differs from `r-0003`'s by exactly one line, the `event_filter`. That is the whole change being tested. For the rule edit, `runs/r-0006/cfg/rules.rules` differs from `r-0003`'s in the one rule, which is what the report's diff shows.
- Every `run.json` records the Docker image digest and the arguments Snort was started with, so a run can be reproduced.
- Paths were rewritten to `<repo>/...` and `~/.detection-workbench/cases/...` when the example was generated, so no machine-specific paths are committed. Paths like `/home/snorty/...` are inside the Snort container image.
- The hashes in `evidence.json` are of the fixture files under `tests/fixtures/`, so they still match.
