# Example case

[`case/example-marker-rule-and-syn-scan-noise/`](case/example-marker-rule-and-syn-scan-noise) is a real case produced by the workbench's own tools, not written by hand. It is what you would find under `~/.detection-workbench/cases/` after a short session on the synthetic `http_marker.pcap` fixture:

1. register a pcap and a rule file, then `pcap_summary`
2. `validate_rules`, then `run_pcap` (9 alerts from 3 rules)
3. record a confirmed finding about the marker rule
4. `test_tuning` with an `event_filter` limit on the noisy SYN rule (sid 1000003: 6 alerts become 1; the other rules are unchanged)
5. record a second finding, add a note, write the analysis with `update_case` (which also closes the case), and export a Markdown report and a Timesketch CSV

The format is described in [../case-schema.md](../case-schema.md). Regenerate it with `uv run scripts/make_example_case.py` (needs Docker with the pinned Snort image, or native Snort 3).

## What each file is

| Path | What it holds |
|---|---|
| `case.json` | Case id, title, status, the analyst summary, timestamps and the id counters |
| `evidence.json` | The registered pcap and rules file, each with its SHA-256, size and detected type. Files are referenced, never copied |
| `findings.json` | Statements tied to run ids, with status (`open`, `confirmed`, `dismissed`) and a change history |
| `decisions.json` | The tuning change, its reason, the before and after run ids and the per-SID counts. Status `proposed` until a person decides |
| `notes.json` | Free-text notes |
| `events.jsonl` | Append-only log of every change, in order |
| `exports/*.md` | The Markdown report: summary, overview, evidence, findings, per-run results, decisions, caveats, timeline, notes, run appendix |
| `exports/*.csv` | The Timesketch-ready CSV |
| `runs/r-0001/` | `pcap_summary`: parsed capture summary only, no engine process |
| `runs/r-0002/` | `validate_rules`: the generated validation config, the rules checked, Snort's output and the parsed result |
| `runs/r-0003/` | `run_pcap`: the baseline run |
| `runs/r-0004/` | `test_tuning`: the same pcap and rules with the filter applied, linked to r-0003 by `parent_run` |

Inside an engine run:

| Path | What it holds |
|---|---|
| `run.json` | Engine and version, backend, the exact argument list, input hashes, rule-set and config hashes, timings, exit status and result pointers. Written once and never edited |
| `cfg/` | The generated `snort.lua` and the exact `rules.rules` that Snort ran |
| `out/alert_json.txt` | Snort's raw alert output |
| `results/` | Parsed alerts (`alerts.jsonl`, one per line) and `summary.json` |
| `stdout.txt`, `stderr.txt` | Captured process output (never returned wholesale by the tools) |

## Things to notice

- `runs/r-0004/cfg/snort.lua` differs from `r-0003`'s by exactly one line, the `event_filter`. That is the whole change being tested.
- Every `run.json` records the Docker image digest and the arguments Snort was started with, so a run can be reproduced.
- Paths were rewritten to `<repo>/...` and `~/.detection-workbench/cases/...` when the example was generated, so no machine-specific paths are committed. Paths like `/home/snorty/...` are inside the Snort container image.
- The hashes in `evidence.json` are of the fixture files under `tests/fixtures/`, so they still match.
