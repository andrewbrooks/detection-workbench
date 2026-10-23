# Changelog

All notable changes are recorded here. The format follows [Keep a Changelog](https://keepachangelog.com/).

## [0.1.0] - 2026-10-22

First release: Phase 1 of the plan in [docs/plan.md](docs/plan.md).

### Added
- MCP server (stdio) with 22 tools: case management, `register_evidence`, `pcap_summary`, `validate_rules`, `run_pcap`,
  `get_alerts`, `explain_alert`, `profile_rules`, `suggest_tuning_targets`, `test_tuning`, `diff_runs`, `write_rules_file`,
  `convert_snort2`, `update_case` and `export_case`, plus the `detection_engineering` prompt.
- Snort 3 engine running natively or in Docker (image pinned by digest), verified on Snort 3.10.0.0.
- Case file (schema v1): immutable runs, findings, decisions, notes and an append-only event log.
- Markdown case report (analyst summary, per-run results, decisions with before/after change, caveats, timeline) and a
  Timesketch-ready CSV export.
- Docker backend: builds a small local image from the pinned one on first use so containers run as the host user for any uid
  (the published image only admits uid 1000); the Docker CLI is found on the server's own `PATH`; `get_status` probes the
  engine the way runs execute.
- Safety layer: argument lists only, typed Lua escaping, offline-only argument gate, path checks on the open file,
  evidence verified by hash while it is copied for each run, `include` directives refused, resource limits.
- Stream caveats: `run_pcap` reports flows whose data Snort 3.10 cannot inspect because the peer never ACKed it.
- Example case in [docs/examples/](docs/examples/README.md), a demo script, and a write-up with worked examples.

### Known limitations
See *Known limitations* in the [README](README.md). Phases 2 (Zeek and tshark) and 3 (Zircolite) are designed, not built.
