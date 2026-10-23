# Development notes

Offline MCP server: write, test, explain and tune Snort 3 detections against real engine output, recorded in a case file.
Never captures live, never inline. Phase 1 (case file, runner, safety, Snort 3) is built; Phases 2 (Zeek/tshark) and 3 (Zircolite) are design only.

## Docs
- docs/notes.md      verified Snort 3.10.0.0 behavior (validation, alert_json, pkt_num, un-ACKed data, profiling)
- docs/plan.md       architecture, safety layer, tools, Phase 2/3 extension points, deviations (B9)
- docs/case-schema.md  case file format (schema v1)
- docs/writeup.md    walkthrough, use cases and example output
- CONTRIBUTING.md, SECURITY.md   contribution rules and vulnerability reporting (repository root)

## Commands
- Tests (no Snort needed):    `uv run pytest -q`
- Integration (needs Docker): `DW_INTEGRATION=1 uv run pytest -q tests/integration`
- Run the server (stdio):     `uv run detection-workbench`
- As a CI runner (uid 1001):  `scripts/ci_parity.sh` or `scripts/ci_parity.sh unit` (Linux, needs Docker)
- Demo end to end:            `uv run scripts/demo_noisy_rule.py`
- Regenerate the example case: `uv run scripts/make_example_case.py` (needs Docker/Snort; a unit test checks it stays valid)
- Regenerate fixtures:        `uv run scripts/make_fixtures.py`, then `uv run scripts/record_snort_outputs.py`
- Docker image (pinned in config.py): `docker pull ciscotalos/snort3@sha256:f15f714f...`

## Layout
src/detection_workbench/: config.py, workbench.py (all tool logic), server.py (MCP declarations),
case/ (store, export), safety/ (paths, lua escaping, argv gate), runner/ (runner, recorder),
engines/ (base protocol; snort/ plugin, config_gen, parsers, lint, rules, explain), pcap/ (reader, flows, reassembly).

## Rules for changes
- argv lists only; never shell=True, never `--lua`; caller values reach Lua only through safety/lua.py.
- Cases default to ~/.detection-workbench/cases (outside the repo; cases/ is in .gitignore).
- Runs are immutable. Evidence is referenced, hashed, never modified.
- mcp is 2.x: use mcp.server.mcpserver.MCPServer, not FastMCP.

## Status
Phase 1 complete: the unit/parser tests and the integration tests pass on Snort 3.10.0.0 (Docker).
Not yet verified on Snort 3.12.x (latest upstream 3.12.4.0) or native Linux/macOS installs.
Next: Phase 2 (add ZeekEngine/TsharkEngine, pivot_alert) per docs/plan.md B7.
