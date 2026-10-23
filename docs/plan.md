# Implementation plan (Phase 1 and extension points)

## B1. Stack & layout
- Python 3.12, `uv`, `src/` layout, package `detection_workbench`.
- Dependencies: `mcp` 2.x (official SDK, `MCPServer`, stdio), `dpkt` (pcap/pcapng reading and TCP reassembly).
- Dev dependencies: `pytest`, `ruff`, `scapy` (fixture generation only).

```
pyproject.toml  LICENSE  .gitignore
README.md  docs/{notes,plan,case-schema,development,writeup}.md  docs/examples/
src/detection_workbench/
  config.py            # load TOML, defaults, validation
  workbench.py         # every tool's logic (Workbench class), testable without MCP
  server.py            # MCP server: instructions, `detection_engineering` prompt, tool declarations
  guidance.py          # the instructions/prompt text (single source)
  case/{model.py,store.py,export.py}
  safety/{paths.py,lua.py,argv.py}
  runner/{runner.py,recorder.py}
  engines/base.py      # Engine protocol + registry
  engines/snort/{plugin.py,config_gen.py,parse_alerts.py,parse_validate.py,parse_profile.py,rules.py,lint.py,explain.py}
  pcap/{reader.py,summary.py,flows.py,reassembly.py,hexdump.py}
tests/{unit,parsers,integration}/  tests/fixtures/{pcaps,rules,recorded}/
scripts/{make_fixtures.py,record_snort_outputs.py,make_example_case.py,demo_noisy_rule.py}
```

## B2. Configuration (`~/.detection-workbench/config.toml`, overridable via `DW_CONFIG`)
- `case_dir` = `~/.detection-workbench/cases`
- `allowed_roots` = [] (read roots for evidence). Case dirs are always readable and writable. If a path is outside the roots, the error names the config key to change.
- `[limits]`
  - `timeout_s=120`, `max_input_bytes=2 GiB`, `max_rules_bytes=50 MiB`
  - `max_alerts_returned=200`, `max_alerts_parsed=250_000`, `alert_json_limit_mb=512`
  - `payload_display_bytes=512`, `error_excerpt_lines=20`
- `[snort]`
  - `backend = "auto"|"native"|"docker"`. auto = native if `snort` is on PATH and reports 3.x, else docker.
  - `binary`, `defaults_lua` (override discovery)
  - `docker_image = "ciscotalos/snort3@sha256:f15f…322f"`, `docker_binary="/home/snorty/snort3/bin/snort"`, `docker_etc="/home/snorty/snort3/etc/snort"`
- Native runs refuse `euid == 0`. Docker runs with `--user <host uid>:<gid>` and refuses uid 0.

## B3. Case file (see [case-schema.md](case-schema.md)): `case/store.py`
- `CaseStore` writes atomically (temp file + `os.replace`). Every mutation appends to `events.jsonl` (under `fcntl.flock`).
- Ids are per-case sequences: `e-0001`, `r-0001`, `f-0001`, `d-0001`, `n-0001`. Case ids are `YYYYMMDD-<slug>`.
- Runs are write-once: the store refuses to rewrite `runs/<id>/run.json`, and the file is chmodded 0444.
- The active case is server state (`open_case`). Engine tools error with "create_case or open_case first" when none is active.
- Exports: `export.py` writes Markdown (summary, evidence table, findings, decisions, runs appendix) and Timesketch CSV.
  - Columns: `message,datetime,timestamp_desc,timestamp,data_type,case_id,run_id,finding_id,gid,sid,rev,msg,src_ip,src_port,dst_ip,dst_port,proto,pkt_num,pkt_gen,status`.
  - Alerts use `timestamp_desc="Snort alert"`; findings use `"Workbench finding"` (time = created).
  - Output goes to `<case>/exports/`, or a path the user names (must end `.csv`/`.md`, no overwrite unless asked).

## B4. Safety layer
- **`safety/paths.py`**
  - `resolve_read(path, kind)`: expanduser → `Path.resolve(strict=True)` (follows symlinks, so a link escaping the roots is rejected after resolution) → must be under an allowed root or the case dir → `os.stat` must be `S_ISREG` (rejects devices, FIFOs, sockets, dirs) → size cap.
  - `resolve_write(path, overwrite=False)`: parent resolved and under the roots or the case dir. Refuse if the target exists unless `overwrite`. **Never overwrite a registered evidence file** (path + hash check) or any `*.rules` file the user supplied. Write a new file or return a diff instead.
- **`safety/lua.py`**: the only way a value enters generated Lua.
  - Typed validators plus one quoting function `lua_str(value)`. It rejects non-`str`, control chars/newlines, `\`, `'`, `"`, `[`/`]` sequences that could form long brackets, `--`, and over-long values, then emits `'value'`.
  - Validators: `lua_net` (IPv4/IPv6/CIDR, `!`, `[..,..]` lists, `$VAR` from a fixed allowlist, `any`), `lua_port`, `lua_int(lo,hi)`, `lua_bool`, `lua_enum(allowed)`, `lua_path` (must resolve inside the run dir).
  - Hostile-input tests: `'; os.execute('x') --`, `]]`, `\n`, unicode tricks, NUL, `$(…)`, long strings.
- **Command building:** `runner` takes `argv: list[str]` only. `subprocess.Popen(argv, shell=False, start_new_session=True, stdin=DEVNULL, env=minimal{PATH,TZ=UTC,LC_ALL=C})`.
  - `engines/snort` builds argv from typed options. A final `assert_safe_argv()` rejects `-i`, `-Q`, `--daq` other than `pcap`, any `--daq-mode` other than `read-file`, `--lua`, `--daq-dir`, `--plugin-path`, `--script-path`, `--pcap-dir/--pcap-file/--pcap-loop`, `-s`/`--snaplen` overrides and `--shell`.
  - A unit test greps `src/` for `shell=True`, `os.system`, `os.popen`, `--lua`.
- **Docker image and user:** containers run as the host uid. The pinned image only lets uid 1000 into `/home/snorty`, so the engine builds `detection-workbench/snort3:<digest>-<hash>` from it (`engines/snort/image.py`: `chmod o+x` on the directories above the install, built with `--network none`) and probes it as the host user with the run-time flags before reporting Snort as available. The Docker CLI is resolved on the server's own `PATH` (`docker_bin()`) because engines run with a minimal one. See notes.md A12.
- **Writes and exports:** `write_text_safely` creates files exclusively (or truncates an existing regular file) with `O_NOFOLLOW`, so a link placed after vetting is not followed; an existing file is read for a diff only through the checked open. Case directories are created `0700`, JSON is written atomically and fsynced, CSV cells that begin with `=`, `+`, `-`, `@` or a control character are prefixed with a quote, and findings and notes are collapsed to one line in the report.
- **Bounded responses and memory:** lists returned to the client are capped (`MAX_SID_ROWS`), per-SID decision counts are trimmed to `MAX_DECISION_COUNTS` (with `counts_omitted`), engine output is read through `read_capped`, flow and address tables are capped, and validation re-checks share one time budget.
- **Verified evidence:** `safety/verified.py` opens evidence with `O_NOFOLLOW`, confirms on the descriptor that it is a regular file inside the allowed roots (via `/proc/self/fd`, or `F_GETPATH` on macOS), and copies it into the run directory while hashing the bytes read. A mismatch removes the copy and raises `EvidenceChanged`; the engine only ever sees the verified copy, which is deleted after the run. Rules files are read through `read_verified`.
- **Rule sets and mounts:** Snort follows `include` lines in a rules file, so rule sets containing one are refused (`find_includes`, checked for registered files and inline text alike). For the Docker backend every host path in a `-v` mount is checked for `:`, `,`, quotes and control characters, and in-container names are sanitized, so a filename cannot change how a mount is parsed.
- **Offline-only:**
  - The only packet input is `-r <registered pcap>` with `--daq pcap --daq-mode read-file`.
  - Generated configs never set `daq`, `ips.mode` or anything inline.
  - Tools expose no interface or inline parameter. Requests for one get a fixed refusal message.
- **Limits:**
  - Timeout: on expiry, kill the process group (native) or `docker kill dw-<case>-<run>` (the container is named per run), then mark the run `timed_out`.
  - Stdout/stderr stream to files in the run dir. Tools return only parsed results plus an error excerpt of ≤20 lines/2 KiB.
  - `alert_json.limit` caps file size. Parsing stops at `max_alerts_parsed` with `truncated=true`, and totals are reported.
- **Docker flags:** `docker run --rm --name dw-… --network none --cap-drop ALL --security-opt no-new-privileges --pids-limit 256 --memory 2g --read-only --tmpfs /tmp --user uid:gid --entrypoint <docker_binary>`.
  - Each evidence file is mounted `:ro` at `/in/<eid>/<name>`, the run's generated inputs `:ro` at `/cfg`, and only `<run>/out` rw at `/out`.
  - If `--read-only` breaks Snort, drop it and record that in notes.md.
- **Payload display:** `hexdump(bytes, limit)` → offset, hex, ASCII with `.` for non-printables, truncated with a `"truncated": N` marker.

## B5. Engine plugin interface (`engines/base.py`)
```python
class Engine(Protocol):
    name: str                              # "snort"
    evidence_types: set[str]               # {"pcap"}; zeek later {"pcap"}, zircolite {"evtx","jsonl"}
    def version(self) -> EngineVersion     # cached at startup per backend
    def validate(self, rules: RuleSource, ctx: RunContext) -> ValidationResult
    def run(self, evidence: list[Evidence], rules: RuleSource | None, options: dict, ctx: RunContext) -> RawRun
    def parse(self, raw: RawRun) -> ParsedResults   # writes results/*.jsonl + summary.json
```
- `RunContext` holds the run dir, backend, limits and a mount map.
- The runner records the run (see case-schema.md) around `run()` and `parse()`, so plugins never touch the case store. A registry maps names to plugins, and `get_status` iterates it.

**Snort plugin specifics**
- `config_gen.py` writes `<run>/cfg/snort.lua` from typed options using notes.md A3 as the base. It adds:
  - `profiler` when profiling
  - filter tables for tuning
  - a fixed `alert_json.fields` list: `timestamp seconds pkt_num proto pkt_gen pkt_len dir src_addr src_port dst_addr dst_port service rule gid sid rev msg class priority action b64_data`
  - the inspectors `http_inspect`, `dns`, `ssl` and `ssh` (more can be added the same way, each checked with `-T` first)
- **validate:** argv `[snort,-c,cfg/validate.lua,-R,rules,-T,--warn-all]`.
  - `parse_validate.py` maps `ERROR|WARNING: file:line msg` lines to `{line, sid, rule_excerpt, severity, error, plain}`. `plain` is a plain-language rewrite from a small message table. The sid is read from the rule text at that line.
  - **Cascade handling:** if an error is `syntax error`/`unknown rule action`/`incomplete rule`, re-validate each flagged rule and the following rule as single-rule files (≤20 extra runs) and replace the cascaded errors. Output notes "re-checked individually".
  - Inline rules are written to `<run>/cfg/inline.rules` first.
  - Validation is recorded as a lightweight run (`kind: validate`).
- **Workbench lint (`lint.py`)** runs alongside and is reported separately as `source: "workbench_lint"` so provenance stays clear. Checks:
  - missing `sid` (Snort is silent!), missing `rev`/`msg`, sid < 1 000 000, duplicate sid
  - a sticky buffer without `service:` / protocol `http`
  - no `content` (no fast pattern)
  - `content` without anchoring when the protocol allows it.
- **run:** argv `[snort,-c,cfg/snort.lua,-R,rules,-r,pcap,--daq,pcap,--daq-mode,read-file,-A,alert_json,-l,out,-q,-z,1]`.
  - `parse_alerts.py` streams `out/alert_json.txt`.
  - Datetime comes from `seconds` + the µs in `timestamp`, in UTC.
  - Writes `results/alerts.jsonl` (normalized, with `alert_idx`) and `summary.json` (totals, counts by sid with msg, by src, by dst).
- **Un-ACKed data caveat (notes.md A6b):**
  - Before each run, `pcap/flows.py` scans the pcap (dpkt) for TCP flows whose trailing payload in either direction was never ACKed by the peer, and for one-sided flows.
  - `run_pcap` returns `stream_caveats: {unacked_flows: N, one_sided_flows: M, examples:[…≤10]}` with a fixed explanation: *Snort 3.10 doesn't inspect TCP data its peer never ACKed, so service-buffer rules can miss here, while raw-packet rules still fire.*
  - Typed option `flush_one_sided: bool=false` sets `asymmetric_ids_flush_threshold=1`, with the documented side effect on raw rules for those flows.
  - Integration tests pin all five flow endings from notes.md A6b so an engine upgrade (3.12.x) shows up as a test diff.
- **profile:** a run with `profiler` enabled; `parse_profile.py` reads stdout. It splits merged gid/sid tokens by matching the loaded rule set and flags unresolved ones.
- **explain_alert** (`explain.py` + `pcap/reassembly.py`):
  - Rule text is looked up by gid:sid:rev in the run's rules copy. `rules.py` is a tolerant option parser that handles `content` modifiers, `|hex|`, nocase, offset/depth/distance/within, pcre, sticky buffers, flow and service.
  - `pkt_gen == "raw"`: read packet `pkt_num` and search the content/pcre literals in its payload.
  - `pkt_gen != "raw"`: select the alert-direction packets of the 5-tuple whose index ≤ `pkt_num` and whose ts ≥ the alert ts. Reassemble them by seq (handling retransmits and overlap first-wins), keeping a byte→(packet index, offset in packet) map.
  - Search the reassembled stream **and** separately the decoded `b64_data` (labeled "Snort's inspected buffer").
  - pcre is translated to Python `re` when possible, else "not evaluated locally".
  - Output facts: rule text, parsed options, 5-tuple/dir/service, trigger packet vs data packets, a bounded hexdump with match offsets, and which options matched where, labeled by source (`wire_reassembled` / `inspector_buffer`).
  - Note: sticky-buffer offsets are relative to the buffer, so a match found in the raw stream is "present" but not proof of that buffer's offset.
- **tuning** (`test_tuning`): structured input `{type: suppress|event_filter|rate_filter|rule_edit, …typed fields}`.
  - Filters go into a copy of the config via `lua.py`. `rule_edit` = replacement rule text for one sid, validated first and written to a rules copy in the run dir.
  - Re-runs the same pcap with the same options as the `before_run`, then returns before/after counts per sid.
  - Records a decision automatically (status `proposed` until the user confirms).

## B6. Tools (descriptions written for the model, each with a one-line example)
- **Case:** `create_case(title)`, `open_case(case_id)`, `list_cases()`, `register_evidence(path, type?, label?)`, `add_finding(statement, run_ids, evidence_ids)`, `update_finding(id, status?, statement?)`, `add_note(text)`, `update_case(summary?, status?)`, `get_case()`, `export_case(format=markdown|timesketch_csv, path?)`
  - Type detection uses magic bytes: pcap `a1b2c3d4`/`d4c3b2a1`/ns variants, pcapng `0a0d0d0a`. A rules file is text containing a rule-header regex.
- **Snort:**
  - `get_status`
  - `pcap_summary(evidence_id)`: dpkt-based, not an engine run, but recorded as a `kind: summary` run for provenance.
  - `validate_rules(rules_evidence_id | rules_text)`
  - `run_pcap(pcap_id, rules_id | rules_text, home_net?, options{flush_one_sided, profile, extra: typed dict})`
  - `get_alerts(run_id, sid?, src?, dst?, pkt_from?, pkt_to?, offset, limit)`
  - `explain_alert(run_id, alert_idx)`
  - `profile_rules(pcap_id, rules_id, top=20)`
  - `suggest_tuning_targets(run_id)`: ranks by count, distinct src/dst, top-source share.
  - `test_tuning(before_run_id, change, reason)`
  - `diff_runs(a, b)`: added/removed/changed by sid, alerts keyed by (sid, pkt_num, src, dst).
  - `write_rules_file(path, rules_text, overwrite=false)`
  - `convert_snort2(conf_path | rules_path)`: registered only if `snort2lua` is present.
- Every engine tool records a run. Each returns a compact dict (ids, totals, capped lists with `total`/`returned`).
- **Guidance:** the prompt's six bullets live in `guidance.py`, used for both FastMCP `instructions` and `@mcp.prompt("detection_engineering")`.

## B7. Phase 2/3 extension points (design only)
- **Engines** register in `engines/base.py` with their `evidence_types`. The runner, safety layer and case store are unchanged. Run records already carry `engine`, `engine_version`, `backend`, `inputs[]`, `argv` and `results` pointers.
- **Zeek (P2):**
  - `ZeekEngine.run` writes logs to `<run>/out`; `parse` emits `results/conn.jsonl`, `http.jsonl`, …
  - `pivot_alert(run_id, alert_idx, zeek_run_id)` joins on 5-tuple ± time window, then on `uid`, then calls tshark (`TsharkEngine`, argv-only, `-r` only) with a display filter built by a validated filter builder (same pattern as `lua.py`).
  - `pcap/flows.py` 5-tuple normalization is shared.
- **Zircolite (P3):**
  - Evidence gains an optional `label: {class: malicious|benign, technique?: "T1059.001"}`; the schema already reserves it (see case-schema.md).
  - `test_sigma_rule` runs Zircolite over the labeled set and writes `results/matches.jsonl`. `baselines/<rule-hash>.json` in the case stores TP/FN/FP; `regression_check` diffs against it.
  - New evidence types are `evtx` and `jsonl`, through the same path checks.
- **Integration:** Chainsaw, Hayabusa and Timesketch output can be registered as evidence type `external_results` (hashed, read-only). The Timesketch CSV export is already Phase 1.

## B8. Build order
0. Scaffolding: `.gitignore` (includes `cases/`), `pyproject.toml`, `uv sync`.
1. `config.py` + `case/` + tests (schema v1 round-trip, version check, events append, immutability, exports incl. Timesketch columns).
2. `safety/` + `runner/` + tests (argv only, `lua.py` hostile inputs, symlink escape/device/FIFO, timeout kill for native and docker, size caps).
3. `scripts/make_fixtures.py` (scapy: HTTP-with-marker, DNS, port scan, benign background, the five notes.md A6b flow endings, a noisy pcap) → commit pcaps. Record real Snort outputs into `tests/fixtures/recorded/`.
4. Snort plugin + parsers + `pcap/` + tests against recorded output.
5. Tools + `server.py` + guidance. Opt-in integration tests (`DW_INTEGRATION=1`; real captures from `DW_REAL_PCAPS`, skipped when unset).
6. `scripts/demo_noisy_rule.py` (MCP stdio client session), README, `docs/development.md`.


## B9. Deviations from the original plan
- Filters in `test_tuning` use `change.kind` as the discriminator (`suppress`, `event_filter`, `rate_filter`, `rule_edit`) so `type` can be Snort's own `event_filter` field.
- Tool logic lives in `workbench.py` (`Workbench` class); `server.py` only declares MCP tools. The recorder is `runner/recorder.py`.
- Rules are always copied into the run's `cfg/rules.rules`, so `explain_alert` and `test_tuning` read exactly what Snort ran.
- Bad caller input (`ValueError`) removes the empty run directory and leaves no run record; engine/infrastructure failures are recorded as `status: error` runs.
- `pcap_summary` is recorded as `kind: summary`, `engine: dpkt`.
- Validation re-checks suspect rules singly (up to 20 extra Snort processes) when a cascade-prone error appears; the extra argument lists are stored as `extra_argv`.
- Caller-fixable errors (no active case, path outside `allowed_roots`, bad argument) are converted to the SDK's `ToolError` in `server.py`, so the model reads the actionable message instead of a generic failure.
- Free-text fields are capped (`MAX_TEXT_CHARS` for notes, findings and decision reasons; `MAX_SUMMARY_CHARS` for the case summary), and alert files are streamed rather than read whole.

## Verification
- `uv run pytest -q`: unit and parser tests pass with no Snort.
- `DW_INTEGRATION=1 uv run pytest -q tests/integration`. Expected:
  - good/bad rule validation reports the notes.md A1 messages with lines
  - `http_marker.pcap` fires sid→pkt_num as in notes.md A6
  - the five flow endings match notes.md A6b
  - `test_tuning` lowers noisy-sid counts
  - a timeout kills the process or container
  - every run lands in `case.json`/`events.jsonl`.
- `uv run scripts/demo_noisy_rule.py` end to end → Markdown report in the case `exports/`.
- Register the server with an MCP client (see the README), then call `get_status`.
