# Case file schema (v1)

Root: `case_dir` (default `~/.detection-workbench/cases/`). Any JSON object carries `"schema_version": 1`. Readers refuse a higher major version and migrate a lower one via `case/model.py:MIGRATIONS`. Timestamps are ISO 8601 UTC with `Z`. Hashes are lowercase SHA-256 hex.

Case directories are created owner-only (`0700`), and the JSON files are written atomically.

```
<case_dir>/<case-id>/
  case.json  evidence.json  findings.json  decisions.json  notes.json  events.jsonl
  runs/<run-id>/ run.json  cfg/  out/  stdout.txt  stderr.txt  results/{summary.json,alerts.jsonl,…}
  exports/
```

- **case.json** (`summary` and `status` are set with `update_case`; each change logs a `case.updated` event): `{schema_version, id, title, created, updated, status: open|closed, summary, next_ids: {e,r,f,d,n,ev}}  (ev = event sequence counter)`
- **evidence.json:** `{schema_version, items: [{id, path (absolute, resolved), sha256, size, type: pcap|pcapng|rules|log, detected_by: magic|content|ext|user, registered, label: null|{class, technique}, copied: false, copy_path: null}]}`
  - Evidence is referenced, not copied. Hashes are re-checked before each run, and a mismatch is a hard error.
- **runs/<id>/run.json** (write-once, 0444): `{schema_version, id, kind: validate|run|profile|tuning|convert|summary, engine, engine_version, backend: native|docker, docker_image?, argv: [...], inputs: [{evidence_id, sha256, mount}], rules: {source: evidence|inline|derived, evidence_id?, sha256, path}, config: {sha256, path, options: {...typed}}, started, finished, duration_s, exit_code, timed_out, status: ok|partial|error|timeout, error_excerpt, results: {summary: "results/summary.json", alerts?: "results/alerts.jsonl"}, totals: {alerts, by_sid_top: [...]}, parent_run?: id, extra_argv: [[...]] (single-rule re-checks during validate)}`
- **alerts.jsonl** (one per line): `{alert_idx, datetime, seconds, pkt_num, pkt_gen, proto, dir, src_ip, src_port, dst_ip, dst_port, service, gid, sid, rev, msg, class, priority, action, b64_data}`
- **findings.json:** `{schema_version, items: [{id, statement, status: open|confirmed|dismissed, run_ids: [...], evidence_ids: [...], created, updated, history: [{at, field, from, to}]}]}`
  - `add_finding` refuses unknown run/evidence ids.
- **decisions.json:** `{schema_version, items: [{id, kind: suppress|event_filter|rate_filter|rule_edit, change: {...typed}, reason, before_run, after_run, counts: {sid: {before, after}}, counts_omitted? (unchanged SIDs left out of a very long list), status: proposed|accepted|rejected, created}]}`
- **notes.json:** `{schema_version, items: [{id, text, author: user|client, created}]}`
- **events.jsonl** (append-only): `{ts, seq, type: case.created|evidence.registered|run.recorded|finding.added|finding.updated|decision.recorded|note.added|export.written|case.updated, ref, data: {small diff}}`
  - `seq` is monotonic, and the full state is reconstructible from it plus the run dirs.

## Result files

Engine runs point to these through `run.json` `results`. They live under `runs/<id>/results/`.

- **summary.json** (kind `run`, `profile`, `tuning`): `{total, truncated, by_sid: [{gid, sid, rev, msg, count, distinct_sources, distinct_destinations, top_source, top_source_share}], top_sources: [[ip, n], ...], top_destinations: [[ip, n], ...], stream_caveats: {tcp_flows, unacked_flows, one_sided_flows, examples: [...], explanation}}`. `profile` runs also record `profile_rows`.
- **profile.json** (kind `profile`): `{rules: [{rank, gid, sid, rev, checks, matches, alerts, time_us, avg_check, avg_match, avg_non_match, timeouts, suspends, rule_time_pct}], unresolved_rows}`.
- **summary.json** (kind `validate`): `{ok, snort_ok, errors, warnings, lint, rechecked_individually, rules_checked}`; each diagnostic is `{severity, line, sid, error, plain, source: snort|workbench_lint, rule}`.
- **summary.json** (kind `summary`): the `pcap_summary` output (packets, bytes, time range, protocols, top sources and conversations, services).
- **alerts.jsonl**: described above. `b64_data` is Snort's inspected buffer, base64-encoded, and is never returned by `get_alerts`.

