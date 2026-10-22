# Detection Workbench

An offline workbench, exposed as an MCP server, for writing, testing, explaining and tuning Snort 3 detections
against real evidence. Your MCP client's model does the reasoning; the server runs Snort on files you register and
returns structured, bounded results. Every answer about what a rule does is backed by actual Snort output, and every run
is written to a case file you can export as a report.

It works only on files on disk. It never sniffs an interface, runs inline, or touches a live sensor or SIEM.

A long-form write-up with a worked example, use cases and example output is in [docs/writeup.md](docs/writeup.md).
A complete example case directory, with every file explained, is in [docs/examples/](docs/examples/README.md).

## Install

Requires Python 3.12+ and [uv](https://docs.astral.sh/uv/). It runs on Linux and macOS (Windows through WSL2) and has been developed
and tested on Linux under WSL2.

```bash
git clone https://github.com/andrewbrooks/detection-workbench.git ~/detection-workbench && cd ~/detection-workbench
uv sync
```

Snort 3 is needed in one of two forms (`[snort].backend = "auto"` prefers native, then Docker):

**Docker (works anywhere Docker runs).** The official Talos image is pinned by digest:

```bash
docker pull ciscotalos/snort3@sha256:f15f714fd61ade114b1039687dd43352cae26cd6401b89f2b03404e0d21e322f
```

Runs use `--network none --read-only --cap-drop ALL --user <you>` with inputs mounted read-only. The image is Snort 3.10.0.0.

**Native.** Install Snort 3 so `snort` is on `PATH` (build from source, or Homebrew on macOS: `brew install snort`; check `snort -V` reports 3.x). Stock config is found at `<prefix>/etc/snort/`, `/usr/local/etc/snort/` or
`/opt/homebrew/etc/snort/`; override with `[snort].defaults_lua`.

Check with `get_status` once connected, or run the demo: `uv run scripts/demo_noisy_rule.py`.

## Configure

`~/.detection-workbench/config.toml` (override the path with `DW_CONFIG`). Everything is optional.

```toml
case_dir = "~/.detection-workbench/cases"   # cases live outside the repo by default
allowed_roots = ["~/captures", "~/rules"]    # evidence may only be registered from here (and the case dir)

[limits]
timeout_s = 120            # per engine process
max_input_bytes = 2147483648
max_rules_bytes = 52428800
max_alerts_returned = 200  # per call; totals are always reported
max_alerts_parsed = 250000
payload_display_bytes = 512
error_excerpt_lines = 20

[snort]
backend = "auto"           # auto | native | docker
binary = "snort"
# defaults_lua = "/usr/local/etc/snort/snort_defaults.lua"
```

`allowed_roots` is empty by default, so only files inside the case directory can be registered until you add yours.

## Connect

The server speaks MCP over stdio. Add it to any MCP client's server configuration, for example:

```json
{
  "mcpServers": {
    "detection-workbench": {
      "command": "uv",
      "args": ["--directory", "/home/you/detection-workbench", "run", "detection-workbench"]
    }
  }
}
```

The server's instructions (also exposed as the `detection_engineering` prompt) teach the client the workflow:
start a case, write → validate → run → confirm it fires and stays quiet, tune the rule before suppressing, prove changes
with `test_tuning`, and be honest about what one capture proves.

## Tools

| Area | Tools |
|---|---|
| Case | `create_case`, `open_case`, `list_cases`, `register_evidence`, `add_finding`, `update_finding`, `add_note`, `update_case` (write the analysis summary, close the case), `get_case`, `export_case` (Markdown report, Timesketch CSV) |
| Snort | `get_status`, `pcap_summary`, `validate_rules`, `run_pcap`, `get_alerts`, `explain_alert`, `profile_rules`, `suggest_tuning_targets`, `test_tuning`, `diff_runs`, `write_rules_file`, `convert_snort2` (when `snort2lua` is present) |

A case is a directory of JSON files plus an append-only `events.jsonl`; see [docs/case-schema.md](docs/case-schema.md).
Runs are immutable and record the engine and version, argument list, input hashes, and rule-set hash.

`export_case` writes a report with the analyst summary (set with `update_case`), an overview of the captures, engines and rule sets, findings, per-run alert tables, tuning decisions with before and after counts, caveats (stream warnings, truncated or failed runs, single-sample limits), an event timeline and a run appendix. The report presents recorded data; the conclusions in it are the summary the analyst or client wrote. See the [example case](docs/examples/README.md).

## Safety model

The server parses untrusted evidence and passes model-written text to native binaries, so:

- **No shell.** Commands are argument lists; there is no `shell=True` anywhere (a test greps for it).
- **No config injection.** Rules and settings go into generated files in the run directory. Values that appear in generated
  Lua pass through one typed, tested escaping module that rejects anything not plain. Snort's `--lua` is never used.
  Rule sets containing `include` directives are refused, since Snort would open the named file.
- **Path control.** Reads are limited to `allowed_roots` and the case directory after symlinks are resolved; devices, FIFOs,
  sockets and directories are refused. Evidence is hashed at registration. For every run the file is opened without following
  symlinks, its location is checked on the open file, and it is copied into the run directory while being hashed; the engine
  analyses that verified copy (deleted afterwards), so a file cannot be swapped between the check and the use, and the
  engine never sees the original filename.
- **Offline only.** The only packet source is `-r <one registered pcap>` with the pcap DAQ in read-file mode. A final gate rejects
  interface, inline, other-DAQ and plugin-path arguments, and no tool has a parameter for them.
- **Limits.** Per-run timeout that kills the whole process group (or the named container), input-size caps, alert caps per
  call, a minimal environment, and refusal to run as root. Docker runs have no network, a read-only root filesystem, and no capabilities.
- **Choose Docker for evidence you do not trust.** The Docker backend runs Snort with no network, a read-only filesystem and no
  capabilities. The native backend runs Snort as your own user with none of that isolation, so a flaw in Snort's parsing of a hostile
  capture would run with your privileges. (Access to the Docker daemon is itself powerful; only run this as a user you trust with it.)
- **Bounded output.** Raw stdout/stderr are never returned: only parsed results and a short error excerpt. Payloads are shown as
  truncated hex plus printable ASCII.
- **Write discipline.** Writes go only inside the case directory or your `allowed_roots`, at paths you name, and never through a
  symlink. Existing files, and anything registered as evidence, are never overwritten: `write_rules_file` returns a diff instead.
- **Private by default.** Case directories and the files in them are owner-only. Cell values in the CSV export that a spreadsheet
  would read as a formula (starting with `=`, `+`, `-` or `@`) are quoted, and findings and notes cannot add headings to the report.

Talos Registered/Subscriber rules need your Oinkcode and licence: the workbench never downloads them and accepts them only as
local files you point to.

## Known limitations

- **Verified on Snort 3.10.0.0 only** (the Docker image). The latest upstream is 3.12.4.0; the integration tests pin the
  behaviours below so an upgrade shows up as a test diff. Native Linux/macOS installs are supported by the code but untested.
- **Un-ACKed TCP data is not inspected by Snort 3.10**, so rules on service buffers (`http_uri` and similar) can miss on flows where
  the peer never acknowledged the request (truncated or one-sided captures). Raw-packet rules still fire. `run_pcap` reports these flows in
  `stream_caveats`; `flush_one_sided=true` recovers purely one-sided flows at the cost of changing how some raw rules match
  on them. Details in [docs/notes.md](docs/notes.md) (A6b).
- **`pkt_num` for alerts on reassembled data** is the packet that triggered the flush (usually the peer's ACK), not the packet carrying the
  matched bytes. `explain_alert` reassembles the stream itself and reports the data packets.
- **Each run temporarily copies its pcap** into the run directory (up to `max_input_bytes`) and deletes the copy afterwards, so
  large captures cost disk space and time while a run is in progress.
- **`convert_snort2` does not follow `include` lines** (it runs `snort2lua -i`). A Snort 2 config that pulls rules in with
  `include` converts only what is written in the file itself, and the result is reported as `partial` with notes naming the
  skipped lines. Convert each rules file separately.
- **Snort is silent about a rule with no `sid`.** `validate_rules` adds separate `workbench_lint` findings for this and other hygiene problems.
- **Validation reports cascade noise**: a missing `;` makes Snort misreport the next rule. The workbench re-checks suspect rules singly.
- **Evidence text reaches the model.** Packet payloads, rule messages and filenames appear in tool output, so a hostile capture
  can contain text written to look like instructions. The server's instructions tell the model to treat it as data, but that is
  guidance, not enforcement: review what the model proposes, particularly rule changes.
- **One client per server process.** The active case is server state, so concurrent clients would share it. Run one server per client.
- One capture is one sample; results on synthetic or small captures say little about production traffic.
- Phases 2 (Zeek/tshark pivots) and 3 (Zircolite/Sigma regression harness) are designed in [docs/plan.md](docs/plan.md) but not built.

## Development

```bash
uv run pytest -q                                  # unit + parser tests, no Snort needed
DW_INTEGRATION=1 uv run pytest -q tests/integration   # needs Docker or native Snort 3
uv run scripts/make_fixtures.py                   # regenerate synthetic captures (scapy)
uv run scripts/record_snort_outputs.py            # re-record real Snort output used by parser tests
```

Real-world captures are never committed. To run the opt-in real-capture test, set `DW_REAL_PCAPS` to a directory of your own pcaps
(`DW_INTEGRATION=1 DW_REAL_PCAPS=~/captures uv run pytest -q tests/integration -k real`); it is skipped when unset.

## Contributing and security

See [CONTRIBUTING.md](CONTRIBUTING.md) for setup, the rules the code relies on, and how to add an engine. Report vulnerabilities
privately as described in [SECURITY.md](SECURITY.md).

## License

Apache License 2.0. See [LICENSE](LICENSE).
