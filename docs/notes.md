# Verification notes

Verified on **Snort 3.10.0.0** (DAQ 3.0.23, Hyperscan 5.4.2, PCRE2 10.46, LuaJIT 2.1) inside `ciscotalos/snort3@sha256:f15f714fd61ade114b1039687dd43352cae26cd6401b89f2b03404e0d21e322f` (built 2026-01-09). The latest upstream is **3.12.4.0 (2026-10-21)**, which is also the Homebrew formula. Nothing here was re-verified on 3.12.x. The integration tests pin each behavior so a newer engine shows any change. Test pcaps were generated with scapy (13–23 packets, known indices).

## A1. `-T` validation
- `snort -T -R rules` works **without `-c`** (exit 0, about 0.22 s in Docker including container start). Without `-c`, `$HOME_NET`, `$EXTERNAL_NET` and `$HTTP_PORTS` are undefined (`ERROR: f:1 Undefined variable…`, `FATAL: …PortVar Lookup failed`). → Validate with a generated minimal config that includes `snort_defaults.lua` (same speed: about 0.22 s).
- Error format, one per line on stderr/stdout: `ERROR: <file>:<line> <message>`, then `FATAL: see prior N errors (M warnings)`. Exit code 1 if there are errors, 0 otherwise.
- Observed messages: `unknown rule keyword: contnet.`; `syntax error`; `unknown rule action '…'`; `incomplete rule`; `pcre2 compile of '(abc' failed at offset 4 : missing closing parenthesis`; `'depth' must be in 3:65535, inclusive`.
- **Cascade:** a missing `;` on line N also produces bogus errors on line N+1 and **hides that line's real error**. In the test, line 4's pcre error was masked.
- **Silent cases:** a rule with **no `sid`** gets no error or warning, even with `--warn-all`. A duplicate sid only gets `WARNING: f:2 1:1000010 duplicates previous rule. Using revision 1.` (the summary also shows `duplicate rules: 1`).
- `--warn-all` adds e.g. `WARNING: port rule 1:1000013:1 has no fast pattern` (this one has no file:line). Successful runs print `Snort successfully validated the configuration (with N warnings).`

## A2. `alert_json`
- Parameters: `file` (bool, false = stdout), `limit` (MB rollover, 0 = unlimited), `separator` (default `', '`), `fields`.
- All fields: `action class b64_data client_bytes client_pkts dir dst_addr dst_ap dst_port eth_dst eth_len eth_src eth_type flowstart_time geneve_vni gid icmp_code icmp_id icmp_seq icmp_type iface ip_id ip_len msg mpls pkt_gen pkt_len pkt_num priority proto rev rule seconds server_bytes server_pkts service sgt sid src_addr src_ap src_port target tcp_ack tcp_flags tcp_len tcp_seq tcp_win timestamp tos ttl udp_len vlan`.
- One JSON object per line. `timestamp` is `"MM/DD-HH:MM:SS.ffffff"`, **with no year**, in the process TZ. `class` is `"none"` when the rule has no classtype. `service` is `"unknown"` when no service was identified. The file is written mode 0600.

## A3. Minimal config

This config was verified to process pcaps and identify HTTP:
```lua
HOME_NET='…'; EXTERNAL_NET='!$HOME_NET'
include '<stock>/snort_defaults.lua'      -- absolute path; a relative include resolves against the -c dir
stream={} stream_ip={} stream_tcp={} stream_udp={} http_inspect={} dns={} wizard=default_wizard
ips={ variables=default_variables, enable_builtin_rules=false }
alert_json={ file=true, fields='…' }
```
It needs no `binder`; the defaults plus the wizard bind services. Stock config locations:
- Docker image: `/home/snorty/snort3/etc/snort/`. The binary is at `/home/snorty/snort3/bin/snort` and is **not on PATH**. The image's entrypoint is `/bin/sh -c /bin/bash`, so it must be overridden with `--entrypoint`. Default user `snorty` (uid 1000).
- Source build: `<prefix>/etc/snort/` (CMake default `/usr/local/etc/snort/`).
- Homebrew: `$(brew --prefix)/etc/snort/` (`/opt/homebrew` on Apple Silicon, `/usr/local` on Intel). Unconfirmed.
- Discovery rule: `<binary>/../etc/snort/snort_defaults.lua`, then those fallbacks, then the config override.
- Stock `snort.lua` leaves `alert_json.file` false (alerts go to stdout), so the workbench always generates its own config.

## A4. Filters

Filters are Lua config tables only (no rule-file syntax confirmed):
- `suppress = { {gid=,sid=,track='by_src'|'by_dst',ip=''} }`
- `event_filter = { {gid=,sid=,type='limit'|'threshold'|'both',track='by_src'|'by_dst',count=,seconds=,ip=''} }`
- `rate_filter = { {gid=,sid=,track='by_src'|'by_dst'|'by_rule',count=,seconds=,new_action=,timeout=,apply_to=''} }`
- Ranges: gid 0:8129, sid 0:max32, count -1:max31.

## A5. Rule profiling
- Turned on by `profiler = { rules = { show=true, count=0, sort='total_time' } }`; there's no CLI flag. Printed to **stdout at shutdown**, even with `-q`, under the heading `rule profile (all, sorted by total_time)`.
- Columns: `# gid sid rev checks matches alerts time (us) avg/check avg/match avg/non-match timeouts suspends rule_time (%)`.
- **Gotcha:** with 7-digit sids the `gid` and `sid` columns run together (`11000002` is gid 1, sid 1000002). The parser must split them using the set of loaded (gid, sid) pairs.
- A module profile table is printed too.

## A6. `pkt_num` alignment
- `pkt_gen: "raw"` → `pkt_num` is the **1-based pcap packet index**. Verified on 20+ alerts across UDP, TCP SYN and TCP data.
- `pkt_gen: "stream_tcp"` (any rule matched on reassembled/service data, e.g. `http_uri`) → `pkt_num` is the **packet that triggered the flush**, normally the peer's ACK. Example: request at 4, server ACK at 8, alert says 8.
- `timestamp` is the **first data segment's** time.
- `b64_data` is the inspector's buffer (HTTP alert: the header block, `pkt_len` 48), **not** the wire bytes.

## A6b. Missed alerts on un-ACKed TCP data

Observed on 3.10.0.0 in passive read-file mode.
- A client request is **never inspected** by service inspectors (`http_inspect get_requests` doesn't count it, and no service-buffer rule fires) when the peer never ACKs it. This holds when the capture ends right after it, after a client FIN, and after a client RST.
- `stream_tcp.no_ack=true` is applied (`--dump-config-text` confirms it) but has **no effect**, even with `ips.mode='inline-test'`.
- `stream_tcp.queue_limit.asymmetric_ids_flush_threshold=1` makes **purely one-sided flows** (no SYN-ACK seen) flush. The alert then reports the data packet itself. No change on normal flows (identical alerts on two pcaps). Side effect on that one-sided flow: a raw `content:"GET"` rule (no service) that matched the rebuilt stream by default no longer matches.
- Raw-packet rules (`content` with no sticky buffer) still fire on the original packets in every case.

## A7. `snort2lua`

`snort2lua` ships in the image (`/home/snorty/snort3/bin/snort2lua`). Verified usage: `snort2lua -c <snort2.conf or a bare Snort 2 rules file> -r <out.rules> -o <out.lua> -e <errors.txt>`; `uricontent:"/admin"` becomes `http_uri; content:"/admin",nocase`. `u2spewfoo` and `u2boat` are there too.

## A8. Docker image

`ciscotalos/snort3` (official Talos, `latest` only, linux/amd64) is the fallback backend, **pinned by digest**. Alternatives: `openeuler/snort3` (tagged 3.9.5.0), or building a 3.12.4.0 image ourselves later.
- Verified: `--network none` works, read-only `-v …:ro` input mounts work, and output to a separate rw mount works.
- **Verified during the build (3.10.0.0):** the full hardened flag set works: `--read-only --tmpfs /tmp --cap-drop ALL --security-opt no-new-privileges --pids-limit 256 --memory 2g --user <host uid>:<gid> -e HOME=/tmp`, with the run's `cfg/` mounted `:ro` and only `out/` writable.

## A9. Timesketch CSV

From the Timesketch docs and `timesketch/lib/utils.py`:
- Required columns: **`message`, `datetime`, `timestamp_desc`**.
- `datetime` is ISO 8601, e.g. `2015-07-24T19:01:01+00:00`; values without an offset are treated as UTC. `timestamp` is optional and is recomputed from `datetime` (epoch µs).
- Header on the first line, `,` delimiter, UTF-8, the filename **must end `.csv`**. Extra columns are kept.
- Avoid the column names `_id _type _index _source __ts_timeline_id`. Fields over 32 766 bytes can't be aggregated.

## A10. Other CLI facts
- `--daq-list`: built in are `pcap` (readback live), `savefile`, `afpacket` (live inline), `dump`, `bpf`, `trace`, `fst` and `gwlb`.
- `--daq-mode passive|inline|read-file`.
- **Repeated `--lua` chunks are concatenated with no separator.** That's one more reason the workbench never uses `--lua`.
- `--dump-rule-meta` / `--dump-config-text` exist and are useful for tests.

## A11. Build-time findings
- `mcp` is 2.x (2.3.0): `FastMCP` is now `mcp.server.mcpserver.MCPServer`; client results use snake_case (`is_error`, `structured_content`). `pyproject.toml` requires `mcp>=2`.
- Recorded real outputs (Docker, 3.10.0.0) live in `tests/fixtures/recorded/`; regenerate with `scripts/record_snort_outputs.py`.
- The generated config with `ssl = { }` and `ssh = { }` validates and runs on 3.10.0.0.
