# Test fixtures

Everything here is synthetic or recorded from the pinned Snort image. There is no real traffic and no malware.
Regenerate the captures with `uv run scripts/make_fixtures.py` and the recordings with `uv run scripts/record_snort_outputs.py`
(Docker needed for the latter). Packet numbers below are 1-based pcap indices, the numbering Snort uses for `pkt_gen: raw` alerts.

## `pcaps/`

| File | Packets | Contents |
|---|---|---|
| `http_marker.pcap` | 13 | 1-2 DNS queries (`example.com`, `evil-c2.test`) from 10.0.4.20; 3-8 one HTTP exchange (SYN 3, request 6 carrying `WBTEST-MARKER-7731`, response 7); 9-13 a SYN sweep of 10.0.9.9 ports 20-24 |
| `flow_endings.pcap` | 22 | The same GET on five flows that end differently: never ACKed (request in packet 4), client FIN (8), client RST (13), server ACK (18, ACK in 19), and a one-sided flow with no SYN-ACK (22). Used to pin Snort's behaviour on un-ACKed data |
| `noisy.pcap` | 1910 | A scanner (10.0.4.20) making 300 `GET /probe/N` requests, five ordinary clients making 2-4 requests each, one marker request from 10.0.4.77, and 20 DNS queries |

## `rules/`

| File | Purpose |
|---|---|
| `good.rules` | Three valid rules: marker in `http_uri` (sid 1000001), any DNS query (1000002), any SYN (1000003, deliberately has no fast pattern) |
| `bad.rules` | Seven lines covering a misspelled option, a missing `;`, a bad pcre, a missing `sid`, a duplicate sid and an invalid `depth` |
| `noisy.rules` | The noisy-rule demo: `GET` anywhere (1000042), the marker (1000001), and a DNS rule (1000002) |

## `recorded/`

Real Snort 3.10.0.0 output used by the parser tests so they run without Snort: `validate_good.txt` / `validate_bad.txt` (with `.exit` codes),
`alerts_*.jsonl` (raw `alert_json`) and `profile_*.txt` (the rule-profile table) for each capture.
