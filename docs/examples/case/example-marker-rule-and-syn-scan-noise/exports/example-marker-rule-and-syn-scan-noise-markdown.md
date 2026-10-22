# Example: marker rule and SYN-scan noise

Case `example-marker-rule-and-syn-scan-noise` · status **closed** · created 2026-10-22T22:16:12.564990Z · updated 2026-10-22T22:16:13.583256Z

> **At a glance:** 2 engine runs · 2 findings (1 confirmed, 1 open) · 1 decision (1 proposed) · noisiest SID: 1000003 (6 alerts in r-0003)

## Summary

**Question.** Does the marker rule fire on the target request, and which rule in this set is noisy?

**Findings.** The marker rule (sid 1000001) fires exactly once, on the request carrying `WBTEST-MARKER-7731` (f-0001, run r-0003). The only noisy rule is the SYN rule (sid 1000003): 6 alerts, all from one scanner (10.0.4.20) sweeping five ports on 10.0.9.9.

**Tested change.** An `event_filter` limit of one alert per source per minute takes sid 1000003 from 6 to 1 alerts and leaves sids 1000001 and 1000002 unchanged (run r-0004, decision d-0001). It is recorded as `proposed`; nobody has accepted it.

**Limits.** One 13-packet synthetic capture. It shows the change works mechanically, not that a limit of one per minute is right for production traffic.

## Overview

**Captures**

| evidence | packets | first packet | last packet | protocols |
|---|---|---|---|---|
| e-0001 | 13 | 2023-11-14T22:13:20.000000Z | 2023-11-14T22:13:20.120000Z | TCP 11, UDP 2 |

**Engines:** snort 3.10.0.0 (docker)

**Rule sets** (by hash)

| origin | sha256 | used in |
|---|---|---|
| e-0002 · derived from r-0003 | 2870dd02f3d1bf2e… | r-0002, r-0003, r-0004 |

## Evidence

| id | type | path | sha256 | size |
|---|---|---|---|---|
| e-0001 | pcap | <repo>/tests/fixtures/pcaps/http_marker.pcap | e4abeab3ce82ae01f19c8dd3dc7b36a2cd9a7a416b0c4d7463227acb51595dbb | 1133 |
| e-0002 | rules | <repo>/tests/fixtures/rules/good.rules | 2870dd02f3d1bf2e934bf2ab8c180345981417e9e2ac078abfd6b3983e0f6f7f | 357 |

## Findings

- **f-0001** [confirmed] SID 1000001 (marker in URI) fires once, on the target request: data in packet 6, alert reported on packet 7 (the flush trigger).  (runs: r-0003; evidence: e-0001, e-0002)
- **f-0002** [open] SID 1000003 fires 6 times from one scanner; a limit of one alert per source per minute leaves 1.  (runs: r-0003, r-0004; evidence: e-0001, e-0002)

## Results by run

### r-0002 — validate: ok (0 errors, 1 warning, 1 lint note)

### r-0003 — run

9 alerts · status ok

| sid | message | alerts | volume | sources | top source |
|---|---|---|---|---|---|
| 1000003 | WBTEST any SYN | 6 | ██████████ | 1 | 10.0.4.20 (100%) |
| 1000002 | WBTEST any DNS | 2 | ███░░░░░░░ | 1 | 10.0.4.20 (100%) |
| 1000001 | WBTEST marker in URI | 1 | ██░░░░░░░░ | 1 | 10.0.4.20 (100%) |

### r-0004 — tuning · parent `r-0003`

4 alerts · status ok

| sid | message | alerts | volume | sources | top source |
|---|---|---|---|---|---|
| 1000002 | WBTEST any DNS | 2 | ███░░░░░░░ | 1 | 10.0.4.20 (100%) |
| 1000003 | WBTEST any SYN | 1 | ██░░░░░░░░ | 1 | 10.0.4.20 (100%) |
| 1000001 | WBTEST marker in URI | 1 | ██░░░░░░░░ | 1 | 10.0.4.20 (100%) |

## Decisions

### d-0001 — event_filter (proposed)

SYN rule fires on every scan packet; volume, not presence, is the noise

Before `r-0003` → after `r-0004`

| sid | before | after | change |
|---|---|---|---|
| 1000001 | 1 | 1 | no change |
| 1000002 | 2 | 2 | no change |
| 1000003 | 6 | 1 | −83% |

Change: `{"count": 1, "kind": "event_filter", "seconds": 60, "sid": 1000003, "track": "by_src", "type": "limit"}`

## Caveats

- Results describe only the evidence registered in this case. One capture is one sample; they do not show how a rule behaves on other traffic.
- Decisions marked `proposed` have been tested on this evidence but not accepted by a person.

## Timeline

| time (UTC) | event | ref | detail |
|---|---|---|---|
| 2026-10-22T22:16:12.575283Z | case.created | example-marker-rule-and-syn-scan-noise | Example: marker rule and SYN-scan noise |
| 2026-10-22T22:16:12.577592Z | evidence.registered | e-0001 | <repo>/tests/fixtures/pcaps/http_marker.pcap |
| 2026-10-22T22:16:12.581767Z | evidence.registered | e-0002 | <repo>/tests/fixtures/rules/good.rules |
| 2026-10-22T22:16:12.590384Z | run.recorded | r-0001 | summary → ok |
| 2026-10-22T22:16:12.914998Z | run.recorded | r-0002 | validate → ok |
| 2026-10-22T22:16:13.238122Z | run.recorded | r-0003 | run → ok |
| 2026-10-22T22:16:13.240302Z | finding.added | f-0001 | SID 1000001 (marker in URI) fires once, on the target request: data in packet 6, alert re… |
| 2026-10-22T22:16:13.244037Z | finding.updated | f-0001 | status confirmed |
| 2026-10-22T22:16:13.568384Z | run.recorded | r-0004 | tuning → ok |
| 2026-10-22T22:16:13.571008Z | decision.recorded | d-0001 | event_filter |
| 2026-10-22T22:16:13.575478Z | finding.added | f-0002 | SID 1000003 fires 6 times from one scanner; a limit of one alert per source per minute le… |
| 2026-10-22T22:16:13.579552Z | note.added | n-0001 |  |
| 2026-10-22T22:16:13.583215Z | case.updated | example-marker-rule-and-syn-scan-noise | status=closed, summary_chars=759 |

## Notes

- (client, 2026-10-22T22:16:13.579520Z) Synthetic capture bundled with the repository; results say nothing about production traffic.

## Appendix: runs

| id | kind | engine | version | backend | status | duration_s | alerts |
|---|---|---|---|---|---|---|---|
| r-0001 | summary | dpkt |  | native | ok | 0.0 |  |
| r-0002 | validate | snort | 3.10.0.0 | docker | ok | 0.315 |  |
| r-0003 | run | snort | 3.10.0.0 | docker | ok | 0.314 | 9 |
| r-0004 | tuning | snort | 3.10.0.0 | docker | ok | 0.314 | 4 |
