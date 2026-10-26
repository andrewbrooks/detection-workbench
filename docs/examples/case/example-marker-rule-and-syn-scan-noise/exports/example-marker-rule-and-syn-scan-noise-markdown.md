# Example: marker rule and SYN-scan noise

Case `example-marker-rule-and-syn-scan-noise` · status **closed** · created 2026-10-26T21:43:41.333318Z · updated 2026-10-26T21:43:42.853920Z

> **At a glance:** 3 engine runs · 2 findings (1 confirmed, 1 open) · 2 decisions (1 accepted, 1 rejected) · noisiest SID: 1000003 (6 alerts in r-0003)

## Summary

**Question.** Does the marker rule fire on the target request, and which rule in this set is noisy?

**Findings.** The marker rule (sid 1000001) fires exactly once, on the request carrying `WBTEST-MARKER-7731` (f-0001, run r-0003). The only noisy rule is the SYN rule (sid 1000003): 6 alerts, all from one scanner (10.0.4.20) sweeping five ports on 10.0.9.9.

**Two candidate fixes, same result.** An `event_filter` limit of one alert per source per minute (run r-0004, decision d-0001) and a `detection_filter` written into the rule itself (run r-0006, decision d-0002) both take sid 1000003 from 6 to 1 alerts and leave sids 1000001 and 1000002 unchanged.

**Decision.** d-0001 was rejected and d-0002 accepted, because a fix inside the rule travels with the rule set. The accepted rule is in `exports/accepted-tuning.rules`. The rule check notes that sid 1000003 has no content to build a fast pattern on; that was already true before the edit.

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
| inline · derived from r-0003 | dcb1028fc4858d55… | r-0005, r-0006 |

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

### r-0005 — validate: ok (0 errors, 1 warning, 1 lint note)

### r-0006 — tuning · parent `r-0003`

4 alerts · status ok

| sid | message | alerts | volume | sources | top source |
|---|---|---|---|---|---|
| 1000002 | WBTEST any DNS | 2 | ███░░░░░░░ | 1 | 10.0.4.20 (100%) |
| 1000001 | WBTEST marker in URI | 1 | ██░░░░░░░░ | 1 | 10.0.4.20 (100%) |
| 1000003 | WBTEST any SYN | 1 | ██░░░░░░░░ | 1 | 10.0.4.20 (100%) |

## Decisions

### d-0001 — event_filter (rejected)

SYN rule fires on every scan packet; volume, not presence, is the noise

Before `r-0003` → after `r-0004`

Status history: proposed → rejected (last change 2026-10-26T21:43:42.840288Z)

| sid | before | after | change |
|---|---|---|---|
| 1000001 | 1 | 1 | no change |
| 1000002 | 2 | 2 | no change |
| 1000003 | 6 | 1 | −83% |

Config entry:

```lua
-- add this entry to the event_filter table in snort.lua
event_filter = { { gid = 1, sid = 1000003, type = 'limit', track = 'by_src', count = 1, seconds = 60 } }
```

### d-0002 — rule_edit (accepted)

Same effect from inside the rule, so the fix travels with the rule set instead of the sensor config

Before `r-0003` → after `r-0006`

Status history: proposed → accepted (last change 2026-10-26T21:43:42.843889Z)

| sid | before | after | change |
|---|---|---|---|
| 1000001 | 1 | 1 | no change |
| 1000002 | 2 | 2 | no change |
| 1000003 | 6 | 1 | −83% |

Rule diff (option by option):

```diff
  alert tcp any any -> any any
  msg:"WBTEST any SYN"
  flags:S
+ detection_filter:track by_src,count 5,seconds 60
  sid:1000003
- rev:1
+ rev:2
```

Rule check: sid unchanged · rev bumped (1 → 2) · **warning:** no positive content, so the rule has no fast pattern and is evaluated on every packet in scope

## Caveats

- Results describe only the evidence registered in this case. One capture is one sample; they do not show how a rule behaves on other traffic.

## Timeline

| time (UTC) | event | ref | detail |
|---|---|---|---|
| 2026-10-26T21:43:41.343602Z | case.created | example-marker-rule-and-syn-scan-noise | Example: marker rule and SYN-scan noise |
| 2026-10-26T21:43:41.345961Z | evidence.registered | e-0001 | <repo>/tests/fixtures/pcaps/http_marker.pcap |
| 2026-10-26T21:43:41.350008Z | evidence.registered | e-0002 | <repo>/tests/fixtures/rules/good.rules |
| 2026-10-26T21:43:41.358619Z | run.recorded | r-0001 | summary → ok |
| 2026-10-26T21:43:41.630778Z | run.recorded | r-0002 | validate → ok |
| 2026-10-26T21:43:41.902758Z | run.recorded | r-0003 | run → ok |
| 2026-10-26T21:43:41.905124Z | finding.added | f-0001 | SID 1000001 (marker in URI) fires once, on the target request: data in packet 6, alert re… |
| 2026-10-26T21:43:41.909111Z | finding.updated | f-0001 | status confirmed |
| 2026-10-26T21:43:42.232872Z | run.recorded | r-0004 | tuning → ok |
| 2026-10-26T21:43:42.234879Z | decision.recorded | d-0001 | event_filter |
| 2026-10-26T21:43:42.238706Z | finding.added | f-0002 | SID 1000003 fires 6 times from one scanner; a limit of one alert per source per minute le… |
| 2026-10-26T21:43:42.511660Z | run.recorded | r-0005 | validate → ok |
| 2026-10-26T21:43:42.833946Z | run.recorded | r-0006 | tuning → ok |
| 2026-10-26T21:43:42.836425Z | decision.recorded | d-0002 | rule_edit |
| 2026-10-26T21:43:42.840297Z | decision.updated | d-0001 |  |
| 2026-10-26T21:43:42.843896Z | decision.updated | d-0002 |  |
| 2026-10-26T21:43:42.848354Z | export.written | accepted-tuning.rules | tuning →  |
| 2026-10-26T21:43:42.850404Z | note.added | n-0001 |  |
| 2026-10-26T21:43:42.853883Z | case.updated | example-marker-rule-and-syn-scan-noise | status=closed, summary_chars=1101 |

## Notes

- (client, 2026-10-26T21:43:42.850377Z) Synthetic capture bundled with the repository; results say nothing about production traffic.

## Appendix: runs

| id | kind | engine | version | backend | status | duration_s | alerts |
|---|---|---|---|---|---|---|---|
| r-0001 | summary | dpkt |  | native | ok | 0.0 |  |
| r-0002 | validate | snort | 3.10.0.0 | docker | ok | 0.264 |  |
| r-0003 | run | snort | 3.10.0.0 | docker | ok | 0.264 | 9 |
| r-0004 | tuning | snort | 3.10.0.0 | docker | ok | 0.314 | 4 |
| r-0005 | validate | snort | 3.10.0.0 | docker | ok | 0.264 |  |
| r-0006 | tuning | snort | 3.10.0.0 | docker | ok | 0.314 | 4 |
