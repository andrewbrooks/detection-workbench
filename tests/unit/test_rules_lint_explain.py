import json
from pathlib import Path

from detection_workbench.engines.snort.explain import explain_alert
from detection_workbench.engines.snort.lint import lint_rules
from detection_workbench.engines.snort.parse_alerts import normalize
from detection_workbench.engines.snort.rules import decode_content, find_rule, parse_rule, parse_rules, split_options
from detection_workbench.pcap.hexdump import hexdump

FIX = Path(__file__).parents[1] / "fixtures"
GOOD = (FIX / "rules/good.rules").read_text()
NOISY = (FIX / "rules/noisy.rules").read_text()


def alerts(name):
    return [normalize(json.loads(x), i) for i, x in enumerate((FIX / "recorded" / name).read_text().splitlines())]


# ---- rule parser ---------------------------------------------------------------
def test_decode_content():
    assert decode_content("abc|20 41|d") == b"abc Ad"
    assert decode_content(r"a\;b\"c") == b'a;b"c'
    assert decode_content("|zz|") == b"|zz|"  # bad hex is kept literally rather than raising


def test_split_options_honors_quotes():
    assert split_options('msg:"a;b"; content:"x\\";y"; sid:1;') == ['msg:"a;b"', 'content:"x\\";y"', "sid:1"]


def test_parse_rule_options_and_buffers():
    r = parse_rule('alert http any any -> any any ( msg:"m"; http_uri; content:"WB",fast_pattern,nocase; '
                   'content:"x",offset 2,depth 4; pcre:"/a.c/i"; service:http; sid:7; rev:3; )', 4)
    assert (r.sid, r.rev, r.msg, r.gid, r.line, r.services) == (7, 3, "m", 1, 4, ["http"])
    c1, c2 = r.contents
    assert c1.buffer == "http_uri" and c1.fast_pattern and c1.nocase and not c1.anchored
    assert (c2.offset, c2.depth) == (2, 4) and c2.anchored
    assert r.pcres[0].pattern == "a.c" and r.pcres[0].flags == "i" and r.buffers == ["http_uri"]


def test_snort2_style_separate_modifiers():
    r = parse_rule('alert tcp any any -> any any ( content:"abc"; nocase; offset:2; depth:5; sid:1; )')
    assert r.contents[0].nocase and r.contents[0].offset == 2 and r.contents[0].depth == 5


def test_parse_rules_comments_continuations_and_find():
    text = '# comment\n\nalert tcp any any -> any any ( msg:"a"; \\\n sid:1; rev:1; )\nalert udp any any -> any 53 ( sid:2; )\n'
    rs = parse_rules(text)
    assert [(r.sid, r.line) for r in rs] == [(1, 3), (2, 5)]
    assert find_rule(text, 1, 2).proto == "udp" and find_rule(text, 1, 99) is None


def test_unparseable_rule():
    assert parse_rule("this is not a rule").parsed is False


# ---- lint ----------------------------------------------------------------------
def lint(text):
    return [(d["line"], d["severity"], d["error"][:30]) for d in lint_rules(text)]


def test_lint_missing_sid_is_flagged_even_though_snort_is_silent():
    out = lint_rules('alert tcp any any -> any any ( msg:"x"; content:"abc"; rev:1; )')
    assert any(d["severity"] == "error" and "No sid" in d["error"] for d in out)
    assert all(d["source"] == "workbench_lint" for d in out)


def test_lint_checks():
    text = "\n".join([
        'alert tcp any any -> any 80 ( msg:"low sid"; content:"abc"; sid:5; rev:1; )',
        'alert tcp any any -> any 80 ( content:"abc"; sid:1000001; )',
        'alert tcp any any -> any 80 ( msg:"http buf on tcp"; http_uri; content:"a"; sid:1000002; rev:1; )',
        'alert tcp any any -> any 80 ( msg:"no content"; flags:S; sid:1000003; rev:1; )',
        'alert tcp any any -> any 80 ( msg:"dup"; content:"abc"; sid:1000001; rev:1; )',
    ])
    msgs = " | ".join(d["error"] for d in lint_rules(text))
    for s in ("below 1,000,000", "No rev", "No msg", "neither 'alert http'", "No positive content", "Duplicate sid"):
        assert s in msgs


def test_lint_clean_rule():
    r = 'alert http any any -> any any ( msg:"ok"; http_uri; content:"WB",fast_pattern; sid:1000001; rev:1; )'
    assert [d for d in lint_rules(r) if d["severity"] != "info"] == []


def test_lint_unparseable():
    assert lint_rules("alert nonsense")[0]["severity"] == "error"


# ---- hexdump -------------------------------------------------------------------
def test_hexdump_bounded_and_printable():
    h = hexdump(b"GET /\x00\xff" + b"A" * 40, 20)
    assert h["shown"] == 20 and h["total"] == 47 and h["truncated"] == 27 and len(h["lines"]) == 2
    assert h["lines"][0].startswith("00000000  47 45 54 20 2f 00 ff 41") and h["lines"][0].endswith("|GET /..AAAAAAAAA|")
    assert hexdump(b"", 10)["lines"] == [] and hexdump(b"abc", 0)["lines"] == []


# ---- explain_alert ---------------------------------------------------------------
def test_explain_rebuilt_alert_maps_wire_bytes_to_packet():
    a = next(x for x in alerts("alerts_http_marker.jsonl") if x["sid"] == 1000001)
    assert a["pkt_gen"] == "stream_tcp" and a["pkt_num"] == 7
    ex = explain_alert(find_rule(GOOD, 1, 1000001), a, FIX / "pcaps/http_marker.pcap", 256)
    assert ex["packet"]["trigger_packet"] == 7 and ex["packet"]["data_packets"] == [6]
    c = ex["contents"][0]
    off = c["wire_reassembled"]["offsets"][0]
    assert c["wire_reassembled"]["found"] and c["wire_reassembled"]["packets"][0]["pkt"] == 6 and off == 14
    assert c["inspector_buffer"]["found"] is False  # the inspector buffer is the header block, not the URI
    assert ex["rule"]["sticky_buffers"] == ["http_uri"] and "buffer_caveat" in ex
    assert any("GET /download/WBTEST-MARKER-7731" in l for l in ex["payload"]["lines"]) or ex["payload"]["shown"] > 0
    assert "pkt_num is the packet that triggered the flush" in ex["note"]


def test_explain_raw_alert_reads_exact_packet():
    a = next(x for x in alerts("alerts_http_marker.jsonl") if x["sid"] == 1000002 and x["pkt_num"] == 1)
    ex = explain_alert(find_rule(GOOD, 1, 1000002), a, FIX / "pcaps/http_marker.pcap", 64)
    assert a["pkt_gen"] == "raw" and ex["packet"]["data_packets"] == [1]
    assert ex["contents"][0]["wire_reassembled"]["found"] and ex["contents"][0]["anchors"] == {"offset": 2, "depth": 4}
    assert ex["payload"]["shown"] <= 64 and "note" not in ex


def test_explain_unknown_rule_and_missing_packet():
    a = alerts("alerts_http_marker.jsonl")[0]
    ex = explain_alert(None, a, FIX / "pcaps/http_marker.pcap", 64)
    assert ex["rule"] is None and "not found" in ex["note"]
    a2 = dict(a, pkt_num=999)
    assert "no packet 999" in explain_alert(None, a2, FIX / "pcaps/http_marker.pcap", 64)["note"]


def test_explain_pcre_translation():
    a = next(x for x in alerts("alerts_http_marker.jsonl") if x["sid"] == 1000001)
    rule = parse_rule('alert http any any -> any any ( msg:"p"; http_uri; pcre:"/MARKER-\\d{4}/iR"; '
                      'pcre:"/(?<=x)(/"; sid:1000001; rev:1; )')
    ex = explain_alert(rule, a, FIX / "pcaps/http_marker.pcap", 64)
    p1, p2 = ex["pcres"]
    assert p1["evaluated"] and p1["wire_reassembled"]["found"] and "R" in p1["note"]
    assert p2["evaluated"] is False and "not evaluated locally" in p2["reason"]
