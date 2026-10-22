from pathlib import Path

import pytest

from detection_workbench.pcap.flows import analyze_streams, seq_ge
from detection_workbench.pcap.reader import PcapError, iter_packets
from detection_workbench.pcap.reassembly import reassemble
from detection_workbench.pcap.summary import summarize

PC = Path(__file__).parents[1] / "fixtures" / "pcaps"
MARK = b"GET /download/WBTEST-MARKER-7731 HTTP/1.1"


def test_packet_indices_are_one_based_file_order():
    pk = list(iter_packets(PC / "http_marker.pcap"))
    assert [p.idx for p in pk] == list(range(1, 14))
    assert pk[5].payload.startswith(MARK) and pk[5].proto == "TCP" and pk[5].dport == 80
    assert pk[0].proto == "UDP" and pk[0].dport == 53


def test_not_a_pcap(tmp_path):
    bad = tmp_path / "x.pcap"
    bad.write_bytes(b"hello world, definitely not a capture")
    with pytest.raises(PcapError):
        list(iter_packets(bad))


def test_summary():
    s = summarize(PC / "http_marker.pcap")
    assert s["packets"] == 13 and s["protocols"] == {"TCP": 11, "UDP": 2}
    assert s["top_sources"][0] == ("10.0.4.20", 11) or s["top_sources"][0][0] == "10.0.4.20"
    assert s["services"]["http/tcp"] >= 3 and s["services"]["dns/udp"] == 2
    assert s["first_packet"] == "2023-11-14T22:13:20.000000Z" and s["duration_s"] == pytest.approx(0.12)


def test_seq_wraparound():
    assert seq_ge(5, 3) and not seq_ge(3, 5)
    assert seq_ge(2, 0xFFFFFFF0) and not seq_ge(0xFFFFFFF0, 2)


def test_streams_clean_capture_has_no_caveats():
    r = analyze_streams(PC / "http_marker.pcap")
    assert r["unacked_flows"] == 0 and r["one_sided_flows"] == 0 and r["tcp_flows"] >= 6


def test_streams_flow_endings():
    r = analyze_streams(PC / "flow_endings.pcap")
    assert r["tcp_flows"] == 5 and r["unacked_flows"] == 4 and r["one_sided_flows"] == 1
    firsts = sorted(e["first_data_pkt"] for e in r["examples"])
    assert firsts == [4, 8, 13, 22]  # none, fin, rst, one-sided; the server-ACKed flow (18) is clean
    assert any(e["reason"] == "no packets from peer" and e["first_data_pkt"] == 22 for e in r["examples"])


def test_reassemble_single_segment_and_map():
    r = reassemble(PC / "http_marker.pcap", "10.0.4.20", 40000, "203.0.113.5", 80, max_idx=7)
    assert r.data.startswith(MARK) and r.packets == [6] and r.gaps == 0
    off = r.data.index(b"WBTEST-MARKER")
    assert r.locate(off) == (6, off)
    assert r.locate(len(r.data) + 5) is None


def test_reassemble_respects_timestamp_floor_and_max_idx():
    assert reassemble(PC / "http_marker.pcap", "10.0.4.20", 40000, "203.0.113.5", 80, max_idx=5).data == b""
    late = round((1_700_000_000.0 + 0.5) * 1_000_000)
    assert reassemble(PC / "http_marker.pcap", "10.0.4.20", 40000, "203.0.113.5", 80, 13, min_ts_us=late).data == b""


def test_reassemble_multi_segment_overlap_and_gap(tmp_path):
    from scapy.all import IP, TCP, Ether, Raw, wrpcap
    E = Ether()
    def seg(seq, data, t):
        p = E / IP(src="1.1.1.1", dst="2.2.2.2") / TCP(sport=1000, dport=80, flags="PA", seq=seq) / Raw(data)
        p.time = 1_700_000_000 + t
        return p
    out = tmp_path / "m.pcap"
    # in-order "AAAA", out-of-order "CCCC" before "BBBB", retransmit of "AAAA" with different bytes, then a gap
    wrpcap(str(out), [seg(100, b"AAAA", 0), seg(108, b"CCCC", 1), seg(104, b"BBBB", 2),
                      seg(100, b"XXXX", 3), seg(200, b"ZZZZ", 4)])
    r = reassemble(out, "1.1.1.1", 1000, "2.2.2.2", 80, max_idx=99)
    assert r.data == b"AAAABBBBCCCC" and r.gaps == 1
    assert r.locate(5) == (3, 1) and r.locate(9) == (2, 1) and r.locate(0) == (1, 0)
