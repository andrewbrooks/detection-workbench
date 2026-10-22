"""TCP flow bookkeeping: detect client/server data that the peer never ACKed.

Snort 3.10 does not run service inspectors on TCP data its peer never acknowledged (docs/notes.md
A6b), so rules on service buffers can silently miss on such flows. This scans the pcap up front so
run_pcap can say so instead of returning a quietly incomplete result.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from .reader import iter_packets

TCP_ACK = 0x10
MAX_FLOWS = 200_000  # bounds memory on captures with huge numbers of connections
_MOD = 1 << 32


def seq_ge(a: int, b: int) -> bool:
    return ((a - b) % _MOD) < (_MOD >> 1)


def flow_key(src, sport, dst, dport):
    """Direction-independent 5-tuple key (protocol is TCP here, or pass a tag for others)."""
    a, b = (src, sport), (dst, dport)
    return (a, b) if a <= b else (b, a)


@dataclass
class _Dir:
    packets: int = 0
    data_end: int | None = None  # highest seq+len of payload seen
    first_data_idx: int | None = None
    ack_max: int | None = None  # highest ACK number this side has sent


@dataclass
class _Flow:
    dirs: dict = field(default_factory=dict)


def analyze_streams(path: Path, max_examples: int = 10) -> dict:
    flows: dict = {}
    truncated = False
    for p in iter_packets(path):
        if p.proto != "TCP":
            continue
        key = flow_key(p.src, p.sport, p.dst, p.dport)
        if key not in flows and len(flows) >= MAX_FLOWS:
            truncated = True
            continue
        fl = flows.setdefault(key, _Flow())
        d = fl.dirs.setdefault((p.src, p.sport), _Dir())
        d.packets += 1
        if p.payload:
            end = (p.seq + len(p.payload)) % _MOD
            if d.data_end is None or seq_ge(end, d.data_end):
                d.data_end = end
            if d.first_data_idx is None:
                d.first_data_idx = p.idx
        if p.flags & TCP_ACK and (d.ack_max is None or seq_ge(p.ack, d.ack_max)):
            d.ack_max = p.ack
    unacked, one_sided, examples = 0, 0, []
    for key, fl in flows.items():
        flow_unacked = flow_one_sided = False
        for (ip, port), d in fl.dirs.items():
            if d.data_end is None:
                continue
            peers = [pd for k, pd in fl.dirs.items() if k != (ip, port)]
            peer_ack = peers[0].ack_max if peers else None
            if peer_ack is None or not seq_ge(peer_ack, d.data_end):
                flow_unacked = True
                if not peers:
                    flow_one_sided = True
                if len(examples) < max_examples:
                    peer = key[1] if key[0] == (ip, port) else key[0]
                    examples.append({"src": ip, "src_port": port, "dst": peer[0], "dst_port": peer[1],
                                     "first_data_pkt": d.first_data_idx,
                                     "reason": "no packets from peer" if not peers else "peer never ACKed the data"})
        unacked += flow_unacked
        one_sided += flow_one_sided
    return {"tcp_flows": len(flows), "unacked_flows": unacked, "one_sided_flows": one_sided,
            "examples": examples, "flows_truncated": truncated}
