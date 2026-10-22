"""Reassemble one direction of a TCP flow, keeping a byte -> packet map for match reporting."""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from .flows import _MOD
from .reader import iter_packets

MAX_STREAM = 4 * 1024 * 1024


@dataclass
class Segment:
    stream_off: int
    pkt_idx: int
    pkt_off: int
    length: int


@dataclass
class Reassembled:
    data: bytes = b""
    segments: list[Segment] = field(default_factory=list)
    gaps: int = 0  # missing ranges where later data was present (data stops at the first gap)
    packets: list[int] = field(default_factory=list)

    def locate(self, off: int) -> tuple[int, int] | None:
        """stream offset -> (pcap packet index, offset within that packet's TCP payload)."""
        for s in self.segments:
            if s.stream_off <= off < s.stream_off + s.length:
                return s.pkt_idx, s.pkt_off + (off - s.stream_off)
        return None


def reassemble(path: Path, src: str, sport: int, dst: str, dport: int, max_idx: int,
               min_ts_us: int | None = None) -> Reassembled:
    """Data packets src:sport -> dst:dport with idx <= max_idx and timestamp >= min_ts_us (µs).

    Overlaps: first-seen bytes win. Output stops at the first gap in sequence space.
    """
    segs, held = [], 0
    for p in iter_packets(path):
        if p.idx > max_idx:
            break
        if p.proto != "TCP" or not p.payload:
            continue
        if (p.src, p.sport, p.dst, p.dport) != (src, sport, dst, dport):
            continue
        if min_ts_us is not None and round(p.ts * 1_000_000) < min_ts_us:
            continue
        held += len(p.payload)
        if held > 2 * MAX_STREAM:  # a stream far larger than we will rebuild: stop collecting
            break
        segs.append(p)
    out = Reassembled()
    if not segs:
        return out
    base = segs[0].seq
    buf, seen = bytearray(), bytearray()  # seen: 1 where a byte is filled
    placements: list[tuple[int, int, int, int]] = []  # (rel, pkt_idx, length, pkt_off)
    for p in segs:
        rel = (p.seq - base) % _MOD
        if rel >= (_MOD >> 1):  # before the first selected segment
            continue
        end = rel + len(p.payload)
        if end > MAX_STREAM:
            break
        if end > len(buf):
            buf.extend(b"\0" * (end - len(buf)))
            seen.extend(b"\0" * (end - len(seen)))
        start_new = None
        for i, b in enumerate(p.payload):
            if not seen[rel + i]:
                buf[rel + i] = b
                seen[rel + i] = 1
                if start_new is None:
                    start_new = i
            elif start_new is not None:
                placements.append((rel + start_new, p.idx, i - start_new, start_new))
                start_new = None
        if start_new is not None:
            placements.append((rel + start_new, p.idx, len(p.payload) - start_new, start_new))
        out.packets.append(p.idx)
    limit = seen.find(0)
    if limit == -1:
        limit = len(seen)
    else:
        out.gaps = 1
    out.data = bytes(buf[:limit])
    out.segments = [Segment(r, i, o, min(n, limit - r)) for r, i, n, o in sorted(placements) if r < limit]
    return out
