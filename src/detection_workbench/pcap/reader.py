"""Read pcap/pcapng with dpkt. Packet indices are 1-based file order, the numbering Snort uses
for pkt_gen=raw alerts."""
from __future__ import annotations

import socket
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path
from struct import error as struct_error

import dpkt


class PcapError(ValueError):
    pass


@dataclass
class Pkt:
    idx: int
    ts: float
    length: int
    raw: bytes
    proto: str | None = None  # TCP | UDP | ICMP | other IP proto name | None (non-IP)
    src: str | None = None
    dst: str | None = None
    sport: int | None = None
    dport: int | None = None
    payload: bytes = b""
    seq: int | None = None
    ack: int | None = None
    flags: int = 0


def _addr(b: bytes) -> str:
    return socket.inet_ntop(socket.AF_INET if len(b) == 4 else socket.AF_INET6, b)


def _ip_from(link: int, buf: bytes):
    try:
        if link == dpkt.pcap.DLT_EN10MB:
            eth = dpkt.ethernet.Ethernet(buf)
            return eth.data if isinstance(eth.data, (dpkt.ip.IP, dpkt.ip6.IP6)) else None
        if link in (dpkt.pcap.DLT_RAW, 12, 14):
            v = buf[0] >> 4 if buf else 0
            return dpkt.ip.IP(buf) if v == 4 else dpkt.ip6.IP6(buf) if v == 6 else None
        if link == 113:  # Linux cooked
            sll = dpkt.sll.SLL(buf)
            return sll.data if isinstance(sll.data, (dpkt.ip.IP, dpkt.ip6.IP6)) else None
        if link == 0:  # BSD loopback
            return dpkt.ip.IP(buf[4:]) if buf[4:5] and buf[4] >> 4 == 4 else dpkt.ip6.IP6(buf[4:])
    except (dpkt.UnpackError, IndexError, struct_error):
        return None
    return None


def _open(f):
    magic = f.read(4)
    f.seek(0)
    if magic == bytes.fromhex("0a0d0d0a"):
        return dpkt.pcapng.Reader(f)
    try:
        return dpkt.pcap.Reader(f)
    except (ValueError, dpkt.NeedData) as e:
        raise PcapError(f"not a readable pcap: {e}") from None


def iter_packets(path: Path) -> Iterator[Pkt]:
    with Path(path).open("rb") as f:
        rd = _open(f)
        link = rd.datalink()
        for i, (ts, buf) in enumerate(rd, start=1):
            p = Pkt(idx=i, ts=ts, length=len(buf), raw=buf)
            ip = _ip_from(link, buf)
            if ip is not None:
                p.src, p.dst = _addr(ip.src), _addr(ip.dst)
                nxt = ip.data
                if isinstance(nxt, dpkt.tcp.TCP):
                    p.proto, p.sport, p.dport = "TCP", nxt.sport, nxt.dport
                    p.payload, p.seq, p.ack, p.flags = bytes(nxt.data), nxt.seq, nxt.ack, nxt.flags
                elif isinstance(nxt, dpkt.udp.UDP):
                    p.proto, p.sport, p.dport, p.payload = "UDP", nxt.sport, nxt.dport, bytes(nxt.data)
                elif isinstance(nxt, (dpkt.icmp.ICMP, dpkt.icmp6.ICMP6)):
                    p.proto, p.payload = "ICMP", bytes(nxt.data) if not isinstance(nxt.data, bytes) else nxt.data
                else:
                    p.proto = getattr(ip, "p", None) and str(ip.p) or "IP"
            yield p
