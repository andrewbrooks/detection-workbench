"""Generate the synthetic fixture captures (deterministic). Run: uv run scripts/make_fixtures.py

No real traffic and no malware: every payload is invented. Packet roles are documented in
tests/fixtures/README.md so tests can assert exact packet numbers.
"""
from __future__ import annotations

import random
import sys
from pathlib import Path

from scapy.all import DNS, DNSQR, IP, TCP, UDP, Ether, Raw, wrpcap

OUT = Path(__file__).resolve().parents[1] / "tests" / "fixtures" / "pcaps"
E = Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02")
T0 = 1_700_000_000.0
MARKER = b"WBTEST-MARKER-7731"
REQ = b"GET /download/" + MARKER + b" HTTP/1.1\r\nHost: files.example.test\r\nUser-Agent: wbtest/1.0\r\n\r\n"
RESP = b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nContent-Type: text/plain\r\n\r\nhello"


class Cap:
    def __init__(self, step=0.01):
        self.pkts, self.t, self.step = [], T0, step

    def add(self, p):
        p.time = self.t
        self.t += self.step
        self.pkts.append(p)
        return len(self.pkts)  # 1-based pcap index

    def save(self, name):
        OUT.mkdir(parents=True, exist_ok=True)
        wrpcap(str(OUT / name), self.pkts)
        print(f"{name}: {len(self.pkts)} packets")


def tcp(cap, c, s, flags, seq, ack, payload=b"", to_server=True):
    (src, sp), (dst, dp) = (c, s) if to_server else (s, c)
    p = E / IP(src=src, dst=dst) / TCP(sport=sp, dport=dp, flags=flags, seq=seq, ack=ack)
    return cap.add(p / Raw(payload) if payload else p)


def http_exchange(cap, c, s, req=REQ, resp=RESP):
    tcp(cap, c, s, "S", 100, 0)
    tcp(cap, c, s, "SA", 500, 101, to_server=False)
    tcp(cap, c, s, "A", 101, 501)
    r = tcp(cap, c, s, "PA", 101, 501, req)
    tcp(cap, c, s, "PA", 501, 101 + len(req), resp, to_server=False)
    tcp(cap, c, s, "A", 101 + len(req), 501 + len(resp))
    return r


def dns(cap, src, name, sport=5353):
    return cap.add(E / IP(src=src, dst="8.8.8.8") / UDP(sport=sport, dport=53) / DNS(rd=1, qd=DNSQR(qname=name)))


def http_marker():
    """pkt 1,2 DNS; 3-8 HTTP exchange (request = 6); 9-13 SYN scan of 10.0.9.9 ports 20-24."""
    cap = Cap()
    dns(cap, "10.0.4.20", "example.com")
    dns(cap, "10.0.4.20", "evil-c2.test")
    http_exchange(cap, ("10.0.4.20", 40000), ("203.0.113.5", 80))
    for i in range(5):
        cap.add(E / IP(src="10.0.4.20", dst="10.0.9.9") / TCP(sport=41000 + i, dport=20 + i, flags="S"))
    cap.save("http_marker.pcap")


def flow_endings():
    """One un-ACKed GET per flow: none(4) fin(8) rst(13) server-ack(18, ack at 19) one-sided(22)."""
    cap = Cap()
    for port, end in ((40010, "none"), (40011, "fin"), (40012, "rst"), (40013, "srvack"), (40014, "oneside")):
        c, s = ("10.0.4.20", port), ("203.0.113.5", 80)
        tcp(cap, c, s, "S", 100, 0)
        if end != "oneside":
            tcp(cap, c, s, "SA", 500, 101, to_server=False)
        tcp(cap, c, s, "A", 101, 501)
        tcp(cap, c, s, "PA", 101, 501, REQ)
        nxt = 101 + len(REQ)
        if end == "fin":
            tcp(cap, c, s, "FA", nxt, 501)
        elif end == "rst":
            tcp(cap, c, s, "R", nxt, 0)
        elif end == "srvack":
            tcp(cap, c, s, "A", 501, nxt, to_server=False)
    cap.save("flow_endings.pcap")


def noisy():
    """Noisy-rule demo: 10.0.4.20 (a vulnerability scanner) makes 300 'GET /probe' requests; 5 other
    clients make a few; one client sends the real marker request. Benign background throughout."""
    rng = random.Random(7)
    cap = Cap(step=0.002)
    s = ("203.0.113.5", 80)
    port = 20000
    for i in range(300):
        port += 1
        http_exchange(cap, ("10.0.4.20", port), s, req=b"GET /probe/%d HTTP/1.1\r\nHost: app.example.test\r\nUser-Agent: scanner/2.0\r\n\r\n" % i)
    for host in range(31, 36):
        for j in range(rng.randint(2, 4)):
            port += 1
            http_exchange(cap, (f"10.0.4.{host}", port), s, req=b"GET /index%d.html HTTP/1.1\r\nHost: app.example.test\r\nUser-Agent: Mozilla/5.0\r\n\r\n" % j)
    port += 1
    http_exchange(cap, ("10.0.4.77", port), s)
    for k in range(20):
        dns(cap, f"10.0.4.{40 + k % 5}", f"host{k}.example.test", sport=6000 + k)
    cap.save("noisy.pcap")


if __name__ == "__main__":
    OUT.mkdir(parents=True, exist_ok=True)
    http_marker()
    flow_endings()
    noisy()
    sys.exit(0)
