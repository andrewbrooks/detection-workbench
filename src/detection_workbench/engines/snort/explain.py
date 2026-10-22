"""explain_alert: report facts linking rule options to bytes. The client does the explaining."""
from __future__ import annotations

import base64
import re
from datetime import UTC, datetime
from pathlib import Path

from ...pcap.hexdump import hexdump
from ...pcap.reader import iter_packets
from ...pcap.reassembly import Reassembled, reassemble
from .rules import Content, Pcre, Rule

MAX_OFFSETS = 20
_PY_FLAGS = {"i": re.I, "s": re.S, "m": re.M, "x": re.X}


def _alert_us(dt: str) -> int:
    d = datetime.strptime(dt, "%Y-%m-%dT%H:%M:%S.%fZ").replace(tzinfo=UTC)
    return int(d.timestamp()) * 1_000_000 + d.microsecond


def _find_all(hay: bytes, needle: bytes, nocase: bool) -> list[int]:
    if not needle:
        return []
    if nocase:
        hay, needle = hay.lower(), needle.lower()
    out, i = [], hay.find(needle)
    while i != -1 and len(out) < MAX_OFFSETS:
        out.append(i)
        i = hay.find(needle, i + 1)
    return out


def _content_report(c: Content, wire: bytes | None, inspector: bytes | None, locate) -> dict:
    rep = {"option": f'content:{"!" if c.negated else ""}"{c.raw}"', "buffer": c.buffer, "negated": c.negated,
           "nocase": c.nocase, "fast_pattern": c.fast_pattern,
           "anchors": {k: getattr(c, k) for k in ("offset", "depth", "distance", "within") if getattr(c, k) is not None}}
    for label, hay in (("wire_reassembled", wire), ("inspector_buffer", inspector)):
        if hay is None:
            continue
        offs = _find_all(hay, c.value, c.nocase)
        entry = {"found": bool(offs), "offsets": offs}
        if label == "wire_reassembled" and offs and locate:
            entry["packets"] = [{"stream_offset": o, "pkt": loc[0], "payload_offset": loc[1]}
                                for o in offs if (loc := locate(o))]
        rep[label] = entry
    return rep


def _pcre_report(p: Pcre, wire: bytes | None, inspector: bytes | None) -> dict:
    rep = {"option": f'pcre:{"!" if p.negated else ""}"/{p.pattern}/{p.flags}"', "buffer": p.buffer, "negated": p.negated}
    flags, ignored = 0, []
    for f in p.flags:
        if f in _PY_FLAGS:
            flags |= _PY_FLAGS[f]
        else:
            ignored.append(f)
    if ignored:
        rep["note"] = f"Snort-specific flags {''.join(ignored)} are not modelled locally."
    try:
        rx = re.compile(p.pattern.encode("latin-1", "replace"), flags)
    except (re.error, ValueError) as e:
        rep["evaluated"] = False
        rep["reason"] = f"pattern could not be translated to Python re ({e}); not evaluated locally"
        return rep
    rep["evaluated"] = True
    for label, hay in (("wire_reassembled", wire), ("inspector_buffer", inspector)):
        if hay is None:
            continue
        m = rx.search(hay)
        rep[label] = {"found": bool(m), "offset": m.start() if m else None, "length": len(m.group(0)) if m else None}
    return rep


def explain_alert(rule: Rule | None, alert: dict, pcap: Path, display_bytes: int) -> dict:
    out: dict = {"alert": {k: alert.get(k) for k in ("alert_idx", "datetime", "gid", "sid", "rev", "msg", "pkt_num",
                                                     "pkt_gen", "action", "class", "priority")}}
    out["packet"] = {"proto": alert["proto"], "src": f'{alert["src_ip"]}:{alert["src_port"]}',
                     "dst": f'{alert["dst_ip"]}:{alert["dst_port"]}', "direction": alert["dir"],
                     "service": alert["service"], "pkt_gen": alert["pkt_gen"]}
    if rule is None:
        out["rule"] = None
        out["note"] = "Rule text for this gid:sid was not found in the run's rule set."
    else:
        out["rule"] = {"text": rule.text, "line": rule.line, "header": f"{rule.action} {rule.proto} {rule.src} {rule.sport} {rule.direction} {rule.dst} {rule.dport}",
                       "options": [{"name": n, "value": v} for n, v in rule.options], "services": rule.services,
                       "sticky_buffers": rule.buffers}
    inspector = None
    if alert.get("b64_data"):
        try:
            inspector = base64.b64decode(alert["b64_data"], validate=False)
        except ValueError:
            inspector = None
    wire, locate, trigger, data_pkts, dump_src, dump_bytes = None, None, None, [], None, b""
    if alert["pkt_gen"] == "raw":
        for p in iter_packets(pcap):
            if p.idx == alert["pkt_num"]:
                trigger = p
                break
        if trigger is None:
            out["note"] = f"pcap has no packet {alert['pkt_num']}"
        else:
            wire, locate = trigger.payload, (lambda o, i=trigger.idx: (i, o))
            data_pkts = [trigger.idx]
            dump_src, dump_bytes = f"packet {trigger.idx} (frame)", trigger.raw
    else:
        for p in iter_packets(pcap):
            if p.idx == alert["pkt_num"]:
                trigger = p
                break
        if alert["proto"] == "TCP":
            ra: Reassembled = reassemble(pcap, alert["src_ip"], alert["src_port"], alert["dst_ip"], alert["dst_port"],
                                         max_idx=alert["pkt_num"], min_ts_us=_alert_us(alert["datetime"]))
            if ra.data:
                wire, locate, data_pkts = ra.data, ra.locate, ra.packets
                dump_src, dump_bytes = f"reassembled stream, packets {ra.packets}", ra.data
                if ra.gaps:
                    out["reassembly_gap"] = "Data after a sequence gap was not included."
        out["note"] = ("Snort matched this on reassembled/service data: pkt_num is the packet that triggered the flush "
                       "(usually the peer's ACK), not necessarily the packet carrying the matched bytes.")
        if wire is None and inspector is not None:
            out["note"] += " Wire bytes could not be reassembled; only Snort's inspected buffer is shown."
    out["packet"]["trigger_packet"] = trigger.idx if trigger else None
    out["packet"]["data_packets"] = data_pkts
    if rule is not None:
        out["contents"] = [_content_report(c, wire, inspector, locate) for c in rule.contents]
        out["pcres"] = [_pcre_report(p, wire, inspector) for p in rule.pcres]
        if rule.buffers:
            out["buffer_caveat"] = ("Sticky-buffer offsets are relative to Snort's normalized buffer; a match in the raw "
                                    "stream shows the bytes are present, not that they sit at that offset in the buffer.")
    if dump_src:
        out["payload"] = {"source": dump_src, **hexdump(dump_bytes, display_bytes)}
    if inspector is not None:
        out["inspector_buffer"] = {"source": "alert_json b64_data (Snort's inspected buffer)", **hexdump(inspector, display_bytes)}
    return out
