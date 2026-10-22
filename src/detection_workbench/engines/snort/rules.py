"""Tolerant Snort 3 rule parser. Used for lint, explain_alert and profile splitting; Snort itself
remains the authority on whether a rule is valid."""
from __future__ import annotations

import re
from dataclasses import dataclass, field

STICKY_BUFFERS = {
    "http_uri", "http_raw_uri", "http_header", "http_raw_header", "http_method", "http_client_body",
    "http_cookie", "http_raw_cookie", "http_stat_code", "http_stat_msg", "http_version", "http_param",
    "http_trailer", "http_raw_trailer", "http_raw_request", "http_raw_status", "pkt_data", "raw_data",
    "file_data", "dns_query", "ssl_state", "ssl_version", "ssh_version", "ssh_proto", "vba_data",
    "js_data", "base64_data", "smtp_command", "smtp_header",
}
_HEADER = re.compile(r"^\s*(?P<action>\w+)\s+(?P<proto>\S+)\s+(?P<src>\S+)\s+(?P<sport>\S+)\s+"
                     r"(?P<dir>->|<>)\s+(?P<dst>\S+)\s+(?P<dport>\S+)\s*\((?P<body>.*)\)\s*$", re.S)
_HEX = re.compile(r"\|([0-9A-Fa-f\s]*)\|")


@dataclass
class Content:
    value: bytes
    raw: str
    buffer: str | None = None
    negated: bool = False
    nocase: bool = False
    offset: int | None = None
    depth: int | None = None
    distance: int | None = None
    within: int | None = None
    fast_pattern: bool = False

    @property
    def anchored(self) -> bool:
        return any(v is not None for v in (self.offset, self.depth, self.distance, self.within))


@dataclass
class Pcre:
    pattern: str
    flags: str
    raw: str
    buffer: str | None = None
    negated: bool = False


@dataclass
class Rule:
    line: int
    text: str
    action: str = ""
    proto: str = ""
    src: str = ""
    sport: str = ""
    direction: str = ""
    dst: str = ""
    dport: str = ""
    options: list[tuple[str, str | None]] = field(default_factory=list)
    gid: int = 1
    sid: int | None = None
    rev: int | None = None
    msg: str | None = None
    services: list[str] = field(default_factory=list)
    contents: list[Content] = field(default_factory=list)
    pcres: list[Pcre] = field(default_factory=list)
    buffers: list[str] = field(default_factory=list)
    parsed: bool = True


def decode_content(s: str) -> bytes:
    """Decode a Snort content string: |hex| runs and backslash escapes."""
    out, i = bytearray(), 0
    while i < len(s):
        if s[i] == "|":
            j = s.find("|", i + 1)
            if j == -1:
                out += s[i:].encode("latin-1", "replace")
                break
            hexs = re.sub(r"\s+", "", s[i + 1:j])
            try:
                out += bytes.fromhex(hexs)
            except ValueError:
                out += s[i:j + 1].encode("latin-1", "replace")
            i = j + 1
        elif s[i] == "\\" and i + 1 < len(s):
            out += s[i + 1].encode("latin-1", "replace")
            i += 2
        else:
            out += s[i].encode("utf-8", "replace")
            i += 1
    return bytes(out)


def split_options(body: str) -> list[str]:
    """Split on ';' outside double quotes, honoring backslash escapes."""
    parts, cur, q, esc = [], [], False, False
    for ch in body:
        if esc:
            cur.append(ch); esc = False; continue
        if ch == "\\":
            cur.append(ch); esc = True; continue
        if ch == '"':
            q = not q
        if ch == ";" and not q:
            parts.append("".join(cur)); cur = []; continue
        cur.append(ch)
    if "".join(cur).strip():
        parts.append("".join(cur))
    return [p.strip() for p in parts if p.strip()]


def _split_commas(s: str) -> list[str]:
    parts, cur, q, esc = [], [], False, False
    for ch in s:
        if esc:
            cur.append(ch); esc = False; continue
        if ch == "\\":
            cur.append(ch); esc = True; continue
        if ch == '"':
            q = not q
        if ch == "," and not q:
            parts.append("".join(cur)); cur = []; continue
        cur.append(ch)
    parts.append("".join(cur))
    return [p.strip() for p in parts]


def _int(s: str) -> int | None:
    try:
        return int(s)
    except ValueError:
        return None


def _apply_modifier(c: Content, mod: str) -> None:
    name, _, val = mod.partition(" ")
    val = val.strip()
    if name == "nocase":
        c.nocase = True
    elif name == "fast_pattern":
        c.fast_pattern = True
    elif name in ("offset", "depth", "distance", "within"):
        setattr(c, name, _int(val))


def _parse_content(val: str, buffer: str | None) -> Content | None:
    parts = _split_commas(val)
    first = parts[0]
    neg = first.startswith("!")
    first = first[1:].strip() if neg else first
    if len(first) < 2 or first[0] != '"' or first[-1] != '"':
        return None
    c = Content(value=decode_content(first[1:-1]), raw=first[1:-1], buffer=buffer, negated=neg)
    for m in parts[1:]:
        _apply_modifier(c, m)
    return c


def parse_rule(text: str, line: int = 0) -> Rule:
    r = Rule(line=line, text=text)
    m = _HEADER.match(text)
    if not m:
        r.parsed = False
        return r
    r.action, r.proto, r.src, r.sport, r.direction, r.dst, r.dport = (
        m["action"], m["proto"], m["src"], m["sport"], m["dir"], m["dst"], m["dport"])
    buffer, last_content = None, None
    for opt in split_options(m["body"]):
        name, sep, val = opt.partition(":")
        name, val = name.strip(), (val.strip() if sep else None)
        r.options.append((name, val))
        if name in STICKY_BUFFERS:
            buffer = name
            r.buffers.append(name)
        elif name == "content" and val is not None:
            last_content = _parse_content(val, buffer)
            if last_content:
                r.contents.append(last_content)
        elif name in ("nocase", "fast_pattern", "offset", "depth", "distance", "within") and last_content:
            _apply_modifier(last_content, f"{name} {val or ''}")
        elif name == "pcre" and val:
            neg = val.startswith("!")
            v = val[1:].strip() if neg else val
            pm = re.fullmatch(r'"/(.*)/([A-Za-z]*)"', v, re.S)
            if pm:
                r.pcres.append(Pcre(pattern=pm[1], flags=pm[2], raw=v, buffer=buffer, negated=neg))
        elif name == "sid" and val:
            r.sid = _int(val)
        elif name == "rev" and val:
            r.rev = _int(val)
        elif name == "gid" and val:
            r.gid = _int(val) or 1
        elif name == "msg" and val:
            r.msg = val.strip('"')
        elif name == "service" and val:
            r.services = [s.strip() for s in val.split(",") if s.strip()]
    return r


def parse_rules(text: str) -> list[Rule]:
    """One Rule per non-comment rule; backslash-continued lines are joined (line = first line)."""
    rules, buf, start = [], "", 0
    for n, raw in enumerate(text.splitlines(), start=1):
        line = raw.rstrip()
        if not buf:
            if not line.strip() or line.lstrip().startswith("#"):
                continue
            start = n
        if line.endswith("\\"):
            buf += line[:-1]
            continue
        rules.append(parse_rule(buf + line, start))
        buf = ""
    if buf:
        rules.append(parse_rule(buf, start))
    return rules


def find_includes(text: str) -> list[int]:
    """Line numbers of `include` directives. Snort follows them, which would let a rule set make the
    engine open other files, so the workbench refuses rule sets that contain any."""
    return [n for n, line in enumerate(text.splitlines(), start=1) if re.match(r"\s*include\b", line, re.I)]


def find_rule(text: str, gid: int, sid: int) -> Rule | None:
    for r in parse_rules(text):
        if r.sid == sid and r.gid == gid:
            return r
    return None
