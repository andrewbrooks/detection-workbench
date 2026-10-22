"""Parse `snort -T` diagnostics into {severity, line, sid, error, plain} records."""
from __future__ import annotations

import re
from dataclasses import dataclass, field

_DIAG = re.compile(r"^(ERROR|WARNING|FATAL): (?:(?P<file>[^\s:][^:]*?):(?P<line>\d+) )?(?P<msg>.*)$")
_SUMMARY = re.compile(r"Snort successfully validated the configuration \(with (\d+) warnings?\)")
_RULE_SID = re.compile(r"\bsid\s*:\s*(\d+)")
CASCADE_MSGS = ("syntax error", "unknown rule action", "incomplete rule")

# (regex, plain-language rewrite). First match wins; {0} is the first regex group.
_PLAIN = [
    (re.compile(r"unknown rule keyword: (\S+?)\.?$"), "'{0}' is not a Snort 3 rule option. Check the spelling or whether it is a Snort 2 option."),
    (re.compile(r"unknown rule action"), "The rule header is malformed. The first word must be an action such as alert, and a missing ';' between options is a common cause."),
    (re.compile(r"^syntax error$"), "Snort could not parse this line. Look for a missing ';' after an option or an unbalanced parenthesis."),
    (re.compile(r"incomplete rule"), "The rule ends before its closing ')'. Check the line before it for a missing ';' or ')'."),
    (re.compile(r"pcre2? compile of '(.*)' failed at offset (\d+) : (.*)"), "The pcre pattern does not compile: {2} (at offset {1})."),
    (re.compile(r"'(\w+)' must be in (\S+), inclusive"), "'{0}' must be within {1}."),
    (re.compile(r"duplicates previous rule"), "Another rule already uses this gid:sid. Snort keeps the first one it loaded."),
    (re.compile(r"has no fast pattern"), "The rule has no content to use as a fast pattern, so Snort must evaluate it on every packet. Add a unique content."),
    (re.compile(r"Undefined variable|undefined variable"), "The rule uses a variable that is not defined in the config (such as $HOME_NET)."),
    (re.compile(r"PortVar Lookup failed on '(.*)'"), "The rule uses a port variable {0} that is not defined."),
]


def plain_message(msg: str) -> str:
    for rx, text in _PLAIN:
        m = rx.search(msg)
        if m:
            return text.format(*m.groups())
    return msg


@dataclass
class ValidationReport:
    ok: bool = False
    errors: list[dict] = field(default_factory=list)
    warnings: list[dict] = field(default_factory=list)
    summary_warnings: int | None = None

    @property
    def needs_individual_check(self) -> list[int]:
        """Lines whose errors may be cascade noise (and may hide a later rule's real error)."""
        return sorted({e["line"] for e in self.errors if e["line"] and e["error"].startswith(CASCADE_MSGS)})


def parse_validation(text: str, exit_code: int, rules_text: str = "", file_name: str | None = None) -> ValidationReport:
    lines = rules_text.splitlines()
    rep = ValidationReport()
    for raw in text.splitlines():
        s = _SUMMARY.search(raw)
        if s:
            rep.summary_warnings = int(s.group(1))
            continue
        m = _DIAG.match(raw.strip())
        if not m or m.group(1) == "FATAL" and not m.group("line") and raw.startswith("FATAL: see prior"):
            continue
        sev = "error" if m.group(1) in ("ERROR", "FATAL") else "warning"
        line = int(m.group("line")) if m.group("line") else None
        file_ok = file_name is None or not m.group("file") or m.group("file").endswith(file_name)
        if not file_ok:
            continue  # diagnostics from other files (the generated config) are not about the user's rules
        sid = None
        if line and 0 < line <= len(lines):
            sm = _RULE_SID.search(lines[line - 1])
            sid = int(sm.group(1)) if sm else None
        elif g := re.search(r"rule \d+:(\d+):\d+", m.group("msg")) or re.match(r"\d+:(\d+) ", m.group("msg")):
            sid = int(g.group(1))
        rec = {"severity": sev, "line": line, "sid": sid, "error": m.group("msg"),
               "plain": plain_message(m.group("msg")), "source": "snort",
               "rule": lines[line - 1][:300] if line and 0 < line <= len(lines) else None}
        (rep.errors if sev == "error" else rep.warnings).append(rec)
    rep.ok = exit_code == 0 and not rep.errors
    return rep
