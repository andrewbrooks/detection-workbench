"""Describe a tuning change the way a person reviews it, and turn accepted changes into text to paste.

- `rule_diff`: an option-by-option diff of an edited rule, with a few checks a reviewer cares about (did `rev` go up?).
- `filter_entry`: the config entry a suppress / event_filter / rate_filter change adds, built by the same validated
  renderer that generated the config the change was tested with.
- `build_export`: the accepted changes as a rules file and a config snippet.

Everything here is pure: text in, text out. Nothing reads files or runs anything.
"""
from __future__ import annotations

import difflib
import re

from .config_gen import FILTER_TYPES, TuningError, render_filter
from .rules import Rule, parse_rule

MAX_DIFF_LINES = 120
MAX_LINE = 300
MAX_COMMENT = 200


def _header(r: Rule) -> str:
    return f"{r.action} {r.proto} {r.src} {r.sport} {r.direction} {r.dst} {r.dport}"


def _options(r: Rule) -> list[str]:
    return [name if value is None else f"{name}:{value}" for name, value in r.options]


def _clip(line: str) -> str:
    return line if len(line) <= MAX_LINE else line[: MAX_LINE - 1] + "…"


def rule_checks(old: Rule, new: Rule) -> list[dict]:
    """Things worth a second look when a rule is edited. Each is {level: ok|warn, text}."""
    out = []

    def add(level, text):
        out.append({"level": level, "text": text})

    if (old.sid, old.gid) != (new.sid, new.gid):
        add("warn", f"sid changed ({old.gid}:{old.sid} → {new.gid}:{new.sid}): this is a different rule, not an edit")
    else:
        add("ok", "sid unchanged")
    changed = _header(old) != _header(new) or _options(old) != _options(new)
    if not changed:
        add("warn", "the rule text is identical to before")
    if old.rev is None or new.rev is None:
        add("warn", "rev is missing; add 'rev:N;' and raise it on every edit")
    elif new.rev > old.rev:
        add("ok", f"rev bumped ({old.rev} → {new.rev})")
    elif new.rev == old.rev and changed:
        add("warn", f"rev not bumped (still {new.rev}); later runs cannot tell the old and new rules apart")
    elif new.rev < old.rev:
        add("warn", f"rev lowered ({old.rev} → {new.rev})")
    positive = [c for c in new.contents if not c.negated]
    if not positive:
        add("warn", "no positive content, so the rule has no fast pattern and is evaluated on every packet in scope")
    elif any(c.fast_pattern for c in positive):
        add("ok", "has an explicit fast pattern")
    return out


def rule_diff(old_text: str | None, new_text: str) -> dict:
    """{lines, granularity, checks}. Lines start with two characters: '  ' unchanged, '- ' removed, '+ ' added."""
    new = parse_rule(new_text.strip())
    old = parse_rule(old_text.strip()) if old_text else None
    if old is None or not old.parsed or not new.parsed:
        before = [old_text.strip()] if old_text else []
        lines = [f"- {_clip(x)}" for x in before] + [f"+ {_clip(new_text.strip())}"]
        return {"lines": lines, "granularity": "line", "checks": []}
    lines = [f"  {_header(new)}"] if _header(old) == _header(new) else [f"- {_header(old)}", f"+ {_header(new)}"]
    a, b = _options(old), _options(new)
    for tag, i1, i2, j1, j2 in difflib.SequenceMatcher(a=a, b=b, autojunk=False).get_opcodes():
        if tag == "equal":
            lines += [f"  {x}" for x in a[i1:i2]]
        else:
            lines += [f"- {x}" for x in a[i1:i2]] + [f"+ {x}" for x in b[j1:j2]]
    lines = [_clip(x) for x in lines]
    if len(lines) > MAX_DIFF_LINES:
        lines = lines[:MAX_DIFF_LINES] + [f"  … {len(lines) - MAX_DIFF_LINES} more lines"]
    return {"lines": lines, "granularity": "option", "checks": rule_checks(old, new)}


def checks_text(checks: list[dict]) -> str:
    """One line for a report: ok items plainly, warnings in bold."""
    return " · ".join(c["text"] if c["level"] == "ok" else f"**warning:** {c['text']}" for c in checks)


def filter_entry(change: dict) -> tuple[str, str]:
    """(table name, one config record) for a filter change, built by the validated renderer."""
    return render_filter(change)


def filter_snippet(change: dict) -> str:
    table, record = filter_entry(change)
    return f"-- add this entry to the {table} table in snort.lua\n{table} = {{ {record} }}"


def comment_text(text: str) -> str:
    """A reason as one safe comment line: whitespace collapsed, control characters dropped, length capped."""
    flat = re.sub(r"[\x00-\x1f\x7f]", " ", str(text))
    flat = " ".join(flat.split())
    return flat if len(flat) <= MAX_COMMENT else flat[: MAX_COMMENT - 1] + "…"


def build_export(decisions: list[dict]) -> dict:
    """Accepted decisions as {rules, config, included, skipped}.

    `rules` is a rules-file fragment (comments start with #). `config` is a Lua fragment: one table per filter type, to be
    merged into the matching table in snort.lua. When several rule edits target one sid the latest wins."""
    rules_by_sid: dict[int, dict] = {}
    tables: dict[str, list[tuple[str, str, str]]] = {}
    included, skipped = [], []
    for d in decisions:
        change, did = d.get("change") or {}, d["id"]
        kind = change.get("kind")
        try:
            if kind == "rule_edit":
                rule = parse_rule(str(change.get("rule", "")).strip())
                if not rule.parsed or rule.sid is None:
                    raise TuningError("the stored rule cannot be parsed")
                if rule.sid in rules_by_sid:
                    skipped.append(f"{rules_by_sid[rule.sid]['id']}: superseded by {did} (same sid {rule.sid})")
                rules_by_sid[rule.sid] = {"id": did, "text": str(change["rule"]).strip(), "reason": d.get("reason", "")}
            elif kind in FILTER_TYPES:
                table, record = filter_entry(change)
                tables.setdefault(table, []).append((did, d.get("reason", ""), record))
            else:
                raise TuningError(f"unknown change kind {kind!r}")
            included.append(did)
        except (TuningError, KeyError, ValueError) as e:
            skipped.append(f"{did}: {e}")
    rules = ""
    if rules_by_sid:
        body = ["# Detection Workbench: accepted rule changes. Replace the rule with the same sid in your rules file."]
        for sid in sorted(rules_by_sid):
            r = rules_by_sid[sid]
            body += [f"# {r['id']}: {comment_text(r['reason'])}", r["text"]]
        rules = "\n".join(body) + "\n"
    config = ""
    if tables:
        body = ["-- Detection Workbench: accepted configuration changes.",
                "-- Merge each table into the table of the same name in snort.lua (create it if you have none)."]
        for table in sorted(tables):
            body.append(f"{table} = {{")
            for did, reason, record in tables[table]:
                body += [f"    -- {did}: {comment_text(reason)}", f"    {record},"]
            body.append("}")
        config = "\n".join(body) + "\n"
    return {"rules": rules, "config": config, "included": included, "skipped": skipped}
