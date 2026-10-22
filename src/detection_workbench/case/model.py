"""Case file schema constants and helpers (see docs/case-schema.md)."""
from __future__ import annotations

import hashlib
import re
from datetime import UTC, datetime
from pathlib import Path

SCHEMA_VERSION = 1
MIGRATIONS: dict[int, callable] = {}  # {from_version: fn(doc) -> doc at from_version+1}

CASE_STATUSES = ("open", "closed")
MAX_SUMMARY_CHARS = 20_000
MAX_TEXT_CHARS = 5_000  # findings, notes and decision reasons
FINDING_STATUSES = ("open", "confirmed", "dismissed")
DECISION_STATUSES = ("proposed", "accepted", "rejected")
EVIDENCE_TYPES = ("pcap", "pcapng", "rules", "log")
ID_PREFIXES = {"evidence": "e", "run": "r", "finding": "f", "decision": "d", "note": "n"}

_PCAP_MAGICS = {
    bytes.fromhex("a1b2c3d4"), bytes.fromhex("d4c3b2a1"),
    bytes.fromhex("a1b23c4d"), bytes.fromhex("4d3cb2a1"),
}
_PCAPNG_MAGIC = bytes.fromhex("0a0d0d0a")
_RULE_HEADER = re.compile(rb"^\s*(#\s*)?(alert|log|pass|drop|reject|block|react|rewrite)\s+\w+\s+\S+\s+\S+\s+(->|<>)", re.M)


class SchemaError(ValueError):
    pass


def now() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def detect_type_from_head(head: bytes) -> tuple[str, str]:
    """Classify evidence from its first bytes. Falls back to 'log' for unknown content."""
    magic = head[:4]
    if magic in _PCAP_MAGICS:
        return "pcap", "magic"
    if magic == _PCAPNG_MAGIC:
        return "pcapng", "magic"
    if _RULE_HEADER.search(head):
        return "rules", "content"
    return "log", "ext"


def detect_type(path: Path) -> tuple[str, str]:
    with path.open("rb") as f:
        return detect_type_from_head(f.read(65536))


def check_version(doc: dict, what: str) -> dict:
    """Validate and migrate a loaded document to the current schema version."""
    v = doc.get("schema_version")
    if not isinstance(v, int):
        raise SchemaError(f"{what}: missing schema_version")
    if v > SCHEMA_VERSION:
        raise SchemaError(f"{what}: schema_version {v} is newer than supported {SCHEMA_VERSION}")
    while v < SCHEMA_VERSION:
        doc = MIGRATIONS[v](doc)
        v += 1
        doc["schema_version"] = v
    return doc


def slugify(title: str) -> str:
    s = re.sub(r"[^a-z0-9]+", "-", title.lower()).strip("-")
    return s[:40] or "case"
