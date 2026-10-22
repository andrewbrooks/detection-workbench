"""CaseStore: JSON files plus an append-only events.jsonl, under a per-case lock."""
from __future__ import annotations

import fcntl
import json
import os
import tempfile
from contextlib import contextmanager
from pathlib import Path

from .model import (
    CASE_STATUSES,
    DECISION_STATUSES,
    EVIDENCE_TYPES,
    FINDING_STATUSES,
    ID_PREFIXES,
    MAX_SUMMARY_CHARS,
    MAX_TEXT_CHARS,
    SCHEMA_VERSION,
    SchemaError,
    check_version,
    detect_type,
    detect_type_from_head,
    now,
    sha256_file,
    slugify,
)

_DOCS = {"evidence": "evidence.json", "findings": "findings.json",
         "decisions": "decisions.json", "notes": "notes.json"}


class CaseError(ValueError):
    pass


def _check_text(text: str, what: str) -> None:
    if not isinstance(text, str) or not text.strip():
        raise CaseError(f"{what} is empty")
    if len(text) > MAX_TEXT_CHARS:
        raise CaseError(f"{what} is longer than {MAX_TEXT_CHARS} characters; keep it short and put detail in the summary")


def _atomic_write(path: Path, data: dict) -> None:
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=path.name + ".")
    try:
        with os.fdopen(fd, "w") as f:
            json.dump(data, f, indent=2, sort_keys=True)
            f.write("\n")
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
    except BaseException:
        os.unlink(tmp)
        raise


def _read(path: Path) -> dict:
    with path.open() as f:
        return check_version(json.load(f), path.name)


class CaseStore:
    def __init__(self, root: Path):
        self.root = Path(root)
        if not (self.root / "case.json").is_file():
            raise CaseError(f"no case at {self.root}")

    # ---- construction -------------------------------------------------
    @classmethod
    def create(cls, case_dir: Path, title: str) -> "CaseStore":
        case_dir = Path(case_dir)
        fresh = not case_dir.exists()
        case_dir.mkdir(parents=True, exist_ok=True)
        if fresh:
            os.chmod(case_dir, 0o700)  # cases hold paths, hashes and alert data: owner only
        stamp = now()[:10].replace("-", "")
        base = f"{stamp}-{slugify(title)}"
        cid, n = base, 1
        while True:
            try:
                (case_dir / cid).mkdir(mode=0o700)
                break
            except FileExistsError:
                n += 1
                cid = f"{base}-{n}"
        root = case_dir / cid
        (root / "runs").mkdir(mode=0o700)
        (root / "exports").mkdir(mode=0o700)
        t = now()
        _atomic_write(root / "case.json", {
            "schema_version": SCHEMA_VERSION, "id": cid, "title": title, "created": t,
            "updated": t, "status": "open", "summary": "",
            "next_ids": {"e": 1, "r": 1, "f": 1, "d": 1, "n": 1, "ev": 1}})
        _atomic_write(root / "evidence.json", {"schema_version": SCHEMA_VERSION, "items": []})
        for name in ("findings", "decisions", "notes"):
            _atomic_write(root / _DOCS[name], {"schema_version": SCHEMA_VERSION, "items": []})
        store = cls(root)
        with store._txn() as tx:
            tx.event("case.created", cid, {"title": title})
        return store

    @classmethod
    def open(cls, case_dir: Path, case_id: str) -> "CaseStore":
        if "/" in case_id or case_id in ("", ".", ".."):
            raise CaseError("invalid case id")
        return cls(Path(case_dir) / case_id)

    @staticmethod
    def list_cases(case_dir: Path) -> list[dict]:
        out = []
        for p in sorted(Path(case_dir).glob("*/case.json")) if Path(case_dir).is_dir() else []:
            try:
                d = _read(p)
                out.append({k: d[k] for k in ("id", "title", "created", "updated", "status")})
            except (SchemaError, OSError, ValueError, KeyError):
                continue
        return out

    # ---- transactions -------------------------------------------------
    @contextmanager
    def _txn(self):
        lock = open(self.root / ".lock", "a")  # noqa: SIM115 (held across the yield, closed in finally)
        fcntl.flock(lock, fcntl.LOCK_EX)
        try:
            tx = _Txn(self)
            yield tx
            tx.commit()
        finally:
            fcntl.flock(lock, fcntl.LOCK_UN)
            lock.close()

    def _doc(self, name: str) -> dict:
        return _read(self.root / ("case.json" if name == "case" else _DOCS[name]))

    # ---- evidence -----------------------------------------------------
    def register_evidence(self, path: Path, label: dict | None = None, type_: str | None = None,
                          fingerprint: tuple[str, int, bytes] | None = None) -> dict:
        """`path` must already be resolved and vetted. `fingerprint` is (sha256, size, head bytes) read in one pass through
        safety.verified.fingerprint; without it the file is hashed here by path."""
        path = Path(path)
        if not path.is_file():
            raise CaseError(f"not a file: {path}")
        det, how = detect_type_from_head(fingerprint[2]) if fingerprint else detect_type(path)
        if type_ and type_ not in EVIDENCE_TYPES:
            raise CaseError(f"type must be one of {EVIDENCE_TYPES}")
        if type_:
            det, how = type_, "user"
        with self._txn() as tx:
            ev = tx.doc("evidence")
            digest = fingerprint[0] if fingerprint else sha256_file(path)
            for it in ev["items"]:
                if it["path"] == str(path) and it["sha256"] == digest:
                    return it
            item = {"id": tx.next_id("evidence"), "path": str(path), "sha256": digest,
                    "size": fingerprint[1] if fingerprint else path.stat().st_size, "type": det, "detected_by": how,
                    "registered": now(), "label": label, "copied": False, "copy_path": None}
            ev["items"].append(item)
            tx.event("evidence.registered", item["id"], {"path": item["path"], "sha256": digest})
            return item

    def get_evidence(self, evidence_id: str) -> dict:
        for it in self._doc("evidence")["items"]:
            if it["id"] == evidence_id:
                return it
        raise CaseError(f"unknown evidence id {evidence_id}")

    def verify_evidence(self, evidence_id: str) -> dict:
        """Re-hash before use; a changed file is a hard error."""
        it = self.get_evidence(evidence_id)
        p = Path(it["path"])
        if not p.is_file() or sha256_file(p) != it["sha256"]:
            raise CaseError(f"evidence {evidence_id} changed or missing since registration: {p}")
        return it

    # ---- runs ---------------------------------------------------------
    def allocate_run(self) -> tuple[str, Path]:
        with self._txn() as tx:
            rid = tx.next_id("run")
            d = self.root / "runs" / rid
            d.mkdir(mode=0o700)
            for sub in ("cfg", "out", "results"):
                (d / sub).mkdir(mode=0o700)
            return rid, d

    def record_run(self, run: dict) -> dict:
        rid = run["id"]
        f = self.root / "runs" / rid / "run.json"
        if f.exists():
            raise CaseError(f"run {rid} already recorded; runs are immutable")
        run = {"schema_version": SCHEMA_VERSION, **run}
        with self._txn() as tx:
            _atomic_write(f, run)
            os.chmod(f, 0o444)
            tx.event("run.recorded", rid, {"kind": run.get("kind"), "status": run.get("status")})
        return run

    def get_run(self, run_id: str) -> dict:
        if not run_id.startswith("r-") or "/" in run_id:
            raise CaseError(f"bad run id {run_id}")
        f = self.root / "runs" / run_id / "run.json"
        if not f.is_file():
            raise CaseError(f"unknown run {run_id}")
        return _read(f)

    def list_runs(self, limit: int | None = None) -> list[dict]:
        runs = sorted((self.root / "runs").glob("r-*/run.json"))
        if limit:
            runs = runs[-limit:]
        return [_read(p) for p in runs]

    # ---- findings / decisions / notes ---------------------------------
    def add_finding(self, statement: str, run_ids: list[str], evidence_ids: list[str]) -> dict:
        _check_text(statement, "finding statement")
        for r in run_ids:
            self.get_run(r)
        for e in evidence_ids:
            self.get_evidence(e)
        with self._txn() as tx:
            t = now()
            item = {"id": tx.next_id("finding"), "statement": statement, "status": "open",
                    "run_ids": list(run_ids), "evidence_ids": list(evidence_ids),
                    "created": t, "updated": t, "history": []}
            tx.doc("findings")["items"].append(item)
            tx.event("finding.added", item["id"], {"statement": statement})
            return item

    def update_finding(self, finding_id: str, status: str | None = None, statement: str | None = None) -> dict:
        if status is not None and status not in FINDING_STATUSES:
            raise CaseError(f"status must be one of {FINDING_STATUSES}")
        if statement is not None:
            _check_text(statement, "finding statement")
        with self._txn() as tx:
            for it in tx.doc("findings")["items"]:
                if it["id"] == finding_id:
                    break
            else:
                raise CaseError(f"unknown finding {finding_id}")
            t = now()
            for field, new in (("status", status), ("statement", statement)):
                if new is not None and new != it[field]:
                    it["history"].append({"at": t, "field": field, "from": it[field], "to": new})
                    it[field] = new
            it["updated"] = t
            tx.event("finding.updated", finding_id, {"status": it["status"]})
            return it

    def add_decision(self, kind: str, change: dict, reason: str, before_run: str, after_run: str,
                     counts: dict, status: str = "proposed", counts_omitted: int = 0) -> dict:
        if status not in DECISION_STATUSES:
            raise CaseError(f"status must be one of {DECISION_STATUSES}")
        _check_text(reason, "decision reason")
        self.get_run(before_run)
        self.get_run(after_run)
        with self._txn() as tx:
            item = {"id": tx.next_id("decision"), "kind": kind, "change": change, "reason": reason,
                    "before_run": before_run, "after_run": after_run, "counts": counts,
                    "status": status, "created": now()}
            if counts_omitted:
                item["counts_omitted"] = counts_omitted  # unchanged SIDs left out of `counts` to keep the record small
            tx.doc("decisions")["items"].append(item)
            tx.event("decision.recorded", item["id"], {"kind": kind})
            return item

    def add_note(self, text: str, author: str = "client") -> dict:
        if author not in ("user", "client"):
            raise CaseError("author must be user or client")
        _check_text(text, "note")
        with self._txn() as tx:
            item = {"id": tx.next_id("note"), "text": text, "author": author, "created": now()}
            tx.doc("notes")["items"].append(item)
            tx.event("note.added", item["id"], {})
            return item

    def update_case(self, summary: str | None = None, status: str | None = None) -> dict:
        """Set the analyst summary and/or open/closed status; every change is logged."""
        if summary is None and status is None:
            raise CaseError("give a summary, a status, or both")
        if status is not None and status not in CASE_STATUSES:
            raise CaseError(f"status must be one of {CASE_STATUSES}")
        if summary is not None and len(summary) > MAX_SUMMARY_CHARS:
            raise CaseError(f"summary is longer than {MAX_SUMMARY_CHARS} characters")
        with self._txn() as tx:
            changed = {}
            if summary is not None and summary != tx._case["summary"]:
                tx._case["summary"] = summary
                changed["summary_chars"] = len(summary)
            if status is not None and status != tx._case["status"]:
                tx._case["status"] = status
                changed["status"] = status
            if changed:
                tx.event("case.updated", self.root.name, changed)
            return {"id": tx._case["id"], "status": tx._case["status"], "summary": tx._case["summary"],
                    "changed": sorted(changed)}

    def log_event(self, type_: str, ref: str, data: dict) -> None:
        with self._txn() as tx:
            tx.event(type_, ref, data)

    # ---- views --------------------------------------------------------
    def summary(self, recent_runs: int = 5) -> dict:
        case = self._doc("case")
        return {
            "id": case["id"], "title": case["title"], "status": case["status"],
            "created": case["created"], "updated": case["updated"], "summary": case["summary"],
            "evidence": self._doc("evidence")["items"],
            "findings": self._doc("findings")["items"],
            "decisions": self._doc("decisions")["items"],
            "notes": self._doc("notes")["items"],
            "recent_runs": [{k: r.get(k) for k in ("id", "kind", "engine", "status", "started", "totals")}
                            for r in self.list_runs(recent_runs)],
        }

    def events(self) -> list[dict]:
        f = self.root / "events.jsonl"
        if not f.exists():
            return []
        return [json.loads(line) for line in f.read_text().splitlines() if line]


class _Txn:
    """Buffers document changes under the lock; commit writes them atomically."""

    def __init__(self, store: CaseStore):
        self.s = store
        self._docs: dict[str, dict] = {}
        self._events: list[dict] = []
        self._case = store._doc("case")

    def doc(self, name: str) -> dict:
        if name not in self._docs:
            self._docs[name] = self.s._doc(name)
        return self._docs[name]

    def next_id(self, kind: str) -> str:
        p = ID_PREFIXES[kind]
        n = self._case["next_ids"][p]
        self._case["next_ids"][p] = n + 1
        return f"{p}-{n:04d}"

    def event(self, type_: str, ref: str, data: dict) -> None:
        seq = self._case["next_ids"]["ev"]
        self._case["next_ids"]["ev"] = seq + 1
        self._events.append({"ts": now(), "seq": seq, "type": type_, "ref": ref, "data": data})

    def commit(self) -> None:
        for name, doc in self._docs.items():
            _atomic_write(self.s.root / _DOCS[name], doc)
        if self._events:
            with (self.s.root / "events.jsonl").open("a") as f:
                for e in self._events:
                    f.write(json.dumps(e, sort_keys=True) + "\n")
        self._case["updated"] = now()
        _atomic_write(self.s.root / "case.json", self._case)
