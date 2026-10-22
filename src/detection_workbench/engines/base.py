"""Engine plugin interface and registry. Phase 2/3 engines (zeek, tshark, zircolite) implement
the same protocol and register here; the runner, safety layer and case store do not change."""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Protocol

from ..runner.runner import RawRun, RunContext


@dataclass
class EngineVersion:
    name: str
    version: str | None
    backend: str | None  # native | docker | None when unavailable
    available: bool
    detail: str = ""


@dataclass
class EngineResult:
    """Everything the recorder needs to write run.json, plus the tool-facing payload."""
    status: str  # ok | error | timeout
    argv: list[str]
    raw: RawRun | None = None
    inputs: list[dict] = field(default_factory=list)
    rules: dict | None = None
    config: dict | None = None
    results: dict = field(default_factory=dict)  # relative pointers inside the run dir
    totals: dict = field(default_factory=dict)
    payload: dict = field(default_factory=dict)
    error_excerpt: str = ""
    extra_argv: list[list[str]] = field(default_factory=list)


class Engine(Protocol):
    name: str
    evidence_types: set[str]

    def version(self) -> EngineVersion: ...

    def make_context(self, run_dir: Path, run_id: str, case_id: str) -> RunContext: ...

    def validate(self, ctx: RunContext, rules_text: str, rules_name: str) -> EngineResult: ...

    def run(self, ctx: RunContext, pcap: Path, rules_text: str, options: dict) -> EngineResult: ...


REGISTRY: dict[str, Engine] = {}


def register(engine: Engine) -> None:
    REGISTRY[engine.name] = engine
