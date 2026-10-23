"""Wrap an engine call in an immutable run record. Plugins never touch the case store."""
from __future__ import annotations

import shutil
import time
from collections.abc import Callable

from ..case.model import now
from ..case.store import CaseStore
from ..engines.base import Engine, EngineResult
from ..runner.runner import RunContext


def run_recorded(store: CaseStore, engine: Engine, kind: str, work: Callable[[RunContext], EngineResult],
                 inputs: list[dict], parent_run: str | None = None) -> tuple[str, EngineResult]:
    """Allocate a run directory, execute `work`, write run.json.

    Bad caller input (ValueError, including config/tuning validation errors) removes the empty run
    directory and propagates without a record. Anything else is recorded as an error run, then re-raised.
    """
    rid, run_dir = store.allocate_run()
    try:
        ctx = engine.make_context(run_dir, rid, store.root.name)
    except Exception:
        shutil.rmtree(run_dir, ignore_errors=True)
        raise
    ver = engine.version()
    started, t0, failure = now(), time.monotonic(), None
    try:
        res = work(ctx)
    except ValueError:
        shutil.rmtree(run_dir, ignore_errors=True)
        raise
    except Exception as e:  # engine/infrastructure failure: keep the evidence of the attempt
        res = EngineResult(status="error", argv=[], error_excerpt=f"{type(e).__name__}: {str(e)[:500]}")
        failure = e
    raw = res.raw
    doc = {
        "id": rid, "kind": kind, "engine": engine.name, "engine_version": ver.version, "backend": ctx.backend,
        "argv": res.argv, "extra_argv": res.extra_argv, "inputs": inputs, "rules": res.rules, "config": res.config,
        "started": started, "finished": now(),
        "duration_s": raw.duration_s if raw else round(time.monotonic() - t0, 3),
        "exit_code": raw.exit_code if raw else None, "timed_out": bool(raw and raw.timed_out),
        "status": res.status, "error_excerpt": res.error_excerpt[:2048], "results": res.results,
        "totals": res.totals, "parent_run": parent_run,
    }
    if ctx.backend == "docker":
        doc["docker_image"] = ctx.cfg.snort.docker_image  # the pinned base image
        if ctx.image and ctx.image != ctx.cfg.snort.docker_image:
            doc["docker_run_image"] = ctx.image  # the local image derived from it (see engines/snort/image.py)
    store.record_run(doc)
    if failure is not None:
        raise failure
    return rid, res
