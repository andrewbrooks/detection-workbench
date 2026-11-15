"""Finding snort2lua next to a native Snort install must fail with a clear error when Snort itself is not on PATH."""

from __future__ import annotations

import pytest

from detection_workbench.config import Config
from detection_workbench.engines.snort import plugin as plugin_mod
from detection_workbench.runner.runner import RunContext


def test_convert_names_the_missing_snort_binary_instead_of_failing_on_none(tmp_path, monkeypatch):
    cfg = Config()
    eng = plugin_mod.SnortEngine(cfg)
    ctx = RunContext(run_dir=tmp_path, backend="native", cfg=cfg, etc_dir="/x", name="dw-t")
    (tmp_path / "cfg").mkdir()
    source = tmp_path / "in.rules"
    source.write_text('alert tcp any any -> any any ( msg:"x"; sid:1; )\n')
    monkeypatch.setattr(eng, "has_snort2lua", lambda: True)
    monkeypatch.setattr(plugin_mod.shutil, "which", lambda _name: None)
    with pytest.raises(RuntimeError, match=f"cannot find {cfg.snort.binary} on PATH"):
        eng.convert(ctx, source)
