"""The example generator edits docs/writeup.md in place; its block replacement must never swallow other text."""
import importlib.util
from pathlib import Path

import pytest

SPEC = importlib.util.spec_from_file_location("make_example_case", Path(__file__).parents[2] / "scripts/make_example_case.py")
gen = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(gen)

DOC = "intro\n\n```csv\nold,row\n```\n\n## Next heading\n\n```bash\nuv sync\n```\n"


def test_replaces_only_the_named_block():
    out = gen._replace_block(DOC, "```", "csv", "new,row")
    assert out == DOC.replace("old,row", "new,row") and "## Next heading" in out and "uv sync" in out


def test_empty_block_does_not_run_on_to_the_next_fence():
    empty = "intro\n\n```csv\n```\n\n## Next heading\n\n```bash\nuv sync\n```\n"
    assert gen._replace_block(empty, "```", "csv", "a,b") == empty.replace("```csv\n```", "```csv\na,b\n```")


def test_refuses_when_the_old_block_spans_headings():
    broken = "intro\n\n```csv\nrow\n\n## Next heading\n\ntext\n```\n"  # fence closes only after a heading
    with pytest.raises(RuntimeError, match="unbalanced"):
        gen._replace_block(broken, "```", "csv", "x")


def test_report_block_must_start_with_a_title():
    five = "`" * 5
    doc = f"a\n{five}markdown\nnot a title\n{five}\nb\n"
    with pytest.raises(RuntimeError, match="title"):
        gen._replace_block(doc, five, "markdown", "# T")
    ok = f"a\n{five}markdown\n# Old\n{five}\nb\n"
    assert "# T\n" in gen._replace_block(ok, five, "markdown", "# T")
