"""Keep the README's "What it looks like" excerpt in step with the example case report.

The README quotes a results table and a rule diff from the exported report. If the example case is regenerated and
those lines change, this test fails so the README is updated instead of going stale.
"""

from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
README = ROOT / "README.md"
REPORT = next((ROOT / "docs/examples/case").glob("*/exports/*-markdown.md"))
SECTION_START = "## What it looks like"


def quoted_lines(readme_text: str) -> list[str]:
    """Return the table rows and diff lines in the README's example section."""
    section = readme_text.split(SECTION_START, 1)[1].split("\n## ", 1)[0]
    quoted: list[str] = []
    in_diff = False
    for line in section.splitlines():
        if line.startswith("```"):
            in_diff = line == "```diff"
        elif in_diff or line.startswith("|"):
            quoted.append(line)
    return quoted


def test_readme_excerpt_is_copied_from_the_example_report() -> None:
    report_lines = set(REPORT.read_text().splitlines())
    quoted = quoted_lines(README.read_text())

    assert quoted, "the README example section quotes nothing from the report"
    missing = [line for line in quoted if line not in report_lines]
    assert not missing, f"README lines not found in {REPORT.name}: {missing}"


def test_quoted_lines_ignores_prose_and_diagram() -> None:
    text = (
        f"{SECTION_START}\n\nprose | with a pipe\n```mermaid\nflowchart LR\n```\n"
        "| a | b |\n```diff\n+ added\n```\n\n## Next\n| other |\n"
    )
    assert quoted_lines(text) == ["| a | b |", "+ added"]
