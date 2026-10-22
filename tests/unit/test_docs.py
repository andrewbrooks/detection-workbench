"""Markdown docs: relative links and in-page anchors must resolve."""
import re
from pathlib import Path

import pytest

ROOT = Path(__file__).parents[2]
DOCS = [ROOT / "README.md", ROOT / "CONTRIBUTING.md", ROOT / "SECURITY.md", *sorted((ROOT / "docs").glob("*.md")), ROOT / "docs/examples/README.md",
        ROOT / "tests/fixtures/README.md"]


def slug(heading: str) -> str:
    return re.sub(r"[^a-z0-9 -]", "", heading.lower()).strip().replace(" ", "-")


def anchors(path: Path) -> set[str]:
    text = re.sub(r"(?s)(`{3,})[^\n]*\n.*?\n\1", "", path.read_text())  # ignore headings inside code fences
    return {slug(h) for h in re.findall(r"(?m)^#{1,6} (.+)$", text)}


def links(path: Path):
    text = re.sub(r"(?s)(`{3,})[^\n]*\n.*?\n\1", "", path.read_text())  # ignore links inside code fences
    return re.findall(r"\]\(([^)\s]+)\)", text)


@pytest.mark.parametrize("doc", DOCS, ids=lambda p: str(p.relative_to(ROOT)))
def test_links_resolve(doc):
    for href in links(doc):
        if href.startswith(("http://", "https://", "mailto:")):
            continue
        target, _, frag = href.partition("#")
        dest = doc if not target else (doc.parent / target).resolve()
        assert dest.exists(), f"{doc.name}: broken link {href}"
        if frag and dest.suffix == ".md":
            assert frag in anchors(dest), f"{doc.name}: no heading for anchor #{frag} in {dest.name}"


def test_every_doc_is_checked():
    on_disk = {p for p in [ROOT / "README.md", ROOT / "CONTRIBUTING.md", ROOT / "SECURITY.md", *(ROOT / "docs").rglob("*.md"), *(ROOT / "tests/fixtures").glob("*.md")]
               if "examples/case" not in str(p)}
    assert on_disk == set(DOCS)
