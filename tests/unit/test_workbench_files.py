"""write_rules_file / export path handling: nothing outside allowed_roots is ever read or written."""
import pytest

from detection_workbench.config import Config
from detection_workbench.workbench import Workbench, WorkbenchError

NEW = 'alert tcp any any -> any any ( msg:"new"; content:"x"; sid:1000001; rev:1; )'


@pytest.fixture
def wb(tmp_path):
    root = tmp_path / "allowed"
    root.mkdir()
    return Workbench(Config(case_dir=tmp_path / "cases", allowed_roots=(root.resolve(),))), root.resolve()


def test_outside_roots_existing_file_is_not_read(wb, tmp_path):
    w, _ = wb
    secret = tmp_path / "secret.txt"
    secret.write_text("TOP-SECRET-CONTENT")
    with pytest.raises(WorkbenchError, match="outside allowed_roots") as e:
        w.write_rules_file(str(secret), NEW)
    assert "TOP-SECRET" not in str(e.value)
    assert secret.read_text() == "TOP-SECRET-CONTENT"


def test_outside_roots_with_overwrite_is_refused_and_untouched(wb, tmp_path):
    w, _ = wb
    other = tmp_path / "other.rules"
    other.write_text("original")
    with pytest.raises(WorkbenchError):
        w.write_rules_file(str(other), NEW, overwrite=True)
    assert other.read_text() == "original"


def test_system_file_is_not_leaked(wb):
    w, _ = wb
    with pytest.raises(WorkbenchError):
        w.write_rules_file("/etc/hostname", NEW)


def test_new_file_inside_roots_is_written(wb):
    w, root = wb
    out = w.write_rules_file(str(root / "new.rules"), NEW)
    assert out["written"] and (root / "new.rules").read_text() == NEW + "\n"


def test_existing_file_inside_roots_returns_diff_not_overwrite(wb):
    w, root = wb
    f = root / "mine.rules"
    f.write_text("alert tcp any any -> any any ( msg:\"old\"; sid:5; rev:1; )\n")
    out = w.write_rules_file(str(f), NEW)
    assert out["written"] is False and "-alert tcp any any -> any any ( msg:\"old\"" in out["diff"] and "+" in out["diff"]
    assert "old" in f.read_text()


def test_overwrite_replaces_inside_roots(wb):
    w, root = wb
    f = root / "mine.rules"
    f.write_text("old\n")
    assert w.write_rules_file(str(f), NEW, overwrite=True)["written"]
    assert f.read_text() == NEW + "\n"


def test_registered_evidence_is_never_overwritten_but_can_be_diffed(wb):
    w, root = wb
    w.create_case("t")
    ev = root / "evidence.rules"
    ev.write_text(NEW + "\n")
    w.register_evidence(str(ev))
    with pytest.raises(WorkbenchError, match="evidence"):
        w.write_rules_file(str(ev), "alert tcp any any -> any any ( sid:9; )", overwrite=True)
    assert ev.read_text() == NEW + "\n"
    assert w.write_rules_file(str(ev), "alert tcp any any -> any any ( sid:9; )")["written"] is False


def test_symlink_target_is_refused(wb, tmp_path):
    w, root = wb
    outside = tmp_path / "outside.txt"
    outside.write_text("keep")
    (root / "link.rules").symlink_to(outside)
    with pytest.raises(WorkbenchError):
        w.write_rules_file(str(root / "link.rules"), NEW)
    with pytest.raises(WorkbenchError):
        w.write_rules_file(str(root / "link.rules"), NEW, overwrite=True)
    assert outside.read_text() == "keep"


def test_export_path_outside_roots_is_refused(wb, tmp_path):
    w, root = wb
    w.create_case("t")
    with pytest.raises(WorkbenchError):
        w.export_case("markdown", str(tmp_path / "leak.md"))
    assert not (tmp_path / "leak.md").exists()
