"""The derived image that lets any host uid run the pinned Snort image, and the Docker CLI lookup."""
import subprocess
from pathlib import Path

import pytest

from detection_workbench.config import Config, SnortConfig
from detection_workbench.engines.snort import image as image_mod
from detection_workbench.engines.snort.image import derived_tag, dockerfile, ensure_image, traversal_dirs
from detection_workbench.runner import runner as runner_mod
from detection_workbench.runner.runner import RunContext, docker_argv, docker_bin, execute

BASE = "ciscotalos/snort3@sha256:f15f714fd61ade114b1039687dd43352cae26cd6401b89f2b03404e0d21e322f"
PATHS = ["/home/snorty/snort3/bin/snort", "/home/snorty/snort3/etc/snort"]


def test_traversal_dirs_are_the_ancestors_without_root_or_duplicates():
    assert traversal_dirs(PATHS) == ["/home", "/home/snorty", "/home/snorty/snort3", "/home/snorty/snort3/bin", "/home/snorty/snort3/etc"]
    assert traversal_dirs(["/opt/x"]) == ["/opt"]


@pytest.mark.parametrize("bad", ["relative/path", "/a b", "/a;rm -rf /", "/a\nUSER root", "", "/a$(id)"])
def test_unsafe_paths_never_reach_the_dockerfile(bad):
    with pytest.raises(ValueError, match="unsafe path"):
        dockerfile(BASE, [bad])


@pytest.mark.parametrize("bad", ["", "x y", "img\nRUN evil", "img;evil", "-flag", "img$(id)"])
def test_unsafe_image_references_are_refused(bad):
    with pytest.raises(ValueError, match="unsafe image"):
        dockerfile(bad, PATHS)


def test_dockerfile_only_adds_search_permission():
    text = dockerfile(BASE, PATHS)
    assert text.splitlines() == [f"FROM {BASE}", "USER root",
                                 "RUN chmod o+x /home /home/snorty /home/snorty/snort3 /home/snorty/snort3/bin /home/snorty/snort3/etc"]
    assert "COPY" not in text and "ADD" not in text and "curl" not in text


def test_tag_is_deterministic_and_changes_with_base_or_content():
    t1 = derived_tag(BASE, dockerfile(BASE, PATHS))
    assert t1 == derived_tag(BASE, dockerfile(BASE, PATHS)) and t1.startswith("detection-workbench/snort3:f15f714fd61a-")
    assert t1 != derived_tag(BASE, dockerfile(BASE, PATHS + ["/home/other/x"]))
    other = BASE.replace("f15f714fd61a", "0123456789ab")
    assert derived_tag(other, dockerfile(other, PATHS)) != t1
    local = derived_tag("myreg/snort:3.12", dockerfile("myreg/snort:3.12", PATHS))
    assert local.startswith("detection-workbench/snort3:local-myreg-snort-3.12-") and " " not in local


def fake_docker(monkeypatch, exists, build_rc=0):
    calls = []

    def run(argv, **kw):
        calls.append((argv, kw))
        if argv[1:3] == ["image", "inspect"]:
            return subprocess.CompletedProcess(argv, 0 if exists else 1, "", "")
        return subprocess.CompletedProcess(argv, build_rc, "", "boom: build failed\nsecond line")

    monkeypatch.setattr(image_mod.subprocess, "run", run)
    monkeypatch.setattr(image_mod.shutil, "which", lambda n: "/opt/homebrew/bin/docker")
    return calls


def test_ensure_image_skips_the_build_when_present(monkeypatch):
    calls = fake_docker(monkeypatch, exists=True)
    tag = ensure_image(BASE, PATHS)
    assert [c[0][1] for c in calls] == ["image"] and calls[0][0][0] == "/opt/homebrew/bin/docker" and tag.startswith("detection-workbench/")


def test_ensure_image_builds_with_the_dockerfile_on_stdin(monkeypatch):
    calls = fake_docker(monkeypatch, exists=False)
    tag = ensure_image(BASE, PATHS)
    argv, kw = calls[1]
    assert argv[1:3] == ["build", "--quiet"] and argv[3:5] == ["--network", "none"] and argv[-1] == "-" and tag in argv
    assert kw["input"] == dockerfile(BASE, PATHS)


def test_ensure_image_reports_the_first_line_of_a_build_failure(monkeypatch):
    fake_docker(monkeypatch, exists=False, build_rc=1)
    with pytest.raises(RuntimeError, match="docker build failed: boom: build failed$"):
        ensure_image(BASE, PATHS)


# ---- the Docker CLI is found on the server's PATH, not the engine's minimal one ---------------------
def ctx_for(tmp_path, image=""):
    for d in ("cfg", "out"):
        (tmp_path / d).mkdir(exist_ok=True)
    return RunContext(run_dir=tmp_path, backend="docker", cfg=Config(), etc_dir="/x", name="dw-t", image=image)


def test_docker_argv_uses_the_resolved_cli_and_the_derived_image(tmp_path, monkeypatch):
    monkeypatch.setattr(runner_mod.shutil, "which", lambda n: "/opt/homebrew/bin/docker")
    plain = docker_argv(ctx_for(tmp_path), ["-V"])
    assert plain[0] == "/opt/homebrew/bin/docker" and BASE in plain  # no derived image prepared: the pinned one
    derived = docker_argv(ctx_for(tmp_path, image="detection-workbench/snort3:abc"), ["-V"])
    assert "detection-workbench/snort3:abc" in derived and BASE not in derived


def test_docker_bin_falls_back_to_the_bare_name(monkeypatch):
    monkeypatch.setattr(runner_mod.shutil, "which", lambda n: None)
    assert docker_bin() == "docker"


def test_docker_runs_get_the_cli_directory_on_their_path(tmp_path, monkeypatch):
    seen = {}

    class FakePopen:
        def __init__(self, argv, **kw):
            seen["env"] = kw["env"]
            self.returncode, self.pid = 0, 1

        def wait(self, timeout=None):
            return 0

    monkeypatch.setattr(runner_mod.shutil, "which", lambda n: "/opt/homebrew/bin/docker")
    monkeypatch.setattr(runner_mod.subprocess, "Popen", FakePopen)
    ctx = ctx_for(tmp_path)
    execute(["/opt/homebrew/bin/docker", "run"], ctx, 5)
    assert seen["env"]["PATH"].split(":")[0] == "/opt/homebrew/bin" and "/usr/bin" in seen["env"]["PATH"]
    ctx.backend = "native"
    execute(["snort"], ctx, 5)
    assert not seen["env"]["PATH"].startswith("/opt/homebrew")  # native engines keep the minimal PATH


def test_config_still_defaults_to_the_pinned_base_image():
    assert Config().snort.docker_image == BASE and SnortConfig().docker_binary.endswith("/bin/snort")
    assert Path(SnortConfig().docker_etc).is_absolute()
