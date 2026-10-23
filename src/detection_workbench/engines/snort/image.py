"""A small local image derived from the pinned Snort image, so that any host user id can run it.

Containers run as the host user (so the files they write belong to you). The published Snort image keeps its install under
a home directory that only its own user (uid 1000) may enter, so every other uid fails with "permission denied" before
Snort starts. The derived image adds search permission (`chmod o+x`) on the directories leading to the install, and nothing
else. No capability is added to the container and the build needs no network.
"""
from __future__ import annotations

import hashlib
import re
import shutil
import subprocess
from pathlib import PurePosixPath

PREFIX = "detection-workbench/snort3"
_REF = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/:@-]{0,255}$")
_PATH = re.compile(r"^/[A-Za-z0-9._/-]{1,200}$")
BUILD_TIMEOUT_S = 600


def traversal_dirs(paths: list[str]) -> list[str]:
    """Every directory above the given paths (not `/`), shallowest first, without duplicates."""
    seen: dict[str, None] = {}
    for raw in paths:
        if not _PATH.match(raw):
            raise ValueError(f"unsafe path in image configuration: {raw!r}")
        p = PurePosixPath(raw)
        for parent in reversed(p.parents):
            if str(parent) != "/":
                seen.setdefault(str(parent), None)
    return list(seen)


def dockerfile(base: str, paths: list[str]) -> str:
    if not _REF.match(base):
        raise ValueError(f"unsafe image reference: {base!r}")
    dirs = traversal_dirs(paths)
    return f"FROM {base}\nUSER root\nRUN chmod o+x {' '.join(dirs)}\n"  # the run-time --user always overrides USER


def derived_tag(base: str, text: str) -> str:
    """Deterministic: the same base image and Dockerfile always give the same tag, and a change gives a new one."""
    m = re.search(r"@sha256:([0-9a-f]{12})", base)
    ident = m.group(1) if m else "local-" + re.sub(r"[^A-Za-z0-9._-]", "-", base)[-40:]
    return f"{PREFIX}:{ident}-{hashlib.sha256(text.encode()).hexdigest()[:8]}"


def _docker() -> str:
    return shutil.which("docker") or "docker"


def _first_line(text: str, n: int = 200) -> str:
    return next((line.strip() for line in (text or "").splitlines() if line.strip()), "")[:n]


def ensure_image(base: str, paths: list[str]) -> str:
    """Return the tag of the derived image, building it first when it does not exist yet."""
    text = dockerfile(base, paths)
    tag = derived_tag(base, text)
    have = subprocess.run([_docker(), "image", "inspect", tag], capture_output=True, text=True, timeout=30)
    if have.returncode == 0:
        return tag
    built = subprocess.run([_docker(), "build", "--quiet", "--network", "none", "--tag", tag, "-"],
                           input=text, capture_output=True, text=True, timeout=BUILD_TIMEOUT_S)
    if built.returncode:
        raise RuntimeError(f"docker build failed: {_first_line(built.stderr) or 'no error output'}")
    return tag
