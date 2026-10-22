"""Engine runner: argument lists only, bounded time and output, native or Docker backend."""
from __future__ import annotations

import contextlib
import os
import re
import resource
import signal
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path

from ..config import Config
from ..safety.paths import PathError

_ENV = {"PATH": "/usr/local/bin:/usr/bin:/bin", "TZ": "UTC", "LC_ALL": "C"}
MAX_OUTPUT_BYTES = 256 * 1024**2  # per-file cap on captured stdout/stderr


class RunnerError(RuntimeError):
    pass


_UNSAFE_MOUNT_CHARS = re.compile(r'[:,"\x00-\x1f\x7f]')


def _check_mount_path(p: Path) -> str:
    """A host path becomes part of `-v host:target:mode`; ':' and ',' would change how Docker parses it."""
    text = str(p)
    if _UNSAFE_MOUNT_CHARS.search(text):
        raise PathError(f"{text!r} contains a character (one of  : , \" or a control character) that cannot be "
                        "mounted safely into the Docker backend; rename or move the file")
    return text


@dataclass
class RawRun:
    argv: list[str]
    exit_code: int | None
    timed_out: bool
    duration_s: float
    stdout: Path
    stderr: Path
    backend: str


def read_capped(path: Path, limit: int = 8 * 1024**2) -> str:
    """The first `limit` bytes of a captured stream as text. Engine output is capped on disk, but parsing a 256 MB
    stream into memory would still be wasteful, and diagnostics of interest come first."""
    try:
        with path.open("rb") as f:
            return f.read(limit).decode("utf-8", "replace")
    except OSError:
        return ""


def excerpt(path: Path, lines: int, max_bytes: int = 2048) -> str:
    """Short tail of a captured stream; never the whole thing."""
    try:
        with path.open("rb") as f:
            f.seek(0, os.SEEK_END)
            f.seek(max(0, f.tell() - 64 * 1024))
            text = f.read().decode("utf-8", "replace")
    except OSError:
        return ""
    tail = "\n".join(text.splitlines()[-lines:])
    return tail[-max_bytes:]


@dataclass
class RunContext:
    """Where a run lives and how host paths appear to the engine (native: same; Docker: mounts)."""
    run_dir: Path
    backend: str  # native | docker
    cfg: Config
    etc_dir: str  # directory holding snort_defaults.lua, as the engine sees it
    name: str = ""
    _inputs: list[tuple[Path, str]] = field(default_factory=list)

    @property
    def cfg_dir(self) -> Path:
        return self.run_dir / "cfg"

    @property
    def out_dir(self) -> Path:
        return self.run_dir / "out"

    def cfg_arg(self, name: str) -> str:
        return str(self.cfg_dir / name) if self.backend == "native" else f"/cfg/{name}"

    def out_arg(self, name: str = "") -> str:
        base = str(self.out_dir) if self.backend == "native" else "/out"
        return f"{base}/{name}" if name else base

    def input_arg(self, host: Path) -> str:
        """Path for a read-only input (evidence or rules). In Docker each gets its own :ro mount."""
        host = Path(host)
        if self.backend == "native":
            return str(host)
        for h, target in self._inputs:
            if h == host:
                return target
        if self.backend == "docker":
            _check_mount_path(host)
        safe_name = re.sub(r"[^A-Za-z0-9._-]", "_", host.name)[:100] or "input"
        target = f"/in/{len(self._inputs)}/{safe_name}"
        self._inputs.append((host, target))
        return target


def docker_argv(ctx: RunContext, binary_argv: list[str], binary: str | None = None) -> list[str]:
    s = ctx.cfg.snort
    uid, gid = os.getuid(), os.getgid()
    if uid == 0:
        raise RunnerError("refusing to run the Docker backend as root")
    cmd = ["docker", "run", "--rm", "--name", ctx.name, "--network", "none", "--cap-drop", "ALL",
           "--security-opt", "no-new-privileges", "--pids-limit", "256", "--memory", "2g",
           "--read-only", "--tmpfs", "/tmp", "-e", "HOME=/tmp", "--user", f"{uid}:{gid}",
           "-v", f"{_check_mount_path(ctx.cfg_dir)}:/cfg:ro", "-v", f"{_check_mount_path(ctx.out_dir)}:/out"]
    for host, target in ctx._inputs:
        cmd += ["-v", f"{_check_mount_path(host)}:{target}:ro"]
    return cmd + ["--entrypoint", binary or s.docker_binary, s.docker_image] + binary_argv


def _limit_files():
    resource.setrlimit(resource.RLIMIT_FSIZE, (MAX_OUTPUT_BYTES * 4, MAX_OUTPUT_BYTES * 4))


def execute(argv: list[str], ctx: RunContext, timeout_s: int) -> RawRun:
    """Run `argv` (already a full command for the backend). Output goes to files in the run dir."""
    if not isinstance(argv, list) or not argv or not all(isinstance(a, str) for a in argv):
        raise RunnerError("argv must be a non-empty list of strings")
    if ctx.backend == "native" and os.geteuid() == 0:
        raise RunnerError("refusing to run engines as root")
    out, err = ctx.run_dir / "stdout.txt", ctx.run_dir / "stderr.txt"
    env = dict(_ENV)
    if ctx.backend == "docker":  # the docker CLI needs its context (HOME / DOCKER_*) to find the daemon
        env.update({k: v for k, v in os.environ.items() if k in ("HOME", "DOCKER_HOST", "DOCKER_CONFIG", "DOCKER_CONTEXT")})
    start, timed_out = time.monotonic(), False
    with out.open("wb") as fo, err.open("wb") as fe:
        proc = subprocess.Popen(argv, shell=False, stdin=subprocess.DEVNULL, stdout=fo, stderr=fe,
                                env=env, start_new_session=True,
                                preexec_fn=_limit_files if ctx.backend == "native" else None)
        try:
            proc.wait(timeout=timeout_s)
        except subprocess.TimeoutExpired:
            timed_out = True
            if ctx.backend == "docker" and ctx.name:
                subprocess.run(["docker", "kill", ctx.name], stdout=subprocess.DEVNULL,
                               stderr=subprocess.DEVNULL, timeout=15, check=False)
            with contextlib.suppress(ProcessLookupError):
                os.killpg(proc.pid, signal.SIGKILL)
            proc.wait()
    for p in (out, err):
        if p.stat().st_size > MAX_OUTPUT_BYTES:
            with p.open("r+b") as f:
                f.truncate(MAX_OUTPUT_BYTES)
    return RawRun(argv=argv, exit_code=None if timed_out else proc.returncode, timed_out=timed_out,
                  duration_s=round(time.monotonic() - start, 3), stdout=out, stderr=err, backend=ctx.backend)
