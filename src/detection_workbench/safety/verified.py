"""Read evidence so that the bytes analysed are exactly the bytes that were checked.

Checking a file and then handing its path to another program leaves a window in which the file can be swapped.
These helpers open the file once (never following a symlink in the final component), confirm on the open
descriptor that it is a regular file inside the allowed roots, and hash the very bytes they copy or return. The
caller then works from that copy, so nothing can change between the check and the use.
"""
from __future__ import annotations

import hashlib
import os
import stat
from pathlib import Path

from .paths import PathError, _under

CHUNK = 1 << 20


class EvidenceChanged(PathError):
    """The file's content no longer matches the hash recorded when it was registered."""


def _fd_path(fd: int) -> Path | None:
    """Where an open descriptor really lives, or None when the platform cannot say."""
    try:
        if os.path.isdir("/proc/self/fd"):
            return Path(os.readlink(f"/proc/self/fd/{fd}"))
        import fcntl  # macOS
        get_path = getattr(fcntl, "F_GETPATH", None)
        if get_path is not None:
            return Path(fcntl.fcntl(fd, get_path, b"\0" * 1024).split(b"\0", 1)[0].decode())
    except (OSError, ValueError):
        pass
    return None


def _open_checked(path: str | os.PathLike, roots: list[Path], max_bytes: int) -> int:
    flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | getattr(os, "O_CLOEXEC", 0)
    try:
        fd = os.open(path, flags)
    except OSError as e:
        raise PathError(f"cannot open evidence {Path(path).name!r}: {e.strerror} "
                        "(symlinks are not followed)") from None
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            raise PathError(f"{Path(path).name!r} is not a regular file")
        if st.st_size > max_bytes:
            raise PathError(f"{Path(path).name!r} is larger than the {max_bytes}-byte input cap")
        real = _fd_path(fd)
        if real is not None and not _under(real.resolve(), [Path(r).resolve() for r in roots]):
            raise PathError(f"{real} is outside allowed_roots")
        return fd
    except BaseException:
        os.close(fd)
        raise


def _stream(fd: int, expected_sha256: str, max_bytes: int, sink, name: str) -> int:
    h, total = hashlib.sha256(), 0
    with os.fdopen(fd, "rb", closefd=True) as f:
        for chunk in iter(lambda: f.read(CHUNK), b""):
            total += len(chunk)
            if total > max_bytes:
                raise PathError(f"{name!r} grew past the {max_bytes}-byte input cap while being read")
            h.update(chunk)
            sink(chunk)
    if h.hexdigest() != expected_sha256:
        raise EvidenceChanged(f"evidence {name!r} changed since it was registered (hash mismatch); "
                              "register it again if the change is intended")
    return total


def copy_verified(src: str | os.PathLike, dest: Path, expected_sha256: str, roots: list[Path], max_bytes: int) -> int:
    """Copy `src` to `dest` (new file, mode 0600), verifying it against `expected_sha256` as it is read.
    On any failure `dest` is removed. Returns the size in bytes."""
    fd = _open_checked(src, roots, max_bytes)
    dest = Path(dest)
    dest.parent.mkdir(parents=True, exist_ok=True)
    out = os.open(dest, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0), 0o600)
    try:
        with os.fdopen(out, "wb", closefd=True) as w:
            return _stream(fd, expected_sha256, max_bytes, w.write, Path(src).name)
    except BaseException:
        dest.unlink(missing_ok=True)
        raise


def read_verified(src: str | os.PathLike, expected_sha256: str, roots: list[Path], max_bytes: int) -> bytes:
    """Return the verified content of a (small) file, e.g. a rules file."""
    fd = _open_checked(src, roots, max_bytes)
    parts: list[bytes] = []
    _stream(fd, expected_sha256, max_bytes, parts.append, Path(src).name)
    return b"".join(parts)


def read_checked(src: str | os.PathLike, roots: list[Path], max_bytes: int) -> bytes:
    """Read a file's content with the same open-time checks as the verified readers, but without a hash
    (for files that are not registered evidence, such as an existing rules file about to be diffed)."""
    fd = _open_checked(src, roots, max_bytes)
    with os.fdopen(fd, "rb") as f:
        return f.read(max_bytes)


def fingerprint(src: str | os.PathLike, roots: list[Path], max_bytes: int, head_bytes: int = 65536) -> tuple[str, int, bytes]:
    """(sha256, size, first bytes) of a file read once through the checked open, for registering evidence."""
    fd = _open_checked(src, roots, max_bytes)
    h, total, head = hashlib.sha256(), 0, b""
    with os.fdopen(fd, "rb") as f:
        for chunk in iter(lambda: f.read(CHUNK), b""):
            total += len(chunk)
            if total > max_bytes:
                raise PathError(f"{Path(src).name!r} grew past the {max_bytes}-byte input cap while being read")
            if len(head) < head_bytes:
                head += chunk[: head_bytes - len(head)]
            h.update(chunk)
    return h.hexdigest(), total, head

