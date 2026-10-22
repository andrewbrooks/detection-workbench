"""Path control: reads only from allowed roots, writes only where told, never to evidence."""
from __future__ import annotations

import os
import stat
from pathlib import Path


class PathError(ValueError):
    pass


def _under(path: Path, roots) -> bool:
    return any(path == r or r in path.parents for r in roots)


def resolve_read(path: str | os.PathLike, roots: list[Path], max_bytes: int | None = None) -> Path:
    """Resolve symlinks first, then require a regular file under one of `roots`."""
    if "\0" in str(path):
        raise PathError("path contains a NUL byte")
    try:
        p = Path(path).expanduser().resolve(strict=True)
    except (FileNotFoundError, RuntimeError, OSError) as e:
        raise PathError(f"cannot read {path}: {type(e).__name__}") from None
    roots = [Path(r).resolve() for r in roots]
    if not _under(p, roots):
        raise PathError(f"{p} is outside allowed_roots; add its directory to allowed_roots in config.toml")
    mode = os.stat(p).st_mode
    if not stat.S_ISREG(mode):
        raise PathError(f"{p} is not a regular file (devices, FIFOs, sockets and directories are refused)")
    if max_bytes is not None and p.stat().st_size > max_bytes:
        raise PathError(f"{p} is larger than the {max_bytes}-byte input cap")
    return p


def resolve_write(path: str | os.PathLike, roots: list[Path], overwrite: bool = False,
                  protected: set[Path] | None = None) -> Path:
    """Vet a user-named output path. Existing files are only replaced when `overwrite` is set,
    and never when they are registered evidence (`protected`)."""
    if "\0" in str(path):
        raise PathError("path contains a NUL byte")
    raw = Path(path).expanduser()
    if raw.is_symlink():
        raise PathError(f"{raw} is a symlink; name the real path")
    try:
        parent = raw.parent.resolve(strict=True)
    except (FileNotFoundError, OSError):
        raise PathError(f"directory {raw.parent} does not exist") from None
    target = parent / raw.name
    if not _under(target, [Path(r).resolve() for r in roots]):
        raise PathError(f"{target} is outside allowed_roots and the case directory")
    if raw.name in ("", ".", ".."):
        raise PathError("no file name given")
    if target.exists():
        if not stat.S_ISREG(os.stat(target).st_mode):
            raise PathError(f"{target} exists and is not a regular file")
        if protected and target.resolve() in protected:
            raise PathError(f"{target} is registered evidence and is never overwritten")
        if not overwrite:
            raise PathError(f"{target} already exists; pass overwrite=true or choose a new name")
    return target


def write_text_safely(target: Path, text: str, overwrite: bool = False) -> None:
    """Write a text file without following a symlink placed at `target` after it was vetted.

    New files are created exclusively; with `overwrite` an existing regular file is truncated in place."""
    flags = os.O_WRONLY | os.O_CREAT | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0) | (os.O_TRUNC if overwrite else os.O_EXCL)
    try:
        fd = os.open(target, flags, 0o666)  # the umask decides the final mode
    except FileExistsError:
        raise
    except OSError as e:
        raise PathError(f"cannot write {Path(target).name!r}: {e.strerror} (symlinks are not followed)") from None
    with os.fdopen(fd, "w") as f:
        f.write(text)

