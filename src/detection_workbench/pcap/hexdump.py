"""Bounded hex + printable-ASCII display."""
from __future__ import annotations


def hexdump(data: bytes, limit: int, width: int = 16, base: int = 0) -> dict:
    shown = data[:max(0, limit)]
    lines = []
    for i in range(0, len(shown), width):
        chunk = shown[i:i + width]
        hx = " ".join(f"{b:02x}" for b in chunk)
        asc = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        lines.append(f"{base + i:08x}  {hx:<{width * 3 - 1}}  |{asc}|")
    return {"lines": lines, "shown": len(shown), "total": len(data), "truncated": max(0, len(data) - len(shown))}
