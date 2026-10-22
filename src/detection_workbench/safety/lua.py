"""The only way a caller-supplied value may enter generated Lua config.

Every function either returns a Lua literal that is safe to embed or raises LuaValueError.
Nothing here ever builds a command-line `--lua` string; values land in files in the run dir.
"""
from __future__ import annotations

import ipaddress
import re
from pathlib import Path


class LuaValueError(ValueError):
    pass


_PLAIN = re.compile(r"^[A-Za-z0-9_.:/@%+=,!$\[\] -]*$")  # no quotes, backslash, ';', '-' pairs checked below
ALLOWED_VARS = frozenset({"HOME_NET", "EXTERNAL_NET", "HTTP_PORTS", "SSH_PORTS", "FILE_DATA_PORTS",
                          "SIP_PORTS", "ORACLE_PORTS", "GTP_PORTS", "MODBUS_PORTS", "DNP3_PORTS",
                          "CIP_PORTS", "AIM_SERVERS"})
MAX_STR = 512


def lua_str(value) -> str:
    """Quote a plain value as a single-quoted Lua string; reject anything that is not plain."""
    if not isinstance(value, str):
        raise LuaValueError(f"expected a string, got {type(value).__name__}")
    if len(value) > MAX_STR:
        raise LuaValueError("value too long")
    if not value.isascii() or any(ord(c) < 0x20 or ord(c) == 0x7F for c in value):
        raise LuaValueError("value must be printable ASCII without control characters")
    if not _PLAIN.match(value):
        raise LuaValueError("value contains characters that are not allowed in generated config")
    if "--" in value or "[[" in value or "]]" in value or "[=" in value:
        raise LuaValueError("value contains a Lua comment or long-bracket sequence")
    return "'" + value + "'"


def lua_int(value, lo: int, hi: int) -> str:
    if isinstance(value, bool) or not isinstance(value, int):
        raise LuaValueError("expected an integer")
    if not lo <= value <= hi:
        raise LuaValueError(f"integer {value} outside {lo}:{hi}")
    return str(value)


def lua_bool(value) -> str:
    if not isinstance(value, bool):
        raise LuaValueError("expected a boolean")
    return "true" if value else "false"


def lua_enum(value, allowed) -> str:
    if not isinstance(value, str) or value not in allowed:
        raise LuaValueError(f"must be one of {sorted(allowed)}")
    return lua_str(value)


def _net_atom(atom: str) -> str:
    if atom != atom.strip() or not atom:
        raise LuaValueError("whitespace is not allowed in a network entry")
    neg = atom.startswith("!")
    body = atom[1:] if neg else atom
    if body == "any":
        return atom
    if body.startswith("$"):
        if body[1:] not in ALLOWED_VARS:
            raise LuaValueError(f"unknown variable {body}")
        return atom
    try:
        ipaddress.ip_network(body, strict=False)
    except ValueError:
        raise LuaValueError(f"not an IP address or CIDR: {body[:40]!r}") from None
    return atom


def lua_net(value) -> str:
    """HOME_NET-style value: any, $VAR, IP/CIDR, '!' negation, or a bracketed comma list of those."""
    if not isinstance(value, str) or not value or value != value.strip():
        raise LuaValueError("expected a network string without surrounding whitespace")
    v = value
    if v.startswith("[") and v.endswith("]"):
        inner = v[1:-1]
        if "[" in inner or "]" in inner or not inner.strip():
            raise LuaValueError("nested or empty network list")
        atoms = [_net_atom(a) for a in inner.split(",")]
        return lua_str("[" + ",".join(atoms) + "]")
    return lua_str(_net_atom(v))


def lua_port(value) -> str:
    return lua_int(value, 0, 65535)


def lua_path(value, within: Path) -> str:
    """A path that must resolve inside `within` (the run directory)."""
    p = Path(value).resolve()
    w = Path(within).resolve()
    if p != w and w not in p.parents:
        raise LuaValueError(f"path {p} is outside the run directory")
    return lua_str(str(p))


def lua_ident(value) -> str:
    if not isinstance(value, str) or not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{0,63}", value):
        raise LuaValueError("expected a plain identifier")
    return value
