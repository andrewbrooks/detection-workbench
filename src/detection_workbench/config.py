"""Workbench configuration: TOML file with defaults, validated on load."""
from __future__ import annotations

import os
import tomllib
from dataclasses import dataclass, field
from pathlib import Path

DEFAULT_HOME = Path("~/.detection-workbench").expanduser()
DEFAULT_IMAGE = "ciscotalos/snort3@sha256:f15f714fd61ade114b1039687dd43352cae26cd6401b89f2b03404e0d21e322f"


class ConfigError(ValueError):
    pass


@dataclass(frozen=True)
class Limits:
    timeout_s: int = 120
    max_input_bytes: int = 2 * 1024**3
    max_rules_bytes: int = 50 * 1024**2
    max_alerts_returned: int = 200
    max_alerts_parsed: int = 250_000
    alert_json_limit_mb: int = 512
    payload_display_bytes: int = 512
    error_excerpt_lines: int = 20


@dataclass(frozen=True)
class SnortConfig:
    backend: str = "auto"  # auto | native | docker
    binary: str = "snort"
    defaults_lua: str | None = None
    docker_image: str = DEFAULT_IMAGE
    docker_binary: str = "/home/snorty/snort3/bin/snort"
    docker_etc: str = "/home/snorty/snort3/etc/snort"


@dataclass(frozen=True)
class Config:
    case_dir: Path = DEFAULT_HOME / "cases"
    allowed_roots: tuple[Path, ...] = ()
    limits: Limits = field(default_factory=Limits)
    snort: SnortConfig = field(default_factory=SnortConfig)


def _section(cls, raw: dict, name: str):
    unknown = set(raw) - set(cls.__dataclass_fields__)
    if unknown:
        raise ConfigError(f"unknown key(s) in [{name}]: {sorted(unknown)}")
    return cls(**raw)


def parse_config(raw: dict) -> Config:
    raw = dict(raw)
    limits = _section(Limits, raw.pop("limits", {}), "limits")
    snort = _section(SnortConfig, raw.pop("snort", {}), "snort")
    if snort.backend not in ("auto", "native", "docker"):
        raise ConfigError("snort.backend must be auto, native or docker")
    for k, v in vars(limits).items():
        if not isinstance(v, int) or v <= 0:
            raise ConfigError(f"limits.{k} must be a positive integer")
    case_dir = Path(raw.pop("case_dir", DEFAULT_HOME / "cases")).expanduser().resolve()
    roots = tuple(Path(p).expanduser().resolve() for p in raw.pop("allowed_roots", []))
    if any(r == Path(r.anchor) for r in roots):
        raise ConfigError("allowed_roots must not include the filesystem root; list the directories that hold your evidence")
    if raw:
        raise ConfigError(f"unknown top-level key(s): {sorted(raw)}")
    return Config(case_dir=case_dir, allowed_roots=roots, limits=limits, snort=snort)


def load_config(path: str | os.PathLike | None = None) -> Config:
    explicit = path or os.environ.get("DW_CONFIG")
    p = Path(explicit or DEFAULT_HOME / "config.toml").expanduser()
    if not p.exists():
        if explicit:  # a file you named must exist; only the default location is optional
            raise ConfigError(f"config file not found: {p}")
        return Config()
    with p.open("rb") as f:
        return parse_config(tomllib.load(f))
