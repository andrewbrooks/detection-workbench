"""Snort 3 engine plugin: validate and run against a pcap, native or Docker."""
from __future__ import annotations

import hashlib
import json
import re
import shutil
import subprocess
import time
from pathlib import Path

from ...config import Config
from ...pcap.flows import analyze_streams
from ...runner.runner import RawRun, RunContext, docker_argv, excerpt, execute, read_capped
from ...safety.argv import assert_safe_snort_argv
from ..base import EngineResult, EngineVersion, register
from .config_gen import generate_config
from .lint import lint_rules
from .parse_alerts import parse_alert_file
from .parse_profile import parse_profile
from .parse_validate import ValidationReport, parse_validation
from .rules import parse_rules

_VERSION = re.compile(r"Version\s+(\d+(?:\.\d+)+)")
_ETC_CANDIDATES = ("/usr/local/etc/snort", "/opt/homebrew/etc/snort", "/etc/snort", "/usr/etc/snort")
MAX_RECHECKS = 20
RECHECK_UNAVAILABLE_AFTER_S = 30  # a missing Snort is looked for again after this long (e.g. once the image is pulled)
PROFILE_READ_BYTES = 32 * 1024**2
CAVEAT = ("Snort 3.10 does not run service inspectors on TCP data its peer never ACKed, so rules on service "
          "buffers (http_uri and similar) can miss on these flows while raw-packet rules still fire.")


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


class SnortEngine:
    name = "snort"
    evidence_types = {"pcap", "pcapng"}

    def __init__(self, cfg: Config):
        self.cfg = cfg
        self._backend: str | None = None
        self._version: EngineVersion | None = None
        self._checked = 0.0

    # ---- backend discovery -------------------------------------------------
    def _native_version(self) -> str | None:
        exe = shutil.which(self.cfg.snort.binary)
        if not exe:
            return None
        try:
            r = subprocess.run([exe, "-V"], capture_output=True, text=True, timeout=20,
                               env={"PATH": "/usr/local/bin:/usr/bin:/bin", "LC_ALL": "C"})
        except (OSError, subprocess.TimeoutExpired):
            return None
        m = _VERSION.search(r.stdout + r.stderr)
        return m.group(1) if m else None

    @staticmethod
    def _first_line(text: str, n: int = 160) -> str:
        line = (text or "").strip().splitlines()[0] if (text or "").strip() else ""
        return line[:n]

    def _docker_version(self) -> tuple[str | None, str]:
        s = self.cfg.snort
        if not shutil.which("docker"):
            return None, "docker is not installed"
        try:
            have = subprocess.run(["docker", "image", "inspect", s.docker_image], capture_output=True, text=True, timeout=30)
        except (OSError, subprocess.TimeoutExpired):
            return None, "docker did not respond within 30 seconds"
        if have.returncode:
            err = have.stderr.lower()
            if any(k in err for k in ("daemon", "cannot connect", "permission denied", "is the docker")):
                return None, f"Docker is installed but not usable: {self._first_line(have.stderr)}"
            return None, f"image not present; run: docker pull {s.docker_image}"
        try:
            r = subprocess.run(["docker", "run", "--rm", "--network", "none", "--entrypoint", s.docker_binary,
                                s.docker_image, "-V"], capture_output=True, text=True, timeout=60)
        except (OSError, subprocess.TimeoutExpired):
            return None, "docker did not respond within 60 seconds"
        m = _VERSION.search(r.stdout + r.stderr)
        return (m.group(1), "") if m else (None, "could not read Snort version from the image")

    def version(self) -> EngineVersion:
        """Detected once and cached. A failed detection is retried after RECHECK_UNAVAILABLE_AFTER_S, so pulling the
        image or installing Snort does not require restarting the server."""
        if self._version and (self._version.available or time.monotonic() - self._checked < RECHECK_UNAVAILABLE_AFTER_S):
            return self._version
        self._version, self._checked = self._probe(), time.monotonic()
        return self._version

    def _probe(self) -> EngineVersion:
        want, detail = self.cfg.snort.backend, ""
        self._backend = None
        if want in ("auto", "native"):
            v = self._native_version()
            if v and v.startswith("3."):
                self._backend = "native"
                return EngineVersion("snort", v, "native", True)
            detail = "no native Snort 3 on PATH" if not v else f"native Snort is {v}, need 3.x"
            if want == "native":
                return EngineVersion("snort", v, None, False, detail)
        v, d = self._docker_version()
        if v:
            self._backend = "docker"
            return EngineVersion("snort", v, "docker", True, detail)
        return EngineVersion("snort", None, None, False, f"{detail}; {d}".strip("; "))

    def _require(self) -> str:
        v = self.version()
        if not v.available:
            raise RuntimeError(f"Snort is not available: {v.detail}")
        return self._backend  # type: ignore[return-value]

    def _etc_dir(self, backend: str) -> str:
        s = self.cfg.snort
        if backend == "docker":
            return s.docker_etc
        if s.defaults_lua:
            return str(Path(s.defaults_lua).expanduser().parent)
        exe = shutil.which(s.binary)
        cands = [str(Path(exe).resolve().parent.parent / "etc" / "snort")] if exe else []
        for c in cands + list(_ETC_CANDIDATES):
            if (Path(c) / "snort_defaults.lua").is_file():
                return c
        raise RuntimeError("could not find snort_defaults.lua; set [snort].defaults_lua in config.toml")

    def make_context(self, run_dir: Path, run_id: str, case_id: str) -> RunContext:
        backend = self._require()
        name = re.sub(r"[^a-zA-Z0-9_.-]", "-", f"dw-{case_id}-{run_id}")[:100]
        return RunContext(run_dir=run_dir, backend=backend, cfg=self.cfg, etc_dir=self._etc_dir(backend), name=name)

    def status(self) -> dict:
        v = self.version()
        out = {"engine": "snort", "available": v.available, "version": v.version, "backend": v.backend,
               "configured_backend": self.cfg.snort.backend, "detail": v.detail,
               "docker_image": self.cfg.snort.docker_image, "snort2lua": self.has_snort2lua()}
        if v.available:
            try:
                out["config_dir"] = self._etc_dir(v.backend)
            except RuntimeError as e:
                out["config_dir"] = None
                out["detail"] = str(e)
        return out

    def has_snort2lua(self) -> bool:
        if self.version().backend == "docker":
            return True  # shipped in the pinned image (docs/notes.md A7)
        exe = shutil.which(self.cfg.snort.binary)
        return bool(exe and (Path(exe).parent / "snort2lua").exists() or shutil.which("snort2lua"))

    # ---- command construction ---------------------------------------------------
    def _command(self, ctx: RunContext, args: list[str]) -> list[str]:
        """`args` are Snort arguments (no binary). Gate first, then wrap for the backend."""
        assert_safe_snort_argv(["snort"] + args)
        if ctx.backend == "native":
            exe = shutil.which(self.cfg.snort.binary)
            if not exe:
                raise RuntimeError("snort disappeared from PATH")
            return [exe] + args
        return docker_argv(ctx, args)

    def _write_inputs(self, ctx: RunContext, rules_text: str, rules_name: str, config_name: str, config_text: str):
        ctx.cfg_dir.mkdir(parents=True, exist_ok=True)
        (ctx.cfg_dir / rules_name).write_text(rules_text)
        (ctx.cfg_dir / config_name).write_text(config_text)

    def _fail_excerpt(self, raw: RawRun) -> str:
        n = self.cfg.limits.error_excerpt_lines
        return excerpt(raw.stderr, n) or excerpt(raw.stdout, n)

    # ---- validate -------------------------------------------------------------------
    def _validate_once(self, ctx: RunContext, rules_name: str, label: str) -> tuple[RawRun, list[str]]:
        args = ["-c", ctx.cfg_arg("validate.lua"), "-R", ctx.cfg_arg(rules_name), "-T", "--warn-all"]
        base_name = ctx.name
        ctx.name = f"{base_name}{label}"  # a distinct container name per process, so a timeout kills the right one
        try:
            argv = self._command(ctx, args)
            raw = execute(argv, ctx, min(self.cfg.limits.timeout_s, 60))
        finally:
            ctx.name = base_name
        return raw, argv

    def validate(self, ctx: RunContext, rules_text: str, rules_name: str = "rules.rules") -> EngineResult:
        if len(rules_text.encode()) > self.cfg.limits.max_rules_bytes:
            raise ValueError("rule set is larger than the configured max_rules_bytes")
        cfg_text = generate_config(etc_dir=ctx.etc_dir, alert_file=False)
        self._write_inputs(ctx, rules_text, "rules.rules", "validate.lua", cfg_text)
        raw, argv = self._validate_once(ctx, "rules.rules", "")
        base = EngineResult(status="ok", argv=argv, raw=raw,
                            rules={"source": "validate", "sha256": _sha(rules_text.encode()), "path": "cfg/rules.rules"},
                            config={"sha256": _sha(cfg_text.encode()), "path": "cfg/validate.lua", "options": {}})
        if raw.timed_out:
            base.status, base.error_excerpt = "timeout", "validation timed out"
            return base
        text = read_capped(raw.stdout) + "\n" + read_capped(raw.stderr)
        rep = parse_validation(text, raw.exit_code or 0, rules_text, "rules.rules")
        rechecked: list[int] = []
        incomplete = False
        if rep.needs_individual_check:
            rep, rechecked, extra, incomplete = self._recheck_cascade(ctx, rep, rules_text)
            base.extra_argv = extra
        lint = lint_rules(rules_text)
        if raw.exit_code not in (0, 1) and not rep.errors:
            base.status = "error"
            base.error_excerpt = self._fail_excerpt(raw)
        errors = sorted(rep.errors, key=lambda e: (e["line"] or 0))
        lint_errors = [d for d in lint if d["severity"] == "error"]
        ok = rep.ok and not lint_errors if raw.exit_code in (0, 1) else False
        base.payload = {
            "ok": ok, "snort_ok": rep.ok, "errors": errors, "warnings": rep.warnings,
            "lint": lint, "rechecked_individually": rechecked, "recheck_incomplete": incomplete,
            "rules_checked": len(parse_rules(rules_text)),
        }
        base.totals = {"errors": len(errors) + len(lint_errors), "warnings": len(rep.warnings)}
        (ctx.run_dir / "results").mkdir(exist_ok=True)
        (ctx.run_dir / "results" / "summary.json").write_text(json.dumps(base.payload, indent=2) + "\n")
        base.results = {"summary": "results/summary.json"}
        return base

    def _recheck_cascade(self, ctx: RunContext, rep: ValidationReport, rules_text: str):
        """A missing ';' makes Snort misreport the next rule too. Validate the suspect rules singly."""
        by_line = {r.line: r for r in parse_rules(rules_text)}
        flagged = set(rep.needs_individual_check)
        todo = sorted(l for l in (flagged | {l + 1 for l in flagged}) if l in by_line)[:MAX_RECHECKS]
        deadline = time.monotonic() + self.cfg.limits.timeout_s  # one budget for all the single-rule checks together
        done, new_errors, new_warnings, extra = [], [], [], []
        for n, line in enumerate(todo, start=1):
            if time.monotonic() > deadline:
                break
            done.append(line)
            (ctx.cfg_dir / "single.rules").write_text(by_line[line].text + "\n")
            raw, argv = self._validate_once(ctx, "single.rules", f"-c{n}")
            extra.append(argv)
            text = read_capped(raw.stdout) + "\n" + read_capped(raw.stderr)
            one = parse_validation(text, raw.exit_code or 0, by_line[line].text, "single.rules")
            for e in one.errors:
                new_errors.append({**e, "line": line, "rule": by_line[line].text[:300], "sid": e["sid"] or by_line[line].sid})
            for w in one.warnings:
                new_warnings.append({**w, "line": line, "sid": w["sid"] or by_line[line].sid})
        done_set = set(done)
        keep_e = [e for e in rep.errors if e["line"] not in done_set]
        keep_w = [w for w in rep.warnings if w["line"] not in done_set]
        out = ValidationReport(ok=not (keep_e or new_errors), errors=keep_e + new_errors,
                               warnings=keep_w + new_warnings, summary_warnings=rep.summary_warnings)
        return out, done, extra, len(done) < len(todo)

    # ---- snort2lua ---------------------------------------------------------------------
    def convert(self, ctx: RunContext, source: Path) -> EngineResult:
        """Convert a Snort 2 rules file or snort.conf with the snort2lua that ships with Snort 3.

        `-i` is always passed: a config's `include` lines are not followed, so conversion can never make the tool
        open files other than the one registered (relevant for a native snort2lua, which sees the whole host).
        Convert each rules file you want separately."""
        if not self.has_snort2lua():
            raise RuntimeError("snort2lua is not available with this Snort install")
        args = ["-i", "-c", ctx.input_arg(source), "-r", ctx.out_arg("converted.rules"),
                "-o", ctx.out_arg("converted.lua"), "-e", ctx.out_arg("convert_errors.txt")]
        if ctx.backend == "native":
            exe = shutil.which("snort2lua") or str(Path(shutil.which(self.cfg.snort.binary)).parent / "snort2lua")
            argv = [exe] + args
        else:
            argv = docker_argv(ctx, args, binary=str(Path(self.cfg.snort.docker_binary).parent / "snort2lua"))
        raw = execute(argv, ctx, self.cfg.limits.timeout_s)
        res = EngineResult(status="ok", argv=argv, raw=raw)
        if raw.timed_out:
            res.status, res.error_excerpt = "timeout", f"timed out after {self.cfg.limits.timeout_s}s"
        elif raw.exit_code != 0:
            produced = (ctx.out_dir / "converted.rules").exists() or (ctx.out_dir / "converted.lua").exists()
            excerpt_text = self._fail_excerpt(raw)
            # snort2lua exits non-zero when some lines could not be converted (such as skipped includes) but still
            # writes what it could; that is a partial result with notes, not a failure.
            res.status = "partial" if produced and "occurred while converting" in excerpt_text else "error"
            res.error_excerpt = excerpt_text
        return res

    # ---- run ---------------------------------------------------------------------------
    def run(self, ctx: RunContext, pcap: Path, rules_text: str, options: dict) -> EngineResult:
        lim = self.cfg.limits
        if len(rules_text.encode()) > lim.max_rules_bytes:
            raise ValueError("rule set is larger than the configured max_rules_bytes")
        opts = {"home_net": options.get("home_net"), "external_net": options.get("external_net"),
                "flush_one_sided": bool(options.get("flush_one_sided")), "profile": bool(options.get("profile")),
                "filters": options.get("filters") or []}
        cfg_text = generate_config(etc_dir=ctx.etc_dir, home_net=opts["home_net"], external_net=opts["external_net"],
                                   alert_limit_mb=lim.alert_json_limit_mb, profile=opts["profile"],
                                   flush_one_sided=opts["flush_one_sided"], filters=opts["filters"])
        self._write_inputs(ctx, rules_text, "rules.rules", "snort.lua", cfg_text)
        args = ["-q", "-c", ctx.cfg_arg("snort.lua"), "-R", ctx.cfg_arg("rules.rules"),
                "-r", ctx.input_arg(pcap), "--daq", "pcap", "--daq-mode", "read-file",
                "-A", "alert_json", "-l", ctx.out_arg(), "-z", "1"]
        argv = self._command(ctx, args)
        raw = execute(argv, ctx, lim.timeout_s)
        res = EngineResult(
            status="ok", argv=argv, raw=raw,
            rules={"source": "run", "sha256": _sha(rules_text.encode()), "path": "cfg/rules.rules"},
            config={"sha256": _sha(cfg_text.encode()), "path": "cfg/snort.lua", "options": opts})
        if raw.timed_out:
            res.status, res.error_excerpt = "timeout", f"timed out after {lim.timeout_s}s"
            return res
        if raw.exit_code != 0:
            res.status, res.error_excerpt = "error", self._fail_excerpt(raw)
            return res
        results = ctx.run_dir / "results"
        results.mkdir(exist_ok=True)
        summary = parse_alert_file(ctx.out_dir / "alert_json.txt", results / "alerts.jsonl", lim.max_alerts_parsed)
        caveats = analyze_streams(pcap)
        caveats["explanation"] = CAVEAT if caveats["unacked_flows"] else None
        summary["stream_caveats"] = caveats
        res.results = {"summary": "results/summary.json", "alerts": "results/alerts.jsonl"}
        if opts["profile"]:
            prof = parse_profile(read_capped(raw.stdout, PROFILE_READ_BYTES), rules_text)
            (results / "profile.json").write_text(json.dumps(prof, indent=2) + "\n")
            res.results["profile"] = "results/profile.json"
            summary["profile_rows"] = len(prof["rules"])
        (results / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
        res.totals = {"alerts": summary["total"], "truncated": summary["truncated"],
                      "by_sid_top": [{"sid": r["sid"], "count": r["count"]} for r in summary["by_sid"][:10]]}
        res.payload = summary
        return res


def make_engine(cfg: Config) -> SnortEngine:
    e = SnortEngine(cfg)
    register(e)
    return e
