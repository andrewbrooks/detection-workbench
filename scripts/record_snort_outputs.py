"""Record real Snort output (Docker) into tests/fixtures/recorded for the parser tests.

Usage: uv run scripts/record_snort_outputs.py   (needs Docker and the pinned image)
"""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path

from detection_workbench.config import Config
from detection_workbench.engines.snort.config_gen import generate_config

ROOT = Path(__file__).resolve().parents[1]
FIX = ROOT / "tests" / "fixtures"
REC = FIX / "recorded"
S = Config().snort


def docker(args: list[str], workdir: Path) -> subprocess.CompletedProcess:
    cmd = ["docker", "run", "--rm", "--network", "none", "-v", f"{FIX}:/fix:ro", "-v", f"{workdir}:/work",
           "--user", "1000:1000", "--entrypoint", S.docker_binary, S.docker_image] + args
    return subprocess.run(cmd, capture_output=True, text=True, timeout=120)


def main() -> int:
    import tempfile
    REC.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory() as td:
        td = Path(td)
        td.chmod(0o777)
        (td / "validate.lua").write_text(generate_config(etc_dir=S.docker_etc, alert_file=False))
        (td / "run.lua").write_text(generate_config(etc_dir=S.docker_etc))
        (td / "prof.lua").write_text(generate_config(etc_dir=S.docker_etc, profile=True))
        for name in ("good", "bad"):
            r = docker(["-c", "/work/validate.lua", "-R", f"/fix/rules/{name}.rules", "-T", "--warn-all"], td)
            (REC / f"validate_{name}.txt").write_text(r.stdout + r.stderr)
            (REC / f"validate_{name}.exit").write_text(f"{r.returncode}\n")
        for pcap in ("http_marker", "flow_endings", "noisy"):
            rules = "noisy" if pcap != "http_marker" else "good"
            (td / "out").mkdir(exist_ok=True)
            (td / "out").chmod(0o777)
            for f in (td / "out").glob("*"):
                f.unlink()
            r = docker(["-q", "-c", "/work/prof.lua", "-R", f"/fix/rules/{rules}.rules", "-r", f"/fix/pcaps/{pcap}.pcap",
                        "--daq", "pcap", "--daq-mode", "read-file", "-A", "alert_json", "-l", "/work/out"], td)
            if r.returncode:
                print(pcap, "failed:", r.stderr[-500:], file=sys.stderr)
                return 1
            (REC / f"alerts_{pcap}.jsonl").write_text((td / "out" / "alert_json.txt").read_text())
            (REC / f"profile_{pcap}.txt").write_text(r.stdout)
    print("recorded:", sorted(p.name for p in REC.iterdir()))
    return 0


if __name__ == "__main__":
    sys.exit(main())
