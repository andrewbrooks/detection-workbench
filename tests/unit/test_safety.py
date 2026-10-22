import os
import re
import socket
import sys
import time
from pathlib import Path

import pytest

from detection_workbench.config import Config
from detection_workbench.runner.runner import RunContext, RunnerError, docker_argv, excerpt, execute
from detection_workbench.safety import lua
from detection_workbench.safety.argv import UnsafeArgv, assert_safe_snort_argv
from detection_workbench.safety.paths import PathError, resolve_read, resolve_write

HOSTILE = [
    "'; os.execute('id') --", "x]] os.execute('id') --[[", "a\nb", "a\rb", "a\0b", "a\\b", 'a"b',
    "$(id)", "`id`", "a;b", "é", "‮", "x" * 600, "--comment", "[=[x]=]", "a(b)", "a{b}",
]


@pytest.mark.parametrize("v", HOSTILE)
def test_lua_str_rejects_hostile(v):
    with pytest.raises(lua.LuaValueError):
        lua.lua_str(v)


def test_lua_str_accepts_plain():
    assert lua.lua_str("by_src") == "'by_src'"
    assert lua.lua_str("timestamp pkt_num sid") == "'timestamp pkt_num sid'"
    for bad in (None, 5, b"x", ["a"]):
        with pytest.raises(lua.LuaValueError):
            lua.lua_str(bad)


def test_lua_output_never_contains_breakouts():
    for v in ["10.0.0.0/8", "[10.0.0.0/8,!10.1.0.0/16]", "$HOME_NET", "any"]:
        out = lua.lua_net(v)
        assert out.startswith("'") and out.endswith("'") and not re.search(r"[\\\n\"]|--", out[1:-1])


@pytest.mark.parametrize("v", ["10.0.0.0/8", "!10.0.0.1", "[10.0.0.0/8,192.168.0.0/16]", "any", "$HOME_NET",
                               "2001:db8::/32", "[$HOME_NET,!10.0.0.5]"])
def test_lua_net_accepts(v):
    assert lua.lua_net(v) == f"'{v}'"


@pytest.mark.parametrize("v", ["10.0.0.0/33", "evil", "$NOPE", "[[10.0.0.1]]", "[]", "", "10.0.0.1'; x='",
                               "10.0.0.1\n", "[10.0.0.1,", None, 5, "!any!"])
def test_lua_net_rejects(v):
    with pytest.raises(lua.LuaValueError):
        lua.lua_net(v)


def test_lua_scalars():
    assert lua.lua_int(5, 0, 10) == "5"
    for bad in (True, "5", 11, -1, 1.5):
        with pytest.raises(lua.LuaValueError):
            lua.lua_int(bad, 0, 10)
    assert lua.lua_bool(True) == "true"
    with pytest.raises(lua.LuaValueError):
        lua.lua_bool(1)
    assert lua.lua_enum("by_src", {"by_src", "by_dst"}) == "'by_src'"
    with pytest.raises(lua.LuaValueError):
        lua.lua_enum("by_x", {"by_src"})
    assert lua.lua_ident("alert_json") == "alert_json"
    with pytest.raises(lua.LuaValueError):
        lua.lua_ident("a b")


def test_lua_path_inside_run_dir(tmp_path):
    (tmp_path / "cfg").mkdir()
    assert lua.lua_path(tmp_path / "cfg" / "x.rules", tmp_path).startswith("'")
    with pytest.raises(lua.LuaValueError):
        lua.lua_path("/etc/passwd", tmp_path)
    with pytest.raises(lua.LuaValueError):
        lua.lua_path(tmp_path / ".." / "x", tmp_path)


# ---- paths ----------------------------------------------------------------
def test_read_inside_root(tmp_path):
    f = tmp_path / "a.pcap"; f.write_bytes(b"x")
    assert resolve_read(f, [tmp_path]) == f.resolve()


def test_read_outside_root_names_config_key(tmp_path):
    root = tmp_path / "ok"; root.mkdir()
    f = tmp_path / "a"; f.write_bytes(b"x")
    with pytest.raises(PathError, match="allowed_roots"):
        resolve_read(f, [root])


def test_read_symlink_escape(tmp_path):
    root = tmp_path / "ok"; root.mkdir()
    secret = tmp_path / "secret"; secret.write_text("s")
    (root / "link").symlink_to(secret)
    with pytest.raises(PathError):
        resolve_read(root / "link", [root])
    (root / "dirlink").symlink_to(tmp_path)
    with pytest.raises(PathError):
        resolve_read(root / "dirlink" / "secret", [root])


def test_read_symlink_staying_inside_ok(tmp_path):
    (tmp_path / "real").write_text("x")
    (tmp_path / "ln").symlink_to(tmp_path / "real")
    assert resolve_read(tmp_path / "ln", [tmp_path]) == (tmp_path / "real").resolve()


def test_read_rejects_devices_fifos_sockets_dirs(tmp_path):
    os.mkfifo(tmp_path / "fifo")
    s = socket.socket(socket.AF_UNIX); s.bind(str(tmp_path / "sock"))
    try:
        for name in ("fifo", "sock"):
            with pytest.raises(PathError, match="regular file"):
                resolve_read(tmp_path / name, [tmp_path])
        with pytest.raises(PathError, match="regular file"):
            resolve_read(tmp_path, [tmp_path])
        with pytest.raises(PathError):
            resolve_read("/dev/null", [Path("/dev")])
    finally:
        s.close()


def test_read_size_cap_and_nul(tmp_path):
    f = tmp_path / "big"; f.write_bytes(b"x" * 100)
    with pytest.raises(PathError, match="cap"):
        resolve_read(f, [tmp_path], max_bytes=10)
    with pytest.raises(PathError):
        resolve_read("a\0b", [tmp_path])
    with pytest.raises(PathError):
        resolve_read(tmp_path / "missing", [tmp_path])


def test_write_discipline(tmp_path):
    existing = tmp_path / "mine.rules"; existing.write_text("user rules")
    with pytest.raises(PathError, match="already exists"):
        resolve_write(existing, [tmp_path])
    assert resolve_write(existing, [tmp_path], overwrite=True) == existing
    with pytest.raises(PathError, match="evidence"):
        resolve_write(existing, [tmp_path], overwrite=True, protected={existing.resolve()})
    assert resolve_write(tmp_path / "new.rules", [tmp_path]) == tmp_path / "new.rules"
    with pytest.raises(PathError, match="outside"):
        resolve_write("/tmp/elsewhere-x.rules", [tmp_path])
    with pytest.raises(PathError, match="does not exist"):
        resolve_write(tmp_path / "nodir" / "x", [tmp_path])
    (tmp_path / "ln").symlink_to(existing)
    with pytest.raises(PathError, match="symlink"):
        resolve_write(tmp_path / "ln", [tmp_path], overwrite=True)


# ---- argv gate --------------------------------------------------------------
GOOD = ["snort", "-c", "/cfg/snort.lua", "-R", "/in/0/r.rules", "-r", "/in/1/a.pcap", "--daq", "pcap",
        "--daq-mode", "read-file", "-A", "alert_json", "-l", "/out", "-q", "-z", "1"]


def test_argv_gate_accepts_good():
    assert_safe_snort_argv(GOOD)


@pytest.mark.parametrize("extra", [["-i", "eth0"], ["-Q"], ["--lua", "x=1"], ["--lua=x=1"], ["--daq-dir", "/x"],
                                   ["--plugin-path", "/x"], ["--pcap-dir", "/"], ["--pcap-loop", "0"],
                                   ["--shell"], ["-s", "9"], ["--stdin-rules"], ["--rule", "alert"], ["-r", "b.pcap"]])
def test_argv_gate_rejects(extra):
    with pytest.raises(UnsafeArgv):
        assert_safe_snort_argv(GOOD + extra)


@pytest.mark.parametrize("a,b", [("--daq", "afpacket"), ("--daq", "nfq"), ("--daq-mode", "inline"),
                                 ("--daq-mode", "passive")])
def test_argv_gate_daq(a, b):
    argv = list(GOOD)
    argv[argv.index(a) + 1] = b
    with pytest.raises(UnsafeArgv):
        assert_safe_snort_argv(argv)
    with pytest.raises(UnsafeArgv):
        assert_safe_snort_argv(["snort", "--daq=afpacket"])


def test_argv_gate_type():
    with pytest.raises(UnsafeArgv):
        assert_safe_snort_argv("snort -T")  # type: ignore[arg-type]


# ---- runner -----------------------------------------------------------------
@pytest.fixture
def ctx(tmp_path):
    for d in ("cfg", "out"):
        (tmp_path / d).mkdir()
    return RunContext(run_dir=tmp_path, backend="native", cfg=Config(), etc_dir="/x", name="dw-t")


def test_execute_no_shell_metacharacters(ctx, tmp_path):
    marker = tmp_path / "pwned"
    r = execute([sys.executable, "-c", "import sys; print(sys.argv[1])", f"; touch {marker}; $(touch {marker})"],
                ctx, 10)
    assert r.exit_code == 0 and not marker.exists()
    assert "touch" in r.stdout.read_text()


def test_execute_timeout_kills_process_group(ctx, tmp_path):
    pidfile = tmp_path / "child.pid"
    code = ("import subprocess,sys,time;"
            f"p=subprocess.Popen(['sleep','60']);open({str(pidfile)!r},'w').write(str(p.pid));time.sleep(60)")
    r = execute([sys.executable, "-c", code], ctx, 1)
    assert r.timed_out and r.exit_code is None and r.duration_s < 10
    pid = int(pidfile.read_text())
    for _ in range(50):
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            break
        time.sleep(0.1)
    else:
        pytest.fail("child survived the timeout")


def test_execute_captures_to_files_and_excerpt_is_bounded(ctx):
    r = execute([sys.executable, "-c", "import sys\nfor i in range(5000): print('line', i)\nsys.stderr.write('boom')"], ctx, 20)
    assert r.stdout.stat().st_size > 20000
    ex = excerpt(r.stdout, 20)
    assert len(ex.splitlines()) <= 20 and len(ex) <= 2048 and ex.endswith("line 4999")
    assert excerpt(r.stderr, 20) == "boom"


def test_execute_rejects_bad_argv(ctx):
    for bad in ([], "ls -l", [1, 2]):
        with pytest.raises(RunnerError):
            execute(bad, ctx, 1)  # type: ignore[arg-type]


def test_execute_minimal_env(ctx):
    os.environ["DW_SECRET_TEST"] = "leak"
    r = execute([sys.executable, "-c", "import os; print(sorted(os.environ))"], ctx, 10)
    assert "DW_SECRET_TEST" not in r.stdout.read_text()


def test_docker_argv_flags(ctx, tmp_path):
    ctx.backend, ctx.name = "docker", "dw-x"
    pcap = tmp_path / "a.pcap"
    t = ctx.input_arg(pcap)
    assert ctx.input_arg(pcap) == t and t == "/in/0/a.pcap"
    assert ctx.cfg_arg("snort.lua") == "/cfg/snort.lua" and ctx.out_arg("alerts") == "/out/alerts"
    cmd = docker_argv(ctx, ["-T"])
    joined = " ".join(cmd)
    for flag in ("--network none", "--cap-drop ALL", "no-new-privileges", "--read-only", "--entrypoint"):
        assert flag in joined
    assert f"{pcap}:/in/0/a.pcap:ro" in joined and f"{ctx.cfg_dir}:/cfg:ro" in joined
    assert f"{ctx.out_dir}:/out" in joined and f"{ctx.out_dir}:/out:" not in joined
    assert "ciscotalos/snort3@sha256:" in cmd[cmd.index("--entrypoint") + 2]
    assert cmd[-1] == "-T"


def test_source_never_uses_shell_or_inline_lua():
    src = Path(__file__).parents[2] / "src"
    bad = re.compile(r"shell\s*=\s*True|os\.system|os\.popen|commands\.getoutput")
    for p in src.rglob("*.py"):
        text = p.read_text()
        assert not bad.search(text), p
        if p.name != "argv.py":
            assert '"--lua"' not in text and "'--lua'" not in text, p
