# Contributing

Thanks for taking an interest. The workbench is small and deliberately conservative: it runs detection engines on files
and records what happened, and it handles hostile input. Changes that keep that promise are easy to accept.

## Set up

Requires Python 3.12+ and [uv](https://docs.astral.sh/uv/). Docker is needed only for the integration tests and the
example/demo scripts.

```bash
uv sync
docker pull ciscotalos/snort3@sha256:f15f714fd61ade114b1039687dd43352cae26cd6401b89f2b03404e0d21e322f

uv run pytest -q                                       # unit and parser tests, no Snort needed
DW_INTEGRATION=1 uv run pytest -q tests/integration    # needs Docker (or native Snort 3)
uv run ruff check src tests scripts                    # lint
uv run scripts/demo_noisy_rule.py                      # the whole loop through a real MCP session
```

More commands, the code layout and current status are in [docs/development.md](docs/development.md).

**Test as a different user.** Anything involving Docker can pass on your machine and fail in CI, because the Snort image only
admits uid 1000 and your uid may be 1000. `scripts/ci_parity.sh` (Linux) runs the integration tests, or `unit`, as uid 1001
against your Docker daemon, the way a CI runner does; run it before changing anything in `runner/` or `engines/snort/`.

## Before you open a pull request

1. **Add tests.** Every behaviour change needs a test. Safety-relevant changes need a test that fails on the old code
   (for example a hostile filename, an `include` line, a path that escapes `allowed_roots`).
2. **Keep the tests and lint green:** the unit suite, the integration suite if you touched the engine, runner or
   workbench code, and `ruff`.
3. **Update the docs** that describe what you changed: the README, [docs/case-schema.md](docs/case-schema.md) for any
   change to what is stored, and [docs/plan.md](docs/plan.md) for design changes. A test checks that Markdown links resolve.
4. **Regenerate generated files** when your change affects them: `uv run scripts/make_example_case.py` rewrites the
   [example case](docs/examples/README.md) and the report embedded in the write-up;
   `uv run scripts/record_snort_outputs.py` re-records the Snort output used by the parser tests.

## Rules the code relies on

These are not style preferences; the safety model depends on them.

- **Argument lists only.** Never `shell=True`, `os.system` or a string-built command. Snort's `--lua` is never used.
- **Caller values reach generated Lua only through `safety/lua.py`.** Add a validator there; do not format values into config.
- **Offline only.** The only packet source is one registered pcap read through the pcap DAQ in read-file mode. Do not add
  parameters for interfaces, inline mode or other DAQs.
- **Evidence is referenced, hashed and never modified.** Engines work from a verified copy (`safety/verified.py`), not
  from the original path.
- **Runs are immutable** once written. Fix forward by recording a new run.
- **Bounded output.** Tools return parsed results and short excerpts, never whole engine output, and lists in a response
  are capped (anything that grows with the input must be).
- **Open once, check on the open file.** Read and write user-named paths through `safety/verified.py` and
  `write_text_safely`, which do not follow symlinks; never check a path and then use it by name.
- **Free text is capped,** and every value that reaches a file path, mount or command is validated first.

## Adding an engine

Zeek, tshark and Zircolite are designed but not built. Implement the `Engine` protocol in `engines/base.py`, register it,
and reuse the runner, safety layer and case store unchanged. The extension points are described in
[docs/plan.md](docs/plan.md) (B5 and B7).

## Data and licensing

- Fixtures are synthetic. Do not commit real captures, malware, or Talos Registered or Subscriber rules (they need your own
  Oinkcode and licence and cannot be redistributed). Real captures for local testing go in a directory you point
  `DW_REAL_PCAPS` at.
- The project is licensed under the [Apache License 2.0](LICENSE). By contributing you agree your contribution is
  licensed under the same terms (section 5 of the license).

## Reporting problems

Bugs and ideas: open an issue with the Snort version, whether you used the native or Docker backend, and the smallest
rule file and capture that show the problem. For anything that might be a security issue, follow [SECURITY.md](SECURITY.md)
instead.
