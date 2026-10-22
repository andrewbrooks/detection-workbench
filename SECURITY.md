# Security policy

The Detection Workbench parses untrusted evidence (packet captures, rule files) and passes text written by a language
model to native programs such as Snort. Treat reports about how it handles that input as security issues, not just bugs.

## Reporting a vulnerability

Please report privately through GitHub: open the repository's **Security** tab and choose **Report a vulnerability**.
Do not put exploit details in a public issue or pull request. If private reporting is not enabled on the repository, open a
public issue that says only that you have a security report and asks for a private channel.

Helpful details: what you did, what you expected, what happened, the workbench commit or version, the Snort version and
backend (native or Docker), and your `config.toml` with anything private removed. A small capture or rule file that
reproduces it is ideal; use synthetic data, never real traffic or malware.

This is a small open-source project maintained by one person. Reports are handled on a best-effort basis; there is no
service-level agreement and no bounty.

## What counts as a security issue

- Reading or writing a file outside `allowed_roots` and the case directory, including through symlinks, special files,
  filenames, or the contents of a rule file
- Getting a command, a Lua setting, or a Docker option into what is executed that was not built from typed, validated values
  (shell or argument injection, config injection, an `include` or similar directive that makes an engine open other files)
- Any way to make the workbench capture from an interface, run inline, or contact a sensor, SIEM or the network
- Evidence being modified, or analysed content differing from what was hashed at registration
- Output that returns raw engine output, file contents or secrets beyond the documented bounded excerpts
- Resource limits that can be bypassed to exhaust memory, disk, processes or time
- Escapes from the Docker backend's restrictions (network, read-only filesystem, capabilities, mounts)

Out of scope: vulnerabilities in Snort, Docker, Python or the MCP SDK themselves (report those upstream, though a way the
workbench makes them exploitable is in scope), and rule-quality or detection-accuracy problems.

## How the workbench defends itself

The safety model is described in plain terms in the [README](README.md#safety-model) and designed in
[docs/plan.md](docs/plan.md) (section B4). Known gaps are listed in the README under *Known limitations*. In short:
argument lists only (never a shell), no inline Lua, typed and escaped config values, `include` directives refused,
paths resolved and checked on the open file, evidence verified by hash while it is copied for each run, `snort2lua` run without include-following, timeouts and size
caps, and an offline-only argument gate.

## Supported versions

Only the latest commit on the default branch is supported while the project is pre-1.0.
