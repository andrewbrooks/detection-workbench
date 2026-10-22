"""Final gate on Snort argument lists: offline pcap reading only."""
from __future__ import annotations


class UnsafeArgv(ValueError):
    pass


# Flags that would capture live, run inline, load code, or widen input beyond one registered pcap.
_FORBIDDEN = {"-i", "-Q", "--lua", "--daq-dir", "--plugin-path", "--script-path", "--pcap-dir",
              "--pcap-file", "--pcap-loop", "--pcap-list", "--shell", "-s", "--snaplen", "--daq-var",
              "--daq-batch-size", "--rule-path", "-v", "--stdin-rules", "--rule", "-L"}
_REFUSAL = ("The workbench is offline-only: it reads one registered pcap and never captures from an "
            "interface, runs inline, or touches a live sensor.")


def assert_safe_snort_argv(argv: list[str]) -> None:
    if not isinstance(argv, list) or not all(isinstance(a, str) for a in argv):
        raise UnsafeArgv("argv must be a list of strings")
    for i, a in enumerate(argv):
        flag = a.split("=", 1)[0]
        if flag in _FORBIDDEN:
            raise UnsafeArgv(f"{flag} is not allowed. {_REFUSAL}")
        if flag == "--daq" and (argv[i + 1:i + 2] != ["pcap"] if "=" not in a else a != "--daq=pcap"):
            raise UnsafeArgv(f"only the pcap DAQ is allowed. {_REFUSAL}")
        if flag == "--daq-mode" and (argv[i + 1:i + 2] != ["read-file"] if "=" not in a else a != "--daq-mode=read-file"):
            raise UnsafeArgv(f"only --daq-mode read-file is allowed. {_REFUSAL}")
    if "-r" in argv and argv.count("-r") != 1:
        raise UnsafeArgv("exactly one -r pcap is allowed")
