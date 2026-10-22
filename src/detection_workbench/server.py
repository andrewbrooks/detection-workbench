"""MCP server (stdio). Tool bodies live in workbench.py; this file only declares them."""
from __future__ import annotations

import functools
import sys

from mcp.server.mcpserver import MCPServer
from mcp.server.mcpserver.exceptions import ToolError

from .config import Config, ConfigError, load_config
from .guidance import GUIDANCE
from .workbench import Workbench, WorkbenchError


def _tool_errors(fn):
    """Show caller-fixable errors (no active case, path outside allowed_roots, bad argument ...) to the model as
    the tool result, instead of the SDK's generic "Error executing tool" with a traceback in the server log."""
    @functools.wraps(fn)
    def wrapper(*args, **kwargs):
        try:
            return fn(*args, **kwargs)
        except (WorkbenchError, ValueError) as e:  # case, path, pcap and tuning errors are all ValueErrors
            raise ToolError(str(e)) from None
    return wrapper


def build_server(cfg: Config | None = None, wb: Workbench | None = None) -> MCPServer:
    cfg = cfg or load_config()
    wb = wb or Workbench(cfg)
    mcp = MCPServer("detection-workbench", instructions=GUIDANCE)
    mcp._workbench = wb  # exposed for tests

    def tool():
        return lambda fn: mcp.tool()(_tool_errors(fn))

    @mcp.prompt(name="detection_engineering", description="How to write, test, explain and tune detections with this workbench.")
    def detection_engineering() -> str:
        return GUIDANCE

    # ---- case tools ----
    @tool()
    def create_case(title: str) -> dict:
        """Create a case and make it active. Every run, finding and decision is recorded in it.
        Example: create_case(title="Noisy SID 1000042 on the proxy capture")"""
        return wb.create_case(title)

    @tool()
    def open_case(case_id: str) -> dict:
        """Make an existing case active. Example: open_case(case_id="20261022-noisy-sid-1000042")"""
        return wb.open_case(case_id)

    @tool()
    def list_cases() -> dict:
        """List cases in the case directory with ids, titles and status."""
        return wb.list_cases()

    @tool()
    def register_evidence(path: str, type: str | None = None, label: dict | None = None) -> dict:
        """Register a pcap/pcapng or rules file in the active case (hashed, type-detected, never copied or
        modified). The path must be under allowed_roots. Returns the evidence id (e-0001 ...) used by other tools.
        Example: register_evidence(path="~/captures/proxy.pcap")"""
        return wb.register_evidence(path, type, label)

    @tool()
    def add_finding(statement: str, run_ids: list[str], evidence_ids: list[str] | None = None) -> dict:
        """Record a short statement supported by specific runs, e.g. 'SID 1000042 fires 300 times, 95% from
        10.0.4.20'. Run and evidence ids must exist. Starts as status 'open'.
        Example: add_finding(statement="SID 1000042 is dominated by one scanner", run_ids=["r-0002"])"""
        return wb.add_finding(statement, run_ids, evidence_ids)

    @tool()
    def update_finding(finding_id: str, status: str | None = None, statement: str | None = None) -> dict:
        """Change a finding's status (open, confirmed, dismissed) or wording; history is kept.
        Example: update_finding(finding_id="f-0001", status="confirmed")"""
        return wb.update_finding(finding_id, status, statement)

    @tool()
    def add_note(text: str) -> dict:
        """Add free-text context to the case. Example: add_note(text="Capture taken during the 14:00 scan window")"""
        return wb.add_note(text)

    @tool()
    def update_case(summary: str | None = None, status: str | None = None) -> dict:
        """Write the case summary (your analysis and conclusions, Markdown allowed) and/or set the status to
        'open' or 'closed'. The summary appears at the top of the exported report, so cite run and finding ids
        in it. Call it again to revise; each change is logged.
        Example: update_case(summary="SID 1000042 is too broad (f-0001, r-0003); the rewrite in r-0005 fixes it.", status="closed")"""
        return wb.update_case(summary, status)

    @tool()
    def get_case() -> dict:
        """Summary of the active case: evidence, findings, decisions, notes and recent runs."""
        return wb.get_case()

    @tool()
    def export_case(format: str = "markdown", path: str | None = None, overwrite: bool = False) -> dict:
        """Export the case as a Markdown report ('markdown') or a Timesketch-importable CSV ('timesketch_csv').
        Without a path the file goes in the case's exports/ folder. A path must end in .md or .csv and an
        existing file is only replaced with overwrite=true.
        Example: export_case(format="markdown")"""
        return wb.export_case(format, path, overwrite)

    # ---- snort tools ----
    @tool()
    def get_status() -> dict:
        """Engine versions and backend (native or Docker), config location, allowed_roots, limits and the
        active case. Call this first if something is unavailable."""
        return wb.get_status()

    @tool()
    def pcap_summary(evidence_id: str) -> dict:
        """Packet count, time range, protocols, top talkers and services for a registered pcap.
        Example: pcap_summary(evidence_id="e-0001")"""
        return wb.pcap_summary(evidence_id)

    @tool()
    def validate_rules(rules_id: str | None = None, rules_text: str | None = None) -> dict:
        """Check rules with Snort itself. Give a registered rules file (rules_id) or inline rules_text.
        Returns errors as {line, sid, error, plain}, warnings, and workbench_lint hygiene items (e.g. a
        missing sid, which Snort does not report). Fast enough for a write-test-fix loop.
        Example: validate_rules(rules_text='alert http any any -> any any ( msg:"x"; http_uri; content:"abc"; sid:1000001; rev:1; )')"""
        return wb.validate_rules(rules_id, rules_text)

    @tool()
    def run_pcap(pcap_id: str, rules_id: str | None = None, rules_text: str | None = None,
                 home_net: str | None = None, external_net: str | None = None, flush_one_sided: bool = False,
                 profile: bool = False) -> dict:
        """Run rules against a registered pcap. Returns the run id, total alerts, counts by SID with msg, the
        first alerts, and stream_caveats (flows where Snort cannot inspect un-ACKed data). home_net is an IP/CIDR
        or list like '[10.0.0.0/8,192.168.0.0/16]'; no raw Lua is accepted.
        Example: run_pcap(pcap_id="e-0001", rules_id="e-0002", home_net="10.0.0.0/8")"""
        return wb.run_pcap(pcap_id, rules_id, rules_text, home_net, external_net, flush_one_sided, profile)

    @tool()
    def get_alerts(run_id: str, sid: int | None = None, src: str | None = None, dst: str | None = None,
                   pkt_from: int | None = None, pkt_to: int | None = None, offset: int = 0, limit: int = 50) -> dict:
        """Page or filter a run's alerts by SID, source/destination address or packet range.
        Example: get_alerts(run_id="r-0002", sid=1000042, src="10.0.4.20", limit=20)"""
        return wb.get_alerts(run_id, sid, src, dst, pkt_from, pkt_to, offset, limit)

    @tool()
    def explain_alert(run_id: str, alert_idx: int) -> dict:
        """Facts about one alert: the rule text and parsed options, the 5-tuple/direction/service, a bounded
        hex+ASCII dump, and which content/pcre options appear in the payload and at what offsets (wire bytes
        reassembled from the pcap, plus Snort's own inspected buffer). Report facts; you do the explaining.
        Example: explain_alert(run_id="r-0002", alert_idx=0)"""
        return wb.explain_alert(run_id, alert_idx)

    @tool()
    def profile_rules(pcap_id: str, rules_id: str | None = None, rules_text: str | None = None, top: int = 20) -> dict:
        """Run the rules with Snort's rule profiler and return the slowest rules with checks, matches and time.
        Example: profile_rules(pcap_id="e-0001", rules_id="e-0002", top=10)"""
        return wb.profile_rules(pcap_id, rules_id, rules_text, top)

    @tool()
    def suggest_tuning_targets(run_id: str, top: int = 10) -> dict:
        """Rank the noisiest SIDs in a run by count, with distinct sources/destinations and how concentrated the
        hits are in one source. Example: suggest_tuning_targets(run_id="r-0002")"""
        return wb.suggest_tuning_targets(run_id, top)

    @tool()
    def test_tuning(before_run_id: str, change: dict, reason: str) -> dict:
        """Apply one structured change to a copy, re-run the same pcap, and return before/after counts per SID.
        Records a decision. change.kind is one of:
          suppress: {kind, sid, track:'by_src'|'by_dst', ip}
          event_filter: {kind, sid, type:'limit'|'threshold'|'both', track, count, seconds}
          rate_filter: {kind, sid, track, count, seconds, new_action, timeout}
          rule_edit: {kind, sid, rule:'<complete replacement rule on one line>'}
        Example: test_tuning(before_run_id="r-0002", change={"kind":"suppress","sid":1000042,"track":"by_src","ip":"10.0.4.20"}, reason="known scanner")"""
        return wb.test_tuning(before_run_id, change, reason)

    @tool()
    def diff_runs(run_a: str, run_b: str) -> dict:
        """Alerts added, removed and changed between two runs, grouped by SID. Example: diff_runs(run_a="r-0002", run_b="r-0003")"""
        return wb.diff_runs(run_a, run_b)

    @tool()
    def write_rules_file(path: str, rules_text: str, overwrite: bool = False) -> dict:
        """Save rules to a path you name. Existing files are never overwritten unless overwrite=true; instead a
        diff is returned. Registered evidence is never overwritten.
        Example: write_rules_file(path="~/rules/local-new.rules", rules_text="alert ...")"""
        return wb.write_rules_file(path, rules_text, overwrite)

    if wb.engine.version().available and wb.engine.has_snort2lua():
        @tool()
        def convert_snort2(evidence_id: str) -> dict:
            """Convert a registered Snort 2 rules file or snort.conf with snort2lua. The output stays in the run
            directory for review; validate it, then save with write_rules_file.
            Example: convert_snort2(evidence_id="e-0003")"""
            return wb.convert_snort2(evidence_id)

    return mcp


def main() -> None:
    try:
        server = build_server()
    except ConfigError as e:
        sys.exit(f"detection-workbench: configuration error: {e}")
    server.run()


if __name__ == "__main__":
    main()
