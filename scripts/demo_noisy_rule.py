"""Drive the server through a real MCP stdio session on a synthetic capture with a deliberately noisy rule:
find the noise, propose a fix, prove it with before/after counts, export the case report.

Run: uv run scripts/demo_noisy_rule.py      (needs Docker with the pinned Snort image, or native Snort 3)
"""
from __future__ import annotations

import asyncio
import json
import os
import sys
import tempfile
from pathlib import Path

from mcp import ClientSession
from mcp.client.stdio import StdioServerParameters, stdio_client

ROOT = Path(__file__).resolve().parents[1]
FIX = ROOT / "tests" / "fixtures"


def unwrap(result) -> dict:
    if result.is_error:
        raise RuntimeError("tool error: " + " ".join(getattr(c, "text", "") for c in result.content))
    if getattr(result, "structured_content", None):
        sc = result.structured_content
        return sc.get("result", sc) if set(sc) == {"result"} else sc
    return json.loads(result.content[0].text)


async def main() -> int:
    work = Path(tempfile.mkdtemp(prefix="dw-demo-"))
    cfg = work / "config.toml"
    cfg.write_text(f'case_dir = "{work / "cases"}"\nallowed_roots = ["{FIX}"]\n')
    params = StdioServerParameters(
        command=sys.executable, args=["-m", "detection_workbench.server"],
        env={"PATH": os.environ.get("PATH", ""), "HOME": os.environ.get("HOME", ""), "DW_CONFIG": str(cfg)})

    async with stdio_client(params) as (r, w), ClientSession(r, w) as s:
        await s.initialize()

        async def call(name, **args):
            return unwrap(await s.call_tool(name, args))

        def say(msg):
            print(f"\n== {msg}")

        status = await call("get_status")
        eng = status["engines"][0]
        if not eng["available"]:
            print("Snort unavailable:", eng["detail"])
            return 1
        say(f"Snort {eng['version']} via {eng['backend']}")

        await call("create_case", title="Noisy rule SID 1000042 on the proxy capture")
        pcap = (await call("register_evidence", path=str(FIX / "pcaps/noisy.pcap")))["id"]
        rules = (await call("register_evidence", path=str(FIX / "rules/noisy.rules")))["id"]
        summ = await call("pcap_summary", evidence_id=pcap)
        say(f"capture: {summ['packets']} packets, top source {summ['top_sources'][0]}")

        v = await call("validate_rules", rules_id=rules)
        say(f"rules validate: ok={v['ok']} errors={len(v['errors'])}")

        before = await call("run_pcap", pcap_id=pcap, rules_id=rules)
        say(f"run {before['run_id']}: {before['total_alerts']} alerts")
        for row in before["by_sid"]:
            print(f"   sid {row['sid']:>8}  {row['count']:>4}  {row['msg']}")

        top = (await call("suggest_tuning_targets", run_id=before["run_id"]))["targets"][0]
        say(f"noisiest: sid {top['sid']} ({top['count']} hits, {top['top_source_share']:.0%} from {top['top_source']})")
        first = (await call("get_alerts", run_id=before["run_id"], sid=top["sid"], limit=1))["alerts"][0]
        ex = await call("explain_alert", run_id=before["run_id"], alert_idx=first["alert_idx"])
        print("   matched:", [c["option"] for c in ex["contents"]], "->", ex["contents"][0].get("wire_reassembled", {}).get("found"))
        f1 = await call("add_finding", run_ids=[before["run_id"]], evidence_ids=[pcap, rules],
                        statement=f"SID {top['sid']} fires {top['count']} times, {top['top_source_share']:.0%} from {top['top_source']}; "
                                  "it matches any GET, so it is too broad.")

        fix = ('alert http any any -> any any ( msg:"LOCAL GET to /download"; flow:to_server,established; '
               'http_uri; content:"/download/",fast_pattern; sid:1000042; rev:2; classtype:web-application-activity; )')
        t = await call("test_tuning", before_run_id=before["run_id"],
                       change={"kind": "rule_edit", "sid": 1000042, "rule": fix},
                       reason="Anchor on the /download/ path instead of matching every GET")
        say(f"test_tuning ({t['before_run']} -> {t['after_run']}):")
        for sid, c in t["counts"].items():
            print(f"   sid {sid:>8}  {c['before']:>4} -> {c['after']:>4}")
        print("   other SIDs changed:", t["other_sids_changed"] or "none")
        await call("update_finding", finding_id=f1["id"], status="confirmed")
        await call("add_finding", run_ids=[t["after_run"]],
                   statement=f"Rewrite of 1000042 removes {t['counts']['1000042']['before'] - t['counts']['1000042']['after']} "
                             "hits on this capture and keeps the marker alert (sid 1000001). One synthetic capture "
                             "says little about production traffic.")

        cut = t["counts"]["1000042"]
        await call("update_case", status="closed", summary=(
            f"**Question.** Why is SID 1000042 so noisy, and can it be fixed without losing the real detection?\n\n"
            f"**Findings.** SID 1000042 fired {top['count']} times ({top['top_source_share']:.0%} from {top['top_source']}) "
            f"because it matches any GET (f-0001, run {before['run_id']}).\n\n"
            f"**Tested change.** Anchoring it on `/download/` takes it from {cut['before']} to {cut['after']} alerts and "
            f"leaves SID 1000001 unchanged (run {t['after_run']}, decision {t['decision_id']}).\n\n"
            "**Limits.** One synthetic capture; it shows the change works, not that the anchor is right for production."))
        out = await call("export_case", format="markdown")
        csv = await call("export_case", format="timesketch_csv")
        say("exported")
        print("   report:", out["path"])
        print("   timesketch csv:", csv["path"])
        print("\n" + Path(out["path"]).read_text()[:1800] + "\n...")
    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
