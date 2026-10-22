"""The MCP surface: tool registration, tool-visible errors, and schemas. No Snort or Docker needed."""
import asyncio
import json
from pathlib import Path

import pytest
from mcp.server.mcpserver.exceptions import ToolError

from detection_workbench.config import Config
from detection_workbench.engines.base import EngineVersion
from detection_workbench.server import build_server
from detection_workbench.workbench import Workbench


class NoEngine:
    name = "snort"
    evidence_types = {"pcap"}

    def version(self):
        return EngineVersion("snort", None, None, False, "not installed (test double)")

    def status(self):
        return {"engine": "snort", "available": False, "version": None, "backend": None, "detail": "test double"}

    def has_snort2lua(self):
        return False


@pytest.fixture
def server(tmp_path):
    cfg = Config(case_dir=tmp_path / "cases", allowed_roots=(tmp_path.resolve(),))
    return build_server(cfg, Workbench(cfg, engine=NoEngine()))


def call(server, name, **args):
    """-> (is_error, payload). In-process, a ToolError propagates; over stdio the SDK turns it into is_error=True."""
    try:
        res = asyncio.run(server.call_tool(name, args))
    except ToolError as e:
        return True, str(e)
    sc = getattr(res, "structured_content", None)
    if sc:
        return res.is_error, (sc.get("result", sc) if set(sc) == {"result"} else sc)
    text = res.content[0].text if res.content else ""
    try:
        return res.is_error, json.loads(text)
    except ValueError:
        return res.is_error, text


EXPECTED = {"create_case", "open_case", "list_cases", "register_evidence", "add_finding", "update_finding", "add_note",
            "update_case", "get_case", "export_case", "get_status", "pcap_summary", "validate_rules", "run_pcap",
            "get_alerts", "explain_alert", "profile_rules", "suggest_tuning_targets", "test_tuning", "diff_runs",
            "write_rules_file"}


def test_tools_prompt_and_instructions(server):
    tools = asyncio.run(server.list_tools())
    assert {t.name for t in tools} == EXPECTED  # convert_snort2 only registers when snort2lua is available
    assert [p.name for p in asyncio.run(server.list_prompts())] == ["detection_engineering"]
    assert "offline-only" in server.instructions and "update_case" in server.instructions


def test_every_tool_is_described_with_an_example(server):
    for t in asyncio.run(server.list_tools()):
        assert t.description and "Example" in t.description or t.name in {"list_cases", "get_case", "get_status"}, t.name


def test_wrapped_tools_keep_their_parameter_schemas(server):
    by = {t.name: t for t in asyncio.run(server.list_tools())}
    assert {"before_run_id", "change", "reason"} <= set(by["test_tuning"].input_schema["properties"])
    assert by["run_pcap"].input_schema["required"] == ["pcap_id"]
    assert "overwrite" in by["write_rules_file"].input_schema["properties"]


def test_caller_errors_reach_the_model_as_the_tool_result(server):
    err, text = call(server, "run_pcap", pcap_id="e-0001", rules_text="x")
    assert err and "No active case" in text and "create_case" in text
    err, text = call(server, "update_case", status="closed")
    assert err and "No active case" in text


def test_unknown_ids_and_bad_values_are_readable_errors(server, tmp_path):
    assert call(server, "create_case", title="t")[0] is False
    err, text = call(server, "add_finding", statement="x", run_ids=["r-9999"])
    assert err and "r-9999" in text
    err, text = call(server, "update_case", status="archived")
    assert err and "status must be one of" in text
    outside = tmp_path.parent / "elsewhere.pcap"
    err, text = call(server, "register_evidence", path=str(outside))
    assert err and "elsewhere.pcap" in text
    err, text = call(server, "register_evidence", path=str(tmp_path / "x"), type="exe")
    assert err and "type must be one of" in text


def test_engine_unavailable_is_explained(server, tmp_path):
    call(server, "create_case", title="t")
    err, text = call(server, "validate_rules", rules_text="alert tcp any any -> any any ( sid:1; )")
    assert err and "Snort is not available" in text and "test double" in text


def test_happy_path_through_the_protocol(server, tmp_path):
    err, out = call(server, "create_case", title="Protocol test")
    assert not err and out["active"] and out["case_id"].endswith("protocol-test")
    f = tmp_path / "a.rules"
    f.write_text('alert tcp any any -> any any ( msg:"x"; content:"a"; sid:1000001; rev:1; )\n')
    err, ev = call(server, "register_evidence", path=str(f))
    assert not err and ev["type"] == "rules" and ev["id"] == "e-0001"
    err, upd = call(server, "update_case", summary="done", status="closed")
    assert not err and upd["status"] == "closed"
    err, exp = call(server, "export_case", format="markdown")
    assert not err and "done" in Path(exp["path"]).read_text()
    err, st = call(server, "get_status")
    assert not err and st["active_case"] and st["engines"][0]["available"] is False
    json.dumps(st)
