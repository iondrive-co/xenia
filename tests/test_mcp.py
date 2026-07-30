from __future__ import annotations

import io
import json

import pytest
from conftest import CORE, FAKE_GITLAB_PAT, FAKE_GRAFANA_TOKEN, pre

from xenia import db as xdb
from xenia import ingest, mcp


@pytest.fixture
def server(conn, clock, tmp_path):
    clock()
    ingest.record(conn, pre("Bash", {
        "command": f"curl -H 'PRIVATE-TOKEN: {FAKE_GITLAB_PAT}' https://x.test",
    }))
    clock()
    ingest.record(conn, pre("Write", {
        "file_path": f"{CORE}/.env", "content": f"SECRET={FAKE_GRAFANA_TOKEN}\n",
    }))
    conn.commit()
    return mcp.Server(tmp_path / "audit.db")


def call(server, name, arguments=None):
    reply = server.handle({
        "jsonrpc": "2.0", "id": 1, "method": "tools/call",
        "params": {"name": name, "arguments": arguments or {}},
    })
    return reply["result"]


def test_initialize_reports_tools_capability(server):
    reply = server.handle({
        "jsonrpc": "2.0", "id": 1, "method": "initialize",
        "params": {"protocolVersion": "2025-06-18", "capabilities": {}},
    })
    result = reply["result"]
    assert result["serverInfo"]["name"] == "xenia"
    assert "tools" in result["capabilities"]
    assert result["protocolVersion"] == "2025-06-18"


def test_a_retired_reader_is_reported_when_the_next_one_connects(server, tmp_path):
    conn = xdb.connect(tmp_path / "audit.db")
    ingest.log_ingest_error(conn, "reader", "retired 1 reader(s) still on schema 8")
    conn.close()

    reply = server.handle({"jsonrpc": "2.0", "id": 1, "method": "initialize",
                           "params": {}})
    assert "retired 1 reader(s) still on schema 8" in reply["result"]["instructions"]


def test_the_instructions_survive_a_database_that_cannot_be_read(tmp_path):
    reply = mcp.Server(tmp_path / "nothing-here.db").handle(
        {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}})
    assert reply["result"]["instructions"].startswith("Read-only record")


def test_notifications_are_never_answered(server):
    assert server.handle({"jsonrpc": "2.0", "method": "notifications/initialized"}) is None


def test_unknown_method_is_a_jsonrpc_error(server):
    reply = server.handle({"jsonrpc": "2.0", "id": 7, "method": "nope"})
    assert reply["error"]["code"] == -32601


def test_every_tool_is_listed_with_a_schema(server):
    tools = server.handle({"jsonrpc": "2.0", "id": 1, "method": "tools/list"})["result"]["tools"]
    assert {t["name"] for t in tools} == {
        "xenia_report", "xenia_calls", "xenia_trace",
    }
    for tool in tools:
        assert tool["description"]
        assert tool["inputSchema"]["type"] == "object"


def test_every_view_is_offered_and_answers(server):
    tool = next(t for t in mcp.TOOLS if t["name"] == "xenia_report")
    assert tool["inputSchema"]["properties"]["view"]["enum"] == list(mcp.VIEWS)
    assert tool["inputSchema"]["required"] == ["view"]
    for view in mcp.VIEWS:
        result = call(server, "xenia_report", {"view": view})
        assert result["structuredContent"]["view"] == view
        assert isinstance(result["structuredContent"]["rows"], list)


def test_a_view_is_required_and_must_be_one_of_the_six(server):
    for arguments in ({}, {"view": "everything"}):
        reply = server.handle({
            "jsonrpc": "2.0", "id": 1, "method": "tools/call",
            "params": {"name": "xenia_report", "arguments": arguments},
        })
        assert reply["error"]["code"] == -32602
        assert "tasks" in reply["error"]["message"]


def test_a_filter_a_view_cannot_read_is_refused_not_ignored(server):
    reply = server.handle({
        "jsonrpc": "2.0", "id": 1, "method": "tools/call",
        "params": {"name": "xenia_report",
                   "arguments": {"view": "tasks", "path": "/etc/*"}},
    })
    assert reply["error"]["code"] == -32602
    assert "'path' (a disk parameter)" in reply["error"]["message"]


def test_a_grouping_belonging_to_another_view_is_refused(server):
    reply = server.handle({
        "jsonrpc": "2.0", "id": 1, "method": "tools/call",
        "params": {"name": "xenia_report",
                   "arguments": {"view": "disk", "group_by": "host"}},
    })
    assert reply["error"]["code"] == -32602
    assert "group_by must be one of" in reply["error"]["message"]


def test_a_bad_tool_call_is_reported_not_fatal(server):
    reply = server.handle({
        "jsonrpc": "2.0", "id": 1, "method": "tools/call",
        "params": {"name": "xenia_nonexistent", "arguments": {}},
    })
    assert "error" in reply
    assert call(server, "xenia_report", {"view": "tasks"})["structuredContent"]["rows"]


def test_the_stdio_loop_answers_over_a_pipe(server):
    lines = "\n".join([
        json.dumps({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}}),
        json.dumps({"jsonrpc": "2.0", "method": "notifications/initialized"}),
        json.dumps({"jsonrpc": "2.0", "id": 2, "method": "tools/list"}),
    ])
    out = io.StringIO()
    server.serve(io.StringIO(lines), out)

    replies = [json.loads(line) for line in out.getvalue().splitlines()]
    assert [r["id"] for r in replies] == [1, 2], "the notification must draw no reply"


def test_malformed_json_does_not_kill_the_server():
    out = io.StringIO()
    mcp.Server().serve(io.StringIO("{not json\n"), out)
    assert json.loads(out.getvalue())["error"]["code"] == -32700


def test_no_credential_survives_a_tool_call(server):
    blob = json.dumps([call(server, "xenia_report", {"view": v}) for v in mcp.VIEWS]
                      + [call(server, "xenia_calls"), call(server, "xenia_trace")])
    assert FAKE_GITLAB_PAT not in blob
    assert FAKE_GRAFANA_TOKEN not in blob
    assert ".env" in blob


def test_the_disk_report_names_the_file_without_its_contents(server):
    blob = json.dumps(call(server, "xenia_report", {"view": "disk"}))
    assert ".env" in blob
    assert FAKE_GRAFANA_TOKEN not in blob


def test_the_final_scrub_catches_what_a_query_might_add():
    leaky = {"some_future_column": f"token={FAKE_GITLAB_PAT}"}
    assert "glpat-" not in json.dumps(mcp._scrub(leaky))


def test_file_snippets_are_not_reachable_through_any_tool(server):
    for view in mcp.VIEWS:
        assert "snippet" not in json.dumps(call(server, "xenia_report", {"view": view}))
    assert "snippet" not in json.dumps(call(server, "xenia_calls"))


def test_no_tool_mutates(server):
    tools = server.handle({"jsonrpc": "2.0", "id": 1, "method": "tools/list"})["result"]["tools"]
    forbidden = ("delete", "write", "insert", "update", "rebuild", "resolve", "exec")
    for tool in tools:
        assert not any(word in tool["name"].lower() for word in forbidden)


def test_arguments_cannot_reach_sql(server):
    result = call(server, "xenia_report",
                  {"view": "tasks", "repo": "'; DROP TABLE action; --"})
    assert result["structuredContent"]["rows"] == []
    assert call(server, "xenia_report", {"view": "tasks"})["structuredContent"]["rows"]


def test_a_non_object_arguments_payload_is_rejected(server):
    reply = server.handle({
        "jsonrpc": "2.0", "id": 1, "method": "tools/call",
        "params": {"name": "xenia_report", "arguments": "not-an-object"},
    })
    assert reply["error"]["code"] == -32602


def test_limits_are_capped_regardless_of_what_is_asked_for(server):
    rows = call(server, "xenia_report",
                {"view": "tasks", "limit": 999999})["structuredContent"]["rows"]
    assert len(rows) <= 500
