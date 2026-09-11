from __future__ import annotations

import io
import json
from datetime import datetime

import pytest
from conftest import CORE, FAKE_GITLAB_PAT, FAKE_GRAFANA_TOKEN, post, pre

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
        "xenia_report", "xenia_calls", "xenia_trace", "xenia_fetch",
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


def test_the_instruction_is_carried_once_not_on_every_task_row(conn, clock,
                                                               tmp_path):
    clock()
    prompt = "add a byte budget to the loki renderer, and keep the tests green"
    ingest.record(conn, {"hook_event_name": "UserPromptSubmit",
                         "session_id": "s1", "cwd": CORE, "prompt": prompt})
    for name in ("alpha", "beta", "gamma"):
        clock()
        ingest.record(conn, pre("Bash", {"command": f"./{name}.sh",
                                         "description": f"run {name}"}))
    conn.commit()

    payload = call(mcp.Server(tmp_path / "audit.db"),
                   "xenia_report", {"view": "tasks"})["structuredContent"]

    assert len(payload["rows"]) == 3
    assert not any("goal_summary" in row for row in payload["rows"])
    assert list(payload["instructions"].values()) == [prompt]
    goal = next(iter(payload["instructions"]))
    assert {str(row["goal_id"]) for row in payload["rows"]} == {goal}


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


def test_a_reply_over_the_ceiling_is_cut_rather_than_discarded(conn, clock,
                                                               tmp_path,
                                                               monkeypatch):
    # Rows carrying whole shell commands: a few hundred of them is past any
    # client's ceiling, and the client's answer to that is to drop the reply
    # whole rather than shorten it.
    for i in range(300):
        clock()
        ingest.record(conn, pre("Bash", {"command": f"echo {'x' * 400} {i}"}))
    conn.commit()
    monkeypatch.setattr(mcp.config, "REPLY_LIMIT", 8000)

    result = call(mcp.Server(tmp_path / "audit.db"), "xenia_calls",
                  {"tool": "Bash", "limit": 300})
    payload = result["structuredContent"]

    assert len(mcp._compact(payload)) <= 8000
    assert 0 < len(payload["calls"]) < 300
    assert payload["truncated"]["rows_returned"] == len(payload["calls"])
    assert payload["truncated"]["rows_dropped"] == 300 - len(payload["calls"])
    # The text copy is the same answer, so it has to have been cut too.
    assert json.loads(result["content"][0]["text"]) == payload


def test_a_reply_within_the_ceiling_says_nothing_about_truncation(server):
    for view in mcp.VIEWS:
        payload = call(server, "xenia_report", {"view": view})["structuredContent"]
        assert "truncated" not in payload
    assert "truncated" not in call(server, "xenia_calls")["structuredContent"]


def test_trimming_tasks_drops_the_instructions_left_with_no_rows(conn, clock,
                                                                 tmp_path,
                                                                 monkeypatch):
    for i in range(60):
        clock()
        ingest.record(conn, {
            "hook_event_name": "UserPromptSubmit", "session_id": f"s{i}",
            "cwd": CORE, "prompt": f"instruction number {i} " + "y" * 600,
        })
        clock()
        ingest.record(conn, pre("Bash", {"command": f"echo {i}"},
                                session=f"s{i}"))
    conn.commit()
    monkeypatch.setattr(mcp.config, "REPLY_LIMIT", 6000)

    payload = call(mcp.Server(tmp_path / "audit.db"), "xenia_report",
                   {"view": "tasks", "limit": 200})["structuredContent"]

    assert payload["truncated"]["rows_dropped"] > 0
    kept = {str(r["goal_id"]) for r in payload["rows"] if r.get("goal_id")}
    assert set(payload.get("instructions", {})) <= kept
    assert len(mcp._compact(payload)) <= 6000


def test_the_reply_is_not_padded_with_indentation(server):
    text = call(server, "xenia_report", {"view": "tools"})["content"][0]["text"]
    assert "\n" not in text
    assert ": " not in text.replace('": "', '":"')


def test_every_reply_says_what_time_it_is(server):
    for payload in (call(server, "xenia_report", {"view": "tasks"}),
                    call(server, "xenia_calls"),
                    call(server, "xenia_trace", {"action_id": 1})):
        answer = payload["structuredContent"]
        assert answer["now"].endswith("Z"), "the record is UTC and says so"
        # The same instant on the other clock the reader has: their shell,
        # their logs, their file mtimes.
        assert (datetime.fromisoformat(answer["now"].replace("Z", "+00:00"))
                == datetime.fromisoformat(answer["now_local"]))


def test_a_cut_reply_names_the_order_it_kept_the_top_of(conn, clock, tmp_path,
                                                        monkeypatch):
    # One failure, buried under a page of the one-action successes that fill
    # any real window, and then cut down to what fits.
    bad = {"command": "curl https://nope.test", "description": "reach the API"}
    clock()
    ingest.record(conn, pre("Bash", bad))
    clock()
    ingest.record(conn, post("Bash", bad, ok=False))
    for i in range(60):
        args = {"command": f"sed -n '{i}p' notes.md",
                "description": f"read part {i} " + "x" * 200}
        clock()
        ingest.record(conn, pre("Bash", args))
        clock()
        ingest.record(conn, post("Bash", args))
    clock()
    ingest.record(conn, {"hook_event_name": "Stop", "session_id": "s1",
                         "cwd": CORE})
    conn.commit()
    monkeypatch.setattr(mcp.config, "REPLY_LIMIT", 6000)

    payload = call(mcp.Server(tmp_path / "audit.db"),
                   "xenia_report", {"view": "tasks"})["structuredContent"]

    assert payload["truncated"]["rows_dropped"] > 0
    # The row the question was about is the row that survived the cut.
    assert payload["rows"][0]["status"] == "failed"
    # And the note describes the order the rows were really in, rather than
    # promising a significance the view might not have been sorted by.
    assert payload["ordered_by"] in payload["truncated"]["advice"]
    assert "failed" in payload["ordered_by"]


def test_a_timeline_says_it_is_a_timeline(server):
    payload = call(server, "xenia_report",
                   {"view": "tasks", "order": "at"})["structuredContent"]
    assert payload["ordered_by"] == "most recent first"


def test_the_orders_the_other_views_use_are_named_too(server):
    for view, expected in (("failures", "recovered"), ("tools", "highest"),
                           ("disk", "highest"), ("repeats", "highest"),
                           ("instructions", "recent")):
        payload = call(server, "xenia_report", {"view": view})["structuredContent"]
        assert expected in payload["ordered_by"], view
    assert call(server, "xenia_calls",
                {"order": "at"})["structuredContent"]["ordered_by"] == (
        "most recent first")


def test_failures_can_be_grouped_by_cause_and_searched(server):
    payload = call(server, "xenia_report",
                   {"view": "failures", "group_by": "cause",
                    "search": "nothing matches this"})["structuredContent"]
    assert payload["group_by"] == "cause"
    assert payload["rows"] == []


def test_a_grouping_no_view_offers_is_still_refused(server):
    reply = server.handle({
        "jsonrpc": "2.0", "id": 1, "method": "tools/call",
        "params": {"name": "xenia_report",
                   "arguments": {"view": "failures", "group_by": "host"}},
    })
    assert "cause" in reply["error"]["message"]


def test_a_cut_reply_does_not_still_claim_the_rows_it_dropped():
    """The row count is there to stop a page reading as the whole window.

    So it has to survive being one of the things the cut changed: a reply
    trimmed from 500 rows to 48 that still says 500 is worse than one that
    says nothing, because the number is the part a reader trusts.
    """
    payload = {
        "view": "tasks",
        "ordered_by": "failed first",
        "totals": {"tasks_in_window": 900, "matched_by_this_query": 500,
                   "rows_returned": 500},
        "rows": [{"task_id": i, "note": "x" * 200} for i in range(500)],
    }
    cut = mcp._fit(payload, 4000)

    assert "truncated" in cut
    assert cut["totals"]["rows_returned"] == len(cut["rows"]) < 500
    assert cut["totals"]["tasks_in_window"] == 900, "the window itself is unchanged"


# -- credentials ------------------------------------------------------------

def test_the_credentials_view_reports_policy_without_any_value(server, conn):
    from xenia import broker

    broker.register(conn, "gitlab-pat", backend="memory",
                    hosts=["gitlab.example.com"], methods=["GET"])
    broker.grant(conn, "gitlab-pat", "gitlab.example.com", source="test")
    conn.commit()

    answer = json.loads(call(server, "xenia_report",
                             {"view": "credentials"})["content"][0]["text"])
    row = answer["rows"][0]
    assert row["name"] == "gitlab-pat"
    assert row["hosts"] == ["gitlab.example.com"]
    assert row["usable_now"] is True
    assert "value" not in row


def test_a_credential_name_comes_back_as_the_user_typed_it(server, conn):
    """The name is the handle. xenia_fetch takes it, and the page posts it.

    So a name is kept whatever it happens to contain, while everything the
    user wrote beside it is still redacted: a blanked name leaves the caller
    nothing to ask for and the page nothing to rename or remove.
    """
    from xenia import broker

    name = f"gitlab {FAKE_GITLAB_PAT}"
    broker.register(conn, name, backend="memory",
                    hosts=["gitlab.example.com"],
                    note=f"rotate this with {FAKE_GITLAB_PAT}")
    conn.commit()

    answer = json.loads(call(server, "xenia_report",
                             {"view": "credentials"})["content"][0]["text"])
    row = answer["rows"][0]
    assert row["name"] == name
    assert FAKE_GITLAB_PAT not in row["note"]


def test_the_credentials_view_takes_no_filters(server):
    reply = server.handle({
        "jsonrpc": "2.0", "id": 1, "method": "tools/call",
        "params": {"name": "xenia_report",
                   "arguments": {"view": "credentials", "session": "s1"}}})

    assert "session" in reply["error"]["message"]


def test_fetch_asks_for_a_url_and_a_name_and_explains_the_placeholder():
    tool = next(t for t in mcp.TOOLS if t["name"] == "xenia_fetch")

    assert tool["inputSchema"]["required"] == ["url", "secret"]
    assert "{{secret}}" in tool["description"]
    assert "{{sign}}" in tool["description"]
    # Short enough to be read: this was 2,900 characters of prose once.
    assert len(tool["description"]) < 1200


def test_fetch_goes_to_the_service_and_never_opens_the_store(server, monkeypatch):
    from xenia import broker

    seen = {}

    def pretend(payload, **kwargs):
        seen.update(payload)
        return {"status": 200, "body": "{}", "url": payload["url"]}

    monkeypatch.setattr(broker, "request", pretend)
    answer = json.loads(call(server, "xenia_fetch", {
        "url": "https://gitlab.example.com/api/v4/user",
        "secret": "gitlab-pat",
        "headers": {"PRIVATE-TOKEN": "{{secret}}"},
    })["content"][0]["text"])

    assert seen["op"] == "fetch"
    assert seen["secret"] == "gitlab-pat"
    assert answer["status"] == 200


def test_fetch_says_plainly_when_the_service_is_not_running(server, monkeypatch):
    from xenia import broker

    def absent(payload, **kwargs):
        raise broker.BrokerError("the xenia service is not listening at /x")

    monkeypatch.setattr(broker, "request", absent)
    answer = json.loads(call(server, "xenia_fetch", {
        "url": "https://gitlab.example.com/api/v4/user",
        "secret": "gitlab-pat",
    })["content"][0]["text"])

    assert "not listening" in answer["refused"]
