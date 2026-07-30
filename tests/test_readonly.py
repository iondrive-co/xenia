from __future__ import annotations

import sqlite3

import pytest
from conftest import CORE, FAKE_AWS_KEY, FAKE_GITLAB_PAT, OPS, post, pre

from xenia import ingest, readonly, resolve


@pytest.fixture
def populated(conn, clock, tmp_path):
    clock()
    ingest.record(conn, pre("Bash", {
        "command": f"curl -H 'PRIVATE-TOKEN: {FAKE_GITLAB_PAT}' "
                   "https://gitlab.example.com/api/v4/user",
    }))
    clock()
    ingest.record(conn, pre("Write", {
        "file_path": f"{CORE}/config/app.yml",
        "content": f"password: hunter2\napi_key: {FAKE_AWS_KEY}\n",
    }))
    clock()
    ingest.record(conn, pre("Bash", {"command": "ls -la"}))
    clock()
    ingest.record(conn, post("Bash", {"command": "ls -la"}))
    conn.commit()
    return conn


@pytest.fixture
def ro(populated, tmp_path):
    handle = readonly.connect(tmp_path / "audit.db")
    yield handle
    handle.close()


def test_the_handle_cannot_write(ro):
    with pytest.raises(sqlite3.OperationalError, match="readonly"):
        ro.execute("DELETE FROM action")


def test_the_handle_cannot_create_tables(ro):
    with pytest.raises(sqlite3.OperationalError, match="readonly"):
        ro.execute("CREATE TABLE sneaky (x INT)")


def test_a_credential_never_appears_in_an_interaction(ro):
    rows = readonly.interactions(ro)
    blob = repr(rows)
    assert FAKE_GITLAB_PAT not in blob
    assert "[REDACTED:GITLAB_PAT]" in blob


def test_file_snippets_are_never_returned(ro, populated):
    stored = populated.execute(
        "SELECT snippet FROM fs_change WHERE snippet IS NOT NULL").fetchall()
    assert stored, "fixture should have captured a snippet to make this meaningful"

    blob = repr(readonly.interactions(ro))
    assert "snippet" not in blob
    assert "hunter2" not in blob
    assert FAKE_AWS_KEY not in blob


def test_the_raw_event_ledger_is_not_exposed(ro):
    for row in readonly.interactions(ro):
        assert "payload" not in row
        assert "digest" not in row


def test_filters_narrow_the_result(ro):
    everything = readonly.interactions(ro)
    remote = readonly.interactions(ro, kind="remote_call")
    assert 0 < len(remote) < len(everything)
    assert {r["kind"] for r in remote} == {"remote_call"}


def test_an_unknown_filter_value_is_ignored_rather_than_erroring(ro):
    assert readonly.interactions(ro, kind="not-a-kind") == readonly.interactions(ro)


def test_search_matches_across_command_and_path(ro):
    assert readonly.interactions(ro, search="gitlab")
    assert readonly.interactions(ro, search="app.yml")
    assert readonly.interactions(ro, search="zzzznope") == []


def test_sorting_is_restricted_to_a_whitelist(ro):
    injected = readonly.interactions(ro, order="a.id; DROP TABLE action")
    assert injected == readonly.interactions(ro, order="at")


def test_sort_direction_is_honoured(ro):
    down = [r["at"] for r in readonly.interactions(ro, order="at", descending=True)]
    up = [r["at"] for r in readonly.interactions(ro, order="at", descending=False)]
    assert down == sorted(down, reverse=True)
    assert up == sorted(up)


def test_the_limit_is_capped(ro):
    assert len(readonly.interactions(ro, limit=10_000)) <= readonly.MAX_LIMIT


def test_since_accepts_relative_windows():
    assert readonly.parse_since("24h")
    assert readonly.parse_since("7d")
    assert readonly.parse_since(None) is None
    assert readonly.parse_since("nonsense") is None


def test_summary_counts_match_the_rows(ro):
    stats = readonly.summary(ro)
    assert stats["actions"] == len(readonly.interactions(ro, limit=readonly.MAX_LIMIT))
    assert stats["fs_changes"] >= 1


LONG_PROMPT = "Roll out the retention change. " + ("paste of an ansible log " * 200)


@pytest.fixture
def wordy(conn, clock, tmp_path):
    clock()
    ingest.record(conn, {"hook_event_name": "UserPromptSubmit",
                         "session_id": "s1", "cwd": CORE, "prompt": LONG_PROMPT})
    for i in range(4):
        clock()
        ingest.record(conn, pre("Bash", {"command": f"echo {i}"}))
        clock()
        ingest.record(conn, post("Bash", {"command": f"echo {i}"}))
    conn.commit()
    handle = readonly.connect(tmp_path / "audit.db")
    yield handle
    handle.close()


def test_the_instruction_is_summarised_on_an_action_row(wordy):
    rows = readonly.interactions(wordy)
    assert rows, "fixture should have recorded actions"
    for row in rows:
        assert "goal_prompt" not in row, "the whole prompt has no business here"
        assert row["goal_id"]
        assert len(row["goal_summary"]) <= readonly.SUMMARY_CHARS + 1
        assert row["goal_summary"].endswith("…")
        assert row["goal_summary"].startswith("Roll out the retention change.")


def test_the_same_holds_for_the_task_report(wordy):
    for row in readonly.tasks(wordy):
        assert "goal_prompt" not in row
        assert len(row["goal_summary"] or "") <= readonly.SUMMARY_CHARS + 1


def test_a_short_instruction_is_not_marked_as_cut(conn, clock, tmp_path):
    clock()
    ingest.record(conn, {"hook_event_name": "UserPromptSubmit", "session_id": "s1",
                         "cwd": CORE, "prompt": "Fix the health check"})
    clock()
    ingest.record(conn, pre("Bash", {"command": "ls"}))
    conn.commit()
    ro = readonly.connect(tmp_path / "audit.db")
    try:
        assert readonly.interactions(ro)[0]["goal_summary"] == "Fix the health check"
    finally:
        ro.close()


def test_the_whole_prompt_is_still_reachable_by_id(wordy):
    goal_id = readonly.interactions(wordy)[0]["goal_id"]
    rows = readonly.goals(wordy, goal_id=goal_id)
    assert len(rows) == 1
    assert rows[0]["prompt"].startswith("Roll out the retention change.")
    assert len(rows[0]["prompt"]) > readonly.SUMMARY_CHARS


def test_a_heredoc_does_not_dominate_the_friction_report(conn, clock, tmp_path):
    args = {"command": "ssh deploy@prod-1 <<'EOF'\n" + ("echo padding\n" * 200) + "EOF"}
    for _ in range(2):
        clock()
        ingest.record(conn, pre("Bash", args))
        clock()
        ingest.record(conn, post("Bash", args, ok=False))
    conn.commit()

    ro = readonly.connect(tmp_path / "audit.db")
    try:
        row = readonly.friction(ro)[0]
        assert row["failures"] == 2
        assert len(row["example"]) <= readonly.EXAMPLE_CHARS + 1
        assert row["example"].endswith("…")
    finally:
        ro.close()


@pytest.fixture
def brokered(conn, clock, tmp_path):
    calls = [
        ("mcp__acme-ssh__shell", {"host": "kafka-dev-1", "command": "uptime",
                                   "reason": "check the broker is up"}),
        ("mcp__acme-prom__prom_query", {"query": "up", "reason": "confirm scrape"}),
        ("mcp__fleet-gitlab__issue", {"project": "core", "reason": "file it"}),
        ("Bash", {"command": "ls", "description": "mcp__acme-ssh__shell"}),
    ]
    for tool, args in calls:
        clock()
        ingest.record(conn, pre(tool, args))
        clock()
        ingest.record(conn, post(tool, args))
    conn.commit()
    handle = readonly.connect(tmp_path / "audit.db")
    yield handle
    handle.close()


def test_a_broker_glob_selects_every_server_at_one_site(brokered):
    rows = readonly.interactions(brokered, via="acme-*")
    assert {r["via"] for r in rows} == {"acme-ssh", "acme-prom"}


def test_a_tool_filter_does_not_match_a_task_that_was_named_after_the_tool(brokered):
    assert {r["tool"] for r in readonly.interactions(brokered, tool="mcp__acme*")} == {
        "mcp__acme-ssh__shell", "mcp__acme-prom__prom_query"}
    assert "Bash" in {r["tool"] for r in readonly.interactions(brokered, search="acme")}


def test_an_exact_tool_name_is_not_treated_as_a_pattern(brokered):
    rows = readonly.interactions(brokered, tool="Bash")
    assert {r["tool"] for r in rows} == {"Bash"}


def test_a_channel_filter_narrows_to_one_kind_of_far_side(brokered):
    assert {r["via"] for r in readonly.interactions(brokered, channel="ssh")} \
        == {"acme-ssh"}


def test_a_signature_filter_drills_in_from_an_aggregate_row(brokered):
    signature = readonly.tool_stats(brokered, group_by="signature")[0]["group"]
    rows = readonly.interactions(brokered, signature=signature)
    assert rows and {r["tool"] for r in rows} == {rows[0]["tool"]}


def test_a_glob_cannot_reach_further_than_a_glob(brokered):
    assert readonly.interactions(brokered, tool="'; DROP TABLE action; --") == []
    assert readonly.interactions(brokered)


def test_tool_stats_counts_without_returning_rows(brokered):
    stats = {row["group"]: row for row in readonly.tool_stats(brokered)}
    assert stats["Bash"]["calls"] == 1
    assert stats["mcp__acme-ssh__shell"]["ok"] == 1
    for row in stats.values():
        assert row["failure_rate"] == 0.0


def test_tool_stats_rates_blocked_calls_as_failures(conn, clock, tmp_path):
    clock()
    ingest.record(conn, pre("Bash", {"command": "ssh prod-1 uptime"}))
    clock()
    ingest.record(conn, pre("Bash", {"command": "curl https://ok.test"}))
    clock()
    ingest.record(conn, post("Bash", {"command": "curl https://ok.test"}))
    clock()
    ingest.record(conn, {"hook_event_name": "Stop", "session_id": "s1", "cwd": CORE})
    conn.commit()

    ro = readonly.connect(tmp_path / "audit.db")
    try:
        row = readonly.tool_stats(ro)[0]
        assert (row["calls"], row["ok"], row["blocked"]) == (2, 1, 1)
        assert row["failure_rate"] == 0.5
    finally:
        ro.close()


def test_tool_stats_percentiles_are_values_a_call_really_took(conn, clock,
                                                              monkeypatch, tmp_path):
    for i, (start, end) in enumerate([("09:00:00", "09:00:01"),
                                      ("09:01:00", "09:01:02"),
                                      ("09:02:00", "09:02:10")]):
        args = {"command": f"sleep {i}"}
        monkeypatch.setenv("XENIA_FAKE_NOW", f"2026-07-27T{start}.000+00:00")
        ingest.record(conn, pre("Bash", args))
        monkeypatch.setenv("XENIA_FAKE_NOW", f"2026-07-27T{end}.000+00:00")
        ingest.record(conn, post("Bash", args))
    conn.commit()

    ro = readonly.connect(tmp_path / "audit.db")
    try:
        row = readonly.tool_stats(ro)[0]
        assert (row["timed"], row["p50_ms"], row["max_ms"]) == (3, 2000, 10_000)
        assert row["total_ms"] == 13_000
    finally:
        ro.close()


def test_tool_stats_groups_by_a_whitelisted_dimension_only(brokered):
    injected = readonly.tool_stats(brokered, group_by="a.tool; DROP TABLE action")
    assert injected == readonly.tool_stats(brokered, group_by="tool")
    assert {r["group"] for r in readonly.tool_stats(brokered, group_by="via")} \
        == {"acme-ssh", "acme-prom", "fleet-gitlab", None}


def test_tool_stats_can_be_sorted_by_what_it_cost(brokered):
    assert readonly.tool_stats(brokered, order="nonsense") \
        == readonly.tool_stats(brokered, order="total_ms")


def test_redundancy_finds_repeated_work_that_never_failed(conn, clock, tmp_path):
    args = {"file_path": f"{CORE}/README.md"}
    for _ in range(4):
        clock()
        ingest.record(conn, pre("Read", args))
        clock()
        ingest.record(conn, post("Read", args))
    conn.commit()

    ro = readonly.connect(tmp_path / "audit.db")
    try:
        assert readonly.friction(ro) == [], "nothing failed, so friction has nothing"
        row = readonly.redundancy(ro)[0]
        assert (row["calls"], row["repeats"]) == (4, 3)
        assert row["distinct_args"] == 1, "the very same call, four times"
        assert row["tool"] == "Read"
    finally:
        ro.close()


def test_redundancy_ignores_repeats_outside_the_window(conn, clock, monkeypatch,
                                                       tmp_path):
    args = {"file_path": f"{CORE}/README.md"}
    for stamp in ("09:00:00", "11:30:00"):
        monkeypatch.setenv("XENIA_FAKE_NOW", f"2026-07-27T{stamp}.000+00:00")
        ingest.record(conn, pre("Read", args))
        ingest.record(conn, post("Read", args))
    conn.commit()

    ro = readonly.connect(tmp_path / "audit.db")
    try:
        assert readonly.redundancy(ro, within_minutes=10) == []
        assert readonly.redundancy(ro, within_minutes=200)[0]["repeats"] == 1
    finally:
        ro.close()


def test_redundancy_does_not_count_a_retry_after_a_failure(conn, clock, tmp_path):
    args = {"command": "pytest -q"}
    clock()
    ingest.record(conn, pre("Bash", args))
    clock()
    ingest.record(conn, post("Bash", args, ok=False))
    clock()
    ingest.record(conn, pre("Bash", args))
    clock()
    ingest.record(conn, post("Bash", args))
    conn.commit()

    ro = readonly.connect(tmp_path / "audit.db")
    try:
        assert readonly.redundancy(ro) == []
        assert readonly.friction(ro, min_failures=1)[0]["failures"] == 1
    finally:
        ro.close()


def test_redundancy_does_not_count_an_agent_restating_its_plan(conn, clock, tmp_path):
    for done in range(3):
        args = {"todos": [{"content": f"step {i}",
                           "status": "completed" if i <= done else "pending"}
                          for i in range(3)]}
        clock()
        ingest.record(conn, pre("TodoWrite", args))
        clock()
        ingest.record(conn, post("TodoWrite", args))
    conn.commit()

    ro = readonly.connect(tmp_path / "audit.db")
    try:
        assert readonly.redundancy(ro) == []
    finally:
        ro.close()


def test_redundancy_keeps_sessions_apart(conn, clock, tmp_path):
    args = {"file_path": f"{CORE}/README.md"}
    for session in ("s1", "s2"):
        clock()
        ingest.record(conn, pre("Read", args, session=session))
        clock()
        ingest.record(conn, post("Read", args, session=session))
    conn.commit()

    ro = readonly.connect(tmp_path / "audit.db")
    try:
        assert readonly.redundancy(ro) == []
    finally:
        ro.close()


def write(conn, clock, path, content, session="s1"):
    args = {"file_path": path, "content": content}
    clock()
    ingest.record(conn, pre("Write", args, session=session))
    clock()
    ingest.record(conn, post("Write", args, session=session))


def test_disk_churn_counts_writes_per_file(conn, clock, tmp_path):
    for i in range(4):
        write(conn, clock, f"{CORE}/notes.md", f"draft {i}\n")
    write(conn, clock, f"{CORE}/other.md", "once\n")
    conn.commit()

    ro = readonly.connect(tmp_path / "audit.db")
    try:
        rows = {r["group"]: r for r in readonly.disk_churn(ro, order="writes")}
        notes = rows[f"{CORE}/notes.md"]
        assert (notes["writes"], notes["rewrites"]) == (4, 3)
        assert rows[f"{CORE}/other.md"]["rewrites"] == 0
    finally:
        ro.close()


def test_disk_churn_separates_rewriting_from_wasting(conn, clock, tmp_path):
    write(conn, clock, f"{CORE}/log.txt", "line one\n")
    write(conn, clock, f"{CORE}/log.txt", "line one\n")
    write(conn, clock, f"{CORE}/log.txt", "line one\n")
    write(conn, clock, f"{CORE}/real.txt", "one\n")
    write(conn, clock, f"{CORE}/real.txt", "two\n")
    conn.commit()

    ro = readonly.connect(tmp_path / "audit.db")
    try:
        rows = {r["group"]: r for r in readonly.disk_churn(ro)}
        assert rows[f"{CORE}/log.txt"]["unchanged"] == 2
        assert rows[f"{CORE}/log.txt"]["wasted_bytes"] == len("line one\n") * 2
        assert rows[f"{CORE}/real.txt"]["rewrites"] == 1
        assert rows[f"{CORE}/real.txt"]["unchanged"] == 0
    finally:
        ro.close()


def test_disk_churn_is_worst_first(conn, clock, tmp_path):
    write(conn, clock, f"{CORE}/small.txt", "x\n")
    write(conn, clock, f"{CORE}/small.txt", "x\n")
    for _ in range(3):
        write(conn, clock, f"{CORE}/big.txt", "y" * 500 + "\n")
    conn.commit()

    ro = readonly.connect(tmp_path / "audit.db")
    try:
        assert readonly.disk_churn(ro)[0]["group"] == f"{CORE}/big.txt"
    finally:
        ro.close()


def test_disk_churn_can_group_by_who_did_the_writing(conn, clock, tmp_path):
    write(conn, clock, f"{CORE}/a.md", "a\n", session="s1")
    write(conn, clock, f"{CORE}/b.md", "b\n", session="s2")
    conn.commit()

    ro = readonly.connect(tmp_path / "audit.db")
    try:
        by_repo = readonly.disk_churn(ro, group_by="repo")
        assert len(by_repo) == 1 and by_repo[0]["writes"] == 2
        assert by_repo[0]["files"] == 2
        assert {r["group"] for r in readonly.disk_churn(ro, group_by="session")} \
            == {"s1", "s2"}
        assert readonly.disk_churn(ro, group_by="nonsense") \
            == readonly.disk_churn(ro, group_by="path")
    finally:
        ro.close()


def test_disk_churn_says_how_much_of_the_volume_it_could_measure(conn, clock,
                                                                 tmp_path):
    write(conn, clock, f"{CORE}/known.txt", "sized\n")
    clock()
    ingest.record(conn, pre("Bash", {"command": f"echo hello > {CORE}/spooled.log"}))
    conn.commit()

    ro = readonly.connect(tmp_path / "audit.db")
    try:
        rows = {r["group"]: r for r in readonly.disk_churn(ro, order="writes")}
        spooled = rows[f"{CORE}/spooled.log"]
        assert (spooled["writes"], spooled["sized_writes"]) == (1, 0)
        assert rows[f"{CORE}/known.txt"]["sized_writes"] == 1
    finally:
        ro.close()


def test_disk_churn_ignores_reads_and_deletions(conn, clock, tmp_path):
    clock()
    ingest.record(conn, pre("Read", {"file_path": f"{CORE}/notes.md"}))
    clock()
    ingest.record(conn, pre("Bash", {"command": f"rm {CORE}/notes.md"}))
    conn.commit()

    ro = readonly.connect(tmp_path / "audit.db")
    try:
        assert readonly.disk_churn(ro) == []
    finally:
        ro.close()


def _call(conn, clock, tool, args, *, ok=True, session="s1", cwd=CORE):
    clock()
    ingest.record(conn, pre(tool, args, session=session, cwd=cwd))
    clock()
    ingest.record(conn, post(tool, args, ok=ok, session=session, cwd=cwd))


@pytest.fixture
def crowded(conn, clock, tmp_path):
    args = {"command": "./gradlew test"}
    edit = {"file_path": f"{CORE}/application-test.yml", "new_string": "db: local"}

    _call(conn, clock, "Bash", args, ok=False)
    for i in range(3):
        _call(conn, clock, "Write", {"file_path": f"{OPS}/panel-{i}.py",
                                     "content": "x"}, session="s2", cwd=OPS)
    _call(conn, clock, "Edit", edit)
    _call(conn, clock, "Bash", args)
    clock()
    ingest.record(conn, {"hook_event_name": "Stop", "session_id": "s1", "cwd": CORE})
    conn.commit()

    handle = readonly.connect(tmp_path / "audit.db")
    yield handle
    handle.close()


def test_a_trace_is_one_sessions_work(crowded):
    failure = readonly.interactions(crowded, status="error")[0]
    out = readonly.trace(crowded, failure["action_id"])

    assert out["session"] == "s1"
    assert out["resolved_by"]
    assert [r["tool"] for r in out["series"]] == ["Bash", "Edit", "Bash"]
    assert out["series_truncated"] is False

    spanned = crowded.execute(
        "SELECT COUNT(*) AS n FROM action WHERE id BETWEEN ? AND ?",
        (out["action_id"], out["resolved_by"])).fetchone()["n"]
    assert spanned > len(out["series"]), \
        "the id range must really cross another session for this to prove anything"


def test_calls_is_the_drill_down_the_grouped_reports_need(ro):
    biggest = readonly.tool_stats(ro, group_by="tool", order="total_bytes")[0]
    rows = readonly.calls(ro, tool=biggest["group"], order="bytes")

    assert rows, "a tool with recorded bytes must have calls behind it"
    assert rows[0]["result_bytes"] == biggest["max_bytes"]
    assert rows[0]["action_id"]


def test_calls_carries_nothing_that_repeats_down_the_rows(ro):
    for row in readonly.calls(ro):
        assert "goal_prompt" not in row
        assert "goal_summary" not in row
        assert "task" not in row
        assert len(str(row["detail"] or "")) <= readonly.CALL_CHARS + 20


def test_calls_sorts_calls_that_never_returned_last(ro, populated):
    populated.execute("UPDATE action SET result_bytes = NULL, status = 'blocked' "
                      "WHERE id = (SELECT MIN(id) FROM action)")
    populated.commit()

    sizes = [r["result_bytes"] for r in readonly.calls(ro, limit=readonly.MAX_LIMIT)]
    assert None in sizes, "fixture must contain an unsized call to prove anything"
    assert sizes[0] is not None
    assert sizes[-1] is None


def test_a_credential_never_appears_in_a_call(ro):
    blob = repr(readonly.calls(ro, limit=readonly.MAX_LIMIT))
    assert FAKE_GITLAB_PAT not in blob
    assert "hunter2" not in blob


def test_friction_hands_out_an_id_that_trace_accepts(crowded):
    row = readonly.friction(crowded, min_failures=1)[0]
    out = readonly.trace(crowded, row["example_action_id"])

    assert out["status"] in ("error", "blocked")
    assert out["resolved_by"], "a recovered failure is preferred: it has a series"
    assert out["series"]


def test_a_trace_does_not_leak_the_internal_session_row_id(crowded):
    out = readonly.trace(crowded, readonly.interactions(crowded, status="error")[0]
                         ["action_id"])
    assert "session_row" not in out


def test_a_fix_in_a_later_session_is_reported_as_two_endpoints(conn, clock, tmp_path):
    args = {"command": "ansible-playbook site.yml"}
    _call(conn, clock, "Bash", args, ok=False, session="a", cwd=OPS)
    clock()
    ingest.record(conn, {"hook_event_name": "Stop", "session_id": "a", "cwd": OPS})
    _call(conn, clock, "Write", {"file_path": f"{OPS}/site.yml", "content": "x"},
          session="b", cwd=OPS)
    _call(conn, clock, "Bash", args, session="b", cwd=OPS)
    clock()
    ingest.record(conn, {"hook_event_name": "Stop", "session_id": "b", "cwd": OPS})
    assert resolve.resolve_repo(conn, "ops") == 1
    conn.commit()

    ro = readonly.connect(tmp_path / "audit.db")
    try:
        failure = ro.execute(
            "SELECT id FROM action WHERE status = 'error'").fetchone()["id"]
        out = readonly.trace(ro, failure)
        assert out["crossed_session"] == 1
        assert [r["session"] for r in out["series"]] == ["a", "b"]
    finally:
        ro.close()


def test_tracing_something_that_was_never_fixed_returns_no_series(conn, clock,
                                                                  tmp_path):
    _call(conn, clock, "Bash", {"command": "ssh nope-1 uptime"}, ok=False)
    clock()
    ingest.record(conn, {"hook_event_name": "Stop", "session_id": "s1", "cwd": CORE})
    conn.commit()

    ro = readonly.connect(tmp_path / "audit.db")
    try:
        out = readonly.trace(ro, 1)
        assert out["status"] == "error"
        assert "series" not in out
    finally:
        ro.close()


def test_tracing_an_action_that_does_not_exist_is_empty_not_an_error(ro):
    assert readonly.trace(ro, 999_999) == {}


def test_redundancy_reports_the_agents_own_reason(conn, clock, tmp_path):
    args = {"query": "up", "reason": "confirm the scrape is still running"}
    for _ in range(2):
        clock()
        ingest.record(conn, pre("mcp__acme-prom__prom_query", args))
        clock()
        ingest.record(conn, post("mcp__acme-prom__prom_query", args))
    conn.commit()

    ro = readonly.connect(tmp_path / "audit.db")
    try:
        row = readonly.redundancy(ro)[0]
        assert row["example_intent"] == "confirm the scrape is still running"
        assert row["repeats"] == 1
    finally:
        ro.close()


def test_the_timeline_carries_and_sorts_by_reply_size(conn, clock):
    small = {"command": "echo hi"}
    huge = {"command": "kubectl logs deploy/api"}
    for args, reply in ((small, "hi"), (huge, "x" * 50_000)):
        clock()
        ingest.record(conn, pre("Bash", args))
        clock()
        ingest.record(conn, post("Bash", args, response={"stdout": reply}))

    rows = readonly.interactions(conn, order="bytes", descending=True)
    assert rows[0]["detail"].endswith("kubectl logs deploy/api")
    assert rows[0]["result_bytes"] > 50_000
    assert rows[-1]["result_bytes"] < 100


def test_tool_stats_totals_the_bytes_a_group_cost(conn, clock):
    args = {"command": "kubectl logs deploy/api"}
    for _ in range(3):
        clock()
        ingest.record(conn, pre("Bash", args))
        clock()
        ingest.record(conn, post("Bash", args, response={"stdout": "y" * 10_000}))

    row = next(r for r in readonly.tool_stats(conn, order="total_bytes")
               if r["group"] == "Bash")
    assert row["calls"] == 3
    assert row["measured"] == 3
    assert row["total_bytes"] > 30_000
    assert row["max_bytes"] == row["p95_bytes"] > 10_000


def test_bytes_and_duration_are_counted_over_their_own_denominators(conn, clock):
    args = {"command": "ls"}
    clock()
    ingest.record(conn, pre("Bash", args))
    clock()
    ingest.record(conn, pre("Bash", args))
    clock()
    ingest.record(conn, post("Bash", args, response={"stdout": "hi"}))

    row = next(r for r in readonly.tool_stats(conn) if r["group"] == "Bash")
    assert row["calls"] == 2
    assert row["measured"] == 1
    assert row["timed"] == 1


def test_a_reader_older_than_the_database_says_so(conn, clock, tmp_path):
    conn.execute("INSERT INTO meta (key, value) VALUES ('schema_version', '99') "
                 "ON CONFLICT (key) DO UPDATE SET value = excluded.value")
    conn.commit()

    exc = sqlite3.OperationalError("no such table: finding")
    explained = readonly.explain_failure(conn, exc)
    assert isinstance(explained, readonly.StaleReader)
    assert "must be restarted" in str(explained)
    assert "no such table: finding" in str(explained), "keeps the original cause"


def test_a_current_reader_gets_the_original_error_unchanged(conn):
    exc = sqlite3.OperationalError("no such column: a.nonsense")
    assert readonly.explain_failure(conn, exc) is exc


def test_a_task_carries_the_bytes_written_under_it(conn, clock):
    args = {"command": "./deploy.sh", "description": "roll out the config"}
    ingest.record(conn, pre("Bash", args))
    ingest.record(conn, post("Bash", args))
    ingest.record(conn, pre("Write", {"file_path": f"{CORE}/a.yml", "content": "x" * 400}))
    ingest.record(conn, pre("Write", {"file_path": f"{CORE}/b.yml", "content": "y" * 600}))

    row = next(r for r in readonly.tasks(conn) if r["label"] == "roll out the config")
    assert row["bytes_written"] == 1000
    assert (row["writes"], row["sized_writes"]) == (2, 2)


def test_an_unmeasurable_write_is_counted_but_not_sized(conn, clock):
    args = {"command": "pg_dump core > /tmp/core.sql", "description": "take a dump"}
    ingest.record(conn, pre("Bash", args))
    ingest.record(conn, post("Bash", args))

    row = next(r for r in readonly.tasks(conn) if r["label"] == "take a dump")
    assert row["writes"] >= 1
    assert row["sized_writes"] == 0
    assert row["bytes_written"] == 0


def test_a_task_that_wrote_nothing_reports_zero_not_null(conn, clock):
    args = {"command": "pytest -q", "description": "run the suite"}
    ingest.record(conn, pre("Bash", args))
    ingest.record(conn, post("Bash", args))

    row = next(r for r in readonly.tasks(conn) if r["label"] == "run the suite")
    assert row["bytes_written"] == 0 and row["writes"] == 0


def test_a_delete_is_not_a_write(conn, clock):
    args = {"command": "rm -f /tmp/old.log", "description": "clean up"}
    ingest.record(conn, pre("Bash", args))
    ingest.record(conn, post("Bash", args))

    row = next(r for r in readonly.tasks(conn) if r["label"] == "clean up")
    assert (row["writes"], row["bytes_written"]) == (0, 0)


def test_a_stale_reader_refuses_before_it_queries(conn):
    conn.execute("INSERT INTO meta (key, value) VALUES ('schema_version', '99') "
                 "ON CONFLICT (key) DO UPDATE SET value = excluded.value")
    conn.commit()

    with pytest.raises(readonly.StaleReader) as info:
        readonly.require_current(conn)
    assert "must be restarted" in str(info.value)


def test_a_current_reader_reports_normally(conn):
    readonly.require_current(conn)


def test_a_database_with_no_version_at_all_is_not_stale(conn):
    conn.execute("DELETE FROM meta WHERE key = 'schema_version'")
    conn.commit()
    readonly.require_current(conn)
