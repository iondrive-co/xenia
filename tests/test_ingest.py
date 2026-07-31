from __future__ import annotations

import json

import pytest

from conftest import CORE, FAKE_GITLAB_PAT, OPS, make_repo, post, pre

from xenia import classify, ingest


def one(conn, sql, params=()):
    row = conn.execute(sql, params).fetchone()
    return dict(row) if row else None


def test_a_tool_call_produces_one_action_with_an_outcome(conn, clock):
    clock()
    ingest.record(conn, pre("Bash", {"command": "ls -la", "description": "List files"}))
    clock()
    ingest.record(conn, post("Bash", {"command": "ls -la", "description": "List files"}))

    action = one(conn, "SELECT * FROM action")
    assert action["tool"] == "Bash"
    assert action["status"] == "ok"
    assert action["intent"] == "List files"
    assert action["kind"] == "exec"
    assert conn.execute("SELECT COUNT(*) AS n FROM action").fetchone()["n"] == 1


def test_a_reason_argument_is_the_agents_stated_intent(conn, clock):
    args = {"query": "kafka_log_start_offset", "reason": "check whether the "
            "retention change moved the earliest offset forward on the dev primary"}
    clock()
    ingest.record(conn, pre("mcp__acme-prom__prom_query", args))

    action = one(conn, "SELECT * FROM action")
    assert action["intent"] == args["reason"]


def test_a_description_still_wins_over_a_reason(conn, clock):
    clock()
    ingest.record(conn, pre("Bash", {"command": "ls", "description": "look around",
                                     "reason": "because"}))
    assert one(conn, "SELECT intent FROM action")["intent"] == "look around"


def test_a_promoted_reason_is_not_also_repeated_in_the_detail(conn, clock):
    reason = "confirm the scrape is still running"
    clock()
    ingest.record(conn, pre("mcp__acme-prom__prom_query",
                            {"query": "up", "reason": reason}))
    action = one(conn, "SELECT intent, detail FROM action")
    assert action["intent"] == reason
    assert reason not in action["detail"]
    assert "up" in action["detail"], "the arguments themselves are still recorded"


def test_a_non_string_reason_is_ignored(conn, clock):
    clock()
    ingest.record(conn, pre("mcp__thing__do", {"reason": {"code": 7}}))
    assert one(conn, "SELECT intent FROM action")["intent"] is None


def test_pre_and_post_are_paired_not_double_counted(conn, clock):
    args = {"command": "curl https://x.test"}
    clock()
    ingest.record(conn, pre("Bash", args))
    clock()
    ingest.record(conn, post("Bash", args, ok=False))

    assert conn.execute("SELECT COUNT(*) AS n FROM action").fetchone()["n"] == 1
    assert one(conn, "SELECT status FROM action")["status"] == "error"


def test_two_identical_calls_stay_separate(conn, clock):
    args = {"command": "./gradlew test"}
    for _ in range(2):
        clock()
        ingest.record(conn, pre("Bash", args))
    clock()
    ingest.record(conn, post("Bash", args, ok=False))
    clock()
    ingest.record(conn, post("Bash", args, ok=True))

    statuses = [r["status"] for r in conn.execute("SELECT status FROM action ORDER BY seq")]
    assert statuses == ["error", "ok"]


def test_a_remote_call_gets_a_remote_row(conn, clock):
    clock()
    ingest.record(conn, pre("Bash", {
        "command": "curl -X POST -d '{}' https://api.production.example.com/v1/deploy"
    }))

    remote = one(conn, "SELECT * FROM remote_call")
    assert remote["channel"] == "http"
    assert remote["environment"] == "production"
    assert remote["mutating"] == 1
    assert one(conn, "SELECT kind FROM action")["kind"] == "remote_call"


def test_a_file_write_gets_an_fs_row_with_a_content_hash(conn, clock):
    clock()
    ingest.record(conn, pre("Write", {
        "file_path": f"{CORE}/src/app.py", "content": "print('hi')\n",
    }))

    change = one(conn, "SELECT * FROM fs_change")
    assert change["op"] == "create"
    assert change["bytes_after"] == 12
    assert change["sha256_after"]
    assert change["snippet"] == "print('hi')\n"


def test_an_existing_file_is_a_modify_not_a_create(conn, clock, tmp_path):
    target = tmp_path / "already-there.py"
    target.write_text("old\n")
    clock()
    ingest.record(conn, pre("Write", {"file_path": str(target), "content": "new\n"}))
    assert one(conn, "SELECT op FROM fs_change")["op"] == "modify"


def test_one_command_can_record_several_changed_paths(conn, clock):
    clock()
    ingest.record(conn, pre("Bash", {"command": "rm -f a.txt b.txt c.txt"}))
    paths = [r["path"] for r in conn.execute("SELECT path FROM fs_change ORDER BY path")]
    assert paths == ["a.txt", "b.txt", "c.txt"]


def test_mcp_tools_are_recorded_as_remote_calls_with_the_broker_named(conn, clock):
    clock()
    ingest.record(conn, pre("mcp__fleet-ssh__shell", {
        "environment": "production", "host": "monitoring-prod-1",
        "command": "systemctl restart grafana",
    }))

    remote = one(conn, "SELECT * FROM remote_call")
    assert remote["via"] == "fleet-ssh"
    assert remote["channel"] == "ssh"
    assert remote["host"] == "monitoring-prod-1"
    assert remote["environment"] == "production"
    assert remote["mutating"] == 1


def test_reads_are_recorded_but_are_not_changes(conn, clock):
    clock()
    ingest.record(conn, pre("Read", {"file_path": f"{CORE}/README.md"}))
    assert one(conn, "SELECT kind FROM action")["kind"] == "fs_read"
    assert conn.execute("SELECT COUNT(*) AS n FROM fs_change").fetchone()["n"] == 0


def test_a_prompt_opens_a_goal_that_later_actions_attach_to(conn, clock):
    clock()
    ingest.record(conn, {
        "hook_event_name": "UserPromptSubmit", "session_id": "s1",
        "cwd": CORE, "prompt": "Fix the failing health check",
    })
    clock()
    ingest.record(conn, pre("Bash", {"command": "ls"}))

    goal = one(conn, "SELECT * FROM goal")
    assert goal["prompt"] == "Fix the failing health check"
    assert one(conn, "SELECT goal_id FROM action")["goal_id"] == goal["id"]


def test_a_call_with_no_completion_is_still_settled(conn, clock):
    """Nothing is left 'started' once the session that made it has ended."""
    clock()
    ingest.record(conn, pre("Bash", {"command": "ssh monitoring-prod-1 uptime"}))
    clock()
    ingest.record(conn, {"hook_event_name": "Stop", "session_id": "s1",
                         "cwd": CORE})

    action = one(conn, "SELECT * FROM action")
    assert action["status"] == "unanswered"
    assert action["ended_at"] is not None


def test_a_call_the_agent_worked_around_reads_as_a_denial(conn, clock):
    clock()
    ingest.record(conn, pre("Bash", {"command": "ssh monitoring-prod-1 uptime"}))
    clock()
    ingest.record(conn, pre("Bash", {"command": "curl https://broker.test/uptime"}))
    clock()
    ingest.record(conn, post("Bash", {"command": "curl https://broker.test/uptime"}))
    clock()
    ingest.record(conn, {"hook_event_name": "Stop", "session_id": "s1",
                         "cwd": CORE})

    rows = conn.execute("SELECT status, error FROM action ORDER BY seq").fetchall()
    assert rows[0]["status"] == "blocked"
    assert rows[0]["error"].startswith("denied —")
    assert rows[1]["status"] == "ok"


def test_a_call_still_in_flight_at_the_end_is_not_called_a_denial(conn, clock):
    clock()
    ingest.record(conn, pre("Bash", {"command": "ssh monitoring-prod-1 uptime"}))
    clock()
    ingest.record(conn, {"hook_event_name": "Stop", "session_id": "s1",
                         "cwd": CORE})

    action = one(conn, "SELECT * FROM action")
    assert action["status"] == "unanswered", \
        "not 'blocked' either — nothing refused it, so nothing here is a failure"
    assert action["error"].startswith("outstanding —")


def test_one_dangling_call_does_not_explain_another(conn, clock):
    clock()
    ingest.record(conn, pre("Bash", {"command": "ssh a-prod-1 uptime"}))
    clock()
    ingest.record(conn, pre("Bash", {"command": "ssh b-prod-1 uptime"}))
    clock()
    ingest.record(conn, {"hook_event_name": "Stop", "session_id": "s1",
                         "cwd": CORE})

    assert [r["error"].split(" —")[0] for r in conn.execute(
        "SELECT error FROM action ORDER BY seq")] == ["outstanding", "outstanding"]


def test_a_post_without_a_pre_is_still_recorded(conn, clock):
    clock()
    ingest.record(conn, post("Bash", {"command": "ls"}))
    action = one(conn, "SELECT * FROM action")
    assert action["status"] == "ok"
    assert "no PreToolUse seen" in action["detail"]


def test_error_shapes_from_both_runtimes_are_understood(conn, clock):
    shapes = [
        {"is_error": True, "stderr": "boom"},
        {"isError": True, "content": "boom"},
        {"error": "something went wrong"},
        {"exit_code": 1, "stdout": ""},
        {"interrupted": True},
    ]
    for i, response in enumerate(shapes):
        args = {"command": f"cmd-{i}"}
        clock()
        ingest.record(conn, pre("Bash", args))
        clock()
        ingest.record(conn, post("Bash", args, response=response))

    statuses = [r["status"] for r in conn.execute("SELECT status FROM action ORDER BY seq")]
    assert statuses == ["error"] * len(shapes)


def test_a_successful_response_is_not_read_as_a_failure(conn, clock):
    args = {"command": "echo hi"}
    clock()
    ingest.record(conn, pre("Bash", args))
    clock()
    ingest.record(conn, post("Bash", args, response={"stdout": "hi", "stderr": "", "exit_code": 0}))
    assert one(conn, "SELECT status FROM action")["status"] == "ok"


def test_secrets_never_reach_the_database(conn, clock):
    token = FAKE_GITLAB_PAT
    clock()
    ingest.record(conn, pre("Bash", {
        "command": f"curl -H 'PRIVATE-TOKEN: {token}' https://gitlab.example.com/api/v4/user"
    }))

    everything = json.dumps([
        dict(r) for r in conn.execute(
            "SELECT payload FROM event UNION ALL SELECT detail FROM action "
            "UNION ALL SELECT snippet FROM fs_change"
        )
    ])
    assert token not in everything
    assert "REDACTED" in everything


def test_a_secret_on_the_command_line_is_redacted_but_still_evidenced(conn, clock):
    clock()
    ingest.record(conn, pre("Bash", {
        "command": f"curl -H 'PRIVATE-TOKEN: {FAKE_GITLAB_PAT}' https://gitlab.test/api"
    }))
    action = one(conn, "SELECT * FROM action")
    assert FAKE_GITLAB_PAT not in action["detail"]
    assert "REDACTED" in action["detail"]


def test_writing_to_the_agents_own_settings_is_recorded_as_a_guardrail_change(conn, clock):
    clock()
    ingest.record(conn, pre("Edit", {
        "file_path": f"{CORE}/.claude/settings.json",
        "old_string": '"allow": []', "new_string": '"allow": ["Bash(ssh:*)"]',
    }))
    assert one(conn, "SELECT sensitivity FROM fs_change")["sensitivity"] == "guardrail"


def test_repo_is_derived_from_the_working_directory(conn, clock, tmp_path):
    repo = tmp_path / "myrepo"
    make_repo(repo)
    (repo / "sub").mkdir()
    clock()
    ingest.record(conn, {"hook_event_name": "SessionStart", "session_id": "s9",
                         "cwd": str(repo / "sub")})

    session = one(conn, "SELECT * FROM session WHERE session_uid = 's9'")
    assert session["repo"] == "myrepo"
    assert session["repo_path"] == str(repo)


def test_agent_is_detected_from_the_transcript_path(conn, clock):
    clock()
    ingest.record(conn, {
        "hook_event_name": "SessionStart", "session_id": "cx1",
        "cwd": OPS,
        "transcript_path": "/home/agent/.codex/sessions/abc.jsonl",
    })
    assert one(conn, "SELECT agent FROM session")["agent"] == "codex"


def test_the_transcript_beats_an_inherited_environment(conn, clock, monkeypatch):
    # codex started from a Claude Code shell inherits CLAUDECODE=1. The
    # transcript path is this session's own; the variable is the parent's.
    monkeypatch.setenv("CLAUDECODE", "1")
    clock()
    ingest.record(conn, {
        "hook_event_name": "SessionStart", "session_id": "cx2", "cwd": OPS,
        "transcript_path": "/home/agent/.codex/sessions/abc.jsonl",
    })

    assert one(conn, "SELECT agent FROM session")["agent"] == "codex"
    assert one(conn, "SELECT agent FROM event")["agent"] == "codex"


def test_a_session_named_wrongly_is_put_right_by_a_later_event(conn, clock,
                                                              monkeypatch):
    monkeypatch.setenv("CLAUDECODE", "1")
    clock()
    ingest.record(conn, {"hook_event_name": "SessionStart",
                         "session_id": "cx3", "cwd": OPS})
    assert one(conn, "SELECT agent FROM session")["agent"] == "claude"

    clock()
    ingest.record(conn, dict(
        pre("Bash", {"command": "ls"}, session="cx3", cwd=OPS),
        transcript_path="/home/agent/.codex/sessions/abc.jsonl"))

    # Every view joins through the session to name the agent, so leaving this
    # would report the whole run as Claude's work.
    assert one(conn, "SELECT agent FROM session")["agent"] == "codex"


def test_an_inline_script_is_not_the_identity_of_the_work(conn, clock):
    body = "import pathlib\nsrc = pathlib.Path('/tmp/a').read_text()\nprint(src)\n"
    clock()
    ingest.record(conn, pre("Bash", {"command": f"python3 -c '{body}'"}))

    signature = one(conn, "SELECT signature FROM action")["signature"]
    assert "pathlib" not in signature, "the program is not the group it belongs to"
    assert signature.startswith("exec:python3:-c ")
    assert len(signature) < 40


def test_a_script_fed_in_as_a_heredoc_is_named_the_same_way(conn, clock):
    clock()
    ingest.record(conn, pre("Bash", {"command":
        "python3 - <<'PY'\nimport pathlib\nprint(pathlib.Path('x'))\nPY"}))

    action = one(conn, "SELECT signature, target, kind FROM action")
    assert action["signature"].startswith("exec:python3:-c ")
    assert "pathlib" not in action["signature"]
    assert action["target"] == "python3 import pathlib", "the label still reads"
    assert action["kind"] == "exec"


def test_two_scripts_in_heredocs_are_two_kinds_of_work(conn, clock):
    for program in ("print(1)", "print(2)"):
        clock()
        ingest.record(conn, pre("Bash", {
            "command": f"python3 - <<'PY'\n{program}\nPY"}))

    sigs = [r["signature"] for r in conn.execute(
        "SELECT signature FROM action ORDER BY id")]
    assert sigs[0] != sigs[1], "not every heredoc script is the same work"


def test_two_different_inline_scripts_are_two_kinds_of_work(conn, clock):
    for program in ("print(1)", "print(2)"):
        clock()
        ingest.record(conn, pre("Bash", {"command": f"python3 -c '{program}'"}))

    sigs = [r["signature"] for r in conn.execute(
        "SELECT signature FROM action ORDER BY id")]
    assert sigs[0] != sigs[1]


def test_the_same_inline_script_twice_is_one_kind_of_work(conn, clock):
    for _ in range(2):
        clock()
        ingest.record(conn, pre("Bash", {"command": "python3 -c 'print(1)'"}))

    sigs = {r["signature"] for r in conn.execute("SELECT signature FROM action")}
    assert len(sigs) == 1


def test_a_greater_than_inside_a_quoted_program_is_not_a_file_write(conn, clock):
    clock()
    ingest.record(conn, pre("Bash", {"command":
        "python3 -c 'for n in xs:\n    if n > 3: print(\"%s -> big\" % n)\n'"}))

    action = one(conn, "SELECT kind FROM action")
    assert action["kind"] == "exec"
    assert conn.execute("SELECT COUNT(*) AS n FROM fs_change").fetchone()["n"] == 0


def test_a_real_redirect_beside_a_quoted_one_is_still_found(conn, clock):
    clock()
    ingest.record(conn, pre("Bash", {"command":
        "echo 'a > b' > /tmp/out.txt"}))

    paths = [r["path"] for r in conn.execute("SELECT path FROM fs_change")]
    assert paths == ["/tmp/out.txt"]


@pytest.mark.parametrize(
    "server,channel,host",
    [
        ("fleet-ssh", "ssh", None),
        ("acme-sftp", "ssh", None),
        ("infra-ansible", "ssh", None),
        ("prod-kubernetes", "cloud", None),
        ("warehouse-postgres", "db", None),
        ("company-github", "http", "api.github.com"),
        ("company-gitlab", "http", None),
        ("alerts-slack", "http", "slack.com"),
        ("metrics-prometheus", "http", None),
        ("some-opaque-name", "mcp", None),
    ],
)
def test_broker_channel_is_read_from_the_server_name(server, channel, host):
    assert ingest.broker_for(server) == (channel, host)


def test_site_config_overrides_the_name_heuristic(site_config):
    assert ingest.broker_for("zeta") == ("mcp", None)
    site_config({"brokers": {"zeta": {"channel": "http", "host": "zeta.example.com"}}})
    assert ingest.broker_for("zeta") == ("http", "zeta.example.com")


def test_site_config_can_describe_a_family_of_brokers_with_a_glob(site_config):
    site_config({"brokers": {"acme-*": {"channel": "ssh"}}})
    assert ingest.broker_for("acme-anything") == ("ssh", None)
    assert ingest.broker_for("other") == ("mcp", None)


def test_site_config_can_correct_a_misread_name(site_config):
    assert ingest.broker_for("notes-sshots") == ("ssh", None)
    site_config({"brokers": {"notes-sshots": {"channel": "mcp"}}})
    assert ingest.broker_for("notes-sshots") == ("mcp", None)


def test_an_unknown_broker_is_still_recorded_as_a_remote_call(conn, clock):
    clock()
    ingest.record(conn, pre("mcp__mystery__do_thing", {"target": "somewhere"}))
    remote = one(conn, "SELECT * FROM remote_call")
    assert remote is not None
    assert remote["via"] == "mystery"
    assert remote["channel"] == "mcp"


def test_a_configured_broker_host_reaches_the_environment_tag(conn, clock, site_config):
    site_config({"brokers": {"zeta": {"channel": "http", "host": "api.production.example.com"}}})
    clock()
    ingest.record(conn, pre("mcp__zeta__deploy", {}))
    remote = one(conn, "SELECT * FROM remote_call")
    assert remote["host"] == "api.production.example.com"
    assert remote["environment"] == "production"
    assert remote["mutating"] == 1


def test_work_outside_any_repo_is_filed_under_general(conn, clock, outside_any_repo):
    clock()
    ingest.record(conn, pre("Bash", {"command": "ls -la"}, cwd=str(outside_any_repo)))

    session = one(conn, "SELECT * FROM session")
    assert session["repo"] == "general"
    assert session["repo_path"] is None


def test_the_general_bucket_is_told_apart_by_a_null_repo_path(conn, clock, tmp_path,
                                                              outside_any_repo):
    real = tmp_path / "general"
    make_repo(real)
    clock()
    ingest.record(conn, pre("Bash", {"command": "ls"}, session="s1", cwd=str(real)))
    clock()
    ingest.record(conn, pre("Bash", {"command": "ls"}, session="s2", cwd=str(outside_any_repo)))

    rows = {r["session_uid"]: r for r in conn.execute("SELECT * FROM session")}
    assert rows["s1"]["repo"] == "general" and rows["s1"]["repo_path"] == str(real)
    assert rows["s2"]["repo"] == "general" and rows["s2"]["repo_path"] is None


def test_a_write_outside_any_repo_is_not_flagged_as_leaving_one(conn, clock, outside_any_repo):
    clock()
    ingest.record(conn, pre("Write", {
        "file_path": str(outside_any_repo / "notes.md"), "content": "hello\n",
    }, cwd=str(outside_any_repo)))

    assert one(conn, "SELECT in_repo FROM fs_change")["in_repo"] == 0
    assert one(conn, "SELECT repo_path FROM session")["repo_path"] is None


def test_a_write_outside_the_working_repo_is_still_distinguishable(conn, clock, tmp_path):
    clock()
    ingest.record(conn, pre("Write", {
        "file_path": str(tmp_path / "elsewhere.md"), "content": "hello\n",
    }, cwd=CORE))

    assert one(conn, "SELECT in_repo FROM fs_change")["in_repo"] == 0
    assert one(conn, "SELECT repo_path FROM session")["repo_path"] is not None


def test_sensitive_paths_are_still_caught_outside_a_repo(conn, clock, outside_any_repo):
    clock()
    ingest.record(conn, pre("Write", {
        "file_path": str(outside_any_repo / ".env"),
        "content": f"TOKEN={FAKE_GITLAB_PAT}\n",
    }, cwd=str(outside_any_repo)))

    assert one(conn, "SELECT sensitivity FROM fs_change")["sensitivity"] == "sensitive"
    assert "REDACTED" in one(conn, "SELECT snippet FROM fs_change")["snippet"]


def test_a_guardrail_edit_to_user_level_config_is_caught(conn, clock, outside_any_repo):
    home = outside_any_repo / "home"
    (home / ".claude").mkdir(parents=True)
    clock()
    ingest.record(conn, pre("Edit", {
        "file_path": str(home / ".claude" / "settings.json"),
        "old_string": "{}", "new_string": '{"permissions": {"allow": ["Bash"]}}',
    }, cwd=str(home)))

    assert one(conn, "SELECT sensitivity FROM fs_change")["sensitivity"] == "guardrail"


def test_a_stray_empty_git_directory_is_not_a_repository(conn, clock, tmp_path,
                                                         outside_any_repo):
    (outside_any_repo / ".git").mkdir()
    work = outside_any_repo / "work"
    work.mkdir()
    clock()
    ingest.record(conn, pre("Bash", {"command": "ls"}, cwd=str(work)))

    assert one(conn, "SELECT * FROM session")["repo"] == "general"


def test_a_worktree_gitdir_pointer_counts_as_a_repository(conn, clock, outside_any_repo):
    tree = outside_any_repo / "feature-branch"
    tree.mkdir()
    (tree / ".git").write_text("gitdir: /srv/repos/core/.git/worktrees/feature-branch\n")
    clock()
    ingest.record(conn, pre("Bash", {"command": "ls"}, cwd=str(tree)))

    session = one(conn, "SELECT * FROM session")
    assert session["repo"] == "feature-branch"
    assert session["repo_path"] == str(tree)


def test_editing_claude_md_is_recorded_as_ordinary_work(conn, clock):
    clock()
    ingest.record(conn, pre("Edit", {
        "file_path": f"{CORE}/CLAUDE.md",
        "old_string": "old guidance", "new_string": "new guidance",
    }))

    change = one(conn, "SELECT path, sensitivity FROM fs_change")
    assert change["path"] == "CLAUDE.md"
    assert change["sensitivity"] == "normal"


def test_editing_settings_json_is_still_a_guardrail_change(conn, clock):
    clock()
    ingest.record(conn, pre("Edit", {
        "file_path": f"{CORE}/.claude/settings.json",
        "old_string": '"allow": []', "new_string": '"allow": ["Bash"]',
    }))

    assert one(conn, "SELECT sensitivity FROM fs_change")["sensitivity"] == "guardrail"


def test_the_size_of_a_reply_is_recorded(conn, clock):
    args = {"command": "kubectl logs deploy/api"}
    flood = "x" * 90_000
    clock()
    ingest.record(conn, pre("Bash", args))
    clock()
    ingest.record(conn, post("Bash", args, response={"stdout": flood}))

    assert one(conn, "SELECT result_bytes FROM action")["result_bytes"] > 90_000


def test_a_reply_is_measured_before_redaction(conn, clock):
    args = {"command": "cat /etc/secrets"}
    clock()
    ingest.record(conn, pre("Bash", args))
    clock()
    ingest.record(conn, post("Bash", args, response={
        "stdout": f"PRIVATE-TOKEN: {FAKE_GITLAB_PAT}"}))

    raw = len(f'{{"stdout": "PRIVATE-TOKEN: {FAKE_GITLAB_PAT}"}}')
    assert one(conn, "SELECT result_bytes FROM action")["result_bytes"] == raw


def test_an_edit_reply_is_measured_without_the_file_it_echoes_back(conn, clock):
    """result_bytes is what floods a context, not what the hook was handed.

    Claude Code returns the whole pre-edit file as 'originalFile'. Sizing it
    made a one-line change to a big file look like a huge reply — the live
    record had 405 KB against a 383 KB src/main.ts whose patch was ~1 KB.
    """
    path = f"{CORE}/big.ts"
    args = {"file_path": path, "old_string": "a", "new_string": "b"}
    whole_file = "x" * 100_000

    clock()
    ingest.record(conn, pre("Edit", args))
    clock()
    ingest.record(conn, post("Edit", args, response={
        "filePath": path, "oldString": "a", "newString": "b",
        "structuredPatch": [{"lines": ["-a", "+b"]}],
        "originalFile": whole_file,
    }))

    measured = one(conn, "SELECT result_bytes FROM action")["result_bytes"]
    assert measured < 200, "the echoed file is not context the agent paid for"


def _transcript(tmp_path, *records) -> str:
    path = tmp_path / "transcript.jsonl"
    path.write_text("\n".join(json.dumps(r) for r in records) + "\n")
    return str(path)


def _denial(use_id: str, kind: str, result: str) -> dict:
    """One transcript record of the shape the runtime writes for a refusal."""
    return {
        "type": "user",
        "toolDenialKind": kind,
        "toolUseResult": result,
        "message": {"content": [
            {"type": "tool_result", "tool_use_id": use_id, "is_error": True,
             "content": result},
        ]},
    }


def test_a_refused_call_records_who_refused_it(conn, clock, tmp_path):
    """Three refusals need three different fixes, so they are not one status.

    No PostToolUse fires for a refused call, so from inside the hook a rule,
    a person and a session that just ended all look identical. The runtime
    writes the difference to the transcript and nowhere else.
    """
    hooked = {"command": "ssh prod-1 uptime"}
    declined = {"command": "rm -rf /tmp/scratch"}
    vanished = {"command": "sleep 600"}

    for use_id, args in (("toolu_rule", hooked), ("toolu_user", declined),
                         ("toolu_none", vanished)):
        clock()
        ingest.record(conn, dict(pre("Bash", args), tool_use_id=use_id))

    clock()
    ingest.record(conn, {
        "hook_event_name": "Stop", "session_id": "s1", "cwd": CORE,
        "transcript_path": _transcript(
            tmp_path,
            _denial("toolu_rule", "permission-rule",
                    "Error: Direct `ssh` from the Bash tool is disabled."),
            _denial("toolu_user", "user-rejected", "User rejected tool use"),
        ),
    })

    rows = {r["detail"]: r for r in conn.execute(
        "SELECT detail, status, blocked_by, error FROM action")}
    rule = rows["ssh prod-1 uptime"]
    user = rows["rm -rf /tmp/scratch"]
    gone = rows["sleep 600"]

    assert (rule["status"], rule["blocked_by"]) == ("blocked", "rule")
    assert "is disabled" in rule["error"], "a rule's reason names the fix"
    assert (user["status"], user["blocked_by"]) == ("blocked", "user")
    assert gone["blocked_by"] is None, "nothing explained this one; do not guess"


def _result(use_id: str, text: str, *, is_error: bool = False) -> dict:
    """A transcript record for a call that ran, with no denial attached."""
    return {"type": "user", "message": {"content": [
        {"type": "tool_result", "tool_use_id": use_id, "is_error": is_error,
         "content": text},
    ]}}


def test_a_call_that_merely_failed_is_not_reported_as_a_denial(conn, clock,
                                                               tmp_path):
    """A missing completion event does not mean somebody refused the call.

    No PostToolUse fires for plenty of ordinary failures, and calling them
    all denials made a hundred rows say 'a PreToolUse hook refused this one'
    over what were really `Exit code 1` and a screenshot timeout. Six in a
    hundred were refusals. The transcript has the real message.
    """
    broke = {"command": "python3 -c 'raise SystemExit(1)'"}
    worked = {"command": "echo fine"}

    for use_id, args in (("toolu_broke", broke), ("toolu_worked", worked)):
        clock()
        ingest.record(conn, dict(pre("Bash", args), tool_use_id=use_id))

    clock()
    ingest.record(conn, {
        "hook_event_name": "Stop", "session_id": "s1", "cwd": CORE,
        "transcript_path": _transcript(
            tmp_path,
            _result("toolu_broke", "Exit code 1\nTraceback (most recent call "
                                   "last):\n  File \"<string>\"", is_error=True),
            _result("toolu_worked", "fine"),
        ),
    })

    rows = {r["detail"]: r for r in conn.execute(
        "SELECT detail, status, blocked_by, error FROM action")}
    broken = rows["python3 -c 'raise SystemExit(1)'"]
    assert (broken["status"], broken["blocked_by"]) == ("error", None)
    assert "Traceback" in broken["error"], "the real message, not a guess"

    fine = rows["echo fine"]
    assert fine["status"] == "ok", "it ran and returned; nothing refused it"


def test_a_real_completion_event_is_never_overwritten(conn, clock, tmp_path):
    """The transcript is the fallback, not the authority.

    A call that got its PostToolUse already has timings and a reply size this
    cannot supply, so it is left exactly as recorded.
    """
    args = {"command": "echo hello"}
    clock()
    ingest.record(conn, dict(pre("Bash", args), tool_use_id="toolu_done"))
    clock()
    ingest.record(conn, dict(post("Bash", args, response={"stdout": "hello"}),
                             tool_use_id="toolu_done"))

    clock()
    ingest.record(conn, {
        "hook_event_name": "Stop", "session_id": "s1", "cwd": CORE,
        "transcript_path": _transcript(
            tmp_path, _result("toolu_done", "nonsense", is_error=True)),
    })

    row = one(conn, "SELECT status, error, result_bytes FROM action")
    assert (row["status"], row["error"]) == ("ok", None)
    assert row["result_bytes"] is not None


def test_a_call_nobody_answered_is_not_scored_as_a_failure(conn, clock):
    """An approval prompt still open at exit is not breakage.

    It used to land as 'blocked', which put a row in every failures query
    that no fix would ever clear.
    """
    clock()
    ingest.record(conn, pre("Bash", {"command": "sleep 600"}))
    clock()
    ingest.record(conn, {"hook_event_name": "Stop", "session_id": "s1",
                         "cwd": CORE})

    row = one(conn, "SELECT status, error FROM action")
    assert row["status"] == "unanswered"
    assert "outstanding" in row["error"]


def test_a_refusal_is_explained_after_the_fact_too(conn, clock, tmp_path):
    """Classifying only new refusals leaves every row an audit reads null.

    A session already closed has its blocked calls settled by inference. The
    transcript still says who refused them, so a later pass can improve the
    row it could not explain at the time.
    """
    args = {"command": "ssh prod-1 uptime"}
    clock()
    ingest.record(conn, dict(pre("Bash", args), tool_use_id="toolu_late"))
    clock()
    ingest.record(conn, pre("Bash", {"command": "echo carried on"}))
    clock()
    ingest.record(conn, post("Bash", {"command": "echo carried on"}))
    clock()
    ingest.record(conn, {"hook_event_name": "Stop", "session_id": "s1",
                         "cwd": CORE})

    inferred = one(conn, "SELECT status, blocked_by, error FROM action "
                         "WHERE detail = 'ssh prod-1 uptime'")
    assert (inferred["status"], inferred["blocked_by"]) == ("blocked", None)
    assert "denied" in inferred["error"], "inference is all it had"

    settled = ingest.apply_outcomes(conn, 1, _transcript(
        tmp_path,
        _denial("toolu_late", "permission-rule",
                "Error: Direct `ssh` from the Bash tool is disabled."),
    ))

    after = one(conn, "SELECT status, blocked_by, error FROM action "
                      "WHERE detail = 'ssh prod-1 uptime'")
    assert settled == 1
    assert (after["status"], after["blocked_by"]) == ("blocked", "rule")
    assert "is disabled" in after["error"], "the placeholder gave way"


def test_a_missing_transcript_leaves_the_inferred_answer_alone(conn, clock):
    clock()
    ingest.record(conn, dict(pre("Bash", {"command": "ssh prod-1 uptime"}),
                             tool_use_id="toolu_x"))
    clock()
    ingest.record(conn, {"hook_event_name": "Stop", "session_id": "s1",
                         "cwd": CORE, "transcript_path": "/no/such/file.jsonl"})

    row = one(conn, "SELECT status, blocked_by, error FROM action")
    assert row["status"] == "unanswered" and row["blocked_by"] is None
    assert "outstanding" in row["error"]


def test_an_absent_reply_is_not_zero_bytes(conn, clock):
    clock()
    ingest.record(conn, pre("Bash", {"command": "ls"}))

    assert one(conn, "SELECT result_bytes FROM action")["result_bytes"] is None
    assert ingest.response_bytes({"tool_response": ""}) == 0


def test_a_wrapper_spawn_is_attributed_to_its_broker_end_to_end(conn, clock):
    clock()
    ingest.record(conn, pre("Bash", {"command":
        "printf '%s\\n' '{\"jsonrpc\":\"2.0\",\"method\":\"tools/call\"}' "
        "| ~/.local/bin/acme-gitlab-mcp | tail -1"}))

    action = one(conn, "SELECT kind FROM action")
    assert action["kind"] == "exec", "a binary ran; what it reached is unknown"
    remote = one(conn, "SELECT via, channel FROM remote_call")
    assert remote["via"] == "acme-gitlab"
    assert remote["channel"] == classify.MCP_SPAWN_CHANNEL


def test_a_spawn_that_also_writes_a_file_is_still_a_spawn(conn, clock):
    clock()
    ingest.record(conn, pre("Bash", {"command":
        "make install && printf '%s\\n' '{\"jsonrpc\":\"2.0\"}' "
        "| ~/.local/bin/acme-gitlab-mcp > /tmp/reply.json"}))

    action = one(conn, "SELECT kind, signature FROM action")
    assert action["signature"] == "remote:mcp_spawn:stdio"
    assert action["kind"] == "exec", "the scratch file is not what the call was"
    paths = [r["path"] for r in conn.execute("SELECT path FROM fs_change")]
    assert paths == ["/tmp/reply.json"], "and it is still recorded"


def test_a_compound_command_is_not_named_after_cd(conn, clock):
    clock()
    ingest.record(conn, pre("Bash", {"command":
        'cd /srv/core && echo "=== migrating ===" && alembic upgrade head'}))

    assert one(conn, "SELECT label FROM task")["label"] == "alembic upgrade"


def test_a_command_that_only_moves_still_gets_its_name(conn, clock):
    clock()
    ingest.record(conn, pre("Bash", {"command": "cd /srv/core"}))

    assert one(conn, "SELECT label FROM task")["label"] == "cd /srv/core"


def test_a_fragment_of_shell_syntax_is_never_a_task_name(conn, clock):
    clock()
    ingest.record(conn, pre("Bash", {"command":
        'cmd=$(ps -o args= -p 1); printf "%s" "${cmd:0:70}"'}))

    label = one(conn, "SELECT label FROM task")["label"]
    assert "${" not in label and '"' not in label, label


def test_a_target_that_only_restates_the_tool_is_dropped(conn, clock):
    # Separate sessions: within one, consecutive unnamed work is a single task,
    # and only the call that opened it gets to name it.
    clock()
    ingest.record(conn, pre("ToolSearch", {"query": "select:Read"}, session="s1"))
    clock()
    ingest.record(conn, pre("mcp__xenia__xenia_summary", {"since": "24h"},
                            session="s2"))

    labels = {r["label"] for r in conn.execute("SELECT label FROM task")}
    assert "ToolSearch" in labels
    assert "mcp__xenia__xenia_summary" in labels


def test_an_mcp_label_keeps_the_host_it_reached(conn, clock):
    clock()
    ingest.record(conn, pre("mcp__acme-ssh__shell",
                            {"host": "app-07.example.com", "command": "uptime"}))

    label = one(conn, "SELECT label FROM task")["label"]
    assert label == "mcp__acme-ssh__shell -> app-07.example.com", label


def test_an_mcp_reply_is_weighed_like_any_other(conn, clock):
    args = {"host": "app-07", "command": "cat /var/log/app.log",
            "reason": "read the tail of the log"}
    clock()
    ingest.record(conn, pre("mcp__acme-ssh__shell", args))
    clock()
    ingest.record(conn, post("mcp__acme-ssh__shell", args, response={
        "content": [{"type": "text", "text": "z" * 40_000}]}))

    assert one(conn, "SELECT result_bytes FROM action")["result_bytes"] > 40_000


def test_a_bare_verb_is_not_a_label(conn, clock):
    clock()
    ingest.record(conn, pre("Bash", {"command": "nl ~/.ssh/known_hosts"}))

    assert one(conn, "SELECT label FROM task")["label"] == "nl ~/.ssh/known_hosts"


def test_one_command_is_one_task_whichever_runtime_ran_it(conn, clock):
    clock()
    ingest.record(conn, pre("Bash", {"command": "git status --short"}))
    clock()
    ingest.record(conn, pre("shell", {"command": "git status --short"}))

    assert {r["label"] for r in conn.execute("SELECT label FROM task")} \
        == {"git status"}
    assert [r["kind"] for r in conn.execute("SELECT kind FROM action ORDER BY id")] \
        == ["exec", "exec"]


def test_a_script_passed_inline_does_not_become_the_label(conn, clock):
    clock()
    ingest.record(conn, pre("Bash", {"command":
        "python3 -c 'import sqlite3\nfor row in db:\n    print(row)\n'"}))

    label = one(conn, "SELECT label FROM task")["label"]
    assert label == "python3 import sqlite3"


def test_a_tool_that_is_not_a_shell_keeps_its_name(conn, clock):
    clock()
    ingest.record(conn, pre("Edit", {"file_path": f"{CORE}/CLAUDE.md",
                                     "old_string": "a", "new_string": "b"}))

    assert one(conn, "SELECT label FROM task")["label"] == "Edit CLAUDE.md"


def test_two_commands_sharing_a_cd_are_not_the_same_work(conn, clock):
    clock()
    ingest.record(conn, pre("Bash", {"command": "cd /srv && pytest -q"}))
    clock()
    ingest.record(conn, pre("Bash", {"command": "cd /srv && ruff check ."}))

    sigs = [r["signature"] for r in conn.execute("SELECT signature FROM action ORDER BY id")]
    assert sigs[0] != sigs[1], "the cd is not what either command is"
    assert "pytest" in sigs[0] and "ruff" in sigs[1]
