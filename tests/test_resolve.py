from __future__ import annotations

from conftest import CORE, FAKE_GRAFANA_TOKEN, OPS, post, pre

from xenia import ingest, resolve


def run(conn, clock, tool, args, *, ok=True, session="s1", cwd=CORE):
    clock()
    ingest.record(conn, pre(tool, args, session=session, cwd=cwd))
    clock()
    ingest.record(conn, post(tool, args, ok=ok, session=session, cwd=cwd))


def prompt(conn, clock, text, session="s1", cwd=CORE):
    clock()
    ingest.record(conn, {"hook_event_name": "UserPromptSubmit", "session_id": session,
                         "cwd": cwd, "prompt": text})


def stop(conn, clock, session="s1", cwd=CORE):
    clock()
    ingest.record(conn, {"hook_event_name": "Stop", "session_id": session, "cwd": cwd})


def actions(conn):
    return [dict(r) for r in conn.execute("SELECT * FROM action ORDER BY seq")]


def test_a_failure_links_to_the_retry_that_worked(conn, clock):
    prompt(conn, clock, "Get the tests passing")
    run(conn, clock, "Bash", {"command": "./gradlew test"}, ok=False)
    run(conn, clock, "Edit", {"file_path": f"{CORE}/src/app.py",
                              "new_string": "fixed"})
    run(conn, clock, "Bash", {"command": "./gradlew test"}, ok=True)
    stop(conn, clock)

    rows = actions(conn)
    failure, fix = rows[0], rows[2]
    assert failure["status"] == "error"
    assert failure["resolved_by_action_id"] == fix["id"]
    assert failure["resolution_span"] == 1
    assert failure["attempt_no"] == 1
    assert fix["attempt_no"] == 2


def test_an_unrelated_success_is_not_treated_as_a_fix(conn, clock):
    prompt(conn, clock, "Do two unrelated things")
    run(conn, clock, "Bash", {"command": "./gradlew test"}, ok=False)
    run(conn, clock, "Bash", {"command": "git status"}, ok=True)
    stop(conn, clock)

    failure = actions(conn)[0]
    assert failure["resolved_by_action_id"] is None


def test_a_failure_fixed_under_a_later_instruction_is_marked_as_such(conn, clock):
    prompt(conn, clock, "Deploy it")
    run(conn, clock, "Bash", {"command": "curl -sS https://x.staging.test/health"}, ok=False)
    prompt(conn, clock, "Wait for the rollout, then try again")
    run(conn, clock, "Bash", {"command": "curl -sS https://x.staging.test/health"}, ok=True)
    stop(conn, clock)

    failure = actions(conn)[0]
    assert failure["resolved_by_action_id"] is not None
    assert failure["crossed_goal"] == 1


def test_a_never_fixed_failure_stays_unresolved(conn, clock):
    prompt(conn, clock, "Try the thing")
    run(conn, clock, "Bash", {"command": "./deploy.sh"}, ok=False)
    stop(conn, clock)

    assert actions(conn)[0]["resolved_by_action_id"] is None


def test_only_the_first_later_success_is_credited(conn, clock):
    prompt(conn, clock, "Retry until it works")
    run(conn, clock, "Bash", {"command": "./flaky.sh"}, ok=False)
    run(conn, clock, "Bash", {"command": "./flaky.sh"}, ok=True)
    run(conn, clock, "Bash", {"command": "./flaky.sh"}, ok=True)
    stop(conn, clock)

    rows = actions(conn)
    assert rows[0]["resolved_by_action_id"] == rows[1]["id"]


def test_an_earlier_success_cannot_resolve_a_later_failure(conn, clock):
    prompt(conn, clock, "Run it twice")
    run(conn, clock, "Bash", {"command": "./check.sh"}, ok=True)
    run(conn, clock, "Bash", {"command": "./check.sh"}, ok=False)
    stop(conn, clock)

    rows = actions(conn)
    assert rows[1]["status"] == "error"
    assert rows[1]["resolved_by_action_id"] is None


def test_a_blocked_call_counts_as_a_failure_to_resolve(conn, clock):
    prompt(conn, clock, "Check the prod box")
    clock()
    ingest.record(conn, pre("Bash", {"command": "ssh monitoring-prod-1 uptime"}))
    stop(conn, clock)

    blocked = actions(conn)[0]
    assert blocked["status"] == "blocked"
    assert blocked["resolved_by_action_id"] is None


def test_a_clean_run_is_achieved(conn, clock):
    prompt(conn, clock, "Simple job")
    run(conn, clock, "Bash", {"command": "ls"})
    stop(conn, clock)
    goal = dict(conn.execute("SELECT * FROM goal").fetchone())
    assert goal["status"] == "achieved"


def test_a_recovered_failure_still_counts_as_achieved(conn, clock):
    prompt(conn, clock, "Get the tests passing")
    run(conn, clock, "Bash", {"command": "./gradlew test"}, ok=False)
    run(conn, clock, "Bash", {"command": "./gradlew test"}, ok=True)
    stop(conn, clock)

    goal = dict(conn.execute("SELECT * FROM goal").fetchone())
    assert goal["status"] == "achieved"
    assert "all later resolved" in goal["resolution_note"]


def test_a_run_with_leftover_failures_is_partial(conn, clock):
    prompt(conn, clock, "Do two things")
    run(conn, clock, "Bash", {"command": "ls"}, ok=True)
    run(conn, clock, "Bash", {"command": "./deploy.sh"}, ok=False)
    stop(conn, clock)

    goal = dict(conn.execute("SELECT * FROM goal").fetchone())
    assert goal["status"] == "partial"


def test_a_run_where_nothing_worked_is_failed(conn, clock):
    prompt(conn, clock, "Do the impossible")
    run(conn, clock, "Bash", {"command": "./deploy.sh"}, ok=False)
    stop(conn, clock)
    assert dict(conn.execute("SELECT * FROM goal").fetchone())["status"] == "failed"


def test_an_instruction_with_no_tool_calls_is_marked_as_such(conn, clock):
    prompt(conn, clock, "What does this repo do?")
    stop(conn, clock)
    assert dict(conn.execute("SELECT * FROM goal").fetchone())["status"] == "no_action"


def test_a_fix_in_a_later_session_is_linked_but_flagged(conn, clock, tmp_path):
    repo = OPS
    prompt(conn, clock, "Roll out the token", session="a", cwd=repo)
    run(conn, clock, "Bash", {"command": "ansible-playbook site.yml"},
        ok=False, session="a", cwd=repo)
    stop(conn, clock, session="a", cwd=repo)

    prompt(conn, clock, "Retry yesterday's rollout", session="b", cwd=repo)
    run(conn, clock, "Bash", {"command": "ansible-playbook site.yml"},
        ok=True, session="b", cwd=repo)
    stop(conn, clock, session="b", cwd=repo)

    assert actions(conn)[0]["resolved_by_action_id"] is None

    linked = resolve.resolve_repo(conn, "ops")
    assert linked == 1

    failure = actions(conn)[0]
    assert failure["resolved_by_action_id"] is not None
    assert failure["crossed_session"] == 1


def test_cross_session_linking_respects_the_time_window(conn, clock, monkeypatch):
    repo = OPS
    monkeypatch.setenv("XENIA_FAKE_NOW", "2026-07-01T09:00:00.000+00:00")
    ingest.record(conn, pre("Bash", {"command": "ansible-playbook site.yml"},
                            session="a", cwd=repo))
    ingest.record(conn, post("Bash", {"command": "ansible-playbook site.yml"},
                             ok=False, session="a", cwd=repo))

    monkeypatch.setenv("XENIA_FAKE_NOW", "2026-07-20T09:00:00.000+00:00")
    ingest.record(conn, pre("Bash", {"command": "ansible-playbook site.yml"},
                            session="b", cwd=repo))
    ingest.record(conn, post("Bash", {"command": "ansible-playbook site.yml"},
                             ok=True, session="b", cwd=repo))

    assert resolve.resolve_repo(conn, "ops", within_hours=72) == 0
    assert resolve.resolve_repo(conn, "ops", within_hours=24 * 30) == 1


def test_rebuild_reproduces_the_projections_exactly(conn, clock):
    prompt(conn, clock, "Get the tests passing")
    run(conn, clock, "Bash", {"command": "./gradlew test"}, ok=False)
    run(conn, clock, "Bash", {"command": "./gradlew test"}, ok=True)
    run(conn, clock, "Write", {"file_path": f"{CORE}/x.py", "content": "x = 1\n"})
    stop(conn, clock)

    def snapshot():
        return [
            (r["seq"], r["tool"], r["kind"], r["status"], r["signature"],
             r["resolved_by_action_id"] is not None)
            for r in conn.execute("SELECT * FROM action ORDER BY seq")
        ]

    before = snapshot()
    events_before = conn.execute("SELECT COUNT(*) AS n FROM event").fetchone()["n"]

    resolve.rebuild(conn)

    assert snapshot() == before
    assert conn.execute("SELECT COUNT(*) AS n FROM event").fetchone()["n"] == events_before


def test_rebuild_restores_cross_session_links(conn, clock):
    repo = OPS
    prompt(conn, clock, "Roll it out", session="a", cwd=repo)
    run(conn, clock, "Bash", {"command": "ansible-playbook site.yml"},
        ok=False, session="a", cwd=repo)
    stop(conn, clock, session="a", cwd=repo)
    prompt(conn, clock, "Retry it", session="b", cwd=repo)
    run(conn, clock, "Bash", {"command": "ansible-playbook site.yml"},
        ok=True, session="b", cwd=repo)
    stop(conn, clock, session="b", cwd=repo)

    assert resolve.resolve_repo(conn, "ops") == 1
    counts = resolve.rebuild(conn)

    assert counts["cross_session"] == 1
    failure = actions(conn)[0]
    assert failure["resolved_by_action_id"] is not None
    assert failure["crossed_session"] == 1


def test_rebuild_preserves_the_original_timestamps(conn, clock, monkeypatch):
    monkeypatch.setenv("XENIA_FAKE_NOW", "2026-07-01T09:00:00.000+00:00")
    ingest.record(conn, {"hook_event_name": "UserPromptSubmit", "session_id": "s1",
                         "cwd": CORE, "prompt": "Do the thing"})
    ingest.record(conn, pre("Bash", {"command": "ls"}))
    ingest.record(conn, post("Bash", {"command": "ls"}))
    ingest.record(conn, {"hook_event_name": "Stop", "session_id": "s1",
                         "cwd": CORE})

    before = [r["started_at"] for r in conn.execute("SELECT started_at FROM action")]

    monkeypatch.setenv("XENIA_FAKE_NOW", "2026-09-15T12:00:00.000+00:00")
    resolve.rebuild(conn)

    after = [r["started_at"] for r in conn.execute("SELECT started_at FROM action")]
    assert after == before
    assert all(ts.startswith("2026-07-01") for ts in after)


def test_rebuild_reproduces_the_classification_from_redacted_payloads(conn, clock):
    prompt(conn, clock, "Roll out the token")
    run(conn, clock, "Write", {
        "file_path": f"{CORE}/.env",
        "content": f"GRAFANA_SA_TOKEN={FAKE_GRAFANA_TOKEN}\n",
    })
    run(conn, clock, "Edit", {
        "file_path": f"{CORE}/.claude/settings.json",
        "new_string": '"allow": ["Bash(ssh:*)"]',
    })
    stop(conn, clock)

    def snapshot():
        return sorted(
            (r["path"], r["sensitivity"], r["bytes_after"], r["sha256_after"],
             r["snippet"])
            for r in conn.execute("SELECT * FROM fs_change"))

    before = snapshot()
    sensitivities = sorted(s for _, s, *_ in before)
    assert sensitivities == ["guardrail", "sensitive"]
    assert any("REDACTED" in (snip or "") for *_, snip in before)

    resolve.rebuild(conn)
    assert snapshot() == before


def test_rebuild_reapplies_site_guardrail_patterns(conn, clock, site_config):
    site_config({"guardrail_patterns": [r"(^|/)bin/fleet-"]})
    run(conn, clock, "Edit", {"file_path": f"{CORE}/bin/fleet-checks",
                              "old_string": "DENY=1", "new_string": "DENY=0"})

    def sensitivity():
        row = conn.execute("SELECT sensitivity FROM fs_change").fetchone()
        return row["sensitivity"]

    assert sensitivity() == "guardrail"
    resolve.rebuild(conn)
    assert sensitivity() == "guardrail"


def test_losing_the_site_config_downgrades_a_past_finding_on_rebuild(conn, clock, site_config,
                                                                    monkeypatch, tmp_path):
    from xenia import classify, config as xconfig

    site_config({"guardrail_patterns": [r"(^|/)bin/fleet-"]})
    run(conn, clock, "Edit", {"file_path": f"{CORE}/bin/fleet-checks",
                              "old_string": "DENY=1", "new_string": "DENY=0"})
    assert conn.execute("SELECT sensitivity FROM fs_change").fetchone()["sensitivity"] == "guardrail"

    monkeypatch.setenv("XENIA_CONFIG", str(tmp_path / "gone.json"))
    xconfig.reset_cache()
    classify.reset_cache()
    resolve.rebuild(conn)

    assert conn.execute("SELECT sensitivity FROM fs_change").fetchone()["sensitivity"] == "normal"
    assert "bin/fleet-checks" in conn.execute(
        "SELECT payload FROM event WHERE payload LIKE '%fleet-checks%' LIMIT 1"
    ).fetchone()["payload"]
