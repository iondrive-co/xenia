from __future__ import annotations

import pytest
from conftest import CORE, post, pre

from xenia import ingest, plan, readonly, resolve


def run(conn, clock, *events):
    for event in events:
        clock()
        ingest.record(conn, event)


def stop(conn, clock, session="s1"):
    clock()
    ingest.record(conn, {"hook_event_name": "Stop", "session_id": session,
                         "cwd": CORE})


def tasks(conn):
    return {row["label"]: row for row in conn.execute(
        "SELECT * FROM v_task_outcomes ORDER BY task_id")}


def todo(items, session="s1"):
    return pre("TodoWrite", {"todos": [
        {"content": text, "status": state} for text, state in items]}, session=session)


@pytest.mark.parametrize("tool,args,expected", [
    ("TodoWrite", {"todos": [{"content": "Fix the tests", "status": "in_progress"}]},
     [("Fix the tests", "in_progress")]),
    ("update_plan", {"plan": [{"step": "Ship it", "status": "completed"}]},
     [("Ship it", "completed")]),
    ("TaskCreate", {"subject": "Add the index", "description": "on session_id"},
     [("Add the index", "pending")]),
    ("TodoWrite", {"todos": [{"content": "A", "status": "in-progress"},
                             {"content": "B", "status": "done"},
                             {"content": "C", "status": "cancelled"}]},
     [("A", "in_progress"), ("B", "completed"), ("C", "dropped")]),
])
def test_the_plan_dialects_read_the_same(tool, args, expected):
    stated = plan.read(tool, args)
    assert [(i.label, i.status) for i in stated.items] == expected


def test_a_created_task_takes_the_id_from_the_reply(conn):
    stated = plan.read("TaskCreate", {"subject": "Add the index"},
                       {"task": {"id": "22", "subject": "Add the index"}})
    assert stated.items[0].external_id == "22"


def test_a_status_only_update_is_matched_by_id(conn, clock):
    run(conn, clock,
        pre("TaskCreate", {"subject": "Add the index"}),
        post("TaskCreate", {"subject": "Add the index"},
             response={"task": {"id": "22"}}),
        pre("TaskUpdate", {"taskId": "22", "status": "completed"}))

    row = conn.execute("SELECT label, declared FROM task").fetchone()
    assert (row["label"], row["declared"]) == ("Add the index", "completed")


def test_a_plan_call_is_not_counted_as_work(conn, clock):
    run(conn, clock, todo([("Write the thing", "in_progress")]))
    assert conn.execute(
        "SELECT COUNT(*) FROM action WHERE task_id IS NOT NULL").fetchone()[0] == 0


def test_actions_land_on_the_item_the_agent_says_it_is_on(conn, clock):
    run(conn, clock,
        todo([("Run the health check", "in_progress"), ("Ship it", "pending")]),
        pre("Bash", {"command": "./gradlew test", "description": "run tests"}),
        post("Bash", {"command": "./gradlew test", "description": "run tests"}))

    row = conn.execute(
        "SELECT t.label FROM action a JOIN task t ON t.id = a.task_id "
        "WHERE a.tool = 'Bash'").fetchone()
    assert row["label"] == "Run the health check"


def test_a_plan_outranks_the_description_on_one_call(conn, clock):
    run(conn, clock,
        todo([("Make the build green", "in_progress")]),
        pre("Bash", {"command": "ls", "description": "look around"}),
        post("Bash", {"command": "ls", "description": "look around"}))

    row = conn.execute(
        "SELECT a.intent, t.label FROM action a JOIN task t ON t.id = a.task_id "
        "WHERE a.tool = 'Bash'").fetchone()
    assert row["label"] == "Make the build green"
    assert row["intent"] == "look around"


def test_without_a_plan_the_description_groups_the_work(conn, clock):
    args = {"command": "./gradlew test", "description": "Run the health check tests"}
    run(conn, clock, pre("Bash", args), post("Bash", args, ok=False),
        pre("Edit", {"file_path": f"{CORE}/application-test.yml",
                     "new_string": "db: local"}),
        post("Edit", {"file_path": f"{CORE}/application-test.yml",
                      "new_string": "db: local"}),
        pre("Bash", args), post("Bash", args))
    stop(conn, clock)

    row = tasks(conn)["Run the health check tests"]
    assert row["source"] == "intent"
    assert row["actions"] == 3
    assert (row["failures"], row["failures_fixed"]) == (1, 1)
    assert row["status"] == "achieved"


def test_with_neither_the_work_is_grouped_by_its_own_shape(conn, clock):
    args = {"file_path": f"{CORE}/notes.md", "content": "hello"}
    run(conn, clock, pre("Write", args), post("Write", args),
        pre("Write", args), post("Write", args))
    stop(conn, clock)

    row = next(iter(tasks(conn).values()))
    assert row["source"] == "signature"
    assert row["actions"] == 2


def test_a_new_instruction_starts_new_work(conn, clock):
    run(conn, clock,
        {"hook_event_name": "UserPromptSubmit", "session_id": "s1",
         "cwd": CORE, "prompt": "first"},
        pre("Bash", {"command": "ls", "description": "look around"}),
        post("Bash", {"command": "ls", "description": "look around"}),
        {"hook_event_name": "UserPromptSubmit", "session_id": "s1",
         "cwd": CORE, "prompt": "second"},
        pre("Write", {"file_path": f"{CORE}/x.md", "content": "hi"}),
        post("Write", {"file_path": f"{CORE}/x.md", "content": "hi"}))

    labels = [r["label"] for r in conn.execute(
        "SELECT t.label FROM action a JOIN task t ON t.id = a.task_id ORDER BY a.id")]
    assert labels[0] == "look around"
    assert labels[1] != "look around"


def test_derived_work_does_not_reopen_a_task_from_an_earlier_instruction(conn, clock):
    args = {"file_path": f"{CORE}/notes.md", "content": "hello"}
    run(conn, clock,
        {"hook_event_name": "UserPromptSubmit", "session_id": "s1",
         "cwd": CORE, "prompt": "write the notes"},
        pre("Write", args), post("Write", args),
        {"hook_event_name": "UserPromptSubmit", "session_id": "s1",
         "cwd": CORE, "prompt": "something else entirely"},
        pre("Write", args), post("Write", args))
    stop(conn, clock)

    rows = conn.execute(
        "SELECT t.id, t.goal_id, COUNT(a.id) AS actions FROM task t "
        "JOIN action a ON a.task_id = t.id GROUP BY t.id ORDER BY t.id").fetchall()
    assert [r["actions"] for r in rows] == [1, 1], "one task per instruction"
    assert len({r["goal_id"] for r in rows}) == 2


def test_a_description_that_repeats_a_plan_item_is_that_item(conn, clock):
    args = {"command": "./deploy.sh", "description": "Cover the eu-west hosts too"}
    run(conn, clock,
        {"hook_event_name": "UserPromptSubmit", "session_id": "s1",
         "cwd": CORE, "prompt": "check the monitoring boxes"},
        todo([("Check the agent versions", "in_progress"),
              ("Cover the eu-west hosts too", "pending")]),
        todo([("Check the agent versions", "completed"),
              ("Cover the eu-west hosts too", "pending")]),
        pre("Bash", args), post("Bash", args))
    stop(conn, clock)

    row = tasks(conn)["Cover the eu-west hosts too"]
    assert row["source"] == "plan"
    assert row["actions"] == 1
    assert row["status"] == "achieved"
    assert conn.execute("SELECT COUNT(*) FROM task").fetchone()[0] == 2


def test_a_repeat_under_the_same_instruction_is_still_one_task(conn, clock):
    args = {"file_path": f"{CORE}/notes.md", "content": "hello"}
    run(conn, clock,
        {"hook_event_name": "UserPromptSubmit", "session_id": "s1",
         "cwd": CORE, "prompt": "write the notes"},
        pre("Write", args), post("Write", args),
        pre("Write", args), post("Write", args))
    stop(conn, clock)

    row = next(iter(tasks(conn).values()))
    assert (row["source"], row["actions"], row["attempts"]) == ("signature", 2, 2)


def test_a_derived_task_stops_collecting_once_it_has_gone_quiet(conn, clock,
                                                               monkeypatch):
    monkeypatch.setenv("XENIA_FAKE_NOW", "2026-07-27T09:11:00.000+00:00")
    args = {"command": "pytest", "description": "Run the suite"}
    ingest.record(conn, pre("Bash", args))
    ingest.record(conn, post("Bash", args))

    monkeypatch.setenv("XENIA_FAKE_NOW", "2026-07-27T10:12:00.000+00:00")
    plan_file = {"file_path": f"{CORE}/PLAN.md", "new_string": "notes"}
    ingest.record(conn, pre("Edit", plan_file))
    ingest.record(conn, post("Edit", plan_file))
    ingest.record(conn, {"hook_event_name": "Stop", "session_id": "s1", "cwd": CORE})

    labels = [r["label"] for r in conn.execute(
        "SELECT t.label FROM action a JOIN task t ON t.id = a.task_id ORDER BY a.id")]
    assert labels[0] == "Run the suite"
    assert labels[1] != "Run the suite"


def test_a_plan_task_keeps_collecting_however_long_the_gap(conn, clock, monkeypatch):
    monkeypatch.setenv("XENIA_FAKE_NOW", "2026-07-27T09:00:00.000+00:00")
    ingest.record(conn, todo([("Migrate the schema", "in_progress")]))
    args = {"file_path": f"{CORE}/1.sql", "content": "ALTER"}
    ingest.record(conn, pre("Write", args))
    ingest.record(conn, post("Write", args))

    monkeypatch.setenv("XENIA_FAKE_NOW", "2026-07-27T11:30:00.000+00:00")
    later = {"file_path": f"{CORE}/2.sql", "content": "ALTER"}
    ingest.record(conn, pre("Write", later))
    ingest.record(conn, post("Write", later))

    assert conn.execute(
        "SELECT COUNT(DISTINCT task_id) AS n FROM action "
        "WHERE task_id IS NOT NULL").fetchone()["n"] == 1


def test_a_plan_survives_a_new_instruction(conn, clock):
    run(conn, clock,
        todo([("Migrate the schema", "in_progress")]),
        {"hook_event_name": "UserPromptSubmit", "session_id": "s1",
         "cwd": CORE, "prompt": "keep going"},
        pre("Write", {"file_path": f"{CORE}/x.sql", "content": "ALTER"}),
        post("Write", {"file_path": f"{CORE}/x.sql", "content": "ALTER"}))

    row = conn.execute(
        "SELECT t.label FROM action a JOIN task t ON t.id = a.task_id "
        "WHERE a.tool = 'Write'").fetchone()
    assert row["label"] == "Migrate the schema"


def test_repeating_a_description_is_the_same_task_again(conn, clock):
    args = {"command": "pytest", "description": "Run the suite"}
    run(conn, clock, pre("Bash", args), post("Bash", args, ok=False),
        pre("Bash", args), post("Bash", args))
    assert conn.execute("SELECT COUNT(*) FROM task").fetchone()[0] == 1


def test_dropping_an_item_from_the_plan_is_recorded(conn, clock):
    run(conn, clock,
        todo([("Keep this", "in_progress"), ("Drop this", "pending")]),
        todo([("Keep this", "in_progress")]))
    stop(conn, clock)

    assert tasks(conn)["Drop this"]["declared"] == "dropped"


def test_an_agent_marking_its_own_work_done_does_not_make_it_so(conn, clock):
    args = {"command": "curl https://prod.example.com", "description": "check prod"}
    run(conn, clock,
        todo([("Verify production", "in_progress")]),
        pre("Bash", args), post("Bash", args, ok=False),
        todo([("Verify production", "completed")]))
    stop(conn, clock)

    row = tasks(conn)["Verify production"]
    assert row["declared"] == "completed"
    assert row["status"] == "failed"
    assert row["overstated"] == 1
    assert "marked this task completed" in row["note"]


def test_a_plan_arriving_after_the_work_still_claims_it(conn, clock):
    args = {"command": "sh check-agents.sh --all-regions",
            "description": "Cover the eu-west hosts too"}
    run(conn, clock,
        {"hook_event_name": "UserPromptSubmit", "session_id": "s1",
         "cwd": CORE, "prompt": "check which boxes are behind"},
        pre("Bash", args), post("Bash", args, ok=False),
        todo([("Cover the eu-west hosts too", "completed")]))
    stop(conn, clock)

    rows = tasks(conn)
    assert len(rows) == 1, "one unit of work, named twice"
    row = rows["Cover the eu-west hosts too"]
    assert (row["source"], row["actions"]) == ("plan", 1)
    assert (row["status"], row["overstated"]) == ("failed", 1)


def test_an_honest_completion_is_not_flagged(conn, clock):
    args = {"command": "pytest", "description": "run"}
    run(conn, clock,
        todo([("Run the suite", "in_progress")]),
        pre("Bash", args), post("Bash", args),
        todo([("Run the suite", "completed")]))
    stop(conn, clock)

    row = tasks(conn)["Run the suite"]
    assert (row["status"], row["overstated"]) == ("achieved", 0)


def test_failures_that_were_all_fixed_still_count_as_achieved(conn, clock):
    args = {"command": "pytest", "description": "run"}
    run(conn, clock,
        pre("Bash", args), post("Bash", args, ok=False),
        pre("Bash", args), post("Bash", args))
    stop(conn, clock)

    row = tasks(conn)["run"]
    assert row["status"] == "achieved"
    assert (row["failures"], row["failures_fixed"], row["attempts"]) == (1, 1, 2)


def test_a_task_left_in_progress_is_abandoned_not_failed(conn, clock):
    run(conn, clock, todo([("Write the docs", "in_progress")]))
    stop(conn, clock)

    row = tasks(conn)["Write the docs"]
    assert row["status"] == "abandoned"
    assert row["actions"] == 0


def test_partial_work_is_not_rounded_up(conn, clock):
    ok = {"command": "ls", "description": "poke about"}
    bad = {"command": "curl https://nope.test", "description": "poke about"}
    run(conn, clock,
        pre("Bash", ok), post("Bash", ok),
        pre("Bash", bad), post("Bash", bad, ok=False))
    stop(conn, clock)

    assert tasks(conn)["poke about"]["status"] == "partial"


def test_tasks_survive_a_rebuild(conn, clock):
    args = {"command": "pytest", "description": "run the suite"}
    run(conn, clock,
        todo([("Make it pass", "in_progress")]),
        pre("Bash", args), post("Bash", args, ok=False),
        todo([("Make it pass", "completed")]))
    stop(conn, clock)

    before = {k: dict(v) for k, v in tasks(conn).items()}
    resolve.rebuild(conn)
    after = {k: dict(v) for k, v in tasks(conn).items()}
    assert [v["status"] for v in before.values()] == [v["status"] for v in after.values()]
    assert [v["overstated"] for v in before.values()] == [v["overstated"] for v in after.values()]


def test_the_read_side_reports_tasks(conn, clock, tmp_path):
    args = {"command": "pytest", "description": "run the suite"}
    run(conn, clock, pre("Bash", args), post("Bash", args, ok=False))
    stop(conn, clock)
    conn.commit()

    ro = readonly.connect(tmp_path / "audit.db")
    try:
        rows = readonly.tasks(ro)
        assert [r["label"] for r in rows] == ["run the suite"]
        assert rows[0]["status"] == "failed"
        assert readonly.summary(ro)["tasks"] == 1

        under = readonly.interactions(ro, task=rows[0]["task_id"])
        assert [r["tool"] for r in under] == ["Bash"]
    finally:
        ro.close()


def test_friction_groups_repeated_failures(conn, clock, tmp_path):
    args = {"command": "./gradlew test", "description": "run tests"}
    for session in ("s1", "s2"):
        run(conn, clock,
            pre("Bash", args, session=session),
            post("Bash", args, ok=False, session=session))
        stop(conn, clock, session=session)
    conn.commit()

    ro = readonly.connect(tmp_path / "audit.db")
    try:
        rows = readonly.friction(ro)
        assert len(rows) == 1
        assert rows[0]["failures"] == 2
        assert rows[0]["sessions"] == 2
        assert rows[0]["recovered"] == 0

        assert readonly.friction(ro, min_failures=3) == []
    finally:
        ro.close()


def test_a_run_of_unnamed_work_is_one_task_whatever_shape_the_calls_are(conn, clock):
    run(conn, clock,
        {"hook_event_name": "UserPromptSubmit", "session_id": "s1",
         "cwd": CORE, "prompt": "add a byte budget to the renderer"},
        pre("Read", {"file_path": f"{CORE}/CLAUDE.md"}),
        post("Read", {"file_path": f"{CORE}/CLAUDE.md"}),
        pre("Grep", {"pattern": "budget"}), post("Grep", {"pattern": "budget"}),
        pre("Bash", {"command": "go vet ./..."}),
        post("Bash", {"command": "go vet ./..."}),
        pre("Edit", {"file_path": f"{CORE}/render.go",
                     "old_string": "a", "new_string": "b"}),
        post("Edit", {"file_path": f"{CORE}/render.go",
                      "old_string": "a", "new_string": "b"}))
    stop(conn, clock)

    rows = list(conn.execute("SELECT label, source, actions FROM v_task_outcomes"))
    assert len(rows) == 1, "one job, not one task per call"
    assert (rows[0]["source"], rows[0]["actions"]) == ("signature", 4)


def test_work_under_a_task_the_agent_named_is_still_inherited(conn, clock):
    args = {"command": "pytest -q", "description": "get the suite green"}
    run(conn, clock,
        pre("Bash", args), post("Bash", args, ok=False),
        pre("Edit", {"file_path": f"{CORE}/app.py",
                     "old_string": "a", "new_string": "b"}),
        pre("Bash", args), post("Bash", args))
    stop(conn, clock)

    row = tasks(conn)["get the suite green"]
    assert row["actions"] == 3, "two attempts and the edit between them"
