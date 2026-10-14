from __future__ import annotations

import subprocess

import pytest

from conftest import SHOP

from xenia import agora, config, db, ingest, mcp, readonly


def a_dead_pid() -> int:
    """A pid that certainly is not running: one we started and reaped."""
    proc = subprocess.Popen(["true"])
    proc.wait()
    return proc.pid


@pytest.fixture
def sleeper():
    started = []

    def spawn():
        proc = subprocess.Popen(["sleep", "120"])
        started.append(proc)
        return proc.pid

    yield spawn
    for proc in started:
        proc.kill()
        proc.wait()


def claim(conn, **kw):
    fields = {"resource": "chrome-headless-shell x4",
              "purpose": "recording the clip for the 4a gate"}
    return agora.post(conn, **{**fields, **kw})


# ------------------------------------------------------------------ posting


def test_a_claim_starts_as_live_work_nobody_may_kill(conn):
    posted = claim(conn, ram_mb=6000, holds_for="90m")

    assert posted["state"] == "held"
    assert posted["may_kill"] == "no"
    assert posted["ram_mb"] == 6000
    assert posted["holder_alive"] is True


def test_a_claim_needs_to_say_what_it_is_and_what_it_is_for(conn):
    with pytest.raises(KeyError):
        agora.post(conn, resource="", purpose="something")
    with pytest.raises(KeyError):
        agora.post(conn, resource="a browser", purpose="   ")


def test_an_unreadable_window_is_an_error_not_the_default(conn):
    with pytest.raises(KeyError) as raised:
        claim(conn, holds_for="ages")
    assert "10m" in str(raised.value)


def test_the_claim_says_which_runtime_and_checkout_it_came_from(conn,
                                                                monkeypatch):
    monkeypatch.setenv("CLAUDECODE", "1")
    posted = claim(conn)
    assert posted["agent"] == "claude"
    assert posted["repo"]


# --------------------------------------------------------------- processes


def test_attaching_pids_turns_a_declared_number_into_a_measured_one(conn,
                                                                    sleeper):
    posted = claim(conn, ram_mb=6000)
    assert "rss_mb" not in posted

    updated = agora.update(conn, posted["id"], pids=[sleeper()])
    assert updated["rss_mb"] > 0
    assert updated["processes"][0]["alive"] is True
    # The estimate survives alongside the measurement; they answer different
    # halves of the question.
    assert updated["ram_mb"] == 6000


def test_a_recycled_pid_is_not_the_process_that_was_claimed(conn, sleeper,
                                                            monkeypatch):
    pid = sleeper()
    posted = claim(conn, pids=[pid])
    assert posted["processes"][0]["alive"] is True

    # Same number, different process: what `ps` reports started at a clock
    # that is not the one the claim recorded.
    monkeypatch.setattr(agora, "_ps", lambda pids: {
        int(p): {"pid": int(p), "rss_mb": 9.0, "started": "some other day"}
        for p in pids})
    again = agora.assess(readonly.claims(conn))[0]
    assert again["processes"][0]["alive"] is False


def test_an_agora_that_cannot_see_the_process_table_says_hold(
        conn, monkeypatch):
    """The safety property. An agora that read a failing 'ps' as 'nothing is
    running' would mark every claim on the machine free to kill."""
    claim(conn, holder_pid=a_dead_pid())

    # With a process table to read, this claim is plainly an orphan.
    assert agora.assess(readonly.claims(conn))[0]["state"] == "abandoned"

    # Without one, the same row must not be handed out as free.
    monkeypatch.setattr(agora, "_ps", lambda pids: None)
    rows = agora.assess(readonly.claims(conn))

    assert rows[0]["state"] == "held"
    assert rows[0]["may_kill"] == "no"
    assert rows[0]["holder_alive"] is None
    assert "could not be read" in rows[0]["unmeasured"]


# ------------------------------------------------------------------ states


def test_a_claim_whose_session_is_gone_with_running_processes_is_detached(
        conn, sleeper):
    pid = sleeper()
    posted = claim(conn, ram_mb=6000, pids=[pid], holder_pid=a_dead_pid(),
                   kill_note="ask before killing")

    assert posted["state"] == "detached"
    assert posted["may_kill"] == "ask"
    assert str(pid) in posted["may_kill_why"]
    assert "ask before killing" in posted["may_kill_why"]


def test_a_claim_whose_session_is_gone_with_no_processes_is_abandoned(conn):
    posted = claim(conn, ram_mb=6000, holder_pid=a_dead_pid())

    assert posted["state"] == "abandoned"
    assert posted["may_kill"] == "yes"


def test_a_claim_past_its_own_window_is_asked_about_not_killed(conn,
                                                              monkeypatch):
    monkeypatch.setenv("XENIA_FAKE_NOW", "2026-07-27T09:00:00.000+00:00")
    claim(conn, holds_for="10m")

    monkeypatch.setenv("XENIA_FAKE_NOW", "2026-07-27T11:00:00.000+00:00")
    row = agora.assess(readonly.claims(conn))[0]

    assert row["state"] == "overrun"
    assert row["may_kill"] == "ask"
    assert "still running" in row["may_kill_why"]


def test_a_released_claim_whose_processes_are_still_up_is_an_orphan(conn,
                                                                    sleeper):
    pid = sleeper()
    posted = claim(conn, pids=[pid])
    agora.release(conn, posted["id"], note="done")

    row = agora.assess(readonly.claims(conn, released=True))[0]
    assert row["state"] == "released"
    assert row["may_kill"] == "yes"
    assert "still running" in row["may_kill_why"]


def test_released_claims_are_history_and_not_in_the_agora(conn):
    posted = claim(conn)
    agora.release(conn, posted["id"])

    assert readonly.claims(conn) == []
    assert len(readonly.claims(conn, released=True)) == 1


# --------------------------------------------------------------- authority


def test_a_peer_cannot_release_live_work_out_from_under_its_holder(conn):
    posted = claim(conn)

    refused = agora.release(conn, posted["id"], holder_pid=a_dead_pid())

    assert "refused" in refused
    assert str(posted["holder_pid"]) in refused["refused"]
    assert readonly.claims(conn), "the claim must survive the refusal"


def test_a_peer_may_clear_up_after_a_session_that_ended(conn):
    posted = claim(conn, holder_pid=a_dead_pid())

    cleared = agora.release(conn, posted["id"], note="killed; 6.1 GB back")

    assert cleared["state"] == "released"
    assert cleared["release_note"] == "killed; 6.1 GB back"


def test_an_abandoned_claim_can_be_taken_over_but_a_live_one_cannot(conn):
    orphan = claim(conn, holder_pid=a_dead_pid())
    mine = claim(conn)

    adopted = agora.update(conn, orphan["id"], purpose="finishing this off")
    assert adopted["state"] == "held"
    assert adopted["holder_pid"] != orphan["holder_pid"]

    refused = agora.update(conn, mine["id"], holder_pid=a_dead_pid(),
                           purpose="mine now")
    assert "refused" in refused


def test_update_refuses_a_field_it_does_not_own(conn):
    posted = claim(conn)
    with pytest.raises(KeyError) as raised:
        agora.update(conn, posted["id"], holder_pid_override=1)
    assert "holder_pid_override" in str(raised.value)


def test_releasing_twice_is_not_an_error(conn):
    posted = claim(conn)
    agora.release(conn, posted["id"])
    again = agora.release(conn, posted["id"])
    assert again["state"] == "released"


# ----------------------------------------------------------------- totals


def test_a_forecast_outranks_a_process_that_has_not_grown_into_it_yet(conn,
                                                                      sleeper):
    posted = claim(conn, ram_mb=6000)
    agora.update(conn, posted["id"], pids=[sleeper()])

    totals = agora.summary(agora.assess(readonly.claims(conn)))
    # Not the few MB the process has taken so far: the 6 GB it announced is
    # what the next agent has to budget against.
    assert totals["claimed_mb"] == 6000


def test_what_can_be_reclaimed_is_what_is_actually_resident(conn, sleeper):
    posted = agora.post(conn, resource="a browser", purpose="gone", ram_mb=6000,
                        pids=[sleeper()])
    agora.release(conn, posted["id"])
    agora.post(conn, resource="a suite", purpose="also gone", ram_mb=9000,
               holder_pid=a_dead_pid())

    totals = agora.summary(agora.assess(readonly.claims(conn, released=True)))

    assert totals["claimed_mb"] == 0
    assert 0 < totals["reclaimable_mb"] < 6000


def test_the_totals_say_when_a_claim_named_no_number_at_all(conn):
    claim(conn)
    totals = agora.summary(agora.assess(readonly.claims(conn)))
    assert totals["unstated"] == 1


def test_the_totals_carry_what_the_machine_has(conn):
    totals = agora.summary([])
    assert totals["total_mb"] > 0
    assert totals["available_mb"] > 0


# -------------------------------------------------------------------- mcp


@pytest.fixture
def server(conn, tmp_path):
    return mcp.Server(tmp_path / "audit.db")


def call(server, name, arguments=None):
    reply = server.handle({
        "jsonrpc": "2.0", "id": 1, "method": "tools/call",
        "params": {"name": name, "arguments": arguments or {}},
    })
    return reply["result"]


def refusal(server, name, arguments):
    """The message from a call the server rejected before running it."""
    reply = server.handle({
        "jsonrpc": "2.0", "id": 1, "method": "tools/call",
        "params": {"name": name, "arguments": arguments},
    })
    return reply["error"]["message"]


def test_the_agora_round_trips_through_the_tools(server, sleeper):
    posted = call(server, "xenia_claim", {
        "op": "post", "resource": "chrome-headless-shell x4",
        "purpose": "the paradise suite", "ram_mb": 6000, "holds_for": "90m",
        "kill_note": "re-runnable from scratch"})["structuredContent"]["claim"]

    call(server, "xenia_claim", {"op": "update", "id": posted["id"],
                                 "pids": [sleeper()]})

    agora_reply = call(server, "xenia_report",
                       {"view": "claims"})["structuredContent"]
    assert agora_reply["ram"]["claimed_mb"] == 6000
    assert agora_reply["rows"][0]["kill_note"] == "re-runnable from scratch"

    call(server, "xenia_claim", {"op": "release", "id": posted["id"]})
    assert call(server, "xenia_report",
                {"view": "claims"})["structuredContent"]["rows"] == []


def test_the_agora_is_filtered_by_state(server):
    call(server, "xenia_claim", {"op": "post", "resource": "a browser",
                                 "purpose": "live work"})
    rows = call(server, "xenia_report",
                {"view": "claims", "state": "abandoned"})["structuredContent"]
    assert rows["rows"] == []
    # The totals are the whole agora's, not the filter's — an agent asking
    # what it can reclaim must not read 0 as "the machine is free".
    assert rows["ram"]["unstated"] == 1


def test_a_filter_the_claims_view_does_not_read_is_an_error(server):
    assert "does not read" in refusal(
        server, "xenia_report", {"view": "claims", "tool": "Bash"})


def test_update_and_release_say_which_claim_they_need(server):
    assert "'id'" in refusal(server, "xenia_claim", {"op": "release"})


def test_the_claims_view_is_empty_rather_than_broken_on_an_old_database(
        server, tmp_path):
    import sqlite3
    conn = sqlite3.connect(tmp_path / "audit.db")
    conn.execute("DROP TABLE claim")
    conn.commit()
    conn.close()

    reply = call(server, "xenia_report", {"view": "claims"})
    assert reply["structuredContent"]["rows"] == []


# -------------------------------------------------------------------- nudge


def a_call(command: str, session: str = "s1") -> dict:
    return {"hook_event_name": "PreToolUse", "session_id": session,
            "cwd": SHOP, "tool_name": "Bash", "tool_input": {"command": command}}


@pytest.mark.parametrize("command, expected", [
    ("python3 -m pytest -q", "python3 -m pytest"),
    ("cd ui && npm run build", "npm run build"),
    ("CI=1 npx playwright test --reporter=list", "playwright"),
    ("time make -j8 all", "make -j8"),
    ("docker compose up -d", "docker compose up"),
    ("uv run pytest tests/test_agora.py", "pytest"),
    ("ollama serve &", "ollama serve"),
    # The other half, and the half that matters more: reading about a suite
    # is not running one. A nudge that fires on these is one an agent learns
    # to skip before it ever reaches the call it was written for.
    ("grep -rn pytest src/", None),
    ("cat playwright.config.ts", None),
    ("git log --grep=build -5", None),
    ("echo 'npm test'", None),
    ("git grep -n -E 'foo|gradle|bar' -- .", None),
    ('rg "build|pytest" src', None),
    ("grep -E 'x;npm run build' notes.txt", None),
    ("cd web; npm run build", "npm run build"),
    ("(cd web && pytest -q)", "pytest"),
    ("ls -la", None),
])
def test_what_counts_as_starting_something_heavy(command, expected):
    assert agora.looks_heavy("Bash", {"command": command}) == expected


def test_only_a_shell_call_is_looked_at():
    assert agora.looks_heavy("Read", {"file_path": "/x/pytest.ini"}) is None
    assert agora.looks_heavy("Bash", {}) is None
    assert agora.looks_heavy("Bash", "npm run build") is None


def test_the_first_heavy_call_of_a_session_is_told_about_the_agora(conn):
    said = agora.nudge(conn, a_call("python3 -m pytest -q"))

    assert said is not None
    assert "python3 -m pytest" in said
    assert "xenia_claim" in said
    assert "nothing is claimed" in said


def test_and_then_never_again_that_session(conn):
    first = a_call("python3 -m pytest -q")
    assert agora.nudge(conn, first) is not None
    ingest.record(conn, first)

    second = a_call("npx playwright test")
    assert agora.nudge(conn, second) is None

    # A different session has not been told anything yet.
    assert agora.nudge(conn, a_call("npx playwright test", session="s2")) is not None


def test_the_call_asked_about_may_already_be_recorded(conn):
    # xenia-hook and xenia-guard run side by side, so the recording can land
    # before the nudge is asked. That row is this call, not an earlier one.
    first = {**a_call("python3 -m pytest -q"), "tool_use_id": "toolu_1"}
    ingest.record(conn, first)
    assert agora.nudge(conn, first) is not None

    # Without a tool_use_id the key is the command itself; still this call.
    other = a_call("npm run build", session="s3")
    ingest.record(conn, other)
    assert agora.nudge(conn, other) is not None

    # And a finished one really is earlier.
    ingest.record(conn, {**first, "hook_event_name": "PostToolUse",
                         "tool_response": {"stdout": "ok"}})
    assert agora.nudge(conn, {**a_call("npx playwright test"), "tool_use_id": "toolu_2"}) is None


def test_an_ordinary_command_is_left_alone(conn):
    assert agora.nudge(conn, a_call("ls -la")) is None
    assert agora.nudge(conn, {**a_call("python3 -m pytest"),
                              "hook_event_name": "PostToolUse"}) is None


def test_the_nudge_says_what_the_agora_is_holding_right_now(conn):
    claim(conn, ram_mb=6000, holds_for="90m")

    said = agora.nudge(conn, a_call("python3 -m pytest -q"))

    assert "1 claim holding 5.9 GB" in said


def test_the_nudge_can_be_silenced(conn, monkeypatch):
    monkeypatch.setattr(config, "AGORA_NUDGE", False)

    assert agora.nudge(conn, a_call("python3 -m pytest -q")) is None


def test_claim_held_by_systemd_unit_is_alive_when_unit_is_active(conn, monkeypatch):
    monkeypatch.setattr(agora, "_units_active",
                        lambda units: {u: (u == "worker-job-1.service") for u in units})
    posted = claim(conn, unit="worker-job-1.service", holder_pid=a_dead_pid())

    assert posted["state"] == "held"
    assert posted["holder_alive"] is True
    assert posted["holder_unit"] == "worker-job-1.service"
    assert posted["unit"] == "worker-job-1.service"


def test_claim_held_by_systemd_unit_when_unit_is_inactive_and_process_runs(
        conn, sleeper, monkeypatch):
    monkeypatch.setattr(agora, "_units_active", lambda units: {u: False for u in units})
    pid = sleeper()
    posted = claim(conn, unit="worker-job-1.service", pids=[pid],
                   holder_pid=a_dead_pid(), kill_note="keep alive")

    assert posted["state"] == "detached"
    assert posted["may_kill"] == "ask"
    assert posted["holder_alive"] is False
    assert "keep alive" in posted["may_kill_why"]
    assert "worker-job-1.service" in posted["may_kill_why"]


def test_claim_held_by_systemd_unit_when_unit_is_inactive_and_processes_dead(
        conn, monkeypatch):
    monkeypatch.setattr(agora, "_units_active", lambda units: {u: False for u in units})
    posted = claim(conn, unit="worker-job-1.service", holder_pid=a_dead_pid())

    assert posted["state"] == "abandoned"
    assert posted["may_kill"] == "yes"
    assert posted["holder_alive"] is False
    assert "worker-job-1.service" in posted["may_kill_why"]


def test_claim_unit_can_be_updated(conn, monkeypatch):
    monkeypatch.setattr(agora, "_units_active", lambda units: {u: True for u in units})
    posted = claim(conn, unit="worker-job-1.service")
    updated = agora.update(conn, posted["id"], unit="job-42.service")

    assert updated["holder_unit"] == "job-42.service"
    assert updated["unit"] == "job-42.service"


def test_auto_release_releases_abandoned_claims(conn):
    abandoned = claim(conn, holder_pid=a_dead_pid())
    live = claim(conn)

    released_ids = agora.auto_release(conn)

    assert released_ids == [abandoned["id"]]
    assert len(readonly.claims(conn)) == 1
    assert readonly.claims(conn)[0]["id"] == live["id"]
    hist = [c for c in readonly.claims(conn, released=True) if c["released_at"]]
    assert len(hist) == 1
    assert hist[0]["id"] == abandoned["id"]
    assert hist[0]["release_note"] == (
        "auto-released: holder is gone and no processes are running")


def test_auto_release_does_not_release_detached_claims(conn, sleeper):
    detached = claim(conn, pids=[sleeper()], holder_pid=a_dead_pid())

    released_ids = agora.auto_release(conn)

    assert released_ids == []
    open_claims = readonly.claims(conn)
    assert len(open_claims) == 1
    assert open_claims[0]["id"] == detached["id"]


def test_claims_view_auto_releases_abandoned_claims(server, tmp_path):
    conn = db.connect(tmp_path / "audit.db")
    claim(conn, holder_pid=a_dead_pid())
    live = claim(conn)
    conn.close()

    reply = call(server, "xenia_report", {"view": "claims"})
    rows = reply["structuredContent"]["rows"]
    assert len(rows) == 1
    assert rows[0]["id"] == live["id"]


def test_ram_block_reports_unclaimed_heavy_processes(conn, monkeypatch):
    fake_procs = [
        {"pid": 999901, "rss_mb": 512.0, "command": "python3 worker.py"},
        {"pid": 999902, "rss_mb": 300.0, "command": "node runner.js"},
    ]
    monkeypatch.setattr(agora, "_unclaimed_heavy",
                        lambda claimed_pids: [p for p in fake_procs if p["pid"] not in claimed_pids])

    totals = agora.summary([])
    assert totals["unclaimed_mb"] == 812
    assert totals["unclaimed"] == fake_procs

    held = claim(conn, pids=[999901])
    totals_with_claim = agora.summary(agora.assess([held]))
    assert totals_with_claim["unclaimed_mb"] == 300
    assert len(totals_with_claim["unclaimed"]) == 1
    assert totals_with_claim["unclaimed"][0]["pid"] == 999902


def test_unclaimed_heavy_reads_ps(monkeypatch):
    ps_output = "  100   102400 python3 small.py\n  200   524288 /bin/heavy-worker arg\n"
    monkeypatch.setattr(subprocess, "run",
                        lambda *args, **kw: subprocess.CompletedProcess(
                            args=args[0], returncode=0, stdout=ps_output))
    monkeypatch.setattr(config, "AGORA_HEAVY_MB", 200)

    heavy = agora._unclaimed_heavy(claimed_pids={100})
    assert len(heavy) == 1
    assert heavy[0]["pid"] == 200
    assert heavy[0]["rss_mb"] == 512.0
    assert heavy[0]["command"] == "/bin/heavy-worker arg"


def test_mcp_claim_with_unit(server):
    reply = call(server, "xenia_claim", {
        "op": "post",
        "resource": "background worker",
        "purpose": "processing queue",
        "unit": "worker-job-1.service",
    })
    claim_dict = reply["structuredContent"]["claim"]
    assert claim_dict["unit"] == "worker-job-1.service"
    assert claim_dict["holder_unit"] == "worker-job-1.service"


def test_the_agora_filters_detached_state(server, sleeper, monkeypatch):
    monkeypatch.setattr(agora, "_units_active", lambda units: {u: False for u in units})
    call(server, "xenia_claim", {
        "op": "post", "resource": "a detached worker",
        "purpose": "outliving session",
        "unit": "worker-job-1.service",
        "pids": [sleeper()],
    })
    rows = call(server, "xenia_report",
                {"view": "claims", "state": "detached"})["structuredContent"]["rows"]
    assert len(rows) == 1
    assert rows[0]["state"] == "detached"
