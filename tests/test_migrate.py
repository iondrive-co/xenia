from __future__ import annotations

import re
import sqlite3
from pathlib import Path

import pytest

from xenia import chain, config, db, ingest, readonly, resolve

SCHEMA = __import__("pathlib").Path(
    db.__file__).with_name("schema.sql")


REMOVED_TABLES = """
CREATE TABLE finding (
    id         INTEGER PRIMARY KEY,
    action_id  INTEGER NOT NULL REFERENCES action (id) ON DELETE CASCADE,
    rule       TEXT    NOT NULL,
    severity   TEXT    NOT NULL,
    message    TEXT    NOT NULL,
    evidence   TEXT,
    created_at TEXT    NOT NULL,
    category   TEXT
);
CREATE TABLE finding_dismissal (
    rule         TEXT    NOT NULL,
    event_id     INTEGER NOT NULL REFERENCES event (id),
    dismissed_at TEXT    NOT NULL,
    note         TEXT,
    PRIMARY KEY (rule, event_id)
);
CREATE TABLE finding_mute (
    id         INTEGER PRIMARY KEY,
    rule       TEXT NOT NULL,
    pattern    TEXT NOT NULL DEFAULT '*',
    created_at TEXT NOT NULL,
    note       TEXT,
    UNIQUE (rule, pattern)
);
CREATE TABLE finding_category (
    key        TEXT PRIMARY KEY,
    rule       TEXT NOT NULL,
    pattern    TEXT NOT NULL,
    label      TEXT NOT NULL,
    sample     TEXT,
    first_seen TEXT NOT NULL,
    decision   TEXT,
    decided_at TEXT
);
"""


def previous_schema() -> str:
    text = SCHEMA.read_text()

    text = text.replace(
        "    status          TEXT    NOT NULL,\n",
        "    risk            TEXT    NOT NULL DEFAULT 'normal',\n"
        "    status          TEXT    NOT NULL,\n")

    text = re.sub(r"CREATE TABLE IF NOT EXISTS task \(.*?\);", "", text,
                  flags=re.S)
    text = re.sub(r"CREATE INDEX IF NOT EXISTS task_\w+.*?;", "", text)
    text = re.sub(r"CREATE INDEX IF NOT EXISTS action_task_idx.*?;", "", text)

    text = text.replace("    task_id         INTEGER REFERENCES task (id),\n", "")
    text = text.replace("    current_task_id INTEGER\n", "")
    text = text.replace("    end_reason  TEXT,", "    end_reason  TEXT")

    for view in ("v_task_outcomes", "v_friction"):
        text = re.sub(rf"DROP VIEW IF EXISTS {view};\s*CREATE VIEW {view} AS.*?;",
                      "", text, flags=re.S)
    return text + REMOVED_TABLES


@pytest.fixture
def legacy(tmp_path, monkeypatch):
    monkeypatch.setenv("XENIA_FAKE_NOW", "2026-07-27T09:00:00.000+00:00")
    path = tmp_path / "legacy.db"

    conn = sqlite3.connect(str(path), isolation_level=None)
    conn.row_factory = sqlite3.Row
    conn.executescript(previous_schema())
    conn.execute("INSERT INTO meta (key, value) VALUES ('schema_version', '4')")
    conn.execute("INSERT INTO finding_mute (rule, pattern, created_at) "
                 "VALUES ('guardrail_write', '*', '2026-07-27T09:00:00+00:00')")
    conn.commit()

    assert chain.mode(conn) == chain.UNKEYED
    repo = tmp_path / "old-repo"
    (repo / ".git").mkdir(parents=True)
    (repo / ".git" / "HEAD").write_text("ref: refs/heads/main\n")

    conn.execute(
        "INSERT INTO session (session_uid, agent, repo, repo_path, cwd, started_at) "
        "VALUES ('s1', 'claude', 'old-repo', ?, ?, ?)",
        (str(repo), str(repo), "2026-07-27T09:00:00.000+00:00"))
    for i in range(4):
        payload = {
            "hook_event_name": "PreToolUse", "session_id": "s1",
            "cwd": str(repo), "tool_name": "Bash",
            "tool_input": {"command": f"echo {i}", "description": "count things"},
        }
        event_id = ingest.append_event(conn, payload, "claude")
        conn.commit()
        conn.execute(
            "INSERT INTO action (session_id, seq, start_event_id, tool, kind, "
            "                    intent, signature, detail, status, started_at) "
            "VALUES (1, ?, ?, 'Bash', 'exec', 'count things', ?, ?, 'ok', ?)",
            (i + 1, event_id, f"exec:echo:{i}", f"echo {i}",
             "2026-07-27T09:00:00.000+00:00"))
    conn.commit()
    conn.close()
    return path


def test_the_previous_schema_really_lacks_the_new_shape(legacy):
    conn = sqlite3.connect(str(legacy))
    tables = {r[0] for r in conn.execute("SELECT name FROM sqlite_master")}
    assert "task" not in tables and "v_task_outcomes" not in tables
    assert "finding" in tables and "finding_mute" in tables
    columns = {r[1] for r in conn.execute("PRAGMA table_info(action)")}
    assert "task_id" not in columns
    assert "risk" in columns
    conn.close()


def test_an_existing_database_upgrades(legacy):
    conn = db.connect(legacy)
    assert db.schema_version(conn) == config.SCHEMA_VERSION
    tables = {r[0] for r in conn.execute("SELECT name FROM sqlite_master")}
    assert "task" in tables and "v_task_outcomes" in tables
    assert "task_id" in {r["name"] for r in conn.execute("PRAGMA table_info(action)")}
    conn.close()


def test_an_existing_database_gains_the_reply_size_column(legacy):
    conn = db.connect(legacy)
    assert "result_bytes" in {r["name"] for r in
                              conn.execute("PRAGMA table_info(action)")}
    conn.close()


def test_the_findings_tables_are_dropped(legacy):
    conn = db.connect(legacy)
    tables = {r[0] for r in conn.execute("SELECT name FROM sqlite_master")}
    assert not {t for t in tables if t.startswith("finding")}
    assert conn.execute("SELECT COUNT(*) FROM event").fetchone()[0] == 4
    conn.close()


def test_the_risk_column_is_dropped(legacy):
    conn = db.connect(legacy)
    assert "risk" not in {r["name"] for r in
                          conn.execute("PRAGMA table_info(action)")}
    assert conn.execute("SELECT COUNT(*) FROM event").fetchone()[0] == 4
    assert "sensitivity" in {r["name"] for r in
                             conn.execute("PRAGMA table_info(fs_change)")}
    conn.close()


def test_a_migrated_database_still_takes_new_actions(legacy):
    conn = db.connect(legacy)
    conn.execute("ALTER TABLE action ADD COLUMN risk TEXT NOT NULL DEFAULT 'normal'")
    conn.commit()
    ingest.record(conn, {
        "hook_event_name": "PreToolUse", "session_id": "s1",
        "cwd": str(Path(legacy).parent / "old-repo"), "tool_name": "Bash",
        "tool_input": {"command": "echo after", "description": "write again"},
    })
    assert conn.execute("SELECT COUNT(*) FROM action").fetchone()[0] == 5
    conn.close()


def test_the_old_ledger_still_verifies_after_the_upgrade(legacy):
    conn = db.connect(legacy)
    assert chain.mode(conn) == chain.UNKEYED
    result = chain.verify(conn)
    assert result.ok and not result.keyed and result.checked == 4
    conn.close()


def test_history_gains_tasks_when_it_is_replayed(legacy):
    conn = db.connect(legacy)
    assert conn.execute("SELECT COUNT(*) FROM task").fetchone()[0] == 0

    resolve.rebuild(conn)
    rows = conn.execute("SELECT label, source FROM task").fetchall()
    assert [(r["label"], r["source"]) for r in rows] == [("count things", "intent")]

    assert chain.verify(conn).ok
    conn.close()


def misnamed_session(legacy, uid: str, agent: str) -> None:
    """A session row that says claude over events that say otherwise."""
    conn = sqlite3.connect(str(legacy))
    conn.row_factory = sqlite3.Row
    conn.execute(
        "INSERT INTO session (session_uid, agent, repo, cwd, started_at) "
        "VALUES (?, 'claude', 'old-repo', '/tmp', '2026-07-27T09:00:00.000+00:00')",
        (uid,))
    conn.commit()
    for i in range(3):
        ingest.append_event(conn, {
            "hook_event_name": "PreToolUse", "session_id": uid,
            "tool_name": "Bash", "tool_input": {"command": f"echo {i}"},
        }, agent)
        conn.commit()
    conn.close()


def test_a_session_misnamed_in_an_old_database_is_put_right(legacy):
    misnamed_session(legacy, "s2", "codex")

    # The ledger said codex on every event and the session row said claude, so
    # every view reported the run as Claude's work. The events are the record.
    conn = db.connect(legacy)
    named = dict(conn.execute("SELECT session_uid, agent FROM session").fetchall())
    assert named["s2"] == "codex"
    assert named["s1"] == "claude", "a session its events agree with is left alone"
    assert chain.verify(conn).ok, "and the ledger itself is untouched"
    conn.close()


def test_a_backfill_leaves_a_session_its_events_do_not_name(legacy):
    misnamed_session(legacy, "s3", "unknown")

    conn = db.connect(legacy)
    assert conn.execute(
        "SELECT agent FROM session WHERE session_uid = 's3'").fetchone()[0] == "claude"
    conn.close()


def test_the_read_side_survives_a_database_it_cannot_migrate(legacy):
    ro = readonly.connect(legacy)
    try:
        stats = readonly.summary(ro)
        assert stats["actions"] == 4
        assert stats["tasks"] == 0
    finally:
        ro.close()
