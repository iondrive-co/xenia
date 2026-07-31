from __future__ import annotations

import json
import sqlite3
from pathlib import Path

from . import config

_SCHEMA = Path(__file__).with_name("schema.sql")


def connect(path: Path | str | None = None, *, read_only: bool = False) -> sqlite3.Connection:
    target = Path(path) if path is not None else config.db_path()
    if not read_only:
        target.parent.mkdir(parents=True, exist_ok=True)

    conn = sqlite3.connect(str(target), timeout=config.BUSY_TIMEOUT_MS / 1000)
    conn.row_factory = sqlite3.Row
    conn.execute(f"PRAGMA busy_timeout = {config.BUSY_TIMEOUT_MS}")
    conn.execute("PRAGMA foreign_keys = ON")
    if not read_only:
        conn.execute("PRAGMA journal_mode = WAL")
        conn.execute("PRAGMA synchronous = NORMAL")
        migrate(conn)
    return conn


def migrate(conn: sqlite3.Connection) -> None:
    current = schema_version(conn)
    if current == config.SCHEMA_VERSION:
        return

    _add_columns(conn)
    conn.executescript(_SCHEMA.read_text())
    _add_columns(conn)
    _drop_removed(conn)
    _set_chain_mode(conn)
    _agree_on_the_agent(conn)
    _separate_the_unanswered(conn)
    _settle_guessed_calls(conn)
    conn.execute(
        "INSERT INTO meta (key, value) VALUES ('schema_version', ?) "
        "ON CONFLICT (key) DO UPDATE SET value = excluded.value",
        (str(config.SCHEMA_VERSION),),
    )
    conn.commit()

    _retire_stale_readers(conn, current)


def _retire_stale_readers(conn: sqlite3.Connection, was: int) -> None:
    try:
        from . import readers
        retired = readers.retire_stale(config.SCHEMA_VERSION)
    except Exception:
        return
    if not retired:
        return

    note = (f"retired {len(retired)} reader(s) still on schema {was} after "
            f"migrating to {config.SCHEMA_VERSION} — pid(s) "
            f"{', '.join(str(p) for p in retired)}. A reader older than the "
            f"database cannot be trusted to report from it; the MCP client is "
            f"expected to restart its server, and a session that loses xenia "
            f"here should reconnect rather than conclude it is gone.")
    from . import ingest
    try:
        ingest.log_ingest_error(conn, "reader", note)
        conn.commit()
    except Exception:
        pass
    try:
        path = config.fallback_log()
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("a") as handle:
            handle.write(f"{ingest.utcnow()} xenia.migrate: {note}\n")
    except OSError:
        pass


def _agree_on_the_agent(conn: sqlite3.Connection) -> None:
    """Settle every session on the agent its own events name.

    The ledger has always recorded the agent per event; the session row is what
    every view joins through to report it. Where the two disagreed the session
    won, and a codex run whose events all say codex was reported as Claude's
    work — invisible under `agent: "codex"`, and miscounted under Claude.
    The events are the record, so the events decide.
    """
    try:
        conn.execute("""
            UPDATE session SET agent = COALESCE((
                SELECT e.agent FROM event e
                WHERE e.session_uid = session.session_uid AND e.agent <> 'unknown'
                GROUP BY e.agent
                ORDER BY COUNT(*) DESC, MIN(e.id)
                LIMIT 1
            ), agent)
        """)
    except sqlite3.OperationalError:
        pass


def _separate_the_unanswered(conn: sqlite3.Connection) -> None:
    """Take the calls nobody answered back out of the failure count.

    They were recorded as 'blocked' because they never completed, which put a
    row in every failures query that no fix would ever clear: an approval
    prompt still open when the window closed is not breakage. Their own error
    text is what identifies them, since it is the one xenia wrote when it
    could find nothing that ended them.
    """
    from . import ingest

    try:
        conn.execute(
            "UPDATE action SET status = 'unanswered' "
            "WHERE status = 'blocked' AND error = ?",
            (ingest.OUTSTANDING_ERROR,),
        )
    except sqlite3.OperationalError:
        pass


def _settle_guessed_calls(conn: sqlite3.Connection) -> None:
    """Replace every guess about an uncompleted call with what the runtime said.

    A call with no completion event was recorded as 'denied — a PreToolUse
    hook refused this one, or it was declined at the permission prompt'. The
    transcripts say otherwise: most were `Exit code 1` with a traceback, a
    screenshot that timed out, a browser tool with no page open — ordinary
    failures whose completion hook never fired — and at least one that
    succeeded outright. Six in a hundred were real refusals.

    So the guess is not narrowed here, it is replaced: the runtime's own
    tool_result decides, and the guess survives only where the transcript is
    gone.
    """
    from . import ingest

    try:
        sessions = conn.execute("""
            SELECT a.session_id AS session_id,
                   (SELECT e.payload FROM event e
                    WHERE e.session_uid = s.session_uid
                      AND e.payload LIKE '%transcript_path%'
                    LIMIT 1)          AS payload
            FROM action a
            JOIN session s ON s.id = a.session_id
            WHERE a.status IN ('blocked', 'unanswered') AND a.blocked_by IS NULL
            GROUP BY a.session_id
        """).fetchall()
    except sqlite3.OperationalError:
        return

    for row in sessions:
        if not row["payload"]:
            continue
        try:
            transcript = json.loads(row["payload"]).get("transcript_path")
        except (ValueError, AttributeError):
            continue
        try:
            # Whole file, not the tail the live path reads: these sessions
            # ended long ago and their answers sit wherever they happened.
            ingest.apply_outcomes(conn, row["session_id"], transcript,
                                  whole=True)
        except sqlite3.OperationalError:
            continue


def _set_chain_mode(conn: sqlite3.Connection) -> None:
    from . import chain

    row = conn.execute("SELECT value FROM meta WHERE key = 'chain_mode'").fetchone()
    if row is not None:
        return
    existing = conn.execute("SELECT COUNT(*) AS n FROM event").fetchone()["n"]
    conn.execute("INSERT INTO meta (key, value) VALUES ('chain_mode', ?)",
                 (chain.UNKEYED if existing else chain.KEYED,))


_ADDED_COLUMNS = (
    ("action", "task_id", "INTEGER REFERENCES task (id)"),
    ("session", "current_task_id", "INTEGER"),
    ("action", "result_bytes", "INTEGER"),
    ("action", "blocked_by", "TEXT"),
)

_DROPPED_TABLES = ("finding", "finding_dismissal", "finding_mute",
                   "finding_category")

_DROPPED_COLUMNS = (("action", "risk"),)


def _add_columns(conn: sqlite3.Connection) -> None:
    for table, column, kind in _ADDED_COLUMNS:
        existing = {row["name"] for row in conn.execute(f"PRAGMA table_info({table})")}
        if existing and column not in existing:
            conn.execute(f"ALTER TABLE {table} ADD COLUMN {column} {kind}")


def _drop_removed(conn: sqlite3.Connection) -> None:
    for table in _DROPPED_TABLES:
        conn.execute(f"DROP TABLE IF EXISTS {table}")

    for table, column in _DROPPED_COLUMNS:
        existing = {row["name"] for row in conn.execute(f"PRAGMA table_info({table})")}
        if column not in existing:
            continue
        try:
            conn.execute(f"ALTER TABLE {table} DROP COLUMN {column}")
        except sqlite3.OperationalError:
            pass


def schema_version(conn: sqlite3.Connection) -> int:
    try:
        row = conn.execute("SELECT value FROM meta WHERE key = 'schema_version'").fetchone()
    except sqlite3.OperationalError:
        return 0
    return int(row["value"]) if row else 0
