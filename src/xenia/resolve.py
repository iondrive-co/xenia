from __future__ import annotations

import sqlite3
from datetime import datetime, timedelta

FAILED = ("error", "blocked")


def resolve_session(conn: sqlite3.Connection, session_id: int) -> int:
    rows = conn.execute(
        "SELECT id, seq, goal_id, signature, status FROM action "
        "WHERE session_id = ? ORDER BY seq",
        (session_id,),
    ).fetchall()

    by_signature: dict[str, list[sqlite3.Row]] = {}
    for row in rows:
        by_signature.setdefault(row["signature"], []).append(row)

    linked = 0
    for group in by_signature.values():
        for position, row in enumerate(group):
            conn.execute(
                "UPDATE action SET attempt_no = ? WHERE id = ?", (position + 1, row["id"])
            )
            if row["status"] not in FAILED:
                continue

            fix = next(
                (later for later in group[position + 1 :] if later["status"] == "ok"),
                None,
            )
            if fix is None:
                conn.execute(
                    "UPDATE action SET resolved_by_action_id = NULL, resolution_span = NULL, "
                    "crossed_goal = 0 WHERE id = ?",
                    (row["id"],),
                )
                continue

            conn.execute(
                "UPDATE action SET resolved_by_action_id = ?, resolution_span = ?, "
                "                  crossed_goal = ?, crossed_session = 0 WHERE id = ?",
                (
                    fix["id"],
                    fix["seq"] - row["seq"] - 1,
                    int(bool(row["goal_id"]) and row["goal_id"] != fix["goal_id"]),
                    row["id"],
                ),
            )
            linked += 1

    _score_goals(conn, session_id)
    _score_tasks(conn, session_id)
    conn.commit()
    return linked


def _score_goals(conn: sqlite3.Connection, session_id: int) -> None:
    from . import ingest

    goals = conn.execute(
        "SELECT id FROM goal WHERE session_id = ?", (session_id,)
    ).fetchall()

    for goal in goals:
        stats = conn.execute(
            "SELECT COUNT(*) AS total, "
            "       SUM(status = 'ok') AS ok, "
            "       SUM(status IN ('error', 'blocked')) AS failed, "
            "       SUM(status IN ('error', 'blocked') AND resolved_by_action_id IS NULL) "
            "           AS unresolved, "
            "       SUM(status IN ('error', 'blocked') AND crossed_goal = 1) AS late_fix "
            "FROM action WHERE goal_id = ?",
            (goal["id"],),
        ).fetchone()

        total = stats["total"] or 0
        ok = stats["ok"] or 0
        failed = stats["failed"] or 0
        unresolved = stats["unresolved"] or 0
        late_fix = stats["late_fix"] or 0

        if total == 0:
            status, note = "no_action", "No tool calls were made for this instruction."
        elif failed == 0:
            status, note = "achieved", f"{ok} action(s), no failures."
        elif unresolved == 0:
            status = "achieved"
            note = f"{failed} failure(s), all later resolved."
            if late_fix:
                note += f" {late_fix} needed a follow-up instruction."
        elif ok > 0:
            status = "partial"
            note = (
                f"{ok} action(s) succeeded but {unresolved} of {failed} failure(s) "
                "were never resolved."
            )
        else:
            status = "failed"
            note = f"All {failed} action(s) failed with no successful retry."

        conn.execute(
            "UPDATE goal SET status = ?, resolution_note = ?, "
            "                resolved_at = COALESCE(resolved_at, ?) "
            "WHERE id = ?",
            (status, note, ingest.utcnow(), goal["id"]),
        )


#: How much of an error belongs in a one-line outcome note. Long enough for
#: an exit code, a refused path or the first sentence of a traceback; short
#: enough that a page of task rows is still scannable.
REASON_CHARS = 140


def _reason(conn: sqlite3.Connection, task_id: int) -> str | None:
    """What actually went wrong, for the note to say instead of the count.

    "All 1 action(s) failed with no successful retry." was the note on every
    failed row in the record, because most tasks are one action and the
    sentence has nothing in it but the count — which 'actions' and 'failures'
    already carry. An agent read a page of them, concluded the classifier was
    stuck on one string and the status field was worthless, and went off to
    read the work by hand. The count was never the useful half.

    The last unresolved failure, because that is the one still standing when
    the task ended. First line only: an error is stored up to 1,000
    characters and a note is a line.
    """
    row = conn.execute(
        "SELECT tool, error FROM action "
        "WHERE task_id = ? AND status IN ('error', 'blocked') "
        "      AND resolved_by_action_id IS NULL "
        "ORDER BY seq DESC LIMIT 1",
        (task_id,),
    ).fetchone()
    if row is None:
        return None

    lines = [line.strip() for line in (row["error"] or "").splitlines()]
    text = next((line for line in lines if line), "")
    if len(text) > REASON_CHARS:
        text = text[:REASON_CHARS - 1].rstrip() + "…"
    tool = row["tool"] or "the call"
    return f"{tool}: {text}" if text else f"{tool}, with no error recorded"


def _score_tasks(conn: sqlite3.Connection, session_id: int) -> None:
    session = conn.execute(
        "SELECT ended_at FROM session WHERE id = ?", (session_id,)
    ).fetchone()
    ended = bool(session and session["ended_at"])

    tasks = conn.execute(
        "SELECT id, declared FROM task WHERE session_id = ?", (session_id,)
    ).fetchall()

    for task in tasks:
        stats = conn.execute(
            "SELECT COUNT(*) AS total, "
            "       SUM(status = 'ok') AS ok, "
            "       SUM(status IN ('error', 'blocked')) AS failed, "
            "       SUM(status IN ('error', 'blocked') AND resolved_by_action_id IS NULL) "
            "           AS unresolved, "
            "       SUM(status = 'error' AND resolved_by_action_id IS NULL) "
            "           AS unresolved_errors, "
            "       MAX(COALESCE(ended_at, started_at)) AS last_at "
            "FROM action WHERE task_id = ?",
            (task["id"],),
        ).fetchone()

        total = stats["total"] or 0
        ok = stats["ok"] or 0
        failed = stats["failed"] or 0
        unresolved = stats["unresolved"] or 0
        declared = task["declared"]

        if not ended and total == 0:
            status, note = "open", "Still running."
        elif total == 0:
            status = "no_action"
            note = "No tool calls were attributed to this task."
        elif failed == 0:
            status, note = "achieved", f"{ok} action(s), nothing failed."
        elif unresolved == 0:
            status = "achieved"
            note = (f"{ok} action(s), reached after {failed} failed "
                    f"attempt(s) that were later put right.")
        elif ok > 0:
            status = "partial"
            note = (f"{ok} action(s) succeeded but {unresolved} of {failed} "
                    "failure(s) were never resolved.")
            why = _reason(conn, task["id"])
            if why:
                note += f" Last of them — {why}"
        else:
            status = "failed"
            why = _reason(conn, task["id"])
            if total == 1:
                note = (f"The one action failed and was not retried — {why}"
                        if why else
                        "The one action failed and was not retried.")
            else:
                note = f"All {failed} action(s) failed with no successful retry."
                if why:
                    note += f" Last of them — {why}"

        if ended and total == 0 and declared in ("in_progress", "dropped"):
            status = "abandoned"
            note = ("Left in progress when the session ended."
                    if declared == "in_progress"
                    else "Dropped from the plan without being attempted.")

        overstated = int(declared == "completed"
                         and ((stats["unresolved_errors"] or 0) > 0
                              or status == "failed"))
        if overstated:
            note += " The agent marked this task completed."

        conn.execute(
            "UPDATE task SET status = ?, outcome_note = ?, overstated = ?, "
            "                ended_at = COALESCE(?, ended_at) WHERE id = ?",
            (status, note, overstated, stats["last_at"], task["id"]),
        )


def resolve_repo(conn: sqlite3.Connection, repo: str, *, within_hours: int = 72) -> int:
    unresolved = conn.execute(
        "SELECT a.id, a.signature, a.started_at, a.session_id "
        "FROM action a JOIN session s ON s.id = a.session_id "
        "WHERE s.repo = ? AND a.status IN ('error', 'blocked') "
        "      AND a.resolved_by_action_id IS NULL "
        "ORDER BY a.started_at",
        (repo,),
    ).fetchall()

    linked = 0
    for row in unresolved:
        cutoff = _plus_hours(row["started_at"], within_hours)
        if cutoff is None:
            continue
        fix = conn.execute(
            "SELECT a.id, a.started_at FROM action a "
            "JOIN session s ON s.id = a.session_id "
            "WHERE s.repo = ? AND a.signature = ? AND a.status = 'ok' "
            "      AND a.session_id != ? AND a.started_at > ? AND a.started_at <= ? "
            "ORDER BY a.started_at LIMIT 1",
            (repo, row["signature"], row["session_id"], row["started_at"], cutoff),
        ).fetchone()
        if fix is None:
            continue

        conn.execute(
            "UPDATE action SET resolved_by_action_id = ?, crossed_session = 1, "
            "                  resolution_span = NULL WHERE id = ?",
            (fix["id"], row["id"]),
        )
        linked += 1

    if linked:
        for session in conn.execute(
            "SELECT id FROM session WHERE repo = ?", (repo,)
        ).fetchall():
            _score_goals(conn, session["id"])
            _score_tasks(conn, session["id"])
    conn.commit()
    return linked


def rebuild(conn: sqlite3.Connection) -> dict[str, int]:
    from . import ingest

    cross_session_repos = [
        row["repo"]
        for row in conn.execute(
            "SELECT DISTINCT s.repo AS repo FROM action a "
            "JOIN session s ON s.id = a.session_id "
            "WHERE a.crossed_session = 1 AND s.repo IS NOT NULL"
        ).fetchall()
    ]

    for table in ("fs_change", "remote_call", "action", "task",
                  "goal", "session"):
        conn.execute(f"DELETE FROM {table}")
    conn.commit()

    counts = {"events": 0, "skipped": 0}
    import json

    rows = conn.execute("SELECT id, ts, payload FROM event ORDER BY id").fetchall()
    last_ts = None
    for row in rows:
        try:
            payload = json.loads(row["payload"])
        except (ValueError, TypeError):
            counts["skipped"] += 1
            continue
        last_ts = row["ts"]
        with ingest.replay_at(row["ts"]):
            _replay(conn, row["id"], payload)
        counts["events"] += 1

    with ingest.replay_at(last_ts):
        for session in conn.execute(
            "SELECT id FROM session WHERE ended_at IS NULL"
        ).fetchall():
            ingest.close_session(conn, session["id"], reason="inferred")

    counts["cross_session"] = sum(
        resolve_repo(conn, repo) for repo in cross_session_repos
    )

    conn.commit()
    return counts


def _replay(conn: sqlite3.Connection, event_id: int, payload: dict) -> None:
    from . import ingest

    agent = payload.get("_agent") or ingest.detect_agent(payload)
    session_id = ingest.ensure_session(conn, payload, agent)
    hook = payload.get("hook_event_name") or ""

    if hook == "UserPromptSubmit":
        ingest.add_goal(conn, session_id, str(payload.get("prompt") or ""))
    elif hook == "PreToolUse":
        ingest._open_action(conn, event_id, session_id, payload)
    elif hook == "PostToolUse":
        ingest._close_action(conn, event_id, session_id, payload)
    elif hook in ("Stop", "SubagentStop", "SessionEnd"):
        # The ledger stores the payload, so a rebuild can re-read the
        # transcript and recover denial kinds for history — if the transcript
        # is still on disk. When it is gone, outcomes_in() finds nothing and
        # the row falls back to the inferred 'denied', as it did before.
        ingest.close_session(conn, session_id, reason=hook.lower(),
                             transcript=payload.get("transcript_path"))


def _plus_hours(iso: str | None, hours: int) -> str | None:
    if not iso:
        return None
    try:
        return (datetime.fromisoformat(iso) + timedelta(hours=hours)).isoformat(
            timespec="milliseconds"
        )
    except ValueError:
        return None
