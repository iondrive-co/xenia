from __future__ import annotations

import re
import sqlite3
from datetime import datetime, timedelta, timezone
from typing import Any

from . import config, plan as plan_mod, redact

MAX_LIMIT = 500
DEFAULT_LIMIT = 200

SUMMARY_CHARS = 160
EXAMPLE_CHARS = 320
# An error is the one field on a failure an agent can act on, and the half it
# acts on is usually the last sentence — "ACTION: retry this tool", the path
# that was refused, the flag that was wrong. Cutting a long error from the tail
# throws exactly that away, so errors are cut from the middle instead.
ERROR_CHARS = 240
# How much of a normalised error is enough to call two failures the same cause.
CAUSE_CHARS = 90

SORTABLE = {
    "at": "a.started_at",
    "repo": "s.repo",
    "agent": "s.agent",
    "tool": "a.tool",
    "kind": "a.kind",
    "status": "a.status",
    "environment": "r.environment",
    "host": "r.host",
    "duration_ms": "a.duration_ms",
    "bytes": "a.result_bytes",
}

KINDS = ("remote_call", "fs_change", "fs_read", "exec", "other")
# 'blocked' is a call something refused. 'unanswered' is one nobody answered
# — in flight when the session ended — which is not a failure and is counted
# as one nowhere.
STATUSES = ("started", "ok", "error", "blocked", "unanswered")
FAILED_STATUSES = ("error", "blocked")
# Who refused a call. 'rule' and 'user' are what the runtime itself recorded.
# 'unattributed' is not a stored value: it is a refusal nothing named an owner
# for, read off the error text — see REFUSAL_PHRASES.
BLOCKED_BY = ("rule", "user", "unattributed")
TASK_STATUSES = ("open", "achieved", "partial", "failed", "no_action", "abandoned")
TASK_SOURCES = ("plan", "intent", "signature")
TASK_ORDERS = ("significance", "at")

# What a task row is worth reading. A window with no filter is mostly
# one-action successes, and putting them first buries the three rows the
# question was about under fifty-five that answer nothing — and then the reply
# ceiling drops the interesting tail. Failure first, then the outcomes that
# disagree with themselves, then the rest; recency only decides ties.
TASK_SIGNIFICANCE = """CASE
    WHEN t.status = 'failed'                          THEN 0
    WHEN t.status = 'partial' OR t.overstated = 1     THEN 1
    WHEN t.status = 'abandoned'                       THEN 2
    WHEN t.status = 'no_action'                       THEN 3
    WHEN t.status = 'achieved'                        THEN 4
    ELSE 5 END"""
TASK_ORDER_SQL = {
    "significance": f"{TASK_SIGNIFICANCE}, t.at DESC",
    "at": "t.at DESC",
}
#: What each ordering is, in words, for the reply to say out loud.
TASK_ORDER_NOTE = {
    "significance": "failed and overstated first, then partial, abandoned, "
                    "no_action, achieved, open — most recent first within each",
    "at": "most recent first",
}

FAILURE_GROUPS = ("signature", "cause")

# A refusal nothing recorded an owner for. The runtime sets blocked_by only
# for what *it* refused, so a daemon or an MCP server saying no — the most
# actionable failure class on a machine with brokered tools — arrives as an
# ordinary tool error and is invisible to both refusal counts.
#
# Matched on the error text, which is the only evidence there is, and left
# unattributed rather than guessed at: who refused it is in the error itself,
# and a wrong attribution here sends the reader to the wrong file. Only ever
# text something else wrote, too. These phrases used to match xenia's own
# guess about a call with no completion event, which put 542 rows nothing had
# refused into this count; a guess is not evidence, and no longer says any of
# the words below.
# Deliberately phrases and not single words: 'refused' alone reads
# ECONNREFUSED as a policy decision, which is the opposite kind of problem.
REFUSAL_PHRASES = (
    "approval", "not permitted", "not allowed", "permission denied",
    "denied by", "denied —", "access denied", "declined", "refused by",
    "refused this", "forbidden", "unauthorized", "unauthorised",
    "blocked by", "requires confirmation", "was rejected",
)

GROUPABLE = {
    "tool": "a.tool",
    "kind": "a.kind",
    "status": "a.status",
    "signature": "a.signature",
    "intent": "a.intent",
    "via": "r.via",
    "channel": "r.channel",
    "host": "r.host",
    "environment": "r.environment",
    "repo": "s.repo",
    "agent": "s.agent",
}

STAT_ORDERS = {
    "total_ms": "total_ms",
    "calls": "calls",
    "failure_rate": "failure_rate",
    "p95_ms": "p95_ms",
    "total_bytes": "total_bytes",
    "p95_bytes": "p95_bytes",
}

REPEAT_ORDERS = {
    "repeats": "SUM(repeated)",
    "repeated_bytes": "repeated_bytes",
    "repeated_ms": "repeated_ms",
}

DISK_GROUPS = {
    "path": "m.path",
    "repo": "m.repo",
    "agent": "m.agent",
    "tool": "m.tool",
    "session": "m.session",
}

DISK_ORDERS = {
    "wasted_bytes": "wasted_bytes",
    "unchanged": "unchanged",
    "bytes_written": "bytes_written",
    "writes": "writes",
    "rewrites": "rewrites",
}

WRITE_OPS = ("create", "modify", "truncate")


def connect(path=None) -> sqlite3.Connection:
    target = path or config.db_path()
    conn = sqlite3.connect(f"file:{target}?mode=ro", uri=True,
                           timeout=config.BUSY_TIMEOUT_MS / 1000)
    conn.row_factory = sqlite3.Row
    conn.execute(f"PRAGMA busy_timeout = {config.BUSY_TIMEOUT_MS}")
    return conn


class StaleReader(RuntimeError):
    pass


def stored_version(conn: sqlite3.Connection) -> int:
    try:
        row = conn.execute(
            "SELECT value FROM meta WHERE key = 'schema_version'").fetchone()
    except sqlite3.OperationalError:
        return 0
    return int(row["value"]) if row and row["value"] else 0


def _stale_message(stored: int) -> str:
    return (f"this xenia process was built for schema {config.SCHEMA_VERSION} "
            f"and the database is at {stored}: it is running code older than the "
            f"database and must be restarted before its reports can be trusted")


def require_current(conn: sqlite3.Connection) -> None:
    stored = stored_version(conn)
    if stored > config.SCHEMA_VERSION:
        raise StaleReader(_stale_message(stored))


def explain_failure(conn: sqlite3.Connection,
                    exc: sqlite3.OperationalError) -> Exception:
    stored = stored_version(conn)
    if stored > config.SCHEMA_VERSION:
        return StaleReader(f"{_stale_message(stored)} — the underlying error "
                           f"was: {exc}")
    return exc


def reader_retirements(conn: sqlite3.Connection, *, limit: int = 3) -> list[dict[str, Any]]:
    try:
        return _rows(conn.execute("""
            SELECT ts, detail FROM ingest_error
            WHERE stage = 'reader' ORDER BY id DESC LIMIT :limit
        """, {"limit": max(1, int(limit))}))
    except sqlite3.OperationalError:
        return []


def parse_since(since: str | None) -> str | None:
    """A window, as a cutoff string that compares against a stored timestamp.

    Every timestamp in this record is one shape — `2026-09-02T05:08:07.645+00:00`
    — and every window is a string comparison against it, so a cutoff that is
    not in that shape does not error, it silently selects the wrong rows.
    Which is what happened: `since` lower-cased its whole argument, and a
    perfectly ordinary `2026-09-02T00:00:00Z` became `...t00:00:00z`, whose
    lower-case `t` sorts *after* the `T` in every timestamp of that day. The
    query matched nothing, said so, and read as "no work happened" — a whole
    day of it. So an absolute cutoff is parsed and re-emitted here, never
    passed through.

    Unparseable is an error, not an empty window. `1w` used to fall through as
    a literal, comparing below every timestamp there is and quietly meaning
    all time; `yesterday` became None, which means all time on purpose. Both
    read as an answer. Raising names the forms that work instead.
    """
    if not since:
        return None
    text = str(since).strip()
    now = datetime.now(timezone.utc)

    unit = {"h": "hours", "d": "days", "m": "minutes", "w": "weeks"}.get(
        text[-1:].lower())
    if unit:
        try:
            return (now - timedelta(**{unit: float(text[:-1])})).isoformat()
        except ValueError:
            pass

    moment = _moment(text)
    if moment is not None:
        return moment
    raise KeyError(
        f"since: cannot read {since!r} as a window. Give a length back from "
        "now — '30m', '4h', '7d', '2w' — or a moment to start from: "
        "'2026-09-02', '2026-09-02T04:30' or '2026-09-02T04:30:00Z'."
    )


def _moment(text: str) -> str | None:
    """An absolute cutoff, in the shape the stored timestamps are in.

    Tolerates what people and agents actually type — a trailing `Z`, a space
    for the `T`, a bare date — and normalises all of it, because the
    comparison is textual and only the normalised form is right. A bare date
    is midnight UTC, and a moment with no offset is read as UTC, which is the
    only clock this record keeps.
    """
    candidate = text[:-1] + "+00:00" if text[-1:] in ("Z", "z") else text
    try:
        stamp = datetime.fromisoformat(candidate.replace(" ", "T", 1))
    except ValueError:
        return None
    if stamp.tzinfo is None:
        stamp = stamp.replace(tzinfo=timezone.utc)
    return stamp.astimezone(timezone.utc).isoformat(timespec="milliseconds")


def _window_before(cutoff: str) -> str:
    """Where the window of the same length immediately before this one starts.

    A date like '2026-07-01' is a cutoff, not a duration, so its length is
    measured to now the same way an explicit '7d' is: both arrive here as a
    timestamp, and what came before it is the same span again.
    """
    try:
        start = datetime.fromisoformat(cutoff)
    except ValueError:
        return cutoff
    if start.tzinfo is None:
        start = start.replace(tzinfo=timezone.utc)
    return (start - (datetime.now(timezone.utc) - start)).isoformat()


def _clean(value: Any) -> Any:
    if isinstance(value, str):
        return redact.redact(value)
    return value


def _rows(cursor) -> list[dict[str, Any]]:
    return [{k: _clean(row[k]) for k in row.keys()} for row in cursor]


def _brief(column: str, chars: int) -> str:
    """Head of a long value, saying how much of it is not here.

    A bare ellipsis leaves the reader guessing whether four characters went or
    four hundred, which is the difference between reading on and drilling in.
    Same marker the capture side uses, so one cut is not two notations.
    """
    chars = int(chars)
    return (f"CASE WHEN length({column}) > {chars} "
            f"THEN substr({column}, 1, {chars}) || '…[+' || "
            f"(length({column}) - {chars}) || ' chars]' "
            f"ELSE {column} END")


def _brief_ends(column: str, chars: int) -> str:
    """Both ends of a long value, with the middle marked and counted.

    For errors. A message that runs long is a sentence saying what failed
    followed, often enough, by one saying what to do about it, and a cut from
    the tail keeps the half the agent already knows and drops the half it
    needs.
    """
    chars = int(chars)
    head, tail = chars * 2 // 3, chars - chars * 2 // 3
    return (f"CASE WHEN length({column}) > {chars} "
            f"THEN substr({column}, 1, {head}) || '…[+' || "
            f"(length({column}) - {chars}) || ' chars]…' || "
            f"substr({column}, length({column}) - {tail} + 1) "
            f"ELSE {column} END")


def _refused_unattributed() -> str:
    """SQL for: nothing recorded a block, but the error is itself a refusal."""
    tests = " OR ".join(f"lower(a.error) LIKE '%{phrase}%'"
                        for phrase in REFUSAL_PHRASES)
    return f"(a.blocked_by IS NULL AND a.error IS NOT NULL AND ({tests}))"


#: What varies between two reports of the same cause, and has to go before
#: they will group: the host, the pid, the byte offset, the temp directory.
_VOLATILE_TEXT = (
    (re.compile(r"https?://\S+"), "<url>"),
    (re.compile(r"(?:/[\w.+-]+){2,}/?"), "<path>"),
    (re.compile(r"\b[0-9a-f]{8,}\b", re.IGNORECASE), "<id>"),
    (re.compile(r"\d+"), "N"),
    (re.compile(r"\s+"), " "),
)


def _cause_key(error: str | None) -> str:
    """What two failures have to share to be the same cause.

    The signature is the identity of the *work* — one host, one command, one
    endpoint — so eight calls refused for one reason arrive as six rows that
    have to be read one at a time before the reason is visible. The error text
    is the other key, and normalising it groups them into the row that was
    always the answer.
    """
    if not error:
        return "(no error text)"
    # Lowercased first, so what is left standing in upper case is a
    # placeholder and reads as one.
    text = str(error).strip().lower()
    for pattern, placeholder in _VOLATILE_TEXT:
        text = pattern.sub(placeholder, text)
    return text[:CAUSE_CHARS] if len(text) > CAUSE_CHARS else text


def _is_glob(value: str) -> bool:
    return any(ch in value for ch in "*?[")


def _match(where: list[str], params: dict[str, Any], column: str,
           value: str, name: str) -> None:
    text = str(value)
    where.append(f"{column} {'GLOB' if _is_glob(text) else '='} :{name}")
    params[name] = text


def _action_filters(
    *,
    since: str | None = None,
    repo: str | None = None,
    kind: str | None = None,
    status: str | None = None,
    agent: str | None = None,
    environment: str | None = None,
    tool: str | None = None,
    via: str | None = None,
    channel: str | None = None,
    signature: str | None = None,
    session: str | None = None,
    goal: int | None = None,
    task: int | None = None,
) -> tuple[list[str], dict[str, Any]]:
    where = ["1=1"]
    params: dict[str, Any] = {}

    cutoff = parse_since(since)
    if cutoff:
        where.append("a.started_at >= :since")
        params["since"] = cutoff
    if repo:
        where.append("s.repo = :repo")
        params["repo"] = repo
    if kind in KINDS:
        where.append("a.kind = :kind")
        params["kind"] = kind
    if status in STATUSES:
        where.append("a.status = :status")
        params["status"] = status
    if agent:
        where.append("s.agent = :agent")
        params["agent"] = agent
    if environment:
        where.append("r.environment = :environment")
        params["environment"] = environment
    if tool:
        _match(where, params, "a.tool", tool, "tool")
    if via:
        _match(where, params, "r.via", via, "via")
    if channel:
        _match(where, params, "r.channel", channel, "channel")
    if signature:
        _match(where, params, "a.signature", signature, "signature")
    if session:
        _match(where, params, "s.session_uid", session, "session")
    if goal:
        where.append("a.goal_id = :goal")
        params["goal"] = int(goal)
    if task:
        where.append("a.task_id = :task")
        params["task"] = int(task)

    return where, params


CALL_CHARS = 120
CALLS_DEFAULT_LIMIT = 20


def calls(conn: sqlite3.Connection, *, since: str | None = None,
          repo: str | None = None, tool: str | None = None,
          via: str | None = None, session: str | None = None,
          signature: str | None = None, status: str | None = None,
          kind: str | None = None, agent: str | None = None,
          blocked_by: str | None = None,
          order: str = "bytes", descending: bool = True,
          limit: int = CALLS_DEFAULT_LIMIT) -> list[dict[str, Any]]:
    where, params = _action_filters(
        since=since, repo=repo, tool=tool, via=via, session=session,
        signature=signature, status=status, kind=kind, agent=agent)
    if blocked_by == "unattributed":
        where.append(_refused_unattributed())
    elif blocked_by:
        where.append("a.blocked_by = :blocked_by")
        params["blocked_by"] = blocked_by
    column = SORTABLE.get(order, "a.result_bytes")
    direction = "DESC" if descending else "ASC"
    params["limit"] = max(1, min(int(limit or CALLS_DEFAULT_LIMIT), MAX_LIMIT))

    rows = _rows(conn.execute(f"""
        SELECT a.id            AS action_id,
               a.started_at    AS at,
               s.agent         AS agent,
               s.repo          AS repo,
               a.tool          AS tool,
               a.status        AS status,
               -- Only ever set on a blocked call, so it costs a key on the
               -- rows where the next question is "refused by what?".
               a.blocked_by    AS blocked_by,
               a.duration_ms   AS duration_ms,
               a.result_bytes  AS result_bytes,
               r.via           AS via,
               r.host          AS host,
               {_brief("a.detail", CALL_CHARS)} AS detail,
               -- The reason a failed row failed. Absent everywhere else, so it
               -- costs nothing on the rows that worked, and the one thing a
               -- drill-down onto a failure exists to show.
               {_brief_ends("a.error", ERROR_CHARS)} AS error
        FROM action a
        JOIN session s ON s.id = a.session_id
        LEFT JOIN remote_call r ON r.action_id = a.id
        WHERE {' AND '.join(where)}
        ORDER BY ({column} IS NULL), {column} {direction}, a.id {direction}
        LIMIT :limit
    """, params))

    # This view carries nothing that repeats identically down the rows, and
    # blocked_by and error are both null on every call that completed.
    for row in rows:
        for empty in ("blocked_by", "error"):
            if row.get(empty) is None:
                row.pop(empty, None)
    return rows


def interactions(
    conn: sqlite3.Connection,
    *,
    since: str | None = None,
    repo: str | None = None,
    kind: str | None = None,
    status: str | None = None,
    agent: str | None = None,
    environment: str | None = None,
    tool: str | None = None,
    via: str | None = None,
    channel: str | None = None,
    signature: str | None = None,
    session: str | None = None,
    search: str | None = None,
    goal: int | None = None,
    task: int | None = None,
    order: str = "at",
    descending: bool = True,
    limit: int = DEFAULT_LIMIT,
) -> list[dict[str, Any]]:
    where, params = _action_filters(
        since=since, repo=repo, kind=kind, status=status,
        agent=agent, environment=environment, tool=tool, via=via,
        channel=channel, signature=signature, session=session,
        goal=goal, task=task)

    if search:
        where.append(
            "(a.detail LIKE :q OR a.intent LIKE :q OR a.target LIKE :q "
            " OR r.host LIKE :q OR a.tool LIKE :q OR paths LIKE :q "
            " OR t.label LIKE :q OR a.error LIKE :q)"
        )
        params["q"] = f"%{search}%"

    column = SORTABLE.get(order, SORTABLE["at"])
    direction = "DESC" if descending else "ASC"
    params["limit"] = max(1, min(int(limit or DEFAULT_LIMIT), MAX_LIMIT))

    sql = f"""
        SELECT a.id                AS action_id,
               a.started_at        AS at,
               s.repo              AS repo,
               s.agent             AS agent,
               s.session_uid       AS session,
               a.goal_id           AS goal_id,
               {_brief("g.prompt", SUMMARY_CHARS)} AS goal_summary,
               a.task_id           AS task_id,
               t.label             AS task,
               a.tool              AS tool,
               a.kind              AS kind,
               a.status            AS status,
               a.intent            AS intent,
               a.detail            AS detail,
               a.error             AS error,
               a.duration_ms       AS duration_ms,
               a.result_bytes      AS result_bytes,
               a.resolved_by_action_id AS resolved_by,
               r.channel           AS channel,
               r.via               AS via,
               r.host              AS host,
               r.environment       AS environment,
               r.mutating          AS mutating,
               f.paths             AS paths,
               f.sensitivity       AS sensitivity
        FROM action a
        JOIN session s ON s.id = a.session_id
        LEFT JOIN goal g ON g.id = a.goal_id
        LEFT JOIN task t ON t.id = a.task_id
        LEFT JOIN remote_call r ON r.action_id = a.id
        LEFT JOIN (
            SELECT action_id,
                   GROUP_CONCAT(path, ', ') AS paths,
                   MAX(CASE sensitivity WHEN 'guardrail' THEN 3
                                        WHEN 'sensitive' THEN 2 ELSE 1 END) AS sens_rank,
                   CASE MAX(CASE sensitivity WHEN 'guardrail' THEN 3
                                             WHEN 'sensitive' THEN 2 ELSE 1 END)
                        WHEN 3 THEN 'guardrail' WHEN 2 THEN 'sensitive'
                        ELSE 'normal' END AS sensitivity
            FROM fs_change GROUP BY action_id
        ) f ON f.action_id = a.id
        WHERE {' AND '.join(where)}
        ORDER BY {column} {direction}, a.id {direction}
        LIMIT :limit
    """
    return _rows(conn.execute(sql, params))


def summary(conn: sqlite3.Connection, *, since: str | None = None) -> dict[str, Any]:
    params: dict[str, Any] = {}
    clause = ""
    cutoff = parse_since(since)
    if cutoff:
        clause = " AND a.started_at >= :since"
        params["since"] = cutoff

    row = conn.execute(f"""
        SELECT COUNT(*)                                   AS actions,
               SUM(a.kind = 'remote_call')                AS remote_calls,
               SUM(a.kind = 'fs_change')                  AS fs_changes,
               SUM(a.status = 'error')                    AS failed,
               SUM(a.status = 'blocked')                  AS blocked,
               SUM(a.status = 'unanswered')               AS unanswered
        FROM action a WHERE 1=1{clause}
    """, params).fetchone()
    out = {k: (row[k] or 0) for k in row.keys()}

    task_clause = clause.replace("a.started_at", "t.started_at")
    try:
        work = conn.execute(f"""
            SELECT COUNT(*)                        AS tasks,
                   SUM(t.status = 'achieved')      AS tasks_achieved,
                   SUM(t.status = 'partial')       AS tasks_partial,
                   SUM(t.status IN ('failed', 'abandoned')) AS tasks_failed,
                   SUM(t.overstated = 1)           AS tasks_overstated
            FROM task t WHERE 1=1{task_clause}
        """, params).fetchone()
        out.update({k: (work[k] or 0) for k in work.keys()})
    except sqlite3.OperationalError:
        out.update({k: 0 for k in ("tasks", "tasks_achieved", "tasks_partial",
                                   "tasks_failed", "tasks_overstated")})

    out["sessions"] = conn.execute("SELECT COUNT(*) AS n FROM session").fetchone()["n"]
    out["repos"] = [
        r["repo"] for r in conn.execute(
            "SELECT DISTINCT repo FROM session WHERE repo IS NOT NULL ORDER BY repo")
    ]
    out["agents"] = [
        r["agent"] for r in conn.execute(
            "SELECT DISTINCT agent FROM session ORDER BY agent")
    ]
    return out


def goals(conn: sqlite3.Connection, *, since: str | None = None,
          status: str | None = None, repo: str | None = None,
          goal_id: int | None = None,
          limit: int = DEFAULT_LIMIT) -> list[dict[str, Any]]:
    where = ["1=1"]
    params: dict[str, Any] = {}
    cutoff = parse_since(since)
    if cutoff:
        where.append("at >= :since")
        params["since"] = cutoff
    if status:
        where.append("status = :status")
        params["status"] = status
    if repo:
        where.append("repo = :repo")
        params["repo"] = repo
    if goal_id:
        where.append("goal_id = :goal_id")
        params["goal_id"] = int(goal_id)
    params["limit"] = max(1, min(int(limit or DEFAULT_LIMIT), MAX_LIMIT))

    return _rows(conn.execute(f"""
        SELECT goal_id, at, repo, agent, status, prompt, actions,
               remote_calls, fs_changes, failures
        FROM v_goal_outcomes
        WHERE {' AND '.join(where)}
        ORDER BY at DESC LIMIT :limit
    """, params))


def _task_scope(since: str | None, repo: str | None, source: str | None,
                agent: str | None, goal: int | None,
                search: str | None) -> tuple[list[str], dict[str, Any]]:
    """Which tasks the question is about, before any outcome narrows it.

    Split out from the outcome filters on purpose: this is the population a
    row has to be read against, and `task_totals` counts it while `tasks`
    returns a page of it.
    """
    where = ["1=1"]
    params: dict[str, Any] = {}
    cutoff = parse_since(since)
    if cutoff:
        where.append("at >= :since")
        params["since"] = cutoff
    if repo:
        where.append("repo = :repo")
        params["repo"] = repo
    if source in TASK_SOURCES:
        where.append("source = :source")
        params["source"] = source
    if agent:
        where.append("agent = :agent")
        params["agent"] = agent
    if goal:
        where.append("goal_id = :goal")
        params["goal"] = int(goal)
    if search:
        where.append("(label LIKE :q OR goal_prompt LIKE :q)")
        params["q"] = f"%{search}%"
    return where, params


def _task_outcome_filter(status: str | None,
                         overstated_only: bool) -> tuple[list[str], dict[str, Any]]:
    """The part of a task query that selects on how the work turned out."""
    where: list[str] = []
    params: dict[str, Any] = {}
    if status in TASK_STATUSES:
        where.append("status = :status")
        params["status"] = status
    if overstated_only:
        where.append("overstated = 1")
    return where, params


def task_totals(conn: sqlite3.Connection, *, since: str | None = None,
                repo: str | None = None, status: str | None = None,
                source: str | None = None, agent: str | None = None,
                goal: int | None = None, overstated_only: bool = False,
                search: str | None = None) -> dict[str, Any]:
    """The denominator for a page of task rows.

    The tasks view is ordered worst-first by design, so the top of it is all
    failures whenever there are any — and a client that reads a page of it
    and nothing else concludes the window is all failures. One did: it called
    a 1.5% failure rate "100% of tasks failed with an identical note", decided
    the classifier was broken, and went and read the work by hand instead.
    It was reading thirty rows off the top of twelve thousand.

    So the shape of the whole window ships with the page. `by_status` is
    counted over the window and its subject filters but *not* over the
    outcome ones, because it is there to say what the rows returned are a
    slice of; `matched` is the same count with the whole query applied.
    """
    where, params = _task_scope(since, repo, source, agent, goal, search)
    outcome, outcome_params = _task_outcome_filter(status, overstated_only)
    params.update(outcome_params)
    # One scan, not two: a second query for the matched count can disagree
    # with the breakdown it is printed beside if a session closes between them.
    matched = f"SUM({' AND '.join(outcome)})" if outcome else "COUNT(*)"

    rows = conn.execute(f"""
        SELECT status, COUNT(*) AS tasks, {matched} AS matched
        FROM v_task_outcomes
        WHERE {' AND '.join(where)}
        GROUP BY status ORDER BY tasks DESC
    """, params).fetchall()

    return {
        "tasks_in_window": sum(r["tasks"] for r in rows),
        "matched_by_this_query": sum(r["matched"] or 0 for r in rows),
        "by_status": {r["status"]: r["tasks"] for r in rows},
    }


def tasks(conn: sqlite3.Connection, *, since: str | None = None,
          repo: str | None = None, status: str | None = None,
          source: str | None = None, agent: str | None = None,
          goal: int | None = None, overstated_only: bool = False,
          search: str | None = None, order: str = "significance",
          limit: int = DEFAULT_LIMIT) -> list[dict[str, Any]]:
    where, params = _task_scope(since, repo, source, agent, goal, search)
    outcome, outcome_params = _task_outcome_filter(status, overstated_only)
    where += outcome
    params.update(outcome_params)
    params["limit"] = max(1, min(int(limit or DEFAULT_LIMIT), MAX_LIMIT))
    sort = TASK_ORDER_SQL.get(order or "significance",
                              TASK_ORDER_SQL["significance"])

    return _rows(conn.execute(f"""
        SELECT t.task_id, t.at, t.ended_at, t.repo, t.agent, t.session, t.goal_id,
               {_brief("t.goal_prompt", SUMMARY_CHARS)} AS goal_summary,
               t.label, t.source, t.declared, t.status, t.overstated, t.note,
               t.actions, t.attempts, t.failures, t.failures_fixed, t.blocked,
               t.duration_ms, t.first_action_id,
               COALESCE(w.bytes_written, 0) AS bytes_written,
               COALESCE(w.writes, 0)        AS writes,
               COALESCE(w.sized_writes, 0)  AS sized_writes
        FROM v_task_outcomes t
        LEFT JOIN (
            SELECT a.task_id                          AS task_id,
                   COUNT(*)                           AS writes,
                   SUM(f.bytes_after IS NOT NULL)     AS sized_writes,
                   SUM(COALESCE(f.bytes_after, 0))    AS bytes_written
            FROM fs_change f
            JOIN action a ON a.id = f.action_id
            WHERE a.task_id IS NOT NULL AND f.op <> 'delete'
            GROUP BY a.task_id
        ) w ON w.task_id = t.task_id
        WHERE {' AND '.join(where)}
        ORDER BY {sort} LIMIT :limit
    """, params))


def friction(conn: sqlite3.Connection, *, since: str | None = None,
             repo: str | None = None, search: str | None = None,
             group_by: str = "signature", min_failures: int = 2,
             limit: int = DEFAULT_LIMIT) -> list[dict[str, Any]]:
    where = ["1=1"]
    params: dict[str, Any] = {}
    cutoff = parse_since(since)
    if cutoff:
        where.append("a.started_at >= :since")
        params["since"] = cutoff
    if repo:
        where.append("s.repo = :repo")
        params["repo"] = repo
    if search:
        where.append("(a.error LIKE :q OR a.detail LIKE :q "
                     "OR a.intent LIKE :q OR a.signature LIKE :q)")
        params["q"] = f"%{search}%"
    params["min_failures"] = max(1, int(min_failures or 1))
    params["limit"] = max(1, min(int(limit or DEFAULT_LIMIT), MAX_LIMIT))

    if group_by == "cause":
        return _causes(conn, where, params)

    # The window immediately before this one, same length. A count from it
    # turns "8 failures" into "8 failures, none last week" — which is the
    # difference between a new breakage and one somebody already decided to
    # live with. Only meaningful when a window was asked for; over all time
    # there is nothing before.
    previously = "NULL"
    if cutoff:
        params["previous_start"] = _window_before(cutoff)
        previously = """(
            SELECT COUNT(*) FROM action p
            JOIN session ps ON ps.id = p.session_id
            WHERE p.signature = a.signature
              AND p.status IN ('error', 'blocked')
              AND p.started_at >= :previous_start
              AND p.started_at < :since
              AND (:repo IS NULL OR ps.repo = :repo)
        )"""
        params.setdefault("repo", None)

    return _rows(conn.execute(f"""
        SELECT a.signature                              AS signature,
               COUNT(*)                                 AS failures,
               {previously}                             AS previously,
               COUNT(DISTINCT a.session_id)             AS sessions,
               -- Named, not counted. Every fix for a failing signature lands
               -- in a repo, so a row that says '2' sends the reader back for
               -- another query before they can act on it.
               GROUP_CONCAT(DISTINCT s.repo)            AS repos,
               -- Zero, not null, when nothing in the group was refused.
               -- SUM over a column that is null on every row is null, and a
               -- null reads as "cannot tell" on the one question this split
               -- exists to answer.
               COALESCE(SUM(a.blocked_by = 'rule'), 0)  AS refused_by_rule,
               COALESCE(SUM(a.blocked_by = 'user'), 0)  AS declined_by_user,
               -- The refusals the runtime never saw: something said no and
               -- it came back as an ordinary error. Which something is in
               -- 'example_error', and is not guessed at here.
               SUM({_refused_unattributed()})           AS refused_unattributed,
               SUM(a.resolved_by_action_id IS NOT NULL) AS recovered,
               SUM(a.crossed_goal)                      AS needed_new_instruction,
               SUM(a.crossed_session)                   AS needed_new_session,
               MAX(a.attempt_no)                        AS worst_attempt,
               MIN(a.started_at)                        AS first_at,
               MAX(a.started_at)                        AS last_at,
               -- One representative row per group. MAX over text picks an
               -- arbitrary member, which is all that is wanted here, and picks
               -- the same one every time, which a bare aggregate would not.
               MAX(a.tool)                              AS tool,
               MAX(a.kind)                              AS kind,
               MAX(t.label)                             AS example_task,
               MAX(a.intent)                            AS example_intent,
               -- The one action id this report hands out, because `trace` is
               -- the whole point of landing on a friction row and it takes an
               -- id. A failure that was *recovered* is preferred over the most
               -- recent one: those are the rows with a series to show, and a
               -- report about getting stuck is most useful pointing at the
               -- time somebody got unstuck.
               COALESCE(
                   MAX(CASE WHEN a.resolved_by_action_id IS NOT NULL
                            THEN a.id END),
                   MAX(a.id))                           AS example_action_id,
               -- Capped: the representative command is often a heredoc, and one
               -- 1,700-character example per row buries the counts that are the
               -- reason to read this report at all.
               {_brief("MAX(a.detail)", EXAMPLE_CHARS)} AS example,
               {_brief_ends("MAX(a.error)", EXAMPLE_CHARS)} AS example_error
        FROM action a
        JOIN session s ON s.id = a.session_id
        LEFT JOIN task t ON t.id = a.task_id
        WHERE a.status IN ('error', 'blocked') AND {' AND '.join(where)}
        GROUP BY a.signature
        HAVING COUNT(*) >= :min_failures
        ORDER BY (COUNT(*) - SUM(a.resolved_by_action_id IS NOT NULL)) DESC,
                 COUNT(*) DESC
        LIMIT :limit
    """, params))


#: How many names a cause row will list before it stops naming them.
CAUSE_NAMES = 8


def _names(seen: list[str]) -> str | None:
    """The distinct names in a group, listed rather than counted.

    A cause spanning six signatures is the finding; '6' is not, and sends the
    reader back for another query to learn which six.
    """
    if not seen:
        return None
    if len(seen) <= CAUSE_NAMES:
        return ",".join(seen)
    return ",".join(seen[:CAUSE_NAMES]) + f",+{len(seen) - CAUSE_NAMES} more"


def _causes(conn: sqlite3.Connection, where: list[str],
            params: dict[str, Any]) -> list[dict[str, Any]]:
    """The same failures, keyed on why they failed rather than on what failed.

    Grouped here rather than in SQL because the key is a normalised error and
    SQLite has no regex: the read is one pass over the window's failures, which
    is the same scan the signature grouping does.
    """
    rows = _rows(conn.execute(f"""
        SELECT a.id                                   AS action_id,
               a.error                                AS full_error,
               {_brief_ends("a.error", EXAMPLE_CHARS)} AS example_error,
               {_brief("a.detail", EXAMPLE_CHARS)}    AS example,
               a.signature, a.tool, a.session_id, a.attempt_no,
               a.started_at                           AS at,
               a.blocked_by                           AS blocked_by,
               {_refused_unattributed()}              AS refused_unattributed,
               a.resolved_by_action_id IS NOT NULL    AS recovered,
               a.crossed_goal, a.crossed_session,
               s.repo                                 AS repo,
               t.label                                AS task
        FROM action a
        JOIN session s ON s.id = a.session_id
        LEFT JOIN task t ON t.id = a.task_id
        WHERE a.status IN ('error', 'blocked') AND {' AND '.join(where)}
        ORDER BY a.id
    """, params))

    groups: dict[str, dict[str, Any]] = {}
    members: dict[str, dict[str, list[Any]]] = {}
    for row in rows:
        key = _cause_key(row.pop("full_error"))
        group = groups.get(key)
        if group is None:
            group = groups[key] = {
                "cause": key, "failures": 0, "sessions": 0, "repos": None,
                "signatures": None, "tools": None,
                "refused_by_rule": 0, "declined_by_user": 0,
                "refused_unattributed": 0, "recovered": 0,
                "needed_new_instruction": 0, "needed_new_session": 0,
                "worst_attempt": 0, "first_at": row["at"], "last_at": row["at"],
                "example_task": row["task"], "example_action_id": row["action_id"],
                "example": row["example"], "example_error": row["example_error"],
            }
            members[key] = {"repos": [], "signatures": [], "tools": [],
                            "sessions": []}

        seen = members[key]
        for field, value in (("repos", row["repo"]), ("tools", row["tool"]),
                             ("signatures", row["signature"]),
                             ("sessions", row["session_id"])):
            if value is not None and value not in seen[field]:
                seen[field].append(value)

        group["failures"] += 1
        group["refused_by_rule"] += row["blocked_by"] == "rule"
        group["declined_by_user"] += row["blocked_by"] == "user"
        group["refused_unattributed"] += row["refused_unattributed"]
        group["recovered"] += row["recovered"]
        group["needed_new_instruction"] += row["crossed_goal"]
        group["needed_new_session"] += row["crossed_session"]
        group["worst_attempt"] = max(group["worst_attempt"], row["attempt_no"])
        group["last_at"] = row["at"]
        # A failure that was recovered is the one worth handing to trace: it
        # is the one with a series to show. Same preference the signature
        # grouping makes, for the same reason.
        if row["recovered"]:
            group["example_action_id"] = row["action_id"]
            group["example"] = row["example"]
            group["example_error"] = row["example_error"]
            group["example_task"] = row["task"]

    for key, group in groups.items():
        seen = members[key]
        group["sessions"] = len(seen["sessions"])
        group["repos"] = _names(seen["repos"])
        group["signatures"] = _names(seen["signatures"])
        group["tools"] = _names(seen["tools"])

    ordered = sorted(groups.values(),
                     key=lambda g: (g["failures"] - g["recovered"],
                                    g["failures"]), reverse=True)
    floor = int(params.get("min_failures") or 1)
    kept = [g for g in ordered if g["failures"] >= floor]
    return kept[:int(params.get("limit") or DEFAULT_LIMIT)]


def tool_stats(
    conn: sqlite3.Connection,
    *,
    group_by: str = "tool",
    since: str | None = None,
    repo: str | None = None,
    agent: str | None = None,
    kind: str | None = None,
    status: str | None = None,
    environment: str | None = None,
    tool: str | None = None,
    via: str | None = None,
    channel: str | None = None,
    session: str | None = None,
    signature: str | None = None,
    min_calls: int = 1,
    order: str = "total_ms",
    limit: int = DEFAULT_LIMIT,
) -> list[dict[str, Any]]:
    column = GROUPABLE.get(group_by, GROUPABLE["tool"])
    sort = STAT_ORDERS.get(order, STAT_ORDERS["total_ms"])
    where, params = _action_filters(
        since=since, repo=repo, kind=kind, status=status, agent=agent,
        environment=environment, tool=tool, via=via, channel=channel,
        signature=signature, session=session)
    params["min_calls"] = max(1, int(min_calls or 1))
    params["limit"] = max(1, min(int(limit or DEFAULT_LIMIT), MAX_LIMIT))

    return _rows(conn.execute(f"""
        WITH scoped AS (
            SELECT {column} AS grp, a.status AS status, a.duration_ms AS ms,
                   a.result_bytes AS bytes, a.session_id AS session_id
            FROM action a
            JOIN session s ON s.id = a.session_id
            LEFT JOIN remote_call r ON r.action_id = a.id
            WHERE {' AND '.join(where)}
        ),
        ranked AS (
            SELECT grp, ms,
                   ROW_NUMBER() OVER (PARTITION BY grp ORDER BY ms) AS rank,
                   COUNT(*)    OVER (PARTITION BY grp)              AS n
            FROM scoped WHERE ms IS NOT NULL
        ),
        latency AS (
            -- Nearest-rank percentile: ceil(p * n) as integer arithmetic.
            SELECT grp, n AS timed,
                   MAX(CASE WHEN rank = (n * 50 + 99) / 100 THEN ms END) AS p50_ms,
                   MAX(CASE WHEN rank = (n * 95 + 99) / 100 THEN ms END) AS p95_ms,
                   MAX(ms) AS max_ms,
                   SUM(ms) AS total_ms
            FROM ranked GROUP BY grp
        ),
        -- Output volume, ranked the same way. Separately counted from `timed`:
        -- a call can be measured for one and not the other, and averaging over
        -- the wrong denominator is how a quiet tool starts looking noisy.
        sized AS (
            SELECT grp, bytes,
                   ROW_NUMBER() OVER (PARTITION BY grp ORDER BY bytes) AS rank,
                   COUNT(*)     OVER (PARTITION BY grp)                AS n
            FROM scoped WHERE bytes IS NOT NULL
        ),
        volume AS (
            SELECT grp, n AS measured,
                   MAX(CASE WHEN rank = (n * 95 + 99) / 100 THEN bytes END) AS p95_bytes,
                   MAX(bytes) AS max_bytes,
                   SUM(bytes) AS total_bytes
            FROM sized GROUP BY grp
        )
        SELECT scoped.grp                                    AS "group",
               COUNT(*)                                      AS calls,
               COUNT(DISTINCT scoped.session_id)             AS sessions,
               SUM(scoped.status = 'ok')                     AS ok,
               SUM(scoped.status = 'error')                  AS failed,
               SUM(scoped.status = 'blocked')                AS blocked,
               -- Reported, never rated: nobody answered the prompt before
               -- the session closed, and no fix to this tool changes that.
               SUM(scoped.status = 'unanswered')             AS unanswered,
               ROUND(1.0 * SUM(scoped.status IN ('error', 'blocked'))
                         / COUNT(*), 3)                      AS failure_rate,
               COALESCE(latency.timed, 0)                    AS timed,
               latency.p50_ms                                AS p50_ms,
               latency.p95_ms                                AS p95_ms,
               latency.max_ms                                AS max_ms,
               latency.total_ms                              AS total_ms,
               COALESCE(volume.measured, 0)                  AS measured,
               volume.p95_bytes                              AS p95_bytes,
               volume.max_bytes                              AS max_bytes,
               volume.total_bytes                            AS total_bytes
        FROM scoped
        LEFT JOIN latency ON latency.grp IS scoped.grp
        LEFT JOIN volume  ON volume.grp  IS scoped.grp
        GROUP BY scoped.grp
        HAVING COUNT(*) >= :min_calls
        ORDER BY {sort} DESC, calls DESC
        LIMIT :limit
    """, params))


def redundancy(
    conn: sqlite3.Connection,
    *,
    since: str | None = None,
    repo: str | None = None,
    agent: str | None = None,
    kind: str | None = None,
    tool: str | None = None,
    via: str | None = None,
    channel: str | None = None,
    session: str | None = None,
    within_minutes: float = 10.0,
    min_repeats: int = 1,
    order: str = "repeats",
    limit: int = DEFAULT_LIMIT,
) -> list[dict[str, Any]]:
    order_by = REPEAT_ORDERS.get(order or "repeats", REPEAT_ORDERS["repeats"])
    where, params = _action_filters(
        since=since, repo=repo, kind=kind, agent=agent, tool=tool, via=via,
        channel=channel, session=session)
    where.append("a.status = 'ok'")

    bookkeeping = sorted(plan_mod.PLAN_TOOLS)
    names = ", ".join(f":plan{i}" for i in range(len(bookkeeping)))
    where.append(f"a.tool NOT IN ({names})")
    params.update({f"plan{i}": name for i, name in enumerate(bookkeeping)})
    params["window"] = max(0.0, float(within_minutes or 0))
    params["min_repeats"] = max(1, int(min_repeats or 1))
    params["limit"] = max(1, min(int(limit or DEFAULT_LIMIT), MAX_LIMIT))

    return _rows(conn.execute(f"""
        WITH scoped AS (
            SELECT a.id AS id, a.session_id AS session_id, a.signature AS signature,
                   a.tool AS tool, a.kind AS kind, a.intent AS intent,
                   a.detail AS detail, a.duration_ms AS ms,
                   a.result_bytes AS bytes,
                   -- What has to match for a call to be the same call again.
                   -- 'detail' alone is enough for a command or a query, whose
                   -- arguments are in it — but a file edit's detail is only
                   -- 'Edit <path>', so eighteen successive edits to one file
                   -- read as eighteen repeats of one edit. The content hash
                   -- is what separates rewriting a file from writing it: an
                   -- edit that produced different bytes did different work.
                   a.detail || COALESCE('|' || f.sha256_after, '') AS same_work,
                   a.started_at AS at, s.session_uid AS session,
                   s.repo AS repo, s.agent AS agent, t.label AS task
            FROM action a
            JOIN session s ON s.id = a.session_id
            LEFT JOIN task t ON t.id = a.task_id
            LEFT JOIN remote_call r ON r.action_id = a.id
            LEFT JOIN fs_change f ON f.action_id = a.id
            WHERE {' AND '.join(where)}
        ),
        flagged AS (
            -- Partitioned by the arguments as well as the signature. A
            -- signature is a kind of work, not an instance of it: a query tool
            -- asked seventy-three different questions shares one signature and
            -- repeated nothing. Work is only redone when the same call is made
            -- again, so `detail` — the command, or the arguments the call was
            -- given — is part of what has to match.
            SELECT scoped.*,
                   CASE WHEN (julianday(at) - julianday(
                                 LAG(at) OVER (PARTITION BY session_id, signature,
                                                            same_work
                                               ORDER BY at, id))) * 1440.0
                             <= :window
                        THEN 1 ELSE 0 END AS repeated
            FROM scoped
        )
        SELECT session, repo, agent, signature,
               -- MAX over text picks an arbitrary member of the group, which is
               -- all that is wanted, and picks the same one every time.
               MAX(tool)                                 AS tool,
               MAX(kind)                                 AS kind,
               COUNT(*)                                  AS calls,
               SUM(repeated)                             AS repeats,
               COUNT(DISTINCT same_work)                 AS distinct_args,
               SUM(CASE WHEN repeated = 1
                        THEN COALESCE(ms, 0) ELSE 0 END) AS repeated_ms,
               -- What the redoing actually cost. Redone work is rarely slow —
               -- 25 repeated edits came to 4.2 seconds — but every repeat
               -- puts its whole reply back into the context: one file was
               -- re-read for 322 KB. Time is the wrong unit for this view.
               SUM(CASE WHEN repeated = 1
                        THEN COALESCE(bytes, 0) ELSE 0 END) AS repeated_bytes,
               MIN(at)                                   AS first_at,
               MAX(at)                                   AS last_at,
               MAX(id)                                   AS last_action_id,
               MAX(task)                                 AS example_task,
               MAX(intent)                               AS example_intent,
               {_brief("MAX(detail)", EXAMPLE_CHARS)}    AS example
        FROM flagged
        GROUP BY session_id, signature
        HAVING SUM(repeated) >= :min_repeats
        ORDER BY {order_by} DESC, SUM(repeated) DESC
        LIMIT :limit
    """, params))


def disk_churn(
    conn: sqlite3.Connection,
    *,
    group_by: str = "path",
    since: str | None = None,
    repo: str | None = None,
    agent: str | None = None,
    tool: str | None = None,
    session: str | None = None,
    path: str | None = None,
    min_writes: int = 1,
    order: str = "wasted_bytes",
    limit: int = DEFAULT_LIMIT,
) -> list[dict[str, Any]]:
    column = DISK_GROUPS.get(group_by, DISK_GROUPS["path"])
    sort = DISK_ORDERS.get(order, DISK_ORDERS["wasted_bytes"])

    where = ["1=1"]
    params: dict[str, Any] = {}
    cutoff = parse_since(since)
    if cutoff:
        where.append("a.started_at >= :since")
        params["since"] = cutoff
    if repo:
        where.append("s.repo = :repo")
        params["repo"] = repo
    if agent:
        where.append("s.agent = :agent")
        params["agent"] = agent
    if tool:
        _match(where, params, "a.tool", tool, "tool")
    if session:
        _match(where, params, "s.session_uid", session, "session")
    if path:
        _match(where, params, "COALESCE(f.abs_path, f.path)", path, "path")

    ops = ", ".join(f":op{i}" for i in range(len(WRITE_OPS)))
    params.update({f"op{i}": op for i, op in enumerate(WRITE_OPS)})
    params["min_writes"] = max(1, int(min_writes or 1))
    params["limit"] = max(1, min(int(limit or DEFAULT_LIMIT), MAX_LIMIT))

    return _rows(conn.execute(f"""
        WITH scoped AS (
            SELECT f.id                          AS id,
                   COALESCE(f.abs_path, f.path)  AS path,
                   f.bytes_after                 AS bytes,
                   f.sha256_after                AS sha,
                   a.started_at                  AS at,
                   a.tool                        AS tool,
                   a.session_id                  AS session_row,
                   s.session_uid                 AS session,
                   s.repo                        AS repo,
                   s.agent                       AS agent
            FROM fs_change f
            JOIN action a  ON a.id = f.action_id
            JOIN session s ON s.id = a.session_id
            WHERE f.op IN ({ops}) AND {' AND '.join(where)}
        ),
        m AS (
            -- A write is wasted when the content it left behind is the content
            -- that was already there. Compared against the previous write to
            -- the same file whatever session or tool made it: the drive does
            -- not care which agent wrote the same bytes twice.
            SELECT scoped.*,
                   CASE WHEN sha IS NOT NULL AND sha = LAG(sha) OVER (
                             PARTITION BY path ORDER BY at, id)
                        THEN 1 ELSE 0 END AS unchanged
            FROM scoped
        )
        SELECT {column}                                       AS "group",
               COUNT(*)                                       AS writes,
               COUNT(DISTINCT m.path)                         AS files,
               COUNT(*) - COUNT(DISTINCT m.path)              AS rewrites,
               SUM(m.unchanged)                               AS unchanged,
               SUM(m.bytes IS NOT NULL)                       AS sized_writes,
               COALESCE(SUM(m.bytes), 0)                      AS bytes_written,
               COALESCE(SUM(CASE WHEN m.unchanged = 1
                                 THEN m.bytes ELSE 0 END), 0) AS wasted_bytes,
               COUNT(DISTINCT m.session_row)                  AS sessions,
               -- MAX over text picks an arbitrary member of the group, which
               -- is all a representative value needs to be, and picks the same
               -- one every time.
               MAX(m.repo)                                    AS repo,
               MAX(m.agent)                                   AS agent,
               MAX(m.tool)                                    AS tool,
               MIN(m.at)                                      AS first_at,
               MAX(m.at)                                      AS last_at
        FROM m
        GROUP BY {column}
        HAVING COUNT(*) >= :min_writes
        ORDER BY {sort} DESC, writes DESC
        LIMIT :limit
    """, params))


SERIES_LIMIT = 200


def trace(conn: sqlite3.Connection, action_id: int) -> dict[str, Any]:
    row = conn.execute("""
        SELECT a.id AS action_id, a.started_at AS at, s.repo, s.agent,
               s.session_uid AS session, a.session_id AS session_row,
               a.tool, a.kind, a.status, a.intent, a.detail, a.error,
               a.attempt_no, a.resolved_by_action_id AS resolved_by,
               -- Two different measures of "how long until this was put
               -- right", because one of them alone misleads. The span counts
               -- what the session did in between, so it is 0 for a fix that
               -- took seven minutes of the agent waiting and nothing else;
               -- the seconds are the clock.
               a.resolution_span, (
                   SELECT ROUND((julianday(w.started_at)
                                 - julianday(a.started_at)) * 86400, 1)
                   FROM action w WHERE w.id = a.resolved_by_action_id
               ) AS resolution_seconds,
               a.crossed_goal, a.crossed_session,
               a.task_id, t.label AS task, t.status AS task_status,
               a.goal_id, g.prompt AS goal_prompt
        FROM action a
        JOIN session s ON s.id = a.session_id
        LEFT JOIN task t ON t.id = a.task_id
        LEFT JOIN goal g ON g.id = a.goal_id
        WHERE a.id = :id
    """, {"id": int(action_id)}).fetchone()
    if row is None:
        return {}

    session_row = row["session_row"]
    out = {k: _clean(row[k]) for k in row.keys() if k != "session_row"}
    if not out.get("resolved_by"):
        return out

    if out.get("crossed_session"):
        out["series"] = _rows(conn.execute("""
            SELECT a.id AS action_id, a.started_at AS at, s.session_uid AS session,
                   a.tool, a.kind, a.status, a.detail
            FROM action a JOIN session s ON s.id = a.session_id
            WHERE a.id IN (:start, :end) ORDER BY a.id
        """, {"start": int(action_id), "end": int(out["resolved_by"])}))
        out["series_truncated"] = False
        return out

    out["series"] = _rows(conn.execute("""
        SELECT a.id AS action_id, a.started_at AS at, a.tool, a.kind,
               a.status, a.detail
        FROM action a
        WHERE a.session_id = :session AND a.id BETWEEN :start AND :end
        ORDER BY a.id
        LIMIT :limit
    """, {"session": session_row, "start": int(action_id),
          "end": int(out["resolved_by"]), "limit": SERIES_LIMIT + 1}))
    out["series_truncated"] = len(out["series"]) > SERIES_LIMIT
    del out["series"][SERIES_LIMIT:]
    return out
