from __future__ import annotations

import sqlite3
from datetime import datetime, timedelta, timezone
from typing import Any

from . import config, plan as plan_mod, redact

MAX_LIMIT = 500
DEFAULT_LIMIT = 200

SUMMARY_CHARS = 160
EXAMPLE_CHARS = 320

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
STATUSES = ("started", "ok", "error", "blocked")
TASK_STATUSES = ("open", "achieved", "partial", "failed", "no_action", "abandoned")
TASK_SOURCES = ("plan", "intent", "signature")

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
    if not since:
        return None
    text = str(since).strip().lower()
    now = datetime.now(timezone.utc)
    try:
        if text.endswith("h"):
            return (now - timedelta(hours=float(text[:-1]))).isoformat()
        if text.endswith("d"):
            return (now - timedelta(days=float(text[:-1]))).isoformat()
        if text.endswith("m"):
            return (now - timedelta(minutes=float(text[:-1]))).isoformat()
    except ValueError:
        return None
    return text if text[:1].isdigit() else None


def _clean(value: Any) -> Any:
    if isinstance(value, str):
        return redact.redact(value)
    return value


def _rows(cursor) -> list[dict[str, Any]]:
    return [{k: _clean(row[k]) for k in row.keys()} for row in cursor]


def _brief(column: str, chars: int) -> str:
    return (f"CASE WHEN length({column}) > {int(chars)} "
            f"THEN substr({column}, 1, {int(chars)}) || '…' ELSE {column} END")


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
          order: str = "bytes", descending: bool = True,
          limit: int = CALLS_DEFAULT_LIMIT) -> list[dict[str, Any]]:
    where, params = _action_filters(
        since=since, repo=repo, tool=tool, via=via, session=session,
        signature=signature, status=status, kind=kind, agent=agent)
    column = SORTABLE.get(order, "a.result_bytes")
    direction = "DESC" if descending else "ASC"
    params["limit"] = max(1, min(int(limit or CALLS_DEFAULT_LIMIT), MAX_LIMIT))

    return _rows(conn.execute(f"""
        SELECT a.id            AS action_id,
               a.started_at    AS at,
               s.agent         AS agent,
               s.repo          AS repo,
               a.tool          AS tool,
               a.status        AS status,
               a.duration_ms   AS duration_ms,
               a.result_bytes  AS result_bytes,
               r.via           AS via,
               r.host          AS host,
               {_brief("a.detail", CALL_CHARS)} AS detail
        FROM action a
        JOIN session s ON s.id = a.session_id
        LEFT JOIN remote_call r ON r.action_id = a.id
        WHERE {' AND '.join(where)}
        ORDER BY ({column} IS NULL), {column} {direction}, a.id {direction}
        LIMIT :limit
    """, params))


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
               SUM(a.status = 'blocked')                  AS blocked
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


def tasks(conn: sqlite3.Connection, *, since: str | None = None,
          repo: str | None = None, status: str | None = None,
          source: str | None = None, agent: str | None = None,
          goal: int | None = None, overstated_only: bool = False,
          search: str | None = None,
          limit: int = DEFAULT_LIMIT) -> list[dict[str, Any]]:
    where = ["1=1"]
    params: dict[str, Any] = {}
    cutoff = parse_since(since)
    if cutoff:
        where.append("at >= :since")
        params["since"] = cutoff
    if repo:
        where.append("repo = :repo")
        params["repo"] = repo
    if status in TASK_STATUSES:
        where.append("status = :status")
        params["status"] = status
    if source in TASK_SOURCES:
        where.append("source = :source")
        params["source"] = source
    if agent:
        where.append("agent = :agent")
        params["agent"] = agent
    if goal:
        where.append("goal_id = :goal")
        params["goal"] = int(goal)
    if overstated_only:
        where.append("overstated = 1")
    if search:
        where.append("(label LIKE :q OR goal_prompt LIKE :q)")
        params["q"] = f"%{search}%"
    params["limit"] = max(1, min(int(limit or DEFAULT_LIMIT), MAX_LIMIT))

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
        ORDER BY t.at DESC LIMIT :limit
    """, params))


def friction(conn: sqlite3.Connection, *, since: str | None = None,
             repo: str | None = None, min_failures: int = 2,
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
    params["min_failures"] = max(1, int(min_failures or 1))
    params["limit"] = max(1, min(int(limit or DEFAULT_LIMIT), MAX_LIMIT))

    return _rows(conn.execute(f"""
        SELECT a.signature                              AS signature,
               COUNT(*)                                 AS failures,
               COUNT(DISTINCT a.session_id)             AS sessions,
               COUNT(DISTINCT s.repo)                   AS repos,
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
               {_brief("MAX(a.error)", EXAMPLE_CHARS)}  AS example_error
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
    limit: int = DEFAULT_LIMIT,
) -> list[dict[str, Any]]:
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
                   a.started_at AS at, s.session_uid AS session,
                   s.repo AS repo, s.agent AS agent, t.label AS task
            FROM action a
            JOIN session s ON s.id = a.session_id
            LEFT JOIN task t ON t.id = a.task_id
            LEFT JOIN remote_call r ON r.action_id = a.id
            WHERE {' AND '.join(where)}
        ),
        flagged AS (
            SELECT scoped.*,
                   CASE WHEN (julianday(at) - julianday(
                                 LAG(at) OVER (PARTITION BY session_id, signature
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
               COUNT(DISTINCT detail)                    AS distinct_args,
               SUM(CASE WHEN repeated = 1
                        THEN COALESCE(ms, 0) ELSE 0 END) AS repeated_ms,
               MIN(at)                                   AS first_at,
               MAX(at)                                   AS last_at,
               MAX(id)                                   AS last_action_id,
               MAX(task)                                 AS example_task,
               MAX(intent)                               AS example_intent,
               {_brief("MAX(detail)", EXAMPLE_CHARS)}    AS example
        FROM flagged
        GROUP BY session_id, signature
        HAVING SUM(repeated) >= :min_repeats
        ORDER BY SUM(repeated) DESC, repeated_ms DESC
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
               a.resolution_span, a.crossed_goal, a.crossed_session,
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
