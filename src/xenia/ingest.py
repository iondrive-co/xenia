from __future__ import annotations

import fnmatch
import json
import os
import re
import socket
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from typing import Any

from . import chain, classify, config, plan as plan_mod, redact


_replay_ts: str | None = None


@contextmanager
def replay_at(ts: str | None):
    global _replay_ts
    previous = _replay_ts
    _replay_ts = ts
    try:
        yield
    finally:
        _replay_ts = previous


def utcnow() -> str:
    if _replay_ts:
        return _replay_ts
    override = os.environ.get("XENIA_FAKE_NOW")
    if override:
        return override
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds")


def _cap(text: str | None, limit: int) -> str | None:
    if text is None:
        return None
    text = str(text)
    return text if len(text) <= limit else text[:limit] + f"…[+{len(text) - limit} chars]"


def _cap_ends(text: str | None, limit: int) -> str | None:
    """Keep both ends of a long value, and mark the middle that went.

    For errors, and only for errors. A command is identified by its head, so
    the head is what `_cap` keeps; an error is a sentence saying what failed
    followed, often enough, by one saying what to do about it — "ACTION: retry
    this tool", the flag that was wrong, the approval it wants. Storing only
    the head throws away the half an agent can act on, and no report can put
    it back afterwards.
    """
    if text is None:
        return None
    text = str(text)
    if len(text) <= limit:
        return text
    head, tail = limit * 2 // 3, limit - limit * 2 // 3
    return f"{text[:head]}…[+{len(text) - limit} chars]…{text[-tail:]}"


def declared_agent(payload: dict[str, Any]) -> str | None:
    """The agent this payload names, from the payload itself.

    The transcript path is the one piece of evidence that belongs to *this*
    session. Environment variables are ambient and travel: a codex run started
    from a Claude Code shell inherits CLAUDECODE=1, and reading that first
    files the whole session under the wrong agent.
    """
    transcript = payload.get("transcript_path") or ""
    if "/.codex/" in transcript:
        return "codex"
    if "/.claude/" in transcript:
        return "claude"
    return None


def detect_agent(payload: dict[str, Any]) -> str:
    named = declared_agent(payload)
    if named:
        return named

    if os.environ.get("CLAUDECODE") == "1" or os.environ.get("CLAUDE_CODE") == "1":
        return "claude"
    if os.environ.get("CODEX_SANDBOX") or os.environ.get("CODEX_HOME"):
        return "codex"

    declared = (os.environ.get("AI_AGENT") or "").lower()
    if "claude" in declared:
        return "claude"
    if "codex" in declared:
        return "codex"
    return "unknown"


def is_repo_root(path: str) -> bool:
    marker = os.path.join(path, ".git")
    if os.path.isfile(marker):
        return True
    return os.path.exists(os.path.join(marker, "HEAD"))


def repo_for(cwd: str | None) -> tuple[str, str | None]:
    if not cwd:
        return config.GENERAL_REPO, None
    path = os.path.abspath(cwd)
    while True:
        if is_repo_root(path):
            return os.path.basename(path), path
        parent = os.path.dirname(path)
        if parent == path:
            return config.GENERAL_REPO, None
        path = parent


# Fields a runtime echoes into the hook payload that the agent never sees.
# Claude Code returns the whole pre-edit file as 'originalFile' on every
# Edit reply, so a one-line change to a 400 KB file was recorded as a
# 400 KB reply — and 'tools' ordered by total_bytes, the view that answers
# "what floods a context", put Edit top at 51 MB against Read's 7 MB. What
# reaches the model is the patch, which is measured with everything else.
ECHOED_BACK = ("originalFile",)


def response_bytes(payload: dict[str, Any]) -> int | None:
    response = payload.get("tool_response")
    if response is None:
        return None
    if isinstance(response, str):
        return len(response.encode("utf-8", "replace"))
    if isinstance(response, dict):
        response = {k: v for k, v in response.items() if k not in ECHOED_BACK}
    try:
        return len(json.dumps(response, default=str).encode("utf-8", "replace"))
    except (TypeError, ValueError):
        return len(str(response).encode("utf-8", "replace"))


def outcome_of(payload: dict[str, Any]) -> tuple[str, str | None, str | None]:
    response = payload.get("tool_response")

    if isinstance(response, str):
        summary = _cap(response, config.RESPONSE_LIMIT)
        if response.lstrip().lower().startswith(("error:", "error executing")):
            return "error", _cap_ends(response, 500), summary
        return "ok", None, summary

    if not isinstance(response, dict):
        return "ok", None, None

    flagged = bool(response.get("isError") or response.get("is_error"))
    exit_code = response.get("exit_code", response.get("exitCode"))
    interrupted = bool(response.get("interrupted"))

    error_text = response.get("error")
    if isinstance(error_text, dict):
        error_text = error_text.get("message") or json.dumps(error_text)

    summary_source = (
        error_text
        or response.get("stdout")
        or response.get("stderr")
        or response.get("result")
        or response.get("content")
    )
    if not isinstance(summary_source, (str, type(None))):
        summary_source = json.dumps(summary_source)[: config.RESPONSE_LIMIT]
    summary = _cap(summary_source, config.RESPONSE_LIMIT)

    if flagged or error_text or (isinstance(exit_code, int) and exit_code != 0):
        detail = error_text or response.get("stderr") or f"exit code {exit_code}"
        return "error", _cap_ends(str(detail), 500), summary
    if interrupted:
        return "error", "interrupted", summary
    return "ok", None, summary


INTENT_KEYS = ("description", "reason", "intent", "purpose")


def stated_intent(args: Any) -> str | None:
    if not isinstance(args, dict):
        return None
    for key in INTENT_KEYS:
        value = args.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return None


def append_event(conn: sqlite3.Connection, payload: dict[str, Any], agent: str) -> int:
    safe = redact.redact_obj(payload)
    body = json.dumps(safe, sort_keys=True, default=str)
    digest = chain.sha256(body)

    fields = {
        "ts": payload.get("_ts") or utcnow(),
        "agent": agent,
        "session_uid": payload.get("session_id"),
        "hook": payload.get("hook_event_name") or "Unknown",
        "tool": payload.get("tool_name"),
        "cwd": payload.get("cwd"),
        "payload_sha256": digest,
    }

    keyed = chain.mode(conn) == chain.KEYED
    conn.execute("BEGIN IMMEDIATE")
    prev = chain.head(conn)
    cursor = conn.execute(
        "INSERT INTO event (ts, recorded_at, agent, session_uid, hook, tool, cwd, "
        "                   payload, payload_sha256, prev_hash, row_hash) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (
            fields["ts"], utcnow(), agent, fields["session_uid"], fields["hook"],
            fields["tool"], fields["cwd"], body, digest, prev,
            chain.row_hash(prev, fields, keyed=keyed),
        ),
    )
    return int(cursor.lastrowid)


def reconcile_agent(conn: sqlite3.Connection, session_id: int, stored: str,
                    payload: dict[str, Any], agent: str) -> None:
    """Correct a session whose agent was settled before its runtime said so.

    Every view names the agent by joining through the session row, so a
    session opened under the wrong name reports its whole run as another
    agent's work. Evidence carried by the payload overrules what is stored;
    an unknown session yields to anything at all.
    """
    settled = declared_agent(payload) or (agent if stored == "unknown" else None)
    if settled and settled != stored:
        conn.execute("UPDATE session SET agent = ? WHERE id = ?", (settled, session_id))


def ensure_session(conn: sqlite3.Connection, payload: dict[str, Any], agent: str) -> int:
    uid = payload.get("session_id") or f"anon-{agent}-{os.getppid()}"
    row = conn.execute("SELECT id, agent FROM session WHERE session_uid = ?",
                       (uid,)).fetchone()
    if row:
        reconcile_agent(conn, int(row["id"]), row["agent"], payload, agent)
        return int(row["id"])

    cwd = payload.get("cwd") or os.getcwd()
    repo, repo_path = repo_for(cwd)
    cursor = conn.execute(
        "INSERT INTO session (session_uid, agent, repo, repo_path, cwd, host, "
        "                     os_user, started_at) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        (uid, agent, repo, repo_path, cwd, socket.gethostname(),
         os.environ.get("USER") or os.environ.get("LOGNAME"), utcnow()),
    )
    return int(cursor.lastrowid)


def current_goal(conn: sqlite3.Connection, session_id: int) -> int | None:
    row = conn.execute(
        "SELECT id FROM goal WHERE session_id = ? ORDER BY seq DESC LIMIT 1",
        (session_id,),
    ).fetchone()
    return int(row["id"]) if row else None


def add_goal(conn: sqlite3.Connection, session_id: int, prompt: str) -> int:
    row = conn.execute(
        "SELECT COALESCE(MAX(seq), 0) + 1 AS next FROM goal WHERE session_id = ?",
        (session_id,),
    ).fetchone()
    text = redact.redact(prompt) or ""
    cursor = conn.execute(
        "INSERT INTO goal (session_id, seq, prompt, prompt_sha256, created_at) "
        "VALUES (?, ?, ?, ?, ?)",
        (session_id, int(row["next"]), _cap(text, config.PROMPT_LIMIT),
         chain.sha256(prompt or ""), utcnow()),
    )

    current = current_task(conn, session_id)
    if current and current["source"] != "plan":
        set_current_task(conn, session_id, None)
    return int(cursor.lastrowid)


_SOURCE_RANK = {"signature": 1, "intent": 2, "plan": 3}


def current_task(conn: sqlite3.Connection, session_id: int) -> sqlite3.Row | None:
    return conn.execute(
        "SELECT t.id, t.source, t.declared, "
        "       (SELECT MAX(COALESCE(a.ended_at, a.started_at)) FROM action a "
        "         WHERE a.task_id = t.id) AS last_at "
        "FROM task t JOIN session s ON s.current_task_id = t.id WHERE s.id = ?",
        (session_id,),
    ).fetchone()


def went_cold(task: sqlite3.Row) -> bool:
    last = task["last_at"]
    if not last:
        return False
    try:
        gap = datetime.fromisoformat(utcnow()) - datetime.fromisoformat(last)
    except ValueError:
        return False
    return gap > timedelta(minutes=config.TASK_IDLE_MINUTES)


def set_current_task(conn: sqlite3.Connection, session_id: int,
                     task_id: int | None) -> None:
    conn.execute("UPDATE session SET current_task_id = ? WHERE id = ?",
                 (task_id, session_id))


def signature_label(tool: str, result: classify.Result) -> str:
    target = (result.target or "").strip()
    if result.kind == "exec" and target:
        return target
    if not target:
        return _cap(result.detail, 80) or tool
    if _same_name(tool, target):
        return tool
    head, arrow, tail = target.partition(" -> ")
    if arrow and _same_name(tool, head):
        return f"{tool} -> {tail}".strip()
    return f"{tool} {target}"


def _same_name(tool: str, target: str) -> bool:
    flat_tool = re.sub(r"[^a-z0-9]", "", tool.lower())
    flat_target = re.sub(r"[^a-z0-9]", "", target.lower())
    if not flat_target:
        return True
    return flat_target in flat_tool or flat_tool in flat_target


def upsert_task(conn: sqlite3.Connection, session_id: int, *, label: str,
                source: str, key: str | None = None, scope: int | None = None,
                external_id: str | None = None,
                declared: str | None = None) -> int | None:
    text = redact.redact(label) or ""
    base_key = key or plan_mod.label_key(text)
    match_key = f"{base_key}#g{scope}" if base_key and scope else base_key

    row = None
    if external_id:
        row = conn.execute(
            "SELECT id, source, label FROM task "
            "WHERE session_id = ? AND external_id = ?",
            (session_id, external_id),
        ).fetchone()
    if row is None and match_key:
        row = conn.execute(
            "SELECT id, source, label FROM task "
            "WHERE session_id = ? AND label_key = ?",
            (session_id, match_key),
        ).fetchone()

    if row is not None:
        task_id = int(row["id"])
        if _SOURCE_RANK.get(source, 0) > _SOURCE_RANK.get(row["source"], 0):
            conn.execute("UPDATE task SET source = ? WHERE id = ?", (source, task_id))
        if text and text[:plan_mod.LABEL_LIMIT] != row["label"]:
            conn.execute(
                "UPDATE OR IGNORE task SET label = ?, label_key = ? WHERE id = ?",
                (text[:plan_mod.LABEL_LIMIT], match_key, task_id))
        if external_id:
            conn.execute("UPDATE task SET external_id = ? WHERE id = ?",
                         (external_id, task_id))
        if declared:
            conn.execute(
                "UPDATE task SET declared = ?, declared_at = ? WHERE id = ?",
                (declared, utcnow(), task_id))
        return task_id

    if not text or not match_key:
        return None

    seq = conn.execute(
        "SELECT COALESCE(MAX(seq), 0) + 1 AS next FROM task WHERE session_id = ?",
        (session_id,),
    ).fetchone()
    cursor = conn.execute(
        "INSERT INTO task (session_id, goal_id, seq, label, label_key, source, "
        "                  external_id, declared, declared_at, started_at) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (session_id, current_goal(conn, session_id), int(seq["next"]),
         text[:plan_mod.LABEL_LIMIT], match_key, source, external_id,
         declared, utcnow() if declared else None, utcnow()),
    )
    return int(cursor.lastrowid)


def apply_plan(conn: sqlite3.Connection, session_id: int,
               stated: plan_mod.Plan) -> None:
    in_progress: int | None = None
    named: list[int] = []

    for item in stated.items:
        task_id = upsert_task(
            conn, session_id, label=item.label, source="plan",
            external_id=item.external_id, declared=item.status)
        if task_id is None:
            continue
        named.append(task_id)
        if item.status == "in_progress":
            in_progress = task_id

    if stated.whole_list:
        placeholders = ",".join("?" * len(named)) or "NULL"
        conn.execute(
            f"UPDATE task SET declared = 'dropped', declared_at = ? "
            f"WHERE session_id = ? AND source = 'plan' "
            f"  AND COALESCE(declared, '') NOT IN ('completed', 'dropped') "
            f"  AND id NOT IN ({placeholders})",
            (utcnow(), session_id, *named),
        )

    if in_progress is not None:
        set_current_task(conn, session_id, in_progress)
        return

    current = current_task(conn, session_id)
    if current and current["declared"] in ("completed", "dropped"):
        set_current_task(conn, session_id, None)


def task_for_action(conn: sqlite3.Connection, session_id: int, tool: str,
                    intent: str | None, result: classify.Result) -> int | None:
    if plan_mod.is_plan_tool(tool):
        return None

    current = current_task(conn, session_id)
    if current is not None and current["source"] == "plan":
        return int(current["id"])

    if current is not None and went_cold(current):
        set_current_task(conn, session_id, None)
        current = None

    if intent:
        task_id = upsert_task(conn, session_id, label=intent, source="intent")
        if task_id is not None:
            set_current_task(conn, session_id, task_id)
            return task_id

    # A run of work the agent never named: same instruction, no idle gap. It is
    # one job, so it is one task. Splitting it per signature turned a single
    # piece of work into a row for every call it took — a read, fourteen greps
    # and an edit reported as sixteen tasks of one action each. What the calls
    # were is what xenia_calls is for; a new instruction (add_goal) or a quiet
    # spell (went_cold) is what ends the run.
    if current is not None:
        return int(current["id"])

    task_id = upsert_task(conn, session_id, label=signature_label(tool, result),
                          source="signature", key=result.signature,
                          scope=current_goal(conn, session_id))
    if task_id is not None:
        set_current_task(conn, session_id, task_id)
    return task_id


def corr_key(payload: dict[str, Any]) -> str:
    explicit = payload.get("tool_use_id") or payload.get("toolUseId")
    if explicit:
        return f"id:{explicit}"
    args = json.dumps(payload.get("tool_input") or {}, sort_keys=True, default=str)
    return f"sig:{payload.get('tool_name')}:{chain.sha256(args)[:16]}"


def _mcp_parts(tool: str) -> tuple[str, str] | None:
    if not tool.startswith("mcp__"):
        return None
    parts = tool.split("__", 2)
    if len(parts) < 3:
        return None
    return parts[1], parts[2]


_BROKER_HINTS: tuple[tuple[str, str, str | None], ...] = (
    ("sftp",             "ssh",    None),
    ("ssh",              "ssh",    None),
    ("ansible",          "ssh",    None),
    ("kubernetes",       "cloud",  None),
    ("kubectl",          "cloud",  None),
    ("k8s",              "cloud",  None),
    ("terraform",        "cloud",  None),
    ("aws",              "cloud",  None),
    ("gcloud",           "cloud",  None),
    ("azure",            "cloud",  None),
    ("postgres",         "db",     None),
    ("mysql",            "db",     None),
    ("sqlserver",        "db",     None),
    ("redis",            "db",     None),
    ("mongo",            "db",     None),
    ("github",           "http",   "api.github.com"),
    ("gitlab",           "http",   None),
    ("bitbucket",        "http",   "api.bitbucket.org"),
    ("slack",            "http",   "slack.com"),
    ("pagerduty",        "http",   "api.pagerduty.com"),
    ("jira",             "http",   None),
    ("prometheus",       "http",   None),
    ("grafana",          "http",   None),
    ("loki",             "http",   None),
    ("elastic",          "http",   None),
    ("monitor",          "http",   None),
    ("dashboard",        "http",   None),
    ("registry",         "http",   None),
    ("http",             "http",   None),
    ("fetch",            "http",   None),
)

_MCP_MUTATING = ("write", "create", "update", "delete", "set", "post", "apply",
                 "restart", "deploy", "send", "exec", "shell", "run")


def broker_for(server: str) -> tuple[str, str | None]:
    configured = config.site().get("brokers")
    if isinstance(configured, dict):
        entry = configured.get(server)
        if entry is None:
            for pattern, candidate in configured.items():
                if fnmatch.fnmatchcase(server, str(pattern)):
                    entry = candidate
                    break
        if isinstance(entry, dict):
            return str(entry.get("channel") or "mcp"), entry.get("host") or None
        if isinstance(entry, str):
            return entry, None

    lowered = server.lower()
    for fragment, channel, host in _BROKER_HINTS:
        if fragment in lowered:
            return channel, host
    return "mcp", None


def analyse(payload: dict[str, Any], cwd: str | None, repo_path: str | None) -> classify.Result:
    tool = payload.get("tool_name") or ""
    args = payload.get("tool_input") or {}
    if not isinstance(args, dict):
        args = {"value": args}

    mcp = _mcp_parts(tool)
    if mcp:
        return _analyse_mcp(tool, mcp, args)
    if tool == "Bash":
        return _analyse_bash(args, cwd, repo_path)
    if tool in ("Write", "Edit", "MultiEdit", "NotebookEdit", "Update"):
        return _analyse_write(tool, args, cwd, repo_path)
    if tool in ("Read", "Glob", "Grep", "LS", "NotebookRead"):
        return _analyse_read(tool, args, cwd, repo_path)
    if tool in ("WebFetch", "WebSearch"):
        return _analyse_web(tool, args)
    if tool in ("Task", "Agent"):
        target = args.get("subagent_type") or "general-purpose"
        return classify.Result(
            kind="other",
            signature=classify.signature("subagent", target),
            target=target,
            detail=_cap(args.get("description") or args.get("prompt"), config.DETAIL_LIMIT) or "",
        )

    command = args.get("command")
    if isinstance(command, str) and command.strip():
        return _analyse_bash(args, cwd, repo_path)

    return classify.Result(
        kind="other",
        signature=classify.signature("tool", tool),
        target=tool,
        detail=_cap(json.dumps(args, default=str), config.DETAIL_LIMIT) or "",
    )


def _analyse_mcp(tool: str, mcp: tuple[str, str], args: dict[str, Any]) -> classify.Result:
    server, operation = mcp
    channel, default_host = broker_for(server)

    host = args.get("host") or args.get("hostname") or default_host
    if not host and isinstance(args.get("hosts"), list) and args["hosts"]:
        host = ", ".join(str(h) for h in args["hosts"][:3])
    environment = args.get("environment") or args.get("env") or classify.environment_of(host)
    mutating = any(word in operation.lower() for word in _MCP_MUTATING)

    detail_args = {
        k: v for k, v in args.items()
        if k not in ("content", "body", "text") and k not in INTENT_KEYS
    }
    result = classify.Result(
        kind="remote_call",
        signature=classify.signature("mcp", server, operation, str(environment or "")),
        target=f"{server}/{operation}" + (f" -> {host}" if host else ""),
        detail=_cap(json.dumps(detail_args, default=str), config.DETAIL_LIMIT) or "",
        remote=classify.RemoteFact(
            channel=channel,
            via=server,
            method=operation,
            host=str(host) if host else None,
            environment=str(environment) if environment else None,
            mutating=mutating,
        ),
    )
    return result


def _exec_target(verb: str, verb_args: list[str],
                 heredoc: str | None = None) -> str:
    # The label keeps the opening line of a script, which reads far better
    # than a digest of it. The signature cannot: two unrelated one-off scripts
    # open `import json, os` alike, and grouping by that would call them the
    # same work. See classify.exec_operand.
    code, rest = classify.program_of(verb, verb_args, heredoc)
    operand = (code if code is not None else classify.first_operand(rest) or "").strip()
    first_line = operand.splitlines()[0].strip() if operand else ""
    return _cap(f"{verb} {first_line}".strip(), 120)


def _analyse_bash(args: dict[str, Any], cwd: str | None, repo_path: str | None) -> classify.Result:
    command = str(args.get("command") or "")

    remote: classify.RemoteFact | None = None
    fs: list[classify.FsFact] = []
    calls: list[tuple[str, list[str]]] = []

    for segment in classify.segments(command):
        verb, seg_args = classify.verb_and_args(classify.tokenise(segment))
        if not verb:
            continue
        calls.append((verb, seg_args))

        found = classify.remote_fact(verb, seg_args, segment)
        if found and (remote is None or _outranks(found, remote)):
            remote = found

        for path, op in classify.fs_facts(verb, seg_args, segment):
            display, absolute, in_repo = classify.normalise_path(path, cwd, repo_path)
            fs.append(classify.FsFact(
                path=display, op=op, abs_path=absolute, in_repo=in_repo,
                sensitivity=classify.sensitivity_of(display),
            ))

    spawned = bool(remote and remote.channel == classify.MCP_SPAWN_CHANNEL)
    if remote and not spawned:
        kind = "remote_call"
    elif spawned:
        # Running the server binary is what this command is. A file written
        # somewhere else on the same line — a scratch file, a redirected
        # transcript — is incidental to it, and taking the kind from there
        # filed the spawn as a file change. The write is still recorded; it is
        # just not what the action was.
        kind = "exec"
    else:
        kind = "fs_change" if fs else "exec"

    primary, primary_args = classify.significant_call(calls)
    heredoc = classify.heredoc_bodies(command)
    if remote:
        sig = classify.signature("remote", remote.channel, remote.host or "", remote.method or "")
    elif fs:
        sig = classify.signature("fs", fs[0].op, fs[0].path)
    else:
        sig = classify.signature("exec", primary,
                                 classify.exec_operand(primary, primary_args, heredoc))

    result = classify.Result(
        kind=kind,
        signature=sig,
        target=(remote.host or remote.url if remote
                else (fs[0].path if fs
                      else _exec_target(primary, primary_args, heredoc))),
        detail=_cap(redact.redact(command), config.DETAIL_LIMIT) or "",
        remote=remote,
        fs=fs,
    )
    return result


def _outranks(candidate: classify.RemoteFact, current: classify.RemoteFact) -> bool:
    def score(fact: classify.RemoteFact) -> tuple[int, int, int]:
        return (
            fact.environment == "production",
            fact.mutating,
            fact.channel not in ("package",),
        )
    return score(candidate) > score(current)


def _analyse_write(
    tool: str, args: dict[str, Any], cwd: str | None, repo_path: str | None
) -> classify.Result:
    path = (
        args.get("file_path")
        or args.get("notebook_path")
        or args.get("path")
        or "<unknown>"
    )
    display, absolute, in_repo = classify.normalise_path(str(path), cwd, repo_path)
    sensitivity = classify.sensitivity_of(display)

    content = args.get("content")
    if content is None and tool == "Edit":
        content = args.get("new_string")
    if content is None and tool == "MultiEdit" and isinstance(args.get("edits"), list):
        content = "\n".join(
            str(e.get("new_string", "")) for e in args["edits"] if isinstance(e, dict)
        )
    content = redact.redact(content) if isinstance(content, str) else None

    if tool == "Write":
        op = "modify" if os.path.exists(absolute) else "create"
    else:
        op = "modify"

    fact = classify.FsFact(
        path=display,
        op=op,
        abs_path=absolute,
        in_repo=in_repo,
        sensitivity=sensitivity,
        bytes_after=len(content.encode()) if content is not None else None,
        sha256_after=chain.sha256(content) if content is not None else None,
        snippet=(
            _cap(content, config.SNIPPET_LIMIT)
            if content is not None and config.capture_snippets()
            else None
        ),
    )

    result = classify.Result(
        kind="fs_change",
        signature=classify.signature("fs", op, display),
        target=display,
        detail=f"{tool} {display}",
        fs=[fact],
    )
    return result


def _analyse_read(
    tool: str, args: dict[str, Any], cwd: str | None, repo_path: str | None
) -> classify.Result:
    path = args.get("file_path") or args.get("path") or args.get("pattern") or ""
    display = classify.normalise_path(str(path), cwd, repo_path)[0] if path else ""

    return classify.Result(
        kind="fs_read",
        signature=classify.signature("read", display or tool),
        target=display or None,
        detail=f"{tool} {display}".strip(),
    )


def _analyse_web(tool: str, args: dict[str, Any]) -> classify.Result:
    url = str(args.get("url") or "")
    query = args.get("query")
    host, port = (None, None)
    if url:
        from urllib.parse import urlsplit
        parts = urlsplit(url)
        host, port = parts.hostname, parts.port

    result = classify.Result(
        kind="remote_call",
        signature=classify.signature("remote", "http", host or tool),
        target=host or str(query or tool),
        detail=_cap(redact.redact(url or str(query)), config.DETAIL_LIMIT) or "",
        remote=classify.RemoteFact(
            channel="http", method="GET", host=host, port=port, url=url or None,
            environment=classify.environment_of(host),
        ),
    )
    return result


def record(conn: sqlite3.Connection, payload: dict[str, Any]) -> int:
    agent = detect_agent(payload)
    event_id = append_event(conn, payload, agent)

    hook = payload.get("hook_event_name") or ""
    session_id = ensure_session(conn, payload, agent)

    if hook == "UserPromptSubmit":
        add_goal(conn, session_id, str(payload.get("prompt") or ""))
    elif hook == "PreToolUse":
        _open_action(conn, event_id, session_id, payload)
    elif hook == "PostToolUse":
        _close_action(conn, event_id, session_id, payload)
    elif hook in ("Stop", "SubagentStop", "SessionEnd"):
        close_session(conn, session_id, reason=hook.lower(),
                      transcript=payload.get("transcript_path"))

    conn.commit()
    return event_id


def _open_action(
    conn: sqlite3.Connection, event_id: int, session_id: int, payload: dict[str, Any]
) -> int:
    row = conn.execute("SELECT repo_path FROM session WHERE id = ?", (session_id,)).fetchone()
    repo_path = row["repo_path"] if row else None
    cwd = payload.get("cwd")

    result = analyse(payload, cwd, repo_path)
    seq_row = conn.execute(
        "SELECT COALESCE(MAX(seq), 0) + 1 AS next FROM action WHERE session_id = ?",
        (session_id,),
    ).fetchone()

    args = payload.get("tool_input") or {}
    tool = payload.get("tool_name") or ""
    intent = stated_intent(args)

    stated = plan_mod.read(tool, args)
    if stated is not None:
        apply_plan(conn, session_id, stated)

    cursor = conn.execute(
        "INSERT INTO action (session_id, goal_id, task_id, seq, start_event_id, corr_key, "
        "                    tool, kind, intent, signature, target, detail, status, "
        "                    started_at) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'started', ?)",
        (
            session_id, current_goal(conn, session_id),
            task_for_action(conn, session_id, tool, intent, result),
            int(seq_row["next"]), event_id,
            corr_key(payload), tool, result.kind,
            _cap(redact.redact(intent), 400) if intent else None,
            result.signature, _cap(result.target, 400), result.detail, utcnow(),
        ),
    )
    action_id = int(cursor.lastrowid)

    if result.remote:
        r = result.remote
        conn.execute(
            "INSERT INTO remote_call (action_id, channel, method, host, port, url, "
            "                         environment, via, mutating) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (action_id, r.channel, _cap(r.method, 200), r.host, r.port,
             _cap(redact.redact(r.url), 1000), r.environment, r.via, int(r.mutating)),
        )

    for fact in result.fs:
        conn.execute(
            "INSERT INTO fs_change (action_id, path, abs_path, op, in_repo, "
            "                       bytes_after, sha256_after, sensitivity, snippet) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (action_id, fact.path, fact.abs_path, fact.op, int(fact.in_repo),
             fact.bytes_after, fact.sha256_after, fact.sensitivity, fact.snippet),
        )

    return action_id


def _close_action(
    conn: sqlite3.Connection, event_id: int, session_id: int, payload: dict[str, Any]
) -> None:
    key = corr_key(payload)
    row = conn.execute(
        "SELECT id, started_at FROM action "
        "WHERE session_id = ? AND corr_key = ? AND status = 'started' "
        "ORDER BY seq LIMIT 1",
        (session_id, key),
    ).fetchone()

    if row is None:
        action_id = _open_action(conn, event_id, session_id, payload)
        conn.execute(
            "UPDATE action SET detail = detail || ' [recorded at completion; "
            "no PreToolUse seen]' WHERE id = ?",
            (action_id,),
        )
        row = conn.execute(
            "SELECT id, started_at FROM action WHERE id = ?", (action_id,)
        ).fetchone()

    status, error, summary = outcome_of(payload)
    ended = utcnow()
    duration = _elapsed_ms(row["started_at"], ended)

    args = payload.get("tool_input") or {}
    stated = plan_mod.read(payload.get("tool_name"), args,
                           payload.get("tool_response"))
    if stated is not None and status == "ok":
        apply_plan(conn, session_id, stated)

    conn.execute(
        "UPDATE action SET status = ?, error = ?, ended_at = ?, duration_ms = ?, "
        "                  result_bytes = ?, end_event_id = ? WHERE id = ?",
        (status, _cap_ends(redact.redact(error), 1000), ended, duration,
         response_bytes(payload), event_id, row["id"]),
    )
    if summary:
        conn.execute(
            "UPDATE remote_call SET response_summary = ? WHERE action_id = ?",
            (_cap(redact.redact(summary), config.RESPONSE_LIMIT), row["id"]),
        )


def _elapsed_ms(start: str | None, end: str) -> int | None:
    if not start:
        return None
    try:
        began = datetime.fromisoformat(start)
        finished = datetime.fromisoformat(end)
    except ValueError:
        return None
    return int((finished - began).total_seconds() * 1000)


DENIED_ERROR = (
    "denied — no completion event, and the agent went on to make further calls: "
    "a PreToolUse hook refused this one, or it was declined at the permission "
    "prompt, and the agent carried on around it"
)

# What the runtime calls each kind of refusal, mapped to what someone reading
# the report has to DO about it. A rule is a code or config change; a user
# decline is a permissions decision that is not the agent's to make. Anything
# else stays NULL rather than guessing, because a wrong attribution here sends
# the reader to the wrong file.
DENIAL_KINDS = {
    "permission-rule": "rule",
    "user-rejected": "user",
}

# How far back through a transcript to look for denial records. They sit next
# to the calls they refused, and a session's dangling actions are resolved at
# its close, so the tail is where the answers are. Bounded because this runs
# inside a hook: a transcript grows to tens of MB and no denial is worth
# stalling the agent's next tool call over.
TRANSCRIPT_TAIL_BYTES = 2_000_000


def outcomes_in(transcript_path: str | None, *,
                whole: bool = False) -> dict[str, tuple[str, str | None, str | None]]:
    """Map tool_use_id -> (status, blocked_by, error) from the runtime's record.

    No PostToolUse hook fires for a call the runtime refused — and, it turns
    out, for a good many that simply FAILED: of the calls this record had
    settled as denials, the transcripts show `Exit code 1` with a traceback,
    `screenshot failed`, and one review that completed successfully. Inferring
    "something refused this" from a missing completion turned every one of
    those into a permission problem, and the failures view into a list of
    identical sentences explaining nothing.

    The transcript has the answer the hook never got: a `toolDenialKind` when
    something really did refuse the call, and otherwise the tool_result the
    call actually returned.

    Reads only the tail by default, which is where a just-ended call's answer
    is and keeps a hook off the critical path. `whole` is for going back over
    a session that ended long ago: transcripts here run to 10 MB and an answer
    from the middle of one is nowhere near the end.
    """
    if not transcript_path or not os.path.exists(transcript_path):
        return {}

    try:
        handle = open(transcript_path, "rb")
    except OSError:
        return {}

    with handle:
        if not whole:
            try:
                handle.seek(0, os.SEEK_END)
                size = handle.tell()
                handle.seek(max(0, size - TRANSCRIPT_TAIL_BYTES))
                # A partial first line when the file was longer than the tail.
                if size > TRANSCRIPT_TAIL_BYTES:
                    handle.readline()
            except OSError:
                return {}
        return _outcomes_from(handle)


def _text_of(block: dict[str, Any]) -> str | None:
    content = block.get("content")
    if isinstance(content, str):
        return content
    if content is None:
        return None
    try:
        return json.dumps(content, default=str)
    except (TypeError, ValueError):
        return str(content)


def _outcomes_from(lines) -> dict[str, tuple[str, str | None, str | None]]:
    found: dict[str, tuple[str, str | None, str | None]] = {}
    for raw_line in lines:
        line = raw_line.decode("utf-8", "replace") if isinstance(
            raw_line, bytes) else raw_line
        if '"tool_result"' not in line:
            continue
        try:
            record = json.loads(line)
        except ValueError:
            continue

        blocked_by = DENIAL_KINDS.get(record.get("toolDenialKind") or "")
        for block in (record.get("message") or {}).get("content") or []:
            if not isinstance(block, dict) or block.get("type") != "tool_result":
                continue
            use_id = block.get("tool_use_id")
            if not use_id:
                continue

            if blocked_by:
                # A refusal: the runtime names who, and for a rule the
                # result is that rule's own words — the reason to keep.
                result = record.get("toolUseResult")
                reason = result if isinstance(result, str) else _text_of(block)
                found[str(use_id)] = (
                    "blocked", blocked_by,
                    _cap_ends(reason, config.RESPONSE_LIMIT))
            elif block.get("is_error"):
                found[str(use_id)] = (
                    "error", None,
                    _cap_ends(_text_of(block), config.RESPONSE_LIMIT))
            else:
                # It ran and returned. Whatever kept the completion hook from
                # firing, this was never a refusal.
                found[str(use_id)] = ("ok", None, None)
    return found
OUTSTANDING_ERROR = (
    "outstanding — no completion event and nothing followed it: the call was "
    "still in flight when the session ended, waiting on an approval that never "
    "came or on a runtime that exited under it"
)


def apply_outcomes(conn: sqlite3.Connection, session_id: int,
                   transcript: str | None, *, whole: bool = False) -> int:
    """Settle this session's uncompleted calls on what the runtime recorded.

    Runs at every session close, and again over history when the record is
    migrated: a row settled by inference is exactly the row this can improve,
    so one is re-opened when nothing better has explained it yet. A call that
    got a real completion event is never touched — it already has the truth,
    with the timings and reply size this cannot supply.

    The inferred texts are placeholders and give way to the real message;
    anything else on the row came from somewhere better and is left alone.
    """
    settled = 0
    for use_id, (status, blocked_by, why) in outcomes_in(
            transcript, whole=whole).items():
        settled += conn.execute(
            "UPDATE action SET status = ?, "
            "                  ended_at = COALESCE(ended_at, ?), "
            "                  blocked_by = ?, "
            "                  error = CASE WHEN error IS NULL "
            "                                 OR error IN (?, ?) "
            "                               THEN ? ELSE error END "
            "WHERE session_id = ? AND corr_key = ? "
            "  AND (status = 'started' "
            "       OR (blocked_by IS NULL "
            "           AND status IN ('blocked', 'unanswered')))",
            (status, utcnow(), blocked_by, DENIED_ERROR, OUTSTANDING_ERROR,
             why, session_id, f"id:{use_id}"),
        ).rowcount
    return settled


def close_session(conn: sqlite3.Connection, session_id: int, reason: str,
                  transcript: str | None = None) -> None:
    from . import resolve

    # What the runtime said, before what xenia can infer. A refused call is
    # only ever settled here — no PostToolUse fires for one — so this is the
    # last chance to record why, and 'denied' below is the fallback for the
    # ones the transcript does not explain.
    apply_outcomes(conn, session_id, transcript)

    conn.execute(
        "UPDATE action SET status = 'blocked', ended_at = ?, "
        "                  error = COALESCE(error, ?) "
        "WHERE session_id = ? AND status = 'started' "
        "  AND EXISTS (SELECT 1 FROM action later "
        "               WHERE later.session_id = action.session_id "
        "                 AND later.seq > action.seq "
        "                 AND later.status IN ('ok', 'error'))",
        (utcnow(), DENIED_ERROR, session_id),
    )
    # Not 'blocked'. Nothing refused these — the session ended with the call
    # still in flight, usually on an approval prompt nobody answered before
    # closing the window. Scoring that as breakage put a row in every
    # failures query that no fix would ever remove, so it gets an outcome of
    # its own and the failure predicates stop matching it.
    conn.execute(
        "UPDATE action SET status = 'unanswered', ended_at = ?, "
        "                  error = COALESCE(error, ?) "
        "WHERE session_id = ? AND status = 'started'",
        (utcnow(), OUTSTANDING_ERROR, session_id),
    )
    conn.execute(
        "UPDATE session SET ended_at = ?, end_reason = ? WHERE id = ? AND ended_at IS NULL",
        (utcnow(), reason, session_id),
    )
    resolve.resolve_session(conn, session_id)


def log_ingest_error(conn: sqlite3.Connection, stage: str, detail: str, raw: str = "") -> None:
    conn.execute(
        "INSERT INTO ingest_error (ts, stage, detail, raw_prefix) VALUES (?, ?, ?, ?)",
        (utcnow(), stage, _cap(detail, 2000), _cap(redact.redact(raw), 400)),
    )
    conn.commit()
