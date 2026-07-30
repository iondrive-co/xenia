from __future__ import annotations

import json
import signal
import sqlite3
import sys
from typing import Any

from . import config, readers, readonly, redact

PROTOCOL_VERSION = "2025-06-18"
SERVER_INFO = {"name": "xenia", "version": "0.1.0"}

_SINCE = {
    "type": "string",
    "description": "Window to look back over: '24h', '7d', '30m', or a date "
                   "like '2026-07-01'. Omit for all time.",
}
_REPO = {
    "type": "string",
    "description": "Limit to one repository by name. Agent work outside any "
                   "checkout is filed under 'general'.",
}
_LIMIT = {
    "type": "integer",
    "description": f"Maximum rows (default {readonly.DEFAULT_LIMIT}, "
                   f"capped at {readonly.MAX_LIMIT}).",
}
_AGENT = {"type": "string", "description": "Which runtime: claude or codex."}

_TOOL = {
    "type": "string",
    "description": "Tool name, exactly or as a glob: 'Bash', "
                   "'mcp__acme-ssh__shell', 'mcp__acme*'.",
}
_VIA = {
    "type": "string",
    "description": "Which broker carried the call: an MCP server name, or "
                   "'direct' for the shell. Globs, so 'acme-*' covers every "
                   "server at one site.",
}
_CHANNEL = {
    "type": "string",
    "description": "What kind of far side it reached: http, ssh, git, mcp, db, "
                   "package, cloud, raw.",
}
_SESSION = {
    "type": "string",
    "description": "One agent run, by session id. Worth using on a machine "
                   "running several agents at once, where a timeline is "
                   "otherwise several agents interleaved.",
}
_SIGNATURE = {
    "type": "string",
    "description": "The normalised identity of the work, as returned by the "
                   "failures, repeats and tools views. This is how you drill "
                   "from one of those rows into the calls behind it.",
}

VIEWS = ("tasks", "instructions", "failures", "repeats", "tools", "disk")

UNIVERSAL_PARAMS = frozenset({"view", "since", "repo", "limit"})
VIEW_PARAMS: dict[str, frozenset[str]] = {
    "tasks": frozenset({"agent", "status", "source", "overstated_only", "search"}),
    "instructions": frozenset({"status", "goal_id"}),
    "failures": frozenset({"min_count"}),
    "repeats": frozenset({"agent", "tool", "via", "channel", "session", "kind",
                          "within_minutes", "min_count"}),
    "tools": frozenset({"agent", "tool", "via", "channel", "session", "signature",
                        "kind", "status", "environment", "group_by", "order",
                        "min_count"}),
    "disk": frozenset({"agent", "tool", "session", "path", "group_by", "order",
                       "min_count"}),
}


def _views(names: str, spec: dict[str, Any]) -> dict[str, Any]:
    return {**spec, "description": f"[{names}] {spec['description']}"}


TOOLS: list[dict[str, Any]] = [
    {
        "name": "xenia_report",
        "description": (
            "How coding agents have been getting on with their work on this "
            "machine. One record, six views of it — choose what a row should "
            "be with 'view':\n"
            "\n"
            "  tasks         one unit of work an agent named for itself, and "
            "whether it got there: achieved, partial, failed, abandoned or "
            "no_action. The outcome is read off the calls made under the task, "
            "never off the agent's claim about it; where the two disagree "
            "'overstated' is 1 and 'declared' is what the agent said. Start "
            "here.\n"
            "  instructions  the same question one level up: one thing the "
            "*user* asked for, and how it turned out. The only view that "
            "carries whole prompts, which is why the rest carry a 'goal_id' — "
            "pass one back as 'goal_id' for the full text of that instruction.\n"
            "  failures      one kind of work that keeps failing, worst first, "
            "grouped across sessions and repos. 'recovered' is how often a "
            "later call put it right; many failures and few recoveries is a "
            "gap in the environment or the instructions, and the most "
            "actionable row here. Pass 'example_action_id' to xenia_trace.\n"
            "  repeats       one piece of work a session did again minutes "
            "after it had already succeeded. This is the waste 'failures' "
            "cannot show, since none of it failed.\n"
            "  tools         one tool, broker, host, repo or signature, with "
            "calls, failure rate, latency and reply bytes. Ask this rather "
            "than totalling rows yourself; order by 'total_bytes' for what "
            "floods a context rather than what takes time.\n"
            "  disk          one file (or repo, tool, session) with what was "
            "written to it, how often it was rewritten, and how much of that "
            "hashed to what was already there — 'unchanged' is bytes that "
            "reached the drive and changed nothing.\n"
            "\n"
            "Rows come back under 'rows'. 'since', 'repo' and 'limit' apply to "
            "every view; each other parameter names the views that read it, "
            "and passing one to a view that does not is an error rather than a "
            "filter that quietly does nothing. For the individual calls behind "
            "any row, take its 'signature' to xenia_calls."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "view": {"type": "string", "enum": list(VIEWS),
                         "description": "Which of the six above."},
                "since": _SINCE, "repo": _REPO, "limit": _LIMIT,
                "agent": _views("tasks repeats tools disk", _AGENT),
                "tool": _views("repeats tools disk", _TOOL),
                "via": _views("repeats tools", _VIA),
                "channel": _views("repeats tools", _CHANNEL),
                "session": _views("repeats tools disk", _SESSION),
                "signature": _views("tools", _SIGNATURE),
                "kind": _views("repeats tools", {
                    "type": "string", "enum": list(readonly.KINDS),
                    "description": "Restrict to one kind of action."}),
                "status": {
                    "type": "string",
                    "description": "[tasks instructions tools] Restrict to one "
                                   "outcome. For tasks and instructions: "
                                   f"{', '.join(readonly.TASK_STATUSES)}. For "
                                   f"tools: {', '.join(readonly.STATUSES)}."},
                "source": _views("tasks", {
                    "type": "string", "enum": list(readonly.TASK_SOURCES),
                    "description": "How the task was identified: the agent's "
                                   "plan, the description on a call, or the "
                                   "shape of the work."}),
                "overstated_only": _views("tasks", {
                    "type": "boolean",
                    "description": "Only tasks the agent called finished that "
                                   "the calls under them say were not."}),
                "search": _views("tasks", {
                    "type": "string",
                    "description": "Substring match over the task label and "
                                   "the instruction it sat under."}),
                "goal_id": _views("instructions", {
                    "type": "integer",
                    "description": "One instruction, in full, by the id the "
                                   "other views return."}),
                "environment": _views("tools", {
                    "type": "string",
                    "description": "Target environment of a remote call, e.g. "
                                   "production."}),
                "path": _views("disk", {
                    "type": "string",
                    "description": "One absolute path, exactly or as a glob: "
                                   "'/home/*/.cache/*'."}),
                "group_by": {
                    "type": "string",
                    "enum": sorted(set(readonly.GROUPABLE) | set(readonly.DISK_GROUPS)),
                    "description": "[tools disk] What one row covers. For "
                                   f"tools: {', '.join(sorted(readonly.GROUPABLE))} "
                                   "(default 'tool'; a call with no such "
                                   "property — a file edit has no host — groups "
                                   "under null). For disk: "
                                   f"{', '.join(sorted(readonly.DISK_GROUPS))} "
                                   "(default 'path')."},
                "order": {
                    "type": "string",
                    "enum": sorted(set(readonly.STAT_ORDERS) | set(readonly.DISK_ORDERS)),
                    "description": "[tools disk] Sort by. For tools: "
                                   f"{', '.join(sorted(readonly.STAT_ORDERS))} "
                                   "(default 'total_ms', the time the group "
                                   "actually cost). For disk: "
                                   f"{', '.join(sorted(readonly.DISK_ORDERS))} "
                                   "(default 'wasted_bytes'; use 'writes' when "
                                   "sizes are unknown)."},
                "min_count": {
                    "type": "integer",
                    "description": "[failures repeats tools disk] Drop rows "
                                   "below this many failures, repeats, calls or "
                                   "writes. Defaults to 2 for failures — one "
                                   "failure is an incident rather than a "
                                   "pattern — and to 1 elsewhere, so nothing is "
                                   "hidden unless you ask."},
                "within_minutes": _views("repeats", {
                    "type": "number",
                    "description": "How close together two calls have to be to "
                                   "count as a repeat (default 10). Widen it "
                                   "for a slow-moving session; a large window "
                                   "starts counting honest re-runs."}),
            },
            "required": ["view"],
        },
    },
    {
        "name": "xenia_calls",
        "description": (
            "Individual calls, for the one question every xenia_report view "
            "raises and cannot answer: which call was that. A 'tools' row "
            "reporting a 33KB maximum does not say which call returned it, and "
            "one signature covering six journalctl runs is one row on purpose. "
            "Deliberately thin — action id, time, tool, status, duration, reply "
            "size and a short command, and nothing that repeats identically "
            "down the rows. Defaults to the heaviest replies first; pass the "
            "'signature' or 'tool' from a report row to drill into it, and the "
            "'action_id' it returns to xenia_trace."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "since": _SINCE, "repo": _REPO, "agent": _AGENT,
                "tool": _TOOL, "via": _VIA, "session": _SESSION,
                "signature": _SIGNATURE,
                "kind": {"type": "string", "enum": list(readonly.KINDS),
                         "description": "Restrict to one kind of action."},
                "status": {"type": "string", "enum": list(readonly.STATUSES),
                           "description": "Restrict to one outcome."},
                "order": {"type": "string",
                          "enum": ["bytes", "duration_ms", "at"],
                          "description": "Sort by reply size (default), time "
                                         "taken, or when it ran. Calls that "
                                         "never returned sort last either way."},
                "descending": {"type": "boolean",
                               "description": "Sort descending (default true)."},
                "limit": {"type": "integer",
                          "description": f"Maximum rows (default "
                                         f"{readonly.CALLS_DEFAULT_LIMIT}, "
                                         f"capped at {readonly.MAX_LIMIT}). "
                                         f"Small on purpose: this is a "
                                         f"drill-down, not a timeline."},
            },
        },
    },
    {
        "name": "xenia_trace",
        "description": "One action, the task it was working towards, its "
                       "outcome, and — when a later action fixed it — every "
                       "action in between, from that one session. This is how a "
                       "failure was actually recovered from. A fix in a later "
                       "session gives the two endpoints only: the work between "
                       "them belongs to two sessions and threading it into one "
                       "list by clock time would not be a reading of anything.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "action_id": {"type": "integer",
                              "description": "The action to trace."},
            },
            "required": ["action_id"],
        },
    },
]


def _scrub(payload: Any) -> Any:
    return json.loads(redact.redact(json.dumps(payload, default=str)))


def _one_of(name: str, value: Any, allowed) -> Any:
    if value is None:
        return None
    if value not in allowed:
        raise KeyError(f"{name} must be one of: {', '.join(sorted(allowed))}")
    return value


def _check_params(view: str, args: dict[str, Any]) -> None:
    allowed = UNIVERSAL_PARAMS | VIEW_PARAMS[view]
    strays = []
    for key in sorted(args):
        if key in allowed:
            continue
        takers = [v for v in VIEWS if key in VIEW_PARAMS[v]]
        where = f"a {'/'.join(takers)} parameter" if takers else "not a parameter"
        strays.append(f"'{key}' ({where})")
    if strays:
        raise KeyError(f"view '{view}' does not read " + ", ".join(strays))


def _report(conn, args: dict[str, Any]) -> Any:
    view = _one_of("view", args.get("view"), VIEWS)
    if view is None:
        raise KeyError(f"view is required, one of: {', '.join(VIEWS)}")
    _check_params(view, args)

    since, repo = args.get("since"), args.get("repo")
    limit = int(args.get("limit") or readonly.DEFAULT_LIMIT)

    if view == "tasks":
        return {"view": view, "rows": readonly.tasks(
            conn, since=since, repo=repo,
            status=_one_of("status", args.get("status"), readonly.TASK_STATUSES),
            source=_one_of("source", args.get("source"), readonly.TASK_SOURCES),
            agent=args.get("agent"), search=args.get("search"),
            overstated_only=bool(args.get("overstated_only")), limit=limit)}

    if view == "instructions":
        return {"view": view, "rows": readonly.goals(
            conn, since=since, repo=repo,
            status=_one_of("status", args.get("status"), readonly.TASK_STATUSES),
            goal_id=int(args["goal_id"]) if args.get("goal_id") else None,
            limit=limit)}

    if view == "failures":
        return {"view": view, "rows": readonly.friction(
            conn, since=since, repo=repo,
            min_failures=int(args.get("min_count") or 2), limit=limit)}

    if view == "repeats":
        window = float(args.get("within_minutes") or 10)
        return {"view": view, "window_minutes": window,
                "rows": readonly.redundancy(
                    conn, since=since, repo=repo, agent=args.get("agent"),
                    kind=_one_of("kind", args.get("kind"), readonly.KINDS),
                    tool=args.get("tool"), via=args.get("via"),
                    channel=args.get("channel"), session=args.get("session"),
                    within_minutes=window,
                    min_repeats=int(args.get("min_count") or 1), limit=limit)}

    if view == "tools":
        group_by = _one_of(
            "group_by", args.get("group_by"), readonly.GROUPABLE) or "tool"
        return {"view": view, "group_by": group_by,
                "rows": readonly.tool_stats(
                    conn, group_by=group_by, since=since, repo=repo,
                    agent=args.get("agent"),
                    kind=_one_of("kind", args.get("kind"), readonly.KINDS),
                    status=_one_of("status", args.get("status"), readonly.STATUSES),
                    environment=args.get("environment"), tool=args.get("tool"),
                    via=args.get("via"), channel=args.get("channel"),
                    session=args.get("session"), signature=args.get("signature"),
                    min_calls=int(args.get("min_count") or 1),
                    order=_one_of("order", args.get("order"),
                                  readonly.STAT_ORDERS) or "total_ms",
                    limit=limit)}

    group_by = _one_of(
        "group_by", args.get("group_by"), readonly.DISK_GROUPS) or "path"
    return {"view": view, "group_by": group_by,
            "rows": readonly.disk_churn(
                conn, group_by=group_by, since=since, repo=repo,
                agent=args.get("agent"), tool=args.get("tool"),
                session=args.get("session"), path=args.get("path"),
                min_writes=int(args.get("min_count") or 1),
                order=_one_of("order", args.get("order"),
                              readonly.DISK_ORDERS) or "wasted_bytes",
                limit=limit)}


def _dispatch(name: str, args: dict[str, Any], db_path=None) -> Any:
    conn = readonly.connect(db_path)
    try:
        readonly.require_current(conn)
        if name == "xenia_report":
            return _report(conn, args)
        if name == "xenia_calls":
            return {"calls": readonly.calls(
                conn,
                since=args.get("since"), repo=args.get("repo"),
                agent=args.get("agent"), tool=args.get("tool"),
                via=args.get("via"), session=args.get("session"),
                signature=args.get("signature"), kind=args.get("kind"),
                status=args.get("status"),
                order=args.get("order") or "bytes",
                descending=bool(args.get("descending", True)),
                limit=int(args.get("limit") or readonly.CALLS_DEFAULT_LIMIT),
            )}
        if name == "xenia_trace":
            return readonly.trace(conn, int(args.get("action_id", 0)))
        raise KeyError(f"unknown tool: {name}")
    except sqlite3.OperationalError as exc:
        raise readonly.explain_failure(conn, exc) from exc
    finally:
        conn.close()


class Server:
    def __init__(self, db_path=None) -> None:
        self.db_path = db_path

    def handle(self, message: dict[str, Any]) -> dict[str, Any] | None:
        method = message.get("method")
        msg_id = message.get("id")

        if msg_id is None:
            return None

        try:
            if method == "initialize":
                asked = (message.get("params") or {}).get("protocolVersion")
                return _ok(msg_id, {
                    "protocolVersion": asked or PROTOCOL_VERSION,
                    "capabilities": {"tools": {}},
                    "serverInfo": SERVER_INFO,
                    "instructions": (
                        "Read-only record of how coding agents have been "
                        "getting on with their work on this machine.\n"
                        "\n"
                        "xenia_report answers it, in six views: 'tasks' (what "
                        "agents were trying to do, and whether it worked — "
                        "start here), 'instructions' (what the user asked for), "
                        "'failures' (kinds of work that keep failing), "
                        "'repeats' (work redone that never failed), 'tools' "
                        "(counts, failure rates, latency and reply bytes — ask "
                        "for these rather than totalling rows yourself) and "
                        "'disk' (what was written, and how much of it changed "
                        "nothing).\n"
                        "\n"
                        "Every view groups. xenia_calls is the drill-down to "
                        "the individual calls behind one of their rows, and "
                        "xenia_trace takes an action id and shows how that "
                        "failure was recovered from."
                    ) + self._retirement_notice(),
                })

            if method == "ping":
                return _ok(msg_id, {})

            if method == "tools/list":
                return _ok(msg_id, {"tools": TOOLS})

            if method == "tools/call":
                params = message.get("params") or {}
                name = params.get("name") or ""
                args = params.get("arguments") or {}
                if not isinstance(args, dict):
                    return _err(msg_id, -32602, "arguments must be an object")

                payload = _scrub(_dispatch(name, args, self.db_path))
                return _ok(msg_id, {
                    "content": [{"type": "text",
                                 "text": json.dumps(payload, indent=2, default=str)}],
                    "structuredContent": payload,
                    "isError": False,
                })

            return _err(msg_id, -32601, f"method not found: {method}")

        except KeyError as exc:
            return _err(msg_id, -32602, str(exc))
        except Exception as exc:
            return _ok(msg_id, {
                "content": [{"type": "text",
                             "text": f"{type(exc).__name__}: {redact.redact(str(exc))}"}],
                "isError": True,
            })

    def _retirement_notice(self) -> str:
        try:
            conn = readonly.connect(self.db_path)
            try:
                notes = readonly.reader_retirements(conn, limit=2)
            finally:
                conn.close()
        except Exception:
            return ""
        if not notes:
            return ""
        lines = "".join(f"\n  {n['ts']}: {n['detail']}" for n in notes)
        return ("\n\nNote — a reader of this database was retired recently. If a "
                "previous xenia server in this conversation stopped answering, "
                "this is why, and reconnecting (as now) is the fix:" + lines)

    def serve(self, stdin=None, stdout=None) -> int:
        stdin = stdin or sys.stdin
        stdout = stdout or sys.stdout
        readers.register(config.SCHEMA_VERSION)
        _announce_retirement_on_sigterm()
        try:
            return self._serve(stdin, stdout)
        finally:
            readers.unregister()

    def _serve(self, stdin, stdout) -> int:
        for line in stdin:
            line = line.strip()
            if not line:
                continue
            try:
                message = json.loads(line)
            except ValueError:
                _write(stdout, _err(None, -32700, "parse error"))
                continue
            if not isinstance(message, dict):
                _write(stdout, _err(None, -32600, "invalid request"))
                continue
            response = self.handle(message)
            if response is not None:
                _write(stdout, response)
        return 0


def _ok(msg_id, result) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": msg_id, "result": result}


def _err(msg_id, code: int, text: str) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": msg_id, "error": {"code": code, "message": text}}


def _write(stdout, payload: dict[str, Any]) -> None:
    stdout.write(json.dumps(payload, default=str) + "\n")
    stdout.flush()


def _announce_retirement_on_sigterm() -> None:
    def farewell(signum, _frame):
        try:
            sys.stderr.write(
                f"xenia-mcp: exiting on signal {signum}. If a schema migration "
                f"retired this server (it was built for schema "
                f"{config.SCHEMA_VERSION}), that is expected and not an error: a "
                f"reader older than the database cannot be trusted to report "
                f"from it. Restart the server to resume — the record itself is "
                f"intact, and the hooks never stopped writing to it.\n")
            sys.stderr.flush()
        except Exception:
            pass
        readers.unregister()
        raise SystemExit(128 + signum)

    try:
        signal.signal(signal.SIGTERM, farewell)
    except (ValueError, OSError):
        pass


def main(argv: list[str] | None = None) -> int:
    return Server().serve()


if __name__ == "__main__":
    raise SystemExit(main())
