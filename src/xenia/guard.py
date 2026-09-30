"""xenia-guard: everything xenia says to an agent, and the one call it stops.

xenia-hook only records. What xenia says BACK to an agent lives here, in a
hook of its own with its own entry in settings.json, so either can be removed
without the other: a record that also vetoes commands changes what it
measures, and nobody who installs a record expects it to refuse a call.

On PreToolUse for Bash, in this order:

- a refusal (selfmatch.py): a `pkill -f` / `pgrep -f` that would find the
  agent's own shell. The only call anything in xenia stops.
- otherwise the agora nudge (agora.nudge): once a session, on the first heavy
  command, what the agora is holding and how to post a claim.

The runtime starts every hook of an event together, so this runs BESIDE
xenia-hook, not after it: neither may depend on the other having run (the
nudge leaves the call it is asked about out of "has this session run one
before", whichever hook wrote first). And nothing here may cost the agent its
call — whatever goes wrong is logged to the fallback log and the call runs.
"""

from __future__ import annotations

import json
import sys
from typing import Any

from .hook import _fallback


def main(argv: list[str] | None = None) -> int:
    try:
        payload = json.loads(sys.stdin.read() or "{}")
    except Exception:
        return 0
    if not isinstance(payload, dict):
        return 0
    argv = argv if argv is not None else sys.argv[1:]
    if argv and not payload.get("hook_event_name"):
        payload["hook_event_name"] = argv[0]
    if payload.get("hook_event_name") != "PreToolUse":
        return 0

    refused = _refusal(payload)
    if refused:
        print(json.dumps({"hookSpecificOutput": {
            "hookEventName": "PreToolUse", "permissionDecision": "deny",
            "permissionDecisionReason": refused}}))
        return 0

    said = _nudge(payload)
    if said:
        # A notice, not a refusal. PreToolUse shows the model nothing but
        # this: stdout is otherwise dropped, and stderr only reaches it by
        # blocking the call, which a notice has no business doing.
        print(json.dumps({"hookSpecificOutput": {
            "hookEventName": "PreToolUse", "additionalContext": said}}))
    return 0


def _refusal(payload: dict[str, Any]) -> str | None:
    try:
        from . import selfmatch

        return selfmatch.check(payload)
    except Exception as exc:
        _fallback("guard", f"{type(exc).__name__}: {exc}")
        return None


def _nudge(payload: dict[str, Any]) -> str | None:
    try:
        from . import agora, db

        conn = db.connect()
        try:
            return agora.nudge(conn, payload)
        finally:
            conn.close()
    except Exception as exc:
        _fallback("nudge", f"{type(exc).__name__}: {exc}")
        return None


if __name__ == "__main__":
    raise SystemExit(main())
