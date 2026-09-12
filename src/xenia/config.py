from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

SCHEMA_VERSION = 21

GENERAL_REPO = "general"

GENESIS_HASH = "0" * 64


def _xdg(var: str, default: str) -> Path:
    return Path(os.environ.get(var) or Path.home() / default)


def db_path() -> Path:
    explicit = os.environ.get("XENIA_DB")
    if explicit:
        return Path(explicit).expanduser()
    return _xdg("XDG_DATA_HOME", ".local/share") / "xenia" / "audit.db"


def fallback_log() -> Path:
    explicit = os.environ.get("XENIA_FALLBACK_LOG")
    if explicit:
        return Path(explicit).expanduser()
    return _xdg("XDG_STATE_HOME", ".local/state") / "xenia" / "hook-errors.log"


def ledger_key_path() -> Path:
    explicit = os.environ.get("XENIA_LEDGER_KEY_FILE")
    if explicit:
        return Path(explicit).expanduser()
    return _xdg("XDG_STATE_HOME", ".local/state") / "xenia" / "ledger.key"


def ledger_anchor_path() -> Path | None:
    explicit = os.environ.get("XENIA_LEDGER_ANCHOR")
    return Path(explicit).expanduser() if explicit else None


def broker_socket() -> Path:
    """Where the service listens for credential requests.

    A runtime directory when there is one: per-user, 0700 and cleared on
    logout. macOS has none, so the state directory stands in.
    """
    explicit = os.environ.get("XENIA_BROKER_SOCKET")
    if explicit:
        return Path(explicit).expanduser()
    runtime = os.environ.get("XDG_RUNTIME_DIR")
    base = Path(runtime) if runtime else _xdg("XDG_STATE_HOME", ".local/state")
    return base / "xenia" / "broker.sock"


def site_config_path() -> Path:
    explicit = os.environ.get("XENIA_CONFIG")
    if explicit:
        return Path(explicit).expanduser()
    return _xdg("XDG_CONFIG_HOME", ".config") / "xenia" / "config.json"


_site_cache: dict[str, Any] | None = None


def site() -> dict[str, Any]:
    global _site_cache
    if _site_cache is not None:
        return _site_cache

    _site_cache = {}
    try:
        path = site_config_path()
        if path.exists():
            loaded = json.loads(path.read_text() or "{}")
            if isinstance(loaded, dict):
                _site_cache = loaded
    except Exception:
        _site_cache = {}
    return _site_cache


def reset_cache() -> None:
    global _site_cache
    _site_cache = None


def _flag(name: str, default: bool) -> bool:
    raw = os.environ.get(name)
    if raw is None:
        return default
    return raw.strip().lower() in ("1", "true", "yes", "on")


def capture_snippets() -> bool:
    return _flag("XENIA_CAPTURE_SNIPPETS", True)


SNIPPET_LIMIT = int(os.environ.get("XENIA_SNIPPET_LIMIT", "600"))
DETAIL_LIMIT = int(os.environ.get("XENIA_DETAIL_LIMIT", "2000"))
PROMPT_LIMIT = int(os.environ.get("XENIA_PROMPT_LIMIT", "4000"))
RESPONSE_LIMIT = int(os.environ.get("XENIA_RESPONSE_LIMIT", "400"))

# The most a single MCP reply may serialise to. Row limits bound rows, and rows
# are not one size — a grouped report row is a hundred bytes, a call carrying a
# shell heredoc is two thousand — so a reply inside its row limit can still be
# large enough that the client discards it whole and the agent gets nothing for
# the query. Every failure xenia has on record against its own MCP is that one:
# 57k, 92k and 106k character replies, all thrown away. Replies at 39k have
# been accepted, so the ceiling sits below that with room to spare.
REPLY_LIMIT = int(os.environ.get("XENIA_REPLY_LIMIT", "32000"))

TASK_IDLE_MINUTES = float(os.environ.get("XENIA_TASK_IDLE_MINUTES", "20"))

# How long an agora claim is believed when its holder does not say. A
# claim is released by the agent that posted it, and an agent that forgets is
# the ordinary case rather than the exception — so a claim nobody renewed
# stops being read as live work after this, and starts asking to be checked.
# It is not a licence to kill: an overrun claim whose session is still alive
# reads as 'ask', never 'yes'.
AGORA_HOLD_MINUTES = float(os.environ.get("XENIA_AGORA_HOLD_MINUTES", "120"))

# Whether the hook says one line back to an agent about to start something
# expensive — what the agora holds right now, and how to post to it. The agora
# is a convention, and a convention nobody is told about at the moment it
# applies is not one: the MCP server mentions it at startup, thousands of
# tokens before anyone types `npm run build`, and nothing else on the machine
# mentions it at all. Set XENIA_AGORA_NUDGE=0 to silence it.
AGORA_NUDGE = os.environ.get("XENIA_AGORA_NUDGE", "1") not in ("0", "no", "false")

# How far back down a session the nudge looks for heavy work it has already
# seen. Far enough to cover a long session, bounded because it is read on the
# way into a tool call that has not started yet.
AGORA_NUDGE_SCAN = int(os.environ.get("XENIA_AGORA_NUDGE_SCAN", "400"))

# The most processes one claim may name. A claim is a handle on work, not an
# inventory of a process tree; past this, name the parent and give a pattern.
AGORA_MAX_PIDS = int(os.environ.get("XENIA_AGORA_MAX_PIDS", "32"))

BUSY_TIMEOUT_MS = int(os.environ.get("XENIA_BUSY_TIMEOUT_MS", "5000"))

# How long one approval lasts. Reads get the long window, writes the short
# one, and no approval outlives the ceiling however much work happens inside
# it. Thirty minutes was measured to be too short for reads: most prompts it
# raised were a window reopening mid-task rather than a real decision.
GRANT_READ_SECONDS = int(os.environ.get("XENIA_GRANT_READ_SECONDS", 4 * 3600))
GRANT_WRITE_SECONDS = int(os.environ.get("XENIA_GRANT_WRITE_SECONDS", 30 * 60))
GRANT_CEILING_SECONDS = int(os.environ.get("XENIA_GRANT_CEILING_SECONDS", 4 * 3600))

# What one brokered response may cost. The read cap is what xenia pulls off
# the wire; the returned body is cut well below it so the reply still fits
# inside REPLY_LIMIT.
FETCH_MAX_BYTES = int(os.environ.get("XENIA_FETCH_MAX_BYTES", 1_048_576))
# What a BINARY response may cost instead. It is not decoded and never enters a
# reply, so the read cap above — sized so a reply still fits — does not bind it.
# This one exists only so a runaway download cannot fill the disk.
FETCH_MAX_BINARY_BYTES = int(
    os.environ.get("XENIA_FETCH_MAX_BINARY_BYTES", 256 * 1_048_576))
FETCH_BODY_CHARS = int(os.environ.get("XENIA_FETCH_BODY_CHARS", 20_000))
FETCH_TIMEOUT = float(os.environ.get("XENIA_FETCH_TIMEOUT", 30))
FETCH_MAX_TIMEOUT = float(os.environ.get("XENIA_FETCH_MAX_TIMEOUT", 120))
FETCH_MAX_REDIRECTS = int(os.environ.get("XENIA_FETCH_MAX_REDIRECTS", 3))

# The socket contract's version. Something outside this repo parses these
# replies, so it rises when a field changes meaning or leaves, never for an
# addition.
PROTOCOL_VERSION = 1

# Where a whole response may be written. The caller is the agent, so it gives
# a name under this directory rather than a path.
def capture_dir() -> Path:
    explicit = os.environ.get("XENIA_CAPTURE_DIR")
    if explicit:
        return Path(explicit).expanduser()
    return _xdg("XDG_DATA_HOME", ".local/share") / "xenia" / "captures"


# How long a verified scope is believed before it counts as stale.
SCOPE_MAX_AGE_DAYS = int(os.environ.get("XENIA_SCOPE_MAX_AGE_DAYS", 90))

ENV_PATTERNS: tuple[tuple[str, str], ...] = (
    ("prod", "production"),
    ("production", "production"),
    ("staging", "staging"),
    ("stage", "staging"),
    ("inf", "inf"),
    ("dev", "dev"),
    ("localhost", "local"),
    ("127.0.0.1", "local"),
)
