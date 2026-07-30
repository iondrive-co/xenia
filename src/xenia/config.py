from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

SCHEMA_VERSION = 9

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

TASK_IDLE_MINUTES = float(os.environ.get("XENIA_TASK_IDLE_MINUTES", "20"))

BUSY_TIMEOUT_MS = int(os.environ.get("XENIA_BUSY_TIMEOUT_MS", "5000"))

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
