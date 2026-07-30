from __future__ import annotations

import json
import os
import signal
import subprocess
from pathlib import Path

from . import config

_MARKER = "xenia"


def registry_dir() -> Path:
    explicit = os.environ.get("XENIA_READER_DIR")
    if explicit:
        return Path(explicit).expanduser()
    return config.fallback_log().parent / "readers"


def _entry(pid: int) -> Path:
    return registry_dir() / f"{pid}.json"


def register(schema_version: int, pid: int | None = None) -> Path | None:
    pid = os.getpid() if pid is None else pid
    try:
        registry_dir().mkdir(parents=True, exist_ok=True)
        path = _entry(pid)
        path.write_text(json.dumps({
            "pid": pid,
            "schema_version": int(schema_version),
        }))
        return path
    except OSError:
        return None


def unregister(pid: int | None = None) -> None:
    pid = os.getpid() if pid is None else pid
    try:
        _entry(pid).unlink()
    except OSError:
        pass


def _cmdline(pid: int) -> str | None:
    try:
        return Path(f"/proc/{pid}/cmdline").read_bytes().replace(b"\0", b" ").decode(
            "utf-8", "replace").strip()
    except OSError:
        pass
    try:
        out = subprocess.run(["ps", "-o", "command=", "-p", str(pid)],
                             capture_output=True, text=True, timeout=5)
    except (OSError, ValueError, subprocess.SubprocessError):
        return None
    return out.stdout.strip() or None


def registered() -> list[dict]:
    out: list[dict] = []
    try:
        entries = sorted(registry_dir().glob("*.json"))
    except OSError:
        return out

    for path in entries:
        try:
            row = json.loads(path.read_text())
            pid = int(row["pid"])
        except (OSError, ValueError, KeyError, TypeError):
            _remove(path)
            continue
        live = _cmdline(pid)
        if live is None:
            _remove(path)
            continue
        row["cmdline"] = live
        row["path"] = str(path)
        out.append(row)
    return out


def _remove(path: Path) -> None:
    try:
        path.unlink()
    except OSError:
        pass


def retire_stale(current_version: int) -> list[int]:
    retired: list[int] = []
    for row in registered():
        pid = int(row["pid"])
        try:
            version = int(row.get("schema_version", 0))
        except (TypeError, ValueError):
            version = 0
        if version >= current_version or pid == os.getpid():
            continue
        if _MARKER not in (row.get("cmdline") or ""):
            continue
        try:
            os.kill(pid, signal.SIGTERM)
        except OSError:
            _remove(Path(row["path"]))
            continue
        retired.append(pid)
        _remove(Path(row["path"]))
    return retired
