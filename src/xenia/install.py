from __future__ import annotations

import json
import os
import shutil
from datetime import datetime
from pathlib import Path
from typing import Any

EVENTS = ("SessionStart", "UserPromptSubmit", "PreToolUse", "PostToolUse", "Stop", "SubagentStop")

MATCHED = ("PreToolUse", "PostToolUse")

MARKER = "xenia-hook"


def hook_command(hook_path: Path, event: str) -> str:
    return f"{hook_path} {event}"


def _entry(hook_path: Path, event: str) -> dict[str, Any]:
    entry: dict[str, Any] = {
        "hooks": [{"type": "command", "command": hook_command(hook_path, event)}]
    }
    if event in MATCHED:
        entry["matcher"] = "*"
    return entry


def _merge(existing: dict[str, Any], hook_path: Path) -> tuple[dict[str, Any], list[str]]:
    merged = json.loads(json.dumps(existing)) if existing else {}
    hooks = merged.setdefault("hooks", {})
    added: list[str] = []

    for event in EVENTS:
        entries = hooks.setdefault(event, [])
        if not isinstance(entries, list):
            continue
        already = any(
            MARKER in str(hook.get("command", ""))
            for entry in entries
            if isinstance(entry, dict)
            for hook in entry.get("hooks", [])
            if isinstance(hook, dict)
        )
        if already:
            continue
        entries.append(_entry(hook_path, event))
        added.append(event)

    return merged, added


def machine_targets() -> list[tuple[str, Path]]:
    claude_home = Path(os.environ.get("CLAUDE_CONFIG_DIR") or Path.home() / ".claude")
    codex_home = Path(os.environ.get("CODEX_HOME") or Path.home() / ".codex")
    return [
        ("claude", claude_home / "settings.json"),
        ("codex", codex_home / "hooks.json"),
    ]


def repo_targets(repo: Path) -> list[tuple[str, Path]]:
    return [
        ("claude", repo / ".claude" / "settings.json"),
        ("codex", repo / ".codex" / "hooks.json"),
    ]


def plan(targets: list[tuple[str, Path]], hook_path: Path) -> list[dict[str, Any]]:
    out = []
    for label, target in targets:
        current: dict[str, Any] = {}
        if target.exists():
            try:
                current = json.loads(target.read_text() or "{}")
            except ValueError as exc:
                out.append({
                    "runtime": label, "path": str(target), "error": f"unparseable: {exc}",
                    "added": [], "content": None,
                })
                continue

        merged, added = _merge(current, hook_path)
        out.append({
            "runtime": label,
            "path": str(target),
            "exists": target.exists(),
            "added": added,
            "content": merged,
            "error": None,
        })
    return out


def apply(targets: list[tuple[str, Path]], hook_path: Path) -> list[dict[str, Any]]:
    results = plan(targets, hook_path)
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")

    for item in results:
        if item["error"] or not item["added"]:
            continue
        target = Path(item["path"])
        target.parent.mkdir(parents=True, exist_ok=True)
        if target.exists():
            backup = target.with_suffix(target.suffix + f".xenia-backup-{stamp}")
            shutil.copy2(target, backup)
            item["backup"] = str(backup)
        target.write_text(json.dumps(item["content"], indent=2) + "\n")
        item["written"] = True

    return results


def status() -> list[dict[str, Any]]:
    out = []
    for label, target in machine_targets():
        entry: dict[str, Any] = {
            "runtime": label, "path": str(target),
            "exists": target.exists(), "events": [], "error": None,
        }
        if target.exists():
            try:
                current = json.loads(target.read_text() or "{}")
            except ValueError as exc:
                entry["error"] = f"unparseable: {exc}"
                out.append(entry)
                continue
            hooks = current.get("hooks") if isinstance(current, dict) else None
            if isinstance(hooks, dict):
                entry["events"] = sorted(
                    event for event, entries in hooks.items()
                    if isinstance(entries, list) and any(
                        MARKER in str(hook.get("command", ""))
                        for item in entries if isinstance(item, dict)
                        for hook in item.get("hooks", []) if isinstance(hook, dict)
                    )
                )
        out.append(entry)
    return out
