from __future__ import annotations

import hashlib
import os
import re
import shlex
import time
from typing import Any, Iterable

from . import config, selfmatch

_AGENT_NAMES = {"claude": ("claude",), "codex": ("codex",)}
_RUNTIMES = {"node", "bun", "deno"}
_KILLERS = {"kill", "pkill", "killall"}
_PARENT_READ = re.compile(
    r"\bps\b[^;&|\n]*\bppid\b|\$\{?PPID\b|/proc/[^\s/]+/stat(?:us)?\b|\bPPid\b|\bpstree\b[^;&|\n]*-s\b")


class Tree:
    def __init__(self, start: int | None = None) -> None:
        self.start = start if start is not None else os.getpid()

    def parent(self, pid: int) -> int | None:
        try:
            with open(f"/proc/{pid}/stat", "rb") as f:
                raw = f.read()
            return int(raw[raw.rfind(b")") + 2:].split()[1])
        except (OSError, ValueError, IndexError):
            return None

    def argv(self, pid: int) -> list[str]:
        try:
            with open(f"/proc/{pid}/cmdline", "rb") as f:
                raw = f.read()
        except OSError:
            return []
        return [a.decode("utf-8", "replace") for a in raw.rstrip(b"\0").split(b"\0") if a]

    def children(self, pid: int) -> list[int]:
        found: list[int] = []
        try:
            tasks = os.listdir(f"/proc/{pid}/task")
        except OSError:
            return found
        for tid in tasks:
            try:
                with open(f"/proc/{pid}/task/{tid}/children") as f:
                    found.extend(int(p) for p in f.read().split())
            except (OSError, ValueError):
                continue
        return found

    def ancestors(self, pid: int, limit: int = 12) -> list[int]:
        chain: list[int] = []
        current: int | None = pid
        while current and current > 1 and len(chain) < limit:
            current = self.parent(current)
            if current:
                chain.append(current)
        return chain


def _is_agent(argv: list[str], agent: str) -> bool:
    if not argv:
        return False
    names = _AGENT_NAMES.get(agent) or tuple(n for v in _AGENT_NAMES.values() for n in v)
    head = os.path.basename(argv[0])
    if head in _RUNTIMES and len(argv) > 1:
        head = os.path.basename(argv[1])
    return head in names


def agent_pid(tree: Tree, agent: str) -> int | None:
    for pid in tree.ancestors(tree.start):
        if _is_agent(tree.argv(pid), agent):
            return pid
    return None


def warning(payload: dict[str, Any], tree: Tree | None = None) -> str | None:
    if payload.get("hook_event_name") != "PreToolUse" or payload.get("tool_name") != "Bash":
        return None
    args = payload.get("tool_input")
    command = args.get("command") if isinstance(args, dict) else None
    if not isinstance(command, str) or not any(k in command for k in ("kill", "pgrep")):
        return None
    from .ingest import detect_agent

    tree = tree or Tree()
    agent = detect_agent(payload)
    cli = agent_pid(tree, agent)
    if cli is None:
        return None
    found = list(_sibling_matches(command, tree, cli)) + list(_parent_kills(command, tree, cli))
    if not found:
        return None
    return _message(found, cli, " ".join(tree.argv(cli))[:80])


def _sibling_matches(command: str, tree: Tree, cli: int) -> Iterable[str]:
    own = set(tree.ancestors(tree.start)) | {tree.start}
    relatives = [p for p in tree.children(cli) if p not in own]
    if not relatives:
        return
    lines = {p: " ".join(tree.argv(p)) for p in relatives}
    for call in selfmatch.invocations(command):
        if not call["full"]:
            continue
        if call["tool"] == "pgrep" and not call["consumed"]:
            continue
        pattern = call["pattern"]
        if pattern is None or selfmatch._unreadable(pattern):
            continue
        flags = re.IGNORECASE if call["ignore_case"] else 0
        for pid, line in lines.items():
            try:
                hit = (re.fullmatch if call["exact"] else re.search)(pattern, line, flags)
            except (re.error, RecursionError, ValueError):
                break
            if hit:
                shown = " ".join(shlex.quote(w) for w in call.get("shown") or call["words"])
                yield (f"`{shown}` matches PID {pid}, which is not the job: it is another "
                       f"process your CLI started (`{line[:100]}`), such as the shell a "
                       f"background command runs in or an MCP server. -A does not leave it "
                       f"out, because it is not an ancestor of this shell. Its parent is "
                       f"your CLI, so `ps -o ppid=` on it gives your CLI's PID.")


def _parent_kills(command: str, tree: Tree, cli: int) -> Iterable[str]:
    text = selfmatch._without_heredocs(command)
    tokens = selfmatch._tokens(text) or []
    killers = [i for i, t in enumerate(tokens)
               if os.path.basename(t) in _KILLERS and selfmatch._command_position(tokens, i)]
    for body in selfmatch._substitutions(text):
        if any(os.path.basename(t) in _KILLERS for t in selfmatch._tokens(body) or []):
            killers.append(-1)
    if not killers:
        return
    if _PARENT_READ.search(text):
        yield ("it reads a parent PID and kills. Every shell your tool starts, foreground "
               "or background, is a direct child of your CLI, so the parent of a shell "
               "you found is your CLI itself, and `$PPID` here is your CLI too.")
    protected = {cli, *tree.ancestors(cli)}
    for i in killers:
        if i < 0:
            continue
        j = i + 1
        while j < len(tokens) and tokens[j] not in selfmatch._OPERATORS:
            if tokens[j].isdigit() and int(tokens[j]) in protected:
                what = "your CLI" if int(tokens[j]) == cli else "a parent of your CLI"
                yield f"it kills PID {tokens[j]}, which is {what}."
            j += 1


def _message(found: list[str], cli: int, cli_line: str) -> str:
    said = " ".join(f"({n}) {f}" for n, f in enumerate(dict.fromkeys(found), 1))
    return (f"xenia-guard is holding this command once, because it may kill your own CLI "
            f"(PID {cli}, `{cli_line}`) or one of its other processes: {said} "
            f"Killing the CLI ends this session and every background job it runs (exit 143). "
            f"To stop a job, use the PID you captured when you started it (`$!`, a pidfile), "
            f"its own stop script, or your tool's way of stopping a background task. "
            f"If you have checked and this is what you mean, run exactly the same command "
            f"again and it will run.")


def _key(payload: dict[str, Any], command: str) -> str:
    session = str(payload.get("session_id") or "")
    return hashlib.sha256(f"{session}\0{command}".encode()).hexdigest()


def held_before(payload: dict[str, Any]) -> bool:
    command = (payload.get("tool_input") or {}).get("command") or ""
    marker = config.guard_held_dir() / _key(payload, command)
    try:
        age = time.time() - marker.stat().st_mtime
    except OSError:
        return False
    try:
        marker.unlink()
    except OSError:
        pass
    return age <= config.GUARD_HOLD_SECONDS


def hold(payload: dict[str, Any]) -> None:
    command = (payload.get("tool_input") or {}).get("command") or ""
    folder = config.guard_held_dir()
    folder.mkdir(parents=True, exist_ok=True, mode=0o700)
    now = time.time()
    for old in folder.iterdir():
        try:
            if now - old.stat().st_mtime > config.GUARD_HOLD_SECONDS:
                old.unlink()
        except OSError:
            continue
    (folder / _key(payload, command)).touch()
