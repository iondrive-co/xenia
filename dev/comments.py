#!/usr/bin/env python3

import io
import json
import re
import subprocess
import sys
import tokenize
from collections import Counter
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent

HASH_COMMENTED = {".toml", ".sh", ".cfg", ".ini", ".yml", ".yaml"}
DIRECTIVE = re.compile(r"#\s*(?:noqa\b|type:|pragma\b|fmt:|pylint:)")
WORD = re.compile(r"[a-z0-9_]+")

REASON = (
    "Agents do not write comments or docstrings in this repo (CLAUDE.md, "
    "\"Comments\"). This change adds comment text to {path}: {sample}. "
    "Deleting comment text is allowed; writing or rewording it is not. Make "
    "the change without the comment, and put the explanation in your reply "
    "to the user instead."
)


def is_python(path: str, text: str) -> bool:
    return path.endswith(".py") or text.startswith("#!/usr/bin/env python")


def python_comments(text: str) -> list[str]:
    try:
        tokens = list(tokenize.generate_tokens(io.StringIO(text).readline))
    except (tokenize.TokenError, IndentationError, SyntaxError):
        return fallback_comments(text)
    found = []
    for i, token in enumerate(tokens):
        if token.type == tokenize.COMMENT:
            if token.start[0] == 1 and token.string.startswith("#!"):
                continue
            if DIRECTIVE.match(token.string):
                continue
            found.append(token.string)
        elif token.type == tokenize.STRING and is_docstring(tokens, i):
            found.append(token.string)
    return found


def is_docstring(tokens: list, i: int) -> bool:
    j = i - 1
    while j >= 0 and tokens[j].type in (tokenize.NL, tokenize.COMMENT):
        j -= 1
    if j >= 0 and tokens[j].type not in (tokenize.INDENT, tokenize.NEWLINE,
                                         tokenize.DEDENT, tokenize.ENCODING):
        return False
    k = i + 1
    while k < len(tokens) and tokens[k].type == tokenize.NL:
        k += 1
    return k < len(tokens) and tokens[k].type in (tokenize.NEWLINE, tokenize.ENDMARKER)


def fallback_comments(text: str) -> list[str]:
    found = re.findall(r'"""[\s\S]*?(?:"""|\Z)|\'\'\'[\s\S]*?(?:\'\'\'|\Z)', text)
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith("#") and not stripped.startswith("#!") \
                and not DIRECTIVE.match(stripped):
            found.append(stripped)
    return found


def comments(path: str, text: str) -> list[str]:
    if is_python(path, text):
        return python_comments(text)
    suffix = Path(path).suffix
    if suffix == ".sql":
        return re.findall(r"--.*", text)
    if suffix in HASH_COMMENTED:
        return [m for m in re.findall(r"(?:^|\s)(#.*)", text, re.M)
                if not m.startswith("#!")]
    return []


def words(path: str, text: str) -> Counter:
    counted = Counter()
    for comment in comments(path, text):
        counted.update(WORD.findall(comment.lower()))
    return counted


def added(path: str, before: str, after: str) -> list[str]:
    grown = words(path, after) - words(path, before)
    return sorted(grown)


def sample(path: str, before: str, after: str, limit: int = 3) -> str:
    old = set(comments(path, before))
    new = [c for c in comments(path, after) if c not in old]
    shown = [" ".join(c.split())[:120] for c in new[:limit]]
    return "; ".join(repr(s) for s in shown) or ", ".join(added(path, before, after)[:12])


def after_edit(tool: str, args: dict, before: str) -> str | None:
    if tool == "Write":
        return args.get("content")
    if tool == "Edit":
        edits = [args]
    elif tool == "MultiEdit":
        edits = args.get("edits") or []
    else:
        return None
    text = before
    for edit in edits:
        old, new = edit.get("old_string"), edit.get("new_string")
        if not isinstance(old, str) or not isinstance(new, str) or old not in text:
            return None
        text = text.replace(old, new) if edit.get("replace_all") else text.replace(old, new, 1)
    return text


def inside_repo(file_path: str) -> str | None:
    try:
        target = Path(file_path).resolve()
        relative = target.relative_to(REPO)
    except (ValueError, OSError):
        return None
    if relative.parts and relative.parts[0] == ".git":
        return None
    return str(relative)


def refusal(payload: dict) -> str | None:
    if payload.get("hook_event_name") != "PreToolUse":
        return None
    tool = payload.get("tool_name")
    args = payload.get("tool_input")
    if tool not in ("Edit", "MultiEdit", "Write") or not isinstance(args, dict):
        return None
    file_path = args.get("file_path")
    if not isinstance(file_path, str):
        return None
    path = inside_repo(file_path)
    if path is None:
        return None
    try:
        before = Path(file_path).read_text(encoding="utf-8")
    except FileNotFoundError:
        before = ""
    except (OSError, UnicodeDecodeError):
        return None
    after = after_edit(tool, args, before)
    if after is None or not added(path, before, after):
        return None
    return REASON.format(path=path, sample=sample(path, before, after))


def committed(path: str) -> str:
    shown = subprocess.run(["git", "-C", str(REPO), "show", f"HEAD:{path}"],
                           capture_output=True)
    if shown.returncode != 0:
        return ""
    return shown.stdout.decode("utf-8", "replace")


def uncommitted_comments() -> dict[str, list[str]]:
    listed = subprocess.run(
        ["git", "-C", str(REPO), "ls-files", "--cached", "--others", "--exclude-standard"],
        capture_output=True, text=True)
    if listed.returncode != 0:
        return {}
    found = {}
    for path in listed.stdout.split():
        try:
            now = (REPO / path).read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            continue
        grown = added(path, committed(path), now)
        if grown:
            found[path] = grown
    return found


def main() -> int:
    try:
        payload = json.loads(sys.stdin.read() or "{}")
        refused = refusal(payload) if isinstance(payload, dict) else None
    except Exception:
        return 0
    if refused:
        print(json.dumps({"hookSpecificOutput": {
            "hookEventName": "PreToolUse", "permissionDecision": "deny",
            "permissionDecisionReason": refused}}))
    return 0


if __name__ == "__main__":
    sys.exit(main())
