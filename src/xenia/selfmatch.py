"""Whether a shell command's process match will find the agent's own shell.

The check behind the one call xenia-guard refuses (guard.py runs it).

An agent's shell tool runs a command as `bash -c "<the whole command>"` —
Claude Code inside a `source <snapshot> … eval '…'` wrapper, Codex as
`bash -lc`. `pkill -f P` and `pgrep -f P` test P against the FULL command line
of every process, that shell's included, and the pattern is written inside the
command it is testing, so it nearly always matches its own shell:

- `pkill -f P` kills the shell running it. The tool reports a bare
  `Exit code 144` and the rest of the output is lost.
- `kill $(pgrep -f P)` and `pgrep -f P | xargs kill` do the same.
- `until ! pgrep -f P; do sleep 20; done` waits for itself, until the tool's
  timeout.
- `pgrep -f P >/dev/null && echo running` reports itself as the job.

procps-ng 4 has the exact fix — `-A` / `--ignore-ancestors` leaves out the
calling shell and its parents — so the refusal names it.

Nothing here guesses. A pattern that cannot be read as a literal (a variable,
a regex Python will not compile) is let through, and so is a `pgrep` whose
answer only reaches the agent's eyes: it shows its own shell in the list, which
is misleading but harmless, and refusing every `pgrep -af` would cost more than
it saves.
"""

from __future__ import annotations

import os
import re
import shlex
from typing import Any, Iterator

_OPERATORS = {";", "&", "&&", "|", "||", "(", ")", "\n", ";;", "|&"}
# Words after which the next word is a command, not an argument.
_PREFIXES = {"do", "then", "else", "elif", "if", "while", "until", "!", "{",
             "sudo", "command", "exec", "nohup", "nice", "time", "xargs", "env",
             "$", "`"}
# Short options that take a value, for pkill and pgrep (procps-ng 4).
_SHORT_VALUE = set("qgGOPstuUFrd")
_LONG_VALUE = {"--queue", "--pgroup", "--group", "--older", "--parent", "--session",
               "--signal", "--terminal", "--euid", "--uid", "--pidfile", "--runstates",
               "--cgroup", "--ns", "--nslist", "--delimiter"}
_SIGNAL = re.compile(r"-(?:\d+|(?:SIG)?[A-Z][A-Z0-9+-]+)$")
_HEREDOC = re.compile(r"(?<!<)<<(?!<)(-?)\s*(['\"]?)([A-Za-z_][A-Za-z0-9_]*)\2")
# Runs of punctuation shlex hands back whole, split into what the shell reads.
_PUNCT = re.compile(r"&&|\|\||;;|\|&|>>|>&|<&|&>|>\||<<<|<<|<>|[();<>|&\n]")
_CONSUMERS = {"kill", "xargs", "read", "wc"}


def check(payload: dict[str, Any]) -> str | None:
    """The reason to refuse this call, or None to let it run."""
    if payload.get("hook_event_name") != "PreToolUse" or payload.get("tool_name") != "Bash":
        return None
    args = payload.get("tool_input")
    command = args.get("command") if isinstance(args, dict) else None
    if not isinstance(command, str) or "pkill" not in command and "pgrep" not in command:
        return None
    from .ingest import detect_agent

    return refusal(command, agent=detect_agent(payload))


def refusal(command: str, *, agent: str = "claude") -> str | None:
    target = _wrapper(command, agent)
    for call in invocations(command):
        if call["ignore_ancestors"] or call["exact"] or not call["full"]:
            continue
        if call["tool"] == "pgrep" and not call["consumed"]:
            continue
        pattern = call["pattern"]
        if pattern is None or _unreadable(pattern):
            continue
        try:
            found = re.search(pattern, target, re.IGNORECASE if call["ignore_case"] else 0)
        except (re.error, RecursionError, ValueError):
            continue
        if found:
            return _message(call, found.group(0))
    return None


def invocations(command: str) -> Iterator[dict[str, Any]]:
    """Every pkill/pgrep this command runs, with the options that decide it.

    Heredoc bodies are data (a script being written, a Python program), so a
    pkill inside one is not run here. `$(…)` and backticks are scanned as
    commands of their own, because shlex reads `"$(pgrep -f x)"` as one word.
    """
    text = _without_heredocs(command)
    seen: set[tuple[int, str]] = set()
    queue = list(_parts(text))
    while queue:
        depth, part = queue.pop(0)
        tokens = _tokens(part)
        if tokens is None:
            continue
        # `timeout 60 bash -c 'until ! pgrep -f …'`: the script is one word
        # here and a command line of its own to the shell that runs it.
        for i, token in enumerate(tokens[:-2]):
            if (os.path.basename(token) in ("bash", "sh", "dash", "zsh")
                    and re.fullmatch(r"-[a-z]*c[a-z]*", tokens[i + 1])
                    and len(queue) < 32):
                queue.extend(_parts(_without_heredocs(tokens[i + 2])))
        for i, token in enumerate(tokens):
            if os.path.basename(token) not in ("pkill", "pgrep") or not _command_position(tokens, i):
                continue
            call = _parse(tokens, i, nested=depth > 0)
            key = (depth, " ".join(tokens[i:i + 6]))
            if key in seen:
                continue
            seen.add(key)
            yield call


def _parse(tokens: list[str], i: int, *, nested: bool) -> dict[str, Any]:
    call = {"tool": os.path.basename(tokens[i]), "full": False, "ignore_ancestors": False,
            "exact": False, "ignore_case": False, "pattern": None, "consumed": nested,
            "words": [tokens[i]]}
    j = i + 1
    while j < len(tokens) and tokens[j] not in _OPERATORS:
        word = tokens[j]
        call["words"].append(word)
        if call["pattern"] is None and word == "--":
            j += 1
            if j < len(tokens) and tokens[j] not in _OPERATORS:
                call["pattern"] = tokens[j]
                call["words"].append(tokens[j])
            j += 1
            continue
        if call["pattern"] is None and word.startswith("--"):
            name = word.split("=", 1)[0]
            call["full"] |= name == "--full"
            call["ignore_ancestors"] |= name == "--ignore-ancestors"
            call["exact"] |= name == "--exact"
            call["ignore_case"] |= name == "--ignore-case"
            if name in _LONG_VALUE and "=" not in word:
                j += 1
                if j < len(tokens):
                    call["words"].append(tokens[j])
        elif call["pattern"] is None and word.startswith("-") and len(word) > 1:
            if word == "-A":
                call["ignore_ancestors"] = True
            elif call["tool"] == "pkill" and _SIGNAL.match(word):
                pass
            else:
                for k, flag in enumerate(word[1:]):
                    call["full"] |= flag == "f"
                    call["ignore_ancestors"] |= flag == "A"
                    call["exact"] |= flag == "x"
                    call["ignore_case"] |= flag == "i"
                    call["consumed"] |= flag == "c"
                    if flag in _SHORT_VALUE:
                        if k == len(word) - 2:
                            j += 1
                            if j < len(tokens):
                                call["words"].append(tokens[j])
                        break
        elif word in (">", ">>", ">|", "&>"):
            # stdout goes somewhere other than the agent's eyes; `2>` does not count
            call["consumed"] |= tokens[j - 1] != "2" or word == "&>"
            if j + 1 < len(tokens) and tokens[j + 1] not in _OPERATORS:
                j += 1
                call["words"].append(tokens[j])
        elif word in (">&", "<", "<&"):
            if j + 1 < len(tokens) and tokens[j + 1] not in _OPERATORS:
                j += 1
                call["words"].append(tokens[j])
        elif call["pattern"] is None:
            call["pattern"] = word
            call["shown"] = list(call["words"])
        j += 1
    call["consumed"] |= _feeds_something(tokens, i, j)
    return call


def _feeds_something(tokens: list[str], start: int, end: int) -> bool:
    """Whether the shell acts on this pgrep's answer instead of printing it."""
    before = tokens[start - 1] if start > 0 else None
    if before in ("if", "while", "until", "!", "&&", "||", "$", "`"):
        return True
    if end < len(tokens) and tokens[end] in ("&&", "||"):
        return True
    # Follow the pipeline this pgrep starts, to the end of its command.
    j = end
    while j < len(tokens) and tokens[j] == "|":
        j += 1
        if j < len(tokens) and (os.path.basename(tokens[j]) in _CONSUMERS or tokens[j] in ("while", "for", "{", "(")):
            return True
        while j < len(tokens) and tokens[j] not in _OPERATORS:
            j += 1
    return False


def _command_position(tokens: list[str], i: int) -> bool:
    if i == 0:
        return True
    before = tokens[i - 1]
    if before in _OPERATORS or before in _PREFIXES:
        return True
    if re.match(r"[A-Za-z_][A-Za-z0-9_]*=", before):
        return True
    # `timeout 30 pkill …`, `sudo -n pkill …`
    return i >= 2 and tokens[i - 2] in ("timeout", "sudo")


def _tokens(text: str) -> list[str] | None:
    lexer = shlex.shlex(text, posix=True, punctuation_chars="();<>|&\n")
    lexer.whitespace = " \t\r"
    lexer.whitespace_split = False
    lexer.commenters = "#"
    try:
        raw = list(lexer)
    except ValueError:
        return None
    out: list[str] = []
    for token in raw:
        if token and all(c in "();<>|&\n" for c in token):
            out.extend(_PUNCT.findall(token))
        else:
            out.append(token)
    return out


def _parts(text: str) -> Iterator[tuple[int, str]]:
    """The command, then the body of each `$(…)` and backtick inside it."""
    yield 0, text
    for body in _substitutions(text):
        yield 1, body


def _substitutions(text: str) -> Iterator[str]:
    i = 0
    while True:
        i = text.find("$(", i)
        if i < 0:
            break
        depth, j = 1, i + 2
        while j < len(text) and depth:
            depth += {"(": 1, ")": -1}.get(text[j], 0)
            j += 1
        if depth == 0:
            yield text[i + 2:j - 1]
        i += 2
    for body in re.findall(r"`([^`]*)`", text):
        yield body


def _without_heredocs(command: str) -> str:
    lines = command.split("\n")
    out: list[str] = []
    i = 0
    while i < len(lines):
        line = lines[i]
        out.append(line)
        ends = [(m.group(1) == "-", m.group(3)) for m in _HEREDOC.finditer(line)]
        i += 1
        for dash, word in ends:
            while i < len(lines):
                body = lines[i].lstrip("\t") if dash else lines[i]
                i += 1
                if body == word:
                    break
    return "\n".join(out)


def _unreadable(pattern: str) -> bool:
    # A variable or a substitution: its value is not in the command, so its
    # match against the command cannot be decided here.
    return bool(re.search(r"\$[{(A-Za-z_0-9@*#?!-]|`", pattern))


def _wrapper(command: str, agent: str) -> str:
    """What the shell running this command looks like to `pgrep -f`."""
    if agent == "codex":
        return f"/bin/bash -lc {command}"
    home = os.environ.get("CLAUDE_CONFIG_DIR") or os.path.expanduser("~/.claude")
    return (f"/bin/bash -c source {home}/shell-snapshots/snapshot-bash-0-0.sh 2>/dev/null || true"
            f" && shopt -u extglob 2>/dev/null || true && eval {command} < /dev/null"
            f" && pwd -P >| /tmp/claude-0000-cwd")


def _message(call: dict[str, Any], matched: str) -> str:
    words = call.get("shown") or call["words"]
    shown = " ".join(shlex.quote(w) for w in words)
    fixed = " ".join(shlex.quote(w) for w in [words[0], "-A", *words[1:]])
    effect = ("kill the shell that is running it: the tool would report a bare "
              "`Exit code 144` and lose the rest of the output"
              if call["tool"] == "pkill" else
              "find the shell that is running it, so a kill of its answer kills that shell "
              "(`Exit code 144`), a wait on it never ends, and a check on it always says "
              "\"still running\"")
    return (f"xenia-guard refused this command before it ran: `{shown}` matches its own shell. "
            f"The shell tool runs the whole command as `bash -c \"…\"`, and the pattern "
            f"matches {matched[:60]!r} in that text, so it would {effect}. "
            f"Add -A (--ignore-ancestors), which leaves out this shell and its parents: "
            f"`{fixed}`. Or act on the PID you started (`$!`, a pidfile, "
            f"`tail --pid=PID -f /dev/null` to wait for it).")
