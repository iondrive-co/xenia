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
_SHELLS = ("bash", "sh", "dash", "zsh")
_GREPS = ("grep", "egrep", "fgrep", "rg")
_REDIRECT = {">", ">>", ">|", "&>", ">&", "<", "<&", "<>", "<<<"}
_ASSIGN = re.compile(r"([A-Za-z_][A-Za-z0-9_]*)(\+?)=(.*)", re.S)
_VARIABLE = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)\}|\$([A-Za-z_][A-Za-z0-9_]*)")
_DECLARE = {"export", "local", "declare", "readonly", "typeset"}
_STARTERS = {"do", "then", "else", "{", "!"}
_RUNNER_PREFIXES = {"sudo", "env", "nohup", "nice", "time", "command", "exec", "setsid", "!"}
_NARROWING = {"--parent", "--session", "--pgroup", "--terminal", "--pidfile", "--ns",
              "--nslist", "--cgroup", "--older"}
_PS_SHORT_VALUE = set("oOpqCgGstuUn")
_PS_LONG_VALUE = {"--format", "--pid", "--ppid", "--sid", "--tty", "--user", "--User",
                  "--group", "--Group", "--sort", "--cols", "--columns", "--width",
                  "--rows", "--lines", "--quick-pid"}
_PS_BSD_VALUE = set("oOpqtUk")
_GREP_SHORT_VALUE = set("efmABCdD")
_RG_SHORT_VALUE = set("efmABCgtTjMEr")
_GREP_LONG_VALUE = {"--regexp", "--file", "--max-count", "--after-context",
                    "--before-context", "--context", "--label", "--include", "--exclude",
                    "--exclude-dir", "--binary-files", "--devices", "--directories",
                    "--glob", "--iglob", "--type", "--type-not", "--threads",
                    "--max-columns", "--encoding", "--replace", "--max-depth"}


def check(payload: dict[str, Any]) -> str | None:
    """The reason to refuse this call, or None to let it run."""
    if payload.get("hook_event_name") != "PreToolUse" or payload.get("tool_name") != "Bash":
        return None
    args = payload.get("tool_input")
    command = args.get("command") if isinstance(args, dict) else None
    if not isinstance(command, str) or not re.search(r"pkill|pgrep|\bps\b", command):
        return None
    from .ingest import detect_agent

    return refusal(command, agent=detect_agent(payload))


def refusal(command: str, *, agent: str = "claude") -> str | None:
    target = _wrapper(command, agent)
    for call in invocations(command):
        if call["ignore_ancestors"] or call["exact"] or not call["full"] or call["restricted"]:
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
    for pipe in pipelines(command):
        found = _kept(pipe["filters"], target)
        if found:
            return _pipe_message(pipe, found)
    return None


def invocations(command: str) -> Iterator[dict[str, Any]]:
    """Every pkill/pgrep this command runs, with the options that decide it.

    `$(…)` and backticks are scanned as
    commands of their own, because shlex reads `"$(pgrep -f x)"` as one word.
    """
    parts = _commands(command)
    names = _assignments(parts)
    seen: set[tuple[int, str]] = set()
    for depth, tokens in parts:
        for i, token in enumerate(tokens):
            if os.path.basename(token) not in ("pkill", "pgrep") or not _command_position(tokens, i):
                continue
            call = _parse(tokens, i, nested=depth > 0)
            key = (depth, " ".join(tokens[i:i + 6]))
            if key in seen:
                continue
            seen.add(key)
            if call["pattern"] is not None and _unreadable(call["pattern"]):
                call["pattern"] = _resolve(call["pattern"], names) or call["pattern"]
            yield call


def pipelines(command: str) -> Iterator[dict[str, Any]]:
    parts = _commands(command)
    names = _assignments(parts)
    for depth, tokens in parts:
        for i, token in enumerate(tokens):
            if os.path.basename(token) != "ps" or not _command_position(tokens, i):
                continue
            listed, j = _parse_ps(tokens, i)
            if not listed:
                continue
            filters: list[dict[str, Any]] = []
            while (j + 1 < len(tokens) and tokens[j] == "|"
                   and os.path.basename(tokens[j + 1]) in _GREPS):
                found = _parse_grep(tokens, j + 1, names)
                if found is None:
                    filters = []
                    break
                filters.append(found)
                j = found["end"]
            if not any(not f["invert"] for f in filters):
                continue
            if depth > 0 or any(f["quiet"] for f in filters) or _feeds_something(tokens, i, j):
                yield {"words": tokens[i:j], "filters": filters}


def _commands(command: str) -> list[tuple[int, list[str]]]:
    out: list[tuple[int, list[str]]] = []
    queue = [command]
    taken = 0
    while queue and taken < 32:
        text, scripts = _split_heredocs(queue.pop(0))
        taken += 1
        for depth, part in _parts(text):
            tokens = _tokens(part)
            if tokens is None:
                continue
            out.append((depth, tokens))
            # `timeout 60 bash -c 'until ! pgrep -f …'`: the script is one word
            # here and a command line of its own to the shell that runs it.
            for i, token in enumerate(tokens[:-2]):
                if (os.path.basename(token) in _SHELLS
                        and re.fullmatch(r"-[a-z]*c[a-z]*", tokens[i + 1])):
                    queue.append(tokens[i + 2])
        queue.extend(scripts)
    return out


def _assignments(parts: list[tuple[int, list[str]]]) -> dict[str, set[str | None]]:
    values: dict[str, set[str | None]] = {}
    for _depth, tokens in parts:
        for k, token in enumerate(tokens):
            before = tokens[k - 1] if k else None
            if before == "for":
                values.setdefault(token, set()).add(None)
                continue
            if token == "read" and _command_position(tokens, k):
                j = k + 1
                while j < len(tokens) and tokens[j] not in _OPERATORS and tokens[j] not in _REDIRECT:
                    values.setdefault(tokens[j], set()).add(None)
                    j += 1
                continue
            found = _ASSIGN.fullmatch(token)
            if not found:
                continue
            declared = before in _DECLARE
            if not (declared or before is None or before in _OPERATORS or before in _STARTERS
                    or _ASSIGN.fullmatch(before)):
                continue
            j = k + 1
            while j < len(tokens) and _ASSIGN.fullmatch(tokens[j]):
                j += 1
            if not declared and j < len(tokens) and tokens[j] not in _OPERATORS:
                continue
            name, append, value = found.groups()
            readable = not append and "$" not in value and "`" not in value
            values.setdefault(name, set()).add(value if readable else None)
    return values


def _resolve(pattern: str, names: dict[str, set[str | None]]) -> str | None:
    def value(match: re.Match) -> str:
        known = names.get(match.group(1) or match.group(2))
        if not known or len(known) != 1 or None in known:
            raise LookupError
        return next(iter(known))

    try:
        out = _VARIABLE.sub(value, pattern)
    except LookupError:
        return None
    return None if _unreadable(out) else out


def _parse_ps(tokens: list[str], i: int) -> tuple[bool, int]:
    lists = unix_full = bsd = False
    formats: list[str] = []
    j = i + 1
    while j < len(tokens) and tokens[j] not in _OPERATORS:
        word = tokens[j]
        if word in _REDIRECT:
            j += 2
            continue
        if word.isdigit() and j + 1 < len(tokens) and tokens[j + 1] in _REDIRECT:
            j += 1
            continue
        if word.startswith("--"):
            name, eq, value = word.partition("=")
            if name in ("--deselect", "--context"):
                return False, j
            if name in _PS_LONG_VALUE:
                if not eq:
                    j += 1
                    value = tokens[j] if j < len(tokens) else ""
                if name == "--format":
                    formats.append(value)
                lists |= name in ("--user", "--User") and not _someone_else(value)
        elif word.startswith("-") and len(word) > 1:
            for k, flag in enumerate(word[1:]):
                if flag == "N":
                    return False, j
                lists |= flag in "eA"
                unix_full |= flag in "fF"
                if flag in _PS_SHORT_VALUE:
                    value = word[k + 2:]
                    if not value:
                        j += 1
                        value = tokens[j] if j < len(tokens) else ""
                    if flag in "oO":
                        formats.append(value)
                    lists |= flag in "uU" and not _someone_else(value)
                    break
        else:
            bsd = True
            if "c" in word:
                return False, j
            lists |= "x" in word or "U" in word
            takes = [flag for flag in word if flag in _PS_BSD_VALUE]
            if len(takes) > 1:
                return False, j
            if takes:
                j += 1
                if takes[0] in "oO" and j < len(tokens):
                    formats.append(tokens[j])
        j += 1
    if formats:
        full = any(re.search(r"\b(?:args|cmd|command)\b", f) for f in formats)
    else:
        full = bsd or unix_full
    return lists and full, j


def _parse_grep(tokens: list[str], k: int, names: dict[str, set[str | None]]) -> dict[str, Any] | None:
    tool = os.path.basename(tokens[k])
    mode = {"egrep": "E", "fgrep": "F", "rg": "E"}.get(tool, "G")
    takes = _RG_SHORT_VALUE if tool == "rg" else _GREP_SHORT_VALUE
    patterns: list[str] = []
    positional: list[str] = []
    invert = ignore_case = quiet = word_match = smart = False
    ended = False
    j = k + 1
    while j < len(tokens) and tokens[j] not in _OPERATORS:
        word = tokens[j]
        if word in _REDIRECT:
            j += 2
            continue
        if word.isdigit() and j + 1 < len(tokens) and tokens[j + 1] in _REDIRECT:
            j += 1
            continue
        if not ended and word == "--":
            ended = True
        elif not ended and word.startswith("--"):
            name, eq, value = word.partition("=")
            if name in _GREP_LONG_VALUE and not eq:
                j += 1
                value = tokens[j] if j < len(tokens) else ""
            if name in ("--file", "--line-regexp"):
                return None
            if name == "--regexp":
                patterns.append(value)
            invert |= name == "--invert-match"
            ignore_case |= name == "--ignore-case"
            quiet |= name in ("--quiet", "--silent", "--count", "--files-with-matches")
            word_match |= name == "--word-regexp"
            smart |= name == "--smart-case"
            if name == "--fixed-strings":
                mode = "F"
            elif name in ("--extended-regexp", "--perl-regexp", "--pcre2"):
                mode = "E"
        elif not ended and word.startswith("-") and len(word) > 1:
            for n, flag in enumerate(word[1:]):
                if flag in takes:
                    value = word[n + 2:]
                    if not value:
                        j += 1
                        value = tokens[j] if j < len(tokens) else ""
                    if flag == "f":
                        return None
                    if flag == "e":
                        patterns.append(value)
                    break
                if flag == "x":
                    return None
                invert |= flag == "v"
                ignore_case |= flag == "i"
                quiet |= flag in "qcl"
                word_match |= flag == "w"
                if tool == "rg":
                    smart |= flag == "S"
                    ignore_case &= flag != "s"
                if flag == "F":
                    mode = "F"
                elif flag in "EP" and tool != "rg" or flag == "P":
                    mode = "E"
                elif flag == "G" and tool != "rg":
                    mode = "G"
        else:
            positional.append(word)
        j += 1
    if not patterns:
        if not positional:
            return None
        patterns, positional = positional[:1], positional[1:]
    if positional:
        return None
    regexes = []
    for pattern in patterns:
        if _unreadable(pattern):
            pattern = _resolve(pattern, names)
            if pattern is None:
                return None
        regexes.append(_regex(pattern, mode, word_match))
        ignore_case |= smart and not any(c.isupper() for c in pattern)
    return {"regex": "|".join(f"(?:{r})" for r in regexes), "invert": invert,
            "ignore_case": ignore_case, "quiet": quiet, "end": j}


def _regex(pattern: str, mode: str, word_match: bool) -> str:
    if mode == "F":
        out = re.escape(pattern)
    elif mode == "E":
        out = pattern
    else:
        out = _basic(pattern)
    return rf"(?<![A-Za-z0-9_])(?:{out})(?![A-Za-z0-9_])" if word_match else out


def _basic(pattern: str) -> str:
    out: list[str] = []
    i = 0
    while i < len(pattern):
        c = pattern[i]
        if c == "\\" and i + 1 < len(pattern):
            n = pattern[i + 1]
            out.append(n if n in "|(){}+?" else c + n)
            i += 2
        elif c == "[":
            j = i + 1
            if j < len(pattern) and pattern[j] == "^":
                j += 1
            if j < len(pattern) and pattern[j] == "]":
                j += 1
            while j < len(pattern) and pattern[j] != "]":
                j += 1
            out.append(pattern[i:j + 1])
            i = j + 1
        else:
            out.append("\\" + c if c in "|(){}+?" else c)
            i += 1
    return "".join(out)


def _kept(filters: list[dict[str, Any]], target: str) -> str | None:
    import warnings

    found = None
    for f in filters:
        try:
            with warnings.catch_warnings():
                warnings.simplefilter("ignore")
                match = re.search(f["regex"], target, re.IGNORECASE if f["ignore_case"] else 0)
        except (re.error, RecursionError, ValueError, OverflowError):
            return None
        if bool(match) == f["invert"]:
            return None
        if match and found is None:
            found = match.group(0)
    return found


def _parse(tokens: list[str], i: int, *, nested: bool) -> dict[str, Any]:
    call = {"tool": os.path.basename(tokens[i]), "full": False, "ignore_ancestors": False,
            "exact": False, "ignore_case": False, "pattern": None, "consumed": nested,
            "restricted": False, "words": [tokens[i]]}
    ended = False
    j = i + 1
    while j < len(tokens) and tokens[j] not in _OPERATORS:
        word = tokens[j]
        call["words"].append(word)
        if not ended and word == "--":
            ended = True
            if call["pattern"] is None:
                j += 1
                if j < len(tokens) and tokens[j] not in _OPERATORS:
                    call["pattern"] = tokens[j]
                    call["words"].append(tokens[j])
            j += 1
            continue
        if not ended and word.startswith("--"):
            name = word.split("=", 1)[0]
            call["full"] |= name == "--full"
            call["ignore_ancestors"] |= name == "--ignore-ancestors"
            call["exact"] |= name == "--exact"
            call["ignore_case"] |= name == "--ignore-case"
            value = word.split("=", 1)[1] if "=" in word else None
            if name in _LONG_VALUE and "=" not in word:
                j += 1
                if j < len(tokens):
                    call["words"].append(tokens[j])
                    value = tokens[j]
            call["restricted"] |= name in _NARROWING or (
                name in ("--euid", "--uid") and _someone_else(value))
        elif not ended and word.startswith("-") and len(word) > 1:
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
                        value = word[k + 2:]
                        if k == len(word) - 2:
                            j += 1
                            if j < len(tokens):
                                call["words"].append(tokens[j])
                                value = tokens[j]
                        call["restricted"] |= flag in "PsgtFO" or (
                            flag in "uU" and _someone_else(value))
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
    lexer.wordchars += "$,:@%+^[]{}"
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
    yield 0, _hollow(text)
    for body in _substitutions(text):
        yield 1, body


def _hollow(text: str) -> str:
    out: list[str] = []
    i = 0
    while i < len(text):
        if text.startswith("$(", i):
            depth, j = 1, i + 2
            while j < len(text) and depth:
                depth += {"(": 1, ")": -1}.get(text[j], 0)
                j += 1
            if depth:
                out.append(text[i:])
                break
            out.append("$_sub")
            i = j
        elif text[i] == "`" and "`" in text[i + 1:]:
            out.append("$_sub")
            i = text.index("`", i + 1) + 1
        else:
            out.append(text[i])
            i += 1
    return "".join(out)


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
    return _split_heredocs(command)[0]


def _split_heredocs(command: str) -> tuple[str, list[str]]:
    lines = command.split("\n")
    out: list[str] = []
    docs: list[tuple[str, list[str]]] = []
    i = 0
    while i < len(lines):
        line = lines[i]
        out.append(line)
        ends = [(m.group(1) == "-", m.group(3)) for m in _HEREDOC.finditer(line)]
        i += 1
        bodies: list[str] = []
        for dash, word in ends:
            body: list[str] = []
            while i < len(lines):
                raw = lines[i]
                i += 1
                if (raw.lstrip("\t") if dash else raw) == word:
                    break
                body.append(raw)
            bodies.append("\n".join(body))
        if bodies:
            docs.append((line, bodies))
    text = "\n".join(out)
    if not docs:
        return text, []
    tokens = _tokens(text) or []
    run: list[str] = []
    for line, bodies in docs:
        for runner, body in zip(_heredoc_runners(line), bodies):
            if runner is True or isinstance(runner, str) and _runs(tokens, runner):
                run.append(body)
    return text, run


def _heredoc_runners(line: str) -> list[bool | str | None]:
    tokens = _tokens(line) or []
    runners: list[bool | str | None] = []
    start = 0
    for k, token in enumerate(tokens):
        if token in _OPERATORS:
            start = k + 1
        elif token == "<<":
            end = k
            while end < len(tokens) and tokens[end] not in _OPERATORS:
                end += 1
            runners.append(_runner(tokens[start:end]))
    return runners


def _runner(words: list[str]) -> bool | str | None:
    plain: list[str] = []
    written = None
    j = 0
    while j < len(words):
        word = words[j]
        if word == "<<":
            j += 2
            continue
        if word.isdigit() and j + 1 < len(words) and words[j + 1] in _REDIRECT:
            j += 1
            continue
        if word in _REDIRECT:
            if word in (">", ">>", ">|") and j + 1 < len(words):
                written = words[j + 1]
            j += 2
            continue
        plain.append(word)
        j += 1
    k = 0
    while k < len(plain):
        if _ASSIGN.fullmatch(plain[k]) or plain[k] in _RUNNER_PREFIXES:
            k += 1
        elif plain[k] == "timeout":
            k += 1
            while k < len(plain) and plain[k].startswith("-"):
                k += 2 if plain[k] in ("-s", "-k", "--signal", "--kill-after") else 1
            k += 1
        else:
            break
    if k >= len(plain):
        return None
    name, args = os.path.basename(plain[k]), plain[k + 1:]
    if name in _SHELLS:
        flags = "".join(a[1:] for a in args if a.startswith("-") and not a.startswith("--"))
        if "n" in flags or "c" in flags:
            return None
        if "s" in flags or not any(not a.startswith("-") for a in args):
            return True
        return None
    if name == "cat":
        return written
    if name == "tee":
        files = [a for a in args if not a.startswith("-")]
        return files[0] if files else None
    return None


def _runs(tokens: list[str], path: str) -> bool:
    want = os.path.normpath(path)
    for k, token in enumerate(tokens):
        if not token or os.path.normpath(token) != want:
            continue
        if _command_position(tokens, k):
            return True
        j = k - 1
        while j >= 0 and tokens[j].startswith("-"):
            j -= 1
        if j < 0 or not _command_position(tokens, j):
            continue
        runner = os.path.basename(tokens[j])
        if runner in ("source", "."):
            return True
        if runner in _SHELLS:
            flags = "".join(t[1:] for t in tokens[j + 1:k] if not t.startswith("--"))
            if "n" not in flags and "c" not in flags:
                return True
    return False


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
    shown = " ".join(_quote(w) for w in words)
    fixed = " ".join(_quote(w) for w in [words[0], "-A", *words[1:]])
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


def _pipe_message(pipe: dict[str, Any], matched: str) -> str:
    shown = " ".join(w if w in _OPERATORS else _quote(w) for w in pipe["words"])
    return (f"xenia-guard refused this command before it ran: `{shown}` finds the shell "
            f"that is running it. The shell tool runs the whole command as `bash -c \"…\"`, "
            f"`ps` lists that shell with its whole command line, and the filter keeps it "
            f"because it matches {matched[:60]!r} there, so a wait on it never ends, a check "
            f"on it always says \"still running\", and a kill of its answer kills this shell "
            f"(`Exit code 144`). Use `pgrep -A -f PATTERN` instead, which leaves out this "
            f"shell and its parents, or act on the PID you started (`$!`, a pidfile, "
            f"`tail --pid=PID -f /dev/null` to wait for it).")


def _someone_else(value: str | None) -> bool:
    if not value or "$" in value or "`" in value:
        return False
    try:
        import pwd
        uid = os.getuid()
        me = {str(uid), pwd.getpwuid(uid).pw_name}
    except (ImportError, KeyError, AttributeError):
        return False
    return not any(name in me for name in value.split(","))


def _quote(word: str) -> str:
    if _VARIABLE.search(word) and not re.search(r'["`\\]', word):
        return f'"{word}"'
    return shlex.quote(word)
