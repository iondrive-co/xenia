from __future__ import annotations

import hashlib
import os
import posixpath
import re
import shlex
from dataclasses import dataclass, field
from urllib.parse import urlsplit

from . import config


@dataclass
class RemoteFact:
    channel: str
    via: str = "direct"
    method: str | None = None
    host: str | None = None
    port: int | None = None
    url: str | None = None
    environment: str | None = None
    mutating: bool = False


@dataclass
class FsFact:
    path: str
    op: str
    abs_path: str | None = None
    in_repo: bool = True
    bytes_after: int | None = None
    sha256_after: str | None = None
    sensitivity: str = "normal"
    snippet: str | None = None


@dataclass
class Result:
    kind: str
    signature: str
    target: str | None = None
    detail: str = ""
    remote: RemoteFact | None = None
    fs: list[FsFact] = field(default_factory=list)


_WRAPPERS = {
    "sudo", "doas", "env", "time", "nohup", "nice", "ionice", "xargs",
    "command", "exec", "builtin", "stdbuf", "timeout", "watch", "setsid",
    "bash", "sh", "zsh", "dash", "ash", "ksh",
}

_SEPARATORS = ("&&", "||", "|&", ";", "|", "&", "\n")


def _split_unquoted(text: str) -> list[str]:
    parts: list[str] = []
    current: list[str] = []
    quote: str | None = None
    i = 0
    while i < len(text):
        char = text[i]
        if char == "\\" and quote != "'" and i + 1 < len(text):
            current.append(char)
            current.append(text[i + 1])
            i += 2
            continue
        if quote:
            current.append(char)
            if char == quote:
                quote = None
            i += 1
            continue
        if char in "'\"":
            quote = char
            current.append(char)
            i += 1
            continue
        for sep in _SEPARATORS:
            if text.startswith(sep, i):
                parts.append("".join(current))
                current = []
                i += len(sep)
                break
        else:
            current.append(char)
            i += 1
    parts.append("".join(current))
    return parts


def mask_quoted(text: str) -> str:
    """The same text with the inside of every quoted run blanked out.

    A `>` between quotes is a character in a string, not a redirection: it is
    a comparison in an inline Python program, an arrow in a format string, a
    fragment of a grep pattern. Scanning the raw text for redirections reads
    those as writes and invents a file — `fs:modify:',` — so the scan runs
    over this instead. Blanks are the same width as what they replace, so
    offsets still line up with the original.
    """
    out: list[str] = []
    quote: str | None = None
    i = 0
    while i < len(text):
        char = text[i]
        if char == "\\" and quote != "'" and i + 1 < len(text):
            out.append("  ")
            i += 2
            continue
        if quote:
            out.append(char if char == quote else " ")
            if char == quote:
                quote = None
        elif char in "'\"":
            quote = char
            out.append(char)
        else:
            out.append(char)
        i += 1
    return "".join(out)


_HEREDOC = re.compile(r"<<(?P<dash>-?)\s*(?P<quote>['\"]?)"
                      r"(?P<word>[A-Za-z_][\w.-]*)(?P=quote)")


def split_heredocs(command: str) -> tuple[str, list[str]]:
    """The command with every heredoc body lifted out, and those bodies.

    The bodies are not shell and must not be tokenised as any, but they are
    not nothing either: fed to an interpreter, the body *is* the program, and
    it is what tells one run apart from another.
    """
    text = command or ""
    if "<<" not in text:
        return text, []

    lines = text.split("\n")
    kept: list[str] = []
    bodies: list[str] = []
    i = 0
    while i < len(lines):
        line = lines[i]
        kept.append(line)
        i += 1
        for match in _HEREDOC.finditer(line):
            word, dashed = match.group("word"), bool(match.group("dash"))
            body: list[str] = []
            while i < len(lines):
                candidate = lines[i]
                i += 1
                if (candidate.strip() if dashed else candidate.rstrip()) == word:
                    break
                body.append(candidate)
            if body:
                bodies.append("\n".join(body))
    return "\n".join(kept), bodies


def strip_heredocs(command: str) -> str:
    return split_heredocs(command)[0]


def heredoc_bodies(command: str) -> str | None:
    bodies = split_heredocs(command)[1]
    return "\n".join(bodies) if bodies else None


def segments(command: str) -> list[str]:
    return [s.strip() for s in _split_unquoted(strip_heredocs(command)) if s.strip()]


def tokenise(segment: str) -> list[str]:
    try:
        return shlex.split(segment)
    except ValueError:
        return segment.split()


_SHELLS = {"bash", "sh", "zsh", "dash", "ash", "ksh"}

_WRAPPER_VALUE_FLAGS = {
    "-u", "-g", "-p", "-n", "-C", "-S", "-k", "-s", "-I", "-P",
    "--user", "--group", "--chdir", "--signal", "--kill-after",
}

_DURATION = re.compile(r"^\d+(?:\.\d+)?[smhd]?$")


def verb_and_args(tokens: list[str], _depth: int = 0) -> tuple[str, list[str]]:
    i = 0
    while i < len(tokens):
        tok = tokens[i].strip("()'\"{}")
        if not tok:
            i += 1
            continue
        if "=" in tok and not tok.startswith("-") and tok.split("=", 1)[0].isidentifier():
            i += 1
            continue

        base = posixpath.basename(tok)
        if base not in _WRAPPERS:
            return base, tokens[i + 1 :]

        is_shell = base in _SHELLS
        i += 1
        while i < len(tokens):
            arg = tokens[i]
            if arg.startswith("-"):
                if is_shell and arg.lstrip("-") in ("c", "lc", "ic"):
                    if i + 1 < len(tokens) and _depth < 3:
                        return verb_and_args(tokenise(tokens[i + 1]), _depth + 1)
                    return "", []
                i += 2 if (arg in _WRAPPER_VALUE_FLAGS and "=" not in arg) else 1
                continue
            if base in ("timeout", "nice", "ionice") and _DURATION.match(arg):
                i += 1
                continue
            break

    return "", []


def operands(args: list[str]) -> list[str]:
    out: list[str] = []
    skip_next = False
    for arg in args:
        if skip_next:
            skip_next = False
            continue
        if arg.startswith("-"):
            if "=" not in arg and arg in _FLAGS_WITH_VALUE:
                skip_next = True
            continue
        out.append(arg)
    return out


def first_operand(args: list[str]) -> str | None:
    found = operands(args)
    return found[0] if found else None


# Runtimes that take a program on the command line. Shells are deliberately
# absent: `bash -c` is followed into by verb_and_args, because what it carries
# really is another command. What python3 -c carries is not.
_INTERPRETERS = frozenset({
    "python", "python2", "python3", "node", "nodejs", "deno", "bun",
    "ruby", "perl", "php", "rscript", "lua", "osascript",
})

_CODE_FLAGS = ("-c", "-e", "--command", "--eval")


def is_interpreter(verb: str) -> bool:
    return posixpath.basename((verb or "").strip()).lower() in _INTERPRETERS


def inline_code(verb: str, args: list[str]) -> tuple[str | None, list[str]]:
    """The program handed to an interpreter with -c/-e, split off from the rest.

    Source is not shell. Left in the argument list it becomes the command's
    first operand, and a whole program ends up as the identity of the work —
    `exec:python3:import pathlib\\nsrc = pathlib.path(...)` as a signature, and
    the same body again as the task label.
    """
    if not is_interpreter(verb):
        return None, args

    code: str | None = None
    rest: list[str] = []
    skip = False
    for i, arg in enumerate(args):
        if skip:
            skip = False
            continue
        if code is None:
            if arg in _CODE_FLAGS and i + 1 < len(args):
                code, skip = args[i + 1], True
                continue
            joined = next((f for f in _CODE_FLAGS if arg.startswith(f + "=")), None)
            if joined:
                code = arg.split("=", 1)[1]
                continue
        rest.append(arg)
    return code, rest


# Consonants only, so a digest can never be mistaken for the hex or the digit
# runs that signature() normalises away as volatile.
_DIGEST_ALPHABET = "bcdfghjklmnpqrstvwxyz"


def code_digest(code: str) -> str:
    value = int(hashlib.sha256(code.encode("utf-8", "replace")).hexdigest()[:12], 16)
    out: list[str] = []
    for _ in range(6):
        value, index = divmod(value, len(_DIGEST_ALPHABET))
        out.append(_DIGEST_ALPHABET[index])
    return "".join(out)


def program_of(verb: str, args: list[str],
               heredoc: str | None = None) -> tuple[str | None, list[str]]:
    """The program this command runs, however it was handed over.

    Inline after -c, or piped in as a heredoc — either way it is source, and
    either way the rest of the argument list is what remains to be read as
    shell.
    """
    code, rest = inline_code(verb, args)
    if code is None and heredoc and is_interpreter(verb) \
            and any(a.startswith("<<") for a in args):
        code = heredoc
        rest = [a for a in rest if not a.startswith("<<")]
    return code, rest


def exec_operand(verb: str, args: list[str], heredoc: str | None = None) -> str:
    """What names this command apart from others of the same verb.

    A program is named by a digest of itself: short enough to read, stable
    enough that the same script run twice is one kind of work, and distinct
    enough that two unrelated one-off scripts are not.
    """
    code, rest = program_of(verb, args, heredoc)
    if code is not None:
        return f"-c {code_digest(code)}"
    return first_operand(rest) or ""


def flag_value(args: list[str], *names: str) -> str | None:
    for i, arg in enumerate(args):
        for name in names:
            if arg == name and i + 1 < len(args):
                return args[i + 1]
            if arg.startswith(name + "="):
                return arg.split("=", 1)[1]
    return None


_FLAGS_WITH_VALUE = {
    "-o", "-O", "-X", "-H", "-d", "-u", "-T", "-F", "-e", "-p", "-P", "-i",
    "-L", "-n", "-t", "--output", "--request", "--header", "--data", "--user",
    "--upload-file", "--url", "--port", "--identity",
    "--limit", "--inventory", "--context", "--namespace", "--cluster",
}


_HTTP_VERBS = {"curl", "wget", "http", "https", "httpie", "xh", "curlie", "aria2c"}
_SSH_VERBS = {"ssh", "scp", "sftp", "rsync", "ansible", "ansible-playbook", "ansible-inventory"}
_VCS_API = {"gh", "glab", "hub"}

_FORGE_HOSTS = {"gh": "api.github.com", "hub": "api.github.com"}


def forge_host(verb: str) -> str | None:
    configured = config.site().get("forge_hosts")
    if isinstance(configured, dict) and configured.get(verb):
        return str(configured[verb])
    return _FORGE_HOSTS.get(verb)
_DB_VERBS = {"psql", "mysql", "mongosh", "mongo", "redis-cli", "clickhouse-client", "cqlsh"}
_CLOUD_VERBS = {"aws", "gcloud", "az", "kubectl", "helm", "terraform", "docker", "podman", "flyctl"}
_PKG_VERBS = {
    "pip", "pip3", "npm", "yarn", "pnpm", "apt", "apt-get", "brew", "cargo",
    "gem", "go", "gradle", "mvn", "uv", "poetry", "nix",
}
_RAW_VERBS = {"nc", "ncat", "netcat", "telnet", "dig", "nslookup", "host", "ping", "traceroute"}

_GIT_REMOTE_SUB = {"push", "pull", "fetch", "clone", "ls-remote", "remote", "submodule"}

_URL_RE = re.compile(r"\b(?:https?|ftp|ws{1,2}s?)://[^\s'\"<>|;)]+")
_SSH_TARGET_RE = re.compile(r"^(?:(?P<user>[\w.\-]+)@)?(?P<host>[A-Za-z0-9._\-]+):(?!//)")

_MUTATING_HTTP = {"POST", "PUT", "DELETE", "PATCH"}
_MUTATING_CLOUD_SUB = {
    "apply", "delete", "create", "replace", "patch", "destroy", "push", "scale",
    "rollout", "drain", "cordon", "exec", "cp", "set", "annotate", "label",
    "put-object", "delete-object", "update", "run", "restart",
}


def environment_of(host: str | None) -> str | None:
    if not host:
        return None
    lowered = host.lower()
    for needle, env in config.ENV_PATTERNS:
        if needle in lowered:
            return env
    return None


def _host_of(url: str) -> tuple[str | None, int | None]:
    try:
        parts = urlsplit(url)
        return parts.hostname, parts.port
    except ValueError:
        return None, None


def _http_fact(args: list[str], raw: str) -> RemoteFact:
    method = None
    mutating = False
    for i, arg in enumerate(args):
        if arg in ("-X", "--request") and i + 1 < len(args):
            method = args[i + 1].upper()
        elif arg.startswith("--request="):
            method = arg.split("=", 1)[1].upper()
        elif arg in ("-d", "--data", "--data-raw", "--data-binary", "-F", "--form",
                     "-T", "--upload-file") or arg.startswith("--data"):
            mutating = True
    if method in _MUTATING_HTTP:
        mutating = True
    if method is None:
        method = "POST" if mutating else "GET"

    url_match = _URL_RE.search(raw)
    url = url_match.group() if url_match else None
    host, port = _host_of(url) if url else (None, None)
    if host is None:
        operand = first_operand(args)
        if operand and not operand.startswith("-"):
            host = operand.split("/", 1)[0] or None

    return RemoteFact(
        channel="http",
        method=method,
        host=host,
        port=port,
        url=url,
        environment=environment_of(host),
        mutating=mutating,
    )


def _ssh_fact(verb: str, args: list[str]) -> RemoteFact:
    if verb.startswith("ansible"):
        target = flag_value(args, "--limit", "-l")
        inventory = flag_value(args, "-i", "--inventory") or ""
        return RemoteFact(
            channel="ssh",
            method=verb,
            host=target,
            environment=environment_of(inventory) or _env_from_args(args),
            mutating=verb == "ansible-playbook",
        )

    positional = operands(args)
    host = None
    for arg in positional:
        match = _SSH_TARGET_RE.match(arg)
        if match:
            host = match.group("host")
            break
        if "@" in arg:
            host = arg.split("@", 1)[1]
            break
        if verb == "ssh":
            host = arg
            break

    remote_cmd = positional[1:] if verb == "ssh" else []
    return RemoteFact(
        channel="ssh",
        method=" ".join(remote_cmd[:3]) if remote_cmd else verb,
        host=host,
        environment=environment_of(host),
        mutating=bool(remote_cmd) or verb in ("scp", "rsync"),
    )


def _git_fact(args: list[str]) -> RemoteFact | None:
    sub = first_operand(args)
    if sub not in _GIT_REMOTE_SUB:
        return None
    if sub == "submodule" and "update" not in args:
        return None
    if sub == "remote" and not any(a in ("update", "add", "set-url") for a in args):
        return None

    url = None
    host = None
    url_match = _URL_RE.search(" ".join(args))
    if url_match:
        url = url_match.group()
        host, _ = _host_of(url)
    else:
        for arg in args:
            target = _SSH_TARGET_RE.match(arg)
            if target:
                host = target.group("host")
                break

    return RemoteFact(
        channel="git",
        method=sub,
        host=host,
        url=url,
        environment=environment_of(host),
        mutating=sub == "push" or (sub == "remote" and "set-url" in args),
    )


def _cloud_fact(verb: str, args: list[str]) -> RemoteFact | None:
    sub = first_operand(args) or ""
    if verb in ("docker", "podman") and sub not in ("push", "pull", "login"):
        return None
    mutating = sub in _MUTATING_CLOUD_SUB
    return RemoteFact(
        channel="cloud",
        method=f"{verb} {sub}".strip(),
        host=None,
        environment=_env_from_args(args),
        mutating=mutating,
    )


def _env_from_args(args: list[str]) -> str | None:
    joined = " ".join(args).lower()
    for needle, env in config.ENV_PATTERNS:
        if re.search(rf"\b{re.escape(needle)}\b", joined):
            return env
    return None


MCP_SPAWN_CHANNEL = "mcp_spawn"

_COMMAND_TOKEN = re.compile(r"[A-Za-z0-9][\w.+-]*$")
_MCP_SUFFIXES = ("-mcp", "_mcp", "-mcp-server", "_mcp_server")
_MCP_PREFIXES = ("mcp-server-", "mcp_server_", "mcp-", "mcp_")


def is_command_name(token: str) -> bool:
    return bool(_COMMAND_TOKEN.fullmatch((token or "").strip()))


INCIDENTAL_VERBS = frozenset({
    "cd", "pushd", "popd", "export", "set", "true", "false", ":", "echo",
    "printf", "source", ".",
})


def significant_call(calls: list[tuple[str, list[str]]]) -> tuple[str, list[str]]:
    plausible = [(v, a) for v, a in calls if is_command_name(v)]
    for verb, verb_args in plausible:
        if verb not in INCIDENTAL_VERBS:
            return verb, verb_args
    return plausible[0] if plausible else ("", [])


def mcp_server_binary(verb: str) -> str | None:
    base = posixpath.basename((verb or "").strip())
    if not base or base in _WRAPPERS or not _COMMAND_TOKEN.fullmatch(base):
        return None
    for suffix in _MCP_SUFFIXES:
        if base.endswith(suffix) and len(base) > len(suffix):
            return base[: -len(suffix)]
    for prefix in _MCP_PREFIXES:
        if base.startswith(prefix) and len(base) > len(prefix):
            return base[len(prefix):]
    return None


def remote_fact(verb: str, args: list[str], raw: str) -> RemoteFact | None:
    broker = mcp_server_binary(verb)
    if broker:
        return RemoteFact(channel=MCP_SPAWN_CHANNEL, via=broker, method="stdio")
    if verb in _HTTP_VERBS:
        return _http_fact(args, raw)
    if verb in _SSH_VERBS:
        if verb == "rsync" and not any(_SSH_TARGET_RE.match(a) or "@" in a for a in args):
            return None
        return _ssh_fact(verb, args)
    if verb == "git":
        return _git_fact(args)
    if verb in _VCS_API:
        return RemoteFact(
            channel="http",
            method=f"{verb} {first_operand(args) or ''}".strip(),
            host=forge_host(verb),
            mutating=any(
                a in ("create", "close", "merge", "delete", "edit", "comment")
                for a in args
            ),
        )
    if verb in _DB_VERBS:
        host = None
        for i, arg in enumerate(args):
            if arg in ("-h", "--host") and i + 1 < len(args):
                host = args[i + 1]
        return RemoteFact(
            channel="db", method=verb, host=host, environment=environment_of(host)
        )
    if verb in _CLOUD_VERBS:
        return _cloud_fact(verb, args)
    if verb in _RAW_VERBS:
        return RemoteFact(channel="raw", method=verb, host=first_operand(args))
    if verb in _PKG_VERBS:
        sub = first_operand(args) or ""
        if sub in ("install", "add", "get", "download", "update", "upgrade", "sync", "ci", "fetch"):
            return RemoteFact(channel="package", method=f"{verb} {sub}", mutating=False)
        return None
    return None


_FS_OPS: dict[str, str] = {
    "rm": "delete", "rmdir": "delete", "unlink": "delete", "shred": "delete",
    "mv": "move", "rename": "move",
    "cp": "create", "install": "create", "mkdir": "create", "touch": "create",
    "ln": "create",
    "chmod": "chmod", "chown": "chmod", "chgrp": "chmod",
    "truncate": "truncate", "dd": "truncate",
    "tee": "modify", "patch": "modify",
}

_REDIRECT_RE = re.compile(r"(?<![0-9<>&])>>?\s*(?P<path>[^\s;|&>]+)")
_SED_INPLACE = re.compile(r"(?:^|\s)-i(?:\.\w+)?(?:\s|$)")

_GIT_FS_SUB = {"checkout", "restore", "reset", "clean", "apply", "stash", "revert", "rm", "mv"}


def fs_facts(verb: str, args: list[str], raw: str) -> list[tuple[str, str]]:
    out: list[tuple[str, str]] = []

    op = _FS_OPS.get(verb)
    if op:
        operands = [a for a in args if not a.startswith("-")]
        if verb in ("cp", "mv", "install", "ln") and len(operands) >= 2:
            out.append((operands[-1], op))
        elif verb == "tee":
            out.extend((p, "modify") for p in operands)
        else:
            out.extend((p, op) for p in operands)

    elif verb in ("sed", "perl", "ruby") and _SED_INPLACE.search(raw):
        positional = [a for a in args if not a.startswith("-")]
        out.extend((path, "modify") for path in positional[1:])

    elif verb == "git":
        sub = first_operand(args)
        if sub in _GIT_FS_SUB:
            operands = [a for a in args if not a.startswith("-")][1:]
            targets = operands or ["<worktree>"]
            out.extend((t, "modify") for t in targets)

    for match in _REDIRECT_RE.finditer(mask_quoted(raw)):
        path = match.group("path")
        if path not in ("/dev/null", "/dev/stdout", "/dev/stderr"):
            out.append((path, "modify"))

    seen: set[tuple[str, str]] = set()
    unique: list[tuple[str, str]] = []
    for pair in out:
        if pair not in seen:
            seen.add(pair)
            unique.append(pair)
    return unique


_GUARDRAIL_PATTERNS = (
    r"\.claude/settings(\.local)?\.json$",
    r"\.claude/hooks/",
    r"\.claude/(agents|commands|skills)/",
    r"(^|/)\.claude\.json$",
    r"\.codex/hooks\.json$",
    r"\.codex/config\.toml$",
    r"\.mcp\.json$",
    r"\.git/hooks/",
    r"\.git/config$",
    r"(^|/)\.gitconfig$",
    r"\.gitlab-ci\.ya?ml$",
    r"\.github/workflows/",
    r"(^|/)\.pre-commit-config\.ya?ml$",
)

_SENSITIVE_PATTERNS = (
    r"(^|/)\.env(\.|$)",
    r"(^|/)\.netrc$",
    r"(^|/)\.ssh/",
    r"(^|/)id_(rsa|ed25519|ecdsa)",
    r"\.(pem|key|p12|pfx|jks|keystore)$",
    r"(^|/)\.aws/",
    r"(^|/)\.gitlab-token$",
    r"(^|/)\.git-credentials$",
    r"(?i:secret|credential|passwd|password|vault)",
    r"^/etc/",
    r"(^|/)authorized_keys$",
    r"(^|/)sudoers",
)

def _site_patterns(key: str) -> tuple[str, ...]:
    raw = config.site().get(key)
    if not isinstance(raw, list):
        return ()
    good: list[str] = []
    for item in raw:
        try:
            re.compile(str(item))
        except re.error:
            continue
        good.append(str(item))
    return tuple(good)


_re_cache: dict[str, re.Pattern[str]] = {}


def _pattern_re(key: str, builtin: tuple[str, ...]) -> re.Pattern[str]:
    cached = _re_cache.get(key)
    if cached is None:
        cached = re.compile("|".join(builtin + _site_patterns(key)))
        _re_cache[key] = cached
    return cached


def reset_cache() -> None:
    _re_cache.clear()


def sensitivity_of(path: str) -> str:
    if _pattern_re("guardrail_patterns", _GUARDRAIL_PATTERNS).search(path):
        return "guardrail"
    if _pattern_re("sensitive_patterns", _SENSITIVE_PATTERNS).search(path):
        return "sensitive"
    return "normal"


def normalise_path(path: str, cwd: str | None, repo_path: str | None) -> tuple[str, str, bool]:
    raw = os.path.expanduser(path)
    absolute = raw if os.path.isabs(raw) else os.path.normpath(os.path.join(cwd or "", raw))
    if repo_path:
        try:
            relative = os.path.relpath(absolute, repo_path)
        except ValueError:
            return absolute, absolute, False
        if not relative.startswith(".."):
            return relative, absolute, True
    return absolute, absolute, False


_VOLATILE = re.compile(r"\b(?:[0-9a-f]{7,40}|\d{3,})\b")


def signature(kind: str, *parts: str | None) -> str:
    cleaned = [_VOLATILE.sub("N", p.strip().lower()) for p in parts if p]
    return ":".join([kind, *cleaned]) if cleaned else kind
