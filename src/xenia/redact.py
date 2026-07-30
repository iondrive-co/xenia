from __future__ import annotations

import re
from typing import NamedTuple


class Rule(NamedTuple):
    name: str
    pattern: re.Pattern[str]
    label: str


RULES: tuple[Rule, ...] = (
    Rule(
        "private_key",
        re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |PGP |DSA )?PRIVATE KEY-----"),
        "PRIVATE_KEY",
    ),
    Rule("gitlab_pat", re.compile(r"\bglpat-[A-Za-z0-9_\-]{20,}"), "GITLAB_PAT"),
    Rule(
        "gitlab_runner_token",
        re.compile(r"\bglrt-[A-Za-z0-9_\-]{20,}"),
        "GITLAB_RUNNER_TOKEN",
    ),
    Rule(
        "github_token",
        re.compile(r"\bgh[pousr]_[A-Za-z0-9]{16,}"),
        "GITHUB_TOKEN",
    ),
    Rule("slack_token", re.compile(r"\bxox[abprs]-[A-Za-z0-9\-]{10,}"), "SLACK_TOKEN"),
    Rule("aws_access_key", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"), "AWS_KEY"),
    Rule("google_api_key", re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b"), "GOOGLE_API_KEY"),
    Rule("openai_key", re.compile(r"\bsk-[A-Za-z0-9]{20,}"), "OPENAI_KEY"),
    Rule("anthropic_key", re.compile(r"\bsk-ant-[A-Za-z0-9_\-]{20,}"), "ANTHROPIC_KEY"),
    Rule(
        "jwt",
        re.compile(r"\beyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}"),
        "JWT",
    ),
    Rule(
        "ansible_vault",
        re.compile(r"\$ANSIBLE_VAULT;[0-9.]+;[A-Z0-9]+"),
        "ANSIBLE_VAULT_BLOB",
    ),
    Rule(
        "assigned_secret",
        re.compile(
            r"""(?ix)
            (?:[A-Za-z0-9]+[_\-\.])*
            (?:pass(?:wd|word)?|secret|token|api[_\-]?key|auth|access[_\-]?key|
               private[_\-]?key|credential|bearer)
            \b\s*[:=]\s*
            ['"]?(?P<value>[A-Za-z0-9/+_\-\.]{8,})['"]?
            """
        ),
        "SECRET_VALUE",
    ),
    Rule(
        "url_userinfo",
        re.compile(r"(?i)\b(?:https?|ssh|ftp)://[^\s/@:]+:(?P<value>[^\s/@]{3,})@"),
        "URL_PASSWORD",
    ),
)

_PLACEHOLDERS = re.compile(
    r"(?i)^(?:x{3,}|\.{3,}|<[^>]*>|\$\{?[A-Za-z_][A-Za-z0-9_]*\}?|"
    r"your[_\-]?\w+|example\w*|redacted|changeme|placeholder|dummy|"
    r"none|null|true|false|test|foo|bar)$"
)


class Hit(NamedTuple):
    rule: str
    label: str
    start: int
    end: int


def scan(text: str | None) -> list[Hit]:
    if not text:
        return []

    hits: list[Hit] = []
    claimed: list[tuple[int, int]] = []

    for rule in RULES:
        for match in rule.pattern.finditer(text):
            if "value" in (match.groupdict() or {}) and match.group("value") is not None:
                start, end = match.span("value")
                value = match.group("value")
            else:
                start, end = match.span()
                value = match.group()

            if _PLACEHOLDERS.match(value.strip()):
                continue
            if any(start < c_end and end > c_start for c_start, c_end in claimed):
                continue

            claimed.append((start, end))
            hits.append(Hit(rule.name, rule.label, start, end))

    hits.sort(key=lambda h: h.start)
    return hits


def redact(text: str | None) -> str | None:
    if not text:
        return text

    hits = scan(text)
    if not hits:
        return text

    out: list[str] = []
    cursor = 0
    for hit in hits:
        out.append(text[cursor : hit.start])
        out.append(f"[REDACTED:{hit.label}]")
        cursor = hit.end
    out.append(text[cursor:])
    return "".join(out)


def redact_obj(obj: object) -> object:
    if isinstance(obj, str):
        return redact(obj)
    if isinstance(obj, dict):
        return {k: redact_obj(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [redact_obj(v) for v in obj]
    return obj
