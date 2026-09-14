"""The credential broker: the only part of xenia that reads a secret value.

An agent names a credential and says where it goes. The broker decides whether
it may, reads the value, makes the request, and returns the response. The
value is never returned, never written to the database, and never leaves this
process: the filled-in request is built in `_resolve` and passed straight to
the HTTP client, while what gets stored and quoted back is the template. The
scrub over the response is the second line of defence, not the first.

This runs in the service. The MCP server is a client of the socket here — it
makes no request, opens no store and holds no value.
"""

from __future__ import annotations

import base64
import fnmatch
import hashlib
import http.client
import ipaddress
import ssl
import json
import os
import posixpath
import re
import shlex
import socket
import struct
import sys
import threading
import time
import urllib.error
import urllib.request
from datetime import datetime, timedelta, timezone
from decimal import Decimal
from typing import Any
from pathlib import Path
from urllib.parse import quote, urljoin, urlsplit, urlunsplit

from . import config, policy as bodies, signing, vault

PLACEHOLDER = "{{secret}}"

#: `{{secret}}`, `{{secret:name}}`, `{{sign}}`, `{{sign:profile}}`.
PLACEHOLDER_RE = re.compile(
    r"\{\{(secret|sign)(?::([A-Za-z0-9_.\-]+))?\}\}")

#: The machine-readable half of every refusal. A program branches on these; the
#: prose beside them is what makes a refusal actionable for an agent, and both
#: are always present. Adding a code is a protocol change — see PROTOCOL_VERSION.
CODES = {
    "unapproved": "no live grant covers this credential, host and method",
    "off-policy": "the credential is registered, and not for this",
    "no-value": "registered, but the credential store holds no value for it",
    "unavailable": "xenia cannot do this here — a missing signing scheme, a "
                   "locked store, a service that is not running",
    "timeout": "no answer inside the timeout, before any bytes were sent",
    "sent-outcome-unknown": "the request went out and no answer came back. "
                            "Whether the far side acted on it is NOT known "
                            "from here, so it must not simply be repeated",
    "malformed": "the request could not be understood",
}

METHODS = ("GET", "HEAD", "POST", "PUT", "PATCH", "DELETE")
MUTATING = frozenset({"POST", "PUT", "PATCH", "DELETE"})
DEFAULT_METHODS = ("GET", "HEAD")

LOCAL_HOSTS = frozenset({"localhost", "127.0.0.1", "::1"})

#: Headers never passed back. A cookie is a credential the far side minted,
#: and the agent has no more business holding one of those than the token it
#: was made from.
DROPPED_HEADERS = frozenset({"set-cookie", "set-cookie2"})

#: Headers the caller does not get to choose. `Host` is the routing decision
#: on a shared address: the policy binds the hostname in the URL, and a Host
#: header of the agent's own would send the credential to a different virtual
#: host at the same place while every check still passed.
CALLER_MAY_NOT_SET = frozenset({"host"})

#: The pseudo-host a signature-only use is approved against. There is no
#: hostname in a `sign` call, and a grant has to be scoped to something.
SIGN_SCOPE = "(sign)"


class BrokerError(RuntimeError):
    """The broker could not be reached, or would not answer."""


def utcnow() -> datetime:
    from . import ingest
    return datetime.fromisoformat(ingest.utcnow())


def stamp(when: datetime) -> str:
    return when.isoformat(timespec="milliseconds")


# --------------------------------------------------------------------------
# The registry: which credentials exist, and where each may be sent
# --------------------------------------------------------------------------

def methods_for(methods: list[str] | None) -> list[str]:
    """The methods a policy may name, normalised — or a refusal naming the typo.

    Separate from `register` so a caller holding a value can find out whether
    the policy will be accepted before it puts anything in the store.
    """
    out = [m.upper() for m in (methods or DEFAULT_METHODS)]
    unknown = [m for m in out if m not in METHODS]
    if unknown:
        raise ValueError(f"not an HTTP method: {', '.join(unknown)}")
    return out


def register(conn, name: str, *, backend: str | None = None,
             hosts: list[str] | None = None,
             methods: list[str] | None = None,
             paths: list[str] | None = None, note: str | None = None,
             service: str | None = None, scope: list[str] | None = None,
             verified_at: str | None = None,
             expires_hint: str | None = None) -> dict:
    """Record a credential xenia may use. The value is not passed here."""
    if not name or not name.strip():
        raise ValueError("a credential needs a name")
    methods = methods_for(methods)

    if service and not body_policy_of(entry(conn, name)):
        # Naming a service says this credential does more than read: a harmless
        # call and a damaging one there share a host and a method, so route
        # policy alone cannot separate them.
        raise ValueError(
            f"'{name}' names a service ({service}) and has no body policy, so "
            f"nothing here could tell one of its requests from another. Set "
            f"the actions it may take first:\n"
            f"    xenia secret body {name} < policy.json")

    hosts = list(hosts or [])
    now = stamp(utcnow())
    conn.execute(
        "INSERT INTO secret (name, backend, hosts, methods, paths, note, "
        "                    created_at, service, scope, scope_verified_at, "
        "                    expires_hint) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) "
        "ON CONFLICT (name) DO UPDATE SET backend = excluded.backend, "
        "  hosts = excluded.hosts, methods = excluded.methods, "
        "  paths = excluded.paths, note = excluded.note, "
        "  service = excluded.service, scope = excluded.scope, "
        "  scope_verified_at = excluded.scope_verified_at, "
        "  expires_hint = excluded.expires_hint",
        (name, backend or vault.configured_kind(), json.dumps(hosts),
         json.dumps(methods), json.dumps(paths) if paths else None, note, now,
         service, json.dumps(scope) if scope else None, verified_at,
         expires_hint))
    conn.commit()
    return dict(entry(conn, name) or {})


def set_profile(conn, name: str, profile: str, config_json: dict) -> dict:
    """Store one signing profile on a credential.

    Both the scheme and the string it signs live here rather than in the
    caller's request: a caller that chooses what gets signed could have
    arbitrary bytes signed with the key.
    """
    row = entry(conn, name)
    if row is None:
        raise ValueError(f"no credential called '{name}'")
    scheme = config_json.get("scheme")
    if scheme not in signing.SCHEMES:
        raise ValueError(f"no signing scheme called {scheme!r} — xenia has: "
                         f"{', '.join(sorted(signing.SCHEMES))}")
    try:
        held = json.loads(row["schemes"]) if row["schemes"] else {}
    except (TypeError, ValueError):
        held = {}
    held[profile] = config_json
    conn.execute("UPDATE secret SET schemes = ? WHERE name = ?",
                 (json.dumps(held), name))
    conn.commit()
    return held


def body_policy_of(row) -> dict:
    if row is None:
        return {}
    try:
        return json.loads(row["body_policy"]) if row["body_policy"] else {}
    except (TypeError, ValueError, IndexError):
        return {}


def set_body_policy(conn, name: str, policy: dict) -> dict:
    """Store the actions a credential may take.

    Validated on the way in: a policy that cannot be read is a policy nobody
    finds out is broken until the call it should have refused.
    """
    if entry(conn, name) is None:
        raise ValueError(f"no credential called '{name}'")
    actions = (policy or {}).get("actions")
    if not isinstance(actions, dict) or not actions:
        raise ValueError("a body policy needs an 'actions' object, and an "
                         "empty one permits nothing")
    for action, spec in actions.items():
        if not isinstance(spec, dict):
            raise ValueError(f"action '{action}' is not an object")
        if not spec.get("paths"):
            raise ValueError(f"action '{action}' names no paths")
        for key in ("max", "min"):
            for field, bound in (spec.get(key) or {}).items():
                try:
                    Decimal(str(bound))
                except (ArithmeticError, TypeError, ValueError) as exc:
                    raise ValueError(
                        f"action '{action}' caps {field} at {bound!r}, which "
                        f"is not a number") from exc
    conn.execute("UPDATE secret SET body_policy = ? WHERE name = ?",
                 (json.dumps(policy), name))
    conn.commit()
    return policy


def forget(conn, name: str) -> bool:
    cursor = conn.execute("DELETE FROM secret WHERE name = ?", (name,))
    conn.execute("DELETE FROM secret_grant WHERE name = ?", (name,))
    conn.commit()
    return cursor.rowcount > 0


def entry(conn, name: str):
    return conn.execute("SELECT * FROM secret WHERE name = ?", (name,)).fetchone()


def rename(conn, name: str, to: str) -> None:
    """Give a credential a different name, and take its history with it.

    The grants and the uses move too: it is the same credential, and a history
    left behind under a name nothing answers to would say it had never been
    used.

    The new row goes in before the old one comes out, because `secret_grant`
    references the name and a grant orphaned for even one statement is a grant
    the foreign key deletes.
    """
    to = (to or "").strip()
    if not to:
        raise ValueError("a credential needs a name")
    row = entry(conn, name)
    if row is None:
        raise ValueError(f"no credential called '{name}'")
    if to == name:
        return
    if entry(conn, to) is not None:
        raise ValueError(f"there is already a credential called '{to}'")

    columns = list(row.keys())
    conn.execute(
        f"INSERT INTO secret ({', '.join(columns)}) "
        f"VALUES ({', '.join('?' * len(columns))})",
        [to if column == "name" else row[column] for column in columns])
    conn.execute("UPDATE secret_grant SET name = ? WHERE name = ?", (to, name))
    conn.execute("UPDATE secret_use SET name = ? WHERE name = ?", (to, name))
    conn.execute("DELETE FROM secret WHERE name = ?", (name,))
    conn.commit()


def registry(conn) -> list[dict]:
    return [_readable(row) for row in
            conn.execute("SELECT * FROM secret ORDER BY name")]


def _readable(row) -> dict:
    out = dict(row)
    out["hosts"] = json.loads(out.get("hosts") or "[]")
    out["methods"] = json.loads(out.get("methods") or "[]")
    out["paths"] = json.loads(out["paths"]) if out.get("paths") else None
    out["scope"] = json.loads(out["scope"]) if out.get("scope") else None
    try:
        out["schemes"] = (sorted(json.loads(out["schemes"]))
                          if out.get("schemes") else [])
    except (TypeError, ValueError):
        out["schemes"] = []
    out["scope_stale"] = scope_is_stale(out.get("scope_verified_at"))
    out["actions"] = bodies.describe(body_policy_of(row))
    return out


def scope_is_stale(verified_at: str | None) -> bool:
    """Whether a scope check is old enough to have stopped being evidence.

    A scope verified eleven months ago is a label rather than a fact, and
    never verified counts as stale.
    """
    if not verified_at:
        return True
    try:
        age = utcnow() - datetime.fromisoformat(verified_at)
    except (TypeError, ValueError):
        return True
    return age > timedelta(days=config.SCOPE_MAX_AGE_DAYS)


# --------------------------------------------------------------------------
# Grants: one human approval, with two clocks on it
# --------------------------------------------------------------------------

def default_window(mutating: bool) -> float:
    return (config.GRANT_WRITE_SECONDS if mutating
            else config.GRANT_READ_SECONDS)


def grant(conn, name: str, host: str, *, mutating: bool = False,
          seconds: float | None = None, source: str = "cli",
          ceiling_seconds: float | None = None,
          profiles: list[str] | None = None, reason: str | None = None) -> dict:
    """Approve one credential against one host, until one of two clocks stops.

    `ceiling_seconds` is the clock that does not slide. It defaults to the
    interactive ceiling, and a STANDING approval — `source='standing'` — is
    the one caller that passes its own, because the work it covers runs when
    nobody is there to answer a prompt. See `standing()`, which is the only
    way to make one and enforces what one costs.
    """
    if entry(conn, name) is None:
        raise ValueError(f"no credential called '{name}'")

    now = utcnow()
    window = seconds if seconds is not None else default_window(mutating)
    ceiling = now + timedelta(
        seconds=(config.GRANT_CEILING_SECONDS if ceiling_seconds is None
                 else ceiling_seconds))
    expires = min(now + timedelta(seconds=window), ceiling)

    profiles_json = json.dumps(sorted(profiles)) if profiles else None
    if source == "standing":
        # A standing approval only supersedes an existing grant covering the
        # exact same profile scope (or another unscoped grant on the same host).
        # It must not revoke standing approvals for other profiles on the same
        # credential.
        if profiles_json is not None:
            conn.execute(
                "UPDATE secret_grant SET revoked_at = ? "
                "WHERE name = ? AND host = ? AND mutating = ? AND revoked_at IS NULL "
                "  AND profiles = ?",
                (stamp(now), name, host, int(mutating), profiles_json))
        else:
            conn.execute(
                "UPDATE secret_grant SET revoked_at = ? "
                "WHERE name = ? AND host = ? AND mutating = ? AND revoked_at IS NULL "
                "  AND profiles IS NULL",
                (stamp(now), name, host, int(mutating)))
    else:
        # An interactive / session grant (from a desktop prompt or CLI --for)
        # only supersedes prior session grants. It MUST NOT revoke standing
        # approvals: an unattended job running on a timer must not lose its
        # standing approval just because someone answered a prompt on the desktop.
        conn.execute(
            "UPDATE secret_grant SET revoked_at = ? "
            "WHERE name = ? AND host = ? AND mutating = ? AND revoked_at IS NULL "
            "  AND (source IS NULL OR source != 'standing')",
            (stamp(now), name, host, int(mutating)))

    cursor = conn.execute(
        "INSERT INTO secret_grant (name, host, mutating, granted_at, "
        "                          window_s, expires_at, ceiling_at, source, "
        "                          profiles, reason) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (name, host, int(mutating), stamp(now), window, stamp(expires),
         stamp(ceiling), source, profiles_json, (reason or None)))
    conn.commit()
    return dict(conn.execute("SELECT * FROM secret_grant WHERE id = ?",
                             (cursor.lastrowid,)).fetchone())


def standing(conn, name: str, host: str, *, until: datetime,
             profiles: list[str] | None = None, reason: str = "",
             mutating: bool = True, source: str = "standing") -> dict:
    """An approval for work that runs while nobody is at the keyboard.

    THE PROBLEM IT SOLVES. An ordinary grant assumes a person: the first use
    raises a prompt, and an unanswered one is a delay. On a timer there is
    nobody to ask, so the prompt times out and the call is REFUSED — silently,
    at 03:00, with no second chance. Handing that case a longer ordinary grant
    would be the wrong fix, because the four-hour ceiling is what stops "for
    thirty minutes" from meaning "until you stop".

    WHAT IT COSTS INSTEAD. A standing approval buys its length with
    narrowness and with accountability:

      * an END DATE, not a sliding window — it expires on the day it was
        given for, and `_extend` cannot move it;
      * a REASON, in the grantor's words, on the row and in the report;
      * for signing, the PROFILES it covers. An interactive `(sign)` approval
        covers every profile on the credential; this one covers the ones
        named, so a standing approval for one job's profiles is not a
        signing oracle for the others.

    It is still revocable at any moment, and it is bounded by
    `GRANT_STANDING_MAX_SECONDS` however far out `until` is.
    """
    now = utcnow()
    reason = (reason or "").strip()
    if not reason:
        raise ValueError(
            "a standing approval needs a reason: it outlives the ceiling that "
            "would otherwise end it, so the record has to say what for")
    seconds = (until - now).total_seconds()
    if seconds <= 0:
        raise ValueError(f"{stamp(until)[:19]} is not in the future")
    if seconds > config.GRANT_STANDING_MAX_SECONDS:
        days = config.GRANT_STANDING_MAX_SECONDS / 86400
        raise ValueError(
            f"a standing approval may not run past {days:g} days "
            f"(asked for {seconds / 86400:.0f}); give a shorter one and renew it")
    if host == SIGN_SCOPE and not profiles:
        raise ValueError(
            "a standing approval for signing has to name the profiles it "
            "covers — without them it approves every profile on the "
            "credential for the whole period, which is the thing the ceiling "
            "was stopping")
    return grant(conn, name, host, mutating=mutating, seconds=seconds,
                 source=source, ceiling_seconds=seconds, profiles=profiles,
                 reason=reason)


def is_standing(row) -> bool:
    try:
        return (row["source"] or "") == "standing"
    except (KeyError, IndexError, TypeError):
        return False


def grant_profiles(row) -> list[str] | None:
    """The profile patterns a grant covers, or None for every profile."""
    try:
        raw = row["profiles"]
    except (KeyError, IndexError, TypeError):
        return None
    if not raw:
        return None
    try:
        loaded = json.loads(raw)
    except (TypeError, ValueError):
        return None
    return [str(x) for x in loaded] if isinstance(loaded, list) else None


def grant_covers(row, profile: str | None) -> bool:
    """Whether this approval reaches the signing profile being asked for.

    A grant that names no profiles covers all of them — that is what
    answering a prompt gives, and what it has always given. A grant that
    names some covers exactly those, matched as shell globs so one line can
    say `i079-*` rather than three hundred and eighteen.
    """
    patterns = grant_profiles(row)
    if patterns is None:
        return True
    if profile is None:
        return False
    return any(fnmatch.fnmatchcase(profile, pattern) for pattern in patterns)


def revoke(conn, name: str, host: str | None = None, *,
           grant_id: int | None = None) -> int:
    now = stamp(utcnow())
    if grant_id is not None:
        cursor = conn.execute(
            "UPDATE secret_grant SET revoked_at = ? WHERE id = ? AND "
            "name = ? AND revoked_at IS NULL", (now, grant_id, name))
    elif host:
        cursor = conn.execute(
            "UPDATE secret_grant SET revoked_at = ? WHERE name = ? AND "
            "host = ? AND revoked_at IS NULL", (now, name, host))
    else:
        cursor = conn.execute(
            "UPDATE secret_grant SET revoked_at = ? WHERE name = ? AND "
            "revoked_at IS NULL", (now, name))
    conn.commit()
    return cursor.rowcount


def live_grant(conn, name: str, host: str, mutating: bool,
               profile: str | None = None):
    """The approval that covers this call, if there is one.

    A grant that covers writing covers reading too — nobody approving a POST
    means to withhold the GET. The reverse is not true, which is the point of
    keeping the two apart.

    `profile` narrows a SIGNING call to the approvals that reach it. More than
    one can be live at once — a standing approval scoped to one job's
    profiles, and an interactive one from a prompt answered five minutes ago —
    so the rows are walked rather than the first one taken.
    """
    now = stamp(utcnow())
    rows = conn.execute(
        "SELECT * FROM secret_grant "
        "WHERE name = ? AND host = ? AND mutating >= ? AND revoked_at IS NULL "
        "  AND expires_at > ? AND ceiling_at > ? "
        "ORDER BY mutating, expires_at DESC",
        (name, host, int(mutating), now, now)).fetchall()
    for row in rows:
        if grant_covers(row, profile):
            return row
    return None


def grants(conn, *, live_only: bool = True) -> list[dict]:
    now = stamp(utcnow())
    sql = "SELECT * FROM secret_grant"
    args: tuple = ()
    if live_only:
        sql += (" WHERE revoked_at IS NULL AND expires_at > ? "
                "AND ceiling_at > ?")
        args = (now, now)
    sql += " ORDER BY name, host"
    return [dict(row) for row in conn.execute(sql, args)]


def _extend(conn, row, mutating: bool) -> None:
    """Slide the window forward, but never past the ceiling.

    The window sliding keeps a live piece of work from being interrupted; the
    ceiling not sliding keeps "for 30 minutes" from meaning "until you stop".
    The window is the one this grant was given rather than the current
    default, or a grant deliberately made small is silently made large.
    """
    now = utcnow()
    stored = row["window_s"] if "window_s" in row.keys() else None
    window = stored if stored is not None else default_window(row["mutating"])
    ceiling = datetime.fromisoformat(row["ceiling_at"])
    expires = min(now + timedelta(seconds=window), ceiling)
    conn.execute(
        "UPDATE secret_grant SET expires_at = ?, last_used_at = ?, "
        "uses = uses + 1 WHERE id = ?",
        (stamp(expires), stamp(now), row["id"]))


# --------------------------------------------------------------------------
# Policy
# --------------------------------------------------------------------------

def _matches(value: str, patterns: list[str]) -> bool:
    return any(fnmatch.fnmatch(value, pattern) for pattern in patterns)


def normalised(path: str) -> str:
    """The path the far side will actually route on.

    `/allowed/../admin` matches the glob `/allowed/*` and is served as
    `/admin`. Checking the string the agent wrote rather than the one it
    resolves to is checking the wrong thing, so the resolved path is both what
    the policy sees and what gets sent.
    """
    resolved = posixpath.normpath(path or "/")
    if path.endswith("/") and not resolved.endswith("/"):
        resolved += "/"
    return resolved if resolved.startswith("/") else "/" + resolved


def _resolved_addresses(host: str) -> list[str]:
    try:
        info = socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
    except OSError as exc:
        raise Refusal(f"{host} does not resolve: {exc}") from exc
    return sorted({item[4][0] for item in info})


def check_target(url: str) -> tuple[str, str, str]:
    """Refuse anything that is not an ordinary outbound HTTPS call.

    Returns the host, the resolved path, and **the address the connection must
    use**. That third value is what closes the gap between checking a name and
    connecting to it.
    """
    parts = urlsplit(url)
    if parts.scheme not in ("https", "http"):
        raise Refusal(f"only http(s) URLs can be brokered, not '{parts.scheme}'")
    host = parts.hostname or ""
    if not host:
        raise Refusal("no host in that URL")
    if parts.scheme == "http" and host not in LOCAL_HOSTS:
        raise Refusal(
            f"http would put the credential on the wire in clear — use https "
            f"for {host}")
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        address = None
    pinned = host if address is not None else ""
    if address is not None and address.is_link_local:
        raise Refusal(
            f"{host} is link-local — that range is where cloud instance "
            f"metadata lives, and no credential of yours belongs there")

    # A name is not an address, and not the same address twice: resolving here
    # and letting the connection resolve again leaves a gap for DNS rebinding.
    # The address that passed is the one connected to, and the hostname travels
    # separately for SNI, certificate validation and the Host header.
    if address is None:
        for candidate in _resolved_addresses(host):
            try:
                resolved = ipaddress.ip_address(candidate)
            except ValueError:
                continue
            if resolved.is_link_local:
                raise Refusal(
                    f"{host} resolves to {candidate}, which is link-local — "
                    f"that range is where cloud instance metadata lives, and "
                    f"no credential of yours belongs there")
            if not pinned:
                pinned = candidate

    return host, normalised(parts.path or "/"), pinned


class Refusal(Exception):
    """A call xenia will not make.

    Two audiences, one object: `code` is what a program branches on and the
    message is what an agent reads and acts on. Neither substitutes for the
    other — a code cannot say which host to add, and a sentence cannot be
    switched on.
    """

    def __init__(self, message: str, code: str = "off-policy") -> None:
        super().__init__(message)
        self.code = code


def check_policy(row, host: str, method: str, path: str) -> None:
    hosts = json.loads(row["hosts"])
    if not _matches(host, hosts):
        raise Refusal(
            f"'{row['name']}' may only be sent to {', '.join(hosts)} — not "
            f"{host}. This is a policy refusal, not a missing approval: "
            f"widen it with `xenia secret add {row['name']} --host {host}` if "
            f"that is really where it belongs.")

    methods = json.loads(row["methods"])
    if method not in methods:
        raise Refusal(
            f"'{row['name']}' is registered for {', '.join(methods)}, so "
            f"{method} is refused")

    paths = json.loads(row["paths"]) if row["paths"] else None
    if paths and not _matches(path, paths):
        raise Refusal(
            f"'{row['name']}' is limited to {', '.join(paths)} on that host, "
            f"and {path} is outside it")


def permit(row, url: str, method: str) -> tuple[str, str, str]:
    """Everything that must hold before a credential goes on this URL.

    Returns the host, the URL to actually send — the one that was checked, path
    normalised, rather than the string it came in as — and the address that URL
    must be connected to.
    """
    host, path, pinned = check_target(url)
    check_policy(row, host, method, path)
    parts = urlsplit(url)
    return host, urlunsplit((parts.scheme, parts.netloc, path, parts.query,
                             parts.fragment)), pinned


# --------------------------------------------------------------------------
# Putting the credential where the agent said it goes
# --------------------------------------------------------------------------

def _json_escaped(value: str) -> str:
    return json.dumps(value)[1:-1]


def _slots(url: str, headers: dict, body: Any) -> set[tuple[str, str | None]]:
    """Every placeholder the request carries, as (kind, name)."""
    text = " ".join([url, json.dumps(headers or {}, default=str),
                     json.dumps(body, default=str) if body is not None else ""])
    return {(m.group(1), m.group(2)) for m in PLACEHOLDER_RE.finditer(text)}


def credentials_named(url: str, headers: dict, body: Any,
                      primary: str) -> list[str]:
    """Which credentials this request needs, primary first.

    Some APIs want a key, a secret and a passphrase in one call, so a request
    can name more than one. Each is checked against its own policy: a
    credential's policy borrows nothing from the company it keeps.
    """
    names = [primary]
    for kind, name in sorted(_slots(url, headers, body),
                             key=lambda slot: (slot[0], slot[1] or "")):
        if kind == "secret" and name and name not in names:
            names.append(name)
    return names


def next_nonce(conn, name: str, now: float) -> int:
    """A strictly increasing counter for one credential, kept across restarts.

    The broker sees every call for a credential, so it is the only thing that
    can keep one: two callers with their own would race. Seeded from the clock
    so a restored backup cannot re-issue a number already used.

    ONE STATEMENT, AND COMMITTED BEFORE THE CALLER REACHES THE NETWORK. Both
    halves are load-bearing and the read-then-update this replaces had neither:

      the RACE   two callers read the same `last_nonce` and both wrote it back.
                 The second blocked on the first's write lock, but it had
                 already read, so it issued a number that was no longer free.
                 Doing the max() inside the UPDATE closes the window, because
                 there is no longer a gap between the read and the write.
      the LOCK   sqlite opens a write transaction on the first DML and holds it
                 until commit, and `fetch` calls this BEFORE it sends. So the
                 transaction stayed open for the whole request: milliseconds on
                 a small reply, tens of seconds on a 30 MB download. Measured
                 2026-09-11, pulling an S3 archive: at six concurrent downloads
                 four died with "database is locked" against a 5,000 ms
                 busy_timeout, and while any transfer was in flight EVERY other
                 xenia write blocked — `xenia secret sign` from a separate
                 process failed the same way. The broker advertises
                 MAX_CLIENTS=16 and could not serve two.

    A nonce is consumed even when the request that asked for it then fails.
    That is what a nonce is for, not a leak: numbers may be skipped, never
    reissued.
    """
    floor = int(now * 1000)
    row = conn.execute(
        "UPDATE secret SET last_nonce = max(?, coalesce(last_nonce, 0) + 1) "
        "WHERE name = ? RETURNING last_nonce", (floor, name)).fetchone()
    conn.commit()
    return row["last_nonce"] if row else floor


def _json_body(body: Any) -> tuple[str, bool]:
    if isinstance(body, (dict, list)):
        return json.dumps(body), True
    return ("" if body is None else str(body)), False


def _resolve(url: str, headers: dict, body: Any, values: dict[str, str],
             primary: str, profiles: dict[str, dict], nonce: int, now: float,
             scrubber: Scrubber, gate=None
             ) -> tuple[str, dict, bytes | None, list[str], list[str]]:
    """Put every credential, and every signature, where the request says.

    Credentials go in first, then signatures are computed over the request
    that results, so what is signed and what is sent cannot differ. `gate`
    runs between the two and may refuse — a callback rather than a step the
    caller takes first, so no signature can exist for a refused request.
    """
    placed: list[str] = []
    signed: list[str] = []
    parts = urlsplit(url)
    netloc = parts.netloc
    out_headers = {str(k): str(v) for k, v in (headers or {}).items()}

    def value_of(name: str | None) -> str:
        return values[name or primary]

    def swap(text: str, encode) -> str:
        def one(match):
            if match.group(1) != "secret":
                return match.group(0)
            return encode(value_of(match.group(2)))
        return PLACEHOLDER_RE.sub(one, text)

    # -- userinfo becomes basic auth, before the URL is rebuilt
    if "@" in netloc:
        userinfo, _, hostpart = netloc.rpartition("@")
        if PLACEHOLDER_RE.search(userinfo):
            pair = swap(userinfo, lambda v: v)
            encoded = base64.b64encode(pair.encode()).decode()
            out_headers["Authorization"] = "Basic " + encoded
            scrubber.add_form(primary, pair)
            scrubber.add_form(primary, encoded)
            netloc = hostpart
            placed.append("basic")

    # In the path and the query a credential is a URL component, so it goes in
    # percent-encoded — and that form is scrubbed coming back, because it is
    # the shape the far side will echo.
    path, query = parts.path, parts.query
    if PLACEHOLDER_RE.search(path):
        path = swap(path, lambda v: quote(v, safe=""))
        placed.append("path")
    if PLACEHOLDER_RE.search(query):
        query = swap(query, lambda v: quote(v, safe=""))
        placed.append("query")

    for key, header in list(out_headers.items()):
        if PLACEHOLDER_RE.search(header):
            filled = swap(header, lambda v: v)
            if filled != header:
                out_headers[key] = filled
                placed.append(f"header:{key}")

    text, is_json = _json_body(body)
    if body is not None:
        if is_json:
            out_headers.setdefault("Content-Type", "application/json")
        filled = swap(text, _json_escaped if is_json else (lambda v: v))
        if filled != text:
            placed.append("body")
        text = filled

    target = urlunsplit((parts.scheme, netloc, path, query, parts.fragment))

    # -- the gate, on the substituted request and before any signature exists
    if gate is not None:
        gate(target, out_headers, text if body is not None else None)

    # -- pass two: sign what is now actually going to be sent
    sign_slots = [(kind, name) for kind, name in _slots(target, out_headers,
                                                        text if body is not None
                                                        else None)
                  if kind == "sign"]
    for _kind, profile_name in sign_slots:
        key = profile_name or "default"
        profile = profiles.get(key)
        if profile is None:
            raise Refusal(
                f"'{primary}' has no signing profile called '{key}'"
                + (f" — it has: {', '.join(sorted(profiles))}" if profiles else
                   ". Signing profiles are set with `xenia secret sign`, and "
                   "live on the credential rather than in the request."),
                code="off-policy")

        # The headers the signature covers must not include the one the
        # signature is about to land in: SigV4 excludes Authorization by
        # definition, and any scheme would otherwise sign a placeholder.
        marker = f"{{{{sign:{profile_name}}}}}" if profile_name else "{{sign}}"
        for_signing = {k: v for k, v in out_headers.items() if marker not in v}

        extras = {}
        source = profile.get("key_id_from")
        if source:
            extras["key_id"] = values[source]
        context = signing.Context(
            secret=value_of(profile.get("credential")),
            method=profile.get("_method", "GET"), url=target,
            headers=for_signing, body=text if body is not None else "",
            config=profile, nonce=nonce, now=now, extras=extras)
        try:
            signature = signing.sign(profile, context)
        except signing.SchemeError as exc:
            raise Refusal(str(exc), code=exc.code) from exc

        # A scheme may need headers of its own on the wire — SigV4 signs
        # x-amz-date, so the value it signed has to be the value that is sent.
        for key_name, value in context.headers.items():
            out_headers.setdefault(key_name, value)

        for header_key, header_value in list(out_headers.items()):
            if marker in header_value:
                out_headers[header_key] = header_value.replace(marker, signature)
        if marker in target:
            target = target.replace(marker, quote(signature, safe=""))
        if body is not None and marker in text:
            if is_json:
                placed_signature = _json_escaped(signature)
            elif bodies.content_type(out_headers) in bodies.FORM_TYPES:
                # base64 carries '+' and '=', which mean something else in a
                # form body: the far side would verify a different string.
                placed_signature = quote(signature, safe="")
            else:
                placed_signature = signature
            text = text.replace(marker, placed_signature)
        signed.append(key)
        placed.append(f"sign:{key}")

    data = text.encode() if body is not None else None
    return target, out_headers, data, placed, signed


def _forms(value: str) -> list[str]:
    """Every shape a credential could come back in.

    Raw; percent-encoded, as a server echoes it from a query string; base64,
    as it echoes a basic-auth header; and JSON-escaped, as a JSON body renders
    a value containing a quote or a backslash.
    """
    forms = {value, quote(value, safe=""), _json_escaped(value)}
    try:
        forms.add(base64.b64encode(value.encode()).decode())
    except Exception:
        pass
    return [form for form in forms if form]


class Scrubber:
    """Every credential a call touched, and every shape each could return in.

    One call can carry several credentials, so this is a set rather than a
    value. A signature is not added to it: it is derived from a credential but
    is not one, and blanking it would remove the field the caller needs.
    """

    def __init__(self) -> None:
        self._forms: list[tuple[str, str]] = []

    def add(self, name: str, value: str) -> None:
        for form in _forms(value):
            self._forms.append((form, f"[REDACTED:{name}]"))

    def add_form(self, name: str, form: str) -> None:
        if form:
            self._forms.append((form, f"[REDACTED:{name}]"))

    def text(self, text: str | None) -> str | None:
        if not text:
            return text
        for form, label in self._forms:
            text = text.replace(form, label)
        return text

    def echoed(self, text: str) -> bool:
        return any(form in text for form, _ in self._forms)

    def echoed_bytes(self, payload: bytes) -> bool:
        """The same question over bytes nothing has decoded.

        A binary body is never turned into text, so `echoed` cannot see it.
        Encoding the forms is right where decoding the body would be wrong.
        """
        return any(form.encode("utf-8", "ignore") in payload
                   for form, _ in self._forms)


# --------------------------------------------------------------------------
# The request itself
# --------------------------------------------------------------------------

class _NoRedirects(urllib.request.HTTPRedirectHandler):
    """Let a 3xx come back as a response instead of being followed blindly.

    urllib will happily carry an Authorization header to wherever a Location
    points, which is the ordinary way a token ends up at a host nobody
    approved. Redirects are handled a level up, where the origin can be
    compared first.
    """

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def _opener(pinned: str = ""):
    """An opener that connects where the check said, not where DNS says now.

    The socket goes to the address `check_target` approved; the hostname is
    still what TLS presents for SNI, what the certificate is validated against,
    and what the `Host` header carries. Rebinding between the two lookups has
    nothing left to rebind.
    """
    if not pinned:
        return urllib.request.build_opener(_NoRedirects)

    class Secure(http.client.HTTPSConnection):
        def connect(self):
            self.sock = socket.create_connection(
                (pinned, self.port), self.timeout, self.source_address)
            if self._tunnel_host:
                self._tunnel()
            context = getattr(self, "_context", None) or \
                ssl.create_default_context()
            self.sock = context.wrap_socket(self.sock, server_hostname=self.host)

    class Plain(http.client.HTTPConnection):
        def connect(self):
            self.sock = socket.create_connection(
                (pinned, self.port), self.timeout, self.source_address)

    class SecureHandler(urllib.request.HTTPSHandler):
        def https_open(self, req):
            return self.do_open(Secure, req,
                                context=getattr(self, "_context", None))

    class PlainHandler(urllib.request.HTTPHandler):
        def http_open(self, req):
            return self.do_open(Plain, req)

    return urllib.request.build_opener(_NoRedirects, SecureHandler(),
                                       PlainHandler())


def _origin(url: str) -> tuple[str, str, int | None]:
    parts = urlsplit(url)
    return parts.scheme, (parts.hostname or ""), parts.port


def _send(target: str, method: str, headers: dict, data: bytes | None,
          timeout: float, opener=None, pinned: str = "",
          sink: Path | None = None, watch=None) -> dict:
    request = urllib.request.Request(target, data=data, method=method)
    for key, value in headers.items():
        request.add_header(key, value)

    opener = opener or _opener(pinned)
    try:
        response = opener.open(request, timeout=timeout)
        # ONLY a success is streamed. A redirect's body is routing, not
        # content, and has to stay in `raw` for the hop loop to read; an error
        # body is the reason the call failed, and a caller handed a file path
        # instead of it is left guessing. Both are small and both are text.
        if sink is not None and 200 <= response.status < 300:
            return {"status": response.status, "reason": response.reason or "",
                    "headers": dict(response.headers.items()), "raw": b"",
                    "streamed": _drain_to_file(response, sink, watch)}
        raw = response.read(config.FETCH_MAX_BYTES + 1)
        return {"status": response.status, "reason": response.reason or "",
                "headers": dict(response.headers.items()), "raw": raw}
    except urllib.error.HTTPError as exc:
        # An HTTPError *is* the response — status, headers and body — and for
        # a brokered call it is usually the interesting one. It is never
        # streamed, whatever the caller asked for: an error body is small and
        # is text, and a caller handed a file path instead of the reason is
        # left guessing why its download failed.
        raw = exc.read(config.FETCH_MAX_BYTES + 1)
        return {"status": exc.code, "reason": exc.reason or "",
                "headers": dict(exc.headers.items()), "raw": raw}


def _authorise(conn, names: list[str], url: str, method: str, *,
               store=None, notify: bool = True):
    """Every check, for every credential the call names, before any value moves.

    A credential's policy is a statement about that credential. Two of them in
    one request do not pool their permissions: each is checked on its own, and
    the call proceeds only if all of them permit it.
    """
    rows: dict[str, Any] = {}
    grants: dict[str, Any] = {}
    values: dict[str, str] = {}
    host = ""
    sending = url
    pinned = ""

    for name in names:
        row = entry(conn, name)
        if row is None:
            known = [item["name"] for item in registry(conn)]
            raise Refusal(
                f"no credential called '{name}'"
                + (f" — xenia holds {', '.join(known)}" if known else
                   " — none are registered; the user adds one with "
                   "`xenia secret new`"),
                code="off-policy")
        # The hard checks first: no prompt can make a link-local address or
        # a cleartext URL acceptable.
        host, _path, _pinned = check_target(url)

        approval = live_grant(conn, name, host, method in MUTATING)
        if approval is None or not _approved_for(row, host, method):
            row, approval = _decide(conn, row, host, method, notify=notify)

        rows[name] = row
        host, sending, pinned = permit(row, url, method)
        grants[name] = approval

        value = (store or vault.backend(row["backend"])).get(name)
        if value is None:
            raise Refusal(
                f"'{name}' is registered but the credential store has no "
                f"value under that name. The user can set one with "
                f"`xenia secret add {name}`.",
                code="no-value")
        values[name] = value

    return rows, grants, values, host, sending, pinned


def profiles_for(row, method: str) -> dict[str, dict]:
    """The signing profiles on a credential, with the request's method folded in.

    The method is part of what almost every scheme signs and is not something
    the profile can know, so it is passed rather than templated — a profile
    that could name a method could sign a GET and send a DELETE.
    """
    try:
        loaded = json.loads(row["schemes"]) if row["schemes"] else {}
    except (TypeError, ValueError):
        loaded = {}
    return {key: {**profile, "_method": method}
            for key, profile in loaded.items()}


#: How much of a binary body is read at a time, and how much of the previous
#: chunk each echo check sees again — a credential could straddle the boundary.
BINARY_CHUNK = 1 << 20
ECHO_OVERLAP = 512


def _capture_target(name: str, kind: str) -> Path:
    """Where a capture goes. The name is a name and not a path: the caller is
    the agent, and it does not choose where xenia writes."""
    safe = re.sub(r"[^A-Za-z0-9_.\-]", "_", name)[:80] or "capture"
    root = config.capture_dir()
    root.mkdir(parents=True, exist_ok=True)
    try:
        root.chmod(0o700)
    except OSError:
        pass
    return root / f"{safe}.{kind}"


def _capture(name: str, kind: str, payload: bytes) -> tuple[str, str]:
    """Write whole bytes where a program can read them, and return where.

    The reply caps exist because a client discards an over-large reply; a
    program parsing one has the opposite problem, since a truncated body does
    not fail loudly.
    """
    target = _capture_target(name, kind)
    target.write_bytes(payload)
    try:
        target.chmod(0o600)
    except OSError:
        pass
    return str(target), hashlib.sha256(payload).hexdigest()


def _drain_to_file(response, target: Path, watch) -> dict:
    """Stream a response body to disk without decoding it, and without holding it.

    THE DECODE IS THE BUG THIS EXISTS TO AVOID. The text path does
    `raw[:FETCH_MAX_BYTES].decode("utf-8", "replace")`, which is right for a
    reply a person reads and fatal for bytes: every invalid byte becomes U+FFFD
    and the object can never be reconstructed. Splitting a download into
    sub-cap Range requests does not rescue it either, because the loss is in
    the decode and not in the length. So nothing here decodes, nothing here
    holds the whole body, and the caller gets a path, a length and a digest
    rather than a string.
    """
    digest = hashlib.sha256()
    written = 0
    truncated = False
    tail = b""
    ceiling = config.FETCH_MAX_BINARY_BYTES
    try:
        with target.open("wb") as handle:
            try:
                target.chmod(0o600)
            except OSError:
                pass
            while True:
                chunk = response.read(BINARY_CHUNK)
                if not chunk:
                    break
                if written + len(chunk) > ceiling:
                    chunk = chunk[:max(0, ceiling - written)]
                    truncated = True
                if chunk:
                    if watch is not None:
                        watch(tail + chunk)
                        tail = chunk[-ECHO_OVERLAP:]
                    handle.write(chunk)
                    digest.update(chunk)
                    written += len(chunk)
                if truncated:
                    break
    finally:
        try:
            response.close()
        except Exception:
            pass
    return {"path": str(target), "bytes": written,
            "sha256": digest.hexdigest(), "truncated": truncated}


def fetch(conn, request: dict, *, store=None, opener=None,
          notify: bool = True) -> dict:
    """Make one authenticated request on an agent's behalf."""
    started = time.monotonic()
    name = str(request.get("secret") or "").strip()
    url = str(request.get("url") or "").strip()
    method = str(request.get("method") or "GET").upper()
    headers = request.get("headers") or {}
    body = request.get("body")
    client = request.get("client")
    capture = request.get("capture")
    binary = bool(request.get("binary"))
    timeout = min(float(request.get("timeout") or config.FETCH_TIMEOUT),
                  config.FETCH_MAX_TIMEOUT)
    mutating = method in MUTATING
    scrubber = Scrubber()
    host = ""

    def refuse(exc: Refusal, placed=None, grant_id=None) -> dict:
        _record(conn, name=name, client=client, host=host, method=method,
                url=url, placed=placed, decision="refused", reason=str(exc),
                code=exc.code, grant_id=grant_id, status=None, size=None,
                duration_ms=int((time.monotonic() - started) * 1000),
                echoed=False)
        return {"refused": str(exc), "code": exc.code, "secret": name,
                "url": url}

    try:
        if not name:
            raise Refusal("no credential named — pass 'secret'", code="malformed")
        if method not in METHODS:
            raise Refusal(f"not an HTTP method xenia will send: {method}",
                          code="malformed")
        if binary and not capture:
            raise Refusal(
                "a binary response needs 'capture' to name it: xenia will not "
                "decode these bytes, so there is nowhere in the reply to put "
                "them and a file is the only answer that keeps them whole",
                code="malformed")
        forbidden = [key for key in (headers or {})
                     if str(key).lower() in CALLER_MAY_NOT_SET]
        if forbidden:
            raise Refusal(
                f"xenia sets {', '.join(sorted(forbidden))} itself. A Host "
                f"header of your own would send the credential to a different "
                f"virtual host on the approved address, which is the binding "
                f"this refusal exists to keep.",
                code="off-policy")

        names = credentials_named(url, headers, body, name)
        rows, grants, values, host, sending, pinned = _authorise(
            conn, names, url, method, store=store, notify=notify)

        profiles = profiles_for(rows[name], method)
        for profile in profiles.values():
            source = profile.get("key_id_from")
            if source and source not in values:
                raise Refusal(
                    f"the '{name}' signing profile reads its key id from "
                    f"'{source}', which this call did not authorise — name it "
                    f"with {{{{secret:{source}}}}} so its policy is checked "
                    f"too.",
                    code="off-policy")

        for extra in names:
            scrubber.add(extra, values[extra])
        nonce = next_nonce(conn, name, time.time())

        rules = body_policy_of(rows[name])
        permitted: list[str] = []

        def gate(target_url: str, sent: dict, sent_body: str | None) -> None:
            """What the request may say, checked on what will actually be sent.

            A check against the template and a signature over the substitution
            are two different requests, so this sees the substituted one — and
            it runs before any signature exists.
            """
            if not rules:
                return
            try:
                permitted.append(
                    bodies.check(rules, method, target_url, sent, sent_body))
            except bodies.Unparsed as exc:
                raise Refusal(
                    f"'{name}' has a body policy and this request cannot be "
                    f"read: {exc}. A body xenia cannot parse is one whose "
                    f"fields it cannot check, so it is refused rather than "
                    f"waved through.",
                    code="off-policy") from exc
            except bodies.Denied as exc:
                raise Refusal(f"'{name}' does not permit this request — {exc}",
                              code="off-policy") from exc

        target, sent_headers, data, placed, signed = _resolve(
            sending, headers, body, values, name, profiles, nonce,
            time.time(), scrubber, gate=gate)

        if not placed:
            raise Refusal(
                f"nothing in that request says where '{name}' goes. Put "
                f"{PLACEHOLDER} where the credential belongs — commonly a "
                f"header, e.g. headers: {{\"Authorization\": \"Bearer "
                f"{PLACEHOLDER}\"}} — or {{{{sign}}}} where the far side "
                f"wants a signature instead of the credential itself.",
                code="malformed")

    except Refusal as refusal:
        return refuse(refusal)
    except vault.VaultError as exc:
        return refuse(Refusal(
            f"the credential store would not answer: {exc}", code="unavailable"))

    approval = grants[name]
    warnings: list[str] = []
    if "query" in placed:
        warnings.append(
            "the credential went into the query string, where it will sit in "
            "that server's access log — a header is free and does not")

    redirects: list[str] = []
    sent = False
    echoed_binary = False
    sink = _capture_target(str(capture), "response") if binary else None

    def watch(payload: bytes) -> None:
        """The echo check, over bytes, while they go past.

        A streamed body is never decoded and never held, so the text check at
        the end cannot see it. This is the only chance to notice a far side
        handing the credential back.
        """
        nonlocal echoed_binary
        if not echoed_binary and scrubber.echoed_bytes(payload):
            echoed_binary = True

    try:
        sent = True
        answer = _send(target, method, sent_headers, data, timeout, opener,
                       pinned, sink=sink, watch=watch)
        for _hop in range(config.FETCH_MAX_REDIRECTS):
            location = answer["headers"].get("Location") or \
                answer["headers"].get("location")
            if not (300 <= answer["status"] < 400 and location):
                break
            following = urljoin(target, location)
            redirects.append(scrubber.text(following) or "")
            if mutating:
                # A redirected write is a second write, and the far side has
                # already seen the first.
                warnings.append(
                    "did not follow a redirect on a mutating call: re-sending "
                    "the body would be a second write. Re-issue against the "
                    "new location yourself if that is what you meant.")
                break
            if _origin(following) != _origin(target):
                warnings.append(
                    f"stopped at a redirect to "
                    f"{scrubber.text(_origin(following)[1])}: the credential "
                    f"is not carried across origins")
                break
            try:
                _host, following, pinned = permit(rows[name], following,
                                                  method)
            except Refusal as refused:
                warnings.append(f"stopped at a redirect: {refused}")
                break
            target = following
            answer = _send(target, method, sent_headers, data, timeout, opener,
                           pinned, sink=sink, watch=watch)
    except Exception as exc:
        detail = scrubber.text(f"{type(exc).__name__}: {exc}")
        # After the bytes went out a timeout is not a failure but an unknown:
        # the far side may have acted. Saying 'timeout' would invite a retry.
        code = "sent-outcome-unknown" if sent else "timeout"
        _record(conn, name=name, client=client, host=host, method=method,
                url=url, placed=",".join(placed), decision="allowed",
                reason=detail, code=code, grant_id=approval["id"], status=None,
                size=None,
                duration_ms=int((time.monotonic() - started) * 1000),
                echoed=False)
        return {"error": detail, "code": code, "secret": name, "url": url,
                "warnings": warnings, "signed": signed}

    raw: bytes = answer["raw"]
    streamed = answer.get("streamed")
    if streamed:
        # Nothing was decoded and nothing is held: the body is already on disk.
        truncated_bytes = streamed["truncated"]
        text = ""
    else:
        truncated_bytes = len(raw) > config.FETCH_MAX_BYTES
        text = raw[:config.FETCH_MAX_BYTES].decode("utf-8", "replace")
    size = streamed["bytes"] if streamed else len(raw)

    out_headers = {k: v for k, v in answer["headers"].items()
                   if k.lower() not in DROPPED_HEADERS}
    cookies = [k for k in answer["headers"] if k.lower() in DROPPED_HEADERS]

    echoed = echoed_binary or scrubber.echoed(text) or any(
        scrubber.echoed(str(v)) for v in out_headers.values())
    if echoed:
        warnings.append(
            f"that response contained a credential this call used — the far "
            f"side has it in something it sent back, and the fix for that is "
            f"to rotate it, not to redact this reply")

    scrubbed = scrubber.text(text) or ""
    captured: dict[str, Any] = {}
    if capture:
        request_path, request_digest = _capture(
            str(capture), "request", scrubber.text(
                f"{method} {url}\n" + json.dumps(
                    {k: v for k, v in (headers or {}).items()}, indent=1)
                + "\n\n" + (_json_body(body)[0] if body is not None else "")
            ).encode())
        if streamed:
            # Already written, byte for byte, by the drain. It is NOT scrubbed:
            # these bytes are the object the caller asked for, and rewriting
            # them would corrupt it as surely as decoding would. `echoed` is
            # how a credential in there is reported instead.
            response_path = streamed["path"]
            response_digest = streamed["sha256"]
            response_bytes = streamed["bytes"]
        else:
            response_path, response_digest = _capture(
                str(capture), "response", scrubbed.encode())
            response_bytes = len(scrubbed.encode())
        captured = {"request_path": request_path,
                    "request_sha256": request_digest,
                    "response_path": response_path,
                    "response_sha256": response_digest,
                    "response_bytes": response_bytes}

    body_text = scrubbed
    if streamed:
        body_text = (f"[{streamed['bytes']:,} bytes written undecoded to "
                     f"{streamed['path']}; sha256 {streamed['sha256']}"
                     + ("; TRUNCATED at the binary ceiling]" if truncated_bytes
                        else "]"))
    elif len(body_text) > config.FETCH_BODY_CHARS:
        kept = f"…[+{len(body_text) - config.FETCH_BODY_CHARS} chars"
        kept += f"; whole response at {captured['response_path']}]" if captured \
            else ("; pass 'capture' for the whole response in a file, since a "
                  "cut JSON body does not fail loudly]")
        body_text = body_text[:config.FETCH_BODY_CHARS] + kept
    elif truncated_bytes:
        body_text += "…[response longer than xenia will read]"

    duration = int((time.monotonic() - started) * 1000)
    _extend(conn, approval, mutating)
    conn.execute("UPDATE secret SET last_used_at = ? WHERE name = ?",
                 (stamp(utcnow()), name))
    _record(conn, name=name, client=client, host=host, method=method, url=url,
            placed=",".join(placed),
            decision="allowed", reason=(f"action: {permitted[0]}"
                                        if permitted else None),
            code=None, grant_id=approval["id"], status=answer["status"],
            size=size, duration_ms=duration, echoed=echoed, **{
                key: captured.get(key) for key in
                ("request_path", "response_path", "request_sha256",
                 "response_sha256")})

    if cookies:
        warnings.append(
            f"dropped {len(cookies)} cookie header(s): a session cookie is a "
            f"credential too")

    return {
        "status": answer["status"],
        "reason": scrubber.text(answer["reason"]),
        "headers": {scrubber.text(k): scrubber.text(v)
                    for k, v in out_headers.items()},
        "body": body_text,
        "bytes": size,
        "binary": bool(streamed),
        "duration_ms": duration,
        # The template, not the request that was sent. They differ by exactly
        # the credential.
        "url": url,
        "secret": name,
        "used": names,
        "signed": signed,
        "action": permitted[0] if permitted else None,
        "placed": placed,
        "redirects": redirects,
        "warnings": warnings,
        **captured,
    }


def sign_only(conn, request: dict, *, store=None, notify: bool = True) -> dict:
    """Sign a payload xenia is not going to send.

    Where the caller sends the request itself, there is nothing here to make
    — only a signature. It comes back because a signature is not the
    credential: it is specific to this payload and worth nothing against
    another.
    """
    started = time.monotonic()
    name = str(request.get("secret") or "").strip()
    profile_name = str(request.get("profile") or "default")
    payload = request.get("payload")
    client = request.get("client")

    def refuse(exc: Refusal) -> dict:
        _record(conn, name=name, client=client, host="(sign)", method="SIGN",
                url=f"profile:{profile_name}", placed=None, decision="refused",
                reason=str(exc), code=exc.code, grant_id=None, status=None,
                size=None,
                duration_ms=int((time.monotonic() - started) * 1000),
                echoed=False)
        return {"refused": str(exc), "code": exc.code, "secret": name}

    try:
        if not name or payload is None:
            raise Refusal("sign needs 'secret' and 'payload'", code="malformed")
        row = entry(conn, name)
        if row is None:
            raise Refusal(f"no credential called '{name}'", code="off-policy")

        # A SIGNATURE IS A USE. There is no host to bind it to, so the grant is
        # the whole control here and it is required exactly as for a request.
        # The PROFILE is part of the question: a standing approval names the
        # profiles it covers, so one job's unattended approval is not a
        # signing oracle for every other profile on the same credential.
        approval = live_grant(conn, name, SIGN_SCOPE, True, profile_name)
        if approval is None:
            # ASK THE SAME WAY A REQUEST DOES. Until 2026-09-11 this path only
            # posted a notification carrying the command, so a SIGNATURE — the
            # more dangerous of the two — was the one thing a user could not
            # approve from the desktop, while an ordinary GET could. The
            # prompt, the cool-off and the grant are the same on both now.
            ended: dict[str, Any] = {}
            allowed = None
            if notify and (time.monotonic()
                           - _asked.get((name, SIGN_SCOPE), 0.0)) > ASK_COOLOFF:
                _asked[(name, SIGN_SCOPE)] = time.monotonic()
                allowed = ask_to_use(name, SIGN_SCOPE, "SIGN", known=False,
                                     ended=ended)
            if not allowed:
                raise Refusal(
                    f"'{name}' is not approved for signing "
                    f"'{profile_name}' right now."
                    + _why_not(ended if allowed is not None
                               else {"how": "unasked"},
                               name, SIGN_SCOPE, True, profile_name),
                    code="unapproved")
            approval = grant(conn, name, SIGN_SCOPE, mutating=True,
                             source="prompt")
            _asked.pop((name, SIGN_SCOPE), None)

        value = (store or vault.backend(row["backend"])).get(name)
        if value is None:
            raise Refusal(f"the credential store has no value for '{name}'",
                          code="no-value")

        profiles = profiles_for(row, "SIGN")
        profile = profiles.get(profile_name)
        if profile is None:
            raise Refusal(
                f"'{name}' has no signing profile called '{profile_name}'",
                code="off-policy")

        text, is_json = _json_body(payload)
        context = signing.Context(
            secret=value, method="SIGN", url="", headers={}, body=text,
            config=profile, nonce=next_nonce(conn, name, time.time()),
            now=time.time())
        try:
            signature = signing.sign(profile, context)
        except signing.SchemeError as exc:
            raise Refusal(str(exc), code=exc.code) from exc
    except Refusal as refusal:
        return refuse(refusal)
    except vault.VaultError as exc:
        return refuse(Refusal(f"the credential store would not answer: {exc}",
                              code="unavailable"))

    _extend(conn, approval, True)
    _record(conn, name=name, client=client, host=SIGN_SCOPE, method="SIGN",
            url=f"profile:{profile_name}", placed=f"sign:{profile_name}",
            decision="allowed", reason=None, code=None,
            grant_id=approval["id"], status=None, size=len(text),
            duration_ms=int((time.monotonic() - started) * 1000), echoed=False)
    return {"signature": signature, "secret": name, "profile": profile_name,
            "nonce": context.nonce, "signed_bytes": len(text),
            "headers": dict(context.headers)}


def _record(conn, **row) -> None:
    try:
        conn.execute(
            "INSERT INTO secret_use (at, name, client, host, method, url, "
            "  placed, decision, reason, code, grant_id, status, bytes, "
            "  duration_ms, echoed, request_path, response_path, "
            "  request_sha256, response_sha256) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (stamp(utcnow()), row["name"], row.get("client"), row["host"],
             row["method"], row["url"], row["placed"], row["decision"],
             row["reason"], row.get("code"), row["grant_id"], row["status"],
             row["size"], row["duration_ms"], int(bool(row["echoed"])),
             row.get("request_path"), row.get("response_path"),
             row.get("request_sha256"), row.get("response_sha256")))
        conn.commit()
    except Exception:
        # A call that worked is not reported as failed because the record of
        # it could not be written. The record is the point of xenia, so this
        # is not silence — it goes to the same log every other capture failure
        # goes to.
        try:
            from . import ingest
            path = config.fallback_log()
            path.parent.mkdir(parents=True, exist_ok=True)
            with path.open("a") as handle:
                handle.write(f"{ingest.utcnow()}\tbroker\tcould not record a "
                             f"credential use for {row.get('name')}\n")
        except Exception:
            pass


#: How long a prompt stays in front of the user before the call gives up on
#: it. Short enough to sit inside an agent's own timeout, so the answer
#: usually arrives while the call is still waiting for it.
APPROVAL_WAIT = float(os.environ.get("XENIA_APPROVAL_WAIT", 25))

#: After a refusal or an unanswered prompt, how long before the same question
#: may be put on screen again. An agent in a retry loop must not be able to
#: paper the desktop with prompts.
ASK_COOLOFF = float(os.environ.get("XENIA_ASK_COOLOFF", 60))

_asked: dict[tuple[str, str], float] = {}


#: How long after taking a prompt down an answer already on the wire still
#: counts. Not politeness: the daemon sends ActionInvoked before it answers a
#: close, so a click in that last instant is an answer xenia already has, and
#: would otherwise throw away for having asked one moment too late.
CLOSE_GRACE = float(os.environ.get("XENIA_PROMPT_CLOSE_GRACE", 0.75))

#: What the reason in NotificationClosed means, in the words the refusal uses.
#: 3 is "a CloseNotification call", which here is only ever xenia's own.
CLOSED_REASONS = {1: "expired", 2: "dismissed", 3: "timed-out", 4: "dismissed"}


def _short(text: str, limit: int = 34) -> str:
    """A name that still fits in a notification, recognisable at both ends.

    The prompt is a fixed-width box with its buttons UNDER the body, so a long
    name grows the body until the daemon pushes Allow and Deny off the bottom
    and the user is left holding a question they cannot answer. Measured
    2026-09-11 on xfce4-notifyd: a 52-character name — "Aster wallet" plus a
    42-character address — did exactly that. Eliding the middle keeps the head
    and the tail, which is where a wallet address carries its identity.
    """
    text = str(text)
    if len(text) <= limit:
        return text
    head = limit // 2
    tail = limit - head - 1
    return f"{text[:head]}…{text[-tail:]}"


def ask_to_use(name: str, host: str, method: str, *, known: bool,
               wait: float | None = None,
               ended: dict | None = None) -> bool | None:
    """Put the decision in front of the user. True, False, or None if unasked.

    A notification with buttons, because it is the one dialogue this machine
    can raise without a toolkit — and dismissing it counts as no.

    xenia takes the prompt down itself, on every path out of here. The
    expire_timeout in the spec is a hint and the daemons that matter ignore it
    for any notification carrying actions: on Xfce Notify Daemon 0.9.7 one
    sent with a 3s hint was still on screen 13s later, at either urgency. A
    prompt left to the daemon therefore outlives the call it belongs to, and
    what is left on screen is Allow and Deny on a question nobody is waiting
    on any more — a click that gets no grant, no error and no feedback at all,
    and a refusal that then tells the agent the user declined. It is worst
    with two calls queued: the prompts stack up on the desktop while the calls
    run one at a time, so all but one of them is already dead.

    `ended` is filled in with how it ended, which is what the refusal an agent
    reads is written from.
    """
    from .dbus import Connection, Variant

    ended = {} if ended is None else ended
    window = APPROVAL_WAIT if wait is None else wait
    ended["seconds"] = window
    answer: dict[str, Any] = {}
    wanted: dict[str, Any] = {}
    done = threading.Event()

    try:
        conn = Connection().connect()
    except Exception:
        ended["how"] = "unasked"
        return None

    def take_down() -> None:
        """Take the prompt off the screen, once, whatever happened to it."""
        if not wanted.get("id") or wanted.get("gone"):
            return
        wanted["gone"] = True
        try:
            conn.call("org.freedesktop.Notifications",
                      "/org/freedesktop/Notifications",
                      "org.freedesktop.Notifications", "CloseNotification",
                      "u", [wanted["id"]], timeout=2.0)
        except Exception:
            pass

    try:
        caps = conn.call("org.freedesktop.Notifications",
                         "/org/freedesktop/Notifications",
                         "org.freedesktop.Notifications", "GetCapabilities")[0]
        if "actions" not in list(caps):
            ended["how"] = "unasked"
            return None

        def invoked(message) -> None:
            if message.body and message.body[0] == wanted.get("id"):
                answer["choice"] = message.body[1]
                done.set()

        def closed(message) -> None:
            if message.body and message.body[0] == wanted.get("id"):
                answer.setdefault(
                    "closed", message.body[1] if len(message.body) > 1 else 0)
                wanted["gone"] = True
                done.set()

        for member, handler in (("ActionInvoked", invoked),
                                ("NotificationClosed", closed)):
            conn.on_signal("/org/freedesktop/Notifications",
                           "org.freedesktop.Notifications", member, handler)

        wanted["id"] = conn.call(
            "org.freedesktop.Notifications", "/org/freedesktop/Notifications",
            "org.freedesktop.Notifications", "Notify", "susssasa{sv}i",
            ["xenia", 0, "dialog-password",
             # SHORT, because the buttons sit under this text. Naming the
             # credential and the host once each is the whole message; saying
             # them again is what cost the user the Allow button.
             f"Use '{_short(name)}' at {_short(host, 28)}?",
             (f"An agent wants to "
              f"{'sign with it' if host == SIGN_SCOPE else ('send ' + method) if method in MUTATING else ('read ' + method)}"
              f"{'' if host == SIGN_SCOPE else ' here'}."
              + ("" if known else " Allowing also keeps it allowed.")),
             ["allow", "Allow", "deny", "Deny"],
             {"urgency": Variant("y", 2)},
             # Still sent, because a daemon that honours it is a backstop for
             # a xenia that dies holding the prompt. Nothing here depends on
             # it being honoured.
             int(window * 1000)])[0]

        if not done.wait(window):
            take_down()
            done.wait(CLOSE_GRACE)

        if answer.get("choice"):
            ended["how"] = ("allowed" if answer["choice"] == "allow"
                            else "denied")
            return answer["choice"] == "allow"
        if "closed" in answer:
            ended["how"] = CLOSED_REASONS.get(answer["closed"], "dismissed")
            return False
        ended["how"] = "timed-out"
        return False
    except Exception:
        ended.setdefault("how", "unasked")
        return None
    finally:
        # Every path, including the ones that got here by raising: a prompt
        # that outlives the call is a button with nothing behind it.
        take_down()
        try:
            conn.close()
        except Exception:
            pass


#: What to tell an agent about a prompt that did not come back as an approval.
#: Which of these it was is the difference between the user having said no and
#: the user never having been given a live prompt to say it with.
PROMPT_ENDINGS = {
    "allowed": "",
    "denied": " The prompt on the user's desktop was declined.",
    "dismissed": " The prompt on the user's desktop was dismissed without an "
                 "answer.",
    "expired": " The prompt on the user's desktop closed before it was "
               "answered.",
    "timed-out": " The prompt on the user's desktop went unanswered for "
                 "{seconds:.0f}s and has been taken down, so there is nothing "
                 "left on screen to click.",
}

#: What it used to say for every one of them, and still says for a caller that
#: did not ask how it ended.
PROMPT_ENDED_SOMEHOW = (" The prompt on the user's desktop was declined or "
                        "went unanswered.")


def _why_not(ended: dict, name: str, host: str, mutating: bool,
             profile: str | None = None) -> str:
    """The second half of an unapproved refusal: what happened, then what to do."""
    how = ended.get("how")
    if how is None:
        said = PROMPT_ENDED_SOMEHOW
    elif how == "unasked":
        said = ""
    else:
        said = PROMPT_ENDINGS.get(how, PROMPT_ENDED_SOMEHOW).format(
            seconds=ended.get("seconds") or APPROVAL_WAIT)

    if how in ("denied", "dismissed"):
        return said

    # NOBODY WAS THERE. A prompt that timed out is the signature of work on a
    # timer, and telling that caller to "ask the user to run" something is
    # advice for a case that will recur at the same hour tomorrow. Name the
    # standing approval instead, and say where it is given with a mouse.
    if how in ("timed-out", "expired"):
        said += (" Nobody answered, which is what unattended work looks like: "
                 "a prompt is not a control when there is no one at the "
                 "keyboard. If this runs on a schedule it wants a STANDING "
                 "approval — an end date and a written reason instead of a "
                 "four-hour ceiling"
                 + (f", scoped to the profiles it needs ('{profile}')"
                    if profile else "")
                 + ". Open the xenia report, Credentials, Approve…, or see "
                   "`xenia grant --help`.")

    # QUOTED, because this is an instruction someone pastes. A credential named
    # after a wallet has spaces in it and the signing scope is literally
    # "(sign)", so the unquoted form printed here was a command that fails in
    # any shell — a parenthesis error, or a grant for the wrong name.
    return (f"{said} ACTION: ask the user to run "
            f"`xenia grant {shlex.quote(name)} --host {shlex.quote(host)}"
            f"{' --write' if mutating else ''}` in their own terminal, "
            f"then retry.")


def _approved_for(row, host: str, method: str) -> bool:
    """Whether this exact use has been said yes to before."""
    return (_matches(host, json.loads(row["hosts"]))
            and method in json.loads(row["methods"]))


def _decide(conn, row, host: str, method: str, *, notify: bool = True):
    """Ask whether this use is allowed, and let the answer set the scope.

    Store credential scope on approval
    """
    name = row["name"]
    mutating = method in MUTATING
    known = _approved_for(row, host, method)
    recent = _asked.get((name, host), 0.0)
    allowed = None
    ended: dict[str, Any] = {}

    if notify and time.monotonic() - recent > ASK_COOLOFF:
        _asked[(name, host)] = time.monotonic()
        allowed = ask_to_use(name, host, method, known=known, ended=ended)

    if not allowed:
        raise Refusal(
            f"'{name}' is not approved for {method} {host}."
            + _why_not(ended if allowed is not None else {"how": "unasked"},
                       name, host, mutating),
            code="unapproved")

    hosts = json.loads(row["hosts"])
    methods = json.loads(row["methods"])
    if not _matches(host, hosts):
        hosts.append(host)
    if method not in methods:
        methods.append(method)
    conn.execute("UPDATE secret SET hosts = ?, methods = ? WHERE name = ?",
                 (json.dumps(hosts), json.dumps(methods), name))
    conn.commit()
    _asked.pop((name, host), None)
    return entry(conn, name), grant(conn, name, host, mutating=mutating,
                                    source="prompt")


def _ask(name: str, host: str, mutating: bool, *, notify: bool = True) -> None:
    """Tell the user an agent is waiting on them, on their own desktop.

    A refusal the agent can read is not enough on its own: the person who can
    lift it is looking at something else, and the message telling them what to
    run is inside a transcript they are not reading.
    """
    if not notify:
        return
    verb = "write with" if mutating else "read with"
    # The body keeps the command VERBATIM — it is there to be copied — but the
    # summary is elided like every other prompt.
    _notify(f"xenia: {_short(name)} not approved",
            f"An agent wants to {verb} it against {_short(host, 28)}.\n"
            f"xenia grant {shlex.quote(name)} --host {shlex.quote(host)}"
            f"{' --write' if mutating else ''}")


def _notify(summary: str, body: str) -> None:
    try:
        if sys.platform == "darwin":
            import subprocess
            subprocess.run(
                ["osascript", "-e",
                 f'display notification {json.dumps(body)} with title '
                 f'{json.dumps(summary)}'],
                capture_output=True, timeout=5)
            return
        from .dbus import Connection, Variant
        conn = Connection().connect()
        try:
            conn.call("org.freedesktop.Notifications",
                      "/org/freedesktop/Notifications",
                      "org.freedesktop.Notifications", "Notify",
                      "susssasa{sv}i",
                      ["xenia", 0, "dialog-password", summary, body, [],
                       {"urgency": Variant("y", 2)}, 0])
        finally:
            conn.close()
    except Exception:
        pass


# --------------------------------------------------------------------------
# The socket: how the MCP server asks for a call it cannot make itself
# --------------------------------------------------------------------------

def socket_path() -> str:
    return str(config.broker_socket())


class BrokerAlreadyListening(BrokerError, OSError):
    """Another xenia is already answering on this socket. Not ours to take."""


def socket_is_live(path: str, timeout: float = 1.0) -> bool:
    """Is something ANSWERING at `path`, as opposed to a file left behind?

    The two are indistinguishable by `os.path.exists`, and telling them apart
    is the whole difference between a restart and a machine where every
    credentialed call fails. A unix socket whose listener is gone still leaves
    the file; connecting to it raises ECONNREFUSED.
    """
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        sock.connect(path)
    except OSError:
        return False
    finally:
        try:
            sock.close()
        except OSError:
            pass
    return True


#: The socket contract. A program outside this repo depends on it, so this is
#: documentation of an interface xenia intends to keep, not a list of what the
#: code happens to do today.
OPS = {
    "ping": "is the broker up. -> {ok, pid}",
    "ops": "this contract, the refusal codes, and which signing schemes are "
           "available on this machine. -> {ops, codes, schemes}",
    "fetch": "make one authenticated HTTP request. Takes {secret, url, "
             "method, headers, body, timeout, capture, binary}; credentials go "
             "where {{secret}} / {{secret:name}} appear and signatures where "
             "{{sign}} / {{sign:profile}} do. -> {status, reason, headers, "
             "body, bytes, duration_ms, url, used, signed, placed, redirects, "
             "warnings, binary} or {refused, code} or {error, code}. With "
             "'capture', also {request_path, response_path, request_sha256, "
             "response_sha256}. 'binary' needs 'capture' and streams the body "
             "to that file undecoded and uncut, up to FETCH_MAX_BINARY_BYTES: "
             "the ordinary path decodes as UTF-8 with 'replace', which "
             "silently corrupts anything that is not text.",
    "sign": "sign a payload xenia will not send, for a chain the caller "
            "broadcasts to itself. Takes {secret, profile, payload}. -> "
            "{signature, nonce, signed_bytes} or {refused, code}.",
}


#: How long an accepted connection has to finish sending its request, and how
#: many may be in flight at once. Without these a same-uid process opens
#: connections, sends no newline, and every handler thread blocks in recv
#: forever — the broker stops answering anyone, having refused nothing.
CLIENT_READ_TIMEOUT = float(os.environ.get("XENIA_BROKER_READ_TIMEOUT", 20))
MAX_CLIENTS = int(os.environ.get("XENIA_BROKER_MAX_CLIENTS", 16))


class Server:
    """Listens on a unix socket in the service, one request per connection."""

    def __init__(self, path: str | None = None, db_path=None) -> None:
        self.path = path or socket_path()
        self.db_path = db_path
        self._sock: socket.socket | None = None
        self._thread: threading.Thread | None = None
        self._running = False
        self._inode: int | None = None
        self._slots = threading.Semaphore(MAX_CLIENTS)

    def start(self) -> str:
        parent = os.path.dirname(self.path)
        os.makedirs(parent, mode=0o700, exist_ok=True)
        try:
            os.chmod(parent, 0o700)
        except OSError:
            pass
        if os.path.exists(self.path):
            # NEVER unlink a socket something is still answering on. Doing that
            # is how a machine ends up with a live broker nobody can reach:
            # the second instance unlinks the first's socket, binds a NEW inode
            # at the same path and then exits, leaving a file that every client
            # gets ECONNREFUSED from while the first instance listens happily
            # on an inode with no name. `ss -lx` still shows a LISTEN row at the
            # path, which is what makes it look like the service is fine.
            # Measured 2026-09-14 on ptah: every `credentials.fetch` and every
            # xenia_fetch on the box failed "broker-unreachable" for hours.
            if socket_is_live(self.path):
                raise BrokerAlreadyListening(
                    f"another xenia is already listening on {self.path}; "
                    "stop it before starting a second one. Nothing was "
                    "changed, and the running broker still answers.")
            os.unlink(self.path)

        self._sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self._sock.bind(self.path)
        os.chmod(self.path, 0o600)
        # Which inode we bound, so stop() removes OUR socket and not whatever
        # is at the path by then. The unlink is the same hazard as the bind.
        try:
            self._inode = os.stat(self.path).st_ino
        except OSError:
            self._inode = None
        self._sock.listen(8)
        self._running = True
        self._thread = threading.Thread(target=self._accept, daemon=True,
                                        name="xenia-broker")
        self._thread.start()
        return self.path

    def stop(self) -> None:
        self._running = False
        if self._sock is not None:
            try:
                self._sock.close()
            finally:
                self._sock = None
        try:
            if self._inode is not None and os.stat(self.path).st_ino == self._inode:
                os.unlink(self.path)
        except OSError:
            pass
        self._inode = None

    def _accept(self) -> None:
        while self._running and self._sock is not None:
            try:
                client, _ = self._sock.accept()
            except OSError:
                break
            if not self._slots.acquire(blocking=False):
                # Refusing is the answer, not queueing behind it: a caller
                # told the broker is busy can retry, and a caller waiting on a
                # thread that will never free is just another wedged client.
                _turn_away(client)
                continue
            threading.Thread(target=self._one, args=(client,), daemon=True,
                             name="xenia-broker-call").start()

    def _one(self, client: socket.socket) -> None:
        try:
            self._answer(client)
        finally:
            self._slots.release()

    def _answer(self, client: socket.socket) -> None:
        with client:
            client.settimeout(CLIENT_READ_TIMEOUT)
            try:
                who = _peer(client)
                if who.get("uid") not in (None, os.getuid()):
                    client.sendall(json.dumps(
                        {"protocol": config.PROTOCOL_VERSION,
                         "error": "not your socket",
                         "code": "off-policy"}).encode() + b"\n")
                    return
                payload = _read_line(client)
                reply = self.handle(json.loads(payload), who)
            except Exception as exc:
                # PROTOCOL BELONGS ON THIS REPLY TOO. Without it a caller that
                # checks the version — which it must, since that is what the
                # number is for — reads every server-side crash as "your client
                # is out of date" and reports that instead of the actual error.
                # Measured 2026-09-11: a real exception during a download came
                # back to hermes as "broker speaks protocol None".
                reply = {"protocol": config.PROTOCOL_VERSION,
                         "error": f"{type(exc).__name__}: {exc}",
                         "code": "unknown"}
            try:
                client.sendall(json.dumps(reply, default=str).encode() + b"\n")
            except OSError:
                pass

    def handle(self, message: dict, who: dict | None = None) -> dict:
        """One request, one reply, both JSON. See OPS for the contract.

        Every reply carries `protocol`. Something outside this repo parses
        these, so the shape is a promise rather than an implementation detail:
        a field changing meaning or leaving raises the number, an addition
        does not.
        """
        op = message.get("op")
        reply: dict[str, Any]

        if op == "ping":
            reply = {"ok": True, "pid": os.getpid()}
        elif op == "ops":
            reply = {"ops": OPS, "codes": CODES,
                     "schemes": {name: signing.available(name)
                                 for name in sorted(signing.SCHEMES)}}
        elif op in ("fetch", "sign"):
            from . import db
            conn = db.connect(self.db_path)
            try:
                message = dict(message)
                message.setdefault("client", _describe(who))
                reply = (fetch(conn, message) if op == "fetch"
                         else sign_only(conn, message))
            finally:
                conn.close()
        else:
            reply = {"refused": f"unknown op: {op}. This socket speaks: "
                                f"{', '.join(sorted(OPS))}.",
                     "code": "malformed"}

        return {"protocol": config.PROTOCOL_VERSION, **reply}


def _turn_away(client: socket.socket) -> None:
    with client:
        try:
            client.settimeout(1.0)
            client.sendall(json.dumps({
                "protocol": config.PROTOCOL_VERSION,
                "refused": f"the broker is already handling {MAX_CLIENTS} "
                           f"calls. Retry.",
                "code": "unavailable"}).encode() + b"\n")
        except OSError:
            pass


def _peer(client: socket.socket) -> dict:
    try:
        raw = client.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED,
                                struct.calcsize("3i"))
        pid, uid, _gid = struct.unpack("3i", raw)
        return {"pid": pid, "uid": uid}
    except Exception:
        return {}


def _describe(who: dict | None) -> str | None:
    if not who or not who.get("pid"):
        return None
    name = vault._comm(who["pid"]) or "?"
    return f"{name} (pid {who['pid']})"


def _read_line(client: socket.socket, limit: int = 1_048_576) -> bytes:
    """One newline-terminated request, or an error.

    The socket carries a read timeout, so a caller that opens a connection and
    says nothing costs one slot for that long rather than a thread for ever.
    """
    buffer = b""
    while b"\n" not in buffer:
        chunk = client.recv(65536)
        if not chunk:
            break
        buffer += chunk
        if len(buffer) > limit:
            raise ValueError("request too large")
    return buffer.split(b"\n", 1)[0]


def request(payload: dict, *, path: str | None = None,
            timeout: float | None = None) -> dict:
    """Ask the service to make a call. Used by the MCP server."""
    path = path or socket_path()
    timeout = timeout or (config.FETCH_MAX_TIMEOUT + 10)
    client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    client.settimeout(timeout)
    try:
        client.connect(path)
    except (FileNotFoundError, ConnectionRefusedError, PermissionError) as exc:
        raise BrokerError(
            f"the xenia service is not listening at {path} ({exc.__class__.__name__}). "
            f"Credentials are held by the service, not by this MCP server, so "
            f"the user needs to start it — `xenia` — before this tool can do "
            f"anything.") from exc
    try:
        client.sendall(json.dumps(payload).encode() + b"\n")
        reply = _read_line(client)
    finally:
        client.close()
    if not reply:
        raise BrokerError("the xenia service closed the connection without "
                          "answering")
    return json.loads(reply)
