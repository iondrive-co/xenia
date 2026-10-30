from __future__ import annotations

import base64
import json
import os
import shutil
import subprocess
from typing import Any, Callable

from . import broker, config, vault

PREFIX = "xenia: "
FIELD = "xenia-name"
# Bitwarden refuses a note longer than 10,000 characters in its encrypted form ("2.iv|ciphertext|mac", base64 of
# AES-CBC), not as typed: 7,000 bytes of UTF-8 encrypt to 9,416 characters, so the limit counts bytes.
NOTE_LIMIT = 7000
ENCRYPTED_NOTE_CAP = 10000
CALL_TIMEOUT = 120.0


class BackupError(RuntimeError):
    pass


def settings() -> dict[str, Any]:
    chosen = config.site().get("backup")
    return chosen if isinstance(chosen, dict) else {}


def configured_kind() -> str:
    return str(settings().get("target") or "bitwarden")


def pending(conn, kind: str | None = None) -> list[dict]:
    kind = kind or configured_kind()
    return [row for row in broker.registry(conn)
            if row.get("backup_target") != kind
            or row.get("backup_revision") != row.get("revision")]


def summary(conn) -> dict[str, Any]:
    kind = configured_kind()
    rows = broker.registry(conn)
    copied = [row["backed_up_at"] for row in rows
              if row.get("backup_target") == kind and row.get("backed_up_at")]
    return {"target": kind, "total": len(rows),
            "pending": [row["name"] for row in pending(conn, kind)],
            "last": max(copied, default=None)}


def describe(state: dict[str, Any]) -> str:
    waiting = state["pending"]
    if not state["total"]:
        return "No credentials to back up."
    if not waiting:
        return (f"All {state['total']} credential(s) are in the {state['target']} "
                f"backup (last copied {(state['last'] or '?')[:16]}).")
    shown = ", ".join(waiting[:8])
    if len(waiting) > 8:
        shown += f" and {len(waiting) - 8} more"
    return (f"{len(waiting)} of {state['total']} credential(s) are not in the "
            f"{state['target']} backup: {shown} — `xenia secret backup` copies them.")


def in_use(conn) -> bool:
    if settings():
        return True
    return conn.execute("SELECT 1 FROM secret WHERE backup_target IS NOT NULL "
                        "LIMIT 1").fetchone() is not None


def nudge(conn, name: str, notify: Callable[[str, str], None] | None = None) -> bool:
    if not in_use(conn):
        return False
    (notify or broker._notify)(
        "xenia: not backed up yet",
        f"'{name}' was stored and is not in your backup. "
        f"Credentials → Back up… copies it.")
    return True


def _parsed(text):
    if not text:
        return None
    try:
        return json.loads(text)
    except (TypeError, ValueError):
        return text


def policy_of(row) -> dict[str, Any]:
    quota = {"bytes": row["quota_bytes"], "requests": row["quota_requests"],
             "window_s": row["quota_window_s"]}
    out = {"name": row["name"], "note": row["note"], "backend": row["backend"],
           "hosts": _parsed(row["hosts"]), "methods": _parsed(row["methods"]),
           "paths": _parsed(row["paths"]), "service": row["service"],
           "scope": _parsed(row["scope"]), "expires_hint": row["expires_hint"],
           "schemes": _parsed(row["schemes"]),
           "body_policy": _parsed(row["body_policy"]),
           "quota": quota if any(v is not None for v in quota.values()) else None}
    return {key: value for key, value in out.items() if value not in (None, [], {})}


def notes_for(policy: dict[str, Any]) -> str:
    head = str(policy.get("note") or "").strip()
    rest = {key: value for key, value in policy.items() if key != "note"}

    def written(shown: dict[str, Any]) -> str:
        body = "xenia policy:\n" + json.dumps(shown, indent=1, sort_keys=True)
        return f"{head}\n\n{body}" if head else body

    text = written(rest)
    if len(text.encode()) > NOTE_LIMIT:
        if isinstance(rest.get("schemes"), dict):
            rest["schemes"] = sorted(rest["schemes"])
        if isinstance(rest.get("body_policy"), dict):
            rest["body_policy"] = {"actions": sorted(rest["body_policy"].get("actions") or {})}
        text = written(rest)
    return text.encode()[:NOTE_LIMIT].decode(errors="ignore")      # never half a character


def record(conn, name: str, kind: str, revision, ref: str) -> bool:
    cursor = conn.execute(
        "UPDATE secret SET backup_target = ?, backup_revision = ?, backup_ref = ?, "
        "backed_up_at = ? WHERE name = ? AND revision IS ?",
        (kind, revision, ref, broker.stamp(broker.utcnow()), name, revision))
    conn.commit()
    return cursor.rowcount > 0


def _encode(payload: dict) -> str:
    return base64.b64encode(json.dumps(payload).encode()).decode()


class Bitwarden:
    kind = "bitwarden"
    label = "Bitwarden"

    def __init__(self, command: str | None = None, folder: str | None = None,
                 run: Callable = subprocess.run, environ: dict | None = None) -> None:
        chosen = settings()
        self.command = command or chosen.get("bw") or shutil.which("bw")
        self.folder = folder or chosen.get("folder") or "xenia"
        self._run = run
        self._environ = dict(os.environ if environ is None else environ)
        self._session: str | None = None
        self._opened_here = False
        self._folder_id: str | None = None

    def _call(self, *args: str, stdin: str | None = None,
              interactive: bool = False) -> str:
        env = dict(self._environ)
        if self._session:
            env["BW_SESSION"] = self._session
        if not interactive:
            env["BW_NOINTERACTION"] = "true"
        try:
            done = self._run([self.command, *args], input=stdin,
                             stdout=subprocess.PIPE,
                             stderr=None if interactive else subprocess.PIPE,
                             text=True, env=env,
                             timeout=None if interactive else CALL_TIMEOUT)
        except (OSError, subprocess.SubprocessError) as exc:
            raise BackupError(f"bw {args[0]}: {exc}") from exc
        if done.returncode != 0:
            said = (done.stderr or "").strip().splitlines()
            raise BackupError(f"bw {args[0]} failed: "
                              f"{said[-1] if said else f'exit {done.returncode}'}")
        return done.stdout or ""

    def _json(self, *args: str, stdin: str | None = None):
        text = self._call(*args, stdin=stdin)
        try:
            return json.loads(text)
        except ValueError as exc:
            raise BackupError(f"bw {args[0]} did not answer in JSON") from exc

    def open(self) -> None:
        if not self.command:
            raise BackupError(
                "the Bitwarden CLI is not installed: install `bw` "
                "(https://bitwarden.com/help/cli/), or name it as \"bw\" under "
                "\"backup\" in xenia's config.json")
        state = str(self._json("status").get("status") or "")
        if state in ("unauthenticated", "locked"):
            verb = "login" if state == "unauthenticated" else "unlock"
            self._session = self._call(verb, "--raw", interactive=True).strip()
            self._opened_here = True
            if not self._session:
                raise BackupError(f"bw {verb} gave no session: the vault is still locked")
        elif state != "unlocked":
            raise BackupError(f"bw says the vault is {state or 'in an unknown state'}")
        self._call("sync")
        self._folder_id = self._folder()

    def close(self) -> None:
        if self._opened_here:
            try:
                self._call("lock")
            except BackupError:
                pass
        self._session = None
        self._opened_here = False

    def _folder(self) -> str:
        for found in self._json("list", "folders", "--search", self.folder):
            if found.get("name") == self.folder:
                return found["id"]
        return self._json("create", "folder", stdin=_encode({"name": self.folder}))["id"]

    def _existing(self, name: str, ref: str | None) -> dict | None:
        if ref:
            try:
                item = self._json("get", "item", ref)
            except BackupError:
                item = None
            if isinstance(item, dict) and not item.get("deletedDate") \
                    and not item.get("organizationId"):
                return item
        for found in self._json("list", "items", "--folderid", self._folder_id,
                                "--search", PREFIX + name):
            if found.get("organizationId"):
                continue
            named = [field.get("value") for field in found.get("fields") or []
                     if field.get("name") == FIELD]
            if named == [name] or (not named and found.get("name") == PREFIX + name):
                return found
        return None

    def put(self, name: str, value: str, policy: dict[str, Any], ref: str | None) -> str:
        item = self._existing(name, ref) or {
            "type": 1, "organizationId": None, "collectionIds": None,
            "favorite": False, "reprompt": 0, "fields": [],
            "login": {"username": None, "totp": None, "uris": []}}
        item.update(name=PREFIX + name, notes=notes_for(policy), folderId=self._folder_id)
        item["login"] = {**(item.get("login") or {}), "password": value}
        item["fields"] = [field for field in item.get("fields") or []
                          if field.get("name") != FIELD] + [
            {"name": FIELD, "value": name, "type": 0}]
        if item.get("id"):
            saved = self._json("edit", "item", item["id"], stdin=_encode(item))
        else:
            saved = self._json("create", "item", stdin=_encode(item))
        return str(saved["id"])


class Command:
    kind = "command"
    label = "the backup command"

    def __init__(self, command: list[str] | None = None, run: Callable = subprocess.run,
                 timeout: float | None = None) -> None:
        chosen = settings()
        self.command = list(command or chosen.get("command") or [])
        self.timeout = float(timeout or chosen.get("timeout_s") or CALL_TIMEOUT)
        self._run = run

    def open(self) -> None:
        if not self.command or not all(isinstance(part, str) for part in self.command):
            raise BackupError(
                "a \"command\" backup names its program as a list: "
                "\"backup\": {\"target\": \"command\", \"command\": [\"/path/to/program\"]} "
                "in xenia's config.json")

    def close(self) -> None:
        pass

    def put(self, name: str, value: str, policy: dict[str, Any], ref: str | None) -> str:
        payload = json.dumps({"name": name, "value": value, "policy": policy, "ref": ref})
        try:
            done = self._run(self.command, input=payload, stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE, text=True, timeout=self.timeout)
        except (OSError, subprocess.SubprocessError) as exc:
            raise BackupError(f"{self.command[0]}: {exc}") from exc
        if done.returncode != 0:
            said = (done.stderr or "").strip().splitlines()
            raise BackupError(f"{self.command[0]} failed: "
                              f"{said[-1] if said else f'exit {done.returncode}'}")
        try:
            answer = json.loads(done.stdout or "")
        except ValueError as exc:
            raise BackupError(f"{self.command[0]} did not answer in JSON") from exc
        if not isinstance(answer, dict) or not isinstance(answer.get("ref"), str) \
                or not answer["ref"]:
            raise BackupError(f"{self.command[0]} answered without a \"ref\"")
        return answer["ref"]


TARGETS: dict[str, Callable[[], Any]] = {"bitwarden": Bitwarden, "command": Command}


def target(kind: str | None = None):
    kind = kind or configured_kind()
    make = TARGETS.get(kind)
    if make is None:
        raise BackupError(f"unknown backup target '{kind}' — known: "
                          f"{', '.join(sorted(TARGETS))}")
    return make()


def run(conn, chosen=None, *, everything: bool = False, store=None,
        say: Callable[[str], None] = print) -> dict[str, list]:
    chosen = chosen or target()
    rows = broker.registry(conn) if everything else pending(conn, chosen.kind)
    out: dict[str, list] = {"done": [], "missing": [], "failed": []}
    if not rows:
        return out
    store = store or vault.backend()
    chosen.open()
    try:
        for row in rows:
            raw = broker.entry(conn, row["name"])
            if raw is None:
                continue
            name = raw["name"]
            value = store.get(name)
            if value is None:
                out["missing"].append(name)
                continue
            ref = raw["backup_ref"] if raw["backup_target"] == chosen.kind else None
            try:
                ref = chosen.put(name, value, policy_of(raw), ref)
            except BackupError as exc:
                out["failed"].append((name, str(exc)))
                continue
            finally:
                del value
            if record(conn, name, chosen.kind, raw["revision"], ref):
                out["done"].append(name)
                say(f"  {name}")
            else:
                out["failed"].append((name, "it changed while it was being copied; "
                                            "run the backup again"))
    finally:
        chosen.close()
    return out
