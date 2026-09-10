"""Where credential values actually live: the operating system's own store.

Xenia writes no crypto and holds no ciphertext. On Linux that is the Secret
Service D-Bus API, which gnome-keyring, KWallet and KeePassXC all implement,
so which one is the user's choice; on macOS it is the Keychain.

A backend can get, set, delete, list its own items and describe itself.
Listing is not a way in: anything running as the user can enumerate the store
directly, so withholding it here only cost the user a working `secret list`.
"""

from __future__ import annotations

import base64
import os
import secrets as _random
import shlex
import subprocess
import sys
import threading
from typing import Any, Callable

from . import config

APP = "xenia"

#: How long to wait on a provider that has put a dialog in front of the user.
#: Long, because the thing on the other side is somebody typing a password.
PROMPT_TIMEOUT = 120.0

#: How long to wait on a provider that should answer immediately.
CALL_TIMEOUT = 10.0


class VaultError(RuntimeError):
    """The store could not do it — no provider, still locked, or refused."""


def attributes(name: str) -> dict[str, str]:
    return {"application": APP, "name": name}


# --------------------------------------------------------------------------
# Secret Service (Linux)
# --------------------------------------------------------------------------

SERVICE = "org.freedesktop.secrets"
ROOT = "/org/freedesktop/secrets"
DEFAULT_COLLECTION = "/org/freedesktop/secrets/aliases/default"
I_SERVICE = "org.freedesktop.Secret.Service"
I_COLLECTION = "org.freedesktop.Secret.Collection"
I_ITEM = "org.freedesktop.Secret.Item"
I_PROMPT = "org.freedesktop.Secret.Prompt"

NO_OBJECT = "/"


class SecretService:
    """The freedesktop Secret Service, over xenia's own D-Bus client.

    A connection per operation rather than one held open: these are rare, and
    a stale connection to a restarted keyring is the worse failure.
    """

    kind = "secret-service"

    def __init__(self, connect: Callable[[], Any] | None = None) -> None:
        self._connect = connect or _session_bus

    # -- interface ---------------------------------------------------------

    def get(self, name: str) -> str | None:
        conn = self._connect()
        try:
            session = self._session(conn)
            item = self._find(conn, name)
            if item is None:
                return None
            secret = conn.call(SERVICE, item, I_ITEM, "GetSecret", "o",
                               [session], timeout=CALL_TIMEOUT)[0]
            return bytes(secret[2]).decode()
        finally:
            _close(conn)

    def set(self, name: str, value: str) -> None:
        from .dbus import Variant

        conn = self._connect()
        try:
            session = self._session(conn)
            self._unlock(conn, [DEFAULT_COLLECTION])
            props = {
                f"{I_ITEM}.Label": Variant("s", f"{APP}: {name}"),
                f"{I_ITEM}.Attributes": Variant("a{ss}", attributes(name)),
            }
            item, prompt = conn.call(
                SERVICE, DEFAULT_COLLECTION, I_COLLECTION, "CreateItem",
                "a{sv}(oayays)b",
                [props, (session, b"", value.encode(), "text/plain"), True],
                timeout=CALL_TIMEOUT)
            if item == NO_OBJECT and prompt != NO_OBJECT:
                self._prompt(conn, prompt)
        finally:
            _close(conn)

    def delete(self, name: str) -> bool:
        conn = self._connect()
        try:
            self._session(conn)
            item = self._find(conn, name)
            if item is None:
                return False
            prompt = conn.call(SERVICE, item, I_ITEM, "Delete",
                               timeout=CALL_TIMEOUT)[0]
            if prompt != NO_OBJECT:
                self._prompt(conn, prompt)
            return True
        finally:
            _close(conn)

    def names(self) -> list[str]:
        """Every credential xenia has put in the store, by name."""
        conn = self._connect()
        try:
            self._session(conn)
            found, locked = conn.call(SERVICE, ROOT, I_SERVICE, "SearchItems",
                                      "a{ss}", [{"application": APP}],
                                      timeout=CALL_TIMEOUT)
            out = []
            for path in list(found) + list(locked):
                try:
                    attrs = conn.call(
                        SERVICE, path, "org.freedesktop.DBus.Properties",
                        "Get", "ss",
                        ["org.freedesktop.Secret.Item", "Attributes"],
                        timeout=CALL_TIMEOUT)[0]
                    value = getattr(attrs, "value", attrs)
                    if value.get("name"):
                        out.append(value["name"])
                except Exception:
                    continue
            return sorted(set(out))
        finally:
            _close(conn)

    def describe(self) -> dict[str, Any]:
        out: dict[str, Any] = {"kind": self.kind, "available": False}
        try:
            conn = self._connect()
        except Exception as exc:
            out["detail"] = f"no session bus: {exc}"
            return out
        try:
            if not conn.name_has_owner(SERVICE):
                out["detail"] = (
                    "nothing is serving org.freedesktop.secrets on this "
                    "session bus")
                return out
            out["available"] = True
            pid = conn.call("org.freedesktop.DBus", "/org/freedesktop/DBus",
                            "org.freedesktop.DBus",
                            "GetConnectionUnixProcessID", "s", [SERVICE],
                            timeout=CALL_TIMEOUT)[0]
            out["pid"] = pid
            out["provider"] = _comm(pid) or "unknown"
            out["detail"] = f"{out['provider']} (pid {pid})"
        except Exception as exc:
            out["detail"] = f"{type(exc).__name__}: {exc}"
        finally:
            _close(conn)
        return out

    # -- internals ---------------------------------------------------------

    def _session(self, conn) -> str:
        from .dbus import Variant

        try:
            _output, session = conn.call(SERVICE, ROOT, I_SERVICE,
                                         "OpenSession", "sv",
                                         ["plain", Variant("s", "")],
                                         timeout=CALL_TIMEOUT)
        except Exception as exc:
            raise VaultError(
                f"could not open a session with the secret service: {exc}. "
                f"Run `xenia secrets setup` to see what is serving it."
            ) from exc
        return session

    def _find(self, conn, name: str) -> str | None:
        unlocked, locked = conn.call(SERVICE, ROOT, I_SERVICE, "SearchItems",
                                     "a{ss}", [attributes(name)],
                                     timeout=CALL_TIMEOUT)
        if unlocked:
            return unlocked[0]
        if not locked:
            return None
        self._unlock(conn, list(locked))
        unlocked, still_locked = conn.call(SERVICE, ROOT, I_SERVICE,
                                           "SearchItems", "a{ss}",
                                           [attributes(name)],
                                           timeout=CALL_TIMEOUT)
        if unlocked:
            return unlocked[0]
        if still_locked:
            raise VaultError(
                f"'{name}' is in a locked collection and the unlock was "
                f"dismissed or timed out")
        return None

    def _unlock(self, conn, paths: list[str]) -> None:
        if not paths:
            return
        _unlocked, prompt = conn.call(SERVICE, ROOT, I_SERVICE, "Unlock",
                                      "ao", [paths], timeout=CALL_TIMEOUT)
        if prompt != NO_OBJECT:
            self._prompt(conn, prompt)

    def _prompt(self, conn, path: str) -> None:
        """Run a provider's own dialog and wait for the person in front of it.

        Without this a locked keyring is a dead end after every reboot, with
        nothing on screen to say so. The signal is matched before the prompt
        is raised, or the answer arrives with nothing listening.
        """
        done = threading.Event()
        outcome: dict[str, Any] = {"dismissed": True}

        def completed(message) -> None:
            body = message.body or []
            outcome["dismissed"] = bool(body[0]) if body else True
            done.set()

        conn.on_signal(path, I_PROMPT, "Completed", completed)
        conn.call(SERVICE, path, I_PROMPT, "Prompt", "s", [""],
                  timeout=CALL_TIMEOUT)
        if not done.wait(PROMPT_TIMEOUT):
            raise VaultError(
                f"the credential store asked for an unlock and nothing "
                f"answered within {int(PROMPT_TIMEOUT)}s")
        if outcome["dismissed"]:
            raise VaultError("the unlock prompt was dismissed")


def _session_bus():
    from .dbus import Connection
    return Connection().connect()


def _close(conn) -> None:
    try:
        conn.close()
    except Exception:
        pass


def _comm(pid: Any) -> str | None:
    try:
        with open(f"/proc/{int(pid)}/comm") as handle:
            return handle.read().strip()
    except OSError:
        return None


# --------------------------------------------------------------------------
# Keychain (macOS)
# --------------------------------------------------------------------------

class Keychain:
    """The login keychain, through `security`.

    Writes go through `security -i`, which reads commands from stdin, so the
    value never appears in a command line. Untested: this repo has no mac, and
    the write path is the one to check first if it misbehaves.
    """

    kind = "keychain"

    def __init__(self, run: Callable[..., Any] | None = None) -> None:
        self._run = run or _run

    def _service(self, name: str) -> str:
        return f"{APP}:{name}"

    def _account(self) -> str:
        return os.environ.get("USER") or APP

    def get(self, name: str) -> str | None:
        done = self._run(["security", "find-generic-password",
                          "-s", self._service(name), "-a", self._account(),
                          "-w"])
        if done.returncode != 0:
            # 44 is "no such item", which is an answer rather than a fault.
            if done.returncode == 44 or "could not be found" in (done.stderr or ""):
                return None
            raise VaultError(f"security: {(done.stderr or '').strip()}")
        return (done.stdout or "").rstrip("\n")

    def set(self, name: str, value: str) -> None:
        script = " ".join([
            "add-generic-password", "-U",
            "-s", shlex.quote(self._service(name)),
            "-a", shlex.quote(self._account()),
            "-w", shlex.quote(value),
        ]) + "\n"
        done = self._run(["security", "-i"], stdin=script)
        if done.returncode != 0:
            raise VaultError(f"security: {(done.stderr or '').strip()}")

    def delete(self, name: str) -> bool:
        done = self._run(["security", "delete-generic-password",
                          "-s", self._service(name), "-a", self._account()])
        return done.returncode == 0

    def names(self) -> list[str]:
        """Not available: `security` cannot list by attribute without
        dumping the whole keychain, which prompts."""
        return []

    def describe(self) -> dict[str, Any]:
        done = self._run(["security", "default-keychain"])
        ok = done.returncode == 0
        return {"kind": self.kind, "available": ok,
                "provider": "macOS Keychain",
                "detail": (done.stdout or done.stderr or "").strip()
                          or "no default keychain"}


def _run(argv: list[str], stdin: str | None = None):
    return subprocess.run(argv, input=stdin, capture_output=True, text=True,
                          timeout=CALL_TIMEOUT)


# --------------------------------------------------------------------------
# Choosing one
# --------------------------------------------------------------------------

BACKENDS: dict[str, Callable[[], Any]] = {
    SecretService.kind: SecretService,
    Keychain.kind: Keychain,
}


def default_kind() -> str:
    if sys.platform == "darwin":
        return Keychain.kind
    if sys.platform.startswith("linux"):
        return SecretService.kind
    raise VaultError(
        f"no credential store for {sys.platform} — xenia can use the "
        f"freedesktop Secret Service on Linux and the Keychain on macOS")


def configured_kind() -> str:
    chosen = (config.site().get("secrets") or {}).get("backend")
    return chosen or default_kind()


def backend(kind: str | None = None):
    kind = kind or configured_kind()
    make = BACKENDS.get(kind)
    if make is None:
        raise VaultError(
            f"unknown credential store '{kind}' — known: "
            f"{', '.join(sorted(BACKENDS))}")
    return make()


def selftest(store=None) -> dict[str, Any]:
    """Store a throwaway value, read it back, delete it.

    A listing is not evidence: the only way to know the broker will work is to
    make the store do what the broker does.
    """
    store = store or backend()
    name = "selftest"
    value = base64.urlsafe_b64encode(_random.token_bytes(18)).decode()
    out: dict[str, Any] = {"backend": store.kind, "ok": False}
    try:
        out["provider"] = store.describe()
        store.set(name, value)
        got = store.get(name)
        out["ok"] = got == value
        if not out["ok"]:
            out["detail"] = ("stored a value and read back "
                             + ("nothing" if got is None else "something else"))
    except Exception as exc:
        out["detail"] = f"{type(exc).__name__}: {exc}"
    finally:
        try:
            store.delete(name)
        except Exception:
            pass
    if out["ok"]:
        out["detail"] = "stored, read back and deleted a test value"
    return out
