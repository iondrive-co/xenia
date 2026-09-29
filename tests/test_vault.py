from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from xenia import config, vault
from xenia.dbus import Variant


class FakeBus:
    """A Secret Service that answers the way gnome-keyring does."""

    def __init__(self, *, locked: bool = False, prompts: bool = False) -> None:
        self.items: dict[str, bytes] = {}
        self.calls: list[tuple] = []
        self.locked = locked
        self.prompts = prompts
        self.closed = False
        self._signals: dict[tuple, object] = {}

    def name_has_owner(self, name):
        return True

    def on_signal(self, path, interface, member, handler):
        self._signals[(path, interface, member)] = handler

    def close(self):
        self.closed = True

    def _complete(self, path):
        handler = self._signals.get((path, vault.I_PROMPT, "Completed"))
        if handler is not None:
            handler(type("M", (), {"body": [False, None]})())

    def call(self, dest, path, interface, member, signature="", body=(),
             timeout=None):
        self.calls.append((interface, member, body))

        if member == "GetNameOwner":
            return [":1.7"]
        if member == "GetConnectionUnixProcessID":
            return [4242]
        if member == "OpenSession":
            return [Variant("s", ""), "/session/1"]
        if member == "SearchItems":
            name = body[0]["name"]
            if name not in self.items:
                return [[], []]
            path = f"/item/{name}"
            return [[], [path]] if self.locked else [[path], []]
        if member == "Unlock":
            if self.prompts:
                return [[], "/prompt/1"]
            self.locked = False
            return [list(body[0]), "/"]
        if member == "Prompt":
            self.locked = False
            self._complete(path)
            return []
        if member == "CreateItem":
            name = body[0][f"{vault.I_ITEM}.Attributes"].value["name"]
            self.items[name] = body[1][2]
            return [f"/item/{name}", "/"]
        if member == "GetSecret":
            name = path.rsplit("/", 1)[1]
            return [("/session/1", b"", self.items[name], "text/plain")]
        if member == "Delete":
            self.items.pop(path.rsplit("/", 1)[1], None)
            return ["/"]
        raise AssertionError(f"unexpected call: {interface}.{member}")


def store(bus, gate=None):
    return vault.SecretService(connect=lambda: bus, gate=gate or vault.UnlockGate())


def test_round_trips_a_value_through_the_secret_service():
    bus = FakeBus()
    box = store(bus)

    box.set("gitlab-pat", "s3cret-value")
    assert box.get("gitlab-pat") == "s3cret-value"
    assert box.delete("gitlab-pat") is True
    assert box.get("gitlab-pat") is None


def test_a_missing_name_is_an_answer_not_an_error():
    assert store(FakeBus()).get("never-stored") is None


def test_the_item_is_filed_under_xenias_own_attributes():
    bus = FakeBus()
    store(bus).set("token", "v")
    created = [call for call in bus.calls if call[1] == "CreateItem"][0]
    props = created[2][0]
    assert props[f"{vault.I_ITEM}.Attributes"].value == {
        "application": "xenia", "name": "token"}
    assert props[f"{vault.I_ITEM}.Label"].value == "xenia: token"


def test_a_locked_collection_is_unlocked_rather_than_reported_as_empty():
    bus = FakeBus()
    bus.items["pat"] = b"value"
    bus.locked = True

    assert store(bus).get("pat") == "value"
    assert any(call[1] == "Unlock" for call in bus.calls)


def test_a_provider_that_raises_a_dialog_is_waited_for():
    bus = FakeBus(locked=True, prompts=True)
    bus.items["pat"] = b"value"

    assert store(bus).get("pat") == "value"
    assert any(call[1] == "Prompt" for call in bus.calls)


def test_a_dismissed_prompt_is_an_error_and_not_a_missing_value():
    bus = FakeBus(locked=True, prompts=True)
    bus.items["pat"] = b"value"
    bus._complete = lambda path: bus._signals[
        (path, vault.I_PROMPT, "Completed")](
            type("M", (), {"body": [True, None]})())

    with pytest.raises(vault.VaultError, match="dismissed"):
        store(bus).get("pat")


def test_an_unanswered_prompt_is_reported_as_keyring_locked(monkeypatch):
    monkeypatch.setattr(vault, "PROMPT_TIMEOUT", 0.05)
    bus = FakeBus(locked=True, prompts=True)
    bus.items["pat"] = b"value"
    bus.call = lambda dest, path, iface, member, sig="", body=(), timeout=None: (
        [] if member == "Prompt" else FakeBus.call(bus, dest, path, iface, member, sig, body, timeout)
    )

    with pytest.raises(vault.VaultError, match="the keyring is locked"):
        store(bus).get("pat")


class PromptBus(FakeBus):

    def __init__(self, shared_items, shared_state):
        self._state = shared_state
        super().__init__(locked=True, prompts=True)
        self.items = shared_items
        self.dismissed = False

    @property
    def locked(self):
        return self._state["locked"]

    @locked.setter
    def locked(self, value):
        if value is False or "locked" not in self._state:
            self._state["locked"] = value

    def call(self, dest, path, interface, member, signature="", body=(), timeout=None):
        if member == "Prompt":
            self.calls.append((interface, member, body))
            return []
        if member == "Dismiss":
            self.calls.append((interface, member, body))
            self.dismissed = True
            self._signals[(path, vault.I_PROMPT, "Completed")](type("M", (), {"body": [True, None]})())
            return []
        return FakeBus.call(self, dest, path, interface, member, signature, body, timeout)

    def answer(self, path="/prompt/1"):
        self.locked = False
        self._signals[(path, vault.I_PROMPT, "Completed")](type("M", (), {"body": [False, None]})())


def _buses():
    items, state, made = {"pat": b"value"}, {}, []

    def connect():
        bus = PromptBus(items, state)
        made.append(bus)
        return bus
    return connect, made


def test_one_dialog_serves_every_caller_and_its_connection_outlives_them(monkeypatch):
    monkeypatch.setattr(vault, "PROMPT_TIMEOUT", 0.05)
    gate, (connect, made) = vault.UnlockGate(), _buses()
    box = vault.SecretService(connect=connect, gate=gate)
    for _ in range(3):
        with pytest.raises(vault.VaultError, match="waiting for the password"):
            box.get("pat")
    dialogs = [b for b in made if any(c[1] == "Prompt" for c in b.calls)]
    assert len(dialogs) == 1
    assert not dialogs[0].closed
    dialogs[0].answer()
    for _ in range(100):
        if dialogs[0].closed:
            break
        __import__("time").sleep(0.01)
    assert dialogs[0].closed and not dialogs[0].dismissed
    assert box.get("pat") == "value"


def test_a_dialog_left_open_is_dismissed_by_xenia_never_dropped(monkeypatch):
    monkeypatch.setattr(vault, "PROMPT_TIMEOUT", 0.05)
    monkeypatch.setattr(vault, "DIALOG_LIFETIME", 0.1)
    gate, (connect, made) = vault.UnlockGate(), _buses()
    with pytest.raises(vault.VaultError):
        vault.SecretService(connect=connect, gate=gate).get("pat")
    dialog = [b for b in made if any(c[1] == "Prompt" for c in b.calls)][0]
    for _ in range(100):
        if dialog.closed:
            break
        __import__("time").sleep(0.01)
    assert dialog.dismissed and dialog.closed
    assert [c[1] for c in dialog.calls].index("Dismiss") > [c[1] for c in dialog.calls].index("Prompt")


def test_a_dismissed_dialog_is_not_raised_again_during_the_cooldown(monkeypatch):
    monkeypatch.setattr(vault, "PROMPT_TIMEOUT", 0.5)
    gate, (connect, made) = vault.UnlockGate(), _buses()
    box = vault.SecretService(connect=connect, gate=gate)
    import threading
    t = threading.Timer(0.05, lambda: [b for b in made if any(c[1] == "Prompt" for c in b.calls)][0]
                        ._signals[("/prompt/1", vault.I_PROMPT, "Completed")](type("M", (), {"body": [True, None]})()))
    t.start()
    with pytest.raises(vault.VaultError, match="dismissed"):
        box.get("pat")
    t.join()
    before = sum(1 for b in made for c in b.calls if c[1] == "Prompt")
    with pytest.raises(vault.VaultError, match="no new one"):
        box.get("pat")
    assert sum(1 for b in made for c in b.calls if c[1] == "Prompt") == before


def test_the_connection_is_closed_even_when_the_call_fails(monkeypatch):
    monkeypatch.setattr(vault, "LINGER", 0.05)
    bus = FakeBus()

    def explode(*_args, **_kwargs):
        raise RuntimeError("bus went away")

    bus.call = explode
    with pytest.raises(Exception):
        store(bus).get("pat")
    assert not bus.closed
    __import__("time").sleep(0.2)
    assert bus.closed


def test_a_clean_operation_closes_its_connection_at_once():
    bus = FakeBus()
    bus.items["pat"] = b"value"
    assert store(bus).get("pat") == "value"
    assert bus.closed


def test_describe_names_the_program_serving_the_store(monkeypatch):
    monkeypatch.setattr(vault, "_comm", lambda pid: "keepassxc")
    described = store(FakeBus()).describe()
    assert described["available"] is True
    assert described["provider"] == "keepassxc"
    assert "4242" in described["detail"]


# -- keychain ---------------------------------------------------------------

class FakeRun:
    def __init__(self, returncode=0, stdout="", stderr=""):
        self.result = type("R", (), {"returncode": returncode,
                                     "stdout": stdout, "stderr": stderr})()
        self.calls: list[tuple] = []

    def __call__(self, argv, stdin=None):
        self.calls.append((argv, stdin))
        return self.result


def test_keychain_writes_never_put_the_value_in_a_command_line():
    run = FakeRun()
    vault.Keychain(run=run).set("pat", "s3cret-value")

    argv, stdin = run.calls[0]
    assert argv == ["security", "-i"]
    assert "s3cret-value" not in " ".join(argv)
    assert "s3cret-value" in stdin


def test_keychain_reports_a_missing_item_as_absent_not_broken():
    run = FakeRun(returncode=44, stderr="could not be found")
    assert vault.Keychain(run=run).get("pat") is None


def test_keychain_raises_on_a_real_failure():
    run = FakeRun(returncode=1, stderr="keychain is locked")
    with pytest.raises(vault.VaultError, match="locked"):
        vault.Keychain(run=run).get("pat")


# -- choosing ---------------------------------------------------------------

def test_the_platform_decides_unless_the_site_says_otherwise(site_config):
    assert vault.configured_kind() in (vault.SecretService.kind,
                                       vault.Keychain.kind)
    site_config({"secrets": {"backend": "keychain"}})
    config.reset_cache()
    assert vault.configured_kind() == "keychain"


def test_an_unknown_backend_says_what_it_knows():
    with pytest.raises(vault.VaultError, match="secret-service"):
        vault.backend("hashicorp")


# -- the self-test ----------------------------------------------------------

class Memory:
    kind = "memory"

    def __init__(self, *, broken: bool = False) -> None:
        self.values: dict[str, str] = {}
        self.broken = broken

    def get(self, name):
        return self.values.get(name)

    def set(self, name, value):
        if not self.broken:
            self.values[name] = value

    def delete(self, name):
        return self.values.pop(name, None) is not None

    def describe(self):
        return {"kind": self.kind, "available": True}


def test_the_selftest_proves_a_round_trip_and_leaves_nothing_behind():
    store = Memory()
    outcome = vault.selftest(store)

    assert outcome["ok"] is True
    assert store.values == {}


def test_a_store_that_answers_but_cannot_hold_a_value_fails_the_selftest():
    outcome = vault.selftest(Memory(broken=True))

    assert outcome["ok"] is False
    assert "read back nothing" in outcome["detail"]
