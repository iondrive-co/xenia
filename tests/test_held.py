from __future__ import annotations

import json
import sys
import threading
from datetime import timedelta

import pytest

from xenia import broker, db, providers, vault


SERVE = (
    "import hashlib, json, sys\n"
    "print(json.dumps({'protocol': 2, 'ready': True}), flush=True)\n"
    "for line in sys.stdin:\n"
    "    request = json.loads(line)\n"
    "    digest = hashlib.sha256(request['secret'].encode()).hexdigest()[:12]\n"
    "    reply = {'protocol': 2, 'id': request['id'],\n"
    "             'signature': digest + ':' + str(request['config'].get('limit'))}\n"
    "    sys.stdout.write(json.dumps(reply) + '\\n')\n"
    "    sys.stdout.flush()\n"
)


class Store:
    kind = "memory"

    def __init__(self, value="example-secret-one"):
        self.value = value
        self.reads = 0
        self.lock = threading.Lock()

    def get(self, name):
        with self.lock:
            self.reads += 1
        return self.value


@pytest.fixture(autouse=True)
def nothing_held():
    providers.stop()
    broker.forget_held()
    yield
    providers.stop()
    broker.forget_held()


@pytest.fixture
def signer(tmp_path, site_config, conn):
    path = tmp_path / "resident.py"
    path.write_text(SERVE)
    site_config({"signing_providers": {"example-signing": {
        "command": [sys.executable, "-I", str(path)], "timeout_s": 10, "resident": True,
        "request_timeout_s": 2}}})
    broker.register(conn, "service-key", backend="memory")
    broker.set_profile(conn, "service-key", "submit", {"scheme": "example-signing", "limit": 1})
    return conn


def approve(conn, hold=True, until_days=5):
    return broker.standing(conn, "service-key", broker.SIGN_SCOPE,
                           until=broker.utcnow() + timedelta(days=until_days),
                           profiles=["submit"], reason="scheduled requests", hold=hold)


def sign(conn, store):
    return broker.sign_only(conn, {"secret": "service-key", "profile": "submit", "payload": {}},
                            store=store, notify=False)


def test_a_holding_approval_reads_the_store_once(signer):
    approve(signer)
    store = Store()
    answers = [sign(signer, store) for _ in range(3)]
    assert all(answer.get("signature") for answer in answers)
    assert len({answer["signature"] for answer in answers}) == 1
    assert store.reads == 1
    assert broker.held_names() == ["service-key"]
    assert answers[1]["timing"]["keyring_ms"] == 0


def test_without_hold_every_use_reads_the_store(signer):
    approve(signer, hold=False)
    store = Store()
    for _ in range(3):
        assert sign(signer, store).get("signature")
    assert store.reads == 3
    assert broker.held_names() == []


def test_revoking_stops_signing_at_once(signer):
    approve(signer)
    store = Store()
    assert sign(signer, store).get("signature")
    broker.revoke(signer, "service-key")
    refused = sign(signer, store)
    assert refused["code"] == "unapproved"
    assert broker.held_names() == []


def test_an_approval_without_hold_drops_a_held_value(signer):
    approve(signer)
    store = Store()
    sign(signer, store)
    approve(signer, hold=False)
    assert sign(signer, store).get("signature")
    assert broker.held_names() == []
    assert store.reads == 2


def test_a_replaced_value_is_read_again(signer):
    approve(signer)
    store = Store()
    first = sign(signer, store)["signature"]
    store.value = "example-secret-two"
    broker.register(signer, "service-key", backend="memory")
    second = sign(signer, store)["signature"]
    assert first != second
    assert store.reads == 2


def test_a_changed_profile_is_used_at_once(signer):
    approve(signer)
    store = Store()
    assert sign(signer, store)["signature"].endswith(":1")
    broker.set_profile(signer, "service-key", "submit", {"scheme": "example-signing", "limit": 2})
    assert sign(signer, store)["signature"].endswith(":2")


def test_the_sweep_lets_go_of_values_whose_approval_ended(signer):
    approve(signer)
    store = Store()
    sign(signer, store)
    assert broker.sweep_held(signer) == 0
    broker.revoke(signer, "service-key")
    assert broker.sweep_held(signer) == 1
    assert broker.held_names() == []


def test_only_a_standing_approval_can_hold(signer):
    with pytest.raises(ValueError, match="standing"):
        broker.grant(signer, "service-key", broker.SIGN_SCOPE, mutating=True, hold=True)


def test_a_cached_profile_follows_writes_from_anywhere(conn):
    broker.register(conn, "service-key", backend="memory")
    broker.set_profile(conn, "service-key", "submit", {"scheme": "hmac", "limit": 1})
    assert broker.profile_of(conn, "service-key", "submit", "SIGN")["limit"] == 1
    conn.execute("UPDATE secret SET schemes = ? WHERE name = ?",
                 (json.dumps({"submit": {"scheme": "hmac", "limit": 2}}), "service-key"))
    conn.commit()
    assert broker.profile_of(conn, "service-key", "submit", "SIGN")["limit"] == 2
    broker.forget(conn, "service-key")
    assert broker.profile_of(conn, "service-key", "submit", "SIGN") is None
    broker.register(conn, "service-key", backend="memory")
    assert broker.profile_of(conn, "service-key", "submit", "SIGN") is None


def test_a_returned_profile_is_a_copy(conn):
    broker.register(conn, "service-key", backend="memory")
    broker.set_profile(conn, "service-key", "submit", {"scheme": "hmac", "fields": ["a"]})
    first = broker.profile_of(conn, "service-key", "submit", "SIGN")
    first["fields"].append("b")
    assert broker.profile_of(conn, "service-key", "submit", "SIGN")["fields"] == ["a"]


def test_revisions_are_never_reused(conn):
    broker.register(conn, "one", backend="memory")
    broker.register(conn, "two", backend="memory")
    revision = broker.entry(conn, "two")["revision"]
    broker.forget(conn, "two")
    broker.register(conn, "two", backend="memory")
    assert broker.entry(conn, "two")["revision"] > revision
    broker.rename(conn, "two", "three")
    assert broker.entry(conn, "three")["revision"] > revision + 1


def test_an_existing_database_gains_the_triggers(tmp_path):
    path = tmp_path / "audit.db"
    first = db.connect(path)
    for name in ("one", "two"):
        broker.register(first, name, backend="memory")
    first.execute("DROP TRIGGER secret_added")
    first.execute("DROP TRIGGER secret_revised")
    first.execute("DELETE FROM meta WHERE key = 'secret_revision'")
    first.execute("UPDATE secret SET revision = NULL")
    first.commit()
    first.close()
    again = db.connect(path)
    revisions = [row[0] for row in again.execute("SELECT revision FROM secret ORDER BY name")]
    assert None not in revisions and len(set(revisions)) == 2
    broker.register(again, "three", backend="memory")
    assert broker.entry(again, "three")["revision"] > max(revisions)
    again.close()


def test_the_server_migrates_once_and_sees_a_revoke_at_once(signer, tmp_path, monkeypatch):
    approve(signer)
    store = Store()
    monkeypatch.setattr(vault, "backend", lambda kind=None: store)
    monkeypatch.setattr(broker, "ask_to_use", lambda *args, **kwargs: False)
    opened = []
    real = db.connect

    def counting(*args, **kwargs):
        opened.append(kwargs.get("migrated"))
        return real(*args, **kwargs)

    monkeypatch.setattr(db, "connect", counting)
    server = broker.Server(path=str(tmp_path / "broker.sock"), db_path=tmp_path / "audit.db")
    server.start()
    request = {"op": "sign", "secret": "service-key", "profile": "submit", "payload": {}}
    try:
        replies = [broker.request(request, path=server.path) for _ in range(3)]
        report = broker.request({"op": "ops"}, path=server.path)
        broker.revoke(signer, "service-key")
        refused = broker.request(request, path=server.path)
        after = broker.request({"op": "ops"}, path=server.path)
    finally:
        server.stop()
    assert all(reply.get("signature") for reply in replies)
    assert store.reads == 1
    assert report["held"] == ["service-key"]
    assert refused["code"] == "unapproved"
    assert after["held"] == []
    served = [flag for flag in opened if flag is not None]
    assert served[:1] == [False] and served[1:] == [True] * (len(served) - 1)
