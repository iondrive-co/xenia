from __future__ import annotations

import importlib.util
import json
import os
import py_compile
import sys
import threading
import time

import pytest

from xenia import broker, providers, signing


SERVE = (
    "import json, os, sys, time\n"
    "print(json.dumps({'protocol': 2, 'ready': True}), flush=True)\n"
    "for line in sys.stdin:\n"
    "    request = json.loads(line)\n"
    "    body = json.loads(request['body'])\n"
    "HANDLER"
    "    reply = {'protocol': 2, 'id': request['id'],\n"
    "             'signature': f\"{os.getpid()}:{request['id']}:{request['config']['scheme']}\"}\n"
    "    sys.stdout.write(json.dumps(reply) + '\\n')\n"
    "    sys.stdout.flush()\n"
)


@pytest.fixture(autouse=True)
def no_pools_left():
    providers.stop()
    yield
    providers.stop()


@pytest.fixture
def resident(tmp_path, site_config):
    def install(handler="", source=None, schemes=("example-signing",), **settings):
        path = tmp_path / "resident.py"
        path.write_text(source if source is not None else SERVE.replace("HANDLER", handler))
        held = {"command": [sys.executable, "-I", str(path)], "timeout_s": 10, "resident": True,
                "request_timeout_s": 2, **settings}
        site_config({"signing_providers": {name: dict(held) for name in schemes}})
        return path
    return install


def context(body="{}", nonce=12):
    return signing.Context(secret="example-secret-value", method="SIGN", url="", headers={}, body=body,
                           config={}, nonce=nonce, now=1_600_000_000.0, extras={})


def sign(body=None, scheme="example-signing"):
    return signing.sign({"scheme": scheme}, context(json.dumps(body or {})))


def pid_of(signature):
    return int(signature.split(":")[0])


def test_a_resident_provider_starts_once_and_serves_every_request(resident, tmp_path):
    seen = tmp_path / "seen.jsonl"
    resident("    open(" + repr(str(seen)) + ", 'a').write(json.dumps(request) + '\\n')\n")
    first, second = sign({"amount": 1}), sign({"amount": 2})
    assert pid_of(first) == pid_of(second)
    rows = [json.loads(line) for line in seen.read_text().splitlines()]
    assert [row["protocol"] for row in rows] == [2, 2]
    assert rows[1]["id"] > rows[0]["id"]
    assert rows[0]["secret"] == "example-secret-value"
    assert rows[0]["nonce"] == 12 and rows[0]["method"] == "SIGN"
    assert first.endswith(":example-signing")


def test_a_provider_that_does_not_report_ready_is_unavailable(resident):
    resident(source="import json\nprint(json.dumps({'protocol': 2, 'ready': False}), flush=True)\n"
                    "import time\ntime.sleep(30)\n")
    with pytest.raises(signing.SchemeError, match="did not report ready") as raised:
        sign()
    assert raised.value.code == "unavailable"


def test_a_slow_request_is_refused_and_the_provider_is_started_again(resident):
    resident("    if body.get('slow'):\n        time.sleep(30)\n", request_timeout_s=0.5)
    before = pid_of(sign())
    started = time.monotonic()
    with pytest.raises(signing.SchemeError, match="timed out") as raised:
        sign({"slow": True})
    assert raised.value.code == "unavailable"
    assert time.monotonic() - started < 5
    with pytest.raises(signing.SchemeError, match="restarting"):
        sign()
    time.sleep(1.1)
    after = pid_of(sign())
    assert after != before
    with pytest.raises(ProcessLookupError):
        os.kill(before, 0)


def test_a_provider_that_exits_between_requests_is_started_again(resident):
    resident("    if body.get('last'):\n"
             "        sys.stdout.write(json.dumps({'protocol': 2, 'id': request['id'], 'signature': 'final'}) + '\\n')\n"
             "        sys.stdout.flush()\n        sys.exit(0)\n")
    first = pid_of(sign())
    assert sign({"last": True}) == "final"
    time.sleep(0.2)
    assert pid_of(sign()) != first


def test_a_reply_to_another_request_is_refused(resident):
    resident(source="import json, sys\nprint(json.dumps({'protocol': 2, 'ready': True}), flush=True)\n"
                    "for line in sys.stdin:\n"
                    "    request = json.loads(line)\n"
                    "    sys.stdout.write(json.dumps({'protocol': 2, 'id': request['id'] + 1, 'signature': 'x'}) + '\\n')\n"
                    "    sys.stdout.flush()\n")
    with pytest.raises(signing.SchemeError, match="another request") as raised:
        sign()
    assert raised.value.code == "unavailable"


@pytest.mark.parametrize("reply", [
    "{'protocol': 2, 'signature': 'x'}",
    "{'protocol': 1, 'id': request['id'], 'signature': 'x'}",
    "{'protocol': 2, 'id': request['id'], 'signature': ''}",
    "{'protocol': 2, 'id': request['id'], 'signature': 'x', 'secret': request['secret']}",
    "{'protocol': 2, 'id': request['id'], 'refused': 'no', 'code': 'other'}",
    "[request['id']]",
])
def test_invalid_resident_replies_are_unavailable(resident, reply):
    resident(source="import json, sys\nprint(json.dumps({'protocol': 2, 'ready': True}), flush=True)\n"
                    "for line in sys.stdin:\n"
                    "    request = json.loads(line)\n"
                    f"    sys.stdout.write(json.dumps({reply}) + '\\n')\n"
                    "    sys.stdout.flush()\n")
    with pytest.raises(signing.SchemeError) as raised:
        sign()
    assert raised.value.code == "unavailable"


def test_a_refusal_keeps_its_code_and_the_running_provider(resident):
    resident("    if body.get('amount', 0) > 10:\n"
             "        sys.stdout.write(json.dumps({'protocol': 2, 'id': request['id'],\n"
             "                                     'refused': 'amount exceeds the limit', 'code': 'off-policy'}) + '\\n')\n"
             "        sys.stdout.flush()\n        continue\n")
    before = pid_of(sign())
    with pytest.raises(signing.SchemeError, match="exceeds the limit") as raised:
        sign({"amount": 11})
    assert raised.value.code == "off-policy"
    assert pid_of(sign()) == before


def test_schemes_with_the_same_settings_share_one_process(resident):
    resident(schemes=("example-one", "example-two"))
    one, two = sign(scheme="example-one"), sign(scheme="example-two")
    assert pid_of(one) == pid_of(two)
    assert one.endswith(":example-one") and two.endswith(":example-two")


def test_workers_serve_requests_side_by_side(resident):
    resident("    time.sleep(0.4)\n", workers=2)
    providers.start()
    deadline = time.monotonic() + 10
    while providers.status()["example-signing"]["running"] < 2 and time.monotonic() < deadline:
        time.sleep(0.05)
    found = []
    threads = [threading.Thread(target=lambda: found.append(sign())) for _ in range(2)]
    started = time.monotonic()
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert time.monotonic() - started < 0.75
    assert len({pid_of(signature) for signature in found}) == 2


def test_start_warms_the_provider_and_stop_ends_it(resident):
    resident()
    providers.start()
    deadline = time.monotonic() + 10
    while not providers.status()["example-signing"]["running"] and time.monotonic() < deadline:
        time.sleep(0.05)
    status = providers.status()["example-signing"]
    assert status["running"] == 1 and status["served"] == 0
    pid = status["pids"][0]
    providers.stop()
    time.sleep(0.1)
    with pytest.raises(ProcessLookupError):
        os.kill(pid, 0)


def test_a_pinned_provider_refuses_once_its_files_change(resident):
    path = resident()
    pin = providers.digest([str(path)])
    resident(files=[str(path)], sha256=pin)
    assert sign()
    providers.stop()
    path.write_text(path.read_text() + "\n")
    with pytest.raises(signing.SchemeError, match="changed since they were pinned"):
        sign()


def test_a_pinned_one_shot_provider_is_checked_on_every_call(tmp_path, site_config):
    path = tmp_path / "once.py"
    path.write_text("import json\nprint(json.dumps({'protocol': 1, 'signature': 'example'}))\n")
    site_config({"signing_providers": {"example-signing": {
        "command": [sys.executable, "-I", str(path)], "files": [str(path)],
        "sha256": providers.digest([str(path)])}}})
    assert sign() == "example"
    path.write_text(path.read_text() + "\n")
    with pytest.raises(signing.SchemeError, match="changed since they were pinned"):
        sign()


def test_the_digest_covers_every_file_including_bytecode(tmp_path):
    tree = tmp_path / "tree"
    (tree / "pkg" / "__pycache__").mkdir(parents=True)
    (tree / "pkg" / "mod.py").write_text("value = 1\n")
    first = providers.digest([str(tree)])
    (tree / "pkg" / "__pycache__" / "mod.cpython.pyc").write_bytes(b"\x00")
    second = providers.digest([str(tree)])
    assert second != first
    (tree / "pkg" / "__pycache__" / "mod.cpython.pyc").write_bytes(b"\x01")
    assert providers.digest([str(tree)]) not in (first, second)
    (tree / "pkg" / "loose.pyc").write_bytes(b"\x00")
    assert providers.digest([str(tree)]) not in (first, second)


def test_a_link_is_pinned_by_where_it_points_and_what_is_there(tmp_path):
    tree, outside = tmp_path / "tree", tmp_path / "outside"
    tree.mkdir()
    outside.mkdir()
    (outside / "one.py").write_text("value = 1\n")
    (outside / "two.py").write_text("value = 1\n")
    (tree / "link.py").symlink_to(outside / "one.py")
    first = providers.digest([str(tree)])
    (outside / "one.py").write_text("value = 2\n")
    second = providers.digest([str(tree)])
    assert second != first
    (tree / "link.py").unlink()
    (tree / "link.py").symlink_to(outside / "two.py")
    assert providers.digest([str(tree)]) not in (first, second)
    (tree / "dir").symlink_to(outside, target_is_directory=True)
    linked = providers.digest([str(tree)])
    (outside / "two.py").write_text("value = 3\n")
    assert providers.digest([str(tree)]) != linked


def test_a_link_back_into_the_tree_is_walked_once(tmp_path):
    tree = tmp_path / "tree"
    (tree / "pkg").mkdir(parents=True)
    (tree / "pkg" / "mod.py").write_text("value = 1\n")
    (tree / "pkg" / "loop").symlink_to(tree, target_is_directory=True)
    first = providers.digest([str(tree)])
    (tree / "pkg" / "loop").unlink()
    (tree / "pkg" / "loop").symlink_to(tree / "pkg", target_is_directory=True)
    assert providers.digest([str(tree)]) != first


def test_a_missing_link_target_or_a_special_file_cannot_be_pinned(tmp_path):
    tree = tmp_path / "tree"
    tree.mkdir()
    (tree / "gone").symlink_to(tmp_path / "nowhere")
    with pytest.raises(providers.ProviderError, match="missing"):
        providers.digest([str(tree)])
    (tree / "gone").unlink()
    os.mkfifo(tree / "pipe")
    with pytest.raises(providers.ProviderError, match="regular files"):
        providers.digest([str(tree)])


def provider_tree(tmp_path, conn, site_config):
    signer = tmp_path / "signer"
    signer.mkdir()
    store = type("Store", (), {"get": lambda self, name: "example-secret-value"})()

    def pin(files, entry):
        site_config({"signing_providers": {"example-signing": {
            "command": [sys.executable, "-I", "-B", str(entry)], "files": [str(f) for f in files],
            "sha256": providers.digest([str(f) for f in files])}}})

    def unpinned(entry):
        site_config({"signing_providers": {"example-signing": {
            "command": [sys.executable, "-I", "-B", str(entry)]}}})

    def sign_now():
        return broker.sign_only(conn, {"secret": "service-key", "profile": "submit", "payload": {}},
                                store=store, notify=False)

    unpinned(signer / "run.py")
    broker.register(conn, "service-key", backend="memory")
    broker.set_profile(conn, "service-key", "submit", {"scheme": "example-signing"})
    broker.grant(conn, "service-key", broker.SIGN_SCOPE, mutating=True, source="test")
    return signer, pin, unpinned, sign_now


def test_a_changed_link_target_cannot_sign(tmp_path, conn, site_config):
    signer, pin, _unpinned, sign_now = provider_tree(tmp_path, conn, site_config)
    outside = tmp_path / "outside.py"
    outside.write_text("import json\nprint(json.dumps({'protocol': 1, 'signature': 'original'}))\n")
    (signer / "run.py").symlink_to(outside)
    pin([signer], signer / "run.py")
    assert sign_now()["signature"] == "original"
    outside.write_text("import json\nprint(json.dumps({'protocol': 1, 'signature': 'tampered'}))\n")
    refused = sign_now()
    assert refused["code"] == "unavailable" and "changed since they were pinned" in refused["refused"]


def test_planted_bytecode_cannot_sign(tmp_path, conn, site_config):
    signer, pin, unpinned, sign_now = provider_tree(tmp_path, conn, site_config)
    (signer / "helper.py").write_text("def sign():\n    return 'original'\n")
    (signer / "run.py").write_text(
        "import json, sys\nsys.path.insert(0, " + repr(str(signer)) + ")\nimport helper\n"
        "print(json.dumps({'protocol': 1, 'signature': helper.sign()}))\n")
    pin([signer], signer / "run.py")
    assert sign_now()["signature"] == "original"
    planted = tmp_path / "planted" / "helper.py"
    planted.parent.mkdir()
    planted.write_text("def sign():\n    return 'tampered'\n")
    py_compile.compile(str(planted), cfile=importlib.util.cache_from_source(str(signer / "helper.py")),
                       invalidation_mode=py_compile.PycInvalidationMode.UNCHECKED_HASH)
    refused = sign_now()
    assert refused["code"] == "unavailable" and "changed since they were pinned" in refused["refused"]
    unpinned(signer / "run.py")
    assert sign_now()["signature"] == "tampered"


@pytest.mark.parametrize("settings", [
    {"resident": "yes"}, {"resident": True, "workers": 0}, {"resident": True, "workers": 17},
    {"resident": True, "request_timeout_s": 0}, {"resident": True, "request_timeout_s": 121},
    {"files": ["relative/path"], "sha256": "0" * 64}, {"files": ["/srv/repos/shop"]},
    {"files": ["/srv/repos/shop"], "sha256": "short"},
])
def test_invalid_resident_settings_are_unavailable(tmp_path, site_config, settings):
    path = tmp_path / "unused.py"
    path.write_text("")
    site_config({"signing_providers": {"example-signing": {
        "command": [sys.executable, "-I", str(path)], **settings}}})
    assert not signing.available("example-signing")
    with pytest.raises(signing.SchemeError):
        sign()


def test_the_broker_reports_resident_providers(resident):
    resident()
    sign()
    answer = broker.Server.__new__(broker.Server).handle({"op": "ops"})
    held = answer["providers"]["example-signing"]
    assert held["resident"] is True and held["running"] == 1 and held["served"] == 1
    assert held["p50_ms"] is not None


def test_a_profile_lookup_matches_reading_them_all(conn):
    broker.register(conn, "service-key", backend="memory")
    held = {f"job-{n}": {"scheme": "example-signing", "limit": n} for n in range(50)}
    held['odd "name".x'] = {"scheme": "example-signing"}
    conn.execute("UPDATE secret SET schemes = ? WHERE name = ?", (json.dumps(held), "service-key"))
    conn.commit()
    row = broker.entry(conn, "service-key")
    for name in ("job-0", "job-49", 'odd "name".x'):
        assert broker.profile_of(conn, "service-key", name, "SIGN") == broker.profiles_for(row, "SIGN")[name]
    assert broker.profile_of(conn, "service-key", "job-50", "SIGN") is None
    conn.execute("UPDATE secret SET schemes = ? WHERE name = ?",
                 (json.dumps({**held, "list": ["not", "a", "profile"]}), "service-key"))
    conn.commit()
    assert broker.profile_of(conn, "service-key", "list", "SIGN") is None
    assert broker.profile_of(conn, "other-key", "job-0", "SIGN") is None
    conn.execute("UPDATE secret SET schemes = ? WHERE name = ?", ("{not json", "service-key"))
    conn.commit()
    assert broker.profile_of(conn, "service-key", "job-0", "SIGN") is None
