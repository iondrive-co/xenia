from __future__ import annotations

import json
import os
import sys
import time
from datetime import timedelta
from pathlib import Path
from types import SimpleNamespace

import pytest

from xenia import broker, providers, signing


@pytest.fixture
def provider(tmp_path, site_config):
    def install(source, **settings):
        path = tmp_path / "provider.py"
        path.write_text(source)
        command = [sys.executable, "-I", str(path)]
        site_config({"signing_providers": {"example-signing": {
            "command": command, "timeout_s": 2, **settings}}})
        return path
    return install


def context(**overrides):
    values = {"secret": "example-secret-value", "method": "POST",
              "url": "https://api.example.test/submit", "headers": {},
              "body": '{"amount":7}', "config": {}, "nonce": 12,
              "now": 1_600_000_000.0, "extras": {"key_id": "example-key"}}
    values.update(overrides)
    return signing.Context(**values)


def response(reply):
    return "import json\nprint(json.dumps(" + repr(reply) + "))\n"


def test_a_provider_receives_the_approved_context_and_returns_a_signature(provider):
    provider("import json, sys\n"
             "request = json.load(sys.stdin)\n"
             "assert request['protocol'] == 1\n"
             "assert request['secret'] == 'example-secret-value'\n"
             "assert request['method'] == 'POST'\n"
             "assert request['url'] == 'https://api.example.test/submit'\n"
             "assert request['body'] == '{\"amount\":7}'\n"
             "assert request['config']['limits'] == {'amount': 10}\n"
             "assert request['nonce'] == 12\n"
             "assert request['now'] == 1600000000\n"
             "assert request['extras'] == {'key_id': 'example-key'}\n"
             "assert request['headers'] == {'Content-Type': 'application/json'}\n"
             "print(json.dumps({'protocol': 1, 'signature': 'example-signature',\n"
             "                  'headers': {'X-Request-Nonce': str(request['nonce'])}}))\n")
    profile = {"scheme": "example-signing", "limits": {"amount": 10}}
    ctx = context(headers={"Content-Type": "application/json"})

    assert signing.sign(profile, ctx) == "example-signature"
    assert ctx.headers == {"Content-Type": "application/json", "X-Request-Nonce": "12"}
    assert "example-signing" in signing.schemes()
    assert signing.available("example-signing")


@pytest.mark.parametrize("code", ["off-policy", "unavailable"])
def test_provider_refusals_preserve_their_reason_and_code(provider, code):
    provider(response({"protocol": 1, "refused": "amount exceeds the configured limit", "code": code}))
    with pytest.raises(signing.SchemeError, match="configured limit") as raised:
        signing.sign({"scheme": "example-signing"}, context())
    assert raised.value.code == code


@pytest.mark.parametrize("reply", [
    [], {}, {"protocol": 2, "signature": "example"},
    {"protocol": True, "signature": "example"},
    {"protocol": 1, "signature": ""}, {"protocol": 1, "signature": 7},
    {"protocol": 1, "signature": "example", "headers": []},
    {"protocol": 1, "signature": "example", "headers": {"X-Example": 7}},
    {"protocol": 1, "signature": "example", "headers": {"X-Example\n": "value"}},
    {"protocol": 1, "signature": "example", "headers": {"X-Example": "one\r\ntwo"}},
    {"protocol": 1, "signature": "example", "debug": "example-secret-value"},
    {"protocol": 1, "refused": "denied", "signature": "example"},
    {"protocol": 1, "refused": "denied", "code": "unknown"},
    {"protocol": 1, "refused": ""},
])
def test_invalid_provider_responses_are_unavailable(provider, reply):
    provider(response(reply))
    with pytest.raises(signing.SchemeError) as raised:
        signing.sign({"scheme": "example-signing"}, context())
    assert raised.value.code == "unavailable"
    assert "example-secret-value" not in str(raised.value)


@pytest.mark.parametrize("source", [
    "print('example-secret-value')\n",
    "import sys\nsys.stdout.buffer.write(b'\\xff')\n",
    "import sys\nsys.stderr.write('example-secret-value')\nsys.exit(3)\n",
    "print('[' * 2000)\n",
])
def test_provider_diagnostics_are_not_exposed(provider, source):
    provider(source)
    with pytest.raises(signing.SchemeError) as raised:
        signing.sign({"scheme": "example-signing"}, context())
    assert raised.value.code == "unavailable"
    assert "example-secret-value" not in str(raised.value)


def test_provider_output_is_bounded_while_it_is_being_read(provider, monkeypatch):
    monkeypatch.setattr(providers, "OUTPUT_LIMIT", 1024)
    provider("import os\nwhile True:\n    os.write(1, b'x' * 4096)\n")
    with pytest.raises(signing.SchemeError, match="too large"):
        signing.sign({"scheme": "example-signing"}, context())


def test_provider_timeouts_stop_the_process_and_its_children(provider, tmp_path):
    parent_pid, child_pid = tmp_path / "parent.pid", tmp_path / "child.pid"
    provider("import os, pathlib, subprocess, sys, time\n"
             f"pathlib.Path({str(parent_pid)!r}).write_text(str(os.getpid()))\n"
             "child = subprocess.Popen([sys.executable, '-I', '-c', 'import time; time.sleep(30)'])\n"
             f"pathlib.Path({str(child_pid)!r}).write_text(str(child.pid))\n"
             "time.sleep(30)\n", timeout_s=0.5)
    with pytest.raises(signing.SchemeError, match="timed out"):
        signing.sign({"scheme": "example-signing"}, context())
    parent, child = int(parent_pid.read_text()), int(child_pid.read_text())
    with pytest.raises(ProcessLookupError):
        os.kill(parent, 0)
    for _ in range(100):
        try:
            os.kill(child, 0)
        except ProcessLookupError:
            break
        status = Path(f"/proc/{child}/status")
        if status.exists() and "State:\tZ" in status.read_text():
            break
        time.sleep(0.01)
    else:
        pytest.fail("provider child is still running")


def test_input_and_output_are_drained_without_a_pipe_deadlock(provider):
    provider("import json, sys\n"
             "sys.stdout.write(' ' * 200000)\n"
             "sys.stdout.flush()\n"
             "request = json.load(sys.stdin)\n"
             "assert len(request['body']) == 200000\n"
             "print(json.dumps({'protocol': 1, 'signature': 'example-signature'}))\n")
    assert signing.sign({"scheme": "example-signing"}, context(body="x" * 200000)) == "example-signature"


@pytest.mark.parametrize("settings", [
    {"command": "example-signer"}, {"command": []}, {"command": ["relative-signer"]},
    {"command": ["/srv/repos/shop/missing-signer"]}, {"command": [sys.executable, None]},
    {"command": [sys.executable, "\x00"]}, {"timeout_s": 0}, {"timeout_s": True},
    {"timeout_s": 121}, {"timeout_s": float("inf")}, {"timeout_s": float("nan")},
])
def test_invalid_provider_settings_are_unavailable(provider, settings):
    provider(response({"protocol": 1, "signature": "example"}), **settings)
    assert "example-signing" in signing.schemes()
    assert not signing.available("example-signing")
    with pytest.raises(signing.SchemeError) as raised:
        signing.sign({"scheme": "example-signing"}, context())
    assert raised.value.code == "unavailable"


@pytest.mark.parametrize("held", [[], None, "example", {"bad name": {}}, {"": {}}])
def test_invalid_registration_does_not_break_builtin_schemes(site_config, held):
    site_config({"signing_providers": held})
    assert signing.schemes() == set(signing.SCHEMES)
    assert signing.available("hmac")
    assert signing.sign({"scheme": "hmac", "template": "{path}"}, context())


def test_provider_registration_cannot_replace_a_builtin(site_config):
    site_config({"signing_providers": {"hmac": {"command": ["/srv/repos/shop/missing-signer"]}}})
    assert signing.available("hmac")
    assert signing.sign({"scheme": "hmac", "template": "{path}"}, context())


def test_profile_settings_cannot_register_an_executable(tmp_path):
    marker = tmp_path / "called"
    with pytest.raises(signing.SchemeError, match="no signing scheme"):
        signing.sign({"scheme": "example-signing", "command": [str(marker)]}, context())
    assert not marker.exists()


def test_an_unavailable_provider_can_be_stored_and_reports_in_capabilities(conn, site_config):
    site_config({"signing_providers": {"example-signing": {
        "command": ["/srv/repos/shop/missing-signer"]}}})
    broker.register(conn, "service-key", backend="memory")
    held = broker.set_profile(conn, "service-key", "submit", {"scheme": "example-signing"})
    assert held["submit"]["scheme"] == "example-signing"
    answer = broker.Server.__new__(broker.Server).handle({"op": "ops"})
    assert answer["schemes"]["example-signing"] is False


def test_provider_signing_uses_profile_approvals_and_records_refusals(provider, conn, tmp_path):
    marker = tmp_path / "called"
    provider("import json, pathlib, sys\nrequest = json.load(sys.stdin)\n"
             f"pathlib.Path({str(marker)!r}).write_text('called')\n"
             "if json.loads(request['body']) != {'amount': 7}:\n"
             "    print(json.dumps({'protocol': 1, 'refused': 'amount is not approved'}))\n"
             "else:\n"
             "    print(json.dumps({'protocol': 1, 'signature': 'example-signature'}))\n")
    broker.register(conn, "service-key", backend="memory")
    for name in ("submit", "other"):
        broker.set_profile(conn, "service-key", name, {"scheme": "example-signing"})
    broker.standing(conn, "service-key", broker.SIGN_SCOPE,
                    until=broker.utcnow() + timedelta(days=5),
                    profiles=["submit"], reason="scheduled requests")
    store = type("Store", (), {"get": lambda self, name: "example-secret-value"})()
    request = {"secret": "service-key", "profile": "other", "payload": {"amount": 7}}
    denied = broker.sign_only(conn, request, store=store, notify=False)
    assert denied["code"] == "unapproved" and not marker.exists()
    allowed = broker.sign_only(conn, {**request, "profile": "submit"}, store=store, notify=False)
    assert allowed["signature"] == "example-signature"
    refused = broker.sign_only(conn, {**request, "profile": "submit", "payload": {"amount": 11}},
                               store=store, notify=False)
    assert refused["code"] == "off-policy"
    decisions = [row[0] for row in conn.execute("SELECT decision FROM secret_use ORDER BY id")]
    assert decisions == ["refused", "allowed", "refused"]


def test_provider_refusals_are_scrubbed_before_returning_or_recording(provider, conn):
    provider("import json, sys\nrequest = json.load(sys.stdin)\n"
             "print(json.dumps({'protocol': 1, 'refused': 'rejected ' + request['secret']}))\n")
    broker.register(conn, "service-key", backend="memory")
    broker.set_profile(conn, "service-key", "submit", {"scheme": "example-signing"})
    broker.grant(conn, "service-key", broker.SIGN_SCOPE, mutating=True, source="test")
    store = type("Store", (), {"get": lambda self, name: "example-secret-value"})()
    answer = broker.sign_only(conn, {"secret": "service-key", "profile": "submit", "payload": {}},
                              store=store, notify=False)
    assert answer["code"] == "off-policy"
    assert "example-secret-value" not in json.dumps(answer)
    assert "example-secret-value" not in conn.execute("SELECT reason FROM secret_use").fetchone()[0]


def test_a_provider_signs_the_http_request_and_supplies_public_headers(provider, conn, monkeypatch):
    provider("import json, sys\nrequest = json.load(sys.stdin)\n"
             "assert request['method'] == 'POST'\n"
             "assert request['url'] == 'https://api.example.test/submit'\n"
             "assert json.loads(request['body']) == {'amount': 7}\n"
             "assert request['config']['_method'] == 'POST'\n"
             "assert 'X-Signature' not in request['headers']\n"
             "print(json.dumps({'protocol': 1, 'signature': 'example-signature',\n"
             "                  'headers': {'X-Provider-Nonce': str(request['nonce'])}}))\n")
    monkeypatch.setattr(broker, "_resolved_addresses", lambda host: ["203.0.113.19"])
    broker.register(conn, "service-key", backend="memory", hosts=["api.example.test"], methods=["POST"])
    broker.set_profile(conn, "service-key", "submit", {"scheme": "example-signing"})
    broker.grant(conn, "service-key", "api.example.test", mutating=True, source="test")
    sent = []

    def open_request(request, timeout):
        sent.append(request)
        return SimpleNamespace(status=200, reason="OK", headers={}, read=lambda size: b"{}")

    answer = broker.fetch(conn, {"secret": "service-key", "method": "POST",
                                "url": "https://api.example.test/submit",
                                "headers": {"X-Signature": "{{sign:submit}}"}, "body": {"amount": 7}},
                          store=SimpleNamespace(get=lambda name: "example-secret-value"),
                          opener=SimpleNamespace(open=open_request), notify=False)
    assert answer["status"] == 200 and answer["signed"] == ["submit"]
    headers = {key.lower(): value for key, value in sent[0].header_items()}
    assert headers["x-signature"] == "example-signature"
    assert headers["x-provider-nonce"].isdigit()
    assert "example-secret-value" not in json.dumps(headers)


def test_an_executable_that_cannot_start_refuses_cleanly(provider, tmp_path):
    executable = tmp_path / "invalid-executable"
    executable.write_text("invalid executable\n")
    executable.chmod(0o700)
    provider(response({"protocol": 1, "signature": "example"}), command=[str(executable)])
    assert signing.available("example-signing")
    with pytest.raises(signing.SchemeError, match="could not be started") as raised:
        signing.sign({"scheme": "example-signing"}, context())
    assert raised.value.code == "unavailable"


def test_the_scheme_listing_includes_configured_providers(provider, capsys):
    from xenia import secrets

    provider(response({"protocol": 1, "signature": "example"}))
    assert secrets._secret(None, broker, ["schemes"]) == 0
    assert "example-signing" in capsys.readouterr().out
