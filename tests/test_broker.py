from __future__ import annotations

import hashlib
import json
import socket
import sys
import time
import threading
from datetime import datetime, timedelta
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from xenia import broker, config, db, readonly, vault

VALUE = "glpat-" + "not-a-real-token-9876"
HOST = "gitlab.example.com"


class Store:
    kind = "memory"

    def __init__(self, values=None):
        self.values = dict({"gitlab-pat": VALUE} if values is None else values)

    def get(self, name):
        return self.values.get(name)


class Reply:
    def __init__(self, status=200, body=b"{}", headers=None, reason="OK"):
        self.status = status
        self.reason = reason
        self._body = body
        self.headers = _Headers(headers or {"Content-Type": "application/json"})

    def read(self, size=None):
        return self._body[:size] if size else self._body


class _Headers:
    def __init__(self, mapping):
        self._mapping = mapping

    def items(self):
        return self._mapping.items()


class Opener:
    """Stands in for urllib, and remembers exactly what was sent."""

    def __init__(self, *replies):
        self.replies = list(replies) or [Reply()]
        self.sent: list = []

    def open(self, request, timeout=None):
        self.sent.append(request)
        return self.replies[min(len(self.sent) - 1, len(self.replies) - 1)]


@pytest.fixture(autouse=True)
def _dns(monkeypatch):
    """Every test host resolves somewhere ordinary unless it says otherwise.

    The broker resolves a hostname before releasing a credential, so a test
    host that resolves nowhere is refused before it reaches anything the test
    is about.
    """
    monkeypatch.setattr(broker, "_resolved_addresses",
                        lambda host: ["203.0.113.7"])
    # The prompt cool-off is process state, so one test's refusal would
    # otherwise silence the next test's question.
    broker._asked.clear()


@pytest.fixture
def wired(conn):
    broker.register(conn, "gitlab-pat", backend="memory", hosts=[HOST],
                    methods=["GET", "POST"])
    return conn


def allow(conn, *, mutating=False, host=HOST):
    return broker.grant(conn, "gitlab-pat", host, mutating=mutating,
                        source="test")


def call(conn, opener=None, store=None, **request):
    request.setdefault("secret", "gitlab-pat")
    request.setdefault("url", f"https://{HOST}/api/v4/projects")
    request.setdefault("headers", {"PRIVATE-TOKEN": broker.PLACEHOLDER})
    return broker.fetch(conn, request, store=store or Store(),
                        opener=opener or Opener(), notify=False)


# -- policy -----------------------------------------------------------------

def test_an_unregistered_name_is_refused_and_says_what_exists(wired):
    answer = call(wired, secret="aws-key")

    assert "no credential called 'aws-key'" in answer["refused"]
    assert "gitlab-pat" in answer["refused"]


def test_an_unapproved_host_is_refused_and_says_which(wired):
    allow(wired)
    answer = call(wired, url="https://elsewhere.example/api")

    assert answer["code"] == "unapproved"
    assert "elsewhere.example" in answer["refused"]


def test_an_unapproved_method_is_refused(wired):
    allow(wired, mutating=True)
    answer = call(wired, method="DELETE")

    assert answer["code"] == "unapproved"
    assert "DELETE" in answer["refused"]


def test_a_path_outside_the_registered_prefix_is_refused(conn):
    broker.register(conn, "gitlab-pat", backend="memory", hosts=[HOST],
                    methods=["GET"], paths=["/api/v4/*"])
    allow(conn)
    answer = call(conn, url=f"https://{HOST}/admin/users")

    assert "outside it" in answer["refused"]


def test_plain_http_is_refused_except_on_this_machine(wired):
    allow(wired, host="localhost")
    assert "clear" in call(wired, url=f"http://{HOST}/api")["refused"]

    broker.register(wired, "local", backend="memory", hosts=["localhost"])
    broker.grant(wired, "local", "localhost", source="test")
    answer = call(wired, secret="local", url="http://localhost:9000/x",
                  store=Store({"local": VALUE}))
    assert answer.get("status") == 200


def test_link_local_is_refused_because_that_is_where_metadata_lives(conn):
    broker.register(conn, "cloud", backend="memory", hosts=["*"])
    broker.grant(conn, "cloud", "169.254.169.254", source="test")
    answer = call(conn, secret="cloud",
                  url="https://169.254.169.254/latest/meta-data/",
                  store=Store({"cloud": VALUE}))

    assert "link-local" in answer["refused"]


# -- grants -----------------------------------------------------------------

def test_without_an_approval_the_refusal_says_what_to_run(wired):
    answer = call(wired)

    assert "not approved" in answer["refused"]
    assert "xenia grant gitlab-pat --host gitlab.example.com" in answer["refused"]


def test_a_read_approval_does_not_cover_a_write(wired):
    allow(wired, mutating=False)

    assert call(wired).get("status") == 200
    assert "not approved" in call(wired, method="POST")["refused"]


def test_a_write_approval_covers_reading_too(wired):
    allow(wired, mutating=True)

    assert call(wired).get("status") == 200
    assert call(wired, method="POST").get("status") == 200


def test_an_expired_window_refuses(wired):
    broker.grant(wired, "gitlab-pat", HOST, seconds=-1, source="test")

    assert "not approved" in call(wired)["refused"]


def test_use_slides_the_window_but_never_past_the_ceiling(wired, monkeypatch,
                                                          clock):
    monkeypatch.setattr(config, "GRANT_READ_SECONDS", 60)
    monkeypatch.setattr(config, "GRANT_CEILING_SECONDS", 90)
    given = allow(wired)

    clock()
    call(wired)
    after = wired.execute("SELECT * FROM secret_grant WHERE id = ?",
                          (given["id"],)).fetchone()

    assert after["uses"] == 1
    assert after["expires_at"] > given["expires_at"]
    assert after["expires_at"] <= given["ceiling_at"]
    assert after["ceiling_at"] == given["ceiling_at"]


def test_revoking_ends_it(wired):
    allow(wired)
    assert broker.revoke(wired, "gitlab-pat") == 1

    assert "not approved" in call(wired)["refused"]


# -- placement --------------------------------------------------------------

def test_the_placeholder_goes_wherever_the_agent_put_it(wired):
    allow(wired, mutating=True)
    opener = Opener()
    answer = call(wired, opener=opener,
                  headers={"Authorization": f"Bearer {broker.PLACEHOLDER}"})

    assert opener.sent[0].get_header("Authorization") == f"Bearer {VALUE}"
    assert answer["placed"] == ["header:Authorization"]


def test_a_query_placeholder_is_encoded_and_earns_a_warning(wired):
    allow(wired)
    opener = Opener()
    answer = call(wired, opener=opener, headers={},
                  url=f"https://{HOST}/api?private_token={broker.PLACEHOLDER}")

    assert VALUE in opener.sent[0].full_url
    assert "query" in answer["placed"]
    assert any("access log" in warning for warning in answer["warnings"])


def test_userinfo_becomes_basic_auth_and_leaves_the_url(wired):
    allow(wired)
    opener = Opener()
    answer = call(wired, opener=opener, headers={},
                  url=f"https://user:{broker.PLACEHOLDER}@{HOST}/api")

    sent = opener.sent[0]
    assert "@" not in sent.full_url
    assert sent.get_header("Authorization").startswith("Basic ")
    assert answer["placed"] == ["basic"]


def test_a_json_body_carries_the_credential_and_sets_its_type(wired):
    allow(wired, mutating=True)
    opener = Opener()
    call(wired, opener=opener, method="POST", headers={},
         body={"token": broker.PLACEHOLDER, "ref": "main"})

    sent = opener.sent[0]
    assert json.loads(sent.data)["token"] == VALUE
    assert sent.get_header("Content-type") == "application/json"


def test_a_request_with_no_placeholder_is_refused_rather_than_guessed(wired):
    allow(wired)
    answer = call(wired, headers={"Accept": "application/json"})

    assert "nothing in that request says where" in answer["refused"]


# -- what comes back --------------------------------------------------------

def test_the_url_that_comes_back_is_the_template_not_the_expansion(wired):
    allow(wired)
    template = f"https://{HOST}/api?private_token={broker.PLACEHOLDER}"
    answer = call(wired, headers={}, url=template)

    assert answer["url"] == template
    assert VALUE not in json.dumps(answer)


def test_a_credential_echoed_in_the_body_is_redacted_and_called_out(wired):
    allow(wired)
    body = json.dumps({"error": f"bad token {VALUE}"}).encode()
    answer = call(wired, opener=Opener(Reply(401, body, reason="Unauthorized")))

    assert VALUE not in answer["body"]
    assert "[REDACTED:gitlab-pat]" in answer["body"]
    assert any("rotate" in warning for warning in answer["warnings"])
    assert wired.execute(
        "SELECT echoed FROM secret_use ORDER BY id DESC").fetchone()[0] == 1


def test_the_percent_encoded_form_is_scrubbed_too(wired):
    from urllib.parse import quote

    allow(wired)
    body = f"no such token: {quote(VALUE, safe='')}".encode()
    answer = call(wired, opener=Opener(Reply(404, body)))

    assert quote(VALUE, safe="") not in answer["body"]


def test_the_basic_auth_form_is_scrubbed_too(wired):
    import base64

    allow(wired)
    encoded = base64.b64encode(VALUE.encode()).decode()
    answer = call(wired, opener=Opener(Reply(403, f"sent {encoded}".encode())))

    assert encoded not in answer["body"]


def test_cookies_are_dropped(wired):
    allow(wired)
    answer = call(wired, opener=Opener(Reply(
        200, b"{}", {"Set-Cookie": "session=abc", "ETag": "x"})))

    assert "Set-Cookie" not in answer["headers"]
    assert answer["headers"]["ETag"] == "x"
    assert any("cookie" in warning for warning in answer["warnings"])


def test_a_same_origin_redirect_is_followed(wired):
    allow(wired)
    opener = Opener(
        Reply(302, b"", {"Location": f"https://{HOST}/api/v4/projects/2"}),
        Reply(200, b'{"id":2}'))
    answer = call(wired, opener=opener)

    assert answer["status"] == 200
    assert len(opener.sent) == 2
    assert answer["redirects"] == [f"https://{HOST}/api/v4/projects/2"]


def test_a_cross_origin_redirect_is_not_followed_with_the_credential(wired):
    allow(wired)
    opener = Opener(Reply(302, b"", {"Location": "https://elsewhere.example/x"}))
    answer = call(wired, opener=opener)

    assert len(opener.sent) == 1
    assert answer["status"] == 302
    assert any("not carried across origins" in w for w in answer["warnings"])


def test_a_long_body_is_cut_rather_than_returned_whole(wired, monkeypatch):
    monkeypatch.setattr(config, "FETCH_BODY_CHARS", 50)
    allow(wired)
    answer = call(wired, opener=Opener(Reply(200, b"x" * 500)))

    assert len(answer["body"]) < 220
    assert "chars" in answer["body"]
    assert "does not fail loudly" in answer["body"], (
        "a cut body has to say how to get the whole one")


def test_a_transport_failure_comes_back_as_an_error_not_a_crash(wired):
    class Broken:
        def open(self, request, timeout=None):
            raise OSError(f"connection refused while sending {VALUE}")

    allow(wired)
    answer = call(wired, opener=Broken())

    assert "OSError" in answer["error"]
    assert VALUE not in answer["error"]


def test_a_store_with_no_value_under_that_name_says_so(wired):
    allow(wired)
    answer = call(wired, store=Store({}))

    assert "has no value under that name" in answer["refused"]


# -- the record -------------------------------------------------------------

def test_every_call_lands_in_the_ledger_with_the_template(wired):
    allow(wired)
    template = f"https://{HOST}/api?private_token={broker.PLACEHOLDER}"
    call(wired, headers={}, url=template)

    row = wired.execute("SELECT * FROM secret_use").fetchone()
    assert row["decision"] == "allowed"
    assert row["url"] == template
    assert row["host"] == HOST
    assert row["placed"] == "query"
    assert row["status"] == 200
    assert VALUE not in " ".join(str(value) for value in tuple(row))


def test_a_refusal_is_recorded_with_its_reason(wired):
    call(wired)

    row = wired.execute("SELECT * FROM secret_use").fetchone()
    assert row["decision"] == "refused"
    assert "not approved" in row["reason"]
    assert row["status"] is None


def test_the_credentials_view_reports_policy_and_approval(wired):
    allow(wired)
    call(wired)

    row = readonly.credentials(wired)[0]
    assert row["name"] == "gitlab-pat"
    assert row["hosts"] == [HOST]
    assert row["usable_now"] is True
    assert row["uses"] == 1
    assert row["approved_for"][0]["host"] == HOST


def test_a_credential_is_stored_with_nothing_said_about_where_it_may_go(conn):
    """Nobody is asked to predict a hostname while typing in a token.

    The scope arrives later, from someone answering a question about a real
    request.
    """
    broker.register(conn, "fresh", backend="memory")

    row = broker.registry(conn)[0]
    assert row["hosts"] == []
    assert row["usable_now"] is False if "usable_now" in row else True


def test_forgetting_takes_the_grants_with_it(wired):
    allow(wired)
    assert broker.forget(wired, "gitlab-pat") is True

    assert broker.grants(wired) == []
    assert readonly.credentials(wired) == []


# -- the socket -------------------------------------------------------------

def test_the_socket_answers_a_ping_and_refuses_an_unknown_op(tmp_path):
    server = broker.Server(path=str(tmp_path / "b.sock"))
    server.start()
    try:
        assert broker.request({"op": "ping"}, path=server.path)["ok"] is True
        unknown = broker.request({"op": "mint"}, path=server.path)
        assert "unknown op" in unknown["refused"]
        assert unknown["code"] == "malformed"
        assert unknown["protocol"] == config.PROTOCOL_VERSION
    finally:
        server.stop()


def test_the_socket_is_private_to_its_owner(tmp_path):
    import os
    import stat

    server = broker.Server(path=str(tmp_path / "b.sock"))
    server.start()
    try:
        mode = stat.S_IMODE(os.stat(server.path).st_mode)
        assert mode == 0o600
    finally:
        server.stop()


def test_a_second_broker_refuses_to_take_a_live_socket(tmp_path):
    """The stale-socket wedge, measured on ptah 2026-09-14.

    A second instance used to unlink the first's socket, bind a NEW inode at
    the same path and — when it then went away — leave a file every client got
    ECONNREFUSED from, while the first listened on an inode with no name. The
    box looked healthy (`ss -lx` still showed a LISTEN row at the path) and
    every credentialed call failed `broker-unreachable`.
    """
    first = broker.Server(path=str(tmp_path / "b.sock"))
    first.start()
    try:
        second = broker.Server(path=first.path)
        with pytest.raises(broker.BrokerAlreadyListening):
            second.start()
        # The running broker is untouched: that is the point of refusing.
        assert broker.request({"op": "ping"}, path=first.path)["ok"] is True
    finally:
        first.stop()


def test_a_broker_replaces_a_socket_nothing_is_answering_on(tmp_path):
    """The other half: a file left by a crash must not block a restart."""
    import os

    path = str(tmp_path / "b.sock")
    dead = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    dead.bind(path)          # bound, never listened, then closed: a stale file
    dead.close()
    assert os.path.exists(path)
    assert broker.socket_is_live(path) is False

    server = broker.Server(path=path)
    server.start()
    try:
        assert broker.request({"op": "ping"}, path=server.path)["ok"] is True
    finally:
        server.stop()
    assert not os.path.exists(path)


def test_stopping_does_not_unlink_a_socket_it_no_longer_owns(tmp_path):
    """stop() is the same hazard as start(): it removed whatever was at the
    path, not the socket it bound."""
    import os

    path = str(tmp_path / "b.sock")
    mine = broker.Server(path=path)
    mine.start()
    os.unlink(path)
    other = broker.Server(path=path)
    other.start()                      # a legitimate restart after the unlink
    try:
        mine.stop()                    # must NOT take the new one's socket
        assert broker.request({"op": "ping"}, path=path)["ok"] is True
    finally:
        other.stop()


def test_a_fetch_over_the_socket_reaches_the_broker(tmp_path, monkeypatch):
    database = tmp_path / "audit.db"
    conn = db.connect(database)
    broker.register(conn, "gitlab-pat", backend="memory", hosts=[HOST])
    broker.grant(conn, "gitlab-pat", HOST, source="test")
    conn.close()

    monkeypatch.setattr(vault, "backend", lambda kind=None: Store())
    monkeypatch.setattr(broker, "_opener", lambda pinned="": Opener())

    server = broker.Server(path=str(tmp_path / "b.sock"), db_path=database)
    server.start()
    try:
        answer = broker.request({
            "op": "fetch", "secret": "gitlab-pat",
            "url": f"https://{HOST}/api/v4/projects",
            "headers": {"PRIVATE-TOKEN": broker.PLACEHOLDER},
        }, path=server.path)
    finally:
        server.stop()

    assert answer["status"] == 200
    conn = db.connect(database)
    assert conn.execute("SELECT client FROM secret_use").fetchone()[0]
    conn.close()


def test_no_service_is_a_clear_message_rather_than_a_stack_trace(tmp_path):
    with pytest.raises(broker.BrokerError, match="not listening"):
        broker.request({"op": "ping"}, path=str(tmp_path / "absent.sock"))


def test_an_echoed_basic_auth_header_is_scrubbed(wired):
    """base64 of the credential is not base64 of `user:credential`.

    A server quoting the Authorization header back would otherwise return the
    whole pair in a form no scrub of the value alone can find.
    """
    import base64

    allow(wired)
    encoded = base64.b64encode(f"user:{VALUE}".encode()).decode()
    answer = call(wired, headers={},
                  url=f"https://user:{broker.PLACEHOLDER}@{HOST}/api",
                  opener=Opener(Reply(401, f"rejected Basic {encoded}".encode())))

    assert encoded not in answer["body"]
    assert VALUE not in json.dumps(answer)
    assert any("rotate" in warning for warning in answer["warnings"])


# -- what the review of 2026-09-10 found ------------------------------------

def test_a_redirect_cannot_carry_the_credential_outside_the_path_policy(conn):
    """Same origin is not the same path.

    A credential approved for /api/v4/* was being carried to wherever that
    host redirected it, /admin included, because the policy was read once
    against the URL the agent wrote.
    """
    broker.register(conn, "gitlab-pat", backend="memory", hosts=[HOST],
                    methods=["GET"], paths=["/api/v4/*"])
    allow(conn)
    opener = Opener(Reply(302, b"", {"Location": f"https://{HOST}/admin"}),
                    Reply(200, b"secrets"))
    answer = call(conn, opener=opener, url=f"https://{HOST}/api/v4/user")

    assert len(opener.sent) == 1, "the credential must not reach /admin"
    assert answer["status"] == 302
    assert any("stopped at a redirect" in w and "outside it" in w
               for w in answer["warnings"])


def test_a_dot_segment_path_is_resolved_before_the_policy_reads_it(conn):
    broker.register(conn, "gitlab-pat", backend="memory", hosts=[HOST],
                    methods=["GET"], paths=["/allowed/*"])
    allow(conn)
    answer = call(conn, url=f"https://{HOST}/allowed/../admin")

    assert "outside it" in answer["refused"]


def test_the_path_that_was_checked_is_the_path_that_is_sent(conn):
    broker.register(conn, "gitlab-pat", backend="memory", hosts=[HOST],
                    methods=["GET"], paths=["/api/*"])
    allow(conn)
    opener = Opener()
    call(conn, opener=opener, url=f"https://{HOST}/api/v4/./projects")

    assert opener.sent[0].full_url == f"https://{HOST}/api/v4/projects"


def test_a_caller_supplied_host_header_is_refused(wired):
    allow(wired)
    answer = call(wired, headers={"Host": "internal.example",
                                  "PRIVATE-TOKEN": broker.PLACEHOLDER})

    assert "xenia sets host itself" in answer["refused"].lower()


def test_a_name_resolving_into_link_local_space_is_refused(wired, monkeypatch):
    """A name is not an address.

    Checking only literal IPs left the metadata range reachable by anything
    that resolves into it.
    """
    monkeypatch.setattr(broker, "_resolved_addresses",
                        lambda host: ["169.254.169.254"])
    allow(wired)
    answer = call(wired)

    assert "link-local" in answer["refused"]
    assert "169.254.169.254" in answer["refused"]


def test_a_name_that_resolves_nowhere_is_refused_rather_than_tried(wired,
                                                                   monkeypatch):
    def nowhere(host):
        raise broker.Refusal(f"{host} does not resolve: [Errno -5]")

    monkeypatch.setattr(broker, "_resolved_addresses", nowhere)
    allow(wired)

    assert "does not resolve" in call(wired)["refused"]


def test_a_json_escaped_credential_is_scrubbed(conn):
    """A credential with a quote in it comes back escaped, and was missed.

    The module already escapes on the way in; not doing so on the way out was
    an inconsistency as much as a hole.
    """
    awkward = 'tok"en\\with/quotes'
    broker.register(conn, "odd", backend="memory", hosts=[HOST])
    broker.grant(conn, "odd", HOST, source="test")
    body = json.dumps({"error": f"rejected {awkward}"}).encode()

    answer = call(conn, secret="odd", store=Store({"odd": awkward}),
                  opener=Opener(Reply(401, body)))

    assert awkward not in answer["body"]
    assert json.dumps(awkward)[1:-1] not in answer["body"]
    assert any("rotate" in warning for warning in answer["warnings"])


def test_a_credential_in_a_header_name_is_scrubbed_too(wired):
    allow(wired)
    answer = call(wired, opener=Opener(Reply(200, b"{}", {f"X-{VALUE}": "1"})))

    assert VALUE not in json.dumps(answer)


def test_a_credential_in_a_redirect_host_is_scrubbed_in_the_warning(wired):
    allow(wired)
    answer = call(wired, opener=Opener(Reply(
        302, b"", {"Location": f"https://{VALUE}.elsewhere.example/x"})))

    assert VALUE not in json.dumps(answer)


def test_a_short_grant_stays_short_after_it_is_used(wired, clock):
    """`--for 60s` became nearly four hours on the first call.

    The window belongs to the grant, not to the config: a grant deliberately
    made small must not be silently made large by using it.
    """
    given = broker.grant(wired, "gitlab-pat", HOST, seconds=60, source="test")

    clock()
    call(wired)
    after = wired.execute("SELECT * FROM secret_grant WHERE id = ?",
                          (given["id"],)).fetchone()

    assert after["window_s"] == 60
    slid = (datetime.fromisoformat(after["expires_at"])
            - datetime.fromisoformat(after["granted_at"])).total_seconds()
    assert slid <= 120, f"a 60s window slid to {slid}s"


def test_a_grant_from_before_the_window_was_stored_still_slides(wired, clock):
    # A write grant, because the read window equals the ceiling and a window
    # already pinned there has nowhere to slide to.
    given = broker.grant(wired, "gitlab-pat", HOST, mutating=True,
                         source="test")
    wired.execute("UPDATE secret_grant SET window_s = NULL WHERE id = ?",
                  (given["id"],))

    clock()
    call(wired)
    after = wired.execute("SELECT * FROM secret_grant WHERE id = ?",
                          (given["id"],)).fetchone()

    assert after["expires_at"] > given["expires_at"]


# -- the hermes brief: signing, several credentials, a contract -------------

def profile(conn, name, **settings):
    broker.set_profile(conn, name, "default", settings)


def test_a_signature_goes_where_the_credential_would_have(wired):
    profile(wired, "gitlab-pat", scheme="hmac", template="{ts}{method}{path}",
            digest="sha256", encoding="hex")
    allow(wired)
    opener = Opener()
    answer = call(wired, opener=opener, headers={"SIGN": "{{sign}}"})

    sent = opener.sent[0].get_header("Sign")
    assert sent and VALUE not in sent, "the credential itself must not go"
    assert len(sent) == 64
    assert answer["signed"] == ["default"]
    assert answer["placed"] == ["sign:default"]


def test_the_signature_covers_the_request_actually_sent(wired):
    profile(wired, "gitlab-pat", scheme="hmac", template="{path}",
            encoding="hex")
    allow(wired)
    one, two = Opener(), Opener()
    call(one_conn := wired, opener=one, headers={"SIGN": "{{sign}}"},
         url=f"https://{HOST}/api/v4/one")
    call(one_conn, opener=two, headers={"SIGN": "{{sign}}"},
         url=f"https://{HOST}/api/v4/two")

    assert one.sent[0].get_header("Sign") != two.sent[0].get_header("Sign")


def test_a_caller_cannot_choose_what_gets_signed(wired):
    """The template is config, not a request field.

    A caller who picks the string to sign has a signing oracle: arbitrary bytes
    signed with the key and reused as a different request.
    """
    allow(wired)
    answer = call(wired, headers={"SIGN": "{{sign:anything-i-like}}"})

    assert "no signing profile called 'anything-i-like'" in answer["refused"]
    assert answer["code"] == "off-policy"


def test_a_credential_with_no_profile_cannot_sign(wired):
    allow(wired)
    answer = call(wired, headers={"SIGN": "{{sign}}"})

    assert "no signing profile" in answer["refused"]


def test_an_unavailable_scheme_refuses_by_name(wired):
    if broker.signing.available("secp256k1-eip712"):
        pytest.skip("the optional curve dependency is installed here")
    profile(wired, "gitlab-pat", scheme="secp256k1-eip712")
    allow(wired)
    answer = call(wired, headers={"SIGN": "{{sign}}"})

    assert answer["code"] == "unavailable"
    assert "pip install" in answer["refused"]


def test_several_credentials_in_one_call_are_each_checked(conn):
    """Some APIs want a key, a secret and a passphrase in one request.

    Each is a separate statement of where that credential may go, and they do
    not pool: the call proceeds only if every one of them permits it.
    """
    for each in ("api-key", "api-secret", "api-pass"):
        broker.register(conn, each, backend="memory", hosts=[HOST])
        broker.grant(conn, each, HOST, source="test")
    store = Store({"api-key": "K", "api-secret": "S", "api-pass": "P"})

    opener = Opener()
    answer = broker.fetch(conn, {
        "secret": "api-key", "url": f"https://{HOST}/api/account",
        "headers": {"X-API-KEY": "{{secret}}",
                    "X-API-SIGN": "{{secret:api-secret}}",
                    "X-API-PASS": "{{secret:api-pass}}"},
    }, store=store, opener=opener, notify=False)

    assert answer["status"] == 200
    assert answer["used"] == ["api-key", "api-pass", "api-secret"]
    sent = opener.sent[0]
    assert sent.get_header("X-api-key") == "K"
    assert sent.get_header("X-api-pass") == "P"


def test_one_unapproved_credential_refuses_the_whole_call(conn):
    broker.register(conn, "api-key", backend="memory", hosts=[HOST])
    broker.register(conn, "api-pass", backend="memory", hosts=[HOST])
    broker.grant(conn, "api-key", HOST, source="test")   # and not the other

    opener = Opener()
    answer = broker.fetch(conn, {
        "secret": "api-key", "url": f"https://{HOST}/api",
        "headers": {"A": "{{secret}}", "B": "{{secret:api-pass}}"},
    }, store=Store({"api-key": "K", "api-pass": "P"}), opener=opener,
        notify=False)

    assert answer["code"] == "unapproved"
    assert "api-pass" in answer["refused"]
    assert opener.sent == [], "nothing may go out"


def test_every_credential_in_a_call_is_scrubbed_from_the_reply(conn):
    for each in ("a-key", "b-key"):
        broker.register(conn, each, backend="memory", hosts=[HOST])
        broker.grant(conn, each, HOST, source="test")
    echo = json.dumps({"saw": "AAA and BBB"}).encode()

    answer = broker.fetch(conn, {
        "secret": "a-key", "url": f"https://{HOST}/api",
        "headers": {"A": "{{secret}}", "B": "{{secret:b-key}}"},
    }, store=Store({"a-key": "AAA", "b-key": "BBB"}),
        opener=Opener(Reply(200, echo)), notify=False)

    assert "AAA" not in answer["body"] and "BBB" not in answer["body"]
    assert "[REDACTED:a-key]" in answer["body"]
    assert "[REDACTED:b-key]" in answer["body"]


def test_a_refusal_carries_a_code_a_program_can_branch_on(wired):
    assert call(wired)["code"] == "unapproved"
    allow(wired)
    assert call(wired, url="https://elsewhere.example/x")["code"] == "unapproved"
    assert call(wired, store=Store({}))["code"] == "no-value"
    assert call(wired, secret="")["code"] == "malformed"


def test_the_codes_are_documented_and_the_contract_is_versioned(tmp_path):
    server = broker.Server(path=str(tmp_path / "b.sock"))
    server.start()
    try:
        contract = broker.request({"op": "ops"}, path=server.path)
    finally:
        server.stop()

    assert contract["protocol"] == config.PROTOCOL_VERSION
    assert set(contract["ops"]) == {"ping", "ops", "fetch", "sign"}
    for code in ("unapproved", "off-policy", "no-value", "unavailable",
                 "timeout", "sent-outcome-unknown"):
        assert code in contract["codes"]
    assert contract["schemes"]["hmac"] is True


def test_a_mutating_call_is_never_followed_to_a_redirect(wired):
    """A redirect is a retry, and the far side has already seen the first
    body."""
    allow(wired, mutating=True)
    opener = Opener(Reply(302, b"", {"Location": f"https://{HOST}/api/v4/x"}),
                    Reply(200, b"{}"))
    answer = call(wired, method="POST", opener=opener)

    assert len(opener.sent) == 1
    assert answer["status"] == 302
    assert any("second write" in w for w in answer["warnings"])


def test_a_failure_after_the_bytes_went_out_is_not_called_a_timeout(wired):
    class Hangs:
        def open(self, request, timeout=None):
            raise TimeoutError("read timed out")

    allow(wired, mutating=True)
    answer = call(wired, method="POST", opener=Hangs())

    assert answer["code"] == "sent-outcome-unknown"
    assert wired.execute(
        "SELECT code FROM secret_use ORDER BY id DESC").fetchone()[0] == \
        "sent-outcome-unknown"


def test_the_nonce_rises_and_survives_a_restart(wired):
    first = broker.next_nonce(wired, "gitlab-pat", time.time())
    second = broker.next_nonce(wired, "gitlab-pat", time.time())
    assert second > first

    # A fresh connection is what a restarted service has.
    held = wired.execute("SELECT last_nonce FROM secret WHERE name = ?",
                         ("gitlab-pat",)).fetchone()[0]
    assert held == second
    assert broker.next_nonce(wired, "gitlab-pat", 0.0) > second


def test_the_whole_response_can_be_written_to_a_file(wired, monkeypatch,
                                                     tmp_path):
    """A cut JSON body does not fail loudly, it parses to a different price."""
    monkeypatch.setattr(config, "capture_dir", lambda: tmp_path / "captures")
    monkeypatch.setattr(config, "FETCH_BODY_CHARS", 100)
    allow(wired)
    payload = json.dumps({"rows": ["x" * 50 for _ in range(40)]}).encode()

    answer = call(wired, opener=Opener(Reply(200, payload)),
                  capture="account-listing")

    kept = Path(answer["response_path"]).read_bytes()
    assert kept == payload
    assert answer["response_sha256"] == hashlib.sha256(payload).hexdigest()
    assert len(answer["body"]) < len(payload)
    assert answer["response_path"] in answer["body"]


def test_a_capture_name_cannot_choose_where_xenia_writes(wired, monkeypatch,
                                                         tmp_path):
    root = tmp_path / "captures"
    monkeypatch.setattr(config, "capture_dir", lambda: root)
    allow(wired)

    answer = call(wired, capture="../../etc/xenia-was-here")

    assert Path(answer["response_path"]).parent == root
    assert not (tmp_path.parent / "etc").exists()


def test_a_capture_is_scrubbed_before_it_is_written(wired, monkeypatch,
                                                    tmp_path):
    monkeypatch.setattr(config, "capture_dir", lambda: tmp_path / "captures")
    allow(wired)
    answer = call(wired, capture="echoed",
                  opener=Opener(Reply(200, f"you sent {VALUE}".encode())))

    assert VALUE not in Path(answer["response_path"]).read_text()
    assert VALUE not in Path(answer["request_path"]).read_text()


def test_the_capture_is_recorded_against_the_use(wired, monkeypatch, tmp_path):
    monkeypatch.setattr(config, "capture_dir", lambda: tmp_path / "captures")
    allow(wired)
    call(wired, capture="audit-me")

    row = wired.execute("SELECT * FROM secret_use ORDER BY id DESC").fetchone()
    assert row["response_path"] and row["response_sha256"]


# -- signing without a request ----------------------------------------------

def test_sign_returns_a_signature_for_a_chain_xenia_does_not_speak(wired):
    """Some callers send the request themselves, so there is nothing for
    xenia to make — only a payload to sign."""
    profile(wired, "gitlab-pat", scheme="hmac", template="{body}",
            encoding="hex")
    broker.grant(wired, "gitlab-pat", broker.SIGN_SCOPE, mutating=True,
                 source="test")

    answer = broker.sign_only(wired, {"secret": "gitlab-pat",
                                      "payload": {"msg": "transfer"}},
                              store=Store(), notify=False)

    assert len(answer["signature"]) == 64
    assert VALUE not in json.dumps(answer)
    assert answer["nonce"] > 0


def test_signing_needs_its_own_approval(wired):
    profile(wired, "gitlab-pat", scheme="hmac", template="{body}")
    allow(wired)          # a grant for the HOST, which is not the sign scope

    answer = broker.sign_only(wired, {"secret": "gitlab-pat", "payload": {}},
                              store=Store(), notify=False)

    assert answer["code"] == "unapproved"


def test_a_signature_is_recorded_like_any_other_use(wired):
    profile(wired, "gitlab-pat", scheme="hmac", template="{body}")
    broker.grant(wired, "gitlab-pat", broker.SIGN_SCOPE, mutating=True,
                 source="test")
    broker.sign_only(wired, {"secret": "gitlab-pat", "payload": {"a": 1}},
                     store=Store(), notify=False)

    row = wired.execute("SELECT * FROM secret_use ORDER BY id DESC").fetchone()
    assert row["method"] == "SIGN" and row["decision"] == "allowed"


# -- what a credential must have before it is held -------------------------

def test_a_service_credential_needs_a_body_policy_to_be_held_at_all(conn):
    """Naming a service says the credential does more than read.

    A harmless call and a damaging one there share a host and a method, so a
    route allowlist alone cannot separate them.
    """
    with pytest.raises(ValueError, match="no body policy"):
        broker.register(conn, "api-key", backend="memory",
                        hosts=["api.test"], service="acme")

    # With one, it registers: the gate is the policy, not a build flag.
    broker.register(conn, "api-key", backend="memory", hosts=["api.test"])
    broker.set_body_policy(conn, "api-key", {"actions": {"read": {
        "methods": ["GET"], "paths": ["/api/account/*"]}}})
    broker.register(conn, "api-key", backend="memory", hosts=["api.test"],
                    service="acme")

    assert broker.registry(conn)[0]["service"] == "acme"


def test_a_scope_nobody_verified_reads_as_stale(conn):
    broker.register(conn, "aws", backend="memory", hosts=["s3.test"],
                    scope=["read-only"])

    assert broker.registry(conn)[0]["scope_stale"] is True
    assert broker.scope_is_stale(broker.stamp(broker.utcnow())) is False


# -- the review of 2026-09-11 -----------------------------------------------

def test_the_connection_goes_to_the_address_that_was_checked(conn,
                                                             monkeypatch):
    """Resolving twice is the rebinding hole: a harmless answer for the check,
    the real one microseconds later when the socket opens.

    Pinned to an address with nothing on it, the call must fail — if it
    succeeded, the socket had resolved the name for itself.
    """
    import http.server
    import threading as _threading

    served = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _Ok)
    _threading.Thread(target=served.serve_forever, daemon=True).start()
    port = served.server_address[1]
    try:
        broker.register(conn, "local", backend="memory", hosts=["localhost"])
        broker.grant(conn, "local", "localhost", source="test")

        monkeypatch.setattr(broker, "_resolved_addresses",
                            lambda host: ["127.0.0.1"])
        good = broker.fetch(conn, {
            "secret": "local", "url": f"http://localhost:{port}/",
            "headers": {"X-Token": broker.PLACEHOLDER}},
            store=Store({"local": VALUE}), notify=False)
        assert good["status"] == 200, "the pinned address must still work"

        # Now the check approves an address the server is not on. A socket
        # that resolved 'localhost' itself would still reach it.
        monkeypatch.setattr(broker, "_resolved_addresses",
                            lambda host: ["127.0.0.9"])
        rebound = broker.fetch(conn, {
            "secret": "local", "url": f"http://localhost:{port}/",
            "headers": {"X-Token": broker.PLACEHOLDER}},
            store=Store({"local": VALUE}), notify=False)
    finally:
        served.shutdown()

    assert "status" not in rebound, (
        "the request reached the server despite being pinned elsewhere")
    assert rebound["code"] in ("timeout", "sent-outcome-unknown")


class _Ok(__import__("http.server", fromlist=["x"]).BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Length", "2")
        self.end_headers()
        self.wfile.write(b"{}")


def test_a_literal_address_pins_to_itself(monkeypatch):
    monkeypatch.setattr(broker, "_resolved_addresses",
                        lambda host: pytest.fail("a literal must not resolve"))
    _host, _path, pinned = broker.check_target("https://198.51.100.7/api")

    assert pinned == "198.51.100.7"


def test_a_name_pins_to_the_address_that_passed(monkeypatch):
    monkeypatch.setattr(broker, "_resolved_addresses",
                        lambda host: ["203.0.113.7", "203.0.113.8"])
    _host, _path, pinned = broker.check_target("https://many.test/api")

    assert pinned == "203.0.113.7"


def test_a_client_that_says_nothing_does_not_hold_a_thread_for_ever(tmp_path,
                                                                    monkeypatch):
    monkeypatch.setattr(broker, "CLIENT_READ_TIMEOUT", 0.3)
    server = broker.Server(path=str(tmp_path / "b.sock"))
    server.start()
    try:
        mute = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        mute.connect(server.path)          # connects, sends no newline
        try:
            started = time.monotonic()
            # The broker must still answer somebody else meanwhile.
            assert broker.request({"op": "ping"}, path=server.path)["ok"]
            assert time.monotonic() - started < 2
        finally:
            mute.close()
    finally:
        server.stop()


def test_too_many_at_once_are_refused_rather_than_queued(tmp_path,
                                                         monkeypatch):
    monkeypatch.setattr(broker, "MAX_CLIENTS", 2)
    monkeypatch.setattr(broker, "CLIENT_READ_TIMEOUT", 5)
    server = broker.Server(path=str(tmp_path / "b.sock"))
    server.start()
    held = []
    try:
        for _ in range(2):
            mute = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            mute.connect(server.path)
            held.append(mute)
        time.sleep(0.2)

        turned_away = broker.request({"op": "ping"}, path=server.path)
        assert turned_away["code"] == "unavailable"
        assert "already handling" in turned_away["refused"]
    finally:
        for mute in held:
            mute.close()
        server.stop()


# -- body predicates, round 2 ----------------------------------------------

ITEM_POLICY = {"actions": {
    "create": {
        "methods": ["POST"], "paths": ["/v1/items"],
        "in": {"project": ["alpha"], "mode": ["standard"]},
        "equals": {"dryRun": True},
        "max": {"count": "10"},
    },
    "read": {"methods": ["GET"], "paths": ["/api/account/*"]},
}}


@pytest.fixture
def wired_policy(conn):
    broker.register(conn, "api-key", backend="memory", hosts=[HOST],
                    methods=["GET", "POST"])
    broker.set_body_policy(conn, "api-key", ITEM_POLICY)
    broker.set_profile(conn, "api-key", "default", {
        "scheme": "hmac", "template": "{ts}{method}{path}{body}",
        "digest": "sha256", "encoding": "base64"})
    broker.grant(conn, "api-key", HOST, mutating=True, source="test")
    return conn


def create_item(conn, opener=None, **overrides):
    body = {"project": "alpha", "label": "nightly", "mode": "standard",
            "count": "2", "dryRun": True}
    body.update(overrides)
    return broker.fetch(conn, {
        "secret": "api-key", "method": "POST",
        "url": f"https://{HOST}/v1/items",
        "headers": {"X-API-SIGN": "{{sign}}",
                    "Content-Type": "application/json"},
        "body": body,
    }, store=Store({"api-key": VALUE}), opener=opener or Opener(), notify=False)


def test_a_permitted_request_is_signed_sent_and_recorded_by_its_rule(wired_policy):
    opener = Opener()
    answer = create_item(wired_policy, opener=opener)

    assert answer["status"] == 200
    assert answer["action"] == "create"
    assert answer["signed"] == ["default"]
    assert opener.sent[0].get_header("X-api-sign")
    row = wired_policy.execute(
        "SELECT reason FROM secret_use ORDER BY id DESC").fetchone()[0]
    assert row == "action: create"


def test_a_request_over_the_cap_never_reaches_the_wire(wired_policy):
    opener = Opener()
    answer = create_item(wired_policy, opener=opener, count="500")

    assert answer["code"] == "off-policy"
    assert "over the cap" in answer["refused"]
    assert opener.sent == []


def test_an_unlisted_endpoint_is_refused_on_the_same_credential(wired_policy):
    opener = Opener()
    answer = broker.fetch(wired_policy, {
        "secret": "api-key", "method": "POST",
        "url": f"https://{HOST}/v1/projects/purge",
        "headers": {"X-API-SIGN": "{{sign}}",
                    "Content-Type": "application/json"},
        "body": {"project": "alpha"},
    }, store=Store({"api-key": VALUE}), opener=opener, notify=False)

    assert answer["code"] == "off-policy"
    assert "no action permits" in answer["refused"]
    assert opener.sent == []


def test_nothing_is_signed_for_a_request_that_is_refused(wired_policy, monkeypatch):
    """A signature over a body asserts that body is final.

    A check that ran after signing would already have produced a valid
    signature for an order nobody approved — and once computed, that exists.
    """
    signed = []
    real = broker.signing.sign
    monkeypatch.setattr(broker.signing, "sign",
                        lambda profile, ctx: signed.append(1) or real(profile, ctx))

    assert create_item(wired_policy, count="999")["code"] == "off-policy"
    assert signed == [], "a refused request must not be signed"

    assert create_item(wired_policy)["status"] == 200
    assert signed == [1]


def test_the_gate_sees_the_request_after_substitution(conn):
    """A check against the template and a signature over the substitution are
    two different requests."""
    broker.register(conn, "api-key", backend="memory", hosts=[HOST],
                    methods=["POST"])
    broker.set_body_policy(conn, "api-key", {"actions": {"order": {
        "methods": ["POST"], "paths": ["/order"],
        "in": {"key": ["the-real-value"]}}}})
    broker.grant(conn, "api-key", HOST, mutating=True, source="test")

    answer = broker.fetch(conn, {
        "secret": "api-key", "method": "POST", "url": f"https://{HOST}/order",
        "headers": {"Content-Type": "application/json"},
        "body": {"key": broker.PLACEHOLDER},
    }, store=Store({"api-key": "the-real-value"}), opener=Opener(), notify=False)

    assert answer["status"] == 200, answer.get("refused")


def test_a_body_the_policy_cannot_read_is_refused(wired_policy):
    opener = Opener()
    answer = broker.fetch(wired_policy, {
        "secret": "api-key", "method": "POST",
        "url": f"https://{HOST}/v1/items",
        "headers": {"X-API-SIGN": "{{sign}}",
                    "Content-Type": "application/octet-stream"},
        "body": "\\x00\\x01not-readable",
    }, store=Store({"api-key": VALUE}), opener=opener, notify=False)

    assert answer["code"] == "off-policy"
    assert "cannot be read" in answer["refused"]
    assert opener.sent == []


def test_a_credential_with_no_body_policy_is_unaffected(wired):
    """Route policy alone still works for a read-only PAT."""
    allow(wired)
    assert call(wired)["status"] == 200


def test_a_form_encoded_order_is_checked_and_signed(conn):
    """Parameters in the query with the signature beside them: a layer that
    only read JSON would leave this shape unchecked."""
    broker.register(conn, "form-api", backend="memory", hosts=[HOST],
                    methods=["POST"])
    broker.set_body_policy(conn, "form-api", {"actions": {"create": {
        "methods": ["POST"], "paths": ["/api/create"],
        "in": {"project": ["alpha"]}, "max": {"count": "10"}}}})
    broker.set_profile(conn, "form-api", "default", {
        "scheme": "hmac", "template": "{query}", "digest": "sha256",
        "encoding": "hex"})
    broker.grant(conn, "form-api", HOST, mutating=True, source="test")

    opener = Opener()
    good = broker.fetch(conn, {
        "secret": "form-api", "method": "POST",
        "url": f"https://{HOST}/api/create?project=alpha&count=2",
        "headers": {"X-API-KEY": broker.PLACEHOLDER,
                    "X-SIGNATURE": "{{sign}}"},
    }, store=Store({"form-api": VALUE}), opener=opener, notify=False)

    assert good["action"] == "create"
    assert len(opener.sent[0].get_header("X-signature")) == 64

    over = broker.fetch(conn, {
        "secret": "form-api", "method": "POST",
        "url": f"https://{HOST}/api/create?project=alpha&count=999",
        "headers": {"X-API-KEY": broker.PLACEHOLDER,
                    "X-SIGNATURE": "{{sign}}"},
    }, store=Store({"form-api": VALUE}), opener=Opener(), notify=False)

    assert over["code"] == "off-policy"


def test_a_policy_that_cannot_be_read_is_refused_when_it_is_set(conn):
    broker.register(conn, "api-key", backend="memory", hosts=[HOST])

    with pytest.raises(ValueError, match="names no paths"):
        broker.set_body_policy(conn, "api-key", {"actions": {"bad": {}}})
    with pytest.raises(ValueError, match="not a number"):
        broker.set_body_policy(conn, "api-key", {"actions": {"bad": {
            "paths": ["/x"], "max": {"count": "loads"}}}})
    with pytest.raises(ValueError, match="permits nothing"):
        broker.set_body_policy(conn, "api-key", {"actions": {}})


# -- scope decided by the person, at first use ------------------------------

def test_a_credential_starts_with_nothing_allowed(conn):
    broker.register(conn, "fresh", backend="memory")

    assert json.loads(broker.entry(conn, "fresh")["hosts"]) == []


def test_saying_yes_is_what_records_the_host(conn, monkeypatch):
    """The scope is a decision about a real request, not a guess typed in
    advance."""
    broker.register(conn, "fresh", backend="memory")
    asked = []
    monkeypatch.setattr(broker, "ask_to_use",
                        lambda name, host, method, **kw:
                        asked.append((name, host, method)) or True)

    answer = broker.fetch(conn, {
        "secret": "fresh", "url": f"https://{HOST}/api",
        "headers": {"X": broker.PLACEHOLDER}},
        store=Store({"fresh": VALUE}), opener=Opener())

    assert answer["status"] == 200
    assert asked == [("fresh", HOST, "GET")]
    assert json.loads(broker.entry(conn, "fresh")["hosts"]) == [HOST]
    assert broker.grants(conn)[0]["source"] == "prompt"


def test_saying_no_refuses_and_records_nothing(conn, monkeypatch):
    broker.register(conn, "fresh", backend="memory")
    monkeypatch.setattr(broker, "ask_to_use",
                        lambda name, host, method, **kw: False)

    answer = broker.fetch(conn, {
        "secret": "fresh", "url": f"https://{HOST}/api",
        "headers": {"X": broker.PLACEHOLDER}},
        store=Store({"fresh": VALUE}), opener=Opener())

    assert answer["code"] == "unapproved"
    assert "declined" in answer["refused"]
    assert json.loads(broker.entry(conn, "fresh")["hosts"]) == []
    assert broker.grants(conn) == []


def test_a_second_host_asks_again(conn, monkeypatch):
    broker.register(conn, "fresh", backend="memory")
    asked = []
    monkeypatch.setattr(broker, "ask_to_use",
                        lambda name, host, method, **kw:
                        asked.append(host) or True)

    for host in (HOST, "other.example"):
        broker.fetch(conn, {"secret": "fresh", "url": f"https://{host}/api",
                            "headers": {"X": broker.PLACEHOLDER}},
                     store=Store({"fresh": VALUE}), opener=Opener())

    assert asked == [HOST, "other.example"]
    assert json.loads(broker.entry(conn, "fresh")["hosts"]) == [
        HOST, "other.example"]


def test_an_approved_host_is_not_asked_about_again(conn, monkeypatch):
    broker.register(conn, "fresh", backend="memory")
    asked = []
    monkeypatch.setattr(broker, "ask_to_use",
                        lambda name, host, method, **kw:
                        asked.append(host) or True)

    for _ in range(3):
        broker.fetch(conn, {"secret": "fresh", "url": f"https://{HOST}/api",
                            "headers": {"X": broker.PLACEHOLDER}},
                     store=Store({"fresh": VALUE}), opener=Opener())

    assert asked == [HOST], "one decision covers the calls under it"


def test_a_write_asks_even_where_reading_was_allowed(conn, monkeypatch):
    broker.register(conn, "fresh", backend="memory")
    asked = []
    monkeypatch.setattr(broker, "ask_to_use",
                        lambda name, host, method, **kw:
                        asked.append(method) or True)

    for method in ("GET", "POST"):
        broker.fetch(conn, {"secret": "fresh", "method": method,
                            "url": f"https://{HOST}/api",
                            "headers": {"X": broker.PLACEHOLDER}},
                     store=Store({"fresh": VALUE}), opener=Opener())

    assert asked == ["GET", "POST"]


def test_an_agent_retrying_cannot_paper_the_desktop_with_prompts(conn,
                                                                  monkeypatch):
    broker.register(conn, "fresh", backend="memory")
    asked = []
    monkeypatch.setattr(broker, "ask_to_use",
                        lambda name, host, method, **kw:
                        asked.append(host) or False)

    for _ in range(5):
        broker.fetch(conn, {"secret": "fresh", "url": f"https://{HOST}/api",
                            "headers": {"X": broker.PLACEHOLDER}},
                     store=Store({"fresh": VALUE}), opener=Opener())

    assert len(asked) == 1, "a refusal holds off the next prompt"


def test_a_hard_refusal_is_never_put_to_the_user(conn, monkeypatch):
    """No prompt can make a link-local address acceptable."""
    broker.register(conn, "fresh", backend="memory")
    monkeypatch.setattr(broker, "_resolved_addresses",
                        lambda host: ["169.254.169.254"])
    asked = []
    monkeypatch.setattr(broker, "ask_to_use",
                        lambda *a, **kw: asked.append(1) or True)

    answer = broker.fetch(conn, {"secret": "fresh",
                                 "url": "https://metadata.test/latest",
                                 "headers": {"X": broker.PLACEHOLDER}},
                          store=Store({"fresh": VALUE}), opener=Opener())

    assert "link-local" in answer["refused"]
    assert asked == []


# -- the prompt on the desktop ----------------------------------------------

class Notified:
    """A notification daemon that behaves like the ones people run.

    It ignores expire_timeout on anything carrying actions — measured on Xfce
    Notify Daemon 0.9.7, and the reason a prompt used to outlive the call that
    raised it — so the only thing that ever takes one of these off the screen
    is a CloseNotification.
    """

    def __init__(self, capabilities=("body", "actions"), on_close=None):
        self.capabilities = list(capabilities)
        self.calls: list[tuple[str, list]] = []
        self.handlers: dict[str, object] = {}
        self.on_screen: set[int] = set()
        self.on_close = on_close
        self.closed = False

    # the bit of xenia.dbus.Connection that ask_to_use uses
    def connect(self):
        return self

    def call(self, destination, path, interface, member, signature="",
             body=(), timeout=5.0):
        self.calls.append((member, list(body)))
        if member == "GetCapabilities":
            return [self.capabilities]
        if member == "Notify":
            self.on_screen.add(7)
            return [7]
        if member == "CloseNotification":
            if self.on_close is not None:
                self.on_close(self)
            self.on_screen.discard(body[0])
            self.fire("NotificationClosed", [body[0], 3])
            return []
        raise AssertionError(f"unexpected call: {member}")

    def on_signal(self, path, interface, member, handler):
        self.handlers[member] = handler

    def close(self):
        self.closed = True

    # what the daemon does back
    def fire(self, member, body):
        handler = self.handlers.get(member)
        if handler is not None:
            handler(type("Signal", (), {"body": body})())

    def click(self, action):
        self.fire("ActionInvoked", [7, action])

    def sent(self, member):
        return [body for name, body in self.calls if name == member]


@pytest.fixture
def daemon(monkeypatch):
    def serving(**kwargs):
        bus = Notified(**kwargs)
        monkeypatch.setattr("xenia.dbus.Connection", lambda *a, **kw: bus)
        return bus
    return serving


def test_a_prompt_nobody_is_listening_to_is_taken_off_the_screen(daemon):
    """The bug this exists for: the window is xenia's, not the daemon's.

    Waiting on expire_timeout leaves Allow and Deny on screen after the call
    has given up, and a click on them is discarded in silence.
    """
    bus = daemon()
    ended: dict = {}

    assert broker.ask_to_use("aws", HOST, "GET", known=False, wait=0.05,
                             ended=ended) is False

    assert bus.sent("CloseNotification") == [[7]]
    assert bus.on_screen == set()
    assert ended["how"] == "timed-out"
    assert bus.closed, "the bus connection is closed after the prompt is"


def test_the_prompt_is_taken_down_before_the_connection_that_would_answer_it(
        daemon):
    order = []
    bus = daemon()
    bus.close = lambda: order.append("bus")
    original = bus.call

    def watched(*args, **kwargs):
        if args[3] == "CloseNotification":
            order.append("close")
        return original(*args, **kwargs)

    bus.call = watched
    broker.ask_to_use("aws", HOST, "GET", known=False, wait=0.05)

    assert order == ["close", "bus"]


def test_a_click_that_lands_as_it_gives_up_still_counts(daemon):
    """A click already on the wire is an answer xenia has, not one it lost."""
    bus = daemon(on_close=lambda bus: bus.click("allow"))
    ended: dict = {}

    assert broker.ask_to_use("aws", HOST, "GET", known=False, wait=0.05,
                             ended=ended) is True
    assert ended["how"] == "allowed"


def test_an_answer_ends_the_wait_and_says_which_it_was(daemon):
    for action, expected, how in (("allow", True, "allowed"),
                                  ("deny", False, "denied")):
        bus = daemon()
        ended: dict = {}
        answered = threading.Thread(target=lambda: (time.sleep(0.05),
                                                    bus.click(action)))
        answered.start()
        try:
            assert broker.ask_to_use("aws", HOST, "GET", known=False, wait=5,
                                     ended=ended) is expected
        finally:
            answered.join()
        assert ended["how"] == how


def test_a_prompt_the_user_dismisses_is_not_recorded_as_a_decline(daemon):
    bus = daemon()
    ended: dict = {}
    dismissed = threading.Thread(
        target=lambda: (time.sleep(0.05),
                        bus.fire("NotificationClosed", [7, 2])))
    dismissed.start()
    try:
        assert broker.ask_to_use("aws", HOST, "GET", known=False, wait=5,
                                 ended=ended) is False
    finally:
        dismissed.join()
    assert ended["how"] == "dismissed"


def test_a_daemon_that_cannot_show_buttons_is_not_asked_at_all(daemon):
    bus = daemon(capabilities=("body",))
    ended: dict = {}

    assert broker.ask_to_use("aws", HOST, "GET", known=False, wait=0.05,
                             ended=ended) is None
    assert bus.sent("Notify") == []
    assert ended["how"] == "unasked"


def test_the_expire_hint_is_still_sent_as_a_backstop(daemon):
    """A daemon that honours it clears a prompt xenia died holding."""
    bus = daemon()
    broker.ask_to_use("aws", HOST, "GET", known=False, wait=0.05)

    assert bus.sent("Notify")[0][-1] == 50


def test_an_unanswered_prompt_does_not_tell_the_agent_the_user_said_no(
        conn, monkeypatch):
    broker.register(conn, "fresh", backend="memory")
    monkeypatch.setattr(
        broker, "ask_to_use",
        lambda name, host, method, ended=None, **kw:
        ended.update({"how": "timed-out", "seconds": 25}) or False)

    answer = broker.fetch(conn, {
        "secret": "fresh", "url": f"https://{HOST}/api",
        "headers": {"X": broker.PLACEHOLDER}},
        store=Store({"fresh": VALUE}), opener=Opener())

    assert "went unanswered for 25s" in answer["refused"]
    assert "taken down" in answer["refused"]
    assert "declined" not in answer["refused"], "nobody declined anything"
    assert "xenia grant fresh --host" in answer["refused"]


def test_a_real_decline_is_not_dressed_up_as_a_timeout(conn, monkeypatch):
    broker.register(conn, "fresh", backend="memory")
    monkeypatch.setattr(
        broker, "ask_to_use",
        lambda name, host, method, ended=None, **kw:
        ended.update({"how": "denied"}) or False)

    answer = broker.fetch(conn, {
        "secret": "fresh", "url": f"https://{HOST}/api",
        "headers": {"X": broker.PLACEHOLDER}},
        store=Store({"fresh": VALUE}), opener=Opener())

    assert "was declined" in answer["refused"]
    assert "xenia grant" not in answer["refused"], \
        "going around a no is not the next step"


# -- binary responses -------------------------------------------------------
#
# The text path decodes with "replace", which is right for a reply a person
# reads and fatal for bytes. These hold the other path: whole, undecoded, on
# disk, and still watched for a credential handed back.

class Stream(Reply):
    """A response that is CONSUMED as it is read, the way a real one is.

    `Reply.read(size)` returns the same prefix every time, which is fine for a
    body read once and an infinite loop for a body drained in chunks.
    """

    def __init__(self, status=200, body=b"", headers=None, reason="OK"):
        super().__init__(status, body, headers, reason)
        self._at = 0

    def read(self, size=None):
        if size is None:
            size = len(self._body) - self._at
        chunk = self._body[self._at:self._at + size]
        self._at += len(chunk)
        return chunk

    def close(self):
        pass


LZ4ISH = bytes(range(256)) * 64          # every byte value: never valid UTF-8


def test_a_binary_response_is_written_undecoded(wired, monkeypatch, tmp_path):
    monkeypatch.setattr(config, "capture_dir", lambda: tmp_path / "captures")
    allow(wired)

    answer = call(wired, opener=Opener(Stream(200, LZ4ISH)),
                  capture="object", binary=True)

    assert answer["binary"] is True
    kept = Path(answer["response_path"]).read_bytes()
    assert kept == LZ4ISH, "a decode would have replaced every invalid byte"
    assert answer["response_sha256"] == hashlib.sha256(LZ4ISH).hexdigest()
    assert answer["bytes"] == len(LZ4ISH)


def test_a_binary_response_needs_somewhere_to_put_the_bytes(wired):
    allow(wired)
    answer = call(wired, opener=Opener(Stream(200, LZ4ISH)), binary=True)

    assert answer["code"] == "malformed"
    assert "capture" in answer["refused"]


def test_a_binary_body_is_not_cut_at_the_text_cap(wired, monkeypatch, tmp_path):
    """The 1 MiB read cap exists so a REPLY stays small. Nothing replies here."""
    monkeypatch.setattr(config, "capture_dir", lambda: tmp_path / "captures")
    monkeypatch.setattr(config, "FETCH_MAX_BYTES", 1024)
    allow(wired)
    payload = LZ4ISH * 40                                    # 640 KiB, >> 1 KiB

    answer = call(wired, opener=Opener(Stream(200, payload)),
                  capture="big", binary=True)

    assert Path(answer["response_path"]).read_bytes() == payload


def test_a_binary_response_stops_at_its_own_ceiling(wired, monkeypatch,
                                                    tmp_path):
    """Unbounded would be an OOM in the process that holds the credentials."""
    monkeypatch.setattr(config, "capture_dir", lambda: tmp_path / "captures")
    monkeypatch.setattr(config, "FETCH_MAX_BINARY_BYTES", 100)
    allow(wired)

    answer = call(wired, opener=Opener(Stream(200, LZ4ISH)),
                  capture="runaway", binary=True)

    assert answer["bytes"] == 100
    assert Path(answer["response_path"]).read_bytes() == LZ4ISH[:100]
    assert "TRUNCATED" in answer["body"]


def test_a_credential_echoed_in_binary_bytes_is_still_noticed(wired, monkeypatch,
                                                              tmp_path):
    """Scrubbing the file would corrupt the object; saying so is the answer."""
    monkeypatch.setattr(config, "capture_dir", lambda: tmp_path / "captures")
    allow(wired)
    payload = LZ4ISH + VALUE.encode() + LZ4ISH

    answer = call(wired, opener=Opener(Stream(200, payload)),
                  capture="leaky", binary=True)

    assert any("rotate" in w for w in answer["warnings"])
    assert Path(answer["response_path"]).read_bytes() == payload


def test_a_credential_split_across_two_chunks_is_still_noticed(wired, monkeypatch,
                                                               tmp_path):
    monkeypatch.setattr(config, "capture_dir", lambda: tmp_path / "captures")
    monkeypatch.setattr(broker, "BINARY_CHUNK", 64)
    allow(wired)
    # Land the credential astride a 64-byte boundary.
    payload = b"a" * 50 + VALUE.encode() + b"b" * 50

    answer = call(wired, opener=Opener(Stream(200, payload)),
                  capture="astride", binary=True)

    assert any("rotate" in w for w in answer["warnings"])


def test_an_error_body_is_never_streamed_away(wired, monkeypatch, tmp_path):
    """A caller handed a file path instead of the reason cannot see why it failed."""
    monkeypatch.setattr(config, "capture_dir", lambda: tmp_path / "captures")
    allow(wired)
    denied = b"<Error><Code>AccessDenied</Code></Error>"

    answer = call(wired, opener=Opener(Stream(403, denied, reason="Forbidden")),
                  capture="denied", binary=True)

    assert answer["status"] == 403
    assert "AccessDenied" in answer["body"]
    assert answer["binary"] is False


# -- the nonce, and the write lock it used to hold --------------------------
#
# Earned 2026-09-11 pulling 9 GB from an S3 archive: `next_nonce` read then
# updated without committing, and `fetch` calls it BEFORE it sends. So one
# transfer held a write transaction for its whole duration.

def test_concurrent_nonces_are_unique_and_increasing(tmp_path, monkeypatch):
    """Two callers must never be issued the same number, whatever the timing."""
    monkeypatch.setenv("XENIA_FAKE_NOW", "2026-07-27T09:00:00.000+00:00")
    path = tmp_path / "audit.db"
    setup = db.connect(path)
    broker.register(setup, "gitlab-pat", backend="memory", hosts=[HOST],
                    methods=["GET"])
    setup.close()

    issued, errors = [], []
    lock = threading.Lock()
    start = threading.Barrier(8)

    def one():
        c = db.connect(path)
        try:
            start.wait(timeout=10)
            n = broker.next_nonce(c, "gitlab-pat", time.time())
            with lock:
                issued.append(n)
        except Exception as exc:          # a lock timeout is a failure here
            with lock:
                errors.append(f"{type(exc).__name__}: {exc}")
        finally:
            c.close()

    threads = [threading.Thread(target=one) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=30)

    assert errors == [], errors
    assert len(issued) == 8
    assert len(set(issued)) == 8, f"a nonce was issued twice: {sorted(issued)}"


def test_a_slow_request_does_not_hold_the_database(wired, monkeypatch, tmp_path):
    """The whole point: a transfer in flight must not freeze every other write.

    The opener blocks the way a 30 MB download does. While it is blocked, a
    SEPARATE connection must still be able to commit — before this fix it sat
    on the write lock until the transfer finished and then raised
    'database is locked'.
    """
    monkeypatch.setattr(config, "BUSY_TIMEOUT_MS", 1500)
    allow(wired)
    path = Path(str(wired.execute("PRAGMA database_list").fetchone()["file"]))
    sending = threading.Event()
    release = threading.Event()

    class Slow(Opener):
        def open(self, request, timeout=None):
            sending.set()
            release.wait(timeout=10)
            return super().open(request, timeout=timeout)

    outcome = {}

    def other_writer():
        assert sending.wait(timeout=10), "the request never went out"
        c = db.connect(path)
        try:
            c.execute("UPDATE secret SET note = 'written during a transfer' "
                      "WHERE name = ?", ("gitlab-pat",))
            c.commit()
            outcome["ok"] = True
        except Exception as exc:
            outcome["ok"] = False
            outcome["why"] = f"{type(exc).__name__}: {exc}"
        finally:
            c.close()
            release.set()

    t = threading.Thread(target=other_writer)
    t.start()
    answer = call(wired, opener=Slow())
    t.join(timeout=20)

    assert outcome.get("ok"), f"another writer was blocked: {outcome.get('why')}"
    assert answer["status"] == 200


# -- standing approvals: the unattended case -------------------------------
#
# A prompt is not a control when nobody is at the keyboard. These cover the
# approval that replaces it: longer than an interactive one, and narrower,
# because the length is what has to be paid for.

def test_a_standing_approval_outlives_the_interactive_ceiling(wired):
    row = broker.standing(wired, "gitlab-pat", HOST,
                          until=broker.utcnow() + timedelta(days=85),
                          reason="the timer fires at 03:00 and nobody is up")

    ceiling = datetime.fromisoformat(row["ceiling_at"]) - broker.utcnow()
    assert ceiling > timedelta(days=84), "a 4h ceiling would refuse every bar"
    assert row["source"] == "standing"
    assert row["reason"].startswith("the timer fires")


def test_a_standing_approval_without_a_reason_is_refused(wired):
    with pytest.raises(ValueError, match="needs a reason"):
        broker.standing(wired, "gitlab-pat", HOST,
                        until=broker.utcnow() + timedelta(days=3), reason="  ")


def test_a_standing_approval_for_signing_must_name_its_profiles(wired):
    """Otherwise the long approval is a signing oracle for every profile."""
    with pytest.raises(ValueError, match="name the profiles"):
        broker.standing(wired, "gitlab-pat", broker.SIGN_SCOPE,
                        until=broker.utcnow() + timedelta(days=30),
                        reason="unattended trading")


def test_a_standing_approval_is_bounded_however_far_out_it_asks(wired):
    with pytest.raises(ValueError, match="may not run past"):
        broker.standing(wired, "gitlab-pat", HOST,
                        until=broker.utcnow() + timedelta(days=4000),
                        reason="forever is not a duration")


def test_a_standing_approval_expires_rather_than_sliding(wired):
    """`_extend` slides an ordinary window forward on use. An end date is an
    end date: using it must not push it out."""
    row = broker.standing(wired, "gitlab-pat", HOST,
                          until=broker.utcnow() + timedelta(days=10),
                          reason="nightly")
    was = row["expires_at"]

    broker._extend(wired, row, True)
    wired.commit()

    now = wired.execute("SELECT * FROM secret_grant WHERE id = ?",
                        (row["id"],)).fetchone()
    assert now["expires_at"] <= was


def test_a_scoped_standing_approval_signs_only_what_it_names(wired):
    broker.set_profile(wired, "gitlab-pat", "i079-open-BTC",
                       {"scheme": "hmac", "template": "{body}"})
    broker.set_profile(wired, "gitlab-pat", "payouts",
                       {"scheme": "hmac", "template": "{body}"})
    broker.standing(wired, "gitlab-pat", broker.SIGN_SCOPE,
                    until=broker.utcnow() + timedelta(days=85),
                    profiles=["i079-*"], reason="I-079 trades on a 4h timer")

    named = broker.sign_only(
        wired, {"secret": "gitlab-pat", "profile": "i079-open-BTC",
                "payload": {"a": 1}}, store=Store(), notify=False)
    other = broker.sign_only(
        wired, {"secret": "gitlab-pat", "profile": "payouts",
                "payload": {"a": 1}}, store=Store(), notify=False)

    assert named.get("signature"), named
    assert other.get("code") == "unapproved", other
    assert "payouts" in other["refused"]


def test_an_unanswered_prompt_says_a_standing_approval_is_the_fix(wired):
    """The refusal an unattended caller actually gets has to name the cure.

    Telling a 03:00 timer to 'ask the user to run' something is advice for a
    case that recurs at the same hour tomorrow.
    """
    said = broker._why_not({"how": "timed-out", "seconds": 25},
                           "gitlab-pat", broker.SIGN_SCOPE, True,
                           "i079-open-BTC")

    assert "STANDING" in said
    assert "i079-open-BTC" in said


def test_an_interactive_approval_still_covers_every_profile(wired):
    """The narrowing is what a standing approval buys its length with; it must
    not quietly become a new requirement on answering a prompt."""
    broker.set_profile(wired, "gitlab-pat", "anything",
                       {"scheme": "hmac", "template": "{body}"})
    broker.grant(wired, "gitlab-pat", broker.SIGN_SCOPE, mutating=True,
                 source="prompt")

    answer = broker.sign_only(
        wired, {"secret": "gitlab-pat", "profile": "anything",
                "payload": {"a": 1}}, store=Store(), notify=False)

    assert answer.get("signature"), answer


def test_a_standing_approval_is_revoked_like_any_other(wired):
    broker.standing(wired, "gitlab-pat", HOST,
                    until=broker.utcnow() + timedelta(days=85),
                    reason="nightly")

    assert broker.revoke(wired, "gitlab-pat", HOST) == 1
    assert broker.live_grant(wired, "gitlab-pat", HOST, False) is None


def test_an_interactive_approval_does_not_revoke_a_standing_approval(wired):
    """Answering a prompt for one call must not blow away a standing
    approval given for unattended work on a timer."""
    broker.standing(wired, "gitlab-pat", broker.SIGN_SCOPE,
                    until=broker.utcnow() + timedelta(days=85),
                    profiles=["i079-*"], reason="unattended trading")
    broker.grant(wired, "gitlab-pat", broker.SIGN_SCOPE, mutating=True,
                 source="prompt")

    standing_row = broker.live_grant(wired, "gitlab-pat", broker.SIGN_SCOPE,
                                     True, "i079-open-BTC")
    assert standing_row is not None
    assert standing_row["source"] == "standing"


def test_multiple_standing_approvals_with_different_profiles_coexist(wired):
    broker.set_profile(wired, "gitlab-pat", "i079-open-BTC",
                       {"scheme": "hmac", "template": "{body}"})
    broker.set_profile(wired, "gitlab-pat", "payouts",
                       {"scheme": "hmac", "template": "{body}"})

    broker.standing(wired, "gitlab-pat", broker.SIGN_SCOPE,
                    until=broker.utcnow() + timedelta(days=85),
                    profiles=["i079-*"], reason="I-079")
    broker.standing(wired, "gitlab-pat", broker.SIGN_SCOPE,
                    until=broker.utcnow() + timedelta(days=85),
                    profiles=["payouts"], reason="payouts")

    named1 = broker.sign_only(
        wired, {"secret": "gitlab-pat", "profile": "i079-open-BTC",
                "payload": {"a": 1}}, store=Store(), notify=False)
    named2 = broker.sign_only(
        wired, {"secret": "gitlab-pat", "profile": "payouts",
                "payload": {"a": 1}}, store=Store(), notify=False)

    assert named1.get("signature")
    assert named2.get("signature")


def test_reissuing_a_standing_approval_for_the_same_scope_replaces_it(wired):
    g1 = broker.standing(wired, "gitlab-pat", broker.SIGN_SCOPE,
                         until=broker.utcnow() + timedelta(days=10),
                         profiles=["i079-*"], reason="old reason")
    g2 = broker.standing(wired, "gitlab-pat", broker.SIGN_SCOPE,
                         until=broker.utcnow() + timedelta(days=85),
                         profiles=["i079-*"], reason="new reason")

    old = wired.execute("SELECT revoked_at FROM secret_grant WHERE id = ?",
                        (g1["id"],)).fetchone()
    assert old["revoked_at"] is not None
    cur = broker.live_grant(wired, "gitlab-pat", broker.SIGN_SCOPE, True, "i079-open")
    assert cur["id"] == g2["id"]


def test_revoking_by_grant_id_leaves_other_grants_live(wired):
    g1 = broker.standing(wired, "gitlab-pat", broker.SIGN_SCOPE,
                         until=broker.utcnow() + timedelta(days=85),
                         profiles=["i079-*"], reason="I-079")
    g2 = broker.standing(wired, "gitlab-pat", broker.SIGN_SCOPE,
                         until=broker.utcnow() + timedelta(days=85),
                         profiles=["payouts"], reason="payouts")

    assert broker.revoke(wired, "gitlab-pat", grant_id=g1["id"]) == 1
    assert broker.live_grant(wired, "gitlab-pat", broker.SIGN_SCOPE, True, "i079-open") is None
    assert broker.live_grant(wired, "gitlab-pat", broker.SIGN_SCOPE, True, "payouts") is not None


def test_stopping_an_unstarted_broker_does_not_unlink_active_socket(tmp_path):
    """If a Server was never started or failed to start, calling stop() must
    not touch the file at path."""
    import os, socket
    path = str(tmp_path / "active.sock")
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    sock.bind(path)
    try:
        unstarted = broker.Server(path=path)
        unstarted.stop()
        assert os.path.exists(path), "unstarted server unlinked active socket"
    finally:
        sock.close()
        os.unlink(path)


def test_sign_only_returns_headers_generated_by_profile(wired):
    broker.set_profile(wired, "gitlab-pat", "bm",
                       {"scheme": "hmac", "template": "{method}{ts_ms}",
                        "timestamp_header": "BM-AUTH-TIMESTAMP",
                        "api_key_header": "BM-AUTH-APIKEY",
                        "key_id": "test-key-id"})
    broker.grant(wired, "gitlab-pat", broker.SIGN_SCOPE, mutating=True,
                 source="prompt")

    res = broker.sign_only(
        wired, {"secret": "gitlab-pat", "profile": "bm", "payload": {}},
        store=Store(), notify=False)

    assert res.get("signature")
    assert "headers" in res
    assert res["headers"]["BM-AUTH-APIKEY"] == "test-key-id"
    assert "BM-AUTH-TIMESTAMP" in res["headers"]
