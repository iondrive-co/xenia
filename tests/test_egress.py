from __future__ import annotations

import json
import os
import socket
import urllib.error

import pytest

from xenia import broker


SOURCE = "10.99.0.7"
LISTED = "api.shop.example.com"
OTHER = "api.infra.example.com"
ADDRESS = "192.0.2.10"


class FakeSocket:
    def __init__(self):
        self.timeouts = []

    def settimeout(self, value):
        self.timeouts.append(value)


class Seen(list):
    pass


@pytest.fixture
def site(tmp_path, monkeypatch):
    path = tmp_path / "config.json"
    monkeypatch.setenv("XENIA_CONFIG", str(path))
    monkeypatch.setattr(broker, "_egress_cache", {"stamp": None, "rule": {}})
    monkeypatch.setattr(broker, "_egress_state", {"down_until": 0.0})

    def write(egress=None, **extra):
        body = dict(extra)
        if egress is not None:
            body["egress"] = egress
        path.write_text(json.dumps(body))
        stamp = path.stat().st_mtime_ns + write.bump
        write.bump += 1_000_000
        os.utime(path, ns=(stamp, stamp))

    write.bump = 1_000_000
    return write


@pytest.fixture
def calls(monkeypatch):
    seen = Seen()
    plan = {"fail_bound": False}

    def fake(address, timeout=None, source_address=None):
        seen.append({"address": address, "timeout": timeout,
                     "source": source_address})
        if source_address is not None and plan["fail_bound"]:
            raise TimeoutError("timed out")
        return FakeSocket()

    monkeypatch.setattr(broker.socket, "create_connection", fake)
    seen.plan = plan
    return seen


@pytest.fixture
def clock(monkeypatch):
    now = {"t": 1000.0}
    monkeypatch.setattr(broker.time, "monotonic", lambda: now["t"])
    return now


def test_a_listed_host_leaves_from_the_egress_source(site, calls):
    site({"source": SOURCE, "hosts": [LISTED]})

    sock = broker._connect(ADDRESS, 443, 30, None, LISTED)

    assert calls[0]["source"] == (SOURCE, 0)
    assert calls[0]["timeout"] == 2
    assert sock.timeouts == [30]


def test_an_unlisted_host_keeps_the_normal_route(site, calls):
    site({"source": SOURCE, "hosts": [LISTED]})

    broker._connect(ADDRESS, 443, 30, None, OTHER)

    assert calls == [{"address": (ADDRESS, 443), "timeout": 30, "source": None}]


def test_host_matching_ignores_case_and_a_trailing_dot(site, calls):
    site({"source": SOURCE, "hosts": [LISTED.upper() + "."]})

    broker._connect(ADDRESS, 443, 30, None, LISTED)

    assert calls[0]["source"] == (SOURCE, 0)


def test_no_egress_setting_changes_nothing(site, calls):
    site(signing_providers={})

    broker._connect(ADDRESS, 443, 30, None, LISTED)

    assert calls[0]["source"] is None


def test_a_missing_config_file_changes_nothing(tmp_path, monkeypatch, calls):
    monkeypatch.setenv("XENIA_CONFIG", str(tmp_path / "absent.json"))
    monkeypatch.setattr(broker, "_egress_cache", {"stamp": None, "rule": {}})

    broker._connect(ADDRESS, 443, 30, None, LISTED)

    assert calls[0]["source"] is None


@pytest.mark.parametrize("egress", [
    {"source": "not-an-address", "hosts": [LISTED]},
    {"source": "2001:db8::7", "hosts": [LISTED]},
    {"hosts": [LISTED]},
    {"source": SOURCE, "hosts": []},
    {"source": SOURCE, "hosts": [LISTED], "connect_timeout": "soon"},
    ["not", "a", "mapping"],
])
def test_a_malformed_setting_keeps_the_normal_route(site, calls, egress):
    site(egress)

    broker._connect(ADDRESS, 443, 30, None, LISTED)

    assert calls[0]["source"] is None


def test_an_ipv6_destination_keeps_the_normal_route(site, calls):
    site({"source": SOURCE, "hosts": [LISTED]})

    broker._connect("2001:db8::10", 443, 30, None, LISTED)

    assert calls[0]["source"] is None


def test_a_star_sends_every_host_through_the_source(site, calls):
    site({"source": SOURCE, "hosts": ["*"]})

    broker._connect(ADDRESS, 443, 30, None, OTHER)

    assert calls[0]["source"] == (SOURCE, 0)


def test_an_explicit_source_address_is_left_alone(site, calls):
    site({"source": SOURCE, "hosts": [LISTED]})

    broker._connect(ADDRESS, 443, 30, ("10.99.0.8", 0), LISTED)

    assert calls == [{"address": (ADDRESS, 443), "timeout": 30,
                      "source": ("10.99.0.8", 0)}]


def test_a_shorter_request_timeout_caps_the_egress_connect(site, calls):
    site({"source": SOURCE, "hosts": [LISTED], "connect_timeout": 5})

    sock = broker._connect(ADDRESS, 443, 1.5, None, LISTED)

    assert calls[0]["timeout"] == 1.5
    assert sock.timeouts == [1.5]


def test_the_default_timeout_is_restored_after_an_egress_connect(site, calls):
    site({"source": SOURCE, "hosts": [LISTED]})

    sock = broker._connect(ADDRESS, 443, socket._GLOBAL_DEFAULT_TIMEOUT, None,
                           LISTED)

    assert calls[0]["timeout"] == 2
    assert sock.timeouts == [socket.getdefaulttimeout()]


def test_a_failed_egress_connect_falls_back_and_cools_down(site, calls, clock,
                                                           capsys):
    site({"source": SOURCE, "hosts": [LISTED], "cooldown": 60})
    calls.plan["fail_bound"] = True

    sock = broker._connect(ADDRESS, 443, 30, None, LISTED)

    assert isinstance(sock, FakeSocket)
    assert [c["source"] for c in calls] == [(SOURCE, 0), None]
    assert calls[1]["timeout"] == 30
    assert "direct for 60s" in capsys.readouterr().err

    clock["t"] += 59
    broker._connect(ADDRESS, 443, 30, None, LISTED)
    assert [c["source"] for c in calls[2:]] == [None]

    calls.plan["fail_bound"] = False
    clock["t"] += 2
    broker._connect(ADDRESS, 443, 30, None, LISTED)
    assert calls[-1]["source"] == (SOURCE, 0)


def test_a_failed_direct_connect_still_raises(site, monkeypatch):
    site({"source": SOURCE, "hosts": [LISTED]})

    def refuse(address, timeout=None, source_address=None):
        raise ConnectionRefusedError("refused")

    monkeypatch.setattr(broker.socket, "create_connection", refuse)

    with pytest.raises(ConnectionRefusedError):
        broker._connect(ADDRESS, 443, 30, None, LISTED)


def test_an_edited_config_applies_without_a_restart(site, calls):
    site({"source": SOURCE, "hosts": [LISTED]})
    broker._connect(ADDRESS, 443, 30, None, OTHER)

    site({"source": SOURCE, "hosts": [LISTED, OTHER]})
    broker._connect(ADDRESS, 443, 30, None, OTHER)

    site(signing_providers={})
    broker._connect(ADDRESS, 443, 30, None, LISTED)

    assert [c["source"] for c in calls] == [None, (SOURCE, 0), None]


def test_the_opener_hands_the_request_host_to_the_egress_choice(site,
                                                                 monkeypatch):
    site({"source": SOURCE, "hosts": [LISTED]})
    seen = []

    def record(address, timeout=None, source_address=None):
        seen.append((address, source_address))
        raise ConnectionRefusedError("stop here")

    monkeypatch.setattr(broker.socket, "create_connection", record)

    for host in (LISTED, OTHER):
        with pytest.raises(urllib.error.URLError):
            broker._opener(ADDRESS).open(f"https://{host}/v1/time", timeout=5)

    assert seen == [((ADDRESS, 443), (SOURCE, 0)), ((ADDRESS, 443), None),
                    ((ADDRESS, 443), None)]
