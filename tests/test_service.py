from __future__ import annotations

import plistlib
import sys

import pytest

from xenia import app, service


@pytest.fixture
def calls(monkeypatch):
    seen: list[list[str]] = []

    def fake_run(args):
        seen.append(args)
        return True, ""

    monkeypatch.setattr(service, "_run", fake_run)
    return seen


@pytest.fixture
def systemd(fake_home, monkeypatch, calls):
    monkeypatch.setattr(sys, "platform", "linux")
    monkeypatch.setattr(service, "manager", lambda: "systemd")
    monkeypatch.setattr(service, "is_running", lambda: True)
    return calls


def test_systemd_gets_a_user_unit_that_starts_now_and_at_login(systemd, fake_home):
    report = service.install()

    unit = fake_home / ".config" / "systemd" / "user" / "xenia.service"
    assert unit.exists()
    body = unit.read_text()
    assert body.count("ExecStart=") == 1
    assert "xenia-service" in body
    assert "WantedBy=default.target" in body
    assert "Restart=on-failure" in body

    assert ["systemctl", "--user", "daemon-reload"] in systemd
    assert ["systemctl", "--user", "enable", "--now", "xenia.service"] in systemd
    assert report["started"] is True


def test_a_retired_service_comes_back_without_looking_like_a_failure(systemd):
    from xenia import readers

    service.install()
    body = service.unit_file().read_text()

    status = readers.RETIRED_EXIT_STATUS
    assert f"RestartForceExitStatus={status}" in body, "it would not come back"
    assert f"SuccessExitStatus={status}" in body, \
        "stopping it deliberately sends the same signal, and is not a failure"


def test_the_unit_runs_the_service_binary_not_the_bootstrap(systemd):
    service.install()
    exec_line = next(
        l for l in service.unit_file().read_text().splitlines()
        if l.startswith("ExecStart=")
    )
    assert exec_line.endswith("xenia-service")


def test_installing_the_unit_removes_the_login_entry(systemd, fake_home):
    stale = service.autostart_file()
    stale.parent.mkdir(parents=True, exist_ok=True)
    stale.write_text("[Desktop Entry]\n")

    service.install()

    assert not stale.exists()


def test_systemd_install_is_repeatable(systemd):
    first = service.install()
    second = service.install()
    assert first["unit"] == second["unit"]
    assert second["started"] is True


@pytest.fixture
def launchd(fake_home, monkeypatch, calls):
    monkeypatch.setattr(sys, "platform", "darwin")
    monkeypatch.setattr(service, "manager", lambda: "launchd")
    return calls


def test_launchd_gets_an_agent_that_is_kept_alive(launchd, fake_home):
    report = service.install()

    path = fake_home / "Library" / "LaunchAgents" / f"{service.LABEL}.plist"
    assert path.exists()
    plist = plistlib.loads(path.read_bytes())
    assert plist["RunAtLoad"] is True
    assert plist["KeepAlive"] is True
    assert plist["ProgramArguments"][0].endswith("xenia-service")
    assert report["started"] is True


def test_launchd_is_asked_to_start_it_now(launchd):
    service.install()
    assert any(args[:2] == ["launchctl", "bootstrap"] for args in launchd)


def test_launchd_falls_back_to_load_when_bootstrap_is_unsupported(
    fake_home, monkeypatch
):
    seen: list[list[str]] = []

    def fake_run(args):
        seen.append(args)
        return (False, "unrecognised") if args[1] == "bootstrap" else (True, "")

    monkeypatch.setattr(sys, "platform", "darwin")
    monkeypatch.setattr(service, "manager", lambda: "launchd")
    monkeypatch.setattr(service, "_run", fake_run)

    report = service.install()

    assert [a[1] for a in seen] == ["bootstrap", "load"]
    assert report["started"] is True


def test_no_supervisor_falls_back_to_a_login_entry(fake_home, monkeypatch):
    monkeypatch.setattr(sys, "platform", "linux")
    monkeypatch.setattr(service, "manager", lambda: None)

    report = service.install()

    assert report["manager"] is None
    assert report["started"] is False
    assert report["unit"].endswith("xenia.desktop")
    assert "foreground" in report["detail"]


def test_the_command_runs_in_the_foreground_when_there_is_no_service(
    fake_home, monkeypatch, capsys
):
    monkeypatch.setattr(service, "manager", lambda: None)
    monkeypatch.setattr(app.webbrowser, "open", lambda _url: None)
    ran = []
    monkeypatch.setattr(app.App, "run", lambda self, **kw: ran.append(True) or 0)

    assert app.main([]) == 0
    assert ran == [True]
    assert "Running in this terminal" in capsys.readouterr().out


def test_the_command_exits_once_the_service_has_the_report(
    fake_home, monkeypatch, capsys
):
    monkeypatch.setattr(service, "manager", lambda: "systemd")
    monkeypatch.setattr(service, "install", lambda: {
        "manager": "systemd", "started": True, "detail": "unit", "unit": "/x"})
    monkeypatch.setattr(app, "_await_report", lambda **_kw: "http://127.0.0.1:1/?t=x")
    opened = []
    monkeypatch.setattr(app.webbrowser, "open", opened.append)
    monkeypatch.setattr(app.App, "run", lambda self, **kw: pytest.fail(
        "must not run in the foreground when the service started"))

    assert app.main([]) == 0
    assert opened == ["http://127.0.0.1:1/?t=x"]


def test_a_service_that_never_publishes_a_report_does_not_hang(fake_home, monkeypatch):
    monkeypatch.setattr(app, "_read_runtime", lambda: {})
    assert app._await_report(timeout=0.5) is None


def test_a_departing_instance_does_not_delete_a_newer_one_s_runtime_file(
    fake_home, monkeypatch
):
    import json
    app.runtime_file().write_text(json.dumps({"pid": 999_999, "url": "http://x/"}))

    app._release_runtime()

    assert app.runtime_file().exists(), "another process's file must survive"


def test_an_instance_does_remove_its_own_runtime_file(fake_home):
    import json
    import os
    app.runtime_file().write_text(json.dumps({"pid": os.getpid(), "url": "http://x/"}))

    app._release_runtime()

    assert not app.runtime_file().exists()
