from __future__ import annotations

import json
from pathlib import Path

from xenia import app, icon, install


def test_the_icon_is_a_valid_png():
    png = icon.render()
    assert png.startswith(b"\x89PNG\r\n\x1a\n")
    assert png.endswith(b"IEND\xaeB`\x82")


def test_the_icon_never_changes():
    assert icon.render() == icon.render()


def test_the_dbus_pixmap_is_argb_of_the_right_size():
    width, height, argb = icon.argb_for_dbus()
    assert (width, height) == (icon.SIZE, icon.SIZE)
    assert len(argb) == icon.SIZE * icon.SIZE * 4


def test_the_tray_menu_is_the_three_things_it_can_do(fake_home):
    menu = app.App().menu()

    assert [item.label for item in menu] == [
        "Show Report", "Credentials", "Quit xenia"]
    assert [item.label for item in menu[1].items] == [
        "Add…", "List", "Approvals…", "Delete…"]


def test_approvals_opens_the_page_where_a_standing_one_is_given(fake_home,
                                                                monkeypatch):
    """Unattended work cannot be approved by a prompt — nobody is there to
    answer it — so the approval is given in advance, on the page that lists
    what is already approved."""
    opened = []
    monkeypatch.setattr(app.webbrowser, "open", opened.append)

    app.App().menu()[1].items[2].action()

    assert opened and opened[0].endswith("#credentials")


def test_a_submenu_is_numbered_flat_because_a_click_is_only_an_id(fake_home):
    from xenia.tray import Tray

    tray = Tray("xenia", app.App().menu())
    numbered = tray.numbered()

    assert [(i, item.label, parent) for i, item, parent in numbered] == [
        (1, "Show Report", 0), (2, "Credentials", 0),
        (3, "Add…", 2), (4, "List", 2), (5, "Approvals…", 2),
        (6, "Delete…", 2), (7, "Quit xenia", 0)]


def test_clicking_a_submenu_header_does_nothing(fake_home, monkeypatch):
    from xenia.tray import MenuItem, Tray

    fired = []
    tray = Tray("xenia", [
        MenuItem("Credentials", lambda: fired.append("header"),
                 items=[MenuItem("Add", lambda: fired.append("add"))])])

    tray.click(1)
    tray.click(2)

    assert fired == ["add"]


def test_show_report_opens_the_served_page(fake_home, monkeypatch):
    instance = app.App()
    instance.report.start()
    opened = []
    monkeypatch.setattr(app.webbrowser, "open", opened.append)
    try:
        url = instance.report.url
        show, _credentials, quit_ = instance.menu()
        show.action()
    finally:
        instance.report.stop()

    assert opened == [url]
    assert quit_.action == instance.quit


def test_setup_wires_up_everything_a_fresh_machine_needs(fake_home):
    report = app.run_setup()

    assert (fake_home / ".claude" / "settings.json").exists()
    assert (fake_home / ".codex" / "hooks.json").exists()
    assert Path(report["service"]["unit"]).exists()
    assert (fake_home / ".claude.json").exists()
    assert app.setup_marker().exists()
    assert report["mcp"]["ok"]


def test_setup_is_idempotent(fake_home):
    app.run_setup()
    again = app.run_setup()

    assert all(item["added"] == [] for item in again["capture"])
    assert again["mcp"]["changed"] is False


def test_setup_registers_the_mcp_server_as_stdio(fake_home):
    app.run_setup()
    config = json.loads((fake_home / ".claude.json").read_text())

    server = config["mcpServers"]["xenia"]
    assert server["type"] == "stdio"
    assert server["command"].endswith("xenia-mcp")


def test_mcp_registration_leaves_the_rest_of_the_file_alone(fake_home):
    target = fake_home / ".claude.json"
    target.write_text(json.dumps({
        "anonymousId": "keep-me",
        "projects": {"/some/path": {"history": ["a", "b"]}},
    }))

    app.run_setup()
    config = json.loads(target.read_text())

    assert config["anonymousId"] == "keep-me"
    assert config["projects"] == {"/some/path": {"history": ["a", "b"]}}
    assert "xenia" in config["mcpServers"]
    assert json.loads((fake_home / ".claude.json.xenia-backup").read_text())["anonymousId"]


def test_an_existing_mcp_server_is_not_displaced(fake_home):
    (fake_home / ".claude.json").write_text(json.dumps({
        "mcpServers": {"other": {"type": "stdio", "command": "/usr/bin/other"}},
    }))
    app.run_setup()

    servers = json.loads((fake_home / ".claude.json").read_text())["mcpServers"]
    assert servers["other"]["command"] == "/usr/bin/other"
    assert "xenia" in servers


def test_unparseable_claude_config_is_reported_not_overwritten(fake_home):
    target = fake_home / ".claude.json"
    target.write_text("{ not json")

    report = app.run_setup()

    assert report["mcp"]["ok"] is False
    assert target.read_text() == "{ not json"
    assert (fake_home / ".claude" / "settings.json").exists()


def test_the_autostart_entry_points_at_an_absolute_command(fake_home):
    report = app.run_setup()
    entry = Path(report["service"]["unit"]).read_text()

    exec_line = next(l for l in entry.splitlines() if l.startswith("Exec="))
    assert exec_line.split("=", 1)[1].startswith("/")
    assert exec_line.rstrip().endswith("xenia-service")
    assert "Type=Application" in entry


def test_capture_status_reflects_the_install(fake_home):
    assert app.capture_is_live() is False
    app.run_setup()
    assert app.capture_is_live() is True


def test_capture_can_be_repaired_after_being_stripped(fake_home):
    app.run_setup()
    settings = fake_home / ".claude" / "settings.json"
    settings.write_text(json.dumps({"model": "opus"}))
    (fake_home / ".codex" / "hooks.json").write_text("{}")
    assert app.capture_is_live() is False

    app.ensure_capture()
    assert app.capture_is_live() is True
    assert json.loads(settings.read_text())["model"] == "opus"


def test_the_command_takes_no_arguments(fake_home, capsys):
    assert app.main(["--json"]) == 2
    assert app.main(["report"]) == 2
    assert "takes no arguments" in capsys.readouterr().err


def test_a_second_invocation_restarts_the_running_one(fake_home, monkeypatch):
    import os
    app.runtime_file().write_text(json.dumps({
        "pid": os.getpid(), "url": "http://127.0.0.1:9/?t=old",
    }))

    monkeypatch.setattr(app.service, "restart", lambda: (True, "xenia.service"))
    monkeypatch.setattr(app, "_await_report", lambda **_kw: "http://127.0.0.1:9/?t=new")
    opened = []
    monkeypatch.setattr(app.webbrowser, "open", opened.append)
    monkeypatch.setattr(app.App, "run", lambda self, **kw: (_ for _ in ()).throw(
        AssertionError("must not start a second instance")))

    assert app.main([]) == 0
    assert opened == ["http://127.0.0.1:9/?t=new"], \
        "the report of the instance that was replaced is the old code's"


def test_the_restart_waits_for_the_new_instance_not_the_departing_one(fake_home):
    import os
    app.runtime_file().write_text(json.dumps({
        "pid": os.getpid(), "url": "http://127.0.0.1:9/?t=old",
    }))

    assert app._await_report(timeout=0.5, exclude_pid=os.getpid()) is None


def test_an_unmanaged_instance_is_stopped_before_a_new_one_starts(
    fake_home, monkeypatch
):
    import signal
    app.runtime_file().write_text(json.dumps({
        "pid": 4242, "url": "http://127.0.0.1:9/?t=x",
    }))

    signals: list[tuple[int, int]] = []
    monkeypatch.setattr(app.service, "restart", lambda: (False, "no service manager"))
    monkeypatch.setattr(app.service, "manager", lambda: None)
    monkeypatch.setattr(app.os, "kill", lambda pid, sig: signals.append((pid, sig)))
    monkeypatch.setattr(app, "_alive", lambda pid: not signals)
    monkeypatch.setattr(app.webbrowser, "open", lambda _url: None)
    started = []
    monkeypatch.setattr(app.App, "run", lambda self, **kw: started.append(True) or 0)

    assert app.main([]) == 0
    assert signals == [(4242, signal.SIGTERM)]
    assert started == [True]


def test_an_instance_that_will_not_stop_is_reported_rather_than_doubled(
    fake_home, monkeypatch, capsys
):
    app.runtime_file().write_text(json.dumps({
        "pid": 4242, "url": "http://127.0.0.1:9/?t=x",
    }))

    monkeypatch.setattr(app.service, "restart", lambda: (False, "no service manager"))
    monkeypatch.setattr(app, "_alive", lambda pid: True)
    monkeypatch.setattr(app, "_retire", lambda pid, **_kw: False)
    monkeypatch.setattr(app.App, "run", lambda self, **kw: (_ for _ in ()).throw(
        AssertionError("must not start a second instance")))

    assert app.main([]) == 1
    assert "would not restart" in capsys.readouterr().err


def test_a_stale_runtime_file_does_not_block_startup(fake_home, monkeypatch):
    app.runtime_file().write_text(json.dumps({
        "pid": 999_999_999, "url": "http://127.0.0.1:9/?t=x",
    }))

    started = []
    monkeypatch.setattr(app.App, "run",
                        lambda self, **kw: started.append(True) or 0)
    monkeypatch.setattr(app.webbrowser, "open", lambda _url: None)

    assert app.main([]) == 0
    assert started == [True]


def test_setup_runs_before_the_app_starts(fake_home, monkeypatch):
    monkeypatch.setattr(app.App, "run", lambda self, **kw: 0)
    monkeypatch.setattr(app.webbrowser, "open", lambda _url: None)

    app.main([])

    assert app.capture_is_live() is True
    assert install.status()[0]["events"]


def test_setup_puts_the_command_on_path(fake_home, monkeypatch):
    monkeypatch.setenv("PATH", str(fake_home / ".local" / "bin"))
    report = app.run_setup()

    link = fake_home / ".local" / "bin" / "xenia"
    assert link.is_symlink()
    assert link.resolve() == app._entry_point().resolve()
    assert report["path"]["linked"] == ["xenia", "xenia-mcp"]
    assert report["path"]["on_path"] is True


def test_linking_is_idempotent(fake_home):
    app.link_commands()
    again = app.link_commands()
    assert again["linked"] == []
    assert again["skipped"] == []


def test_a_name_already_taken_is_left_alone(fake_home):
    target = fake_home / ".local" / "bin"
    target.mkdir(parents=True)
    (target / "xenia").write_text("#!/bin/sh\necho someone else's\n")

    report = app.link_commands()

    assert (target / "xenia").read_text().startswith("#!/bin/sh")
    assert any("already exists" in note for note in report["skipped"])


def test_a_path_without_the_bin_dir_is_reported(fake_home, monkeypatch, capsys):
    monkeypatch.setenv("PATH", "/usr/bin:/bin")
    app._print_setup(app.run_setup(), first_run=True)
    assert "is not on your PATH" in capsys.readouterr().out


def test_the_entry_points_resolve_symlinks(fake_home):
    for name in ("xenia", "xenia-hook", "xenia-mcp"):
        body = (app._entry_point().parent / name).read_text()
        assert "os.path.realpath(__file__)" in body
        assert "os.path.abspath(__file__)" not in body


def test_adding_a_credential_is_still_a_terminal(fake_home, monkeypatch):
    """The value has to be typed without being echoed, which a menu cannot do."""
    from xenia import secrets as secrets_cli

    opened, launched = [], []
    monkeypatch.setattr(app.webbrowser, "open", opened.append)
    monkeypatch.setattr(secrets_cli, "open_in_terminal",
                        lambda command: launched.append(command) or True)

    add, _listing, _approvals, _delete = app.App().menu()[1].items
    add.action()

    assert opened == [], "a typed value does not go through the browser"
    assert launched and launched[0][-2:] == ["secret", "new"]


def test_listing_credentials_opens_the_tab_that_lists_them(fake_home,
                                                           monkeypatch):
    """The list is a page now: it stays open, and it is where one is removed."""
    from xenia import secrets as secrets_cli

    opened, launched = [], []
    monkeypatch.setattr(app.webbrowser, "open", opened.append)
    monkeypatch.setattr(secrets_cli, "open_in_terminal",
                        lambda command: launched.append(command) or True)

    instance = app.App()
    instance.report.start()
    try:
        wanted = instance.report.tab("credentials")
        instance.menu()[1].items[1].action()
    finally:
        instance.report.stop()

    assert launched == [], "no terminal window for a list"
    assert opened == [wanted]
    assert wanted.endswith("#credentials")


def test_deleting_asks_in_a_terminal_because_it_cannot_be_undone(fake_home,
                                                                 monkeypatch):
    from xenia import secrets as secrets_cli

    launched = []
    monkeypatch.setattr(secrets_cli, "open_in_terminal",
                        lambda command: launched.append(command) or True)

    app.App().menu()[1].items[3].action()

    assert launched and launched[0][-3:] == ["secret", "rm", "--wait"]


def test_no_terminal_says_what_to_run_instead(fake_home, monkeypatch):
    from xenia import broker as broker_module
    from xenia import secrets as secrets_cli

    told = []
    monkeypatch.setattr(secrets_cli, "open_in_terminal", lambda command: False)
    monkeypatch.setattr(broker_module, "_notify",
                        lambda summary, body: told.append(body))

    app.App().menu()[1].items[0].action()

    assert told and "xenia secret new" in told[0]


def test_a_backend_that_cannot_nest_gets_the_tree_flattened(fake_home):
    """The mac status item has no submenus, so it shows the leaves."""
    from xenia.tray import Tray

    labels = [item.label for item in Tray("xenia", app.App().menu()).flattened()]

    assert labels == ["Show Report", "Credentials: Add…",
                      "Credentials: List", "Credentials: Approvals…",
                      "Credentials: Delete…", "Quit xenia"]
