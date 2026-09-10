from __future__ import annotations

import ast
import ctypes.util
import pathlib
import sys

import pytest


from xenia import app, tray

SRC = pathlib.Path(__file__).resolve().parents[1] / "src" / "xenia"

STDLIB = {
    "argparse", "ast", "base64", "contextlib", "ctypes", "dataclasses",
    "datetime", "decimal", "fnmatch", "getpass", "hashlib", "hmac", "http", "io",
    "ipaddress", "json", "os", "pathlib", "platform",
    "plistlib", "posixpath", "re", "secrets", "shlex", "shutil", "signal",
    "socket", "ssl",
    "sqlite3", "struct", "subprocess", "sys", "threading", "time", "typing",
    "urllib", "webbrowser", "zlib",
}


def imported_modules(path: pathlib.Path) -> set[str]:
    tree = ast.parse(path.read_text())
    found = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            found.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            if node.level == 0 and node.module:
                found.add(node.module.split(".")[0])
    return found


@pytest.mark.parametrize("source", sorted(SRC.glob("*.py")), ids=lambda p: p.name)
def test_no_module_imports_anything_outside_the_standard_library(source):
    outside = imported_modules(source) - STDLIB - {"xenia", "__future__"}
    assert not outside, (
        f"{source.name} imports {sorted(outside)}, which would make xenia "
        f"depend on something a fresh machine may not have"
    )


def test_the_hook_never_reaches_for_a_desktop():
    forbidden = {"tray", "tray_linux", "tray_macos", "report", "icon",
                 "dbus", "ctypes"}
    tree = ast.parse((SRC / "hook.py").read_text())

    reached = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.level:
            reached.update(alias.name for alias in node.names)
        elif isinstance(node, ast.Import):
            reached.update(alias.name.split(".")[0] for alias in node.names)

    assert not (reached & forbidden)


def a_tray():
    return tray.Tray("xenia", [tray.MenuItem("Quit", lambda: None)])


def test_an_unsupported_platform_degrades_rather_than_crashing(monkeypatch):
    monkeypatch.setattr(sys, "platform", "sunos5")
    with pytest.raises(tray.Unavailable, match="sunos5"):
        a_tray().start()


def test_available_is_false_on_an_unsupported_platform(monkeypatch):
    monkeypatch.setattr(sys, "platform", "sunos5")
    assert tray.available() is False


def test_the_backend_follows_the_platform(monkeypatch):
    monkeypatch.setattr(sys, "platform", "darwin")
    from xenia import tray_macos
    assert tray._backend.__module__
    monkeypatch.setattr(tray_macos, "Backend", lambda owner: "macos-backend")
    assert tray._backend(a_tray()) == "macos-backend"

    monkeypatch.setattr(sys, "platform", "linux")
    from xenia import tray_linux
    monkeypatch.setattr(tray_linux, "Backend", lambda owner: "linux-backend")
    assert tray._backend(a_tray()) == "linux-backend"


def test_the_macos_backend_refuses_to_run_off_macos():
    from xenia import tray_macos
    assert tray_macos.available() is False
    with pytest.raises(tray.Unavailable, match="only runs on macOS"):
        tray_macos.Backend(a_tray()).start()


def test_linux_autostart_is_an_xdg_desktop_entry(fake_home, monkeypatch):
    monkeypatch.setattr(sys, "platform", "linux")
    path = app.write_autostart()

    assert path.suffix == ".desktop"
    assert path.parent == fake_home / ".config" / "autostart"
    body = path.read_text()
    assert "[Desktop Entry]" in body
    assert next(l for l in body.splitlines() if l.startswith("Exec=")).split("=", 1)[1].startswith("/")


def test_macos_autostart_is_a_launch_agent_plist(fake_home, monkeypatch):
    import plistlib

    monkeypatch.setattr(sys, "platform", "darwin")
    path = app.write_autostart()

    assert path.parent == fake_home / "Library" / "LaunchAgents"
    plist = plistlib.loads(path.read_bytes())
    assert plist["Label"] == app.LAUNCH_AGENT_LABEL
    assert plist["RunAtLoad"] is True
    assert plist["KeepAlive"] is False
    assert plist["ProgramArguments"][0].endswith("xenia-service")


def test_the_two_platforms_do_not_share_a_path(fake_home, monkeypatch):
    monkeypatch.setattr(sys, "platform", "linux")
    linux_path = app.autostart_file()
    monkeypatch.setattr(sys, "platform", "darwin")
    assert app.autostart_file() != linux_path


@pytest.mark.parametrize("name", ["xenia", "xenia-hook", "xenia-mcp"])
def test_every_entry_point_checks_the_python_version(name):
    body = (SRC.parents[1] / "bin" / name).read_text()
    assert "sys.version_info < (3, 11)" in body


def test_the_hook_exits_zero_even_on_an_unusable_python():
    body = (SRC.parents[1] / "bin" / "xenia-hook").read_text()
    version_guard = body.split("sys.version_info < (3, 11)")[1].split("\n\n")[0]
    assert "SystemExit(0)" in version_guard
