from __future__ import annotations

import os
import shutil
import subprocess
import sys
from pathlib import Path

from .readers import RETIRED_EXIT_STATUS

LABEL = "dev.xenia.tray"
UNIT_NAME = "xenia.service"


def manager() -> str | None:
    if sys.platform == "darwin":
        return "launchd" if shutil.which("launchctl") else None
    if sys.platform.startswith("linux"):
        if not shutil.which("systemctl"):
            return None
        try:
            probe = subprocess.run(["systemctl", "--user", "is-system-running"],
                                   capture_output=True, text=True, timeout=5)
            if probe.returncode != 0 and "offline" in (probe.stdout + probe.stderr):
                return None
        except (OSError, subprocess.SubprocessError):
            return None
        return "systemd"
    return None


def service_command() -> Path:
    from . import app
    return app._entry_point().with_name("xenia-service")


def unit_file() -> Path:
    base = os.environ.get("XDG_CONFIG_HOME") or (Path.home() / ".config")
    return Path(base) / "systemd" / "user" / UNIT_NAME


def plist_file() -> Path:
    return Path.home() / "Library" / "LaunchAgents" / f"{LABEL}.plist"


def autostart_file() -> Path:
    if sys.platform == "darwin":
        return plist_file()
    base = os.environ.get("XDG_CONFIG_HOME") or (Path.home() / ".config")
    return Path(base) / "autostart" / "xenia.desktop"


def write_autostart() -> Path:
    path = autostart_file()
    path.parent.mkdir(parents=True, exist_ok=True)

    if sys.platform == "darwin":
        _write_plist(path, keep_alive=False)
        return path

    path.write_text(
        "[Desktop Entry]\n"
        "Type=Application\n"
        "Name=xenia\n"
        "Comment=Record what coding agents do on this machine\n"
        f"Exec={service_command()}\n"
        "Terminal=false\n"
        "X-GNOME-Autostart-enabled=true\n"
    )
    return path


def _write_plist(path: Path, *, keep_alive: bool) -> None:
    import plistlib

    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("wb") as handle:
        plistlib.dump({
            "Label": LABEL,
            "ProgramArguments": [str(service_command())],
            "RunAtLoad": True,
            "KeepAlive": keep_alive,
            "ProcessType": "Interactive",
        }, handle)


def _write_unit(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        "[Unit]\n"
        "Description=xenia — record what coding agents do on this machine\n"
        "After=graphical-session.target\n"
        "\n"
        "[Service]\n"
        "Type=simple\n"
        f"ExecStart={service_command()}\n"
        "Restart=on-failure\n"
        "RestartSec=5\n"
        # Retired by a schema migration. Forced so it comes back on the new
        # code, and successful so that stopping it deliberately — which sends
        # the same signal — leaves the unit inactive rather than failed.
        f"SuccessExitStatus={RETIRED_EXIT_STATUS}\n"
        f"RestartForceExitStatus={RETIRED_EXIT_STATUS}\n"
        "\n"
        "[Install]\n"
        "WantedBy=default.target\n"
    )


def _run(args: list[str]) -> tuple[bool, str]:
    try:
        done = subprocess.run(args, capture_output=True, text=True, timeout=30)
        return done.returncode == 0, (done.stderr or done.stdout).strip()
    except (OSError, subprocess.SubprocessError) as exc:
        return False, str(exc)


def install() -> dict:
    kind = manager()
    report: dict = {"manager": kind, "started": False, "detail": "", "unit": None}

    if kind == "systemd":
        path = unit_file()
        _write_unit(path)
        report["unit"] = str(path)
        _run(["systemctl", "--user", "daemon-reload"])
        ok, detail = _run(["systemctl", "--user", "enable", "--now", UNIT_NAME])
        report["started"] = ok and is_running()
        report["detail"] = detail if not ok else f"systemd user unit {UNIT_NAME}"
        _remove_autostart()
        return report

    if kind == "launchd":
        path = plist_file()
        _write_plist(path, keep_alive=True)
        report["unit"] = str(path)
        uid = os.getuid()
        ok, detail = _run(["launchctl", "bootstrap", f"gui/{uid}", str(path)])
        if not ok:
            ok, detail = _run(["launchctl", "load", "-w", str(path)])
        report["started"] = ok or is_running()
        report["detail"] = detail if not ok else f"launchd agent {LABEL}"
        return report

    report["unit"] = str(write_autostart())
    report["detail"] = "no service manager — starting in the foreground"
    return report


def _remove_autostart() -> None:
    try:
        autostart_file().unlink(missing_ok=True)
    except OSError:
        pass


def is_running() -> bool:
    kind = manager()
    if kind == "systemd":
        ok, out = _run(["systemctl", "--user", "is-active", UNIT_NAME])
        return ok and out.strip() == "active"
    if kind == "launchd":
        ok, out = _run(["launchctl", "list", LABEL])
        return ok
    return False


def restart() -> tuple[bool, str]:
    """Ask the service manager to start the unit again on the current code.

    A running process holds the code it started with, so this is what `xenia`
    does when it finds one — it is nearly always typed by someone who has just
    changed something. False means there was nothing to restart, and the caller
    has to retire the process itself.
    """
    kind = manager()
    if kind == "systemd":
        ok, detail = _run(["systemctl", "--user", "restart", UNIT_NAME])
        return ok, (detail if not ok else f"systemd user unit {UNIT_NAME}")

    if kind == "launchd":
        uid = os.getuid()
        ok, detail = _run(
            ["launchctl", "kickstart", "-k", f"gui/{uid}/{LABEL}"])
        if not ok:
            _run(["launchctl", "bootout", f"gui/{uid}/{LABEL}"])
            ok, detail = _run(["launchctl", "bootstrap", f"gui/{uid}",
                               str(plist_file())])
        return ok, (detail if not ok else f"launchd agent {LABEL}")

    return False, "no service manager"


def stop() -> bool:
    kind = manager()
    if kind == "systemd":
        return _run(["systemctl", "--user", "disable", "--now", UNIT_NAME])[0]
    if kind == "launchd":
        ok, _ = _run(["launchctl", "bootout", f"gui/{os.getuid()}/{LABEL}"])
        if not ok:
            ok, _ = _run(["launchctl", "unload", "-w", str(plist_file())])
        return ok
    return False
