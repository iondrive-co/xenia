from __future__ import annotations

import json
import os
import signal
import sys
import webbrowser
from pathlib import Path

from . import config, db, install, readers, report as report_mod, service

STATE_DIR_NAME = "xenia"


def _state_dir() -> Path:
    base = os.environ.get("XDG_STATE_HOME") or (Path.home() / ".local" / "state")
    path = Path(base) / STATE_DIR_NAME
    path.mkdir(parents=True, exist_ok=True)
    return path


def runtime_file() -> Path:
    return _state_dir() / "runtime.json"


def setup_marker() -> Path:
    return _state_dir() / "setup.json"


def _read_runtime() -> dict:
    try:
        return json.loads(runtime_file().read_text())
    except Exception:
        return {}


def _release_runtime() -> None:
    try:
        current = _read_runtime()
        if current.get("pid") in (None, os.getpid()):
            runtime_file().unlink(missing_ok=True)
    except Exception:
        pass


def _alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
        return True
    except (ProcessLookupError, ValueError, TypeError):
        return False
    except PermissionError:
        return True


LAUNCH_AGENT_LABEL = service.LABEL

autostart_file = service.autostart_file
write_autostart = service.write_autostart


def _entry_point() -> Path:
    candidate = Path(__file__).resolve().parents[2] / "bin" / "xenia"
    if candidate.exists():
        return candidate
    found = shutil_which("xenia")
    return Path(found) if found else candidate


def shutil_which(name: str) -> str | None:
    import shutil
    return shutil.which(name)


def register_mcp() -> dict:
    target = Path.home() / ".claude.json"
    server = {
        "type": "stdio",
        "command": str(_entry_point().with_name("xenia-mcp")),
        "args": [],
        "env": {},
    }

    current: dict = {}
    if target.exists():
        try:
            current = json.loads(target.read_text() or "{}")
        except ValueError as exc:
            return {"ok": False, "detail": f"{target} is not valid JSON: {exc}"}
        if not isinstance(current, dict):
            return {"ok": False, "detail": f"{target} is not a JSON object"}

    servers = current.get("mcpServers")
    if not isinstance(servers, dict):
        servers = {}
    if servers.get("xenia") == server:
        return {"ok": True, "detail": "already registered", "changed": False}

    if target.exists():
        backup = target.with_suffix(".json.xenia-backup")
        backup.write_text(target.read_text())

    servers["xenia"] = server
    current["mcpServers"] = servers
    target.write_text(json.dumps(current, indent=2) + "\n")
    return {"ok": True, "detail": str(target), "changed": True}


def bin_dir() -> Path:
    return Path.home() / ".local" / "bin"


def link_commands() -> dict:
    source_dir = _entry_point().parent
    target_dir = bin_dir()
    out: dict = {"dir": str(target_dir), "linked": [], "skipped": [], "on_path": True}

    if not (source_dir / "xenia").exists():
        out["skipped"].append("installed as a package — nothing to link")
        return out

    target_dir.mkdir(parents=True, exist_ok=True)
    for name in ("xenia", "xenia-mcp"):
        source = source_dir / name
        target = target_dir / name
        try:
            if target.is_symlink() and target.resolve() == source.resolve():
                continue
            if target.exists() or target.is_symlink():
                out["skipped"].append(f"{target} already exists and is not ours")
                continue
            target.symlink_to(source)
            out["linked"].append(name)
        except OSError as exc:
            out["skipped"].append(f"{target}: {exc}")

    path_entries = (os.environ.get("PATH") or "").split(os.pathsep)
    out["on_path"] = str(target_dir) in path_entries
    return out


def hook_path() -> Path:
    return _entry_point().with_name("xenia-hook")


def ensure_capture() -> list[dict]:
    return install.apply(install.machine_targets(), hook_path())


def capture_is_live() -> bool:
    return any(item["events"] for item in install.status())


def run_setup() -> dict:
    report: dict = {}

    conn = db.connect()
    conn.close()
    report["database"] = str(config.db_path())

    report["capture"] = ensure_capture()
    report["mcp"] = register_mcp()
    report["path"] = link_commands()
    report["service"] = service.install()
    report["autostart"] = report["service"]["unit"]

    setup_marker().write_text(json.dumps({
        "entry_point": str(_entry_point()),
        "database": str(config.db_path()),
    }, indent=2) + "\n")
    return report


def _print_setup(report: dict, *, first_run: bool) -> None:
    print("Setting up xenia on this machine.\n" if first_run
          else "Checking xenia's setup on this machine.\n")

    for item in report["capture"]:
        state = ("installed " + ", ".join(item["added"])) if item["added"] else "already wired up"
        if item["error"]:
            state = f"FAILED — {item['error']}"
        print(f"  {item['runtime']:7} {state}")
        print(f"          {item['path']}")
    print(f"\n  database    {report['database']}")
    print(f"  autostart   {report['autostart']}")
    mcp = report["mcp"]
    print(f"  mcp server  {'registered — ' if mcp['ok'] else 'NOT registered — '}{mcp['detail']}")

    svc = report["service"]
    if svc["manager"]:
        print(f"  service     {svc['detail']}"
              f"{'' if svc['started'] else '  (NOT started)'}")

    path = report["path"]
    if path["linked"]:
        print(f"  on PATH     {', '.join(path['linked'])} -> {path['dir']}")
    for note in path["skipped"]:
        print(f"  on PATH     skipped: {note}")

    from . import tray
    if not tray.available():
        print("\n  No tray icon on this system — the report and the recording "
              "work regardless.")

    if not path["on_path"]:
        print(f"\n  {path['dir']} is not on your PATH. Add it to run xenia by "
              f"name:\n    export PATH=\"{path['dir']}:$PATH\"")

    print("\nRecording started.\n")

    sys.stdout.flush()


def _come_back_on_retirement() -> None:
    """Ask to be started again when a migration retires this process.

    The report is a reader like any other, so a schema bump SIGTERMs it. The
    exit status is what decides whether it comes back: a service manager
    ignores a clean exit, and does not restart a stop it asked for itself, so
    leaving non-zero is restarted on the new code while `systemctl stop` still
    stops. Recording is unaffected either way — that is the hook's job, and the
    hook is a fresh process every time.
    """
    def farewell(signum, _frame):
        try:
            sys.stderr.write(
                f"xenia: exiting on signal {signum}. If a schema migration "
                f"retired this process (it was built for schema "
                f"{config.SCHEMA_VERSION}), that is expected and not an error, "
                f"and it will be started again on the new code. Nothing stopped "
                f"being recorded.\n")
            sys.stderr.flush()
        except Exception:
            pass
        _release_runtime()
        readers.unregister()
        raise SystemExit(128 + signum)

    try:
        signal.signal(signal.SIGTERM, farewell)
    except (ValueError, OSError):
        pass


class App:
    def __init__(self) -> None:
        self.report = report_mod.Report()
        self.tray = None


    def menu(self):
        from .tray import MenuItem
        return [
            MenuItem("Show Report", self.show_report),
            MenuItem("Quit xenia", self.quit),
        ]

    def show_report(self) -> None:
        webbrowser.open(self.report.url)

    def quit(self) -> None:
        _release_runtime()
        self.report.stop()
        if self.tray is not None:
            self.tray.stop()

    def publish_anchor(self) -> bool:
        from . import chain
        try:
            conn = db.connect()
            try:
                chain.anchor(conn)
            finally:
                conn.close()
        except Exception:
            pass
        return True


    def run(self, *, show_report: bool = False) -> int:
        from . import tray as tray_mod

        self.report.start()
        readers.register(config.SCHEMA_VERSION)
        _come_back_on_retirement()
        runtime_file().write_text(json.dumps({
            "pid": os.getpid(), "url": self.report.url,
        }, indent=2) + "\n")
        if show_report:
            self.show_report()

        try:
            self.tray = tray_mod.Tray("xenia", self.menu())
            self.tray.every(60, self.publish_anchor)
            self.tray.start()
        except tray_mod.Unavailable as exc:
            print(f"No tray icon on this desktop: {exc}", file=sys.stderr)
            print(f"Report: {self.report.url}", file=sys.stderr)
            try:
                import time
                while True:
                    time.sleep(3600)
            except KeyboardInterrupt:
                pass
        finally:
            readers.unregister()
            _release_runtime()
        return 0


def main(argv: list[str] | None = None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    if argv:
        print("xenia takes no arguments.\n\n"
              "  xenia            set up on first run, then open the report\n\n"
              "Everything else is in the report itself, or in the read-only "
              "MCP server (xenia-mcp).", file=sys.stderr)
        return 2

    running = _read_runtime()
    if running.get("url") and _alive(running.get("pid", -1)):
        webbrowser.open(running["url"])
        print(f"xenia is already running. Report: {running['url']}")
        return 0

    first_run = not setup_marker().exists()
    setup = run_setup()
    _print_setup(setup, first_run=first_run)

    if setup["service"]["started"]:
        url = _await_report()
        if url:
            webbrowser.open(url)
            print(f"Report: {url}")
        return 0

    print(f"  Running in this terminal — {setup['service']['detail']}.\n"
          f"  Closing it stops the tray and the report; recording continues, "
          f"since that is the hook's job.\n")
    sys.stdout.flush()
    return App().run(show_report=True)


def _await_report(timeout: float = 10.0) -> str | None:
    import time

    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        running = _read_runtime()
        if running.get("url") and _alive(running.get("pid", -1)):
            return running["url"]
        time.sleep(0.25)
    return None


if __name__ == "__main__":
    raise SystemExit(main())
