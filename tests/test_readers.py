from __future__ import annotations

import os
import signal
import subprocess
import sys
import time
from pathlib import Path

import pytest

from xenia import config, db, mcp, readers


@pytest.fixture
def registry(tmp_path, monkeypatch):
    monkeypatch.setenv("XENIA_READER_DIR", str(tmp_path / "readers"))
    return tmp_path / "readers"


@pytest.fixture
def sleeper(tmp_path):
    started: list[subprocess.Popen] = []

    def spawn():
        proc = subprocess.Popen(
            [sys.executable, "-c",
             "import time,sys; sys.argv[0]='xenia-mcp'; time.sleep(30)"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        started.append(proc)
        return proc

    yield spawn
    for proc in started:
        if proc.poll() is None:
            proc.kill()
        proc.wait(timeout=5)


def test_a_migration_retires_a_reader_left_behind(registry, sleeper):
    proc = sleeper()
    readers.register(config.SCHEMA_VERSION - 1, pid=proc.pid)

    retired = readers.retire_stale(config.SCHEMA_VERSION)

    assert retired == [proc.pid]
    assert proc.wait(timeout=5) is not None, "SIGTERM reached it"
    assert not list(registry.glob("*.json")), "its entry is cleaned up too"


def test_a_current_reader_is_left_alone(registry, sleeper):
    proc = sleeper()
    readers.register(config.SCHEMA_VERSION, pid=proc.pid)

    assert readers.retire_stale(config.SCHEMA_VERSION) == []
    assert proc.poll() is None, "still serving"


def test_a_recycled_pid_is_not_signalled(registry, monkeypatch):
    readers.register(config.SCHEMA_VERSION - 1, pid=4242)
    monkeypatch.setattr(readers, "_cmdline", lambda pid: "/usr/bin/postgres -D /var/lib/pg")
    killed = []
    monkeypatch.setattr(os, "kill", lambda pid, sig: killed.append(pid))

    assert readers.retire_stale(config.SCHEMA_VERSION) == []
    assert killed == []


def test_a_dead_reader_is_pruned_not_signalled(registry, monkeypatch):
    readers.register(config.SCHEMA_VERSION - 1, pid=4243)
    monkeypatch.setattr(readers, "_cmdline", lambda pid: None)
    killed = []
    monkeypatch.setattr(os, "kill", lambda pid, sig: killed.append(pid))

    assert readers.retire_stale(config.SCHEMA_VERSION) == []
    assert killed == []
    assert not list(registry.glob("*.json"))


def test_the_migrator_retires_readers_after_it_commits(registry, sleeper, tmp_path):
    proc = sleeper()
    readers.register(config.SCHEMA_VERSION - 1, pid=proc.pid)

    conn = db.connect(tmp_path / "fresh.db")
    conn.close()

    assert proc.wait(timeout=5) is not None


def test_a_migration_that_changes_nothing_retires_nobody(registry, sleeper, tmp_path):
    path = tmp_path / "fresh.db"
    db.connect(path).close()

    proc = sleeper()
    readers.register(config.SCHEMA_VERSION - 1, pid=proc.pid)
    db.connect(path).close()

    assert proc.poll() is None


def test_a_retirement_is_recorded_where_it_can_be_found(registry, sleeper, tmp_path):
    proc = sleeper()
    readers.register(config.SCHEMA_VERSION - 1, pid=proc.pid)

    conn = db.connect(tmp_path / "fresh.db")
    try:
        row = conn.execute(
            "SELECT stage, detail FROM ingest_error ORDER BY id DESC LIMIT 1"
        ).fetchone()
    finally:
        conn.close()

    assert row is not None, "nothing was written about it"
    assert row["stage"] == "reader"
    assert str(proc.pid) in row["detail"]
    assert str(config.SCHEMA_VERSION) in row["detail"]
    assert "restart" in row["detail"]


def test_the_retirement_note_also_reaches_the_log(registry, sleeper, tmp_path,
                                                  monkeypatch):
    log = tmp_path / "state" / "hook-errors.log"
    monkeypatch.setenv("XENIA_FALLBACK_LOG", str(log))
    monkeypatch.setenv("XENIA_READER_DIR", str(tmp_path / "readers"))

    proc = sleeper()
    readers.register(config.SCHEMA_VERSION - 1, pid=proc.pid)
    db.connect(tmp_path / "fresh.db").close()

    assert log.exists(), "no line was written"
    assert str(proc.pid) in log.read_text()


def test_nothing_is_recorded_when_nobody_was_retired(registry, tmp_path):
    conn = db.connect(tmp_path / "fresh.db")
    try:
        n = conn.execute("SELECT COUNT(*) AS n FROM ingest_error "
                         "WHERE stage = 'reader'").fetchone()["n"]
    finally:
        conn.close()
    assert n == 0


def test_the_report_registers_itself_while_it_serves(fake_home, monkeypatch):
    from xenia import app, tray as tray_mod

    seen: list[dict] = []

    class Tray:
        def __init__(self, name, menu):
            pass

        def every(self, seconds, action):
            pass

        def start(self):
            seen.extend(readers.registered())

        def stop(self):
            pass

    monkeypatch.setattr(tray_mod, "Tray", Tray)
    instance = app.App()
    try:
        assert instance.run() == 0
    finally:
        instance.report.stop()

    assert [(row["pid"], row["schema_version"]) for row in seen] == [
        (os.getpid(), config.SCHEMA_VERSION)], "not registered while serving"
    assert not list(readers.registry_dir().glob("*.json")), "left behind on exit"


def test_the_report_asks_to_be_started_again_when_it_is_retired(fake_home, capsys):
    from xenia import app

    previous = signal.getsignal(signal.SIGTERM)
    try:
        app._come_back_on_retirement()
        handler = signal.getsignal(signal.SIGTERM)
        assert callable(handler), "no handler was installed"

        with pytest.raises(SystemExit) as exit_info:
            handler(signal.SIGTERM, None)
    finally:
        signal.signal(signal.SIGTERM, previous)

    assert exit_info.value.code == readers.RETIRED_EXIT_STATUS, \
        "the service unit is written to expect exactly this status back"
    said = capsys.readouterr().err
    assert "not an error" in said, "a retirement is expected, and has to read that way"


def test_a_retired_reader_says_why_on_its_way_out(monkeypatch, capsys):
    import signal as signal_mod

    previous = signal_mod.getsignal(signal_mod.SIGTERM)
    try:
        mcp._announce_retirement_on_sigterm()
        handler = signal_mod.getsignal(signal_mod.SIGTERM)
        assert callable(handler), "no handler was installed"

        with pytest.raises(SystemExit) as exit_info:
            handler(signal_mod.SIGTERM, None)
    finally:
        signal_mod.signal(signal_mod.SIGTERM, previous)

    assert exit_info.value.code == 128 + signal_mod.SIGTERM
    said = capsys.readouterr().err
    assert "xenia-mcp" in said
    assert "not an error" in said, "a retirement is expected, and has to read that way"
    assert "Restart" in said
