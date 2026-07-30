from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest
from conftest import CORE

from xenia import db, hook

ROOT = Path(__file__).resolve().parents[1]
HOOK_BIN = ROOT / "bin" / "xenia-hook"


@pytest.fixture
def hook_env(tmp_path, monkeypatch):
    monkeypatch.setenv("XENIA_DB", str(tmp_path / "audit.db"))
    monkeypatch.setenv("XENIA_FALLBACK_LOG", str(tmp_path / "errors.log"))
    monkeypatch.delenv("XENIA_DEBUG", raising=False)
    return tmp_path


def feed(payload: str, monkeypatch) -> int:
    monkeypatch.setattr("sys.stdin", _FakeStdin(payload))
    return hook.main([])


class _FakeStdin:
    def __init__(self, text: str) -> None:
        self.text = text

    def read(self) -> str:
        return self.text


def test_a_normal_payload_is_recorded(hook_env, monkeypatch):
    payload = {"hook_event_name": "PreToolUse", "session_id": "s1",
               "cwd": CORE, "tool_name": "Bash",
               "tool_input": {"command": "ls"}}
    assert feed(json.dumps(payload), monkeypatch) == 0

    conn = db.connect(hook_env / "audit.db")
    assert conn.execute("SELECT COUNT(*) AS n FROM event").fetchone()["n"] == 1


@pytest.mark.parametrize(
    "payload",
    [
        "",
        "   \n",
        "not json at all",
        "[1, 2, 3]",
        '{"unclosed": ',
        "\x00\xff binary",
    ],
)
def test_malformed_input_never_fails_the_hook(payload, hook_env, monkeypatch):
    assert feed(payload, monkeypatch) == 0


def test_an_unreadable_database_falls_back_to_a_log(tmp_path, monkeypatch):
    monkeypatch.setenv("XENIA_DB", str(tmp_path / "nope" / "audit.db"))
    monkeypatch.setenv("XENIA_FALLBACK_LOG", str(tmp_path / "errors.log"))
    (tmp_path / "nope").write_text("this is a file, not a directory")

    assert feed('{"hook_event_name": "PreToolUse"}', monkeypatch) == 0
    assert (tmp_path / "errors.log").exists()
    assert "store" in (tmp_path / "errors.log").read_text()


def test_the_event_name_can_come_from_the_command_line(hook_env, monkeypatch):
    monkeypatch.setattr("sys.stdin", _FakeStdin('{"session_id": "s1", "cwd": "/tmp"}'))
    assert hook.main(["SessionStart"]) == 0

    conn = db.connect(hook_env / "audit.db")
    assert conn.execute("SELECT hook FROM event").fetchone()["hook"] == "SessionStart"


def test_a_payload_name_wins_over_the_argument(hook_env, monkeypatch):
    monkeypatch.setattr("sys.stdin", _FakeStdin(
        '{"hook_event_name": "PostToolUse", "session_id": "s1", "cwd": "/tmp"}'))
    assert hook.main(["PreToolUse"]) == 0

    conn = db.connect(hook_env / "audit.db")
    assert conn.execute("SELECT hook FROM event").fetchone()["hook"] == "PostToolUse"


def test_the_binary_writes_nothing_to_stdout(tmp_path):
    result = subprocess.run(
        [sys.executable, str(HOOK_BIN), "PreToolUse"],
        input=json.dumps({"hook_event_name": "PreToolUse", "session_id": "s1",
                          "cwd": CORE, "tool_name": "Bash",
                          "tool_input": {"command": "ls"}}),
        text=True, capture_output=True,
        env={"PATH": "/usr/bin:/bin", "XENIA_DB": str(tmp_path / "a.db"),
             "XENIA_FALLBACK_LOG": str(tmp_path / "e.log"),
             "HOME": str(tmp_path)},
    )
    assert result.returncode == 0
    assert result.stdout == ""


def test_the_binary_exits_zero_on_garbage(tmp_path):
    result = subprocess.run(
        [sys.executable, str(HOOK_BIN), "PreToolUse"],
        input="}{ not json", text=True, capture_output=True,
        env={"PATH": "/usr/bin:/bin", "XENIA_DB": str(tmp_path / "a.db"),
             "XENIA_FALLBACK_LOG": str(tmp_path / "e.log"),
             "HOME": str(tmp_path)},
    )
    assert result.returncode == 0
    assert result.stdout == ""


def test_concurrent_hooks_do_not_fork_the_chain(tmp_path, monkeypatch):
    key_file = str(tmp_path / "ledger.key")
    monkeypatch.delenv("XENIA_LEDGER_KEY", raising=False)
    monkeypatch.setenv("XENIA_LEDGER_KEY_FILE", key_file)

    env = {"PATH": "/usr/bin:/bin", "XENIA_DB": str(tmp_path / "a.db"),
           "XENIA_FALLBACK_LOG": str(tmp_path / "e.log"), "HOME": str(tmp_path),
           "XENIA_LEDGER_KEY_FILE": key_file}
    payloads = [
        json.dumps({"hook_event_name": "PreToolUse", "session_id": f"s{i}",
                    "cwd": CORE, "tool_name": "Bash",
                    "tool_input": {"command": f"echo {i}"}})
        for i in range(12)
    ]

    procs = [
        subprocess.Popen([sys.executable, str(HOOK_BIN), "PreToolUse"],
                         stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                         stderr=subprocess.PIPE, text=True, env=env)
        for _ in payloads
    ]
    for proc, payload in zip(procs, payloads):
        proc.communicate(payload)
    for proc in procs:
        assert proc.returncode == 0

    from xenia import chain
    chain.reset_key_cache()

    conn = db.connect(tmp_path / "a.db")
    assert conn.execute("SELECT COUNT(*) AS n FROM event").fetchone()["n"] == 12
    assert chain.verify(conn).ok
