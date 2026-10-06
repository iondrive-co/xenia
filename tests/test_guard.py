from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest
from conftest import SHOP

from xenia import db, guard

ROOT = Path(__file__).resolve().parents[1]
HOOK_BIN = ROOT / "bin" / "xenia-hook"
GUARD_BIN = ROOT / "bin" / "xenia-guard"


@pytest.fixture
def guard_env(tmp_path, monkeypatch):
    monkeypatch.setenv("XENIA_DB", str(tmp_path / "audit.db"))
    monkeypatch.setenv("XENIA_FALLBACK_LOG", str(tmp_path / "errors.log"))
    monkeypatch.delenv("XENIA_DEBUG", raising=False)
    monkeypatch.setenv("XENIA_GUARD_HELD", str(tmp_path / "held"))
    return tmp_path


class _Stdin:
    def __init__(self, text: str) -> None:
        self.text = text

    def read(self) -> str:
        return self.text


def said(command, monkeypatch, capsys, event="PreToolUse"):
    payload = {"hook_event_name": event, "session_id": "s1", "cwd": SHOP,
               "tool_name": "Bash", "tool_input": {"command": command}}
    monkeypatch.setattr("sys.stdin", _Stdin(json.dumps(payload)))
    assert guard.main([]) == 0
    out = capsys.readouterr().out
    return json.loads(out)["hookSpecificOutput"] if out.strip() else None


def test_a_self_matching_kill_is_refused(guard_env, monkeypatch, capsys):
    spoken = said("pkill -f worker.sh", monkeypatch, capsys)
    assert spoken["permissionDecision"] == "deny"
    assert "pkill -A -f worker.sh" in spoken["permissionDecisionReason"]


def test_a_refusal_is_not_also_a_nudge(guard_env, monkeypatch, capsys):
    # A heavy command that also kills its own shell: the refusal is the answer.
    spoken = said("pkill -f pytest; python3 -m pytest -q", monkeypatch, capsys)
    assert spoken["permissionDecision"] == "deny"
    assert "additionalContext" not in spoken


def test_a_heavy_command_is_nudged_about_the_agora(guard_env, monkeypatch, capsys):
    spoken = said("python3 -m pytest -q", monkeypatch, capsys)
    assert "permissionDecision" not in spoken
    assert "xenia_claim" in spoken["additionalContext"]


def test_it_records_nothing(guard_env, monkeypatch, capsys):
    said("python3 -m pytest -q", monkeypatch, capsys)
    conn = db.connect(guard_env / "audit.db")
    assert conn.execute("SELECT COUNT(*) AS n FROM event").fetchone()["n"] == 0


def test_only_pre_tool_use_is_answered(guard_env, monkeypatch, capsys):
    assert said("pkill -f worker.sh", monkeypatch, capsys, event="PostToolUse") is None


def test_a_kill_of_the_cli_is_held_once_then_runs(guard_env, monkeypatch, capsys):
    from test_relatives import FakeTree

    monkeypatch.setattr("xenia.relatives.Tree", FakeTree)
    monkeypatch.setattr("xenia.ingest.detect_agent", lambda _payload: "claude")
    first = said("kill $PPID", monkeypatch, capsys)
    assert first["permissionDecision"] == "deny"
    assert "run exactly the same command again" in first["permissionDecisionReason"]
    assert said("kill $PPID", monkeypatch, capsys) is None
    assert said("kill $PPID", monkeypatch, capsys)["permissionDecision"] == "deny"


@pytest.mark.parametrize("broken, command", [
    ("xenia.selfmatch.check", "pkill -f worker.sh"),
    ("xenia.agora.nudge", "python3 -m pytest -q"),
    ("xenia.relatives.warning", "kill $PPID"),
])
def test_nothing_that_breaks_here_costs_the_call(broken, command, guard_env, monkeypatch, capsys):
    def explode(*_args, **_kw):
        raise RuntimeError("broken today")

    monkeypatch.setattr(broken, explode)
    assert said(command, monkeypatch, capsys) is None
    assert "broken today" in (guard_env / "errors.log").read_text()


@pytest.mark.parametrize("payload", ["", "not json", "[1, 2]", '{"unclosed": '])
def test_malformed_input_is_silent(payload, guard_env, monkeypatch, capsys):
    monkeypatch.setattr("sys.stdin", _Stdin(payload))
    assert guard.main([]) == 0
    assert capsys.readouterr().out == ""


def test_the_binaries_side_by_side_nudge_once_a_session(tmp_path):
    """How the runtime runs them: both hooks, on every call, either one first.
    The nudge must come once whichever order the two land in."""
    env = {"PATH": "/usr/bin:/bin", "XENIA_DB": str(tmp_path / "a.db"),
           "XENIA_FALLBACK_LOG": str(tmp_path / "e.log"), "HOME": str(tmp_path)}

    def call(n: int, record_first: bool) -> str:
        payload = json.dumps({"hook_event_name": "PreToolUse", "session_id": "s1",
                              "cwd": SHOP, "tool_name": "Bash", "tool_use_id": f"toolu_{n}",
                              "tool_input": {"command": "python3 -m pytest -q"}})
        order = [HOOK_BIN, GUARD_BIN] if record_first else [GUARD_BIN, HOOK_BIN]
        out = ""
        for binary in order:
            done = subprocess.run([sys.executable, str(binary), "PreToolUse"],
                                  input=payload, text=True, capture_output=True, env=env)
            assert done.returncode == 0
            out += done.stdout
        return out

    first = call(1, record_first=True)
    assert "xenia_claim" in json.loads(first)["hookSpecificOutput"]["additionalContext"]
    assert call(2, record_first=False) == ""
    assert call(3, record_first=True) == ""
