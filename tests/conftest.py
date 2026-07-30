from __future__ import annotations

import json
import os
import shutil
import sys
import tempfile
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from xenia import classify as xclassify
from xenia import config as xconfig
from xenia import db as xdb

_SANDBOX = Path(tempfile.mkdtemp(prefix="xenia-tests-"))


def make_repo(path: Path) -> str:
    (path / ".git").mkdir(parents=True, exist_ok=True)
    (path / ".git" / "HEAD").write_text("ref: refs/heads/main\n")
    return str(path)


def _sandbox_repo(name: str) -> str:
    return make_repo(_SANDBOX / name)


CORE = _sandbox_repo("core")
OPS = _sandbox_repo("ops")

# Invented credentials, used only to prove that redaction catches them. Each is
# spliced together at import time so no line of this repo contains a string that
# a secret scanner will read as a live token.
FAKE_GITLAB_PAT = "glpat-" + "xK9dM2vQ7hL4nR8sT1wY"
FAKE_GITLAB_RUNNER_TOKEN = "glrt-" + "Ab3dEf6hIj9lMn2pQr5t"
FAKE_GITHUB_TOKEN = "ghp_" + "16CharsAndMoreABCDEFGHIJKLMNOP"
FAKE_SLACK_TOKEN = "xoxb-" + "123456789012-abcdefghijkl"
FAKE_AWS_KEY = "AKIA" + "IOSFODNN7EXAMPLE"
FAKE_ANTHROPIC_KEY = "sk-ant-" + "api03-abcdefghijklmnopqrstuvwxyz"
FAKE_GRAFANA_TOKEN = "glsa_" + "8Kd92nQmXr4vT7wLpY1cB6hN3fJ5sZ0a"


@pytest.fixture(scope="session", autouse=True)
def _tear_down_sandbox():
    yield
    shutil.rmtree(_SANDBOX, ignore_errors=True)


@pytest.fixture(autouse=True)
def clean_site_config(monkeypatch, tmp_path):
    monkeypatch.setenv("XENIA_CONFIG", str(tmp_path / "no-such-config.json"))
    from xenia import chain as _chain

    monkeypatch.setenv("XENIA_LEDGER_KEY", "test-ledger-key")
    monkeypatch.delenv("XENIA_LEDGER_ANCHOR", raising=False)
    _chain.reset_key_cache()
    monkeypatch.setenv("CLAUDE_CONFIG_DIR", str(tmp_path / "runtime" / "claude"))
    monkeypatch.setenv("CODEX_HOME", str(tmp_path / "runtime" / "codex"))
    xconfig.reset_cache()
    xclassify.reset_cache()
    yield
    xconfig.reset_cache()
    xclassify.reset_cache()


@pytest.fixture
def site_config(tmp_path, monkeypatch):
    def write(payload: dict) -> Path:
        path = tmp_path / "config.json"
        path.write_text(json.dumps(payload))
        monkeypatch.setenv("XENIA_CONFIG", str(path))
        xconfig.reset_cache()
        xclassify.reset_cache()
        return path

    return write


@pytest.fixture
def fake_home(tmp_path, monkeypatch):
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("XDG_CONFIG_HOME", str(home / ".config"))
    monkeypatch.setenv("XDG_DATA_HOME", str(home / ".local" / "share"))
    monkeypatch.setenv("XDG_STATE_HOME", str(home / ".local" / "state"))
    monkeypatch.delenv("CLAUDE_CONFIG_DIR", raising=False)
    monkeypatch.delenv("CODEX_HOME", raising=False)
    monkeypatch.delenv("XENIA_DB", raising=False)

    from xenia import service
    monkeypatch.setattr(service, "manager", lambda: None)
    return home


@pytest.fixture
def outside_any_repo(tmp_path, monkeypatch):
    ambient = set()
    probe = tmp_path
    while True:
        candidate = probe / ".git"
        if candidate.exists():
            ambient.add(str(candidate))
        if probe.parent == probe:
            break
        probe = probe.parent

    real_exists = os.path.exists
    monkeypatch.setattr(
        os.path, "exists", lambda p: False if str(p) in ambient else real_exists(p)
    )

    loose = tmp_path / "scratch"
    loose.mkdir()
    return loose


@pytest.fixture
def conn(tmp_path, monkeypatch):
    monkeypatch.setenv("XENIA_FAKE_NOW", "2026-07-27T09:00:00.000+00:00")
    monkeypatch.delenv("CLAUDECODE", raising=False)
    monkeypatch.delenv("CODEX_HOME", raising=False)
    connection = xdb.connect(tmp_path / "audit.db")
    yield connection
    connection.close()


@pytest.fixture
def clock(monkeypatch):
    state = {"n": 0}

    def tick() -> str:
        state["n"] += 1
        stamp = f"2026-07-27T09:{state['n'] // 60:02d}:{state['n'] % 60:02d}.000+00:00"
        monkeypatch.setenv("XENIA_FAKE_NOW", stamp)
        return stamp

    return tick


def pre(tool: str, args: dict, session: str = "s1", cwd: str = CORE) -> dict:
    return {
        "hook_event_name": "PreToolUse", "session_id": session, "cwd": cwd,
        "tool_name": tool, "tool_input": args,
    }


def post(tool: str, args: dict, *, ok: bool = True, session: str = "s1",
         cwd: str = CORE, response: dict | None = None) -> dict:
    if response is None:
        response = {"stdout": "done"} if ok else {"stderr": "boom", "is_error": True}
    return {
        "hook_event_name": "PostToolUse", "session_id": session, "cwd": cwd,
        "tool_name": tool, "tool_input": args, "tool_response": response,
    }
