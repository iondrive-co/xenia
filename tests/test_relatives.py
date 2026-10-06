from __future__ import annotations

import pytest

from xenia import relatives

HOOK, HOOK_SH, CLI, TERMINAL = 5120, 5118, 4000, 3000
BACKGROUND, MCP = 4410, 4020

ARGV = {
    HOOK: ["python3", "/srv/repos/infra/bin/xenia-guard", "PreToolUse"],
    HOOK_SH: ["/bin/sh", "-c", "/srv/repos/infra/bin/xenia-guard PreToolUse"],
    CLI: ["/opt/agent/bin/claude", "--model", "x"],
    TERMINAL: ["/opt/term/bin/term"],
    BACKGROUND: ["/bin/bash", "-c", "source snap.sh && eval 'bin/run-job.sh --name nightly-export' < /dev/null"],
    MCP: ["/srv/repos/infra/bin/xenia-mcp"],
}
PARENT = {HOOK: HOOK_SH, HOOK_SH: CLI, CLI: TERMINAL, TERMINAL: 1,
          BACKGROUND: CLI, MCP: CLI}


class FakeTree(relatives.Tree):
    def __init__(self, argv=None) -> None:
        super().__init__(HOOK)
        self.table = argv or ARGV

    def parent(self, pid):
        return PARENT.get(pid)

    def argv(self, pid):
        return self.table.get(pid, [])

    def children(self, pid):
        return [p for p, parent in PARENT.items() if parent == pid]


def warned(command, tree=None):
    payload = {"hook_event_name": "PreToolUse", "tool_name": "Bash", "session_id": "s1",
               "transcript_path": "/srv/repos/shop/.claude/t.jsonl", "tool_input": {"command": command}}
    return relatives.warning(payload, tree or FakeTree())


THE_INCIDENT = ("P1=$(pgrep -A -f 'run-job.sh --name nightly-export' | head -1); "
                "P0=$(ps -o ppid= -p $P1 2>/dev/null | tr -d ' '); "
                "kill -TERM $P1 $P0 2>/dev/null; sleep 2")


def test_the_incident_is_held_for_both_reasons():
    said = warned(THE_INCIDENT)
    assert f"matches PID {BACKGROUND}" in said
    assert "reads a parent PID" in said
    assert f"PID {CLI}" in said
    assert "run exactly the same command again" in said


@pytest.mark.parametrize("command", [
    "pgrep -A -f nightly-export | xargs kill",
    "pkill -A -f 'name nightly-export'",
    "kill $(pgrep -A -f xenia-mcp)",
    "kill $PPID",
    "pkill -P $PPID",
    f"kill -9 {CLI}",
    f"kill {TERMINAL}",
    "kill $(awk '/PPid/ {print $2}' /proc/4410/status)",
])
def test_a_kill_that_reaches_the_cli_or_its_processes_is_held(command):
    assert warned(command)


@pytest.mark.parametrize("command", [
    "pgrep -af nightly-export",
    "pkill -A -f 'import_orders.py'",
    "kill 41230",
    "ps -o ppid= -p 41230",
    "pgrep -A -x -f 'bin/run-job.sh'",
    "kill $(cat /srv/repos/shop/var/job.pid)",
    "echo kill $PPID",
    "pkill -A -f \"$PATTERN\"",
])
def test_everything_else_runs(command):
    assert warned(command) is None


def test_no_agent_in_the_ancestry_means_no_opinion():
    table = {**ARGV, CLI: ["/usr/bin/make"]}
    assert warned(THE_INCIDENT, FakeTree(table)) is None


def test_the_hook_s_own_shell_is_not_a_sibling():
    assert warned("pgrep -A -f 'xenia-guard PreToolUse' | xargs kill") is None


def test_a_cli_run_by_node_is_found():
    table = {**ARGV, CLI: ["node", "/opt/agent/lib/claude", "--model", "x"]}
    assert relatives.agent_pid(FakeTree(table), "claude") == CLI


def test_a_held_command_runs_on_retry_and_only_once(tmp_path, monkeypatch):
    monkeypatch.setenv("XENIA_GUARD_HELD", str(tmp_path / "held"))
    payload = {"session_id": "s1", "tool_input": {"command": "kill $PPID"}}
    assert not relatives.held_before(payload)
    relatives.hold(payload)
    assert relatives.held_before(payload)
    assert not relatives.held_before(payload)


def test_a_hold_is_per_session_and_per_command(tmp_path, monkeypatch):
    monkeypatch.setenv("XENIA_GUARD_HELD", str(tmp_path / "held"))
    relatives.hold({"session_id": "s1", "tool_input": {"command": "kill $PPID"}})
    assert not relatives.held_before({"session_id": "s2", "tool_input": {"command": "kill $PPID"}})
    assert not relatives.held_before({"session_id": "s1", "tool_input": {"command": "kill -9 $PPID"}})


def test_a_stale_hold_does_not_let_a_retry_through(tmp_path, monkeypatch):
    monkeypatch.setenv("XENIA_GUARD_HELD", str(tmp_path / "held"))
    monkeypatch.setattr("xenia.config.GUARD_HOLD_SECONDS", -1)
    payload = {"session_id": "s1", "tool_input": {"command": "kill $PPID"}}
    relatives.hold(payload)
    assert not relatives.held_before(payload)
