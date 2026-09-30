from __future__ import annotations

import pytest

from xenia import selfmatch

REFUSED = [
    'pkill -f "npm run dev:web" 2>/dev/null; pkill -f "vite --port 5173" 2>/dev/null; true',
    'pkill -f worker.sh 2>/dev/null; pkill -f "site/index.php" 2>/dev/null; echo "worker stopped"',
    'until ! pgrep -f "make integration" >/dev/null 2>&1; do sleep 20; done; echo "suite finished"',
    'for p in $(pgrep -f "queue-watcher --job nightly-export"); do kill $p; done',
    # The bracket trick does not help when the name is elsewhere in the command.
    'pkill -TERM -f "[r]enderd"; sleep 6; tail -3 $LOGS/renderd.log',
    # Always says "still running": its own shell is running.
    'pgrep -f "backup verify" >/dev/null && echo "still running" || echo finished',
    'kill "$(pgrep -f worker.sh)"',
    'P=$(pgrep -f "node-7.example.invalid" | head -1); echo $P',
    'pgrep -f import_orders.py | xargs kill',
    'pgrep -c -f rebuild_search_index',
    'sudo -n pkill -9 -f appserver',
    'pkill --signal TERM --full appserver',
    "timeout 60 bash -c 'until ! pgrep -f appserver; do sleep 1; done'",
]

ALLOWED = [
    'pkill -A -f "npm run dev:web"',
    'pgrep -A -f worker.sh | xargs kill',
    'until ! pgrep --ignore-ancestors -f "make integration"; do sleep 20; done',
    # The bracket trick, with the name nowhere else in the command.
    'pkill -TERM -f "[r]enderd"; sleep 6',
    # A pgrep whose answer only reaches the agent: its own shell shows in the
    # list, which misleads but harms nothing.
    'pgrep -af "export_cli.py verify" | head -3',
    'pgrep -af "admin/ui.py" 2>/dev/null | grep -v pgrep',
    # Not a process match at all.
    'kill 41230 41228; pkill appserver; pgrep -x java',
    'pkill -x -f "java -jar app.jar"',
    'echo pkill -f foo',
    'grep -rn "pkill -f" .',
    # Data being written, not a command being run here.
    "cat > stop.sh <<'EOF'\npkill -f foo\nEOF\nchmod +x stop.sh",
    # Cannot be read as a literal, so cannot be decided.
    'pkill -f "$PATTERN"',
    'pkill -f "$(cat pattern.txt)"',
]


@pytest.mark.parametrize("command", REFUSED)
def test_a_match_that_finds_its_own_shell_is_refused(command):
    assert selfmatch.refusal(command)


@pytest.mark.parametrize("command", ALLOWED)
def test_everything_else_runs(command):
    assert selfmatch.refusal(command) is None


def test_the_refusal_names_the_fix():
    said = selfmatch.refusal('pkill -f "vite --port 5173" 2>/dev/null; echo done')
    assert "Exit code 144" in said
    assert "pkill -A -f 'vite --port 5173'" in said
    # The redirect is not part of the invocation it shows.
    assert "/dev/null" not in said.split("Add -A")[1].split("`")[1]


def test_a_pattern_that_only_matches_the_wrapper_is_refused():
    # `shell-snapshots` is nowhere in the command (the bracket keeps it out),
    # but it is in the wrapper Claude Code runs it in, and not in Codex's.
    assert selfmatch.refusal('pkill -f "[s]hell-snapshots"', agent="claude")
    assert selfmatch.refusal('pkill -f "[s]hell-snapshots"', agent="codex") is None


def test_only_a_pre_tool_use_bash_call_is_checked():
    call = {"hook_event_name": "PreToolUse", "tool_name": "Bash",
            "tool_input": {"command": "pkill -f worker.sh"}}
    assert selfmatch.check(call)
    assert selfmatch.check({**call, "hook_event_name": "PostToolUse"}) is None
    assert selfmatch.check({**call, "tool_name": "Read"}) is None
    assert selfmatch.check({**call, "tool_input": "pkill -f worker.sh"}) is None
