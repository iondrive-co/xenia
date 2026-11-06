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
    'job=import_orders.py; while pgrep -f "$job" >/dev/null; do sleep 30; done',
    'export JOB="make integration"\nuntil ! pgrep -f "${JOB}"; do sleep 20; done',
    'while ps aux | grep -q "render-queue --once"; do sleep 10; done',
    'ps -eo pid,args | grep -E "export_cli|render-queue" | wc -l',
    "kill $(ps aux | grep appserver | awk '{print $2}')",
    'until ! ps -ef | grep -iq APPSERVER; do sleep 5; done',
    "cat > wait.sh <<'EOF'\nwhile pgrep -f nightly-export >/dev/null; do sleep 30; done\nEOF\nbash wait.sh",
    "bash -s <<'EOF'\npkill -f worker.sh\nEOF",
    "cat <<EOF > /srv/repos/shop/stop.sh\npkill -f queue-watcher\nEOF\nchmod +x /srv/repos/shop/stop.sh && /srv/repos/shop/stop.sh",    'job=worker.sh; pkill -f $job',
    'pkill -TERM -f [r]enderd; tail -3 renderd.log',
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
    'read -r job < job.txt; pkill -f "$job"',
    'job=$(cat job.txt); pkill -f "$job"',
    'job=worker.sh pkill -f "$job"',
    'pgrep -f render-queue -A >/dev/null && echo running',
    'pkill -f appserver --ignore-ancestors',
    'while ps aux | grep -v grep | grep -q render-queue; do sleep 10; done',
    'while ps aux | grep -q "[r]ender-queue"; do sleep 10; done',
    'ps aux | grep render-queue',
    'ps -e | grep -q render-queue',
    'ps -p 4242 -o args | grep -q render-queue',
    'ps aux | grep -q render-queue jobs.txt',
    "cat > stop.sh <<'EOF'\npkill -f foo\nEOF\nbash -n stop.sh",
    "bash wait.sh <<'EOF'\npkill -f foo\nEOF",    'pkill -f $PATTERN',
    'pgrep -f $JOB | xargs kill',
    'job=$(cat job.txt); pkill -f $job',
    'pkill -TERM -f [r]enderd; sleep 6',    'pkill -P $$ -f worker.sh',
    'until pgrep -P "$pid" -f render-queue >/dev/null; do sleep 2; done',
    'pkill --parent 4242 -f appserver',
    'pgrep -s 0 -f appserver | xargs kill',
    'pgrep -t pts/3 -f appserver | xargs kill',
    'pgrep -F app.pid -f appserver | xargs kill',
    'pgrep -u nobody -f appserver | xargs kill',
    'ps -fu nobody | grep -q appserver',
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


def test_a_refusal_keeps_a_variable_a_variable():
    said = selfmatch.refusal('job=worker.sh; pgrep -f "$job" | xargs kill')
    assert 'pgrep -A -f "$job"' in said


def test_a_ps_refusal_names_pgrep_a():
    said = selfmatch.refusal('until ! ps aux | grep -q appserver; do sleep 5; done')
    assert "ps aux | grep -q appserver" in said
    assert "pgrep -A -f" in said


def test_a_ps_pipeline_reaches_the_check():
    call = {"hook_event_name": "PreToolUse", "tool_name": "Bash",
            "tool_input": {"command": "ps aux | grep -q appserver && echo up"}}
    assert selfmatch.check(call)


def test_the_agent_s_own_user_does_not_narrow_the_match():
    import getpass
    import os
    for user in (getpass.getuser(), str(os.getuid()), '"$USER"', "$(id -u)"):
        assert selfmatch.refusal(f"pgrep -u {user} -f appserver | xargs kill"), user
        assert selfmatch.refusal(f"ps -fu {user} | grep -q appserver"), user
