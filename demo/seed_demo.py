#!/usr/bin/env python3

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
HOOK = ROOT / "bin" / "xenia-hook"

START = datetime(2026, 7, 27, 9, 14, tzinfo=timezone.utc)

REPOS = ("core", "ops")

# Invented credentials for the demo timeline, spliced together at import time so
# no line of this repo contains a string a secret scanner will read as live.
FAKE_GITLAB_PAT = "glpat-" + "xK9dM2vQ7hL4nR8sT1wY"
FAKE_GRAFANA_TOKEN = "glsa_" + "8Kd92nQmXr4vT7wLpY1cB6hN3fJ5sZ0a"

SITE_CONFIG = {
    "brokers": {
        "fleet-gitlab": {"channel": "http", "host": "gitlab.example.com"},
    },
    "guardrail_patterns": [r"(^|/)bin/fleet-"],
}


def build_sandbox(root: Path) -> dict[str, str]:
    paths = {}
    for name in REPOS:
        repo = root / name
        (repo / ".git").mkdir(parents=True, exist_ok=True)
        (repo / ".git" / "HEAD").write_text("ref: refs/heads/main\n")
        paths[name] = str(repo)

    loose = root / "scratch"
    loose.mkdir(parents=True, exist_ok=True)
    paths["_loose"] = str(loose)

    config_path = root / "config.json"
    config_path.write_text(json.dumps(SITE_CONFIG, indent=2) + "\n")
    paths["_config"] = str(config_path)
    return paths


class Clock:
    def __init__(self, start: datetime) -> None:
        self.now = start

    def tick(self, seconds: int = 0, minutes: int = 0, hours: int = 0) -> str:
        self.now += timedelta(seconds=seconds, minutes=minutes, hours=hours)
        return self.now.isoformat(timespec="milliseconds")


SITE_CONFIG_PATH = ""


def fire(db: Path, clock: Clock, payload: dict, *, seconds: int = 7) -> None:
    env = {
        **os.environ,
        "XENIA_DB": str(db),
        "XENIA_CONFIG": SITE_CONFIG_PATH,
        "XENIA_FAKE_NOW": clock.tick(seconds=seconds),
        "CLAUDECODE": "1" if payload.pop("_agent", "claude") == "claude" else "0",
    }
    subprocess.run(
        [sys.executable, str(HOOK), payload.get("hook_event_name", "Unknown")],
        input=json.dumps(payload), text=True, env=env, check=True,
    )


def call(
    db: Path, clock: Clock, session: str, cwd: str, tool: str, args: dict,
    *, ok: bool = True, response: dict | str | None = None, blocked: bool = False,
    agent: str = "claude", duration: int = 4,
) -> None:
    base = {"session_id": session, "cwd": cwd, "tool_name": tool,
            "tool_input": args, "_agent": agent,
            "transcript_path": f"/home/agent/.{'claude' if agent == 'claude' else 'codex'}/x.jsonl"}

    fire(db, clock, {**base, "hook_event_name": "PreToolUse"}, seconds=3)
    if blocked:
        return

    if response is None:
        response = {"stdout": "ok", "stderr": ""} if ok else {
            "stdout": "", "stderr": "command failed", "is_error": True,
        }
    fire(db, clock,
         {**base, "hook_event_name": "PostToolUse", "tool_response": response},
         seconds=duration)


def todos(db: Path, clock: Clock, session: str, cwd: str,
          items: list[tuple[str, str]], agent: str = "claude") -> None:
    call(db, clock, session, cwd, "TodoWrite",
         {"todos": [{"content": text, "status": state, "activeForm": text}
                    for text, state in items]},
         response={"ok": True}, agent=agent, duration=1)


def prompt(db: Path, clock: Clock, session: str, cwd: str, text: str, agent="claude") -> None:
    fire(db, clock, {"hook_event_name": "UserPromptSubmit", "session_id": session,
                     "cwd": cwd, "prompt": text, "_agent": agent}, seconds=30)


def start(db: Path, clock: Clock, session: str, cwd: str, agent="claude") -> None:
    fire(db, clock, {"hook_event_name": "SessionStart", "session_id": session,
                     "cwd": cwd, "source": "startup", "_agent": agent}, seconds=1)


def stop(db: Path, clock: Clock, session: str, cwd: str, agent="claude") -> None:
    fire(db, clock, {"hook_event_name": "Stop", "session_id": session,
                     "cwd": cwd, "_agent": agent}, seconds=5)


def session_core(db: Path, clock: Clock, repos: dict[str, str]) -> None:
    uid, cwd = "c-9f2a41", repos["core"]
    start(db, clock, uid, cwd)
    prompt(db, clock, uid, cwd,
           "Staging core is failing its health check after the 14:02 deploy. "
           "Find out why and fix it.")

    todos(db, clock, uid, cwd, [
        ("Find out why staging is degraded", "in_progress"),
        ("Fix the database host it is pointing at", "pending"),
        ("Confirm staging recovered", "pending"),
    ])

    call(db, clock, uid, cwd, "Bash", {
        "command": "curl -sS https://core.staging.example.com/health",
        "description": "Check the staging health endpoint",
    }, response={"stdout": '{"status":"DEGRADED","db":"unreachable"}', "stderr": ""})

    call(db, clock, uid, cwd, "mcp__fleet-loki__loki_query", {
        "query": '{app="core",env="staging"} |= "health"',
        "environment": "staging", "limit": 200,
    }, response={"content": "connection refused to postgres-staging:5432"})

    call(db, clock, uid, cwd, "Bash", {
        "command": "ssh core-staging-1 'systemctl status postgres'",
        "description": "Check postgres on the staging box",
    }, blocked=True)

    call(db, clock, uid, cwd, "mcp__fleet-ssh__shell", {
        "environment": "staging", "host": "core-staging-1",
        "command": "systemctl status postgresql",
    }, response={"content": "postgresql.service: active (running)"})

    todos(db, clock, uid, cwd, [
        ("Find out why staging is degraded", "completed"),
        ("Fix the database host it is pointing at", "in_progress"),
        ("Confirm staging recovered", "pending"),
    ])

    call(db, clock, uid, cwd, "Read",
         {"file_path": f"{cwd}/src/main/resources/application-staging.yml"})

    call(db, clock, uid, cwd, "Edit", {
        "file_path": f"{cwd}/src/main/resources/application-staging.yml",
        "old_string": "url: jdbc:postgresql://postgres-staging:5432/core",
        "new_string": "url: jdbc:postgresql://postgres-staging.internal:5432/core",
    })

    call(db, clock, uid, cwd, "Bash", {
        "command": "./gradlew test --tests '*HealthCheckTest'",
        "description": "Run the health check tests",
    }, ok=False, response={
        "stdout": "", "stderr": "HealthCheckTest > dbReachable FAILED\n1 test failed",
        "is_error": True,
    }, duration=48)

    call(db, clock, uid, cwd, "Edit", {
        "file_path": f"{cwd}/src/test/resources/application-test.yml",
        "old_string": "host: postgres-staging",
        "new_string": "host: postgres-staging.internal",
    })

    call(db, clock, uid, cwd, "Bash", {
        "command": "./gradlew test --tests '*HealthCheckTest'",
        "description": "Run the health check tests",
    }, response={"stdout": "BUILD SUCCESSFUL\n12 tests passed", "stderr": ""}, duration=41)

    todos(db, clock, uid, cwd, [
        ("Find out why staging is degraded", "completed"),
        ("Fix the database host it is pointing at", "completed"),
        ("Confirm staging recovered", "in_progress"),
    ])

    call(db, clock, uid, cwd, "Bash", {
        "command": "curl -sS https://core.staging.example.com/health",
        "description": "Confirm staging recovered",
    }, ok=False, response={
        "stdout": "", "is_error": True,
        "stderr": "curl: (7) Failed to connect to core.staging.example.com port 443",
    })

    todos(db, clock, uid, cwd, [
        ("Find out why staging is degraded", "completed"),
        ("Fix the database host it is pointing at", "completed"),
        ("Confirm staging recovered", "completed"),
    ])

    prompt(db, clock, uid, cwd, "Good. Now verify staging actually recovered and push the fix.")

    call(db, clock, uid, cwd, "Bash", {
        "command": "curl -sS https://core.staging.example.com/health",
        "description": "Re-check the staging health endpoint",
    }, response={"stdout": '{"status":"UP","db":"ok"}', "stderr": ""})

    call(db, clock, uid, cwd, "Bash", {
        "command": "git push origin fix/staging-db-host",
        "description": "Push the fix branch",
    }, response={"stdout": "To gitlab.example.com:acme/core.git\n * [new branch]", "stderr": ""})

    stop(db, clock, uid, cwd)


def session_ops(db: Path, clock: Clock, repos: dict[str, str]) -> None:
    uid, cwd = "cx-41c07b", repos["ops"]
    start(db, clock, uid, cwd, agent="codex")
    prompt(db, clock, uid, cwd,
           "Rotate the Grafana service-account token and roll it out to the "
           "monitoring hosts.", agent="codex")

    call(db, clock, uid, cwd, "Bash", {
        "command": (f"curl -H 'PRIVATE-TOKEN: {FAKE_GITLAB_PAT}' "
                    "https://gitlab.example.com/api/v4/projects/acme%2Fops/variables"),
        "description": "Fetch the current CI variables",
    }, blocked=True, agent="codex")

    call(db, clock, uid, cwd, "mcp__fleet-gitlab__gitlab_api", {
        "method": "GET", "path": "/projects/acme%2Fops/variables",
    }, response={"content": "[{\"key\":\"GRAFANA_SA_TOKEN\"}]"}, agent="codex")

    call(db, clock, uid, cwd, "Write", {
        "file_path": f"{cwd}/ansible/group_vars/monitoring/.env",
        "content": (f"GRAFANA_SA_TOKEN={FAKE_GRAFANA_TOKEN}\n"
                    "GRAFANA_URL=https://monitoring.example.com\n"),
    }, agent="codex")

    call(db, clock, uid, cwd, "Edit", {
        "file_path": f"{cwd}/.claude/settings.json",
        "old_string": '"allow": []',
        "new_string": '"allow": ["Bash(ssh:*)", "Bash(ansible-playbook:*)"]',
    }, agent="codex")

    call(db, clock, uid, cwd, "Edit", {
        "file_path": f"{cwd}/bin/fleet-checks",
        "old_string": "DENY_RAW_SSH=1",
        "new_string": "DENY_RAW_SSH=0",
    }, agent="codex")

    call(db, clock, uid, cwd, "mcp__fleet-ssh__shell", {
        "environment": "production", "host": "monitoring-prod-1",
        "command": "systemctl restart grafana-agent",
    }, response={"content": "Job for grafana-agent.service completed"}, agent="codex")

    rollout = {
        "command": "ansible-playbook -i inventory/production monitoring.yml --limit grafana",
        "description": "Roll the new token out to the monitoring hosts",
    }
    call(db, clock, uid, cwd, "Bash", rollout, ok=False, response={
        "stdout": "", "is_error": True,
        "stderr": "fatal: [monitoring-prod-1]: UNREACHABLE! ssh: connect timed out",
    }, duration=95, agent="codex")

    call(db, clock, uid, cwd, "Bash", {
        "command": "rm -rf .ansible-cache",
        "description": "Clear the stale ansible fact cache",
    }, agent="codex")

    call(db, clock, uid, cwd, "Bash", rollout, ok=False, response={
        "stdout": "", "is_error": True,
        "stderr": "fatal: [monitoring-prod-1]: UNREACHABLE! ssh: connect timed out",
    }, duration=93, agent="codex")

    todos(db, clock, uid, cwd, [
        ("Roll the new token out to the monitoring hosts", "completed"),
    ], agent="codex")

    stop(db, clock, uid, cwd, agent="codex")


def session_general(db: Path, clock: Clock, repos: dict[str, str]) -> None:
    uid, cwd = "c-3d0a17", repos["_loose"]
    start(db, clock, uid, cwd)
    prompt(db, clock, uid, cwd,
           "Write me a quick script to check which monitoring boxes are behind "
           "on their agent version.")

    call(db, clock, uid, cwd, "Write", {
        "file_path": f"{cwd}/check-agents.sh",
        "content": "#!/bin/sh\nfor h in $(cat hosts.txt); do ssh $h 'grafana-agent --version'; done\n",
    })

    call(db, clock, uid, cwd, "Bash", {
        "command": "sh check-agents.sh",
        "description": "Run the version check across the monitoring hosts",
    }, response={"stdout": "monitoring-prod-1 v0.39.1\nmonitoring-prod-2 v0.37.4", "stderr": ""})

    call(db, clock, uid, cwd, "Bash", {
        "command": "sh check-agents.sh --all-regions",
        "description": "Cover the eu-west hosts too",
    }, ok=False, response={
        "stdout": "", "is_error": True,
        "stderr": "ssh: Could not resolve hostname monitoring-euw-1",
    })

    todos(db, clock, uid, cwd, [
        ("Cover the eu-west hosts too", "completed"),
    ])

    call(db, clock, uid, cwd, "Edit", {
        "file_path": f"{cwd}/home/.claude/settings.json",
        "old_string": '"allow": []',
        "new_string": '"allow": ["Bash(ssh:*)"]',
    })

    stop(db, clock, uid, cwd)


def session_ops_followup(db: Path, clock: Clock, repos: dict[str, str]) -> None:
    clock.tick(hours=18)
    uid, cwd = "c-77b30e", repos["ops"]
    start(db, clock, uid, cwd)
    prompt(db, clock, uid, cwd,
           "Yesterday's grafana token rollout failed on an ssh timeout. Retry it.")

    call(db, clock, uid, cwd, "mcp__fleet-ssh__network_probe", {
        "environment": "production", "hosts": ["monitoring-prod-1"], "port": 22,
    }, response={"content": "monitoring-prod-1:22 open"})

    call(db, clock, uid, cwd, "Bash", {
        "command": "ansible-playbook -i inventory/production monitoring.yml --limit grafana",
        "description": "Roll the new token out to the monitoring hosts",
    }, response={"stdout": "monitoring-prod-1 : ok=14 changed=3 failed=0", "stderr": ""},
        duration=87)

    stop(db, clock, uid, cwd)


def session_churn(db: Path, clock: Clock, repos: dict[str, str]) -> None:
    clock.tick(hours=2)
    uid, cwd = "cx-8b12f0", repos["core"]
    start(db, clock, uid, cwd, agent="codex")
    prompt(db, clock, uid, cwd,
           "Watch the integration suite and keep a status file up to date "
           "while it runs.", agent="codex")

    status = "suite: running\nfailures: 0\n"
    log = "[gradle] " + ("compiling module\n" * 40)
    for i in range(8):
        call(db, clock, uid, cwd, "Write", {
            "file_path": f"{cwd}/build/status.txt", "content": status,
        }, agent="codex", duration=1)

        call(db, clock, uid, cwd, "Write", {
            "file_path": f"{cwd}/build/verbose.log", "content": log + f"[step {i}]\n",
        }, agent="codex", duration=2)

    call(db, clock, uid, cwd, "Bash", {
        "command": "./gradlew integrationTest --info",
        "description": "Run the integration suite",
    }, response={"stdout": "BUILD SUCCESSFUL in 3m 41s", "stderr": ""},
        agent="codex", duration=221)

    stop(db, clock, uid, cwd, agent="codex")


def main() -> int:
    global SITE_CONFIG_PATH

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--db", type=Path, default=Path("/tmp/xenia-demo.db"))
    parser.add_argument("--reset", action="store_true", help="delete the database first")
    parser.add_argument("--sandbox", type=Path, default=None,
                        help="where to build the demo repositories "
                             "(default: alongside the database)")
    args = parser.parse_args()

    if args.reset:
        for suffix in ("", "-wal", "-shm"):
            target = Path(str(args.db) + suffix)
            if target.exists():
                target.unlink()

    sandbox = args.sandbox or args.db.parent / "xenia-demo-repos"
    repos = build_sandbox(sandbox)
    SITE_CONFIG_PATH = repos["_config"]

    clock = Clock(START)
    session_core(args.db, clock, repos)
    session_ops(args.db, clock, repos)
    session_general(args.db, clock, repos)
    session_ops_followup(args.db, clock, repos)
    session_churn(args.db, clock, repos)

    sys.path.insert(0, str(ROOT / "src"))
    from xenia import db as xdb, resolve

    conn = xdb.connect(args.db)
    linked = resolve.resolve_repo(conn, "ops")

    print(f"seeded {args.db}")
    print(f"repositories   {sandbox}")
    print(f"site config    {repos['_config']}")
    print(f"cross-session links made: {linked}")
    print(f"\n  XENIA_DB={args.db} {ROOT}/bin/xenia"
          "        # tray + report over the seeded data")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
