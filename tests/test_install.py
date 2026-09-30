from __future__ import annotations

import json
from pathlib import Path

import pytest

from xenia import install

HOOK = Path("/opt/xenia/bin/xenia-hook")
GUARD = Path("/opt/xenia/bin/xenia-guard")


@pytest.fixture
def targets(tmp_path):
    return install.machine_targets()


def read(path) -> dict:
    return json.loads(Path(path).read_text())


def commands(config: dict, event: str) -> list[str]:
    return [
        hook.get("command", "")
        for entry in config.get("hooks", {}).get(event, [])
        for hook in entry.get("hooks", [])
    ]


def test_machine_targets_follow_the_runtime_config_variables(tmp_path):
    paths = {label: Path(p) for label, p in install.machine_targets()}
    assert paths["claude"] == tmp_path / "runtime" / "claude" / "settings.json"
    assert paths["codex"] == tmp_path / "runtime" / "codex" / "hooks.json"


def test_repo_targets_stay_inside_the_repo():
    paths = {label: p for label, p in install.repo_targets(Path("/srv/repos/shop"))}
    assert paths["claude"] == Path("/srv/repos/shop/.claude/settings.json")
    assert paths["codex"] == Path("/srv/repos/shop/.codex/hooks.json")


def test_a_fresh_machine_gets_all_six_events(targets):
    results = install.apply(targets, HOOK)
    assert {r["runtime"] for r in results} == {"claude", "codex"}

    for result in results:
        assert set(result["added"]) == set(install.EVENTS) | {install.GUARD}
        config = read(result["path"])
        for event in install.EVENTS:
            recorded = [c for c in commands(config, event) if "xenia-hook" in c]
            assert recorded == [f"{HOOK} {event}"]


def test_the_guard_is_its_own_entry_on_shell_calls_only(targets):
    """What xenia says back is removable without touching the record."""
    install.apply(targets, HOOK)
    for _, path in targets:
        pre = read(path)["hooks"]["PreToolUse"]
        guard = [e for e in pre if any("xenia-guard" in h["command"] for h in e["hooks"])]
        assert guard == [{"matcher": "Bash", "hooks": [
            {"type": "command", "command": f"{GUARD} PreToolUse"}]}]
        assert not any("xenia-hook" in h["command"] for h in guard[0]["hooks"])


def test_a_machine_that_only_records_gets_the_guard_added(targets):
    claude = Path(dict(targets)["claude"])
    claude.parent.mkdir(parents=True)
    # A settings file from before xenia-guard existed: xenia-hook on every event.
    claude.write_text(json.dumps({"hooks": {e: [install._entry(HOOK, e)] for e in install.EVENTS}}))

    result = next(r for r in install.apply(targets, HOOK) if r["runtime"] == "claude")
    assert result["added"] == [install.GUARD]
    assert f"{GUARD} PreToolUse" in commands(read(claude), "PreToolUse")


def test_tool_events_are_wired_with_a_wildcard_matcher(targets):
    install.apply(targets, HOOK)
    config = read(dict(targets)["claude"])

    for event in ("PreToolUse", "PostToolUse"):
        recording = [e for e in config["hooks"][event]
                     if any("xenia-hook" in h["command"] for h in e["hooks"])]
        assert recording and all(e["matcher"] == "*" for e in recording)
    for event in ("SessionStart", "Stop"):
        assert all("matcher" not in e for e in config["hooks"][event])


def test_dry_run_writes_nothing(targets):
    results = install.plan(targets, HOOK)
    assert all(r["added"] for r in results)
    assert not any(Path(p).exists() for _, p in targets)


def test_installing_twice_changes_nothing_the_second_time(targets):
    install.apply(targets, HOOK)
    before = {str(p): Path(p).read_text() for _, p in targets}

    again = install.apply(targets, HOOK)
    assert all(r["added"] == [] for r in again)
    assert {str(p): Path(p).read_text() for _, p in targets} == before


def test_an_existing_hook_survives_and_keeps_its_place(targets):
    claude = Path(dict(targets)["claude"])
    claude.parent.mkdir(parents=True)
    claude.write_text(json.dumps({
        "hooks": {
            "PreToolUse": [{
                "matcher": "Bash",
                "hooks": [{"type": "command", "command": "/usr/local/bin/policy-check"}],
            }],
        },
    }))

    install.apply(targets, HOOK)
    config = read(claude)

    assert config["hooks"]["PreToolUse"][0]["matcher"] == "Bash"
    assert commands(config, "PreToolUse")[0] == "/usr/local/bin/policy-check"
    assert f"{HOOK} PreToolUse" in commands(config, "PreToolUse")


def test_unrelated_settings_are_preserved(targets):
    claude = Path(dict(targets)["claude"])
    claude.parent.mkdir(parents=True)
    claude.write_text(json.dumps({"model": "opus", "permissions": {"allow": ["Bash(ls:*)"]}}))

    install.apply(targets, HOOK)
    config = read(claude)

    assert config["model"] == "opus"
    assert config["permissions"] == {"allow": ["Bash(ls:*)"]}
    assert config["hooks"]["Stop"]


def test_an_existing_file_is_backed_up_before_being_rewritten(targets):
    claude = Path(dict(targets)["claude"])
    claude.parent.mkdir(parents=True)
    claude.write_text(json.dumps({"model": "opus"}))

    result = next(r for r in install.apply(targets, HOOK) if r["runtime"] == "claude")

    assert read(result["backup"]) == {"model": "opus"}


def test_an_unparseable_config_is_reported_and_left_alone(targets):
    claude = Path(dict(targets)["claude"])
    claude.parent.mkdir(parents=True)
    claude.write_text("{ this is not json")

    results = install.apply(targets, HOOK)
    claude_result = next(r for r in results if r["runtime"] == "claude")

    assert "unparseable" in claude_result["error"]
    assert claude.read_text() == "{ this is not json"
    assert next(r for r in results if r["runtime"] == "codex")["added"]


def test_status_reports_an_uninstalled_machine(targets):
    assert all(not item["events"] for item in install.status())
    assert all(not item["exists"] for item in install.status())


def test_status_reports_a_wired_up_machine(targets):
    install.apply(targets, HOOK)
    for item in install.status():
        assert item["events"] == sorted(install.EVENTS)
        assert item["guard"] is True
        assert item["error"] is None


def test_status_distinguishes_a_config_with_no_xenia_hook(targets):
    claude = Path(dict(targets)["claude"])
    claude.parent.mkdir(parents=True)
    claude.write_text(json.dumps({
        "hooks": {"PreToolUse": [{"hooks": [{"command": "/usr/local/bin/policy-check"}]}]},
    }))

    item = next(i for i in install.status() if i["runtime"] == "claude")
    assert item["exists"] is True
    assert item["events"] == []
