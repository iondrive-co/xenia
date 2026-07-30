from __future__ import annotations

import json
from pathlib import Path

import pytest

from xenia import install

HOOK = Path("/opt/xenia/bin/xenia-hook")


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
    paths = {label: p for label, p in install.repo_targets(Path("/srv/repos/core"))}
    assert paths["claude"] == Path("/srv/repos/core/.claude/settings.json")
    assert paths["codex"] == Path("/srv/repos/core/.codex/hooks.json")


def test_a_fresh_machine_gets_all_six_events(targets):
    results = install.apply(targets, HOOK)
    assert {r["runtime"] for r in results} == {"claude", "codex"}

    for result in results:
        assert set(result["added"]) == set(install.EVENTS)
        config = read(result["path"])
        for event in install.EVENTS:
            assert commands(config, event) == [f"{HOOK} {event}"]


def test_tool_events_are_wired_with_a_wildcard_matcher(targets):
    install.apply(targets, HOOK)
    config = read(dict(targets)["claude"])

    for event in ("PreToolUse", "PostToolUse"):
        assert all(e["matcher"] == "*" for e in config["hooks"][event])
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
