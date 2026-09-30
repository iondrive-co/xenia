from __future__ import annotations

import getpass
import io
import json
import re
import socket
import subprocess
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "dev"))

import comments  # noqa: E402

GENERIC_NAMES = {"root", "user", "dev", "admin", "agent", "test", "runner", "ubuntu",
                 "home", "localhost", "users", "noreply", "gmail", "github"}


def git(*args: str) -> str | None:
    done = subprocess.run(["git", "-C", str(REPO), *args], capture_output=True, text=True)
    return done.stdout if done.returncode == 0 else None


def tracked_text_files() -> list[tuple[str, str]]:
    listed = git("ls-files", "--cached", "--others", "--exclude-standard")
    if listed is None:
        pytest.skip("not a git checkout")
    found = []
    for path in listed.split():
        try:
            found.append((path, (REPO / path).read_text(encoding="utf-8")))
        except (OSError, UnicodeDecodeError):
            continue
    return found


def private_terms() -> set[str]:
    terms = {getpass.getuser(), socket.gethostname().split(".")[0], str(Path.home())}
    email = (git("config", "user.email") or "").strip().lower()
    if "@" in email:
        local, domain = email.split("@", 1)
        terms.add(local)
        terms.update(domain.split(".")[:-1])
    listed = git("rev-parse", "--git-path", "info/private-terms")
    if listed:
        terms_file = Path(listed.strip())
        if not terms_file.is_absolute():
            terms_file = REPO / terms_file
        if terms_file.exists():
            for line in terms_file.read_text(encoding="utf-8").splitlines():
                line = line.strip()
                if line and not line.startswith("#"):
                    terms.add(line)
    return {t.lower() for t in terms if len(t) >= 3 and t.lower() not in GENERIC_NAMES}


def test_no_tracked_file_names_this_machine_its_user_or_its_other_repos():
    terms = private_terms()
    if not terms:
        pytest.skip("nothing on this machine to look for")
    pattern = re.compile(r"(?<![\w-])(?:" + "|".join(map(re.escape, sorted(terms))) + r")(?![\w-])",
                         re.IGNORECASE)
    leaks = []
    for path, text in tracked_text_files():
        for number, line in enumerate(text.splitlines(), 1):
            hit = pattern.search(line)
            if hit:
                leaks.append(f"{path}:{number}: {hit.group(0)}")
    assert not leaks, (
        "This repo is public. Tests and demo data are synthetic, and no file names the "
        "machine, its user, their accounts or their other repositories:\n  "
        + "\n  ".join(leaks[:40]))


def test_agents_have_added_no_comment_text():
    if git("rev-parse", "HEAD") is None:
        pytest.skip("no commit to compare against")
    grown = comments.uncommitted_comments()
    assert not grown, (
        "Agents do not write comments or docstrings in this repo (CLAUDE.md, \"Comments\"). "
        "Delete the comment text added since the last commit in:\n  "
        + "\n  ".join(f"{path}: {', '.join(words[:12])}" for path, words in grown.items()))


def edit(path: Path, old: str, new: str) -> dict:
    return {"hook_event_name": "PreToolUse", "tool_name": "Edit",
            "tool_input": {"file_path": str(path), "old_string": old, "new_string": new}}


@pytest.fixture
def module(monkeypatch, tmp_path):
    monkeypatch.setattr(comments, "REPO", tmp_path)
    target = tmp_path / "src" / "thing.py"
    target.parent.mkdir()
    target.write_text('def f():\n    """Return one."""\n    # the answer\n    return 1\n')
    return target


def test_an_edit_that_adds_a_comment_is_refused(module):
    said = comments.refusal(edit(module, "    return 1\n", "    # always one\n    return 1\n"))
    assert said and "src/thing.py" in said and "always one" in said


def test_an_edit_that_adds_a_docstring_is_refused(module):
    assert comments.refusal(edit(module, "def f():\n", 'def g():\n    """New words."""\n\n\ndef f():\n'))


def test_rewording_a_comment_is_refused(module):
    assert comments.refusal(edit(module, "# the answer", "# the only answer"))


def test_deleting_comment_text_is_allowed(module):
    assert comments.refusal(edit(module, '    """Return one."""\n    # the answer\n', "")) is None


def test_a_code_only_edit_is_allowed(module):
    assert comments.refusal(edit(module, "return 1", "return 2")) is None


def test_a_file_outside_the_repo_is_not_looked_at(module, tmp_path_factory):
    elsewhere = tmp_path_factory.mktemp("elsewhere") / "notes.py"
    assert comments.refusal({"hook_event_name": "PreToolUse", "tool_name": "Write",
                             "tool_input": {"file_path": str(elsewhere),
                                            "content": "# anything\n"}}) is None


def test_a_new_file_with_a_comment_is_refused(module):
    fresh = module.parent / "fresh.py"
    assert comments.refusal({"hook_event_name": "PreToolUse", "tool_name": "Write",
                             "tool_input": {"file_path": str(fresh),
                                            "content": "#!/usr/bin/env python3\nx = 1  # why\n"}})


def test_a_shebang_and_a_directive_are_not_comments(module):
    fresh = module.parent / "fresh.py"
    assert comments.refusal({"hook_event_name": "PreToolUse", "tool_name": "Write",
                             "tool_input": {"file_path": str(fresh),
                                            "content": "#!/usr/bin/env python3\n"
                                                       "import os  # noqa: F401\n"}}) is None


def test_the_hook_answers_in_the_shape_the_runtime_reads(module, monkeypatch, capsys):
    payload = edit(module, "    return 1\n", "    # always one\n    return 1\n")
    monkeypatch.setattr(sys, "stdin", io.StringIO(json.dumps(payload)))
    assert comments.main() == 0
    said = json.loads(capsys.readouterr().out)["hookSpecificOutput"]
    assert said["permissionDecision"] == "deny"
