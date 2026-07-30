from __future__ import annotations

import pytest
from conftest import (FAKE_ANTHROPIC_KEY, FAKE_AWS_KEY, FAKE_GITHUB_TOKEN,
                     FAKE_GITLAB_PAT, FAKE_GITLAB_RUNNER_TOKEN,
                     FAKE_GRAFANA_TOKEN, FAKE_SLACK_TOKEN)

from xenia import redact


@pytest.mark.parametrize(
    "text,label",
    [
        (f"PRIVATE-TOKEN: {FAKE_GITLAB_PAT}", "GITLAB_PAT"),
        (f"runner token {FAKE_GITLAB_RUNNER_TOKEN}", "GITLAB_RUNNER_TOKEN"),
        (FAKE_GITHUB_TOKEN, "GITHUB_TOKEN"),
        (FAKE_SLACK_TOKEN, "SLACK_TOKEN"),
        (FAKE_AWS_KEY, "AWS_KEY"),
        (FAKE_ANTHROPIC_KEY, "ANTHROPIC_KEY"),
        ("-----BEGIN OPENSSH PRIVATE KEY-----", "PRIVATE_KEY"),
        ("$ANSIBLE_VAULT;1.1;AES256", "ANSIBLE_VAULT_BLOB"),
        (f"GRAFANA_SA_TOKEN={FAKE_GRAFANA_TOKEN}", "SECRET_VALUE"),
        ("db_password: s3cretValue123", "SECRET_VALUE"),
        ("https://deploy:hunter2pass@gitlab.test/repo.git", "URL_PASSWORD"),
    ],
)
def test_real_credentials_are_caught(text, label):
    hits = redact.scan(text)
    assert hits, f"missed a credential in {text!r}"
    assert label in [h.label for h in hits]
    assert f"[REDACTED:{label}]" in redact.redact(text)


@pytest.mark.parametrize(
    "text",
    [
        "export API_KEY=${GITLAB_TOKEN}",
        "token = <your-token-here>",
        "password: changeme",
        "SECRET_KEY=xxxxxxxxxx",
        "api_key: example_value",
        "url: jdbc:postgresql://postgres-staging.internal:5432/core",
        "curl -sS https://core.staging.example.com/health",
        "git commit -m 'add token refresh handling'",
        "./gradlew test --tests '*HealthCheckTest'",
    ],
)
def test_ordinary_text_is_left_alone(text):
    assert redact.scan(text) == []
    assert redact.redact(text) == text


def test_the_most_specific_rule_wins():
    hits = redact.scan(f"PRIVATE_TOKEN={FAKE_GITLAB_PAT}")
    assert [h.label for h in hits] == ["GITLAB_PAT"]


def test_several_secrets_in_one_string_are_all_redacted():
    text = (f"curl -H 'PRIVATE-TOKEN: {FAKE_GITLAB_PAT}' "
            f"-H 'X-Other: {FAKE_GITHUB_TOKEN}' https://x.test")
    out = redact.redact(text)
    assert "glpat-" not in out
    assert "ghp_" not in out
    assert out.count("[REDACTED:") == 2


def test_redaction_keeps_the_surrounding_text_intact():
    out = redact.redact(f"curl -H 'PRIVATE-TOKEN: {FAKE_GITLAB_PAT}' https://gl.test/api")
    assert out.startswith("curl -H 'PRIVATE-TOKEN: ")
    assert out.endswith("' https://gl.test/api")


def test_nested_structures_are_walked():
    payload = {
        "tool_input": {"command": "curl -u admin:realpassword123 https://x.test"},
        "list": [FAKE_GITLAB_PAT, {"deep": FAKE_AWS_KEY}],
        "count": 3,
        "flag": True,
    }
    out = redact.redact_obj(payload)
    text = str(out)
    assert "glpat-" not in text
    assert FAKE_AWS_KEY not in text
    assert out["count"] == 3 and out["flag"] is True


def test_empty_and_none_are_safe():
    assert redact.redact(None) is None
    assert redact.redact("") == ""
    assert redact.scan(None) == []


def test_an_already_redacted_marker_is_not_a_fresh_hit():
    already = "GRAFANA_SA_TOKEN=[REDACTED:SECRET_VALUE]"
    assert redact.scan(already) == []
    assert redact.redact(already) == already


def test_markers_are_not_wrapped_twice():
    once = redact.redact(f"token: {FAKE_GITLAB_PAT}")
    assert redact.redact(once) == once
    assert once.count("REDACTED") == 1
