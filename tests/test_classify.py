from __future__ import annotations

import pytest

from xenia import classify, config


def analyse(command: str):
    remote = None
    fs: list[tuple[str, str]] = []
    for segment in classify.segments(command):
        verb, args = classify.verb_and_args(classify.tokenise(segment))
        found = classify.remote_fact(verb, args, segment)
        if found and remote is None:
            remote = found
        fs.extend(classify.fs_facts(verb, args, segment))
    return remote, fs


@pytest.mark.parametrize(
    "command,expected",
    [
        ("ls -la", "ls"),
        ("sudo systemctl restart nginx", "systemctl"),
        ("env FOO=bar curl https://x.test", "curl"),
        ("FOO=bar BAZ=1 ./gradlew test", "./gradlew"),
        ("bash -c 'ssh prod-1 uptime'", "ssh"),
        ("time sudo -u deploy rsync -a src/ prod-1:/srv/", "rsync"),
        ("(cd /tmp && wget https://x.test/f)", "cd"),
    ],
)
def test_verb_extraction_skips_wrappers(command, expected):
    verb, _ = classify.verb_and_args(classify.tokenise(classify.segments(command)[0]))
    assert verb == classify.posixpath.basename(expected)


def test_a_denied_verb_hidden_behind_cd_is_still_found():
    remote, _ = analyse("cd /srv/repos/ops && ssh monitoring-prod-1 'systemctl restart grafana'")
    assert remote is not None
    assert remote.channel == "ssh"
    assert remote.host == "monitoring-prod-1"
    assert remote.mutating is True


def test_curl_get_is_read_only():
    remote, _ = analyse("curl -sS https://core.staging.example.com/health")
    assert remote.channel == "http"
    assert remote.method == "GET"
    assert remote.host == "core.staging.example.com"
    assert remote.environment == "staging"
    assert remote.mutating is False


def test_curl_with_a_body_is_mutating():
    remote, _ = analyse("curl -X POST -d '{\"a\":1}' https://api.prod.example.com/v1/things")
    assert remote.method == "POST"
    assert remote.mutating is True
    assert remote.environment == "production"


def test_git_push_is_a_mutating_remote_call():
    remote, _ = analyse("git push origin fix/staging-db-host")
    assert remote.channel == "git"
    assert remote.mutating is True


def test_local_git_commands_are_not_remote():
    remote, _ = analyse("git status --short")
    assert remote is None


def test_local_rsync_is_not_remote():
    remote, _ = analyse("rsync -a build/ dist/")
    assert remote is None


def test_scp_target_host_is_extracted():
    remote, _ = analyse("scp report.txt deploy@monitoring-prod-1:/srv/reports/")
    assert remote.channel == "ssh"
    assert remote.host == "monitoring-prod-1"
    assert remote.environment == "production"


def test_package_installs_are_recorded_but_not_mutating():
    remote, _ = analyse("pip install requests")
    assert remote.channel == "package"
    assert remote.mutating is False


def test_kubectl_apply_is_mutating():
    remote, _ = analyse("kubectl apply -f deploy.yaml")
    assert remote.channel == "cloud"
    assert remote.mutating is True


def test_plain_local_command_has_no_remote_fact():
    remote, fs = analyse("./gradlew test --tests '*HealthCheckTest'")
    assert remote is None
    assert fs == []


def test_rm_records_a_delete():
    _, fs = analyse("rm -rf /srv/repos/ops/.ansible-cache")
    assert ("/srv/repos/ops/.ansible-cache", "delete") in fs


def test_cp_records_only_the_destination():
    _, fs = analyse("cp config.yml config.yml.bak")
    assert fs == [("config.yml.bak", "create")]


def test_redirection_is_a_change_whatever_the_verb():
    _, fs = analyse("echo 'DEBUG=1' >> .env")
    assert (".env", "modify") in fs


def test_redirect_to_dev_null_is_not_a_change():
    _, fs = analyse("./gradlew test > /dev/null")
    assert fs == []


def test_a_download_that_writes_a_file_records_both_effects():
    remote, fs = analyse("curl -sS https://x.test/config.yml > config.yml")
    assert remote is not None
    assert ("config.yml", "modify") in fs


def test_sed_in_place_records_a_modify():
    _, fs = analyse("sed -i 's/foo/bar/' src/main/app.py")
    assert ("src/main/app.py", "modify") in fs


@pytest.mark.parametrize(
    "path,expected",
    [
        (".claude/settings.json", "guardrail"),
        (".codex/hooks.json", "guardrail"),
        (".gitlab-ci.yml", "guardrail"),
        (".claude/agents/deployer.md", "guardrail"),
        (".mcp.json", "guardrail"),
        ("CLAUDE.md", "normal"),
        ("AGENTS.md", "normal"),
        (".git/hooks/pre-commit", "guardrail"),
        ("/home/agent/.claude.json", "guardrail"),
        ("/home/agent/work/.git/config", "guardrail"),
        ("/home/agent/.gitconfig", "guardrail"),
        ("docs/claude.json", "normal"),
        ("configs/gitconfig.sample", "normal"),
        ("ansible/group_vars/monitoring/.env", "sensitive"),
        ("/home/agent/.ssh/id_ed25519", "sensitive"),
        ("certs/server.pem", "sensitive"),
        ("/etc/hosts", "sensitive"),
        ("src/main/java/App.java", "normal"),
        ("README.md", "normal"),
    ],
)
def test_path_sensitivity(path, expected):
    assert classify.sensitivity_of(path) == expected


def test_paths_are_normalised_relative_to_the_repo():
    display, absolute, in_repo = classify.normalise_path(
        "src/app.py", "/srv/repos/core/sub", "/srv/repos/core"
    )
    assert display == "sub/src/app.py"
    assert absolute == "/srv/repos/core/sub/src/app.py"
    assert in_repo is True


def test_a_path_outside_the_repo_is_flagged():
    display, _, in_repo = classify.normalise_path(
        "/etc/nginx/nginx.conf", "/srv/repos/core", "/srv/repos/core"
    )
    assert in_repo is False
    assert display == "/etc/nginx/nginx.conf"


@pytest.mark.parametrize(
    "host,expected",
    [
        ("core.staging.example.com", "staging"),
        ("monitoring-prod-1", "production"),
        ("api.production.example.com", "production"),
        ("localhost", "local"),
        ("some-box", None),
    ],
)
def test_environment_from_hostname(host, expected):
    assert classify.environment_of(host) == expected


def test_signature_ignores_volatile_fragments():
    first = classify.signature("exec", "gradlew", "test-run-4821")
    second = classify.signature("exec", "gradlew", "test-run-9137")
    assert first == second


def test_signature_still_separates_genuinely_different_work():
    assert classify.signature("fs", "modify", "src/a.py") != classify.signature(
        "fs", "modify", "src/b.py"
    )


def test_tokenise_survives_broken_quoting():
    assert classify.tokenise("echo 'unterminated") == ["echo", "'unterminated"]


def test_ansible_inventory_path_is_not_mistaken_for_a_host():
    remote, _ = analyse(
        "ansible-playbook -i inventory/production monitoring.yml --limit grafana"
    )
    assert remote.channel == "ssh"
    assert remote.host == "grafana"
    assert remote.environment == "production"
    assert remote.mutating is True


def test_ansible_environment_comes_from_the_inventory_path():
    remote, _ = analyse("ansible-playbook -i inventory/staging site.yml")
    assert remote.environment == "staging"
    assert remote.host is None


def test_ansible_inventory_is_a_read_not_a_write():
    remote, _ = analyse("ansible-inventory -i inventory/production --list")
    assert remote.mutating is False


def test_flag_values_are_skipped_when_finding_operands():
    assert classify.operands(["-i", "inventory/prod", "site.yml", "--limit", "web"]) == [
        "site.yml"
    ]


def test_flag_value_reads_both_spellings():
    assert classify.flag_value(["--limit", "web"], "--limit") == "web"
    assert classify.flag_value(["--limit=web"], "--limit") == "web"


def test_the_sed_script_is_not_recorded_as_a_path():
    _, fs = analyse("sed -i 's/postgres-staging/postgres-staging.internal/' app.yml")
    assert fs == [("app.yml", "modify")]


def test_sed_records_every_file_it_edits():
    _, fs = analyse("sed -i.bak 's/a/b/' one.txt two.txt")
    assert fs == [("one.txt", "modify"), ("two.txt", "modify")]


def test_a_site_can_add_its_own_guardrail_paths(site_config):
    assert classify.sensitivity_of("bin/fleet-checks") == "normal"
    site_config({"guardrail_patterns": [r"(^|/)bin/fleet-"]})
    assert classify.sensitivity_of("bin/fleet-checks") == "guardrail"


def test_a_site_can_add_its_own_sensitive_paths(site_config):
    site_config({"sensitive_patterns": [r"(^|/)deploy-keys/"]})
    assert classify.sensitivity_of("deploy-keys/web01") == "sensitive"


def test_guardrail_still_outranks_sensitive_with_site_patterns(site_config):
    site_config({"sensitive_patterns": [r"\.claude/"]})
    assert classify.sensitivity_of(".claude/settings.json") == "guardrail"


def test_a_bad_site_pattern_is_dropped_not_fatal(site_config):
    site_config({"guardrail_patterns": ["(unclosed", r"(^|/)bin/fleet-"]})
    assert classify.sensitivity_of("bin/fleet-checks") == "guardrail"
    assert classify.sensitivity_of(".claude/settings.json") == "guardrail"
    assert classify.sensitivity_of("src/app.py") == "normal"


def test_an_unreadable_site_config_is_ignored(tmp_path, monkeypatch):
    bad = tmp_path / "config.json"
    bad.write_text("{not json at all")
    monkeypatch.setenv("XENIA_CONFIG", str(bad))
    config.reset_cache()
    classify.reset_cache()
    assert classify.sensitivity_of(".claude/settings.json") == "guardrail"


def test_github_cli_has_a_known_host():
    remote, _ = analyse("gh pr create --title x")
    assert remote.host == "api.github.com"


def test_gitlab_cli_host_is_blank_rather_than_guessed():
    remote, _ = analyse("glab mr create --title x")
    assert remote.host is None


def test_a_site_can_name_its_own_forge(site_config):
    site_config({"forge_hosts": {"glab": "gitlab.example.com"}})
    remote, _ = analyse("glab mr create --title x")
    assert remote.host == "gitlab.example.com"


@pytest.mark.parametrize("path", [
    "CLAUDE.md", "AGENTS.md", "docs/CLAUDE.md", ".claude/CLAUDE.md",
    ".cursorrules",
])
def test_instruction_files_are_not_guardrails(path):
    assert classify.sensitivity_of(path) == "normal"


@pytest.mark.parametrize("path", [
    ".claude/settings.json", ".mcp.json", ".git/hooks/pre-commit",
])
def test_permission_files_are_guardrails(path):
    assert classify.sensitivity_of(path) == "guardrail"


@pytest.mark.parametrize("path", ["CLAUDE.md", "AGENTS.md", "docs/AGENTS.md"])
def test_instruction_files_are_not_guardrails(path):
    assert classify.sensitivity_of(path) == "normal"


def test_running_an_mcp_server_binary_from_a_shell_is_attributed_to_its_broker():
    remote, _ = analyse(
        "printf '%s\\n' '{\"jsonrpc\":\"2.0\",\"method\":\"tools/call\"}' "
        "| ~/.local/bin/acme-gitlab-mcp 2>/dev/null | tail -1")

    assert remote is not None
    assert remote.channel == classify.MCP_SPAWN_CHANNEL
    assert remote.via == "acme-gitlab"


@pytest.mark.parametrize("command", [
    'cd /home/dev/acme\npython3 - <<\'PY\'\np = pathlib.Path("cmd/acme-loki-mcp/main.go")\nPY',
    "ps -eo pid,cmd | grep 'xenia-mcp' | grep -v grep",
    "cat notes-mcp.txt",
    "grep -rn acme-prom-mcp src/",
])
def test_naming_a_wrapper_is_not_running_one(command):
    remote, _ = analyse(command)
    spawned = remote and remote.channel == classify.MCP_SPAWN_CHANNEL
    assert not spawned


def test_the_broker_name_drops_the_mcp_decoration():
    assert classify.mcp_server_binary("acme-gitlab-mcp") == "acme-gitlab"
    assert classify.mcp_server_binary("mcp-server-github") == "github"
    assert classify.mcp_server_binary("/usr/local/bin/acme_ssh_mcp") == "acme_ssh"
    assert classify.mcp_server_binary("kubectl") is None
    assert classify.mcp_server_binary("bash") is None


@pytest.mark.parametrize("command", [
    "cat >> tests/test_ingest.py <<'PYEOF'\n"
    "    ingest.record(conn, pre('Bash', {'command':\n"
    "        \"printf '%s' '{}' | ~/.local/bin/acme-gitlab-mcp | tail -1\"}))\n"
    "PYEOF\n"
    "python3 -m pytest -q",
    "python3 - <<'EOF'\nanalyse('echo hi | acme-ssh-mcp')\nEOF",
    "cat <<-'END' | grep x\n\tacme-ssh-mcp\n\tEND",
    "python3 - <<'PY'\nsubprocess.run(['acme-loki-mcp'])",
])
def test_a_wrapper_named_inside_a_heredoc_is_not_a_spawn(command):
    remote, _ = analyse(command)
    assert not (remote and remote.channel == classify.MCP_SPAWN_CHANNEL)


def test_the_line_that_opens_a_heredoc_is_still_a_command():
    remote, _ = analyse('cat <<EOF | ~/.local/bin/acme-gitlab-mcp\n{"a":1}\nEOF')
    assert remote is not None
    assert remote.channel == classify.MCP_SPAWN_CHANNEL
    assert remote.via == "acme-gitlab"


def test_a_herestring_is_not_a_heredoc():
    command = 'grep -q x <<< "$data"\nrm -f /tmp/junk'
    assert classify.strip_heredocs(command) == command


def test_a_destructive_command_inside_a_heredoc_is_not_a_deletion():
    _, fs = analyse("cat > cfg.yml <<'EOF'\nkey: value\nrm -rf /srv/data\nEOF")
    assert not [path for path, op in fs if op == "delete"]


@pytest.mark.parametrize("command,expected", [
    (r'grep -rn "do_start\|llm_mcp_server" --include=*.py .',
     [r'grep -rn "do_start\|llm_mcp_server" --include=*.py .']),
    ("grep -E 'a|b' file.txt", ["grep -E 'a|b' file.txt"]),
    ('echo "a; b" && ls /tmp', ['echo "a; b"', 'ls /tmp']),
    ("curl 'https://x.test/?a=1&b=2'", ["curl 'https://x.test/?a=1&b=2'"]),
    ("ps aux | grep ssh", ["ps aux", "grep ssh"]),
    (r"echo a\;b", [r"echo a\;b"]),
])
def test_a_separator_inside_quotes_does_not_split(command, expected):
    assert classify.segments(command) == expected


def test_a_wrapper_named_in_a_quoted_pattern_is_not_a_spawn():
    remote, _ = analyse(r'grep -rn "do_start\|llm_mcp_server" --include=*.py .')
    assert not (remote and remote.channel == classify.MCP_SPAWN_CHANNEL)


def test_a_url_keeps_its_query_string():
    remote, _ = analyse("curl 'https://api.test/v1/x?a=1&b=2'")
    assert remote is not None
    assert remote.url and remote.url.endswith("?a=1&b=2")


def test_the_significant_call_keeps_its_own_arguments():
    calls = [("cd", ["/srv"]), ("pytest", ["-q", "tests/"])]
    assert classify.significant_call(calls) == ("pytest", ["-q", "tests/"])


def test_a_command_that_is_only_incidental_still_names_itself():
    assert classify.significant_call([("cd", ["/srv"])]) == ("cd", ["/srv"])


def test_a_fragment_is_never_the_significant_call():
    calls = [('${cmd:0:70}"', []), ("printf", ["%s"])]
    assert classify.significant_call(calls) == ("printf", ["%s"])
    assert classify.significant_call([('${cmd:0:70}"', [])]) == ("", [])


def test_nothing_in_means_nothing_out():
    assert classify.significant_call([]) == ("", [])
