from __future__ import annotations

import io
import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from xenia import broker, db, secrets, vault

VALUE = "glpat-" + "cli-entered-value-4321"


class Memory:
    kind = "memory"

    def __init__(self):
        self.values: dict[str, str] = {}

    def get(self, name):
        return self.values.get(name)

    def set(self, name, value):
        self.values[name] = value

    def delete(self, name):
        return self.values.pop(name, None) is not None

    def names(self):
        return list(self.values)

    def describe(self):
        return {"kind": self.kind, "available": True, "provider": "memory"}


class Tty(io.StringIO):
    """A stdin that says it is a terminal, for the dialogues that only run there."""

    def isatty(self):
        return True


@pytest.fixture
def answers(monkeypatch):
    """Queue up what a person would type at the prompts, in order."""
    def give(*replies):
        queued = list(replies)
        monkeypatch.setattr(sys, "stdin", Tty())
        monkeypatch.setattr("builtins.input",
                            lambda prompt="": queued.pop(0) if queued else "")
    return give


@pytest.fixture
def cli(tmp_path, monkeypatch):
    """The CLI, wired to a throwaway database and an in-memory store."""
    monkeypatch.setenv("XENIA_DB", str(tmp_path / "audit.db"))
    store = Memory()
    monkeypatch.setattr(vault, "backend", lambda kind=None: store)
    monkeypatch.setattr(vault, "configured_kind", lambda: store.kind)
    monkeypatch.setattr(secrets.vault, "backend", lambda kind=None: store)

    def run(*argv, stdin=None):
        if stdin is not None:
            monkeypatch.setattr(sys, "stdin", io.StringIO(stdin))
        return secrets.main(list(argv))

    run.store = store
    run.db = lambda: db.connect(tmp_path / "audit.db")
    return run


# -- entering a credential --------------------------------------------------

def test_adding_registers_the_policy_and_stores_the_value(cli, capsys):
    assert cli("secret", "add", "gitlab-pat",
               "--host", "gitlab.example.com", stdin=VALUE) == 0

    assert cli.store.values == {"gitlab-pat": VALUE}
    conn = cli.db()
    row = broker.registry(conn)[0]
    conn.close()
    assert row["name"] == "gitlab-pat"
    assert row["hosts"] == ["gitlab.example.com"]
    assert row["methods"] == list(broker.DEFAULT_METHODS)


def test_a_piped_value_is_read_from_stdin(monkeypatch):
    monkeypatch.setattr(sys, "stdin", io.StringIO(VALUE + "\n"))
    assert secrets.read_value("pat") == VALUE


def test_a_typed_value_is_asked_for_twice_and_never_echoed(monkeypatch):
    """A value reaches xenia from a terminal or a pipe, and nowhere else.

    There is deliberately no flag that takes one: an argument is in the
    process table for every user on the machine while the command runs, and
    in the shell history for good.
    """
    typed = iter([VALUE, VALUE])
    monkeypatch.setattr(sys.stdin, "isatty", lambda: True, raising=False)
    monkeypatch.setattr(secrets.getpass, "getpass", lambda prompt: next(typed))

    assert secrets.read_value("pat") == VALUE


def test_a_mistyped_value_is_rejected_rather_than_stored(monkeypatch):
    typed = iter(["one", "other"])
    monkeypatch.setattr(sys.stdin, "isatty", lambda: True, raising=False)
    monkeypatch.setattr(secrets.getpass, "getpass", lambda prompt: next(typed))

    with pytest.raises(ValueError, match="did not match"):
        secrets.read_value("pat")


def test_a_host_is_optional_because_the_first_use_will_ask(cli, capsys):
    """Nobody typing in a token knows the hostname it will be used against."""
    assert cli("secret", "add", "loose", stdin=VALUE) == 0

    conn = cli.db()
    assert broker.registry(conn)[0]["hosts"] == []
    conn.close()
    assert cli.store.values == {"loose": VALUE}
    assert "asked the first time" in capsys.readouterr().out


def test_policy_only_leaves_the_stored_value_alone(cli):
    cli("secret", "add", "pat", "--host", "one.example", stdin=VALUE)
    assert cli("secret", "add", "pat", "--host", "two.example",
               "--policy-only") == 0

    conn = cli.db()
    assert broker.registry(conn)[0]["hosts"] == ["two.example"]
    conn.close()
    assert cli.store.values == {"pat": VALUE}


def test_methods_and_paths_narrow_it(cli):
    cli("secret", "add", "pat", "--host", "h.example", "--method", "GET",
        "--method", "POST", "--path", "/api/*", stdin=VALUE)

    conn = cli.db()
    row = broker.registry(conn)[0]
    conn.close()
    assert row["methods"] == ["GET", "POST"]
    assert row["paths"] == ["/api/*"]


def test_removing_takes_the_value_with_the_policy(cli):
    cli("secret", "add", "pat", "--host", "h.example", stdin=VALUE)
    assert cli("secret", "rm", "pat") == 0

    conn = cli.db()
    assert broker.registry(conn) == []
    conn.close()
    assert cli.store.values == {}


def test_renaming_moves_the_value_and_the_policy_together(cli, capsys):
    cli("secret", "add", "pat", "--host", "h.example", stdin=VALUE)
    capsys.readouterr()

    assert cli("secret", "rename", "pat", "gitlab-pat") == 0

    assert cli.store.values == {"gitlab-pat": VALUE}
    conn = cli.db()
    rows = broker.registry(conn)
    conn.close()
    assert [row["name"] for row in rows] == ["gitlab-pat"]
    assert rows[0]["hosts"] == ["h.example"]
    assert "{{secret:gitlab-pat}}" in capsys.readouterr().out


def test_a_rename_keeps_an_approval_that_is_already_live(cli):
    cli("secret", "add", "pat", "--host", "h.example", stdin=VALUE)
    cli("grant", "pat", "--host", "h.example")

    assert cli("secret", "rename", "pat", "moved") == 0

    conn = cli.db()
    live = broker.grants(conn)
    conn.close()
    assert [row["name"] for row in live] == ["moved"]


def test_renaming_onto_a_name_that_is_taken_changes_nothing(cli, capsys):
    cli("secret", "add", "pat", "--host", "h.example", stdin=VALUE)
    cli("secret", "add", "other", "--host", "o.example", stdin=VALUE + "-b")
    capsys.readouterr()

    assert cli("secret", "rename", "pat", "other") == 2

    assert "already" in capsys.readouterr().err
    assert cli.store.values == {"pat": VALUE, "other": VALUE + "-b"}


def test_renaming_something_that_is_not_there_says_so(cli, capsys):
    assert cli("secret", "rename", "ghost", "pat") == 2
    assert "no credential" in capsys.readouterr().err


def test_removing_with_no_name_lists_them_and_asks_which(cli, answers, capsys):
    """What the tray's Credentials → Delete… opens: a click has no name in it."""
    cli("secret", "add", "pat", "--host", "h.example", stdin=VALUE)
    cli("secret", "add", "other", "--host", "o.example", stdin=VALUE)
    capsys.readouterr()

    answers("pat", "y")
    assert cli("secret", "rm") == 0

    shown = capsys.readouterr().out
    assert "pat" in shown and "other" in shown
    assert "h.example" in shown, "which hosts it reaches is what tells them apart"
    assert cli.store.values == {"other": VALUE}


def test_one_can_be_picked_by_number(cli, answers):
    cli("secret", "add", "pat", "--host", "h.example", stdin=VALUE)
    cli("secret", "add", "other", "--host", "o.example", stdin=VALUE)

    answers("2", "y")  # listed by name: other, pat
    assert cli("secret", "rm") == 0

    assert cli.store.values == {"other": VALUE}


def test_the_confirmation_is_no_by_default(cli, answers):
    cli("secret", "add", "pat", "--host", "h.example", stdin=VALUE)

    answers("pat", "")
    assert cli("secret", "rm") == 0

    assert cli.store.values == {"pat": VALUE}, "enter is not a yes here"


def test_an_answer_that_names_nothing_removes_nothing(cli, answers, capsys):
    cli("secret", "add", "pat", "--host", "h.example", stdin=VALUE)

    answers("9", "y")
    assert cli("secret", "rm") == 2

    assert cli.store.values == {"pat": VALUE}
    assert "nothing was changed" in capsys.readouterr().err


def test_a_value_left_behind_by_a_cancelled_add_can_be_picked_too(cli, answers):
    cli.store.values["orphan"] = VALUE

    answers("orphan", "y")
    assert cli("secret", "rm") == 0

    assert cli.store.values == {}


def test_removing_needs_a_name_where_nothing_can_be_asked(cli, capsys):
    assert cli("secret", "rm") == 2
    assert "xenia secret rm NAME" in capsys.readouterr().err


# -- approving --------------------------------------------------------------

def test_granting_reports_both_clocks(cli, capsys):
    cli("secret", "add", "pat", "--host", "h.example", stdin=VALUE)
    assert cli("grant", "pat", "--host", "h.example") == 0

    out = capsys.readouterr().out
    assert "reads only" in out
    assert "slides forward on use" in out
    assert "does not move" in out


def test_the_single_registered_host_is_assumed(cli):
    cli("secret", "add", "pat", "--host", "only.example", stdin=VALUE)
    assert cli("grant", "pat") == 0

    conn = cli.db()
    assert broker.grants(conn)[0]["host"] == "only.example"
    conn.close()


def test_a_write_grant_is_asked_for_explicitly(cli):
    cli("secret", "add", "pat", "--host", "h.example", "--method", "POST",
        stdin=VALUE)
    cli("grant", "pat", "--host", "h.example", "--write")

    conn = cli.db()
    assert broker.grants(conn)[0]["mutating"] == 1
    conn.close()


def test_a_window_can_be_shortened(cli):
    cli("secret", "add", "pat", "--host", "h.example", stdin=VALUE)
    cli("grant", "pat", "--host", "h.example", "--for", "10m")

    conn = cli.db()
    row = broker.grants(conn)[0]
    conn.close()
    assert row["expires_at"] < row["ceiling_at"]


def test_granting_something_unknown_says_so(cli, capsys):
    assert cli("grant", "nothing", "--host", "h.example") == 2
    assert "no credential" in capsys.readouterr().err


def test_revoking_ends_every_grant_for_a_name(cli, capsys):
    cli("secret", "add", "pat", "--host", "h.example", stdin=VALUE)
    cli("grant", "pat", "--host", "h.example")
    assert cli("revoke", "pat") == 0

    conn = cli.db()
    assert broker.grants(conn) == []
    conn.close()


def test_listing_says_what_is_registered_and_approved(cli, capsys):
    cli("secret", "add", "pat", "--host", "h.example", stdin=VALUE)
    cli("grant", "pat", "--host", "h.example")
    capsys.readouterr()

    assert cli("secret", "list") == 0
    out = capsys.readouterr().out
    assert "pat" in out
    assert "1 live grant" in out


def test_an_empty_list_says_how_to_start(cli, capsys):
    cli("secret", "list")
    assert "xenia secret new" in capsys.readouterr().out


# -- durations --------------------------------------------------------------

@pytest.mark.parametrize("text,seconds", [
    ("90s", 90), ("30m", 1800), ("4h", 14400), ("2d", 172800), ("45", 2700)])
def test_durations(text, seconds):
    assert secrets.duration(text) == seconds


def test_a_bad_duration_says_what_one_looks_like():
    with pytest.raises(ValueError, match="30m"):
        secrets.duration("soon")


# -- setup ------------------------------------------------------------------

def test_probe_reports_the_provider_and_the_round_trip(monkeypatch):
    store = Memory()
    monkeypatch.setattr(vault, "backend", lambda kind=None: store)

    found = secrets.probe()
    assert found["available"] is True
    assert found["selftest"]["ok"] is True


def test_probe_survives_a_platform_with_no_store(monkeypatch):
    def unsupported(kind=None):
        raise vault.VaultError("no credential store for sunos")

    monkeypatch.setattr(vault, "backend", unsupported)
    found = secrets.probe()

    assert found["available"] is False
    assert "sunos" in found["detail"]


def test_keepassxc_state_reads_its_ini(tmp_path, monkeypatch):
    ini = tmp_path / "keepassxc.ini"
    ini.write_text("[General]\nx=1\n\n[FdoSecrets]\nEnabled=true\n"
                   "ExposedGroup={abc}\n")
    monkeypatch.setattr(secrets, "keepassxc_config", lambda: ini)

    state = secrets.keepassxc_state()
    assert state["fdo_enabled"] is True
    assert state["exposed_group"] is True


def test_wiring_keepassxc_turns_the_integration_on(tmp_path):
    ini = tmp_path / "keepassxc.ini"
    ini.write_text("[General]\nRememberLastDatabases=true\n")

    secrets.enable_keepassxc_fdo(ini)

    text = ini.read_text()
    assert "[FdoSecrets]" in text
    assert "Enabled=true" in text
    assert "RememberLastDatabases=true" in text


def test_wiring_flips_an_existing_false_rather_than_adding_a_second(tmp_path):
    ini = tmp_path / "keepassxc.ini"
    ini.write_text("[FdoSecrets]\nEnabled=false\n")

    secrets.enable_keepassxc_fdo(ini)

    assert ini.read_text().count("Enabled=") == 1
    assert "Enabled=true" in ini.read_text()


def test_wiring_a_missing_config_creates_one(tmp_path):
    ini = tmp_path / "nested" / "keepassxc.ini"
    secrets.enable_keepassxc_fdo(ini)

    assert ini.read_text().startswith("[FdoSecrets]")


def test_setup_reports_a_working_store_and_stops(monkeypatch, capsys):
    monkeypatch.setattr(vault, "backend", lambda kind=None: Memory())

    assert secrets.setup([]) == 0
    out = capsys.readouterr().out
    assert "self-test   passed" in out
    assert "xenia secret new" in out


def test_setup_offers_the_clients_when_nothing_is_serving(monkeypatch, capsys):
    monkeypatch.setattr(secrets, "probe", lambda: {
        "platform": "linux", "backend": "secret-service", "provider": None,
        "available": False, "selftest": None, "detail": "nothing is serving"})

    assert secrets.setup([]) == 1
    out = capsys.readouterr().out
    assert "keepassxc" in out
    assert "gnome-keyring" in out
    assert "only one program can own org.freedesktop.secrets" in out


def test_a_cancelled_entry_leaves_the_old_policy_in_place(cli, capsys,
                                                          monkeypatch):
    """Widening the hosts and then failing to enter the value used to stick.

    The wider policy — and any live grant under it — stayed in force over the
    OLD value, which is a credential reachable somewhere its owner never
    approved it for.
    """
    cli("secret", "add", "pat", "--host", "one.example", stdin=VALUE)

    def cancelled(name):
        raise KeyboardInterrupt

    monkeypatch.setattr(secrets, "read_value", cancelled)
    assert cli("secret", "add", "pat", "--host", "widened.example") == 1

    conn = cli.db()
    assert broker.registry(conn)[0]["hosts"] == ["one.example"]
    conn.close()
    assert cli.store.values == {"pat": VALUE}


def test_a_store_that_refuses_the_write_leaves_the_old_policy_too(cli,
                                                                  monkeypatch):
    from xenia import vault as vault_mod

    cli("secret", "add", "pat", "--host", "one.example", stdin=VALUE)

    def refuses(name, value):
        raise vault_mod.VaultError("the keyring is locked")

    monkeypatch.setattr(cli.store, "set", refuses)
    assert cli("secret", "add", "pat", "--host", "widened.example",
               stdin="new-value") == 1

    conn = cli.db()
    assert broker.registry(conn)[0]["hosts"] == ["one.example"]
    conn.close()


def test_a_short_grant_is_recorded_with_its_window(cli):
    cli("secret", "add", "pat", "--host", "h.example", stdin=VALUE)
    cli("grant", "pat", "--host", "h.example", "--for", "60s")

    conn = cli.db()
    assert broker.grants(conn)[0]["window_s"] == 60
    conn.close()


def test_a_body_policy_is_set_from_stdin_and_read_back(cli, capsys):
    cli("secret", "add", "api-key", "--host", "api.test", stdin=VALUE)
    capsys.readouterr()

    assert cli("secret", "body", "api-key", stdin=json.dumps({"actions": {
        "create": {"methods": ["POST"], "paths": ["/v1/items"],
                   "max": {"count": "10"}}}})) == 0
    out = capsys.readouterr().out
    assert "may now take these actions and no others" in out
    assert "count<=10" in out
    assert "is refused" in out

    assert cli("secret", "body", "api-key", "--show") == 0
    assert "create" in capsys.readouterr().out


def test_a_credential_with_no_body_policy_says_so(cli, capsys):
    cli("secret", "add", "pat", "--host", "h.example", stdin=VALUE)
    capsys.readouterr()
    cli("secret", "body", "pat", "--show")

    assert "no body policy" in capsys.readouterr().out


def test_a_service_credential_cannot_be_added_without_one(cli, capsys):
    assert cli("secret", "add", "api-key", "--host", "api.test",
               "--service", "acme", stdin=VALUE) == 2
    assert "no body policy" in capsys.readouterr().err


def test_a_service_credential_registers_once_the_policy_is_there(cli, capsys):
    cli("secret", "add", "api-key", "--host", "api.test", stdin=VALUE)
    cli("secret", "body", "api-key", stdin=json.dumps({"actions": {
        "read": {"methods": ["GET"], "paths": ["/api/account/*"]}}}))

    assert cli("secret", "add", "api-key", "--host", "api.test",
               "--service", "acme", "--policy-only") == 0
    conn = cli.db()
    assert broker.registry(conn)[0]["service"] == "acme"
    conn.close()


# -- the interactive dialogue the tray opens --------------------------------

@pytest.fixture
def typed(monkeypatch):
    """Drive the wizard the way a person at a terminal would."""
    def answers(*lines, password=VALUE):
        replies = iter(lines)
        monkeypatch.setattr(sys.stdin, "isatty", lambda: True, raising=False)
        monkeypatch.setattr("builtins.input", lambda prompt="": next(replies))
        monkeypatch.setattr(secrets.getpass, "getpass",
                            lambda prompt: password)
    return answers


def test_the_wizard_asks_for_a_name_and_a_value_and_nothing_else(cli, typed,
                                                                  capsys):
    """It cannot sensibly ask where a token will be used, so it does not.

    Hosts, methods and paths were four questions nobody typing in a token can
    answer; the scope arrives later, from the first real request.
    """
    typed("api-key", "")
    assert secrets.wizard([]) == 0

    conn = cli.db()
    row = broker.registry(conn)[0]
    assert row["name"] == "api-key"
    assert row["hosts"] == []
    assert broker.grants(conn) == []
    conn.close()
    assert cli.store.values == {"api-key": VALUE}

    out = capsys.readouterr().out
    assert "you do not have to say where it may go" in out
    for gone in ("Host(s)", "Methods", "Path prefixes", "Note"):
        assert gone not in out


def test_the_wizard_says_a_prompt_will_decide_the_scope(cli, typed, capsys):
    typed("api-key", "")
    secrets.wizard([])

    out = " ".join(capsys.readouterr().out.split())
    assert "The first time something reaches for it you will be asked" in out


def test_a_cancelled_wizard_stores_nothing(cli, typed, monkeypatch):
    typed("api-key", "api.test", "GET,HEAD", "", "")

    def cancelled(name):
        raise KeyboardInterrupt

    monkeypatch.setattr(secrets, "read_value", cancelled)
    assert secrets.wizard([]) == 1

    conn = cli.db()
    assert broker.registry(conn) == []
    conn.close()
    assert cli.store.values == {}


def test_the_wizard_sets_the_store_up_first_when_there_is_none(cli, typed,
                                                               monkeypatch):
    """'setup if not already' is the first half of what the tray item does."""
    ran = []
    monkeypatch.setattr(secrets, "probe", lambda: {
        "platform": "linux", "backend": "secret-service", "provider": None,
        "available": False, "selftest": None, "detail": "nothing is serving"})
    monkeypatch.setattr(secrets, "setup",
                        lambda argv: ran.append(argv) or 1)
    typed("api-key")

    assert secrets.wizard([]) == 1
    assert ran == [[]], "setup must be offered before anything is asked for"


def test_the_wizard_refuses_to_run_where_nothing_can_be_typed(cli, capsys):
    assert secrets.wizard([]) == 2
    assert "interactive" in capsys.readouterr().err


def test_a_terminal_is_chosen_by_its_own_convention(monkeypatch):
    monkeypatch.setattr(secrets.shutil, "which",
                        lambda name: f"/usr/bin/{name}"
                        if name == "gnome-terminal" else None)

    assert secrets.terminal_for(["xenia", "secret", "new"]) == [
        "/usr/bin/gnome-terminal", "--", "xenia", "secret", "new"]


def test_no_terminal_at_all_is_reported_rather_than_guessed(monkeypatch):
    monkeypatch.setattr(secrets.shutil, "which", lambda name: None)

    assert secrets.terminal_for(["xenia"]) is None
    assert secrets.open_in_terminal(["xenia"]) is False


# -- a signing profile that nests -------------------------------------------

NESTED_PROFILE = {
    "scheme": "secp256k1-eip712",
    "domain": {"name": "Example", "version": "1", "chainId": 1,
               "verifyingContract": "0x" + "00" * 20},
    "types": {"Agent": [{"name": "nonce", "type": "uint64"}]},
    "primary_type": "Agent",
    "payload_policy": {"actions": {"one": {
        "methods": ["SIGN"], "paths": ["/"], "required": ["nonce"]}}},
}


def profile_on(cli, name="service-key"):
    conn = cli.db()
    row = broker.entry(conn, name)
    held = broker.profiles_for(row, "SIGN")
    conn.close()
    return held


def test_a_nested_signing_profile_is_stored_as_json_not_as_strings(cli):
    """`key=value` cannot spell a domain, a schema or a message binding.

    Stringifying them would store a profile the scheme then refuses at signing
    time — the failure arriving one operator step after the mistake.
    """
    assert cli("secret", "add", "service-key", "--host", "api.example.com",
               stdin=VALUE) == 0
    assert cli("secret", "sign", "service-key", "dispatch",
               stdin=json.dumps(NESTED_PROFILE)) == 0

    held = profile_on(cli)["dispatch"]
    assert held["domain"] == NESTED_PROFILE["domain"]
    assert held["types"] == NESTED_PROFILE["types"]
    assert held["payload_policy"] == NESTED_PROFILE["payload_policy"]


def test_the_flat_form_still_works(cli):
    assert cli("secret", "add", "service-key", "--host", "api.example.com",
               stdin=VALUE) == 0
    assert cli("secret", "sign", "service-key", "hm", "scheme=hmac",
               "template={ts}{body}", "digest=sha256") == 0

    held = profile_on(cli)["hm"]
    assert held["scheme"] == "hmac"
    assert held["template"] == "{ts}{body}"


def test_a_profile_that_is_not_json_is_refused_rather_than_stored(cli):
    assert cli("secret", "add", "service-key", "--host", "api.example.com",
               stdin=VALUE) == 0

    assert cli("secret", "sign", "service-key", "dispatch", stdin="not json") == 2
    assert cli("secret", "sign", "service-key", "dispatch", stdin="[1, 2]") == 2
    assert profile_on(cli) == {}


# -- until, the standing approval's clock ----------------------------------

def test_a_bare_date_means_the_end_of_that_day():
    """"Until the 8th" means through the 8th. An approval that stopped at
    00:00 on the morning of the date it was given for would fail on exactly
    the day it was needed."""
    moment = secrets.until_moment("2026-12-08")

    assert moment.isoformat() == "2026-12-08T23:59:59+00:00"


def test_until_also_takes_a_duration_and_a_timestamp():
    from datetime import datetime, timezone

    assert secrets.until_moment("2026-12-08T12:00Z") == datetime(
        2026, 12, 8, 12, 0, tzinfo=timezone.utc)
    assert secrets.until_moment("85d") > datetime.now(timezone.utc)


def test_until_refuses_something_that_is_neither():
    with pytest.raises(ValueError, match="not a date or duration"):
        secrets.until_moment("next tuesday")


def test_granting_for_signing_infers_mutating_even_without_write_flag(cli):
    """Signing is inherently mutating; omitting --write must not create a
    grant with mutating=0 that is never matched."""
    assert cli("secret", "add", "service-key", "--host", "api.example.com", stdin=VALUE) == 0
    assert cli("secret", "sign", "service-key", "dispatch", "scheme=hmac", "template={body}") == 0

    status = cli("grant", "service-key", "--host", "(sign)", "--until", "2026-12-08",
                 "--profiles", "dispatch", "--reason", "batch processing")

    assert status == 0
    row = cli.db().execute("SELECT mutating FROM secret_grant WHERE name = 'service-key'").fetchone()
    assert row["mutating"] == 1
