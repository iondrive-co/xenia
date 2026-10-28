from __future__ import annotations

import base64
import io
import json
import subprocess
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from xenia import backup, broker, db, secrets, vault

VALUE = "glpat-" + "backup-value-7781"
OTHER = "glpat-" + "backup-other-1290"
HOST = "gitlab.example.com"


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
    def isatty(self):
        return True


class Vault:
    def __init__(self, state="unlocked", session="session-token-1"):
        self.state = state
        self.session = session
        self.items: dict[str, dict] = {}
        self.folders: dict[str, str] = {}
        self.calls: list[dict] = []
        self.refuse: set[str] = set()
        self.during_create = None
        self.made = 0

    def _id(self, kind):
        self.made += 1
        return f"{kind}-{self.made}"

    def __call__(self, argv, input=None, stdout=None, stderr=None, text=None,
                 env=None, timeout=None):
        self.calls.append({"argv": list(argv), "input": input, "env": dict(env or {}),
                           "stderr": stderr})
        args = list(argv[1:])

        def ok(out=""):
            return subprocess.CompletedProcess(argv, 0, out, "")

        def no(why):
            return subprocess.CompletedProcess(argv, 1, "", why)

        if args[0] == "status":
            return ok(json.dumps({"status": self.state}))
        if args[0] in ("unlock", "login"):
            self.state = "unlocked"
            return ok(self.session + "\n")
        if args[0] == "lock":
            self.state = "locked"
            return ok("Your vault is locked.")
        if args[0] == "sync":
            return ok("Syncing complete.")
        sent = json.loads(base64.b64decode(input)) if input else None
        if args[:2] == ["list", "folders"]:
            return ok(json.dumps([{"id": key, "name": name} for key, name in self.folders.items()]))
        if args[:2] == ["create", "folder"]:
            key = self._id("folder")
            self.folders[key] = sent["name"]
            return ok(json.dumps({"id": key, **sent}))
        if args[:2] == ["list", "items"]:
            search = args[args.index("--search") + 1]
            return ok(json.dumps([item for item in self.items.values() if search in item["name"]]))
        if args[:2] == ["get", "item"]:
            item = self.items.get(args[2])
            return ok(json.dumps(item)) if item else no("Not found.")
        if args[:2] == ["create", "item"]:
            if sent["fields"][-1]["value"] in self.refuse:
                return no("an invented refusal")
            if self.during_create:
                self.during_create()
            key = self._id("item")
            self.items[key] = {**sent, "id": key}
            return ok(json.dumps(self.items[key]))
        if args[:2] == ["edit", "item"]:
            if args[2] not in self.items:
                return no("Not found.")
            self.items[args[2]] = {**sent, "id": args[2]}
            return ok(json.dumps(self.items[args[2]]))
        return no(f"not something this fake does: {args}")

    def verbs(self):
        return [call["argv"][1] for call in self.calls]

    def named(self):
        return {item["name"]: item for item in self.items.values()}


@pytest.fixture
def world(tmp_path, monkeypatch):
    monkeypatch.setenv("XENIA_DB", str(tmp_path / "audit.db"))
    store = Memory()
    monkeypatch.setattr(vault, "backend", lambda kind=None: store)
    monkeypatch.setattr(vault, "configured_kind", lambda: store.kind)
    told: list[tuple[str, str]] = []
    monkeypatch.setattr(broker, "_notify", lambda summary, body: told.append((summary, body)))
    conn = db.connect(tmp_path / "audit.db")
    yield conn, store, told
    conn.close()


def bitwarden(fake, environ=None):
    return backup.Bitwarden(command="bw", run=fake, environ=environ or {})


def quiet(conn, chosen, **kwargs):
    return backup.run(conn, chosen, say=lambda line: None, **kwargs)


def pending(conn):
    return [row["name"] for row in backup.pending(conn, "bitwarden")]


def test_each_credential_is_copied_into_an_item_of_its_own_and_recorded(world):
    conn, _store, _told = world
    secrets.add(conn, "gitlab-pat", VALUE, hosts=[HOST], note="CI reads issues")
    secrets.add(conn, "shop-api", OTHER, hosts=["api.shop.test"])
    fake = Vault()

    out = quiet(conn, bitwarden(fake))

    assert out == {"done": ["gitlab-pat", "shop-api"], "missing": [], "failed": []}
    items = fake.named()
    assert items["xenia: gitlab-pat"]["login"]["password"] == VALUE
    assert items["xenia: shop-api"]["login"]["password"] == OTHER
    assert list(fake.folders.values()) == ["xenia"]
    assert {item["folderId"] for item in items.values()} == set(fake.folders)
    notes = items["xenia: gitlab-pat"]["notes"]
    assert notes.startswith("CI reads issues") and HOST in notes
    assert pending(conn) == []


def test_a_value_reaches_bw_on_its_stdin_and_never_on_its_command_line(world):
    conn, _store, _told = world
    secrets.add(conn, "gitlab-pat", VALUE, hosts=[HOST])
    fake = Vault()

    quiet(conn, bitwarden(fake))

    for call in fake.calls:
        assert VALUE not in " ".join(call["argv"])
        assert VALUE not in json.dumps(call["env"])
    assert any(call["input"] and VALUE in base64.b64decode(call["input"]).decode()
               for call in fake.calls)
    assert VALUE not in fake.named()["xenia: gitlab-pat"]["notes"]


def test_a_changed_value_is_copied_again_into_the_same_item(world):
    conn, _store, _told = world
    secrets.add(conn, "gitlab-pat", VALUE, hosts=[HOST])
    fake = Vault()
    quiet(conn, bitwarden(fake))
    first = fake.named()["xenia: gitlab-pat"]["id"]

    secrets.add(conn, "gitlab-pat", OTHER, hosts=[HOST])
    assert pending(conn) == ["gitlab-pat"]
    quiet(conn, bitwarden(fake))

    assert list(fake.items) == [first]
    assert fake.items[first]["login"]["password"] == OTHER
    assert ["edit", "item", first] in [call["argv"][1:4] for call in fake.calls]
    assert pending(conn) == []


@pytest.mark.parametrize("saved_ref", [True, False])
@pytest.mark.parametrize("marked", [True, False])
def test_a_shared_item_never_receives_a_private_credential(world, saved_ref, marked):
    conn, _store, _told = world
    secrets.add(conn, "shop-api", VALUE, hosts=["api.shop.test"])
    fake = Vault()
    quiet(conn, bitwarden(fake))
    shared = fake.named()["xenia: shop-api"]
    shared.update(organizationId="organization-7", collectionIds=["collection-9"])
    if not marked:
        shared["fields"] = []
    if not saved_ref:
        conn.execute("UPDATE secret SET backup_ref = NULL WHERE name = 'shop-api'")
        conn.commit()
    secrets.add(conn, "shop-api", OTHER, hosts=["api.shop.test"])

    out = quiet(conn, bitwarden(fake))

    assert out == {"done": ["shop-api"], "missing": [], "failed": []}
    assert shared["login"]["password"] == VALUE
    assert not any(call["argv"][1:4] == ["edit", "item", shared["id"]]
                   for call in fake.calls)
    ref = broker.entry(conn, "shop-api")["backup_ref"]
    assert ref != shared["id"]
    copied = fake.items[ref]
    assert copied["login"]["password"] == OTHER
    assert copied["organizationId"] is None and copied["collectionIds"] is None
    assert pending(conn) == []


def test_using_a_credential_does_not_make_it_due_again(world):
    conn, _store, _told = world
    secrets.add(conn, "gitlab-pat", VALUE, hosts=[HOST])
    quiet(conn, bitwarden(Vault()))

    conn.execute("UPDATE secret SET last_used_at = '2026-01-02T03:04:05', last_nonce = 7")
    conn.commit()

    assert pending(conn) == []


def test_a_renamed_credential_keeps_its_item(world):
    conn, _store, _told = world
    secrets.add(conn, "gitlab-pat", VALUE, hosts=[HOST])
    fake = Vault()
    quiet(conn, bitwarden(fake))
    first = fake.named()["xenia: gitlab-pat"]["id"]

    secrets.rename(conn, "gitlab-pat", "gitlab-token")
    assert pending(conn) == ["gitlab-token"]
    quiet(conn, bitwarden(fake))

    assert list(fake.named()) == ["xenia: gitlab-token"]
    assert fake.items[first]["fields"] == [{"name": "xenia-name", "value": "gitlab-token", "type": 0}]
    assert fake.items[first]["login"]["password"] == VALUE


@pytest.mark.parametrize("state, verb", [("locked", "unlock"), ("unauthenticated", "login")])
def test_a_closed_vault_is_opened_for_the_run_and_locked_after(world, state, verb):
    conn, _store, _told = world
    secrets.add(conn, "gitlab-pat", VALUE, hosts=[HOST])
    fake = Vault(state=state)

    quiet(conn, bitwarden(fake))

    assert fake.verbs()[:2] == ["status", verb] and fake.verbs()[-1] == "lock"
    opening = fake.calls[1]
    assert opening["input"] is None and opening["stderr"] is None
    assert "BW_NOINTERACTION" not in opening["env"]
    later = fake.calls[2:]
    assert all(call["env"].get("BW_SESSION") == "session-token-1" for call in later)
    assert all(call["env"].get("BW_NOINTERACTION") == "true" for call in later)
    assert fake.state == "locked"


def test_a_vault_its_user_already_unlocked_is_left_unlocked(world):
    conn, _store, _told = world
    secrets.add(conn, "gitlab-pat", VALUE, hosts=[HOST])
    fake = Vault(state="unlocked")

    quiet(conn, bitwarden(fake, environ={"BW_SESSION": "their-session"}))

    assert "unlock" not in fake.verbs() and "lock" not in fake.verbs()
    assert all(call["env"]["BW_SESSION"] == "their-session" for call in fake.calls)


def test_a_copy_that_fails_stays_due_and_the_rest_go_on(world):
    conn, _store, _told = world
    secrets.add(conn, "gitlab-pat", VALUE, hosts=[HOST])
    secrets.add(conn, "shop-api", OTHER, hosts=["api.shop.test"])
    fake = Vault()
    fake.refuse = {"gitlab-pat"}

    out = quiet(conn, bitwarden(fake))

    assert out["done"] == ["shop-api"]
    assert [name for name, _why in out["failed"]] == ["gitlab-pat"]
    assert "an invented refusal" in out["failed"][0][1]
    assert pending(conn) == ["gitlab-pat"]


def test_a_credential_with_no_value_in_the_store_is_named_not_copied(world):
    conn, _store, _told = world
    broker.register(conn, "never-stored", hosts=[HOST])
    fake = Vault()

    out = quiet(conn, bitwarden(fake))

    assert out == {"done": [], "missing": ["never-stored"], "failed": []}
    assert fake.items == {}
    assert pending(conn) == ["never-stored"]


def test_an_item_deleted_from_the_vault_is_made_again(world):
    conn, _store, _told = world
    secrets.add(conn, "gitlab-pat", VALUE, hosts=[HOST])
    fake = Vault()
    quiet(conn, bitwarden(fake))
    fake.items.clear()

    secrets.add(conn, "gitlab-pat", OTHER, hosts=[HOST])
    out = quiet(conn, bitwarden(fake))

    assert out["done"] == ["gitlab-pat"]
    assert fake.named()["xenia: gitlab-pat"]["login"]["password"] == OTHER


def test_a_credential_changed_while_it_is_copied_stays_due(world):
    conn, _store, _told = world
    secrets.add(conn, "gitlab-pat", VALUE, hosts=[HOST])
    fake = Vault()
    fake.during_create = lambda: secrets.add(conn, "gitlab-pat", OTHER, hosts=[HOST])

    out = quiet(conn, bitwarden(fake))

    assert out["done"] == [] and "changed while" in out["failed"][0][1]
    assert pending(conn) == ["gitlab-pat"]


def test_no_cli_says_how_to_get_one(world, monkeypatch):
    monkeypatch.setattr(backup.shutil, "which", lambda name: None)

    with pytest.raises(backup.BackupError, match="not installed"):
        backup.Bitwarden(run=Vault()).open()


def test_an_unknown_target_names_the_ones_there_are(site_config):
    site_config({"backup": {"target": "carrier-pigeon"}})

    with pytest.raises(backup.BackupError, match="bitwarden, command"):
        backup.target()


def test_a_long_policy_is_shortened_to_fit_the_note(world):
    conn, _store, _told = world
    secrets.add(conn, "gitlab-pat", VALUE, hosts=[HOST])
    actions = {f"action-{n}": {"paths": ["/api/" + "x" * 200]} for n in range(60)}
    broker.set_body_policy(conn, "gitlab-pat", {"actions": actions})

    notes = backup.notes_for(backup.policy_of(broker.entry(conn, "gitlab-pat")))

    assert len(notes) <= backup.NOTE_LIMIT
    assert "action-59" in notes and "/api/xxx" not in notes


def command_target(tmp_path, answer="{'ref': 'kept-' + seen['name']}"):
    script = tmp_path / "keep.py"
    script.write_text("import json, sys\n"
                      "seen = json.load(sys.stdin)\n"
                      "open(sys.argv[1], 'a').write(json.dumps(seen) + '\\n')\n"
                      f"print(json.dumps({answer}))\n")
    kept = tmp_path / "kept.jsonl"
    return backup.Command([sys.executable, str(script), str(kept)]), kept


def test_a_command_target_reads_json_on_its_stdin_and_answers_a_ref(world, tmp_path):
    conn, _store, _told = world
    secrets.add(conn, "gitlab-pat", VALUE, hosts=[HOST])
    chosen, kept = command_target(tmp_path)

    assert quiet(conn, chosen)["done"] == ["gitlab-pat"]
    assert quiet(conn, chosen)["done"] == []
    secrets.add(conn, "gitlab-pat", OTHER, hosts=[HOST])
    quiet(conn, chosen)

    first, second = [json.loads(line) for line in kept.read_text().splitlines()]
    assert (first["name"], first["value"], first["ref"]) == ("gitlab-pat", VALUE, None)
    assert first["policy"]["hosts"] == [HOST]
    assert (second["value"], second["ref"]) == (OTHER, "kept-gitlab-pat")
    assert broker.entry(conn, "gitlab-pat")["backup_ref"] == "kept-gitlab-pat"
    assert [row["name"] for row in backup.pending(conn, "command")] == []


def test_a_command_that_answers_no_ref_has_copied_nothing(world, tmp_path):
    conn, _store, _told = world
    secrets.add(conn, "gitlab-pat", VALUE, hosts=[HOST])
    chosen, _kept = command_target(tmp_path, answer="{}")

    out = quiet(conn, chosen)

    assert out["done"] == [] and "without a \"ref\"" in out["failed"][0][1]
    assert [row["name"] for row in backup.pending(conn, "command")] == ["gitlab-pat"]


def test_the_command_will_not_run_without_a_terminal(world, monkeypatch, capsys):
    conn, _store, _told = world
    secrets.add(conn, "gitlab-pat", VALUE, hosts=[HOST])
    monkeypatch.setattr(sys, "stdin", io.StringIO(""))

    assert secrets.main(["secret", "backup"]) == 2
    assert "terminal" in capsys.readouterr().err


def test_the_command_copies_what_is_due_in_a_terminal(world, monkeypatch, capsys):
    conn, _store, _told = world
    secrets.add(conn, "gitlab-pat", VALUE, hosts=[HOST])
    fake = Vault()
    monkeypatch.setitem(backup.TARGETS, "bitwarden", lambda: bitwarden(fake))
    monkeypatch.setattr(sys, "stdin", Tty())

    assert secrets.main(["secret", "backup"]) == 0
    assert "Copied 1." in capsys.readouterr().out
    assert secrets.main(["secret", "backup"]) == 0
    assert "already in Bitwarden" in capsys.readouterr().out


def test_check_names_what_is_not_backed_up_and_fails_until_it_is(world, monkeypatch, capsys):
    conn, _store, _told = world
    secrets.add(conn, "gitlab-pat", VALUE, hosts=[HOST])

    assert secrets.main(["secret", "backup", "--check"]) == 1
    assert "gitlab-pat" in capsys.readouterr().out
    quiet(conn, bitwarden(Vault()))
    assert secrets.main(["secret", "backup", "--check"]) == 0
    assert "All 1 credential(s) are in the bitwarden backup" in capsys.readouterr().out


def test_the_list_ends_with_what_is_not_backed_up(world, capsys):
    conn, _store, _told = world
    secrets.add(conn, "gitlab-pat", VALUE, hosts=[HOST])

    assert secrets.main(["secret", "list"]) == 0

    assert "1 of 1 credential(s) are not in the bitwarden backup: gitlab-pat" in capsys.readouterr().out


def test_storing_a_credential_tells_the_desktop_once_backups_are_in_use(world):
    conn, _store, told = world
    secrets.add(conn, "gitlab-pat", VALUE, hosts=[HOST])
    assert told == []
    quiet(conn, bitwarden(Vault()))

    secrets.add(conn, "shop-api", OTHER, hosts=["api.shop.test"])

    assert len(told) == 1 and "'shop-api'" in told[0][1]


def test_a_configured_backup_tells_the_desktop_from_the_first_credential(world, site_config):
    conn, _store, told = world
    site_config({"backup": {"target": "bitwarden"}})

    secrets.add(conn, "gitlab-pat", VALUE, hosts=[HOST])

    assert len(told) == 1 and "'gitlab-pat'" in told[0][1]


def test_an_existing_database_gains_the_backup_columns(tmp_path):
    path = tmp_path / "audit.db"
    conn = db.connect(path)
    for column in ("backup_target", "backup_revision", "backup_ref", "backed_up_at"):
        conn.execute(f"ALTER TABLE secret DROP COLUMN {column}")
    conn.commit()
    conn.close()

    again = db.connect(path)
    columns = {row["name"] for row in again.execute("PRAGMA table_info(secret)")}
    again.close()

    assert {"backup_target", "backup_revision", "backup_ref", "backed_up_at"} <= columns
