from __future__ import annotations

import json
import urllib.error
import urllib.request
from pathlib import Path

import pytest
from conftest import CORE, FAKE_GITLAB_PAT, pre

from xenia import ingest, report as report_mod, vault

#: Never stored by any other test, so finding it anywhere is proof it leaked.
TYPED = "glpat-" + "typed-into-the-page-9f2a"


class Memory:
    """A credential store that keeps values in this process and nowhere else."""

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


@pytest.fixture
def store(monkeypatch):
    held = Memory()
    monkeypatch.setattr(vault, "backend", lambda kind=None: held)
    monkeypatch.setattr(vault, "configured_kind", lambda: held.kind)
    return held


@pytest.fixture
def served(conn, clock, tmp_path):
    clock()
    ingest.record(conn, pre("Bash", {
        "command": f"curl -H 'PRIVATE-TOKEN: {FAKE_GITLAB_PAT}' https://x.test",
    }))
    clock()
    ingest.record(conn, pre("Write", {
        "file_path": f"{CORE}/notes.md", "content": "hello\n",
    }))
    conn.commit()

    report = report_mod.Report(tmp_path / "audit.db")
    report.start()
    yield report
    report.stop()


def fetch(report, path):
    with urllib.request.urlopen(f"http://127.0.0.1:{report.port}{path}") as reply:
        return reply.read()


def api(report, path):
    joiner = "&" if "?" in path else "?"
    return json.loads(fetch(report, f"{path}{joiner}t={report.token}"))


def post(report, path, payload, *, token=True, headers=None):
    request = urllib.request.Request(
        f"http://127.0.0.1:{report.port}{path}"
        + (f"?t={report.token}" if token else ""),
        data=json.dumps(payload).encode(),
        headers={"Content-Type": "application/json", **(headers or {})},
        method="POST")
    with urllib.request.urlopen(request) as reply:
        return json.loads(reply.read())


def test_it_binds_to_loopback_only(served):
    assert served.host == "127.0.0.1"
    assert served.url.startswith("http://127.0.0.1:")


def test_a_request_without_the_token_is_refused(served):
    with pytest.raises(urllib.error.HTTPError) as caught:
        fetch(served, "/api/summary")
    assert caught.value.code == 403


def test_a_request_with_the_wrong_token_is_refused(served):
    with pytest.raises(urllib.error.HTTPError) as caught:
        fetch(served, "/api/summary?t=guess")
    assert caught.value.code == 403


def test_the_token_is_fresh_per_run(tmp_path):
    assert (report_mod.Report(tmp_path / "a.db").token
            != report_mod.Report(tmp_path / "a.db").token)


def test_an_unknown_path_is_a_404(served):
    with pytest.raises(urllib.error.HTTPError) as caught:
        fetch(served, f"/../../etc/passwd?t={served.token}")
    assert caught.value.code == 404


def test_the_page_is_served_with_a_restrictive_policy(served):
    with urllib.request.urlopen(f"{served.url}") as reply:
        body = reply.read()
        assert b"<table>" in body
        assert reply.headers["Content-Security-Policy"].startswith("default-src 'none'")
        assert reply.headers["Cache-Control"] == "no-store"


def test_summary_and_interactions_agree(served):
    stats = api(served, "/api/summary")
    rows = api(served, "/api/interactions")["rows"]
    assert stats["actions"] == len(rows)


def test_filters_are_applied_server_side(served):
    rows = api(served, "/api/interactions?kind=fs_change")["rows"]
    assert rows and all(r["kind"] == "fs_change" for r in rows)


def test_search_is_applied_server_side(served):
    assert api(served, "/api/interactions?q=notes.md")["rows"]
    assert api(served, "/api/interactions?q=zzzznope")["rows"] == []


def test_sorting_is_applied_server_side(served):
    stamps = [r["at"] for r in api(served, "/api/interactions?order=at&dir=asc")["rows"]]
    assert stamps == sorted(stamps)


def test_every_tab_has_an_endpoint_behind_it(served):
    for path in ("/api/tasks", "/api/interactions", "/api/friction",
                 "/api/disk", "/api/goals"):
        assert "rows" in api(served, path), path


def test_the_disk_report_is_served(served):
    rows = api(served, "/api/disk")["rows"]
    assert [r for r in rows if r["group"].endswith("notes.md")]


def test_credentials_are_redacted_in_what_the_page_fetches(served):
    blob = json.dumps(api(served, "/api/interactions"))
    assert FAKE_GITLAB_PAT not in blob
    assert "REDACTED" in blob


def test_a_broken_query_reports_rather_than_500s(served):
    assert "error" in api(served, "/api/nonexistent")


def test_the_record_itself_has_no_write_path(served):
    """Credentials are the user's to change. What an agent did is not.

    Every view is served from a read-only connection, and the only paths that
    answer a POST at all are the three credential ones.
    """
    for path in ("/api/dismiss", "/api/mute", "/api/decide", "/api/summary",
                 "/api/tasks", "/api/interactions", "/api/goals",
                 "/api/secrets"):
        request = urllib.request.Request(
            f"http://127.0.0.1:{served.port}{path}?t={served.token}",
            data=b"{}", headers={"Content-Type": "application/json"},
            method="POST")
        with pytest.raises(urllib.error.HTTPError) as caught:
            urllib.request.urlopen(request)
        assert caught.value.code == 501, f"{path} answered a POST"


def test_the_database_handle_is_opened_read_only(served):
    import sqlite3

    from xenia import readonly

    conn = readonly.connect(served.db_path)
    try:
        with pytest.raises(sqlite3.OperationalError):
            conn.execute("DELETE FROM action")
    finally:
        conn.close()


def test_the_page_offers_three_tabs():
    nav = report_mod._PAGE.split('<nav class="tabs">')[1].split("</nav>")[0]
    assert 'id="tab-tasks"' in nav
    assert 'id="tab-friction">Failed' in nav, "Friction is called Failed"
    assert 'id="tab-goals"' in nav
    assert "tab-activity" not in nav and "tab-disk" not in nav
    assert "Friction<" not in nav


def test_the_drill_down_survives_losing_its_tab():
    assert "setTab('activity')" in report_mod._PAGE
    # A prefix, not the whole line: the subject here is the drill-down, and
    # a tab added beside these three is not a regression in it.
    assert "const TABS = ['tasks','friction','goals'" in report_mod._PAGE
    assert "VIEWS.includes(HASH_TAB)" in report_mod._PAGE


def test_the_task_table_drops_the_columns_that_were_about_xenia():
    heads = report_mod._PAGE.split("const TCOLS = ")[1].split(";")[0]
    assert "Known from" not in heads and "Actions" not in heads
    assert "Written" in heads and "Outcome" in heads
    assert "SOURCE_LABEL" not in report_mod._PAGE, "dead with the column it fed"


def test_the_panel_refuses_to_serve_from_a_newer_database(served, conn):
    conn.execute("INSERT INTO meta (key, value) VALUES ('schema_version', '99') "
                 "ON CONFLICT (key) DO UPDATE SET value = excluded.value")
    conn.commit()

    payload = api(served, "/api/tasks")
    assert "error" in payload, f"served anyway: {list(payload)}"
    assert "restarted" in payload["error"]
    assert "rows" not in payload


def test_the_credentials_api_reports_policy_and_approval(served, conn):
    from xenia import broker

    broker.register(conn, "gitlab-pat", backend="memory",
                    hosts=["gitlab.example.com"], methods=["GET"])
    broker.grant(conn, "gitlab-pat", "gitlab.example.com", source="test")
    conn.commit()

    rows = api(served, "/api/secrets")["rows"]
    assert rows[0]["name"] == "gitlab-pat"
    assert rows[0]["approved_for"][0]["host"] == "gitlab.example.com"


def test_the_page_offers_a_credentials_tab(served):
    page = fetch(served, f"/?t={served.token}").decode()
    assert 'id="tab-credentials"' in page
    assert "/api/secrets" in page


def test_the_page_offers_a_way_in_and_out(served):
    page = fetch(served, f"/?t={served.token}").decode()
    assert 'id="newSecret"' in page and 'id="secretForm"' in page
    assert "/api/secrets/add" in page and "/api/secrets/remove" in page
    assert "/api/secrets/rename" in page


def test_a_credential_can_be_added_from_the_page(served, store, conn):
    out = post(served, "/api/secrets/add", {
        "name": "gitlab-pat", "value": TYPED,
        "hosts": "gitlab.example.com, ops.example.com", "note": "read only"})

    assert out["ok"] and out["store"] == "memory"
    assert store.values == {"gitlab-pat": TYPED}

    row = api(served, "/api/secrets")["rows"][0]
    assert row["name"] == "gitlab-pat"
    assert row["hosts"] == ["gitlab.example.com", "ops.example.com"]
    assert row["note"] == "read only"
    assert row["approved_for"] == [], "adding one does not approve it"


def test_a_credential_added_with_nowhere_to_go_is_asked_about_on_first_use(
        served, store, conn):
    post(served, "/api/secrets/add", {"name": "pat", "value": TYPED})

    assert api(served, "/api/secrets")["rows"][0]["hosts"] == []


def test_the_value_reaches_the_store_and_nothing_else(served, store, conn):
    post(served, "/api/secrets/add", {"name": "pat", "value": TYPED})

    assert TYPED not in json.dumps(api(served, "/api/secrets"))
    for suffix in ("", "-wal", "-shm"):
        path = Path(str(served.db_path) + suffix)
        if path.exists():
            assert TYPED.encode() not in path.read_bytes(), suffix


def test_replacing_a_value_keeps_where_it_was_allowed_to_go(served, store, conn):
    post(served, "/api/secrets/add", {"name": "pat", "value": TYPED,
                                      "hosts": "gitlab.example.com"})
    post(served, "/api/secrets/add", {"name": "pat", "value": TYPED + "-new"})

    assert store.values["pat"] == TYPED + "-new"
    assert api(served, "/api/secrets")["rows"][0]["hosts"] == ["gitlab.example.com"]


def test_a_credential_can_be_renamed_from_the_page(served, store, conn):
    post(served, "/api/secrets/add", {"name": "pat", "value": TYPED,
                                      "hosts": "gitlab.example.com"})

    out = post(served, "/api/secrets/rename", {"name": "pat",
                                               "to": "gitlab-pat"})

    assert out["ok"] and out["to"] == "gitlab-pat"
    assert store.values == {"gitlab-pat": TYPED}
    row = api(served, "/api/secrets")["rows"][0]
    assert row["name"] == "gitlab-pat"
    assert row["hosts"] == ["gitlab.example.com"], "the policy came with it"


def test_a_rename_carries_the_approvals_and_the_history(served, store, conn):
    from xenia import broker

    post(served, "/api/secrets/add", {"name": "pat", "value": TYPED,
                                      "hosts": "h.example"})
    broker.grant(conn, "pat", "h.example", source="test")
    conn.execute("INSERT INTO secret_use (at, name, host, decision) "
                 "VALUES ('2026-07-27T09:00:00.000+00:00', 'pat', 'h.example',"
                 " 'allowed')")
    conn.commit()

    post(served, "/api/secrets/rename", {"name": "pat", "to": "moved"})

    row = api(served, "/api/secrets")["rows"][0]
    assert row["name"] == "moved"
    assert row["uses"] == 1, "a history left behind would say it was never used"
    assert [g["host"] for g in row["approved_for"]] == ["h.example"]


def test_renaming_onto_a_name_that_is_taken_is_refused(served, store, conn):
    post(served, "/api/secrets/add", {"name": "pat", "value": TYPED})
    post(served, "/api/secrets/add", {"name": "other", "value": TYPED + "-b"})

    out = post(served, "/api/secrets/rename", {"name": "pat", "to": "other"})

    assert "error" in out and "already" in out["error"]
    assert store.values == {"pat": TYPED, "other": TYPED + "-b"}


def test_renaming_one_that_is_not_there_says_so(served, store, conn):
    out = post(served, "/api/secrets/rename", {"name": "ghost", "to": "pat"})

    assert "error" in out and "no credential" in out["error"]
    assert store.values == {}


def test_a_credential_can_be_removed_from_the_page(served, store, conn):
    post(served, "/api/secrets/add", {"name": "pat", "value": TYPED})

    out = post(served, "/api/secrets/remove", {"name": "pat"})

    assert out["ok"] and out["policy"] and out["value"]
    assert store.values == {}
    assert api(served, "/api/secrets")["rows"] == []


def test_removing_one_that_is_not_there_says_so(served, store, conn):
    out = post(served, "/api/secrets/remove", {"name": "never-existed"})

    assert "error" in out and "no credential" in out["error"]


def test_an_add_with_no_name_or_no_value_changes_nothing(served, store, conn):
    assert "error" in post(served, "/api/secrets/add",
                           {"name": "", "value": TYPED})
    assert "error" in post(served, "/api/secrets/add",
                           {"name": "pat", "value": ""})
    assert store.values == {}
    assert api(served, "/api/secrets")["rows"] == []


def test_a_write_without_the_token_is_refused(served, store):
    with pytest.raises(urllib.error.HTTPError) as raised:
        post(served, "/api/secrets/add", {"name": "pat", "value": TYPED},
             token=False)
    assert raised.value.code == 403
    assert store.values == {}


def test_a_write_from_another_page_is_refused(served, store):
    """The token is what a caller must know; this is for one that knows it."""
    for headers in ({"Origin": "https://elsewhere.example"},
                    {"Host": "rebound.example"}):
        with pytest.raises(urllib.error.HTTPError) as raised:
            post(served, "/api/secrets/add", {"name": "pat", "value": TYPED},
                 headers=headers)
        assert raised.value.code == 403, headers
    assert store.values == {}


def test_a_body_that_is_not_a_credential_is_refused_before_it_is_read(served):
    request = urllib.request.Request(
        f"http://127.0.0.1:{served.port}/api/secrets/add?t={served.token}",
        data=b"[]", headers={"Content-Type": "application/json"},
        method="POST")
    with pytest.raises(urllib.error.HTTPError) as raised:
        urllib.request.urlopen(request)
    assert raised.value.code == 400
