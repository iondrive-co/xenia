from __future__ import annotations

import json
import urllib.error
import urllib.request

import pytest
from conftest import CORE, FAKE_GITLAB_PAT, pre

from xenia import ingest, report as report_mod


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


def test_there_is_no_write_path(served):
    for path in ("/api/dismiss", "/api/mute", "/api/decide", "/api/summary"):
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
    assert "const TABS = ['tasks','friction','goals']" in report_mod._PAGE
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
