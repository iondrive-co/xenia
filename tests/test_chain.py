from __future__ import annotations

from conftest import pre

from xenia import chain, ingest


def seed(conn, clock, n=5):
    for i in range(n):
        clock()
        ingest.record(conn, pre("Bash", {"command": f"echo {i}"}))


def test_an_untouched_ledger_verifies(conn, clock):
    seed(conn, clock)
    result = chain.verify(conn)
    assert result.ok
    assert result.checked == 5


def test_editing_a_payload_is_detected(conn, clock):
    seed(conn, clock)
    conn.execute("UPDATE event SET payload = '{\"hook_event_name\":\"Innocent\"}' WHERE id = 3")
    conn.commit()

    result = chain.verify(conn)
    assert not result.ok
    assert any(b.event_id == 3 and "digest" in b.reason for b in result.breaks)


def test_editing_a_payload_and_its_digest_is_still_detected(conn, clock):
    seed(conn, clock)
    forged = '{"hook_event_name":"Innocent"}'
    conn.execute(
        "UPDATE event SET payload = ?, payload_sha256 = ? WHERE id = 3",
        (forged, chain.sha256(forged)),
    )
    conn.commit()

    result = chain.verify(conn)
    assert not result.ok
    assert any(b.event_id == 3 and "altered" in b.reason for b in result.breaks)


def test_deleting_an_event_is_detected(conn, clock):
    seed(conn, clock)
    conn.execute("PRAGMA foreign_keys = OFF")
    conn.execute("DELETE FROM event WHERE id = 3")
    conn.commit()

    result = chain.verify(conn)
    assert not result.ok
    assert any("gap in event ids" in b.reason for b in result.breaks)


def test_changing_which_host_a_call_targeted_is_detected(conn, clock):
    clock()
    ingest.record(conn, pre("mcp__fleet-ssh__shell", {
        "environment": "production", "host": "prod-1", "command": "rm -rf /srv",
    }))
    conn.execute(
        "UPDATE event SET payload = replace(payload, 'production', 'staging')"
    )
    conn.commit()
    assert not chain.verify(conn).ok


def test_truncating_the_tail_is_not_detected_by_the_chain_alone(conn, clock):
    seed(conn, clock)
    head_before = chain.head(conn)
    conn.execute("PRAGMA foreign_keys = OFF")
    conn.execute("DELETE FROM event WHERE id > 3")
    conn.commit()

    assert chain.verify(conn).ok
    assert chain.head(conn) != head_before


def test_the_chain_survives_a_gap_without_cascading(conn, clock):
    seed(conn, clock, n=8)
    conn.execute("UPDATE event SET cwd = '/somewhere/else' WHERE id = 4")
    conn.commit()

    breaks = chain.verify(conn).breaks
    assert {b.event_id for b in breaks} == {4}


def test_row_hash_is_not_reorderable_between_fields(conn):
    a = chain.row_hash("0" * 64, {"tool": "ab", "cwd": "c"})
    b = chain.row_hash("0" * 64, {"tool": "a", "cwd": "bc"})
    assert a != b


def test_the_first_event_links_to_genesis(conn, clock):
    clock()
    ingest.record(conn, pre("Bash", {"command": "ls"}))
    row = conn.execute("SELECT prev_hash FROM event WHERE id = 1").fetchone()
    assert row["prev_hash"] == "0" * 64


def _forge_forward_unkeyed(conn):
    import hashlib

    covered = ("ts", "agent", "session_uid", "hook", "tool", "cwd", "payload_sha256")
    conn.execute("PRAGMA foreign_keys = OFF")
    conn.execute("DELETE FROM event WHERE id = 3")

    prev = "0" * 64
    for row in conn.execute("SELECT * FROM event ORDER BY id").fetchall():
        parts = [prev] + [
            f"{name}={len(str(row[name] or ''))}:{str(row[name] or '')}"
            for name in covered
        ]
        digest = hashlib.sha256("\x1f".join(parts).encode()).hexdigest()
        conn.execute("UPDATE event SET prev_hash = ?, row_hash = ? WHERE id = ?",
                     (prev, digest, row["id"]))
        prev = digest
    conn.commit()


def test_a_new_ledger_is_keyed(conn, clock):
    seed(conn, clock, n=2)
    assert chain.mode(conn) == chain.KEYED
    assert chain.verify(conn).keyed


def test_recomputing_the_chain_forward_no_longer_verifies(conn, clock):
    seed(conn, clock, n=6)
    _forge_forward_unkeyed(conn)

    result = chain.verify(conn)
    assert not result.ok
    assert any("altered" in b.reason for b in result.breaks)


def test_the_key_is_not_in_the_database(conn, clock, monkeypatch, tmp_path):
    monkeypatch.delenv("XENIA_LEDGER_KEY", raising=False)
    monkeypatch.setenv("XENIA_LEDGER_KEY_FILE", str(tmp_path / "k" / "ledger.key"))
    chain.reset_key_cache()

    material = chain.key()
    assert material and (tmp_path / "k" / "ledger.key").exists()
    assert oct((tmp_path / "k" / "ledger.key").stat().st_mode)[-3:] == "600"

    blob = "".join(str(r[0]) for r in conn.execute("SELECT * FROM meta"))
    assert material.decode() not in blob


def test_a_ledger_written_before_keying_still_verifies(tmp_path, monkeypatch):
    from xenia import db

    monkeypatch.setenv("XENIA_FAKE_NOW", "2026-07-27T09:00:00.000+00:00")
    conn = db.connect(tmp_path / "legacy.db")
    conn.execute("UPDATE meta SET value = ? WHERE key = 'chain_mode'", (chain.UNKEYED,))
    conn.commit()

    for i in range(3):
        ingest.record(conn, pre("Bash", {"command": f"echo {i}"}))

    result = chain.verify(conn)
    assert result.ok and not result.keyed
    conn.close()


def test_an_unanchored_ledger_says_so(conn, clock):
    seed(conn, clock)
    result = chain.verify(conn)
    assert result.ok
    assert not result.anchored
    assert not result.trusted
    assert "anchor" in result.anchor_note


def test_an_anchor_confirms_the_ledger(conn, clock, tmp_path, monkeypatch):
    monkeypatch.setenv("XENIA_LEDGER_ANCHOR", str(tmp_path / "anchor.json"))
    seed(conn, clock)
    assert chain.anchor(conn)

    result = chain.verify(conn)
    assert result.ok and result.anchored and result.trusted


def test_the_anchor_catches_a_truncated_tail(conn, clock, tmp_path, monkeypatch):
    monkeypatch.setenv("XENIA_LEDGER_ANCHOR", str(tmp_path / "anchor.json"))
    seed(conn, clock)
    chain.anchor(conn)

    conn.execute("PRAGMA foreign_keys = OFF")
    conn.execute("DELETE FROM event WHERE id > 3")
    conn.commit()

    result = chain.verify(conn)
    assert not result.ok
    assert any("truncated" in b.reason for b in result.breaks)


def test_the_anchor_catches_a_wholesale_rewrite(conn, clock, tmp_path, monkeypatch):
    monkeypatch.setenv("XENIA_LEDGER_ANCHOR", str(tmp_path / "anchor.json"))
    seed(conn, clock, n=6)
    chain.anchor(conn)

    conn.execute("UPDATE event SET row_hash = ? WHERE id = 6",
                 ("f" * 64,))
    conn.commit()

    result = chain.verify(conn)
    assert not result.ok
    assert any("rewritten" in b.reason for b in result.breaks)


def test_no_anchor_is_written_when_none_is_configured(conn, clock):
    seed(conn, clock)
    assert chain.anchor(conn) is None
    assert chain.read_anchor() is None
