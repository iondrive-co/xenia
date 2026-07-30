from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import NamedTuple

from . import config
from .config import GENESIS_HASH

_COVERED = ("ts", "agent", "session_uid", "hook", "tool", "cwd", "payload_sha256")

UNKEYED = "sha256"
KEYED = "hmac-sha256"

_key_cache: tuple[str, bytes] | None = None


def sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8", "replace")).hexdigest()


def reset_key_cache() -> None:
    global _key_cache
    _key_cache = None


def key() -> bytes:
    global _key_cache

    literal = os.environ.get("XENIA_LEDGER_KEY")
    if literal:
        return literal.encode()

    path = config.ledger_key_path()
    if _key_cache is not None and _key_cache[0] == str(path):
        return _key_cache[1]

    material = _read_key(path)
    if not material:
        material = _create_key(path)

    _key_cache = (str(path), material)
    return material


def _read_key(path: Path) -> bytes:
    try:
        return path.read_bytes().strip()
    except OSError:
        return b""


def _create_key(path: Path) -> bytes:
    path.parent.mkdir(parents=True, exist_ok=True)
    material = secrets.token_bytes(32).hex().encode()
    staging = path.with_name(f".{path.name}.{os.getpid()}.{secrets.token_hex(4)}")

    handle = os.open(str(staging), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        os.write(handle, material + b"\n")
    finally:
        os.close(handle)

    try:
        os.link(str(staging), str(path))
    except OSError:
        pass
    finally:
        try:
            os.unlink(str(staging))
        except OSError:
            pass

    return _read_key(path) or material


def mode(conn: sqlite3.Connection) -> str:
    try:
        row = conn.execute(
            "SELECT value FROM meta WHERE key = 'chain_mode'").fetchone()
    except sqlite3.OperationalError:
        return UNKEYED
    return row["value"] if row else UNKEYED


def row_hash(prev: str, fields: dict[str, object], *, keyed: bool = False) -> str:
    parts = [prev]
    for name in _COVERED:
        value = fields.get(name)
        text = "" if value is None else str(value)
        parts.append(f"{name}={len(text)}:{text}")
    body = "\x1f".join(parts).encode("utf-8", "replace")

    if keyed:
        return hmac.new(key(), body, hashlib.sha256).hexdigest()
    return hashlib.sha256(body).hexdigest()


def head(conn: sqlite3.Connection) -> str:
    row = conn.execute("SELECT row_hash FROM event ORDER BY id DESC LIMIT 1").fetchone()
    return row["row_hash"] if row else GENESIS_HASH


class Break(NamedTuple):
    event_id: int
    reason: str
    expected: str
    found: str


class VerifyResult(NamedTuple):
    checked: int
    breaks: list[Break]
    keyed: bool = False
    anchored: bool = False
    anchor_note: str = ""

    @property
    def ok(self) -> bool:
        return not self.breaks

    @property
    def trusted(self) -> bool:
        return self.ok and self.anchored


def verify(conn: sqlite3.Connection, *, start_id: int = 0) -> VerifyResult:
    breaks: list[Break] = []
    checked = 0
    prev = GENESIS_HASH
    expect_id = None
    keyed = mode(conn) == KEYED

    rows = conn.execute(
        "SELECT id, ts, agent, session_uid, hook, tool, cwd, payload, "
        "       payload_sha256, prev_hash, row_hash "
        "FROM event WHERE id > ? ORDER BY id",
        (start_id,),
    )

    for row in rows:
        checked += 1
        if expect_id is not None and row["id"] != expect_id:
            breaks.append(
                Break(row["id"], "gap in event ids", str(expect_id), str(row["id"]))
            )
        expect_id = row["id"] + 1

        if sha256(row["payload"]) != row["payload_sha256"]:
            breaks.append(
                Break(row["id"], "payload does not match its digest",
                      row["payload_sha256"], sha256(row["payload"]))
            )

        if row["prev_hash"] != prev:
            breaks.append(
                Break(row["id"], "prev_hash does not match the previous row",
                      prev, row["prev_hash"])
            )

        recomputed = row_hash(row["prev_hash"], dict(row), keyed=keyed)
        if recomputed != row["row_hash"]:
            breaks.append(
                Break(row["id"], "row contents were altered", recomputed, row["row_hash"])
            )

        prev = row["row_hash"]

    anchored, note, anchor_breaks = check_anchor(conn)
    return VerifyResult(checked, breaks + anchor_breaks, keyed, anchored, note)


def anchor(conn: sqlite3.Connection) -> dict | None:
    path = config.ledger_anchor_path()
    if path is None:
        return None
    try:
        row = conn.execute(
            "SELECT id, row_hash FROM event ORDER BY id DESC LIMIT 1").fetchone()
        record = {
            "at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "event_id": int(row["id"]) if row else 0,
            "head": row["row_hash"] if row else GENESIS_HASH,
        }
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(record, indent=2) + "\n")
        return record
    except Exception:
        return None


def read_anchor(path: Path | None = None) -> dict | None:
    target = path or config.ledger_anchor_path()
    if target is None:
        return None
    try:
        loaded = json.loads(target.read_text())
    except Exception:
        return None
    return loaded if isinstance(loaded, dict) else None


def check_anchor(conn: sqlite3.Connection) -> tuple[bool, str, list[Break]]:
    if config.ledger_anchor_path() is None:
        return False, "no anchor is configured (set XENIA_LEDGER_ANCHOR)", []

    record = read_anchor()
    if record is None:
        return False, "the configured anchor has not been written yet", []

    event_id = int(record.get("event_id") or 0)
    expected = str(record.get("head") or "")
    if event_id == 0:
        return True, "anchored at an empty ledger", []

    row = conn.execute(
        "SELECT row_hash FROM event WHERE id = ?", (event_id,)).fetchone()
    if row is None:
        return False, f"event {event_id} is in the anchor and not in the ledger", [
            Break(event_id, "anchored event is missing — the ledger was truncated",
                  expected, "")]
    if row["row_hash"] != expected:
        return False, f"event {event_id} does not match the anchor", [
            Break(event_id, "anchored event does not match — the chain was rewritten",
                  expected, row["row_hash"])]
    return True, f"matches the anchor at event {event_id}", []
