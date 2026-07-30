from __future__ import annotations

import json
import os
import sys


def main(argv: list[str] | None = None) -> int:
    raw = ""
    try:
        raw = sys.stdin.read()
    except Exception:
        _fallback("read", "could not read stdin")
        return 0

    try:
        payload = json.loads(raw) if raw.strip() else {}
    except ValueError as exc:
        _fallback("parse", f"invalid JSON on stdin: {exc}", raw)
        return 0

    if not isinstance(payload, dict):
        _fallback("parse", f"expected a JSON object, got {type(payload).__name__}", raw)
        return 0

    argv = argv if argv is not None else sys.argv[1:]
    if argv and not payload.get("hook_event_name"):
        payload["hook_event_name"] = argv[0]

    try:
        from . import db, ingest

        conn = db.connect()
        try:
            ingest.record(conn, payload)
        finally:
            conn.close()
    except Exception as exc:
        _fallback("store", f"{type(exc).__name__}: {exc}", raw)

    return 0


def _fallback(stage: str, detail: str, raw: str = "") -> None:
    if os.environ.get("XENIA_DEBUG"):
        print(f"xenia hook {stage}: {detail}", file=sys.stderr)
    try:
        from . import config, redact
        from .ingest import utcnow

        path = config.fallback_log()
        path.parent.mkdir(parents=True, exist_ok=True)
        excerpt = (redact.redact(raw) or "")[:400].replace("\n", " ")
        with path.open("a", encoding="utf-8") as handle:
            handle.write(f"{utcnow()}\t{stage}\t{detail}\t{excerpt}\n")
    except Exception:
        pass


if __name__ == "__main__":
    raise SystemExit(main())
