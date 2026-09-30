# xenia

Read [ARCHITECTURE.md](ARCHITECTURE.md) before starting, and run `python3 -m pytest -q` before finishing (takes a couple of minutes).

## No comments

Agents do not write comments or docstrings in this repo: not new ones, and
not rewordings of old ones. Deleting comment text is fine. When a change needs
explaining, explain it in your reply to the user, not in the code.

## Test and demo data are invented

Every value in `tests/` and `demo/` is made up:
- hostnames under `example.com`, `.test` or `.invalid`
- paths under `tmp_path` or `/srv/repos/<name>`, with repos named `shop` and
  `infra`
- commands, error text, pids, key ids, counts and dates

## There is no build

`bin/xenia`, `bin/xenia-hook`, `bin/xenia-guard`, `bin/xenia-mcp` and `bin/xenia-service` each put
`src/` on `sys.path` and import from it. Nothing is compiled, installed or
copied, so an edit under `src/xenia/` is live the moment it is saved — for
whatever starts after it.

A process holds the code it started with:

| | |
| --- | --- |
| `bin/xenia-hook` | one process per hook event — always current, never needs restarting |
| `bin/xenia-guard` | the same, on PreToolUse for `Bash` — but it runs only in a session started after `xenia` setup (`install.apply`) wired it into that session's settings file |
| `bin/xenia-service` | `systemctl --user restart xenia.service`, or on mac `launchctl kickstart -k gui/$(id -u)/dev.xenia.tray` |
| `bin/xenia-mcp` | one per agent session — only its client can restart it, so ask |

So after changing anything under `src/xenia/`, restart the service; and if you
touched `mcp.py`, `readonly.py`, `db.py` or anything they import, your own MCP
server is running the old code too. Ask for it to be reconnected rather than
reading your change back out of a server that predates it — that is the trap
this file exists to prevent, and it is silent, because the stale server answers
perfectly well in the shape it was built for.

## The source files here are big — read them once

`ingest.py`, `readonly.py`, `mcp.py`, `classify.py` and `ARCHITECTURE.md` are
30–55 KB each. Grep for the symbol, read the range around it, don't reread unless it changes

## Changing the schema

Bumping `SCHEMA_VERSION` in `config.py` is not free. The next process to open
the database migrates it and SIGTERMs every registered reader still on the old
version (`readers.py`), because a reader older than the database cannot be
trusted to report from it. Your own MCP server is one of those readers, so
expect xenia to stop answering mid-session on a schema change; that is the
migration working, and reconnecting is the fix.

`mcp.py` and `app.py` both register at startup, so both are retired and both
come back. Anything new that opens the database for reading has to do the same:
a reader that never registered is never retired, and stays up raising
`StaleReader` on every query until someone restarts it by hand.
