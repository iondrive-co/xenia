# Architecture

## Entry points

| | |
| --- | --- |
| `bin/xenia` | the command — sets up, starts the service (restarting one already running, so it picks up the code on disk), opens the report, exits |
| `bin/xenia-service` | the long-running process: tray and report |
| `bin/xenia-hook` | hook entry point — fails soft, always exits 0 |
| `bin/xenia-mcp` | the read-only MCP server, over stdio |

## Capture

Turning a hook payload into rows. This runs inside an agent's own tool call,
which is why every part of it fails soft.

| Module | What is in it |
| --- | --- |
| `hook.py` | the hook entry point |
| `ingest.py` | hook payload → ledger → projections |
| `classify.py` | remote-call and filesystem-change detection — `RemoteFact`, `FsFact`, `Result` |
| `plan.py` | the agent's own plan, read out of its tool calls — `Plan`, `PlanItem` |
| `redact.py` | secret detection and redaction, before anything is stored — `Rule`, `Hit` |
| `resolve.py` | outcome linkage, and the scoring of tasks and goals |

## Store

| Module | What is in it |
| --- | --- |
| `schema.sql` | the ledger, the projections derived from it, and the reporting views |
| `db.py` | connection, and the migrations that reach an old file |
| `chain.py` | the hash chain and its verification — `Break`, `VerifyResult` |

## Read

Two front ends over one read path. Neither can write, and neither returns file
content.

| Module | What is in it |
| --- | --- |
| `readonly.py` | every query there is, and the credential boundary — `StaleReader` |
| `mcp.py` | the MCP protocol and the three tool definitions — `Server` |
| `report.py` | the local page and its JSON API — `Report` |
| `readers.py` | the register of long-lived readers, and retiring them on a migration |

## Desktop

| Module | What is in it |
| --- | --- |
| `app.py` | first-run setup, single instance, tray wiring — `App` |
| `tray.py` | the menu, and the choice of platform backend — `Tray`, `MenuItem`, `Unavailable` |
| `tray_linux.py` | StatusNotifierItem and dbusmenu — `Backend` |
| `tray_macos.py` | NSStatusItem through the Objective-C runtime — `Backend`, `_Runtime` |
| `dbus.py` | a D-Bus client, spoken on the wire from the standard library — `Connection`, `Message`, `Reader`, `Writer`, `Variant` |
| `icon.py` | the tray icon, rasterised at startup |

## Setup

| Module | What is in it |
| --- | --- |
| `install.py` | merging the hooks into each runtime's config |
| `service.py` | systemd and launchd registration |
| `config.py` | paths, tunables, and site configuration |

## Elsewhere

| | |
| --- | --- |
| `demo/seed_demo.py` | seeded sessions, driven through the real hook binary |
| `docs/DESIGN.md` | why it is built this way |
| `docs/SCHEMA.md` | the tables, column by column |

```bash
python3 -m pytest -q
```
