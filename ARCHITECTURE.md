# Architecture

## Entry points

| | |
| --- | --- |
| `bin/xenia` | the command — sets up, starts the service (restarting one already running, so it picks up the code on disk), opens the report, exits. Also the credential commands: `secret`, `secrets`, `grant`, `grants`, `revoke` |
| `bin/xenia-service` | the long-running process: tray, report and the credential broker |
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

## Credentials

Values live in the operating system's store; xenia holds the name, the policy
and the record. Only the service ever reads a value, and only for the length of
one outbound request.

| Module | What is in it |
| --- | --- |
| `vault.py` | the OS stores — Secret Service over `dbus.py`, Keychain over `security` — behind `get`/`set`/`delete` |
| `broker.py` | policy, grants, the request itself, the socket contract and the scrubbing — `Refusal`, `Scrubber`, `Server`, `OPS`, `CODES` |
| `signing.py` | how a credential authenticates a request without appearing in it — `Context`, `SCHEMES`, `SchemeError` |
| `policy.py` | what a request may say, over its parsed body and query — `check`, `fields`, `Denied`, `Unparsed` |
| `secrets.py` | first-use setup for the store, and adding, renaming, removing and approving credentials — `add`, `rename`, `remove`, shared by the command and the page |

## Read

Two front ends over one read path. Neither returns file content, and neither
can write to the record — what an agent did is not editable from the page that
reports it. The one exception is the credentials themselves, which are the
user's rather than the record's: the page can add, rename and remove one, and
does it through `secrets.py` like every other front end.

| Module | What is in it |
| --- | --- |
| `readonly.py` | every query there is, and the credential boundary — `StaleReader` |
| `mcp.py` | the MCP protocol and the four tool definitions — `Server`. `xenia_fetch` is forwarded to the broker's socket: this server makes no request, opens no store and holds no value |
| `report.py` | the local page and its JSON API — `Report`. Every view is served from a read-only connection; the three paths in `WRITES` are the only ones that answer a POST at all |
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

```bash
python3 -m pytest -q
```
