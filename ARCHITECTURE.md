# Architecture

## Entry points

| | |
| --- | --- |
| `bin/xenia` | the command — sets up, starts the service (restarting one already running, so it picks up the code on disk), opens the report, exits. Also the credential commands: `secret`, `secrets`, `grant`, `grants`, `revoke` |
| `bin/xenia-service` | the long-running process: tray, report and the credential broker |
| `bin/xenia-hook` | hook entry point — fails soft, always exits 0 |
| `bin/xenia-mcp` | the MCP server, over stdio — the record read-only, the agora and `xenia_fetch` writing through their own modules |

## Capture

Turning a hook payload into rows. This runs inside an agent's own tool call,
which is why every part of it fails soft.

| Module | What is in it |
| --- | --- |
| `hook.py` | the hook entry point, and the one thing it ever says back: the agora nudge, on PreToolUse |
| `ingest.py` | hook payload → ledger → projections |
| `classify.py` | remote-call and filesystem-change detection — `RemoteFact`, `FsFact`, `Result` |
| `plan.py` | the agent's own plan, read out of its tool calls — `Plan`, `PlanItem` |
| `redact.py` | secret detection and redaction, before anything is stored — `Rule`, `Hit` |
| `resolve.py` | outcome linkage, and the scoring of tasks and goals |

## Store

| Module | What is in it |
| --- | --- |
| `schema.sql` | the ledger, the projections derived from it, the reporting views, and the one table nothing derives — `claim`, which agents author |
| `db.py` | connection, and the migrations that reach an old file |
| `chain.py` | the hash chain and its verification — `Break`, `VerifyResult` |

## Credentials

Values live in the operating system's store; xenia holds the name, the policy
and the record. Only the service ever reads a value, and only for the length of
one outbound request.

| Module | What is in it |
| --- | --- |
| `vault.py` | the OS stores — Secret Service over `dbus.py`, Keychain over `security` — behind `get`/`set`/`delete` |
| `broker.py` | policy, grants, the request itself, the socket contract and the scrubbing — `Refusal`, `Scrubber`, `Server`, `OPS`, `CODES`. `Server.start()` REFUSES rather than replacing a socket something is still answering on (`socket_is_live`, `BrokerAlreadyListening`), and `stop()` unlinks only the inode it bound: a second instance that took the path and then left used to strand the first on an anonymous inode, and every credentialed call on the machine failed `broker-unreachable` while `ss -lx` still showed a listener |
| `signing.py` | how a credential authenticates a request without appearing in it — `Context`, `SCHEMES`, `SchemeError` |
| `policy.py` | what a request may say, over its parsed body and query — `check`, `fields`, `Denied`, `Unparsed` |
| `secrets.py` | first-use setup for the store, and adding, renaming, removing and approving credentials — `add`, `rename`, `remove`, shared by the command and the page |

## Coordinate

| Module | What is in it |
| --- | --- |
| `agora.py` | the agora — what agents have told each other they are running, what it costs, and whether it is safe to kill. Posting, updating and releasing a claim, the process and memory probing behind `assess`, the totals in `summary`, and `nudge` — what the hook tells an agent starting something heavy for the first time in a session |

The claim table is the one thing an agent writes. It is not part of the
record: a claim is authored by the agent rather than derived from its events,
it is released when the work is done rather than kept forever, and nothing
about what an agent *did* can be reached through it. The holder of a claim is
the `xenia-mcp` process that posted it — one per agent session — so liveness
needs no heartbeat, and a claim outliving its session says so by itself.

Two rules hold the write path up. A claim is released by its own holder, or by
anyone once it is no longer live work, so the agora cannot be used to clear a
peer's claim out from under it. And liveness that cannot be measured is
reported as live: `_ps` returns `None` rather than an empty result when the
process table cannot be read, and every claim then reads as held.

## Read

Two front ends over one read path. Neither returns file content, and neither
can write to the record — what an agent did is not editable from the page that
reports it. Two things are the exception, and both are somebody else's rather
than the record's: the credentials, which are the user's, added, renamed and
removed through `secrets.py`; and the agora, which is the agents', written
through `agora.py`. Both go through their own module whichever front end asks.

| Module | What is in it |
| --- | --- |
| `readonly.py` | every query there is, and the credential boundary — `StaleReader`. `claims` reads the agora as stored; what is live about it is `agora.assess` |
| `mcp.py` | the MCP protocol and the five tool definitions — `Server`. `xenia_fetch` is forwarded to the broker's socket: this server makes no request, opens no store and holds no value. `xenia_claim` is the one call that opens a read-write connection, through `_writable`, which re-runs the stale-reader check first because opening one is what would migrate the file |
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
