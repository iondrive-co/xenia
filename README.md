# xenia

A local MCP and tray icon for keeping track of how well agents are acheiving their goals, and what is going wrong. Install and run on linux or mac with
```bash
./bin/xenia
```
Needs Python 3.11+

## MCP tools

### `xenia_report`

| `view` | One row is |
| --- | --- |
| `tasks` | What an agent set out to do, in its own words, and whether it got there. The label comes from its plan where it kept one and the outcome is read off the calls made under it.  |
| `instructions` | Something the user asked for, and how it turned out. |
| `failures` | A kind of work that has failed more than once, worst first, grouped across sessions and repos. |
| `repeats` | Work a session did again soon after it had already attempted the same thing. |
| `tools` | Counts, failure rates, latency and reply size, per tool, broker, channel, host, repo or signature. |
| `disk` | What was written, how often each file was rewritten, and how much of that hashed to what was already there. |

### `xenia_calls`

One row of any of the above, broken into the individual calls behind it.

### `xenia_trace`

The actions between an `action_id` failure and the fix.

### Arguments

`since` (`24h`, `7d`, or a date), `repo` — work outside any checkout is filed under `general` — and `limit` apply to every view. Where `tool`, `via`, `channel`, `session` and `signature` are accepted they match exactly or as a glob, so one `via: "acme-*"` covers every call through a site's brokers, and a `signature` from any view drills straight into the calls behind that row.

See [ARCHITECTURE.md](ARCHITECTURE.md).
