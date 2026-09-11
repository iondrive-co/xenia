# xenia

Xenia helps agents work better on your computer by providing a local MCP for them to:
- check for repeated mistakes from agents on this computer
- request actions requiring credentials without revealing the credentials to the agent

It runs with a tray icon and gives you an overview page. 
Install and run on linux or mac with:
```bash
./bin/xenia
```
Needs Python 3.11+

## MCP tools

### `xenia_report`

| `view` | One row is |
| --- | --- |
| `tasks` | What an agent set out to do, in its own words, and whether it got there. The label comes from its plan where it kept one and the outcome is read off the calls made under it. Ordered by what went wrong, not by the clock — pass `order: "at"` for a timeline. |
| `instructions` | Something the user asked for, and how it turned out. |
| `failures` | A kind of work that has failed more than once, worst first, grouped across sessions and repos — or, with `group_by: "cause"`, one row per reason rather than per kind of work. |
| `repeats` | Work a session did again soon after it had already attempted the same thing. |
| `tools` | Counts, failure rates, latency and reply size, per tool, broker, channel, host, repo or signature. |
| `disk` | What was written, how often each file was rewritten, and how much of that hashed to what was already there. |

### `xenia_calls`

Breaks a xenia_report row into its calls.

### `xenia_trace`

The actions between an `action_id` failure and the fix, including how long it took.

### Arguments

`since` (`24h`, `7d`, or a date)
`repo` (work outside any checkout is filed under `general`)
`limit` applies to every view. Every reply starts with `now` and `now_local` because the record is UTC and the logs it gets lined up against usually are not.

Where `tool`, `via`, `channel`, `session` and `signature` are accepted they match exactly or as a glob (`via: "acme-*"`), and a `signature` from any view drills straight into the calls behind that row.

See [ARCHITECTURE.md](ARCHITECTURE.md).
