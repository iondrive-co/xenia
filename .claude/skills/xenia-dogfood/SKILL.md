---
name: xenia-dogfood
description: Test xenia against its own record — use xenia's MCP tools to check whether xenia itself behaves well, then verify a fix the same way. Use when working in this repo on the MCP surface, reply sizes, reader retirement, classification quality or task/failure accuracy, and whenever a change needs evidence that it worked in the field rather than only in pytest. Also read before your first xenia_report/xenia_calls/xenia_trace call here.
metadata:
  short-description: Test xenia using xenia's own record
---

# Testing xenia with xenia

xenia records every tool call every agent makes on this machine, and your own
calls are in it within seconds. That makes this repo unusual: the thing under
test is also the instrument, and the instrument reports on itself. The tests in
`tests/` prove the code does what it says on fixtures. This is how you find out
what it does in the field.

`python3 -m pytest -q` still gates everything. This is the pass on top of it.

## The loop

1. **Ask xenia about xenia.** `xenia_report view=tools tool="mcp__xenia*"` and
   `via="xenia"` are the two queries that matter — the first is per-tool, the
   second gives xenia's own failure rate next to every other broker on the
   machine. If xenia looks bad in a table it generated, that is a finding you
   can act on and nobody else was going to report.
2. **Drill to the actual call.** `xenia_calls tool="mcp__xenia*" status="error"`
   then `xenia_trace` on an id. The trace shows what the agent did *next*, which
   is where the real cost is: recovery work, or routing around xenia entirely.
3. **Fix it, restart, re-measure the same way.** A change is done when the query
   that exposed the problem comes back clean against the live database — not
   when pytest is green.

## Reproducing your own findings is fair game

You are an agent on this machine, so you can produce the behaviour you are
investigating and it lands in the record like anyone else's. This is the
cheapest evidence available: it dates the problem to now, against the current
surface, rather than to whenever the historical rows were written. Note honestly
that the row is yours.

Watch for the opposite trap. Most historical xenia rows name tools that no
longer exist — `xenia_summary`, `xenia_findings`, `xenia_friction`,
`xenia_tasks`, `xenia_recent_interactions`, `xenia_tool_stats`,
`xenia_redundancy` were consolidated into today's three. **Check the tool name
still exists in `TOOLS` in `mcp.py` before treating an old failure as live.**

## Query rules

Every failure xenia has recorded against its own MCP is one shape: a wide call
whose reply went past the client's ceiling and was **discarded whole** — 57k,
92k and 106k characters, three answers nobody ever read.

- **Grouped `xenia_report` view first.** Rows are pre-aggregated, a few hundred
  bytes to ~14 KB. Find *which* thing is interesting before asking for detail.
- **Then `xenia_calls`, with a filter** carried over from that row — `signature`,
  `tool`, `session`, `status`. Its default `limit: 20` is deliberate.
- **Never total rows yourself.** The `tools` view returns counts, failure rates,
  latency and bytes; that is one call instead of a page of rows you add up by
  hand.
- **Always pass `since`** unless you mean all time. The record spans thousands of
  calls across every repo on the machine.

Replies are now capped at `config.REPLY_LIMIT` (32,000 chars) and cut to fit,
with a `truncated` key saying how many rows went and why. **If you see it,
narrow the query — do not raise `limit`.** Raising the limit on a reply that was
already cut asks for more of the thing that did not fit.

If something does spill to a file, the data is already on disk: `jq` it rather
than re-querying. Probe with `jq 'type, length, keys?'` first — `Read`'s line
offsets will not chunk single-line JSON.

## Which view answers which question

| Question | View |
| --- | --- |
| What was an agent trying to do, and did it work? | `tasks` — start here |
| What did the *user* ask for? | `instructions` (only view with full prompts) |
| What kind of work keeps breaking? | `failures` (low `recovered` = real gap) |
| What got redone despite never failing? | `repeats` |
| What is slow, or flooding the context? | `tools`, `order: total_bytes` / `total_ms` |
| What was written that changed nothing? | `disk`, `order: wasted_bytes` |
| Did an agent claim more than it delivered? | `tasks`, `overstated_only: true` |
| How was this specific failure recovered from? | `xenia_trace` |

## When xenia stops answering

Hanging or `blocked` calls almost always mean **the reader was retired**, not
that xenia is down: bumping `SCHEMA_VERSION` makes the next process to open the
database SIGTERM every reader still on the old schema, and your MCP server is
one of those readers.

**Ask the user to reconnect the MCP server.** That is the fix, and the
retirement notice on the next `initialize` will confirm it.

Do not route around it with `sqlite3` on `~/.local/share/xenia/audit.db` to keep
moving — agents have done this repeatedly and it reads as progress while the
stale server stays stale for the rest of the session. Reading the DB directly is
right only when the schema itself is what you are working on.

## Things worth checking that only this record can tell you

- **Is xenia's own failure rate above the brokers it reports on?** It has been.
- **Does anyone outside this repo use it?** Adoption is visible directly:
  `xenia_report view=tools group_by=repo` for the denominator, `via="xenia"` for
  the numerator. The MCP is registered at user scope, so a repo with thousands
  of calls and no xenia rows is a discovery problem, not a config one.
- **Do the six views agree with the record?** Spot-check a `tasks` row marked
  `overstated` against `xenia_trace` on its actions. The outcome is inferred, and
  the inference is the product.
- **What does xenia cost the agent asking?** `xenia_report view=tools
  via="xenia" order=total_bytes`. A tool that exists to find context waste is the
  last one that should be causing it.
