"""The agora: what agents have told each other they are running.

Several agents share this machine, and the expensive things they start — a
headless browser per test job, a suite that runs for ninety minutes, a bake, a
model — are invisible to each other until the box begins to swap. What is
missing is not a way to kill them. Every agent already has that. It is knowing
whether the 6 GB chromium it just found is a peer's live work or something a
session that ended two hours ago never cleaned up: kill the first and somebody
loses a run they are waiting on, leave the second and the machine ends up
carrying orphans nobody will ever claim.

So a claim says four things — what is running, what it is for, what it will
cost, and how to find it — and xenia fills in the two an agent cannot be
relied on to keep true itself:

  * whether the session that posted it is still alive. The holder is this
    process, and `bin/xenia-mcp` is one per agent session, so its pid is the
    session's liveness with no heartbeat for anyone to maintain. When the
    session goes the pid goes, and every claim it abandoned says so.
  * what the processes are ACTUALLY using, read off the operating system next
    to what the agent said they would use — the same instinct as a task's
    outcome being read off its calls rather than off its own account of them.

The safety property that matters is the one about not knowing. An agora that
cannot see the process table would report every claim as abandoned and hand
out a licence to kill the whole machine, so liveness that cannot be measured
is reported as live, never as gone: 'yes' is only ever said about a process
this module has looked at.
"""

from __future__ import annotations

import json
import os
import re
import sqlite3
import subprocess
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

from . import config

#: Where a claim can be in its life. 'held' is live work, 'overrun' is live
#: work past the window its own holder gave it, 'abandoned' is a claim whose
#: session is gone, 'released' is one the holder finished with.
STATES = ("held", "overrun", "abandoned", "released")

#: The three answers to "may I kill this", and the only three there are.
#: 'yes' is reserved for work nobody is waiting on any more.
MAY_KILL = ("no", "ask", "yes")

#: Fields `update` will take. Everything else about a claim is either xenia's
#: (the holder, the clocks) or fixed at the moment it was posted.
UPDATABLE = ("resource", "purpose", "ram_mb", "pids", "pattern", "holds_for",
             "kill_note", "repo")

_COLUMNS = ("id", "posted_at", "updated_at", "released_at", "release_note",
            "holder_pid", "holder_start", "agent", "repo", "resource",
            "purpose", "ram_mb", "pids", "pattern", "expires_at", "kill_note")

_UNITS = {"m": 1.0, "h": 60.0, "d": 1440.0, "w": 10080.0}


def _now() -> str:
    from . import ingest
    return ingest.utcnow()


def _whoami() -> tuple[str | None, str | None]:
    """The runtime and the checkout this server is running for.

    Both are guesses and both are better than the blank an agent would
    otherwise have to fill in by hand on every claim. The runtime is read off
    the environment, which `ingest.declared_agent` rightly distrusts for a
    hook — env travels, and a codex run started from a Claude shell inherits
    CLAUDECODE — but a hook has a transcript to do better with and this
    process has nothing. The checkout is wherever the client spawned this
    server, which is the repo the agent is working in.
    """
    from . import ingest
    try:
        agent = ingest.detect_agent({})
        repo = ingest.repo_for(os.getcwd())[0]
    except (OSError, ValueError):
        return None, None
    return (agent if agent != "unknown" else None), repo


def _minutes(text: Any) -> float:
    """A window forward from now, in the shapes `since` reads backward.

    Same letters, same tolerance, so an agent that has learned one does not
    have to learn the other. Unparseable raises rather than defaulting: a
    claim that silently took the default window would be believed for two
    hours when its holder asked for ten minutes, which is the direction that
    costs somebody a machine.
    """
    if text is None:
        return config.AGORA_HOLD_MINUTES
    raw = str(text).strip()
    unit = _UNITS.get(raw[-1:].lower())
    if unit:
        try:
            value = float(raw[:-1]) * unit
            if value > 0:
                return value
        except ValueError:
            pass
    raise KeyError(
        f"holds_for: cannot read {text!r} as a length of time. Give one of "
        "'10m', '90m', '2h', '1d' — how long this should still be running "
        f"before anyone should wonder about it (default "
        f"{config.AGORA_HOLD_MINUTES:g}m).")


# ---------------------------------------------------------------- processes


def _ps(pids) -> dict[int, dict[str, Any]] | None:
    """What the OS says about these pids, or None when it would not say.

    None is not an empty result and callers must not read it as one: it means
    the process table could not be consulted, and everything downstream of it
    treats a claim it cannot see as still held. One `ps` for the whole agora,
    because the alternative is a subprocess per pid per read.
    """
    wanted = sorted({int(p) for p in pids if p})
    if not wanted:
        return {}
    try:
        out = subprocess.run(
            ["ps", "-o", "pid=,rss=,lstart=", "-p",
             ",".join(str(p) for p in wanted)],
            capture_output=True, text=True, timeout=5)
    except (OSError, ValueError, subprocess.SubprocessError):
        return None

    # `ps` exits 1 only when NONE of the pids exist; a partial match still
    # prints the live ones and is the answer we want.
    found: dict[int, dict[str, Any]] = {}
    for line in out.stdout.splitlines():
        parts = line.split(None, 2)
        if len(parts) < 3:
            continue
        try:
            pid, rss_kb = int(parts[0]), int(parts[1])
        except ValueError:
            continue
        found[pid] = {"pid": pid, "rss_mb": round(rss_kb / 1024, 1),
                      "started": parts[2].strip()}
    return found


def _same_process(seen: dict[str, Any] | None, started: str | None) -> bool:
    """Whether what is at that pid now is what was there when it was claimed.

    A pid on its own is a reused number. The clock the OS started it on is
    what makes it an identity, and without this a recycled pid reports a dead
    session as a live one — which is the reading that keeps an orphan alive
    forever.
    """
    if seen is None:
        return False
    if not started or not seen.get("started"):
        return True
    return str(seen["started"]) == str(started)


def machine_ram() -> dict[str, Any]:
    """Total and available RAM, in MB, or nothing rather than a guess."""
    out: dict[str, Any] = {}
    try:
        meminfo = Path("/proc/meminfo")
        if meminfo.exists():
            for line in meminfo.read_text().splitlines():
                if line.startswith("MemTotal:"):
                    out["total_mb"] = int(int(line.split()[1]) / 1024)
                elif line.startswith("MemAvailable:"):
                    out["available_mb"] = int(int(line.split()[1]) / 1024)
            return out

        total = subprocess.run(["sysctl", "-n", "hw.memsize"],
                               capture_output=True, text=True, timeout=5)
        if total.returncode == 0:
            out["total_mb"] = int(int(total.stdout.strip()) / 1024 / 1024)
        stat = subprocess.run(["vm_stat"], capture_output=True, text=True,
                              timeout=5)
        if stat.returncode == 0:
            size, free = 4096, 0
            for line in stat.stdout.splitlines():
                if "page size of" in line:
                    size = int(line.split("page size of")[1].split()[0])
                for label in ("Pages free:", "Pages inactive:",
                              "Pages speculable:", "Pages speculative:"):
                    if line.startswith(label):
                        free += int(line.split(":")[1].strip().rstrip("."))
            out["available_mb"] = int(free * size / 1024 / 1024)
    except (OSError, ValueError, IndexError, subprocess.SubprocessError):
        pass
    return out


# -------------------------------------------------------------------- write


def _text(name: str, value: Any, *, required: bool = False,
          limit: int = 500) -> str | None:
    if value is None or str(value).strip() == "":
        if required:
            raise KeyError(f"{name} is required and cannot be empty")
        return None
    return str(value).strip()[:limit]


def _pids(value: Any) -> list[int]:
    if value is None:
        return []
    if isinstance(value, (int, str)):
        value = [value]
    if not isinstance(value, (list, tuple)):
        raise KeyError("pids must be a list of process ids")
    out: list[int] = []
    for item in value:
        try:
            pid = int(item)
        except (TypeError, ValueError):
            raise KeyError(f"pids: {item!r} is not a process id") from None
        if pid > 0 and pid not in out:
            out.append(pid)
    if len(out) > config.AGORA_MAX_PIDS:
        raise KeyError(
            f"pids: {len(out)} is more than one claim should carry "
            f"({config.AGORA_MAX_PIDS}). Name the parent process and give a "
            f"'pattern' for the tree under it.")
    return out


def _stamp_pids(pids: list[int]) -> str | None:
    """Each pid with the clock it started on, so a recycled one is not
    mistaken later for the process that was claimed."""
    if not pids:
        return None
    seen = _ps(pids) or {}
    return json.dumps({str(p): (seen.get(p) or {}).get("started")
                       for p in pids})


def _ram(value: Any) -> int | None:
    if value is None or value == "":
        return None
    try:
        mb = int(float(value))
    except (TypeError, ValueError):
        raise KeyError("ram_mb must be a number of megabytes") from None
    if mb < 0:
        raise KeyError("ram_mb cannot be negative")
    return mb


def _expiry(now: str, holds_for: Any) -> str:
    return (datetime.fromisoformat(now)
            + timedelta(minutes=_minutes(holds_for))).isoformat(
                timespec="milliseconds")


def _row(conn: sqlite3.Connection, claim_id: int) -> dict[str, Any] | None:
    cursor = conn.execute(
        f"SELECT {', '.join(_COLUMNS)} FROM claim WHERE id = ?", (claim_id,))
    row = cursor.fetchone()
    return dict(row) if row is not None else None


def post(conn: sqlite3.Connection, *, resource: Any, purpose: Any,
         ram_mb: Any = None, pids: Any = None, pattern: Any = None,
         holds_for: Any = None, kill_note: Any = None, repo: Any = None,
         agent: Any = None, holder_pid: int | None = None) -> dict[str, Any]:
    """Write a claim to the agora, and hand back what a reader of it will see.

    Posting BEFORE the work starts is the point — a peer weighing up a job of
    its own needs the number while there is still a decision to make — so pids
    are optional here and attached with `update` once they exist.
    """
    now = _now()
    holder = os.getpid() if holder_pid is None else int(holder_pid)
    named = _pids(pids)
    here_agent, here_repo = _whoami()
    cursor = conn.execute("""
        INSERT INTO claim (posted_at, updated_at, holder_pid, holder_start,
                           agent, repo, resource, purpose, ram_mb, pids,
                           pattern, expires_at, kill_note)
        VALUES (:posted_at, :updated_at, :holder_pid, :holder_start, :agent,
                :repo, :resource, :purpose, :ram_mb, :pids, :pattern,
                :expires_at, :kill_note)
    """, {
        "posted_at": now, "updated_at": now,
        "holder_pid": holder,
        "holder_start": (_ps([holder]) or {}).get(holder, {}).get("started"),
        "agent": _text("agent", agent, limit=40) or here_agent,
        "repo": _text("repo", repo, limit=120) or here_repo,
        "resource": _text("resource", resource, required=True),
        "purpose": _text("purpose", purpose, required=True, limit=1000),
        "ram_mb": _ram(ram_mb),
        "pids": _stamp_pids(named),
        "pattern": _text("pattern", pattern),
        "expires_at": _expiry(now, holds_for),
        "kill_note": _text("kill_note", kill_note, limit=1000),
    })
    conn.commit()
    return assess([_row(conn, int(cursor.lastrowid))])[0]


def update(conn: sqlite3.Connection, claim_id: int, *,
           holder_pid: int | None = None, **fields: Any) -> dict[str, Any]:
    """Change a claim — usually to attach the pids once the work has started.

    The holder may change its own claim. Anyone may take over one whose
    session is gone, because an orphan with a live pid attached to it is worth
    more to the next reader than a tidy refusal.
    """
    caller = os.getpid() if holder_pid is None else int(holder_pid)
    row = _row(conn, int(claim_id))
    if row is None:
        raise KeyError(f"no claim with id {claim_id}")

    strays = sorted(set(fields) - set(UPDATABLE))
    if strays:
        raise KeyError(f"update does not change {', '.join(strays)} — it "
                       f"takes {', '.join(UPDATABLE)}")

    seen = assess([dict(row)])[0]
    if row["released_at"]:
        return {"refused": f"claim {claim_id} was released at "
                           f"{row['released_at']} and is history now. Post a "
                           f"new one for new work.", "claim": seen}
    if row["holder_pid"] != caller and seen["state"] != "abandoned":
        return {"refused": f"claim {claim_id} belongs to a session that is "
                           f"still running (holder pid {row['holder_pid']}). "
                           f"Only its own holder changes it while it is "
                           f"{seen['state']}.", "claim": seen}

    sets: dict[str, Any] = {"updated_at": _now()}
    if "resource" in fields:
        sets["resource"] = _text("resource", fields["resource"], required=True)
    if "purpose" in fields:
        sets["purpose"] = _text("purpose", fields["purpose"], required=True,
                                limit=1000)
    if "ram_mb" in fields:
        sets["ram_mb"] = _ram(fields["ram_mb"])
    if "pids" in fields:
        sets["pids"] = _stamp_pids(_pids(fields["pids"]))
    if "pattern" in fields:
        sets["pattern"] = _text("pattern", fields["pattern"])
    if "kill_note" in fields:
        sets["kill_note"] = _text("kill_note", fields["kill_note"], limit=1000)
    if "repo" in fields:
        sets["repo"] = _text("repo", fields["repo"], limit=120)
    if "holds_for" in fields:
        sets["expires_at"] = _expiry(sets["updated_at"], fields["holds_for"])
    if row["holder_pid"] != caller:
        # Taking over an abandoned claim: the new holder is this session, and
        # its liveness is what the claim is measured by from here.
        sets["holder_pid"] = caller
        sets["holder_start"] = (_ps([caller]) or {}).get(
            caller, {}).get("started")

    assignments = ", ".join(f"{k} = :{k}" for k in sets)
    conn.execute(f"UPDATE claim SET {assignments} WHERE id = :id",
                 {**sets, "id": int(claim_id)})
    conn.commit()
    return assess([_row(conn, int(claim_id))])[0]


def release(conn: sqlite3.Connection, claim_id: int, *, note: Any = None,
            holder_pid: int | None = None) -> dict[str, Any]:
    """Take a claim out of the agora.

    Its holder may always do this. Anyone else may only release what is not
    live work — which is the whole of the agora's authority model: it will not
    be used to launder a kill of something a peer is waiting on, and the
    refusal names the session to ask instead.
    """
    caller = os.getpid() if holder_pid is None else int(holder_pid)
    row = _row(conn, int(claim_id))
    if row is None:
        raise KeyError(f"no claim with id {claim_id}")
    if row["released_at"]:
        return assess([dict(row)])[0]

    seen = assess([dict(row)])[0]
    if row["holder_pid"] != caller and seen["may_kill"] == "no":
        return {"refused": f"claim {claim_id} is live work held by a session "
                           f"that is still running (holder pid "
                           f"{row['holder_pid']}). Ask there, or ask the "
                           f"user; a claim is not released out from under "
                           f"its holder.", "claim": seen}

    conn.execute(
        "UPDATE claim SET released_at = :at, updated_at = :at, "
        "release_note = :note WHERE id = :id",
        {"at": _now(), "note": _text("note", note, limit=1000),
         "id": int(claim_id)})
    conn.commit()
    return assess([_row(conn, int(claim_id))])[0]


# --------------------------------------------------------------------- read


def assess(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Stored claims, plus everything only the live machine can say.

    One `ps` for every pid in the agora — holders and claimed processes
    together — because a read of the whole agora is one question and should
    cost one subprocess.
    """
    rows = [dict(r) for r in rows]
    wanted: set[int] = set()
    for row in rows:
        wanted.add(int(row["holder_pid"]))
        wanted.update(int(p) for p in _stored_pids(row))

    probe = _ps(wanted)
    return [_assess_one(row, probe) for row in rows]


def _stored_pids(row: dict[str, Any]) -> dict[int, str | None]:
    try:
        stored = json.loads(row.get("pids") or "{}")
    except (ValueError, TypeError):
        return {}
    out: dict[int, str | None] = {}
    for pid, started in (stored or {}).items():
        try:
            out[int(pid)] = started
        except (TypeError, ValueError):
            continue
    return out


def _assess_one(row: dict[str, Any],
                probe: dict[int, dict[str, Any]] | None) -> dict[str, Any]:
    now = _now()
    blind = probe is None
    holder = int(row["holder_pid"])
    holder_alive = True if blind else _same_process(
        (probe or {}).get(holder), row.get("holder_start"))

    processes = []
    measured: float | None = None
    for pid, started in _stored_pids(row).items():
        seen = (probe or {}).get(pid)
        alive = _same_process(seen, started)
        entry: dict[str, Any] = {"pid": pid,
                                 "alive": None if blind else alive}
        if alive and seen and seen.get("rss_mb") is not None:
            entry["rss_mb"] = seen["rss_mb"]
            measured = (measured or 0) + seen["rss_mb"]
        processes.append(entry)

    state, may_kill, why = _verdict(row, now, holder_alive, blind, processes)

    out: dict[str, Any] = {
        "id": row["id"], "state": state, "may_kill": may_kill,
        "may_kill_why": why,
        "resource": row["resource"], "purpose": row["purpose"],
        "ram_mb": row["ram_mb"],
        "holder_pid": holder,
        "holder_alive": None if blind else holder_alive,
        "posted_at": row["posted_at"], "expires_at": row["expires_at"],
        "age_minutes": _age(row["posted_at"], now),
    }
    if measured is not None:
        out["rss_mb"] = round(measured, 1)
    if processes:
        out["processes"] = processes
    for key in ("repo", "agent", "pattern", "kill_note", "released_at",
                "release_note"):
        if row.get(key):
            out[key] = row[key]
    if blind:
        out["unmeasured"] = ("the process table could not be read here, so "
                             "liveness is assumed rather than checked")
    return out


def _verdict(row: dict[str, Any], now: str, holder_alive: bool, blind: bool,
             processes: list[dict[str, Any]]) -> tuple[str, str, str]:
    live_pids = [p["pid"] for p in processes if p.get("alive")]

    if row["released_at"]:
        if live_pids:
            return ("released", "yes",
                    f"the holder released this at {row['released_at']} and "
                    f"said it was finished with, but "
                    f"{', '.join(str(p) for p in live_pids)} "
                    f"{'is' if len(live_pids) == 1 else 'are'} still running "
                    f"— an orphan of work that is over")
        return ("released", "yes",
                f"released at {row['released_at']}; nothing here is running")

    if not holder_alive:
        gone = ("nothing of it is still running, so there may be nothing left "
                "to do" if not live_pids else
                f"kill {', '.join(str(p) for p in live_pids)}")
        return ("abandoned", "yes",
                f"the session that posted this (pid {row['holder_pid']}) is "
                f"gone and never released it — {gone}")

    if blind:
        return ("held", "no",
                "liveness could not be checked on this machine, so this is "
                "read as live work; do not kill it on the strength of this "
                "row")

    if row["expires_at"] and row["expires_at"] < now:
        return ("overrun", "ask",
                f"past the window its holder gave it ({row['expires_at']}), "
                f"but that session is still running. It is more likely a "
                f"release nobody sent than work that died — check what the "
                f"processes are doing, and ask before killing")

    return ("held", "no",
            f"live work, held by a running session until {row['expires_at']}")


def _age(posted_at: str | None, now: str) -> float | None:
    try:
        delta = datetime.fromisoformat(now) - datetime.fromisoformat(posted_at)
    except (TypeError, ValueError):
        return None
    return round(delta.total_seconds() / 60, 1)


#: Most useful first: what can be reclaimed, then what to ask about, then live
#: work — and the biggest of each, since the reason to read this at all is
#: usually that something needs the memory.
_RANK = {"yes": 0, "ask": 1, "no": 2}


def order(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return sorted(rows, key=lambda r: (
        _RANK.get(r.get("may_kill"), 3),
        -(r.get("rss_mb") or r.get("ram_mb") or 0),
        -(r.get("id") or 0)))


def summary(rows: list[dict[str, Any]]) -> dict[str, Any]:
    """What the agora adds up to, which is the question it is usually read for.

    Measured where the processes could be seen and declared where they could
    not, and it says how many rows had neither rather than quietly totalling a
    agora full of blanks — an agent deciding whether it can afford a 6 GB job
    is owed the difference between 'nothing is claimed' and 'nobody said'.
    """
    out: dict[str, Any] = dict(machine_ram())
    claimed = reclaimable = 0.0
    unstated = 0
    for row in rows:
        declared, measured = row.get("ram_mb"), row.get("rss_mb")
        if row["may_kill"] == "yes":
            # What killing it would actually hand back is what it is holding
            # now. A forecast is worth nothing here: the claim may name
            # processes that have already gone, and the peak somebody expected
            # an hour ago is not memory anybody can have back.
            reclaimable += measured or 0
            continue
        if row.get("state") == "released":
            continue
        # The larger of the two, because they answer different halves of one
        # question: declared is the PEAK the holder expects and measured is
        # what it has taken so far. Preferring the measurement read a browser
        # four seconds after launch as 2 MB against the 6 GB it had just
        # announced, and told the next agent the machine was free.
        if declared is None and measured is None:
            unstated += 1
            continue
        claimed += max(declared or 0, measured or 0)
    out["claimed_mb"] = int(claimed)
    out["reclaimable_mb"] = int(reclaimable)
    if unstated:
        out["unstated"] = unstated
    return out


# -------------------------------------------------------------------- nudge


#: Command starts worth telling the rest of the machine about: a suite, a
#: build, a browser, a dev server, a model.
_HEAVY_VERBS = r"""
      pytest | tox | nox
    | jest | vitest | mocha | karma | rspec | phpunit | ctest
    | playwright | puppeteer | selenium | cypress | chromedriver
    | chrome-headless-shell | google-chrome | chromium | chrome | firefox
    | gradlew | gradle | mvn | bazel | ninja | sbt
    | cargo \s+ (?: build | test | bench | clippy )
    | go \s+ (?: build | test )
    | docker (?: \s+ compose )? \s+ (?: build | up | run )
    | (?: npm | pnpm | yarn | bun ) \s+ (?: run \s+ )?
      (?: build | test | dev | start | watch | e2e )
    | (?: vite | webpack | rollup | esbuild | next | nuxt ) \s+ (?: build | dev )
    | make \s+ (?: -j \S* | \S* (?: build | test | all ) )
    | cmake \s+ --build
    | ollama \s+ (?: run | serve ) | vllm | llama-server | torchrun
    | uvicorn | gunicorn | daphne
    | python3? \s+ -m \s+ (?: pytest | unittest | uvicorn | gunicorn | vllm\S* )
"""

#: Matched at a command start — the top of the line or the far side of a
#: separator, past anything that only wraps what follows (`time`, `env FOO=1`,
#: `uv run`) — and never anywhere in the line. `grep -rn pytest src/` is a
#: question about a suite and not a suite, and a nudge that fires on reading
#: is one an agent learns to skip long before it reaches the call it is about.
_HEAVY = re.compile(
    r"(?: \A | [\n;&|()] ) \s*"
    r"(?: (?: [A-Za-z_]\w* = \S*"
    r"        | time | nohup | exec | sudo | env | xvfb-run | npx | bunx"
    r"        | uv | uvx | poetry | pipenv | run ) \s+ )*"
    r"(?P<verb>" + _HEAVY_VERBS + r") \b",
    re.X | re.I)


def looks_heavy(tool: Any, tool_input: Any) -> str | None:
    """What this call is about to start that will hold memory, or nothing.

    Names what matched, so the nudge can say which command it means. A regex
    is never going to be right about `./run-everything.sh`, and does not have
    to be: a nudge missed is one claim not posted, a nudge misfired is an
    agent that stops reading them.
    """
    if tool != "Bash":
        return None
    command = tool_input.get("command") if isinstance(tool_input, dict) else None
    if not isinstance(command, str) or not command.strip():
        return None
    found = _HEAVY.search(command)
    return " ".join(found.group("verb").split()) if found else None


def nudge(conn: sqlite3.Connection, payload: dict[str, Any]) -> str | None:
    """What to say to an agent about to start something the others can't see.

    Once a session, on the first such command, and never again. The agora is
    a convention rather than a mechanism, and nothing else on this machine
    mentions it at the moment it matters: the MCP server says so at startup,
    thousands of tokens before anyone types `npm run build`. A line repeated
    on every `pytest` after that is one an agent filters out, so it is spent
    where it buys the most and then not again.

    Whether it has been spent is asked of the record rather than kept as a
    flag, because the hook is one process per event and a flag would have to
    outlive it — and the record already knows what this session has run.
    """
    if not config.AGORA_NUDGE:
        return None
    if payload.get("hook_event_name") != "PreToolUse":
        return None
    what = looks_heavy(payload.get("tool_name"), payload.get("tool_input"))
    if not what:
        return None
    if _heavy_before(conn, payload.get("session_id")):
        return None
    return _advice(conn, what)


def _heavy_before(conn: sqlite3.Connection, session_uid: Any) -> bool:
    """Has this session already started something like it?

    The call being nudged about is not in the record yet — the hook asks
    before it records — so anything found here really is earlier. A payload
    with no session to be first in is left alone rather than nudged on every
    command it ever runs.
    """
    if not session_uid:
        return True
    row = conn.execute("SELECT id FROM session WHERE session_uid = ?",
                       (str(session_uid),)).fetchone()
    if row is None:
        return False
    earlier = conn.execute(
        "SELECT detail FROM action WHERE session_id = ? AND tool = 'Bash' "
        "ORDER BY seq DESC LIMIT ?",
        (row["id"], config.AGORA_NUDGE_SCAN)).fetchall()
    return any(looks_heavy("Bash", {"command": r["detail"]}) for r in earlier)


def _gb(mb: Any) -> str:
    if not mb:
        return "0 GB"
    return f"{mb} MB" if mb < 1024 else f"{mb / 1024:.1f} GB"


def _advice(conn: sqlite3.Connection, what: str) -> str:
    # Only the call that actually speaks pays for this import, and the hook
    # runs on every tool call there is.
    from . import readonly

    rows = assess(readonly.claims(conn))
    ram = summary(rows)
    live = [r for r in rows if r.get("state") in ("held", "overrun")]
    free = (f"{_gb(ram.get('available_mb'))} of {_gb(ram.get('total_mb'))} free"
            if ram.get("available_mb") else "")

    if live:
        state = (f"{len(live)} claim{'' if len(live) == 1 else 's'} "
                 f"holding {_gb(ram.get('claimed_mb'))}")
    else:
        state = "nothing is claimed"
    loose = sum(1 for r in rows if r.get("may_kill") == "yes")
    if loose:
        state += (f", plus {loose} abandoned worth {_gb(ram.get('reclaimable_mb'))} "
                  "to whoever reclaims it")

    return (
        f"xenia: `{what}` will hold memory for a while, and the other agents "
        f"on this machine cannot see it. Right now {state}"
        + (f"; {free}" if free else "") + ". Announce yours with "
        "xenia_claim(op='post', resource=…, purpose=…, ram_mb=…, holds_for=…), "
        "attach its pids with op='update' once they exist, and op='release' "
        "when it is done. Read xenia_report(view='claims') before you kill "
        "anything you did not start yourself. Said once a session."
    )
