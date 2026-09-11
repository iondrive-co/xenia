PRAGMA journal_mode = WAL;

CREATE TABLE IF NOT EXISTS meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS event (
    id             INTEGER PRIMARY KEY,
    ts             TEXT    NOT NULL,
    recorded_at    TEXT    NOT NULL,
    agent          TEXT    NOT NULL,
    session_uid    TEXT,
    hook           TEXT    NOT NULL,
    tool           TEXT,
    cwd            TEXT,
    payload        TEXT    NOT NULL,
    payload_sha256 TEXT    NOT NULL,
    prev_hash      TEXT    NOT NULL,
    row_hash       TEXT    NOT NULL
);

CREATE INDEX IF NOT EXISTS event_session_idx ON event (session_uid, id);
CREATE INDEX IF NOT EXISTS event_ts_idx      ON event (ts);

CREATE TABLE IF NOT EXISTS ingest_error (
    id         INTEGER PRIMARY KEY,
    ts         TEXT NOT NULL,
    stage      TEXT NOT NULL,
    detail     TEXT NOT NULL,
    raw_prefix TEXT
);

CREATE TABLE IF NOT EXISTS session (
    id          INTEGER PRIMARY KEY,
    session_uid TEXT    NOT NULL UNIQUE,
    agent       TEXT    NOT NULL,
    repo        TEXT,
    repo_path   TEXT,
    cwd         TEXT,
    host        TEXT,
    os_user     TEXT,
    started_at  TEXT    NOT NULL,
    ended_at    TEXT,
    end_reason  TEXT,
    current_task_id INTEGER
);

CREATE INDEX IF NOT EXISTS session_repo_idx ON session (repo, started_at);

CREATE TABLE IF NOT EXISTS goal (
    id              INTEGER PRIMARY KEY,
    session_id      INTEGER NOT NULL REFERENCES session (id),
    seq             INTEGER NOT NULL,
    prompt          TEXT    NOT NULL,
    prompt_sha256   TEXT    NOT NULL,
    created_at      TEXT    NOT NULL,
    status          TEXT    NOT NULL DEFAULT 'open',
    resolved_at     TEXT,
    resolution_note TEXT,
    UNIQUE (session_id, seq)
);

CREATE INDEX IF NOT EXISTS goal_status_idx ON goal (status);

CREATE TABLE IF NOT EXISTS task (
    id           INTEGER PRIMARY KEY,
    session_id   INTEGER NOT NULL REFERENCES session (id),
    goal_id      INTEGER REFERENCES goal (id),
    seq          INTEGER NOT NULL,
    label        TEXT    NOT NULL,
    label_key    TEXT    NOT NULL,
    source       TEXT    NOT NULL,
    external_id  TEXT,
    declared     TEXT,
    declared_at  TEXT,
    status       TEXT    NOT NULL DEFAULT 'open',
    outcome_note TEXT,
    overstated   INTEGER NOT NULL DEFAULT 0,
    started_at   TEXT    NOT NULL,
    ended_at     TEXT,
    UNIQUE (session_id, label_key)
);

CREATE INDEX IF NOT EXISTS task_session_idx ON task (session_id, seq);
CREATE INDEX IF NOT EXISTS task_status_idx  ON task (status, started_at);
CREATE INDEX IF NOT EXISTS task_goal_idx    ON task (goal_id);
CREATE INDEX IF NOT EXISTS task_external_idx ON task (session_id, external_id);

CREATE TABLE IF NOT EXISTS action (
    id              INTEGER PRIMARY KEY,
    session_id      INTEGER NOT NULL REFERENCES session (id),
    goal_id         INTEGER REFERENCES goal (id),
    task_id         INTEGER REFERENCES task (id),
    seq             INTEGER NOT NULL,
    start_event_id  INTEGER NOT NULL REFERENCES event (id),
    end_event_id    INTEGER REFERENCES event (id),
    corr_key        TEXT,
    tool            TEXT    NOT NULL,
    kind            TEXT    NOT NULL,
    intent          TEXT,
    signature       TEXT    NOT NULL,
    target          TEXT,
    detail          TEXT,
    status          TEXT    NOT NULL,
    -- Why a 'blocked' action never completed, when the runtime said so:
    -- 'user' (declined at the permission prompt), 'rule' (a hook or a
    -- permission rule refused it, and `error` carries that reason), or NULL
    -- for the ones nothing explains — in flight when the session ended.
    -- The three want different fixes, which is why they are not one status.
    blocked_by      TEXT,
    error           TEXT,
    started_at      TEXT    NOT NULL,
    ended_at        TEXT,
    duration_ms     INTEGER,
    result_bytes    INTEGER,

    attempt_no           INTEGER NOT NULL DEFAULT 1,
    resolved_by_action_id INTEGER REFERENCES action (id),
    resolution_span      INTEGER,
    crossed_goal         INTEGER NOT NULL DEFAULT 0,
    crossed_session      INTEGER NOT NULL DEFAULT 0
);

CREATE INDEX IF NOT EXISTS action_session_idx  ON action (session_id, seq);
CREATE INDEX IF NOT EXISTS action_kind_idx     ON action (kind, started_at);
CREATE INDEX IF NOT EXISTS action_sig_idx      ON action (session_id, signature, seq);
CREATE INDEX IF NOT EXISTS action_status_idx   ON action (status);
CREATE INDEX IF NOT EXISTS action_goal_idx     ON action (goal_id);
CREATE INDEX IF NOT EXISTS action_task_idx     ON action (task_id, seq);
CREATE INDEX IF NOT EXISTS action_corr_idx     ON action (session_id, corr_key, status);

CREATE TABLE IF NOT EXISTS remote_call (
    action_id   INTEGER PRIMARY KEY REFERENCES action (id) ON DELETE CASCADE,
    channel     TEXT    NOT NULL,
    method      TEXT,
    host        TEXT,
    port        INTEGER,
    url         TEXT,
    environment TEXT,
    via         TEXT    NOT NULL,
    mutating    INTEGER NOT NULL DEFAULT 0,
    response_summary TEXT
);

CREATE INDEX IF NOT EXISTS remote_host_idx ON remote_call (host);
CREATE INDEX IF NOT EXISTS remote_env_idx  ON remote_call (environment, mutating);

CREATE TABLE IF NOT EXISTS fs_change (
    id           INTEGER PRIMARY KEY,
    action_id    INTEGER NOT NULL REFERENCES action (id) ON DELETE CASCADE,
    path         TEXT    NOT NULL,
    abs_path     TEXT,
    op           TEXT    NOT NULL,
    in_repo      INTEGER NOT NULL DEFAULT 1,
    bytes_after  INTEGER,
    sha256_after TEXT,
    sensitivity  TEXT    NOT NULL DEFAULT 'normal',
    snippet      TEXT
);

CREATE INDEX IF NOT EXISTS fs_path_idx   ON fs_change (path);
CREATE INDEX IF NOT EXISTS fs_sens_idx   ON fs_change (sensitivity);
CREATE INDEX IF NOT EXISTS fs_action_idx ON fs_change (action_id);

-- A credential xenia may use on an agent's behalf. The value is not here: it
-- lives in the operating system's own store. This row is the name, and the
-- rules bounding where it may be sent.
CREATE TABLE IF NOT EXISTS secret (
    name         TEXT PRIMARY KEY,
    backend      TEXT NOT NULL,
    hosts        TEXT NOT NULL,          -- JSON array of host globs
    methods      TEXT NOT NULL,          -- JSON array of HTTP methods
    paths        TEXT,                   -- JSON array of path globs, NULL = any
    note         TEXT,
    created_at   TEXT NOT NULL,
    last_used_at TEXT,
    -- Signing profiles, as JSON: {"default": {"scheme": "hmac", ...}}. Both
    -- the scheme and the string it signs live here rather than in the
    -- caller's request.
    schemes      TEXT,
    -- A strictly increasing counter, for APIs that require one. The broker
    -- sees every call for a credential, so it is the only thing that can keep
    -- one. Persisted: a restart that reset it would break every later call.
    last_nonce   INTEGER,
    -- What this credential is for, and what it was proven able to do. A scope
    -- nobody checked with the far side is a claim rather than a fact, and it
    -- goes stale.
    -- The allowlist of actions this credential may take, as JSON: which
    -- endpoints, and what the request is allowed to say. Required for any
    -- credential that names a service, where a route alone cannot separate a
    -- harmless call from a damaging one.
    body_policy       TEXT,
    service           TEXT,
    scope             TEXT,
    scope_verified_at TEXT,
    expires_hint      TEXT
);

-- One approval, by a human, for one credential against one host. Two clocks:
-- expires_at slides forward on every use, ceiling_at never moves.
CREATE TABLE IF NOT EXISTS secret_grant (
    id           INTEGER PRIMARY KEY,
    name         TEXT    NOT NULL REFERENCES secret (name) ON DELETE CASCADE,
    host         TEXT    NOT NULL,
    mutating     INTEGER NOT NULL DEFAULT 0,
    granted_at   TEXT    NOT NULL,
    -- The sliding window this grant was given, in seconds. It belongs to the
    -- grant rather than to the config, or `--for 60s` slides out to the
    -- default on first use.
    window_s     INTEGER,
    expires_at   TEXT    NOT NULL,
    ceiling_at   TEXT    NOT NULL,
    last_used_at TEXT,
    uses         INTEGER NOT NULL DEFAULT 0,
    source       TEXT    NOT NULL,
    revoked_at   TEXT
);

CREATE INDEX IF NOT EXISTS secret_grant_idx ON secret_grant (name, host, mutating);

-- Every request a credential was asked for, allowed or refused. `url` is the
-- template the agent wrote, placeholder still in it: the filled-in string is
-- never formed anywhere that outlives the request.
CREATE TABLE IF NOT EXISTS secret_use (
    id          INTEGER PRIMARY KEY,
    at          TEXT    NOT NULL,
    name        TEXT    NOT NULL,
    client      TEXT,
    host        TEXT,
    method      TEXT,
    url         TEXT,
    placed      TEXT,
    decision    TEXT    NOT NULL,       -- 'allowed' | 'refused'
    reason      TEXT,
    grant_id    INTEGER,
    status      INTEGER,
    bytes       INTEGER,
    duration_ms INTEGER,
    -- 1 when the far side sent the credential back in its own response, which
    -- is not a redaction problem but a rotation one.
    echoed      INTEGER NOT NULL DEFAULT 0,
    -- The machine-readable half of a refusal; the prose beside it is what
    -- makes one actionable for an agent.
    code        TEXT,
    -- What was sent and what came back, scrubbed and kept whole on disk past
    -- any reply cap.
    request_path     TEXT,
    response_path    TEXT,
    request_sha256   TEXT,
    response_sha256  TEXT
);

CREATE INDEX IF NOT EXISTS secret_use_idx      ON secret_use (at);
CREATE INDEX IF NOT EXISTS secret_use_name_idx ON secret_use (name, at);

-- The agora. Not part of the record: a claim is what one agent told the
-- others it is running, authored by the agent rather than derived from its
-- events, and it is deleted-by-release rather than kept forever. It lives here
-- so every front end reads one store, and so "who left this running" survives
-- the session that left it.
CREATE TABLE IF NOT EXISTS claim (
    id            INTEGER PRIMARY KEY,
    posted_at     TEXT    NOT NULL,
    updated_at    TEXT    NOT NULL,
    released_at   TEXT,
    release_note  TEXT,
    -- The pid of the xenia-mcp server that posted it. One of those runs per
    -- agent session, so its liveness IS the session's, with no heartbeat to
    -- maintain. `holder_start` is the clock the OS started it on: a pid alone
    -- is reused, and a recycled one would report a dead session as alive.
    holder_pid    INTEGER NOT NULL,
    holder_start  TEXT,
    agent         TEXT,
    repo          TEXT,
    resource      TEXT    NOT NULL,
    purpose       TEXT    NOT NULL,
    ram_mb        INTEGER,
    -- {"<pid>": "<lstart>"} — the processes the claim covers, each with the
    -- clock it started on, for the same reason as the holder.
    pids          TEXT,
    pattern       TEXT,
    expires_at    TEXT,
    kill_note     TEXT
);

CREATE INDEX IF NOT EXISTS claim_open_idx  ON claim (released_at, posted_at);
CREATE INDEX IF NOT EXISTS claim_holder_idx ON claim (holder_pid);

DROP VIEW IF EXISTS v_remote_calls;
CREATE VIEW v_remote_calls AS
SELECT a.id            AS action_id,
       s.repo          AS repo,
       s.agent         AS agent,
       a.started_at    AS at,
       r.channel       AS channel,
       r.via           AS via,
       r.environment   AS environment,
       r.host          AS host,
       r.url           AS url,
       r.mutating      AS mutating,
       a.status        AS status,
       a.intent        AS intent,
       a.detail        AS detail,
       a.resolved_by_action_id AS resolved_by
FROM action a
JOIN session s     ON s.id = a.session_id
JOIN remote_call r ON r.action_id = a.id;

DROP VIEW IF EXISTS v_fs_changes;
CREATE VIEW v_fs_changes AS
SELECT f.id         AS change_id,
       a.id         AS action_id,
       s.repo       AS repo,
       s.agent      AS agent,
       a.started_at AS at,
       f.op         AS op,
       f.path       AS path,
       f.in_repo    AS in_repo,
       f.sensitivity AS sensitivity,
       f.bytes_after AS bytes_after,
       a.status     AS status,
       a.intent     AS intent,
       a.resolved_by_action_id AS resolved_by
FROM action a
JOIN session s   ON s.id = a.session_id
JOIN fs_change f ON f.action_id = a.id;

DROP VIEW IF EXISTS v_goal_outcomes;
CREATE VIEW v_goal_outcomes AS
SELECT g.id                 AS goal_id,
       s.repo               AS repo,
       s.agent              AS agent,
       g.created_at         AS at,
       g.status             AS status,
       g.prompt             AS prompt,
       COUNT(a.id)                                            AS actions,
       SUM(a.kind = 'remote_call')                            AS remote_calls,
       SUM(a.kind = 'fs_change')                              AS fs_changes,
       SUM(a.status IN ('error', 'blocked'))                  AS failures,
       SUM(a.status IN ('error', 'blocked') AND a.resolved_by_action_id IS NOT NULL)
                                                              AS failures_fixed,
       SUM(a.status = 'blocked')                              AS blocked,
       g.resolution_note    AS note
FROM goal g
JOIN session s ON s.id = g.session_id
LEFT JOIN action a ON a.goal_id = g.id
GROUP BY g.id;

DROP VIEW IF EXISTS v_task_outcomes;
CREATE VIEW v_task_outcomes AS
SELECT t.id                 AS task_id,
       s.repo               AS repo,
       s.agent              AS agent,
       s.session_uid        AS session,
       t.goal_id            AS goal_id,
       g.prompt             AS goal_prompt,
       t.started_at         AS at,
       t.ended_at           AS ended_at,
       t.label              AS label,
       t.source             AS source,
       t.declared           AS declared,
       t.status             AS status,
       t.overstated         AS overstated,
       t.outcome_note       AS note,
       COUNT(a.id)                                            AS actions,
       (SELECT MAX(n) FROM (SELECT COUNT(*) AS n FROM action x
                            WHERE x.task_id = t.id GROUP BY x.signature))
                                                              AS attempts,
       SUM(a.status IN ('error', 'blocked'))                  AS failures,
       SUM(a.status IN ('error', 'blocked') AND a.resolved_by_action_id IS NOT NULL)
                                                              AS failures_fixed,
       SUM(a.status = 'blocked')                              AS blocked,
       SUM(a.duration_ms)                                     AS duration_ms,
       MIN(a.id)                                              AS first_action_id
FROM task t
JOIN session s ON s.id = t.session_id
LEFT JOIN goal g ON g.id = t.goal_id
LEFT JOIN action a ON a.task_id = t.id
GROUP BY t.id;

DROP VIEW IF EXISTS v_friction;
CREATE VIEW v_friction AS
SELECT a.signature                                   AS signature,
       COUNT(*)                                      AS failures,
       COUNT(DISTINCT a.session_id)                  AS sessions,
       COUNT(DISTINCT s.repo)                        AS repos,
       SUM(a.resolved_by_action_id IS NOT NULL)      AS recovered,
       SUM(a.crossed_goal)                           AS needed_new_instruction,
       SUM(a.crossed_session)                        AS needed_new_session,
       MAX(a.attempt_no)                             AS worst_attempt,
       MIN(a.started_at)                             AS first_at,
       MAX(a.started_at)                             AS last_at
FROM action a
JOIN session s ON s.id = a.session_id
WHERE a.status IN ('error', 'blocked')
GROUP BY a.signature;

DROP VIEW IF EXISTS v_retry_chains;
CREATE VIEW v_retry_chains AS
SELECT f.id            AS failed_action_id,
       s.repo          AS repo,
       f.started_at    AS failed_at,
       f.kind          AS kind,
       f.signature     AS signature,
       f.intent        AS intent,
       substr(COALESCE(f.error, ''), 1, 160) AS failure,
       f.attempt_no    AS attempt_no,
       w.id            AS fixed_by_action_id,
       w.started_at    AS fixed_at,
       f.resolution_span AS actions_between,
       f.crossed_goal  AS needed_new_instruction,
       f.crossed_session AS needed_new_session
FROM action f
JOIN session s ON s.id = f.session_id
LEFT JOIN action w ON w.id = f.resolved_by_action_id
WHERE f.status IN ('error', 'blocked');
