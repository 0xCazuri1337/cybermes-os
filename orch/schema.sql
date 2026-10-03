-- Orchestration layer (spec §4 orchestrator, §5 delegation, §6 DAG,
-- §7 priority, §25 scope gate, §26 validation, §28 dedup, §29 evidence,
-- §30 reporting, §39 workers, §41 events, §46 A/B, §49 checkpoints).
--
-- SEPARATE FROM wks/schema.sql ON PURPOSE. wks/ is the knowledge engine and
-- carries invariant I6 ("research, not intrusion") plus CONTROL's layer
-- ownership. Orchestration owns work, not knowledge, and must be removable
-- without touching the gate. One database file, two schemas, two owners.
--
-- Design rules:
--   * No state is asserted without an artifact behind it (invariant I10).
--   * A task's runnable-ness is DERIVED from edges, never stored as a flag.
--   * Evidence is immutable. Dedup never deletes evidence.

PRAGMA journal_mode=WAL;
PRAGMA foreign_keys=ON;

-- ===========================================================================
-- TASK DAG
-- ===========================================================================

-- Real edges, not a JSON blob. The previous `task.depends_on` column could not
-- answer "what does this block?" or detect a cycle without parsing every row;
-- `task_dep` is queryable in both directions and the cycle check is a JOIN.
CREATE TABLE IF NOT EXISTS task_dep (
  task_key   TEXT NOT NULL,
  depends_on TEXT NOT NULL,        -- task_key this one waits for
  kind       TEXT NOT NULL DEFAULT 'finish', -- finish|blocks(soft)
  PRIMARY KEY (task_key, depends_on)
);
CREATE INDEX IF NOT EXISTS ix_task_dep_rev ON task_dep(depends_on);

-- ===========================================================================
-- AGENTS (§5) — roles are DATA, constructed per goal, not a hard-coded enum
-- ===========================================================================

CREATE TABLE IF NOT EXISTS agent_role (
  role_key     TEXT PRIMARY KEY,
  domain       TEXT NOT NULL,       -- web|api|network|ad|identity|research|validation|reporting|system
  objective_kind TEXT,              -- task kind this role is fit for; NULL = general
  toolsets     TEXT,                -- JSON array
  capabilities TEXT,                -- JSON array from capability.LEVELS
  max_depth    INTEGER NOT NULL DEFAULT 1,  -- recursion guard: nested delegation budget
  rationale    TEXT,                -- WHY this role was created (audit, §5)
  created_at   TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS agent_run (
  id            INTEGER PRIMARY KEY,
  run_key       TEXT NOT NULL UNIQUE,
  role_key      TEXT NOT NULL,
  task_key      TEXT,
  parent_run_key TEXT,              -- NULL at depth 0
  depth         INTEGER NOT NULL DEFAULT 0,
  status        TEXT NOT NULL,      -- planned|dispatched|running|completed|failed|timeout|blocked
  objective     TEXT NOT NULL,
  input_json    TEXT,
  output_json   TEXT,
  artifact_path TEXT,
  attempts      INTEGER NOT NULL DEFAULT 0,
  last_error    TEXT,
  started_at    TEXT,
  finished_at   TEXT,
  created_at    TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS ix_agent_run_status ON agent_run(status);
CREATE INDEX IF NOT EXISTS ix_agent_run_parent ON agent_run(parent_run_key);

-- ===========================================================================
-- CAPABILITY + SCOPE (§25, §35)
-- ===========================================================================

CREATE TABLE IF NOT EXISTS capability_grant (
  id         INTEGER PRIMARY KEY,
  subject    TEXT NOT NULL,         -- agent run_key, role_key, or task_key
  level      TEXT NOT NULL,         -- READ|ANALYZE|WRITE|EXECUTE|DESTRUCTIVE
  granted_by TEXT NOT NULL,
  rationale  TEXT,
  granted_at TEXT NOT NULL,
  expires_at TEXT
);

-- The authorization gate. Offensive execution is DENIED unless a row exists
-- that names the target, names the authorization, and allows it. Absence of a
-- row is a deny, never a default-allow (spec §25: never infer authorization
-- from a public endpoint).
CREATE TABLE IF NOT EXISTS scope_grant (
  scope_key       TEXT PRIMARY KEY,
  target          TEXT NOT NULL,
  kind            TEXT NOT NULL,     -- lab|bugbounty|internal_authorized|research_only
  authorization_ref TEXT NOT NULL,   -- program URL, signed scope doc, or lab id
  offensive_allowed INTEGER NOT NULL DEFAULT 0,
  granted_at      TEXT NOT NULL,
  expires_at      TEXT,
  notes           TEXT
);
CREATE INDEX IF NOT EXISTS ix_scope_target ON scope_grant(target);

-- ===========================================================================
-- EVIDENCE (§29) + FINDINGS (§28, §30)
-- ===========================================================================

CREATE TABLE IF NOT EXISTS evidence (
  id           INTEGER PRIMARY KEY,
  task_key     TEXT,
  finding_id   INTEGER REFERENCES finding(id) ON DELETE SET NULL,
  kind         TEXT NOT NULL,       -- request|response|payload|log|screenshot|repro|note
  target       TEXT, asset TEXT, endpoint TEXT,
  request_raw  TEXT, response_raw TEXT, payload TEXT,
  sha256       TEXT,                -- content hash: dedup + tamper evidence
  provenance   TEXT,                -- which agent run produced this
  captured_at  TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS ix_evidence_finding ON evidence(finding_id);
CREATE INDEX IF NOT EXISTS ix_evidence_sha ON evidence(sha256);

CREATE TABLE IF NOT EXISTS finding (
  id            INTEGER PRIMARY KEY,
  finding_key   TEXT NOT NULL UNIQUE,
  title         TEXT NOT NULL,
  target        TEXT, asset TEXT, endpoint TEXT,
  class_id      TEXT,               -- links to wks bug_class (shared taxonomy)
  hypothesis    TEXT,
  severity      TEXT,               -- critical|high|medium|low|info
  status        TEXT NOT NULL DEFAULT 'candidate',
                -- candidate|validating|validated|duplicate|false_positive|reported|rejected
  validation_json TEXT,             -- L1..L6 results (spec §26)
  dedup_group   TEXT,               -- canonical identity key (spec §28)
  canonical_id  INTEGER REFERENCES finding(id) ON DELETE SET NULL,
  validator_run TEXT,               -- L4: who validated, MUST differ from claimant
  report_path   TEXT,
  created_at    TEXT NOT NULL,
  updated_at    TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS ix_finding_status ON finding(status);
CREATE INDEX IF NOT EXISTS ix_finding_dedup ON finding(dedup_group);

-- ===========================================================================
-- EVENTS (§41) — event-driven work activation
-- ===========================================================================

CREATE TABLE IF NOT EXISTS event (
  id          INTEGER PRIMARY KEY,
  event_key   TEXT NOT NULL UNIQUE, -- idempotence: same signal twice = one event
  kind        TEXT NOT NULL,        -- cve|technique|gap|validation_failure|finding|tool_failure|health|architecture
  source      TEXT,
  severity    TEXT NOT NULL DEFAULT 'info',
  payload_json TEXT,
  relevance   REAL NOT NULL DEFAULT 0.0,  -- relevance analysis decides whether work is created
  state       TEXT NOT NULL DEFAULT 'new', -- new|triaged|worked|dismissed
  created_task TEXT,
  created_at  TEXT NOT NULL,
  acted_at    TEXT
);
CREATE INDEX IF NOT EXISTS ix_event_state ON event(state, relevance DESC);

-- ===========================================================================
-- WORKERS (§39) + CHECKPOINTS (§37, §49)
-- ===========================================================================

CREATE TABLE IF NOT EXISTS worker_heartbeat (
  worker_key  TEXT PRIMARY KEY,
  kind        TEXT NOT NULL,
  status      TEXT NOT NULL,       -- idle|running|failed|stopped
  cycle       INTEGER NOT NULL DEFAULT 0,
  last_beat   TEXT NOT NULL,
  last_result TEXT,
  pid         INTEGER
);

CREATE TABLE IF NOT EXISTS checkpoint (
  id          INTEGER PRIMARY KEY,
  scope       TEXT NOT NULL,       -- project|target|hunt|research|lab|system
  label       TEXT NOT NULL,
  state_json  TEXT NOT NULL,       -- resumable state; survives compaction (§37)
  created_at  TEXT NOT NULL,
  UNIQUE(scope, label)
);

-- ===========================================================================
-- A/B EXPERIMENTS (§46)
-- ===========================================================================

CREATE TABLE IF NOT EXISTS ab_experiment (
  exp_key     TEXT PRIMARY KEY,
  question    TEXT NOT NULL,
  metric      TEXT NOT NULL,       -- what is being measured
  arms        TEXT NOT NULL,       -- JSON array of arm keys
  status      TEXT NOT NULL DEFAULT 'planned', -- planned|running|decided|rolled_back
  winner      TEXT,
  verdict     TEXT,
  created_at  TEXT NOT NULL,
  decided_at  TEXT
);

CREATE TABLE IF NOT EXISTS ab_result (
  id         INTEGER PRIMARY KEY,
  exp_key    TEXT NOT NULL REFERENCES ab_experiment(exp_key) ON DELETE CASCADE,
  arm        TEXT NOT NULL,
  metric     TEXT NOT NULL,
  value      REAL,
  detail     TEXT,
  recorded_at TEXT NOT NULL,
  UNIQUE(exp_key, arm, metric)
);

-- ===========================================================================
-- RETRY / RECOVERY (§36) — attempts are counted so "block" is earned, not declared
-- ===========================================================================

CREATE TABLE IF NOT EXISTS recovery_attempt (
  id         INTEGER PRIMARY KEY,
  task_key   TEXT NOT NULL,
  attempt    INTEGER NOT NULL,
  strategy   TEXT NOT NULL,        -- retry|inspect_logs|alt_method|alt_tool|delegate|research
  outcome    TEXT NOT NULL,        -- failed|progress|resolved
  detail     TEXT,
  at         TEXT NOT NULL,
  UNIQUE(task_key, attempt)
);
CREATE INDEX IF NOT EXISTS ix_recovery_task ON recovery_attempt(task_key, attempt);