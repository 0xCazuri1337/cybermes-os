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
  captured_at  TEXT NOT NULL,
  -- The CORPUS LINK. MEASURED 2026-11-01: these three columns existed in
  -- the live database but in NO schema file and NO migration, so they were
  -- added by hand at some point. The consequence was that a FRESH database
  -- could not import exam evidence at all -- `wks.assess_evidence`
  -- writes `class_id` and `exam_id`, and the INSERT failed with "table
  -- evidence has no column named class_id". The import was therefore only
  -- ever possible on the one database that had been patched by hand, which
  -- is not a schema, it is a coincidence.
  --
  -- `class_id` links the evidence to a wks bug_class (shared taxonomy);
  -- `item_id` links it to a corpus item; `exam_id` names the graded exam
  -- that produced it. `orch.store.open_db` applies this migration to
  -- existing databases, so an old database and a new one now agree.
  class_id     TEXT,
  item_id      INTEGER,
  exam_id      TEXT
);
CREATE INDEX IF NOT EXISTS ix_evidence_finding ON evidence(finding_id);
CREATE INDEX IF NOT EXISTS ix_evidence_sha ON evidence(sha256);
CREATE INDEX IF NOT EXISTS ix_evidence_class ON evidence(class_id);

CREATE TABLE IF NOT EXISTS finding (
  id            INTEGER PRIMARY KEY,
  finding_key   TEXT NOT NULL UNIQUE,
  title         TEXT NOT NULL,
  target        TEXT, asset TEXT, endpoint TEXT,
  class_id      TEXT,               -- links to wks bug_class (shared taxonomy)
  hypothesis    TEXT,
  severity      TEXT,               -- critical|high|medium|low|info
                -- SEVERITY says how bad the impact would be IF real.
  confidence    REAL NOT NULL DEFAULT 0.0,
                -- CONFIDENCE says how sure we are that it IS real. It is a
                -- SEPARATE axis from severity and must never be derived
                -- from it: a critical-severity claim with weak evidence is
                -- low confidence, and a low-severity claim proven twice is
                -- high confidence. MEASURED 2026-11-01: `finding` carried
                -- only `severity`, so "how sure are we" was inferred from
                -- "how bad would it be" wherever it was needed.
  priority      INTEGER NOT NULL DEFAULT 5,
                -- PRIORITY says what to work on NEXT. Also a separate axis:
                -- it is driven by cost, staleness, novelty and declared
                -- intent (orch/priority.py), never by severity alone.
  status        TEXT NOT NULL DEFAULT 'candidate',
                -- candidate|validating|validated|duplicate|false_positive|reported|rejected
  validation_json TEXT,             -- L1..L6 results (spec §26)
  dedup_group   TEXT,               -- canonical identity key (spec §28)
  canonical_id  INTEGER REFERENCES finding(id) ON DELETE SET NULL,
  validator_run TEXT,               -- L4: who validated, MUST differ from claimant
  report_path   TEXT,
  hunt_id       TEXT,
                -- THE HUNT THAT PRODUCED THIS FINDING.
                --
                -- MEASURED 2026-11-02: `finding` had no hunt id, so hunt
                -- membership had to be inferred from the finding's own KEY
                -- (a substring match) or from the task graph. That inference
                -- is what made an origin unverifiable: there was no way to
                -- ask "which authorization backs this finding?" without
                -- guessing. The hunt id is recorded at creation, by the
                -- caller that knows it, and it is what `hunt_authorization`
                -- is keyed on.
                --
                -- NULL means the record was not produced by a hunt -- a
                -- manual entry, an imported write-up, a test fixture.
  provenance    TEXT NOT NULL DEFAULT 'UNKNOWN',
                -- WHERE THIS RECORD CAME FROM, and therefore what it may
                -- be used for. MEASURED 2026-11-01: the test suite wrote
                -- 44 findings into the live canonical database, and the
                -- scheduler counted every one of them as "potential
                -- impact" -- because there was NO field that said a
                -- finding was test output. The quarantine fixed the
                -- records; this column prevents the class of defect.
                --
                -- PRODUCTION_HUNT|EXAM_FIXTURE|EVAL_TEST|IMPORTED_RESEARCH|
                -- MANUAL_ENTRY|UNKNOWN
                --
                -- Only PRODUCTION_HUNT and MANUAL_ENTRY count as impact.
                -- EXAM_FIXTURE stays usable by the exam harness but
                -- contributes zero. EVAL_TEST and UNKNOWN contribute zero
                -- and may not be promoted. The vocabulary and the
                -- eligibility rules live in `orch/provenance.py`; the
                -- column is only the storage.
  created_at    TEXT NOT NULL,
  updated_at    TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS ix_finding_status ON finding(status);
CREATE INDEX IF NOT EXISTS ix_finding_dedup ON finding(dedup_group);
-- The index on `finding(provenance)` is NOT created here.
--
-- MEASURED 2026-11-01: this file created the index unconditionally, but
-- `CREATE TABLE IF NOT EXISTS` does not add a column to a table that
-- already exists. So on the live database -- where `finding` predated
-- the `provenance` column -- the index statement failed with "no such
-- column: provenance" and the schema script aborted, taking the whole
-- database open with it.
--
-- The index belongs to the MIGRATION that adds the column
-- (`orch/store._migrate_provenance`), because only that code knows
-- whether the column is present. A fresh database gets the column from
-- the CREATE TABLE above and the index from the migration on the first
-- open; an old database gets both from the migration.

-- Which lesson a finding taught.
--
-- MEASURED 2026-11-01: this table was created at RUNTIME by
-- `orch/learning_bridge._link_lesson`, with a `CREATE TABLE IF NOT EXISTS`
-- inside the write path. That is three problems at once: the table was not
-- in the schema (so a fresh database and a migrated one differed), it was
-- not in the ownership map (so the runtime authorizer refused the write as
-- an UNMAPPED table -- "not authorized"), and the failure was swallowed by
-- a bare `except sqlite3.Error: pass`, so the link was silently lost.
--
-- It is an ORCHESTRATION table: it records what a hunting outcome taught,
-- which is operational state, not corpus knowledge.
CREATE TABLE IF NOT EXISTS finding_lesson (
  finding_key TEXT PRIMARY KEY,
  lesson_key  TEXT NOT NULL,
  outcome     TEXT,                -- confirmed|rejected|open|ineligible_origin
                -- `ineligible_origin` MEASURED 2026-11-01: the finding
                -- was confirmed, but its origin was not eligible to
                -- become hunting experience, so the lesson was recorded
                -- and deliberately NOT verified. The link says which
                -- happened, so the refusal is visible in the query
                -- "what did this finding teach?" rather than being
                -- indistinguishable from an open outcome.
  recorded_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS ix_finding_lesson_key
  ON finding_lesson(lesson_key);

-- ===========================================================================
-- THE TABLES THE GATE READS
--
-- MEASURED 2026-11-02: six tables the final gate reads were created at
-- RUNTIME by their owning modules (`orch/agentkit.py`, `orch/lifecycle.py`,
-- `orch/tools.py`) with a `CREATE TABLE IF NOT EXISTS` inside the write
-- path, and were declared in NO schema file. On a FRESH database the gate
-- therefore CRASHED -- "no such table: tool_attempt" -- rather than
-- judging the finding. A gate that crashes instead of refusing is a gate
-- whose verdict cannot be relied upon.
--
-- A schema that exists only in one database is the same defect as a
-- registry that only one caller reads: two databases, two shapes, and the
-- difference is invisible until a fresh one is created.
--
-- The definitions below are the owning modules' own, verbatim. The
-- runtime `CREATE TABLE IF NOT EXISTS` calls remain, and remain harmless:
-- a table that already exists is not altered.
-- ===========================================================================

-- The agent-output ledgers (owner: orch/agentkit.py).
CREATE TABLE IF NOT EXISTS agent_result (
  result_key  TEXT PRIMARY KEY,
  run_key     TEXT,
  task_key    TEXT,
  type        TEXT NOT NULL,          -- one of RESULT_TYPES
  original_type TEXT,                  -- what the agent CLAIMED
  downgraded  INTEGER NOT NULL DEFAULT 0,
  payload     TEXT,                   -- JSON
  evidence_ids TEXT,                  -- JSON array of evidence ids
  reported_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS ix_agent_result_task ON agent_result(task_key);

CREATE TABLE IF NOT EXISTS agent_failure (
  id         INTEGER PRIMARY KEY,
  role_key   TEXT NOT NULL,
  class_id   TEXT,
  task_key   TEXT,
  reason     TEXT NOT NULL,
  at         TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS ix_agent_failure ON agent_failure(role_key, class_id);

-- The finding's CURRENT state (owner: orch/lifecycle.py).
CREATE TABLE IF NOT EXISTS finding_state (
  finding_key TEXT PRIMARY KEY,
  lifecycle   TEXT NOT NULL,
  levels_failed TEXT,                 -- JSON list
  evidence_refs  TEXT,                -- JSON list of evidence ids
  changed_by  TEXT,
  reason      TEXT,
  at          TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS ix_fstate_life ON finding_state(lifecycle);

-- The APPEND-ONLY transition history.
CREATE TABLE IF NOT EXISTS finding_transition (
  seq          INTEGER PRIMARY KEY AUTOINCREMENT,
  finding_key  TEXT NOT NULL,
  from_state   TEXT,
  to_state     TEXT NOT NULL,
  levels_failed TEXT,                -- JSON list
  evidence_refs TEXT,                -- JSON list of evidence ids
  changed_by   TEXT,
  reason       TEXT,
  at           TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS ix_ftrans_key ON finding_transition(finding_key, seq);
CREATE INDEX IF NOT EXISTS ix_ftrans_at  ON finding_transition(at);

-- Promotion is EVIDENCE-GATED.
CREATE TABLE IF NOT EXISTS promotion_requirement (
  to_state   TEXT PRIMARY KEY,
  requires_evidence INTEGER NOT NULL DEFAULT 0,
  requires_reason   INTEGER NOT NULL DEFAULT 0,
  note       TEXT
);

CREATE TABLE IF NOT EXISTS revalidation_queue (
  rq_key        TEXT PRIMARY KEY,
  hunt_id       TEXT,
  finding_key   TEXT NOT NULL,
  reason        TEXT NOT NULL,
  levels_failed TEXT,
  evidence_ids  TEXT,
  state         TEXT NOT NULL DEFAULT 'queued',  -- queued|retested|closed
  queued_at     TEXT NOT NULL,
  resolved_at   TEXT
);
CREATE INDEX IF NOT EXISTS ix_rq_state ON revalidation_queue(state);

CREATE TABLE IF NOT EXISTS retest_record (
  retest_key   TEXT PRIMARY KEY,
  hunt_id      TEXT,
  finding_key  TEXT NOT NULL,
  trigger      TEXT NOT NULL,   -- §40's list
  verdict      TEXT,            -- confirmed|weakened|refuted|inconclusive
  detail       TEXT,
  at           TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS ix_retest_finding ON retest_record(finding_key);

CREATE TABLE IF NOT EXISTS dedup_decision (
  decision_key TEXT PRIMARY KEY,
  finding_key  TEXT NOT NULL,
  vs_key       TEXT NOT NULL,
  verdict      TEXT NOT NULL,   -- duplicate|variant|independent
  rung         TEXT NOT NULL,   -- which rung of the §38 ladder decided it
  reason       TEXT,
  at           TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS ix_dedup_finding ON dedup_decision(finding_key);

CREATE TABLE IF NOT EXISTS target_change (
  change_key  TEXT PRIMARY KEY,
  hunt_id     TEXT,
  kind        TEXT NOT NULL,   -- endpoint_removed|asset_new|behaviour_changed|
                               -- scope_changed|tech_changed
  subject     TEXT,
  before      TEXT,
  after       TEXT,
  impact      TEXT,             -- tasks invalidated | none
  rebuilt     TEXT,             -- JSON list of what was rebuilt
  preserved   TEXT,             -- JSON list of what was preserved
  at          TEXT NOT NULL
);

-- The tool-attempt ledger (owner: orch/tools.py). This is what the gate's
-- program-rules stage reads to see whether a prohibited technique was
-- attempted and refused.
CREATE TABLE IF NOT EXISTS tool_attempt (
  attempt_id  INTEGER PRIMARY KEY,
  hunt_id     TEXT,
  tool        TEXT NOT NULL,
  objective   TEXT,
  action      TEXT,
  target      TEXT,
  outcome     TEXT NOT NULL,     -- ok|unavailable|refused|failed|substituted
  detail      TEXT,
  substitute  TEXT,
  artifact    TEXT,
  provenance  TEXT,
  at          TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS ix_tool_attempt ON tool_attempt(tool, outcome);

-- ===========================================================================
-- SCOPE OBSERVATION (§6) — the out-of-scope register
-- ===========================================================================
--
-- MEASURED 2026-11-02: this table was created at RUNTIME by
-- `orch.authz.ScopeLedger._ensure`, with a `CREATE TABLE IF NOT EXISTS`
-- inside the write path, and was declared in NO schema file. So on a
-- FRESH database the final gate crashed with "no such table:
-- scope_observation" -- the gate's scope stage read a table that only
-- existed if a hunt had already run.
--
-- It is an ORCHESTRATION table: it records the scope verdict of each
-- discovered asset, which is operational state, not corpus knowledge.
CREATE TABLE IF NOT EXISTS scope_observation (
  asset        TEXT PRIMARY KEY,
  verdict      TEXT NOT NULL,   -- in_scope|out_of_scope|undetermined
  discovered_by TEXT,
  evidence     TEXT,
  tested       INTEGER NOT NULL DEFAULT 0,
  recorded_at  TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS ix_scope_observation_verdict
  ON scope_observation(verdict);

-- ===========================================================================
-- HUNT AUTHORIZATION — the persisted backing for a PRODUCTION_HUNT origin
-- ===========================================================================
--
-- MEASURED 2026-11-02: `finding.provenance` recorded WHERE a record came
-- from, but the value was DERIVED, never BACKED. `classify_from_context`
-- returned PRODUCTION_HUNT for any hunt with an id and a routable target,
-- so a caller that merely possessed a hunt id could assert production
-- impact without any authorization existing anywhere. The origin was a
-- claim the system made about itself.
--
-- The origin is now a CLAIM WITH A RECEIPT. A finding may only carry
-- PRODUCTION_HUNT when a row in this table backs the hunt it came from:
-- the row names the hunt, the program, the target, the authorization
-- reference, and whether the authorization context was VALIDATED (complete,
-- unambiguous, and permitted to probe the named target).
--
-- Absence of a row is a deny, never a default-allow — the same rule the
-- `scope_grant` table already follows for offensive execution. A hunt
-- whose authorization was never validated produces findings with an
-- UNKNOWN origin, and UNKNOWN contributes zero impact.
--
-- This is ORCHESTRATION state: it records what a hunt was permitted to do,
-- which is operational history, not corpus knowledge.
CREATE TABLE IF NOT EXISTS hunt_authorization (
  auth_id           TEXT PRIMARY KEY,
  hunt_id          TEXT NOT NULL UNIQUE,
  program          TEXT NOT NULL,
  target           TEXT NOT NULL,
  kind             TEXT NOT NULL,
  authorization_ref TEXT NOT NULL,
  offensive_allowed INTEGER NOT NULL DEFAULT 0,
  validated        INTEGER NOT NULL DEFAULT 0,
  validated_at     TEXT,
  created_at       TEXT NOT NULL,
  context_json     TEXT,
  note             TEXT
);
CREATE INDEX IF NOT EXISTS ix_hunt_authorization_target
  ON hunt_authorization(target);

-- ===========================================================================
-- PROVENANCE CORRECTION — the ONLY way a record's origin may change
-- ===========================================================================
--
-- MEASURED 2026-11-02: `orch.provenance.set_provenance` performed a bare
-- UPDATE of the origin column, with no record of what it was, why it
-- changed, or who changed it. So a misclassified record could be quietly
-- promoted into production impact and the change left no trace.
--
-- The origin is now immutable after creation. A correction is an APPEND-ONLY
-- audit row that names the record, the old value, the new value, the reason
-- and the corrector — and it is written in the same transaction as the
-- UPDATE, so the change and its receipt cannot diverge.
CREATE TABLE IF NOT EXISTS provenance_correction (
  correction_id  TEXT PRIMARY KEY,
  table_name     TEXT NOT NULL,
  record_key     TEXT NOT NULL,
  old_provenance TEXT NOT NULL,
  new_provenance TEXT NOT NULL,
  reason         TEXT NOT NULL,
  corrected_by   TEXT NOT NULL,
  evidence_ref   TEXT,
  corrected_at   TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS ix_provenance_correction_record
  ON provenance_correction(table_name, record_key);

-- ===========================================================================
-- THE ORIGIN IS IMMUTABLE AT THE DATABASE LEVEL
-- ===========================================================================
--
-- MEASURED 2026-11-02: `orch.provenance.set_provenance` was the ONLY
-- sanctioned correction path -- but nothing at the database level stopped a
-- caller from writing `UPDATE finding SET provenance='PRODUCTION_HUNT'`.
-- The audit trail described every origin change that went through the
-- function; it did not prevent the ones that did not.
--
-- The guarantee was therefore one raw SQL statement away from being
-- absent, and the raw statement is exactly what a migration tool, an
-- incident reconciliation, or an ad-hoc repair would reach for.
--
-- So the column is guarded by a TRIGGER. The trigger permits the change
-- ONLY when a matching `provenance_correction` audit row exists for the
-- record -- which `set_provenance` writes in the SAME transaction, before
-- the UPDATE. The correction row is the proof that the change was
-- deliberate and audited; without it, the UPDATE is refused by SQLite
-- itself.
--
-- The guard is deliberately NOT a trigger that refuses every change. The
-- correction path must still work, and it must work in the same
-- transaction as the audit row. A trigger that demanded "no audit row"
-- would refuse the legitimate change too.
--
-- `tools/apply_provenance.py` performs exactly this kind of repair, so it
-- goes through `set_provenance` as well -- which is why its writes still
-- succeed after this guard is installed.
CREATE TRIGGER IF NOT EXISTS trg_finding_origin_immutable
BEFORE UPDATE OF provenance ON finding
FOR EACH ROW
WHEN NEW.provenance IS NOT OLD.provenance
 AND NOT EXISTS (
   SELECT 1 FROM provenance_correction c
   WHERE c.table_name='finding'
     AND c.record_key=OLD.finding_key
     AND c.old_provenance=OLD.provenance
     AND c.new_provenance=NEW.provenance
 )
BEGIN
  SELECT RAISE(ABORT, 'the origin of a finding may only change through a recorded provenance_correction: use orch.provenance.set_provenance');
END;

-- The `lesson` table's trigger lives with its OWNER -- the learning
-- engine's schema (`learning_engine/engine.py`) -- because `lesson` is a
-- KNOWLEDGE table and the orchestration schema does not create it. A
-- trigger on a table this script does not create would fail to apply on
-- an orchestration-only database.

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
-- GATE FINGERPRINT — the baseline the self-audit compares the quality gate
-- against.
--
-- MEASURED 2026-10-31: this table was created AD HOC by `orch/gate_guard.py`
-- with a `CREATE TABLE IF NOT EXISTS` at call time, and was declared in
-- NEITHER schema file. The runtime ownership authorizer -- which enforces
-- "every table has an owner" -- refused the ad-hoc creation, because a
-- table that no schema declares has no declared owner.
--
-- Declaring it here makes it an ORCHESTRATION table (it records the state of
-- the knowledge engine's gate files, which is operational state, not
-- knowledge), and makes the ownership map complete: every table in the
-- canonical database now has exactly one owner.
-- ===========================================================================

CREATE TABLE IF NOT EXISTS gate_fingerprint (
  file        TEXT PRIMARY KEY,
  sha256      TEXT NOT NULL,
  recorded_at TEXT NOT NULL,
  reason      TEXT
);

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