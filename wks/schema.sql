-- WKS (Web & API Knowledge System) — canonical schema.
-- SQLite. One file. FTS5 for lexical retrieval; no vector store (none available,
-- and curated metadata beats a blind embedding bucket for hunting knowledge).
--
-- Design rule: an item's state is derived from EVIDENCE, never asserted.
-- `validation_state` is writable only by the gate in quality.py.

PRAGMA journal_mode=WAL;
PRAGMA foreign_keys=ON;

-- -------------------------------------------------------------------
-- SOURCES: the provenance root. Nothing enters the corpus without one.
--
-- `access_state` is the recorded REACHABILITY of the page, written by
-- wks.http on every fetch and migrated in by wks/migrate.py. It is the
-- difference between "we know this page is reachable" and "we only know
-- somebody declared it", which is the distinction the store could not
-- previously make: http_status and content_hash were NULL on every row, so
-- staleness was unmeasurable and a 0.0 stale rate meant "not checked".
-- Vocabulary is closed in wks/http.py ACCESS_STATES and enforced there.
-- -------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS source (
  id            INTEGER PRIMARY KEY,
  url           TEXT NOT NULL UNIQUE,
  host          TEXT NOT NULL,              -- registrable host; corroboration counts HOSTS
  title         TEXT,
  publisher     TEXT,                       -- org, for independence assessment
  source_type   TEXT NOT NULL,              -- taxonomy|advisory|research|writeup|report|docs|cheatsheet|blog|social|dataset|vendor
  authority     INTEGER NOT NULL DEFAULT 3,-- 1=normative .. 5=unverified lead
  retrieved_at  TEXT NOT NULL,
  http_status   INTEGER,
  content_hash  TEXT,                       -- sha256[:32] of the PROSE a quote is matched against
  access_state        TEXT NOT NULL DEFAULT 'UNVERIFIED',
                                           -- ACTIVE|RATE_LIMITED|BLOCKED|PAYWALLED
                                           -- |BROWSER_REQUIRED|STALE|UNVERIFIED (wks/http.py)
  access_checked_at   TEXT,                  -- when access_state was last measured
  access_detail       TEXT,                  -- why: error text, paywall notice, retry budget spent
  last_ok_at          TEXT,                  -- last time this source returned ACTIVE
  notes         TEXT
);
CREATE INDEX IF NOT EXISTS ix_source_host ON source(host);
CREATE INDEX IF NOT EXISTS ix_source_access ON source(access_state);

-- ---------------------------------------------------------------------------
-- CLASSES: one row per bug class / attack surface. Taxonomy lives here.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS bug_class (
  id            TEXT PRIMARY KEY,           -- stable slug
  name          TEXT NOT NULL,
  surface       TEXT NOT NULL,              -- web|api|identity|client|mobile|business|cross
  cwe           TEXT,
  owasp         TEXT,
  aliases       TEXT,                       -- JSON array
  summary       TEXT,
  status        TEXT NOT NULL DEFAULT 'planned', -- planned|researching|mature|stale
  methodology   TEXT,                       -- path to methodology md
  skill_path    TEXT,
  first_seen    TEXT NOT NULL,
  last_reviewed TEXT
);

-- ---------------------------------------------------------------------------
-- ITEMS: atomic knowledge. One claim, one row.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS item (
  id            INTEGER PRIMARY KEY,
  item_key      TEXT NOT NULL UNIQUE,       -- slug: <class>.<slug>
  class_id      TEXT NOT NULL REFERENCES bug_class(id),
  claim         TEXT NOT NULL,              -- the single falsifiable assertion
  kind          TEXT NOT NULL,              -- prerequisite|signal|technique|test|validation
                                           -- |fp_rule|evidence|impact|variant|bypass|chain_link
  surface       TEXT,                       -- rest|graphql|ws|oauth|jwt|session|sso|mobile|web|infra
  severity_hint TEXT,                       -- critical|high|medium|low|info
  hunting_value INTEGER NOT NULL DEFAULT 3,-- 1..5, practical utility per §2
  body          TEXT,                       -- elaboration, never the whole KB
  disproof      TEXT,                       -- what would falsify this claim (§ method: a test that cannot fail proves nothing)
  origin        TEXT,                       -- RESEARCH|LEARNING provenance of this item
  status        TEXT NOT NULL DEFAULT 'active',   -- active|superseded|rejected|outdated
  -- Duplicate bookkeeping. The corpus carried one byte-identical claim twice,
  -- both live and both promoted, and nothing recorded that they were the same
  -- knowledge. `dedup_of` marks the row as a duplicate of another; `canonical_id`
  -- points at the row a reader should follow. NEITHER deletes anything: the
  -- duplicate keeps its own citations and its own audit history, because a
  -- duplicate that cited a different source is evidence, not garbage.
  dedup_of      INTEGER REFERENCES item(id) ON DELETE SET NULL,
  canonical_id  INTEGER REFERENCES item(id) ON DELETE SET NULL,
  created_at    TEXT NOT NULL,
  updated_at    TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS ix_item_class ON item(class_id);
CREATE INDEX IF NOT EXISTS ix_item_kind  ON item(kind);
CREATE INDEX IF NOT EXISTS ix_item_canonical ON item(canonical_id);

-- Evidence: many-to-many. An item with 0 evidence can never leave 'discovered'.
CREATE TABLE IF NOT EXISTS item_source (
  item_id       INTEGER NOT NULL REFERENCES item(id) ON DELETE CASCADE,
  source_id     INTEGER NOT NULL REFERENCES source(id) ON DELETE CASCADE,
  quote         TEXT,                       -- supporting span from the source
  locator       TEXT,                       -- anchor within page
  PRIMARY KEY (item_id, source_id)
);

-- Per-item quality vector (§15). Ten dimensions, 0..1 each.
CREATE TABLE IF NOT EXISTS quality (
  item_id        INTEGER PRIMARY KEY REFERENCES item(id) ON DELETE CASCADE,
  source_credibility REAL NOT NULL DEFAULT 0,
  technical_specificity REAL NOT NULL DEFAULT 0,
  evidence_strength     REAL NOT NULL DEFAULT 0,
  reproducibility       REAL NOT NULL DEFAULT 0,
  corroboration         REAL NOT NULL DEFAULT 0,
  practical_usefulness  REAL NOT NULL DEFAULT 0,
  recency               REAL NOT NULL DEFAULT 0,
  internal_consistency  REAL NOT NULL DEFAULT 0,
  real_world_demo       REAL NOT NULL DEFAULT 0,
  limitations_documented REAL NOT NULL DEFAULT 0,
  score            REAL NOT NULL DEFAULT 0, -- weighted mean
  validation_state TEXT NOT NULL DEFAULT 'discovered',
  gate_reasons     TEXT,                    -- JSON: why it is not promoted
  assessed_at      TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS ix_quality_state ON quality(validation_state);

-- ---------------------------------------------------------------------------
-- QUARANTINE: records that are RETAINED but must not count as live.
--
-- MEASURED 2026-10-31 (db-layer audit): five `quality` rows referenced
-- item_ids that no longer existed (1959-1963). The cause was
-- `wks.readonly.sandbox()` opening its copy with SQLite's default
-- `foreign_keys=OFF`, which made every `ON DELETE CASCADE` in this schema
-- INERT -- a sandbox experiment deleted items and their quality vectors
-- outlived them. `sandbox()` now enables foreign keys, so the corruption
-- cannot recur.
--
-- The five residual rows are assessment history: the only record that the
-- items were ever reviewed. The mission rule is that nothing is deleted and
-- legacy records go to `quarantine/` with a recorded verdict. So the rows
-- MOVE here -- their full content is copied, the verdict says why, and the
-- live `quality` table goes back to the 1:1 invariant with `item`.
--
-- This is a table rather than a directory because the quarantined row must
-- keep its link to the item it assessed, and a file cannot do that.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS quarantine (
  quarantine_key TEXT PRIMARY KEY,
  table_name     TEXT NOT NULL,            -- the table the row came from
  row_key        TEXT,                     -- the row's own primary key
  verdict        TEXT NOT NULL,            -- why it was quarantined
  payload        TEXT,                     -- JSON: the full row, verbatim
  quarantined_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS ix_quarantine_table ON quarantine(table_name);

-- ---------------------------------------------------------------------------
-- CLASS -> DOMAIN mapping. Owns which of the two domains (web / network) a
-- class belongs to; every bundle, skill and methodology path is derived from
-- it. Lives here rather than on `bug_class` because a class can be reachable
-- from more than one domain's router and `class_dir` must resolve to exactly
-- one place.
--
-- It was previously only present in the live database, never in this file, so
-- every freshly-created database (a dry run, a test scratch db, a new install)
-- raised "no such table: class_domain" the moment skillgen rendered a skill.
-- A table that exists only in one db file is not part of the schema.
CREATE TABLE IF NOT EXISTS class_domain (
  class_id   TEXT NOT NULL REFERENCES bug_class(id) ON DELETE CASCADE,
  domain     TEXT NOT NULL,                  -- web | network
  registered_at TEXT NOT NULL,
  PRIMARY KEY (class_id)
);
CREATE INDEX IF NOT EXISTS ix_class_domain ON class_domain(domain);

-- ---------------------------------------------------------------------------
-- CHAINS: first-class (§10). A -> enables -> B, with justification.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS chain (
  id            INTEGER PRIMARY KEY,
  chain_key     TEXT NOT NULL UNIQUE,
  name          TEXT NOT NULL,
  goal          TEXT NOT NULL,              -- account_takeover|cross_tenant|priv_esc|...
  summary       TEXT,
  impact        TEXT,
  created_at    TEXT NOT NULL,
  updated_at    TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS chain_step (
  id        INTEGER PRIMARY KEY,
  chain_id  INTEGER NOT NULL REFERENCES chain(id) ON DELETE CASCADE,
  ord       INTEGER NOT NULL,
  item_id   INTEGER REFERENCES item(id),
  class_id  TEXT REFERENCES bug_class(id),
  action    TEXT NOT NULL,                  -- what the attacker does
  why       TEXT NOT NULL,                  -- why it works; no unjustified chains (§10)
  needs     TEXT,                           -- prerequisites
  UNIQUE(chain_id, ord)
);
CREATE TABLE IF NOT EXISTS chain_edge (
  chain_id  INTEGER NOT NULL REFERENCES chain(id) ON DELETE CASCADE,
  from_step INTEGER NOT NULL,
  to_step   INTEGER NOT NULL,
  relation  TEXT NOT NULL,                  -- enables|amplifies|requires|bypasses
  PRIMARY KEY (chain_id, from_step, to_step)
);

-- ---------------------------------------------------------------------------
-- FALSE POSITIVES: training data, not garbage (§17).
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS fp_case (
  id             INTEGER PRIMARY KEY,
  fp_key         TEXT NOT NULL UNIQUE,
  class_id       TEXT REFERENCES bug_class(id),
  hypothesis     TEXT NOT NULL,
  looked_vulnerable_because TEXT,
  test_performed TEXT NOT NULL,
  invalidated_by TEXT NOT NULL,             -- the signal that killed it
  early_signal_missed TEXT,                 -- what should have been checked FIRST
  rejection_rule TEXT NOT NULL,             -- the durable lesson
  skill_updated  TEXT,
  created_at     TEXT NOT NULL
);

-- ---------------------------------------------------------------------------
-- TASKS: the backlog (§20). Project state lives here, not in chat history.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS task (
  id            INTEGER PRIMARY KEY,
  task_key      TEXT NOT NULL UNIQUE,
  objective     TEXT NOT NULL,
  class_id      TEXT REFERENCES bug_class(id),
  priority      INTEGER NOT NULL DEFAULT 5,-- 1 = highest
  status        TEXT NOT NULL DEFAULT 'todo', -- todo|doing|done|blocked|rejected
  assigned_role TEXT,
  depends_on    TEXT,                       -- JSON array of task_keys
  expected_artifact TEXT NOT NULL,
  evidence_req  TEXT,
  result        TEXT,
  follow_up     TEXT,
  created_at    TEXT NOT NULL,
  updated_at    TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS ix_task_status ON task(status, priority);

-- ---------------------------------------------------------------------------
-- CONFLICTS: surfaced, never silently resolved (§14).
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS conflict (
  id          INTEGER PRIMARY KEY,
  class_id    TEXT REFERENCES bug_class(id),
  topic       TEXT NOT NULL,
  claim_a     TEXT NOT NULL,
  claim_b     TEXT NOT NULL,
  item_a      INTEGER REFERENCES item(id),
  item_b      INTEGER REFERENCES item(id),
  status      TEXT NOT NULL DEFAULT 'open', -- open|resolved|dismissed
  resolution  TEXT,
  created_at  TEXT NOT NULL
);

-- ---------------------------------------------------------------------------
-- RUNS: every autonomous cycle is an auditable artifact (§31).
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS run (
  id          INTEGER PRIMARY KEY,
  run_key     TEXT NOT NULL UNIQUE,
  started_at  TEXT NOT NULL,
  finished_at TEXT,
  summary_md  TEXT,
  metrics_json TEXT,
  status      TEXT NOT NULL DEFAULT 'running'
);

-- ---------------------------------------------------------------------------
-- Retrieval: FTS5 over item claims. Rebuilt from canonical tables, never
-- authored — so it can always be regenerated and never drifts.
-- ---------------------------------------------------------------------------
CREATE VIRTUAL TABLE IF NOT EXISTS item_fts USING fts5(
  claim, body, disproof,
  content='item', content_rowid='id',
  tokenize="porter unicode61 remove_diacritics 2"
);

CREATE TRIGGER IF NOT EXISTS item_ai AFTER INSERT ON item BEGIN
  INSERT INTO item_fts(rowid, claim, body, disproof)
  VALUES (new.id, new.claim, coalesce(new.body,''), coalesce(new.disproof,''));
END;
CREATE TRIGGER IF NOT EXISTS item_ad AFTER DELETE ON item BEGIN
  INSERT INTO item_fts(item_fts, rowid, claim, body, disproof)
  VALUES ('delete', old.id, old.claim, coalesce(old.body,''), coalesce(old.disproof,''));
END;
CREATE TRIGGER IF NOT EXISTS item_au AFTER UPDATE ON item BEGIN
  INSERT INTO item_fts(item_fts, rowid, claim, body, disproof)
  VALUES ('delete', old.id, old.claim, coalesce(old.body,''), coalesce(old.disproof,''));
  INSERT INTO item_fts(rowid, claim, body, disproof)
  VALUES (new.id, new.claim, coalesce(new.body,''), coalesce(new.disproof,''));
END;

-- ---------------------------------------------------------------------------
-- PROJECTION MANIFEST: tracks generated Markdown projections of the corpus.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS projection_manifest (
  class_id          TEXT NOT NULL REFERENCES bug_class(id) ON DELETE CASCADE,
  artifact_type     TEXT NOT NULL,
  relative_path     TEXT NOT NULL,
  source_digest     TEXT,
  content_sha256    TEXT,
  generator_version TEXT,
  generated_at      TEXT NOT NULL,
  PRIMARY KEY (class_id, artifact_type)
);
CREATE INDEX IF NOT EXISTS ix_projection_manifest_type ON projection_manifest(artifact_type);

-- -------------------------------------------------------------------
-- PHASE 6: knowledge deduplication & conflict-safe consolidation.
-- Additive only. Original records are never deleted.
-- -------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS dedup_fingerprint (
  id            INTEGER PRIMARY KEY,
  item_id       INTEGER REFERENCES item(id) ON DELETE CASCADE,
  class_id      TEXT REFERENCES bug_class(id) ON DELETE SET NULL,
  fingerprint   TEXT NOT NULL,
  normalized    TEXT NOT NULL,
  polarity      INTEGER NOT NULL DEFAULT 0,
  scope         TEXT,
  version       TEXT,
  preconditions TEXT,
  created_at    TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS ix_dedup_fp_item ON dedup_fingerprint(item_id);
CREATE INDEX IF NOT EXISTS ix_dedup_fp_fp ON dedup_fingerprint(fingerprint);

CREATE TABLE IF NOT EXISTS canonical_group (
  id                 INTEGER PRIMARY KEY,
  group_key          TEXT NOT NULL UNIQUE,
  canonical_item_id  INTEGER REFERENCES item(id) ON DELETE SET NULL,
  status             TEXT NOT NULL DEFAULT 'PENDING_REVIEW',
  created_at         TEXT NOT NULL,
  updated_at         TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS item_group (
  item_id   INTEGER NOT NULL REFERENCES item(id) ON DELETE CASCADE,
  group_id  INTEGER NOT NULL REFERENCES canonical_group(id) ON DELETE CASCADE,
  role      TEXT NOT NULL DEFAULT 'member',
  PRIMARY KEY (item_id, group_id)
);
CREATE INDEX IF NOT EXISTS ix_item_group_group ON item_group(group_id);

CREATE TABLE IF NOT EXISTS merge_proposal (
  id            INTEGER PRIMARY KEY,
  proposal_key  TEXT NOT NULL UNIQUE,
  group_id      INTEGER REFERENCES canonical_group(id) ON DELETE SET NULL,
  item_ids      TEXT NOT NULL,
  relationship  TEXT NOT NULL,
  status        TEXT NOT NULL DEFAULT 'PENDING_REVIEW',
  mode          TEXT NOT NULL DEFAULT 'PROPOSE',
  rationale     TEXT,
  reviewer      TEXT,
  created_at    TEXT NOT NULL,
  reviewed_at   TEXT,
  applied_at    TEXT
);
CREATE INDEX IF NOT EXISTS ix_merge_proposal_status ON merge_proposal(status);

CREATE TABLE IF NOT EXISTS routing_decision (
  id             INTEGER PRIMARY KEY,
  decision_key   TEXT NOT NULL UNIQUE,
  candidate_id   TEXT,
  candidate_hash TEXT NOT NULL,
  status         TEXT NOT NULL DEFAULT 'PRELIMINARY',
  routing_status TEXT NOT NULL DEFAULT 'UNROUTED',
  update_kind    TEXT NOT NULL DEFAULT 'UNROUTED',
  confidence     REAL NOT NULL DEFAULT 0.0,
  reasons        TEXT NOT NULL DEFAULT '[]',
  alternatives   TEXT NOT NULL DEFAULT '[]',
  ai_advisory    TEXT,
  before_hash    TEXT,
  after_hash     TEXT,
  created_at     TEXT NOT NULL,
  finalized_at   TEXT
);
CREATE INDEX IF NOT EXISTS ix_routing_decision_candidate ON routing_decision(candidate_hash);
CREATE INDEX IF NOT EXISTS ix_routing_decision_status ON routing_decision(status);

CREATE TABLE IF NOT EXISTS route (
  id               INTEGER PRIMARY KEY,
  route_key        TEXT NOT NULL UNIQUE,
  decision_id      INTEGER NOT NULL REFERENCES routing_decision(id) ON DELETE CASCADE,
  update_kind      TEXT NOT NULL,
  target_type      TEXT,
  target_id        TEXT,
  label            TEXT,
  execution_status TEXT NOT NULL DEFAULT 'NOT_STARTED',
  result           TEXT,
  created_at       TEXT NOT NULL,
  updated_at       TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS ix_route_decision ON route(decision_id);
CREATE INDEX IF NOT EXISTS ix_route_exec ON route(execution_status);
