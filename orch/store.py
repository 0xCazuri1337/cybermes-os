"""Orchestration store. Owns orch/schema.sql inside the SAME database file as
the knowledge engine, but through its own connection discipline.

Why one file and not a second db: a resumed run must reconstruct work and
knowledge together. Two files mean two WALs, two failure modes, and a
cross-file consistency problem for a system whose whole purpose is surviving a
crash mid-run. One file, two schemas, one transaction boundary.

The wks tables are never written here. `migrate_tasks` migrates ONCE and is
idempotent; after that this module is read/write only on its own tables.
"""
from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from wks import config as wks_config

SCHEMA_PATH = Path(__file__).resolve().parent / "schema.sql"

# Spec §6: the full task state vocabulary. The legacy `task.status` column held
# todo|doing|done|blocked|rejected; the spec asks for a richer set, so status is
# migrated rather than reimplemented in a second table.
TASK_STATES = (
    "planned",    # created, dependencies unknown or unmet
    "ready",      # all deps satisfied — claimable
    "running",
    "blocked",    # failed after exhausting recovery, or waiting on an external fact
    "completed",
    "failed",     # failed, recovery budget not yet spent
    "retrying",
    "superseded",
    "archived",
)

# Capability ladder (spec §35). Ordered least to most privileged. A role must
# both DECLARE a level and hold a matching capability_grant before it may act
# at that level; see agents.authorize_target.
CAPABILITY_LEVELS = ("READ", "ANALYZE", "WRITE", "EXECUTE", "DESTRUCTIVE")

# States that mean "no longer needs attention".
TERMINAL_STATES = {"completed", "superseded", "archived"}


def now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def db_path() -> Path:
    return wks_config.db_path()


def open_db(create: bool = True) -> sqlite3.Connection:
    """Open the shared database with the orchestration schema applied.

    `create=False` is for tests that must prove a clean slate: it refuses to
    make a missing database, so a test cannot pass against a stray file.
    """
    p = db_path()
    if not p.exists() and not create:
        raise FileNotFoundError(f"database absent: {p}")
    con = sqlite3.connect(p, timeout=30)
    con.row_factory = sqlite3.Row
    con.execute("PRAGMA journal_mode=WAL")
    con.execute("PRAGMA foreign_keys=ON")
    # A crashed overnight run must not leave the orchestrator unable to start.
    con.execute("PRAGMA busy_timeout=30000")

    # The orchestrator reuses wks's `task` table rather than shadowing it, so
    # the base schema must exist first. Applying it is idempotent (every
    # statement is CREATE ... IF NOT EXISTS), which is what makes a fresh
    # orchestration-only database legal — the test suite depends on that, and
    # a sandboxed run with no corpus must still be able to schedule work.
    base = wks_config.SCHEMA_PATH
    if base.exists():
        con.executescript(base.read_text(encoding="utf-8"))
    con.executescript(SCHEMA_PATH.read_text(encoding="utf-8"))
    con.commit()
    return con


def migrate_tasks(con: sqlite3.Connection) -> dict[str, int]:
    """Widen the knowledge engine's `task` vocabulary and populate `task_dep`.

    Idempotent: safe to run on every open. Returns what it changed so the
    self-audit can report "migrated 33 rows" instead of asserting a migration
    happened somewhere in the past.
    """
    before = {r["status"]: r["n"] for r in con.execute(
        "SELECT status, count(*) n FROM task GROUP BY status")}

    # legacy -> spec vocabulary
    mapping = {"todo": "planned", "doing": "running", "done": "completed",
               "blocked": "blocked", "rejected": "superseded"}
    for old, new in mapping.items():
        con.execute("UPDATE task SET status=? WHERE status=?", (new, old))

    # depends_on was a JSON blob; explode it into real edges.
    rows = con.execute(
        "SELECT task_key, depends_on FROM task "
        "WHERE depends_on IS NOT NULL AND depends_on != ''").fetchall()
    edges = 0
    for r in rows:
        try:
            deps = json.loads(r["depends_on"])
        except (ValueError, TypeError):
            # A malformed blob is a data defect, not a crash: record it as a
            # self-dependency-free no-op rather than losing the row.
            continue
        if not isinstance(deps, list):
            continue
        for d in deps:
            d = str(d).strip()
            if not d or d == r["task_key"]:
                continue
            cur = con.execute(
                "INSERT OR IGNORE INTO task_dep(task_key, depends_on) VALUES (?,?)",
                (r["task_key"], d))
            edges += cur.rowcount if cur.rowcount > 0 else 0
    con.commit()
    return {"status_groups_before": len(before), "edges_created": edges}


# ---------------------------------------------------------------------------
# Tasks
# ---------------------------------------------------------------------------

def add_task(con: sqlite3.Connection, task_key: str, objective: str, *,
             priority: int = 5, depends_on: list[str] | None = None,
             expected_artifact: str = "", evidence_req: str = "",
             class_id: str | None = None, status: str = "planned",
             role: str | None = None) -> str:
    now_ = now()
    con.execute(
        "INSERT INTO task(task_key, objective, class_id, priority, status,"
        " assigned_role, depends_on, expected_artifact, evidence_req,"
        " created_at, updated_at)"
        " VALUES (?,?,?,?,?,?,?,?,?,?,?)"
        " ON CONFLICT(task_key) DO UPDATE SET objective=excluded.objective,"
        " expected_artifact=excluded.expected_artifact,"
        " evidence_req=excluded.evidence_req, updated_at=excluded.updated_at",
        (task_key, objective, class_id, priority, status, role,
         json.dumps(depends_on or []), expected_artifact, evidence_req,
         now_, now_))
    for d in (depends_on or []):
        if d and d != task_key:
            con.execute("INSERT OR IGNORE INTO task_dep(task_key, depends_on)"
                        " VALUES (?,?)", (task_key, d))
    con.commit()
    return task_key


def set_deps(con: sqlite3.Connection, task_key: str, depends_on: list[str]) -> None:
    con.execute("DELETE FROM task_dep WHERE task_key=?", (task_key,))
    for d in depends_on:
        if d and d != task_key:
            con.execute("INSERT OR IGNORE INTO task_dep(task_key, depends_on)"
                        " VALUES (?,?)", (task_key, d))
    con.commit()


def set_status(con: sqlite3.Connection, task_key: str, status: str,
               *, result: str | None = None) -> None:
    if status not in TASK_STATES:
        raise ValueError(f"unknown task state {status!r}")
    con.execute("UPDATE task SET status=?, updated_at=?"
                + (", result=?" if result is not None else "")
                + " WHERE task_key=?",
                ((status, now(), result, task_key) if result is not None
                 else (status, now(), task_key)))
    con.commit()


def claim(con: sqlite3.Connection, task_key: str, role: str = "master") -> bool:
    """Claim only from `ready`. A conditional UPDATE is the whole concurrency
    control here — two workers racing for one task produce exactly one winner."""
    cur = con.execute(
        "UPDATE task SET status='running', assigned_role=?, updated_at=?"
        " WHERE task_key=? AND status='ready'",
        (role, now(), task_key))
    con.commit()
    return cur.rowcount == 1


def all_tasks(con: sqlite3.Connection) -> list[sqlite3.Row]:
    return con.execute(
        "SELECT * FROM task ORDER BY priority ASC, created_at ASC").fetchall()


def get_task(con: sqlite3.Connection, task_key: str) -> sqlite3.Row | None:
    return con.execute("SELECT * FROM task WHERE task_key=?",
                       (task_key,)).fetchone()


# ---------------------------------------------------------------------------
# Agents
# ---------------------------------------------------------------------------

def add_role(con: sqlite3.Connection, role_key: str, domain: str, *,
             objective_kind: str | None = None,
             toolsets: list[str] | None = None,
             capabilities: list[str] | None = None,
             max_depth: int = 1, rationale: str = "") -> str:
    con.execute(
        "INSERT INTO agent_role(role_key, domain, objective_kind, toolsets,"
        " capabilities, max_depth, rationale, created_at)"
        " VALUES (?,?,?,?,?,?,?,?)"
        " ON CONFLICT(role_key) DO UPDATE SET domain=excluded.domain,"
        " objective_kind=excluded.objective_kind, toolsets=excluded.toolsets,"
        " capabilities=excluded.capabilities, max_depth=excluded.max_depth,"
        " rationale=excluded.rationale",
        (role_key, domain, objective_kind,
         json.dumps(toolsets or []), json.dumps(capabilities or []),
         max_depth, rationale, now()))
    con.commit()
    return role_key


def start_agent_run(con: sqlite3.Connection, run_key: str, role_key: str,
                    objective: str, *, task_key: str | None = None,
                    parent_run_key: str | None = None,
                    depth: int = 0,
                    input_payload: dict[str, Any] | None = None) -> str:
    con.execute(
        "INSERT INTO agent_run(run_key, role_key, task_key, parent_run_key,"
        " depth, status, objective, input_json, started_at, created_at)"
        " VALUES (?,?,?,?,?,'running',?,?,?,?)"
        " ON CONFLICT(run_key) DO UPDATE SET status='running',"
        " started_at=excluded.started_at",
        (run_key, role_key, task_key, parent_run_key, depth, objective,
         json.dumps(input_payload or {}, default=str), now(), now()))
    con.commit()
    return run_key


def finish_agent_run(con: sqlite3.Connection, run_key: str, status: str, *,
                     output: dict[str, Any] | None = None,
                     artifact_path: str | None = None,
                     error: str | None = None) -> None:
    con.execute(
        "UPDATE agent_run SET status=?, output_json=?, artifact_path=?,"
        " last_error=?, finished_at=? WHERE run_key=?",
        (status, json.dumps(output or {}, default=str), artifact_path,
         error, now(), run_key))
    con.commit()


def bump_attempt(con: sqlite3.Connection, run_key: str) -> int:
    con.execute("UPDATE agent_run SET attempts=attempts+1 WHERE run_key=?",
                (run_key,))
    con.commit()
    row = con.execute("SELECT attempts FROM agent_run WHERE run_key=?",
                      (run_key,)).fetchone()
    return row["attempts"] if row else 0


# ---------------------------------------------------------------------------
# Events
# ---------------------------------------------------------------------------

def emit_event(con: sqlite3.Connection, event_key: str, kind: str, *,
               source: str = "", severity: str = "info",
               payload: dict[str, Any] | None = None,
               relevance: float = 0.0) -> bool:
    """Idempotent by event_key. Returns False when the signal was already seen."""
    cur = con.execute(
        "INSERT OR IGNORE INTO event(event_key, kind, source, severity,"
        " payload_json, relevance, created_at) VALUES (?,?,?,?,?,?,?)",
        (event_key, kind, source, severity,
         json.dumps(payload or {}, default=str), relevance, now()))
    con.commit()
    return cur.rowcount > 0


def open_events(con: sqlite3.Connection, min_relevance: float = 0.0,
                limit: int = 50) -> list[sqlite3.Row]:
    return con.execute(
        "SELECT * FROM event WHERE state='new' AND relevance >= ?"
        " ORDER BY relevance DESC, created_at ASC LIMIT ?",
        (min_relevance, limit)).fetchall()


# ---------------------------------------------------------------------------
# Evidence + findings
# ---------------------------------------------------------------------------

def add_evidence(con: sqlite3.Connection, kind: str, *, task_key: str | None = None,
                 finding_id: int | None = None, target: str | None = None,
                 asset: str | None = None, endpoint: str | None = None,
                 request_raw: str | None = None,
                 response_raw: str | None = None,
                 payload: str | None = None,
                 provenance: str | None = None) -> int:
    import hashlib
    blob = "\n".join(x or "" for x in
                     (request_raw, response_raw, payload, endpoint, asset))
    sha = hashlib.sha256(blob.encode("utf-8")).hexdigest()
    cur = con.execute(
        "INSERT INTO evidence(task_key, finding_id, kind, target, asset,"
        " endpoint, request_raw, response_raw, payload, sha256, provenance,"
        " captured_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
        (task_key, finding_id, kind, target, asset, endpoint, request_raw,
         response_raw, payload, sha, provenance, now()))
    con.commit()
    return int(cur.lastrowid)


def add_finding(con: sqlite3.Connection, finding_key: str, title: str, *,
                target: str | None = None, asset: str | None = None,
                endpoint: str | None = None, class_id: str | None = None,
                hypothesis: str | None = None, severity: str | None = None,
                dedup_group: str | None = None,
                validator_run: str | None = None) -> int:
    con.execute(
        "INSERT INTO finding(finding_key, title, target, asset, endpoint,"
        " class_id, hypothesis, severity, status, dedup_group, validator_run,"
        " created_at, updated_at)"
        " VALUES (?,?,?,?,?,?,?,?,'candidate',?,?,?,?)"
        " ON CONFLICT(finding_key) DO UPDATE SET title=excluded.title,"
        " hypothesis=excluded.hypothesis, updated_at=excluded.updated_at",
        (finding_key, title, target, asset, endpoint, class_id, hypothesis,
         severity, dedup_group, validator_run, now(), now()))
    con.commit()
    row = con.execute("SELECT id FROM finding WHERE finding_key=?",
                      (finding_key,)).fetchone()
    return int(row["id"])


def set_finding_status(con: sqlite3.Connection, finding_key: str, status: str, *,
                       validation: dict[str, Any] | None = None,
                       report_path: str | None = None) -> None:
    con.execute(
        "UPDATE finding SET status=?, validation_json=COALESCE(?, validation_json),"
        " report_path=COALESCE(?, report_path), updated_at=? WHERE finding_key=?",
        (status, json.dumps(validation, default=str) if validation else None,
         report_path, now(), finding_key))
    con.commit()


def findings(con: sqlite3.Connection, status: str | None = None) -> list[sqlite3.Row]:
    if status:
        return con.execute("SELECT * FROM finding WHERE status=? ORDER BY id",
                           (status,)).fetchall()
    return con.execute("SELECT * FROM finding ORDER BY id").fetchall()


# ---------------------------------------------------------------------------
# Scope / capability
# ---------------------------------------------------------------------------

def grant_scope(con: sqlite3.Connection, scope_key: str, target: str, kind: str,
                authorization_ref: str, *, offensive_allowed: bool = False,
                expires_at: str | None = None, notes: str = "") -> str:
    con.execute(
        "INSERT INTO scope_grant(scope_key, target, kind, authorization_ref,"
        " offensive_allowed, granted_at, expires_at, notes)"
        " VALUES (?,?,?,?,?,?,?,?)"
        " ON CONFLICT(scope_key) DO UPDATE SET target=excluded.target,"
        " kind=excluded.kind, authorization_ref=excluded.authorization_ref,"
        " offensive_allowed=excluded.offensive_allowed, notes=excluded.notes",
        (scope_key, target, kind, authorization_ref,
         1 if offensive_allowed else 0, now(), expires_at, notes))
    con.commit()
    return scope_key


def grant_capability(con: sqlite3.Connection, subject: str, level: str, *,
                     granted_by: str, rationale: str = "",
                     expires_at: str | None = None) -> str:
    """Authorise a capability level for a role/run/task.

    Without this the capability system was DECLARATION ONLY: `capability_grant`
    existed in the schema, `build_role` let a role declare DESTRUCTIVE, and
    nothing could ever write the grant the gate required — so the gate would
    have been permanently closed rather than meaningfully enforced.
    """
    lvl = level.upper()
    if lvl not in CAPABILITY_LEVELS:
        raise KeyError(f"unknown capability {level!r}; known: "
                       f"{list(CAPABILITY_LEVELS)}")
    con.execute(
        "INSERT INTO capability_grant(subject, level, granted_by, rationale,"
        " granted_at, expires_at) VALUES (?,?,?,?,?,?)",
        (subject, lvl, granted_by, rationale, now(), expires_at))
    con.commit()
    return f"{subject}:{lvl}"


def check_scope(con: sqlite3.Connection, target: str) -> dict[str, Any]:
    """Deny by default. A public endpoint is not authorization (spec §25).

    The target must be a CONCRETE hostname, matched EXACTLY. An earlier
    version used `LIKE '%' || ? || '%'`, which meant:
      * `check_scope("")` matched every grant (the pattern became '%%'),
      * `check_scope("%")` matched every grant (the % was a wildcard),
      * `check_scope("lab.intern")` matched the granted `lab.internal`.
    An empty or wildcard target returning `authorized=True` is the worst
    possible failure for a gate: it silently authorises whatever the caller
    forgot to name. Reproduced all three.
    """
    if not target or not isinstance(target, str):
        return {"authorized": False, "reason": "no_target",
                "detail": "an empty target cannot be authorized; "
                          "name the specific host"}
    t = target.strip().lower()
    if not t:
        return {"authorized": False, "reason": "no_target",
                "detail": "blank target is not a target"}
    # A LIKE wildcard is not a hostname. Refuse rather than interpret it.
    if any(ch in t for ch in ("%", "_*")) or t in ("%", "*"):
        return {"authorized": False, "reason": "wildcard_target",
                "detail": f"{target!r} contains a wildcard; authorization "
                          "must name one specific host"}

    rows = con.execute(
        "SELECT * FROM scope_grant WHERE lower(trim(target)) = ?", (t,)
    ).fetchall()
    if not rows:
        return {"authorized": False, "reason": "no_scope_grant",
                "detail": f"no authorization record names {target!r}"}
    for r in rows:
        if r["expires_at"] and _expired(r["expires_at"]):
            continue
        return {"authorized": True, "offensive_allowed": bool(r["offensive_allowed"]),
                "kind": r["kind"], "authorization_ref": r["authorization_ref"],
                "scope_key": r["scope_key"]}
    return {"authorized": False, "reason": "scope_expired",
            "detail": f"every grant for {target!r} has expired"}


def _expired(stamp: str) -> bool:
    """Is an `expires_at` stamp in the past?

    Compared as a DATE, not as a string. A malformed value like 'not-a-date'
    must NOT read as "never expires" — that is a fail-open on corrupt data,
    and it silently turns a lapsed authorization into a permanent one.
    """
    s = (stamp or "").strip()
    if not s:
        return False
    try:
        # Accept both a plain date and a full ISO-8601 instant.
        d = datetime.fromisoformat(s.replace("Z", "+00:00"))
    except ValueError:
        try:
            d = datetime.strptime(s[:10], "%Y-%m-%d")
        except ValueError:
            # Unparseable expiry: treat as EXPIRED. Refusing to act on data we
            # cannot interpret is the safe direction for a security gate.
            return True
    if d.tzinfo is None:
        d = d.replace(tzinfo=timezone.utc)
    return d < datetime.now(timezone.utc)


# ---------------------------------------------------------------------------
# Recovery
# ---------------------------------------------------------------------------

def orphan_recovery(con: sqlite3.Connection, *, stale_after_s: int = 900
                    ) -> dict[str, int]:
    """Return tasks stuck in `running` to a workable state.

    A crash between `claim` and `complete` leaves a task claimed by an agent
    run that no longer exists. Left alone it is invisible to `ready_tasks`
    forever: the run looks idle, the task looks busy, and nothing progresses.
    This is the most likely shape of damage after an overnight run dies.

    Liveness therefore CANNOT be inferred from the agent_run row alone. A hard
    kill (`os._exit`, SIGKILL, power loss) leaves `agent_run.status='running'`
    with a heartbeat that will never advance — so a row-based predicate sees a
    "live" agent forever and recovers nothing, which is precisely the stall this
    function exists to prevent. Reproduced: a task hard-killed mid-execution
    stayed `running` across a restart with `orphan_recovery -> 0`.

    So a run counts as live only if it is non-terminal AND its
    `started_at`/`created_at` is recent. An older run is a corpse, not a worker.
    `stale_after_s` is therefore a real correctness parameter, not a tuning
    knob: set it too high and a genuinely slow agent is killed mid-flight, so
    it defaults well above any realistic single task.
    """
    from datetime import datetime, timedelta, timezone

    cutoff = (datetime.now(timezone.utc)
              - timedelta(seconds=stale_after_s)).isoformat(timespec="seconds")
    recovered = killed_runs = 0

    for t in con.execute(
            "SELECT task_key FROM task WHERE status='running'").fetchall():
        live = con.execute(
            "SELECT 1 FROM agent_run WHERE task_key=? AND status IN"
            " ('planned','dispatched','running') AND COALESCE("
            "  started_at, created_at) >= ?",
            (t["task_key"], cutoff)).fetchone()
        if live:
            continue  # a recent, genuinely active agent owns this task

        # Any older run for this task is a corpse from a dead process: close it
        # so the row stops masquerading as live work.
        killed = con.execute(
            "UPDATE agent_run SET status='timeout', finished_at=?,"
            " last_error=COALESCE(last_error,'process died; run marked stale')"
            " WHERE task_key=? AND status IN ('planned','dispatched','running')"
            " AND COALESCE(started_at, created_at) < ?",
            (now(), t["task_key"], cutoff))
        killed_runs += killed.rowcount if killed.rowcount > 0 else 0

        row = con.execute("SELECT result FROM task WHERE task_key=?",
                          (t["task_key"],)).fetchone()
        # A recorded result means the work happened but the crash landed before
        # the completion was written; re-running it would duplicate the work.
        target = "ready" if (row["result"] or "").strip() else "failed"
        con.execute("UPDATE task SET status=?, updated_at=? WHERE task_key=?",
                    (target, now(), t["task_key"]))
        recovered += 1
    con.commit()
    return {"recovered": recovered, "stale_runs_closed": killed_runs,
            "stale_after_s": stale_after_s}


def record_recovery(con: sqlite3.Connection, task_key: str, attempt: int,
                    strategy: str, outcome: str, detail: str = "") -> None:
    con.execute(
        "INSERT OR REPLACE INTO recovery_attempt(task_key, attempt, strategy,"
        " outcome, detail, at) VALUES (?,?,?,?,?,?)",
        (task_key, attempt, strategy, outcome, detail, now()))
    con.commit()


def recovery_count(con: sqlite3.Connection, task_key: str) -> int:
    row = con.execute("SELECT count(*) n FROM recovery_attempt WHERE task_key=?",
                      (task_key,)).fetchone()
    return int(row["n"]) if row else 0


# ---------------------------------------------------------------------------
# Checkpoints
# ---------------------------------------------------------------------------

def save_checkpoint(con: sqlite3.Connection, scope: str, label: str,
                    state: dict[str, Any]) -> None:
    con.execute(
        "INSERT INTO checkpoint(scope, label, state_json, created_at)"
        " VALUES (?,?,?,?) ON CONFLICT(scope, label) DO UPDATE SET"
        " state_json=excluded.state_json, created_at=excluded.created_at",
        (scope, label, json.dumps(state, default=str), now()))
    con.commit()


def load_checkpoint(con: sqlite3.Connection, scope: str,
                    label: str) -> dict[str, Any] | None:
    row = con.execute("SELECT state_json FROM checkpoint WHERE scope=? AND label=?",
                      (scope, label)).fetchone()
    return json.loads(row["state_json"]) if row else None


def latest_checkpoint(con: sqlite3.Connection, scope: str) -> dict[str, Any] | None:
    row = con.execute(
        "SELECT scope, label, state_json, created_at FROM checkpoint"
        " WHERE scope=? ORDER BY created_at DESC LIMIT 1", (scope,)).fetchone()
    if not row:
        return None
    return {"scope": row["scope"], "label": row["label"],
            "created_at": row["created_at"],
            "state": json.loads(row["state_json"])}


# ---------------------------------------------------------------------------
# Workers
# ---------------------------------------------------------------------------

def beat(con: sqlite3.Connection, worker_key: str, kind: str, status: str, *,
         result: str | None = None, bump: bool = False) -> None:
    if bump:
        con.execute(
            "INSERT INTO worker_heartbeat(worker_key, kind, status, cycle,"
            " last_beat, last_result) VALUES (?,?,?,1,?,?)"
            " ON CONFLICT(worker_key) DO UPDATE SET status=excluded.status,"
            " cycle=worker_heartbeat.cycle+1, last_beat=excluded.last_beat,"
            " last_result=excluded.last_result",
            (worker_key, kind, status, now(), result))
    else:
        con.execute(
            "INSERT INTO worker_heartbeat(worker_key, kind, status, cycle,"
            " last_beat, last_result) VALUES (?,?,?,0,?,?)"
            " ON CONFLICT(worker_key) DO UPDATE SET status=excluded.status,"
            " last_beat=excluded.last_beat, last_result=excluded.last_result",
            (worker_key, kind, status, now(), result))
    con.commit()


def workers(con: sqlite3.Connection) -> list[sqlite3.Row]:
    return con.execute(
        "SELECT * FROM worker_heartbeat ORDER BY kind, worker_key").fetchall()


# ---------------------------------------------------------------------------
# A/B experiments
# ---------------------------------------------------------------------------

def add_experiment(con: sqlite3.Connection, exp_key: str, question: str,
                   metric: str, arms: list[str]) -> str:
    con.execute(
        "INSERT OR IGNORE INTO ab_experiment(exp_key, question, metric, arms,"
        " created_at) VALUES (?,?,?,?,?)",
        (exp_key, question, metric, json.dumps(arms), now()))
    con.commit()
    return exp_key


def record_arm(con: sqlite3.Connection, exp_key: str, arm: str, metric: str,
               value: float | None, detail: str = "") -> None:
    con.execute(
        "INSERT OR REPLACE INTO ab_result(exp_key, arm, metric, value, detail,"
        " recorded_at) VALUES (?,?,?,?,?,?)",
        (exp_key, arm, metric, value, detail, now()))
    con.commit()


def decide_experiment(con: sqlite3.Connection, exp_key: str, winner: str | None,
                      verdict: str) -> None:
    con.execute(
        "UPDATE ab_experiment SET status='decided', winner=?, verdict=?,"
        " decided_at=? WHERE exp_key=?", (winner, verdict, now(), exp_key))
    con.commit()


def experiments(con: sqlite3.Connection) -> list[sqlite3.Row]:
    return con.execute("SELECT * FROM ab_experiment ORDER BY created_at DESC"
                       ).fetchall()