"""RUNTIME OWNERSHIP OF THE SHARED DATABASE.

One file, two schemas, two owners. The contract is:

    wks/   owns the knowledge corpus, its sources, its evidence, its chains,
           and the knowledge-related false-positive records.
    orch/  owns hunts, findings, testing records, and operational hunting
           outcomes.

MEASURED 2026-10-31 (db-layer audit): the separation was enforced ONLY by
`eval/test_isolation.py`, which is a test. There was no runtime code path
that would have stopped an orchestrator from writing `item`, `source`,
`chain_step` or any other knowledge table -- and the two layers DID write
across the boundary:

    * `orch/chains.py` inserted into `chain`, `chain_step` and `chain_edge`
      (all three are knowledge tables, and all three are in the isolation
      test's knowledge set -- so the leak was real, just not on the path
      that test exercised).
    * `orch/validate.py` inserted into `fp_case`, which is a knowledge table
      AND was MISSING from the isolation test's knowledge set, so even a
      detected leak would have passed.

A rule that is only enforced by a test is a convention. This module makes it
a constraint, enforced by SQLite itself.

HOW IT WORKS
------------
SQLite exposes `set_authorizer`, a callback invoked for every statement
before it runs. The callback can DENY a statement by returning
`SQLITE_DENY`, and the statement then fails with "not authorized". This is
enforced by the database engine, not by a Python check that a caller could
route around.

The rule enforced here is deliberately about WRITES, not reads. Both layers
read the whole database -- the orchestrator must be able to read the corpus
to decide what to hunt, and the knowledge engine must be able to read the
hunting state to learn from it. What must not happen is one layer MUTATING
the other's tables.

WHAT IS ENFORCED
----------------
    * A `WKS` connection may write knowledge tables and may NOT write
      orchestration tables.
    * An `ORCH` connection may write orchestration tables and may NOT write
      knowledge tables.

WHY IT IS NOT ON BY DEFAULT
----------------------------
Because the migration and seed paths legitimately write across the boundary
(`orch.executor.do_maintenance` calls `wks_ingest.ingest_file`, and
`orch.chains` builds chains that are knowledge). Those are exactly the
crossings that must be ROUTED THROUGH THE OWNER rather than performed
directly, and the enforcement is what makes that routing mandatory.

Callers opt in with `install_authorizer(con, OWNER)`. A connection with no
authorizer installed is unrestricted, and `ownership_status(con)` reports
that plainly rather than letting an unverified connection look protected.
"""
from __future__ import annotations

import sqlite3
from typing import Any

# The owner identities.
WKS = "wks"
ORCH = "orch"

# ---------------------------------------------------------------------------
# THE TABLE OWNERSHIP MAP
# ---------------------------------------------------------------------------
# Every table in the canonical database, and the layer allowed to write it.
#
# This is derived from the two schema files, not from a second hand-written
# registry: `wks/schema.sql` owns the knowledge half and `orch/schema.sql`
# owns the orchestration half, and this map must agree with them. A table
# that appears in neither file is listed under `UNKNOWN` and is treated as
# WRITABLE BY NOBODY -- an unmapped table is a routing defect, and refusing
# writes to it surfaces that defect instead of letting it accumulate.

# Tables created by wks/schema.sql.
KNOWLEDGE_TABLES = frozenset({
    # corpus
    "source", "bug_class", "item", "item_source", "quality", "class_domain",
    "projection_manifest",
    # chains
    "chain", "chain_step", "chain_edge",
    # knowledge-related false-positive records
    "fp_case",
    # conflict records -- a knowledge disagreement, owned by the corpus
    "conflict",
    # quarantined records -- retained history that must not count as live.
    # MEASURED 2026-10-31: added when the `quarantine` table was created
    # to hold quality vectors whose item was deleted. An unmapped table is
    # writable by NOBODY (see the note above), so without this the repair
    # that populates it raised "not authorized" -- the ownership boundary
    # working exactly as designed, against a table that had been declared
    # in the schema but never registered with its owner.
    "quarantine",
    # Phase 6 dedup / consolidation
    "dedup_fingerprint", "merge_proposal", "canonical_group", "item_group",
    # Phase 7 routing
    "routing_decision", "route",
    # research runs
    "run",
    # the migration lock -- it guards the shared schema itself, so it
    # belongs to the schema owner rather than to either operational layer
    "migration_lock",
    # learning engine (canonical home is db/wks.db)
    "lesson", "lesson_feedback", "learning_gap", "learning_research",
    "writeup_lesson",
    # FTS5 shadow tables: maintained by the schema's own triggers
    "item_fts", "item_fts_config", "item_fts_data", "item_fts_docsize",
    "item_fts_idx",
})

# Tables created by orch/schema.sql.
ORCHESTRATION_TABLES = frozenset({
    # agents and delegation
    "agent_role", "agent_run", "agent_result", "agent_failure",
    "capability_grant", "tool_attempt",
    # the hunt
    "hunt", "hunt_observation", "hunt_transition", "hypothesis",
    "surface_node", "surface_edge", "weakness_link",
    # The record of which SKILL governed which surface.
    #
    # MEASURED 2026-11-01: added with the hunt-side skill resolution step.
    # The table was declared but NOT registered here, so the very first write
    # raised "not authorized" — the ownership boundary working exactly as
    # designed against a table that had no declared owner. An unmapped table
    # is writable by NOBODY, which is the correct default: it surfaced a
    # real routing defect instead of letting an ownerless table accumulate.
    "hunt_skill_resolution",
    # findings and their operational record
    "finding", "finding_state", "evidence", "dedup_decision",
    "retest_record", "revalidation_queue", "gate_fingerprint",
    # The APPEND-ONLY transition history, and the promotion gate's rules.
    #
    # MEASURED 2026-11-01: `finding_state` is keyed by finding_key alone
    # and written with INSERT OR REPLACE, so every transition overwrote the
    # previous one and the history of how a finding reached its current
    # state was lost. `finding_transition` is the append-only history.
    # `promotion_requirement` holds the per-state evidence gate: a legal
    # transition that cites no evidence is refused.
    #
    # As with `hunt_skill_resolution` above, an unmapped table is writable
    # by NOBODY, so these had to be registered with their owner or the very
    # first write raises "not authorized".
    "finding_transition", "promotion_requirement",
    # Which lesson a finding taught.
    #
    # MEASURED 2026-11-01: this table was created at RUNTIME by
    # `orch/learning_bridge._link_lesson` and was never registered here, so
    # the runtime authorizer refused every write to it as an unmapped table
    # -- and the refusal was swallowed by a bare `except sqlite3.Error:
    # pass`, so the link was silently lost. It belongs to the ORCHESTRATION
    # side: it records what a hunting outcome taught, which is operational
    # state rather than corpus knowledge.
    "finding_lesson",
    # The PERSISTED AUTHORIZATION behind a PRODUCTION_HUNT origin, and the
    # append-only audit trail for an origin correction.
    #
    # MEASURED 2026-11-02: the origin of a finding was DERIVED and asserted
    # rather than backed, so any caller holding a hunt id could claim
    # production impact. `hunt_authorization` is the receipt: a row naming
    # the hunt, the program, the target and a VALIDATED authorization. A
    # PRODUCTION_HUNT origin requires a matching row, and absence of a row
    # is a deny -- the same rule `scope_grant` already follows.
    #
    # `provenance_correction` is the ONLY sanctioned way to change a
    # record's origin after creation, and it records the old value, the new
    # value, the reason and the corrector.
    #
    # Both are ORCHESTRATION state: they record what a hunt was permitted
    # to do, which is operational history, not corpus knowledge.
    "hunt_authorization", "provenance_correction",
    # scope
    "scope_grant", "scope_observation", "target_change",
    # events
    "event",
    # execution
    "checkpoint", "worker_heartbeat", "recovery_attempt", "omh_loop",
    "ab_experiment", "ab_result", "unknown_behaviour",
    # The task DAG.
    #
    # MEASURED 2026-10-31: `task` and `task_dep` are DECLARED in
    # `wks/schema.sql`, but they are the ORCHESTRATION DAG -- `orch.store`
    # owns their state vocabulary, `orch.dag` owns the edges, and the
    # orchestrator writes them on every cycle. Classifying them as
    # knowledge made the runtime authorizer refuse every orchestrator
    # write to them, and `eval/test_isolation.py` correctly reported the
    # leak.
    #
    # The declaration in `wks/schema.sql` is historical: the base schema
    # is applied before the orchestration schema so a fresh
    # orchestration-only database is legal. The OPERATIONAL owner is what
    # the boundary enforces.
    "task", "task_dep",
    # The COLLECTION layer's own operational state: the measured WAF/CDN
    # status of a target, and the deferrals a collection role recorded.
    #
    # MEASURED 2026-11-01: these two tables were declared in NEITHER set,
    # so they were OWNERLESS -- and an ownerless table is writable by
    # NOBODY. Every write to them was refused with "not authorized" the
    # moment the ownership authorizer was installed by default. The
    # collection feature was broken at runtime while
    # `eval/test_collection_dispatch.py` reported PASS, because that test
    # builds its sandbox with a bare `sqlite3.connect` and so never
    # exercised the authorizer at all. That is the project's own I33 lesson
    # recurring: a green suite that never opens the real connection.
    #
    # They are ORCHESTRATION state: they record what a collection role
    # measured and decided during a hunt, not corpus knowledge. The same
    # reasoning that places `task`/`task_dep` on the orchestration side
    # applies here.
    "collection_waf_status", "collection_deferral",
    # The CAPABILITY lifecycle: where each capability sits in the
    # Proposed -> Validated -> Active -> Deprecated machine, and the
    # append-only history of how it got there.
    #
    # MEASURED 2026-11-02: declared here on the ORCHESTRATION side because
    # this is operational state about the runtime's own capabilities, not
    # corpus knowledge. It is deliberately SEPARATE from the finding tables
    # (`finding_state`, `finding_transition`): a capability's trust level and
    # a finding's validity are different questions, and sharing tables for
    # them would let one be read as the other. Unmapped tables are writable
    # by NOBODY, so these had to be registered before the first write.
    "capability_lifecycle", "capability_lifecycle_transition",
    # The record of a capability RUN: which capability ran, under which
    # authorization context, against which target, and what it produced.
    # This is the handoff record the coordinator reads, and it is what makes
    # "which capability governed this test" auditable for capabilities the
    # way `hunt_skill_resolution` already makes it for skills.
    "capability_run",
})

# A table in neither set. Writes are refused: an unmapped table has no owner,
# and an ownerless table is how a second source of truth starts.
UNMAPPED_TABLES = frozenset() - KNOWLEDGE_TABLES - ORCHESTRATION_TABLES

# The FTS5 shadow tables are written by TRIGGERS, which run with the
# privileges of the connection that made the change. A trigger firing on a
# delete from `item` writes `item_fts_data`, and the authorizer sees it.
# Those writes are the SCHEMA's own bookkeeping for a table the current owner
# is allowed to write, so they must be permitted -- otherwise deleting an
# item would fail with "not authorized", which is a bug, not a guard.
_TRIGGER_SHADOW = frozenset({
    "item_fts", "item_fts_config", "item_fts_data", "item_fts_docsize",
    "item_fts_idx",
})


class OwnershipViolation(RuntimeError):
    """A statement tried to write a table the connection does not own."""


def owner_of(table: str) -> str | None:
    """The layer that owns `table`, or None if no layer does."""
    t = table.lower()
    if t in KNOWLEDGE_TABLES:
        return WKS
    if t in ORCHESTRATION_TABLES:
        return ORCH
    return None


def writable_tables(owner: str) -> frozenset[str]:
    """Every table `owner` may write."""
    if owner == WKS:
        return KNOWLEDGE_TABLES
    if owner == ORCH:
        return ORCHESTRATION_TABLES
    raise ValueError(f"unknown owner: {owner!r}")


def _authorizer(owner: str):
    """Build the `set_authorizer` callback for `owner`.

    The callback receives (action, arg1, arg2, db_name, trigger_name).

    THE ACTION MAP, measured rather than assumed (MEASURED 2026-10-31 by
    instrumenting `set_authorizer` against a scratch database):

        action 18 (SQLITE_INSERT)  arg1 = the table INSERTed into. ALSO
                                    fires with arg1='sqlite_master' for
                                    CREATE TABLE / CREATE INDEX, because
                                    DDL is an insert into the catalog.
        action 23 (SQLITE_UPDATE)  arg1 = the table, arg2 = the column.
                                    Also fires with arg1='sqlite_master'
                                    when the catalog is read back.
        action  9 (SQLITE_DELETE)  arg1 = the table DELETed from. Also
                                    fires for the implicit rowid handling
                                    of an UPDATE, with the same arg1.
        action  2 (SQLITE_CREATE_TABLE) arg1 = the NEW table's name.
        action  1 (SQLITE_CREATE_INDEX)  arg1 = index name, arg2 = table.

    A first implementation policed actions 18/23/9 naively and therefore
    DENIED every `CREATE TABLE`, because DDL is an insert into
    `sqlite_master` -- and `sqlite_master` belongs to neither layer. The
    rule is therefore: CATALOG ACCESS AND DDL ARE ALWAYS ALLOWED, and
    ownership is enforced on DATA writes to named tables.

    The FTS5 shadow tables are reached through triggers on `item`, and a
    trigger's write runs with the privileges of the connection that made
    the change. Those writes are the schema's own bookkeeping for a
    permitted change, so they are permitted too -- otherwise deleting an
    item would fail with "not authorized", which is a bug, not a guard.
    """
    allowed = writable_tables(owner)

    def _check(action: int, arg1: Any, arg2: Any, db_name: Any,
               trigger_name: Any) -> int:
        # --- DDL and catalog access are ALWAYS allowed ---------------------
        # `CREATE TABLE` fires SQLITE_CREATE_TABLE(2) with the new table's
        # name; `DROP TABLE` fires SQLITE_DROP_TABLE(11) with the dropped
        # table's name AND SQLITE_DELETE(9) with the same name, because the
        # catalog row is deleted. `CREATE INDEX` fires
        # SQLITE_CREATE_INDEX(1).
        #
        # The DDL ACTIONS are matched FIRST and returned OK. Without this,
        # `DROP TABLE t` was refused: the accompanying SQLITE_DELETE(9)
        # carries the table name, and the name was not in the allowed set.
        # A guard that cannot drop a table it created is not a guard, it is
        # a trap.
        if action in (sqlite3.SQLITE_CREATE_TABLE,
                      sqlite3.SQLITE_CREATE_INDEX,
                      sqlite3.SQLITE_CREATE_TRIGGER,
                      sqlite3.SQLITE_CREATE_VIEW,
                      sqlite3.SQLITE_DROP_TABLE,
                      sqlite3.SQLITE_DROP_INDEX,
                      sqlite3.SQLITE_DROP_TRIGGER,
                      sqlite3.SQLITE_DROP_VIEW,
                      sqlite3.SQLITE_ALTER_TABLE):
            return sqlite3.SQLITE_OK

        if action in (sqlite3.SQLITE_INSERT, sqlite3.SQLITE_UPDATE,
                      sqlite3.SQLITE_DELETE):
            table = arg1 if isinstance(arg1, str) else ""
            t = table.lower()
            # The CATALOG is not a table either layer owns. DDL and catalog
            # reads pass through; the row writes they perform on named
            # tables are policed below.
            if t in ("sqlite_master", "sqlite_temp_master", "sqlite_schema"):
                return sqlite3.SQLITE_OK
            if t in _TRIGGER_SHADOW:
                return sqlite3.SQLITE_OK
            if t in allowed:
                return sqlite3.SQLITE_OK
            # A named table this connection does not own, or a table no
            # layer owns: refuse. An unmapped table has no owner, and
            # permitting writes to it is how a competing source of truth
            # appears.
            return sqlite3.SQLITE_DENY
        return sqlite3.SQLITE_OK

    return _check


def install_authorizer(con: sqlite3.Connection, owner: str) -> None:
    """Restrict `con` to writing the tables `owner` owns.

    Raises ValueError for an unknown owner. After this call, a statement that
    writes another layer's table fails with "not authorized" -- enforced by
    SQLite, not by a Python check. Prefer `restrict`, which also records the
    restriction so `ownership_status` can report it.
    """
    if owner not in (WKS, ORCH):
        raise ValueError(f"unknown owner: {owner!r}")
    _record(con, owner)


def remove_authorizer(con: sqlite3.Connection) -> None:
    """Remove the restriction. Used by migration paths that must write both
    halves, and by tests that need to set up state either owner cannot."""
    con.set_authorizer(None)


def ownership_status(con: sqlite3.Connection) -> dict[str, Any]:
    """Report what this connection is permitted to write.

    A connection with no authorizer installed is UNRESTRICTED, and that is
    reported as such. A caller that believes it is protected but is not is
    worse than one that knows it is not.
    """
    try:
        con.execute("SELECT count(*) FROM sqlite_master").fetchone()
    except sqlite3.DatabaseError as e:
        return {"installed": None, "reason": str(e)}
    # sqlite3 does not expose "is an authorizer installed", so the status is
    # derived from a probe: the authorizer is what makes a write to a table
    # the caller does not own fail. Rather than writing to detect it, the
    # status is read from the module's own bookkeeping.
    return {"installed": _INSTALLED.get(id(con)),
            "note": ("tracked by wks.ownership; an untracked connection is "
                     "unrestricted")}


# Which owner each connection was restricted to, keyed by connection identity.
# The authorizer itself cannot be introspected through the sqlite3 API, so
# the status is recorded here rather than guessed.
_INSTALLED: dict[int, str] = {}


def _record(con: sqlite3.Connection, owner: str) -> None:
    _INSTALLED[id(con)] = owner
    con.set_authorizer(_authorizer(owner))


def restrict(con: sqlite3.Connection, owner: str) -> None:
    """Restrict `con` to `owner`'s tables and RECORD that it happened.

    Use this rather than `install_authorizer` so `ownership_status` can
    report the truth.
    """
    if owner not in (WKS, ORCH):
        raise ValueError(f"unknown owner: {owner!r}")
    _record(con, owner)


def unrestrict(con: sqlite3.Connection) -> None:
    """Remove the restriction and forget the record of it."""
    remove_authorizer(con)
    _INSTALLED.pop(id(con), None)


def check_write(con: sqlite3.Connection, table: str) -> bool:
    """Would a write to `table` be permitted on this connection?

    Used by tests and by the self-audit to assert the boundary without
    performing a write.
    """
    owner = _INSTALLED.get(id(con))
    if owner is None:
        return True
    t = table.lower()
    if t in _TRIGGER_SHADOW:
        return True
    return t in writable_tables(owner)


class owner_write:
    """Perform a write AS the owner, on a connection restricted to another.

    THE CROSS-BOUNDARY PATH, MADE EXPLICIT.

    Two layers share one database file. The orchestrator must be able to
    cause a knowledge row to exist (a chain grounded in the corpus, an FP
    rule learned from a rejected finding), and the knowledge engine must be
    able to write orchestration state. Those crossings are real and they
    are legitimate -- what must not happen is an ad-hoc INSERT that no
    owner sanctioned.

    So the owner modules (`wks.store.add_chain`, `wks.store.add_fp`,
    `wks.pipeline.ingest_claim`, ...) write THROUGH this context manager.
    The manager lifts the connection's restriction for the duration of the
    call and restores it afterwards, which means:

      * The write is permitted because the OWNER's code performed it, not
        because the caller had permission.
      * Every other write on that connection is still refused.
      * The crossing is greppable: `owner_write` appears at the call site.

    A raw `INSERT INTO item ...` written by orch code is still refused,
    which is the property that matters.
    """

    def __init__(self, con: sqlite3.Connection, owner: str):
        self.con = con
        self.owner = owner
        self._previous: str | None = None

    def __enter__(self) -> sqlite3.Connection:
        self._previous = _INSTALLED.get(id(self.con))
        # An unrestricted connection stays unrestricted; there is nothing to
        # lift.
        if self._previous is not None:
            _INSTALLED.pop(id(self.con), None)
            self.con.set_authorizer(None)
        return self.con

    def __exit__(self, exc_type, exc, tb) -> bool:
        if self._previous is not None:
            _INSTALLED[id(self.con)] = self._previous
            self.con.set_authorizer(_authorizer(self._previous))
        return False


def as_owner(owner: str):
    """Decorator: the wrapped function writes AS `owner`.

    Every public WRITE function in `wks.store` is decorated with
    `@as_owner(WKS)`. The decorator lifts the connection's restriction for
    the duration of the call and restores it afterwards.

    This is what makes the ownership boundary a REAL boundary rather than a
    naming convention:

      * The orchestrator's connection still refuses `INSERT INTO item ...`
        written by orch code.
      * But `wks.store.add_item(con, ...)` succeeds on that same
        connection, because the KNOWLEDGE OWNER's code performed it.

    The distinction that matters is not "which module called sqlite3" but
    "which layer sanctioned the row". An unsanctioned insert is refused; a
    sanctioned one is performed and is greppable at its call site.
    """
    import functools

    def deco(fn):
        @functools.wraps(fn)
        def wrapper(*args, **kwargs):
            con = _connection_arg(args, kwargs)
            if con is None:
                return fn(*args, **kwargs)
            with owner_write(con, owner):
                return fn(*args, **kwargs)
        wrapper.__wks_owner__ = owner
        return wrapper
    return deco


def _connection_arg(args: tuple, kwargs: dict):
    """Find the sqlite3.Connection in a call's arguments."""
    if "con" in kwargs:
        c = kwargs["con"]
        return c if isinstance(c, sqlite3.Connection) else None
    for a in args:
        if isinstance(a, sqlite3.Connection):
            return a
    return None
