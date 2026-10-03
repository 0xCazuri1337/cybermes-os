"""Prove the wks/orch two-owner split is real (CONTROL layer ownership).

A separation asserted in prose is not a separation. This test instruments
SQLite and records every table written during a full orchestrator workload,
then asserts the knowledge tables never appear in that write set.

Method note: SQLite exposes no per-statement author, so the test cannot
attribute a write to a caller identity. What it CAN do — and what actually
matters — is observe the write set during an orchestration-only workload and
assert no knowledge table appears in it. That is the real property: an
orchestration run must not be able to mutate knowledge, whatever invoked it.

Runs entirely against a disposable copy of the repository.
"""
from __future__ import annotations

import os
import shutil
import sqlite3
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

FAILURES: list[str] = []
PASSES = 0

# Tables owned by the knowledge engine. An orchestration workload must never
# write any of them.
KNOWLEDGE_TABLES = {"item", "quality", "item_source", "source", "run",
                    "chain", "chain_step", "chain_edge", "bug_class",
                    "item_fts", "class_domain"}

ALL_TABLES = KNOWLEDGE_TABLES | {
    "task", "task_dep", "agent_run", "agent_role", "finding", "evidence",
    "event", "checkpoint", "scope_grant", "worker_heartbeat",
    "recovery_attempt", "fp_case", "ab_experiment", "ab_result"}

# The module-level write set the Tracer appends to.
WRITES: list[str] = []


def check(name: str, cond: bool, detail: str = "") -> None:
    global PASSES
    if cond:
        PASSES += 1
        print(f"  [PASS] {name}")
    else:
        FAILURES.append(f"{name}: {detail}")
        print(f"  [FAIL] {name}  {detail}")


def sandbox() -> Path:
    tmp = Path(tempfile.mkdtemp(prefix="orch-isolation-"))
    dest = tmp / "cyber"
    shutil.copytree(ROOT, dest, ignore=shutil.ignore_patterns(
        "quarantine", "*.tar.gz", "__pycache__", "state"))
    return dest


def main() -> int:
    root = sandbox()
    print(f"sandbox: {root}")
    os.environ["WKS_ROOT"] = str(root)
    sys.path.insert(0, str(root))
    for m in [m for m in list(sys.modules) if m.startswith(("wks", "orch"))]:
        del sys.modules[m]

    from orch import (agents, dag, events, orchestrator, priority, selfaudit,
                      store, validate, workers)

    con = sqlite3.connect(str(root / "db" / "wks.db"), factory=sqlite3.Connection)
    con.close()
    # open through the real store, then swap in a traced connection
    plain = store.open_db()
    db_file = plain.execute("PRAGMA database_list").fetchone()[2]
    plain.close()

    # A tracing Connection subclass is not reachable through store.open_db, so
    # build it directly on the same file.
    #
    # It must intercept executescript AND executemany too. An earlier version
    # overrode only execute(), recorded an empty write set, and "passed" the
    # isolation check for the wrong reason — schema creation and bulk work go
    # through the other two methods. The control case (L0) is what caught it.
    def _record(sql) -> None:
        s = " ".join(str(sql).split()).lstrip()
        up = s.upper()
        if not up.startswith(("INSERT", "UPDATE", "DELETE", "REPLACE")):
            return
        # Compare against the UPPERCASED statement, so the table names must be
        # uppercased too. Matching lowercase names against an uppercased
        # statement silently never fires — which is exactly what happened, and
        # exactly what the L0 control case exists to catch: it recorded an
        # empty write set for a workload that demonstrably writes.
        for t in ALL_TABLES:
            T = t.upper()
            if (f"INTO {T} " in up or f"INTO {T}(" in up
                    or f"UPDATE {T} " in up
                    or (up.startswith("DELETE") and f"FROM {T} " in up)):
                WRITES.append(t)
                return

    class Tracer(sqlite3.Connection):
        def execute(self, sql, *a, **kw):
            _record(sql)
            return super().execute(sql, *a, **kw)

        def executemany(self, sql, *a, **kw):
            _record(sql)
            return super().executemany(sql, *a, **kw)

        def executescript(self, sql, *a, **kw):
            # executescript may hold several statements; scan them all.
            for part in str(sql).split(";"):
                _record(part)
            return super().executescript(sql, *a, **kw)

    con = sqlite3.connect(db_file, factory=Tracer)
    con.row_factory = sqlite3.Row
    con.execute("PRAGMA foreign_keys=ON")

    tables_present = {t: bool(con.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?",
        (t,)).fetchone()) for t in KNOWLEDGE_TABLES}
    check("all knowledge tables exist in the sandbox",
          all(tables_present.values()),
          f"missing: {[t for t, v in tables_present.items() if not v]}")

    before = {t: con.execute(f"SELECT count(*) FROM {t}").fetchone()[0]
              for t in KNOWLEDGE_TABLES if tables_present[t]}

    print("\nL0 control: the tracer actually detects writes")
    from wks import store as wstore
    WRITES.clear()
    wstore.upsert_class(con, "__iso_probe__", "Isolation Probe", "web")
    con.commit()
    check("tracer sees a knowledge-table write by wks",
          "bug_class" in WRITES, f"write set={WRITES}")
    con.execute("DELETE FROM bug_class WHERE id='__iso_probe__'")
    con.commit()

    print("\nL1 an orchestration workload writes NO knowledge table")
    # The self-audit is excluded from the workload and checked separately
    # (L1b), because its FUNCTIONAL checks deliberately call the knowledge
    # gate and rebuild the FTS index — re-verifying the engine is its job.
    # Folding it in here would make a correct audit look like a leak.
    WRITES.clear()
    orchestrator.decompose(con, "learn xss", prefix="iso")
    dag.break_cycles(con)
    dag.refresh_readiness(con)
    priority.rank(con)
    priority.reorder_tasks(con)
    store.orphan_recovery(con)

    def executor(row, ctx):
        return {"ok": True, "summary": f"isolation probe {row['task_key']}"}

    orchestrator.run(con, executor=executor, max_tasks=8,
                     checkpoint_label="iso")
    workers.run_all(con, ["maintenance", "research", "validation", "watcher"])
    validate.dedupe(con)
    events.ingest(con, [{"event_key": "iso.cve1", "kind": "cve",
                         "source": "nvd", "title": "CVE-2026-9999 xss",
                         "needs_action": "research"}])
    orchestrator.triage_events(con)
    agents.build_role(con, "iso-role", "validation", toolsets=["validation"],
                      capabilities=["READ"])

    observed = sorted(set(WRITES))
    leaked = sorted(set(observed) & KNOWLEDGE_TABLES)
    check("no knowledge table written during orchestration",
          not leaked, f"LEAKED: {leaked}")
    check("the orchestrator really did write its own tables",
          bool(set(observed) - KNOWLEDGE_TABLES),
          f"write set was empty — the test proves nothing: {observed}")
    print(f"      write set: {observed}")

    print("\nL1b the self-audit MAY re-verify the engine (and does)")
    WRITES.clear()
    selfaudit.audit(con)
    audit_writes = sorted(set(WRITES))
    audit_knowledge = sorted(set(audit_writes) & KNOWLEDGE_TABLES)
    check("the audit actually exercised the knowledge engine",
          bool(audit_knowledge),
          "audit wrote no knowledge table — its functional checks may be "
          "dead code that never runs")
    allowed = {"quality", "item_fts", "item_fts_data", "item_fts_idx",
               "item_fts_docsize", "item_fts_config"}
    unexpected = [t for t in audit_knowledge if t not in allowed]
    check("the audit touched no knowledge table beyond gate/index rebuild",
          not unexpected, f"unexpected: {unexpected}")
    print(f"      audit write set: {audit_writes}")

    print("\nL2 knowledge row counts are unchanged")
    after = {t: con.execute(f"SELECT count(*) FROM {t}").fetchone()[0]
             for t in before}
    drift = {k: (before[k], after[k]) for k in before if before[k] != after[k]}
    check("all knowledge row counts identical", not drift, str(drift))

    print("\nL3 the knowledge gate is untouched and still authoritative")
    from wks import quality
    counts = quality.assess_all(con)
    check("gate re-assessment ran over the corpus",
          sum(counts.values()) > 100, str(counts))

    print("\nL4 the self-audit is healthy in the sandbox")
    r = selfaudit.audit(con)
    check("audit healthy", r["health"] == "healthy",
          f"{r['failed']} failure(s): {[f['name'] for f in r['failures']]}")

    con.close()
    shutil.rmtree(root.parent, ignore_errors=True)

    print()
    if FAILURES:
        print(f"ISOLATION: {PASSES} passed, {len(FAILURES)} FAILED")
        for f in FAILURES:
            print(f"  - {f}")
        return 1
    print(f"ISOLATION: ALL {PASSES} CHECKS PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())