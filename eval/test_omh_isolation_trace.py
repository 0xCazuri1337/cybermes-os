"""Prove the write-isolation claim by TRACING, not by grepping.

The integration's central safety claim is that OMH cannot grant authority. A
text search for `grant_scope` proves only that the string is absent, which a
renamed import, an alias or a `getattr` would defeat.

This test therefore instruments the connection itself: it overrides
`execute`/`executemany`/`executescript`, records every statement with its
bindings, and asserts that the whitelisted write set is respected. Uppercase
is normalised on the TABLE NAME because SQLite reports the table as written
and a mixed-case fixture would otherwise record nothing -- which is how a
tracer passes for the wrong reason.
"""
from __future__ import annotations

import os
import re
import sqlite3
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

PASS = 0
FAIL = 0
FAILURES: list[str] = []


def check(name: str, ok: bool, detail: str = "") -> None:
    global PASS, FAIL
    if ok:
        PASS += 1
        print(f"  [PASS] {name}")
    else:
        FAIL += 1
        FAILURES.append(f"{name}: {detail}")
        print(f"  [FAIL] {name} — {detail}")


# Tables orch/omh.py is permitted to write. Everything else is a violation.
# `omh_loop` is its own orchestration table and holds no knowledge.
ALLOWED = {
    "omh_loop", "agent_result", "agent_failure", "event", "task",
    "task_dep", "hypothesis", "unknown_behaviour", "checkpoint",
}

FORBIDDEN = {
    "scope_grant", "capability_grant", "item", "item_source", "source",
    "quality", "finding", "evidence", "finding_state", "fp_case",
    "conflict", "chain", "chain_step", "agent_run", "retest_record",
}

WRITE_SQL = re.compile(
    r"^\s*(?:INSERT|UPDATE|DELETE|REPLACE)\b", re.IGNORECASE)


class Traced:
    """A connection proxy recording every statement."""

    def __init__(self, con: sqlite3.Connection):
        self._con = con
        self.log: list[tuple[str, str]] = []

    def execute(self, sql, *a, **kw):
        self.log.append((sql, "execute"))
        return self._con.execute(sql, *a, **kw)

    def executemany(self, sql, *a, **kw):
        self.log.append((sql, "executemany"))
        return self._con.executemany(sql, *a, **kw)

    def executescript(self, sql, *a, **kw):
        self.log.append((sql, "executescript"))
        return self._con.executescript(sql, *a, **kw)

    def __getattr__(self, name):
        return getattr(self._con, name)


def table_of(sql: str) -> str | None:
    m = re.search(
        r"(?:INTO|UPDATE|FROM)\s+[\"'`\[]?(\w+)", sql, re.IGNORECASE)
    return m.group(1).lower() if m else None


def main() -> int:
    from orch import executor, hypothesis, omh, store
    from orch import tools as tools_mod

    tmp = Path(tempfile.mkdtemp(prefix="omh_trace_"))
    # `wks.config.root()` resolves WKS_ROOT at CALL time, so pointing it at the
    # sandbox redirects BOTH the database and `research/incoming/`. Without
    # this, `write_research_intake` wrote a probe file into the LIVE corpus
    # tree -- which then sat in the executor's own intake directory looking
    # exactly like real pending research for a class.
    prev_root = os.environ.get("WKS_ROOT")
    os.environ["WKS_ROOT"] = str(tmp)
    try:
        return run(tmp)
    finally:
        if prev_root is None:
            os.environ.pop("WKS_ROOT", None)
        else:
            os.environ["WKS_ROOT"] = prev_root


def run(tmp: Path) -> int:
    from orch import executor, hypothesis, omh, store
    from orch import tools as tools_mod

    real = store.db_path
    store.db_path = lambda: tmp / "trace.db"  # type: ignore[assignment]
    try:
        con = store.open_db(create=True)
    finally:
        store.db_path = real  # type: ignore[assignment]
    con.executescript(tools_mod.SCHEMA)
    con.commit()

    store.add_task(con, "t.research", "research something",
                   class_id=None, status="ready")
    con.commit()

    t = Traced(con)

    # ---- exercise every write path the module owns -----------------------
    store.add_task(con, "t.2", "another", status="ready")
    con.commit()

    omh._ensure_loop(t)
    lk = omh.open_loop(t, mission="trace", objective="o", budget=5)
    omh.record_iteration(t, lk, phase="TEST")
    omh.stop_loop(t, lk, "done")

    ing = omh.ResultIngest(t)
    ing.ingest({"type": "OBSERVATION", "payload": {"x": 1}},
               run_key="r1", task_key="t.research")
    ing.ingest_failure("role", reason="probe")

    engine = hypothesis.HypothesisEngine(t, "hunt")
    h = engine.propose("a sufficiently long falsifiable statement about the "
                       "target behaviour under test here",
                       class_id="idor", disproof="refuted if absent",
                       origin="surface")
    omh.failure_to_learning(t, hyp_key=h, failure_detail="absent")
    omh.write_research_intake("idor", [{
        "item_key": "idor.technique.x", "kind": "technique",
        "claim": "c" * 50, "body": "b", "disproof": "d",
        "sources": [{"url": "https://example.invalid", "quote": "q"}]}])

    # ---- inspect every recorded write ------------------------------------
    writes: list[tuple[str, str]] = []
    for sql, how in t.log:
        for stmt in sql.split(";"):
            if WRITE_SQL.match(stmt.strip()):
                writes.append((stmt.strip(), how))

    check("the tracer actually recorded writes (not a false pass)",
          len(writes) >= 5, f"only {len(writes)} write statements recorded")

    touched = sorted({table_of(s) for s, _ in writes if table_of(s)})
    print(f"  tables written by the OMH paths: {touched}")

    forbidden_hits = sorted(set(touched) & FORBIDDEN)
    check("OMH paths wrote NO authority/knowledge table", not forbidden_hits,
          str(forbidden_hits))

    unknown = sorted(set(touched) - ALLOWED - {"sqlite_sequence"})
    check("every table written is on the allowlist", not unknown, str(unknown))

    # ---- CONTROL: the tracer CAN catch a forbidden write -----------------
    t2 = Traced(con)
    t2.execute("INSERT INTO scope_grant(scope_key, target, kind,"
               " authorization_ref, offensive_allowed, granted_at)"
               " VALUES ('x','evil.test','bug_bounty','r',1,'now')")
    t2.execute("UPDATE scope_grant SET offensive_allowed=1")
    caught = [table_of(s) for s, _ in t2.log
              if table_of(s) == "scope_grant"]
    check("CONTROL: the tracer detects a scope_grant write",
          len(caught) == 2, f"recorded {caught}")
    check("CONTROL: a forbidden write would be flagged by the allowlist",
          bool(set(caught) & FORBIDDEN), str(caught))

    # ---- CONTROL: UPPERCASE is normalised --------------------------------
    t3 = Traced(con)
    t3.execute("DELETE FROM SCOPE_GRANT WHERE scope_key='x'")
    up = [table_of(s) for s, _ in t3.log]
    check("CONTROL: an uppercase table name is still normalised",
          up == ["scope_grant"], str(up))

    # ---- the intake file went to the SANDBOX, not the live tree ----------
    live_root = Path(__file__).resolve().parent.parent
    stray = [p.name for p in (live_root / "research" / "incoming").glob("omh-*")]
    check("no probe intake file was left in the LIVE research/incoming tree",
          not stray, f"stray files: {stray}")

    con.close()
    print(f"\nISOLATION TRACE: {PASS} passed, {FAIL} failed")
    for f in FAILURES:
        print(f"  - {f}")
    return 1 if FAIL else 0


if __name__ == "__main__":
    raise SystemExit(main())