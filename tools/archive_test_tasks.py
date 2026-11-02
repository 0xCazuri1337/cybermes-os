#!/usr/bin/env python
"""Archive test/demo/lab task families out of the production DAG.

The task table is the production orchestration queue. It also accumulated
hundreds of rows from lab exercises, proof/demo runs, reachability harnesses
and debug probes. Those rows are useful as an audit trail, but leaving them
READY or PLANNED means the orchestrator can dispatch a demo instead of real
work, and it inflates the failed/ready counts reported by `wks.cli metrics`.

This tool NEVER deletes a task. It marks non-completed test/demo rows
`superseded` and appends a note to `result`, preserving the original result.
Completed rows are left untouched: they are history.

    python tools/archive_test_tasks.py            # dry run
    python tools/archive_test_tasks.py --apply    # persist

Refuses to run if a non-test task depends on a test task: in that case the
dependency graph itself needs a human decision, not a bulk status change.
"""
from __future__ import annotations

import argparse
import sqlite3
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DB = ROOT / "db" / "wks.db"

# Every prefix here names a non-production family:
#   hunt.reach.*  reachability harness (ok/stale/broken variants)
#   hunt.lab.*    lab exercises and lab proof chains
#   hunt.probe.*  debug probes
#   hunt.proof.*  demo/proof runs
#   hunt.dbg.*    debug runs
#   itest.*       orchestrator integration-test rows
PREFIXES = (
    "hunt.reach.%",
    "hunt.lab.%",
    "hunt.probe.%",
    "hunt.proof.%",
    "hunt.dbg.%",
    "itest.%",
)

NOTE = ("Archived by tools/archive_test_tasks.py: this is a test/demo/lab "
        "row, not production work. It is retained for audit only; re-add it "
        "as a new task if it becomes a real objective.")


def _where(col: str) -> tuple[str, list[str]]:
    return ("(" + " OR ".join(f"{col} LIKE ?" for _ in PREFIXES) + ")",
            list(PREFIXES))


def main() -> int:
    ap = argparse.ArgumentParser(prog="archive_test_tasks.py")
    ap.add_argument("--apply", action="store_true",
                    help="persist the archive (default: dry run)")
    args = ap.parse_args()

    con = sqlite3.connect(DB)
    con.row_factory = sqlite3.Row

    task_where, params = _where("task_key")
    dep_where, dep_params = _where("depends_on")

    real_deps = con.execute(
        f"""SELECT count(*) n FROM task_dep
            WHERE {dep_where} AND NOT {task_where}""",
        dep_params + params).fetchone()["n"]
    if real_deps:
        print(f"REFUSING: {real_deps} non-test task(s) depend on test tasks.")
        con.close()
        return 2

    rows = con.execute(
        f"""SELECT task_key, status FROM task
            WHERE {task_where}
              AND status NOT IN ('completed', 'superseded')
            ORDER BY task_key""", params).fetchall()
    print(f"non-completed test/demo tasks: {len(rows)}")
    by_status: dict[str, int] = {}
    for r in rows:
        by_status[r["status"]] = by_status.get(r["status"], 0) + 1
    print("by status:", by_status)
    for r in rows[:12]:
        print(" ", r["task_key"], r["status"])

    if not args.apply:
        print("\ndry run — pass --apply to persist")
        con.close()
        return 0

    con.execute(
        f"""UPDATE task
            SET status='superseded',
                result = CASE
                    WHEN result IS NULL OR trim(result)='' THEN ?
                    ELSE result || char(10) || char(10) || ?
                END,
                follow_up = CASE
                    WHEN follow_up IS NULL OR trim(follow_up)='' THEN ?
                    ELSE follow_up || ' | ' || ?
                END
            WHERE {task_where}
              AND status NOT IN ('completed', 'superseded')""",
        (NOTE, NOTE, NOTE, NOTE) + tuple(params))
    con.commit()
    left = con.execute(
        f"""SELECT count(*) n FROM task
            WHERE {task_where}
              AND status NOT IN ('completed', 'superseded')""",
        params).fetchone()["n"]
    print(f"archived; remaining non-completed test/demo tasks: {left}")
    con.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
