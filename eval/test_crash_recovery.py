"""Crash-recovery regression: a hard-killed run must not stall forever.

This test exists because an independent adversarial validator found the defect
it guards. `os._exit(9)` mid-execution leaves `task.status='running'` AND
`agent_run.status='running'`. The original liveness predicate looked only at
the agent_run row, so it saw a "live" agent and recovered nothing — the task
stayed `running` across a restart, permanently, which is precisely the stall
`orphan_recovery` exists to prevent.

The kill happens in a REAL subprocess: it cannot be simulated with an exception
because an exception unwinds and lets `finally` blocks run, which is precisely
the cleanup a real power loss does not perform.
"""
from __future__ import annotations

import os
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import textwrap
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

FAILURES: list[str] = []
PASSES = 0


def check(name: str, cond: bool, detail: str = "") -> None:
    global PASSES
    if cond:
        PASSES += 1
        print(f"  [PASS] {name}")
    else:
        FAILURES.append(f"{name}: {detail}")
        print(f"  [FAIL] {name}  {detail}")


def sandbox() -> Path:
    tmp = Path(tempfile.mkdtemp(prefix="orch-kill-"))
    dest = tmp / "cyber"
    shutil.copytree(ROOT, dest, ignore=shutil.ignore_patterns(
        "quarantine", "*.tar.gz", "__pycache__", "state"))
    shutil.copy2(ROOT / "db" / "wks.db", dest / "db" / "wks.db")
    return dest


def run_py(root: Path, name: str, body: str) -> subprocess.CompletedProcess:
    f = root / f"{name}.py"
    f.write_text(textwrap.dedent(body), encoding="utf-8")
    return subprocess.run([sys.executable, str(f)], capture_output=True,
                          text=True)


def main() -> int:
    root = sandbox()
    print(f"sandbox: {root}")

    print("\nK1 a hard kill leaves the task and its run stranded")
    p = run_py(root, "kill", f"""
        import os, sys
        sys.path.insert(0, r"{root}")
        os.environ["WKS_ROOT"] = r"{root}"
        from orch import store, dag, orchestrator
        con = store.open_db()
        store.add_task(con, "probeA", "probe A", expected_artifact="a")
        store.add_task(con, "probeB", "probe B", expected_artifact="b")
        con.commit(); dag.refresh_readiness(con)
        only = lambda row: row["task_key"].startswith("probe")
        def ex(row, ctx):
            if row["task_key"] == "probeB":
                os._exit(9)
            return {{"ok": True, "summary": "artifact for " + row["task_key"]}}
        orchestrator.run(con, executor=ex, max_tasks=5,
                         checkpoint_label="kill", task_filter=only)
    """)
    check("the child died with the kill signal", p.returncode == 9,
          f"rc={p.returncode}")

    db = root / "db" / "wks.db"
    con = sqlite3.connect(db)
    con.row_factory = sqlite3.Row
    b = con.execute("SELECT status FROM task WHERE task_key='probeB'"
                    ).fetchone()
    r = con.execute("SELECT status FROM agent_run WHERE task_key='probeB'"
                    ).fetchone()
    check("the killed task is stranded in 'running'", b["status"] == "running",
          str(dict(b)))
    check("its agent_run is also stranded in 'running'",
          r and r["status"] == "running", str(dict(r)) if r else "no run row")
    a = con.execute("SELECT status FROM task WHERE task_key='probeA'"
                    ).fetchone()
    check("the task that finished before the kill is completed",
          a["status"] == "completed", str(dict(a)))
    con.close()

    print("\nK2 a restart recovers the stranded task")
    # stale_after_s must exceed the age of the dead run for it to count as
    # stale. Rather than force stale_after_s=0 (which makes cutoff==now and
    # nothing can be older than "now"), backdate the dead run's timestamps to
    # simulate the passage of time — which is what actually happens between a
    # crash and a restart.
    p2 = run_py(root, "restart", f"""
        import os, sys
        sys.path.insert(0, r"{root}")
        os.environ["WKS_ROOT"] = r"{root}"
        from orch import store, dag, orchestrator
        con = store.open_db()
        # Backdate every non-terminal run by 2 hours: it is a corpse.
        con.execute(
            "UPDATE agent_run SET started_at ="
            " datetime('now', '-2 hours'),"
            " created_at = datetime('now', '-2 hours')"
            " WHERE status IN ('planned','dispatched','running')")
        con.commit()
        rec = store.orphan_recovery(con)          # default 900s staleness
        print("orphan_recovery:", rec)
        dag.refresh_readiness(con)
        print("statuses:", {{x["task_key"]: x["status"] for x in con.execute(
            "SELECT task_key,status FROM task WHERE task_key LIKE 'probe%'")}})
    """)
    out = p2.stdout
    check("recovery ran", "orphan_recovery:" in out, out[:300] + p2.stderr[:300])
    check("the stranded task was recovered", "recovered': 1" in out
          or "recovered\": 1" in out, out[:300])
    check("the dead run was closed as a timeout",
          "stale_runs_closed': 1" in out or "stale_runs_closed\": 1" in out,
          out[:300])
    check("the recovered task is no longer running", "probeB" in out, out[:400])
    # A hard kill lands BEFORE any result was written, so the task carries no
    # evidence of progress. It must go to `failed`, not back to `ready` —
    # re-running work whose completion is unknown would duplicate it. The point
    # of recovery here is that the task is VISIBLE and decidable again, not that
    # it silently resumes.
    check("an unproven crashed task goes to failed, not silently retried",
          "'probeB': 'failed'" in out, out[:400])
    check("recovery made it decidable rather than stalled",
          "'probeB': 'running'" not in out, out[:400])

    print("\nK3 a genuinely live run is NOT stolen")
    p3 = run_py(root, "live", f"""
        import os, sys
        sys.path.insert(0, r"{root}")
        os.environ["WKS_ROOT"] = r"{root}"
        from orch import store, dag
        con = store.open_db()
        store.add_task(con, "liveTask", "still working", expected_artifact="x")
        con.commit(); dag.refresh_readiness(con)
        store.claim(con, "liveTask", "worker")
        store.add_role(con, "worker", "system", toolsets=["validation"],
                       capabilities=["READ"], max_depth=0, rationale="probe")
        store.start_agent_run(con, "run-live", "worker", "working",
                              task_key="liveTask")
        # A just-started run (now) must be treated as LIVE by the default
        # 900-second staleness window. Nothing is backdated here on purpose.
        rec = store.orphan_recovery(con)
        print("recovery:", rec)
        print("task_status:", con.execute(
            "SELECT status FROM task WHERE task_key='liveTask'"
        ).fetchone()["status"])
        print("run_status:", con.execute(
            "SELECT status FROM agent_run WHERE run_key='run-live'"
        ).fetchone()["status"])
    """)
    out3 = p3.stdout
    check("a live agent keeps its task",
          "task_status: running" in out3, out3[:300])
    check("nothing was recovered from a live run",
          "'recovered': 0" in out3, out3[:300])
    check("the live run stays running", "run_status: running" in out3,
          out3[:300])

    print("\nK4 recovery is idempotent")
    p4 = run_py(root, "again", f"""
        import os, sys
        sys.path.insert(0, r"{root}")
        os.environ["WKS_ROOT"] = r"{root}"
        from orch import store
        con = store.open_db()
        a = store.orphan_recovery(con)
        b = store.orphan_recovery(con)
        print("second_recovered:", b["recovered"])
        print("second_closed:", b["stale_runs_closed"])
    """)
    check("a second recovery finds nothing to do",
          "second_recovered: 0" in p4.stdout, p4.stdout[:300])
    check("a second recovery closes no further runs",
          "second_closed: 0" in p4.stdout, p4.stdout[:300])

    shutil.rmtree(root.parent, ignore_errors=True)

    print()
    if FAILURES:
        print(f"CRASH: {PASSES} passed, {len(FAILURES)} FAILED")
        for f in FAILURES:
            print(f"  - {f}")
        return 1
    print(f"CRASH: ALL {PASSES} CHECKS PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())