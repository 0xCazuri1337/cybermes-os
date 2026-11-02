"""Overnight / unattended loop (brief §21).

    python -m wks.overnight --cycles 6 --sleep 300

Design constraints:
  * Resumable. Every cycle commits its own run record, so an interrupted night
    leaves an auditable trail rather than a half-written state.
  * Breadth-preserving. Task selection is priority-ordered but tracks which
    classes were touched this session, so a long run spreads across classes
    instead of deepening one (§30: "do not spend the entire run researching one
    endlessly expanding topic").
  * Bounded. `--cycles` and `--sleep` mean it terminates. A loop that cannot stop
    is not automation, it is a leak.
  * Honest. A cycle with no runnable task still records why, so "no change" is
    distinguishable from "never ran".
"""
from __future__ import annotations

import argparse
import json
import sqlite3
import sys
import time
import traceback
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from wks import config, cycle as cycler, pipeline, quality, store  # noqa: E402


def select_tasks(con: sqlite3.Connection, touched: set[str], n: int) -> list:
    """Pick runnable tasks, preferring classes not yet worked this session."""
    pending = con.execute(
        "SELECT * FROM task WHERE status IN "
        "('planned','ready','running','todo','doing') "
        "ORDER BY priority, id"
    ).fetchall()
    done = {
        r["task_key"] for r in con.execute(
            "SELECT task_key FROM task WHERE status IN "
            "('completed','done','superseded','archived','rejected')"
        ).fetchall()
    }
    runnable = []
    for r in pending:
        deps = json.loads(r["depends_on"] or "[]")
        if any(d not in done for d in deps):
            continue
        runnable.append(r)

    fresh = [r for r in runnable if r["class_id"] not in touched]
    chosen = (fresh + [r for r in runnable if r["class_id"] in touched])[:n]
    return chosen


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="wks.overnight")
    ap.add_argument("--cycles", type=int, default=4,
                    help="number of cycles to run (bounded)")
    ap.add_argument("--sleep", type=int, default=0,
                    help="seconds between cycles")
    ap.add_argument("--max-tasks", type=int, default=1,
                    help="tasks to select per cycle")
    args = ap.parse_args(argv)

    con = store.open_db(create=True)
    # Make sure the backlog reflects reality before the first selection.
    pipeline.next_tasks(con)

    touched: set[str] = set()
    session_log: list[str] = []
    print(f"WKS overnight start {datetime.now(timezone.utc).isoformat(timespec='seconds')}")
    print(f"cycles={args.cycles} sleep={args.sleep}s\n")

    for i in range(1, args.cycles + 1):
        try:
            tasks = select_tasks(con, touched, args.max_tasks)
            for t in tasks:
                store.claim_task(con, t["task_key"], "overnight")
                touched.add(t["class_id"] or "")
            r = cycler.run_cycle(con)
            session_log.append(r["run_key"])
            m = r["metrics"]
            print(f"--- cycle {i}/{args.cycles} [{r['run_key']}]")
            print(f"    items={m['items_total']} promoted={m['items_promoted']} "
                  f"({m['promotion_rate_pct']}%) "
                  f"unsupported={m['unsupported_claim_rate_pct']}% "
                  f"mature={m['classes_mature']}/{m['classes']} "
                  f"probe={r['probe']['hit_rate_pct']}%")
            for c in r["changed"]:
                print(f"    changed: {c}")
        except Exception:
            # A failing cycle must not kill the night; record and continue.
            err = traceback.format_exc(limit=3)
            session_log.append(f"ERROR cycle {i}")
            print(f"--- cycle {i}/{args.cycles} FAILED\n{err}")
            con.rollback()

        if args.sleep and i < args.cycles:
            time.sleep(args.sleep)

    # Session summary — a persistent artifact, not console output.
    gaps = quality.gap_report(con)
    summary = {
        "finished_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "cycles_requested": args.cycles,
        "runs": session_log,
        "classes_touched": sorted(touched),
        "top_priorities": [
            {"class_id": g["class_id"], "priority": g["priority"],
             "missing": g["missing"]} for g in gaps[:10]
        ],
    }
    out = config.runtime_dir() /  "overnight-last.json"
    out.write_text(json.dumps(summary, indent=2, default=str), encoding="utf-8")
    print(f"\novernight complete — {len(session_log)} cycles")
    print(f"summary: {out}")
    con.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
