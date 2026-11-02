"""Inspect a sandbox hunt db: what did the engine actually do?

C5 attempt 1 timed out at 300s. A timeout is not a verdict — this reads the rows
the run left behind to establish whether the hunt STARTED (the criterion) and
what it was doing when it stalled, rather than guessing.

Column names are read from PRAGMA rather than assumed: MEASURED, `event` keys on
`kind` (not `event_type`) and the ledger table is `scope_observation` (not
`scope_asset`), so a guessed name raises OperationalError instead of reporting.
"""
import os
import sqlite3
import sys

sb = sys.argv[1]
con = sqlite3.connect(os.path.join(sb, "db", "wks.db"))
con.row_factory = sqlite3.Row

print("=== hunt rows ===")
for r in con.execute("SELECT hunt_id, state, cycles, started_at FROM hunt "
                     "ORDER BY started_at DESC LIMIT 5"):
    print(f"  {r['hunt_id']:28} state={r['state']:22} cycles={r['cycles']}")

print()
print("=== hunt_transition (the state machine, in order) ===")
for r in con.execute("SELECT from_state, to_state, reason FROM hunt_transition "
                     "ORDER BY id"):
    print(f"  {r['from_state']:20} -> {r['to_state']:20} {r['reason'] or ''}")

print()
print("=== events by kind ===")
for r in con.execute("SELECT kind, COUNT(*) c FROM event GROUP BY kind "
                     "ORDER BY c DESC LIMIT 15"):
    print(f"  {r['kind']:28} {r['c']}")

print()
print("=== hunt_observation (the signals the class is derived from) ===")
cols = [c[1] for c in con.execute("PRAGMA table_info(hunt_observation)")]
print(f"  columns: {cols}")
for r in con.execute("SELECT * FROM hunt_observation LIMIT 8"):
    print("   ", {k: (str(v)[:58] if v is not None else None)
                  for k, v in dict(r).items()})

print()
print("=== scope ledger (R32 evidence) ===")
for r in con.execute("SELECT asset, verdict, tested, discovered_by "
                     "FROM scope_observation"):
    print(f"  {r['asset']:26} verdict={r['verdict']:14} tested={r['tested']}")

print()
print("=== tasks the hunt created ===")
n = con.execute("SELECT COUNT(*) c FROM task WHERE task_key LIKE 'hunt.%'"
                ).fetchone()["c"]
print(f"  hunt.* tasks: {n}")
for r in con.execute("SELECT task_key, status FROM task WHERE task_key LIKE "
                     "'hunt.%' ORDER BY task_key LIMIT 15"):
    print(f"    {r['task_key']:54} {r['status']}")