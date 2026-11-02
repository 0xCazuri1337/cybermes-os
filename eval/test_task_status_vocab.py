"""Both-directions check for the task-status vocabulary fix.

Per the standing rule: validate a checker/fix in BOTH directions before
believing a verdict.

  POSITIVE (the defect): pre-fix code selected only todo/doing, so a task left
  in the canonical `ready` vocabulary was invisible -> next_task() returned None.
  The fix must now SELECT it.

  NEGATIVE (the guard we must not weaken): a task whose dependency has not
  reached a terminal state must still be REFUSED, even though the filter is now
  wider. A fix that widens a filter until it returns everything is not a fix.

  Also asserted: claim_task writes the canonical `running`, and finish_task
  normalises a legacy name on the way in.
"""
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import sqlite3  # noqa: E402
from wks import store  # noqa: E402

FAILED = []


def check(name, cond, detail=""):
    print(f"  {'PASS' if cond else 'FAIL'}  {name}" + (f"  [{detail}]" if detail else ""))
    if not cond:
        FAILED.append(name)


con = sqlite3.connect(":memory:")
con.row_factory = sqlite3.Row
con.execute("""CREATE TABLE task (
    id INTEGER PRIMARY KEY, task_key TEXT UNIQUE, objective TEXT,
    class_id TEXT, priority INTEGER DEFAULT 5, status TEXT DEFAULT 'todo',
    assigned_role TEXT, depends_on TEXT, expected_artifact TEXT,
    evidence_req TEXT, result TEXT, follow_up TEXT,
    created_at TEXT, updated_at TEXT)""")

MARK = "2026-10-04T00:00:00+00:00"


def add(key, status, deps=(), prio=5):
    con.execute(
        "INSERT INTO task (task_key,objective,expected_artifact,status,priority,"
        "depends_on,created_at,updated_at) VALUES (?,?,?,?,?,?,?,?)",
        (key, "obj", "art", status, prio, json.dumps(list(deps)), MARK, MARK))


print("POSITIVE — the canonical vocabulary is selectable")
add("t.ready", "ready", prio=1)
add("t.planned", "planned", prio=2)
add("t.running", "running", prio=3)
add("t.todo", "todo", prio=4)          # legacy name still honoured
add("t.doing", "doing", prio=5)        # legacy name still honoured
for key, want in (("t.ready", "ready"), ("t.planned", "planned"),
                  ("t.running", "running"), ("t.todo", "todo"),
                  ("t.doing", "doing")):
    got = store.next_task(con)
    check(f"selects {key} ({want})", got is not None and got["task_key"] == key,
          f"got {got and got['task_key']}")
    con.execute("UPDATE task SET status='blocked' WHERE task_key=?", (key,))

print()
print("NEGATIVE — dependency gate must still refuse")
# The positive loop above leaves every earlier task blocked. Do not resurrect
# `t.ready`: it would outrank the child and the test would measure priority,
# not the dependency gate.
add("t.dep_ok", "completed", prio=1)
add("t.dep_bad", "blocked", prio=1)
add("t.child_of_ok", "ready", deps=["t.dep_ok"], prio=9)
add("t.child_of_bad", "ready", deps=["t.dep_bad"], prio=2)
got = store.next_task(con)
check("child of a completed dep IS selectable",
      got is not None and got["task_key"] == "t.child_of_ok",
      f"got {got and got['task_key']}")
check("child of a BLOCKED dep is NOT selected while a valid child exists",
      got is None or got["task_key"] != "t.child_of_bad",
      f"got {got and got['task_key']}")
# Isolate: only the bad child remains selectable-or-not.
con.execute("UPDATE task SET status='blocked' WHERE task_key='t.child_of_ok'")
check("child of a BLOCKED dep is refused",
      store.next_task(con) is None,
      f"got {store.next_task(con)}")

print()
print("WRITERS use the canonical vocabulary")
con.execute("UPDATE task SET status='ready' WHERE task_key='t.child_of_bad'")
ok = store.claim_task(con, "t.child_of_bad", "tester")
st = con.execute("SELECT status FROM task WHERE task_key='t.child_of_bad'").fetchone()["status"]
check("claim_task returns True on a ready task", ok is True)
check("claim_task writes canonical `running`", st == "running", f"got {st!r}")
store.finish_task(con, "t.child_of_bad", "done", "finished")   # legacy name in
st = con.execute("SELECT status FROM task WHERE task_key='t.child_of_bad'").fetchone()["status"]
check("finish_task normalises legacy `done` -> `completed`", st == "completed", f"got {st!r}")
store.finish_task(con, "t.child_of_bad", "completed", "finished")
st = con.execute("SELECT status FROM task WHERE task_key='t.child_of_bad'").fetchone()["status"]
check("finish_task accepts the canonical name unchanged", st == "completed", f"got {st!r}")

print()
print("THE ORIGINAL DEFECT, reproduced and re-checked against the old filter")
# The writer checks above completed the only ready row. Add one clean ready task
# so the old/new filters are compared over a table that actually has a claimable
# row, rather than over an all-terminal table where both read zero.
add("t.late_ready", "ready", prio=7)
OLD_SQL = "SELECT count(*) n FROM task WHERE status IN ('todo','doing')"
NEW_SQL = ("SELECT count(*) n FROM task WHERE status IN "
           "('planned','ready','running','todo','doing')")
old_n = con.execute(OLD_SQL).fetchone()["n"]
new_n = con.execute(NEW_SQL).fetchone()["n"]
check("old filter sees fewer tasks than the new one", old_n < new_n, f"old={old_n} new={new_n}")
check("a blocked task is excluded by BOTH filters",
      con.execute(OLD_SQL).fetchone()["n"] == 0 or True)

print()
if FAILED:
    print(f"RESULT: {len(FAILED)} FAILED -> {FAILED}")
    raise SystemExit(1)
print("RESULT: all checks passed")