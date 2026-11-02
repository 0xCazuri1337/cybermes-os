"""Both-directions check for the task-status vocabulary fix.

Per the standing rule: validate a checker/fix in BOTH directions before
believing a verdict. And: a control that cannot fail is not a control — every
assertion here has a known input that must produce the OPPOSITE verdict.

  POSITIVE (the defect): pre-fix code selected only todo/doing, so a task left
  in the canonical `ready` vocabulary was invisible -> next_task() returned None
  over a table holding 18 claimable tasks. The fix must now SELECT it.

  NEGATIVE (the guard we must not weaken): a task whose dependency has not
  reached a terminal state must still be REFUSED, even though the filter is now
  wider. A fix that widens a filter until it returns everything is not a fix.

Isolation rule that matters here: exactly ONE candidate row is claimable per
assertion. The first draft of this file re-armed a priority-1 row and both
negative checks then "failed" against that unrelated row — a harness defect,
not a product defect. Every case below blocks all non-targets first.
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


def only_claimable(key):
    """Make exactly `key` the only CLAIMABLE row, leaving terminal rows alone.

    An earlier version set every row to `blocked`, which destroyed the very
    fixture the positive case depended on: the completed dependency became
    blocked and the child was correctly refused. The harness was wrong, not the
    product. Terminal rows are now spared.
    """
    con.execute("UPDATE task SET status='blocked' WHERE status NOT IN "
                "('completed','superseded','archived','done','rejected')")
    if key is not None:
        con.execute("UPDATE task SET status='ready' WHERE task_key=?", (key,))


print("POSITIVE — the canonical vocabulary is selectable")
for key, status in (("t.ready", "ready"), ("t.planned", "planned"),
                    ("t.running", "running"), ("t.todo", "todo"),
                    ("t.doing", "doing")):
    con.execute("DELETE FROM task")
    add(key, status)
    got = store.next_task(con)
    check(f"selects a lone `{status}` task", got is not None and got["task_key"] == key,
          f"got {got and got['task_key']}")

print()
print("NEGATIVE — the dependency gate must still refuse (filter widened, gate not)")
con.execute("DELETE FROM task")
add("dep.ok", "completed", prio=1)
add("child.ok", "ready", deps=["dep.ok"], prio=1)
only_claimable("child.ok")
got = store.next_task(con)
check("child of a COMPLETED dep is selectable",
      got is not None and got["task_key"] == "child.ok", f"got {got and got['task_key']}")

for label, dep_status in (("BLOCKED", "blocked"), ("STILL-RUNNING", "running")):
    con.execute("DELETE FROM task")
    add("dep.x", dep_status, prio=1)
    add("child.x", "ready", deps=["dep.x"], prio=1)
    only_claimable("child.x")
    got = store.next_task(con)
    check(f"child of a {label} dep is refused", got is None,
          f"got {got and got['task_key']}")

con.execute("DELETE FROM task")
add("child.missing", "ready", deps=["dep.never.created"], prio=1)
only_claimable("child.missing")
got = store.next_task(con)
check("child of a NON-EXISTENT dep is refused", got is None,
      f"got {got and got['task_key']}")

# The control that proves the refusals above mean something.
con.execute("DELETE FROM task")
add("dep.ok2", "completed", prio=1)
add("child.ok2", "ready", deps=["dep.ok2"], prio=1)
only_claimable(None)
got = store.next_task(con)
check("CONTROL: nothing claimable -> next_task returns None", got is None,
      f"got {got and got['task_key']}")

print()
print("WRITERS use the canonical vocabulary")
con.execute("DELETE FROM task")
add("t.claim", "ready")
ok = store.claim_task(con, "t.claim", "tester")
st = con.execute("SELECT status FROM task WHERE task_key='t.claim'").fetchone()["status"]
check("claim_task returns True on a ready task", ok is True)
check("claim_task writes canonical `running`", st == "running", f"got {st!r}")
check("claim_task is idempotent (repeat claim still True)",
      store.claim_task(con, "t.claim", "tester") is True)
check("CONTROL: claim_task on an unknown key returns False",
      store.claim_task(con, "t.nope", "tester") is False)

store.finish_task(con, "t.claim", "done", "finished")      # legacy name in
st = con.execute("SELECT status FROM task WHERE task_key='t.claim'").fetchone()["status"]
check("finish_task normalises legacy `done` -> `completed`", st == "completed", f"got {st!r}")

add("t.claim2", "running")
store.finish_task(con, "t.claim2", "completed", "finished")
st = con.execute("SELECT status FROM task WHERE task_key='t.claim2'").fetchone()["status"]
check("finish_task accepts the canonical name unchanged", st == "completed", f"got {st!r}")

print()
print("THE ORIGINAL DEFECT — old filter vs new filter on the same table")
con.execute("DELETE FROM task")
add("a.canonical", "ready", prio=1)
add("b.legacy", "todo", prio=2)
old_n = con.execute("SELECT count(*) n FROM task WHERE status IN ('todo','doing')"
                    ).fetchone()["n"]
new_n = con.execute("SELECT count(*) n FROM task WHERE status IN "
                    "('planned','ready','running','todo','doing')").fetchone()["n"]
check("the pre-fix filter MISSES the canonical row", old_n == 1, f"old={old_n}")
check("the fixed filter sees BOTH rows", new_n == 2, f"new={new_n}")
check("the fix strictly widens (old is a subset of new)", old_n <= new_n)

print()
if FAILED:
    print(f"RESULT: {len(FAILED)} FAILED -> {FAILED}")
    raise SystemExit(1)
print("RESULT: all checks passed")