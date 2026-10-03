"""open_conflicts went 11 -> 43 with no wave-10 class involved, yet the newest
created_at is 10:50 -- BEFORE this session started at 13:21. So no new rows were
inserted by wave 10; existing rows must have had their STATUS flipped, or the
metrics query and the raw query disagree.

Prints, per conflict row: id, status, created_at, and how metrics counts it.
"""
import os
import sqlite3

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
con = sqlite3.connect(os.path.join(ROOT, "db", "wks.db"))
con.row_factory = sqlite3.Row
cur = con.cursor()

import sys
sys.path.insert(0, ROOT)
print("how evalm counts it:")
import inspect
from wks import evalm
src = inspect.getsource(evalm)
for line in src.splitlines():
    if "n_conflicts" in line or "conflict" in line.lower():
        print("   ", line.strip())

print("\nraw counts by status:")
for r in cur.execute("SELECT status, count(*) FROM conflict GROUP BY status"):
    print("   ", tuple(r))

print("\nALL rows (id, status, created_at, class_id, topic):")
for r in cur.execute("SELECT id, status, created_at, class_id, topic FROM conflict "
                     "ORDER BY id"):
    print("  %3d  %-10s %s  %-12s %s" % (r["id"], r["status"], r["created_at"],
                                         r["class_id"], r["topic"]))

print("\ndistinct status spellings:")
for r in cur.execute("SELECT DISTINCT status, length(status) FROM conflict"):
    print("   ", repr(r[0]), r[1])