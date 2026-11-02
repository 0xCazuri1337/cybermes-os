"""Resolve two open questions before drawing any conclusion.

(1) TIMEZONE. created_at is written by `datetime('now')`, which is UTC; the host
    clock is EEST (UTC+3). 10:50 "in the db" is 13:50 local -- INSIDE wave 10.
    The first reading looked like "all conflicts predate the session", which
    would have been a false conclusion from comparing two clocks.

(2) PROVENANCE. ingest.py writes conflict rows with claim_a = it["claim"] (long
    text). store.add_conflict() is called by NOTHING in the tree. So an open row
    with an EMPTY claim_a cannot have come from ingest -- it came from somewhere
    else, and empty claim_a is exactly what makes a dispute unreadable.

Prints both, plus which classes the open rows belong to.
"""
import os
import sqlite3
from datetime import datetime, timedelta, timezone

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
con = sqlite3.connect(os.path.join(ROOT, "db", "wks.db"))
con.row_factory = sqlite3.Row
cur = con.cursor()

utc = datetime.now(timezone.utc)
print("local now:", datetime.now().isoformat(timespec="seconds"))
print("utc   now:", utc.isoformat(timespec="seconds"))

print("\ncreated_at (stored, assumed UTC) -> local (+3h):")
rows = cur.execute("SELECT id, status, created_at, class_id, topic, "
                   "length(coalesce(claim_a,'')) la, length(coalesce(claim_b,'')) lb, "
                   "coalesce(item_a,-1) ia FROM conflict ORDER BY id").fetchall()
for r in rows:
    if r["status"] != "open":
        continue
    try:
        t = datetime.strptime(r["created_at"], "%Y-%m-%d %H:%M:%S")
        loc = t + timedelta(hours=3)
    except Exception:
        loc = r["created_at"]
    print("  %3d  utc=%s  local=%s  %-11s claim_a_len=%-4d claim_b_len=%-4d "
          "item_a=%s" % (r["id"], r["created_at"], loc.strftime("%H:%M:%S"),
                         r["class_id"], r["la"], r["lb"], r["ia"]))

print("\nopen rows with EMPTY claim_a: %d of %d" % (
    cur.execute("SELECT count(*) FROM conflict WHERE status='open' "
                "AND coalesce(claim_a,'')=''").fetchone()[0],
    cur.execute("SELECT count(*) FROM conflict WHERE status='open'").fetchone()[0]))

print("\ndoes any open row name an item?")
for r in cur.execute("SELECT count(*) n FROM conflict WHERE status='open' "
                     "AND item_a IS NOT NULL"):
    print("   ", r["n"])

print("\nclasses in open rows:")
for r in cur.execute("SELECT class_id, count(*) n FROM conflict WHERE status='open' "
                     "GROUP BY class_id ORDER BY n DESC"):
    print("   %-12s %d" % (r["class_id"], r["n"]))