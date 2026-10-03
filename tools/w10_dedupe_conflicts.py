P = r'C:/Users/Administrator/.hermes/cyber/db/wks.db'

# Consolidate the duplicate conflict rows the wave-10 bug created.
#
# MEASURED: 43 open rows, 10 distinct (class_id, claim_a, claim_b). The bug was
# an unconditional INSERT on every rejection, so each re-ingest added a copy.
# These rows carry no item link and no source-file provenance, so they cannot be
# attributed to a producer -- they are pure duplication.
#
# REPORT-ONLY by default. Pass --apply to collapse, keeping the EARLIEST row of
# each fingerprint (the first detection is the evidence) and recording on it how
# many duplicates were folded in, so nothing is silently destroyed.
import os
import sqlite3
import sys

APPLY = "--apply" in sys.argv
con = sqlite3.connect(P)
con.row_factory = sqlite3.Row
cur = con.cursor()

rows = cur.execute("SELECT id, class_id, claim_a, claim_b, created_at "
                   "FROM conflict WHERE status='open' "
                   "ORDER BY class_id, claim_a, id").fetchall()

groups = {}
for r in rows:
    groups.setdefault((r["class_id"], r["claim_a"], r["claim_b"]), []).append(r)

print("open rows: %d   distinct fingerprints: %d" % (len(rows), len(groups)))
dupe_total = sum(len(g) - 1 for g in groups.values())
print("redundant rows that would be folded: %d\n" % dupe_total)

for fp, g in sorted(groups.items(), key=lambda kv: -len(kv[1])):
    keep = g[0]
    print("%-9s x%d  ids=%s" % (keep["class_id"], len(g), [r["id"] for r in g]))
    print("          keep id=%d (%s)  %s" % (keep["id"], keep["created_at"],
                                           keep["claim_a"][:70]))

if not APPLY:
    print("\ndry run -- pass --apply to collapse")
    sys.exit(0)

for fp, g in groups.items():
    if len(g) == 1:
        continue
    keep, extra = g[0], g[1:]
    note = ("consolidated %d duplicate row(s) recorded by the pre-fix "
            "unconditional conflict INSERT (wks/ingest.py, wave 10); "
            "earliest detection id=%d is authoritative. Folded ids: %s"
            % (len(extra), keep["id"], ",".join(str(r["id"]) for r in extra)))
    existing = cur.execute("SELECT resolution FROM conflict WHERE id=?",
                           (keep["id"],)).fetchone()["resolution"]
    merged = (existing + " | " + note) if existing else note
    cur.execute("UPDATE conflict SET resolution=? WHERE id=?", (merged, keep["id"]))
    for r in extra:
        cur.execute("UPDATE conflict SET status='dismissed', resolution=? "
                    "WHERE id=?",
                    ("duplicate of conflict id=%d (same class, claim and detail); "
                     "collapsed by tools/w10_dedupe_conflicts.py on the wave-10 "
                     "idempotence fix." % keep["id"], r["id"]))

con.commit()
after = cur.execute("SELECT status, count(*) FROM conflict GROUP BY status").fetchall()
print("\nAPPLIED. status histogram now:")
for r in after:
    print("   %-10s %d" % (r["status"], r["count"]))
open_now = cur.execute("SELECT count(*) FROM conflict WHERE status='open'").fetchone()[0]
print("open disputes: %d (was %d, %d distinct)" % (open_now, len(rows), len(groups)))
con.close()