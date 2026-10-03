"""Add `provenance` to fp_case, with the two values that matter.

MEASURED, and the reason this exists: the 70 existing rows are FIELD
OBSERVATIONS -- real engagements, where someone looked at a live host, ran a
control, and wrote down what refuted them. Example of what is actually in there:

    hypothesis      GET /api/invoice/{id} returns another user's invoice data
    looked_vulnerable_because
                    HTTP 200 with a fully populated invoice JSON for an id I did
                    not create
    test_performed  Re-ran with a second account in a different tenant and
                    compared the response byte for byte
    invalidated_by  byte-identical bodies; the id resolves within the caller's
                    tenant server-side
    rejection_rule  A 200 with data is not a finding until the same identifier is
                    shown to resolve differently for a second identity

`fp_case` had NO column recording any of that. So a rule derived from a
disproof sentence would have been indistinguishable from an engagement-derived
one, and the two carry very different weight: one says "this is what I saw", the
other says "this is what I would expect to see". After several months the table
would read as field evidence and nobody could tell which was which.

Values:
  field_observation      a real engagement: a live control was run and refuted it
  derived_from_disproof  generalised from an item's disproof; no engagement
  derived_from_finding   generalised from a real finding's validation narrative
"""
import io
import os
import sqlite3
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DB = os.path.join(ROOT, "db", "wks.db")

con = sqlite3.connect(DB)
con.row_factory = sqlite3.Row
cols = [r[1] for r in con.execute("PRAGMA table_info(fp_case)")]
print("fp_case columns before:", cols)

if "provenance" in cols:
    print("already present; nothing to do")
    # what is currently recorded?
    n = con.execute("SELECT COUNT(*) FROM fp_case WHERE provenance IS NOT NULL"
                    " AND provenance != ''").fetchone()[0]
    print("rows already labelled: %d" % n)
else:
    # ALTER TABLE ADD COLUMN is the only write form here that cannot silently
    # no-op: if the column existed it would have raised above.
    con.execute("ALTER TABLE fp_case ADD COLUMN provenance TEXT")
    con.execute("ALTER TABLE fp_case ADD COLUMN source_ref TEXT")
    con.commit()
    print("added provenance + source_ref")

cols = [r[1] for r in con.execute("PRAGMA table_info(fp_case)")]
print("fp_case columns after :", cols)

# the 70 pre-existing rows are engagement-derived by construction: every one of
# them was authored from a real hunt record. Label them so the distinction holds.
cur = con.execute("UPDATE fp_case SET provenance='field_observation'"
                  " WHERE provenance IS NULL OR provenance=''")
con.commit()
print("labelled pre-existing rows: %d" % cur.rowcount)

print()
print("provenance distribution:")
for r in con.execute("SELECT COALESCE(provenance,'(null)') p, COUNT(*) c"
                     " FROM fp_case GROUP BY 1 ORDER BY c DESC"):
    print("   %-24s %d" % (r["p"], r["c"]))

# ASSERT rather than trust: the column must exist and be queryable
assert "provenance" in [r[1] for r in con.execute("PRAGMA table_info(fp_case)")]
con.execute("SELECT COUNT(*) FROM fp_case WHERE provenance='field_observation'")
print("\nASSERT OK: provenance exists and is queryable")
con.close()