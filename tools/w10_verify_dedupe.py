P = r'C:/Users/Administrator/.hermes/cyber/db/wks.db'

# Verify the collapse landed. The previous run's final print raised IndexError
# (the GROUP BY returns positional tuples, not row_factory keys), but
# con.commit() had already executed -- so the write DID happen and the crash was
# only in the reporting. Verify from the db rather than from the script's own
# final line.
import sqlite3

con = sqlite3.connect(P)
cur = con.cursor()
print("status histogram:")
for status, n in cur.execute("SELECT status, count(*) FROM conflict GROUP BY status"):
    print("   %-10s %d" % (status, n))

open_rows = cur.execute("SELECT id, class_id, claim_a, claim_b FROM conflict "
                        "WHERE status='open'").fetchall()
print("\nopen disputes: %d" % len(open_rows))
print("distinct fingerprints among open: %d"
      % len({(r[1], r[2], r[3]) for r in open_rows}))

print("\nrows whose resolution records a consolidation:")
for rid, res in cur.execute("SELECT id, resolution FROM conflict "
                            "WHERE resolution LIKE 'consolidated%' "
                            "   OR resolution LIKE '%duplicate of conflict%'"):
    print("  id=%-3d %s" % (rid, (res or "")[:110]))

print("\nkept rows carrying the folded-count note:")
for rid, cls, res in cur.execute(
        "SELECT id, class_id, resolution FROM conflict "
        "WHERE status='open' AND resolution LIKE '%consolidated%'"):
    print("  id=%-3d %-8s %s" % (rid, cls, res[:150]))
con.close()