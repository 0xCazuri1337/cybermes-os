"""Why did open_conflicts go 11 -> 43 with no wave-10 class involved?

Every open row is a PRE-EXISTING class (xss/idor/race/ssrf/graphql) with topic
'fabricated-evidence' and EMPTY item_a. Wave 10 added no item in any of those
classes. So something in this session re-inserted them -- most likely
`wks.cli gate`, which re-assesses every item and may append rather than
dedupe, or `wks.ingest` doing so per run.

Prints created_at ordering and duplicate fingerprints, so the re-insert is
visible rather than inferred.
"""
import os
import sqlite3
from collections import Counter

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
con = sqlite3.connect(os.path.join(ROOT, "db", "wks.db"))
con.row_factory = sqlite3.Row
cur = con.cursor()

print("total conflict rows:", cur.execute("SELECT count(*) FROM conflict").fetchone()[0])
print("\ncreated_at histogram:")
for r in cur.execute("SELECT substr(created_at,1,16) t, status, count(*) n "
                     "FROM conflict GROUP BY t, status ORDER BY t"):
    print("  ", tuple(r))

print("\nopen rows, ordered by id:")
for r in cur.execute("SELECT id, class_id, topic, status, created_at, "
                     "substr(coalesce(claim_a,''),1,70) "
                     "FROM conflict WHERE status='open' ORDER BY id"):
    print("  %3d %-14s %-22s %s" % (r["id"], r["class_id"], r["topic"],
                                    r["created_at"]))
    print("        %s" % (r["claim_a"] or "(empty)"))

print("\nduplicate fingerprints (class_id, topic, claim_a) among OPEN rows:")
fp = Counter()
for r in cur.execute("SELECT class_id, topic, claim_a FROM conflict WHERE status='open'"):
    fp[(r["class_id"], r["topic"], (r["claim_a"] or "")[:120])] += 1
for k, n in fp.most_common(15):
    print("  %2dx %s / %s / %s" % (n, k[0], k[1], (k[2] or "")[:70]))