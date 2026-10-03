"""Reproduce the duplicate-conflict defect in a SANDBOX db (never the canonical
one).

Symptom: 43 open conflict rows for 10 distinct disputes, and each claim appears
4x (7x for one deser claim) with byte-identical claim_a/claim_b lengths. The db
rows were created between 13:17 and 13:50 local -- inside this session, by a
process that is no longer running -- and none of the 5 wave-10 children reports
touching xss.json / idor.json / race.json / ssrf.json / graphql.json /
w5-fp-web.json.

Hypothesis, from reading wks/ingest.py:135-141: on QUOTE_NOT_FOUND it executes
an unconditional INSERT INTO conflict ... status='open' with claim_a =
it['claim'] and NO item_a and NO source-file provenance, and no UNIQUE/dedupe
check. So re-ingesting the same file N times records the SAME dispute N times,
and nothing links the row to the item or the file that produced it -- which is
exactly why tools/resolve_disputes.py has to match on claim text alone.

This sandbox proves it by ingesting the same file twice against a throwaway db
and counting rows.
"""
import json
import os
import shutil
import subprocess
import sys
import sqlite3
import tempfile
from pathlib import Path

ROOT = Path(r"C:/Users/Administrator/.hermes/cyber")
SRC = ROOT / "research" / "incoming" / "w5-fp-web.json"

sandbox = Path(tempfile.mkdtemp(prefix="wks-sandbox-"))
print("sandbox:", sandbox)
shutil.copytree(ROOT / "db", sandbox / "db")
print("sandbox db copied from canonical (throwaway copy only)")

env = dict(os.environ, WKS_ROOT=str(sandbox), PYTHONPATH=str(ROOT))


def run(args):
    p = subprocess.run([sys.executable, "-m"] + args, cwd=str(ROOT), env=env,
                       capture_output=True, text=True, timeout=1200)
    return p.returncode, (p.stdout or "")[-1500:], (p.stderr or "")[-600:]


def conflicts():
    con = sqlite3.connect(str(sandbox / "db" / "wks.db"))
    rows = con.execute("SELECT id, class_id, topic, claim_a, item_a FROM conflict "
                       "WHERE status='open'").fetchall()
    con.close()
    return rows


print("\n--- pass 1: real ingest of %s ---" % SRC.name)
rc, out, err = run(["wks.ingest", str(SRC)])
print(out)
if err.strip():
    print("STDERR:", err)
c1 = conflicts()
print("open conflict rows after pass 1: %d" % len(c1))

print("\n--- pass 2: SAME file ingested AGAIN (nothing changed) ---")
rc, out, err = run(["wks.ingest", str(SRC)])
print(out)
c2 = conflicts()
print("open conflict rows after pass 2: %d" % len(c2))

from collections import Counter
fp = Counter((r[1], r[2], (r[3] or "")[:120]) for r in c2)
dupes = {k: n for k, n in fp.items() if n > 1}
print("\ndistinct (class,topic,claim_a): %d" % len(fp))
print("fingerprints now stored MORE THAN ONCE: %d" % len(dupes))
for k, n in sorted(dupes.items(), key=lambda kv: -kv[1])[:8]:
    print("   %2dx %-10s %s" % (n, k[0], (k[2] or "")[:80]))

print("\nrows carrying item_a (link back to the offending item): %d of %d"
      % (sum(1 for r in c2 if r[4] is not None), len(c2)))

print("\nVERDICT: duplicate insert on repeat ingest is %s" %
      ("REPRODUCED" if len(c2) > len(c1) else "NOT reproduced -- hypothesis wrong"))
shutil.rmtree(sandbox, ignore_errors=True)
print("sandbox removed:", not sandbox.exists())