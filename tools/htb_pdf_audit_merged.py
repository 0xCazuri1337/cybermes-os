"""Re-verify the MERGED PDF items against live sources, from the db.

The merge log said "promoted", which is a self-report. This walks the db, takes
every item whose body carries the `HTB machine` provenance marker, and re-fetches
each of its cited URLs to confirm the stored quote is still present.

It also records, per item, what the on-disk HTB document contributes -- because
that document is deliberately NOT a citable public URL (the machine page is a
login-gated SPA), so the honest summary of each item is:
    "2 public orgs verify; the practice account is a hashed local document"
"""
import os
import re
import ssl
import sys
import urllib.request

sys.path.insert(0, ".")
from wks import config, pipeline
from wks.verify_quotes import find_quote

ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE
UA = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120",
      "Accept": "application/json"}

# NVD allows 5 unauthenticated requests / 30 s. The first version of this audit
# fired all of them at once and reported 4 of 5 items as FAIL with a bare
# HTTPError -- the auditor reproducing the very rate limit the builder was fixed
# to avoid. A checker that trips the limit it is measuring misreports the
# corpus, so it paces exactly like the producer.
NVD_INTERVAL = 6.5


def paced_get(url, headers):
    """GET with one retry, spaced for NVD and only for NVD."""
    is_nvd = "nist.gov" in url
    for attempt in range(3):
        try:
            req = urllib.request.Request(url, headers=headers)
            with urllib.request.urlopen(req, timeout=45, context=ctx) as resp:
                return resp.status, resp.headers.get("Content-Type", ""), resp.read()
        except urllib.error.HTTPError as e:
            if is_nvd and e.code in (403, 429, 503):
                time.sleep(NVD_INTERVAL * (attempt + 1))
                continue
            return None, None, None
        except Exception:
            if is_nvd:
                time.sleep(NVD_INTERVAL * (attempt + 1))
                continue
            return None, None, None
    return None, None, None

import time
import urllib.error

import sqlite3

db = sqlite3.connect("db/wks.db")
db.row_factory = sqlite3.Row

rows = list(db.execute(
    "SELECT id, item_key, body FROM item "
    "WHERE status='active' AND body LIKE '%HTB machine%' ORDER BY item_key"))

print(f"merged PDF items: {len(rows)}\n")
ok = bad = 0
for r in rows:
    orgs, fails, quotes = set(), [], []
    for s in db.execute("""SELECT s.host, s.url, isr.quote FROM item_source isr
                           JOIN source s ON s.id=isr.source_id
                          WHERE isr.item_id=?""", (r["id"],)):
        orgs.add(config.publisher_org(s["host"]))
        if True:
            status, ct, body = paced_get(s["url"], UA)
            if body is None:
                bad += 1
                fails.append(f"{s['host']}: fetch failed after retry")
                continue
            if find_quote(pipeline.extract_text(body, ct), s["quote"]):
                ok += 1
                quotes.append(1)
            else:
                bad += 1
                fails.append(f"{s['host']}: quote absent")
    sha = re.search(r"sha1 ([0-9a-f]{12})", r["body"] or "")
    status = "OK  " if len(orgs) >= config.MIN_PUBLISHER_HOSTS and not fails else "FAIL"
    print(f"  {status} {r['item_key'][:52]:<54} orgs={len(orgs)} {sorted(orgs)}")
    print(f"        local PDF sha1={sha.group(1) if sha else 'NONE'}")
    for f in fails:
        print(f"        !! {f}")

print(f"\nlive quote checks: {ok} ok, {bad} failed")
sys.exit(1 if bad or not rows else 0)