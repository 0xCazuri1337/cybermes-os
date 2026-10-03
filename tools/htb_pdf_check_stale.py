"""Identify the 3 items whose NVD quote no longer matches, and decide honestly.

MEASURED: the merged audit reports 3 of 24 items with
`services.nvd.nist.gov: quote absent` even though the ingest reported them
promoted. Two innocent explanations and one not:

  * NVD is a MOVING description. The stored quote came from a fetch minutes
    ago; NVD re-issues records and the wording can change, in which case the
    item is fine and the citation is simply stale.
  * the item was merged on a --dry-style pass and never really verified.

Only re-fetching and diffing the stored quote against what the page says NOW can
tell these apart. If the stored quote is a PREFIX/substring of the current
description, it is staleness. If it shares almost nothing with it, the stored
quote is not the page's text and the item must be reported as suspect.
"""
import json
import re
import sqlite3
import ssl
import sys
import time
import urllib.request

sys.path.insert(0, ".")
from wks import pipeline
from wks.verify_quotes import find_quote

ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE
UA = {"User-Agent": "Mozilla/5.0 Chrome/120", "Accept": "application/json"}
NVD_INTERVAL = 6.5


def get(url):
    for attempt in range(3):
        try:
            r = urllib.request.urlopen(urllib.request.Request(url, headers=UA),
                                       timeout=45, context=ctx)
            return pipeline.extract_text(r.read(), r.headers.get("Content-Type", ""))
        except Exception:
            time.sleep(NVD_INTERVAL * (attempt + 1))
    return ""


db = sqlite3.connect("db/wks.db")
db.row_factory = sqlite3.Row

rows = list(db.execute("""
    SELECT DISTINCT i.item_key, i.id FROM item i
      JOIN item_source isr ON isr.item_id = i.id
      JOIN source s ON s.id = isr.source_id
     WHERE i.body LIKE '%HTB machine%' AND i.status='active'
       AND s.host LIKE '%nist.gov%'"""))

print(f"items with an NVD source: {len(rows)}\n")
stale = suspect = clean = 0
for r in rows:
    src = db.execute("""SELECT s.url, isr.quote FROM item_source isr
                         JOIN source s ON s.id=isr.source_id
                        WHERE isr.item_id=? AND s.host LIKE '%nist.gov%'""",
                     (r["id"],)).fetchone()
    text = get(src["url"])
    if not text:
        print(f"  UNFETCHABLE  {r['item_key'][:56]}")
        continue
    if find_quote(text, src["quote"]):
        clean += 1
        continue
    # not matching -- compare normalised overlap to classify WHY
    def norm(s):
        return re.sub(r"\s+", " ", (s or "").lower()).strip()

    q, page = norm(src["quote"]), norm(text)
    # is the stored quote contained in the current description?
    inside = q[:120] in page
    # token overlap as a sanity measure
    qt = set(re.findall(r"[a-z]{4,}", q))
    pt = set(re.findall(r"[a-z]{4,}", page))
    jac = len(qt & pt) / max(1, len(qt | pt))
    if inside or jac > 0.5:
        stale += 1
        print(f"  STALE-but-same  overlap={jac:.2f}  {r['item_key'][:52]}")
    else:
        suspect += 1
        print(f"  SUSPECT         overlap={jac:.2f}  {r['item_key'][:52]}")
        print(f"      stored : {q[:110]}")
        # show what the page actually says about this CVE
        cve = re.search(r"cveId=(CVE-[0-9-]+)", src["url"])
        i = page.find("the ms-") if "the ms-" in page else page.find("the ")
        print(f"      page   : {page[i:i + 110]}")

print(f"\nclean={clean}  stale(same content)={stale}  suspect(different content)={suspect}")
sys.exit(1 if suspect else 0)