"""Find the EXACT character where a stored NVD quote diverges from the page.

Every previous hypothesis has been wrong: it is not the entity unescape, not the
rate limit, not JSON escape residue. `find_quote` says False for a quote whose
first 60 characters ARE in the raw body, and `difflib` against the freshly
parsed description says the two strings are IDENTICAL (similarity 1.0000).

Those two facts can only both be true if the matcher is comparing against a
DIFFERENT rendering of the page than the raw body -- i.e. `extract_text()`
transforms the JSON in a way that breaks the span. So this diffs the quote
against `extract_text(raw)` character by character and prints the first
divergence, which is the only way to see what the matcher actually sees.
"""
import difflib
import re
import sqlite3
import ssl
import sys
import time
import urllib.request

sys.path.insert(0, ".")
from wks import pipeline
from wks.verify_quotes import find_quote, norm

ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE
UA = {"User-Agent": "Mozilla/5.0 Chrome/120", "Accept": "application/json"}


def get(url):
    for a in range(4):
        try:
            r = urllib.request.urlopen(urllib.request.Request(url, headers=UA),
                                       timeout=45, context=ctx)
            return r.read().decode("utf-8", "replace"), r.headers.get("Content-Type", "")
        except Exception:
            time.sleep(8 * (a + 1))
    return None, None


db = sqlite3.connect("db/wks.db")
db.row_factory = sqlite3.Row
r = db.execute("""SELECT i.id, isr.quote FROM item i
                    JOIN item_source isr ON isr.item_id=i.id
                    JOIN source s ON s.id=isr.source_id
                   WHERE i.item_key LIKE '%blunder%' AND s.host LIKE '%nist.gov%'""").fetchone()
quote = r["quote"]
url = db.execute("""SELECT s.url FROM item_source isr JOIN source s ON s.id=isr.source_id
                     WHERE isr.item_id=? AND s.host LIKE '%nist.gov%'""",
                 (r["id"],)).fetchone()[0]

raw, ct = get(url)
print(f"quote len {len(quote)}   raw len {len(raw)}   ctype {ct}")
print(f"find_quote(raw, quote)        : {find_quote(raw, quote)}")

text = pipeline.extract_text(raw.encode(), ct)
print(f"find_quote(extract_text, q)   : {find_quote(text, quote)}")
print(f"extract_text changed the body : {len(text) != len(raw)}  ({len(raw)} -> {len(text)})")

# locate the quote inside each rendering and diff the surroundings
for label, hay in (("raw", raw), ("extract_text", text)):
    i = hay.find(quote[:60])
    if i < 0:
        # try the normalised form
        nq = norm(quote)
        nh = norm(hay)
        j = nh.find(nq[:60])
        print(f"\n[{label}] verbatim head not found; normalised head at {j}")
        if j >= 0:
            window = nh[j:j + len(nq) + 40]
            sm = difflib.SequenceMatcher(None, nq, window)
            print(f"[{label}] similarity to stored: {sm.ratio():.4f}")
            for tag, i1, i2, j1, j2 in sm.get_opcodes():
                if tag != "equal":
                    print(f"   {tag}: stored={nq[i1:i2][:70]!r}")
                    print(f"          page  ={window[j1:j2][:70]!r}")
                    break
        continue
    print(f"\n[{label}] head found at {i}")
    window = hay[i:i + len(quote) + 40]
    sm = difflib.SequenceMatcher(None, quote, window)
    print(f"[{label}] similarity: {sm.ratio():.4f}")
    for tag, i1, i2, j1, j2 in sm.get_opcodes():
        if tag != "equal":
            print(f"   {tag} at {i1}")
            print(f"     stored: {quote[max(0,i1-30):i2+30]!r}")
            print(f"     page  : {window[max(0,j1-30):j2+30]!r}")
            break