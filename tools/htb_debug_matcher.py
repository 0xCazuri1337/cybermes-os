"""Why does find_quote reject a quote that is byte-identical to the page text?

MEASURED: for `blunder / CVE-2019-14287`, `identical? True` -- the stored quote
and the current NVD description are the SAME 330-character string, and the raw
JSON contains it (`q[:60] in raw` is True). Yet `find_quote(raw, stored)` returns
False. A verbatim quote is being refused, which would make the gate report
FABRICATED for correct evidence.

That is the same class of bug as the entity and the markdown-strip defects: the
MATCHER, not the evidence. And it means the "3 quote absent" items were
mislabelled -- they are not stale, not rate-limited, and not fabricated.

This isolates exactly which normalisation step drops the span, by walking the
`norm()` ladder one rule at a time and reporting the first that breaks it.
"""
import re
import sqlite3
import ssl
import sys
import unicodedata
import urllib.request

sys.path.insert(0, ".")
from wks.verify_quotes import find_quote, norm

ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE
UA = {"User-Agent": "Mozilla/5.0 Chrome/120", "Accept": "application/json"}

db = sqlite3.connect("db/wks.db")
db.row_factory = sqlite3.Row
r = db.execute("""SELECT i.id, isr.quote FROM item i
                    JOIN item_source isr ON isr.item_id=i.id
                    JOIN source s ON s.id=isr.source_id
                   WHERE i.item_key LIKE '%blunder%'
                     AND s.host LIKE '%nist.gov%'""").fetchone()
q = r["quote"]
url = db.execute("""SELECT s.url FROM item_source isr JOIN source s ON s.id=isr.source_id
                     WHERE isr.item_id=? AND s.host LIKE '%nist.gov%'""",
                 (r["id"],)).fetchone()[0]
raw = urllib.request.urlopen(urllib.request.Request(url, headers=UA),
                             timeout=45, context=ctx).read().decode("utf-8", "replace")

print(f"stored quote len : {len(q)}")
print(f"verbatim in raw  : {q in raw}")
print(f"find_quote       : {find_quote(raw, q)}")

print("\n--- what is in the stored quote that normalises oddly? ---")
BS = chr(92)
for name, ch in [("backslash", BS), ("newline", "\n"), ("tab", "\t"),
                 ("double space", "  "), ("nbsp", "\u00a0"),
                 ("smart quote", "\u2019"), ("em dash", "\u2014"),
                 ("non-ascii", None)]:
    if ch is None:
        bad = sorted({c for c in q if ord(c) > 126})
        print(f"  {name:<13}: {bad[:8]}")
    else:
        print(f"  {name:<13}: {'YES  ' + repr(ch) if ch in q else 'no'}")

print("\n--- walk the norm() ladder ---")


def step(label, s):
    return s


s1 = unicodedata.normalize("NFKC", q)
print(f"  after NFKC            changed={s1 != q}")
s2 = s1.replace("\u2019", "'").replace("\u2018", "'")
s3 = s2.replace("\u201c", '"').replace("\u201d", '"')
s4 = s3.replace("\u2013", "-").replace("\u2014", "-").replace("\u00a0", " ")
s5 = re.sub(r"\s+", " ", s4).strip().lower()
print(f"  after whitespace+lower len={len(s5)}")
s6 = re.sub(r"\s+([,.;:!?)\]}])", r"\1", s5)
print(f"  after punct-close rule changed={s6 != s5}")
if s6 != s5:
    a, b = s5, s6
    for i, (x, y) in enumerate(zip(a, b)):
        if x != y:
            print(f"    first divergence at {i}: {a[max(0,i-40):i+20]!r} -> {b[max(0,i-40):i+20]!r}")
            break
s7 = re.sub(r"([(\[{])\s+", r"\1", s6)
print(f"  after punct-open rule changed={s7 != s6}")

nq = norm(q)
nr = norm(raw)
print(f"\n  norm(quote) in norm(raw): {nq in nr}")
i = nr.find(nq[:60])
print(f"  norm(raw) around it     : {nr[max(0,i-30):i+90]!r}" if i >= 0 else "  anchor not found")

# the markdown stripper is applied to the PAGE, not the quote -- check whether
# it is what removes it
_MD = re.compile(r"\*\*|__|\*|`")
_TBL = re.compile(r"\s*\|\s*|\s*[-=]{2,}\s*")
stripped = _TBL.sub(" ", _MD.sub(" ", raw))
print(f"\n  after markdown strip    : {find_quote(stripped, q)}")
print(f"  does the quote contain a stripped char? "
      f"{bool(_MD.search(q))}  md-hit={_MD.search(q)}")
if _MD.search(q):
    print(f"  that char in the page?  {_MD.search(q).group(0) in raw}")