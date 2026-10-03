"""How many of OUR 75 harvested items carry a malformed quote?

Two bugs found, one in the diagnostic and one in the data:

BUG 1 (diagnostic): `item_key LIKE '%.ht_%'` — `_` is a single-character
wildcard in SQL LIKE, so `.ht_` also matches `.htm`. The query returned 4
PRE-EXISTING xss items that have nothing to do with this harvest. Fixed here
with an explicit ESCAPE and a GLOB cross-check.

BUG 2 (REAL, in our data): the sentence splitter glued MARKDOWN HEADING FURNITURE
into the middle of a quote. OWASP's page reads:

    ... to prevent XSS.
    ### Output Encoding for "CSS Contexts"
    "CSS Contexts" refer to variables ...

and the harvested quote became one string spanning all three, including the "¶"
anchor character. Every fragment IS on the page, so `find_quote` fails on the
joined form. That is not fabrication — it is a malformed citation, and a quote
that cannot be re-verified is not evidence. This is the same class of defect as
the "table furniture" audit rule from an earlier wave.

Prints every affected item so the parent can re-slice or drop them.
"""
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from wks import store  # noqa: E402

HEADING_RE = re.compile(r"^\s{0,3}#{1,6}\s", re.M)
PILCROW = "¶"


def main():
    con = store.connect()
    rows = list(con.execute(
        "SELECT i.id, i.item_key, i.class_id, s.host, s.url, x.quote"
        "  FROM item i"
        "  JOIN quality q ON q.item_id=i.id"
        "  JOIN item_source x ON x.item_id=i.id"
        "  JOIN source s ON s.id=x.source_id"
        " WHERE q.validation_state='high_confidence'"
        "   AND i.item_key LIKE '%.ht!_%' ESCAPE '!'"))
    glob = list(con.execute(
        "SELECT id FROM item WHERE item_key GLOB '*.ht_*'"))
    print("=" * 76)
    print("MALFORMED-QUOTE SCAN over our harvested items")
    print("=" * 76)
    print("  LIKE-with-ESCAPE rows : %d" % len(rows))
    print("  GLOB '*.ht_*' items    : %d" % len(glob))
    print()

    bad = []
    for r in rows:
        q = r["quote"] or ""
        why = []
        if PILCROW in q:
            why.append("contains the PILCROW heading anchor %r" % PILCROW)
        if HEADING_RE.search(q):
            why.append("contains a markdown heading marker")
        # a quote carrying a whole navigation/heading run reads as furniture
        if len(re.findall(r"\bOutput Encoding\b|\bInput Validation\b|¶", q)) > 1:
            why.append("splices two section headings into one quote")
        if why:
            bad.append((r, why, q))

    print("items with a malformed quote: %d" % len(bad))
    for r, why, q in bad:
        print("-" * 76)
        print("  %s" % r["item_key"])
        print("    class : %s   host: %s" % (r["class_id"], r["host"]))
        print("    why   : %s" % "; ".join(why))
        print("    quote : %s" % q[:230])
    if not bad:
        print("  none -- every harvested quote is clean")


if __name__ == "__main__":
    main()