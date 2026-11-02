"""Are those 3 OWASP mismatches real, or is my verifier wrong?

MEASURED on this host before: an OWASP page returned 200 with 5.4KB containing
none of the cited text, and the pinned v4.2 tag held it verbatim. And separately,
a verifier that had never been checked against a known-good case manufactured
misses. So BOTH directions are tested here before anything is called dead:

  T1  does the quote match the live page?                (the claim to check)
  T2  does it match the page after tag-stripping?        (extraction artefact?)
  T3  does it match a PINNED release of the same doc?    (rewritten upstream?)
  T4  negative control: an invented sentence must NOT match
  T5  is the same quote already trusted elsewhere in OUR corpus, promoted, by
      the gate? (if yes, the gate accepted it once already)
"""
import json
import os
import re
import sys
import time
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import ht_build_items as B  # noqa: E402
from wks import store, verify_quotes as V  # noqa: E402

URL = "https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html"
UA = {"User-Agent": "Mozilla/5.0 (compatible; wks-research/1.0)"}


def get(u):
    try:
        req = urllib.request.Request(u, headers=UA)
        return urllib.request.urlopen(req, timeout=45).read().decode("utf-8", "replace")
    except Exception as e:                                       # noqa: BLE001
        print("   fetch failed %s: %s" % (type(e).__name__, e))
        return ""


def main():
    con = store.connect()
    bad = list(con.execute(
        "SELECT DISTINCT x.quote FROM item_source x JOIN source s ON s.id=x.source_id"
        " WHERE s.url LIKE '%Cross_Site_Scripting_Prevention%'"
        "   AND x.item_id IN (SELECT id FROM item WHERE item_key LIKE '%.ht_%')"))
    print("=" * 74)
    print("DIAGNOSIS: %d OWASP quote(s) flagged" % len(bad))
    print("=" * 74)
    live = get(URL)
    prose = B.fetch_html(URL)
    print("T1 live bytes            : %d" % len(live))
    print("T2 prose chars           : %d" % len(prose))

    for r in bad:
        q = r["quote"]
        print()
        print("quote: %s" % q[:150])
        print("  T1 match live html     : %s" % V.find_quote(live, q))
        print("  T2 match stripped prose: %s" % V.find_quote(prose, q))
        invented = ("Zorblax quicksilver frameworks employ a wibblesprocket "
                    "configuration to defeat spectral authentication.")
        print("  T4 negative control    : %s (must be False)"
              % V.find_quote(prose, invented))
        # T3: is the SAME quote already trusted by our own gate?
        trusted = con.execute(
            "SELECT i.item_key, q.validation_state FROM item_source x"
            " JOIN source s ON s.id=x.source_id"
            " JOIN item i ON i.id=x.item_id"
            " JOIN quality q ON q.item_id=i.id"
            " WHERE x.quote=? AND q.validation_state='high_confidence'"
            "   AND i.item_key NOT LIKE '%.ht_%' LIMIT 3", (q,)).fetchall()
        for t in trusted:
            print("  T5 already promoted   : %s (%s)" % (t["item_key"],
                                                         t["validation_state"]))

    # Does the quoted text appear ANYWHERE on the live page at all?
    print()
    print("WHERE the quoted text lives on the live page:")
    for r in bad:
        frag = " ".join(r["quote"].split()[:6])
        i = live.find(frag)
        print("  fragment %-46r -> offset %s" % (frag[:44], i))
        if i < 0:
            # try the first 4 words
            frag = " ".join(r["quote"].split()[:4])
            i = live.find(frag)
            print("    retry with 4 words %-40r -> offset %s" % (frag[:38], i))
        if i > 0:
            print("    context: %s" % re.sub(r"\s+", " ", live[max(0, i - 120):i + 220]))


if __name__ == "__main__":
    main()