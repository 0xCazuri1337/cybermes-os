"""Exactly which 3 items failed live re-verification, and why.

ht_diag3 over-selected: it queried every quote on that OWASP url across the WHOLE
corpus (7 distinct quotes, most of them pre-existing and already promoted), not
the 3 the live verifier actually flagged. This walks the same set the verifier
walked and prints only the failures, with each quote's provenance:

  - which item, filed under which class
  - whether that EXACT quote already backs a pre-existing promoted item
    (if yes, the gate has trusted it before and this is an upstream rewrite)
  - whether it matches a PINNED git tag of the same document
"""
import os
import re
import subprocess
import sys
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import ht_build_items as B  # noqa: E402
from wks import store, verify_quotes as V  # noqa: E402

UA = {"User-Agent": "Mozilla/5.0 (compatible; wks-research/1.0)"}
OWASP_LIVE = ("https://cheatsheetseries.owasp.org/cheatsheets/"
              "Cross_Site_Scripting_Prevention_Cheat_Sheet.html")
OWASP_PINNED = ("https://raw.githubusercontent.com/OWASP/CheatSheetSeries/"
                "v4.2/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.md")


def get(u):
    try:
        req = urllib.request.Request(u, headers=UA)
        return urllib.request.urlopen(req, timeout=45).read().decode("utf-8", "replace")
    except Exception as e:                                       # noqa: BLE001
        print("   fetch failed %s: %s" % (u[:60], e))
        return ""


def main():
    con = store.connect()
    rows = list(con.execute(
        "SELECT i.id, i.class_id, i.item_key, s.url, s.host, x.quote"
        "  FROM item i"
        "  JOIN quality q ON q.item_id=i.id"
        "  JOIN item_source x ON x.item_id=i.id"
        "  JOIN source s ON s.id=x.source_id"
        " WHERE q.validation_state='high_confidence'"
        "   AND i.item_key LIKE '%.ht_%'"
        "   AND s.host NOT LIKE '%githubusercontent%'"))
    print("non-HackTricks sources on ht_* items: %d" % len(rows))
    print("distinct urls: %s" % sorted({r["url"] for r in rows}))

    live = get(OWASP_LIVE)
    prose = B.fetch_html(OWASP_LIVE)
    pinned = get(OWASP_PINNED)

    fails = 0
    for r in rows:
        if "Cross_Site_Scripting_Prevention" not in r["url"]:
            continue
        q = r["quote"] or ""
        a = V.find_quote(prose, q)
        b = V.find_quote(pinned, q) if pinned else False
        if a:
            continue
        fails += 1
        print()
        print("=" * 74)
        print("FAIL %d  %s" % (fails, r["item_key"]))
        print("  class        : %s" % r["class_id"])
        print("  quote        : %s" % q[:170])
        print("  live prose   : %s" % a)
        print("  pinned v4.2  : %s" % b)
        trusted = con.execute(
            "SELECT i.item_key FROM item_source x"
            " JOIN source s ON s.id=x.source_id"
            " JOIN item i ON i.id=x.item_id"
            " JOIN quality qq ON qq.item_id=i.id"
            " WHERE x.quote=? AND qq.validation_state='high_confidence'"
            "   AND i.item_key NOT LIKE '%.ht_%' LIMIT 3", (q,)).fetchall()
        print("  already promoted elsewhere: %s"
              % ([t["item_key"] for t in trusted] or "NONE"))
        frag = " ".join(q.split()[:5])
        i = live.find(frag)
        print("  fragment in raw html: offset %s" % i)
        if i > 0:
            print("  context: %s" % re.sub(r"\s+", " ", live[max(0, i - 100):i + 200]))

    print()
    print("OWASP failures needing a decision: %d" % fails)
    if fails == 0:
        print("VERDICT: CLEAN -- the earlier 3 were a verifier artefact, not bad data")


if __name__ == "__main__":
    main()