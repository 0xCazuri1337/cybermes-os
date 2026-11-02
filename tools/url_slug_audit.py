"""Audit: does any promoted quote carry class vocabulary ONLY inside a URL slug?

MEASURED motivation: a child authoring Biscuit claims reported that `sqli` and
`authn` candidates had `class_terms_in_quote` hits on words like `boolean-based`,
`time-based` and `password` that appeared ONLY inside article URL slugs, never in
prose -- and rejected them rather than let the class_id pad them in. That is the
right call, and it raises a question about everything already promoted:

    is any item in the corpus resting on vocabulary that lives in a URL?

That failure mode is quiet. The quote is verbatim and the claim reads correctly,
but the only reason it filed under `sqli` is that the page's outbound link said
`boolean-based-sqli`. The URL would verify. The class would still be wrong.

Test: for each promoted item, strip every URL and every markdown link target from
the quote, then re-check whether the claim's class vocabulary still appears. An
item whose vocabulary survives only before stripping is resting on the URL.

Reports; does not modify anything.
"""
import collections
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from wks import relevance, store  # noqa: E402

URLISH = re.compile(
    r"https?://\S+|www\.\S+|\b[\w-]+\.(?:com|org|net|io|blog|md|ru|me|xyz|"
    r"co|dev|app|site|page|post|guide|tutorial)\b(?:/\S*)?",
    re.I)
MDLINK = re.compile(r"\]\([^)]*\)")
SLUGISH = re.compile(r"(?:^|[\s/\-])(?:\d{2,}-)*[a-z]+(?:[-_][a-z0-9]{2,})+"
                     r"(?:[\s/\-]|$)")


def strip_urls(q):
    q = MDLINK.sub("]", q)
    q = URLISH.sub(" ", q)
    q = SLUGISH.sub(" ", q)
    return q


def main():
    con = store.connect()
    rows = list(con.execute(
        "SELECT i.id, i.class_id, i.claim, x.quote, s.host"
        "  FROM item i"
        "  JOIN quality q ON q.item_id=i.id"
        "  JOIN item_source x ON x.item_id=i.id"
        "  JOIN source s ON s.id=x.source_id"
        " WHERE q.validation_state='high_confidence' AND i.status='active'"))
    per_item = collections.defaultdict(dict)
    for r in rows:
        per_item[r["id"]]["class"] = r["class_id"]
        per_item[r["id"]].setdefault("quotes", []).append(r["quote"] or "")
        per_item[r["id"]].setdefault("claims", []).append(r["claim"] or "")

    at_risk = []
    for iid, d in per_item.items():
        cid = d["class"]
        vocab = relevance.CLASS_VOCAB.get(cid) or []
        if not vocab:
            continue
        claim = d["claims"][0]
        joined = " ".join(d["quotes"])
        clean = strip_urls(joined)

        def hits(text):
            out = []
            for t in vocab:
                rx = re.escape(t).replace(r"\ ", r"\s+")
                if re.search(r"(?<![a-z0-9])" + rx + r"(?![a-z0-9])",
                             text, re.I):
                    out.append(t)
            return out

        h_full = hits(joined)
        h_clean = hits(clean)
        # vocabulary that exists only before URL stripping
        lost = [t for t in h_full if t not in h_clean]
        if lost and not h_clean:
            at_risk.append((cid, claim[:70], lost))
        elif len(lost) >= 2:
            at_risk.append((cid, claim[:70], lost))

    print("=" * 76)
    print("URL-SLUG VOCABULARY AUDIT")
    print("=" * 76)
    print("  promoted items examined        : %d" % len(per_item))
    print("  items whose class vocabulary  : %d" % len(at_risk))
    print("  appears ONLY inside a URL/slug  :")
    if not at_risk:
        print("     none -- every item's class rests on prose, not on a link slug")
    for cid, claim, lost in at_risk[:15]:
        print("     %-18s %-58s %s" % (cid, claim, lost))


if __name__ == "__main__":
    main()