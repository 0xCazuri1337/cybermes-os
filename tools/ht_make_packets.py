"""Build HARVEST PACKETS: (class, HackTricks page) -> REAL quotes, no invented claims.

MEASURED DEFECT in the first version of this tool, and the reason it was rewritten:
a claim built by TEMPLATE from a page title ("wifi tools reference is the
practical test for idor") passes the topic gate and is nonsense. The gate returns
ON_TOPIC on any own-vocabulary hit -- by design, to protect genuine knowledge --
so a template that pastes the anchor in is guaranteed to pass. The gate cannot
tell a real claim from a padded one; only reading the evidence can.

So this tool never writes a claim. It writes the EVIDENCE:

    packet[class][page] = [quote, quote, quote, ...]

each quote sliced verbatim out of the cached page and already asserted with the
gate's own matcher. A claim is then authored from a real quote, and the packet
carries the class vocabulary that a good claim must use. The parent re-checks
every authored claim before it is allowed near the db.

Usage:
    python tools/ht_make_packets.py --classes idor,xss --per-class 4 \
        --out research/ht_packets_web.json
"""
import argparse
import collections
import json
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from wks import config, relevance, store, verify_quotes  # noqa: E402
import ht_build_items as B  # noqa: E402
import ht_fetch  # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
XWALK = os.path.join(ROOT, "research", "ht_crosswalk.json")
MIN_PARTNER_CHARS = 110
HT_MARKERS = ("hacktricks.wiki", "HackTricks-wiki/hacktricks")


def is_ht(s):
    return any(m in s for m in HT_MARKERS)


def load_partners(con):
    """class -> recycled, ALREADY-VERIFIED quotes from promoted items.

    Nothing here is typed by us: every quote already promoted on that publisher,
    so it is known to exist verbatim on that page. GitHub and HackTricks are
    excluded because each collapses to one org and would self-corroborate.
    """
    per = collections.defaultdict(list)
    for cid, url, host, quote in con.execute(
            "SELECT i.class_id, s.url, s.host, x.quote"
            "  FROM item i"
            "  JOIN quality qq ON qq.item_id=i.id"
            "  JOIN item_source x ON x.item_id=i.id"
            "  JOIN source s ON s.id=x.source_id"
            " WHERE qq.validation_state='high_confidence'"
            "   AND x.quote IS NOT NULL AND length(x.quote) >= ?", (MIN_PARTNER_CHARS,)):
        if is_ht(url):
            continue
        if config.publisher_org(host) == config.publisher_org("github.com"):
            continue
        per[cid].append({"url": url, "host": host, "quote": quote,
                         "org": config.publisher_org(host)})
    for cid in per:
        seen, uniq = set(), []
        for p in sorted(per[cid], key=lambda p: -len(p["quote"])):
            k = (p["url"], p["quote"][:60])
            if k not in seen:
                seen.add(k)
                uniq.append(p)
        per[cid] = uniq
    return per


def score_sentence(s, cid):
    """How much class vocabulary does this sentence actually carry?"""
    n = re.sub(r"[^a-z0-9]+", " ", s.lower())
    v = relevance.assess(cid, n)
    own = set(v.own_hits) if v else set()
    # prefer sentences with a mechanism term, not just the class acronym
    strong = [h for h in own if len(h.split()) > 1 or len(h) > 4]
    return (len(strong), len(own), len(s)), own, strong


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--classes", required=True)
    ap.add_argument("--per-class", type=int, default=4)
    ap.add_argument("--quotes-per-page", type=int, default=4)
    ap.add_argument("--out", required=True)
    a = ap.parse_args()

    con = store.connect()
    with open(XWALK, encoding="utf-8") as fh:
        xwalk = json.load(fh)
    by_class = collections.defaultdict(list)
    for p in xwalk["MATCHED"]:
        by_class[p["cls"]].append(p)

    partners = load_partners(con)
    want = [c.strip() for c in a.classes.split(",") if c.strip()]

    packets, skipped = {}, []
    idx = ht_fetch.load_index()

    for n, cid in enumerate(want):
        pages = sorted(by_class.get(cid, []), key=lambda p: p["rel"])
        if not pages:
            skipped.append((cid, "no HackTricks page mapped to this class"))
            continue
        if not partners.get(cid):
            skipped.append((cid, "no non-GitHub promoted partner quote available"))
            continue
        pool = partners[cid]
        entries = []
        for pi, p in enumerate(pages):
            if len(entries) >= a.per_class:
                break
            text, status = ht_fetch.get(p["rel"], idx)
            if not text or len(text) < ht_fetch.MIN_BYTES:
                continue
            prose = B.to_text(text)
            cands = []
            for s in B.sentences(prose):
                sc, own, strong = score_sentence(s, cid)
                if not own:
                    continue          # sentence says nothing about this class
                cands.append((sc, s, own, strong))
            if not cands:
                continue
            cands.sort(key=lambda x: -x[0][0])
            picked, seen = [], set()
            for _sc, s, own, strong in cands:
                key = s[:70]
                if key in seen:
                    continue
                seen.add(key)
                if not verify_quotes.find_quote(text, s):
                    continue          # R2: never ship a quote the gate refuses
                picked.append({"quote": s, "class_terms": sorted(strong) or sorted(own)})
                if len(picked) >= a.quotes_per_page:
                    break
            if not picked:
                continue
            part = pool[(n + pi) % len(pool)]
            entries.append({
                "page": p["rel"],
                "title": p["title"],
                "section": p["section"],
                "url": ht_fetch.RAW % p["rel"],
                "quotes": picked,
                # recycled partner: already verified on that publisher
                "partner": {"url": part["url"], "quote": part["quote"],
                            "org": part["org"]},
            })
        if not entries:
            skipped.append((cid, "no page yielded a class-relevant verifiable quote"))
        else:
            packets[cid] = entries
    ht_fetch.save_index(idx)

    with open(a.out, "w", encoding="utf-8") as fh:
        json.dump({"vocab": {c: sorted(relevance.CLASS_VOCAB.get(c, []))
                             for c in packets},
                   "packets": packets}, fh, indent=1)

    total_q = sum(len(e["quotes"]) for v in packets.values() for e in v)
    print("wrote %s" % a.out)
    print("  %d classes, %d pages, %d VERIFIED quotes"
          % (len(packets), sum(len(v) for v in packets.values()), total_q))
    for cid, why in skipped:
        print("  SKIP %-26s %s" % (cid, why))
    print("\nper class pages: %s"
          % {c: len(v) for c, v in sorted(packets.items())})


if __name__ == "__main__":
    sys.exit(main())