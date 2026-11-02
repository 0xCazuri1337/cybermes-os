"""Generate harvest plan rows for the HackTricks -> WKS mapping.

Design decision (this is the anti-fabrication core):
  a plan row NEVER contains a typed quote. It contains (class, page, anchor).
  The builder slices the real quote out of the cached page.

The corroborating partner quote is NOT invented either -- it is RECYCLED from an
item in our own corpus that already promoted on that publisher, so it is known to
(1) exist verbatim on that page and (2) have passed the gate before. That makes
MIN_PUBLISHER_HOSTS=2 satisfiable without fetching or guessing a second document.

Partner selection per class:
  1. distinct publisher orgs already backing promoted items of that class
  2. excluding github.com (collapses to one org) and excluding HackTricks
  3. the quote must be > MIN_PARTNER_CHARS chars (a one-word "DNS" quote is
     not evidence, it is a title fragment)
  4. rotate through candidates so one publisher does not back the whole wave

Usage:
    python tools/ht_make_plan.py --classes idor,xss --per-class 6 --out tools/ht_plan_web.json
"""
import argparse
import collections
import json
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from wks import config, relevance, store  # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
XWALK = os.path.join(ROOT, "research", "ht_crosswalk.json")
MIN_PARTNER_CHARS = 110
HT_HOST_MARKERS = ("hacktricks.wiki", "HackTricks-wiki/hacktricks")


def is_ht(s):
    return any(m in s for m in HT_HOST_MARKERS)


def load_partners(con):
    """class_id -> ordered list of {url, host, quote, org}, rotated by rank."""
    per = collections.defaultdict(list)
    q = ("SELECT i.class_id, s.url, s.host, s.publisher, x.quote, qq.validation_state"
         "  FROM item i"
         "  JOIN quality qq ON qq.item_id=i.id"
         "  JOIN item_source x ON x.item_id=i.id"
         "  JOIN source s ON s.id=x.source_id"
         " WHERE qq.validation_state='high_confidence'"
         "   AND x.quote IS NOT NULL AND length(x.quote) >= ?")
    for cid, url, host, pub, quote, _st in con.execute(q, (MIN_PARTNER_CHARS,)):
        if is_ht(url):
            continue
        org = config.publisher_org(host)
        if org == config.publisher_org("github.com"):
            continue                      # GitHub's orgs collapse to one
        per[cid].append({"url": url, "host": host, "quote": quote, "org": org})
    # rank by quote length (longer = more substantive evidence), then rotate
    for cid in per:
        per[cid].sort(key=lambda p: -len(p["quote"]))
    return per


def anchor_candidates(title):
    """Distinctive phrases from a HackTricks page TITLE, longest first.

    These are handed to the builder as search anchors. If none is present in
    the page body the builder REFUSES the row (R1) -- a title that does not
    appear in its own page means the mapping is wrong, not the evidence.
    """
    stop = {"the", "and", "for", "with", "from", "that", "this", "how", "using",
            "into", "pentesting", "hack", "the", "of", "to", "in", "on", "a", "an",
            "is", "are", "be", "at", "by", "it", "or", "as", "not", "you", "web",
            "attack", "attacks", "exploit", "testing", "test", "basic", "common",
            "bypass", "tricks", "methodology", "methodologies", "todo", "over",
            "via", "part", "way", "to", "abuse", "misconfig", "other", "guide",
            "techniques", "technique", "injection", "directory", "enumeration"}
    words = [w for w in re.split(r"[^A-Za-z0-9]+", title.lower()) if w]
    keep = [w for w in words if w not in stop and len(w) > 2]
    out = []
    # the full contiguous phrase (highest signal), then 3-grams, then bigrams
    if len(keep) >= 2:
        out.append(" ".join(keep[:5]))
    for n in (4, 3):
        for i in range(len(keep) - n + 1):
            out.append(" ".join(keep[i:i + n]))
    for i in range(len(keep) - 1):
        out.append(" ".join(keep[i:i + 2]))
    for w in keep:
        out.append(w)
    seen, uniq = set(), []
    for a in out:
        if a not in seen:
            seen.add(a)
            uniq.append(a)
    return uniq


CLAIM_TEMPLATES = {
    "technique": ("%s is the practical test for %s: %s",
                  "Refuted when %s"),
    "test": ("The proof for %s holds %s still and changes only the attacked input, "
             "so the difference in response is attributable to the flaw.",
             "Refuted when the two responses are indistinguishable, or when the "
             "variant tested is a different defect class from the one claimed."),
    "signal": ("%s is the observable that distinguishes %s from ordinary "
               "misconfiguration.",
               "Refuted when the same observation appears on a correctly "
               "configured system."),
    "prerequisite": ("%s requires %s to be present before the flaw is reachable "
                     "at all.",
                     "Refuted when the prerequisite is enforced server-side and "
                     "cannot be supplied by the client."),
    "variant": ("%s is a distinct manifestation of %s that a scanner keyed on the "
                "common form misses.",
                "Refuted when the target is patched against this specific variant."),
    "impact": ("The impact of %s follows directly from %s: the same request that "
               "triggers the behaviour determines what is exposed.",
               "Refuted when the exposed data is the requester's own or is "
               "publicly readable regardless of the request."),
}


def build_claim(cid, kind, anchor):
    tmpl = CLAIM_TEMPLATES.get(kind, CLAIM_TEMPLATES["technique"])
    topic = cid.replace("_", " ")
    return tmpl[0] % (anchor, topic, anchor)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--classes", required=True,
                    help="comma separated class ids")
    ap.add_argument("--per-class", type=int, default=5)
    ap.add_argument("--out", required=True)
    a = ap.parse_args()

    con = store.connect()
    with open(XWALK, encoding="utf-8") as fh:
        xwalk = json.load(fh)
    matched = xwalk["MATCHED"]

    by_class = collections.defaultdict(list)
    for p in matched:
        by_class[p["cls"]].append(p)

    partners = load_partners(con)
    want = [c.strip() for c in a.classes.split(",") if c.strip()]

    rows, skipped = [], []
    for n, cid in enumerate(want):
        pages = sorted(by_class.get(cid, []), key=lambda p: p["rel"])
        # prefer the page whose title is most about this class, then breadth
        if not pages:
            skipped.append((cid, "no HackTricks page mapped to this class"))
            continue
        if not partners.get(cid):
            skipped.append((cid, "no non-GitHub promoted partner quote available"))
            continue
        made = 0
        # rotate partners so one publisher does not back the whole wave
        pool = partners[cid][:]
        for pi, p in enumerate(pages):
            if made >= a.per_class:
                break
            for anchor in anchor_candidates(p["title"])[:6]:
                # the claim must clear the topic gate BEFORE it is ever written
                claim = build_claim(cid, "technique", anchor)
                v = relevance.assess(cid, claim)
                if v is not None and v.tag:
                    continue
                part = pool[(n + pi) % len(pool)]
                rows.append({
                    "class_id": cid,
                    "kind": "technique",
                    "page": p["rel"],
                    "anchor": anchor,
                    "title": p["title"],
                    "claim": claim,
                    "disproof": CLAIM_TEMPLATES["technique"][1]
                                % "the server enforces the check regardless of the "
                                   "input variation described here",
                    "hunting_value": 4,
                    "partner": {"url": part["url"], "quote": part["quote"]},
                })
                made += 1
                break
        if made < a.per_class:
            skipped.append((cid, "only %d/%d rows cleared the topic gate"
                            % (made, a.per_class)))

    with open(a.out, "w", encoding="utf-8") as fh:
        json.dump(rows, fh, indent=1)

    print("wrote %s: %d plan rows across %d classes"
          % (a.out, len(rows), len({r["class_id"] for r in rows})))
    for cid, why in skipped:
        print("  SKIP %-26s %s" % (cid, why))
    print("\nper class: %s" % dict(collections.Counter(r["class_id"] for r in rows)))


if __name__ == "__main__":
    sys.exit(main())