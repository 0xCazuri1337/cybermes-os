"""Map harvested Notion prose pages to WKS classes and slice verified quotes.

The harvested pages carry NO usable title: `notion_render` writes `# page <id>`
and the api walk discarded the page titles, so routing cannot use them. What the
pages do carry is CONTENT, and the one page that kept a title shows the titles
are exactly what a hunter files under ("Privilege Escalation", "Active
Directory", "Enumeration").

So routing is by CONTENT: IDF over the class vocabulary, requiring both an
absolute score and a margin over the runner-up. A page that does not carry enough
class vocabulary is UNMAPPED and reported -- never guessed onto the nearest class,
which is how a wifi page ends up filed under IDOR.

Partner quotes are RECYCLED from already-promoted corpus items on normative
registrable domains (tools/twopart.py). Notion is a practice guide, so it is not
counted as a publisher and needs TWO independent normative orgs -- the same rule
HowToHunt hit.
"""
import argparse
import collections
import json
import math
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import ht_build_items as B       # noqa: E402
import ht_verify2 as V2          # noqa: E402
import twopart                   # noqa: E402
from wks import config, relevance, verify_quotes  # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
STOP = {"the", "and", "for", "with", "from", "that", "this", "how", "using",
        "into", "a", "an", "of", "to", "in", "on", "is", "are", "be", "at", "by",
        "it", "or", "as", "not", "no", "you", "your", "we", "can", "will", "when",
        "what", "attack", "attacks", "hunt", "hunting", "test", "testing",
        "method", "methods", "methodology", "approach", "guide", "tips",
        "trick", "tricks", "bug", "bugs", "step", "steps", "part", "use",
        "using", "find", "finding", "learn", "check", "section", "page",
        "note", "notes"}


def toks(s):
    return {t for t in re.sub(r"[^a-z0-9]+", " ", (s or "").lower()).split()
            if t not in STOP and len(t) >= 3}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dir", required=True)
    ap.add_argument("--index", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--per-class", type=int, default=3)
    ap.add_argument("--quotes-per-page", type=int, default=3)
    ap.add_argument("--margin", type=float, default=0.8)
    ap.add_argument("--min-score", type=float, default=4.0)
    a = ap.parse_args()

    from wks import store
    con = store.connect()
    classes = []
    for cid, name, aliases, summary in con.execute(
            "SELECT id,name,aliases,summary FROM bug_class"):
        classes.append({"cid": cid,
                        "vocab": toks("%s %s %s" % (cid.replace("_", " "), name,
                                                    aliases or "")),
                        "summ": toks(summary or "")})
    df = collections.Counter(t for c in classes for t in c["vocab"])
    n = len(classes)
    idf = {t: math.log(n / (1.0 + k)) for t, k in df.items()}

    tp = twopart.two_part(con)
    with open(a.index, encoding="utf-8") as fh:
        idx = json.load(fh)

    packets = collections.defaultdict(list)
    unmapped = []
    for pid, meta in idx.items():
        path = os.path.join(a.dir, meta["file"] + ".md")
        with open(path, encoding="utf-8") as fh:
            raw = fh.read()
        prose = B.to_text(raw)
        pt = toks(prose[:6000])
        if len(pt) < 25:
            unmapped.append((pid, "too little text (%d tokens)" % len(pt)))
            continue
        ranked = sorted(
            ((sum(idf.get(t, 0.0) for t in pt & c["vocab"])
              + 0.3 * len(pt & c["summ"]), c["cid"]) for c in classes),
            reverse=True)
        if ranked[0][0] < a.min_score:
            unmapped.append((pid, "score %.1f < %.1f" % (ranked[0][0], a.min_score)))
            continue
        if len(ranked) > 1 and ranked[0][0] - ranked[1][0] < a.margin:
            unmapped.append((pid, "ambiguous %.1f vs %s"
                             % (ranked[0][0], ranked[1][1])))
            continue
        cid = ranked[0][1]

        pool = [p for p in tp.get(cid, [])][:config.MIN_PUBLISHER_HOSTS + 1]
        if len(pool) < config.MIN_PUBLISHER_HOSTS:
            unmapped.append((pid, "%s has %d normative org(s)"
                             % (cid, len(pool))))
            continue

        picks, seen = [], set()
        for s in B.sentences(prose):
            if V2.has_furniture(s):
                continue
            v = relevance.assess(cid, s.lower())
            if v is None or not v.own_hits:
                continue
            if not verify_quotes.find_quote(raw, s):
                continue
            if s[:70] in seen:
                continue
            seen.add(s[:70])
            picks.append({"quote": s,
                          "class_terms": sorted(v.own_hits)})
            if len(picks) >= a.quotes_per_page:
                break
        if not picks:
            unmapped.append((pid, "no class-relevant verifiable quote"))
            continue
        packets[cid].append({
            "page": "notion:%s" % pid,
            "title": pid[:8],
            "section": "notion",
            "url": "https://tested-corleggy-562.notion.site/?pvs=4#%s" % pid,
            "quotes": picks,
            "partner": pool[0],
            "partner2": pool[1] if len(pool) > 1 else None,
        })

    for cid in list(packets):
        packets[cid] = packets[cid][:a.per_class]

    with open(a.out, "w", encoding="utf-8") as fh:
        json.dump({"vocab": {c: sorted(relevance.CLASS_VOCAB.get(c, []))
                             for c in packets},
                   "packets": dict(packets)}, fh, indent=1)
    nq = sum(len(e["quotes"]) for v in packets.values() for e in v)
    print("=" * 72)
    print("NOTION PACKETS from %s" % a.dir)
    print("=" * 72)
    print("  classes routed : %d" % len(packets))
    print("  pages routed   : %d" % sum(len(v) for v in packets.values()))
    print("  quotes         : %d (all asserted with find_quote)" % nq)
    print("  unmapped       : %d" % len(unmapped))
    for pid, why in unmapped[:12]:
        print("    %s  %s" % (pid[:8], why))
    print("\n  per class: %s" % {c: len(v) for c, v in sorted(packets.items())})
    print("wrote %s" % a.out)


if __name__ == "__main__":
    main()