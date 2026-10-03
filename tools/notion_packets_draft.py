"""Map harvested Notion prose pages to WKS classes and slice verified quotes.

The Notion pages carry NO title in their body -- `notion_render` writes
`# page <id>` -- and the api walk discarded the title, so routing cannot use it.
What the pages DO carry is their content, and the one page that did keep a title
proves the titles are what a hunter would file under ("Privilege Escalation",
"Active Directory", "Enumeration").

So routing is by CONTENT, scored the same way as the GitBook books: IDF over the
class vocabulary, requiring a margin over the runner-up. A page whose text does
not carry enough class vocabulary is UNMAPPED, and reported -- not guessed onto
the nearest class, which is how a wifi page ends up filed under IDOR.
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
from wks import config, relevance, store, verify_quotes  # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
STOP = {"the", "and", "for", "with", "from", "that", "this", "how", "using",
        "into", "a", "an", "of", "to", "in", "on", "is", "are", "be", "at", "by",
        "it", "or", "as", "not", "no", "you", "your", "we", "can", "will", "when",
        "what", "attack", "attacks", "hunt", "hunting", "test", "testing",
        "method", "methods", "methodology", "approach", "guide", "tips",
        "trick", "tricks", "bug", "bugs", "step", "steps", "part", "use",
        "using", "find", "finding", "learn", "check", "section", "page",
        "note", "notes", "response", "request", "server", "target"}


def toks(s):
    return {t for t in re.sub(r"[^a-z0-9]+", " ", (s or "").lower()).split()
            if t not in STOP and len(t) >= 3}


def load():
    con = store.connect()
    docs, raw = [], {}
    for cid, name, aliases, summary in con.execute(
            "SELECT id,name,aliases,summary FROM bug_class"):
        v = toks("%s %s %s" % (cid.replace("_", " "), name, aliases or ""))
        docs.append(v)
        raw[cid] = {"vocab": v, "summ": toks(summary or "")}
    n = len(docs)
    df = collections.Counter(t for d in docs for t in d)
    idf = {t: math.log(n / (1.0 + c)) for t, c in df.items()}
    for c in raw.values():
        c["idf"] = idf
    return list(raw.values()), con


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dir", required=True)
    ap.add_argument("--index", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--per-class", type=int, default=3)
    ap.add_argument("--quotes-per-page", type=int, default=3)
    ap.add_argument("--margin", type=float, default=0.8)
    ap.add_argument("--min-score", type=float, default=3.0)
    a = ap.parse_args()

    classes, con = load()
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
        if len(pt) < 20:
            unmapped.append((pid, "too little text"))
            continue
        ranked = []
        for c in classes:
            sc = sum(c["idf"].get(t, 0.0) for t in pt & c["vocab"])
            sc += 0.3 * len(pt & c["summ"])
            ranked.append((sc, c))
        ranked.sort(key=lambda x: -x[0])
        if not ranked or ranked[0][0] < a.min_score:
            unmapped.append((pid, "score %.1f < %.1f"
                             % (ranked[0][0] if ranked else 0, a.min_score)))
            continue
        if len(ranked) > 1 and ranked[0][0] - ranked[1][0] < a.margin:
            unmapped.append((pid, "ambiguous (%.1f vs %s)"
                             % (ranked[0][0], ranked[1][0])))
            continue
        cid = ranked[0][0] and ranked[0][1]["vocab"] and None
        cid = None
        # recover the class id from the vocab object
        for k, c in classes.__class__ and [] or []:
            pass
        unmapped.append((pid, "internal"))
        break

    print("probe only -- routing logic validated next")


if __name__ == "__main__":
    main()