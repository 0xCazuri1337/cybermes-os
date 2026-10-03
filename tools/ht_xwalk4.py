"""Crosswalk HackTricks SUMMARY.md -> WKS bug_class. Report-only, no writes.

v4. Three defects fixed against v3, each measured by probing real paths:

  D1  stem_key() split a filename on '-' and kept the first token, so
      "file-integrity-monitoring.md" scored an exact 99.0 against class
      `file_upload` (stem "file"). Stems are now whole normalised names.
  D2  purely lexical scoring misrouted four paths a human would not
      (DNS -> subdomain_takeover, AD root -> password_attacks, ...).
      A hand-verified ANCHOR table overrides the scorer.
  D3  a single generic token in an alias routed a whole subtree: `file_upload`
      lists the alias "web shell upload", so the token "web" captured 51
      unrelated pages under network-services-pentesting/pentesting-web/.
      Tokens are now IDF-weighted over the class vocabulary and a page must
      beat the RUNNER-UP by a margin -- a word shared by every class cannot
      decide a route.

Buckets: MATCHED (anchored/direct/inherited), UNMAPPED (gap candidate),
OUT_OF_SCOPE (HackTricks section outside the requested scope).
"""
import collections
import json
import math
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from wks import store  # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
# Absolute default: a bare relative path resolves against $PWD, and this host has
# a habit of exporting an MSYS /tmp path that native python cannot open.
SUMMARY = os.environ.get("HT_SUMMARY") or os.path.join(ROOT, "research",
                                                       "ht_summary.md")
MATCH_MIN = float(os.environ.get("MATCH_MIN", "2.0"))
MARGIN = float(os.environ.get("MATCH_MARGIN", "1.0"))

# Verified by hand: (path, class_id, why)
ANCHORS = {
    "network-services-pentesting/pentesting-dns.md": "dns_enum",
    "network-services-pentesting/pentesting-ldap.md": "ldap_enum",
    "windows-hardening/active-directory-methodology/README.md": "ad_enumeration",
    "windows-hardening/active-directory-methodology/adws-enumeration.md": "ad_enumeration",
    # HackTricks merges our two classes in ONE directory; our taxonomy splits them.
    "pentesting-web/cache-deception/README.md": "cache_deception",
    "pentesting-web/cache-deception/cache-poisoning-via-url-discrepancies.md": "cache_poisoning",
    "pentesting-web/cache-deception/cache-poisoning-to-dos.md": "cache_poisoning",
}
SPLIT_RULES = [
    ("pentesting-web/cache-deception/", "cache poisoning", "cache_poisoning"),
    ("pentesting-web/cache-deception/", None, "cache_deception"),
]

IN_SCOPE = {
    "pentesting-web": "web",
    "network-services-pentesting": "network",
    "windows-hardening": "network",
    "linux-hardening": "network",
    "generic-methodologies-and-resources": "network",
}
OUT_OF_SCOPE = (
    "binary-exploitation", "mobile-pentesting", "todo", "stego",
    "hardware-physical-access", "blockchain", "reversing", "privacy",
    "generic-hacking", "crypto", "AI", "macos-hardening", "welcome",
)
STOP = {
    "the", "and", "for", "with", "from", "that", "this", "how", "using", "into",
    "a", "an", "of", "to", "in", "on", "is", "are", "be", "at", "by", "it",
    "or", "as", "not", "no", "you", "your", "we", "can", "will", "when", "what",
    "attack", "attacks", "attacking", "pentest", "pentesting", "hack", "hacking",
    "test", "testing", "exploit", "exploiting", "vuln", "vulnerability",
    "vulnerabilities", "security", "misc", "other", "intro", "index", "readme",
    "summary", "todo", "checklist", "basic", "useful", "common", "generic",
    "methodology", "methodologies", "resources", "tricks", "bypass", "less",
    "than", "greater", "over", "under", "part", "way", "things", "stuff",
    "tutorial", "introduction", "guide", "note", "notes", "main", "page",
}


def norm(s):
    return re.sub(r"[^a-z0-9]+", " ", s.lower()).strip()


def toks(s, minlen=2):
    return {t for t in norm(s).split() if t not in STOP and len(t) >= minlen}


def full_stem(path):
    name = os.path.basename(path)
    if name.lower() == "readme.md":
        name = os.path.basename(os.path.dirname(path)) + ".md"
    if name.lower().endswith(".md"):
        name = name[:-3]
    return norm(name)


def parse_summary(path):
    pages, stack = [], []
    with open(path, encoding="utf-8") as fh:
        for raw in fh:
            m = re.match(r"^(\s*)[-*]\s+\[(.+?)\]\((.+?\.md)\)\s*$", raw)
            if not m:
                continue
            depth = len(m.group(1)) // 2
            stack = stack[:depth]
            p = {"title": m.group(2), "rel": m.group(3),
                 "section": m.group(3).split("/")[0], "depth": depth,
                 "parent": stack[-1]["rel"] if stack else None}
            stack.append(p)
            pages.append(p)
    return pages


def load_classes(con):
    """Return classes plus an IDF table over their name/alias vocabulary."""
    docs = []
    raw = {}
    for cid, name, summary, aliases in con.execute(
            "SELECT id,name,summary,aliases FROM bug_class"):
        dom = con.execute("SELECT domain FROM class_domain WHERE class_id=?",
                          (cid,)).fetchone()
        vocab = toks("%s %s %s" % (cid.replace("_", " "), name, aliases or ""))
        docs.append(vocab)
        raw[cid] = {
            "id": cid, "name": name,
            "domain": dom[0] if dom else None,
            "surface": con.execute("SELECT surface FROM bug_class WHERE id=?",
                                   (cid,)).fetchone()[0],
            "stem": norm(cid), "vocab": vocab, "summ_tok": toks(summary or ""),
        }
    n = len(docs)
    df = collections.Counter(t for d in docs for t in d)
    idf = {t: math.log(n / (1.0 + c)) for t, c in df.items()}
    for c in raw.values():
        c["idf"] = {t: idf[t] for t in c["vocab"]}
    return list(raw.values()), idf, n


def score(page, classes):
    """(class_id, score, runner_up_score). Only a whole-stem match scores 99."""
    pt, fs = toks(page["title"]), full_stem(page["rel"])
    ranked = []
    for c in classes:
        if fs and fs in (c["stem"], c["stem"].replace(" ", "")):
            sc = 99.0
        else:
            sc = sum(c["idf"].get(t, 0.0) for t in pt & c["vocab"])
            sc += 0.25 * sum(1.0 for t in pt & c["summ_tok"])
        ranked.append((sc, c["id"]))
    ranked.sort(reverse=True)
    best = ranked[0]
    second = ranked[1][0] if len(ranked) > 1 else 0.0
    if best[0] < MATCH_MIN or (best[0] - second) < MARGIN:
        return None, best[0], second
    return best[1], best[0], second


def apply_split(page):
    for prefix, needle, cid in SPLIT_RULES:
        if page["rel"].startswith(prefix):
            if needle and needle in norm(page["title"]):
                return cid
            if needle is None:
                return cid
    return None


def main():
    con = store.connect()
    classes, idf, n = load_classes(con)
    pages = parse_summary(SUMMARY)
    by_rel = {p["rel"]: p for p in pages}
    registered = {c["id"] for c in classes}
    print("HackTricks pages: %d unique files in SUMMARY" % len(pages))
    print("WKS classes: %d   (IDF over class name/alias vocabulary, "
          "margin=%s)" % (n, MARGIN))
    print()

    bad_anchor, anchor_hits = [], 0
    for p in pages:
        if p["section"] in OUT_OF_SCOPE:
            p["bucket"] = "OUT_OF_SCOPE"
            continue
        cid = ANCHORS.get(p["rel"]) or apply_split(p)
        if cid:
            if cid in registered:
                p.update(bucket="MATCHED", cls=cid, score=100.0, via="anchor")
                anchor_hits += 1
            else:
                bad_anchor.append((p["rel"], cid))
            continue
        cid, sc, second = score(p, classes)
        if cid:
            p.update(bucket="MATCHED", cls=cid, score=sc, via="direct")
            continue
        anc = p["parent"]
        while anc:
            a = by_rel.get(anc)
            if a and a.get("bucket") == "MATCHED":
                p.update(bucket="MATCHED", cls=a["cls"], score=0.0,
                         via="inherited<-%s" % a["rel"])
                break
            anc = a["parent"] if a else None
        else:
            p["bucket"] = "UNMAPPED"

    if bad_anchor:
        print("!! ANCHORS POINTING AT UNREGISTERED CLASSES:")
        for rel, cid in bad_anchor:
            print("   %-24s %s" % (cid, rel))
        print()

    b = collections.defaultdict(list)
    for p in pages:
        b[p["bucket"]].append(p)
    print("=" * 78)
    print("BUCKET COUNTS")
    for k in ("MATCHED", "UNMAPPED", "OUT_OF_SCOPE"):
        print("  %-14s %d" % (k, len(b[k])))
    print("  (matched: %d anchor, %d direct, %d inherited)"
          % (anchor_hits,
             sum(1 for p in b["MATCHED"] if p["via"] == "direct"),
             sum(1 for p in b["MATCHED"] if p["via"].startswith("inherited"))))
    print()

    items = dict(con.execute(
        "SELECT class_id, COUNT(*) FROM item WHERE status='active' GROUP BY class_id"))
    hosts = collections.defaultdict(set)
    for cid, h in con.execute(
            "SELECT i.class_id, s.host FROM item i JOIN item_source x ON x.item_id=i.id "
            "JOIN source s ON s.id=x.source_id WHERE i.status='active'"):
        hosts[cid].add(h)

    print("=" * 78)
    print("PER-CLASS HackTricks COVERAGE")
    byc = collections.defaultdict(list)
    for p in b["MATCHED"]:
        byc[p["cls"]].append(p)
    for cid, ps in sorted(byc.items(), key=lambda x: -len(x[1])):
        c = next(c for c in classes if c["id"] == cid)
        print("  %-26s %3dp  items=%3d  hosts=%2d  dom=%s"
              % (cid, len(ps), items.get(cid, 0), len(hosts.get(cid, ())),
                 c["domain"] or "via-surface(%s)" % c["surface"]))
        print("      %s" % dict(collections.Counter(p["section"] for p in ps)))

    print()
    print("=" * 78)
    print("CLASSES WITH ZERO HackTricks PAGES")
    for c in sorted(classes, key=lambda c: c["id"]):
        if c["id"] not in byc:
            print("  %-26s items=%3d  hosts=%2d  dom=%s"
                  % (c["id"], items.get(c["id"], 0), len(hosts.get(c["id"], ())),
                     c["domain"] or "via-surface(%s)" % c["surface"]))

    print()
    print("=" * 78)
    print("GAP CANDIDATES: %d unmapped in-scope pages" % len(b["UNMAPPED"]))
    gs = collections.defaultdict(list)
    for p in b["UNMAPPED"]:
        gs[p["section"]].append(p)
    for sec in sorted(gs, key=lambda s: -len(gs[s])):
        ps = sorted(gs[sec], key=lambda p: (p["depth"], p["title"]))
        tops = [p for p in ps if p["depth"] <= 1]
        print("\n-- %s  (%d pages) -> target domain %s"
              % (sec, len(ps), IN_SCOPE.get(sec)))
        for p in tops:
            print("   d%d  %s" % (p["depth"], p["title"]))
        if len(ps) > len(tops):
            print("      (+%d deeper children)" % (len(ps) - len(tops)))

    out = os.path.join(ROOT, "research", "ht_crosswalk.json")
    with open(out, "w", encoding="utf-8") as f:
        json.dump(dict(b), f, indent=1)
    print("\nwrote %s" % out)


if __name__ == "__main__":
    main()