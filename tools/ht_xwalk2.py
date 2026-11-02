"""Crosswalk HackTricks SUMMARY.md -> WKS bug_class. Report-only, no writes.

SUMMARY.md is a real table of contents (indentation = hierarchy), so the walk
uses that structure instead of pure title similarity:

  1. score a page against every class (stem / name / alias / summary)
  2. a page that scores nothing INHERITS its parent's mapping, because most
     HackTricks "unmapped" pages are deep children of a page that matched
     (e.g. the pages under .../pentesting-smb/ are all SMB)
  3. whatever is still unmapped is a gap candidate

Buckets:
  MATCHED      -> a registered class (direct or inherited)
  UNMAPPED     -> no class and no mappable parent; candidate for a NEW class
  OUT_OF_SCOPE -> a HackTricks section outside the requested scope
"""
import json
import os
import re
import sys
import collections

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from wks import store  # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SUMMARY = os.environ.get("HT_SUMMARY", "research/ht_summary.md")
MATCH_MIN = float(os.environ.get("MATCH_MIN", "2.0"))

IN_SCOPE = {
    "pentesting-web": "web",
    "network-services-pentesting": "network",
    "windows-hardening": "network",   # AD lives under network/active-directory
    "linux-hardening": "network",
    "generic-methodologies-and-resources": "network",
}
OUT_OF_SCOPE = (
    "binary-exploitation", "mobile-pentesting", "todo", "stego",
    "hardware-physical-access", "blockchain", "reversing", "privacy",
    "generic-hacking", "crypto", "AI", "macos-hardening",
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
}


def norm(s):
    return re.sub(r"[^a-z0-9]+", " ", s.lower())


def toks(s, minlen=2):
    return {t for t in norm(s).split() if t not in STOP and len(t) >= minlen}


def stem_key(path):
    name = os.path.basename(path)
    if name.lower() == "readme.md":
        name = os.path.basename(os.path.dirname(path)) + ".md"
    return re.split(r"[-_]", name[:-3].lower())[0]


def parse_summary(path):
    """Return pages with a parent link, derived from indentation."""
    pages, stack = [], []
    with open(path, encoding="utf-8") as fh:
        for raw in fh:
            m = re.match(r"^(\s*)[-*]\s+\[(.+?)\]\((.+?\.md)\)\s*$", raw)
            if not m:
                continue
            depth = len(m.group(1)) // 2
            title, rel = m.group(2), m.group(3)
            stack = stack[:depth]
            p = {"title": title, "rel": rel, "section": rel.split("/")[0],
                 "depth": depth,
                 "parent": stack[-1]["rel"] if stack else None,
                 "stem": stem_key(rel)}
            stack.append(p)
            pages.append(p)
    return pages


def load_classes(con):
    out = []
    for cid, name, surface, summary, aliases in con.execute(
            "SELECT id,name,surface,summary,aliases FROM bug_class"):
        dom = con.execute("SELECT domain FROM class_domain WHERE class_id=?",
                          (cid,)).fetchone()
        out.append({
            "id": cid, "name": name, "surface": surface,
            "domain": dom[0] if dom else None,
            "stem": stem_key(cid + ".md"),
            "strong": toks(name) | toks(aliases or "") | {stem_key(cid + ".md")},
            "summ_tok": toks(summary or ""),
        })
    return out


def score(page, classes):
    pt = toks(page["title"])
    best, bs = None, 0.0
    for c in classes:
        if page["stem"] and page["stem"] == c["stem"]:
            sc = 99.0
        else:
            sc = 3.0 * len(pt & c["strong"]) + 0.4 * len(pt & c["summ_tok"])
        if sc > bs:
            best, bs = c, sc
    return (best["id"], bs) if bs >= MATCH_MIN else (None, bs)


def main():
    con = store.connect()
    classes = load_classes(con)
    pages = parse_summary(SUMMARY)
    by_rel = {p["rel"]: p for p in pages}
    print(f"HackTricks pages: {len(pages)} unique files in SUMMARY")
    print(f"WKS classes:     {len(classes)}\n")

    for p in pages:
        if p["section"] in OUT_OF_SCOPE:
            p["bucket"] = "OUT_OF_SCOPE"
            continue
        cid, sc = score(p, classes)
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

    b = collections.defaultdict(list)
    for p in pages:
        b[p["bucket"]].append(p)
    print("=" * 78)
    print("BUCKET COUNTS")
    for k in ("MATCHED", "UNMAPPED", "OUT_OF_SCOPE"):
        print("  %-14s %d" % (k, len(b[k])))
    direct = sum(1 for p in b["MATCHED"] if p["via"] == "direct")
    print("  (matched: %d direct + %d inherited)"
          % (direct, len(b["MATCHED"]) - direct))
    print()

    items = dict(con.execute(
        "SELECT class_id, COUNT(*) FROM item WHERE status='active' GROUP BY class_id"))
    hosts = collections.defaultdict(set)
    for cid, h in con.execute(
            "SELECT i.class_id, s.host FROM item i JOIN item_source x ON x.item_id=i.id "
            "JOIN source s ON s.id=x.source_id WHERE i.status='active'"):
        hosts[cid].add(h)

    print("=" * 78)
    print("PER-CLASS HackTricks COVERAGE  (pages / sections / our items / hosts)")
    byc = collections.defaultdict(list)
    for p in b["MATCHED"]:
        byc[p["cls"]].append(p)
    for cid, ps in sorted(byc.items(), key=lambda x: -len(x[1])):
        c = next(c for c in classes if c["id"] == cid)
        secs = dict(collections.Counter(p["section"] for p in ps))
        print("  %-26s %3dp  items=%3d  hosts=%2d  dom=%s"
              % (cid, len(ps), items.get(cid, 0), len(hosts.get(cid, ())),
                 c["domain"] or "UNMAPPED"))
        print("      %s" % secs)

    print()
    print("=" * 78)
    print("CLASSES WITH ZERO HackTricks PAGES")
    for c in sorted(classes, key=lambda c: c["id"]):
        if c["id"] not in byc:
            print("  %-26s items=%3d  hosts=%2d  dom=%s"
                  % (c["id"], items.get(c["id"], 0), len(hosts.get(c["id"], ())),
                     c["domain"] or "UNMAPPED"))

    print()
    print("=" * 78)
    print("GAP CANDIDATES: %d unmapped in-scope pages" % len(b["UNMAPPED"]))
    gs = collections.defaultdict(list)
    for p in b["UNMAPPED"]:
        gs[p["section"]].append(p)
    for sec in sorted(gs, key=lambda s: -len(gs[s])):
        print("\n-- %s  (%d pages) -> target domain %s"
              % (sec, len(gs[sec]), IN_SCOPE.get(sec)))
        for p in sorted(gs[sec], key=lambda p: (p["depth"], p["title"])):
            print("   %s%s" % ("   " * p["depth"], p["title"]))
            print("      %s" % p["rel"])

    out = os.path.join(ROOT, "research", "ht_crosswalk.json")
    os.makedirs(os.path.dirname(out), exist_ok=True)
    with open(out, "w", encoding="utf-8") as f:
        json.dump(dict(b), f, indent=1)
    print("\nwrote %s" % out)


if __name__ == "__main__":
    main()
