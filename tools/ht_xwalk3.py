"""Crosswalk HackTricks SUMMARY.md -> WKS bug_class. Report-only, no writes.

v3. Two defects fixed against v2, both found by probing real paths:

  D1  stem_key() split a filename on '-' and kept only the FIRST token, so
      "file-integrity-monitoring.md" scored 99.0 (exact-stem) against class
      `file_upload` (stem "file") and dragged 57 unrelated pages in with it.
      A stem is now the WHOLE normalised name; the first token is only a
      weak hint, never an exact match.
  D2  purely lexical scoring misrouted four pages that a human would never
      route that way. An explicit ANCHOR table (below) overrides the scorer,
      and every anchor is a path that was actually opened and read.

Buckets:
  MATCHED      -> a registered class (anchored / direct / inherited)
  UNMAPPED     -> no class and no mappable parent; a gap candidate
  OUT_OF_SCOPE -> a HackTricks section outside the requested scope
"""
import collections
import json
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from wks import store  # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SUMMARY = os.environ.get("HT_SUMMARY", "research/ht_summary.md")
MATCH_MIN = float(os.environ.get("MATCH_MIN", "2.0"))

# Verified by hand: (path, class_id, why)
ANCHORS = {
    "network-services-pentesting/pentesting-dns.md": "dns_enum",
    "network-services-pentesting/pentesting-ldap.md": "ldap_enum",
    "windows-hardening/active-directory-methodology/README.md": "ad_enumeration",
    "windows-hardening/active-directory-methodology/adws-enumeration.md": "ad_enumeration",
    # HackTricks merges the two classes in ONE directory; our taxonomy splits
    # them, so the sub-pages are split by title rather than inherited.
    "pentesting-web/cache-deception/README.md": "cache_deception",
    "pentesting-web/cache-deception/cache-poisoning-via-url-discrepancies.md": "cache_poisoning",
    "pentesting-web/cache-deception/cache-poisoning-to-dos.md": "cache_poisoning",
}
# Split a HackTricks directory across two of our classes by title keyword.
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
    """Whole normalised name: file_integrity_monitoring.md -> file integrity monitoring.

    D1: the old version returned only the first '-'-separated token, which made
    every 'file-something' page an exact match for class `file_upload`.
    """
    name = os.path.basename(path)
    if name.lower() == "readme.md":
        name = os.path.basename(os.path.dirname(path)) + ".md"
    return norm(name[:-3] if name.lower().endswith(".md") else name)


def first_token(path):
    return full_stem(path).split()[0] if full_stem(path) else ""


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
    out = []
    for cid, name, surface, summary, aliases in con.execute(
            "SELECT id,name,surface,summary,aliases FROM bug_class"):
        dom = con.execute("SELECT domain FROM class_domain WHERE class_id=?",
                          (cid,)).fetchone()
        st = norm(cid)
        out.append({
            "id": cid, "name": name, "surface": surface,
            "domain": dom[0] if dom else None,
            "stem": st, "first": st.split()[0] if st.split() else "",
            "strong": toks(name) | toks(aliases or "") | toks(cid.replace("_", " ")),
            "summ_tok": toks(summary or ""),
        })
    return out


def score(page, classes):
    """Return (class_id, score). Exact full-stem is the only 99.0."""
    pt, fs = toks(page["title"]), full_stem(page["rel"])
    best, bs = None, 0.0
    for c in classes:
        if fs and fs == c["stem"]:
            sc = 99.0
        elif fs and fs.replace(" ", "") == c["id"].replace("_", ""):
            sc = 99.0
        else:
            # first token is a weak hint only (D1): worth a third of a strong hit
            hint = 1.0 if (fs and first_token(page["rel"]) == c["first"]) else 0.0
            sc = 3.0 * len(pt & c["strong"]) + 0.4 * len(pt & c["summ_tok"]) + hint
        if sc > bs:
            best, bs = c, sc
    return (best["id"], bs) if bs >= MATCH_MIN else (None, bs)


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
    classes = load_classes(con)
    pages = parse_summary(SUMMARY)
    by_rel = {p["rel"]: p for p in pages}
    registered = {c["id"] for c in classes}
    print("HackTricks pages: %d unique files in SUMMARY" % len(pages))
    print("WKS classes:     %d\n" % len(classes))

    anchor_hits, bad_anchor = 0, []
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

    if bad_anchor:
        print("!! ANCHORS POINTING AT UNREGISTERED CLASSES (fix before use):")
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
    print("PER-CLASS HackTricks COVERAGE  (pages / our items / our hosts / domain)")
    byc = collections.defaultdict(list)
    for p in b["MATCHED"]:
        byc[p["cls"]].append(p)
    for cid, ps in sorted(byc.items(), key=lambda x: -len(x[1])):
        c = next(c for c in classes if c["id"] == cid)
        print("  %-26s %3dp  items=%3d  hosts=%2d  dom=%s"
              % (cid, len(ps), items.get(cid, 0), len(hosts.get(cid, ())),
                 c["domain"] or "via-surface"))
        print("      %s" % dict(collections.Counter(p["section"] for p in ps)))

    print()
    print("=" * 78)
    print("CLASSES WITH ZERO HackTricks PAGES")
    for c in sorted(classes, key=lambda c: c["id"]):
        if c["id"] not in byc:
            print("  %-26s items=%3d  hosts=%2d  dom=%s"
                  % (c["id"], items.get(c["id"], 0), len(hosts.get(c["id"], ())),
                     c["domain"] or "via-surface"))

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
