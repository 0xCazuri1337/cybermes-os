"""Crosswalk HackTricks SUMMARY.md -> WKS bug_class. Report-only, no writes.

Buckets every HackTricks page into:
  MATCHED     -> a registered class scored >= MATCH_MIN
  UNMAPPED    -> no class matched; candidate for a NEW class (gap)
  OUT_OF_SCOPE-> belongs to a HackTricks section the user did not ask for
                 (binary-exploitation, mobile, wifi, stego, hardware, blockchain)

The matcher is deliberately over-generous: false "MATCHED" is caught later by
the gate, while a false "UNMAPPED" would create a junk class. So the score
requires the class's PRIMARY token, not just any shared word.
"""
import json
import os
import re
import sys
import collections

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from wks import store  # noqa: E402

SUMMARY = os.environ.get("HT_SUMMARY", "SUMMARY.md")
MATCH_MIN = float(os.environ.get("MATCH_MIN", "2.0"))
OUT_OF_SCOPE = (
    "binary-exploitation", "mobile-pentesting", "todo", "stego",
    "hardware-physical-access", "blockchain", "reversing", "privacy",
    "generic-hacking", "crypto", "AI", "macos-hardening",
)
# Sections the user DID ask for -> target domain
IN_SCOPE = {
    "pentesting-web": "web",
    "network-services-pentesting": "network",
    "windows-hardening": "network",   # AD lives under network/active-directory
    "linux-hardening": "network",
    "generic-methodologies-and-resources": "network",
}

STOP = {
    "the", "and", "for", "with", "from", "that", "this", "how", "using", "into",
    "a", "an", "of", "to", "in", "on", "is", "are", "be", "at", "by", "it",
    "or", "as", "not", "no", "you", "your", "we", "can", "will", "when", "what",
    "attack", "attacks", "attacking", "pentest", "pentesting", "hack", "hacking",
    "test", "testing", "exploit", "exploiting", "vuln", "vulnerability",
    "vulnerabilities", "security", "misc", "other", "intro", "index", "readme",
    "summary", "todo", "checklist", "basic", "useful", "common", "generic",
    "methodology", "methodologies", "resources", "tricks", "bypass",
}


def norm(s):
    s = s.lower()
    s = re.sub(r"[^a-z0-9]+", " ", s)
    return s


def toks(s):
    return {t for t in norm(s).split() if t not in STOP and len(t) > 2}


def stem_key(path):
    """hacktricks/src/pentesting-web/ssti-server-side-template-injection.md -> ssti"""
    name = os.path.basename(path)
    if name.lower() == "readme.md":
        name = os.path.basename(os.path.dirname(path)) + ".md"
    name = name[:-3]
    return re.split(r"[-_]", name.lower())[0]


def parse_summary(path):
    pages = []
    for line in open(path, encoding="utf-8"):
        m = re.match(r"^\s*[-*]\s+\[(.+?)\]\((.+?\.md)\)\s*$", line)
        if not m:
            continue
        title, rel = m.group(1), m.group(2)
        sec = rel.split("/")[0]
        pages.append({"title": title, "rel": rel, "section": sec,
                      "depth": (len(line) - len(line.lstrip())) // 2,
                      "stem": stem_key(rel)})
    return pages


def main():
    con = store.connect()
    classes = []
    for cid, name, surface, summary, aliases in con.execute(
            "SELECT id,name,surface,summary,aliases FROM bug_class"):
        dom = con.execute(
            "SELECT domain FROM class_domain WHERE class_id=?", (cid,)).fetchone()
        classes.append({
            "id": cid, "name": name, "surface": surface,
            "summary": summary or "", "aliases": aliases or "",
            "domain": dom[0] if dom else None,
            "tok": toks(" ".join([name, aliases or "", summary or ""])),
            "primary": {stem_key(cid + ".md")} | toks(aliases or ""),
        })
    for c in classes:
        c["primary"] |= {stem_key(c["id"] + ".md")}
        c["primary"] |= {t for t in c["tok"] if t in c["aliases"].lower()}

    pages = parse_summary(SUMMARY)
    uniq_rel = {p["rel"] for p in pages}
    print(f"HackTricks pages in SUMMARY: {len(pages)} links, {len(uniq_rel)} unique files")
    print(f"WKS classes: {len(classes)}\n")

    buckets = collections.defaultdict(list)
    for p in pages:
        sec = p["section"]
        if sec in OUT_OF_SCOPE:
            buckets["OUT_OF_SCOPE"].append(p)
            continue
        pt = toks(p["title"])
        best, bestscore = None, 0.0
        for c in classes:
            # hard signal: identical file stem (idor.md -> idor)
            if p["stem"] and p["stem"] == stem_key(c["id"] + ".md"):
                sc = 99.0
            else:
                inter = pt & c["tok"]
                sc = len(inter)
                if inter and not (inter & c["primary"]):
                    sc -= 1.0   # overlap without the class's own name token
            if sc > bestscore:
                best, bestscore = c, sc
        if best and bestscore >= MATCH_MIN:
            p["class"] = best["id"]
            p["score"] = bestscore
            p["target_domain"] = IN_SCOPE.get(sec)
            buckets["MATCHED"].append(p)
        else:
            buckets["UNMAPPED"].append(p)

    print("=" * 78)
    print("BUCKET COUNTS")
    for k in ("MATCHED", "UNMAPPED", "OUT_OF_SCOPE"):
        print(f"  {k:14s} {len(buckets[k])}")
    print()

    print("=" * 78)
    print("PER-CLASS COVERAGE  (pages matched / sections covered / current items)")
    items = dict(con.execute(
        "SELECT class_id, COUNT(*) FROM item WHERE status='active' GROUP BY class_id"))
    byclass = collections.defaultdict(list)
    for p in buckets["MATCHED"]:
        byclass[p["class"]].append(p)
    for cid, ps in sorted(byclass.items(), key=lambda x: -len(x[1])):
        secs = collections.Counter(p["section"] for p in ps)
        c = next(c for c in classes if c["id"] == cid)
        print(f"  {cid:28s} {len(ps):3d} pages  items={items.get(cid,0):3d}  "
              f"dom={c['domain'] or 'UNMAPPED'}")
        print(f"      {dict(secs)}")
    print()

    print("=" * 78)
    print(f"CLASSES WITH ZERO HackTricks PAGES (candidate gaps in our taxonomy)")
    for c in sorted(classes, key=lambda c: c["id"]):
        if c["id"] not in byclass:
            print(f"  {c['id']:28s} items={items.get(c['id'],0):3d}  dom={c['domain'] or 'UNMAPPED'}")
    print()

    print("=" * 78)
    print("UNMAPPED PAGES = GAP CANDIDATES (grouped by section, scored by depth)")
    gapsec = collections.defaultdict(list)
    for p in buckets["UNMAPPED"]:
        gapsec[p["section"]].append(p)
    for sec in sorted(gapsec, key=lambda s: -len(gapsec[s])):
        print(f"\n-- {sec}  ({len(gapsec[sec])} pages) -> target domain {IN_SCOPE.get(sec)}")
        rows = sorted(gapsec[sec], key=lambda p: (-p["depth"], p["title"]))
        for p in rows:
            print(f"   {'  '*(p['depth']-1)}{p['title']}  [{p['rel']}]")

    out = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                       "research", "ht_crosswalk.json")
    os.makedirs(os.path.dirname(out), exist_ok=True)
    with open(out, "w", encoding="utf-8") as f:
        json.dump({k: v for k, v in buckets.items()}, f, indent=1)
    print(f"\n\nwrote {out}")


if __name__ == "__main__":
    main()
