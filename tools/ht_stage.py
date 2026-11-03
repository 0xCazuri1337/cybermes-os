"""Turn AUDITED claims into WKS intake files. The parent's merge, not a child's.

Chain of custody, and each link re-checked here rather than trusted:

  child claims -> ht_audit_claims.py (D1-D4, parent-side)
               -> THIS tool: re-verifies every quote against the CACHED page
               -> knowledge/incoming/ht_<class>.json (staging)
               -> `python -m wks.ingest` (the gate; run by the parent, never --dry)

Nothing is invented here. The quote is copied from the child's row and
re-verified against the cached HackTricks page with the gate's own matcher; the
partner quote was already verified when it was recycled from the corpus.
"""
import argparse
import collections
import json
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import ht_fetch  # noqa: E402
from ht_verify2 import has_furniture  # noqa: E402
import twopart  # noqa: E402
from wks import config, store, verify_quotes  # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
HT_MARKERS = ("hacktricks.wiki", "HackTricks-wiki/hacktricks")



# A practice-guide page carries NO evidentiary weight on its own: the same rule
# that stops a single write-up from promoting an item stops a whole guide. The
# gate enforces this itself (BUILDER_PAGE_NOT_PUBLISHER); this keeps the stager
# from pretending otherwise, so `publishers` in the intake file reports what the
# gate will actually count.
GUIDE_HOSTS = ("gitbook.io", "notion.site", "notion.so", "pentester.land")


def SRC_PREFIX(url):
    host = url.split("/")[2] if "://" in url else url
    if "HackTricks-wiki" in host or "hacktricks" in host:
        return "ht"
    if "kathan19" in host:
        return "hth"
    if "oreobiscuit" in host:
        return "bis"
    if "pentester.land" in host:
        return "pl"
    return re.sub(r"\W+", "_", host.split(".")[0])[:6].strip("_") or "src"


def is_guide(url):
    return any(g in url for g in GUIDE_HOSTS)


def _read_index(path, needle):
    """Look a page up in a cache dir's index.json by full url, then by suffix."""
    try:
        with open(path, encoding="utf-8") as fh:
            meta = json.load(fh)
    except Exception:                                        # noqa: BLE001
        return ""
    m = meta.get(needle)
    if not m and "/src/" in needle:
        m = meta.get(needle.split("/src/", 1)[1])
    if not m:
        # suffix match: the privesc pages were indexed by relative path while
        # the brief carries the absolute raw.githubusercontent URL
        for k, v in meta.items():
            if k.endswith(needle) or needle.endswith(k):
                m = v
                break
    if not m or not m.get("file"):
        return ""
    base = os.path.dirname(path)
    for cand in (os.path.join(base, m["file"] + ".md"),
                 os.path.join(base, m["file"])):
        if os.path.exists(cand):
            with open(cand, encoding="utf-8") as fh:
                return fh.read()
    return ""


def read_page(rel, idx):
    """Read a source page from WHICHEVER cache holds it, by ANY key it was
    stored under.

    Three measured misses, each a different key shape:
      * HackTricks pages live in cache/ht_pages, keyed by RELATIVE path;
        ht_stage asks with the FULL raw.githubusercontent URL -> hash mismatch
        -> "page not cached" on a page it has.
      * HowToHunt/Biscuit pages live in cache/hth and cache/biscuit, keyed by
        the gitbook URL.
      * The Notion pages are not in either.
    So resolution is: every cache index, then ht_fetch's own path. Reporting a
    miss is now only possible when no index holds it under any key.
    """
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    cache = os.path.join(root, "cache")
    if os.path.isdir(cache):
        for d in sorted(os.listdir(cache)):
            ip = os.path.join(cache, d, "index.json")
            if os.path.isdir(os.path.join(cache, d)) and os.path.exists(ip):
                txt = _read_index(ip, rel)
                if txt:
                    return txt
    base = os.path.basename(rel)
    if os.path.isdir(cache):
        for d in sorted(os.listdir(cache)):
            p = os.path.join(cache, d, base)
            if os.path.exists(p):
                with open(p, encoding="utf-8") as fh:
                    return fh.read()
    return ht_fetch.get(rel, idx)[0]


def org_of(url):
    """Publisher org of a CITED SOURCE.

    A practice guide returns "" so it cannot satisfy the 2-publisher rule --
    the gate would refuse it anyway, and counting it here made every item
    report a publisher it would never be credited with.
    """
    if is_guide(url):
        return ""
    host = url.split("/")[2]
    return config.publisher_org(host)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--answers", nargs="+", required=True)
    ap.add_argument("--audit", required=True)
    ap.add_argument("--outdir", default=os.path.join(ROOT, "research", "incoming"))
    ap.add_argument("--prefix", default="ht")
    a = ap.parse_args()

    rows = []
    for f in a.answers:
        with open(f, encoding="utf-8") as fh:
            rows.extend(json.load(fh))
    with open(a.audit, encoding="utf-8") as fh:
        audit = json.load(fh)

    # The audit key must include the QUOTE, not just (class, page).
    # MEASURED: 26 pages carry more than one audited quote, and keying on
    # (class_id, page) let a FAIL on one quote be masked by a PASS on its
    # page-mate -- the ssti client-side-template item was refused by D2 and
    # still staged. The gate caught it independently (OFF_CLASS_TOPIC), which
    # is luck, not design: a masked FAIL that nothing else catches is a
    # silently unchecked item. Key on the claim's own leading span.
    ok = set()
    for r in audit:
        if r["verdict"] == "PASS":
            ok.add((r["class_id"], r["page"], (r.get("claim") or "")[:80]))

    con = store.connect()
    # Two DISTINCT normative publishers per class, so a guide-sourced
    # item can still satisfy MIN_PUBLISHER_HOSTS honestly.
    tp = twopart.two_part(con)
    idx = ht_fetch.load_index()
    # Two DISTINCT normative publishers per class, so a guide-sourced item
    # can still satisfy MIN_PUBLISHER_HOSTS honestly.
    per_class = collections.defaultdict(list)
    refused = []

    for r in rows:
        claim = (r.get("claim") or "").strip()
        page = r.get("hacktricks_page", "")
        quote = r.get("QUOTE_VERBATIM", "")
        if not claim:
            continue
        key = (r["class_id"], page, claim[:80])
        if key not in ok:
            refused.append((r["class_id"], page, "audit FAIL"))
            continue
        text = read_page(page, idx)
        if not text:
            refused.append((r["class_id"], page, "page not cached"))
            continue
        # RE-VERIFY the quote here. The child did not fetch; the packet builder
        # did. This is the last point before the gate sees it.
        if not verify_quotes.find_quote(text, quote):
            refused.append((r["class_id"], page, "quote does not verify"))
            continue
        part = r.get("partner_quote_already_verified") or ""
        if not part:
            refused.append((r["class_id"], page, "no partner quote"))
            continue

        # C3b at RECYCLE time. A partner quote is recycled from an older corpus
        # item, so it can carry defects our own slicer would never produce:
        # measured, one recycled OWASP quote spliced the JSON advice to the
        # heading 'Output Encoding for "CSS Contexts" ¶' and on into the CSS
        # paragraph. Each fragment was verbatim, the joined citation did not
        # re-verify, and 3 items shipped carrying it. Refuse here, before it
        # reaches an item.
        if has_furniture(part):
            refused.append((r["class_id"], page,
                            "partner quote carries heading furniture"))
            continue

        # A PRACTICE GUIDE IS NOT A PUBLISHER -- the gate says so itself
        # (BUILDER_PAGE_NOT_PUBLISHER). It therefore needs TWO independent
        # NORMATIVE publishers to reach MIN_PUBLISHER_HOSTS. A normative source
        # IS a publisher, which is why the HackTricks wave promoted 72 items on
        # this same path with a single partner.
        sources = [{
            "url": r["hacktricks_url"], "source_type": "reference",
            "host": r["hacktricks_url"].split("/")[2],
            "publisher": "source-guide", "quote": quote},
            {"url": r["partner_url"], "source_type": "research",
            "host": r["partner_url"].split("/")[2],
            "publisher": r.get("partner_org") or org_of(r["partner_url"]),
            "quote": part}]

        # A brand-new class carries a SECOND seeded partner on a different
        # registrable org. Without it a reference-doc item cannot reach
        # MIN_PUBLISHER_HOSTS: CWE alone is one publisher, so every
        # privesc item was refused with "only 1 real publisher org(s)".
        # `ht_brief` carries it through the brief; both halves are needed.
        p2 = r.get("partner2_quote_already_verified")
        if p2 and r.get("partner2_url") and r["partner2_url"] != r["partner_url"]:
            sources.append({
                "url": r["partner2_url"], "source_type": "research",
                "host": r["partner2_url"].split("/")[2],
                "publisher": r.get("partner2_org") or org_of(r["partner2_url"]),
                "quote": p2})

        if is_guide(r["hacktricks_url"]):
            pool = tp.get(r["class_id"], [])
            if len(pool) < config.MIN_PUBLISHER_HOSTS:
                refused.append((r["class_id"], page,
                                "guide source needs %d independent normative "
                                "orgs, class has %d"
                                % (config.MIN_PUBLISHER_HOSTS, len(pool))))
                continue
            have = {org_of(r["partner_url"])}
            for cand in pool:
                if cand["org"] in have:
                    continue
                sources.append({
                    "url": cand["url"], "source_type": "research",
                    "host": cand["host"], "publisher": cand["org"],
                    "quote": cand["quote"]})
                have.add(cand["org"])
                if len(have) >= config.MIN_PUBLISHER_HOSTS:
                    break

        pubs = {s["publisher"] for s in sources
                if s["publisher"] not in ("source-guide", "")}
        if len(pubs) < config.MIN_PUBLISHER_HOSTS:
            refused.append((r["class_id"], page,
                            "only %d real publisher org(s): %s"
                            % (len(pubs), sorted(pubs))))
            continue

        # item_key is parsed as <class_id>.<kind>.<name>: the FIRST segment is
        # the class, so the separators must survive slugging. An earlier version
        # stripped them and every item was rejected as "unknown class".
        name = "".join(ch if (ch.isalnum() or ch == "_") else "_"
                       for ch in quote[:34].lower())
        name = "_".join(p for p in name.split("_") if p)[:80]
        # The prefix names the SOURCE, not a fixed string: ht_ = HackTricks,
        # hth_ = HowToHunt, bis_ = Biscuit. A hardcoded prefix made four
        # sources indistinguishable in the db.
        slug = "%s.%s.%s_%s" % (r["class_id"], r.get("kind") or "technique",
                                SRC_PREFIX(r["hacktricks_url"]), name)
        assert slug.split(".")[0] == r["class_id"], "item_key lost its class segment"

        per_class[r["class_id"]].append({
            "item_key": slug,
            "kind": r.get("kind") or "technique",
            "claim": claim,
            "body": claim + "\n\nHackTricks reference: %s (%s)"
                    % (r.get("page_title", ""), page),
            "disproof": r["disproof"],
            "hunting_value": 4,
            "sources": sources,
        })
    ht_fetch.save_index(idx)

    os.makedirs(a.outdir, exist_ok=True)
    total = 0
    print("=" * 74)
    print("BUILD  %d item(s) over %d class(es); %d refusal(s)"
          % (sum(len(v) for v in per_class.values()), len(per_class), len(refused)))
    for cid, items in sorted(per_class.items()):
        path = os.path.join(a.outdir, "%s_%s.json" % (a.prefix, cid))
        with open(path, "w", encoding="utf-8") as fh:
            json.dump({"class_id": cid, "items": items,
                       "publishers": sorted({s["publisher"]
                                             for i in items for s in i["sources"]}),
                       "sources": [s["url"] for i in items
                                   for s in i["sources"]]}, fh, indent=1)
        total += len(items)
        print("  %-24s %2d item(s) -> %s" % (cid, len(items), os.path.basename(path)))
    for cid, page, why in refused[:20]:
        print("  REFUSED %-14s %-46s %s" % (cid, page[-46:], why))
    print("\ntotal staged: %d. Run the gate on each file (never --dry):" % total)
    print("  python -m wks.ingest knowledge/incoming/%s_*.json" % a.prefix)


if __name__ == "__main__":
    main()