"""C3 VERIFIER: every quote in every harvest packet must verify on ITS OWN page.

Two checks, both learned the hard way:

  C3   quote_mismatch -- the quote must be present on ITS OWN cached page. A
        previous check compared one class's quote against a DIFFERENT class's
        page (it passed "" for everything except one), so it reported
        verifies=False for perfectly valid quotes and would have sent me
        hunting a fabrication that did not exist. The page is always looked up
        from the quote's own entry.

  C3b  heading_furniture -- a quote that carries HEADING FURNITURE is refused
        even when every fragment of it is on the page. Measured: OWASP's JSON
        advice spliced to the heading 'Output Encoding for "CSS Contexts" ¶' and
        on into the CSS paragraph. Each fragment is verbatim, the joined form is
        not a sentence, and the citation does not re-verify. That is a
        malformed citation, not evidence.

Also reports self_corroborating: HackTricks and its GitHub mirror are ONE
publisher for this corpus, so an entry citing both would satisfy
MIN_PUBLISHER_HOSTS=2 on a single voice.

Exit code 1 when anything fails, so this can gate a wave.
"""
import json
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import ht_fetch  # noqa: E402
from wks import config, verify_quotes as V  # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PILCROW = "\u00b6"
HEADING_RE = re.compile(r"(?m)^#{1,6}\s")


def has_furniture(quote):
    return PILCROW in quote or bool(HEADING_RE.search(quote))


def self_corroboration(all_packets):
    """Entries whose two publishers are the same editorial voice."""
    HT = {config.publisher_org("hacktricks.wiki"),
          config.publisher_org("raw.githubusercontent.com")}
    n = 0
    for packets in all_packets:
        for _cid, entries in packets.items():
            for e in entries:
                partner = e.get("partner", {}).get("url", "")
                if not partner:
                    n += 1
                    continue
                orgs = {config.publisher_org(e["url"].split("/")[2]),
                        config.publisher_org(partner.split("/")[2])}
                if len(orgs) < config.MIN_PUBLISHER_HOSTS or orgs.issubset(HT):
                    n += 1
    return n


def local_page(rel):
    """Read a cached page from WHICHEVER cache holds it.

    MEASURED: the verifier reported 72 x "PAGE NOT CACHED" for pages that were
    fetched and packet-built fine, because it only ever looked in
    cache/ht_pages/ (the HackTricks cache) and every other source lives in its own
    directory (cache/hth, cache/biscuit). A verifier that reports a MISS it did
    not actually test is worse than no verifier -- it manufactures an emergency.

    Notion pages carry no filename at all: their key is `notion:<page-id>` and the
    body is `<cache>/<file>.md` from the harvest index, so they need their own
    resolution path rather than a basename guess.
    """
    if rel.startswith("notion:"):
        pid = rel.split(":", 1)[1]
        base = os.path.join(ROOT, "cache", "notion_rem01x")
        for idx_name in ("index_prose.json", "index.json"):
            ip = os.path.join(base, idx_name)
            if not os.path.exists(ip):
                continue
            with open(ip, encoding="utf-8") as fh:
                meta = json.load(fh)
            m = meta.get(pid)
            if not m:
                continue
            p = os.path.join(base, m["file"] + ".md")
            if os.path.exists(p):
                with open(p, encoding="utf-8") as fh:
                    return fh.read()
        return ""
    caches = []
    if isinstance(rel, str) and rel.startswith("cache/"):
        caches.append(os.path.join(ROOT, rel))
    caches += [os.path.join(ROOT, "cache", d) for d in
               ("ht_pages", "hth", "biscuit", "pentesterland")]
    for c in caches:
        if not os.path.isdir(c):
            continue
        f = os.path.basename(rel)
        p = os.path.join(c, f)
        if os.path.exists(p):
            with open(p, encoding="utf-8") as fh:
                return fh.read()
        idx = os.path.join(c, "index.json")
        if os.path.exists(idx):
            with open(idx, encoding="utf-8") as fh:
                meta = json.load(fh)
            m = meta.get(rel)
            if m and m.get("file"):
                p = os.path.join(c, m["file"] + ".md")
                if os.path.exists(p):
                    with open(p, encoding="utf-8") as fh:
                        return fh.read()
    return ""


def main(paths):
    total = mismatch = furniture = pages = 0
    problems = []
    all_packets = []
    for p in paths:
        with open(p, encoding="utf-8") as fh:
            data = json.load(fh)
        packets = data["packets"]
        all_packets.append(packets)
        page_cache = {}
        for cid, entries in packets.items():
            for e in entries:
                rel = e["page"]
                if rel not in page_cache:
                    page_cache[rel] = local_page(rel)
                    pages += 1
                page = page_cache[rel]
                for q in e["quotes"]:
                    total += 1
                    quote = q["quote"]
                    if has_furniture(quote):
                        furniture += 1
                        problems.append((cid, rel, "FURNITURE " + quote[:70]))
                        continue
                    if not page:
                        mismatch += 1
                        problems.append((cid, rel, "PAGE NOT CACHED"))
                        continue
                    if not V.find_quote(page, quote):
                        mismatch += 1
                        problems.append((cid, rel, "MISMATCH " + quote[:70]))

    self_corr = self_corroboration(all_packets)
    print("=" * 74)
    print("PACKET VERIFICATION (C3 / C3b / C2)")
    print("=" * 74)
    print("  pages checked      : %d" % pages)
    print("  quotes checked     : %d" % total)
    print("  quote_mismatch     : %d" % mismatch)
    print("  heading_furniture  : %d" % furniture)
    print("  self_corroborating : %d" % self_corr)
    for cid, rel, why in problems[:20]:
        print("  %-14s %-46s %s" % (cid, rel[-46:], why))
    bad = mismatch + furniture + self_corr
    print()
    print("VERDICT:", "CLEAN" if bad == 0 else "DEFECTS=%d" % bad)
    return 1 if bad else 0


if __name__ == "__main__":
    files = sys.argv[1:] or [os.path.join(ROOT, "research", "ht_packets_web.json")]
    sys.exit(main(files))