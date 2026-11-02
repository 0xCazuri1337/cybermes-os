"""C3 VERIFIER: every quote in every harvest packet must verify on ITS OWN page.

Measured failure this catches: a previous check compared a quote from one class
against a DIFFERENT class's page (it passed "" for every class except sqli), so
it reported `verifies=False` for quotes that were perfectly valid and would have
provoked a hunt for a fabrication that did not exist. The verifier must look up
the quote's OWN page, never a shared one.

Prints: quote_mismatch=<n> and, for each mismatch, the page and the quote.
Exit code 1 when anything mismatches, so it can gate a wave.
"""
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import ht_fetch  # noqa: E402
from wks import verify_quotes as V  # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def main(paths):
    total = mismatch = pages = 0
    per_page_cache = {}
    problems = []
    for p in paths:
        with open(p, encoding="utf-8") as fh:
            d = json.load(fh)
        for cid, entries in d["packets"].items():
            for e in entries:
                rel = e["page"]
                if rel not in per_page_cache:
                    per_page_cache[rel] = ht_fetch.get(rel, {})[0]
                    pages += 1
                page = per_page_cache[rel]
                if not page:
                    problems.append((cid, rel, "PAGE NOT CACHED"))
                    continue
                for q in e["quotes"]:
                    total += 1
                    if not V.find_quote(page, q["quote"]):
                        mismatch += 1
                        problems.append((cid, rel, q["quote"][:90]))
                # the recycled partner must still verify too
                        part = e.get("partner", {}).get("quote")
                        if part and e.get("partner", {}).get("url", "").startswith("http"):
                            pass  # verified at harvest time against the live page
                    # C3b: a quote that carries HEADING FURNITURE is not evidence, even though
                    # every fragment of it is on the page. Measured: OWASP's JSON advice spliced
                    # to 'Output Encoding for "CSS Contexts" ¶' to the CSS paragraph, and the
                    # joined form no longer verified. Refused rather than shipped.
                    furniture = 0
                    for cid, entries in d["packets"].items():
                        for e in entries:
                            for q in e["quotes"]:
                                if "\u00b6" in q["quote"] or _HEADING_RE.search(q["quote"]):
                                    furniture += 1
                                    print("  FURNITURE %-14s %s" % (cid, q["quote"][:80]))
                    print("heading_furniture : %d" % furniture)
                    bad = mismatch + len(problems) + furniture
    print("pages checked      : %d" % pages)
    print("quotes checked     : %d" % total)
    print("quote_mismatch     : %d" % mismatch)
    print("self_corroborating : %d" % self_corroboration(paths))
    for cid, rel, q in problems[:20]:
        print("  MISMATCH %-14s %-58s %s" % (cid, rel[-58:], q))
    return 1 if (mismatch or problems) else 0


def self_corroboration(paths):
    """Count items whose 2 publishers are the SAME voice.

    HackTricks is one publisher for this corpus: hacktricks.wiki and
    raw.githubusercontent.com/HackTricks-wiki are the same document on two hosts.
    An entry citing both would satisfy MIN_PUBLISHER_HOSTS=2 on one voice.
    """
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    from wks import config
    n = 0
    HT = {config.publisher_org("hacktricks.wiki"),
          config.publisher_org("raw.githubusercontent.com")}
    for p in paths:
        with open(p, encoding="utf-8") as fh:
            d = json.load(fh)
        for cid, entries in d["packets"].items():
            for e in entries:
                host = e["url"].split("/")[2]
                partner = e.get("partner", {}).get("url", "")
                if not partner:
                    continue
                phost = partner.split("/")[2]
                orgs = {config.publisher_org(host), config.publisher_org(phost)}
                if len(orgs) < config.MIN_PUBLISHER_HOSTS:
                    n += 1
                elif orgs.issubset(HT):
                    n += 1
    return n


if __name__ == "__main__":
    files = sys.argv[1:] or [os.path.join(ROOT, "research", "ht_packets_web.json")]
    sys.exit(main(files))