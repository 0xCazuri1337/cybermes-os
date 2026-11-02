"""INDEPENDENT verification of the promoted HackTricks items, from the LIVE web.

The cache is not evidence of anything: it is what the builder read. This walks
the CANONICAL db, collects every promoted item that cites a HackTricks source,
re-fetches each cited page over the network, and re-checks the quote with the
gate's own matcher.

This is the check that would catch a builder that fabricated, a page that was
rewritten since harvest, or a quote that only ever matched the cache.

Also asserts:
  * no item cites two HackTricks mirrors as its two publishers (self-corroboration)
  * every item has >= MIN_PUBLISHER_HOSTS distinct registrable orgs
  * the item_key's first segment really is the class it is filed under
"""
import collections
import os
import re
import sys
import time
import urllib.error
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from wks import config, store, verify_quotes  # noqa: E402
import ht_build_items as B  # noqa: E402

HT_MARKERS = ("hacktricks.wiki", "HackTricks-wiki/hacktricks")


def is_ht(url):
    return any(m in url for m in HT_MARKERS)


def fetch_live(url, tries=2):
    for i in range(tries):
        try:
            req = urllib.request.Request(url, headers={"User-Agent": ht_ua()})
            body = urllib.request.urlopen(req, timeout=45).read().decode(
                "utf-8", "replace")
            return body
        except urllib.error.HTTPError as e:
            return "" if e.code == 404 else ""
        except Exception:                                        # noqa: BLE001
            time.sleep(1.5 * (i + 1))
    return ""


def ht_ua():
    return "Mozilla/5.0 (compatible; wks-research/1.0)"


def main():
    con = store.connect()
    rows = list(con.execute(
        "SELECT i.id, i.item_key, i.class_id, i.claim, q.validation_state"
        "  FROM item i JOIN quality q ON q.item_id=i.id"
        " WHERE q.validation_state='high_confidence'"))
    targets = []
    for r in rows:
        srcs = list(con.execute(
            "SELECT s.url, s.host, x.quote FROM item_source x"
            " JOIN source s ON s.id=x.source_id WHERE x.item_id=?", (r["id"],)))
        if any(is_ht(s["url"]) for s in srcs):
            targets.append((r, srcs))
    print("=" * 76)
    print("LIVE RE-VERIFICATION of promoted HackTricks-citing items")
    print("=" * 76)
    print("  items citing HackTricks : %d" % len(targets))

    quote_ok = quote_bad = 0
    self_corr = 0
    key_bad = 0
    org_bad = 0
    dead_pages = []
    for r, srcs in targets:
        if r["item_key"].split(".")[0] != r["class_id"]:
            key_bad += 1
        orgs = {config.publisher_org(s["host"]) for s in srcs}
        if len(orgs) < config.MIN_PUBLISHER_HOSTS:
            org_bad += 1
        if len([s for s in srcs if is_ht(s["url"])]) > 1:
            self_corr += 1
        for s in srcs:
            page = fetch_live(s["url"])
            if not page:
                dead_pages.append((r["class_id"], s["url"]))
                quote_bad += 1
                continue
            text = page if s["host"].endswith("githubusercontent.com") else B.fetch_html(
                s["url"]) or page
            if verify_quotes.find_quote(text, s["quote"] or ""):
                quote_ok += 1
            else:
                quote_bad += 1
                print("  QUOTE MISMATCH  %-14s %s" % (r["class_id"], s["url"][:64]))
            time.sleep(0.25)

    print()
    print("  quotes verified LIVE : %d" % quote_ok)
    print("  quote_mismatch       : %d" % quote_bad)
    print("  dead/unfetchable     : %d" % len(dead_pages))
    print("  self_corroborating   : %d" % self_corr)
    print("  wrong_class_segment  : %d" % key_bad)
    print("  under 2 orgs         : %d" % org_bad)
    for cid, u in dead_pages[:10]:
        print("     DEAD %-14s %s" % (cid, u[:70]))
    bad = quote_bad + self_corr + key_bad + org_bad
    print()
    print("VERDICT:", "CLEAN" if bad == 0 else "DEFECTS=%d" % bad)
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())