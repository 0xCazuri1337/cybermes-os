"""A practice guide needs a SECOND real publisher. Where does it come from?

MEASURED PROBLEM: with the guide excluded as a publisher, a HowToHunt item cites
HowToHunt + PortSwigger. PortSwigger is one real publisher, so
`MIN_PUBLISHER_HOSTS = 2` is not met and the item cannot promote. That is the
gate working as designed, and the wrong fix is to lower the threshold or to
re-count the guide.

The correct fix is the same one the HackTricks wave used: the guide supplies the
PRACTICE (how the technique is hunted), and a SECOND, INDEPENDENT NORMATIVE
publisher supplies corroboration of the mechanism. One partner is not enough, so
each packet entry now carries TWO normative quotes from DIFFERENT registrable
domains, and the item cites guide + normative A + normative B.

`twopart` collects, per class, promoted corpus quotes from distinct normative
orgs -- the same recycling rule as before, just requiring two instead of one.
Classes with only one normative org in the corpus are reported, not faked.
"""
import collections
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import ht_build_items as B  # noqa: E402
import ht_verify2 as V2      # noqa: E402
from wks import config, store  # noqa: E402

NORMATIVE = ("portswigger.net", "owasp.org", "mitre.org", "rfc-editor.org",
             "ietf.org", "httpwg.org", "w3.org", "cwe.mitre.org", "nvd.nist.gov",
             "palletsprojects.com", "symfony.com", "projectdiscovery.io",
             "bishopfox.com", "php.net", "python.org", "nodejs.org", "snyk.io",
             "lxml.de", "mongodb.com", "sqlite.org", "djangoproject.com",
             "postgresql.org", "microsoft.com", "elastic.co", "sonarsource.com",
             "qualys.com", "nccgroup.com", "specterops.io", "ired.team")
MIN_CHARS = 110


def two_part(con):
    """class -> list of {"url","quote","org"}, DISTINCT orgs, longest first."""
    per = collections.defaultdict(list)
    for cid, url, host, quote in con.execute(
            "SELECT i.class_id, s.url, s.host, x.quote FROM item i"
            "  JOIN quality q ON q.item_id=i.id"
            "  JOIN item_source x ON x.item_id=i.id"
            "  JOIN source s ON s.id=x.source_id"
            " WHERE q.validation_state='high_confidence'"
            "   AND x.quote IS NOT NULL AND length(x.quote) >= ?", (MIN_CHARS,)):
        if not any(nm in host for nm in NORMATIVE):
            continue
        if V2.has_furniture(quote or ""):
            continue
        org = config.publisher_org(host)
        per[cid].append({"url": url, "host": host, "quote": quote, "org": org})
    out = {}
    for cid, lst in per.items():
        lst.sort(key=lambda p: -len(p["quote"]))
        seen_org, seen_q, uniq = set(), set(), []
        for p in lst:
            k = (p["url"], p["quote"][:60])
            if k in seen_q or p["org"] in seen_org:
                continue
            seen_q.add(k)
            seen_org.add(p["org"])
            uniq.append(p)
        out[cid] = uniq
    return out


if __name__ == "__main__":
    con = store.connect()
    tp = two_part(con)
    json.dump(tp, open(os.path.join(os.path.dirname(os.path.dirname(
        os.path.abspath(__file__))), "research", "two_partner.json"),
        "w", encoding="utf-8"), indent=1)
    print("classes with >=2 DISTINCT normative orgs available: %d of %d"
          % (sum(1 for v in tp.values() if len(v) >= 2), len(tp)))
    print()
    print("  %-26s %s" % ("class", "normative orgs available"))
    short = []
    for cid in sorted(tp, key=lambda c: -len(tp[c]))[:16]:
        orgs = [p["org"] for p in tp[cid]]
        print("  %-26s %d  %s" % (cid, len(orgs), orgs[:6]))
    print()
    only1 = [c for c, v in tp.items() if len(v) < 2]
    print("classes with fewer than 2 normative orgs: %d" % len(only1))
    for c in sorted(only1)[:20]:
        print("    %-26s %s" % (c, [p["org"] for p in tp.get(c, [])]))
    print("\nwrote knowledge/materials/two_partner.json")