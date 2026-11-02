"""Capture the BEFORE baseline so the after-report is measured, not remembered.

Writes research/baseline.json with every number the report will compare against:
corpus totals, per-state, per-class and per-domain counts, publisher-host
diversity, kind distribution, and the gap table. Re-running this later must show
movement; a baseline that is regenerated from the same db twice is worthless, so
it refuses to overwrite unless --force is passed.
"""
import argparse
import collections
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from wks import config, domains, store  # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT = os.path.join(ROOT, "research", "baseline.json")


def snapshot():
    con = store.connect()
    per_class = {}
    for cid, dom in con.execute(
            "SELECT b.id, COALESCE(c.domain,'?') FROM bug_class b "
            "LEFT JOIN class_domain c ON c.class_id=b.id"):
        n = con.execute(
            "SELECT COUNT(*) FROM item i JOIN quality q ON q.item_id=i.id"
            " WHERE i.class_id=? AND i.status='active'", (cid,)).fetchone()[0]
        hc = con.execute(
            "SELECT COUNT(*) FROM item i JOIN quality q ON q.item_id=i.id"
            " WHERE i.class_id=? AND i.status='active'"
            "   AND q.validation_state='high_confidence'", (cid,)).fetchone()[0]
        hosts = {r[0] for r in con.execute(
            "SELECT s.host FROM item i JOIN item_source x ON x.item_id=i.id"
            " JOIN source s ON s.id=x.source_id"
            " WHERE i.class_id=? AND i.status='active'", (cid,))}
        per_class[cid] = {"domain": dom, "items": n, "high_conf": hc,
                          "hosts": len(hosts)}
    per_domain = collections.Counter()
    hc_domain = collections.Counter()
    for cid, v in per_class.items():
        per_domain[v["domain"]] += v["items"]
        hc_domain[v["domain"]] += v["high_conf"]

    kinds = dict(collections.Counter(
        r[0] for r in con.execute(
            "SELECT kind FROM item WHERE status='active'")))
    states = dict(collections.Counter(
        r[0] for r in con.execute(
            "SELECT validation_state FROM quality")))

    sources_by_org = collections.Counter()
    for host, in con.execute("SELECT DISTINCT host FROM source"):
        sources_by_org[config.publisher_org(host)] += 1

    return {
        "items_total": con.execute("SELECT COUNT(*) FROM item").fetchone()[0],
        "items_active": con.execute(
            "SELECT COUNT(*) FROM item WHERE status='active'").fetchone()[0],
        "superseded": con.execute(
            "SELECT COUNT(*) FROM item WHERE status='superseded'").fetchone()[0],
        "classes": con.execute("SELECT COUNT(*) FROM bug_class").fetchone()[0],
        "class_domain_rows": con.execute(
            "SELECT COUNT(*) FROM class_domain").fetchone()[0],
        "chains": con.execute("SELECT COUNT(*) FROM chain").fetchone()[0],
        "fp_cases": con.execute("SELECT COUNT(*) FROM fp_case").fetchone()[0],
        "sources": con.execute("SELECT COUNT(*) FROM source").fetchone()[0],
        "publisher_orgs": len(sources_by_org),
        "states": states,
        "kinds": kinds,
        "per_domain_items": dict(per_domain),
        "per_domain_high_conf": dict(hc_domain),
        "per_class": per_class,
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--force", action="store_true")
    ap.add_argument("--label", default="before")
    a = ap.parse_args()
    if os.path.exists(OUT) and not a.force:
        with open(OUT, encoding="utf-8") as fh:
            print("baseline already exists at %s -- pass --force to replace"
                  % OUT)
        print(json.dumps(json.load(open(OUT, encoding="utf-8"))["totals"]
                         if False else {}, indent=1))
        return 0
    snap = snapshot()
    snap["label"] = a.label
    with open(OUT, "w", encoding="utf-8") as fh:
        json.dump(snap, fh, indent=1)
    print("baseline written: %s" % OUT)
    for k in ("items_total", "items_active", "superseded", "classes",
              "class_domain_rows", "chains", "fp_cases", "sources",
              "publisher_orgs"):
        print("  %-20s %s" % (k, snap[k]))
    print("  per_domain_items    %s" % snap["per_domain_items"])
    print("  high_conf by domain %s" % snap["per_domain_high_conf"])
    return 0


if __name__ == "__main__":
    sys.exit(main())