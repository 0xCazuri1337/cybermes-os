"""BEFORE / AFTER report, measured from knowledge/materials/baseline.json and the live db."""
import collections
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from wks import store  # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BASE = json.load(open(os.path.join(ROOT, "research", "baseline.json"),
                     encoding="utf-8"))


def now():
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
    pd, phd = collections.Counter(), collections.Counter()
    for cid, v in per_class.items():
        pd[v["domain"]] += v["items"]
        phd[v["domain"]] += v["high_conf"]
    return {
        "items_total": con.execute("SELECT COUNT(*) FROM item").fetchone()[0],
        "items_active": con.execute(
            "SELECT COUNT(*) FROM item WHERE status='active'").fetchone()[0],
        "classes": con.execute("SELECT COUNT(*) FROM bug_class").fetchone()[0],
        "class_domain_rows": con.execute(
            "SELECT COUNT(*) FROM class_domain").fetchone()[0],
        "high_confidence": con.execute(
            "SELECT COUNT(*) FROM quality WHERE validation_state='high_confidence'"
        ).fetchone()[0],
        "sources": con.execute("SELECT COUNT(*) FROM source").fetchone()[0],
        "chains": con.execute("SELECT COUNT(*) FROM chain").fetchone()[0],
        "per_domain_items": dict(pd),
        "per_domain_high_conf": dict(phd),
        "per_class": per_class,
    }


def main():
    a = now()
    print("=" * 72)
    print("BEFORE / AFTER  (baseline read from disk, not remembered)")
    print("=" * 72)
    rows = [("items_total", "items_total"),
            ("items_active", "items_active"),
            ("high_confidence", None),
            ("classes", "classes"),
            ("class_domain rows", "class_domain_rows"),
            ("sources", "sources"),
            ("chains", "chains")]
    print("  %-22s %8s %8s %8s" % ("metric", "before", "after", "delta"))
    for label, key in rows:
        k = key or label.replace(" ", "_")
        b = BASE.get(k, BASE.get("items_by_state", {}).get("high_confidence", 0))
        n = a.get(k)
        if k == "high_confidence":
            b = BASE["states"].get("high_confidence", 0)
        d = (n - b) if isinstance(n, int) and isinstance(b, int) else "?"
        print("  %-22s %8s %8s %8s" % (label, b, n, d))

    print()
    print("  PER DOMAIN (active items)")
    doms = sorted(set(list(BASE["per_domain_items"]) + list(a["per_domain_items"])))
    for d in doms:
        b = BASE["per_domain_items"].get(d, 0)
        n = a["per_domain_items"].get(d, 0)
        bh = BASE["per_domain_high_conf"].get(d, 0)
        nh = a["per_domain_high_conf"].get(d, 0)
        print("    %-10s items %5d -> %5d (%+d)   high_conf %4d -> %4d (%+d)"
              % (d, b, n, n - b, bh, nh, nh - bh))

    print()
    print("  NEW CLASSES (no baseline row)")
    for cid in sorted(a["per_class"]):
        if cid not in BASE["per_class"]:
            v = a["per_class"][cid]
            print("    %-26s %-8s items=%d high_conf=%d hosts=%d"
                  % (cid, v["domain"], v["items"], v["high_conf"], v["hosts"]))

    print()
    print("  BIGGEST MOVEMENT PER CLASS (top 12 by items gained)")
    moved = []
    for cid, v in a["per_class"].items():
        b = BASE["per_class"].get(cid, {}).get("items", 0)
        if v["items"] - b:
            moved.append((v["items"] - b, cid, b, v["items"],
                          v["high_conf"], v["hosts"]))
    moved.sort(reverse=True)
    for d, cid, b, n, hc, hosts in moved[:12]:
        print("    %-26s %4d -> %4d (%+d)  hc=%-3d hosts=%d"
              % (cid, b, n, d, hc, hosts))

    out = os.path.join(ROOT, "research", "after.json")
    with open(out, "w", encoding="utf-8") as fh:
        json.dump(a, fh, indent=1)
    print("\nwrote %s" % out)


if __name__ == "__main__":
    main()