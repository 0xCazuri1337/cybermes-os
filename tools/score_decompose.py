"""Where do the missing web points go? Per-axis decomposition.

68.8/100 is not "web is weak" -- it is a weighted average, and an average hides
which axis is dragging. This prints, for one domain, every axis's mean
achieved fraction against its weight, so the shortfall is attributed to a
specific axis instead of being smeared across all eight.
"""
import collections
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from wks import store  # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
AXES = [("COVERAGE", 40, 1.0), ("PROOF", 6, 2.0), ("VARIANT", 5, 1.5),
        ("MARGIN", 5, 1.5), ("FP", 4, 1.5), ("CHAIN", 1, 1.0),
        ("RETRIEVAL", 0.95, 1.0), ("FRESH", 1.0, 0.5)]

DOM = sys.argv[1] if len(sys.argv) > 1 else "web"


def clamp01(x):
    return max(0.0, min(1.0, x))


def main():
    con = store.connect()
    meas = {}
    mp = os.path.join(ROOT, "research", "measured_axes.json")
    if os.path.exists(mp):
        meas = json.load(open(mp, encoding="utf-8"))
    retrieval = (meas.get("retrieval") or {}).get("retrieval", 0.875)
    fresh = (meas.get("freshness") or {}).get("alive_rate", 0.993)

    dom_of = dict(con.execute("SELECT class_id, domain FROM class_domain"))
    rows = []
    for cid in dom_of:
        if dom_of[cid] != DOM:
            continue
        it = con.execute("SELECT COUNT(*) FROM item WHERE class_id=? AND"
                         " status='active'", (cid,)).fetchone()[0]
        hc = con.execute(
            "SELECT COUNT(*) FROM item i JOIN quality q ON q.item_id=i.id"
            " WHERE i.class_id=? AND i.status='active'"
            " AND q.validation_state='high_confidence'", (cid,)).fetchone()[0]
        k = collections.Counter(x[0] for x in con.execute(
            "SELECT i.kind FROM item i JOIN quality q ON q.item_id=i.id"
            " WHERE i.class_id=? AND i.status='active'"
            " AND q.validation_state='high_confidence'", (cid,)))
        fp = con.execute("SELECT COUNT(*) FROM fp_case WHERE class_id=?",
                         (cid,)).fetchone()[0]
        ch = con.execute(
            "SELECT COUNT(DISTINCT c.id) FROM chain c JOIN chain_step s"
            " ON s.chain_id=c.id WHERE s.item_id IN"
            " (SELECT id FROM item WHERE class_id=? AND status='active')",
            (cid,)).fetchone()[0]
        orgs = {o for (o,) in con.execute(
            "SELECT DISTINCT s.host FROM item i JOIN item_source x"
            " ON x.item_id=i.id JOIN source s ON s.id=x.source_id"
            " WHERE i.class_id=? AND i.status='active'", (cid,))}
        rows.append({
            "cid": cid, "items": it, "hc": hc,
            "proof": k["test"] + k["validation"],
            "variant": k["variant"] + k["bypass"],
            "fp": fp, "chains": ch, "orgs": len(orgs)})

    def axis_vals(r):
        return {
            "COVERAGE": clamp01(r["items"] / 40),
            "PROOF": clamp01(r["proof"] / 6),
            "VARIANT": clamp01(r["variant"] / 5),
            "MARGIN": clamp01((r["orgs"] - 1) / 4),
            "FP": clamp01(r["fp"] / 4),
            "CHAIN": clamp01(r["chains"] / 1),
            "RETRIEVAL": retrieval,
            "FRESH": fresh,
        }

    print("=" * 88)
    print("WEB SCORE DECOMPOSITION  (%d classes)" % len(rows))
    print("=" * 88)
    print("  %-11s %8s %8s %10s %12s" % ("axis", "mean", "target", "weight",
                                         "points lost"))
    total_w = sum(a[2] for a in AXES)
    lost_total = 0.0
    for name, target, w in AXES:
        vals = [axis_vals(r)[name] for r in rows]
        mean = sum(vals) / len(vals)
        pts = 100.0 * mean * w / total_w
        lost = 100.0 * (1 - mean) * w / total_w
        lost_total += lost
        print("  %-11s %8.3f %8.2f %10.1f %12.1f" % (name, mean, 1.0, w, lost))
    print()
    score = 100 - lost_total
    print("  score = 100 - %.1f lost = %.1f" % (lost_total, score))
    print()
    print("  RANKED BY POINTS LOST (this is the answer to 'why 68.8'):")
    order = sorted(AXES, key=lambda a: -sum(
        1 - axis_vals(r)[a[0]] for r in rows) * a[2])
    for name, target, w in order:
        mean = sum(axis_vals(r)[name] for r in rows) / len(rows)
        lost = 100.0 * (1 - mean) * w / total_w
        if lost > 0.4:
            print("     %-11s -%.1f pts   (classes short: %d)" % (
                name, lost, sum(1 for r in rows if axis_vals(r)[name] < 0.5)))
    print()
    print("  THE CLASSES HOLDING EACH AXIS BACK:")
    for name in ("VARIANT", "FP", "CHAIN", "MARGIN"):
        bad = sorted([r for r in rows if axis_vals(r)[name] < 0.5],
                     key=lambda r: axis_vals(r)[name])
        if not bad:
            continue
        print("\n   %s: %d class(es) at zero/low" % (name, len(bad)))
        for r in bad[:8]:
            raw = {"VARIANT": r["variant"], "FP": r["fp"],
                   "CHAIN": r["chains"], "MARGIN": r["orgs"]}[name]
            print("      %-26s %s=%d  (items=%d hc=%d proof=%d)"
                  % (r["cid"], name.lower(), raw, r["items"], r["hc"],
                     r["proof"]))


if __name__ == "__main__":
    main()