"""Gap check per DOMAIN and per SURFACE, measured from the corpus + source queue.

A gap report that only counts items is the failure this tool exists to avoid: the
corpus can read 100% mature while every class rests on two publishers, and a
class with 90 items can hold nothing about how to PROVE a finding. So each class
is scored on four axes:

  VOLUME   items and high_confidence against the maturity floor
  PROOF    does it hold a `test`/`validation` item? (how do I prove this?)
  VARIANT  does it hold `variant`/`bypass` items? (do I know the sub-forms?)
  MARGIN   how many DISTINCT publisher ORGs back it? (can it survive one page
           being rewritten? 2 is the bare gate minimum)

Output: a ranked table per domain with the ONE next action per gap, and an
overall verdict per axis.
"""
import collections
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from wks import config, store  # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MIN_ITEMS = 12
MIN_HC = 4
NEED_PROOF = ("test", "validation")
NEED_VARIANT = ("variant", "bypass")
MIN_ORGS = 3          # above the gate's floor of 2, for real margin


def main():
    con = store.connect()
    dom_of = {cid: d for cid, d in con.execute(
        "SELECT class_id, domain FROM class_domain")}
    surf_of = dict(con.execute("SELECT id, surface FROM bug_class"))

    rows = []
    for cid, in con.execute("SELECT id FROM bug_class"):
        items = con.execute(
            "SELECT COUNT(*) FROM item WHERE class_id=? AND status='active'",
            (cid,)).fetchone()[0]
        hc = con.execute(
            "SELECT COUNT(*) FROM item i JOIN quality q ON q.item_id=i.id"
            " WHERE i.class_id=? AND i.status='active'"
            "   AND q.validation_state='high_confidence'", (cid,)).fetchone()[0]
        kinds = collections.Counter(
            k for (k,) in con.execute(
                "SELECT i.kind FROM item i JOIN quality q ON q.item_id=i.id"
                " WHERE i.class_id=? AND i.status='active'"
                "   AND q.validation_state='high_confidence'", (cid,)))
        orgs = {config.publisher_org(h) for (h,) in con.execute(
            "SELECT s.host FROM item i JOIN item_source x ON x.item_id=i.id"
            " JOIN source s ON s.id=x.source_id"
            " WHERE i.class_id=? AND i.status='active'", (cid,))}
        rows.append({
            "cid": cid, "domain": dom_of.get(cid, "?"),
            "surface": surf_of.get(cid, "?"), "items": items, "hc": hc,
            "proof": sum(kinds.get(k, 0) for k in NEED_PROOF),
            "variant": sum(kinds.get(k, 0) for k in NEED_VARIANT),
            "orgs": len(orgs),
        })

    for domain in sorted({r["domain"] for r in rows}):
        sel = [r for r in rows if r["domain"] == domain]
        print("=" * 88)
        print("DOMAIN: %s   (%d classes)" % (domain, len(sel)))
        print("=" * 88)
        gaps = {"volume": [], "proof": [], "variant": [], "margin": []}
        for r in sel:
            if r["items"] < MIN_ITEMS or r["hc"] < MIN_HC:
                gaps["volume"].append(r)
            if r["proof"] == 0:
                gaps["proof"].append(r)
            if r["variant"] == 0:
                gaps["variant"].append(r)
            if r["orgs"] < MIN_ORGS:
                gaps["margin"].append(r)
        print("  %-26s %-10s %5s %5s %6s %8s %6s" %
              ("class", "surface", "items", "hc", "proof", "variant", "orgs"))
        for r in sorted(sel, key=lambda r: (-r["items"])):
            print("  %-26s %-10s %5d %5d %6d %8d %6d%s" %
                  (r["cid"], r["surface"], r["items"], r["hc"], r["proof"],
                   r["variant"], r["orgs"],
                   "  <-- thin margin" if r["orgs"] < MIN_ORGS else ""))
        print()
        for axis, lst in gaps.items():
            print("  GAP %-8s %d class(es): %s"
                  % (axis, len(lst), ", ".join(r["cid"] for r in lst) or "none"))
        print()

    # ---- the one thing to do first --------------------------------------
    allgap = {"volume": [], "proof": [], "variant": [], "margin": []}
    for r in rows:
        if r["items"] < MIN_ITEMS or r["hc"] < MIN_HC:
            allgap["volume"].append(r["cid"])
        if r["proof"] == 0:
            allgap["proof"].append(r["cid"])
        if r["variant"] == 0:
            allgap["variant"].append(r["cid"])
        if r["orgs"] < MIN_ORGS:
            allgap["margin"].append(r["cid"])
    print("=" * 88)
    print("CORPUS-WIDE GAP SUMMARY")
    print("=" * 88)
    for axis, lst in allgap.items():
        print("  %-8s %3d  %s" % (axis, len(lst), ", ".join(lst)[:150]))
    print()
    first = min(allgap["volume"], key=lambda c: next(
        r["hc"] for r in rows if r["cid"] == c), default=None)
    print("  NEXT ACTION, thin-volume classes: research from a source that is not")
    print("  the same genre. `tools/src_packets.py` + `ht_stage.py` per class.")
    print("  Cheapest closeable gaps:")
    cheap = sorted([c for c in allgap["proof"]],
                   key=lambda c: -next(r["items"] for r in rows if r["cid"] == c))
    for c in cheap[:8]:
        r = next(x for x in rows if x["cid"] == c)
        print("     %-26s items=%-3d hc=%-3d orgs=%-2d  -> needs `test` items "
              "(proof criteria); cheapest kind to add"
              % (c, r["items"], r["hc"], r["orgs"]))


if __name__ == "__main__":
    main()