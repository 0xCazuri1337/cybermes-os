"""Measure the BLAST RADIUS of adding vocabulary to relevance.CLASS_VOCAB.

A vocabulary edit is not local: the same terms also decide whether OTHER
classes' items are MISFILED.  This tool reports both directions so a fix is
never shipped on the strength of one number:

  A) api_trust items that currently stop being held (the intended win).
  B) items in EVERY other class whose verdict changes (collateral damage).
  C) the self-test battery still passes in both directions.

Run:  python tools/w12_relevance_blast.py
Exit non-zero if the selftest fails or a candidate term is not inert.
"""
import os
import sys

WKS = os.environ.get("WKS_ROOT", "C:/Users/Administrator/.hermes/cyber")
sys.path.insert(0, WKS)

from wks import relevance, store  # noqa: E402

# Candidate terms for api_trust.  Each MUST be (1) present in the held items,
# (2) absent from every other class's generic prose, or it will swallow them.
CANDIDATES = [
    "audience claim",
    "audience validation",
    "token audience",
    "resource server",
    "service account",
    "service credential",
    "client credential",
    "api gateway",
    "per-application",
    "cross-audience",
]


def verdicts(con):
    rows = con.execute(
        """SELECT i.class_id cid, i.item_key ik, i.claim cl
           FROM item i JOIN quality q ON q.item_id=i.id
           WHERE q.validation_state IN ('under_review','high_confidence')"""
    ).fetchall()
    return [(r["cid"], r["ik"], r["cl"]) for r in rows]


def main():
    con = store.open_db()
    base = {}
    for cid, ik, cl in verdicts(con):
        v = relevance.assess(cid, cl)
        base[ik] = v.state if v else "UNPROBEABLE"

    # --- C) selftest BEFORE the edit, so we know the battery is trustworthy
    ok, fails = relevance.selftest(verbose=False)
    print(f"selftest BEFORE: {'PASS' if ok else 'FAIL'} ({len(fails)} failures)")
    if not ok:
        for f in fails:
            print("   ", f)
        raise SystemExit("refusing to edit vocabulary: battery is already red")

    # --- which candidates fire on the held api_trust items
    held = [r for r in con.execute(
        """SELECT i.item_key ik, i.claim cl FROM item i JOIN quality q
           ON q.item_id=i.id WHERE i.class_id='api_trust'
           AND q.gate_reasons LIKE '%OFF_CLASS_TOPIC%'"""
    ).fetchall()]
    print(f"\nheld api_trust items: {len(held)}")
    for term in CANDIDATES:
        pat = relevance._term_pattern(term)
        fires = [r["ik"] for r in held if pat and
                 __import__("re").search(r"(?<![a-z0-9])" + pat + r"(?![a-z0-9])",
                                         relevance._normalise(r["cl"]))]
        print(f"  {term:24s} fires on {len(fires)}/{len(held)}")

    # --- simulate the edit and diff every item's verdict
    orig = relevance.CLASS_VOCAB["api_trust"]
    relevance.CLASS_VOCAB["api_trust"] = sorted(set(orig) | set(CANDIDATES))
    changed = []
    for cid, ik, cl in verdicts(con):
        v = relevance.assess(cid, cl)
        new = v.state if v else "UNPROBEABLE"
        if new != base[ik]:
            changed.append((ik, cid, base[ik], new))
    relevance.CLASS_VOCAB["api_trust"] = orig

    print(f"\nverdict changes: {len(changed)}")
    for ik, cid, b, a in changed:
        print(f"  {cid:26s} {ik[:52]:52s} {b} -> {a}")

    ok2, fails2 = relevance.selftest(verbose=False)
    print(f"\nselftest AFTER (in-memory only, nothing written): "
          f"{'PASS' if ok2 else 'FAIL'}")
    for f in fails2:
        print("   ", f)

    freed = [c for c in changed if c[2] == "MISFILED" and c[3] != "MISFILED"]
    harmed = [c for c in changed if c[2] != "MISFILED" and c[3] == "MISFILED"]
    print(f"\nSUMMARY: freed={len(freed)} newly_misfiled={len(harmed)}")
    return 1 if harmed else 0


if __name__ == "__main__":
    raise SystemExit(main())