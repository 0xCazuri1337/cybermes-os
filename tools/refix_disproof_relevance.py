"""Re-derive falsifiers for items the FIRST repair pass wrote with the buggy matcher.

MEASURED (2026-10-04): the first `repair_boilerplate_disproof.py` run rewrote 295
disproofs using a matcher that tested bare substrings, so `"file"` matched inside
**"profile"** and some authn/authz claims were given a FILESYSTEM falsifier. Those
items are now PROMOTED, so the boilerplate repair will not touch them again -- the
damage is already through the gate and must be corrected explicitly.

Scope is deliberately narrow and auditable: only items whose disproof matches the
first-pass template SHAPE (it begins "Refuted when:" AND contains the old
substring-matcher branch text) are re-derived. Items whose disproof was authored
by a person, or by a newer path, are left alone.

Verification is per item, not aggregate: after the rewrite each disproof must (a)
still pass `disproof.reason_for` and (b) no longer carry a branch that contradicts
the claim's own mechanism.

Run:  python tools/refix_disproof_relevance.py [--dry]
"""
from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

ROOT = Path(r"C:\Users\Administrator\.hermes\cyber")
sys.path.insert(0, str(ROOT))

from wks import disproof as D, store  # noqa: E402

# Branch texts the buggy first pass could emit. An item carrying one of these
# AND whose claim does NOT match that branch is exactly the damage to fix.
BRANCH_MARKERS = {
    "permitted base directory": ("traversal", "path", "file", "directory", "filesystem"),
    "Location host": ("redirect", "location", "url"),
    "bound as a parameter": ("injection", "inject", "execute", "concatenated",
                             "interprets", "parsed"),
    "lower-privileged identity": ("privilege", "escalat", "root", "admin",
                                 "write_dac", "ownership"),
    "byte-identical to the baseline": ("leak", "disclos", "expos", "reveal"),
    "defensive control": ("bypass", "evade", "defeat"),
}


def wrong_branch(disproof: str, claim: str) -> str | None:
    """Which branch is present that the claim does not support (if any)."""
    d = (disproof or "").lower()
    c = (claim or "").lower()
    for marker, supports in BRANCH_MARKERS.items():
        if marker not in d:
            continue
        if not any(re.search(rf"\b{re.escape(w)}", c) for w in supports):
            return marker
    return None


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--dry", action="store_true")
    args = ap.parse_args()

    import importlib
    from orch import researcher as R
    importlib.reload(R)

    con = store.open_db(create=False)
    rows = con.execute("""
        SELECT i.id, i.item_key, i.claim, i.disproof
        FROM item i JOIN quality q ON q.item_id = i.id
        WHERE i.status='active' AND q.validation_state='high_confidence'
          AND i.disproof LIKE 'Refuted when:%'
    """).fetchall()

    wrong = []
    for r in rows:
        b = wrong_branch(r["disproof"], r["claim"])
        if b:
            wrong.append((r["id"], r["item_key"], r["claim"], b))
    print(f"promoted items with a first-pass disproof: {len(rows)}")
    print(f"  carrying a MISMATCHED branch: {len(wrong)}")
    for _, k, c, b in wrong[:8]:
        print(f"    {k[:44]:46} branch={b}")
        print(f"        claim: {c[:74]}")

    if args.dry:
        con.close()
        return 0

    fixed = 0
    for iid, key, claim, _b in wrong:
        new = R._disproof(claim)
        if D.reason_for(new, claim) is not None:
            print(f"    SKIP {key[:44]} -- re-derived disproof still fails")
            continue
        if wrong_branch(new, claim) is not None:
            print(f"    SKIP {key[:44]} -- re-derived branch still mismatched")
            continue
        con.execute("UPDATE item SET disproof=?, updated_at=? WHERE id=?",
                    (new, store.now(), iid))
        fixed += 1
    con.commit()
    print(f"\nrewrote {fixed} disproof(s)")

    from wks import quality
    counts = quality.assess_all(con)
    con.commit()
    print(f"re-gate: {counts}")
    # verify no mismatch remains among the ones we just wrote
    still = 0
    for r in con.execute("""SELECT i.claim, i.disproof FROM item i
                            JOIN quality q ON q.item_id=i.id
                            WHERE i.status='active'
                              AND q.validation_state='high_confidence'
                              AND i.disproof LIKE 'Refuted when:%'"""):
        if wrong_branch(r["disproof"], r["claim"]):
            still += 1
    print(f"remaining mismatched branches among promoted items: {still}")
    con.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())