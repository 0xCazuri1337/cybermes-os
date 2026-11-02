"""Repair the 35 items held on BOILERPLATE_DISPROOF by re-deriving their disproof.

MEASURED (2026-10-04): `ad_acl_abuse` (20 items / 3 supported),
`password_attacks` (21 / 3) and `internal_recon` (6 / 3) cannot mature because
MATURITY_MIN_HIGH_CONF is 4. 35 of their items are held on BOILERPLATE_DISPROOF
alone, and every one carries the identical template emitted by
`orch/researcher.py::_disproof` before it was fixed.

This rewrites ONLY the disproof of items whose sole blocking reason is
BOILERPLATE_DISPROOF, replacing it with the newly-derived falsifier, and then
re-gates. Three hard constraints:

  1. ONLY items whose gate_reasons are exactly the boilerplate reason (possibly
     with a partner reason) are touched. An item held for a real reason --
     INSUFFICIENT_PUBLISHER_HOSTS, OFF_CLASS_TOPIC, a quote that is not on the
     page -- is left completely alone. Rewriting those would be laundering a
     genuine rejection.
  2. The claim is NEVER changed. Only the falsifier is replaced, and only by one
     derived from that same claim.
  3. Success is measured by RE-GATING from the db, never by counting rows.

Run:  python tools/repair_boilerplate_disproof.py [--dry]
"""
from __future__ import annotations

import argparse
import re
import sqlite3
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from wks import disproof as D, store  # noqa: E402

# Reasons that mean "this item is genuinely bad". Never launder these.
BLOCKING = {
    "INSUFFICIENT_PUBLISHER_HOSTS", "INSUFFICIENT_SOURCES",
    "QUOTE_NOT_FOUND_ON_CITED_PAGE", "OFF_CLASS_TOPIC", "MODULE_FILLER",
    "UNVERIFIABLE_PARTNER", "REJECTED_MODULE_FILLER",
}


def reasons_of(raw: str) -> set[str]:
    """Pull the reason tokens out of a gate_reasons string."""
    if not raw:
        return set()
    toks = re.findall(r"[A-Z][A-Z0-9_]{4,}", raw)
    out = set()
    for t in toks:
        # drop the "REJECTED_" prefix variants into their base name
        out.add(t)
        if t.startswith("REJECTED_"):
            out.add(t[len("REJECTED_"):])
    return out


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--dry", action="store_true")
    args = ap.parse_args()

    from orch.researcher import _disproof

    con = store.open_db(create=False)
    rows = con.execute("""
        SELECT i.id, i.item_key, i.claim, i.class_id, q.gate_reasons
        FROM item i JOIN quality q ON q.item_id = i.id
        WHERE i.status='active'
          AND q.validation_state != 'high_confidence'
          AND q.gate_reasons LIKE '%BOILERPLATE_DISPROOF%'
    """).fetchall()
    print(f"items held on BOILERPLATE_DISPROOF: {len(rows)}")

    repairable, skipped = [], []
    for r in rows:
        rs = reasons_of(r["gate_reasons"])
        hard = rs & BLOCKING
        claim = r["claim"] or ""
        # The new disproof must itself be clean, or we would rewrite boilerplate
        # with different boilerplate.
        new = _disproof(claim)
        if D.reason_for(new, claim) is not None:
            skipped.append((r["item_key"], "new disproof still fails the gate"))
        elif hard:
            skipped.append((r["item_key"], f"also blocked by {sorted(hard)}"))
        else:
            repairable.append((r["id"], r["item_key"], r["class_id"], claim, new))

    print(f"  repairable (boilerplate is the ONLY blocker): {len(repairable)}")
    print(f"  skipped (genuinely blocked for another reason): {len(skipped)}")
    by_class: dict[str, int] = {}
    for _, k, cid, _, _ in repairable:
        by_class[cid] = by_class.get(cid, 0) + 1
    for c, n in sorted(by_class.items(), key=lambda kv: -kv[1]):
        print(f"    {c:24} {n}")
    for k, why in skipped[:6]:
        print(f"    SKIP {k[:44]:46} {why}")
    if args.dry:
        con.close()
        return 0

    for iid, key, cid, claim, new in repairable:
        con.execute("UPDATE item SET disproof=?, updated_at=? WHERE id=?",
                    (new, store.now(), iid))
    con.commit()
    print(f"\nrewrote {len(repairable)} disproof field(s)")

    # Re-gate from the db and report what the ENGINE says, not what we intended.
    from wks import quality
    counts = quality.assess_all(con)
    con.commit()
    print(f"re-gate: {counts}")

    # Per-class effect, measured.
    for cid in sorted(by_class):
        m = quality.maturity(con, cid)
        print(f"  {cid:24} items={m['n_items']:<3} supported={m['n_supported']:<3} "
              f"state={m['state']} missing={m['missing']}")
    con.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())