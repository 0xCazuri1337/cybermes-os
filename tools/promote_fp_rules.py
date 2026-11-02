"""Promote gated `fp_rule` ITEMS into `fp_case` ROWS.

WHY THIS IS A SEPARATE STEP. The learning loop's priority metric counts
`fp_case` rows, but a research wave produces `item` rows with `kind='fp_rule'`.
Those are different tables: an item is knowledge with evidence and a gate
verdict, an fp_case is the durable rejection rule that `quality.maturity()`
counts and that `skillgen` renders into the per-class skill. Research alone
never closes the fp gap, and closing it by hand-editing the db would bypass the
very gate the item already passed.

So the promotion is mechanical and auditable:

  * ONLY items whose gate verdict is `supported` or `high_confidence` are
    promoted. An fp rule the gate refused is not knowledge, and promoting it
    would let a thin item satisfy a maturity gate.
  * `hypothesis`   <- the claim (what was believed)
  * `test`         <- the body (what was actually done)
  * `invalidated_by` <- the disproof (what would show it is real)
  * `rejection_rule` <- the claim restated as a rule

Refuses to double-promote: a key already in `fp_case` is reported, not
duplicated, so re-running this is idempotent.
"""
from __future__ import annotations

import sqlite3
import sys
from pathlib import Path

from wks import store


def main() -> int:
    con = store.open_db(create=True)
    con.row_factory = sqlite3.Row

    promoted, skipped, already = [], [], []
    # `store.add_fp` returns the EXISTING id when fp_key already exists, so it
    # is idempotent on its own. There is no `store.get_fp` — verified against
    # the module rather than assumed — so idempotency is detected by querying
    # fp_case directly instead of calling a function that does not exist.
    existing = {r["fp_key"] for r in con.execute("SELECT fp_key FROM fp_case")}
    rows = con.execute(
        """SELECT i.item_key, i.class_id, i.claim, i.body, i.disproof,
                  q.validation_state
             FROM item i JOIN quality q ON q.item_id = i.id
            WHERE i.kind='fp_rule' AND i.status='active'
            ORDER BY i.class_id, i.item_key"""
    ).fetchall()

    if not rows:
        print("no active fp_rule items found")
        return 0

    for r in rows:
        cid = r["class_id"]
        state = r["validation_state"]
        if state not in ("supported", "high_confidence"):
            skipped.append((r["item_key"], f"gate state {state!r} is not promoted"))
            continue
        key = f"{cid}.fp.{r['item_key'].split('.', 1)[-1]}"
        if key in existing:
            already.append(key)
            continue
        fp_id = store.add_fp(
            con, key, cid,
            hypothesis=r["claim"],
            # `test_performed`, not `test` — verified against the signature in
            # wks/store.py rather than assumed from the fp_case COLUMN name,
            # which is `test_performed` too but the kwarg is not the column.
            test_performed=r["body"],
            invalidated_by=r["disproof"],
            rejection_rule=r["claim"],
            looked_vulnerable_because=None,
            early_signal_missed=None,
        )
        con.execute("UPDATE bug_class SET last_reviewed=? WHERE id=?",
                    (store.now(), cid))
        promoted.append((key, cid, fp_id))

    con.commit()
    con.close()

    print(f"fp_rule items seen   : {len(rows)}")
    print(f"promoted to fp_case  : {len(promoted)}")
    for k, c, i in promoted:
        print(f"   + {k}  (class {c}, fp id {i})")
    if already:
        print(f"already present      : {len(already)}")
        for k in already:
            print(f"   = {k}")
    if skipped:
        print(f"SKIPPED (not gated)  : {len(skipped)}")
        for k, why in skipped:
            print(f"   ! {k}: {why}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())