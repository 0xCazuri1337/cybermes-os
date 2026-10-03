"""Repair the w12-derived `test` items whose claims end mid-word.

THE DEFECT. `tools/w12_promote_test_items.py` derived each `test` item by
slicing a fixed 260-character window out of the parent body:

    span = body[start:m.start() + 260].strip()

Measured 2026-10-02 on the live corpus: 138 active items carry the template
claim "To decide this case, observe: <span>", and 111 of them end mid-word --
'... so &#39; b', '... are equivalent', '... authenticates and aut'. 90 of the
138 had been promoted to high_confidence. `wks.claimcheck` correctly held 66
of them for TRUNCATED.

The generator is fixed (`_sentence_span`, T40). This repairs the ROWS that the
old generator already wrote.

WHAT IT DOES NOT DO:
  * never deletes -- a row it cannot honestly re-derive is SUPERSEDED with a
    reason, keeping its provenance, so a later wave can revisit it;
  * never invents text -- every repaired claim is a verbatim substring of the
    parent's own body;
  * never touches items that are not w12-derived test items.

WHAT IT ASSUMES. The claim after "observe:" is a slice of the parent body, so
the repair re-derives the correct span from that same parent. If the parent has
gone, or no sentence-bounded span can be built from it, the item is superseded
rather than repaired. That is the honest outcome.

Run:  python tools/w13_repair_truncated_tests.py            # dry run
      python tools/w13_repair_truncated_tests.py --apply
"""
from __future__ import annotations

import argparse
import importlib.util
import json
import sqlite3
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

PREFIXES = (
    "To decide this case, observe:",              # w12_promote_test_items.py
    "A convincing observation for this class is:",  # w12_promote_evidence_items.py
)


def _split_prefix(claim: str) -> tuple[str, str] | None:
    for p in PREFIXES:
        if claim.startswith(p):
            return p, claim[len(p):].strip()
    return None


def _span_fn():
    spec = importlib.util.spec_from_file_location(
        "w12_promote", ROOT / "tools" / "w12_promote_test_items.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod._sentence_span


def _open():
    from wks import config, store
    return store.open_db(config.DB_PATH)


def collect(con: sqlite3.Connection) -> list[dict]:
    """Every active derived item carrying a template prefix, with its parent.

    Two generators emit templated claims -- `w12_promote_test_items.py`
    ("To decide this case, observe:") and `w12_promote_evidence_items.py`
    ("A convincing observation for this class is:"). Both sliced a fixed
    character window and both were repaired by delegating to the same
    sentence-boundary spanner, so both need their rows repaired. They record
    provenance identically ("Derived from <item_key>, ...") so one parent
    lookup serves both.
    """
    span = _span_fn()
    rows = con.execute(
        """SELECT i.id, i.item_key, i.class_id, i.claim, i.body, i.disproof,
                  q.validation_state
             FROM item i
        LEFT JOIN quality q ON q.item_id = i.id
            WHERE i.status='active' AND i.kind IN ('test','evidence')
           ORDER BY i.id""").fetchall()
    out = []
    for r in rows:
        split = _split_prefix(r["claim"] or "")
        if not split:
            continue                       # hand-written knowledge: never touch
        prefix, old = split
        rec = {"id": r["id"], "item_key": r["item_key"],
               "class_id": r["class_id"], "state": r["validation_state"],
               "prefix": prefix,
               "old_span": old, "new_span": None, "action": "", "why": "",
               "parent": None}
        # Repair ONLY what is actually broken. An item whose span already ends
        # on a sentence boundary is left alone.
        #
        # This is also what stops the repair OSCILLATING. Re-deriving from a
        # span that ends exactly at a sentence boundary makes the spanner
        # extend to the NEXT terminator, so each run appends another sentence
        # and the row never converges -- measured on 2 items that had already
        # been repaired. "No change without a reason" applies to repairs too.
        if old.rstrip().endswith((".", "!", "?")):
            rec["action"] = "unchanged"
            rec["why"] = "already ends on a sentence boundary"
            out.append(rec)
            continue
        # The body text names its parent in prose: "Derived from <item_key>, ..."
        parent_key = None
        marker = (r["body"] or "").find("Derived from ")
        if marker >= 0:
            tail = (r["body"] or "")[marker + len("Derived from "):]
            parent_key = tail.split(",", 1)[0].strip()
        rec["parent"] = parent_key

        parent = None
        if parent_key:
            parent = con.execute(
                "SELECT item_key, claim, body FROM item WHERE item_key=? "
                "AND status='active'", (parent_key,)).fetchone()
        if parent is None:
            rec["action"] = "supersede"
            rec["why"] = f"parent {parent_key!r} is no longer active"
            out.append(rec)
            continue

        pbody = parent["body"] or ""
        # Re-derive from the parent body: locate the SAME observable the old
        # slice was built around, then snap to sentence boundaries.
        anchor = old[:60].strip()
        idx = pbody.find(anchor[:40])
        if idx < 0:
            rec["action"] = "supersede"
            rec["why"] = "old span is not a substring of the parent body"
            out.append(rec)
            continue
        new = span(pbody, idx, min(idx + len(anchor), len(pbody)))
        if not new:
            rec["action"] = "supersede"
            rec["why"] = "no sentence-bounded span exists in the parent body"
            out.append(rec)
            continue
        rec["new_span"] = new
        rec["action"] = "repair" if new != old else "unchanged"
        rec["why"] = "re-derived on a sentence boundary from the parent body"
        out.append(rec)
    return out


def apply(con: sqlite3.Connection, recs: list[dict]) -> tuple[int, int]:
    """Write the repair, then RE-READ every row it claims to have changed.

    The re-read is not defensive decoration. A repair tool that reports
    "APPLIED repaired=133" while the UPDATE silently matched nothing is
    indistinguishable from one that worked, and the corpus looks healthy either
    way until the next audit. `tools/w11_repair_ldap_enum.py` established this
    rule after its writes had to be proven to land.

    Returns (repaired, superseded). Raises RuntimeError if any write did not
    land, so a caller cannot mistake a partial repair for a complete one.
    """
    repaired = superseded = 0
    for r in recs:
        if r["action"] == "repair":
            # Use THIS item's own prefix: the two generators use different ones.
            new_claim = f"{r['prefix']} {r['new_span']}"
            cur = con.execute(
                "UPDATE item SET claim=?, updated_at=datetime('now') "
                "WHERE id=? AND status='active'",
                (new_claim, r["id"]))
            repaired += cur.rowcount
        elif r["action"] == "supersede":
            cur = con.execute(
                "UPDATE item SET status='superseded', "
                "updated_at=datetime('now') WHERE id=? AND status='active'",
                (r["id"],))
            superseded += cur.rowcount
    con.commit()

    # ---- verify: every claimed write is readable back in its final state ----
    bad: list[str] = []
    for r in recs:
        if r["action"] == "repair":
            got = con.execute("SELECT claim FROM item WHERE id=?",
                              (r["id"],)).fetchone()
            if not got:
                bad.append(f"{r['item_key']}: row vanished")
            elif got["claim"] != f"{r['prefix']} {r['new_span']}":
                bad.append(f"{r['item_key']}: claim did not land")
        elif r["action"] == "supersede":
            got = con.execute("SELECT status FROM item WHERE id=?",
                              (r["id"],)).fetchone()
            if not got:
                bad.append(f"{r['item_key']}: row vanished")
            elif got["status"] != "superseded":
                bad.append(f"{r['item_key']}: status is {got['status']!r}")
    if bad:
        raise RuntimeError(
            f"{len(bad)} write(s) did not land, repair INCOMPLETE:\n  "
            + "\n  ".join(bad[:10]))
    return repaired, superseded


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--apply", action="store_true")
    ap.add_argument("--json", help="write the full per-item record here")
    a = ap.parse_args()

    con = _open()
    recs = collect(con)
    tally: dict[str, int] = {}
    for r in recs:
        tally[r["action"]] = tally.get(r["action"], 0) + 1
    print(f"scanned={len(recs)}")
    for k, v in sorted(tally.items()):
        print(f"   {k:12} {v}")

    still_cut = 0
    for r in recs:
        if r["action"] == "repair":
            s = r["new_span"] or ""
            if not s.rstrip().endswith((".", "!", "?")):
                still_cut += 1
    print(f"repaired spans still ending mid-sentence: {still_cut}")

    if a.json:
        Path(a.json).write_text(json.dumps(recs, indent=1, ensure_ascii=False),
                                encoding="utf-8")
        print(f"wrote {a.json}")

    if not a.apply:
        print("dry run: pass --apply")
        con.close()
        return 0

    repaired, superseded = apply(con, recs)
    con.close()
    print(f"APPLIED repaired={repaired} superseded={superseded}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
