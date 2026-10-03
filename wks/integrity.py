"""Corpus integrity repairs: duplicates, malformed keys, orphaned conflicts.

Three defects, three different correct behaviours. None of them deletes a row,
because every one of these rows is evidence or audit history:

D-1 ONE exact duplicate pair, both live and both promoted
     xss.technique.html_attribute.break_out_and_add_event_handler
     xss.technique.html_attribute.new_event_handler_without_angle_brackets
     carry a byte-identical claim. Deleting one would discard its citations;
     two promoted rows asserting the same knowledge double-counts the corpus
     and makes `duplicate_claim_groups` look like a rounding error. So the
     duplicate is MARKED (`dedup_of` -> the canonical row) and left intact: a
     duplicate that cited different sources is evidence, not garbage. Which row
     is canonical is decided by citation count, then by earliest creation, so
     the choice is deterministic and not a coin flip.

D-2 SIX malformed item_keys with only two segments
     `<class>.<slug>` instead of `<class>.<kind>.<name>`. `item_key` is parsed
     by first segment, so these still resolve their class, but the kind segment
     that every consumer reads is missing. Renamed in place (the key is a slug,
     not a citation), with the row's `class_id` untouched. Renaming is safe
     because no `chain_step`/`evidence`/`mastery` record references an item by
     key -- all of them reference `item.id`, which does not change.

D-3 NINE orphaned conflict rows
     `conflict` rows whose `claim_a` matches no item in the corpus: the claim
     was rejected at ingest and never entered. They are NOT fabrications -- they
     are the audit trail of a rejection, and the invariant is that they are
     retained. What was wrong was the STATUS: they sat `open`, so
     `open_conflicts: 10` reported 10 live integrity questions when there was 1.
     They are marked `dismissed` with a reason naming why, exactly as the 47
     already-dismissed rows are.

Report-only by default. `--apply` writes.
"""
from __future__ import annotations

import argparse
import json
import re
import sqlite3
import sys
from typing import Any

from wks import config, store

CANON_RE = re.compile(r"^[a-z0-9_]+\.[a-z_]+\.[a-z0-9_]+$")


# --------------------------------------------------------------------------
# D-1
# --------------------------------------------------------------------------
def duplicate_groups(con: sqlite3.Connection) -> list[dict[str, Any]]:
    rows = con.execute(
        """SELECT lower(trim(claim)) c, count(*) n
           FROM item WHERE status='active'
           GROUP BY 1 HAVING n > 1""").fetchall()
    out = []
    for r in rows:
        items = con.execute(
            """SELECT i.id, i.item_key, i.class_id, i.kind, i.created_at,
                      (SELECT count(*) FROM item_source x WHERE x.item_id=i.id) nsrc,
                      (SELECT count(*) FROM item_source x JOIN source s ON s.id=x.source_id
                         WHERE x.item_id=i.id AND lower(s.host) NOT IN
                           (SELECT lower(host) FROM item_source x2
                             JOIN source s2 ON s2.id=x2.source_id
                            WHERE x2.item_id=(SELECT MIN(i2.id) FROM item i2
                                               WHERE lower(trim(i2.claim))=?))) ndistinct
               FROM item i WHERE lower(trim(i.claim))=? AND i.status='active'
                 AND i.dedup_of IS NULL
               ORDER BY i.id""", (r["c"], r["c"])).fetchall()
        out.append({"claim": r["c"], "n": r["n"],
                    "items": [dict(i) for i in items]})
    return out


def pick_canonical(items: list[sqlite3.Row]) -> sqlite3.Row:
    """Deterministic choice: most citations, then earliest id.

    NOT a coin flip and not "first found" -- a repair that picks arbitrarily
    leaves the corpus in a state that depends on row order, which is how the
    same defect produces a different fix every time it is run.
    """
    return sorted(items, key=lambda i: (-(i["nsrc"] or 0), i["id"]))[0]


def mark_duplicates(con: sqlite3.Connection, apply: bool = False) -> dict[str, Any]:
    groups = duplicate_groups(con)
    plan = []
    for g in groups:
        canonical = pick_canonical(g["items"])
        for it in g["items"]:
            if it["id"] == canonical["id"]:
                continue
            same_evidence = (it["ndistinct"] or 0) == 0
            plan.append({
                "duplicate": it["item_key"], "duplicate_id": it["id"],
                "canonical": canonical["item_key"], "canonical_id": canonical["id"],
                "duplicate_sources": it["nsrc"], "canonical_sources": canonical["nsrc"],
                "adds_no_new_publisher": bool(same_evidence),
                "action": "mark dedup_of + canonical_id (row RETAINED)",
            })
    applied = []
    if apply:
        for p in plan:
            con.execute(
                "UPDATE item SET dedup_of=?, canonical_id=? WHERE id=?",
                (p["canonical_id"], p["canonical_id"], p["duplicate_id"]))
            applied.append(p["duplicate"])
        con.commit()
    return {"groups": len(groups), "plan": plan, "applied": applied,
            "note": "no row is deleted; the duplicate keeps its citations"}


# --------------------------------------------------------------------------
# D-2
# --------------------------------------------------------------------------
def malformed_keys(con: sqlite3.Connection) -> list[sqlite3.Row]:
    return con.execute(
        "SELECT id, item_key, class_id, kind FROM item "
        "WHERE item_key NOT LIKE '%.%.%' ORDER BY item_key").fetchall()


def repair_keys(con: sqlite3.Connection, apply: bool = False) -> dict[str, Any]:
    rows = malformed_keys(con)
    plan = []
    for r in rows:
        parts = r["item_key"].split(".")
        new = f"{parts[0]}.{r['kind']}.{parts[1]}"
        clash = con.execute("SELECT id FROM item WHERE item_key=?", (new,)).fetchone()
        plan.append({"old": r["item_key"], "new": new, "id": r["id"],
                    "would_clash": clash is not None})
    applied = []
    if apply:
        for p in plan:
            if p["would_clash"]:
                continue
            con.execute("UPDATE item SET item_key=? WHERE id=?",
                        (p["new"], p["id"]))
            applied.append({"old": p["old"], "new": p["new"]})
        con.commit()
    return {"malformed": len(rows), "plan": plan, "applied": applied,
            "note": ("item_key is a slug, not a citation; class_id is untouched "
                     "and no row references an item by key (chains/evidence/"
                     "mastery all use item.id)")}


# --------------------------------------------------------------------------
# D-3
# --------------------------------------------------------------------------
ORPHAN_REASON = ("orphaned bookkeeping: claim_a matches no item in the corpus, so "
                 "the rejection at ingest stands and this row is retained audit "
                 "trail (invariant I5) -- not an open integrity question")


def orphaned_conflicts(con: sqlite3.Connection) -> list[sqlite3.Row]:
    return con.execute(
        """SELECT c.id, c.class_id, c.topic, substr(c.claim_a,1,90) claim
           FROM conflict c WHERE c.status='open'
             AND NOT EXISTS (SELECT 1 FROM item i
                             WHERE i.class_id=c.class_id AND i.claim=c.claim_a)
           ORDER BY c.id""").fetchall()


def settle_orphans(con: sqlite3.Connection, apply: bool = False) -> dict[str, Any]:
    rows = orphaned_conflicts(con)
    live = con.execute(
        """SELECT c.id, c.class_id, substr(c.claim_a,1,90) claim
           FROM conflict c WHERE c.status='open'
             AND EXISTS (SELECT 1 FROM item i
                         WHERE i.class_id=c.class_id AND i.claim=c.claim_a)
           ORDER BY c.id""").fetchall()
    applied = []
    if apply:
        for r in rows:
            con.execute("UPDATE conflict SET status='dismissed', resolution=? "
                        "WHERE id=?", (ORPHAN_REASON, r["id"]))
            applied.append(r["id"])
        con.commit()
    return {"orphaned": len(rows), "orphaned_ids": [r["id"] for r in rows],
            "still_open_with_live_claim": [dict(r) for r in live],
            "applied": applied}


def report(con: sqlite3.Connection, apply: bool = False) -> dict[str, Any]:
    """Aggregate the three repairs.

    `apply` is FORWARDED to every helper. It was not, so `--apply` printed a
    full plan and then applied nothing -- the report looked complete and the
    work was never done. A flag that reaches the entry point but not the writer
    is the "test the wiring, not just the component" failure in its purest form:
    every helper was individually correct and the feature did nothing.
    """
    return {"duplicates": mark_duplicates(con, apply),
            "malformed_keys": repair_keys(con, apply),
            "conflicts": settle_orphans(con, apply)}


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="wks.integrity")
    ap.add_argument("--apply", action="store_true")
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args(argv)
    con = store.open_db(create=a.apply)
    # ONE call, with the flag. The previous shape called report() to decide what
    # to print and again to decide what to write, which is how a repair can
    # report a full plan and apply none of it.
    out = report(con, a.apply)
    con.close()
    if a.json:
        print(json.dumps(out, indent=1, default=str))
        return 0
    print(f"exact duplicate groups : {out['duplicates']['groups']}")
    for p in out["duplicates"]["plan"]:
        print(f"    {p['duplicate']}  -> canonical {p['canonical']} "
              f"(adds_no_new_publisher={p['adds_no_new_publisher']})")
    print(f"malformed item keys    : {out['malformed_keys']['malformed']}")
    for p in out["malformed_keys"]["plan"]:
        print(f"    {p['old']}  ->  {p['new']}"
              + ("  [SKIPPED: name clash]" if p["would_clash"] else ""))
    print(f"orphaned conflict rows : {out['conflicts']['orphaned']} "
          f"{out['conflicts']['orphaned_ids']}")
    print(f"still open, claim live : "
          f"{len(out['conflicts']['still_open_with_live_claim'])}")
    if a.apply:
        print(f"applied: dup={len(out['duplicates']['applied'])} "
              f"keys={len(out['malformed_keys']['applied'])} "
              f"conflicts={len(out['conflicts']['applied'])}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())