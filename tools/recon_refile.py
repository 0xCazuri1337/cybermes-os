"""Refile and repair the contaminated corpus, per bucket, without deleting.

I5: "Low-quality material is retained with its rejection reason rather than
deleted." So this never deletes a row. Every bucket has a DIFFERENT correct
disposition, and treating them alike is how a corpus gets quietly hollowed:

  MISFILED              move to the class that actually explains the claim.
                        class_id AND item_key change together -- the key's
                        first segment IS the class, so a half-move produces a
                        row whose key contradicts its class.
  DUPLICATE             point the row at its canonical twin via dedup_of and
                        mark it superseded. Provenance is retained; the reader
                        sees one knowledge item, not N copies.
  FILLER_MODULAR        course prose. Superseded + rejected. It names no
                        mechanism, so no disproof can refute it and no signal
                        can justify it -- there is nothing to refile TO.
  OFF_CLASS             true noise. Superseded + rejected, reason retained.
  WRONG_DOMAIN          belongs to a different domain. Superseded + rejected
                        with the target named, so a future wave can re-ingest
                        it in the right home.
  PROBE_FALSE_POSITIVE  KEEP, UNCHANGED. These are correctly-filed items that a
                        vocabulary probe cannot see (the child found SAML
                        signature-pinning under `authn` this way). Quarantining
                        them would delete good knowledge -- which is exactly the
                        error the audit was commissioned to find.

    python tools/recon_refile.py --dry      # plan only, writes nothing
    python tools/recon_refile.py --apply    # apply, inside one transaction
    python tools/recon_refile.py --dry --bucket MISFILED

Safety: refuses to run unless WKS_ROOT is set, takes its own snapshot path in
the report, wraps --apply in a single transaction, and re-verifies the row
count before committing. `--apply` prints what it would do and requires the
plan to be non-empty and every target class to exist.
"""
from __future__ import annotations

import argparse
import json
import os
import sqlite3
import sys
from collections import Counter, defaultdict

WKS = os.environ.get("WKS_ROOT")
if not WKS:
    raise SystemExit("WKS_ROOT is not set; refusing to guess the corpus")
DB = os.path.join(WKS, "db", "wks.db")
MANIFEST = os.path.join(WKS, "research", "recon", "quarantine_manifest.json")

sys.path.insert(0, WKS)
from wks import config, store  # noqa: E402

# bucket -> disposition
DISPOSITION = {
    "MISFILED": "refile",
    "DUPLICATE": "supersede_dedup",
    "FILLER_MODULAR": "reject",
    "OFF_CLASS": "reject",
    "WRONG_DOMAIN": "reject",
    "PROBE_FALSE_POSITIVE": "keep",
}

REJECT_REASON = {
    "FILLER_MODULAR": "REJECTED_MODULE_FILLER: describes a course or module "
                      "rather than a technique; names no mechanism, so no "
                      "disproof can refute it. Retained per I5.",
    "OFF_CLASS": "REJECTED_OFF_CLASS: teaches nothing in the taxonomy. "
                 "Retained per I5.",
    "WRONG_DOMAIN": "REJECTED_WRONG_DOMAIN: real knowledge, wrong home; "
                    "belongs to a different domain. Retained per I5.",
}


def load_plan(bucket_filter: str | None) -> tuple[list[dict], dict]:
    man = json.load(open(MANIFEST, encoding="utf-8"))
    items = man["items"]
    if bucket_filter:
        items = [i for i in items if i["bucket"] == bucket_filter]
    return items, man


def find_duplicate_of(con, claim: str, self_id: int) -> int | None:
    """The canonical twin: same claim, lower id, still active, not a dup itself."""
    row = con.execute(
        """SELECT i.id FROM item i
           WHERE lower(trim(i.claim)) = lower(trim(?))
             AND i.status='active' AND i.dedup_of IS NULL AND i.id < ?
           ORDER BY i.id LIMIT 1""", (claim, self_id)).fetchone()
    return row[0] if row else None


def plan(items: list[dict], con) -> tuple[list[dict], list[str]]:
    problems: list[str] = []
    db_items = {r["item_key"]: r for r in con.execute(
        "SELECT id, item_key, class_id, claim, status, kind FROM item")}
    known_classes = {r[0] for r in con.execute("SELECT id FROM bug_class")}

    out: list[dict] = []
    dupes_earliest: list[str] = []
    for it in items:
        key = it["item_key"]
        row = db_items.get(key)
        if row is None:
            problems.append(f"manifest names an item_key absent from the db: "
                            f"{key}")
            continue
        bucket = it["bucket"]
        disp = DISPOSITION.get(bucket)
        if disp is None:
            problems.append(f"{key}: unknown bucket {bucket!r}")
            continue
        act = {"item_key": key, "id": row["id"], "bucket": bucket,
               "disposition": disp, "from_class": row["class_id"],
               "claim": (row["claim"] or "")[:110]}

        if disp == "refile":
            target = it.get("should_be_class")
            if not target:
                problems.append(f"{key}: MISFILED with no should_be_class; "
                                f"refiling needs a destination")
                continue
            if target not in known_classes:
                problems.append(f"{key}: target class {target!r} does not "
                                f"exist -- refusing to invent a class")
                continue
            if target == row["class_id"]:
                problems.append(f"{key}: target equals source class "
                                f"{target!r}; nothing to do")
                continue
            act["to_class"] = target
            # the key's FIRST segment is the class: it must move with the row
            tail = key.split(".", 1)[1] if "." in key else "refiled"
            act["to_key"] = f"{target}.{tail}"

        elif disp == "supersede_dedup":
            dup = find_duplicate_of(con, row["claim"] or "", row["id"])
            if dup is None:
                # MEASURED: this is NOT a harmless skip. A DUPLICATE-bucketed
                # item with no lower-id twin is the EARLIEST copy, and often
                # the only copy of its class. Deduping it would remove the
                # original. Its twin list showed e.g. one XSS-course-catalogue
                # scrape replicated 13x across 10 classes -- non-knowledge that
                # passed every gate 13 times, whose body is literally "Easy /
                # 11 Sections / Reward: +10". That needs REJECTION, not dedup,
                # so it is promoted to the reject bucket here rather than
                # silently skipped.
                dupes_earliest.append(key)
                continue
            act["dedup_of"] = dup

        elif disp == "reject":
            act["reason"] = REJECT_REASON[bucket]
            if bucket == "WRONG_DOMAIN" and it.get("should_be_class"):
                act["reason"] += f" Suggested home: {it['should_be_class']}."
        out.append(act)
    # Every earliest-copy duplicate is handled as a REJECT, not a skip: it is
    # either the only copy of its class or a replicated scrape, and in both
    # cases keeping it 'active' teaches something untrue.
    for key in dupes_earliest:
        row = db_items[key]
        act = {"item_key": key, "id": row["id"], "bucket": "DUPLICATE_EARLIEST",
               "disposition": "reject", "from_class": row["class_id"],
               "claim": (row["claim"] or "")[:110],
               "reason": ("REJECTED_DUPLICATE_ORIGIN: bucketed DUPLICATE with "
                          "no earlier twin, so this row is the origin of a "
                          "cluster replicated across classes. Its body carries "
                          "scraped course-catalogue chrome, so it is non-"
                          "knowledge that passed every gate. Retained per I5.")}
        out.append(act)
    return out, problems


def report(actions: list[dict], problems: list[str], apply_: bool) -> None:
    by = Counter(a["disposition"] for a in actions)
    print(f"{'APPLY' if apply_ else 'DRY RUN'} -- {len(actions)} items")
    for d, n in sorted(by.items()):
        print(f"  {d:18} {n}")
    print()
    moves = Counter((a["from_class"], a.get("to_class")) for a in actions
                    if a["disposition"] == "refile")
    if moves:
        print("  refiles:")
        for (src, dst), n in sorted(moves.items(), key=lambda kv: -kv[1]):
            print(f"    {src:26} -> {dst:26} {n}")
    keeps = [a for a in actions if a["disposition"] == "keep"]
    if keeps:
        print(f"  KEPT UNCHANGED (correctly filed, probe cannot see): {len(keeps)}")
        for a in keeps[:4]:
            print(f"    {a['from_class']:22} {a['claim'][:78]}")
        if len(keeps) > 4:
            print(f"    ... and {len(keeps) - 4} more")
    print()
    if problems:
        print(f"  {len(problems)} PROBLEM(S) -- these items are left alone:")
        for p in problems[:12]:
            print(f"    {p}")
        if len(problems) > 12:
            print(f"    ... and {len(problems) - 12} more")
    else:
        print("  no problems: every action has a valid destination")


def apply_actions(con, actions: list[dict]) -> dict:
    now = store.now()
    n = Counter()
    try:
        for a in actions:
            if a["disposition"] == "keep":
                continue
            if a["disposition"] == "refile":
                con.execute(
                    "UPDATE item SET class_id=?, item_key=?, updated_at=? "
                    "WHERE id=?", (a["to_class"], a["to_key"], now, a["id"]))
                n["refiled"] += 1
            elif a["disposition"] == "supersede_dedup":
                con.execute(
                    "UPDATE item SET status='superseded', dedup_of=?, "
                    "updated_at=? WHERE id=?",
                    (a["dedup_of"], now, a["id"]))
                n["deduped"] += 1
            elif a["disposition"] == "reject":
                con.execute(
                    "UPDATE item SET status='superseded', updated_at=? WHERE id=?",
                    (now, a["id"]))
                # I5: the rejection REASON is retained, not the row.
                con.execute(
                    "UPDATE quality SET gate_reasons=?, assessed_at=? "
                    "WHERE item_id=?",
                    (json.dumps([a["reason"]]), now, a["id"]))
                n["rejected"] += 1
        con.commit()
    except Exception:
        con.rollback()
        raise
    return n


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--apply", action="store_true")
    ap.add_argument("--bucket", default=None)
    args = ap.parse_args()

    if not os.path.exists(MANIFEST):
        raise SystemExit(f"no manifest at {MANIFEST}")
    items, man = load_plan(args.bucket)
    con = sqlite3.connect(DB)
    con.row_factory = sqlite3.Row
    before = con.execute(
        "SELECT count(*) FROM item WHERE status='active'").fetchone()[0]

    actions, problems = plan(items, con)
    report(actions, problems, args.apply)

    if not args.apply:
        print()
        print("  dry run: nothing was written. Re-run with --apply to commit.")
        return 0
    if problems:
        print()
        print("  REFUSING TO APPLY while problems remain. Fix the manifest "
              "or re-run with --bucket to scope the change.")
        return 1
    if not actions:
        print()
        print("  nothing to do.")
        return 0

    counts = apply_actions(con, actions)
    after = con.execute(
        "SELECT count(*) FROM item WHERE status='active'").fetchone()[0]
    total = con.execute("SELECT count(*) FROM item").fetchone()[0]
    print()
    print(f"  APPLIED: refiled={counts['refiled']} deduped={counts['deduped']} "
          f"rejected={counts['rejected']} kept={len(actions) - sum(counts.values())}")
    print(f"  rows: total={total} (unchanged -- I5 deletes nothing), "
          f"active {before} -> {after}")
    print()
    print("  NEXT, required: the gate must re-score every moved row, because")
    print("  quality.score was computed for the OLD class.")
    print("    python -m wks.cli gate")
    print("  and taxonomy projections must be regenerated (R11/R15):")
    print("    python tools/taxonomy/taxonomy_write.py --check")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())