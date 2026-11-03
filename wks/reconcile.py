"""Reconcile the corpus against the current research files.

    python -m wks.reconcile [--apply]

Why this exists: agents rewrite their output files when they correct a quote,
and they may rename items while doing so. `item_key` is the primary identity,
so a renamed item leaves the previous row behind as an orphan — still promoted,
still carrying the old (possibly fabricated) evidence, and returned by retrieval
as though it were current knowledge.

Nothing else in the system detects this, because from the database's point of
view every orphan row is perfectly valid. The only thing that knows better is
the file on disk.

Two policies:
  * `supersede` — the item_key is gone from the file. Its content came from a
    version that no longer exists, so it is marked superseded, not deleted
    (invariant I8), and drops out of retrieval and maturity.
  * `orphan`   — the class has no file at all. Left alone; absence of a file is
    not evidence that its contents are wrong.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from wks import retrieval, store  # noqa: E402


def reconcile(con, incoming: Path, *, apply: bool = False) -> dict:
    incoming.mkdir(parents=True, exist_ok=True)
    files = {p.stem: p for p in sorted(incoming.glob("*.json"))}

    current: dict[str, set[str]] = {}
    unreadable: list[dict[str, str]] = []
    for cid, p in files.items():
        # Intake files carry a trailing `// COMPLETE ...` marker (see
        # `orch.researcher.write_intake`). `store.read_intake_json` strips it.
        # MEASURED: a bare `json.loads` here raised "Extra data" on all 58
        # research files, so this step failed on a corpus that was valid.
        try:
            data = store.read_intake_json(p)
        except (OSError, ValueError) as exc:
            # A genuinely malformed file is a DEFECT to report, not a reason to
            # abort the whole reconcile: the other files still reconcile, and a
            # silently-skipped file would make an incomplete pass look clean.
            unreadable.append({"class_id": cid, "file": str(p),
                               "error": f"{type(exc).__name__}: {exc}"})
            continue
        # A dict without "items" is a legitimate intake shape for source
        # candidate lists (`{"sources": [...]}`) — those files describe no
        # items, so the class reconciles to an empty item set. MEASURED: 12 of
        # the 196 intake files have exactly that shape. A bare
        # `data["items"]` raised KeyError on them.
        if isinstance(data, dict):
            items = data.get("items", [])
        else:
            items = data
        if not isinstance(items, list):
            unreadable.append({"class_id": cid, "file": str(p),
                               "error": "'items' is not a list"})
            continue
        current[cid] = {i["item_key"] for i in items
                        if isinstance(i, dict) and i.get("item_key")}

    rows = con.execute(
        "SELECT i.id, i.item_key, i.class_id, i.status FROM item i"
        # Already-superseded rows are not orphans to fix. Re-reporting them
        # would make `--apply` look like it did nothing on the second run,
        # which is exactly the "silent zero" the coverage checker warns about.
        " WHERE i.status='active'"
    ).fetchall()

    orphans, clean = [], []
    for r in rows:
        cid = r["class_id"]
        if cid not in current:
            continue  # no file for this class: not evidence of anything
        if r["item_key"] not in current[cid]:
            orphans.append({"id": r["id"], "item_key": r["item_key"],
                            "class_id": cid, "was": r["status"]})
        else:
            clean.append(r["item_key"])

    if apply and orphans:
        for o in orphans:
            con.execute(
                """UPDATE item SET status='superseded', updated_at=?
                   WHERE id=?""", (store.now(), o["id"]))
        con.commit()
        retrieval.rebuild_index(con)

    return {"files": sorted(files), "orphan_count": len(orphans),
            "orphans": orphans, "matched": len(clean), "applied": apply,
            "unreadable": unreadable}


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="wks.reconcile")
    ap.add_argument("--apply", action="store_true")
    ap.add_argument("--incoming", default="knowledge/materials/pending")
    args = ap.parse_args(argv)

    con = store.open_db(create=False)
    r = reconcile(con, Path(args.incoming), apply=args.apply)
    print(f"files: {', '.join(r['files'])}")
    print(f"matched items: {r['matched']}")
    print(f"orphans (item_key absent from current file): {r['orphan_count']}")
    for o in r["orphans"]:
        print(f"  {o['item_key']}  [{o['class_id']}, was {o['was']}]")
    for u in r["unreadable"]:
        print(f"  !! UNREADABLE {u['file']}: {u['error']}")
    if r["orphan_count"] and not args.apply:
        print("\ndry run — pass --apply to mark them superseded")
    elif r["applied"]:
        print("\nmarked superseded; retrieval index rebuilt")
    con.close()
    # An unreadable intake file is a real defect: the class it describes was
    # NOT reconciled, so its rows may be wrongly reported as orphans (or
    # wrongly kept). Exit non-zero so a caller cannot mistake a partial
    # reconcile for a clean one.
    return 1 if r["unreadable"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
