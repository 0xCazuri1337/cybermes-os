"""Verify every active item's quotes in bounded batches, so a full pass finishes.

WHY THIS EXISTS. `python -m wks.verify_quotes` walks the whole corpus in one
process. MEASURED: a full run exceeds 900s and gets killed, and a killed run
leaves a PARTIAL list that reads like a complete one -- which is how an orphaned
background run reported `FABRICATED=30` while only part of the corpus had been
examined. A checker whose output is truncated by its own runtime cannot answer
"what fraction of this corpus is verified?", which is the only question that
matters for trusting it.

This shards by CLASS, writes one JSON report per class, and records which
classes were COVERED alongside which items failed -- so a partial run is
distinguishable from a clean one at a glance.

    python tools/verify_all_quotes.py --plan          # list the batches, no fetching
    python tools/verify_all_quotes.py --batch xss     # verify one class
    python tools/verify_all_quotes.py --run 8         # 8 classes in this process
    python tools/verify_all_quotes.py --summary       # aggregate what is on disk

Nothing here decides anything. `wks.verify_quotes` remains the only quote gate,
and this only drives it in slices and aggregates its verdicts.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from wks import config, store  # noqa: E402

OUT = ROOT / "validation" / "quote_verification"


def classes(con) -> list[str]:
    return [r["class_id"] for r in con.execute(
        "SELECT DISTINCT class_id FROM item WHERE status='active' ORDER BY class_id")]


def counts(con, cid: str) -> tuple[int, int]:
    n = con.execute(
        "SELECT COUNT(*) n FROM item WHERE class_id=? AND status='active'",
        (cid,)).fetchone()["n"]
    q = con.execute(
        """SELECT COUNT(*) n FROM item i JOIN item_source q ON q.item_id=i.id
            WHERE i.class_id=? AND i.status='active' AND q.quote IS NOT NULL
              AND TRIM(q.quote) != ''""", (cid,)).fetchone()["n"]
    return n, q


def verify_one(cid: str) -> dict:
    """Run the real gate for one class, capture its verdict, cache to disk."""
    import io
    import contextlib
    from wks import verify_quotes
    OUT.mkdir(parents=True, exist_ok=True)
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        try:
            verify_quotes.main(["--class", cid])
        except SystemExit:
            pass
    text = buf.getvalue()
    rec = {"class_id": cid, "raw": text[-4000:]}
    for key in ("FABRICATED", "VERIFIED"):
        for line in text.splitlines():
            if line.strip().startswith(f"{key}="):
                rec[key.lower()] = int(line.split("=")[1].split()[0])
    rec.setdefault("fabricated", 0)
    rec.setdefault("verified", 0)
    (OUT / f"{cid}.json").write_text(json.dumps(rec, indent=1), encoding="utf-8")
    return rec


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--plan", action="store_true")
    ap.add_argument("--batch")
    ap.add_argument("--run", type=int, help="verify N classes in this process")
    ap.add_argument("--summary", action="store_true")
    a = ap.parse_args()

    con = store.connect(config.DB_PATH)
    try:
        cl = classes(con)
        if a.plan:
            for c in cl:
                n, q = counts(con, c)
                print(f"  {c:26s} {n:4d} items, {q:4d} quoted")
            print(f"  {len(cl)} classes, "
                  f"{sum(counts(con, c)[0] for c in cl)} active items")
            return 0

        if a.summary:
            recs = []
            for c in cl:
                p = OUT / f"{c}.json"
                if p.exists():
                    recs.append(json.loads(p.read_text(encoding="utf-8")))
            done = {r["class_id"] for r in recs}
            tot_items = sum(counts(con, c)[0] for c in cl)
            covered = sum(counts(con, c)[0] for c in done)
            fab = sum(r.get("fabricated", 0) for r in recs)
            ver = sum(r.get("verified", 0) for r in recs)
            print(f"  classes COVERED : {len(done)} of {len(cl)}")
            print(f"  items  COVERED  : {covered} of {tot_items} "
                  f"({100.0*covered/tot_items if tot_items else 0:.1f}%)")
            print(f"  VERIFIED items  : {ver}")
            print(f"  FABRICATED items: {fab}")
            missing = [c for c in cl if c not in done]
            if missing:
                print(f"  NOT yet verified: {', '.join(missing)}")
            return 0

        if a.batch:
            r = verify_one(a.batch)
            print(f"  {a.batch:26s} VERIFIED={r.get('verified',0)} "
                  f"FABRICATED={r.get('fabricated',0)}")
            return 0

        if a.run:
            done = 0
            for c in cl:
                if (OUT / f"{c}.json").exists():
                    continue
                r = verify_one(c)
                print(f"  {c:26s} VERIFIED={r.get('verified',0)} "
                      f"FABRICATED={r.get('fabricated',0)}", flush=True)
                done += 1
                if done >= a.run:
                    break
            return 0

        ap.print_help()
        return 2
    finally:
        con.close()


if __name__ == "__main__":
    sys.exit(main())
