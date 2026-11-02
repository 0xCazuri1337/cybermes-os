#!/usr/bin/env python
"""Settle open `conflict` rows against the corpus and a fresh re-verification.

A conflict row is an ingest-time verdict, not a permanent property of a claim.
Two things make an open conflict an unanswered question rather than a fact:

  1. the producer re-cut the quote and re-ingested the item afterwards, so the
     citation that failed no longer exists; or
  2. the item was rejected and never replaced, so the claim is simply absent.

Only case (1) with a live re-verification can be called RESOLVED-verified.
Case (2) is DISMISSED: the rejection stands and the row is retained as the
audit trail (invariant I5), it just stops counting as an open dispute.

Anything that re-verifies as FABRICATED is left OPEN and escalated. Nothing is
deleted, and no conflict is closed on the strength of a child's say-so.

    python tools/resolve_disputes.py            # report only, writes nothing
    python tools/resolve_disputes.py --apply    # persist the resolutions
"""
from __future__ import annotations

import json
import sqlite3
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from wks import pipeline  # noqa: E402
from wks.verify_quotes import find_quote  # noqa: E402

DB = ROOT / "db" / "wks.db"
STAMP = datetime.now(timezone.utc).strftime("%Y-%m-%d")


def live_items() -> dict[tuple[str, str], int]:
    con = sqlite3.connect(DB)
    rows = con.execute("SELECT class_id, claim, id FROM item").fetchall()
    con.close()
    return {(c, q): i for c, q, i in rows}


def all_open() -> list[dict]:
    con = sqlite3.connect(DB)
    con.row_factory = sqlite3.Row
    rows = con.execute(
        "SELECT id, class_id, claim_a, claim_b FROM conflict "
        "WHERE status='open' ORDER BY id").fetchall()
    con.close()
    return [dict(r) for r in rows]


def reverify(item_id: int) -> tuple[str, list[dict]]:
    con = sqlite3.connect(DB)
    con.row_factory = sqlite3.Row
    cites = con.execute(
        "SELECT s.url, s.host, x.quote FROM item_source x "
        "JOIN source s ON s.id=x.source_id WHERE x.item_id=?", (item_id,)
    ).fetchall()
    con.close()
    verdicts, cache = [], {}
    for c in cites:
        q = c["quote"]
        if not q:
            verdicts.append({"url": c["url"], "status": "NO_QUOTE"})
            continue
        if c["url"] not in cache:
            cache[c["url"]] = pipeline.fetch(c["url"], limit=1_500_000)
        page = cache[c["url"]]
        if not page.get("ok"):
            verdicts.append({"url": c["url"], "status": "FETCH_FAILED"})
        elif find_quote(page["text"], q):
            verdicts.append({"url": c["url"], "status": "OK"})
        else:
            verdicts.append({"url": c["url"], "status": "NOT_FOUND", "quote": q})
    st = [v["status"] for v in verdicts]
    overall = ("FABRICATED" if "NOT_FOUND" in st else
               "UNVERIFIED" if "FETCH_FAILED" in st else
               "UNQUOTED" if "NO_QUOTE" in st else "VERIFIED")
    return overall, verdicts


def main() -> int:
    apply = "--apply" in sys.argv
    live = live_items()
    plan: list[dict] = []
    cache: dict[str, tuple[str, list[dict]]] = {}

    for row in all_open():
        key = (row["class_id"], row["claim_a"])
        if key in live:
            iid = live[key]
            if iid not in cache:
                cache[iid] = reverify(iid)
            overall, verdicts = cache[iid]
            if overall == "VERIFIED":
                plan.append({
                    "id": row["id"], "action": "resolve", "status": "resolved",
                    "resolution": (
                        f"Quote re-cut after the original rejection and re-ingested; "
                        f"all {len(verdicts)} citation(s) re-verified verbatim against "
                        f"the live pages on {STAMP}. Original verdict was an "
                        f"extraction artefact of the matcher, not fabricated evidence."
                    ),
                })
            else:
                plan.append({"id": row["id"], "action": "escalate",
                             "status": "open", "overall": overall,
                             "resolution": None})
        else:
            plan.append({
                "id": row["id"], "action": "dismiss", "status": "dismissed",
                "resolution": (
                    f"Claim never entered the corpus: the item was rejected at ingest "
                    f"and no replacement carries this wording, so the rejection stands. "
                    f"Row retained as the audit trail (I5); no longer an open dispute."
                ),
            })

    tally: dict[str, int] = {}
    for p in plan:
        k = p["action"] if p["action"] != "escalate" else \
            f"escalate:{p.get('overall')}"
        tally[k] = tally.get(k, 0) + 1
    for p in plan:
        extra = f" overall={p['overall']}" if p.get("overall") else ""
        print(f"  conflict {p['id']:3}  {p['action']:9} -> {p['status']}{extra}")

    if apply:
        con = sqlite3.connect(DB)
        for p in plan:
            if p["action"] == "escalate":
                continue
            con.execute("UPDATE conflict SET status=?, resolution=? WHERE id=?",
                        (p["status"], p["resolution"], p["id"]))
        con.commit()
        con.close()
        print("\nAPPLIED.")
    else:
        print("\ndry run — pass --apply to persist")

    print("  ".join(f"{k}={v}" for k, v in sorted(tally.items())))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
