#!/usr/bin/env python
"""Re-verify the citations behind every OPEN conflict whose claim_a is still
present in the corpus.

A `conflict` row records "cited quote not present on page". It is a historical
verdict written at ingest time. It is NOT a durable property of the item: a
child may have re-cut the quote and re-ingested it afterwards. So an open
conflict pointing at a live item is an unresolved integrity question, not a
known fact — this script settles it by re-fetching every cited page and running
the gate's own matcher (wks.verify_quotes.find_quote).

    python tools/reverify_disputes.py            # report
    python tools/reverify_disputes.py --json     # machine-readable

Verdicts per citation:
    OK            quote genuinely present on the cited page
    NOT_FOUND     page fetched, quote absent  -> real fabrication
    FETCH_FAILED  page unreachable            -> unverifiable, NOT a fabrication
    NO_QUOTE      no quote recorded           -> a URL alone is not evidence
"""
from __future__ import annotations

import json
import sqlite3
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from wks import pipeline  # noqa: E402
from wks.verify_quotes import find_quote  # noqa: E402

DB = ROOT / "db" / "wks.db"


def disputed() -> list[dict]:
    con = sqlite3.connect(DB)
    con.row_factory = sqlite3.Row
    rows = con.execute(
        """
        SELECT c.id AS conflict_id, c.class_id, c.claim_a, c.claim_b,
               i.id AS item_id, i.item_key
        FROM conflict c
        JOIN item i ON i.class_id = c.class_id AND i.claim = c.claim_a
        WHERE c.status = 'open'
        ORDER BY c.id
        """
    ).fetchall()
    out = []
    for r in rows:
        cites = con.execute(
            """
            SELECT s.url, s.host, x.quote
            FROM item_source x JOIN source s ON s.id = x.source_id
            WHERE x.item_id = ?
            """,
            (r["item_id"],),
        ).fetchall()
        out.append({
            "conflict_id": r["conflict_id"],
            "class_id": r["class_id"],
            "item_id": r["item_id"],
            "item_key": r["item_key"],
            "claim": r["claim_a"],
            "original_verdict": r["claim_b"],
            "citations": [dict(c) for c in cites],
        })
    con.close()
    return out


def main() -> int:
    as_json = "--json" in sys.argv
    cache: dict[str, dict] = {}
    results = []
    for d in disputed():
        verdicts = []
        for c in d["citations"]:
            url, quote = c["url"], c["quote"]
            if not quote:
                verdicts.append({"url": url, "host": c["host"],
                                 "status": "NO_QUOTE"})
                continue
            if url not in cache:
                cache[url] = pipeline.fetch(url, limit=1_500_000)
            page = cache[url]
            if not page.get("ok"):
                verdicts.append({"url": url, "host": c["host"],
                                 "status": "FETCH_FAILED",
                                 "detail": page.get("error") or page.get("status"),
                                 "chars": len(page.get("text", ""))})
            elif find_quote(page["text"], quote):
                verdicts.append({"url": url, "host": c["host"], "status": "OK"})
            else:
                verdicts.append({"url": url, "host": c["host"],
                                 "status": "NOT_FOUND", "quote": quote})
        st = [v["status"] for v in verdicts]
        if "NOT_FOUND" in st:
            overall = "FABRICATED"
        elif "FETCH_FAILED" in st:
            overall = "UNVERIFIED"
        elif "NO_QUOTE" in st:
            overall = "UNQUOTED"
        else:
            overall = "VERIFIED"
        d["citations"] = verdicts
        d["overall"] = overall
        results.append(d)

    if as_json:
        print(json.dumps(results, indent=2, default=str))
        return 0

    for d in results:
        print(f"\n[{d['overall']}] conflict={d['conflict_id']} "
              f"{d['item_key']} (item {d['item_id']})")
        print(f"  claim: {d['claim'][:150]}")
        for v in d["citations"]:
            line = f"    {v['status']:13} {v['host']:28} {v['url']}"
            if v["status"] == "FETCH_FAILED":
                line += f"  ({v.get('detail')}, {v.get('chars')} chars)"
            print(line)
            if v["status"] == "NOT_FOUND":
                print(f"                   quote: {v['quote'][:150]!r}")

    tally: dict[str, int] = {}
    for d in results:
        tally[d["overall"]] = tally.get(d["overall"], 0) + 1
    print("\n" + "  ".join(f"{k}={v}" for k, v in sorted(tally.items())))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
