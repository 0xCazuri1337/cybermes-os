#!/usr/bin/env python3
"""Bulk quote audit: check EVERY citation against the page that must contain it.

WHY THIS EXISTS
---------------
`wks.verify_quotes` is the reference verifier and it is correct, but it is
SEQUENTIAL and it keys its cache on `(url, quote)`. The live corpus holds
4,446 citations over 959 distinct URLs, so the reference verifier refetches the
same page once per distinct quote on it — a page cited by 40 items is fetched
40 times. Measured: a full-corpus `--json` run exceeded 900s and was killed.

That timeout is the reason this file exists, and it is ALSO the reason the
fabrication rate was never measured. The honest number was not "there might be
some": it was UNKNOWN, because the check could not finish.

WHAT IT DOES
------------
One fetch per distinct URL, cached, with the citations for that URL checked
against it. Concurrent, bounded, and it prints progress so a long run is
visible rather than silent.

The matching logic is NOT reimplemented here. It calls `wks.verify_quotes.find_quote`
— the same function the reference verifier uses — so this tool cannot disagree
with it about whether a quote is present. A second matcher would be a second
source of truth about the same question, which is the exact defect class this
project's invariants exist to prevent.

WHAT IT DOES NOT DO
-------------------
It does not write to the database. It reports. Repairing a fabrication is a
judgement call (find a page that supports the claim, or supersede the item),
and a report is the honest first step. `--record` is deliberately absent.

USAGE
-----
    python tools/audit_quotes_bulk.py                     # full corpus
    python tools/audit_quotes_bulk.py --class X           # one class
    python tools/audit_quotes_bulk.py --workers 8
    python tools/audit_quotes_bulk.py --json out.json
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import threading
import time
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from wks import pipeline, store  # noqa: E402
from wks.verify_quotes import find_quote  # noqa: E402

_print_lock = threading.Lock()


def _log(msg: str) -> None:
    with _print_lock:
        print(msg, flush=True)


def _fetch_one(url: str, quotes: list[str]) -> tuple[str, dict, list[dict]]:
    """Fetch one URL and judge every quote cited against it.

    A URL is fetched ONCE. `pipeline.fetch` takes a `quote=` hint used to
    resolve a moved page; here the first quote is passed as the hint so the
    successor-resolution path behaves the same way it does in the reference
    verifier, and the fetched page is then checked against ALL of its quotes.
    """
    page = pipeline.fetch(url, limit=1_500_000, quote=quotes[0] if quotes else None)
    state = page.get("access_state", "UNVERIFIED")
    verdicts: list[dict] = []
    if state != "ACTIVE":
        for q in quotes:
            verdicts.append({
                "quote": q,
                "status": "FETCH_FAILED",
                "access_state": state,
                "retryable": bool(page.get("rate_limited")),
                "detail": page.get("error") or page.get("status"),
            })
        return url, page, verdicts
    text = page.get("text", "")
    for q in quotes:
        verdicts.append({
            "quote": q,
            "status": "OK" if find_quote(text, q) else "NOT_FOUND",
            "http_status": page.get("status"),
            "content_hash": page.get("content_hash"),
            **({"moved_from": page["moved_from"]}
               if page.get("moved_from") else {}),
        })
    return url, page, verdicts


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="audit_quotes_bulk")
    ap.add_argument("--class", dest="class_id")
    ap.add_argument("--workers", type=int, default=8)
    ap.add_argument("--json", help="write the machine-readable report here")
    ap.add_argument("--limit", type=int, default=0,
                    help="stop after N distinct URLs (for a bounded probe)")
    args = ap.parse_args(argv)

    con = store.open_db()
    q = ("SELECT i.item_key, i.class_id, s.url, s.host, is_.quote "
         "FROM item i "
         "JOIN item_source is_ ON is_.item_id = i.id "
         "JOIN source s ON s.id = is_.source_id "
         "WHERE i.status='active'")
    p: list = []
    if args.class_id:
        q += " AND i.class_id=?"
        p.append(args.class_id)
    rows = con.execute(q, p).fetchall()
    con.close()

    by_url: dict[str, list[dict]] = defaultdict(list)
    for r in rows:
        if not r["quote"]:
            continue
        by_url[r["url"]].append({
            "item_key": r["item_key"], "class_id": r["class_id"],
            "quote": r["quote"], "host": r["host"],
        })

    urls = sorted(by_url)
    if args.limit:
        urls = urls[:args.limit]
    _log(f"auditing {len(urls)} distinct URLs "
         f"({sum(len(by_url[u]) for u in urls)} citations) "
         f"with {args.workers} workers")

    started = time.time()
    done = 0
    verdicts_by_url: dict[str, list[dict]] = {}
    pages: dict[str, dict] = {}
    with ThreadPoolExecutor(max_workers=args.workers) as pool:
        futures = {
            pool.submit(_fetch_one, u, [c["quote"] for c in by_url[u]]): u
            for u in urls
        }
        for fut in as_completed(futures):
            u = futures[fut]
            try:
                _, page, verdicts = fut.result()
            except Exception as e:  # noqa: BLE001 - one bad URL must not kill the run
                verdicts = [{"quote": q, "status": "FETCH_FAILED",
                             "access_state": "ERROR",
                             "detail": f"{type(e).__name__}: {e}"}
                            for q in [c["quote"] for c in by_url[u]]]
                page = {}
            pages[u] = page
            verdicts_by_url[u] = verdicts
            done += 1
            if done % 25 == 0 or done == len(urls):
                el = time.time() - started
                _log(f"  {done}/{len(urls)} urls  ({el:.0f}s)")

    # Join each citation back to its verdict.
    per_citation: list[dict] = []
    for u in urls:
        by_quote = {v["quote"]: v for v in verdicts_by_url.get(u, [])}
        for c in by_url[u]:
            v = dict(by_quote.get(c["quote"], {"status": "MISSING"}))
            v.update({"url": u, "item_key": c["item_key"],
                      "class_id": c["class_id"], "host": c["host"]})
            per_citation.append(v)

    counts: dict[str, int] = defaultdict(int)
    for v in per_citation:
        counts[v["status"]] += 1

    fabricated = [v for v in per_citation if v["status"] == "NOT_FOUND"]
    fetch_failed = [v for v in per_citation if v["status"] == "FETCH_FAILED"]
    retryable = [v for v in fetch_failed if v.get("retryable")]
    by_class: dict[str, int] = defaultdict(int)
    for v in fabricated:
        by_class[v["class_id"]] += 1
    by_host: dict[str, int] = defaultdict(int)
    for v in fabricated:
        by_host[v["host"]] += 1

    print()
    print("=" * 70)
    print(f"BULK QUOTE AUDIT — {len(per_citation)} citations over "
          f"{len(urls)} URLs in {time.time() - started:.0f}s")
    print("=" * 70)
    for status in sorted(counts):
        print(f"  {status:16s} {counts[status]}")
    verified = counts.get("OK", 0)
    total = len(per_citation)
    if total:
        print(f"\n  verified {verified}/{total} "
              f"({100.0 * verified / total:.1f}%)")
    if fabricated:
        print(f"\n  FABRICATED: {len(fabricated)} citations")
        print(f"  by class ({len(by_class)} classes affected):")
        for cid, n in sorted(by_class.items(), key=lambda kv: -kv[1]):
            print(f"    {n:4d}  {cid}")
        print(f"  by host ({len(by_host)} hosts):")
        for h, n in sorted(by_host.items(), key=lambda kv: -kv[1])[:25]:
            print(f"    {n:4d}  {h}")
    if fetch_failed:
        print(f"\n  FETCH_FAILED: {len(fetch_failed)} "
              f"({len(retryable)} retryable/throttled — not fabrications)")

    if args.json:
        Path(args.json).write_text(json.dumps({
            "citations": total,
            "urls": len(urls),
            "counts": dict(counts),
            "fabricated": fabricated,
            "fetch_failed": fetch_failed,
            "by_class": dict(by_class),
            "by_host": dict(by_host),
        }, indent=1), encoding="utf-8")
        _log(f"\n  report written to {args.json}")

    # A fabrication is a REAL defect and must be visible to the caller.
    return 1 if fabricated else 0


if __name__ == "__main__":
    raise SystemExit(main())
