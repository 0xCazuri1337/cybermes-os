#!/usr/bin/env python
"""Measure sources the store has never fetched.

The source-health problem is not a missing declaration; it is a missing
*measurement*. A source row that says UNVERIFIED is honest, but it also means
the corpus cannot distinguish a live page from a dead link. This tool forces a
fetch for those rows only and records the measured state, hash, and HTTP status.

Requests are grouped by host and run one-at-a-time within a host. Different
hosts run concurrently. That keeps the per-host politeness floor meaningful
instead of letting several workers stampede the same site.

    python tools/verify_unmeasured_sources.py            # dry run, 8 hosts
    python tools/verify_unmeasured_sources.py --apply
    python tools/verify_unmeasured_sources.py --apply --workers 4 --limit 20

Dry-run still fetches: a measurement is the point. It prints the result but
does not write the database or the verification cache.
"""
from __future__ import annotations

import argparse
import json
import sys
from collections import Counter, defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from wks import store, transport, verify_sources  # noqa: E402

GAPS = ROOT / "learning" / "gaps"


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _measure_host(host: str, urls: list[str]) -> list[dict[str, Any]]:
    out = []
    for url in urls:
        try:
            r = verify_sources.verify_one(url)
            state = r.get("measured_state") or "UNVERIFIED"
            if state not in transport.ACCESS_STATES:
                state = "UNVERIFIED"
            out.append({**r, "url": url, "measured_state": state, "host": host})
        except Exception as exc:  # a broken fetch is a measurement, not a crash
            out.append({
                "url": url, "host": host, "measured_state": "UNVERIFIED",
                "http_status": None, "content_hash": None, "text_chars": 0,
                "access_detail": f"{type(exc).__name__}: {exc}", "seconds": None,
            })
    return out


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--apply", action="store_true")
    ap.add_argument("--workers", type=int, default=8)
    ap.add_argument("--limit", type=int, default=0,
                    help="limit total URLs (for a smoke run)")
    ap.add_argument("--only", help="substring filter on URL")
    args = ap.parse_args()

    con = store.open_db(create=False)
    rows = con.execute(
        "SELECT url, host FROM source WHERE access_state='UNVERIFIED' "
        "ORDER BY host, url").fetchall()
    by_host: dict[str, list[str]] = defaultdict(list)
    for row in rows:
        if args.only and args.only not in row["url"]:
            continue
        by_host[row["host"] or transport.host_of(row["url"])].append(row["url"])
    urls = [u for host in sorted(by_host) for u in by_host[host]]
    if args.limit:
        urls = urls[:args.limit]
    wanted = set(urls)
    by_host = {
        h: [u for u in us if u in wanted]
        for h, us in by_host.items() if any(u in wanted for u in us)
    }
    print(f"unmeasured sources: {len(rows)}; selected: {len(urls)} across "
          f"{len(by_host)} hosts")

    results: list[dict[str, Any]] = []
    with ThreadPoolExecutor(max_workers=max(1, args.workers)) as pool:
        futures = [pool.submit(_measure_host, h, us)
                   for h, us in sorted(by_host.items())]
        for fut in as_completed(futures):
            batch = fut.result()
            results.extend(batch)
            print(f"  {batch[0]['host']}: {len(batch)} measured", flush=True)
            # Persist a completed host immediately. A slow or hanging host must
            # not hold every other measurement hostage until the process exits.
            if args.apply:
                for r in batch:
                    detail = f"unmeasured-source sweep {_now()}"
                    if r.get("access_detail"):
                        detail += f"; {r['access_detail']}"
                    store.record_access(
                        con, r["url"], access_state=r["measured_state"],
                        http_status=r.get("http_status"),
                        content_hash=r.get("content_hash"), detail=detail,
                    )
                    verify_sources.RESULTS.parent.mkdir(parents=True, exist_ok=True)
                    with verify_sources.RESULTS.open("a", encoding="utf-8") as sink:
                        sink.write(json.dumps({
                            "url": r["url"],
                            "measured_state": r["measured_state"],
                            "http_status": r.get("http_status"),
                            "content_hash": r.get("content_hash"),
                            "text_chars": r.get("text_chars"),
                            "access_detail": r.get("access_detail"),
                            "seconds": r.get("seconds"), "at": _now(),
                            "source": "unmeasured-source sweep",
                        }, default=str) + "\n")
                con.commit()

    states = Counter(r["measured_state"] for r in results)
    report = {
        "generated_at": _now(),
        "selected": len(results),
        "states": dict(sorted(states.items())),
        "by_host": {
            h: dict(Counter(r["measured_state"] for r in results if r["host"] == h))
            for h in sorted(by_host)
        },
        "results": results,
    }
    GAPS.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    report_path = GAPS / f"source-verification-{stamp}.json"
    report_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(f"states: {dict(states)}")
    print(f"wrote {report_path.relative_to(ROOT)}")

    if not args.apply:
        print("dry run; pass --apply to persist")
        con.close()
        return 0

    census = {row["access_state"]: row["n"] for row in con.execute(
        "SELECT access_state, count(*) n FROM source GROUP BY 1")}
    total = sum(census.values())
    active = census.get("ACTIVE", 0)
    print(f"census: {census}; coverage: {100.0 * active / max(total, 1):.1f}%")
    con.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
