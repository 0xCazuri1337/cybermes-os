#!/usr/bin/env python3
"""Locate a missing quote among the pages this corpus already cites.

THE PROBLEM
-----------
`tools/audit_quotes_bulk.py` finds citations whose quote is not on the page
they name. Before treating such a citation as fabricated, there is a cheaper
and far more likely explanation: THE QUOTE IS REAL, but it was filed against
the wrong URL. An agent that fetched page A and page B and cited A while
quoting B produces exactly this.

MEASURED 2026-10-31: `windows_privesc_token` cited the HackTricks
access-tokens page for a sentence that is not on it, while the corpus
contains 73 citations to raw.githubusercontent.com. Checking the quote against
every page this corpus already cites for the SAME HOST is the cheapest
possible repair test, and it needs no new network research.

WHAT IT DOES
------------
For each NOT_FOUND citation, it searches every already-cited URL on the same
host for the quote's text (using the same `find_quote` the verifier uses).
It reports:

  FOUND_ON_CITED   the quote IS on another page of the same host that the
                   corpus already cites -- a MISFILED citation, repairable by
                   re-pointing the citation at a URL already in the registry.
  NOT_ANYWHERE     the quote is on no cited page of that host -- either the
                   source page is not yet cited, or the quote is invented.

The page text is cached per URL, so the whole run costs one fetch per cited
URL of the affected hosts.

Usage:
    python tools/locate_missing_quotes.py --report /tmp/quotes_bulk.json
"""
from __future__ import annotations

import argparse
import json
import sys
from collections import Counter, defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from wks import pipeline, store  # noqa: E402
from wks.verify_quotes import find_quote, norm  # noqa: E402


def _opening(quote: str, min_len: int = 60) -> str:
    q = quote.strip()
    for marker in ("...", "…", "\n"):
        i = q.find(marker)
        if i > 0:
            q = q[:i]
    q = q.strip()
    return q if len(q) >= min_len else quote.strip()


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="locate_missing_quotes")
    ap.add_argument("--report", required=True)
    ap.add_argument("--json", help="write the classified report here")
    ap.add_argument("--workers", type=int, default=8)
    args = ap.parse_args(argv)

    data = json.loads(Path(args.report).read_text(encoding="utf-8"))
    missing = data.get("fabricated", [])
    if not missing:
        print("nothing to locate")
        return 0

    con = store.open_db()
    hosts = {c["host"] for c in missing}
    cited: dict[str, list[str]] = defaultdict(list)
    for r in con.execute("SELECT url, host FROM source"):
        if r["host"] in hosts:
            cited[r["host"]].append(r["url"])
    con.close()

    total_urls = sum(len(v) for v in cited.values())
    print(f"missing quotes: {len(missing)} over {len(hosts)} hosts")
    print(f"cited URLs on those hosts: {total_urls}")

    # Fetch each cited URL of the affected hosts once, concurrently.
    from concurrent.futures import ThreadPoolExecutor

    urls = sorted({u for v in cited.values() for u in v})
    texts: dict[str, str] = {}

    def _get(url: str) -> tuple[str, str]:
        page = pipeline.fetch(url, limit=1_500_000)
        if page.get("access_state") != "ACTIVE":
            return url, ""
        return url, page.get("text", "")

    done = 0
    with ThreadPoolExecutor(max_workers=args.workers) as pool:
        for url, text in pool.map(_get, urls):
            texts[url] = text
            done += 1
            if done % 50 == 0:
                print(f"  fetched {done}/{len(urls)}", flush=True)

    counts: Counter = Counter()
    detail: list[dict] = []
    for c in missing:
        q = c.get("quote", "")
        span = _opening(q)
        hit_url = None
        # Prefer the FULL quote; fall back to the opening span so an elided
        # excerpt can still be located.
        for u in cited.get(c["host"], []):
            t = texts.get(u, "")
            if not t:
                continue
            if find_quote(t, q):
                hit_url = u
                break
        if hit_url is None:
            nt = norm(span)
            for u in cited.get(c["host"], []):
                t = texts.get(u, "")
                if t and nt and nt in norm(t):
                    hit_url = u
                    break
        verdict = "FOUND_ON_CITED" if hit_url else "NOT_ANYWHERE"
        counts[verdict] += 1
        detail.append({**c, "verdict": verdict, "found_at": hit_url})

    print()
    print("=" * 70)
    print("MISSING-QUOTE LOCATION")
    print("=" * 70)
    for k in sorted(counts):
        print(f"  {k:16s} {counts[k]}")

    by_class: dict[str, Counter] = defaultdict(Counter)
    for d in detail:
        by_class[d["class_id"]][d["verdict"]] += 1
    print(f"\n  classes affected: {len(by_class)}")
    for cid, c in sorted(by_class.items(), key=lambda kv: -sum(kv[1].values()))[:20]:
        print(f"    {sum(c.values()):4d}  {cid:35s} {dict(c)}")

    if args.json:
        Path(args.json).write_text(json.dumps({
            "counts": dict(counts),
            "by_class": {k: dict(v) for k, v in by_class.items()},
            "detail": detail,
        }, indent=1), encoding="utf-8")
        print(f"\n  report written to {args.json}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
