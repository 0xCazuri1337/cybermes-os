#!/usr/bin/env python3
"""Decide whether a missing quote was INVENTED or the page simply MOVED ON.

THE DISTINCTION
----------------
A citation whose quote is absent from the live page is not automatically a
fabrication. There is a second, much more common cause: the page was
rewritten after the corpus quoted it. MEASURED 2026-10-31 on the OWASP XSS
Prevention Cheat Sheet:

  stored quote : "The only 'safe' location for placing variables in
                  JavaScript is inside a 'quoted data value'. ..."
  live page    : that sentence is GONE; the section was restructured.
  archived md  : the sentence is present VERBATIM.

The citation was genuine when it was made. Reporting it as fabrication would
be wrong, and — worse — would push an operator into "fixing" a corpus that was
never broken.

HOW THIS IS DECIDED
-------------------
For each NOT_FOUND citation, in order:

  1. The live page is searched for the quote. If it is there, it is not a
     failure at all (the earlier stage said otherwise).
  2. The ARCHIVED page is searched, via the Wayback Machine, for the quote.
     A hit means PAGE_DRIFT: the source has been rewritten since the
     citation was made, and the citation was honest.
  3. Otherwise the quote is INVENTED: it is not on the page, not in any
     archived copy, and (per the earlier stage) not on any other page of the
     same host that this corpus cites.

Step 2 is what makes the verdict trustworthy in both directions. Without it,
every rewritten page in the corpus is reported as fabrication; with it, only
quotes that never existed anywhere are.

A quote that CONTAINS AN ELLIPSIS is judged on its opening span, because the
matcher requires the whole string and a truncated excerpt can never match.

Usage:
    python tools/classify_quote_drift.py --report /tmp/quotes_bulk.json
"""
from __future__ import annotations

import argparse
import json
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from collections import Counter, defaultdict
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from wks import pipeline  # noqa: E402
from wks.verify_quotes import find_quote, norm  # noqa: E402

_UA = "Mozilla/5.0 (compatible; CyberOS-QuoteAudit/1.0)"
_AVAIL = ("https://archive.org/wayback/available?url={url}"
          "&timestamp={ts}")


def _get(url: str, timeout: int = 45) -> str:
    req = urllib.request.Request(url, headers={"User-Agent": _UA})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.read().decode("utf-8", errors="replace")


def _wayback_url(url: str, timestamp: str = "20251001") -> str | None:
    """The Wayback snapshot nearest `timestamp`, or None."""
    try:
        raw = _get(_AVAIL.format(url=urllib.parse.quote(url, safe=""),
                                 ts=timestamp))
        data = json.loads(raw)
    except (urllib.error.URLError, OSError, ValueError, TimeoutError):
        return None
    closest = (data.get("archived_snapshots") or {}).get("closest") or {}
    if closest.get("available"):
        return closest.get("url")
    return None


def _opening(quote: str, min_len: int = 60) -> str:
    q = quote.strip()
    for marker in ("...", "…", "\n"):
        i = q.find(marker)
        if i > 0:
            q = q[:i]
    q = q.strip()
    return q if len(q) >= min_len else quote.strip()


def _page_text(url: str) -> str:
    page = pipeline.fetch(url, limit=1_500_000)
    if page.get("access_state") != "ACTIVE":
        return ""
    return page.get("text", "")


def _archived_text(url: str, timestamp: str) -> str:
    snap = _wayback_url(url, timestamp)
    if not snap:
        return ""
    try:
        raw = _get(snap)
    except (urllib.error.URLError, OSError, TimeoutError):
        return ""
    # Strip tags so the archived HTML can be searched the same way.
    raw = re.sub(r"<script.*?</script>", " ", raw, flags=re.S)
    raw = re.sub(r"<style.*?</style>", " ", raw, flags=re.S)
    raw = re.sub(r"<[^>]+>", " ", raw)
    import html as _html
    raw = _html.unescape(raw)
    return re.sub(r"\s+", " ", raw)


def _judge(cite: dict, live: str, archived: str) -> str:
    q = cite.get("quote", "")
    span = _opening(q)
    has_ell = "..." in q or "…" in q
    if live:
        if find_quote(live, q):
            return "PRESENT_LIVE"
        if has_ell and span and norm(span) in norm(live):
            return "ELIDED"
        if not has_ell and span and norm(span) in norm(live):
            return "REWRITE"
    if archived:
        if find_quote(archived, q):
            return "DRIFT_ARCHIVED"
        if span and norm(span) in norm(archived):
            return "DRIFT_ARCHIVED"
    return "INVENTED"


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="classify_quote_drift")
    ap.add_argument("--report", required=True)
    ap.add_argument("--json", help="write the classified report here")
    ap.add_argument("--timestamp", default="20251001",
                    help="preferred archive snapshot date")
    ap.add_argument("--workers", type=int, default=6)
    args = ap.parse_args(argv)

    data = json.loads(Path(args.report).read_text(encoding="utf-8"))
    missing = data.get("fabricated", [])
    if not missing:
        print("nothing to classify")
        return 0

    by_url: dict[str, list[dict]] = defaultdict(list)
    for c in missing:
        by_url[c["url"]].append(c)

    print(f"classifying {len(missing)} NOT_FOUND citations "
          f"over {len(by_url)} URLs (live + archive)")

    live_pages: dict[str, str] = {}
    archive_pages: dict[str, str] = {}
    done = 0
    with ThreadPoolExecutor(max_workers=args.workers) as pool:
        for url, cites in by_url.items():
            live = _page_text(url)
            live_pages[url] = live
            # Only consult the archive when the live page cannot account for
            # the quote. A quote present live needs no archive.
            need_archive = True
            for c in cites:
                q = c.get("quote", "")
                if live and (find_quote(live, q) or
                             norm(_opening(q)) in norm(live)):
                    need_archive = False
                    break
            if need_archive:
                archive_pages[url] = _archived_text(url, args.timestamp)
            done += 1
            if done % 20 == 0:
                print(f"  {done}/{len(by_url)} urls", flush=True)

    counts: Counter = Counter()
    detail: list[dict] = []
    for url, cites in by_url.items():
        live = live_pages.get(url, "")
        arch = archive_pages.get(url, "")
        for c in cites:
            v = _judge(c, live, arch)
            counts[v] += 1
            detail.append({**c, "verdict": v})

    print()
    print("=" * 70)
    print("QUOTE DRIFT CLASSIFICATION")
    print("=" * 70)
    for k in sorted(counts):
        print(f"  {k:16s} {counts[k]}")
    print()
    print("  PRESENT_LIVE   the quote IS on the live page (a matcher artefact)")
    print("  ELIDED        the stored quote is a truncated excerpt")
    print("  REWRITE       the quote's opening is still live; the rest moved")
    print("  DRIFT_ARCHIVED the quote is in an ARCHIVED copy: the page was")
    print("                rewritten after the citation was made")
    print("  INVENTED      not live, not archived, not on any cited page")

    by_class: dict[str, Counter] = defaultdict(Counter)
    for d in detail:
        by_class[d["class_id"]][d["verdict"]] += 1
    print(f"\n  classes affected: {len(by_class)}")
    for cid, c in sorted(by_class.items(),
                          key=lambda kv: -kv[1].get("INVENTED", 0))[:20]:
        print(f"    {cid:35s} {dict(c)}")

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
