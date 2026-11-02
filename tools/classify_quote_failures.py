#!/usr/bin/env python3
"""Classify each NOT_FOUND citation by WHY the quote was not found.

THE QUESTION
------------
`tools/audit_quotes_bulk.py` reports a citation as NOT_FOUND when the quote is
not present in the fetched page. That single verdict conflates at least four
different situations, and they need different handling:

  A. ELIDED        — the stored quote contains an ellipsis, so it is a
                     truncated excerpt of the page. The matcher requires the
                     WHOLE string, so a legitimate quote is reported missing.
                     This is a MATCHER limitation, not a bad citation.
  B. PAGE DRIFT    — the opening of the quote is still on the page, but the
                     page has since been rewritten. The citation was genuine
                     when made; the source moved on. The quote is stale, not
                     invented.
  C. MISFILED      — the quote's opening is NOT on the cited page, but the
                     quote is real text from somewhere else. The citation
                     names the wrong URL.
  D. INVENTED      — no part of the quote is on the page, and the quote does
                     not appear to be real text. This is fabrication.

Only D is fabrication in the strict sense. Reporting A, B and C as
fabrication would be exactly the over-reporting this project's invariants
warn about: "a rejection rate from an unvalidated verifier is a measurement of
your own bugs".

HOW THIS IS MEASURED
--------------------
For each NOT_FOUND citation, the page text is searched for the quote's
opening SPAN (the first N characters up to the first ellipsis or sentence
boundary). A hit on the opening means the page still carries that text, which
rules out D.

Usage:
    python tools/classify_quote_failures.py --report /tmp/quotes_bulk.json
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from collections import Counter, defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from wks import pipeline  # noqa: E402
from wks.verify_quotes import norm  # noqa: E402


def opening_span(quote: str, min_len: int = 60) -> str:
    """The leading run of the quote, up to an ellipsis or a sentence end.

    A long opening is required: a short one (a handful of common words) can
    match by accident and would turn a fabrication into a false "page drift".
    """
    q = quote.strip()
    # Cut at an ellipsis if there is one.
    for marker in ("...", "…", "\n"):
        i = q.find(marker)
        if i > 0:
            q = q[:i]
    # Cut at the first sentence end, but only if enough text survives.
    m = re.search(r"[.!?](?:\s|$)", q)
    if m and m.end() >= min_len:
        q = q[:m.end()]
    return q.strip()


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="classify_quote_failures")
    ap.add_argument("--report", required=True,
                    help="the JSON report from tools/audit_quotes_bulk.py")
    ap.add_argument("--json", help="write the classified report here")
    args = ap.parse_args(argv)

    data = json.loads(Path(args.report).read_text(encoding="utf-8"))
    fabricated = data.get("fabricated", [])
    if not fabricated:
        print("no NOT_FOUND citations in the report")
        return 0

    # One fetch per distinct URL.
    by_url: dict[str, list[dict]] = defaultdict(list)
    for c in fabricated:
        by_url[c["url"]].append(c)

    print(f"classifying {len(fabricated)} NOT_FOUND citations "
          f"over {len(by_url)} URLs")

    pages: dict[str, str] = {}
    for url in by_url:
        page = pipeline.fetch(url, limit=1_500_000,
                              quote=by_url[url][0].get("quote"))
        pages[url] = page.get("text", "") if page.get("access_state") == "ACTIVE" else ""

    counts: Counter = Counter()
    detail: list[dict] = []
    for url, cites in by_url.items():
        text = pages.get(url, "")
        nt = norm(text)
        for c in cites:
            q = c.get("quote", "")
            span = opening_span(q)
            has_ell = "..." in q or "…" in q
            if not text:
                verdict = "UNFETCHABLE"
            elif has_ell:
                # An elided quote cannot be matched whole; judge it on its
                # leading span.
                verdict = "A_ELIDED" if (span and norm(span) in nt) else "D_INVENTED"
            elif span and norm(span) in nt:
                verdict = "B_PAGE_DRIFT"
            else:
                verdict = "D_INVENTED"
            counts[verdict] += 1
            detail.append({**c, "verdict": verdict, "opening_span": span[:160]})

    print()
    print("=" * 70)
    print("NOT_FOUND CLASSIFICATION")
    print("=" * 70)
    for k in sorted(counts):
        print(f"  {k:16s} {counts[k]}")
    print()
    print("  A_ELIDED      the stored quote is a truncated excerpt (ellipsis)")
    print("  B_PAGE_DRIFT  the quote's opening is still on the page; it has")
    print("                since been rewritten")
    print("  D_INVENTED    no part of the quote is on the page")
    print("  UNFETCHABLE   the page did not deliver prose this run")

    by_class: dict[str, Counter] = defaultdict(Counter)
    for d in detail:
        by_class[d["class_id"]][d["verdict"]] += 1
    print(f"\n  classes affected: {len(by_class)}")
    worst = sorted(by_class.items(), key=lambda kv: -sum(kv[1].values()))
    print("  worst classes:")
    for cid, c in worst[:15]:
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
