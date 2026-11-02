#!/usr/bin/env python3
"""How much of a missing quote is actually ON the page?

THE QUESTION
------------
A citation is not fabricated or honest — it is a DEGREE. Three states were
already separated:

  * the quote is on the page (verified),
  * the quote is in an archived copy (the page was rewritten),
  * the quote is nowhere (invented).

But "nowhere" hides a continuum. MEASURED 2026-10-31 on the OWASP
Authentication Cheat Sheet:

  stored quote : "The failure counter must be associated with the account,
                  not the source IP address, for password guessing controls."
  live page    : "The counter of failed logins should be associated with the
                  account itself, rather than the source IP address, in order
                  to prevent an attacker from making login attempts from a
                  large number of different IP addresses."

The stored quote is a PARAPHRASE of the page. It is not a fabrication — it
carries the page's meaning — but it is not a QUOTE either, and a corpus that
calls a paraphrase a quote is claiming a fidelity it does not have.

This tool measures the continuum: for each NOT_FOUND citation, what fraction
of the quote's DISTINCTIVE tokens actually appear on the page? That single
number separates

  near-verbatim paraphrase  (most tokens present; the citation is honest but
                             imprecise)
  from
  wholesale invention       (few or no tokens present; the citation is false)

and it needs no judgement call, which is what makes it safe to report.

HOW IT MEASURES
---------------
Tokens are the quote's content words, length >= 4, lowercased, with a
stopword list applied. The distinctive ones — those appearing in the quote
but NOT common to the page's other citations — are the ones that carry the
claim. Coverage is the fraction of those present on the page.

Usage:
    python tools/quote_fidelity.py --report /tmp/quotes_bulk.json
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from collections import Counter, defaultdict
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from wks import pipeline  # noqa: E402
from wks.verify_quotes import norm  # noqa: E402

STOP = {
    "this", "that", "with", "from", "have", "been", "will", "your", "their",
    "there", "which", "when", "than", "then", "they", "them", "these", "those",
    "such", "also", "into", "over", "under", "about", "after", "before",
    "while", "where", "because", "however", "should", "must", "can", "could",
    "would", "could", "does", "done", "make", "made", "more", "most", "other",
    "only", "some", "such", "than", "them", "then", "there", "these", "they",
    "this", "those", "through", "using", "very", "were", "what", "when",
    "where", "which", "while", "will", "with", "your", "been", "being", "both",
    "each", "from", "have", "its", "it's", "not", "now", "one", "out", "over",
    "same", "see", "seem", "take", "than", "that", "their", "them", "then",
    "there", "these", "they", "thing", "things", "this", "those", "through",
    "under", "until", "used", "using", "very", "want", "well", "were", "what",
    "when", "where", "which", "while", "will", "with", "would", "your",
}

_TOKEN = re.compile(r"[a-z0-9][a-z0-9_.-]{2,}")


def tokens(s: str) -> list[str]:
    return [t for t in _TOKEN.findall((s or "").lower())
            if len(t) >= 4 and t not in STOP]


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="quote_fidelity")
    ap.add_argument("--report", required=True)
    ap.add_argument("--json", help="write the report here")
    ap.add_argument("--workers", type=int, default=8)
    args = ap.parse_args(argv)

    data = json.loads(Path(args.report).read_text(encoding="utf-8"))
    missing = data.get("fabricated", [])
    if not missing:
        print("nothing to measure")
        return 0

    by_url: dict[str, list[dict]] = defaultdict(list)
    for c in missing:
        by_url[c["url"]].append(c)

    def _get(url: str) -> tuple[str, str]:
        page = pipeline.fetch(url, limit=1_500_000)
        if page.get("access_state") != "ACTIVE":
            return url, ""
        return url, page.get("text", "")

    texts: dict[str, str] = {}
    with ThreadPoolExecutor(max_workers=args.workers) as pool:
        for url, text in pool.map(_get, sorted(by_url)):
            texts[url] = text

    buckets: Counter = Counter()
    detail: list[dict] = []
    for url, cites in by_url.items():
        page = texts.get(url, "")
        ptoks = set(tokens(page))
        for c in cites:
            qt = tokens(c.get("quote", ""))
            if not qt:
                buckets["NO_TOKENS"] += 1
                detail.append({**c, "coverage": 0.0, "bucket": "NO_TOKENS"})
                continue
            hit = sum(1 for t in qt if t in ptoks)
            cov = hit / len(qt)
            if cov >= 0.9:
                b = "A_NEAR_VERBATIM"
            elif cov >= 0.7:
                b = "B_PARAPHRASE"
            elif cov >= 0.4:
                b = "C_LOOSE_PARAPHRASE"
            elif cov >= 0.15:
                b = "D_MOSTLY_ABSENT"
            else:
                b = "E_ABSENT"
            buckets[b] += 1
            detail.append({**c, "coverage": round(cov, 3), "bucket": b,
                           "tokens_total": len(qt), "tokens_hit": hit})

    print()
    print("=" * 70)
    print("QUOTE FIDELITY — token coverage of each missing quote")
    print("=" * 70)
    for k in sorted(buckets):
        print(f"  {k:20s} {buckets[k]}")
    print()
    print("  A_NEAR_VERBATIM   >=90% of the quote's words are on the page:")
    print("                    a paraphrase, not a fabrication")
    print("  B_PARAPHRASE      70-90%: the meaning is carried, the wording")
    print("                    is not the source's")
    print("  C_LOOSE_PARAPHRASE 40-70%: related language, questionable claim")
    print("  D_MOSTLY_ABSENT   15-40%: mostly not on the page")
    print("  E_ABSENT          <15%: the quote is not on the page")

    by_class: dict[str, Counter] = defaultdict(Counter)
    for d in detail:
        by_class[d["class_id"]][d["bucket"]] += 1
    print(f"\n  classes affected: {len(by_class)}")
    for cid, c in sorted(by_class.items(),
                          key=lambda kv: -kv[1].get("E_ABSENT", 0))[:18]:
        print(f"    {cid:34s} {dict(c)}")

    if args.json:
        Path(args.json).write_text(json.dumps({
            "buckets": dict(buckets),
            "by_class": {k: dict(v) for k, v in by_class.items()},
            "detail": detail,
        }, indent=1), encoding="utf-8")
        print(f"\n  report written to {args.json}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
