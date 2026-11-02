#!/usr/bin/env python
"""Quote getter for research agents.

    python tools/qget.py <url>              # print fetch status + full text
    python tools/qget.py <url> --find needle   # print a 400-char window around
                                              # every match, ready to copy

WHY THIS EXISTS. The gate (wks/verify_quotes.py) re-fetches each cited URL with
`pipeline.fetch` and matches the quote against the DE-TAGGED text. A quote copied
out of a markdown extractor, a browser render, or a search snippet will not match
that text, and the item is rejected as FABRICATED even when the researcher read
the page honestly. Copy quotes from THIS tool's output.

Normalization the gate also applies before matching: unicode NFKC, curly quotes
to straight, dashes to hyphen, whitespace collapsed, space removed before
,.;:!?)]} and after ([{. So quote the visible prose, not the markup.
"""
from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from wks import pipeline  # noqa: E402


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="qget.py")
    ap.add_argument("url")
    ap.add_argument("--find", help="print windows around matches instead of all text")
    ap.add_argument("--window", type=int, default=400)
    ap.add_argument("--all", action="store_true", help="show every match, not just the first 5")
    args = ap.parse_args(argv)

    r = pipeline.fetch(args.url, limit=1_500_000)
    if not r.get("ok"):
        print(f"FETCH FAILED status={r.get('status')} error={r.get('error')}")
        print("DEAD URL — do not cite it. Find another page.")
        print("NOTE: a transient DNS/timeout failure looks identical to a dead URL. "
              "Re-run once before concluding the page is gone.")
        return 1
    text = r["text"]
    # A short body on a documentation page is a failure, not a page. Refusing to
    # print it stops an error stub from being cached and later read as evidence.
    if len(text) < 2000:
        print(f"REFUSING: only {len(text)} chars — this is an error stub, not a page.")
        print("Do not cache or quote it. Re-run; if it persists, the fetch path is "
              "broken, not the page.")
        return 2
    print(f"# status={r.get('status')} chars={len(text)} url={args.url}")
    if not args.find:
        print(text)
        return 0

    needle = re.escape(args.find)
    hits = list(re.finditer(needle, text, re.I))
    print(f"# {len(hits)} match(es) for {args.find!r}\n")
    shown = hits if args.all else hits[:5]
    for m in shown:
        a = max(0, m.start() - args.window // 2)
        b = min(len(text), m.end() + args.window // 2)
        print("---")
        print(text[a:b].strip())
        print()
    if len(shown) < len(hits):
        print(f"# ...{len(hits) - len(shown)} more; pass --all")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())