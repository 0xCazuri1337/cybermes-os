#!/usr/bin/env python
"""Sliced quote reader for cached research pages.

    python tools/qlines.py <key> "<phrase>" [--w 700] [--all]

Prints a window around every match of <phrase> in the cached page text, in the
EXACT form quotes must be copied. Every candidate span this returns is then
asserted with wks.verify_quotes.find_quote before it goes into a research file.

This exists because the pages' prose sits behind nav and inline-script blobs
that make a generic "extract the article" pass unreliable; reading around a
known-good phrase is both simpler and safer than trying to guess a boundary.
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from wks.verify_quotes import find_quote  # noqa: E402

CACHE = ROOT / "research" / "tmp" / "xss"


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="qlines.py")
    ap.add_argument("key")
    ap.add_argument("phrase")
    ap.add_argument("--w", type=int, default=700)
    ap.add_argument("--all", action="store_true")
    args = ap.parse_args(argv)

    p = CACHE / f"{args.key}.txt"
    if not p.exists():
        print(f"no cached page for {args.key!r} — run tools/fetch_pages.py {args.key}")
        return 1
    text = p.read_text(encoding="utf-8")
    flat = " ".join(text.split())

    idxs, i = [], -1
    while True:
        i = flat.find(args.phrase, i + 1)
        if i < 0:
            break
        idxs.append(i)
    print(f"# {args.key}: {len(idxs)} match(es) for {args.phrase!r} (flat len={len(flat)})")
    shown = idxs if args.all else idxs[:4]
    for n in shown:
        a, b = max(0, n - args.w // 3), min(len(flat), n + args.w)
        span = flat[a:b]
        print(f"\n--- @{n}  self-verifies={find_quote(text, span)}")
        print(span)
    if len(shown) < len(idxs):
        print(f"\n# ...{len(idxs) - len(shown)} more; pass --all")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())