#!/usr/bin/env python
"""Verify candidate quotes against freshly fetched page text for wave 13.

    python tools/w13_qcheck.py <json-file-of-candidates>

Candidate file: [{"url": ..., "quote": ...}, ...]
Prints OK / MISS per quote. Never cite anything that misses here.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from wks import pipeline  # noqa: E402
from wks.verify_quotes import find_quote  # noqa: E402

CACHE = Path(__file__).resolve().parents[1] / "research" / "tmp" / "w13"


def text_for(url: str) -> str:
    slug = url.replace("://", "_").replace("/", "_")[-120:]
    p = CACHE / f"{slug}.txt"
    if p.exists():
        return p.read_text(encoding="utf-8")
    r = pipeline.fetch(url, limit=1_500_000)
    if not r.get("ok"):
        raise SystemExit(f"FETCH FAILED {url} status={r.get('status')}")
    CACHE.mkdir(parents=True, exist_ok=True)
    p.write_text(r["text"], encoding="utf-8")
    return r["text"]


def main(argv):
    cands = json.loads(Path(argv[1]).read_text(encoding="utf-8"))
    bad = 0
    for c in cands:
        t = text_for(c["url"])
        ok = find_quote(t, c["quote"])
        if ok:
            print(f"OK   {c['url']}")
        else:
            bad += 1
            print(f"MISS {c['url']}\n     {c['quote'][:140]}")
    print(f"\n# {len(cands) - bad}/{len(cands)} verified")
    return 1 if bad else 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))