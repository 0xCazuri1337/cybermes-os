#!/usr/bin/env python
"""Verify every quote in a research incoming file against a live re-fetch.

    python tools/w12_verify.py research/incoming/w12_xxx.json
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from wks import pipeline  # noqa: E402
from wks.verify_quotes import find_quote  # noqa: E402


def main(path: str) -> int:
    doc = json.loads(Path(path).read_text(encoding="utf-8"))
    cache: dict[str, str | None] = {}
    bad = 0
    for it in doc.get("items", []):
        orgs = set()
        for s in it.get("sources", []):
            u = s["url"]
            if u not in cache:
                r = pipeline.fetch(u, limit=1_500_000)
                cache[u] = r["text"] if r.get("ok") else None
            t = cache[u]
            if t is None:
                print(f"FETCHFAIL {it['item_key']} {u}")
                bad += 1
                continue
            ok = bool(find_quote(t, s["quote"]))
            orgs.add(u.split("/")[2])
            if not ok:
                print(f"QUOTEFAIL {it['item_key']} {u}")
                print(f"   want: {s['quote'][:160]}")
                bad += 1
        if len(orgs) < 2:
            print(f"PUBS<2 {it['item_key']} -> {orgs}")
            bad += 1
    n = len(doc.get("items", []))
    print(f"{path}: {n} items, {bad} problems")
    return 1 if bad else 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1]))
