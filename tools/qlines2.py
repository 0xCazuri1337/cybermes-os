#!/usr/bin/env python
"""Print the neighbourhood of a phrase in a fetched page, with the gate's own
matcher verdict per window. Use when a quote is rejected and the question is
"is this a fabrication or an extraction artefact?".

    python tools/qlines2.py <url> "<phrase>" [window]
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from wks import pipeline  # noqa: E402
from wks.verify_quotes import find_quote  # noqa: E402


def main() -> int:
    url, phrase = sys.argv[1], sys.argv[2]
    win = int(sys.argv[3]) if len(sys.argv) > 3 else 300
    r = pipeline.fetch(url, limit=1_500_000)
    if not r.get("ok"):
        print(f"FETCH FAILED status={r.get('status')} err={r.get('error')} "
              f"chars={len(r.get('text',''))}")
        return 1
    text = r["text"]
    print(f"# {url}\n# ok={r.get('status')} chars={len(text)}")
    for m in re.finditer(re.escape(phrase), text, re.I):
        a, b = max(0, m.start() - win), min(len(text), m.end() + win)
        seg = " ".join(text[a:b].split())
        print(f"\n--- offset {m.start()} self-verifies={find_quote(text, seg)}")
        print(seg)
    if not re.search(re.escape(phrase), text, re.I):
        print(f"\nPHRASE ABSENT from page. Loose token scan:")
        toks = [t for t in re.findall(r"[A-Za-z_]{4,}", phrase)]
        flat = " ".join(text.split())
        for t in toks:
            i = flat.lower().find(t.lower())
            print(f"  {t:24} {'@'+str(i) if i>=0 else 'ABSENT'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
