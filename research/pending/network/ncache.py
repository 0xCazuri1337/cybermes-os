"""Network-domain fetch cache built on wks.pipeline.fetch.

WHY THIS EXISTS. The promotion gate verifies every quote against the text that
`wks.pipeline.fetch` returns for the cited URL (see wks/verify_quotes.py, which
calls exactly that function). Mining quotes from any OTHER fetch path (curl, a
different tag-stripper, a browser) produces text that differs in whitespace and
entity decoding, so a genuinely verbatim quote can be reported FABRICATED.

So this module caches the gate's own output. A quote can only enter an item if
it is a literal substring of the string stored here, which is the same string
the gate will re-derive on ingest.

No LLM, no paraphrase: `spans()` returns substrings of the fetched text.
"""
from __future__ import annotations

import hashlib
import json
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[3]))

from wks import pipeline  # noqa: E402

CACHE = Path(__file__).resolve().parent / "ncache"
CACHE.mkdir(parents=True, exist_ok=True)

META = CACHE / "index.json"


def _key(url: str) -> str:
    return hashlib.sha256(url.encode()).hexdigest()[:20]


def _load_index() -> dict:
    if META.exists():
        return json.loads(META.read_text(encoding="utf-8"))
    return {}


def _save_index(idx: dict) -> None:
    META.write_text(json.dumps(idx, indent=1, ensure_ascii=False), encoding="utf-8")


def get(url: str, *, refresh: bool = False) -> dict:
    """Return {'ok','status','text','url'} for url, from cache unless refresh."""
    idx = _load_index()
    k = _key(url)
    blob = CACHE / f"{k}.txt"
    if not refresh and k in idx and blob.exists():
        return {**idx[k], "text": blob.read_text(encoding="utf-8", errors="replace")}
    r = pipeline.fetch(url, limit=1_500_000)
    rec = {
        "url": url,
        "ok": bool(r.get("ok")),
        "status": r.get("status"),
        "mirror": r.get("mirror"),
        "moved_from": r.get("moved_from"),
        "error": r.get("error"),
        "content_hash": r.get("content_hash"),
        "chars": len(r.get("text") or ""),
    }
    blob.write_text(r.get("text") or "", encoding="utf-8", errors="replace")
    idx = _load_index()
    idx[k] = rec
    _save_index(idx)
    return {**rec, "text": r.get("text") or ""}


def report() -> list[dict]:
    return sorted(_load_index().values(), key=lambda r: r["url"])


if __name__ == "__main__":
    refresh = "--refresh" in sys.argv
    for u in [a for a in sys.argv[1:] if a != "--refresh"]:
        r = get(u, refresh=refresh)
        print(f"{r['status']}  chars={r['chars']:>7}  {u}"
              + (f"  -> {r['mirror']}" if r.get("mirror") else "")
              + (f"  ERR {r.get('error')}" if not r["ok"] else ""))
