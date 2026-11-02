#!/usr/bin/env python
"""Fetch candidate pages for held items and propose verbatim sentences.

This is a READING tool, not a promotion tool. It reads the single-publisher
worklist, fetches every candidate URL live, and shows the sentences on that
page that share distinctive vocabulary with the claim. A candidate is only a
place to look: the sentence still has to be read and judged against the claim
before it is linked into the corpus.

    python3 tools/propose_second_sources.py
    python3 tools/propose_second_sources.py --class graphql --workers 4

Writes:
    learning/gaps/second-source-proposals-<YYYYMMDD>.json
    learning/gaps/second-source-proposals-<YYYYMMDD>.md

Nothing in db/wks.db is written.
"""
from __future__ import annotations

import argparse
import collections
import concurrent.futures
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from wks import pipeline, relevance, store  # noqa: E402

GAPS = ROOT / "learning" / "gaps"
_STOP = set(
    """the and for with that this from are was were will would can could should
    not have has had but its their they them then than into over under about
    after before when where which while who whom whose what how why all any each
    other some such only also more most very may might must does did done being
    been because between through during within without across via per upon these
    those there here is are was were be been being to of in on at by or as if it
    its we our you your i""".split()
)
_SENT = re.compile(r"(?<=[.!?])\s+(?=[A-Z0-9(])")


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _tokens(text: str) -> set[str]:
    return {w for w in re.findall(r"[a-z0-9]{4,}", (text or "").lower())
            if w not in _STOP}


def _sentences(text: str) -> list[str]:
    out = []
    for chunk in re.split(r"\n{2,}", text or ""):
        chunk = re.sub(r"\s+", " ", chunk).strip()
        if not chunk:
            continue
        for s in _SENT.split(chunk):
            s = s.strip()
            if 60 <= len(s) <= 700:
                out.append(s)
    return out


def _rank(sentences: list[str], claim: str, class_id: str) -> list[dict]:
    claim_terms = _tokens(claim)
    vocab = relevance.CLASS_VOCAB.get(class_id, {})
    rows = []
    for s in sentences:
        st = _tokens(s)
        overlap = sorted(claim_terms & st)
        class_hits = relevance._hits(relevance._normalise(s), vocab) if vocab else []
        score = len(overlap) + 2 * len(class_hits)
        if not overlap and not class_hits:
            continue
        rows.append({"quote": s, "score": score,
                     "overlap": overlap[:20], "class_hits": class_hits[:10]})
    rows.sort(key=lambda r: (-r["score"], -len(r["quote"]), r["quote"]))
    return rows[:5]


def _fetch_one(url: str) -> dict:
    got = pipeline.fetch(url, limit=250_000, resolve_moved=False)
    return {
        "url": url,
        "access_state": got.get("access_state"),
        "http_status": got.get("http_status") or got.get("status"),
        "text": got.get("text") or "",
        "mirror": got.get("mirror"),
        "error": got.get("error"),
    }


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="propose_second_sources.py")
    ap.add_argument("--class", dest="class_id")
    ap.add_argument("--item", dest="item_key")
    ap.add_argument("--workers", type=int, default=6)
    args = ap.parse_args(argv)

    worklist = json.loads(
        (GAPS / "single-publisher-20261028.json").read_text(encoding="utf-8"))
    items = []
    for cid, group in worklist["classes"].items():
        if args.class_id and cid != args.class_id:
            continue
        for it in group["items"]:
            if it["blocker_class"] != "publisher_only":
                continue
            if args.item_key and it["item_key"] != args.item_key:
                continue
            items.append((cid, it))
    if not items:
        print("no publisher-only items matched", file=sys.stderr)
        return 1

    urls = sorted({c["url"] for _, it in items for c in it["candidates"]
                   if c.get("url") and not c.get("error")})
    print(f"items={len(items)} candidate URLs={len(urls)} workers={args.workers}")
    fetched: dict[str, dict] = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.workers) as ex:
        futs = {ex.submit(_fetch_one, u): u for u in urls}
        for i, fut in enumerate(concurrent.futures.as_completed(futs), 1):
            url = futs[fut]
            try:
                got = fut.result()
            except Exception as exc:  # a fetch failure is data, not a crash
                got = {"url": url, "access_state": "FETCH_ERROR",
                       "text": "", "error": f"{type(exc).__name__}: {exc}"}
            fetched[url] = got
            print(f"  [{i}/{len(urls)}] {got.get('access_state') or '?':16} "
                  f"{len(got.get('text') or ''):7} {url[:100]}")

    out = {"generated_at": _now(), "items": []}
    for cid, it in items:
        rec = {
            "class_id": cid,
            "item_key": it["item_key"],
            "claim": it["claim"],
            "current_orgs": it["current_orgs"],
            "current_sources": it["current_sources"],
            "candidates": [],
        }
        for cand in it["candidates"]:
            url = cand.get("url")
            got = fetched.get(url, {})
            sentences = _sentences(got.get("text") or "")
            rec["candidates"].append({
                **cand,
                "access_state": got.get("access_state"),
                "http_status": got.get("http_status"),
                "text_chars": len(got.get("text") or ""),
                "proposals": _rank(sentences, it["claim"], cid),
            })
        out["items"].append(rec)

    stamp = datetime.now(timezone.utc).strftime("%Y%m%d")
    js = GAPS / f"second-source-proposals-{stamp}.json"
    md = GAPS / f"second-source-proposals-{stamp}.md"
    js.write_text(json.dumps(out, indent=2), encoding="utf-8")

    L = ["# Second-source proposals", "",
         f"Generated from the live candidate pages at `{out['generated_at']}`.",
         "These are **quotes to review**, not accepted evidence. A sentence is a",
         "proposal only if it is on the page; whether it supports the claim is a",
         "separate judgement.", ""]
    for rec in out["items"]:
        L += [f"## `{rec['item_key']}`", "", f"**Claim:** {rec['claim']}", ""]
        for cand in rec["candidates"]:
            L.append(f"### {cand.get('org')} — {cand.get('url')}")
            L.append(f"status `{cand.get('access_state')}`, "
                     f"{cand.get('text_chars')} chars")
            if not cand["proposals"]:
                L.append("_No sentence shared enough vocabulary; read the page manually._")
            for p in cand["proposals"]:
                L.append(f"- score {p['score']}: {p['quote']}")
                L.append(f"  - overlap: `{', '.join(p['overlap'])}`")
            L.append("")
    md.write_text("\n".join(L).rstrip() + "\n", encoding="utf-8")
    print(f"wrote {js.relative_to(ROOT)}")
    print(f"wrote {md.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
