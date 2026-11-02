"""Harvest the bugbountydaily RSS into gated intake items, per class.

The feed is a link index; each linked ARTICLE is the real publisher and the
only quotable source. So the harvest is two-stage:

  1. read the feed -> candidate article URLs
  2. for each article that maps to a registered class, fetch it, extract a
     contiguous span, RE-VERIFY the span against the bytes we hold, and only
     then write an intake item

Every item still needs >= 2 independent publisher hosts to be promoted. A single
article is one host, so these land as `under_review` until a second publisher
corroborates them — that is the gate working, not a failure. Filing them to
research/incoming/ means the real ingest path judges them, not this script.

Run:  python tools/harvest_bugbountydaily.py [--dry]
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from urllib.parse import urlparse

ROOT = Path(r"C:\Users\Administrator\.hermes\cyber")
sys.path.insert(0, str(ROOT))

import sqlite3  # noqa: E402
from wks import pipeline  # noqa: E402
from orch import researcher  # noqa: E402

FEED = "https://pyqacwkytiyzciltgsal.supabase.co/storage/v1/object/public/feeds/rss.xml"
OUT_DIR = ROOT / "research" / "incoming"
OUT = OUT_DIR / "harvest-bugbountydaily.json"

# article host -> (class_id, what the article is about)
# Keys are REGISTRABLE DOMAINS, because the harvester looks the host up after
# `registrable_domain()` folding. The first draft keyed on the raw host
# (`blog.ammaraskar.com`, `lab.ctbb.show`) and three articles silently fell
# through to UNMAPPED — the same host-matching family as the earlier publisher
# org trap, where two hosts of one org must count once.
# Only classes already registered in the taxonomy are eligible; anything else
# is reported as unmapped rather than forced into a neighbouring class.
MAPPING = {
    "ammaraskar.com":    ("supply_chain", "editor/extension -> token theft"),
    "ctbb.show":         ("smuggling", "HTTP/2 framing WAF bypass"),
    "silentsignal.eu":   ("exposed_services", "unauthenticated mgmt plane RCE"),
    "brutecat.com":      ("misconfig", "AI-driven infra-wide key discovery"),
    "varonis.com":       ("mass_assign", "AI agent trust boundary"),
    "zere.es":           ("xss", "self-XSS to account takeover"),
    "elttam.com":        ("supply_chain", "Go module review notes"),
    "jorianwoltjer.com": ("xss", "Blob-URL sandbox escape to XSS"),
    "sectricity.com":    ("misconfig", "exposed Grafana -> private repo chain"),
    "flatt.tech":        ("supply_chain", "CI workflow -> supply chain"),
    "nebusec.ai":        ("deser", "V8 type confusion"),
    "bobdahacker.com":   ("authz", "self-registration onto a data platform"),
    "oddguan.com":       ("container_escape", "agent sandbox escape"),
}

# `candidate_spans` already enforces the gate's MIN_CLAIM_CHARS, so a pair it
# returns is claim-length. A span that short is a caption, not a mechanism.
MIN_QUOTE = 90


def registrable(host: str) -> str:
    return researcher.registrable_domain(host)


def host_of(url: str) -> str:
    """Hostname of a URL, www-stripped.

    Measured bug in the first draft: `re.split(r"/+", url)[2]` assumes the
    `https:` literal collapses, but it does NOT — `https://host/path` splits to
    ['https:', '', 'host', 'path'], so index 2 IS the host, while a scheme-less
    or single-slash URL shifts and index 2 lands on the path segment. That
    produced 'UNMAPPED blog' for every article. urlparse is the correct reader
    and costs nothing.
    """
    h = urlparse(url).netloc
    return h[4:] if h.startswith("www.") else h


def article_urls() -> list[str]:
    page = pipeline.fetch(FEED, limit=400_000)
    text = page.get("text") or ""
    urls = re.findall(r"https?://[^\s<>\"']+", text)
    seen, out = set(), []
    for u in urls:
        u = u.rstrip(",.;)")
        # the feed itself and the aggregator shell are not articles
        if "supabase.co" in u or "bugbountydaily.com" in u:
            continue
        if u in seen:
            continue
        seen.add(u)
        out.append(u)
    return out


def best_span(text: str, class_id: str) -> tuple[str, str] | None:
    """Best (claim, quote) pair drawn from the page, via the vetted extractor.

    Reuses `researcher.candidate_spans` rather than a hand-rolled paragraph
    picker: that extractor already drops boilerplate, headings, code, spans with
    no behaviour verb, and sentences cut mid-thought — every one of which the
    knowledge gate rejects downstream, so filtering here saves the fetch.
    It returns (claim, quote); we need the quote as the citable span.
    """
    pairs = researcher.candidate_spans(text, class_id, limit=12)
    if not pairs:
        return None
    _claim, quote = max(pairs, key=lambda p: len(p[1]))
    return class_id, quote


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--dry", action="store_true")
    ap.add_argument("--max", type=int, default=12)
    args = ap.parse_args()

    con = sqlite3.connect(str(ROOT / "db" / "wks.db"))
    known = {r[0] for r in con.execute("SELECT id FROM bug_class")}
    con.close()

    urls = article_urls()
    print(f"feed: {len(urls)} candidate article(s)")

    items: list[dict] = []
    unmapped: list[str] = []
    for url in urls[: args.max]:
        host = host_of(url)
        key = registrable(host)
        if key not in MAPPING:
            unmapped.append(f"{host} ({url})")
            print(f"  UNMAPPED  {host}")
            continue
        class_id, why = MAPPING[key]
        if class_id not in known:
            unmapped.append(f"{host} -> unmapped class {class_id}")
            print(f"  NO CLASS  {host} -> {class_id}")
            continue
        try:
            page = pipeline.fetch(url, limit=200_000)
        except Exception as e:  # noqa: BLE001
            print(f"  FETCH ERR {host}: {type(e).__name__}")
            continue
        if not page.get("ok"):
            print(f"  DEAD     {host}: status={page.get('status')} "
                  f"{str(page.get('error') or '')[:50]}")
            continue
        text = page.get("text") or ""
        span = best_span(text, class_id)
        if not span:
            print(f"  NO SPAN  {host}: no paragraph carries the vocabulary")
            continue
        _, quote = span
        # Length floor BEFORE verify: a 58-char fragment (measured on
        # nebusec.ai) is a caption, not a mechanism. `candidate_spans` enforces
        # MIN_CLAIM_CHARS but that is the floor for a CLAIM, and these quotes are
        # filed verbatim -- a short one cannot carry the claim the item makes.
        if len(quote) < MIN_QUOTE:
            print(f"  TOO SHORT {host}: {len(quote)}ch < {MIN_QUOTE}")
            continue
        # Re-verify against the bytes we hold. Extraction guarantees
        # membership; this is the guard against a normalisation bug.
        if not researcher.verify_span(quote, text):
            print(f"  VERIFY FAILED {host}: span not in fetched text")
            continue
        items.append({
            "item_key": f"{class_id}.lead.bbd_{key}",
            "claim": f"Public writeup evidence for {class_id}: {why}.",
            "kind": "technique",
            "body": (f"HARVESTED FROM bugbountydaily RSS -> {url}\n"
                     f"Reason it matters: {why}.\n\n{quote}"),
            "disproof": ("Refuted if the fetched page no longer contains this exact "
                         "span, or if the described behaviour is corrected or "
                         "withdrawn by the publisher."),
            "hunting_value": 2,
            "sources": [{
                "url": url,
                "source_type": "writeup",
                "host": key,
                "publisher": key,
                "quote": quote,
            }],
            "_needs_second_publisher": True,
        })
        print(f"  OK       {key:24} -> {class_id}  quote={len(quote)}ch")

    print()
    print(f"harvested {len(items)} single-publisher lead(s); "
          f"{len(unmapped)} unmapped link(s) skipped")

    if args.dry or not items:
        return 0

    payload = {
        "class_id": "multi",
        "items": items,
        "publishers": len({i["sources"][0]["host"] for i in items}),
        "sources": [FEED],
        "note": ("Discovery leads harvested from the bugbountydaily index. Each "
                 "cites ONE publisher, so the gate holds them at under_review "
                 "until a second independent publisher corroborates each one. "
                 "This is the intended outcome, not a failure."),
    }
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(payload, indent=2, ensure_ascii=False),
                   encoding="utf-8")
    OUT.write_text(OUT.read_text(encoding="utf-8") + f"\n// COMPLETE {len(items)}\n",
                   encoding="utf-8")
    print(f"wrote {OUT}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())