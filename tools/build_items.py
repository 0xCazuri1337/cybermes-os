"""Build research items by SLICING real spans out of fetched pages.

Hand-written quotes are the fabrication vector this system exists to stop: a
plausible sentence is written from memory, the ingest gate fetches the page, the
quote is absent, and the item is rejected. Every quote here is cut out of the
actual response body, trimmed to a sentence boundary, and asserted against
`wks.verify_quotes.find_quote` before the file is written. The build ABORTS on
the first bad anchor, so a paraphrase cannot reach the file at all.

The `hosts per item >= 2` assertion is the other half: two pages on one host is
one publisher, and the item can never promote.

    python tools/build_items.py --plan tools/item_plan.json
"""
from __future__ import annotations

import argparse
import json
import re
import sys
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from wks.verify_quotes import find_quote  # noqa: E402

UA = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) WKS-Research/2.0"}
CACHE = ROOT / "research" / "tmp" / "pages"

EXCLUDED = {
    "cwe.mitre.org", "owasp.org", "cheatsheetseries.owasp.org", "wstg.owasp.org",
    "community.owasp.org", "api-security.owasp.org", "portswigger.net",
    "developer.mozilla.org", "html.spec.whatwg.org", "rfc-editor.org",
    "attack.mitre.org", "learn.microsoft.com", "github.com", "docs.github.com",
    "raw.githubusercontent.com", "medium.com", "hackerone.com",
    "bugbountyhunter.com", "sploitus.com", "vulners.com", "cvebase.io",
    "hackthrough.live", "app.notion.com",
}
BUILDER_SUFFIX = (".notion.site", ".gitbook.io", ".readthedocs.io",
                  ".netlify.app", ".vercel.app")


def fetch(url: str) -> str | None:
    """Cache by URL PATH, never by host.

    A host-keyed cache served the first article fetched for a host back for every
    later URL on it: unit42 alone serves dozens of posts. That made
    slice_quote report "anchor not found" for text that WAS on the live page, and
    in the worst case would have attributed one article's bytes to another
    article's citation."""
    CACHE.mkdir(parents=True, exist_ok=True)
    host = url.split("/")[2]
    path = url.split(host, 1)[1] or "/"
    slug = (host.replace(".", "_") + "__" +
            re.sub(r"[^A-Za-z0-9]+", "_", path).strip("_")[:80])
    f = CACHE / (slug + ".html")
    if f.exists() and f.stat().st_size > 2000:
        return f.read_text(encoding="utf-8", errors="replace")
    try:
        with urllib.request.urlopen(urllib.request.Request(url, headers=UA),
                                    timeout=30) as r:
            body = r.read().decode("utf-8", "replace")
    except Exception:
        return None
    if len(body) < 2000:      # an error stub is not a source
        return None
    f.write_text(body, encoding="utf-8")
    return body


def clean(html: str) -> str:
    import html as H
    import re
    t = re.sub(r"(?is)<(script|style|nav|header|footer)[^>]*>.*?</\1>", " ", html)
    t = re.sub(r"(?s)<[^>]+>", " ", t)
    t = H.unescape(t)
    return re.sub(r"[ \t\xa0]+", " ", t)


def slice_quote(page: str, anchor: str, maxlen: int = 190) -> str | None:
    """Cut a real sentence containing `anchor` out of `page`.

    Returns None when the anchor is absent, so the caller aborts rather than
    writing a quote that is not on the page."""
    i = page.find(anchor)
    if i < 0:
        return None
    start = max(page.rfind(". ", 0, i), page.rfind("\n", 0, i))
    start = 0 if start < 0 else start + 1
    end = page.find(". ", i)
    end = i + maxlen if end < 0 else min(end + 1, start + maxlen)
    q = " ".join(page[start:end].split()).strip()
    return q if 20 < len(q) <= 200 else None


def build(plan: dict) -> tuple[list[dict], list[str]]:
    items: list[dict] = []
    problems: list[str] = []
    for spec in plan["items"]:
        sources = []
        for s in spec["sources"]:
            host = s["url"].split("/")[2]
            if host in EXCLUDED or any(host.endswith(x) for x in BUILDER_SUFFIX):
                problems.append(f"{spec['item_key']}: EXCLUDED host {host}")
                sources = []
                break
            page = fetch(s["url"])
            if page is None:
                problems.append(f"{spec['item_key']}: fetch failed {host}")
                sources = []
                break
            text = clean(page)
            q = slice_quote(text, s["anchor"])
            if q is None:
                problems.append(f"{spec['item_key']}: anchor not found on {host} "
                                f"({s['anchor'][:50]!r})")
                sources = []
                break
            if not find_quote(page, q) and not find_quote(text, q):
                problems.append(f"{spec['item_key']}: quote not verifiable {host}")
                sources = []
                break
            sources.append({"url": s["url"], "quote": q})
        if len(sources) < 2:
            if sources or not problems:
                problems.append(f"{spec['item_key']}: fewer than 2 usable sources")
            continue
        hosts = {x["url"].split("/")[2] for x in sources}
        if len(hosts) < 2:
            problems.append(f"{spec['item_key']}: {len(hosts)} distinct host(s) only")
            continue
        for field, n in (("claim", 40), ("disproof", 30)):
            if len(spec.get(field, "")) < n:
                problems.append(f"{spec['item_key']}: {field} too short")
        if not spec.get("body") or len(spec["body"]) < 120:
            problems.append(f"{spec['item_key']}: body too short")
        if any(p.startswith(spec["item_key"]) for p in problems):
            continue
        item = {k: spec[k] for k in
                ("item_key", "class_id", "claim", "kind", "surface",
                 "hunting_value", "body", "disproof")}
        item["sources"] = sources
        items.append(item)
    return items, problems


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="build_items")
    ap.add_argument("--plan", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--dry", action="store_true")
    a = ap.parse_args(argv)

    plan = json.loads(Path(a.plan).read_text(encoding="utf-8"))
    items, problems = build(plan)
    for p in problems:
        print("  !", p)
    print(f"\nbuilt {len(items)}/{len(plan['items'])} items")
    if problems and not items:
        return 1
    if a.dry:
        for it in items:
            hosts = sorted({s['url'].split('/')[2] for s in it['sources']})
            print(f"  {it['item_key']:34} hosts={hosts}")
        return 0
    Path(a.out).write_text(json.dumps({"items": items}, indent=2), encoding="utf-8")
    print("written:", a.out)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
