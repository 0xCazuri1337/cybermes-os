"""Render a PUBLIC Notion page to markdown, and list its sub-pages.

Three shape facts, each MEASURED against a live page before the code was written:

  1. The id must be DASHED (8-4-4-4-12). The same request with the bare 32-hex id
     returns HTTP 400, which is indistinguishable from "not public".
  2. A block record is TWO levels down: `recordMap.block[id].value.value` holds
     the payload. A walker written for one level reads zero blocks and looks
     like an empty page.
  3. `properties.title` is a LIST OF LISTS: `[[{"plain_text": ...}]]`. Joining it
     as if it were a flat list of dicts raises, and a permissive `str()` would
     print the raw JSON as the page title.

That is why `web_extract` saw the sub-page titles (its renderer runs JS) while
raw HTTP saw none: these pages ship a 20KB JS shell with zero block ids.
"""
import argparse
import json
import re
import sys
import urllib.error
import urllib.request

UA = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                  "Chrome/120.0 Safari/537.36",
    "Content-Type": "application/json", "Accept": "*/*",
    "Origin": "https://www.notion.so", "Referer": "https://www.notion.so/",
}
SKIP_WORDS = ("mobile", "android", "ios", "wifi", "wireless", "bluetooth")


def dashed(p):
    h = p.replace("-", "")
    if len(h) != 32:
        raise ValueError("not a notion id: %r" % p)
    return "%s-%s-%s-%s-%s" % (h[0:8], h[8:12], h[12:16], h[16:20], h[20:32])


def chunk(page_id, limit=200):
    payload = {"pageId": dashed(page_id), "limit": limit,
               "cursor": {"stack": []}, "chunkNumber": 0,
               "verticalColumns": False}
    req = urllib.request.Request(
        "https://www.notion.so/api/v3/loadCachedPageChunk",
        data=json.dumps(payload).encode(), headers=UA)
    with urllib.request.urlopen(req, timeout=60) as r:
        return json.loads(r.read().decode("utf-8", "replace"))


def payload_of(rec):
    # shape fact 2
    return (rec.get("value") or {}).get("value") or {}


def plain(props, key="title"):
    """`properties[key]` is a LIST OF LISTS -- shape fact 3."""
    v = props.get(key)
    if v is None:
        return ""
    out = []
    stack = [v]
    while stack:
        cur = stack.pop()
        if isinstance(cur, list):
            stack.extend(cur)
        elif isinstance(cur, dict):
            out.append(cur.get("plain_text") or cur.get("text", {}).get("content", ""))
        elif isinstance(cur, str):
            out.append(cur)
    return "".join(out)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--site", required=True)
    ap.add_argument("--page-id", required=True)
    ap.add_argument("--out")
    ap.add_argument("--skip", default=",".join(SKIP_WORDS))
    a = ap.parse_args()
    skip = {w.strip().lower() for w in a.skip.split(",") if w.strip()}

    try:
        data = chunk(a.page_id)
    except urllib.error.HTTPError as e:
        print("HTTP %s from the notion api -- not public, or the id is wrong" % e.code)
        return 1
    blocks = data.get("recordMap", {}).get("block", {})
    print("block records: %d" % len(blocks))

    pages, lines = [], []
    for k, rec in blocks.items():
        p = payload_of(rec)
        t = p.get("type")
        title = plain(p.get("properties") or {})
        if t in ("page", "collection_view_page", "link_to_page"):
            low = title.lower()
            mark = "SKIP" if any(w in low for w in skip) else "FETCH"
            pages.append((mark, title, p.get("id") or k))
            continue
        text = plain(p.get("properties") or {}) or title
        if text:
            lines.append(("## " if t in ("header", "sub_header") else "") + text)

    print("child pages : %d" % len(pages))
    for m, t, i in pages:
        print("   %-5s %-52s %s" % (m, t[:52], i[:8]))
    body = "\n\n".join(lines)
    if a.out:
        with open(a.out, "w", encoding="utf-8") as fh:
            fh.write("# %s\n\n%s\n" % (plain(blocks[a.page_id.replace('-', '')]
                                              .get('value', {})
                                              .get('value', {})
                                              .get('properties', {}))
                                       if a.page_id.replace('-', '') in blocks
                                       else "notion", body))
        print("\nwrote %s (%d chars of prose)" % (a.out, len(body)))
    fetch = [i for m, _t, i in pages if m == "FETCH"]
    if fetch:
        print("\nsub-page ids to fetch:")
        for i in fetch:
            print("   %s" % i)
    return 0


if __name__ == "__main__":
    sys.exit(main())