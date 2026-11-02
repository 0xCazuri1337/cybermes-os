"""Harvest a whole PUBLIC Notion site into markdown files, recursively.

Routes: for each page id, `loadCachedPageChunk` returns that page's blocks;
child pages are recursed into, so the tree is walked from the DOCUMENT, not from
scraped links (these pages ship a JS shell with zero links -- MEASURED 19,970
bytes, 0 block ids, 0 notion.site hrefs).

Mobile and wireless subtrees are SKIPPED, per the user's instruction. The skip
is applied to the TITLE at every level, so a "Mobile" child of a sub-page is
excluded the same way a top-level one is.

Writes one .md per page into the cache dir and an index.json mapping page id ->
file, which is the shape tools/src_fetch.py and tools/src_packets.py consume.
"""
import argparse
import json
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from notion_render import chunk, payload_of, plain  # noqa: E402

SKIP_WORDS = ("mobile", "android", "ios", "wifi", "wireless", "bluetooth")
MAX_PAGES = 400


def render(page_id, skip, outdir, index, depth=0, seen=None):
    seen = seen if seen is not None else set()
    if page_id in seen or len(index) >= MAX_PAGES:
        return 0
    seen.add(page_id)
    try:
        data = chunk(page_id)
    except Exception as e:                                   # noqa: BLE001
        print("   %s%s: fetch failed (%s)" % ("  " * depth,
                                              page_id[:8], type(e).__name__))
        return 0
    blocks = data.get("recordMap", {}).get("block", {})
    kids, prose = [], []
    for k, rec in blocks.items():
        p = payload_of(rec)
        t = p.get("type")
        title = plain(p.get("properties") or {})
        cid = p.get("id") or k
        if t in ("page", "collection_view_page", "link_to_page"):
            if any(w in title.lower() for w in skip):
                print("   %sSKIP %s" % ("  " * depth, title[:56]))
                continue
            kids.append((title, cid))
            continue
        txt = title
        if not txt and t in ("code", "quote", "bulleted_list_item",
                             "numbered_list_item", "paragraph", "to_do"):
            txt = plain(p.get("properties") or {}, "title")
        if txt:
            prose.append(txt)
    body = "\n\n".join(prose)
    if page_id not in index:
        fn = os.path.join(outdir, page_id.replace("-", "") + ".md")
        with open(fn, "w", encoding="utf-8") as fh:
            fh.write("# page %s\n\n%s\n" % (page_id, body))
        index[page_id] = {"file": os.path.basename(fn)[:-3],
                          "bytes": len(body), "status": "ok",
                          "children": len(kids)}
    print("   %s%s  %d prose block(s), %d child page(s)"
          % ("  " * depth, page_id[:8], len(prose), len(kids)))
    got = 1
    for title, cid in kids:
        got += render(cid, skip, outdir, index, depth + 1, seen)
        time.sleep(0.3)
    return got


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--site", required=True)
    ap.add_argument("--page-id", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--skip", default=",".join(SKIP_WORDS))
    a = ap.parse_args()
    skip = {w.strip().lower() for w in a.skip.split(",") if w.strip()}
    outdir = a.out if os.path.isabs(a.out) else os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))), a.out)
    os.makedirs(outdir, exist_ok=True)

    ip = os.path.join(outdir, "index.json")
    index = {}
    if os.path.exists(ip):
        with open(ip, encoding="utf-8") as fh:
            index = json.load(fh)
        print("resuming: %d page(s) already indexed" % len(index))
    n = render(a.page_id, skip, outdir, index)
    with open(os.path.join(outdir, "index.json"), "w", encoding="utf-8") as fh:
        json.dump(index, fh, indent=1)
    print("\npages harvested: %d  ->  %s" % (n, outdir))
    return 0


if __name__ == "__main__":
    sys.exit(main())