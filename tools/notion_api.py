"""Fetch a PUBLIC Notion page's content + sub-pages via its public API.

MEASURED: the rendered HTML of these pages is a JavaScript shell -- 19,970 bytes
containing ZERO 32-hex block ids and ZERO notion.site links. So neither regex
extraction nor `web_extract` on the parent can enumerate sub-pages; `web_extract`
returned the sub-page TITLES as plain text because its renderer executes JS,
while raw HTTP cannot.

Notion serves public pages through its own loadPageChunk endpoint, which needs no
authentication for a published site. That returns the page record with its
children, so the sub-page list comes from the document tree rather than from
scraped links.
"""
import argparse
import json
import sys
import urllib.error
import urllib.request

UA = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                    "(KHTML, like Gecko) Chrome/120.0 Safari/537.36",
      "Accept": "*/*",
      "Content-Type": "application/json"}
SKIP_WORDS = ("mobile", "android", "ios", "wifi", "wireless", "bluetooth")


def _dashed(page_id):
    """Notion ids must be dashed 8-4-4-4-12. MEASURED: the same call with the
    bare 32-hex id returns HTTP 400, which looks exactly like 'not public'."""
    h = page_id.replace("-", "")
    return "%s-%s-%s-%s-%s" % (h[0:8], h[8:12], h[12:16], h[16:20], h[20:32])


def api(site, page_id):
    url = "https://www.notion.so/api/v3/loadCachedPageChunk"
    body = json.dumps({
        "pageId": _dashed(page_id),
        "limit": 200,
        "cursor": {"stack": []},
        "chunkNumber": 0,
        "verticalColumns": False,
    }).encode()
    req = urllib.request.Request(url, data=body, headers=dict(UA, **{}))
    req.add_header("Origin", "https://www.notion.so")
    req.add_header("Referer", "https://www.notion.so/")
    with urllib.request.urlopen(req, timeout=60) as r:
        return json.loads(r.read().decode("utf-8", "replace"))


def walk(blocks, out, depth=0):
    for b in blocks:
        t = b.get("type")
        v = b.get("value") or b.get(b.get("type", ""), {}) or {}
        title = v.get("title") or []
        text = "".join(t_.get("plain_text", "") for t_ in title)
        if b.get("id"):
            out.append({"depth": depth, "type": t, "id": b["id"],
                        "text": text})
        kids = (v.get("content") if isinstance(v, dict) else None) or \
            b.get("content") or []
        if kids and isinstance(kids, list):
            walk([k for k in kids if isinstance(k, dict)], out, depth + 1)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--site", required=True, help="e.g. tested-corleggy-562")
    ap.add_argument("--page-id", required=True)
    ap.add_argument("--out")
    a = ap.parse_args()

    try:
        data = api(a.site, a.page_id)
    except urllib.error.HTTPError as e:
        print("API refused: HTTP %s -- the page is probably not public"
              % e.code)
        return 1
    rec = (data.get("recordMap") or {}).get("block", {})
    blocks = [v for v in rec.values() if isinstance(v, dict)]
    print("blocks returned: %d" % len(blocks))
    out = []
    walk(blocks, out)
    print("blocks walked    : %d" % len(out))
    skip = {w.strip().lower() for w in SKIP_WORDS}

    child_pages = []
    for b in out:
        if b["type"] not in ("page", "collection_view_page", "link_to_page"):
            continue
        t = b["text"].strip()
        low = t.lower()
        mark = "SKIP" if any(w in low for w in skip) else "FETCH"
        child_pages.append((mark, t, b["id"]))
    fetch = [c for c in child_pages if c[0] == "FETCH"]
    skipped = [c for c in child_pages if c[0] == "SKIP"]
    print("\nchild pages: %d  (fetch %d, skipped by your exclusions %d)"
          % (len(child_pages), len(fetch), len(skipped)))
    for m, t, i in skipped:
        print("   SKIP  %s" % t)
    urls = ["https://%s.notion.site/%s" % (a.site, i) for _m, _t, i in fetch]
    if a.out:
        with open(a.out, "w", encoding="utf-8") as fh:
            fh.write("\n".join(urls))
        print("\nwrote %s (%d urls)" % (a.out, len(urls)))
    return 0


if __name__ == "__main__":
    sys.exit(main())