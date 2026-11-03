"""Extract the sub-page URLs of a PUBLIC Notion page.

MEASURED: `web_extract` on a Notion parent page returns the sub-page TITLES as
plain text but drops the links, so there is nothing to fetch next. The rendered
HTML does carry them, in the `href` of every page card, and the URL shape is
`<site>/<Slugified Title>-<32 hex id>`.

The MCP `notion_fetch` tool cannot be used for these pages at all: every one
returns `object_not_found` for integration `1f8d872b-…`, which is not granted
access to those workspaces. The pages are PUBLIC, so plain HTTP works.

Filters out the ones the user excluded and the non-page links (images, external
refs), and prints the URLs so they can go straight into `tools/src_fetch.py`.
"""
import argparse
import re
import sys
import urllib.request

UA = {"User-Agent": "Mozilla/5.0 (compatible; wks-knowledge/materials/1.0)"}
# Notion page hrefs end in a 32-hex-char block id.
PAGE_RE = re.compile(r'href="(https://([a-z0-9-]+)\.notion\.site/[^"?#]*?-([0-9a-f]{32}))[^"]*"')
SKIP_WORDS = ("mobile", "android", "ios", "wifi", "wireless", "bluetooth")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--url", required=True)
    ap.add_argument("--skip", default=",".join(SKIP_WORDS),
                    help="comma-separated substrings to exclude")
    ap.add_argument("--out")
    a = ap.parse_args()
    skip = {w.strip().lower() for w in a.skip.split(",") if w.strip()}

    req = urllib.request.Request(a.url, headers=UA)
    html = urllib.request.urlopen(req, timeout=60).read().decode("utf-8", "replace")
    print("fetched %d bytes of HTML" % len(html))

    seen, pages, skipped = set(), [], []
    for m in PAGE_RE.finditer(html):
        url, site, _blk = m.group(1), m.group(2), m.group(3)
        if url in seen:
            continue
        seen.add(url)
        slug = url.rsplit("/", 1)[-1]
        title = re.sub(r"-[0-9a-f]{32}$", "", slug).replace("-", " ").strip()
        low = title.lower()
        if any(w in low for w in skip):
            skipped.append((title, url))
            continue
        pages.append((title, url))

    print("\nsub-pages found: %d   skipped by your exclusions: %d"
          % (len(pages), len(skipped)))
    if skipped:
        print("\nSKIPPED (mobile / wireless, as you asked):")
        for t, u in skipped:
            print("   %-46s %s" % (t[:46], u))
    print("\nPAGES TO FETCH:")
    for t, u in sorted(pages):
        print("   %-46s %s" % (t[:46], u))
    if a.out:
        with open(a.out, "w", encoding="utf-8") as fh:
            fh.write("\n".join(u for _t, u in pages))
        print("\nwrote %s" % a.out)
    return 0


if __name__ == "__main__":
    sys.exit(main())