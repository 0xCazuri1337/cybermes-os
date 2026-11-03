"""Fetch any documentation source to disk, in parallel, with a native-safe path.

Why this exists instead of a bash `while read url; do curl -o f.md "$url"; done`:
that loop wrote ZERO files and returned code 000 for all 85 URLs, because the
relative `-o` target resolved somewhere the MSYS shell could not create. MSYS path
translation is DISABLED on this host, so native tools need `C:/...` paths and a
shell loop with a relative output target is the trap. Python + absolute paths +
threads removes it.

Sources handled by their index URL:
  gitbook   <host>/llms.txt          -> every page has a clean .md twin
  plain     an explicit URL list

Usage:
    python tools/src_fetch.py --gitbook https://kathan19.gitbook.io/howtohunt \
        --out cache/hth
    python tools/src_fetch.py --list C:/path/urls.txt --out cache/x
"""
import argparse
import concurrent.futures as cf
import hashlib
import json
import os
import re
import sys
import time
import urllib.error
import urllib.request

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
UA = "Mozilla/5.0 (compatible; wks-knowledge/materials/1.0)"
MIN_BYTES = 400          # below this it is nav chrome or an error stub


def get(url, tries=3, pause=1.2, timeout=45):
    last = "error"
    for i in range(tries):
        try:
            req = urllib.request.Request(url, headers={"User-Agent": UA})
            with urllib.request.urlopen(req, timeout=timeout) as r:
                body = r.read().decode("utf-8", "replace")
            return body, "ok"
        except urllib.error.HTTPError as e:
            last = "http_%d" % e.code
            if e.code in (404, 401, 403):
                break
        except Exception as e:                                # noqa: BLE001
            last = "err:%s" % type(e).__name__
        time.sleep(pause * (i + 1))
    return "", last


def gitbook_urls(index_url):
    body, status = get(index_url)
    if not body:
        raise SystemExit("index fetch failed: %s %s" % (index_url, status))
    urls = re.findall(r"\]\((https?://[^)\s]+?\.md)\)", body)
    # gitbook escapes underscores in its own index
    urls = [u.replace("\\_", "_") for u in urls]
    seen, out = set(), []
    for u in urls:
        if u not in seen:
            seen.add(u)
            out.append(u)
    return out, len(body)


def fetch_all(urls, outdir, workers=6):
    os.makedirs(outdir, exist_ok=True)
    index_path = os.path.join(outdir, "index.json")
    index = {}
    if os.path.exists(index_path):
        try:
            with open(index_path, encoding="utf-8") as fh:
                index = json.load(fh)
        except Exception:                                       # noqa: BLE001
            index = {}

    def one(u):
        h = hashlib.sha1(u.encode()).hexdigest()[:16]
        path = os.path.join(outdir, h + ".md")
        if os.path.exists(path):
            with open(path, encoding="utf-8") as fh:
                return u, len(fh.read()), "cached", h
        body, status = get(u)
        if body and len(body) >= MIN_BYTES:
            with open(path, "w", encoding="utf-8") as fh:
                fh.write(body)
            return u, len(body), status, h
        return u, len(body), (status or "too_small"), None

    results = []
    with cf.ThreadPoolExecutor(max_workers=workers) as ex:
        for u, n, status, h in ex.map(one, urls):
            results.append((u, n, status, h))
            index[u] = {"bytes": n, "status": status, "file": h}
    with open(index_path, "w", encoding="utf-8") as fh:
        json.dump(index, fh, indent=1)

    ok = [r for r in results if r[2] in ("ok", "cached")]
    thin = [r for r in results if r[2] not in ("ok", "cached")]
    print("=" * 72)
    print("FETCH  %d url(s) -> %s" % (len(urls), outdir))
    print("  ok/cached : %d" % len(ok))
    print("  failed    : %d" % len(thin))
    total = sum(r[1] for r in ok)
    print("  bytes     : %d" % total)
    for u, n, s, _h in thin[:15]:
        print("    %-12s %7d  %s" % (s, n, u[-72:]))
    return results


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--gitbook", help="gitbook space root; reads <root>/llms.txt")
    ap.add_argument("--list", help="file with one URL per line")
    ap.add_argument("--out", required=True)
    ap.add_argument("--workers", type=int, default=6)
    a = ap.parse_args()

    outdir = a.out if os.path.isabs(a.out) else os.path.join(ROOT, a.out)
    if a.gitbook:
        base = a.gitbook.rstrip("/")
        urls, n = gitbook_urls(base + "/llms.txt")
        print("index: %s -> %d urls (%d bytes of index)" % (base, len(urls), n))
    elif a.list:
        with open(a.list, encoding="utf-8") as fh:
            urls = [l.strip() for l in fh if l.strip() and not l.startswith("#")]
    else:
        ap.error("need --gitbook or --list")
        return 1
    fetch_all(urls, outdir, a.workers)
    return 0


if __name__ == "__main__":
    sys.exit(main())