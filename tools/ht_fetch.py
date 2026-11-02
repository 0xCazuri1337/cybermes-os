"""Fetch HackTricks source pages and cache them for quote extraction.

Fetch route is raw.githubusercontent.com, and only that:

  * `hacktricks.wiki/en/<path>.html` renders the page but returns 650 bytes of
    "Page not found" shell for some paths (measured on sqli.html), and
  * `book.hacktricks.wiki/en/<path>/` returns a BYTE-IDENTICAL 48195-byte body
    for two unrelated paths (measured), i.e. a catch-all shell, and
  * `raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/<path>.md`
    is the file itself -- distinct per path, real prose, and the URL the gate
    will fetch.

Writes cache/ht_pages/<sha1>.md plus cache/ht_pages/index.json.
"""
import hashlib
import json
import os
import sys
import time
import urllib.error
import urllib.request

RAW = ("https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/"
       "master/src/%s")
UA = "Mozilla/5.0 (compatible; wks-research/1.0)"
OUT = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                   "cache", "ht_pages")

# A page that carries none of these is nav chrome or a stub, not evidence.
MIN_BYTES = 2500


def cache_path(rel):
    return os.path.join(OUT, hashlib.sha1(rel.encode()).hexdigest() + ".md")


def fetch(rel, tries=3, pause=1.5):
    """Return (text, status). status is 'cached' | 'ok' | 'http_<code>' | 'error'."""
    cp = cache_path(rel)
    if os.path.exists(cp):
        with open(cp, encoding="utf-8") as fh:
            return fh.read(), "cached"
    url = RAW % rel
    last = "error"
    for attempt in range(tries):
        try:
            req = urllib.request.Request(url, headers={"User-Agent": UA})
            with urllib.request.urlopen(req, timeout=45) as r:
                body = r.read().decode("utf-8", "replace")
            if len(body) < 200:
                last = "too_small(%d)" % len(body)
            else:
                os.makedirs(OUT, exist_ok=True)
                with open(cp, "w", encoding="utf-8") as fh:
                    fh.write(body)
                return body, "ok"
        except urllib.error.HTTPError as e:
            last = "http_%d" % e.code
            if e.code == 404:
                break          # a moved page will not appear on retry
        except Exception as e:                      # noqa: BLE001
            last = "error:%s" % type(e).__name__
        time.sleep(pause * (attempt + 1))
    return "", last


def load_index():
    p = os.path.join(OUT, "index.json")
    if os.path.exists(p):
        with open(p, encoding="utf-8") as fh:
            return json.load(fh)
    return {}


def save_index(idx):
    """Persist the index, but ONLY entries whose markdown file exists.

    An index entry is a POINTER. Persisting one whose target is absent turns a
    transient fetch failure into a durable lie that every later run reads as
    fact -- which is exactly what happened to the 21 privilege-escalation pages.
    """
    import glob
    have = {os.path.basename(p)[:-3]
            for p in glob.glob(os.path.join(OUT, "*.md"))}
    kept = {k: v for k, v in idx.items() if v.get("file") in have}
    dropped = len(idx) - len(kept)
    os.makedirs(OUT, exist_ok=True)
    with open(os.path.join(OUT, "index.json"), "w", encoding="utf-8") as fh:
        json.dump(kept, fh, indent=1)
    if dropped:
        print("save_index: dropped %d entr(ies) with no file on disk" % dropped)


def get(rel, idx=None):
    """Cached accessor used by the builder. Returns (text, status)."""
    cp = cache_path(rel)
    if os.path.exists(cp):
        with open(cp, encoding="utf-8") as fh:
            text = fh.read()
        if idx is not None and len(text) >= MIN_BYTES:
            idx[rel] = {"bytes": len(text), "status": "cached"}
        return text, "cached"
    text, status = fetch(rel)
    # MEASURED: a failed lookup used to write {bytes: 0, status: http_404} into
    # the caller's index, and ht_stage then saved that index -- overwriting the
    # real entry for a page that was already cached under a different key. The
    # markdown survived; the pointer to it did not. A negative result is a fact
    # about ONE ATTEMPT, not about the page, so it is not recorded.
    if idx is not None and len(text) >= MIN_BYTES:
        idx[rel] = {"bytes": len(text), "status": status}
    return text, status


if __name__ == "__main__":
    rels = sys.argv[1:]
    idx = load_index()
    for rel in rels:
        text, status = get(rel, idx)
        print("%-14s %7d  %s" % (status, len(text), rel))
        time.sleep(0.4)
    save_index(idx)