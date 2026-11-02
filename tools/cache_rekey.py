"""Re-key every unindexed markdown in a cache dir to a REAL url, by hashing.

MEASURED: after the phantom-entry fix, cache/ht_pages holds 177 files but only 67
usable index entries, because pages fetched by the privesc step were cached under
sha1(RELATIVE path) while the index keys were the absolute raw.githubusercontent
URLs -- and the index entries for them were then destroyed by the bug just fixed.
110 files are real, verified content with no pointer at all.

The mapping is exact and re-derivable: for a file whose sha1 is H, the relative
path R is the unique string with sha1(R) == H. So the recovery is to walk the
HackTricks SUMMARY (the authoritative list of every page path), hash each one,
and rebuild the index from the match. No guessing, no fetching.
"""
import argparse
import glob
import hashlib
import json
import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RAW = ("https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/"
       "master/src/%s")


def parse_summary(path):
    rels = []
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            m = re.match(r"^\s*[-*]\s+\[.+?\]\((.+?\.md)\)\s*$", line)
            if m:
                rels.append(m.group(1))
    return rels


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dir", required=True)
    ap.add_argument("--summary", required=True)
    ap.add_argument("--url-template", default=RAW)
    a = ap.parse_args()

    files = {os.path.basename(p)[:-3]
             for p in glob.glob(os.path.join(a.dir, "*.md"))}
    ip = os.path.join(a.dir, "index.json")
    with open(ip, encoding="utf-8") as fh:
        meta = json.load(fh)

    rels = parse_summary(a.summary)
    print("summary pages: %d   files on disk: %d   index entries: %d"
          % (len(rels), len(files), len(meta)))

    added = 0
    for rel in rels:
        h = hashlib.sha1(rel.encode()).hexdigest()
        if h not in files:
            continue
        url = a.url_template % rel
        if url in meta and meta[url].get("file") == h:
            continue
        meta[url] = {"bytes": os.path.getsize(os.path.join(a.dir, h + ".md")),
                     "status": "ok", "file": h}
        added += 1

    # drop every entry whose file is gone, and every record of a failure
    kept = {k: v for k, v in meta.items()
            if v.get("file") in files and (v.get("bytes") or 0) > 0}
    dropped = len(meta) - len(kept)

    print("re-keyed      : %d" % added)
    print("dropped (no file / zero bytes): %d" % dropped)
    print("usable entries after repair: %d for %d files"
          % (len(kept), len(files)))
    missing = files - {v["file"] for v in kept.values()}
    if missing:
        print("files still unkeyed: %d (their path is not in SUMMARY.md)" % len(missing))

    with open(ip, "w", encoding="utf-8") as fh:
        json.dump(kept, fh, indent=1)
    print("wrote %s" % ip)


if __name__ == "__main__":
    sys.exit(main())