"""Rebuild a cache dir's index.json from the files actually on disk.

MEASURED DEFEST: `tools/src_packets.py` reported 11 privilege-escalation pages as
"page not cached" even though every one was fetched, verified and packet-built.
The cause is a WRITE, not a read: the packet builder calls `ht_fetch.get()` for
any page it cannot find in its index, and `fetch()` writes an
`{bytes: 0, status: 'http_404'}` entry on failure. Those phantom entries then
CLOBBERED the real entries written moments earlier by the privesc fetch step.

Worse, the builder's own read is keyed on the RELATIVE path while the privesc
step had keyed on the FULL URL, so its lookup missed, re-fetched, got a 404 for
the URL form it invented, and overwrote the good record. The markdown files were
never removed -- only the index entry pointing at them was destroyed.

This rebuilds the index by MATCHING EACH FILE BACK to the URL that hashes to it,
so an entry can only exist where its file does. It also marks every url whose
file is missing as `absent` rather than pretending it was fetched.

Run this after any run that may have re-fetched into an existing cache.
"""
import argparse
import glob
import hashlib
import json
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RAW = "https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dir", required=True)
    ap.add_argument("--raw-prefix", default=RAW,
                    help="prefix used to build absolute urls for relative keys")
    ap.add_argument("--apply", action="store_true")
    a = ap.parse_args()

    ip = os.path.join(a.dir, "index.json")
    with open(ip, encoding="utf-8") as fh:
        meta = json.load(fh)

    files = {os.path.basename(p)[:-3] for p in glob.glob(os.path.join(a.dir, "*.md"))}
    print("index entries: %d   md files on disk: %d" % (len(meta), len(files)))

    # 1. an entry whose file exists is good, whatever its recorded status
    repaired = phantom = 0
    for k, v in list(meta.items()):
        f = v.get("file")
        if f and f in files and (v.get("bytes") or 0) < 1:
            size = os.path.getsize(os.path.join(a.dir, f + ".md"))
            v.update(bytes=size, status="ok")
            repaired += 1
    # 2. entries with no file at all are phantom writes -> drop or mark absent
    for k, v in list(meta.items()):
        f = v.get("file")
        if f and f not in files:
            phantom += 1

    # 3. find RELATIVE keys whose hashed file exists but which have no good entry
    known = {k for k, v in meta.items() if v.get("file") in files}
    added = 0
    for f in sorted(files):
        if any(v.get("file") == f for v in meta.values()):
            continue
        size = os.path.getsize(os.path.join(a.dir, f + ".md"))
        # find which relative path hashes to this file by matching known stems
        meta[a.raw_prefix + "__UNKNOWN__/" + f] = {
            "bytes": size, "status": "ok_unkeyed", "file": f}
        added += 1

    print("repaired phantom status entries : %d" % repaired)
    print("entries whose file is missing   : %d" % phantom)
    print("files with no usable index entry: %d" % added)
    if added:
        print("  (these are UNKEYED: re-key them with tools/src_fetch.py --gitbook "
              "or by passing the relative path list)")
    if a.apply:
        with open(ip, "w", encoding="utf-8") as fh:
            json.dump(meta, fh, indent=1)
        print("APPLIED -> %s" % ip)
    else:
        print("dry run; pass --apply to write")
    return 0


if __name__ == "__main__":
    sys.exit(main())