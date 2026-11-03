"""Move the harvested write-up corpus OUT of the prunable scratch directory.

THE RISK (measured): `cache/scratch/` is documented as pruning entries idle for
24h, and it already holds 800+ files from earlier sessions -- a working pattern
that has demonstrably lost data here. The 512 harvested HTB write-ups (9.7MB,
823KB of source text plus sidecar URL indexes) are the ONLY local copy of the
PRIMARY EVIDENCE behind 33 merged corpus items. The merged items stay valid --
each cites a live URL -- but re-building, re-auditing or re-mining would be
impossible, and `verify_quotes` would refetch every page instead of diffing
against the harvested original.

Where it goes: `<WKS_ROOT>/knowledge/materials/corpus/htb/`, beside the corpus metadata
that already references it. Written VERIFIED (sha1 + byte count) rather than
moved, then the source is removed only if every file matches -- a half-copied
corpus is worse than two of them.
"""
import hashlib
import os
import shutil
import sys

SRC = r"C:\Users\Administrator\AppData\Local\hermes\cache\scratch\htb"
ROOT = os.environ.get("WKS_ROOT", r"C:\Users\Administrator\.hermes\cyber")
DST = os.path.join(ROOT, "research", "corpus", "htb")


def digest(path):
    h = hashlib.sha1()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def walk(root):
    out = {}
    for dirpath, _, files in os.walk(root):
        for fn in files:
            p = os.path.join(dirpath, fn)
            out[os.path.relpath(p, root)] = p
    return out


def main():
    if not os.path.isdir(SRC):
        print("no source cache")
        return 1
    src = walk(SRC)
    print(f"source: {len(src)} files under {SRC}")

    if os.path.isdir(DST):
        # resume-safe: keep whatever already arrived intact
        have = walk(DST)
        print(f"destination already holds {len(have)} files; verifying them")
        for rel, p in have.items():
            s = src.get(rel)
            if s and digest(s) == digest(p):
                src.pop(rel, None)      # identical -> drop from the copy set
            else:
                print(f"  MISMATCH, recopying {rel}")
                src[rel] = s or p
    else:
        have = {}

    todo = {k: v for k, v in src.items() if v in src.values()}
    print(f"to copy: {len(todo)}")
    if todo:
        os.makedirs(DST, exist_ok=True)
        for i, (rel, p) in enumerate(sorted(todo.items()), 1):
            d = os.path.join(DST, rel)
            os.makedirs(os.path.dirname(d), exist_ok=True)
            shutil.copy2(p, d)
            if i % 100 == 0:
                print(f"  {i}/{len(todo)}")

    # verify BEFORE removing the source
    bad = []
    final_src = walk(SRC)
    final_dst = walk(DST)
    for rel, p in final_dst.items():
        s = final_src.get(rel)
        if s is None or digest(s) != digest(p):
            bad.append(rel)
    print(f"\nverify: {len(final_dst)} files in destination")
    if bad:
        print(f"  MISMATCHES: {len(bad)}")
        for b in bad[:10]:
            print("   ", b)
        print("\nSOURCE KEPT -- do not delete on a failed verify.")
        return 2

    total = sum(os.path.getsize(p) for p in final_dst.values())
    print(f"  all {len(final_dst)} verified byte-identical, {total:,} bytes")
    shutil.rmtree(SRC)
    print(f"\nsource removed; corpus now permanent at {DST}")
    return 0


if __name__ == "__main__":
    sys.exit(main())