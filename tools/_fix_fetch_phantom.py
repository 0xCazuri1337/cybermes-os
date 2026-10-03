"""Stop ht_fetch from persisting phantom entries for pages it never got.

MEASURED DEFEST, and it is a WRITE not a read. The chain:

  1. The privesc fetch step cached 21 pages and recorded each in
     cache/ht_pages/index.json as {file: <sha1 of the RELATIVE path>, ok}.
  2. `ht_stage.read_page` did not find a page (its lookup keyed the relative path
     while the brief carried the absolute raw.githubusercontent URL), and fell
     through to `ht_fetch.get(url, idx)`.
  3. `ht_fetch.get` -> `fetch()` found no cache file under sha1(FULL URL), tried
     the network with the doubled prefix, got 404, and RETURNED ("", "http_404")
     -- and `get()` recorded that status into the index dict it was handed.
  4. `ht_stage.main` then called `ht_fetch.save_index(idx)`, overwriting the real
     entries with {bytes: 0, status: http_404}.

So a failed lookup DESTROYED the record of a page that was already on disk, and
every later run read the destruction as truth. Two fixes, both here:

  * `fetch()` on failure records NOTHING. A negative result is not a fact about
    the page; it is a fact about one attempt.
  * `get()` returns the status without mutating the caller's index, and
    `save_index` refuses to persist an entry whose file does not exist.

The markdown was never deleted. Only the pointer was destroyed.
"""
import io

P = "tools/ht_fetch.py"
src = io.open(P, encoding="utf-8").read()

# 1. get(): never record a failure
old_get = '''    cp = cache_path(rel)
    if os.path.exists(cp):
        with open(cp, encoding="utf-8") as fh:
            text = fh.read()
        if idx is not None:
            idx[rel] = {"bytes": len(text), "status": "cached"}
        return text, "cached"
    text, status = fetch(rel)
    if idx is not None:
        idx[rel] = {"bytes": len(text), "status": status}
    return text, status'''
new_get = '''    cp = cache_path(rel)
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
    return text, status'''
assert old_get in src, "get() body not found verbatim"
src = src.replace(old_get, new_get, 1)

# 2. save_index(): never persist an entry whose file is missing
old_save = '''def save_index(idx):
    os.makedirs(OUT, exist_ok=True)
    with open(os.path.join(OUT, "index.json"), "w", encoding="utf-8") as fh:
        json.dump(idx, fh, indent=1)'''
new_save = '''def save_index(idx):
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
        print("save_index: dropped %d entr(ies) with no file on disk" % dropped)'''
assert old_save in src, "save_index() body not found verbatim"
src = src.replace(old_save, new_save, 1)

compile(src, P, "exec")
io.open(P, "w", encoding="utf-8").write(src)
print("patched ht_fetch: no phantom writes, index entries must exist; lint ok")