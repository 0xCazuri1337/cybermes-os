"""Make ht_stage.read_page resolve a page through the cache INDEX, not a hash.

MEASURED: ht_stage refused 11 valid privilege-escalation items with "page not
cached" even though every page was fetched and its quote verified. The cause is
a hash mismatch:

    pages fetched by the privesc step were keyed on the RELATIVE path
        sha1("windows-hardening/.../access-tokens.md")  -> file exists
    ht_stage asks for the FULL URL
        sha1("https://raw.githubusercontent.com/.../access-tokens.md") -> no file

`ht_fetch.cache_path` was written when the URL passed to it WAS the relative
path, so it silently produced a miss for the same page under a different key.
That is the "a verifier that reports a miss it never tested manufactures an
emergency" trap, one level deeper: it reports a miss for a page it HAS.

Resolution order, and it asserts rather than assumes:
  1. the cache dir's index.json, keyed by url -> file
  2. the cache dir's index.json, keyed by the url's path after /src/
  3. the basename
  4. ht_fetch's own path (the original behaviour)
"""
import io

P = "tools/ht_stage.py"
src = io.open(P, encoding="utf-8").read()

OLD = '''def read_page(rel, idx):
    """Read a source page from WHICHEVER cache holds it.

    MEASURED: ht_stage refused 38 valid HowToHunt items with "page not cached",
    because it called ht_fetch.get() -- the HackTricks-only reader -- on pages
    that live in cache/hth. A checker that reports a miss it never tested
    manufactures an emergency, so the reader is now cache-aware, exactly like
    tools/ht_verify2.local_page.
    """
    if "HackTricks-wiki" in rel:
        return ht_fetch.get(rel, idx)[0]
    from ht_verify2 import local_page
    return local_page(rel)'''

NEW = '''def _read_index(path, needle):
    """Look a page up in a cache dir's index.json by full url, then by suffix."""
    try:
        with open(path, encoding="utf-8") as fh:
            meta = json.load(fh)
    except Exception:                                        # noqa: BLE001
        return ""
    m = meta.get(needle)
    if not m and "/src/" in needle:
        m = meta.get(needle.split("/src/", 1)[1])
    if not m:
        # suffix match: the privesc pages were indexed by relative path while
        # the brief carries the absolute raw.githubusercontent URL
        for k, v in meta.items():
            if k.endswith(needle) or needle.endswith(k):
                m = v
                break
    if not m or not m.get("file"):
        return ""
    base = os.path.dirname(path)
    for cand in (os.path.join(base, m["file"] + ".md"),
                 os.path.join(base, m["file"])):
        if os.path.exists(cand):
            with open(cand, encoding="utf-8") as fh:
                return fh.read()
    return ""


def read_page(rel, idx):
    """Read a source page from WHICHEVER cache holds it, by ANY key it was
    stored under.

    Three measured misses, each a different key shape:
      * HackTricks pages live in cache/ht_pages, keyed by RELATIVE path;
        ht_stage asks with the FULL raw.githubusercontent URL -> hash mismatch
        -> "page not cached" on a page it has.
      * HowToHunt/Biscuit pages live in cache/hth and cache/biscuit, keyed by
        the gitbook URL.
      * The Notion pages are not in either.
    So resolution is: every cache index, then ht_fetch's own path. Reporting a
    miss is now only possible when no index holds it under any key.
    """
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    cache = os.path.join(root, "cache")
    if os.path.isdir(cache):
        for d in sorted(os.listdir(cache)):
            ip = os.path.join(cache, d, "index.json")
            if os.path.isdir(os.path.join(cache, d)) and os.path.exists(ip):
                txt = _read_index(ip, rel)
                if txt:
                    return txt
    base = os.path.basename(rel)
    if os.path.isdir(cache):
        for d in sorted(os.listdir(cache)):
            p = os.path.join(cache, d, base)
            if os.path.exists(p):
                with open(p, encoding="utf-8") as fh:
                    return fh.read()
    return ht_fetch.get(rel, idx)[0]'''

assert OLD in src, "read_page block not found verbatim"
src = src.replace(OLD, NEW, 1)
compile(src, P, "exec")
io.open(P, "w", encoding="utf-8").write(src)
print("patched: read_page resolves through the cache indexes; lint ok")