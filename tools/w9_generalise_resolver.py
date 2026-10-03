"""Generalise wks.resolver beyond WSTG.

MEASURED: `resolver.resolve()` only builds candidates for
`owasp.org/www-project-web-security-testing-guide`. For every other publisher it
returns `_candidates() == []` and therefore `resolved=None` — so the db-side
sweeper reported a genuinely-moved projectdiscovery.io page as UNRESOLVED and
would have left a promoted item citing a 404. An empty candidate list is
indistinguishable from "no successor exists", which is the exact confusion the
resolver exists to prevent.

The fix is a generic SAME-HOST path-trim ladder: drop the last path segment, then
trailing date/id fragments, and re-test. Safety is unchanged — `resolve()` still
accepts a candidate only when `find_quote` confirms the quote is on it, so a
wrong guess costs a fetch and can never launder a citation.

Also adds a non-WSTG assertion to the T15/T17 test family.
"""
import io

P = r"C:/Users/Administrator/.hermes/cyber/wks/resolver.py"
src = io.open(P, encoding="utf-8").read()

HELPER = '''
# Trailing fragments that publishers append to a slug and later drop. Trimming
# these off the last path segment is the first guess for a renamed post.
_TRIM_TAIL = re.compile(
    r"[-_](cve[-_]?\\d{4}[-_]?\\d+|\\d{4}[-_]?\\d{2}|\\d{4}|ghsa[-_]?[a-z0-9]+|"
    r"part[-_]?\\d+|p\\d+)$", re.I)


def _generic_candidates(url: str, limit: int = 8) -> list[str]:
    """Same-host successors for a publisher the resolver has no table for.

    A moved page on an unmodelled host currently yields NO candidates, which
    `resolve()` reports identically to "no successor exists" — so a real move is
    indistinguishable from dead knowledge. This walks the page back up its own
    path: drop the last segment, then drop a trailing date/id fragment, then drop
    the segment before that.

    Every candidate is still subject to the quote test in `resolve()`.
    """
    p = urllib.parse.urlparse(url)
    if not p.netloc:
        return []
    segs = [s for s in p.path.split("/") if s]
    out: list[str] = []
    # variant 1: the last segment with a trailing date/id fragment removed
    if segs:
        stem = _TRIM_TAIL.sub("", segs[-1])
        if stem and stem != segs[-1]:
            out.append(urllib.parse.urlunparse(
                p._replace(path="/".join([""] + segs[:-1] + [stem]))))
    # variants 2..n: successively shallower paths
    for cut in range(1, min(len(segs), 4) + 1):
        trimmed = segs[:len(segs) - cut]
        if not trimmed:
            break
        out.append(urllib.parse.urlunparse(
            p._replace(path="/".join([""] + trimmed))))
        # a deeper cut may also expose a trailing fragment worth trimming
        if trimmed:
            st = _TRIM_TAIL.sub("", trimmed[-1])
            if st and st != trimmed[-1]:
                out.append(urllib.parse.urlunparse(
                    p._replace(path="/".join([""] + trimmed[:-1] + [st]))))
    seen, uniq = set(), []
    for c in out:
        if c not in seen and c != url:
            seen.add(c)
            uniq.append(c)
    return uniq[:limit]

'''

# 1. insert the helper just above resolve()
anchor = "def resolve(url: str, quote: str | None = None) -> dict:"
if "_generic_candidates" not in src:
    if anchor not in src:
        raise SystemExit("resolve() anchor not found - refusing to guess")
    src = src.replace(anchor, HELPER.lstrip("\n") + "\n" + anchor, 1)

# 2. use it in resolve(): WSTG candidates first, then the generic ladder
old_tail = """    tried = []
    for cand in _candidates(url):"""
new_tail = """    tried = []
    # WSTG candidates first (they encode the section/chapter renames that a
    # generic path trim cannot infer), then the same-host ladder for every other
    # publisher. `_candidates()` is empty for unmodelled hosts, and an empty list
    # used to be indistinguishable from "no successor exists".
    for cand in _candidates(url) + _generic_candidates(url):"""
if old_tail in src:
    src = src.replace(old_tail, new_tail, 1)
elif "_generic_candidates(url)" in src:
    print("resolve() already wired to the generic ladder")
else:
    raise SystemExit("resolve() loop not found - refusing to guess")

io.open(P, "w", encoding="utf-8").write(src)
print("patched", P)