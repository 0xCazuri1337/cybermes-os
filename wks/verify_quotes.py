"""Quote verification (Evidence agent, brief §6.B).

A subagent that reports "I read the sources" is a self-report, not evidence. This
fetches each cited page and checks the recorded quote actually appears in it.
A quote that cannot be found is not a weak citation — it is a fabricated one, and
it rejects the item.

    python -m wks.verify_quotes [--class idor] [--fix]

Reported per item:
    OK            quote found verbatim (normalised whitespace)
    NOT_FOUND     page fetched, quote absent  -> fabricated or paraphrased
    FETCH_FAILED  page unreachable           -> unverifiable, do not trust yet
    NO_QUOTE      no quote recorded          -> a URL alone is not evidence
"""
from __future__ import annotations

import argparse
import json
import re
import sys
import unicodedata
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from wks import config, pipeline  # noqa: E402


def norm(s: str) -> str:
    s = unicodedata.normalize("NFKC", s or "")
    s = s.replace("\u2019", "'").replace("\u2018", "'")
    s = s.replace("\u201c", '"').replace("\u201d", '"')
    s = s.replace("\u2013", "-").replace("\u2014", "-").replace("\u00a0", " ")
    s = re.sub(r"\s+", " ", s).strip().lower()
    # Tag-stripping leaves the spaces that separated inline elements, so
    # `deleteUser`</code>, renders as "deleteuser ,". Closing up the space
    # before punctuation is what lets a genuinely verbatim quote match a
    # de-tagged page.
    s = re.sub(r"\s+([,.;:!?)\]}])", r"\1", s)
    s = re.sub(r"([(\[{])\s+", r"\1", s)
    return s.strip()


# Markup that exists in the SOURCE MARKDOWN but not in the rendered page.
# A researcher copying from a .md file keeps the emphasis and the table pipes;
# the HTML the verifier fetches has neither. Comparing raw text against raw
# text therefore reports genuine, correctly-quoted evidence as fabricated.
_MD = re.compile(r"\*\*|__|\*|`")
# Table cell/row separators, which browsers render as layout rather than text.
_TBL = re.compile(r"\s*\|\s*|\s*[-=]{2,}\s*")

# Single-underscore emphasis: `_e.g._` in an OWASP cheat sheet's markdown source
# renders as `e.g.` in the HTML the verifier fetches. `_MD` above cannot fold
# this, because a bare `_` is also a word character in identifiers — stripping
# it unconditionally would rewrite `__typename` and `snake_case` on BOTH sides
# and could let a quote match text it does not contain. Markdown itself refuses
# to emphasise intraword, so mirror that: the delimiters must sit OUTSIDE the
# word (not preceded by alnum/underscore, not followed by alnum/underscore).
# `__typename` fails on both counts and is correctly left alone.
_UL = re.compile(r"(?<![A-Za-z0-9_])_([^_\n]+)_(?![A-Za-z0-9_])")

# An elision marker: the three-dot form, the single-glyph form, or a bracketed
# one. An ellipsis in a QUOTE means "this passage continues"; it is not part of
# the page text.
_ELISION = re.compile(r"\.\.\.|…|\[\.\.\.\]|\[\.\.\.\.\.\]")

# The shortest a leading segment may be. Below this, the segment is a few
# common words that would match by accident, and an accidental match would
# turn a fabricated quote into a "verified" one — the exact inversion of the
# defect this code fixes.
_MIN_ELISION_SEGMENT = 40


def _find_elided(page: str, quote: str) -> bool:
    """Match an elided quote by its segments, in order.

    The quote is split on the elision marker. Each segment must appear on the
    page, and they must appear IN ORDER — so a page that contains the first
    segment and an unrelated second segment does not satisfy the citation.
    """
    segments = [s.strip() for s in _ELISION.split(quote or "")]
    segments = [s for s in segments if s]
    if len(segments) < 2:
        return False
    # The leading segment carries the identity of the excerpt, so it must be
    # distinctive. A trailing segment may be short (the tail of a passage is
    # often a closing clause).
    if len(segments[0]) < _MIN_ELISION_SEGMENT:
        return False

    page_vars = _variants(page)
    seg_vars = [_variants(s) for s in segments]

    for pv in page_vars:
        pos = 0
        ok = True
        for svars in seg_vars:
            found = False
            for sv in svars:
                i = pv.find(sv, pos)
                if i >= 0:
                    pos = i + len(sv)
                    found = True
                    break
            if not found:
                ok = False
                break
        if ok:
            return True
    return False


def _variants(s: str) -> list[str]:
    """Progressively looser normalisations of the same string.

    Ordered strictest-first so an exact match is always preferred over a
    loose one. Without this, quote verification rejects real evidence and the
    rejection is indistinguishable from fabrication — which is worse than not
    checking, because it teaches the operator that the check cries wolf.
    """
    base = norm(s)
    out = [base]
    no_md = norm(_MD.sub("", s))
    if no_md not in out:
        out.append(no_md)
    no_tbl = norm(_TBL.sub(" ", _MD.sub("", s)))
    if no_tbl not in out:
        out.append(no_tbl)
    no_ul = norm(_UL.sub(r"\1", _MD.sub("", s)))
    if no_ul not in out:
        out.append(no_ul)
    both = norm(_TBL.sub(" ", _UL.sub(r"\1", _MD.sub("", s))))
    if both not in out:
        out.append(both)
    return out


def _contained(hay: str, needle: str) -> bool:
    if not needle:
        return False
    if needle in hay:
        return True
    # Token-proximity fallback, for a quote interrupted by markup that the
    # variants above could not fold away (inline code spans mid-sentence).
    #
    # Requires EVERY word to match inside the window. An earlier version
    # allowed 90%, which accepted a quote with "GET" substituted for "POST"
    # and "administrators" for "managers" — i.e. it would have passed exactly
    # the fabrications this function exists to catch. A near-match is not
    # evidence; if the words are not all there, the quote is not there.
    words = needle.split()
    tokens = hay.split()
    n = len(words)
    if n < 4 or n > len(tokens):
        return False
    for i in range(len(tokens) - n + 1):
        if tokens[i:i + n] == words:
            return True
    return False


def find_quote(page: str, quote: str) -> bool:
    """True if the quote is genuinely present in the page.

    Compares across the normalisation variants of BOTH sides, so a quote copied
    out of rendered HTML matches the page and a quote copied out of source
    markdown (emphasis markers, table pipes) matches too.

    MEASURED 2026-10-31: an ELIDED quote — one that carries an ellipsis, which
    is how an agent records "the relevant part of a long passage" — could never
    match, because the matcher requires the whole string. The corpus held 29
    such citations and every one of them was reported FABRICATED. That is the
    worst kind of false positive: it tells the operator their evidence is a
    lie when the evidence is a genuine excerpt of a page that says exactly
    that.

    An elided quote is therefore matched on its SEGMENTS: each side of the
    ellipsis must appear, in order, on the page. The leading segment must be
    long enough to be distinctive (a handful of common words would match by
    accident), and the segments must be found in order rather than anywhere in
    the page, so "A ... B" cannot be satisfied by a page containing "A" and an
    unrelated "B".
    """
    if _ELISION.search(quote or ""):
        return _find_elided(page, quote)
    page_vars = _variants(page)
    for qv in _variants(quote):
        for pv in page_vars:
            if _contained(pv, qv):
                return True
    return False


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="wks.verify_quotes")
    ap.add_argument("--class", dest="class_id")
    ap.add_argument("--file", help="verify an incoming JSON file instead of the db")
    ap.add_argument("--json", action="store_true", help="machine-readable output")
    ap.add_argument("--record", action="store_true",
                    help="persist access_state/http_status/content_hash for every "
                         "cited source. Off by default so a re-audit cannot "
                         "silently rewrite provenance.")
    args = ap.parse_args(argv)

    work: list[tuple[str, list]] = []
    if args.file:
        raw = Path(args.file).read_text(encoding="utf-8")
        # Same marker as wks.ingest: strip a trailing `// COMPLETE <n>` line.
        raw = re.sub(r"\n?//\s*COMPLETE[^\n]*\s*$", "", raw).strip()
        data = json.loads(raw)
        work = [(it["item_key"], it.get("sources", [])) for it in
                (data["items"] if isinstance(data, dict) else data)]
    else:
        from wks import store
        con = store.open_db(create=bool(args.record))
        # `WHERE 1=1` is a placeholder so the optional class filter can be
        # appended; without it the params list binds to a query that takes none.
        # `status='active'` matters: a superseded row is retained for audit and
        # will still fail its quote check forever, so counting it reports dead
        # knowledge as a live failure. MEASURED: after superseding 5 ldap_enum
        # items, verify_quotes still showed 3 of them as FABRICATED. Report
        # them in a separate count instead of silently passing or falsely
        # failing the active corpus.
        q = ("SELECT i.item_key, i.id FROM item i "
             "WHERE i.status='active'")
        p: list = []
        if args.class_id:
            q += " AND i.class_id=?"
            p.append(args.class_id)
        for row in con.execute(q, p).fetchall():
            ev = store.item_evidence(con, int(row["id"]))
            work.append((row["item_key"], [
                {"url": e["url"], "quote": e["quote"], "host": e["host"]}
                for e in ev]))
        if not args.record:
            con.close()

    cache: dict[tuple, dict] = {}
    results: list[dict] = []
    record = bool(args.record)
    if not args.file:
        from wks import store as _store
        con = _store.open_db(create=record)
    else:
        con = None
    for item_key, sources in work:
        verdicts = []
        for s in sources:
            url = s.get("url", "")
            quote = s.get("quote")
            host = (s.get("host") or "").replace("www.", "")
            if not quote:
                verdicts.append({"url": url, "host": host, "status": "NO_QUOTE"})
                continue
            # The cache key MUST include the quote. Resolution on the 404 path
            # is quote-specific — a successor is only accepted when it contains
            # this span — so a page resolved for one item's quote cannot be
            # served as the answer for a different item citing the same URL.
            key = (url, quote)
            if key not in cache:
                cache[key] = pipeline.fetch(url, limit=1_500_000, quote=quote)
            page = cache[key]
            state = page.get("access_state", "UNVERIFIED")
            if state != "ACTIVE":
                # Not ACTIVE means the page did not deliver verifiable prose.
                # `rate_limited` is separated out: a throttled host is a
                # RETRYABLE condition, not a bad citation, and conflating the
                # two is how a throttling host looks like fabrication.
                verdicts.append({
                    "url": url, "host": host, "status": "FETCH_FAILED",
                    "access_state": state,
                    "retryable": bool(page.get("rate_limited")),
                    "attempts": page.get("attempts"),
                    "waited_seconds": page.get("waited_seconds"),
                    "detail": page.get("error") or page.get("status"),
                })
            elif find_quote(page["text"], quote):
                # A moved page verifies, but the cited URL and the URL that
                # actually answered are different. Report that, so provenance
                # never implies the original citation was live.
                verdicts.append({
                    "url": url, "host": host, "status": "OK",
                    "access_state": state,
                    "http_status": page.get("status"),
                    "content_hash": page.get("content_hash"),
                    **({"moved_from": page["moved_from"],
                        "verified_at": page["mirror"]}
                       if page.get("moved_from") else {}),
                })
            else:
                verdicts.append({"url": url, "host": host, "status": "NOT_FOUND",
                                 "access_state": state,
                                 "http_status": page.get("status"),
                                 "content_hash": page.get("content_hash"),
                                 "quote": quote})
        statuses = [v["status"] for v in verdicts]
        if any(s == "NOT_FOUND" for s in statuses):
            overall = "FABRICATED"
        elif "FETCH_FAILED" in statuses:
            overall = "UNVERIFIED"
        elif "NO_QUOTE" in statuses:
            overall = "UNQUOTED"
        else:
            overall = "VERIFIED"
        retryable = any(v.get("retryable") for v in verdicts)
        moved = any(v.get("moved_from") for v in verdicts)
        results.append({"item_key": item_key, "overall": overall,
                        # `retryable` is an honest signal that this item's
                        # verdict is a function of a throttling host, not of the
                        # citation. An audit that reports an unverifiable item
                        # without this will re-research it forever.
                        "retryable": retryable,
                        "verified_via_moved_page": moved,
                        "hosts": sorted({v["host"] for v in verdicts}),
                        "sources": verdicts})

        if record:
            for v in verdicts:
                state = v.get("access_state")
                if not state:
                    continue
                # A moved page is genuinely ACTIVE at the MIRROR; record the
                # state against the cited URL too, with the detail making the
                # indirection explicit rather than silent.
                store.record_access(
                    con, v["url"], access_state=state,
                    http_status=v.get("http_status"),
                    content_hash=v.get("content_hash"),
                    detail=(f"verify_quotes: {v['status']}"
                            + (f" (verified at {v['verified_at']})"
                               if v.get("verified_at") else "")))
    if record:
        con.commit()

    if args.json:
        print(json.dumps(results, indent=2, default=str))
        return 0

    from collections import Counter
    counts = Counter(r["overall"] for r in results)
    for r in results:
        if r["overall"] == "VERIFIED":
            continue
        print(f"[{r['overall']}] {r['item_key']}  hosts={r['hosts']}")
        for v in r["sources"]:
            if v["status"] != "OK":
                print(f"    {v['status']:13} {v['url']}")
                if v.get("quote"):
                    print(f"                   quote: {v['quote'][:110]}")
    retryable = sum(1 for r in results if r.get("retryable"))
    moved = sum(1 for r in results if r.get("verified_via_moved_page"))
    if retryable or moved:
        print(f"retryable (rate-limited host, NOT a bad citation): {retryable}")
        print(f"verified via a moved page (cited URL is dead, quote is live "
              f"elsewhere): {moved}")
    print("\n" + "  ".join(f"{k}={v}" for k, v in sorted(counts.items())))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
