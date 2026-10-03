"""Span miner: extract VERBATIM substrings from cached page text.

The only quotes that may enter an item come from `mine()` here, and `mine()`
can only return literal slices of the text `wks.pipeline.fetch` produced for
that URL. There is no LLM in this file and no paraphrase step, so a returned
span is by construction present on the page the gate will re-fetch.

`mine(url, pattern)` finds sentence-ish windows around each regex match and
returns them exactly as they appear in the cached text (leading/trailing
whitespace trimmed, interior untouched).
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from ncache import get  # noqa: E402

# A sentence boundary: terminator, then whitespace, then something that starts
# a sentence. Deliberately simple — an over-clever splitter produces spans that
# are substrings of nothing a reader would call a quote.
_SENT = re.compile(r"(?<=[.!?])\s+(?=[A-Z(\[\"'\d])")


def _windows(text: str, pattern: str, *, min_chars: int, max_chars: int,
             limit: int) -> list[str]:
    out: list[str] = []
    seen: set[str] = set()
    for m in re.finditer(pattern, text):
        # Expand to the enclosing sentence window.
        left = max((s.end() for s in _SENT.finditer(text, 0, m.start())), default=0)
        right = text.find(". ", m.end())
        if right == -1:
            right = min(len(text), m.end() + max_chars)
        else:
            right += 1
        span = text[left:right].strip()
        # Trim leading page furniture. A quote that opens with a nav fragment
        # ("Home Techniques Enterprise Network Service Discovery ...") is still
        # verbatim and the gate accepts it, but it is not evidence a human can
        # read as a claim. Cut back to the last sentence terminator inside the
        # window rather than dropping the span.
        for cut in (". ", "… "):
            i = span.rfind(cut, 0, len(span) - max_chars // 2)
            if i > 0:
                trimmed = span[i + len(cut):].strip()
                if len(trimmed) >= min_chars:
                    span = trimmed
                break
        if not (min_chars <= len(span) <= max_chars):
            continue
        if span in seen:
            continue
        seen.add(span)
        out.append(span)
        if len(out) >= limit:
            break
    return out


# Microsoft Learn serves a long inline-JSON / theme-toggle preamble before the
# article body. Without an anchor, sentence windows in that preamble are one
# enormous "sentence" and every probe returns nav boilerplate instead of prose.
# The body begins at this marker on every Learn Conceptual/Landing page.
LEARN_BODY_ANCHOR = "In this article"


def prose(text: str, after: str | None = None) -> str:
    """Return the article body: everything after `after`, else the whole text."""
    if after:
        i = text.find(after)
        if i != -1:
            return text[i:]
    return text


def mine(url: str, pattern: str, *, min_chars: int = 90, max_chars: int = 420,
         limit: int = 6, refresh: bool = False, after: str | None = None) -> list[str]:
    page = get(url, refresh=refresh)
    if not page["ok"] or not page["text"]:
        return []
    if after is None and "learn.microsoft.com" in url:
        after = LEARN_BODY_ANCHOR
    body = prose(page["text"], after)
    return _windows(body, pattern, min_chars=min_chars,
                    max_chars=max_chars, limit=limit)


def text_of(url: str, refresh: bool = False) -> str:
    page = get(url, refresh=refresh)
    return page["text"] if page["ok"] else ""


def contains(url: str, span: str, refresh: bool = False) -> bool:
    """Exact substring test against the cached fetch. Used as a pre-flight."""
    return span in text_of(url, refresh=refresh)


if __name__ == "__main__":
    url = sys.argv[1]
    pat = sys.argv[2] if len(sys.argv) > 2 else r"."
    for s in mine(url, pat, limit=12):
        print("-", s)
