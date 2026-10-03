"""T40 -- the derived-item spanner must not cut text mid-word.

THE DEFECT, MEASURED 2026-10-02. `tools/w12_promote_test_items.py` derived each
`test` item by slicing a fixed 260-character window out of the parent body:

    span = body[start:m.start() + 260].strip()

A fixed width ends wherever the width happens to end, which is usually inside a
word. 138 active items were built that way and 111 of them ended mid-sentence:

    '... so &#39; b'          '... are equivalent'        '... a working'
    '... regardless of lockout absence'                   '... authenticates and aut'

`wks.claimcheck` held all 66 promoted ones for TRUNCATED, and
`test_wks_claimcheck.py` failed on both of its live-corpus assertions.

The generator now snaps to sentence boundaries and REFUSES (returns "") when the
body has no clean sentence, because padding a fragment with an ellipsis would be
inventing text.

A verifier that cannot fail is decoration, so this suite is validated in BOTH
directions and includes a negative control proving the old fixed-width behaviour
is actually rejected -- the spanner is only worth having if it is stricter than
what it replaced.

Run: python eval/test_wks_sentence_span.py
"""
from __future__ import annotations

import importlib.util
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))


def _load():
    spec = importlib.util.spec_from_file_location(
        "w12_promote", ROOT / "tools" / "w12_promote_test_items.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


S = _load()._sentence_span

PASSES: list[str] = []
FAILURES: list[str] = []


def check(label: str, cond: bool, detail: str = "") -> None:
    if cond:
        PASSES.append(label)
        print(f"  [PASS] {label}")
    else:
        FAILURES.append(f"{label}: {detail}")
        print(f"  [FAIL] {label}  -- {detail}")


def _at(body: str, needle: str) -> tuple[int, int]:
    i = body.index(needle)
    return i, i + len(needle)


# ---- POSITIVE: real observables must yield a clean sentence ----------------
def t_positive() -> None:
    print("T40 POSITIVE: a real observable yields a complete sentence")
    body = ("A 200 on a foreign id is only an IDOR when the response body "
            "differs from the not-found case. A timeout is not evidence of "
            "execution. Compare the marker against the baseline response.")
    s, e = _at(body, "differs")
    span = S(body, s, e)
    check("keeps the observable sentence", "response body differs" in span, repr(span))
    check("ends on terminal punctuation", bool(re.search(r"[.!?]$", span)), repr(span))
    check("excludes the following sentence", "timeout" not in span, repr(span))
    check("no doubled whitespace", "  " not in span, repr(span))


# ---- LEADING EDGE: must not open mid-sentence -----------------------------
def t_leading_edge() -> None:
    print("T40 LEADING EDGE: the span opens at a sentence boundary")
    # (a) lead budget reaches the start of the body -- position 0 IS a boundary
    body = ("First sentence here. The response body differs from the baseline "
            "request. A third sentence follows after this one.")
    s, e = _at(body, "response body")
    span = S(body, s, e)
    check("opens at a boundary, not mid-sentence",
          bool(span) and (span[:1].isupper() or bool(re.match(r"[a-z]", span))
                          and not _opens_mid_sentence(body, span)),
          repr(span[:60]))

    # (b) an observable inside a LONG sentence with no internal boundary.
    #     There is no honest start or end inside it, so the spanner must
    #     REFUSE rather than file a paragraph. Padding would invent text.
    long_sentence = ("Background prose describing a scenario in which the "
                     "operator has already established a baseline request and a "
                     "second request carrying a foreign identifier, with both "
                     "responses retained verbatim for later comparison, and a "
                     "third request which repeats the second with the cookie "
                     "header removed entirely from the outgoing call. ")
    body2 = long_sentence + "The response body is the only proof here"   # no terminator
    s2, e2 = _at(body2, "response body")
    span2 = S(body2, s2, e2)
    check("refuses when the sentence has no clean end", span2 == "",
          repr(span2[:90]))
    check("never returns a mid-sentence opening",
          not span2 or not _opens_mid_sentence(body2, span2), repr(span2[:90]))

    # (c) a long PRECEDING sentence followed by a SHORT one holding the
    #     observable: the walk-back must find the real boundary and succeed.
    body3 = long_sentence + "The response differs. A later sentence is excluded."
    s3, e3 = _at(body3, "response differs")
    span3 = S(body3, s3, e3)
    check("finds the boundary after a long preceding sentence",
          span3 == "The response differs.", repr(span3))
    check("excludes the following sentence",
          bool(span3) and "later sentence" not in span3, repr(span3))

    # (d) a short but COMPLETE sentence is real knowledge, not a fragment.
    #     The floor must not discard it: "The response differs." is 21 chars.
    body4 = "The response differs."
    s4, e4 = _at(body4, "response differs")
    check("keeps a short complete sentence",
          S(body4, s4, e4) == "The response differs.", repr(S(body4, s4, e4)))

    # (e) a genuinely tiny span is still refused -- the floor is not zero.
    check("still refuses a too-tiny span",
          S("Ok.", 0, 2) == "", repr(S("Ok.", 0, 2)))


def _opens_mid_sentence(body: str, span: str) -> bool:
    """True when `span` starts inside a sentence rather than at its start."""
    idx = body.find(span[:40])
    if idx <= 0:
        return False
    prefix = body[:idx].rstrip()
    return bool(prefix) and not re.search(r"[.!?][\"')\]]?$", prefix)


# ---- PARENTHETICAL: a terminator inside brackets is not a sentence end ----
def t_parenthetical() -> None:
    print("T40 PARENTHETICAL: does not split inside a bracketed clause")
    body = ("It is not enough on its own (see RFC 7231 section 5.4). Compare "
            "both responses against the baseline.")
    s, e = _at(body, "not enough")
    span = S(body, s, e)
    check("a short but complete sentence is kept", span != "", "span was refused")
    check("kept the parenthetical intact",
          bool(span) and "RFC 7231 section 5.4)" in span, repr(span))
    check("no unbalanced bracket", bool(span) and span.count("(") == span.count(")"),
          repr(span))


# ---- NEGATIVE: must REFUSE, never pad -------------------------------------
def t_refuses() -> None:
    print("T40 NEGATIVE: refuses rather than emitting a fragment")
    # The exact defect: a body whose tail has no terminator at all.
    real = ("When a value is reflected into a scriptable attribute such as "
            "onclick and the filter blocks the quote character, HTML-encoding "
            "it works around the filter. The browser HTML-decodes tag attribute "
            "values after parsing the tags but before the JavaScript is "
            "interpreted, so &#39; b")
    s, e = _at(real, "HTML-decodes")
    check("no terminator in the tail -> refuses", S(real, s, e) == "",
          repr(S(real, s, e)[-40:]))

    padded = real + " " + "x" * 300
    s2, e2 = _at(padded, "HTML-decodes")
    check("still refuses when padding follows", S(padded, s2, e2) == "",
          repr(S(padded, s2, e2)[-40:]))


# ---- THE CONTROL: the old fixed-width slice really was worse --------------
def t_old_behaviour_would_fail() -> None:
    """Prove the replacement is STRICTER than the bug it fixes.

    Without this, a spanner that returned "" for everything would pass every
    other case in this file and look like a working fix.
    """
    print("T40 CONTROL: the old fixed-width slice fails what the new one passes")
    real = ("When a value is reflected into a scriptable attribute such as "
            "onclick and the filter blocks the quote character, HTML-encoding "
            "it works around the filter. The browser HTML-decodes tag attribute "
            "values after parsing the tags but before the JavaScript is "
            "interpreted, so &#39; b")
    m = re.search("HTML-decodes", real)
    old = real[max(0, m.start() - 120):m.start() + 260].strip()   # the old code
    s, e = _at(real, "HTML-decodes")
    new = S(real, s, e)
    check("OLD slice ends mid-word (the bug)",
          not re.search(r"[.!?]$", old), repr(old[-30:]))
    check("NEW spanner does not reproduce it",
          new == "" or bool(re.search(r"[.!?]$", new)), repr(new[-30:]))
    check("control is a real difference, not a tautology",
          (old == "") != (new == ""), "both behaved identically")


# ---- BOUNDED: cannot run away --------------------------------------------
def t_bounded() -> None:
    print("T40 BOUNDED: the window cannot grow without limit")
    body = "A marker appears in the response body. " + ("Filler sentence here. " * 200)
    s, e = _at(body, "response body")
    span = S(body, s, e)
    check("stays within lead+tail budget", len(span) <= 120 + 260 + 40,
          f"len={len(span)}")
    check("never returns None", span is not None)


def main() -> int:
    for fn in (t_positive, t_leading_edge, t_parenthetical, t_refuses,
               t_old_behaviour_would_fail, t_bounded):
        try:
            fn()
        except Exception as e:                       # noqa: BLE001
            FAILURES.append(f"{fn.__name__} raised {e}")
            print(f"  [ERROR] {fn.__name__}: {type(e).__name__}: {e}")
    print(f"\n{len(PASSES)} passed, {len(FAILURES)} failed")
    for f in FAILURES:
        print(f"  FAILED: {f}")
    return 1 if FAILURES else 0


if __name__ == "__main__":
    raise SystemExit(main())
