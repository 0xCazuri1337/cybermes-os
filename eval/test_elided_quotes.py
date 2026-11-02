"""An ELIDED quote must be matched by its segments, in order.

THE DEFECT (measured, 2026-10-31)
  `wks.verify_quotes.find_quote` required the WHOLE quote string to appear in
  the page. A quote carrying an ellipsis — how an agent records "the relevant
  part of a long passage" — can never match, so every such citation was
  reported FABRICATED.

  MEASURED on the live corpus: 29 citations carried an ellipsis and every one
  of them was reported as fabricated evidence. That is the worst kind of false
  positive: it tells the operator their evidence is a lie when the evidence is
  a genuine excerpt of a page that says exactly that.

THE FIX
  `find_quote` splits an elided quote on the marker and requires each segment
  to appear on the page, IN ORDER, with the leading segment long enough to be
  distinctive.

WHAT THIS SUITE PINS
  Both directions, because a verifier that cries wolf gets switched off — and
  a verifier that accepts everything protects nothing:
   1. a genuine excerpt MATCHES;
   2. a genuine excerpt with a long tail MATCHES;
   3. a fabricated TAIL does not match;
   4. a fabricated HEAD does not match;
   5. segments out of order do not match;
   6. a too-short leading segment does not match (it would match by accident);
   7. a non-elided quote is unaffected — genuine matches, fabricated does not.

Run: python eval/test_elided_quotes.py
Exit: non-zero on any failure.
"""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from wks.verify_quotes import find_quote  # noqa: E402

FAILURES: list[str] = []

PAGE = (
    "The only safe location for placing variables in JavaScript is inside a "
    "quoted data value. All other contexts are unsafe and you should not "
    "place variable data in them. Encode all characters using the xHH format. "
    "Encoding libraries often have an EncodeForJavaScript or similar."
)

CASES = [
    ("a genuine excerpt matches",
     "The only safe location for placing variables in JavaScript is inside a "
     "quoted data value. ... Encoding libraries often have an "
     "EncodeForJavaScript or similar.",
     True),
    ("a genuine excerpt with a long tail matches",
     "The only safe location for placing variables in JavaScript is inside a "
     "quoted data value. All other contexts are unsafe and you should not "
     "place variable data in them. ... Encoding libraries often have",
     True),
    ("a fabricated TAIL does not match",
     "The only safe location for placing variables in JavaScript is inside a "
     "quoted data value. ... this sentence appears nowhere on the page at all.",
     False),
    ("a fabricated HEAD does not match",
     "This opening sentence is not on the page whatsoever. ... Encoding "
     "libraries often have an EncodeForJavaScript or similar.",
     False),
    ("segments out of order do not match",
     "Encoding libraries often have an EncodeForJavaScript or similar. ... "
     "The only safe location for placing variables in JavaScript is inside a "
     "quoted data value.",
     False),
    ("a too-short leading segment does not match",
     "The only safe ... Encoding libraries often have an EncodeForJavaScript.",
     False),
    ("a non-elided genuine quote still matches",
     "Encode all characters using the xHH format.",
     True),
    ("a non-elided fabricated quote still does not match",
     "Encode all characters using the zHH format.",
     False),
]


def main() -> int:
    print("=== elided quotes: matched by segments, in order ===")
    for name, quote, expect in CASES:
        got = find_quote(PAGE, quote)
        ok = got == expect
        print(f"  [{'PASS' if ok else 'FAIL'}] {name}"
              f" (expected {expect}, got {got})")
        if not ok:
            FAILURES.append(name)
    print()
    if FAILURES:
        print(f"FAIL — {len(FAILURES)} check(s) failed: {FAILURES}")
        return 1
    print("ALL ELIDED-QUOTE CHECKS PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
