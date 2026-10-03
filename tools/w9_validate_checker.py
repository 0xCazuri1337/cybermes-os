"""Validate the checker used by w9_parent_audit, in BOTH directions, on the
exact normalisations that produced this tick's three misses.

Genuine  -> must be FOUND:  markdown code span, space-before-comma from an
                             inline code element, curly quote.
Tampered -> must be ABSENT:  a one-word alteration, a dropped clause, a
                             fabricated sentence.

Usage: python tools/w9_validate_checker.py
"""
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
from wks.verify_quotes import find_quote  # noqa: E402

CASES = [
    # (label, page_text, quote, expected_found)
    ("genuine: markdown code span",
     "the first request of the flow will always be a request to the "
     "`/authorization` endpoint containing a number of query parameters",
     "the first request of the flow will always be a request to the "
     "`/authorization` endpoint containing a number of query parameters", True),
    ("genuine: code span with space before comma",
     "If the server identifies the session based on this username , modifying "
     "its value might enable an attacker to impersonate other logged-in users.",
     "If the server identifies the session based on this `username`, modifying "
     "its value might enable an attacker to impersonate other logged-in users.", True),
    ("genuine: curly opening quote",
     "The \u2018success' response confirms that the server is operational and "
     "doesn't expose sensitive or detailed information directly through this endpoint.",
     "The 'success' response confirms that the server is operational and "
     "doesn't expose sensitive or detailed information directly through this endpoint.", True),
    ("tampered: one word altered",
     "The \u2018success' response confirms that the server is operational and "
     "doesn't expose sensitive or detailed information directly through this endpoint.",
     "The 'success' response confirms that the server is operational and "
     "doesn't expose any sensitive or detailed information directly through this endpoint.",
     False),
    ("tampered: clause dropped",
     "If the server identifies the session based on this username , modifying "
     "its value might enable an attacker to impersonate other logged-in users.",
     "If the server identifies the session based on this `username`, it lets an "
     "attacker impersonate other logged-in users.", False),
    ("tampered: fabricated sentence",
     "The \u2018success' response confirms that the server is operational.",
     "A 200 response here always proves the endpoint is vulnerable to anonymous "
     "write access.", False),
]


def main():
    bad = 0
    for label, page, quote, expected in CASES:
        got = bool(find_quote(page, quote))
        ok = got == expected
        if not ok:
            bad += 1
        print("[%s] %-40s expected_found=%s got=%s"
              % ("PASS" if ok else "FAIL", label, expected, got))
    print("\nchecker validated both directions: %d/%d" % (len(CASES) - bad, len(CASES)))
    return 1 if bad else 0


if __name__ == "__main__":
    raise SystemExit(main())