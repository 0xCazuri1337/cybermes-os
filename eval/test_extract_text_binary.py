#!/usr/bin/env python
"""T29: `extract_text` must not raise on a binary content type.

MEASURED 2026-10-03 (wave 11, `eol_software` seed probe):

    pipeline.fetch("https://nvlpubs.nist.gov/.../NIST.SP.800-40r4.pdf")
    -> UnboundLocalError: cannot access local variable 'text'

The decode guard assigned `text` ONLY on the non-binary branch, and the very
next line called `html_mod.unescape(text)`. So every pdf / zip / image / font
URL raised -- while `fetch()` is documented to never raise ("a dead source is
data, not an exception"). The probe scored two NORMATIVE sources (NIST SP
800-40, NCCoE patching) as unusable for a reason that had nothing to do with
them, and `wks.domains --check`-style audits that touch a pdf would die the
same way.

Asserted BOTH directions, because the neighbouring branch already had a bug of
this exact shape (T26: the decode guard skipped `application/x-txt`):
  * binary  -> returns "" and does NOT raise  (the fix)
  * html    -> tags still stripped            (must not pass by disabling all)
  * markdown-> literal tags PRESERVED         (T26's regression, still green)
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from wks.pipeline import extract_text  # noqa: E402

FAILURES: list[str] = []


def check(cond: bool, label: str) -> None:
    print(f"  [{'PASS' if cond else 'FAIL'}] {label}")
    if not cond:
        FAILURES.append(label)


def main() -> int:
    print("T29 extract_text on binary content types")

    # (1) The failure case: every binary prefix must return, not raise.
    for ct in ("application/pdf", "application/zip", "image/png", "font/woff2",
               "application/octet-stream", "application/gzip"):
        try:
            out = extract_text(b"%PDF-1.7\n<binary body>", ct)
            check(out == "", f"{ct}: returns '' and does not raise (got {out!r})")
        except Exception as exc:  # noqa: BLE001
            check(False, f"{ct}: raised {type(exc).__name__}: {exc}")

    # (2) The pass cases -- the fix must not have disabled extraction.
    html = extract_text(b"<html><body><p>Hello <b>world</b></p></body></html>",
                        "text/html; charset=utf-8")
    check("<b>" not in html and "Hello" in html,
          f"HTML is still tag-stripped (got {html!r})")

    md = extract_text(b"# Title\n\nUse `<script>alert(1)</script>` here.",
                      "text/markdown")
    check("<script>" in md,
          f"markdown literal tags are PRESERVED (got {md!r})")

    txt = extract_text(b"plain body line", "application/x-txt")
    check(txt.strip() == "plain body line",
          f"application/x-txt still decodes (got {txt!r})")

    ent = extract_text(b"It&#x27;s here &amp; there", "text/html")
    check("It's here & there" in ent,
          f"entities still decoded before stripping (got {ent!r})")

    print(f"\n{'ALL PASS' if not FAILURES else str(len(FAILURES)) + ' FAILED'}")
    for f in FAILURES:
        print(f"  - {f}")
    return 1 if FAILURES else 0


if __name__ == "__main__":
    raise SystemExit(main())
