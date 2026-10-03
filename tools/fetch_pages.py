#!/usr/bin/env python
"""Fetch + cache the client-side XSS source pages, and print the CONTENT region
of each (past the site navigation) so quote spans can be chosen from real text.

Caches to research/tmp/xss/<slug>.txt so later runs need no network at all.
Every quote written into a research file is sliced from this cached text and
validated with wks.verify_quotes.find_quote — the same matcher the gate uses.

    python tools/fetch_pages.py            # fetch/cache + print content regions
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from wks import pipeline  # noqa: E402

CACHE = ROOT / "research" / "tmp" / "xss"

PAGES = {
 "dom_ps":    "https://portswigger.net/web-security/cross-site-scripting/dom-based",
 "dom2_ps":   "https://portswigger.net/web-security/dom-based",
 "dangling":  "https://portswigger.net/web-security/cross-site-scripting/dangling-markup",
 "csti":      "https://portswigger.net/web-security/cross-site-scripting/contexts/client-side-template-injection",
 "csp":       "https://portswigger.net/web-security/cross-site-scripting/content-security-policy",
 "proto_ps":  "https://portswigger.net/web-security/prototype-pollution",
 "dom_ow":    "https://cheatsheetseries.owasp.org/cheatsheets/DOM_based_XSS_Prevention_Cheat_Sheet.html",
 "clob_ow":   "https://cheatsheetseries.owasp.org/cheatsheets/DOM_Clobbering_Prevention_Cheat_Sheet.html",
 "proto_ow":  "https://cheatsheetseries.owasp.org/cheatsheets/Prototype_Pollution_Prevention_Cheat_Sheet.html",
 "html5_ow":  "https://cheatsheetseries.owasp.org/cheatsheets/HTML5_Security_Cheat_Sheet.html",
 "mdn_pm":    "https://developer.mozilla.org/en-US/docs/Web/API/Window/postMessage",
 "cwe79":     "https://cwe.mitre.org/data/definitions/79.html",
 "cwe1321":   "https://cwe.mitre.org/data/definitions/1321.html",
}

# PortSwigger and MDN both front-load a large nav/boilerplate block; the prose
# starts at these anchors. Cheatsheets start at their own H1.
#
# PortSwigger repeats its H1 in <title> before the nav, so the FIRST match is
# the wrong one. Each anchor therefore carries the SECOND occurrence index: the
# real article body follows the nav. Anchors of 0 mean "use the only match".
START = {
 "dom_ps":   ("Web security academy Cross-site scripting", 0),
 "dom2_ps":  ("Web security academy DOM-based XSS", 0),
 "dangling":  ("Dangling markup injection", 1),
 "csti":      ("Client-side template injection", 1),
 "csp":      ("Content security policy (CSP)", 1),
 "proto_ps": ("Prototype pollution is a type", 1),
 "dom_ow":   ("DOM based XSS Prevention", 1),
 "clob_ow":  ("DOM Clobbering Prevention", 1),
 "proto_ow": ("Prototype Pollution Prevention", 1),
 "html5_ow": ("HTML5 Security Cheat Sheet", 1),
 "mdn_pm":   ("postMessage() method", 1),
 "cwe79":    ("CWE-79", 0),
 "cwe1321":  ("CWE-1321", 0),
}

MIN_CHARS = 2000

# Boilerplate that survives de-tagging and must be stripped before reading.
_NOISE = [
    "Recent topics View all topics", "Web Security Academy Blog Research",
    "Related Articles", "Table of contents", "References",
    "My account Products Solutions Research Academy Support Company",
]


def _nth(text: str, needle: str, n: int) -> int:
    i = -1
    for _ in range(n + 1):
        i = text.find(needle, i + 1)
        if i < 0:
            return -1
    return i


def content_region(text: str, key: str) -> str:
    spec = START.get(key)
    i = _nth(text, spec[0], spec[1]) if spec else -1
    body = text[i:] if i >= 0 else text
    # Drop the trailing footer/script blob.
    for stop in _NOISE:
        j = body.find(stop)
        if j > 2000:
            body = body[:j]
    return " ".join(body.split())


def main() -> int:
    CACHE.mkdir(parents=True, exist_ok=True)
    only = sys.argv[1:] or list(PAGES)
    for key in only:
        url = PAGES[key]
        cached = CACHE / f"{key}.txt"
        if cached.exists() and cached.stat().st_size > MIN_CHARS:
            text = cached.read_text(encoding="utf-8")
            status = "cache"
        else:
            r = pipeline.fetch(url, limit=1_500_000)
            if not r.get("ok") or len(r.get("text", "")) < MIN_CHARS:
                print(f"FETCH FAILED {key:10} status={r.get('status')} "
                      f"chars={len(r.get('text',''))}  {url}")
                continue
            text = r["text"]
            status = str(r.get("status"))
            cached.write_text(text, encoding="utf-8")
        body = content_region(text, key)
        print(f"\n{'='*78}\n### {key}  [{status}]  raw={len(text)}  content={len(body)}\n"
              f"### {url}\n{'='*78}")
        print(body[:2600])
        print("   ...[truncated for display]")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())