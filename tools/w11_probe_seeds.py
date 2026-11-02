#!/usr/bin/env python
"""GET-verify candidate seed URLs for the three zero-item classes.

WHY: `orch.seeds.derive_seeds()` derives seeds from an existing corpus, so a
class with 0 items has nothing to derive from, and `taxonomy._SEED` covers
only 15 of 70 classes. Those 3 classes can therefore never bootstrap: they get
no page, `wks.cli domains --check` reports them missing, and masterprompt
check c_54 (the architecture auditor) fails. This probe finds LIVE,
ON-TOPIC pages so the bootstrap can be seeded by hand with verified URLs.

RULE (measured): never guess a path from a topic name. A 200 proves the URL
exists; only the marker count proves it is about the subject.
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from wks import pipeline  # noqa: E402

# (class_id, marker terms that must appear in the body)
PROBES: list[tuple[str, list[str], list[str]]] = [
    (
        "otp",
        ["one-time", "otp", "mfa", "factor"],
        [
            "https://www.ncsc.gov.uk/guidance/multi-factor-authentication-online-services",
            "https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html",
            "https://www.cisa.gov/resources-tools/resources/implementing-phishing-resistant-mfa",
            "https://pages.nist.gov/800-63-3/sp800-63b.html",
            "https://portswigger.net/web-security/other-attacks",
            "https://cwe.mitre.org/data/definitions/308.html",
            "https://attack.mitre.org/techniques/T1556/006/",
            "https://owasp.org/www-project-cheat-sheets/",
        ],
    ),
    (
        "rate_limit",
        ["rate limit", "rate-limit", "ratelimit", "brute force", "throttl"],
        [
            "https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html",
            "https://portswigger.net/web-security/graphql/abuse/rate-limiting",
            "https://owasp.org/API-Security/editions/2023/en/0xa4-unrestricted-resource-consumption/",
            "https://cwe.mitre.org/data/definitions/770.html",
            "https://attack.mitre.org/techniques/T1110/",
            "https://en.wikipedia.org/wiki/Rate_limiting",
            "https://www.rfc-editor.org/rfc/rfc6585",
            "https://www.rfc-editor.org/rfc/rfc7231",
        ],
    ),
    (
        "eol_software",
        ["end of life", "end-of-life", "eol", "unsupported", "lifecycle"],
        [
            "https://www.cisa.gov/news-events/directives/bod-22-01-reducing-significant-risk-microsoft-windows-legacy-protocols",
            "https://www.cisa.gov/topics/cyber-threats-and-advisories/information-technology-product-security",
            "https://cwe.mitre.org/data/definitions/1104.html",
            "https://nvd.nist.gov/vuln/detail/CVE-2014-0160",
            "https://endoflife.date/openssl",
            "https://en.wikipedia.org/wiki/End_of_life",
            "https://cheatsheetseries.owasp.org/cheatsheets/Third_Party_Pentest_Cheat_Sheet.html",
        ],
    ),
]

MIN_CHARS = 2000


def main() -> int:
    for class_id, markers, urls in PROBES:
        print(f"\n=== {class_id} ===")
        for url in urls:
            try:
                r = pipeline.fetch(url)
            except Exception as exc:  # noqa: BLE001
                print(f"  [ERR ] {url} :: {type(exc).__name__}: {exc}")
                continue
            status = r.get("status")
            text = (r.get("text") or "")
            ctype = (r.get("content_type") or "").lower()
            # qget refuses to print a body under 2000 chars, so an error stub
            # can never be mistaken for evidence.
            low = text.lower()
            hits = {m: low.count(m.lower()) for m in markers}
            total = sum(hits.values())
            usable = (status == 200 and len(text) >= MIN_CHARS and total > 0
                      and "html" not in ctype)
            flag = "OK   " if usable else "THIN "
            print(f"  [{flag}] {status} len={len(text):>7} ct={ctype[:28]:<28} "
                  f"markers={total:<4} {url}")
            if total:
                print(f"          {hits}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
