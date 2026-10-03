#!/usr/bin/env python
"""GET-verify candidate sources for `eol_software` (wave 11 follow-up).

WHY: the wave-11 probe found NO citable source for `eol_software`, and the
ledger recorded "no source found" as the honest outcome. That was true of the
URLs probed, not of the subject -- web search surfaced normative material
(NIST SP 800-40 Rev 4, CISA KEV/BOD) that the first probe never tried. The
lesson being applied: **"no source found" is a statement about the search, not
about the world, so widen the search before re-scoping the class.**

Scored on the SUBJECT, not on bytes: a host that 404s or returns nav chrome is
unusable, and `endoflife.date/openssl` is DNS-blocked on this host (measured).
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from wks import pipeline  # noqa: E402

MARKERS = ["end of life", "end-of-life", "unsupported", "patch", "remediat",
           "vulnerab", "decommission", "lifecycle", "life cycle", "maintenance"]

CANDIDATES = [
    # NIST -- normative, and says explicitly what to do when patching is gone.
    ("nist-sp800-40r4", "https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-40r4.pdf"),
    ("csrc-sp800-40r4", "https://csrc.nist.gov/pubs/sp/800/40/r4/final"),
    ("nccoe-patching", "https://www.nccoe.nist.gov/sites/default/files/2022-03/patching-nist-sp-1800-31b-final.pdf"),
    # CISA -- KEV catalog and the bad-practice naming EOL as a bad practice.
    ("cisa-kev", "https://www.cisa.gov/known-exploited-vulnerabilities-catalog"),
    ("cisa-badpractices", "https://www.cisa.gov/resources-tools/resources/catalog-bad-practices"),
    ("cisa-kev-print", "https://www.cisa.gov/known-exploited-vulnerabilities-catalog-print"),
    # Independent practice / registry voice (NOT mitre, NOT owasp).
    ("first-eol", "https://endoflife.ai/article-eol-calendar-alerts"),
    ("federalnews-eol", "https://federalnewsnetwork.com/cybersecurity/2026/02/cisa-tells-agencies-to-identify-upgrade-unsupported-edge-devices/"),
]


def main() -> int:
    print(f"{'host/id':<22} {'st':<5} {'len':>8}  {'hits':>4}  url")
    usable = []
    for tag, url in CANDIDATES:
        try:
            r = pipeline.fetch(url)
        except Exception as exc:  # noqa: BLE001
            print(f"{tag:<22} ERR   {'':>8}  {'':>4}  {url}  ({type(exc).__name__})")
            continue
        status = r.get("status")
        text = (r.get("text") or "")
        low = text.lower()
        hits = sum(low.count(m) for m in MARKERS)
        ok = status == 200 and len(text) >= 2000 and hits >= 8
        if ok:
            usable.append((tag, url, len(text), hits))
        print(f"{tag:<22} {str(status):<5} {len(text):>8}  {hits:>4}  {url}")

    print(f"\nUSABLE ({len(usable)}):")
    for tag, url, n, h in usable:
        print(f"  {tag:<22} {n:>8} chars, {h} markers")

    # Independence: the gate needs >= 2 DISTINCT REGISTRABLE ORGS.
    orgs = {url.split("/")[2].lower() for _, url, _, _ in usable}
    print(f"\ndistinct orgs: {sorted(orgs)}")
    print("verdict:", "CAN corroborate" if len(orgs) >= 2 else "CANNOT corroborate yet")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
