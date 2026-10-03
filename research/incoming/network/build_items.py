"""Build the NETWORK research wave.

HOW A QUOTE GETS INTO AN ITEM HERE. Author code below never types a quote. It
names a URL and a short NEEDLE (a few words that must appear on the page), and
`pick()` returns the enclosing sentence window lifted verbatim from the cached
`wks.pipeline.fetch` text. If the needle is absent, the build FAILS — it cannot
emit an item whose evidence does not exist.

What the author DOES write is the analysis: the claim, the body, and the
disproof. That is the part that has to be reasoned, and it is the part a
retrieval step cannot supply.
"""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from mine import _windows, prose, text_of  # noqa: E402

# RFC page furniture: page footers and TOC lines get spliced into "sentences".
_RFC_NOISE = re.compile(r"(Mockapetris|Neuman|Sermersheim|Savola|Network Working"
                        r" Group|Standards Track|RFC \d+|Request for Comments"
                        r"|\[Page \d+\]|\bis a domain name represented)")


def norm_ws(text: str) -> str:
    """Collapse whitespace runs to single spaces.

    MUST match what the gate does to a page before comparing. `verify_quotes.
    norm()` rewrites `\\s+` to a single space on BOTH the quote and the fetched
    page, so a quote selected from whitespace-collapsed text is exactly as
    verifiable as one copied from the rendered page. Selecting from the RAW
    text instead would produce a quote whose internal newlines the gate
    collapses away — still fine — but a needle search against raw text fails on
    any line-wrapped span, which is most RFC prose.
    """
    return re.sub(r"\s+", " ", text)


def pick(url: str, needle: str, *, after: str | None = None,
         min_chars: int = 100, max_chars: int = 460) -> str:
    """Return the sentence window around `needle`, verbatim, or raise."""
    text = text_of(url)
    if "learn.microsoft.com" in url and after is None:
        after = "In this article"
    body = norm_ws(prose(text, after))
    needle_n = norm_ws(needle)
    if needle_n not in body:
        raise SystemExit(f"NEEDLE NOT ON PAGE: {needle!r} @ {url}")
    for span in _windows(body, re.escape(needle_n), min_chars=min_chars,
                         max_chars=max_chars, limit=1):
        if needle_n in span:
            return span
    # The window is empty (needle sits next to no sentence boundary): return a
    # generous literal slice around the needle instead of guessing a boundary.
    i = body.find(needle_n)
    return body[max(0, i - 200):min(len(body), i + 260)].strip()


# Page furniture that precedes the actual sentence of evidence. The gate does
# NOT care: a quote is verified by containment, and "Home Techniques Enterprise
# Network Service Discovery Adversaries may attempt to..." is contained in the
# page just as well. But a citation should read as evidence, so the build strips
# these prefixes. Each rule is anchored on how the specific site renders, and
# stripping is purely cosmetic — the remainder is still a literal substring of
# the fetched text, which is what makes it verifiable.
_LEAD_PREFIXES = (
    # Microsoft Learn body anchor (we slice from this marker, so it leads).
    re.compile(r"^In this article\s+"),
    # MITRE ATT&CK nav: the page description always opens with "Adversaries" or
    # "The adversary", so cut the preceding crumb/technique-name run.
    re.compile(r"^(?:Home\s+)?(?:Techniques|Tactics|Matrices)\b.*?"
               r"(?=Adversaries\b|The adversary\b)"),
    # MITRE section headings that sit immediately before a sentence.
    re.compile(r"^(?:Description|Extended Description|Impact|Details|"
               r"Potential Mitigations|Phase\(s\)|Scope|Mitigations|Detection "
               r"Strategy|Weakness Ordinalities|Reference)\s+"),
)


def strip_lead(span: str) -> str:
    out = span
    for _ in range(3):
        before = out
        for rx in _LEAD_PREFIXES:
            out = rx.sub("", out, count=1)
        out = out.lstrip(" \t•-—¶|")
        if out == before:
            break
    return out.strip() or span.strip()


def item(item_key: str, kind: str, claim: str, body: str, disproof: str,
         sources: list[dict], *, surface: str | None = None,
         severity: str | None = None, hunting_value: int = 5) -> dict:
    assert len(claim) >= 40, f"claim too short: {item_key}"
    assert len(body) >= 200, f"body too short: {item_key}"
    assert disproof, f"no disproof: {item_key}"
    hosts = {s["url"].split("/")[2].removeprefix("www.") for s in sources}
    assert len(hosts) >= 2, f"{item_key}: {len(hosts)} host(s) {hosts} < 2"
    assert len(sources) >= 2, f"{item_key}: {len(sources)} source(s) < 2"
    return {
        "item_key": item_key, "kind": kind, "claim": claim, "body": body,
        "disproof": disproof, "sources": sources, "surface": surface,
        "severity_hint": severity, "hunting_value": hunting_value,
    }


def src(url: str, source_type: str, needle: str, *, locator: str | None = None,
        **kw) -> dict:
    return {"url": url, "source_type": source_type,
            "quote": strip_lead(pick(url, needle, **kw)),
            "locator": locator}


MITRE = "attack.mitre.org"
IETF = "rfc-editor.org"
CWE = "cwe.mitre.org"
MS = "learn.microsoft.com"
OWASP = "cheatsheetseries.owasp.org"


def t(num: str) -> str:
    return f"https://attack.mitre.org/techniques/{num}/"


def cwe(num: int) -> str:
    return f"https://cwe.mitre.org/data/definitions/{num}.html"


def rfc(num: int) -> str:
    return f"https://www.rfc-editor.org/rfc/rfc{num}.html"


def build() -> list[dict]:
    from netitems import ITEMS  # authored analysis, imported separately
    return [it for it in ITEMS]


if __name__ == "__main__":
    items = build()
    out = {"items": items}
    dest = Path("net-wave1.json")
    dest.write_text(json.dumps(out, indent=1, ensure_ascii=False), encoding="utf-8")
    hosts: set[str] = set()
    for it in items:
        for s in it["sources"]:
            hosts.add(s["url"].split("/")[2].removeprefix("www."))
    classes = {it["item_key"].split(".")[0] for it in items}
    print(f"wrote {dest}  items={len(items)} classes={len(classes)} "
          f"hosts={len(hosts)}")
    for h in sorted(hosts):
        print("  host:", h)
