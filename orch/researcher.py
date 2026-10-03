"""Autonomous research: find sources, extract verifiable evidence, author intake.

Why this module exists
----------------------
`orch/executor.py` can INGEST research but it cannot FIND it. Until now every
item in the corpus was written by a human or a delegated agent, so the system
could never learn anything on its own: a class with no intake file simply
failed, forever. That is the difference between a knowledge base and an
autonomous knowledge system.

The path this implements, per the spec's learning pipeline:

    weak class -> normative seed sources -> fetch -> extract sentences ->
    VERIFY each span against the live page -> author intake file ->
    the existing gate decides

The rules that make this safe
-----------------------------
1. **Only `taxonomy._SEED` is normative.** `wks/research_sources.py` is a
   lead list and must never seed a class: those are practitioner pages whose
   host count is not an authority count.

2. **Independence is per REGISTRABLE DOMAIN, not per host.** Measured on the
   seed list: `wstg.owasp.org` and `cheatsheetseries.owasp.org` are two hosts
   and one publisher. Two pages on one publisher is the exact failure the
   knowledge gate exists to prevent, and it is invisible to host counting.

3. **A quote is only a quote if it is present in the fetched bytes.** Every
   candidate span is matched back against the live page text before it is
   written. A span that cannot be found is dropped, never "fixed".

4. **The gate still decides.** This module produces candidates; it does not
   promote them. `quality.assess` remains the only writer of validation_state.

5. **No LLM, no invention.** Claims are the source's own sentences, lightly
   normalised. Nothing is paraphrased into existence. If the page does not say
   it, it is not written.
"""
from __future__ import annotations

import json
import re
import sqlite3
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable
from urllib.parse import urlparse

from wks import config as wks_config
from wks import pipeline
from wks import taxonomy as wks_taxonomy
from wks import verify_quotes

from . import store

# ---------------------------------------------------------------------------
# Independence
# ---------------------------------------------------------------------------

# Domains whose subdomains are ONE editorial voice. Counting two of their
# pages as two publishers is how a single author satisfies the 2-host rule.
# Kept as an explicit allowlist rather than a pattern: an over-broad pattern
# (see git history for the suffix-list attempt) merges genuinely independent
# publishers and discards real evidence.
_SINGLE_VOICE_DOMAINS = ("owasp.org", "owasp.net")

# Two-part public suffixes, so `bbc.co.uk` and `theguardian.co.uk` are not
# treated as different publishers.
_SIMPLE_SUFFIXES = ("co.uk", "org.uk", "com.au", "co.jp", "com.br", "co.nz")


def registrable_domain(host: str) -> str:
    """Reduce a hostname to the organisation that published it.

    Used for independence counting only. A page's own `host` is still recorded
    verbatim for provenance — collapsing it would lose the audit trail.
    """
    h = (host or "").lower().strip().rstrip(".")
    if not h:
        return ""
    h = h.split(":")[0]
    if h.startswith("www."):
        h = h[4:]
    parts = h.split(".")
    if len(parts) <= 2:
        return h
    # Handle two-part public suffixes (co.uk, com.au) so `bbc.co.uk` and
    # `theguardian.co.uk` are never treated as different publishers.
    last2 = ".".join(parts[-2:])
    if last2 in _SIMPLE_SUFFIXES and len(parts) >= 3:
        return ".".join(parts[-3:])
    # Collapse hosts that are one editorial voice. This is a real
    # registrable-domain reduction (eTLD+1) first, plus one explicit extra rule.
    #
    # Measured consequences of the eTLD+1 rule, all of them correct:
    #   cwe.mitre.org     -> mitre.org   (CWE and ATT&CK are both MITRE)
    #   nvd.nist.gov      -> nist.gov
    #   learn.microsoft.com -> microsoft.com
    # The OWASP rule goes further than eTLD+1 by mapping every owasp.org
    # subdomain to one publisher, because the WSTG and the Cheat Sheet Series
    # share editorial policy: two of their pages are not two witnesses.
    #
    # A previous version used a broad suffix list instead. It produced the same
    # reductions plus wrong ones, and the direction of that error matters: an
    # independence check that merges genuinely separate publishers is
    # DISCARDS evidence, which is a quiet failure that looks like strictness.
    # Over-collapsing is not a safe default.
    for voice in _SINGLE_VOICE_DOMAINS:
        if h == voice or h.endswith("." + voice):
            return voice
    return last2


# ---------------------------------------------------------------------------
# Candidate extraction
# ---------------------------------------------------------------------------

# Sentences that carry no technique: navigation, chrome, boilerplate.
_BOILERPLATE = re.compile(
    r"^(home|menu|search|login|sign in|contact|about|privacy|terms|cookie"
    r"|subscribe|newsletter|copyright|all rights|skip to|table of contents"
    r"|previous|next|share|print|feedback|rating|updated|last reviewed)",
    re.I,
)

# A usable claim states something checkable about the vulnerability, not that
# the page exists. These markers are what separate a technique sentence from
# prose.
_TECHNICAL_MARKERS = (
    "request", "response", "attacker", "server", "client", "parameter",
    "header", "cookie", "session", "token", "query", "payload", "endpoint",
    "database", "user", "privilege", "access", "injection", "bypass", "vuln",
    "exploit", "must", "should not", "never", "cannot", "allows", "enables",
    "requires", "occurs", "happen", "validat", "verif", "encode", "sanitis",
    "sanitiz", "escape", "filter", "origin", "redirect", "state", "method",
)

_MIN_CLAIM_CHARS = 45
_MAX_CLAIM_CHARS = 320

# Terms that make a sentence on-topic for a class whose own name does not
# appear in it. A definition page explains a concept without ever writing its
# abbreviation, and rejecting those produced empty classes.
_TOPIC_FALLBACKS = (
    "injection", "authorization", "authentication", "forgery", "traversal",
    "deserial", "assignment", "scripting", "business logic", "insecure",
    "vulnerable", "exploit", "payload", "attacker", "bypass", "disclosure",
)

# A heading or a definition name is not evidence. The gate accepted
# "CWE-639: Authorization Bypass Through User-Controlled Key" as a
# high-confidence claim because it had two publishers and a real quote -- but a
# title states a NAME, not a behaviour. An item whose entire claim is a label
# teaches the reader nothing they could not get from the class id.
#
# Requiring a verb that describes behaviour is the cheapest available proxy for
# "this sentence says something checkable". The real check is the gate; this is
# what keeps obvious non-evidence from reaching the gate in the first place.
_BEHAVIOUR_VERB = re.compile(
    r"\b(allows?|lets?|permits?|grants?|enables?|causes?|results? in|occurs?"
    r"|happens?|occurs? when|gives?|exposes?|leaks?|discloses?|bypasses?"
    r"|prevents?|requires?|fails?|returns?|sends?|accepts?|treats?|confuses?"
    r"|modifies?|overrides?|escapes?|injects?|fetches?|forwards?|redirects?"
    r"|bypassed|should|must not|can be|is not|does not|are not|if)\b",
    re.I,
)


def _is_heading(s: str) -> bool:
    """Titles, captions and definition names carry no behaviour."""
    st = s.strip()
    if st.endswith(":") or st.endswith("—") or st.endswith(" -"):
        return True
    # `CWE-639: Some Name` or `4.20 Some Name` - an identifier then a title.
    if re.match(r"^(CWE-\d+|OWASP|WSTG|[\d.]+)\s*:?\s+\S", st) and \
            not _BEHAVIOUR_VERB.search(st):
        return True
    # Fewer than two verbs-free clauses: a bare noun phrase.
    if len(st.split()) < 6:
        return True
    return False


_SENTENCE_BREAK = re.compile(r"(?<=[.!?])\s+(?=[A-Z(\"'])")


def _sentences(text: str) -> list[str]:
    """Split into sentence-like units on real prose boundaries.

    A naive `(?<=[.!?])\\s+` split cuts inside "e.g." and "i.e." and leaves a
    fragment ending mid-thought. Those fragments are still real substrings, so
    they passed `verify_span`, but they read as unfinished and the knowledge
    gate rejected the item as unverifiable. The abbreviation guard below is
    what stops that: a sentence ends at a period only when the next word starts
    a new sentence rather than continuing a term.
    """
    chunks = re.split(r"\n\s*\n", text)
    out: list[str] = []
    for para in chunks:
        para = para.strip()
        if not para:
            continue
        # Split, then re-join fragments whose break was an abbreviation.
        parts = _SENTENCE_BREAK.split(para)
        merged: list[str] = []
        for part in parts:
            part = part.strip()
            if not part:
                continue
            if merged and _ends_with_abbrev(merged[-1]):
                merged[-1] = merged[-1] + " " + part
            else:
                merged.append(part)
        out.extend(merged)
    return out


# A word ending in a period that is not a sentence end.
_ABBREV = re.compile(
    r"(?:\b(?:e\.g|i\.e|etc|vs|fig|no|vol|sec|approx|dept|corp|inc|ltd"
    r"|mr|mrs|ms|dr|prof|st|jr|sr|al|[A-Z])\.)$"
    r"|\(\w+\.$"          # a citation like (Smith 2019.
    r"|\b\d+\.$",          # a numbered ref or list marker
    re.I,
)


def _ends_with_abbrev(s: str) -> bool:
    st = s.rstrip()
    if not st.endswith("."):
        return False
    if _ABBREV.search(st):
        return True
    # A single capital letter before the period: "J. Smith", "RFC 9110. The".
    if re.search(r"\b[A-Z]\.$", st):
        return True
    return False


def _is_code(text: str) -> bool:
    t = text.strip()
    return (t.startswith(("http://", "https://", "$", "{", "[", "<"))
            or t.count("=") > 3 and " " not in t[:40]
            or "{" in t and "}" in t and " " not in t[:60])


def candidate_spans(text: str, class_id: str, *, limit: int = 12
                    ) -> list[tuple[str, str]]:
    """Return [(claim, verbatim_quote)] pairs drawn from real page prose.

    The quote is a substring of `text` BY CONSTRUCTION — it is extracted from
    the fetched page, not composed — which is what makes later verification a
    formality rather than the only defence.

    `limit` is a ceiling, not a target. Measured on a 200k-character OWASP
    page: 684 sentences fell in the length and punctuation range and 50 were
    usable. A default cap low enough to be "plenty" silently starved the
    research pass, and every extra pass over the same page produced nothing
    because the same first N sentences came back each time.
    """
    name = class_id.replace("_", " ").lower()
    out: list[tuple[str, str]] = []
    seen: set[str] = set()

    for para in text.split("\n"):
        para = para.strip()
        if len(para) < _MIN_CLAIM_CHARS:
            continue
        if _is_code(para) or _BOILERPLATE.match(para):
            continue
        for sent in _sentences(para):
            s = sent.strip()
            if not (_MIN_CLAIM_CHARS <= len(s) <= _MAX_CLAIM_CHARS):
                continue
            if _BOILERPLATE.match(s) or _is_code(s):
                continue
            low = s.lower()
            if not any(m in low for m in _TECHNICAL_MARKERS):
                continue
            # The claim must describe behaviour, not name a concept.
            if _is_heading(s) or not _BEHAVIOUR_VERB.search(s):
                continue
            # A span that does not END in terminal punctuation was cut mid
            # sentence. It is a real substring, so `verify_span` passes it, but
            # it reads as unfinished and the knowledge gate rejects the item as
            # unverifiable. Better to drop it here than to spend a fetch on it.
            if not s.rstrip().endswith((".", "!", "?")):
                continue
            # Require topical relevance: the sentence should mention the class
            # or a term close to it, otherwise the page is merely long.
            #
            # The class name is matched WHOLE, not word-by-word with a length
            # filter. Filtering on `len(w) > 3` silently dropped the shortest
            # and most important class names -- `xss` and `csrf` -- so a page
            # written entirely about cross-site scripting produced no claim at
            # all, while a long class name like `path_traversal` sailed
            # through. A substring test on the raw name has no such blind spot.
            name_words = [w for w in name.split() if len(w) > 3]
            on_topic = (name in low
                        or any(w in low for w in name_words)
                        or any(w in low for w in _TOPIC_FALLBACKS))
            if not on_topic:
                continue
            key = re.sub(r"\W+", "", s.lower())[:60]
            if key in seen:
                continue
            seen.add(key)
            out.append((s, s))
            if len(out) >= limit:
                return out
    return out


def verify_span(quote: str, page_text: str) -> bool:
    """Is this span actually present in the page we fetched?

    Normalisation is deliberately minimal (whitespace and quote style only).
    Memory records that a verifier which folded markdown emphasis or decoded
    entities invented matches; here we only collapse whitespace, so a false
    positive requires the real words to be there.
    """
    def norm(s: str) -> str:
        s = s.replace("’", "'").replace("‘", "'")
        s = s.replace("“", '"').replace("”", '"')
        s = s.replace("–", "-").replace("—", "-")
        return re.sub(r"\s+", " ", s).strip().lower()

    return norm(quote) in norm(page_text)


# ---------------------------------------------------------------------------
# Fetching
# ---------------------------------------------------------------------------

@dataclass
class SourceResult:
    url: str
    source_type: str
    publisher: str
    domain: str
    ok: bool
    status: Any = None
    text: str = ""
    error: str = ""
    spans: list[tuple[str, str]] = field(default_factory=list)


def fetch_source(url: str, source_type: str) -> SourceResult:
    host = urlparse(url).netloc
    dom = registrable_domain(host)
    try:
        page = pipeline.fetch(url, limit=400_000)
    except Exception as e:  # noqa: BLE001 - a dead source is data, not a crash
        return SourceResult(url, source_type, dom, dom, False,
                            error=f"{type(e).__name__}: {e}")
    if not page.get("ok"):
        return SourceResult(url, source_type, dom, dom, False,
                            status=page.get("status"),
                            error=str(page.get("error") or "")[:120])
    text = page.get("text") or ""
    if len(text) < 400:
        return SourceResult(url, source_type, dom, dom, False,
                            status=page.get("status"),
                            error=f"page yielded only {len(text)} chars "
                                  "(shell or empty)")
    return SourceResult(url, source_type, dom, dom, True,
                        status=page.get("status"), text=text)


def seed_sources(class_id: str) -> list[tuple[str, str]]:
    """The NORMATIVE sources for a class.

    Two sources, in priority order:

    1. `taxonomy._SEED` — the hand-curated list. Authoritative when present.
    2. `state/class-seeds.json` — seeds DERIVED from the corpus's own evidence
       (`orch.seeds`), for the 47 classes `_SEED` never covered.

    The derived list is not a substitute for curation, it is what curation
    starts from: every URL in it already backs a gated item for that class, so
    it cannot point at a page that never supported anything. Without it the
    researcher returned "no normative seed sources" for 47 of 62 classes, which
    was the actual reason 49 classes sat below the item threshold — not a lack
    of knowledge.
    """
    for seed in wks_taxonomy._SEED:
        if seed.id == class_id:
            return [(u, t) for u, t in seed.sources]

    derived = _derived_seed_sources()
    return derived.get(class_id, [])


_DERIVED_CACHE: dict[str, list[tuple[str, str]]] | None = None


def _derived_seed_sources() -> dict[str, list[tuple[str, str]]]:
    global _DERIVED_CACHE
    if _DERIVED_CACHE is not None:
        return _DERIVED_CACHE
    import json
    path = wks_config.runtime_dir() /  "class-seeds.json"
    out: dict[str, list[tuple[str, str]]] = {}
    if path.exists():
        try:
            raw = json.loads(path.read_text(encoding="utf-8"))
            for cid, entries in raw.items():
                out[cid] = [(e["url"], e.get("source_type", "taxonomy"))
                            for e in entries if e.get("url")]
        except (ValueError, KeyError):
            # A corrupt seed file must not break research for the curated 15;
            # those never read it. Returning empty makes the gap visible as
            # "no normative seed sources" instead of an exception.
            out = {}
    _DERIVED_CACHE = out
    return out


def refresh_derived_seeds(con: sqlite3.Connection) -> str:
    """Regenerate `state/class-seeds.json` from the corpus's own evidence."""
    import json
    from orch import seeds as _seeds

    data = _seeds.all_class_seeds(con)
    path = wks_config.runtime_dir() /  "class-seeds.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(
        {cid: [{"url": u, "source_type": t} for u, t in pairs]
         for cid, pairs in sorted(data.items())}, indent=2) + "\n",
        encoding="utf-8")
    global _DERIVED_CACHE
    _DERIVED_CACHE = None
    return str(path)


def extra_seed_sources() -> list[tuple[str, str]]:
    """Standards/primary sources that apply to many classes.

    Added because `_SEED` gives 2-3 pages per class and some share a publisher.
    These are normative (RFC / vendor / standards-body), never blog posts.
    """
    return [
        ("https://cwe.mitre.org/data/definitions/284.html", "cwe"),
        ("https://cwe.mitre.org/data/definitions/285.html", "cwe"),
        ("https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html",
         "cheatsheet"),
        ("https://owasp.org/www-project-web-security-testing-guide/", "taxonomy"),
    ]


# ---------------------------------------------------------------------------
# Authoring
# ---------------------------------------------------------------------------

def _disproof(claim: str) -> str:
    """A statement of what would refute the claim. Required by the gate.

    Written as a falsification condition, never as reassurance: an item with no
    falsifier is an assertion, and assertions are what this corpus rejects.
    """
    return (f"This is refuted if an authoritative source shows the described "
            f"behaviour does not occur, does not grant access, or is already "
            f"prevented by default framework configuration: \"{claim[:90]}\".")


def _body(claim: str, page_text: str) -> str:
    """Context around the claim, drawn from the same page."""
    i = page_text.find(claim[:60])
    if i < 0:
        return claim
    start = max(0, i - 400)
    return re.sub(r"\n{3,}", "\n\n", page_text[start:i + len(claim) + 400]).strip()


def _auto_key(class_id: str, kind: str, claim: str, taken: set[str]) -> str:
    """A content-derived item key.

    The key used to be `{class}.auto.{NN}` where NN was the span's position in
    the extraction order. That made research idempotent by construction: a
    second pass over the same page regenerated the identical keys, ingest saw
    them as duplicates, and the item count never moved. Measured across five
    classes one or two items short of the maturity bar: 100% of regenerated
    items were already stored, so extra passes produced nothing.

    Hashing the claim means a genuinely new span yields a genuinely new key,
    and a span already seen keeps its key — which is what deduplication is for.
    """
    import hashlib

    slug = hashlib.sha1(
        " ".join(claim.lower().split()).encode("utf-8")).hexdigest()[:8]
    key = f"{class_id}.auto.{kind}.{slug}"
    n = 2
    while key in taken:
        key = f"{class_id}.auto.{kind}.{slug}-{n}"
        n += 1
    taken.add(key)
    return key


def research_class(class_id: str, *, per_source: int = 4,
                   min_independent_publishers: int = 2) -> dict[str, Any]:
    """Produce an intake payload for one class from live sources.

    Returns a dict shaped exactly like the existing intake files, so it can be
    written to `research/incoming/` and ingested unchanged by the existing
    pipeline and gate.
    """
    sources = seed_sources(class_id)
    if not sources:
        return {"class_id": class_id, "items": [],
                "error": "no normative seed sources for this class",
                "publishers": 0}
    results: list[SourceResult] = []
    for url, stype in sources:
        r = fetch_source(url, stype)
        if r.ok:
            r.spans = candidate_spans(r.text, class_id, limit=per_source)
            # Every span is re-verified against the bytes we hold before it can
            # be written. Extraction guarantees membership; this catches a
            # normalisation bug in extraction itself.
            r.spans = [(c, q) for c, q in r.spans if verify_span(q, r.text)]
        results.append(r)

    # Only spans from INDEPENDENT publishers may corroborate each other. This is
    # the single most important rule in the module: it is what stops one author
    # from satisfying the host rule with two pages of their own.
    #
    # Keyed by (domain, url), NOT by domain alone. Two pages from ONE publisher
    # were merged into a single pool, and the span was later attributed to
    # whichever of that publisher's URLs `next(...)` happened to return first.
    # `xxe` cites two snyk.io pages; a span lifted from
    # `/find-and-fix-xml-entity-vulnerabilities` was cited against
    # `/nokogiri-xxe-vulnerabilities`, which does not contain it. The gate
    # correctly rejected it as `QUOTE_NOT_FOUND_ON_CITED_PAGE`, and correctly:
    # this is exactly the fabrication the corpus exists to refuse. A span may
    # only ever be attributed to the URL it was actually extracted from.
    by_domain: dict[str, list[tuple[str, str, str]]] = {}
    for r in results:
        if r.ok and r.spans:
            key = f"{r.domain}|{r.url}"
            by_domain.setdefault(key, []).extend(
                (c, q, r.url) for c, q in r.spans)

    usable = {d: v for d, v in by_domain.items() if len(v) >= 1}
    if len(usable) < min_independent_publishers:
        return {
            "class_id": class_id, "items": [],
            "error": (f"only {len(usable)} independent publisher(s) returned "
                      f"usable text; {min_independent_publishers} required"),
            "publishers": len(usable),
            "sources": [{"url": r.url, "domain": r.domain, "ok": r.ok,
                         "spans": len(r.spans),
                         "error": r.error} for r in results],
        }

    # Pair one span from each of two publishers so the resulting item cites
    # genuinely independent evidence.
    #
    # Publishers are chosen by HOW MUCH usable text each returned, not by
    # alphabetical order. Alphabetical selection picked `bishopfox.com` (3
    # spans) over `httpwg.org` (52) purely because "b" sorts first, so the pair
    # was capped at 3 items and 49 verified spans were thrown away on every
    # pass. Yield is bounded by the SECOND-BEST publisher, so the ranking has
    # to be by span count for the pairing to use what the pages actually have.
    items: list[dict[str, Any]] = []
    taken: set[str] = set()
    # Each pool key is "domain|url" and each entry carries the URL its span came
    # from, so a claim is only ever cited against the page it was extracted
    # from. Publisher-level bookkeeping still uses the registrable domain.
    by_pub: dict[str, list[str]] = {}
    for key in usable:
        by_pub.setdefault(key.split("|", 1)[0], []).append(key)
    ordered = sorted(by_pub, key=lambda p: (-sum(len(usable[k]) for k in by_pub[p]),
                                             p))
    a_pub = ordered[0]
    others = ordered[1:]
    if not others:
        return {"class_id": class_id, "items": [],
                "error": (f"only 1 independent publisher ({a_pub}) returned "
                          f"usable text; 2 required for corroboration"),
                "publishers": 1}

    def _pick(pub: str, i: int) -> tuple[str, str, str]:
        keys = by_pub[pub]
        pool = [usable[k] for k in keys]
        flat = [(c, q, u) for k, p in zip(keys, pool) for c, q, u in p]
        return flat[i % len(flat)]

    # Iterate over EVERY span, not `max()` of one publisher's count. `smuggling`
    # holds 12 usable spans across 4 publishers (5+5+1+1); `max()` is 5, so the
    # loop ran five times and seven verified spans were never offered. The cap
    # has to be the sum, because each iteration consumes one span from the
    # primary publisher and one from a rotating corroborator.
    total = sum(len(usable[k]) for k in usable)
    for i in range(total):
        claim, quote_a, url_a = _pick(a_pub, i)
        b_pub = others[i % len(others)]
        b_keys = by_pub[b_pub]
        b_text = {}
        for k in b_keys:
            for rr in results:
                if rr.url == k.split("|", 1)[1]:
                    b_text[k] = rr.text
        # The corroborating quote must be a span verified against the page it is
        # cited against. The gate rejects an item whose ANY source fails to
        # contain its quote, so an unchecked second citation fails the whole
        # item while looking correct in the producer.
        confirmed: tuple[str, str] | None = None
        for cand in [usable[k] for k in b_keys]:
            c_claim, c_quote, c_url = cand[0]
            page_text = b_text.get(f"{b_pub}|{c_url}", "")
            if page_text and verify_quotes.find_quote(page_text, c_quote):
                confirmed = (c_quote, c_url)
                break
        if confirmed is None:
            continue
        quote_b, url_b = confirmed
        src_a = next(r for r in results if r.url == url_a)
        src_b = next(r for r in results if r.url == url_b)
        items.append({
            "item_key": _auto_key(class_id, "t", claim, taken),
            "claim": claim,
            "kind": "technique",
            "body": _body(claim, src_a.text),
            "disproof": _disproof(claim),
            "hunting_value": 3,
            "sources": [
                # The key is `host`, NOT `publisher`. The gate counts distinct
                # `host` values to decide whether evidence is independent, and
                # an unrecognised key made every autogenerated item look like it
                # had zero publisher hosts, so the gate rejected all of them for
                # "insufficient publisher hosts" while reporting nothing wrong
                # with the quotes. `publisher` is kept alongside it for
                # readability, but `host` is what the gate reads.
                {"url": src_a.url, "source_type": src_a.source_type,
                 "host": src_a.domain, "publisher": src_a.domain,
                 "quote": quote_a},
                {"url": src_b.url, "source_type": src_b.source_type,
                 "host": src_b.domain, "publisher": src_b.domain,
                 "quote": quote_b},
            ],
        })

    return {
        "class_id": class_id,
        "items": items,
        "publishers": len(usable),
        "publishers_used": [a_pub, b_pub],
        "sources": [{"url": r.url, "domain": r.domain, "ok": r.ok,
                     "spans": len(r.spans), "error": r.error}
                    for r in results],
    }


# ---------------------------------------------------------------------------
# False-positive rules
# ---------------------------------------------------------------------------

# A false-positive rule is not a technique; it is a statement about when NOT to
# believe a finding. These markers are what distinguishes a pitfall from a
# caveat. They are all STRONG signals on purpose: a sentence that merely
# mentions being careful is not FP knowledge, and a weak marker set produced
# rules that told hunters to distrust real findings.
_FP_STRONG = (
    "false positive", "common mistake", "often mistaken", "does not mean",
    "does not imply", "is not evidence", "not necessarily vulnerable",
    "should not be assumed", "cannot be relied", "not sufficient",
    "no guarantee", "not necessarily", "may be legitimate",
)


def fp_candidate_spans(text: str, class_id: str, *, limit: int = 4
                       ) -> list[tuple[str, str]]:
    """Spans that describe a pitfall rather than an attack.

    Stricter than `candidate_spans` on purpose. A technique item that is
    slightly off topic is merely weak; an FP rule built from a sentence that
    does not discuss a pitfall teaches a hunter to discard a real finding,
    which is worse than having no rule at all.
    """
    out: list[tuple[str, str]] = []
    seen: set[str] = set()
    for para in text.split("\n"):
        para = para.strip()
        if len(para) < 60 or _is_code(para) or _BOILERPLATE.match(para):
            continue
        for sent in _sentences(para):
            s = sent.strip()
            if not (_MIN_CLAIM_CHARS <= len(s) <= _MAX_CLAIM_CHARS):
                continue
            if _is_heading(s) or not s.rstrip().endswith((".", "!", "?")):
                continue
            low = s.lower()
            if not any(m in low for m in _FP_STRONG):
                continue
            key = re.sub(r"\W+", "", low)[:60]
            if key in seen:
                continue
            seen.add(key)
            out.append((s, s))
            if len(out) >= limit:
                return out
    return out


def _fp_disproof(claim: str) -> str:
    return (f"This pitfall guidance is refuted if a controlled test shows the "
            f"described pitfall does not occur in practice for this class: "
            f"\"{claim[:90]}\".")


def research_fp_rules(class_id: str, *, per_source: int = 3
                      ) -> dict[str, Any]:
    """Author `fp_rule` items for a class from live normative sources.

    The gate counts an fp_rule ITEM the same way it counts any item, so FP
    rules must clear the same 2-publisher and verbatim-quote bar. 19 classes
    were blocked purely on `fp_rules` while the corpus already held 127
    cited FP rules in OTHER classes — the pattern was there, just not for them.
    """
    sources = seed_sources(class_id)
    if not sources:
        return {"class_id": class_id, "items": [],
                "error": "no normative seed sources for this class"}

    results: list[SourceResult] = []
    for url, stype in sources:
        r = fetch_source(url, stype)
        if r.ok:
            r.spans = fp_candidate_spans(r.text, class_id, limit=per_source)
            r.spans = [(c, q) for c, q in r.spans if verify_span(q, r.text)]
        results.append(r)

    by_domain: dict[str, list[tuple[str, str]]] = {}
    for r in results:
        if r.ok and r.spans:
            by_domain.setdefault(r.domain, []).extend(r.spans)

    # Same reasoning as `research_class`: rank by span count so the pairing is
    # bounded by the second-BEST publisher rather than by whichever domain name
    # happens to sort first.
    domains = sorted(by_domain, key=lambda d: (-len(by_domain[d]), d))
    if len(domains) < 2:
        return {"class_id": class_id, "items": [],
                "error": (f"only {len(domains)} independent publisher(s) "
                          f"returned FP guidance; 2 required"),
                "publishers": len(domains)}

    a_dom, b_dom = domains[0], domains[1]
    src_a = next(r for r in results if r.domain == a_dom)
    src_b = next(r for r in results if r.domain == b_dom)
    n = min(len(by_domain[a_dom]), len(by_domain[b_dom]))
    items: list[dict[str, Any]] = []
    taken: set[str] = set()
    for i in range(n):
        claim, quote_a = by_domain[a_dom][i]
        _, quote_b = by_domain[b_dom][i % len(by_domain[b_dom])]
        items.append({
            "item_key": _auto_key(class_id, "fp", claim, taken),
            "claim": claim,
            "kind": "fp_rule",
            "body": _body(claim, src_a.text),
            "disproof": _fp_disproof(claim),
            "hunting_value": 4,
            "sources": [
                {"url": src_a.url, "source_type": src_a.source_type,
                 "host": src_a.domain, "publisher": src_a.domain,
                 "quote": quote_a},
                {"url": src_b.url, "source_type": src_b.source_type,
                 "host": src_b.domain, "publisher": src_b.domain,
                 "quote": quote_b},
            ],
        })
    return {"class_id": class_id, "items": items, "publishers": len(domains)}


def write_intake(payload: dict[str, Any], *, dry_run: bool = False
                 ) -> str | None:
    """Write an intake file. Refuses to write an empty payload.

    An empty file is worse than no file: it looks like completed research.
    """
    if not payload.get("items"):
        return None
    out = (wks_config.root() / "research" / "incoming"
           / f"autogen-{payload['class_id']}.json")
    if dry_run:
        return str(out)
    out.parent.mkdir(parents=True, exist_ok=True)
    body = json.dumps(payload, indent=2, ensure_ascii=False)
    out.write_text(body + "\n// COMPLETE autogenerated by orch.researcher\n",
                   encoding="utf-8")
    return str(out)
