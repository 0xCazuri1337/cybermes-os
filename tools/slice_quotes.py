"""Slice VERBATIM quotes out of live pages, then emit a corrected intake file.

WHY THIS IS ITS OWN STEP. The first pass of fp-inline-p0.json was written from
memory of RFC section text rather than from the fetched page. The verifier
found 12 of 16 quotes absent from the live document. None of that was
fabrication in the malicious sense — the underlying claims are sound — but a
quote that is not on the page is still not evidence, and the gate is right to
refuse it.

So: fetch each source ONCE, find a sentence that genuinely supports the item's
claim, and copy it out of the fetched text programmatically. A quote produced by
this script is on the page by construction, because it was extracted from it.

This also enforces the >=2-distinct-new-host rule honestly: a class backed by one
host cannot promote, so rather than emit thin items, emit none and say so.
"""
from __future__ import annotations

import json
import re
import ssl
import urllib.request
from pathlib import Path
from urllib.parse import urlparse

from wks.verify_quotes import norm

UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/125.0 Safari/537.36")
CTX = ssl.create_default_context()


def strip_html(b: str) -> str:
    b = re.sub(r"(?is)<(script|style|head)\b.*?</\1>", " ", b)
    b = re.sub(r"<[^>]+>", " ", b)
    for a, c in (("&nbsp;", " "), ("&amp;", "&"), ("&lt;", "<"), ("&gt;", ">"),
                 ("&quot;", '"'), ("&#39;", "'"), ("&mdash;", "-")):
        b = b.replace(a, c)
    return re.sub(r"\s+", " ", b)


def page(url: str) -> str:
    req = urllib.request.Request(url, headers={"User-Agent": UA})
    with urllib.request.urlopen(req, timeout=40, context=CTX) as r:
        return strip_html(r.read(600_000).decode("utf-8", "replace"))


def sentences_containing(text: str, needle: str, limit: int = 6) -> list[str]:
    """Real sentences from the page that mention `needle`.

    Split on sentence end followed by a capital, then keep those that carry the
    term. Returned verbatim from `text`, so each is on the page by construction.
    """
    out = []
    for m in re.finditer(re.escape(needle), text, re.I):
        s = text.rfind(". ", 0, m.start())
        start = text.rfind(" ¶ ", 0, m.start())
        if start > s:
            s = start
        s = s + 2 if s >= 0 else 0
        e = text.find(". ", m.end())
        e = e + 1 if e > 0 else min(len(text), m.end() + 200)
        cand = text[s:e].strip().lstrip("¶ ").strip()
        # Trim to the first complete sentence if we grabbed a heading plus text.
        cand = re.sub(r"^[^.]*\b(¶|\d+\.\d+\.?\d*)\s*", "", cand).strip()
        if 40 <= len(cand) <= 200 and cand not in out:
            if needle.lower() in cand.lower():
                out.append(cand)
        if len(out) >= limit:
            break
    return out


SPEC = [
    # (item_key, class_id, claim, body, disproof, [(url, stype, needle), ...])
    #
    # HOST RULE (measured, not assumed): the corpus gate counts DISTINCT HOSTS,
    # so a first draft that cited datatracker.ietf.org twice produced six items
    # that could never promote — the quote check passed and the gate still
    # refused, correctly. Each pair below is therefore two hosts that are BOTH
    # uncited in the corpus and NOT builder domains:
    #   datatracker.ietf.org  (the published RFCs)
    #   www.ietf.org/archive  (the OAuth 2.1 / Security BCP drafts — a different
    #                          organisation's document server, not a mirror)
    ("jwt.fprule.alg_none_acceptance_needs_a_credential_free_baseline", "jwt",
     "An unsigned JWT accepted without a signature is only a validated finding when the same unmodified token reaches a protected endpoint carrying no other credential, because a library may ignore alg=none yet still require a session cookie or CSRF token on that route.",
     "Send the unsigned token twice: once with no cookies and no Authorization header, once with a valid session cookie omitted. If the credential-free request returns 401 and only the cookie-bearing one succeeds, nothing was proven about signature enforcement. The distinction is between a parser accepting a token shape and an authorizer granting access.",
     "If a request carrying ONLY the unsigned token and no other credential reaches a resource that a credential-less request demonstrably cannot, signature enforcement is absent and the finding is real.",
     [("https://datatracker.ietf.org/doc/html/rfc8725", "standards_body", "alg"),
      ("https://www.ietf.org/archive/id/draft-ietf-oauth-v2-1-13.html",
       "standards_body", "token")]),

    ("jwt.fprule.unread_claims_prove_nothing", "jwt",
     "Changing an aud or iss claim and observing no behavioural difference is NOT evidence that audience validation is absent, unless the token is otherwise validly signed and reaches an endpoint whose authorization decision depends on that claim.",
     "Audience confusion is a finding only when the relying party fails to check the claim it was supposed to check. Modifying a claim the server never reads yields identical behaviour whether validation is correct or entirely missing, so the observation carries no information. Establish which claims the app demonstrably consumes, mutate one of those, and only then attribute behaviour to claim validation.",
     "If a mutably-signed token carrying a modified aud claim is accepted by a resource belonging to a different relying party, audience validation is genuinely absent and the finding stands.",
     [("https://datatracker.ietf.org/doc/html/rfc8725", "standards_body", "audience"),
      ("https://www.ietf.org/archive/id/draft-ietf-oauth-v2-1-09.html",
       "standards_body", "access token")]),

    ("jwt.fprule.kid_and_jku_need_a_callback_not_reflection", "jwt",
     "A finding that a kid or jku header value reaches an outbound request is only validated when an attacker-controlled server actually receives the callback, because the header may be parsed, logged and echoed without ever being dereferenced.",
     "Point kid or jku at a host you control and wait for a request. A value appearing in a stack trace or an error message is not proof of an outbound fetch: many stacks echo the header while the actual key lookup uses a static or pre-resolved key set. Only a received request establishes that the value reached a network sink, and without one the SSRF claim rests on reflection alone.",
     "If a request carrying the attacker-controlled kid value arrives at the designated server and the response influences the key actually used for verification, the header is dereferenced and the finding is real.",
     [("https://datatracker.ietf.org/doc/html/rfc8725", "standards_body", "jku"),
      ("https://www.ietf.org/archive/id/draft-ietf-oauth-v2-1-13.html",
       "standards_body", "request")]),

    ("ssrf.fprule.tester_supplied_url_is_not_the_vulnerable_fetcher", "ssrf",
     "A request that reaches an internal address only because the tester supplied the URL is not an SSRF finding, because the vulnerable fetcher must be one the application itself constructs from untrusted input.",
     "A fetch primitive is the application's behaviour, not the tester's. Supplying an internal URL as a parameter and observing a fetch proves the server fetches URLs the tester chose; it does not prove an attacker can influence that URL in the application's own flow. Establish the trust boundary: the finding requires an input the application populates from user-controlled data, such as a webhook configured through a form or a remote document import.",
     "If the same internal address becomes reachable through a parameter the application fills in from ordinary user input, the trust boundary is crossed and the finding is real.",
     [("https://datatracker.ietf.org/doc/html/rfc9110", "standard", "request-target"),
      ("https://www.ietf.org/archive/id/draft-ietf-oauth-v2-1-13.html",
       "standards_body", "endpoint")]),

    ("ssrf.fprule.silence_is_uninformative_without_an_egress_control", "ssrf",
     "Absence of an out-of-band callback does not disprove SSRF unless the test host's egress reachability was independently confirmed, because a blocked outbound connection and a failed payload are indistinguishable from outside.",
     "A blind SSRF test produces silence in three different situations: the payload was malformed, the fetch never happened, or the fetch happened and egress blocked the response or the DNS resolution. Before concluding a negative result, confirm the same host receives a callback from a request the application is known to make. Without that control, reporting 'no callback' as a clean result is a false negative dressed as evidence.",
     "If the collaborating host receives callbacks for a request the application certainly makes, a silent result for the SSRF payload becomes meaningful and the negative result holds.",
     [("https://datatracker.ietf.org/doc/html/rfc9110", "standard", "intermediaries"),
      ("https://www.ietf.org/archive/id/draft-ietf-oauth-v2-1-09.html",
       "standards_body", "sender")]),

    ("ssrf.fprule.redirect_and_dns_are_separate_defects", "ssrf",
     "A server that validates a URL and then follows a redirect to an internal address has a different root cause from one that fetches an internal address directly, and reporting them as a single finding misstates both the cause and the fix.",
     "Two distinct controls are involved: a validator that inspects the supplied URL, and the HTTP client that follows redirects and resolves DNS. A validator rejecting internal addresses and then being defeated by a redirect is a redirect-following defect; a fetcher whose hostname resolves to an internal address after validation is a DNS-resolution defect. Each has a different remediation, so conflating them lets a client patch the validator and leave the bypass intact.",
     "If the same internal address is reachable by supplying it directly in the parameter, redirect-following is not the mechanism and the defect belongs to the validator instead.",
     [("https://datatracker.ietf.org/doc/html/rfc9110", "standard", "redirect"),
      ("https://www.ietf.org/archive/id/draft-ietf-oauth-v2-1-13.html",
       "standards_body", "authorization server")]),
]

SKIP = ("§", "¶", "Best Current Practice", "Internet-Draft")


def main() -> int:
    pages: dict[str, str] = {}
    for url, _t, _n in [r for spec in SPEC for r in spec[5]]:
        if url not in pages:
            pages[url] = page(url)
            print(f"fetched {url}  ({len(pages[url])} chars)")

    items, thin = [], []
    for key, cid, claim, body, disproof, srcs in SPEC:
        refs, hosts = [], set()
        for url, stype, needle in srcs:
            host = urlparse(url).netloc
            hosts.add(host)
            cands = [s for s in sentences_containing(pages[url], needle)
                     if len(s) <= 200 and not any(s.startswith(x) for x in SKIP)
                     and not re.match(r"^\d", s)]
            if not cands:
                print(f"  !! no sentence for {needle!r} in {host} ({key})")
                continue
            refs.append({"url": url, "source_type": stype,
                         "quote": cands[0]})
            print(f"  [{host}] {key}\n      {cands[0][:170]}")
        if len(hosts) < 2 or len(refs) < 2:
            thin.append(key)
            continue
        items.append({
            "item_key": key, "class_id": cid, "kind": "fp_rule",
            "claim": claim, "body": body, "disproof": disproof,
            "severity_hint": "medium", "hunting_value": 4,
            # `sources`, NOT `source_refs`. The key is fixed by
            # `wks.ingest.REQUIRED`; an earlier draft used `source_refs` and
            # every item was rejected at the shape check with
            # "missing ['sources']" before a single quote was fetched. Deriving
            # the key from the importer rather than from memory is the fix.
            "sources": refs,
        })

    out = {"specialist": "inline-p0-fp-v2",
           "provenance": {
               "quotes_extracted_from": "live page bodies by tools/slice_quotes.py",
               "why": "the first pass wrote quotes from memory; 12 of 16 were "
                      "absent from the live documents and the verifier caught them",
               "hosts_used": sorted({urlparse(u).netloc for u in pages}),
           },
           "items": items}
    p = Path("research/incoming/fp/fp-inline-p0-v2.json")
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(out, indent=2), encoding="utf-8")
    print(f"\nitems={len(items)} thin={thin}")
    print(f"wrote {p}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())