# Debate turn 1 — state your position

CLASS UNDER DISCUSSION: path_traversal
YOUR LENS: practitioner framing — what actually happens on the wire?

## What the corpus already knows (do not repeat it — build on or dispute it)
{
  "class_id": "path_traversal",
  "existing_items": [
    {
      "key": "path_traversal.bypass.percent_encoding_normalization_defeats_allowlist",
      "claim": "A traversal allowlist is bypassed when the filter compares the raw request path but the backend normalizes percent-encoded octets before resolving the file.",
      "kind": "bypass",
      "disproof": "If the percent-encoded form is rejected identically to the literal form, or if the backend serves neither variant outside the intended directory, no allowlist bypass exists and the payload is simply blocked."
    },
    {
      "key": "path_traversal.fprule.normalized_payload_returns_identical_content",
      "claim": "A traversal payload that returns the same content as the baseline request is not a traversal; the path was normalized or rejected before the file layer.",
      "kind": "fp_rule",
      "disproof": "If the identical response is because a CDN or reverse proxy caches by URL prefix and ignores your dot segments, then a cache-busting query parameter that still returns the outside-directory file means the traversal is real and the cache was the only thing hiding it."
    },
    {
      "key": "path_traversal.test.a_traversal_allowlist_is_bypassed_when_the_filte",
      "claim": "To decide this case, observe: Step: send the identical traversal payload twice, once with literal ../ sequences and once with percent-encoded octets for the dot and slash, and compare the response body and status against a baseline request for the same file outside the served directory.",
      "kind": "test",
      "disproof": "This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (path_traversal.bypass.percent_encoding_normalization_defeats_allowlist) states the full boundary."
    },
    {
      "key": "path_traversal.fp_rule.traversal_sequences_stripped_by_the_web_server_never_reach_the_filesystem_api",
      "claim": "A filename=../../../etc/passwd payload sent in a URL path segment or a multipart/form-data filename that the front-end web server removes before the application sees it is not path traversal, because the ../ sequence that would escape the base directory is neutralised upstream of the filesystem call and the read resolves inside the intended directory.",
      "kind": "fp_rule",
      "disproof": "The rule stops being true when a context exists in which the sequence is not stripped \u2014 a query-string or JSON body parameter, a header such as X-Forwarded-Prefix, a filename that arrives base64- or multipart-encoded and is decoded by application code, or a second proxy hop that does not normalise \u2014 because then ../ does reach the pathname constructor and the resolved path leaves the restricted directory, which is exactly the CWE-22 condition."
    },
    {
      "key": "path_traversal.validation.a_statically_served_prefix_is_not_the_same_as_a_scoped_file_handler",
      "claim": "Behaviour on a static-file prefix says nothing about a parameterised download handler, and the reverse holds too - each endpoint needs its own probe because the two are served by different code entirely.",
      "kind": "validation",
      "disproof": "The claim is false when both surfaces are served by the same confined component - a single static-file handler in front of every asset class, or a CDN or object-store gateway that applies one prefix rule to all buckets - in which case the static route's behaviour is genuinely informative about the download route. It also fails when the static surface is served by the web server itself from a document root, since the server's own path handling is a separate implementation and equally consistent across every alias it serves. And a specific finding on either endpoint still stands on its own evidence; this rule is only about the transfer of conclusions between endpoints."
    },
    {
      "key": "path_traversal.fp_rule.a_dot_component_removed_from_the_response_path_is_not_evidence_of_a_filter",
      "claim": "A response whose echoed path has ./ and ../ components stripped is consistent with normalisation by the client, the server, the framework, or the terminal - it does not by itself evidence an input filter, and it is not proof the traversal failed either.",
      "kind": "fp_rule",
      "disproof": "The claim is false when the normalisation is provably server-side and effective - you can show the request as received by the origin, for example through a request log or a reflected value that only the server could have computed, and the traversal payload in that same form still fails, which is a genuine control. It is also false where the client is not in the picture at all: a request made from a script with a raw socket, a binary body carrying the path, or a file upload field bypasses any browser canonicalisation, so evidence from that channel is not subject to this ambiguity. And a genuinely successful read is a finding regardless of how many stages normalised the string on the way in, because the read happened."
    }
  ],
  "publishers_already_cited": [
    "bishopfox.com",
    "blog.qualys.com",
    "cwe.mitre.org",
    "docs.djangoproject.com",
    "httpwg.org",
    "kernel.org",
    "man7.org",
    "owasp.org",
    "portswigger.net",
    "projectdiscovery.io",
    "raw.githubusercontent.com",
    "snyk.io"
  ]
}

## Your task
State THREE claims about path_traversal. For each:
- `claim`     — ONE falsifiable sentence naming a MECHANISM, >= 40 chars.
- `mechanism` — why it is true at the mechanism level, >= 120 chars.
- `disproof`  — the exact condition that would make it FALSE.
- `confidence`- high | medium | low
- `novelty`   — state plainly whether the corpus ALREADY covers this
                (say which item_key) or whether it is NEW.

Pick at least ONE claim you believe the others will dispute. Flag it with
`DISPUTE:` and say what the opposing view would be.

Rank your claims by how confident you are. If you are unsure, say so — an
honest "medium" is worth more than a confident invention.

## OUTPUT FORMAT — read carefully, this has broken three rounds
**Do NOT write any file.** Do not create claims.json or anything else. Writing
outside the project directory is auto-rejected by permission on this host, and
an earlier attempt died on exactly that (`Write /tmp/claims.json failed`).

Instead, print your claims **inline in your reply**, like this:

CLAIM 1
claim: <one falsifiable sentence, >= 40 chars>
mechanism: <why it is true, >= 120 chars>
disproof: <the exact condition that would make it FALSE>
confidence: high | medium | low
novelty: NEW | or the item_key in the corpus that already covers this
DISPUTE: <only on the claim you think others will attack; say what the opposing
view would be>

CLAIM 2
...

Repeat the block for each claim. Plain text only — no JSON, no files.
