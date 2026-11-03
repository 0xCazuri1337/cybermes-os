# jwt — failure analysis: expected vs actual vs wrong assumption vs next test

Two real failures from this class, taken from the corpus's own field records. I am recording both because they
are different species of mistake, and the second one is the one that actually cost the most.

---

## Failure 1 — the 200 that meant nothing

**Expected.** `kid` set to `../../../../dev/null` produced HTTP 500 while a normal `kid` produced 200. I expected
that this proved `kid` was being interpolated into a filesystem path, i.e. that the key-selection step of
[jwt.technique.kid_path_traversal_empty_file_secret] was reachable, and that pointing `kid` at an empty file
would yield a known zero-length HMAC secret I could sign with.

**Actual.** Every `kid` naming a missing file produced the same 500 — **including a nonsense name containing no
traversal characters at all**. The 500 was a missing key file, not a traversal. There was no path
interpolation to exploit, and the empty-file trick was unreachable because nothing was reading a path.

**Wrong assumption.** I assumed that *a difference in behaviour between two `kid` values implies the `kid` value
is used as a path*. The actual requirement is much narrower: a difference implies the value is used **as a
path**, not merely that two different values fail differently. A missing-file error is a *uniform* failure that
looks like a differential failure if you never run the single control that distinguishes them. My control was
missing because I treated "traversal-looking characters" as the variable being tested, when the variable that
mattered was "does the error differ from a plain missing name".

**Next test.** Always run a third arm that changes nothing but the path-ness: a `kid` that certainly does not
exist, with no traversal characters. A traversal claim needs a control where only the path characters differ; an
identical error for a plain missing filename is a missing-file error, not traversal. The general lesson is that
a negative control must isolate **one** variable — and in a header-selection test, "does the file exist" and
"does the value contain traversal characters" are two variables, and I varied the wrong one alone.

---

## Failure 2 — the algorithm the developer chose on purpose

This is the dominant false positive in this class, and the failure is not a technical error. It is a
category error, made twice.

**Expected.** The application issued RS256 tokens and exposed a JWKS endpoint, which made the RS256->HS256 type
binding the obvious thing to try. I built a token signed HS256 with the server's published RSA public key as the
HMAC secret and sent it to the API. **It was accepted with HTTP 200.**

**Actual.** The very same token was accepted by an endpoint that also accepts **no token at all**, and the
protected endpoint in the same application rejected it consistently. Later, on a different target, I also
reported "HS256 in use = weak cryptography" and "tokens carry `kid`/`jku`, therefore key resolution is unsafe" —
both of which are non-findings by construction.

**Wrong assumption.** Three assumptions, in increasing order of how much they cost:

1. **That acceptance implied the confusion technique worked.** Acceptance on a route permissive for everyone
   says nothing about the verifier. Algorithm-confusion proof needs a *protected* endpoint that rejects the
   forged token as a comparison; the credential-free baseline is the control I skipped.
2. **That a symmetric algorithm is a defect.** HS256 with a strong shared secret is a deliberate design choice.
   The class reaches symmetric deployments only through the type binding
   [jwt.technique.rs256_to_hs256_public_key_hmac], which requires an *asymmetric* deployment to exist at all. A
   report that flags "symmetric crypto" without a demonstrated path from it to forgery is reporting a
   preference, not a vulnerability.
3. **That a token field existing means the verifier obeys it.** `kid`, `jku`, `jwk`, `x5u` and `x5c` in
   legitimately issued tokens is normal key selection; only unauthenticated resolution is
   [jwt.fp_rule.key_headers_present_is_not_a_vuln]. `kid` is a selector, not a control — and "the tokens do not
   pin `kid`" is not a finding even when true, because missing `kid` pinning breaks nothing by itself.

The root error behind all three: **I treated an artifact of the token's existence as an artifact of the
verifier's behaviour.** A JWT is attacker-authored input. Everything visible in it — including its own `alg` —
is evidence of what the attacker did, never of what the server decided.

**Next test.** Re-run with the credential-free baseline first and the protected endpoint second, and require the
forged token to be rejected by at least one protected endpoint as the comparison
[jwt.fp_rule.a_library_raising_an_error_is_a_reject_not_a_bypass]. For the header-presence question, the test is differential not
declarative: diff the headers of several legitimate tokens, then present one signed with an attacker-supplied
`jwk` and one fetched from an attacker `jku` host. If both are rejected while the server verifies against its own
preconfigured set, close as not vulnerable — the header is a selector within an already-trusted set.

---

## Failure 3 — a 401 read as a bypass, and the asymmetry I did not see

**Expected.** A token with `exp` six months in the past returned HTTP 200. I expected this to demonstrate that
`exp` is not enforced — a genuine finding, the "signature valid but claims unchecked" case from
`interpret.md`.

**Actual.** The response was a static public shell identical to the token-less baseline, and the session cookie
was never reissued. The token had been *parsed* but was not used for the authorization decision. Separately, in
another run, an expired token was **rejected** — and I initially wrote that up as "the app rejects expired tokens,
which suggests its validation is inconsistent", which is the same error inverted: a rejection is the control
working and needs no explanation at all
[jwt.fp_rule.a_library_raising_an_error_is_a_reject_not_a_bypass].

**Wrong assumption.** I used the status code as the observable. The real observables are **which identity the
server acted on** and **whether a session was issued**. "200" was never in question as a signal — a public shell
returns 200. The assumption that the endpoint consumed my token at all was the untested one, and it is the same
assumption behind both failure 1 and failure 2.

**Next test.** Expired-token acceptance must be proven by a reissued session or a protected resource, not by a
200 on a route that returns the same body without any token. The paired test is to read the response's identity,
not its status: editing a claim is only an attack if the server acts on the edited value; if the response still
reflects the original identity, the claims are not the source of truth.

---

## What I changed, and the rule it produced

Three tests now run before anything else in this class, and each of them is a disproof test surfaced from a
corpus `fp_case` record rather than from my own reasoning:

1. **Credential-free baseline.** No token, malformed token, valid token, on the target endpoint — before any
   forged token is sent. [jwt.fprule.alg_none_acceptance_needs_a_credential_free_baseline]
2. **Single-variable control for whatever I am claiming.** Plain missing `kid` before traversal `kid`; re-hosted
   key before "the URL was fetched"; protected endpoint before "the forgery worked".
   [jwt.fprule.kid_and_jku_need_a_callback_not_reflection]
3. **Read the identity, not the status.** Which `sub` does the response reflect, and did a `Set-Cookie` appear?
   Nothing else counts as an acceptance observable.
   [jwt.fprule.alg_none_acceptance_needs_a_credential_free_baseline]

The gap these three close is the same in all three failures: I had no falsifier attached to my probe, so a
result that was consistent with "the verifier is fine" and with "the verifier is broken" was read as the
latter, because that was the hypothesis I was testing. That is the error the class teaches more than any other —
and the corpus already encodes the correction, in 21 separate places, every one of which is a control I used to
skip.