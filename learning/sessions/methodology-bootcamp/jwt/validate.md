# jwt — validate: the request/response pair that proves impact, and what does not count

## The proof shape

Validation of this class requires demonstrating that the verifier **accepted an attacker-signed token and
acted on the identity it carried**. The evidence is one request and one response, captured verbatim, plus the
negative control that makes it interpretable.

```
# CONTROL — establishes the endpoint is token-governed at all
GET /api/v1/me HTTP/1.1
Host: app.example
(no Authorization header, no cookies)

-> HTTP/1.1 401
   (no Set-Cookie, no user body)

# CONTROL 2 — an unmodified, legitimately issued token works
GET /api/v1/me HTTP/1.1
Host: app.example
Authorization: Bearer <captured.valid.token>

-> HTTP/1.1 200
   Set-Cookie: session=<established>; HttpOnly
   {"sub":"<the real holder of that token>", ...}

# PROOF — the forged token, same endpoint, nothing else changed
GET /api/v1/me HTTP/1.1
Host: app.example
Authorization: Bearer <forged: alg none | HS256-with-pubkey | own-key, sub="victim">

-> HTTP/1.1 200                       <-- NOT a proof on its own
   Set-Cookie: session=<established>; HttpOnly     <-- this is the proof
   {"sub":"victim", "email":"victim@example.com"}   <-- or this: another user's data
```

The proof lives in the **response to the forged request**, and it must contain at least one of: a `Set-Cookie`
establishing a session, another user's data in the body, or a privileged action's effect. The forged request
must carry only the token and no other credential, reaching a resource that a credential-less request
demonstrably cannot [jwt.fprule.alg_none_acceptance_needs_a_credential_free_baseline]. For the `alg:none`
family specifically, this matters because a library may ignore `alg=none`
yet still require a session cookie or CSRF token on that route, and if your 401 was the missing CSRF cookie you
proved nothing about signature enforcement. The distinction is between a parser accepting a token shape and an
authorizer granting access.

## What does NOT count as proof

**1. A 200 on a modified token.** Only a JWT finding if the same 200 does not occur with no token at all. A
malformed token, a wrongly-keyed token and a token-less request all returning the same 200 means the endpoint
never verified anything.

**2. A 401/403 on a forged token, read as "the library processed it".** A verification path that throws, returns
a library error object, or falls through to an anonymous identity is a rejection unless the request then
proceeds to the protected resource [jwt.fp_rule.a_library_raising_an_error_is_a_reject_not_a_bypass], and the
all-variants-rejected outcome is what a verifier with a server-side allowlist looks like
[jwt.validation.algorithm_allowlist_is_the_only_test_that_distinguishes_a_rejecting_verifier].

**3. A stack trace or echoed header.** A library that raises on an unsupported `alg` is doing exactly what
the spec requires, and a tester who reads a stack trace in the response body as partial success has inverted the
meaning [jwt.evidence.a_verification_path_that_throws_returns_a_li]. For `kid`/`jku` a value appearing in an
error message is not proof of an outbound fetch either
[jwt.fprule.kid_and_jku_need_a_callback_not_reflection].

**4. Decoded claims.** Reading JWT claims is not a finding; a signed JWT provides integrity and authenticity but
not confidentiality, so only forgery or failed verification is a vulnerability
[jwt.impact.base64_claims_disclosure_vs_integrity]. "I read the role claim" proves nothing.

**5. A 200 whose body echoes the ORIGINAL subject.** Editing a claim is only an attack if the server acts on
the edited value. If the response still reflects the original identity, the claims are not the source of truth.

**6. A `kid`/traversal 500 with no control.** A traversal claim needs a control where only the path characters
differ; an identical error for a plain missing filename is a missing-file error.

**7. A `jku` acceptance with no re-host.** A remote-key header is only proven fetched when *changing the hosted
key* changes the validation outcome; unchanged behaviour proves a cache or a hardcoded key.

**8. A mutably-signed token accepted with a modified `aud` where the endpoint does not depend on that claim.**
Changing a claim the server never reads yields identical behaviour whether validation is correct or entirely
missing [jwt.fprule.unread_claims_prove_nothing].

**9. Presence of key headers.** The mere presence of `jku`, `jwk`, `x5u`, `x5c` or `kid` in legitimately issued
tokens is normal key selection, not a vulnerability; only unauthenticated resolution is
[jwt.fp_rule.key_headers_present_is_not_a_vuln].

## The pass/fail condition for the verifier itself

The pass condition is that it rejects every algorithm outside the application's allow-list, which requires the
library to pin the accepted set rather than read `alg` from the token and dispatch on it
[jwt.validation.algorithm_allowlist_is_the_only_test_that_distinguishes_a_rejecting_verifier]. Two
documented ways a verifier passes without pinning `alg` in code: the algorithm set is restricted *by
deployment* (a server-side JOSE header with the field stripped or normalised before verification, or an
HSM/provider API accepting only one algorithm identifier), and the key itself is type-bound — a key usable with
exactly one algorithm prevents the confusion regardless of what the header says.

## Impact statement: forgery, not disclosure

The pass condition I am proving leads to a specific impact shape. A verified forgery becomes account takeover,
not info disclosure, only when the edited claim drives server-side identity or authorization decisions; if the
forged token is accepted syntactically but the server re-derives identity from server-side session state, or the
edited claim grants no additional access, there is no impact to report
[jwt.chain_link.forgery_to_account_takeover]. The escalation target is impersonation: the attacker
authenticates as an arbitrary account and inherits that user's data, sessions and any administrative privileges
attached to the role. My report must show the *privileged data or the action*, not merely an admin-shaped page —
a shell that renders identically for every role is a routing artefact.

## Recording the validation

For each candidate finding I record: the exact forged token, the exact endpoint, the credential-free baseline
response, the forged response, and which acceptance observable fired. A finding without the baseline pair is not
validated, regardless of how convincing the 200 looks.