# jwt — reject_fp: 21 false-positive rules, each with its disproof test

This class has the highest false-positive count in the corpus: 7 promoted `fp_rule` items plus 14 curated
`fp_case` records. The reason is structural — every observation in it is a *200* or an *error*, and both are
ambiguous without a control. Below, every rule states the trap and the **disproof test** that kills it.

---

## Part A — the three dominant traps

### A1. The algorithm the developer chose deliberately, reported as a crypto weakness

**Trap.** The scanner (or the tester) sees `HS256` and files "weak cryptography / symmetric algorithm used".
Or sees `alg:none` filtering attempts fail and files "none algorithm bypass" anyway.

**Why it is wrong.** `alg` is a deliberate deployment choice. HS256 with a strong shared secret is a sound
design, not a finding. And when the `none` obfuscation set returns 400/415 for `None`, `NONE`, whitespace and
unencoded variants, that is *filtering working* — the control is present
[jwt.fp_rule.none_alg_obfuscation_attempts_failing]. Equally, servers that string-parse to reject `alg:none` can
be bypassed with mixed capitalization, unexpected encodings, or an omitted trailing dot handling difference
[jwt.bypass.none_alg_filter_obfuscation] — but that is a *conditional* bypass, and it only exists if one of
those variants is actually honoured.

**Disproof test.** Run the full obfuscation set (case variants, `none ` with trailing space, percent/unicode
escaped header bytes, missing vs present trailing dot, alg omitted entirely). If **all** variants are rejected,
close as not vulnerable and note the library's default. If **exactly one** encoding is accepted, the finding is
real — and its impact still depends on whether that endpoint issues sessions or gates data. For the symmetric
case: the disproof is that the deployment never mixes algorithm families, i.e. no RS256 public key is ever
handed to an HMAC routine.

---

### A2. A public key used as an HMAC secret where the deployment is intentionally symmetric

**Trap.** "The API accepts tokens signed with HS256 using the RSA public key as the HMAC secret."

**Why it is usually wrong.** Two independent kills. First, the endpoint that accepted the token may also accept
no token at all — a permissive route proves nothing, and the protected endpoint in the same application
rejected the same token consistently. Algorithm-confusion proof needs a protected endpoint that rejects the
forged token as a comparison; acceptance on a route that is permissive for everyone is not a finding. Second,
the prerequisite for the confusion attack is the attacker's copy of the public key being **byte-identical** to
the server's stored copy, including PEM formatting and newlines
[jwt.prerequisite.obtainable_exact_public_key_bytes]. A key served over a JWKS endpoint is usually base64 DER,
not PEM, and the server may hold PEM — so the forgery simply fails.

**Disproof test.** Build the HS256 token from *every* published key format and every derived modulus
candidate; if all are rejected, the confusion is not reachable. Then confirm the accepted route rejects the
token-less baseline differently. And note the general disproof: every HS256 token signed with the published or
derived public key is rejected, and the server never verifies a MAC against a key whose type is public
[jwt.technique.rs256_to_hs256_public_key_hmac].

**Live field case.** A token signed HS256 with the server's published RSA public key was accepted — and then
the same token turned out to be accepted by an endpoint that also accepts no token at all. The early signal
missed was not comparing against a protected endpoint in the same application before concluding from one
permissive route.

---

### A3. An expired token rejected by the app, reported as a validation bypass

**Trap.** "The server ignores the `exp` claim because an expired token is still accepted" — where in fact the
app *rejected* it, or where the "200" was a static public shell.

**Why it is wrong.** Rejecting an expired token is the control working
[jwt.fp_rule.a_library_raising_an_error_is_a_reject_not_a_bypass]. And where a 200 did appear, the body was a
static shell identical to the token-less baseline and no session cookie was reissued — the token was parsed but
never used for the authorization decision.

**Disproof test.** Re-request with a wildly invalid `exp` value and check whether the response is
**session-bearing** or a cached public page. Expired-token acceptance must be proven by a reissued session or a
protected resource, not by a 200 on a route that returns the same body without any token. The early signal
missed was checking only the status code instead of whether a *new* session was issued.

---

## Part B — the remaining 18 rules

### B1. Unsigned token accepted, but the route was public
**Trap.** `alg:none` token returned 200 "with a valid session instead of 401".
**Disproof test.** Send the identical unsigned token with a completely random `sub`. If that also returns 200,
and a request with **no token at all** returns the same body, the route is public and never read the token.
A 200 on a modified token is only a JWT finding if the same 200 does not occur with no token at all —
capture the no-credential baseline first.
**And the sharper version:** an unsigned JWT accepted without a signature is only validated when the same
unmodified token reaches a protected endpoint carrying *no other credential*
[jwt.fprule.alg_none_acceptance_needs_a_credential_free_baseline]. Send it twice — once with no cookies and no
`Authorization`, once with the session cookie omitted. If the credential-free request 401s and only the
cookie-bearing one succeeds, nothing was proven about signature enforcement.

### B2. Attacker-signed token "accepted" on an endpoint that verifies nothing
**Trap.** A token signed with a freshly generated RSA keypair and a matching `kid` returned 200.
**Disproof test.** A malformed token, a wrongly-keyed token and a token-less request all returning the same 200
means nothing in the request path consulted the signature. Re-request the identical token with a `kid` naming a
non-existent key: if the error does not change at all, the endpoint never looked.

### B3. `kid` traversal inferred from a 500
**Trap.** `kid = ../../../../dev/null` produced 500 where a normal `kid` produced 200.
**Disproof test.** Any `kid` naming a missing file produces the same 500 — **including a nonsense name with no
traversal characters**. So the failure is a missing key file, not a traversal. A traversal claim needs a control
where only the path characters differ.

### B4. Role claim tampering "grants admin" on a shell page
**Trap.** A validly signed token with `role` changed to `admin` returned an administrative page.
**Disproof test.** Compare the actual *data* returned against a genuine admin account's response, and check
whether any state changed. If the page is an empty-list shell served identically with `role=auditor` and with
the role claim deleted entirely, it is a routing artefact. Role tampering is proven by privileged DATA or an
action, not by an admin-shaped page.

### B5. `x5u`/`jku` "fetched" but it was a cache
**Trap.** A token whose `x5u` pointed at an attacker-controlled URL was accepted, and changing the hosted key
appeared to change which key was used.
**Disproof test.** Re-host the key with a *different modulus*, re-request, and see whether the outcome tracks
your key or the original one. If both tokens continue to validate against the ORIGINAL public key, the server
used a cache and never fetched your URL. The early signal missed was changing the hosted key material before
concluding the server fetched it.

### B6. Payload edit returns 200 — but the server acted on the original identity
**Trap.** "The signature is not verified: editing the `sub` claim and resending returned 200."
**Disproof test.** Read *which identity* the response reflects. If it echoes the ORIGINAL subject, the server
re-read a trusted source such as a session store or a re-issued token. Editing a claim is only an attack if the
server acts on the edited value.

### B7. Key headers present in legitimate tokens
**Trap.** "Tokens carry `jku`, `jwk`, `x5u`, `x5c` or `kid`, so key resolution is unsafe."
**Disproof test.** Diff the headers of several legitimate tokens. If every issued token already carries `kid` and
the server still rejects a token signed with your own embedded `jwk` or fetched from your `jku` host, close as
not vulnerable — the header is being used as a selector within an already-trusted set
[jwt.fp_rule.key_headers_present_is_not_a_vuln]. A finding needs the injected key actually used for
verification.

### B8. `kid`/`jku` echoed in an error, assumed dereferenced
**Trap.** The attacker-controlled `kid` value shows up in a stack trace or error message, filed as SSRF.
**Disproof test.** Point `kid`/`jku` at a host you control and wait for a request. A value appearing in a stack
trace is not proof of an outbound fetch — many stacks echo the header while the actual key lookup uses a static
or pre-resolved set. Only a received request establishes a network sink, and the finding is only validated when
the response influences the key actually used for verification
[jwt.fprule.kid_and_jku_need_a_callback_not_reflection].

### B9. Library threw / returned an error object / fell through to anonymous
**Trap.** The absence of an exception is read as success, or an exception is read as partial success.
**Disproof test.** The observable is the protected response, not the absence of an exception
[jwt.fp_rule.a_library_raising_an_error_is_a_reject_not_a_bypass]. A library that raises on an unsupported `alg`
is doing exactly what RFC 8725 requires
[jwt.evidence.a_verification_path_that_throws_returns_a_li]. **Two documented exceptions where it IS a
bypass:** the error is swallowed but a side effect already occurred (a signature check that fails *after* a
database write, or an algorithm rejection *after* the token's claims selected a tenant or account); and the
verifier accepts `alg:none` only where unsecured JWTs are the intended design — a legitimate construct where
content is secured by a means outside the JWT, so the burden is on showing the design did not intend it.

### B10. `aud`/`iss` mutation produced no behavioural difference
**Trap.** "Changed `aud`, nothing happened, so audience validation is absent."
**Disproof test.** It proves nothing unless the token is otherwise validly signed and reaches an endpoint whose
authorization decision depends on that claim [jwt.fprule.unread_claims_prove_nothing]. Establish which claims
the app demonstrably consumes, mutate one of those, and only then attribute behaviour to claim validation. If a
mutably-signed token with a modified `aud` IS accepted by a resource belonging to a different relying party,
audience validation is genuinely absent and the finding stands.

### B11. Valid signature at the wrong resource
**Trap.** A token that verifies cryptographically at an unintended resource is filed as "the endpoint accepts
it".
**Disproof test.** Three disproofs, any of which kills it: the deployment genuinely has one resource and one
audience, so substitution is not expressible and the `aud` check has nothing to compare against; the tokens are
sender-constrained, so a token replayed by a different holder fails on the proof rather than on the audience; or
the verifier *does* check `aud`, in which case presenting a foreign-audience token and getting a 401 is the
control working [jwt.fp_rule.a_valid_signature_on_a_token_meant_for_a_different_recipient_is_not_a_pass].

### B12. Algorithm confusion claimed from "the app uses bearer tokens"
**Trap.** "The application exposes user endpoints that authenticate with bearer tokens, so algorithm confusion is
worth probing" → reported.
**Disproof test.** Send `alg:none` and the RS256-as-HS256 variant against a user endpoint and require the
response to treat the forged subject as authenticated. A shell or 404 in reply is the disproof. The early
signal missed was assuming a library that *parses* a token is a library that *trusts* its header
[jwt.fp_rule.a_library_raising_an_error_is_a_reject_not_a_bypass].

### B13–B18. Six more rules the corpus records, same shape
Each of the following is a rule where a *reachable* condition is mistaken for a *triggered* one:

| # | Trap | Disproof test |
|---|---|---|
| B13 | `kid` resolves by dereference (a 404 from the key URL read as "confirmed SSRF") | A lookup failure is a rejection. Only escalate if a reachable, attacker-controlled key location both fetches **and** is used for verification |
| B14 | Retired-but-still-published key verifies, filed as key-distribution failure | Only keys bound to the validated issuer and current key version should verify; if retired `kid` values yield a lookup failure, the control is present [jwt.technique.stale_or_foreign_kid_key_acceptance] |
| B15 | `typ` header present, filed as type-confusion protection missing | Typing only helps when the validator actually reads `typ`; existing validators often do not, so `typ` may not achieve disambiguation from existing kinds of JWTs at all [jwt.bypass.multiple_token_kinds_from_one_issuer_with_shared_validation_rules] |
| B16 | ID token obtained via authorization code flow with matching `nonce`, filed as a cross-token confusion | The finding requires reachability; an ID token obtained through the authorization code flow with a matching `nonce` generally is not reachable [jwt.bypass.multiple_token_kinds_from_one_issuer_with_shared_validation_rules] |
| B17 | Decoded claims treated as a finding | Reading JWT claims is not a finding — a signed JWT provides integrity and authenticity but not confidentiality [jwt.impact.base64_claims_disclosure_vs_integrity] |
| B18 | A 401 read as "the app tried and failed, therefore the check is weak" | The observable is the protected response, not the absence of an exception — a thrown verification path, a library error object, or an anonymous fallthrough is a rejection unless the request then serves protected data [jwt.fp_rule.a_library_raising_an_error_is_a_reject_not_a_bypass] |

---

## The meta-lesson

Every one of these 21 rules has the same shape: **a condition that is necessary was mistaken for a condition
that is sufficient.** The endpoint exists → the endpoint is protected. The header is present → the header is
obeyed. The library parsed it → the library trusted it. The token is valid → the token is meant for *me*. The
disproof in every case is a control that changes exactly one variable — and in six rules it is the *same*
control: the credential-free baseline.

I did not have a name for this before mining these items. The recurring error is treating **an artifact of the
token's existence** as **an artifact of the verifier's behaviour**. A JWT is attacker-authored input; everything
visible in it, including its own `alg`, is only ever evidence of what the attacker did, never of what the
server decided.