<!-- GENERATED from db/wks.db — do not edit -->
# JWT / Token Validation Failures

## Definition

The application fails to verify a token's signature, algorithm or claims before making an authorization decision.

- **CWE:** CWE-347
- **OWASP:** API8:2023
- **Surface:** identity
- **Aliases:** ["jwt", "algorithm confusion", "none algorithm attack", "jwk injection", "token signature not verified", "kid injection"]

Canonical home for `jwt`. Rendered from `db/wks.db` by `tools/taxonomy/build_taxonomy.py` — edit the rows, not this file.

## Root Cause

Not yet researched.

## Preconditions

**Algorithm confusion is only possible when the verifier's key/algorithm choice is taken from the attacker-controlled `alg` header rather than a server-side allowlist bound to the key.**

Confirm the deployment verifies JWTs with an algorithm-agnostic API that reads `alg` from the token header and hands one fixed key object to it (the classic `verify(token, publicKey)` pattern). In a black-box engagement, the observable signature is asymmetric: a token whose `alg` was flipped from RS256 to HS256 returns 200/302 or an authenticated response instead of an 'invalid signature' error. If every non-RSA alg is rejected outright, the prerequisite is absent and the finding is not a bug.

*Disproof:* An RS256->HS256 token signed with the server's public key is rejected with an explicit signature/algorithm error on every attempt, including HS384/HS512 variants.

**A successful RS256-to-HS256 forgery requires the attacker's copy of the public key to be byte-identical to the server's stored copy, including PEM formatting and newlines.**

Enumerate key material before attempting forgery: hit `/.well-known/jwks.json`, `/jwks.json`, OIDC discovery documents, JWKS endpoints advertised in `.well-known/openid-configuration`, and any key cached in a JS bundle. Convert JWK to X.509 PEM and, if the app stores PKCS#1 or SSH-format keys, try each. If no key is published, derive candidate moduli from two RS256 tokens and replay one forged token per candidate. If none is accepted, report the key as not obtainable, not as confirmed-safe.

*Disproof:* A single attacker-signed HS256 token built from every published key format and every derived modulus candidate is rejected by the server.

## Attack Surface

Surface: **identity**.

The entry points and enabling conditions for this surface are enumerated under **Preconditions**; the observable signals are under **Detection**.

## Detection

**A server that accepts a token signed with a key you supplied inside the token itself (jwk, jku, x5u, x5c) is resolving its trust anchor from unauthenticated token input.**

Baseline first: capture a legitimate token and note whether it already carries `jwk`, `jku`, `x5u` or `x5c`. Generate your own RSA keypair, re-sign a modified payload, and add each header in turn (`jwk` embedded, `jku` pointing at a host you control serving a JWK Set, `x5c` with a self-signed chain). Also enumerate the server's own JWKS: multiple `kid` values, retired keys still published, or keys from other issuers indicate a weak trust boundary.

*Disproof:* Every attacker-supplied key location is ignored, and the server verifies only against keys it resolved out of band from its own pinned or discovered key set.

**The JWT header is client-readable and names the algorithm used for signing, which makes the alg value the first field to inspect and the first one to tamper with.**

The JWT header is client-readable and names the algorithm used for signing, which makes the alg value the first field to inspect and the first one to tamper with.

HackTricks reference: jwt (https://kathan19.gitbook.io/howtohunt/jwt-attack/jwt.md)

*Disproof:* The server ignores the alg stated in the header and validates only tokens it verifies against its own pinned key, so changing alg has no effect.

**The JWT header is client-readable and names the algorithm used for signing, which makes the alg value the first field to inspect and the first one to tamper with.**

The JWT header is client-readable and names the algorithm used for signing, which makes the alg value the first field to inspect and the first one to tamper with.

HackTricks reference: jwt (https://kathan19.gitbook.io/howtohunt/jwt-attack/jwt.md)

*Disproof:* The server ignores the alg stated in the header and validates only tokens it verifies against its own pinned key, so changing alg has no effect.

**A token with header `{"alg":"none"}` (and, correctly formed, a trailing dot and empty signature) that the server honours indicates the verifier accepts unsecured JWTs.**

Base64url-decode the header of every token the target issues, record the `alg` value used in production, then replay a token with `alg` set to `none`, empty signature, and payload claims you control (flip `sub`, `isAdmin`, or `role`). Send it to the same endpoint that issued the session. Treat acceptance as the signal; a 401/403 is the expected-rejection baseline you must record before escalating anything.

*Disproof:* The `alg:none` token is rejected with 401/403 or an 'invalid signature' response, identical to a token whose payload was tampered with.

**A convincing observation for this class is: Define acceptance before testing: HTTP 200, a redirect into an authenticated area, a Set-Cookie establishing a session, or an API response body containing another user's data.**

Derived from jwt.validation.rejection_is_not_a_finding, which states the boundary for this class. The observation above is what a report must contain to be believed: an artifact the reviewer can re-check, not a claim the hunter asserts. A finding without it is an assertion.

*Disproof:* Not evidence when the observable cannot be produced at all -- blind, server-side-only, or identical-in-every-case behaviour leaves nothing to show. The originating rule (jwt.validation.rejection_is_not_a_finding) states the full boundary.

**A convincing observation for this class is: The first is the exception: a library that raises on an unsupported alg is doing exactly what RFC 8725 requires, and a tester who reads a stack trace in the response body as partial success has inverted the meaning.**

Derived from jwt.fp_rule.a_library_raising_an_error_is_a_reject_not_a_bypass, which states the boundary for this class. The observation above is what a report must contain to be believed: an artifact the reviewer can re-check, not a claim the hunter asserts. A finding without it is an assertion.

*Disproof:* Not evidence when the observable cannot be produced at all -- blind, server-side-only, or identical-in-every-case behaviour leaves nothing to show. The originating rule (jwt.fp_rule.a_library_raising_an_error_is_a_reject_not_a_bypass) states the full boundary.

## Exploitation

**When `kid` selects a key from the filesystem and symmetric algorithms are allowed, pointing `kid` at an empty file gives a known zero-length HMAC secret.**

Set `kid` to traversal payloads (`../../dev/null`, absolute paths, URL-encoded variants) and sign with the empty string as the MAC secret. Then try SQL/LDAP payloads in `kid` if keys live in a database. The empty-file case succeeds only when the server reads `kid` as a path AND accepts HS256 with that file's contents as the secret; capture the accepted request verbatim to prove both halves.

*Disproof:* Traversal payloads produce an error or fall back to a default key, and the same forged token is rejected on replay.

**Re-signing a modified payload with HS256 using the server's own RSA public key as the HMAC secret yields a token the confused verifier accepts.**

Obtain the public key, convert to the server's storage format, set the header `alg` to HS256, edit the payload (identity or role claim), and sign with the PEM as the HMAC secret. Where no key is published, run sig2n-style derivation over two RS256 tokens from the same issuer, emit a forged token per candidate modulus, and replay each in Repeater; only one is accepted, and that key then completes the confusion attack. Record the exact request/response pair as proof.

*Disproof:* Every HS256 token signed with the published or derived public key is rejected, and the server never verifies a MAC against a key whose type is public.

**A verifier that resolves the key by header `kid`/`jku` against a multi-key set still accepts tokens signed with retired-but-still-published keys or keys belonging to another trusted issuer.**

Pull the full JWKS and enumerate every `kid` (current, previous, partner-tenant, self-service). Mint a token naming a retired `kid` and re-sign with the corresponding private key if you hold one, or present a legitimately issued token that carries a foreign `kid` at an endpoint that does not scope keys to its own issuer. For `jku`, host your own JWK Set and exploit URL-parsing filter discrepancies (userinfo, redirect, path tricks) to get the server to fetch it.

*Disproof:* Only keys bound to the validated issuer and current key version verify; retired and foreign `kid` values yield a lookup failure and a rejected token.

## Variations

**When one issuer mints more than one kind of JWT, the validation rules for those kinds must be mutually exclusive; overlapping rule sets let a token of one kind be presented where another kind is expected.**

RFC 8725 calls this cross-JWT confusion and treats it as a specific type of substitution attack: as JWTs are used by more different protocols in diverse application areas, it becomes increasingly important to prevent cases of JWT tokens issued for one purpose being subverted and used for another. The mitigation the spec names is not a new crypto primitive but rule separation - when more than one kind of JWT can be issued by the same issuer, the validation rules MUST be mutually exclusive, rejecting JWTs of the wrong kind - implemented through explicit typing with distinct typ values, different required claims or claim values, or different required header parameters. For the hunter this names a concrete target: enumerate every token endpoint on the issuer, collect one sample of each token kind, and present each to every consuming endpoint. The realistic exploit is an ID token replayed as an access token, or a refresh-shaped token accepted by an API, where both are signed by the same key and the API's validator does not require the claims that would distinguish them.

*Disproof:* The claim is false when the token kinds are already separated by the very mechanisms the spec lists - distinct key sets, distinct issuers, distinct audiences, or a validator that enforces a required claim set unique to one kind, in which case the wrong-kind token is rejected by design. It is also false where explicit typing is in force and enforced: RFC 8725 notes the caveat that typ may not achieve disambiguation from existing kinds of JWTs because the validation rules for existing kinds often do not use the typ value, so typing only helps when the validator actually reads it. And the finding requires reachability - the confused token has to be obtainable by the attacker, which an ID token obtained through the authorization code flow with a matching nonce generally is not.

**Servers that string-parse to reject `alg: none` can be bypassed with mixed capitalization, unexpected encodings, or an omitted trailing dot handling difference.**

Iterate over case variants (`none`, `None`, `NONE`, `nOnE`), encodings (URL-encoded, unicode-escaped, duplicate JSON `alg` keys), and header-shape variants (empty signature with and without the trailing dot, signature set to garbage). One accepted variant converts a rejected probe into full token forgery. Test on the same endpoint that issued the session, since some deployments only validate alg on refresh or logout paths.

*Disproof:* All case and encoding variants of the `none` header are rejected identically to a well-formed signature error, and no variant authenticates.

## Technology / Framework Considerations

Not yet researched.

## API Considerations

Not yet researched.

## Attack Chains

- `jwt-weak-verification-to-impersonation` — jwt-weak-verification-to-impersonation (goal: `account_takeover`)

## Real-World Examples

Not yet researched.

## Common False Positives

**A verification path that throws, returns a library error object, or falls through to an anonymous identity is a rejection unless the request then proceeds to the protected resource - the observable is the protected response, not the absence of an exception.**

Two failure modes get mislabelled. The first is the exception: a library that raises on an unsupported alg is doing exactly what RFC 8725 requires, and a tester who reads a stack trace in the response body as partial success has inverted the meaning. The second is the fallthrough: verification fails, the code does not stop, and the handler proceeds with whatever identity is in scope - which is a real finding, but it must be demonstrated by the protected resource returning its data, not by observing that the error path was taken. RFC 8725's requirement is worded for exactly this: all cryptographic operations used in the JWT MUST be validated and the entire JWT MUST be rejected if any of them fail, including nested JWTs where both outer and inner operations must be validated. 'Rejected' in the specification means the resource is not served. Report the protected response body as the evidence, and quote the error only as an explanation of why the request failed.

*Disproof:* The claim is false if the fallthrough path does serve protected data - that is precisely the bypass, and the observable becomes the returned resource. It is also false when the error is swallowed but a side effect has already occurred, for example a signature check that fails after a database write, or an algorithm rejection that happens after the token's claims have been used to select a tenant or an account. And the strictness of 'the entire JWT must be rejected' has a documented exception in the spec's own framing for unsecured JWTs, which are legitimately created for use cases where the content is secured by a means outside the JWT, so a verifier that accepts alg none only where that is the intended design is not in violation - the burden is on showing the design did not intend it.

**A JWT that verifies cryptographically at an unintended resource is not evidence that the endpoint accepts it; RFC 8725 requires the audience to be present and associated with the recipient, and absence of aud must be a rejection.**

This is the substitution attack and it is the most under-reported JWT finding because the tester stops at signature validity. RFC 8725 describes the mechanism as one recipient being given a JWT intended for it and then attempting to use it at a different recipient for which it was not intended, and it names the mitigation unambiguously: the relying party MUST validate the audience value, and if the audience value is not present or not associated with the recipient, it MUST reject the JWT. So the pass condition has two halves - the signature verifies AND the aud claim names this resource - and a report that only shows the first half is incomplete at best. The field test is to take a token legitimately minted for resource A and present it to resource B with an identical signature check, changing nothing but the destination. In the field the practical variant is the ID-token/access-token confusion, where two token kinds from one issuer share a key and differ only in claims.

*Disproof:* The claim is false when the deployment genuinely has one resource and one audience, in which case substitution is not expressible and the aud check has nothing to compare against - a single-recipient system is not vulnerable to this attack. It is also false when the tokens are sender-constrained: RFC 9700 describes sender-constrained access tokens as scoping an access token's applicability to a certain sender, one obliged to demonstrate knowledge of a certain secret as a prerequisite for acceptance, so a token replayed by a different holder fails on the proof, not on the audience. And where the verifier does check aud, the finding is simply false: presenting a foreign-audience token and getting a 401 is the control working.

**The mere presence of `jku`, `jwk`, `x5u`, `x5c` or `kid` in legitimately issued tokens is normal key selection, not a vulnerability; only unauthenticated resolution is.**

Diff the headers of several legitimate tokens before flagging. If every issued token already carries `kid` and the server still rejects a token signed with your own embedded `jwk` or fetched from your `jku` host, close as not vulnerable - the header is being used as a selector within an already-trusted set. A finding needs the injected key actually used for verification, proven by your forged token being accepted.

*Disproof:* Attacker-supplied `jwk`, `jku` and `x5u` key locations are ignored while the server verifies against its own preconfigured key set.

**Reportable only if a none-alg token is actually honoured; 400/415 responses to `None`, `NONE`, whitespace or unencoded variants are filtering working.**

Before reporting, run the full obfuscation set (case variants, `none ` with trailing space, percent/unicode-escaped header bytes, missing vs present trailing dot, alg omitted entirely). If all variants are rejected, close the item as not vulnerable and note the library's default. If exactly one encoding is accepted, the finding is real but the impact still depends on whether that endpoint issues sessions or gates data.

*Disproof:* Every `alg:none` variant, including malformed and case-varied headers, returns a client error and never an authenticated response.

**An unsigned JWT accepted without a signature is only a validated finding when the same unmodified token reaches a protected endpoint carrying no other credential, because a library may ignore alg=none yet still require a session cookie or CSRF token on that route.**

Send the unsigned token twice: once with no cookies and no Authorization header, once with a valid session cookie omitted. If the credential-free request returns 401 and only the cookie-bearing one succeeds, nothing was proven about signature enforcement. The distinction is between a parser accepting a token shape and an authorizer granting access.

*Disproof:* If a request carrying ONLY the unsigned token and no other credential reaches a resource that a credential-less request demonstrably cannot, signature enforcement is absent and the finding is real.

**A finding that a kid or jku header value reaches an outbound request is only validated when an attacker-controlled server actually receives the callback, because the header may be parsed, logged and echoed without ever being dereferenced.**

Point kid or jku at a host you control and wait for a request. A value appearing in a stack trace or an error message is not proof of an outbound fetch: many stacks echo the header while the actual key lookup uses a static or pre-resolved key set. Only a received request establishes that the value reached a network sink, and without one the SSRF claim rests on reflection alone.

*Disproof:* If a request carrying the attacker-controlled kid value arrives at the designated server and the response influences the key actually used for verification, the header is dereferenced and the finding is real.

**Changing an aud or iss claim and observing no behavioural difference is NOT evidence that audience validation is absent, unless the token is otherwise validly signed and reaches an endpoint whose authorization decision depends on that claim.**

Audience confusion is a finding only when the relying party fails to check the claim it was supposed to check. Modifying a claim the server never reads yields identical behaviour whether validation is correct or entirely missing, so the observation carries no information. Establish which claims the app demonstrably consumes, mutate one of those, and only then attribute behaviour to claim validation.

*Disproof:* If a mutably-signed token carrying a modified aud claim is accepted by a resource belonging to a different relying party, audience validation is genuinely absent and the finding stands.
**Hypothesis:** A forged token with alg:none or an RS256-to-HS256 substitution is accepted, therefore the application is vulnerable to JWT algorithm confusion
- Invalidated by: No forged identity was accepted. Responses were the application shell or 404, and the service never treated the forged subject as authenticated
- **Rejection rule:** Algorithm confusion requires a forged token to be ACCEPTED as a valid identity. Send alg:none and the RS256-as-HS256 variant against a user endpoint and require the response to treat the forged subject as authenticated; a shell or 404 in reply is the disproof

**Hypothesis:** Role claim tampering grants admin because a user-role token with role admin is honoured
- Invalidated by: The user-role token returned the same administrative page shell as before with an empty user list, and the identical page was served with a role of auditor and with the role claim deleted entirely
- **Rejection rule:** Role tampering is proven by privileged DATA or an action, not by an admin-shaped page; a shell that renders identically for every role is a routing artefact

**Hypothesis:** Signature verification is broken because a token signed with an attacker key is accepted
- Invalidated by: The server returned the same 200 and the same body for the valid-looking token, an invalid one, and no token, so nothing in the request path consulted the signature
- **Rejection rule:** Forged-token acceptance needs a negative control: if a malformed, a wrongly-keyed and a token-less request all return the same 200, the endpoint never verified anything

**Hypothesis:** The API accepts tokens signed with the HS256 algorithm using the RSA public key as the HMAC secret
- Invalidated by: The very same token was accepted by an endpoint that also accepts no token at all, and the protected endpoint in the same application rejected it consistently
- **Rejection rule:** Algorithm-confusion proof needs a protected endpoint that rejects the forged token; acceptance on a route that is permissive for everyone is not a finding

**Hypothesis:** The jwk x5u header is exploitable because a token referencing an attacker-hosted key is accepted
- Invalidated by: After re-hosting, both tokens continued to validate against the ORIGINAL public key, showing the server used a cached key and never fetched the attacker's URL at all
- **Rejection rule:** A remote-key header is only proven fetched when changing the hosted key changes the validation outcome; unchanged behaviour proves a cache or a hardcoded key

**Hypothesis:** The kid header is injectable because a path traversal value caused a different error
- Invalidated by: Any kid naming a missing file produced the same 500, including a nonsense name with no traversal characters, so the failure is a missing key file and not a traversal
- **Rejection rule:** A traversal claim needs a control where only the path characters differ; an identical error for a plain missing filename is a missing-file error, not traversal

**Hypothesis:** The server accepts unsigned tokens because a token with alg set to none is honoured
- Invalidated by: The identical unsigned token was also accepted with a completely random subject claim, and the endpoint returned the same body for a request with no token at all - the route is public and never read the token
- **Rejection rule:** A 200 on a modified token is only a JWT finding if the same 200 does not occur with no token at all; always capture the no-credential baseline for the endpoint first

**Hypothesis:** The server ignores the exp claim because an expired token is still accepted
- Invalidated by: The response was a static public shell identical to the token-less baseline, and the session cookie was never reissued, so the token was parsed but not used for the authorization decision
- **Rejection rule:** Expired-token acceptance must be proven by a reissued session or a protected resource, not by a 200 on a route that returns the same body without any token

**Hypothesis:** The token signature is not verified because altering the payload without re-signing still works
- Invalidated by: The response echoed the ORIGINAL subject, not the edited one, proving the server re-read a trusted source such as a session store or a re-issued token rather than trusting the presented claims
- **Rejection rule:** Editing a claim is only an attack if the server ACTS on the edited value; if the response still reflects the original identity, the claims are not the source of truth

**Hypothesis:** The mere presence of `jku`, `jwk`, `x5u`, `x5c` or `kid` in legitimately issued tokens is normal key selection, not a vulnerability; only unauthenticated resolution is.
- Invalidated by: Attacker-supplied `jwk`, `jku` and `x5u` key locations are ignored while the server verifies against its own preconfigured key set.
- **Rejection rule:** The mere presence of `jku`, `jwk`, `x5u`, `x5c` or `kid` in legitimately issued tokens is normal key selection, not a vulnerability; only unauthenticated resolution is.

**Hypothesis:** Reportable only if a none-alg token is actually honoured; 400/415 responses to `None`, `NONE`, whitespace or unencoded variants are filtering working.
- Invalidated by: Every `alg:none` variant, including malformed and case-varied headers, returns a client error and never an authenticated response.
- **Rejection rule:** Reportable only if a none-alg token is actually honoured; 400/415 responses to `None`, `NONE`, whitespace or unencoded variants are filtering working.

**Hypothesis:** An unsigned JWT accepted without a signature is only a validated finding when the same unmodified token reaches a protected endpoint carrying no other credential, because a library may ignore alg=none yet still require a session cookie or CSRF token on that route.
- Invalidated by: If a request carrying ONLY the unsigned token and no other credential reaches a resource that a credential-less request demonstrably cannot, signature enforcement is absent and the finding is real.
- **Rejection rule:** An unsigned JWT accepted without a signature is only a validated finding when the same unmodified token reaches a protected endpoint carrying no other credential, because a library may ignore alg=none yet still require a session cookie or CSRF token on that route.

**Hypothesis:** A finding that a kid or jku header value reaches an outbound request is only validated when an attacker-controlled server actually receives the callback, because the header may be parsed, logged and echoed without ever being dereferenced.
- Invalidated by: If a request carrying the attacker-controlled kid value arrives at the designated server and the response influences the key actually used for verification, the header is dereferenced and the finding is real.
- **Rejection rule:** A finding that a kid or jku header value reaches an outbound request is only validated when an attacker-controlled server actually receives the callback, because the header may be parsed, logged and echoed without ever being dereferenced.

**Hypothesis:** Changing an aud or iss claim and observing no behavioural difference is NOT evidence that audience validation is absent, unless the token is otherwise validly signed and reaches an endpoint whose authorization decision depends on that claim.
- Invalidated by: If a mutably-signed token carrying a modified aud claim is accepted by a resource belonging to a different relying party, audience validation is genuinely absent and the finding stands.
- **Rejection rule:** Changing an aud or iss claim and observing no behavioural difference is NOT evidence that audience validation is absent, unless the token is otherwise validly signed and reaches an endpoint whose authorization decision depends on that claim.

## Validation

**The pass condition for a verifier is that it rejects every algorithm outside the application's allow-list, which requires the library to pin the accepted set rather than read alg from the token and dispatch on it.**

RFC 8725 states the requirement as a library obligation, not an application preference: libraries MUST enable the caller to specify a supported set of algorithms and MUST NOT use any other algorithms, and the library MUST ensure the alg or enc header specifies the same algorithm actually used for the cryptographic operation. The second clause is the one that matters for testing, because a verifier that correctly rejects an unsupported alg but then performs the operation with a different algorithm than the header names is still broken. The validation design follows from that: hold the key fixed, hold the claims fixed, vary only the alg header across none, HS256, RS256, HS384, HS512, and a non-existent name, and record the response for each. RFC 7519 adds the independent application-level rule that even a successfully validated JWT SHOULD be rejected unless the algorithms used are acceptable to the application - so a 200 on an alg you did not expect is a finding regardless of whether the signature checked out.

*Disproof:* The claim is false if the verifier restricts the algorithm set by deployment rather than by request - a JOSE header that is built server-side and the header field stripped or normalised before verification, or an HSM/provider API that accepts only one algorithm identifier. It is also false when the key itself is type-bound, since a key usable with exactly one algorithm (the rule RFC 8725 also states) prevents the confusion regardless of what the header says. And a rejection test needs a credential-free baseline: if your modified token is refused because the session expired or the CSRF cookie is missing, the 401 proves nothing about algorithm handling - the control must be re-run with a valid token and only the alg changed.

**A verifier passes only if the accepted algorithm set is a server-side allowlist, the key type matches that algorithm, and the whole token is rejected if any check fails.**

Send a matrix: correct token (control), payload-tampered token, RS256->HS256, ES256->HS256, alg:none, alg:NONE/None casing, and a token signed by an unrelated key. Only the control should be accepted. Any 200/302 or authenticated API response for a tampered or downgraded token is a real finding; a uniform 401 with an explicit error is correct behaviour. Also check nested/inner signatures are validated, not just the outer one.

*Disproof:* All seven variants except the unmodified control are rejected with the same error, and no variant returns authenticated content or a session cookie.

**A 400/401 on a forged JWT is the expected rejection, not evidence of a flaw; a finding requires proof the verifier accepted an attacker-signed token.**

Define acceptance before testing: HTTP 200, a redirect into an authenticated area, a Set-Cookie establishing a session, or an API response body containing another user's data. Error text alone ('invalid signature', 'token expired') proves the check fired. Never report 'the server returned an error' as a vulnerability, and never treat a 500 or a stack trace as acceptance - capture the status code and body for each test case and only escalate on demonstrated acceptance.

*Disproof:* The only observed outcomes are error statuses with signature-verification messages; no forged token ever produced an authenticated response.

**To decide this case, observe: Define acceptance before testing: HTTP 200, a redirect into an authenticated area, a Set-Cookie establishing a session, or an API response body containing another user's data.**

Derived from jwt.validation.rejection_is_not_a_finding, which states the false-positive boundary for this class. The observable above is what separates a real finding from the pattern that only looks like one. A hunter who cannot produce this observation in a request/response pair does not have a finding yet.

*Disproof:* This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (jwt.validation.rejection_is_not_a_finding) states the full boundary.

**To decide this case, observe: Send a matrix: correct token (control), payload-tampered token, RS256->HS256, ES256->HS256, alg:none, alg:NONE/None casing, and a token signed by an unrelated key.**

Derived from jwt.validation.allowlist_algorithm_and_key_binding, which states the false-positive boundary for this class. The observable above is what separates a real finding from the pattern that only looks like one. A hunter who cannot produce this observation in a request/response pair does not have a finding yet.

*Disproof:* This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (jwt.validation.allowlist_algorithm_and_key_binding) states the full boundary.

**To decide this case, observe: Audience confusion is a finding only when the relying party fails to check the claim it was supposed to check.**

Derived from jwt.fprule.unread_claims_prove_nothing, which states the false-positive boundary for this class. The observable above is what separates a real finding from the pattern that only looks like one. A hunter who cannot produce this observation in a request/response pair does not have a finding yet.

*Disproof:* This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (jwt.fprule.unread_claims_prove_nothing) states the full boundary.

## Impact

**Reading JWT claims is not a finding: a signed JWT provides integrity and authenticity but not confidentiality, so only forgery or failed verification is a vulnerability.**

Base64url-decode a captured token and record what it exposes (emails, internal ids, roles) as a defence-in-depth observation, then check whether any of it is sensitive beyond the client. Rate the finding by what the signature controls: a forged token that grants access, changes identity, or replays across recipients is high/critical; a token that only discloses its own already-known claims is informational and usually not reportable.

*Disproof:* Decoding reveals only claims the requesting user already owns, and no signature, issuer, or recipient trust decision can be influenced by them.

**A JWT exists to establish authenticity, not to hide data, so every claim in the token is readable and rewritable by the client and only signature verification should be trusted.**

A JWT exists to establish authenticity, not to hide data, so every claim in the token is readable and rewritable by the client and only signature verification should be trusted.

HackTricks reference: jwt (https://kathan19.gitbook.io/howtohunt/jwt-attack/jwt.md)

*Disproof:* The token is encrypted so its claims are unreadable without the key, or altering a claim makes the server reject the signature.

**A JWT exists to establish authenticity, not to hide data, so every claim in the token is readable and rewritable by the client and only signature verification should be trusted.**

A JWT exists to establish authenticity, not to hide data, so every claim in the token is readable and rewritable by the client and only signature verification should be trusted.

HackTricks reference: jwt (https://kathan19.gitbook.io/howtohunt/jwt-attack/jwt.md)

*Disproof:* The token is encrypted so its claims are unreadable without the key, or altering a claim makes the server reject the signature.

## Related Bug Classes

Not yet researched.

## References

- **cheatsheetseries.owasp.org** (industry_guidance)
  - <https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_Cheat_Sheet.html>
- **clerk.com** (writeup)
  - <https://clerk.com/docs/reference/backend/verify-token>
- **cwe.mitre.org** (weakness_db)
  - <https://cwe.mitre.org/data/definitions/347.html>
- **datatracker.ietf.org** (standards_body)
  - <https://datatracker.ietf.org/doc/html/rfc8725>
- **ietf.org** (standards_body)
  - <https://www.ietf.org/archive/id/draft-ietf-oauth-v2-1-13.html>
- **kathan19.gitbook.io** (reference)
  - <https://kathan19.gitbook.io/howtohunt/jwt-attack/jwt.md>
- **portswigger.net** (vendor_docs)
  - <https://portswigger.net/web-security/jwt>
  - <https://portswigger.net/web-security/jwt/algorithm-confusion>
- **rfc-editor.org** (standards)
  - <https://www.rfc-editor.org/rfc/rfc8725.html>
  - <https://www.rfc-editor.org/rfc/rfc8725.txt>

Every item above is gated on >= 2 distinct publisher hosts (`wks/quality.py`, rule R1). Publisher diversity, not citation count, is what makes these corroborated.
