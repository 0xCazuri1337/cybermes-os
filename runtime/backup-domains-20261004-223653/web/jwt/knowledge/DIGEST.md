# JWT / Token Validation Failures

> surface: `identity` · CWE: CWE-347 · OWASP: API8:2023
> maturity: **mature** — 30 items, 25 supported, 21 FP rules, 1 chains

The application fails to verify a token's signature, algorithm or claims before making an authorization decision.

**Aliases:** jwt, algorithm confusion, none algorithm attack, jwk injection, token signature not verified, kid injection

## Prerequisite

- **Algorithm confusion is only possible when the verifier's key/algorithm choice is taken from the attacker-controlled `alg` header rather than a server-side allowlist bound to the key.**  
  `high_confidence` · score 0.8805 · disproved by: An RS256->HS256 token signed with the server's public key is rejected with an explicit signature/algorithm error on every attempt, including HS384/HS512 variants.
  sources: <https://www.rfc-editor.org/rfc/rfc8725.html> · <https://portswigger.net/web-security/jwt/algorithm-confusion>
- **A successful RS256-to-HS256 forgery requires the attacker's copy of the public key to be byte-identical to the server's stored copy, including PEM formatting and newlines.**  
  `high_confidence` · score 0.823 · disproved by: A single attacker-signed HS256 token built from every published key format and every derived modulus candidate is rejected by the server.
  sources: <https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_Cheat_Sheet.html> · <https://portswigger.net/web-security/jwt/algorithm-confusion>

## Signal

- **A token with header `{"alg":"none"}` (and, correctly formed, a trailing dot and empty signature) that the server honours indicates the verifier accepts unsecured JWTs.**  
  `high_confidence` · score 0.908 · disproved by: The `alg:none` token is rejected with 401/403 or an 'invalid signature' response, identical to a token whose payload was tampered with.
  sources: <https://www.rfc-editor.org/rfc/rfc8725.html> · <https://portswigger.net/web-security/jwt>
- **The JWT header is client-readable and names the algorithm used for signing, which makes the alg value the first field to inspect and the first one to tamper with.**  
  `high_confidence` · score 0.8815 · disproved by: The server ignores the alg stated in the header and validates only tokens it verifies against its own pinned key, so changing alg has no effect.
  sources: <https://datatracker.ietf.org/doc/html/rfc8725> · <https://www.rfc-editor.org/rfc/rfc8725.txt> · <https://kathan19.gitbook.io/howtohunt/jwt-attack/jwt.md>
- **A server that accepts a token signed with a key you supplied inside the token itself (jwk, jku, x5u, x5c) is resolving its trust anchor from unauthenticated token input.**  
  `high_confidence` · score 0.8505 · disproved by: Every attacker-supplied key location is ignored, and the server verifies only against keys it resolved out of band from its own pinned or discovered key set.
  sources: <https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_Cheat_Sheet.html> · <https://portswigger.net/web-security/jwt>
- **The JWT header is client-readable and names the algorithm used for signing, which makes the alg value the first field to inspect and the first one to tamper with.**  
  `under_review` · score 0.7655 · disproved by: The server ignores the alg stated in the header and validates only tokens it verifies against its own pinned key, so changing alg has no effect.
  sources: <https://www.rfc-editor.org/rfc/rfc8725.txt> · <https://kathan19.gitbook.io/howtohunt/jwt-attack/jwt.md>

## Technique

- **Re-signing a modified payload with HS256 using the server's own RSA public key as the HMAC secret yields a token the confused verifier accepts.**  
  `high_confidence` · score 0.908 · disproved by: Every HS256 token signed with the published or derived public key is rejected, and the server never verifies a MAC against a key whose type is public.
  sources: <https://www.rfc-editor.org/rfc/rfc8725.html> · <https://portswigger.net/web-security/jwt/algorithm-confusion>
- **When `kid` selects a key from the filesystem and symmetric algorithms are allowed, pointing `kid` at an empty file gives a known zero-length HMAC secret.**  
  `high_confidence` · score 0.853 · disproved by: Traversal payloads produce an error or fall back to a default key, and the same forged token is rejected on replay.
  sources: <https://www.rfc-editor.org/rfc/rfc8725.html> · <https://portswigger.net/web-security/jwt>
- **A verifier that resolves the key by header `kid`/`jku` against a multi-key set still accepts tokens signed with retired-but-still-published keys or keys belonging to another trusted issuer.**  
  `high_confidence` · score 0.823 · disproved by: Only keys bound to the validated issuer and current key version verify; retired and foreign `kid` values yield a lookup failure and a rejected token.
  sources: <https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_Cheat_Sheet.html> · <https://portswigger.net/web-security/jwt>

## Test

- **To decide this case, observe: Send a matrix: correct token (control), payload-tampered token, RS256->HS256, ES256->HS256, alg:none, alg:NONE/None casing, and a token signed by an unrelated key.**  
  `high_confidence` · score 0.8805 · disproved by: This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (jwt.validation.allowlist_algorithm_and_key_binding) states the full boundary.
  sources: <https://www.rfc-editor.org/rfc/rfc8725.html> · <https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_Cheat_Sheet.html>
- **To decide this case, observe: Define acceptance before testing: HTTP 200, a redirect into an authenticated area, a Set-Cookie establishing a session, or an API response body containing another user's data.**  
  `under_review` · score 0.853 · disproved by: This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (jwt.validation.rejection_is_not_a_finding) states the full boundary.
  sources: <https://cwe.mitre.org/data/definitions/347.html> · <https://portswigger.net/web-security/jwt>
- **To decide this case, observe: Audience confusion is a finding only when the relying party fails to check the claim it was supposed to check.**  
  `high_confidence` · score 0.853 · disproved by: This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (jwt.fprule.unread_claims_prove_nothing) states the full boundary.
  sources: <https://datatracker.ietf.org/doc/html/rfc8725> · <https://portswigger.net/web-security/jwt>

## Validation

- **The pass condition for a verifier is that it rejects every algorithm outside the application's allow-list, which requires the library to pin the accepted set rather than read alg from the token and dispatch on it.**  
  `high_confidence` · score 0.863 · disproved by: The claim is false if the verifier restricts the algorithm set by deployment rather than by request - a JOSE header that is built server-side and the header field stripped or normalised before verification, or an HSM/provider API that accepts only one algorithm identifier. It is also false when the key itself is type-bound, since a key usable with exactly one algorithm (the rule RFC 8725 also states) prevents the confusion regardless of what the header says. And a rejection test needs a credential-free baseline: if your modified token is refused because the session expired or the CSRF cookie is missing, the 401 proves nothing about algorithm handling - the control must be re-run with a valid token and only the alg changed.
  sources: <https://www.rfc-editor.org/rfc/rfc8725.txt> · <https://clerk.com/docs/reference/backend/verify-token>
- **A verifier passes only if the accepted algorithm set is a server-side allowlist, the key type matches that algorithm, and the whole token is rejected if any check fails.**  
  `high_confidence` · score 0.853 · disproved by: All seven variants except the unmodified control are rejected with the same error, and no variant returns authenticated content or a session cookie.
  sources: <https://www.rfc-editor.org/rfc/rfc8725.html> · <https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_Cheat_Sheet.html>
- **A 400/401 on a forged JWT is the expected rejection, not evidence of a flaw; a finding requires proof the verifier accepted an attacker-signed token.**  
  `under_review` · score 0.7015 · disproved by: The only observed outcomes are error statuses with signature-verification messages; no forged token ever produced an authenticated response.
  sources: <https://portswigger.net/web-security/jwt>

## Fp Rule

- **An unsigned JWT accepted without a signature is only a validated finding when the same unmodified token reaches a protected endpoint carrying no other credential, because a library may ignore alg=none yet still require a session cookie or CSRF token on that route.**  
  `high_confidence` · score 0.8965 · disproved by: If a request carrying ONLY the unsigned token and no other credential reaches a resource that a credential-less request demonstrably cannot, signature enforcement is absent and the finding is real.
  sources: <https://datatracker.ietf.org/doc/html/rfc8725> · <https://www.ietf.org/archive/id/draft-ietf-oauth-v2-1-13.html> · <https://portswigger.net/web-security/jwt>
- **Reportable only if a none-alg token is actually honoured; 400/415 responses to `None`, `NONE`, whitespace or unencoded variants are filtering working.**  
  `high_confidence` · score 0.8805 · disproved by: Every `alg:none` variant, including malformed and case-varied headers, returns a client error and never an authenticated response.
  sources: <https://www.rfc-editor.org/rfc/rfc8725.html> · <https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_Cheat_Sheet.html>
- **A finding that a kid or jku header value reaches an outbound request is only validated when an attacker-controlled server actually receives the callback, because the header may be parsed, logged and echoed without ever being dereferenced.**  
  `high_confidence` · score 0.869 · disproved by: If a request carrying the attacker-controlled kid value arrives at the designated server and the response influences the key actually used for verification, the header is dereferenced and the finding is real.
  sources: <https://datatracker.ietf.org/doc/html/rfc8725> · <https://www.ietf.org/archive/id/draft-ietf-oauth-v2-1-13.html> · <https://portswigger.net/web-security/jwt>
- **A verification path that throws, returns a library error object, or falls through to an anonymous identity is a rejection unless the request then proceeds to the protected resource - the observable is the protected response, not the absence of an exception.**  
  `high_confidence` · score 0.863 · disproved by: The claim is false if the fallthrough path does serve protected data - that is precisely the bypass, and the observable becomes the returned resource. It is also false when the error is swallowed but a side effect has already occurred, for example a signature check that fails after a database write, or an algorithm rejection that happens after the token's claims have been used to select a tenant or an account. And the strictness of 'the entire JWT must be rejected' has a documented exception in the spec's own framing for unsecured JWTs, which are legitimately created for use cases where the content is secured by a means outside the JWT, so a verifier that accepts alg none only where that is the intended design is not in violation - the burden is on showing the design did not intend it.
  sources: <https://www.rfc-editor.org/rfc/rfc8725.txt> · <https://clerk.com/docs/reference/backend/verify-token>
- **Changing an aud or iss claim and observing no behavioural difference is NOT evidence that audience validation is absent, unless the token is otherwise validly signed and reaches an endpoint whose authorization decision depends on that claim.**  
  `high_confidence` · score 0.8415 · disproved by: If a mutably-signed token carrying a modified aud claim is accepted by a resource belonging to a different relying party, audience validation is genuinely absent and the finding stands.
  sources: <https://datatracker.ietf.org/doc/html/rfc8725> · <https://www.ietf.org/archive/id/draft-ietf-oauth-v2-1-13.html> · <https://portswigger.net/web-security/jwt>
- **A JWT that verifies cryptographically at an unintended resource is not evidence that the endpoint accepts it; RFC 8725 requires the audience to be present and associated with the recipient, and absence of aud must be a rejection.**  
  `high_confidence` · score 0.8355 · disproved by: The claim is false when the deployment genuinely has one resource and one audience, in which case substitution is not expressible and the aud check has nothing to compare against - a single-recipient system is not vulnerable to this attack. It is also false when the tokens are sender-constrained: RFC 9700 describes sender-constrained access tokens as scoping an access token's applicability to a certain sender, one obliged to demonstrate knowledge of a certain secret as a prerequisite for acceptance, so a token replayed by a different holder fails on the proof, not on the audience. And where the verifier does check aud, the finding is simply false: presenting a foreign-audience token and getting a 401 is the control working.
  sources: <https://www.rfc-editor.org/rfc/rfc8725.txt> · <https://clerk.com/docs/reference/backend/verify-token>
- **The mere presence of `jku`, `jwk`, `x5u`, `x5c` or `kid` in legitimately issued tokens is normal key selection, not a vulnerability; only unauthenticated resolution is.**  
  `high_confidence` · score 0.8255 · disproved by: Attacker-supplied `jwk`, `jku` and `x5u` key locations are ignored while the server verifies against its own preconfigured key set.
  sources: <https://cwe.mitre.org/data/definitions/347.html> · <https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_Cheat_Sheet.html>

## Evidence

- **A convincing observation for this class is: The first is the exception: a library that raises on an unsupported alg is doing exactly what RFC 8725 requires, and a tester who reads a stack trace in the response body as partial success has inverted the meaning.**  
  `high_confidence` · score 0.8355 · disproved by: Not evidence when the observable cannot be produced at all -- blind, server-side-only, or identical-in-every-case behaviour leaves nothing to show. The originating rule (jwt.fp_rule.a_library_raising_an_error_is_a_reject_not_a_bypass) states the full boundary.
  sources: <https://www.rfc-editor.org/rfc/rfc8725.txt> · <https://clerk.com/docs/reference/backend/verify-token>
- **A convincing observation for this class is: Define acceptance before testing: HTTP 200, a redirect into an authenticated area, a Set-Cookie establishing a session, or an API response body containing another user's data.**  
  `under_review` · score 0.8255 · disproved by: Not evidence when the observable cannot be produced at all -- blind, server-side-only, or identical-in-every-case behaviour leaves nothing to show. The originating rule (jwt.validation.rejection_is_not_a_finding) states the full boundary.
  sources: <https://cwe.mitre.org/data/definitions/347.html> · <https://portswigger.net/web-security/jwt>

## Impact

- **A JWT exists to establish authenticity, not to hide data, so every claim in the token is readable and rewritable by the client and only signature verification should be trusted.**  
  `high_confidence` · score 0.854 · disproved by: The token is encrypted so its claims are unreadable without the key, or altering a claim makes the server reject the signature.
  sources: <https://datatracker.ietf.org/doc/html/rfc8725> · <https://www.rfc-editor.org/rfc/rfc8725.txt> · <https://kathan19.gitbook.io/howtohunt/jwt-attack/jwt.md>
- **Reading JWT claims is not a finding: a signed JWT provides integrity and authenticity but not confidentiality, so only forgery or failed verification is a vulnerability.**  
  `high_confidence` · score 0.7955 · disproved by: Decoding reveals only claims the requesting user already owns, and no signature, issuer, or recipient trust decision can be influenced by them.
  sources: <https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_Cheat_Sheet.html> · <https://portswigger.net/web-security/jwt>
- **A JWT exists to establish authenticity, not to hide data, so every claim in the token is readable and rewritable by the client and only signature verification should be trusted.**  
  `under_review` · score 0.738 · disproved by: The token is encrypted so its claims are unreadable without the key, or altering a claim makes the server reject the signature.
  sources: <https://www.rfc-editor.org/rfc/rfc8725.txt> · <https://kathan19.gitbook.io/howtohunt/jwt-attack/jwt.md>

## Bypass

- **When one issuer mints more than one kind of JWT, the validation rules for those kinds must be mutually exclusive; overlapping rule sets let a token of one kind be presented where another kind is expected.**  
  `high_confidence` · score 0.918 · disproved by: The claim is false when the token kinds are already separated by the very mechanisms the spec lists - distinct key sets, distinct issuers, distinct audiences, or a validator that enforces a required claim set unique to one kind, in which case the wrong-kind token is rejected by design. It is also false where explicit typing is in force and enforced: RFC 8725 notes the caveat that typ may not achieve disambiguation from existing kinds of JWTs because the validation rules for existing kinds often do not use the typ value, so typing only helps when the validator actually reads it. And the finding requires reachability - the confused token has to be obtainable by the attacker, which an ID token obtained through the authorization code flow with a matching nonce generally is not.
  sources: <https://www.rfc-editor.org/rfc/rfc8725.txt> · <https://clerk.com/docs/reference/backend/verify-token>
- **Servers that string-parse to reject `alg: none` can be bypassed with mixed capitalization, unexpected encodings, or an omitted trailing dot handling difference.**  
  `high_confidence` · score 0.8805 · disproved by: All case and encoding variants of the `none` header are rejected identically to a well-formed signature error, and no variant authenticates.
  sources: <https://www.rfc-editor.org/rfc/rfc8725.html> · <https://portswigger.net/web-security/jwt>

## Chain Link

- **A verified forgery becomes account takeover, not info disclosure, only when the edited claim drives server-side identity or authorization decisions.**  
  `high_confidence` · score 0.853 · disproved by: The forged token is accepted syntactically but the server re-derives identity from server-side session state or the edited claim grants no additional access.
  sources: <https://cwe.mitre.org/data/definitions/347.html> · <https://portswigger.net/web-security/jwt>

## False-positive rules

- **Hypothesis:** The server accepts unsigned tokens because a token with alg set to none is honoured
  - **Invalidated by:** The identical unsigned token was also accepted with a completely random subject claim, and the endpoint returned the same body for a request with no token at all - the route is public and never read the token
  - **Rule:** A 200 on a modified token is only a JWT finding if the same 200 does not occur with no token at all; always capture the no-credential baseline for the endpoint first

- **Hypothesis:** Signature verification is broken because a token signed with an attacker key is accepted
  - **Invalidated by:** The server returned the same 200 and the same body for the valid-looking token, an invalid one, and no token, so nothing in the request path consulted the signature
  - **Rule:** Forged-token acceptance needs a negative control: if a malformed, a wrongly-keyed and a token-less request all return the same 200, the endpoint never verified anything

- **Hypothesis:** The kid header is injectable because a path traversal value caused a different error
  - **Invalidated by:** Any kid naming a missing file produced the same 500, including a nonsense name with no traversal characters, so the failure is a missing key file and not a traversal
  - **Rule:** A traversal claim needs a control where only the path characters differ; an identical error for a plain missing filename is a missing-file error, not traversal

- **Hypothesis:** The server ignores the exp claim because an expired token is still accepted
  - **Invalidated by:** The response was a static public shell identical to the token-less baseline, and the session cookie was never reissued, so the token was parsed but not used for the authorization decision
  - **Rule:** Expired-token acceptance must be proven by a reissued session or a protected resource, not by a 200 on a route that returns the same body without any token

- **Hypothesis:** Role claim tampering grants admin because a user-role token with role admin is honoured
  - **Invalidated by:** The user-role token returned the same administrative page shell as before with an empty user list, and the identical page was served with a role of auditor and with the role claim deleted entirely
  - **Rule:** Role tampering is proven by privileged DATA or an action, not by an admin-shaped page; a shell that renders identically for every role is a routing artefact

- **Hypothesis:** The jwk x5u header is exploitable because a token referencing an attacker-hosted key is accepted
  - **Invalidated by:** After re-hosting, both tokens continued to validate against the ORIGINAL public key, showing the server used a cached key and never fetched the attacker's URL at all
  - **Rule:** A remote-key header is only proven fetched when changing the hosted key changes the validation outcome; unchanged behaviour proves a cache or a hardcoded key

- **Hypothesis:** The token signature is not verified because altering the payload without re-signing still works
  - **Invalidated by:** The response echoed the ORIGINAL subject, not the edited one, proving the server re-read a trusted source such as a session store or a re-issued token rather than trusting the presented claims
  - **Rule:** Editing a claim is only an attack if the server ACTS on the edited value; if the response still reflects the original identity, the claims are not the source of truth

- **Hypothesis:** The API accepts tokens signed with the HS256 algorithm using the RSA public key as the HMAC secret
  - **Invalidated by:** The very same token was accepted by an endpoint that also accepts no token at all, and the protected endpoint in the same application rejected it consistently
  - **Rule:** Algorithm-confusion proof needs a protected endpoint that rejects the forged token; acceptance on a route that is permissive for everyone is not a finding

- **Hypothesis:** The mere presence of `jku`, `jwk`, `x5u`, `x5c` or `kid` in legitimately issued tokens is normal key selection, not a vulnerability; only unauthenticated resolution is.
  - **Invalidated by:** Attacker-supplied `jwk`, `jku` and `x5u` key locations are ignored while the server verifies against its own preconfigured key set.
  - **Rule:** The mere presence of `jku`, `jwk`, `x5u`, `x5c` or `kid` in legitimately issued tokens is normal key selection, not a vulnerability; only unauthenticated resolution is.

- **Hypothesis:** Reportable only if a none-alg token is actually honoured; 400/415 responses to `None`, `NONE`, whitespace or unencoded variants are filtering working.
  - **Invalidated by:** Every `alg:none` variant, including malformed and case-varied headers, returns a client error and never an authenticated response.
  - **Rule:** Reportable only if a none-alg token is actually honoured; 400/415 responses to `None`, `NONE`, whitespace or unencoded variants are filtering working.

- **Hypothesis:** An unsigned JWT accepted without a signature is only a validated finding when the same unmodified token reaches a protected endpoint carrying no other credential, because a library may ignore alg=none yet still require a session cookie or CSRF token on that route.
  - **Invalidated by:** If a request carrying ONLY the unsigned token and no other credential reaches a resource that a credential-less request demonstrably cannot, signature enforcement is absent and the finding is real.
  - **Rule:** An unsigned JWT accepted without a signature is only a validated finding when the same unmodified token reaches a protected endpoint carrying no other credential, because a library may ignore alg=none yet still require a session cookie or CSRF token on that route.

- **Hypothesis:** A finding that a kid or jku header value reaches an outbound request is only validated when an attacker-controlled server actually receives the callback, because the header may be parsed, logged and echoed without ever being dereferenced.
  - **Invalidated by:** If a request carrying the attacker-controlled kid value arrives at the designated server and the response influences the key actually used for verification, the header is dereferenced and the finding is real.
  - **Rule:** A finding that a kid or jku header value reaches an outbound request is only validated when an attacker-controlled server actually receives the callback, because the header may be parsed, logged and echoed without ever being dereferenced.

- **Hypothesis:** Changing an aud or iss claim and observing no behavioural difference is NOT evidence that audience validation is absent, unless the token is otherwise validly signed and reaches an endpoint whose authorization decision depends on that claim.
  - **Invalidated by:** If a mutably-signed token carrying a modified aud claim is accepted by a resource belonging to a different relying party, audience validation is genuinely absent and the finding stands.
  - **Rule:** Changing an aud or iss claim and observing no behavioural difference is NOT evidence that audience validation is absent, unless the token is otherwise validly signed and reaches an endpoint whose authorization decision depends on that claim.

- **Hypothesis:** A forged token with alg:none or an RS256-to-HS256 substitution is accepted, therefore the application is vulnerable to JWT algorithm confusion
  - **Invalidated by:** No forged identity was accepted. Responses were the application shell or 404, and the service never treated the forged subject as authenticated
  - **Rule:** Algorithm confusion requires a forged token to be ACCEPTED as a valid identity. Send alg:none and the RS256-as-HS256 variant against a user endpoint and require the response to treat the forged subject as authenticated; a shell or 404 in reply is the disproof

## Related classes (via chains)

- `idor` IDOR / BOLA (Object-Level Authorization) (3 chains)
