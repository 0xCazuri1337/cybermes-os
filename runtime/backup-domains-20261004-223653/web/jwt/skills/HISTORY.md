# History

Append-only. Each entry records WHY the skill changed, not just that it did. Improvement means better hunting behaviour, not more text.

## 2026-10-02 15:57 — 1 diff lines
- items: 17 (supported 17), FP rules 18, chains 1, state mature

```diff
(initial generation, 2026-10-02)
```

## 2026-10-02 16:07 — 8 diff lines
- items: 17 (supported 17), FP rules 18, chains 1, state mature

```diff
--- jwt@current
+++ jwt@new
@@ -140,4 +140,4 @@
 - `idor` (3 shared chain(s))
 
 ---
-Full class document: `domains/web/jwt/EVIDENCE.md` · retrieve more with `python -m wks.cli search "<query>" --class-id jwt`
+Full class document: `domains/web/jwt/knowledge/DIGEST.md` · retrieve more with `python -m wks.cli search "<query>" --class-id jwt`
```

## 2026-10-02 19:37 — 30 diff lines
- items: 20 (supported 20), FP rules 18, chains 1, state mature

```diff
--- jwt@current
+++ jwt@new
@@ -10,7 +10,7 @@
      python -m wks.skillgen -->
 
 > surface `identity` · CWE CWE-347 · OWASP API8:2023
-> evidence: 17 items, 17 supported, 18 FP rules, 1 chains
+> evidence: 20 items, 20 supported, 18 FP rules, 1 chains
 > maturity: **mature**
 
 The application fails to verify a token's signature, algorithm or claims before making an authorization decision.
@@ -47,6 +47,18 @@
 - A verifier that resolves the key by header `kid`/`jku` against a multi-key set still accepts tokens signed with retired-but-still-published keys or keys belonging to another trusted issuer.
   - **Disproof:** Only keys bound to the validated issuer and current key version verify; retired and foreign `kid` values yield a lookup failure and a rejected token.
   - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_Cheat_Sheet.html> · <https://portswigger.net/web-security/jwt>
+
+## Tests
+
+- To decide this case, observe: eptance before testing: HTTP 200, a redirect into an authenticated area, a Set-Cookie establishing a session, or an API response body containing another user's data. Error text alone ('invalid signature', 'token expired') proves the check fired. Never report 'the server returned an error' as a vulnerability, and never treat a 500 or a stack trace as acceptance - capture the sta
+  - **Disproof:** This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (jwt.validation.rejection_is_not_a_finding) states the full boundary.
+  - Sources: <https://cwe.mitre.org/data/definitions/347.html> · <https://portswigger.net/web-security/jwt>
+- To decide this case, observe: 6, alg:none, alg:NONE/None casing, and a token signed by an unrelated key. Only the control should be accepted. Any 200/302 or authenticated API response for a tampered or downgraded token is a real finding; a uniform 401 with an explicit error is correct behaviour. Also check nested/inner signatures are validated, not just the outer one.
+  - **Disproof:** This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (jwt.validation.allowlist_algorithm_and_key_binding) states the full boundary.
+  - Sources: <https://www.rfc-editor.org/rfc/rfc8725.html> · <https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_Cheat_Sheet.html>
+- To decide this case, observe: Audience confusion is a finding only when the relying party fails to check the claim it was supposed to check. Modifying a claim the server never reads yields identical behaviour whether validation is correct or entirely missing, so the observation carries no information. Establish which cla
+  - **Disproof:** This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (jwt.fprule.unread_claims_prove_nothing) states the full boundary.
+  - Sources: <https://datatracker.ietf.org/doc/html/rfc8725> · <https://portswigger.net/web-security/jwt>
 
 ## Validation bar (how to prove it)
 
```

## 2026-10-03 01:46 — 102 diff lines
- items: 30 (supported 25), FP rules 20, chains 1, state mature

```diff
--- jwt@current
+++ jwt@new
@@ -10,7 +10,7 @@
      python -m wks.skillgen -->
 
 > surface `identity` · CWE CWE-347 · OWASP API8:2023
-> evidence: 20 items, 20 supported, 18 FP rules, 1 chains
+> evidence: 30 items, 25 supported, 20 FP rules, 1 chains
 > maturity: **mature**
 
 The application fails to verify a token's signature, algorithm or claims before making an authorization decision.
@@ -32,6 +32,12 @@
 - A server that accepts a token signed with a key you supplied inside the token itself (jwk, jku, x5u, x5c) is resolving its trust anchor from unauthenticated token input.
   - **Disproof:** Every attacker-supplied key location is ignored, and the server verifies only against keys it resolved out of band from its own pinned or discovered key set.
   - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_Cheat_Sheet.html> · <https://portswigger.net/web-security/jwt>
+- The JWT header is client-readable and names the algorithm used for signing, which makes the alg value the first field to inspect and the first one to tamper with. _(unverified)_
+  - **Disproof:** The server ignores the alg stated in the header and validates only tokens it verifies against its own pinned key, so changing alg has no effect.
+  - Sources: <https://www.rfc-editor.org/rfc/rfc8725.txt> · <https://kathan19.gitbook.io/howtohunt/jwt-attack/jwt.md>
+- The JWT header is client-readable and names the algorithm used for signing, which makes the alg value the first field to inspect and the first one to tamper with.
+  - **Disproof:** The server ignores the alg stated in the header and validates only tokens it verifies against its own pinned key, so changing alg has no effect.
+  - Sources: <https://datatracker.ietf.org/doc/html/rfc8725> · <https://www.rfc-editor.org/rfc/rfc8725.txt> · <https://kathan19.gitbook.io/howtohunt/jwt-attack/jwt.md>
 - A token with header `{"alg":"none"}` (and, correctly formed, a trailing dot and empty signature) that the server honours indicates the verifier accepts unsecured JWTs.
   - **Disproof:** The `alg:none` token is rejected with 401/403 or an 'invalid signature' response, identical to a token whose payload was tampered with.
   - Sources: <https://www.rfc-editor.org/rfc/rfc8725.html> · <https://portswigger.net/web-security/jwt>
@@ -50,27 +56,36 @@
 
 ## Tests
 
-- To decide this case, observe: eptance before testing: HTTP 200, a redirect into an authenticated area, a Set-Cookie establishing a session, or an API response body containing another user's data. Error text alone ('invalid signature', 'token expired') proves the check fired. Never report 'the server returned an error' as a vulnerability, and never treat a 500 or a stack trace as acceptance - capture the sta
+- To decide this case, observe: Define acceptance before testing: HTTP 200, a redirect into an authenticated area, a Set-Cookie establishing a session, or an API response body containing another user's data. _(unverified)_
   - **Disproof:** This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (jwt.validation.rejection_is_not_a_finding) states the full boundary.
   - Sources: <https://cwe.mitre.org/data/definitions/347.html> · <https://portswigger.net/web-security/jwt>
-- To decide this case, observe: 6, alg:none, alg:NONE/None casing, and a token signed by an unrelated key. Only the control should be accepted. Any 200/302 or authenticated API response for a tampered or downgraded token is a real finding; a uniform 401 with an explicit error is correct behaviour. Also check nested/inner signatures are validated, not just the outer one.
+- To decide this case, observe: Send a matrix: correct token (control), payload-tampered token, RS256->HS256, ES256->HS256, alg:none, alg:NONE/None casing, and a token signed by an unrelated key.
   - **Disproof:** This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (jwt.validation.allowlist_algorithm_and_key_binding) states the full boundary.
   - Sources: <https://www.rfc-editor.org/rfc/rfc8725.html> · <https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_Cheat_Sheet.html>
-- To decide this case, observe: Audience confusion is a finding only when the relying party fails to check the claim it was supposed to check. Modifying a claim the server never reads yields identical behaviour whether validation is correct or entirely missing, so the observation carries no information. Establish which cla
+- To decide this case, observe: Audience confusion is a finding only when the relying party fails to check the claim it was supposed to check.
   - **Disproof:** This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (jwt.fprule.unread_claims_prove_nothing) states the full boundary.
   - Sources: <https://datatracker.ietf.org/doc/html/rfc8725> · <https://portswigger.net/web-security/jwt>
 
 ## Validation bar (how to prove it)
 
+- The pass condition for a verifier is that it rejects every algorithm outside the application's allow-list, which requires the library to pin the accepted set rather than read alg from the token and dispatch on it.
+  - **Disproof:** The claim is false if the verifier restricts the algorithm set by deployment rather than by request - a JOSE header that is built server-side and the header field stripped or normalised before verification, or an HSM/provider API that accepts only one algorithm identifier. It is also false when the key itself is type-bound, since a key usable with exactly one algorithm (the rule RFC 8725 also states) prevents the confusion regardless of what the header says. And a rejection test needs a credential-free baseline: if your modified token is refused because the session expired or the CSRF cookie is missing, the 401 proves nothing about algorithm handling - the control must be re-run with a valid token and only the alg changed.
+  - Sources: <https://www.rfc-editor.org/rfc/rfc8725.txt> · <https://clerk.com/docs/reference/backend/verify-token>
 - A verifier passes only if the accepted algorithm set is a server-side allowlist, the key type matches that algorithm, and the whole token is rejected if any check fails.
   - **Disproof:** All seven variants except the unmodified control are rejected with the same error, and no variant returns authenticated content or a session cookie.
   - Sources: <https://www.rfc-editor.org/rfc/rfc8725.html> · <https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_Cheat_Sheet.html>
-- A 400/401 on a forged JWT is the expected rejection, not evidence of a flaw; a finding requires proof the verifier accepted an attacker-signed token.
+- A 400/401 on a forged JWT is the expected rejection, not evidence of a flaw; a finding requires proof the verifier accepted an attacker-signed token. _(unverified)_
   - **Disproof:** The only observed outcomes are error statuses with signature-verification messages; no forged token ever produced an authenticated response.
-  - Sources: <https://cwe.mitre.org/data/definitions/347.html> · <https://portswigger.net/web-security/jwt>
+  - Sources: <https://portswigger.net/web-security/jwt>
 
 ## False-positive rules (when to reject it)
 
+- A verification path that throws, returns a library error object, or falls through to an anonymous identity is a rejection unless the request then proceeds to the protected resource - the observable is the protected response, not the absence of an exception.
+  - **Disproof:** The claim is false if the fallthrough path does serve protected data - that is precisely the bypass, and the observable becomes the returned resource. It is also false when the error is swallowed but a side effect has already occurred, for example a signature check that fails after a database write, or an algorithm rejection that happens after the token's claims have been used to select a tenant or an account. And the strictness of 'the entire JWT must be rejected' has a documented exception in the spec's own framing for unsecured JWTs, which are legitimately created for use cases where the content is secured by a means outside the JWT, so a verifier that accepts alg none only where that is the intended design is not in violation - the burden is on showing the design did not intend it.
+  - Sources: <https://www.rfc-editor.org/rfc/rfc8725.txt> · <https://clerk.com/docs/reference/backend/verify-token>
+- A JWT that verifies cryptographically at an unintended resource is not evidence that the endpoint accepts it; RFC 8725 requires the audience to be present and associated with the recipient, and absence of aud must be a rejection.
+  - **Disproof:** The claim is false when the deployment genuinely has one resource and one audience, in which case substitution is not expressible and the aud check has nothing to compare against - a single-recipient system is not vulnerable to this attack. It is also false when the tokens are sender-constrained: RFC 9700 describes sender-constrained access tokens as scoping an access token's applicability to a certain sender, one obliged to demonstrate knowledge of a certain secret as a prerequisite for acceptance, so a token replayed by a different holder fails on the proof, not on the audience. And where the verifier does check aud, the finding is simply false: presenting a foreign-audience token and getting a 401 is the control working.
+  - Sources: <https://www.rfc-editor.org/rfc/rfc8725.txt> · <https://clerk.com/docs/reference/backend/verify-token>
 - The mere presence of `jku`, `jwk`, `x5u`, `x5c` or `kid` in legitimately issued tokens is normal key selection, not a vulnerability; only unauthenticated resolution is.
   - **Disproof:** Attacker-supplied `jwk`, `jku` and `x5u` key locations are ignored while the server verifies against its own preconfigured key set.
   - Sources: <https://cwe.mitre.org/data/definitions/347.html> · <https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_Cheat_Sheet.html>
@@ -85,16 +100,34 @@
   - Sources: <https://datatracker.ietf.org/doc/html/rfc8725> · <https://www.ietf.org/archive/id/draft-ietf-oauth-v2-1-13.html> · <https://portswigger.net/web-security/jwt>
 - Changing an aud or iss claim and observing no behavioural difference is NOT evidence that audience validation is absent, unless the token is otherwise validly signed and reaches an endpoint whose authorization decision depends on that claim.
   - **Disproof:** If a mutably-signed token carrying a modified aud claim is accepted by a resource belonging to a different relying party, audience validation is genuinely absent and the finding stands.
-  - Sources: <https://datatracker.ietf.org/doc/html/rfc8725> · <https://www.ietf.org/archive/id/draft-ietf-oauth-v2-1-09.html> · <https://portswigger.net/web-security/jwt>
+  - Sources: <https://datatracker.ietf.org/doc/html/rfc8725> · <https://www.ietf.org/archive/id/draft-ietf-oauth-v2-1-13.html> · <https://portswigger.net/web-security/jwt>
+
+## Evidence requirements
+
+- A convincing observation for this class is: Define acceptance before testing: HTTP 200, a redirect into an authenticated area, a Set-Cookie establishing a session, or an API response body containing another user's data. _(unverified)_
+  - **Disproof:** Not evidence when the observable cannot be produced at all -- blind, server-side-only, or identical-in-every-case behaviour leaves nothing to show. The originating rule (jwt.validation.rejection_is_not_a_finding) states the full boundary.
+  - Sources: <https://cwe.mitre.org/data/definitions/347.html> · <https://portswigger.net/web-security/jwt>
+- A convincing observation for this class is: The first is the exception: a library that raises on an unsupported alg is doing exactly what RFC 8725 requires, and a tester who reads a stack trace in the response body as partial success has inverted the meaning.
+  - **Disproof:** Not evidence when the observable cannot be produced at all -- blind, server-side-only, or identical-in-every-case behaviour leaves nothing to show. The originating rule (jwt.fp_rule.a_library_raising_an_error_is_a_reject_not_a_bypass) states the full boundary.
+  - Sources: <https://www.rfc-editor.org/rfc/rfc8725.txt> · <https://clerk.com/docs/reference/backend/verify-token>
 
 ## Impact framing
 
 - Reading JWT claims is not a finding: a signed JWT provides integrity and authenticity but not confidentiality, so only forgery or failed verification is a vulnerability.
   - **Disproof:** Decoding reveals only claims the requesting user already owns, and no signature, issuer, or recipient trust decision can be influenced by them.
   - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_Cheat_Sheet.html> · <https://portswigger.net/web-security/jwt>
+- A JWT exists to establish authenticity, not to hide data, so every claim in the token is readable and rewritable by the client and only signature verification should be trusted. _(unverified)_
+  - **Disproof:** The token is encrypted so its claims are unreadable without the key, or altering a claim makes the server reject the signature.
+  - Sources: <https://www.rfc-editor.org/rfc/rfc8725.txt> · <https://kathan19.gitbook.io/howtohunt/jwt-attack/jwt.md>
+- A JWT exists to establish authenticity, not to hide data, so every claim in the token is readable and rewritable by the client and only signature verification should be trusted.
+  - **Disproof:** The token is encrypted so its claims are unreadable without the key, or altering a claim makes the server reject the signature.
+  - Sources: <https://datatracker.ietf.org/doc/html/rfc8725> · <https://www.rfc-editor.org/rfc/rfc8725.txt> · <https://kathan19.gitbook.io/howtohunt/jwt-attack/jwt.md>
 
 ## Defence bypasses
 
+- When one issuer mints more than one kind of JWT, the validation rules for those kinds must be mutually exclusive; overlapping rule sets let a token of one kind be presented where another kind is expected.
+  - **Disproof:** The claim is false when the token kinds are already separated by the very mechanisms the spec lists - distinct key sets, distinct issuers, distinct audiences, or a validator that enforces a required claim set unique to one kind, in which case the wrong-kind token is rejected by design. It is also false where explicit typing is in force and enforced: RFC 8725 notes the caveat that typ may not achieve disambiguation from existing kinds of JWTs because the validation rules for existing kinds often do not use the typ value, so typing only helps when the validator actually reads it. And the finding requires reachability - the confused token has to be obtainable by the attacker, which an ID token obtained through the authorization code flow with a matching nonce generally is not.
+  - Sources: <https://www.rfc-editor.org/rfc/rfc8725.txt> · <https://clerk.com/docs/reference/backend/verify-token>
 - Servers that string-parse to reject `alg: none` can be bypassed with mixed capitalization, unexpected encodings, or an omitted trailing dot handling difference.
   - **Disproof:** All case and encoding variants of the `none` header are rejected identically to a well-formed signature error, and no variant authenticates.
   - Sources: <https://www.rfc-editor.org/rfc/rfc8725.html> · <https://portswigger.net/web-security/jwt>
```

## 2026-10-03 05:00 — 21 diff lines
- items: 30 (supported 25), FP rules 21, chains 1, state mature

```diff
--- jwt@current
+++ jwt@new
@@ -10,7 +10,7 @@
      python -m wks.skillgen -->
 
 > surface `identity` · CWE CWE-347 · OWASP API8:2023
-> evidence: 30 items, 25 supported, 20 FP rules, 1 chains
+> evidence: 30 items, 25 supported, 21 FP rules, 1 chains
 > maturity: **mature**
 
 The application fails to verify a token's signature, algorithm or claims before making an authorization decision.
@@ -179,6 +179,9 @@
 - **Changing an aud or iss claim and observing no behavioural difference is NOT evidence that audience validation is absent, unless the token is otherwise validly signed and reaches an endpoint whose authorization decision depends on that claim.**
   - Killed by: If a mutably-signed token carrying a modified aud claim is accepted by a resource belonging to a different relying party, audience validation is genuinely absent and the finding stands.
   - Rule: Changing an aud or iss claim and observing no behavioural difference is NOT evidence that audience validation is absent, unless the token is otherwise validly signed and reaches an endpoint whose authorization decision depends on that claim.
+- **A forged token with alg:none or an RS256-to-HS256 substitution is accepted, therefore the application is vulnerable to JWT algorithm confusion**
+  - Killed by: No forged identity was accepted. Responses were the application shell or 404, and the service never treated the forged subject as authenticated
+  - Rule: Algorithm confusion requires a forged token to be ACCEPTED as a valid identity. Send alg:none and the RS256-as-HS256 variant against a user endpoint and require the response to treat the forged subject as authenticated; a shell or 404 in reply is the disproof
 
 ## Chains to
 
```

## 2026-10-04 00:43 — 201 diff lines
- items: 30 (supported 25), FP rules 21, chains 1, state mature

```diff
--- jwt@current
+++ jwt@new
@@ -20,121 +20,115 @@
 
 ## Prerequisites (do not start without these)
 
-- Algorithm confusion is only possible when the verifier's key/algorithm choice is taken from the attacker-controlled `alg` header rather than a server-side allowlist bound to the key.
+- A successful RS256-to-HS256 forgery requires the attacker's copy of the public key to be byte-identical to the server's stored copy, including PEM formatting and newlines.  _(merged 1 duplicate row(s))_
+  - **Disproof:** A single attacker-signed HS256 token built from every published key format and every derived modulus candidate is rejected by the server.
+  - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_Cheat_Sheet.html> · <https://portswigger.net/web-security/jwt/algorithm-confusion>
+- Algorithm confusion is only possible when the verifier's key/algorithm choice is taken from the attacker-controlled `alg` header rather than a server-side allowlist bound to the key.  _(merged 1 duplicate row(s))_
   - **Disproof:** An RS256->HS256 token signed with the server's public key is rejected with an explicit signature/algorithm error on every attempt, including HS384/HS512 variants.
   - Sources: <https://www.rfc-editor.org/rfc/rfc8725.html> · <https://portswigger.net/web-security/jwt/algorithm-confusion>
-- A successful RS256-to-HS256 forgery requires the attacker's copy of the public key to be byte-identical to the server's stored copy, including PEM formatting and newlines.
-  - **Disproof:** A single attacker-signed HS256 token built from every published key format and every derived modulus candidate is rejected by the server.
-  - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_Cheat_Sheet.html> · <https://portswigger.net/web-security/jwt/algorithm-confusion>
 
 ## Recon signals (where to look)
 
-- A server that accepts a token signed with a key you supplied inside the token itself (jwk, jku, x5u, x5c) is resolving its trust anchor from unauthenticated token input.
+- A server that accepts a token signed with a key you supplied inside the token itself (jwk, jku, x5u, x5c) is resolving its trust anchor from unauthenticated token input.  _(merged 1 duplicate row(s))_
   - **Disproof:** Every attacker-supplied key location is ignored, and the server verifies only against keys it resolved out of band from its own pinned or discovered key set.
   - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_Cheat_Sheet.html> · <https://portswigger.net/web-security/jwt>
-- The JWT header is client-readable and names the algorithm used for signing, which makes the alg value the first field to inspect and the first one to tamper with. _(unverified)_
-  - **Disproof:** The server ignores the alg stated in the header and validates only tokens it verifies against its own pinned key, so changing alg has no effect.
-  - Sources: <https://www.rfc-editor.org/rfc/rfc8725.txt> · <https://kathan19.gitbook.io/howtohunt/jwt-attack/jwt.md>
-- The JWT header is client-readable and names the algorithm used for signing, which makes the alg value the first field to inspect and the first one to tamper with.
+- A token with header `{"alg":"none"}` (and, correctly formed, a trailing dot and empty signature) that the server honours indicates the verifier accepts unsecured JWTs.  _(merged 1 duplicate row(s))_
+  - **Disproof:** The `alg:none` token is rejected with 401/403 or an 'invalid signature' response, identical to a token whose payload was tampered with.
+  - Sources: <https://www.rfc-editor.org/rfc/rfc8725.html> · <https://portswigger.net/web-security/jwt>
+- The JWT header is client-readable and names the algorithm used for signing, which makes the alg value the first field to inspect and the first one to tamper with.  _(merged 2 duplicate row(s))_ _(unverified)_
   - **Disproof:** The server ignores the alg stated in the header and validates only tokens it verifies against its own pinned key, so changing alg has no effect.
   - Sources: <https://datatracker.ietf.org/doc/html/rfc8725> · <https://www.rfc-editor.org/rfc/rfc8725.txt> · <https://kathan19.gitbook.io/howtohunt/jwt-attack/jwt.md>
-- A token with header `{"alg":"none"}` (and, correctly formed, a trailing dot and empty signature) that the server honours indicates the verifier accepts unsecured JWTs.
-  - **Disproof:** The `alg:none` token is rejected with 401/403 or an 'invalid signature' response, identical to a token whose payload was tampered with.
-  - Sources: <https://www.rfc-editor.org/rfc/rfc8725.html> · <https://portswigger.net/web-security/jwt>
 
 ## Techniques (what to change)
 
-- When `kid` selects a key from the filesystem and symmetric algorithms are allowed, pointing `kid` at an empty file gives a known zero-length HMAC secret.
+- A verifier that resolves the key by header `kid`/`jku` against a multi-key set still accepts tokens signed with retired-but-still-published keys or keys belonging to another trusted issuer.  _(merged 1 duplicate row(s))_
+  - **Disproof:** Only keys bound to the validated issuer and current key version verify; retired and foreign `kid` values yield a lookup failure and a rejected token.
+  - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_Cheat_Sheet.html> · <https://portswigger.net/web-security/jwt>
+- Re-signing a modified payload with HS256 using the server's own RSA public key as the HMAC secret yields a token the confused verifier accepts.  _(merged 1 duplicate row(s))_
+  - **Disproof:** Every HS256 token signed with the published or derived public key is rejected, and the server never verifies a MAC against a key whose type is public.
+  - Sources: <https://www.rfc-editor.org/rfc/rfc8725.html> · <https://portswigger.net/web-security/jwt/algorithm-confusion>
+- When `kid` selects a key from the filesystem and symmetric algorithms are allowed, pointing `kid` at an empty file gives a known zero-length HMAC secret.  _(merged 1 duplicate row(s))_
   - **Disproof:** Traversal payloads produce an error or fall back to a default key, and the same forged token is rejected on replay.
   - Sources: <https://www.rfc-editor.org/rfc/rfc8725.html> · <https://portswigger.net/web-security/jwt>
-- Re-signing a modified payload with HS256 using the server's own RSA public key as the HMAC secret yields a token the confused verifier accepts.
-  - **Disproof:** Every HS256 token signed with the published or derived public key is rejected, and the server never verifies a MAC against a key whose type is public.
-  - Sources: <https://www.rfc-editor.org/rfc/rfc8725.html> · <https://portswigger.net/web-security/jwt/algorithm-confusion>
-- A verifier that resolves the key by header `kid`/`jku` against a multi-key set still accepts tokens signed with retired-but-still-published keys or keys belonging to another trusted issuer.
-  - **Disproof:** Only keys bound to the validated issuer and current key version verify; retired and foreign `kid` values yield a lookup failure and a rejected token.
-  - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_Cheat_Sheet.html> · <https://portswigger.net/web-security/jwt>
 
 ## Tests
 
-- To decide this case, observe: Define acceptance before testing: HTTP 200, a redirect into an authenticated area, a Set-Cookie establishing a session, or an API response body containing another user's data. _(unverified)_
+- To decide this case, observe: Audience confusion is a finding only when the relying party fails to check the claim it was supposed to check.  _(merged 1 duplicate row(s))_
+  - **Disproof:** This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (jwt.fprule.unread_claims_prove_nothing) states the full boundary.
+  - Sources: <https://datatracker.ietf.org/doc/html/rfc8725> · <https://portswigger.net/web-security/jwt>
+- To decide this case, observe: Define acceptance before testing: HTTP 200, a redirect into an authenticated area, a Set-Cookie establishing a session, or an API response body containing another user's data.  _(merged 1 duplicate row(s))_ _(unverified)_
   - **Disproof:** This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (jwt.validation.rejection_is_not_a_finding) states the full boundary.
   - Sources: <https://cwe.mitre.org/data/definitions/347.html> · <https://portswigger.net/web-security/jwt>
-- To decide this case, observe: Send a matrix: correct token (control), payload-tampered token, RS256->HS256, ES256->HS256, alg:none, alg:NONE/None casing, and a token signed by an unrelated key.
+- To decide this case, observe: Send a matrix: correct token (control), payload-tampered token, RS256->HS256, ES256->HS256, alg:none, alg:NONE/None casing, and a token signed by an unrelated key.  _(merged 1 duplicate row(s))_
   - **Disproof:** This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (jwt.validation.allowlist_algorithm_and_key_binding) states the full boundary.
   - Sources: <https://www.rfc-editor.org/rfc/rfc8725.html> · <https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_Cheat_Sheet.html>
-- To decide this case, observe: Audience confusion is a finding only when the relying party fails to check the claim it was supposed to check.
-  - **Disproof:** This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (jwt.fprule.unread_claims_prove_nothing) states the full boundary.
-  - Sources: <https://datatracker.ietf.org/doc/html/rfc8725> · <https://portswigger.net/web-security/jwt>
 
 ## Validation bar (how to prove it)
 
-- The pass condition for a verifier is that it rejects every algorithm outside the application's allow-list, which requires the library to pin the accepted set rather than read alg from the token and dispatch on it.
-  - **Disproof:** The claim is false if the verifier restricts the algorithm set by deployment rather than by request - a JOSE header that is built server-side and the header field stripped or normalised before verification, or an HSM/provider API that accepts only one algorithm identifier. It is also false when the key itself is type-bound, since a key usable with exactly one algorithm (the rule RFC 8725 also states) prevents the confusion regardless of what the header says. And a rejection test needs a credential-free baseline: if your modified token is refused because the session expired or the CSRF cookie is missing, the 401 proves nothing about algorithm handling - the control must be re-run with a valid token and only the alg changed.
-  - Sources: <https://www.rfc-editor.org/rfc/rfc8725.txt> · <https://clerk.com/docs/reference/backend/verify-token>
-- A verifier passes only if the accepted algorithm set is a server-side allowlist, the key type matches that algorithm, and the whole token is rejected if any check fails.
+- A 400/401 on a forged JWT is the expected rejection, not evidence of a flaw; a finding requires proof the verifier accepted an attacker-signed token.  _(merged 1 duplicate row(s))_ _(unverified)_
+  - **Disproof:** The only observed outcomes are error statuses with signature-verification messages; no forged token ever produced an authenticated response.
+  - Sources: <https://portswigger.net/web-security/jwt>
+- A verifier passes only if the accepted algorithm set is a server-side allowlist, the key type matches that algorithm, and the whole token is rejected if any check fails.  _(merged 1 duplicate row(s))_
   - **Disproof:** All seven variants except the unmodified control are rejected with the same error, and no variant returns authenticated content or a session cookie.
   - Sources: <https://www.rfc-editor.org/rfc/rfc8725.html> · <https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_Cheat_Sheet.html>
-- A 400/401 on a forged JWT is the expected rejection, not evidence of a flaw; a finding requires proof the verifier accepted an attacker-signed token. _(unverified)_
-  - **Disproof:** The only observed outcomes are error statuses with signature-verification messages; no forged token ever produced an authenticated response.
-  - Sources: <https://portswigger.net/web-security/jwt>
+- The pass condition for a verifier is that it rejects every algorithm outside the application's allow-list, which requires the library to pin the accepted set rather than read alg from the token and dispatch on it.  _(merged 1 duplicate row(s))_
+  - **Disproof:** The claim is false if the verifier restricts the algorithm set by deployment rather than by request - a JOSE header that is built server-side and the header field stripped or normalised before verification, or an HSM/provider API that accepts only one algorithm identifier. It is also false when the key itself is type-bound, since a key usable with exactly one algorithm (the rule RFC 8725 also states) prevents the confusion regardless of what the header says. And a rejection test needs a credential-free baseline: if your modified token is refused because the session expired or the CSRF cookie is missing, the 401 proves nothing about algorithm handling - the control must be re-run with a valid token and only the alg changed.
+  - Sources: <https://www.rfc-editor.org/rfc/rfc8725.txt> · <https://clerk.com/docs/reference/backend/verify-token>
 
 ## False-positive rules (when to reject it)
 
-- A verification path that throws, returns a library error object, or falls through to an anonymous identity is a rejection unless the request then proceeds to the protected resource - the observable is the protected response, not the absence of an exception.
+- A JWT that verifies cryptographically at an unintended resource is not evidence that the endpoint accepts it; RFC 8725 requires the audience to be present and associated with the recipient, and absence of aud must be a rejection.  _(merged 1 duplicate row(s))_
+  - **Disproof:** The claim is false when the deployment genuinely has one resource and one audience, in which case substitution is not expressible and the aud check has nothing to compare against - a single-recipient system is not vulnerable to this attack. It is also false when the tokens are sender-constrained: RFC 9700 describes sender-constrained access tokens as scoping an access token's applicability to a certain sender, one obliged to demonstrate knowledge of a certain secret as a prerequisite for acceptance, so a token replayed by a different holder fails on the proof, not on the audience. And where the verifier does check aud, the finding is simply false: presenting a foreign-audience token and getting a 401 is the control working.
+  - Sources: <https://www.rfc-editor.org/rfc/rfc8725.txt> · <https://clerk.com/docs/reference/backend/verify-token>
+- A finding that a kid or jku header value reaches an outbound request is only validated when an attacker-controlled server actually receives the callback, because the header may be parsed, logged and echoed without ever being dereferenced.  _(merged 1 duplicate row(s))_
+  - **Disproof:** If a request carrying the attacker-controlled kid value arrives at the designated server and the response influences the key actually used for verification, the header is dereferenced and the finding is real.
+  - Sources: <https://datatracker.ietf.org/doc/html/rfc8725> · <https://www.ietf.org/archive/id/draft-ietf-oauth-v2-1-13.html> · <https://portswigger.net/web-security/jwt>
+- A verification path that throws, returns a library error object, or falls through to an anonymous identity is a rejection unless the request then proceeds to the protected resource - the observable is the protected response, not the absence of an exception.  _(merged 1 duplicate row(s))_
   - **Disproof:** The claim is false if the fallthrough path does serve protected data - that is precisely the bypass, and the observable becomes the returned resource. It is also false when the error is swallowed but a side effect has already occurred, for example a signature check that fails after a database write, or an algorithm rejection that happens after the token's claims have been used to select a tenant or an account. And the strictness of 'the entire JWT must be rejected' has a documented exception in the spec's own framing for unsecured JWTs, which are legitimately created for use cases where the content is secured by a means outside the JWT, so a verifier that accepts alg none only where that is the intended design is not in violation - the burden is on showing the design did not intend it.
   - Sources: <https://www.rfc-editor.org/rfc/rfc8725.txt> · <https://clerk.com/docs/reference/backend/verify-token>
-- A JWT that verifies cryptographically at an unintended resource is not evidence that the endpoint accepts it; RFC 8725 requires the audience to be present and associated with the recipient, and absence of aud must be a rejection.
-  - **Disproof:** The claim is false when the deployment genuinely has one resource and one audience, in which case substitution is not expressible and the aud check has nothing to compare against - a single-recipient system is not vulnerable to this attack. It is also false when the tokens are sender-constrained: RFC 9700 describes sender-constrained access tokens as scoping an access token's applicability to a certain sender, one obliged to demonstrate knowledge of a certain secret as a prerequisite for acceptance, so a token replayed by a different holder fails on the proof, not on the audience. And where the verifier does check aud, the finding is simply false: presenting a foreign-audience token and getting a 401 is the control working.
-  - Sources: <https://www.rfc-editor.org/rfc/rfc8725.txt> · <https://clerk.com/docs/reference/backend/verify-token>
-- The mere presence of `jku`, `jwk`, `x5u`, `x5c` or `kid` in legitimately issued tokens is normal key selection, not a vulnerability; only unauthenticated resolution is.
+- An unsigned JWT accepted without a signature is only a validated finding when the same unmodified token reaches a protected endpoint carrying no other credential, because a library may ignore alg=none yet still require a session cookie or CSRF token on that route.  _(merged 1 duplicate row(s))_
+  - **Disproof:** If a request carrying ONLY the unsigned token and no other credential reaches a resource that a credential-less request demonstrably cannot, signature enforcement is absent and the finding is real.
+  - Sources: <https://datatracker.ietf.org/doc/html/rfc8725> · <https://www.ietf.org/archive/id/draft-ietf-oauth-v2-1-13.html> · <https://portswigger.net/web-security/jwt>
+- Changing an aud or iss claim and observing no behavioural difference is NOT evidence that audience validation is absent, unless the token is otherwise validly signed and reaches an endpoint whose authorization decision depends on that claim.  _(merged 1 duplicate row(s))_
+  - **Disproof:** If a mutably-signed token carrying a modified aud claim is accepted by a resource belonging to a different relying party, audience validation is genuinely absent and the finding stands.
+  - Sources: <https://datatracker.ietf.org/doc/html/rfc8725> · <https://www.ietf.org/archive/id/draft-ietf-oauth-v2-1-13.html> · <https://portswigger.net/web-security/jwt>
+- Reportable only if a none-alg token is actually honoured; 400/415 responses to `None`, `NONE`, whitespace or unencoded variants are filtering working.  _(merged 1 duplicate row(s))_
+  - **Disproof:** Every `alg:none` variant, including malformed and case-varied headers, returns a client error and never an authenticated response.
+  - Sources: <https://www.rfc-editor.org/rfc/rfc8725.html> · <https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_Cheat_Sheet.html>
+- The mere presence of `jku`, `jwk`, `x5u`, `x5c` or `kid` in legitimately issued tokens is normal key selection, not a vulnerability; only unauthenticated resolution is.  _(merged 1 duplicate row(s))_
   - **Disproof:** Attacker-supplied `jwk`, `jku` and `x5u` key locations are ignored while the server verifies against its own preconfigured key set.
   - Sources: <https://cwe.mitre.org/data/definitions/347.html> · <https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_Cheat_Sheet.html>
... (truncated)
```

## 2026-10-04 00:50 — 15 diff lines
- items: 30 (supported 25), FP rules 21, chains 1, state mature

```diff
--- jwt@current
+++ jwt@new
@@ -184,10 +184,8 @@
 
 ## Hunt procedure
 
-1. Enumerate the surface before probing: collect every endpoint, parameter and object id the class could plausibly sit on.
-2. Establish a CONTROLLED BASELINE first — one unauthenticated and one authenticated low-privilege request per candidate — and diff against the probe. A difference with no baseline proves nothing.
-3. Change exactly ONE variable per probe. Two changes produce a difference you cannot attribute.
-4. Record raw request and response pairs verbatim, including headers, before you interpret anything.
+1. Decode the token and read the algorithm in the HEADER, not the one the library defaults to. Test alg:none, HS256 signed with the RS256 public key as the HMAC secret, and an empty signature.
+2. Confirm the server validates the signature at all by mutating a claim and re-sending the original token.
 
 ### What counts as proof
 
```
