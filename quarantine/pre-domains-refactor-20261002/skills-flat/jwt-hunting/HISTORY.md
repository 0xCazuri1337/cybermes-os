# History

Append-only. Each entry records WHY the skill changed, not just that it did. Improvement means better hunting behaviour, not more text.

## 2026-10-02 00:09 — 1 diff lines
- items: 14 (supported 14), FP rules 0, chains 0, state researching
- still missing: fp_rules, chain

```diff
(initial generation, 2026-10-02)
```

## 2026-10-02 01:36 — 11 diff lines
- items: 14 (supported 14), FP rules 0, chains 0, state researching
- still missing: fp_rules, chain

```diff
--- jwt@current
+++ jwt@new
@@ -7,7 +7,7 @@
 
 <!-- GENERATED from db/wks.db by wks/skillgen.py. DO NOT HAND-EDIT.
      Edit the rows (or ingest better research) and re-run:
-     python -m wks.skillgen -->
+     python -m wks.skillgen -->
 
 > surface `identity` · CWE CWE-347 · OWASP API8:2023
 > evidence: 14 items, 14 supported, 0 FP rules, 0 chains
```

## 2026-10-02 10:30 — 134 diff lines
- items: 17 (supported 14), FP rules 15, chains 1, state mature

```diff
--- jwt@current
+++ jwt@new
@@ -10,8 +10,8 @@
      python -m wks.skillgen -->
 
 > surface `identity` · CWE CWE-347 · OWASP API8:2023
-> evidence: 14 items, 14 supported, 0 FP rules, 0 chains
-> maturity: **researching** — missing: fp_rules, chain
+> evidence: 17 items, 14 supported, 15 FP rules, 1 chains
+> maturity: **mature**
 
 The application fails to verify a token's signature, algorithm or claims before making an authorization decision.
 
@@ -22,7 +22,7 @@
 
 - Algorithm confusion is only possible when the verifier's key/algorithm choice is taken from the attacker-controlled `alg` header rather than a server-side allowlist bound to the key.
   - **Disproof:** An RS256->HS256 token signed with the server's public key is rejected with an explicit signature/algorithm error on every attempt, including HS384/HS512 variants.
-  - Sources: <https://portswigger.net/web-security/jwt/algorithm-confusion> · <https://www.rfc-editor.org/rfc/rfc8725.html>
+  - Sources: <https://www.rfc-editor.org/rfc/rfc8725.html> · <https://portswigger.net/web-security/jwt/algorithm-confusion>
 - A successful RS256-to-HS256 forgery requires the attacker's copy of the public key to be byte-identical to the server's stored copy, including PEM formatting and newlines.
   - **Disproof:** A single attacker-signed HS256 token built from every published key format and every derived modulus candidate is rejected by the server.
   - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_Cheat_Sheet.html> · <https://portswigger.net/web-security/jwt/algorithm-confusion>
@@ -34,16 +34,16 @@
   - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_Cheat_Sheet.html> · <https://portswigger.net/web-security/jwt>
 - A token with header `{"alg":"none"}` (and, correctly formed, a trailing dot and empty signature) that the server honours indicates the verifier accepts unsecured JWTs.
   - **Disproof:** The `alg:none` token is rejected with 401/403 or an 'invalid signature' response, identical to a token whose payload was tampered with.
-  - Sources: <https://portswigger.net/web-security/jwt> · <https://www.rfc-editor.org/rfc/rfc8725.html>
+  - Sources: <https://www.rfc-editor.org/rfc/rfc8725.html> · <https://portswigger.net/web-security/jwt>
 
 ## Techniques (what to change)
 
 - When `kid` selects a key from the filesystem and symmetric algorithms are allowed, pointing `kid` at an empty file gives a known zero-length HMAC secret.
   - **Disproof:** Traversal payloads produce an error or fall back to a default key, and the same forged token is rejected on replay.
-  - Sources: <https://portswigger.net/web-security/jwt> · <https://www.rfc-editor.org/rfc/rfc8725.html>
+  - Sources: <https://www.rfc-editor.org/rfc/rfc8725.html> · <https://portswigger.net/web-security/jwt>
 - Re-signing a modified payload with HS256 using the server's own RSA public key as the HMAC secret yields a token the confused verifier accepts.
   - **Disproof:** Every HS256 token signed with the published or derived public key is rejected, and the server never verifies a MAC against a key whose type is public.
-  - Sources: <https://portswigger.net/web-security/jwt/algorithm-confusion> · <https://www.rfc-editor.org/rfc/rfc8725.html>
+  - Sources: <https://www.rfc-editor.org/rfc/rfc8725.html> · <https://portswigger.net/web-security/jwt/algorithm-confusion>
 - A verifier that resolves the key by header `kid`/`jku` against a multi-key set still accepts tokens signed with retired-but-still-published keys or keys belonging to another trusted issuer.
   - **Disproof:** Only keys bound to the validated issuer and current key version verify; retired and foreign `kid` values yield a lookup failure and a rejected token.
   - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_Cheat_Sheet.html> · <https://portswigger.net/web-security/jwt>
@@ -52,7 +52,7 @@
 
 - A verifier passes only if the accepted algorithm set is a server-side allowlist, the key type matches that algorithm, and the whole token is rejected if any check fails.
   - **Disproof:** All seven variants except the unmodified control are rejected with the same error, and no variant returns authenticated content or a session cookie.
-  - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_Cheat_Sheet.html> · <https://www.rfc-editor.org/rfc/rfc8725.html>
+  - Sources: <https://www.rfc-editor.org/rfc/rfc8725.html> · <https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_Cheat_Sheet.html>
 - A 400/401 on a forged JWT is the expected rejection, not evidence of a flaw; a finding requires proof the verifier accepted an attacker-signed token.
   - **Disproof:** The only observed outcomes are error statuses with signature-verification messages; no forged token ever produced an authenticated response.
   - Sources: <https://cwe.mitre.org/data/definitions/347.html> · <https://portswigger.net/web-security/jwt>
@@ -61,10 +61,19 @@
 
 - The mere presence of `jku`, `jwk`, `x5u`, `x5c` or `kid` in legitimately issued tokens is normal key selection, not a vulnerability; only unauthenticated resolution is.
   - **Disproof:** Attacker-supplied `jwk`, `jku` and `x5u` key locations are ignored while the server verifies against its own preconfigured key set.
-  - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_Cheat_Sheet.html> · <https://cwe.mitre.org/data/definitions/347.html>
+  - Sources: <https://cwe.mitre.org/data/definitions/347.html> · <https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_Cheat_Sheet.html>
 - Reportable only if a none-alg token is actually honoured; 400/415 responses to `None`, `NONE`, whitespace or unencoded variants are filtering working.
   - **Disproof:** Every `alg:none` variant, including malformed and case-varied headers, returns a client error and never an authenticated response.
-  - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_Cheat_Sheet.html> · <https://www.rfc-editor.org/rfc/rfc8725.html>
+  - Sources: <https://www.rfc-editor.org/rfc/rfc8725.html> · <https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_Cheat_Sheet.html>
+- An unsigned JWT accepted without a signature is only a validated finding when the same unmodified token reaches a protected endpoint carrying no other credential, because a library may ignore alg=none yet still require a session cookie or CSRF token on that route. _(unverified)_
+  - **Disproof:** If a request carrying ONLY the unsigned token and no other credential reaches a resource that a credential-less request demonstrably cannot, signature enforcement is absent and the finding is real.
+  - Sources: <https://datatracker.ietf.org/doc/html/rfc8725> · <https://www.ietf.org/archive/id/draft-ietf-oauth-v2-1-13.html>
+- A finding that a kid or jku header value reaches an outbound request is only validated when an attacker-controlled server actually receives the callback, because the header may be parsed, logged and echoed without ever being dereferenced. _(unverified)_
+  - **Disproof:** If a request carrying the attacker-controlled kid value arrives at the designated server and the response influences the key actually used for verification, the header is dereferenced and the finding is real.
+  - Sources: <https://datatracker.ietf.org/doc/html/rfc8725> · <https://www.ietf.org/archive/id/draft-ietf-oauth-v2-1-13.html>
+- Changing an aud or iss claim and observing no behavioural difference is NOT evidence that audience validation is absent, unless the token is otherwise validly signed and reaches an endpoint whose authorization decision depends on that claim. _(unverified)_
+  - **Disproof:** If a mutably-signed token carrying a modified aud claim is accepted by a resource belonging to a different relying party, audience validation is genuinely absent and the finding stands.
+  - Sources: <https://datatracker.ietf.org/doc/html/rfc8725> · <https://www.ietf.org/archive/id/draft-ietf-oauth-v2-1-09.html>
 
 ## Impact framing
 
@@ -76,7 +85,7 @@
 
 - Servers that string-parse to reject `alg: none` can be bypassed with mixed capitalization, unexpected encodings, or an omitted trailing dot handling difference.
   - **Disproof:** All case and encoding variants of the `none` header are rejected identically to a well-formed signature error, and no variant authenticates.
-  - Sources: <https://portswigger.net/web-security/jwt> · <https://www.rfc-editor.org/rfc/rfc8725.html>
+  - Sources: <https://www.rfc-editor.org/rfc/rfc8725.html> · <https://portswigger.net/web-security/jwt>
 
 ## Chaining opportunities
 
@@ -84,5 +93,51 @@
   - **Disproof:** The forged token is accepted syntactically but the server re-derives identity from server-side session state or the edited claim grants no additional access.
   - Sources: <https://cwe.mitre.org/data/definitions/347.html> · <https://portswigger.net/web-security/jwt>
 
+## Rejected before you report
+
+- **The server accepts unsigned tokens because a token with alg set to none is honoured**
+  - Killed by: The identical unsigned token was also accepted with a completely random subject claim, and the endpoint returned the same body for a request with no token at all - the route is public and never read the token
+  - Rule: A 200 on a modified token is only a JWT finding if the same 200 does not occur with no token at all; always capture the no-credential baseline for the endpoint first
+- **Signature verification is broken because a token signed with an attacker key is accepted**
+  - Killed by: The server returned the same 200 and the same body for the valid-looking token, an invalid one, and no token, so nothing in the request path consulted the signature
+  - Rule: Forged-token acceptance needs a negative control: if a malformed, a wrongly-keyed and a token-less request all return the same 200, the endpoint never verified anything
+- **The kid header is injectable because a path traversal value caused a different error**
+  - Killed by: Any kid naming a missing file produced the same 500, including a nonsense name with no traversal characters, so the failure is a missing key file and not a traversal
+  - Rule: A traversal claim needs a control where only the path characters differ; an identical error for a plain missing filename is a missing-file error, not traversal
+- **The server ignores the exp claim because an expired token is still accepted**
+  - Killed by: The response was a static public shell identical to the token-less baseline, and the session cookie was never reissued, so the token was parsed but not used for the authorization decision
+  - Rule: Expired-token acceptance must be proven by a reissued session or a protected resource, not by a 200 on a route that returns the same body without any token
+- **Role claim tampering grants admin because a user-role token with role admin is honoured**
+  - Killed by: The user-role token returned the same administrative page shell as before with an empty user list, and the identical page was served with a role of auditor and with the role claim deleted entirely
+  - Rule: Role tampering is proven by privileged DATA or an action, not by an admin-shaped page; a shell that renders identically for every role is a routing artefact
+- **The jwk x5u header is exploitable because a token referencing an attacker-hosted key is accepted**
+  - Killed by: After re-hosting, both tokens continued to validate against the ORIGINAL public key, showing the server used a cached key and never fetched the attacker's URL at all
+  - Rule: A remote-key header is only proven fetched when changing the hosted key changes the validation outcome; unchanged behaviour proves a cache or a hardcoded key
+- **The token signature is not verified because altering the payload without re-signing still works**
+  - Killed by: The response echoed the ORIGINAL subject, not the edited one, proving the server re-read a trusted source such as a session store or a re-issued token rather than trusting the presented claims
+  - Rule: Editing a claim is only an attack if the server ACTS on the edited value; if the response still reflects the original identity, the claims are not the source of truth
+- **The API accepts tokens signed with the HS256 algorithm using the RSA public key as the HMAC secret**
+  - Killed by: The very same token was accepted by an endpoint that also accepts no token at all, and the protected endpoint in the same application rejected it consistently
+  - Rule: Algorithm-confusion proof needs a protected endpoint that rejects the forged token; acceptance on a route that is permissive for everyone is not a finding
+- **The mere presence of `jku`, `jwk`, `x5u`, `x5c` or `kid` in legitimately issued tokens is normal key selection, not a vulnerability; only unauthenticated resolution is.**
+  - Killed by: Attacker-supplied `jwk`, `jku` and `x5u` key locations are ignored while the server verifies against its own preconfigured key set.
+  - Rule: The mere presence of `jku`, `jwk`, `x5u`, `x5c` or `kid` in legitimately issued tokens is normal key selection, not a vulnerability; only unauthenticated resolution is.
+- **Reportable only if a none-alg token is actually honoured; 400/415 responses to `None`, `NONE`, whitespace or unencoded variants are filtering working.**
+  - Killed by: Every `alg:none` variant, including malformed and case-varied headers, returns a client error and never an authenticated response.
+  - Rule: Reportable only if a none-alg token is actually honoured; 400/415 responses to `None`, `NONE`, whitespace or unencoded variants are filtering working.
+- **An unsigned JWT accepted without a signature is only a validated finding when the same unmodified token reaches a protected endpoint carrying no other credential, because a library may ignore alg=none yet still require a session cookie or CSRF token on that route.**
+  - Killed by: If a request carrying ONLY the unsigned token and no other credential reaches a resource that a credential-less request demonstrably cannot, signature enforcement is absent and the finding is real.
... (truncated)
```

## 2026-10-02 13:38 — 33 diff lines
- items: 20 (supported 17), FP rules 15, chains 1, state mature

```diff
--- jwt@current
+++ jwt@new
@@ -10,7 +10,7 @@
      python -m wks.skillgen -->
 
 > surface `identity` · CWE CWE-347 · OWASP API8:2023
-> evidence: 17 items, 14 supported, 15 FP rules, 1 chains
+> evidence: 20 items, 17 supported, 15 FP rules, 1 chains
 > maturity: **mature**
 
 The application fails to verify a token's signature, algorithm or claims before making an authorization decision.
@@ -38,6 +38,15 @@
 
 ## Techniques (what to change)
 
+- This cheat sheet provides tips to prevent common security issues when using JSON Web Tokens (JWT).
+  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "This cheat sheet provides tips to prevent common security issues when using JSON Web Token".
+  - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_Cheat_Sheet.html> · <https://portswigger.net/web-security/jwt>
+- In OAuth 2 , the access token used to obtain access to a protected resource can be a JWT .
+  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "In OAuth 2 , the access token used to obtain access to a protected resource can be a JWT .".
+  - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_Cheat_Sheet.html> · <https://portswigger.net/web-security/jwt>
+- A DPoP Proof JWT can be used to prove possession of a private key.
+  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "A DPoP Proof JWT can be used to prove possession of a private key.".
+  - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_Cheat_Sheet.html> · <https://portswigger.net/web-security/jwt>
 - When `kid` selects a key from the filesystem and symmetric algorithms are allowed, pointing `kid` at an empty file gives a known zero-length HMAC secret.
   - **Disproof:** Traversal payloads produce an error or fall back to a default key, and the same forged token is rejected on replay.
   - Sources: <https://www.rfc-editor.org/rfc/rfc8725.html> · <https://portswigger.net/web-security/jwt>
@@ -140,4 +149,4 @@
 - `idor` (3 shared chain(s))
 
 ---
-Full class document: `classes/jwt.md` · retrieve more with `python -m wks.cli search "<query>" --class-id jwt`
+Full class document: `skills/Web/jwt/EVIDENCE.md` · retrieve more with `python -m wks.cli search "<query>" --class-id jwt`
```
