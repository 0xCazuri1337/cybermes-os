# Methodology — JWT / Token Validation Failures

> Derived from 20 verified items. Regenerate with `python -m wks.methodgen --class jwt --apply`. Do not hand-edit: this file is a projection of the evidence, and edits are lost on the next cycle.

**Surface.** The application fails to verify a token's signature, algorithm or claims before making an authorization decision.

**References.** CWE-347 · API8:2023

## 1. Preconditions

_Nothing below is reachable until these hold. Confirm each against the target before spending time on the technique._

**Algorithm confusion is only possible when the verifier's key/algorithm choice is taken from the attacker-controlled `alg` header rather than a server-side allowlist bound to the key.**

Confirm the deployment verifies JWTs with an algorithm-agnostic API that reads `alg` from the token header and hands one fixed key object to it (the classic `verify(token, publicKey)` pattern). In a black-box engagement, the observable signature is asymmetric: a token whose `alg` was flipped from RS256 to HS256 returns 200/302 or an authenticated response instead of an 'invalid signature' error. If every non-RSA alg is rejected outright, the prerequisite is absent and the finding is not a bug.

- *Disproof:* An RS256->HS256 token signed with the server's public key is rejected with an explicit signature/algorithm error on every attempt, including HS384/HS512 variants.
- *Evidence:* high_confidence — [portswigger.net](https://portswigger.net/web-security/jwt/algorithm-confusion); [rfc-editor.org](https://www.rfc-editor.org/rfc/rfc8725.html)

**A successful RS256-to-HS256 forgery requires the attacker's copy of the public key to be byte-identical to the server's stored copy, including PEM formatting and newlines.**

Enumerate key material before attempting forgery: hit `/.well-known/jwks.json`, `/jwks.json`, OIDC discovery documents, JWKS endpoints advertised in `.well-known/openid-configuration`, and any key cached in a JS bundle. Convert JWK to X.509 PEM and, if the app stores PKCS#1 or SSH-format keys, try each. If no key is published, derive candidate moduli from two RS256 tokens and replay one forged token per candidate. If none is accepted, report the key as not obtainable, not as confirmed-safe.

- *Disproof:* A single attacker-signed HS256 token built from every published key format and every derived modulus candidate is rejected by the server.
- *Evidence:* high_confidence — [cheatsheetseries.owasp.org](https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_Cheat_Sheet.html); [portswigger.net](https://portswigger.net/web-security/jwt/algorithm-confusion)

## 2. Reconnaissance signals

_What to look for while mapping the surface, and where each signal tells you the rest of the procedure is worth running._

**A token with header `{"alg":"none"}` (and, correctly formed, a trailing dot and empty signature) that the server honours indicates the verifier accepts unsecured JWTs.**

Base64url-decode the header of every token the target issues, record the `alg` value used in production, then replay a token with `alg` set to `none`, empty signature, and payload claims you control (flip `sub`, `isAdmin`, or `role`). Send it to the same endpoint that issued the session. Treat acceptance as the signal; a 401/403 is the expected-rejection baseline you must record before escalating anything.

- *Disproof:* The `alg:none` token is rejected with 401/403 or an 'invalid signature' response, identical to a token whose payload was tampered with.
- *Evidence:* high_confidence — [portswigger.net](https://portswigger.net/web-security/jwt); [rfc-editor.org](https://www.rfc-editor.org/rfc/rfc8725.html)

**A server that accepts a token signed with a key you supplied inside the token itself (jwk, jku, x5u, x5c) is resolving its trust anchor from unauthenticated token input.**

Baseline first: capture a legitimate token and note whether it already carries `jwk`, `jku`, `x5u` or `x5c`. Generate your own RSA keypair, re-sign a modified payload, and add each header in turn (`jwk` embedded, `jku` pointing at a host you control serving a JWK Set, `x5c` with a self-signed chain). Also enumerate the server's own JWKS: multiple `kid` values, retired keys still published, or keys from other issuers indicate a weak trust boundary.

- *Disproof:* Every attacker-supplied key location is ignored, and the server verifies only against keys it resolved out of band from its own pinned or discovered key set.
- *Evidence:* high_confidence — [cheatsheetseries.owasp.org](https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_Cheat_Sheet.html); [portswigger.net](https://portswigger.net/web-security/jwt)

## 3. Test sequence

_Concrete mutations to try. Each is written to be executable, not to be a description of the vulnerability._

**Re-signing a modified payload with HS256 using the server's own RSA public key as the HMAC secret yields a token the confused verifier accepts.**

Obtain the public key, convert to the server's storage format, set the header `alg` to HS256, edit the payload (identity or role claim), and sign with the PEM as the HMAC secret. Where no key is published, run sig2n-style derivation over two RS256 tokens from the same issuer, emit a forged token per candidate modulus, and replay each in Repeater; only one is accepted, and that key then completes the confusion attack. Record the exact request/response pair as proof.

- *Disproof:* Every HS256 token signed with the published or derived public key is rejected, and the server never verifies a MAC against a key whose type is public.
- *Evidence:* high_confidence — [portswigger.net](https://portswigger.net/web-security/jwt/algorithm-confusion); [rfc-editor.org](https://www.rfc-editor.org/rfc/rfc8725.html)

**When `kid` selects a key from the filesystem and symmetric algorithms are allowed, pointing `kid` at an empty file gives a known zero-length HMAC secret.**

Set `kid` to traversal payloads (`../../dev/null`, absolute paths, URL-encoded variants) and sign with the empty string as the MAC secret. Then try SQL/LDAP payloads in `kid` if keys live in a database. The empty-file case succeeds only when the server reads `kid` as a path AND accepts HS256 with that file's contents as the secret; capture the accepted request verbatim to prove both halves.

- *Disproof:* Traversal payloads produce an error or fall back to a default key, and the same forged token is rejected on replay.
- *Evidence:* high_confidence — [portswigger.net](https://portswigger.net/web-security/jwt); [rfc-editor.org](https://www.rfc-editor.org/rfc/rfc8725.html)

**A verifier that resolves the key by header `kid`/`jku` against a multi-key set still accepts tokens signed with retired-but-still-published keys or keys belonging to another trusted issuer.**

Pull the full JWKS and enumerate every `kid` (current, previous, partner-tenant, self-service). Mint a token naming a retired `kid` and re-sign with the corresponding private key if you hold one, or present a legitimately issued token that carries a foreign `kid` at an endpoint that does not scope keys to its own issuer. For `jku`, host your own JWK Set and exploit URL-parsing filter discrepancies (userinfo, redirect, path tricks) to get the server to fetch it.

- *Disproof:* Only keys bound to the validated issuer and current key version verify; retired and foreign `kid` values yield a lookup failure and a rejected token.
- *Evidence:* high_confidence — [cheatsheetseries.owasp.org](https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_Cheat_Sheet.html); [portswigger.net](https://portswigger.net/web-security/jwt)

## 4. Validation

_How to prove the finding rather than infer it. A technique that cannot be validated must not be reported._

**A verifier passes only if the accepted algorithm set is a server-side allowlist, the key type matches that algorithm, and the whole token is rejected if any check fails.**

Send a matrix: correct token (control), payload-tampered token, RS256->HS256, ES256->HS256, alg:none, alg:NONE/None casing, and a token signed by an unrelated key. Only the control should be accepted. Any 200/302 or authenticated API response for a tampered or downgraded token is a real finding; a uniform 401 with an explicit error is correct behaviour. Also check nested/inner signatures are validated, not just the outer one.

- *Disproof:* All seven variants except the unmodified control are rejected with the same error, and no variant returns authenticated content or a session cookie.
- *Evidence:* high_confidence — [cheatsheetseries.owasp.org](https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_Cheat_Sheet.html); [rfc-editor.org](https://www.rfc-editor.org/rfc/rfc8725.html)

**A 400/401 on a forged JWT is the expected rejection, not evidence of a flaw; a finding requires proof the verifier accepted an attacker-signed token.**

Define acceptance before testing: HTTP 200, a redirect into an authenticated area, a Set-Cookie establishing a session, or an API response body containing another user's data. Error text alone ('invalid signature', 'token expired') proves the check fired. Never report 'the server returned an error' as a vulnerability, and never treat a 500 or a stack trace as acceptance - capture the status code and body for each test case and only escalate on demonstrated acceptance.

- *Disproof:* The only observed outcomes are error statuses with signature-verification messages; no forged token ever produced an authenticated response.
- *Evidence:* high_confidence — [cwe.mitre.org](https://cwe.mitre.org/data/definitions/347.html); [portswigger.net](https://portswigger.net/web-security/jwt)

## 5. False-positive rejection

_The checks that eliminate the most common non-findings. Run these BEFORE reporting, not after a rejection._

**An unsigned JWT accepted without a signature is only a validated finding when the same unmodified token reaches a protected endpoint carrying no other credential, because a library may ignore alg=none yet still require a session cookie or CSRF token on that route.**

Send the unsigned token twice: once with no cookies and no Authorization header, once with a valid session cookie omitted. If the credential-free request returns 401 and only the cookie-bearing one succeeds, nothing was proven about signature enforcement. The distinction is between a parser accepting a token shape and an authorizer granting access.

- *Disproof:* If a request carrying ONLY the unsigned token and no other credential reaches a resource that a credential-less request demonstrably cannot, signature enforcement is absent and the finding is real.
- *Evidence:* high_confidence — [datatracker.ietf.org](https://datatracker.ietf.org/doc/html/rfc8725); [ietf.org](https://www.ietf.org/archive/id/draft-ietf-oauth-v2-1-13.html); [portswigger.net](https://portswigger.net/web-security/jwt)

**Reportable only if a none-alg token is actually honoured; 400/415 responses to `None`, `NONE`, whitespace or unencoded variants are filtering working.**

Before reporting, run the full obfuscation set (case variants, `none ` with trailing space, percent/unicode-escaped header bytes, missing vs present trailing dot, alg omitted entirely). If all variants are rejected, close the item as not vulnerable and note the library's default. If exactly one encoding is accepted, the finding is real but the impact still depends on whether that endpoint issues sessions or gates data.

- *Disproof:* Every `alg:none` variant, including malformed and case-varied headers, returns a client error and never an authenticated response.
- *Evidence:* high_confidence — [cheatsheetseries.owasp.org](https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_Cheat_Sheet.html); [rfc-editor.org](https://www.rfc-editor.org/rfc/rfc8725.html)

**A finding that a kid or jku header value reaches an outbound request is only validated when an attacker-controlled server actually receives the callback, because the header may be parsed, logged and echoed without ever being dereferenced.**

Point kid or jku at a host you control and wait for a request. A value appearing in a stack trace or an error message is not proof of an outbound fetch: many stacks echo the header while the actual key lookup uses a static or pre-resolved key set. Only a received request establishes that the value reached a network sink, and without one the SSRF claim rests on reflection alone.

- *Disproof:* If a request carrying the attacker-controlled kid value arrives at the designated server and the response influences the key actually used for verification, the header is dereferenced and the finding is real.
- *Evidence:* high_confidence — [datatracker.ietf.org](https://datatracker.ietf.org/doc/html/rfc8725); [ietf.org](https://www.ietf.org/archive/id/draft-ietf-oauth-v2-1-13.html); [portswigger.net](https://portswigger.net/web-security/jwt)

**Changing an aud or iss claim and observing no behavioural difference is NOT evidence that audience validation is absent, unless the token is otherwise validly signed and reaches an endpoint whose authorization decision depends on that claim.**

Audience confusion is a finding only when the relying party fails to check the claim it was supposed to check. Modifying a claim the server never reads yields identical behaviour whether validation is correct or entirely missing, so the observation carries no information. Establish which claims the app demonstrably consumes, mutate one of those, and only then attribute behaviour to claim validation.

- *Disproof:* If a mutably-signed token carrying a modified aud claim is accepted by a resource belonging to a different relying party, audience validation is genuinely absent and the finding stands.
- *Evidence:* high_confidence — [datatracker.ietf.org](https://datatracker.ietf.org/doc/html/rfc8725); [ietf.org](https://www.ietf.org/archive/id/draft-ietf-oauth-v2-1-09.html); [portswigger.net](https://portswigger.net/web-security/jwt)

**The mere presence of `jku`, `jwk`, `x5u`, `x5c` or `kid` in legitimately issued tokens is normal key selection, not a vulnerability; only unauthenticated resolution is.**

Diff the headers of several legitimate tokens before flagging. If every issued token already carries `kid` and the server still rejects a token signed with your own embedded `jwk` or fetched from your `jku` host, close as not vulnerable - the header is being used as a selector within an already-trusted set. A finding needs the injected key actually used for verification, proven by your forged token being accepted.

- *Disproof:* Attacker-supplied `jwk`, `jku` and `x5u` key locations are ignored while the server verifies against its own preconfigured key set.
- *Evidence:* high_confidence — [cheatsheetseries.owasp.org](https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_Cheat_Sheet.html); [cwe.mitre.org](https://cwe.mitre.org/data/definitions/347.html)

## 6. Known bypasses

_Filters and controls that have defeated the techniques above. Treat these as the reason a naive test fails, not as proof of safety._

**Servers that string-parse to reject `alg: none` can be bypassed with mixed capitalization, unexpected encodings, or an omitted trailing dot handling difference.**

Iterate over case variants (`none`, `None`, `NONE`, `nOnE`), encodings (URL-encoded, unicode-escaped, duplicate JSON `alg` keys), and header-shape variants (empty signature with and without the trailing dot, signature set to garbage). One accepted variant converts a rejected probe into full token forgery. Test on the same endpoint that issued the session, since some deployments only validate alg on refresh or logout paths.

- *Disproof:* All case and encoding variants of the `none` header are rejected identically to a well-formed signature error, and no variant authenticates.
- *Evidence:* high_confidence — [portswigger.net](https://portswigger.net/web-security/jwt); [rfc-editor.org](https://www.rfc-editor.org/rfc/rfc8725.html)

## 7. Chaining

_How this class escalates when combined with others. Each step is anchored to a promoted item._

**A verified forgery becomes account takeover, not info disclosure, only when the edited claim drives server-side identity or authorization decisions.**

Map which claim the server acts on: `username`/`sub` for session lookup, `isAdmin`/`role` for access control, or a tenant/account id. Replay the forged token to (a) the endpoint that issued it, (b) an authenticated API call, (c) the admin panel, (d) a second service sharing the issuer to test audience confusion. Successful cross-endpoint identity change or privilege change is the escalation; a decoded-but-unused claim is disclosure only.

- *Disproof:* The forged token is accepted syntactically but the server re-derives identity from server-side session state or the edited claim grants no additional access.
- *Evidence:* high_confidence — [cwe.mitre.org](https://cwe.mitre.org/data/definitions/347.html); [portswigger.net](https://portswigger.net/web-security/jwt)

## 8. Impact

_What is actually demonstrable, and what to stop claiming._

**Reading JWT claims is not a finding: a signed JWT provides integrity and authenticity but not confidentiality, so only forgery or failed verification is a vulnerability.**

Base64url-decode a captured token and record what it exposes (emails, internal ids, roles) as a defence-in-depth observation, then check whether any of it is sensitive beyond the client. Rate the finding by what the signature controls: a forged token that grants access, changes identity, or replays across recipients is high/critical; a token that only discloses its own already-known claims is informational and usually not reportable.

- *Disproof:* Decoding reveals only claims the requesting user already owns, and no signature, issuer, or recipient trust decision can be influenced by them.
- *Evidence:* high_confidence — [cheatsheetseries.owasp.org](https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_Cheat_Sheet.html); [portswigger.net](https://portswigger.net/web-security/jwt)

---

*Generated from the evidence base. Where this file and the database disagree, the database is correct.*
