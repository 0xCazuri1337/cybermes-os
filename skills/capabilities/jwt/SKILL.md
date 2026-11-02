---
name: jwt
description: "Canonical JWT capability: hunting, validating, and exploiting JSON Web Token cryptographic and claim-handling weaknesses across APIs, OAuth/OIDC, and SSO. Consolidates 5 sub-skills: exploiting-jwt-algorithm-confusion-attack, hunt-jwt-crypto, performing-jwt-none-algorithm-attack, testing-for-json-web-token-vulnerabilities, testing-jwt-token-security. Use when hunting or validating JWT-related vulnerabilities."
sources: consolidated
---

# JWT — Canonical Capability

## 1. Identity and purpose

This is the single primary executable capability for JSON Web Token (JWT) security testing. It consolidates 5 previously separate sub-skills (`exploiting-jwt-algorithm-confusion-attack`, `hunt-jwt-crypto`, `performing-jwt-none-algorithm-attack`, `testing-for-json-web-token-vulnerabilities`, `testing-jwt-token-security`) into one operational entry point while preserving all source content in `references/` and the original sub-skill directories for rollback.

Primary objectives:
- Discover JWT-based authentication and authorization flows and extract tokens, claims, and key material.
- Validate signature verification, algorithm enforcement, key selection, and claim validation with proof.
- Exploit algorithm confusion, `alg:none`, kid/jku/x5u/jwk injection, weak HMAC secrets, and claim tampering only with concrete identity/privilege impact.
- Produce reproducible, impact-rated findings with remediation guidance.

## 2. Scope

In scope:
- JWTs used as Bearer tokens, cookies, query parameters, or SSO/OIDC tokens (`eyJ...`).
- JWS signature verification: HS256/384/512, RS256/384/512, ES256/384/512, EdDSA.
- Header attacks: `alg:none` (case variants), RS256→HS256 key confusion, `kid`, `jku`, `jwk`, `x5u`, `x5c` injection.
- Key material handling: JWKS endpoints, public-key extraction, weak/reused HMAC secrets, path traversal/SQLi in kid lookups.
- Claim handling: `sub`, `role`, `isAdmin`, tenant/org claims, `exp`/`nbf`/`iat` enforcement, token revocation.
- Cross-tenant claim swaps and expiry manipulation.

Out of scope (hand off):
- Pure session-management flaws without JWT forgery -> `hunt-session`.
- OAuth provider-side redirect/state flaws unrelated to JWT signature -> `hunt-oauth`.
- SAML/XML signature flaws -> `hunt-saml`.
- General API authorization (BOLA/IDOR) not rooted in token forgery -> `hunt-idor` / `hunt-authz`.

## 3. Invocation and routing

Use this capability when:
- A target authenticates with `eyJ...` Bearer tokens, JWT cookies, or login responses containing JWTs.
- You need to test algorithm enforcement, signature verification, or claim validation.
- A finding involves token forgery, privilege escalation via claims, or cross-tenant access through JWTs.

Routing notes:
- Algorithm confusion and `alg:none` exploitation details -> `references/exploiting-jwt-algorithm-confusion-attack.md`.
- Hunting/payload-driven forgery (admin objective, offline cracking, automated suites) -> `references/hunt-jwt-crypto.md`.
- Focused `none` algorithm crafting and mitigation -> `references/performing-jwt-none-algorithm-attack.md`.
- Broad JWT assessment workflow (jwt_tool, Burp) -> `references/testing-for-json-web-token-vulnerabilities.md`.
- End-to-end token security testing incl. revocation/lifetime -> `references/testing-jwt-token-security.md`.

## 4. Inputs and outputs

Inputs:
- Target base URLs, authenticated test accounts, session cookies, captured requests.
- Valid JWTs from login responses or `Authorization: Bearer` headers.
- JWKS/public-key endpoints, OIDC discovery, TLS certificates.
- Tech stack and JWT library signals.

Outputs:
- Confirmed or refuted JWT findings with raw request/response proof.
- Forged tokens (none, confused, kid-injected, weak-secret) and the exact claim/header used.
- Defense matrix (algorithm allowlist, signature verification, kid validation, jku/x5u handling, expiry/revocation).
- Reproduction steps, impact assessment, and remediation guidance.

## 5. Preconditions and authorization

- Confirm written authorization and scope before testing; include hosts, accounts, and impact boundaries.
- Use only test accounts; never forge tokens against real users' data without authorization.
- Avoid destructive admin actions unless explicitly authorized in a sandbox.
- Coordinate rate limits and token-issuance throttling with the owner.
- Treat all captured tokens as secrets; do not paste production tokens into third-party services.

## 6. Reconnaissance

Recon steps:
1. Trigger login/token issuance and capture `token`, `access_token`, `id_token`, or `Set-Cookie: ...=eyJ...`.
2. Decode the header (base64url first segment) and record `alg`, `typ`, `kid`, `jku`, `jwk`, `x5u`, `x5c`.
3. Identify JWKS/public-key endpoints: `/.well-known/jwks.json`, `/.well-known/openid-configuration`, `/oauth/certs`, `/oauth/token_key`, JS bundles.
4. Extract RSA/EC public keys from JWKS, TLS certificates, or token pairs (rsa_sign2n).
5. Map protected endpoints and roles (`/admin`, `/users`, `/api/*`) and claim names (`sub`, `role`, `isAdmin`, `org_id`, `tenant`).
6. Check token lifetime (`exp`, `nbf`, `iat`) and revocation behavior (logout, password change).
7. Fingerprint JWT library/version from error messages, headers, or framework signals.

## 7. Detection methodology

Core detection flow:
1. Decode and analyze token structure; confirm algorithm family (symmetric vs asymmetric).
2. Test `alg:none` first (free): case variants `none`/`None`/`NONE`/`nOnE`, empty/minimal signatures, missing signature segment.
3. If RS256/ES256 and public key is obtainable, test RS256→HS256 (or ES→HS) key confusion with the public key as HMAC secret; try multiple key encodings (PEM, stripped, base64, DER).
4. Test kid injection: path traversal to `/dev/null` (empty secret), SQLi (`' UNION SELECT ...`), SSRF/URL-based kid, command injection where applicable.
5. Test jku/x5u/jwk header injection: point to attacker-controlled JWKS/cert or embed an attacker public key; try open-redirect/SSRF chains to bypass host allowlists.
6. If HS256 and secret unknown, attempt offline cracking (hashcat mode 16500, jwt_tool, john) with wordlists and targeted guesses.
7. Tamper claims (role/admin/subject/tenant) and test expiry removal/manipulation (`exp` far future, remove `exp`, `nbf` in past).
8. Validate each candidate against protected/admin endpoints; only cross-identity data access or admin action counts as proof.
9. Test token replay after logout/password change and expired-token acceptance.

## 8. Technique selection

Select techniques by observed token and defenses:
- `alg:none` accepted -> immediate privilege escalation; try all case variants and signature formats.
- Asymmetric alg + public key available -> key confusion (RS/ES→HS) first; if blocked, try jku/x5u/jwk injection.
- kid present -> path traversal to empty file, then SQLi/SSRF depending on backend.
- HS256 with unknown secret -> offline cracking; if secret cracked, forge arbitrary tokens.
- Strong signature verification -> focus on claim validation (missing `exp`/`aud`/`iss` checks, token replay, cross-tenant swaps).
- jku host allowlisted -> chain open redirect or SSRF-reachable path on target's own domain.

See `references/hunt-jwt-crypto.md` (admin objective, automation) and `references/exploiting-jwt-algorithm-confusion-attack.md` (step-by-step code).

## 9. Execution steps

1. Capture a valid JWT and decode header/payload; record all claims and headers.
2. Obtain the server public key (JWKS, OIDC, TLS cert, JS bundle) when asymmetric.
3. Forge candidate tokens per technique (none, confused, kid, jku/jwk, weak secret, claim tampering).
4. Send forged token to a protected endpoint; record status, body, headers, timing.
5. Decode the token actually sent to confirm edited claims landed.
6. Escalate to an admin identity and an admin-only endpoint; perform a concrete admin action when authorized.
7. Test token lifetime/revocation: expired token, far-future `exp`, post-logout reuse, post-password-change reuse.
8. Document blocked vectors and move to the next technique; do not loop on a single failed forge.
9. Stop and document when a vector is not exploitable or out of scope.

## 10. Tool usage

- jwt_tool: decoding, tampering (`-T`), `alg:none` (`-X a`), key confusion (`-X k -pk`), jku (`-X s`), jwk injection (`-X i`), cracking (`-C`), kid injection (`-I -hc kid`).
- Burp Suite JWT Editor: interactive decode/edit/resign, automated attack modules.
- PyJWT / Python cryptography: programmatic forging, signature verification experiments.
- hashcat (mode 16500) / john the ripper: GPU/CPU HMAC secret cracking.
- openssl: extract public keys from TLS certificates.
- curl / Python requests / httpx: raw token delivery and response capture.
- jwt.io: quick decode (never paste production tokens).

## 11. Payloads and test cases

`alg:none` header variants:
```json
{"alg":"none","typ":"JWT"}
{"alg":"None","typ":"JWT"}
{"alg":"NONE","typ":"JWT"}
{"alg":"nOnE","typ":"JWT"}
```

Empty/minimal signature formats:
```
<header>.<payload>.
<header>.<payload>
<header>.<payload>.AA==
```

RS256→HS256 key confusion (Python):
```python
import jwt
with open('public_key.pem') as f:
    public_key = f.read()
payload = {"sub":"admin","role":"admin","exp":9999999999}
token = jwt.encode(payload, public_key, algorithm='HS256')
```

kid injection payloads:
```
../../../../../../dev/null
' UNION SELECT 'secret-key' --
' OR '1'='1
../../../etc/passwd
https://attacker.com/key.pem
```

jwk header self-signed key injection:
```json
{"alg":"RS256","typ":"JWT","jwk":{"kty":"RSA","n":"<modulus>","e":"AQAB"}}
```

jku/x5u URLs:
```
https://attacker.com/.well-known/jwks.json
https://target.example.com@attacker.com/jwks
https://target.example.com/.well-known/jwks.json#@attacker.com
```

Claim tampering examples:
```json
{"sub":"administrator","role":"admin","org_id":9999}
{"sub":"victim@org.com","nbf":1000000000,"exp":4102444800}
```

Offline cracking:
```bash
hashcat -a 0 -m 16500 <jwt> rockyou.txt
jwt_tool <token> -C -d wordlist.txt
```

Additional variants, full Python forging code, and automation live in `references/`.

## 12. Evidence

Each finding must include:
- Exact request and response (raw HTTP or tool output) showing the forged token accepted.
- The forged token (header/payload/signature) and the claim/header changed.
- Authentication context (victim/attacker accounts, roles, sessions).
- Public-key or secret source and how it was obtained.
- Anti-JWT defenses present and whether enforced (algorithm allowlist, expiry, revocation).
- Impact assessment (identity assumed, data accessed, admin action performed).
- Remediation guidance.

## 13. Reproduction and validation

- Reproduce with curl or a saved raw request in a clean session where possible.
- Decode and confirm the token sent actually carries the edited claims.
- Validate with two accounts/roles; confirm cross-identity data access or admin action, not just a 200.
- For `alg:none`, try all case variants and signature formats before concluding blocked.
- For key confusion, try multiple public-key encodings.
- For offline cracking, document the recovered secret and a forged token using it.
- Mark as refuted if no concrete identity/privilege impact exists.

## 14. False-positive rejection

Reject or downgrade when:
- `alg:none` rejected (401) for all variants (that flaw is patched; try others).
- Algorithm confusion blocked because the server enforces an algorithm allowlist.
- Key confusion fails for all public-key encodings.
- Kid injection returns 401/403 or no key-material effect.
- A 200 response returns only the caller's own data (no cross-identity impact).
- Expired tokens are correctly rejected.
- A weak secret is not actually cracked (no recovered secret).
- Scanner/JWT-tool output alone without exploit proof.

## 15. Impact

Impact guidance:
- Critical: authentication bypass via forged admin token; arbitrary user impersonation; cross-tenant data access.
- High: privilege escalation to non-admin elevated role; expired/revoked token reuse enabling unauthorized access.
- Medium: claim tampering with limited business impact; information disclosure via JWT payload (PII/internal IDs).
- Low: missing hardening without exploit path (e.g., long expiry) or theoretical weakness.

Always tie impact to concrete identity/privilege loss; "a token was accepted" is not impact without data/action proof.

## 16. Reporting

Report template:
- Summary: endpoint, vulnerability type (JWT), technique, impact.
- Scope/authorization: test accounts and window.
- Steps to reproduce: numbered, minimal.
- Forged token: header, payload, signature (or generation script).
- Defenses tested: algorithm allowlist, signature verification, kid validation, jku/x5u handling, expiry/revocation.
- Impact: identity/privilege/data scope.
- Remediation: enforce algorithm allowlist (`algorithms=["RS256"]`), reject `none`, strong random HMAC secrets (256+ bits), validate kid against allowlist, ignore/validate jku/x5u, require and verify `exp`/`iat`/`nbf`/`iss`/`aud`, implement revocation/blocklist, prefer EdDSA where appropriate.
- References: OWASP JWT Testing Guide, relevant CVEs/advisories.

## 17. Failure modes

- Surface not fully discovered -> expand recon (login flows, mobile, SSO, refresh tokens, WebSocket).
- No test account -> request credentials or scope clarification; do not test without authorization.
- WAF/gateway blocks forged tokens -> try header/cookie delivery, encoding, or chunking.
- Rate limiting on token issuance -> coordinate throttling or test windows.
- Blind/asymmetric-only endpoints -> focus on claim validation and expiry/revocation.
- Inconclusive forge result -> repeat with fresh sessions, decode sent token, mark not confirmed if ambiguous.

## 18. References

All 5 sub-skill references are preserved and must resolve:

| Reference | Sub-capability | Load when |
|---|---|---|
| `references/exploiting-jwt-algorithm-confusion-attack.md` | `exploiting-jwt-algorithm-confusion-attack` | Algorithm confusion, alg:none, kid/jku/x5u/jwk injection |
| `references/hunt-jwt-crypto.md` | `hunt-jwt-crypto` | Hunting/payload-driven forgery, admin objective, offline cracking, automation |
| `references/performing-jwt-none-algorithm-attack.md` | `performing-jwt-none-algorithm-attack` | Focused none-algorithm crafting, mitigation, detection |
| `references/testing-for-json-web-token-vulnerabilities.md` | `testing-for-json-web-token-vulnerabilities` | Broad assessment workflow, jwt_tool/Burp, weak secrets |
| `references/testing-jwt-token-security.md` | `testing-jwt-token-security` | End-to-end token security, lifetime, revocation |

Original sub-skills remain intact under their directories (including each sub-skill's own api-reference.md and agent.py where present).

## 19. Testing and mastery

- Validate with the capability tests in `tests/test_jwt_capability.py`.
- Confirm all referenced files resolve and are non-empty.
- Confirm migration map paths/hashes/status are accurate.
- Practice on authorized labs: PortSwigger JWT, OWASP WebGoat, DVWA, HackTheBox.
- Mastery criteria: independently discover, validate, and report a JWT finding with full reproduction, defense matrix, and impact.


## Knowledge sources

- WKS bug classes: jwt
- Domain knowledge: jwt
- WKS remains the structured source of truth; retrieve and validate items through WKS rather than duplicating the full corpus in this skill.
- Research and learning material is mapped in `stage-a/knowledge-source-map.json` and must be validated before promotion.
