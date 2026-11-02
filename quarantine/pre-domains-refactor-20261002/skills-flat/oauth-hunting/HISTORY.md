# History

Append-only. Each entry records WHY the skill changed, not just that it did. Improvement means better hunting behaviour, not more text.

## 2026-10-01 22:49 — 1 diff lines
- items: 12 (supported 12), FP rules 0, chains 0, state researching
- still missing: methodology, fp_rules, chain, skill

```diff
(initial generation, 2026-10-01)
```

## 2026-10-01 22:49 — 17 diff lines
- items: 12 (supported 12), FP rules 0, chains 0, state researching
- still missing: methodology, fp_rules, chain, skill

```diff
--- oauth@current
+++ oauth@new
@@ -9,13 +9,9 @@
      Edit the rows (or ingest better research) and re-run:
      python -m wks.skillgen -->
 
-> surface `identity` · CWE CWE-346 · OWASP API8:2023
+> surface `identity` · CWE — · OWASP —
 > evidence: 12 items, 12 supported, 0 FP rules, 0 chains
 > maturity: **researching** — missing: methodology, fp_rules, chain, skill
-
-The authorization server or client accepts a redirect, scope, token audience or PKCE flow that it should reject.
-
-**Also called:** oauth, oidc, oauth misconfiguration, redirect_uri validation, open redirect in oauth, sso open redirect
 
 
 ## Prerequisites (do not start without these)
```

## 2026-10-01 22:50 — 18 diff lines
- items: 12 (supported 12), FP rules 0, chains 0, state researching
- still missing: methodology, fp_rules, chain, skill

```diff
--- oauth@current
+++ oauth@new
@@ -40,12 +40,12 @@
 
 ## Validation bar (how to prove it)
 
+- Account takeover is proven only when the victim's browser session is bound to the attacker's AS identity, not merely when a code was observed.
+  - **Disproof:** The victim's session resolves to their own pre-existing identity, or the client rejects the callback and never issues a session cookie.
+  - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html> · <https://portswigger.net/web-security/oauth> · <https://www.rfc-editor.org/rfc/rfc9700.html>
 - Scope escalation is proven by replaying the upgraded token against a resource you were never granted, not by observing a wider scope string in the response.
   - **Disproof:** Every out-of-scope field and every secondary audience returns 403/invalid_scope, or the response scope equals the consented scope exactly.
   - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html> · <https://cheatsheetseries.owasp.org/cheatsheets/OAuth2_Cheat_Sheet.html> · <https://portswigger.net/web-security/oauth>
-- Account takeover is proven only when the victim's browser session is bound to the attacker's AS identity, not merely when a code was observed.
-  - **Disproof:** The victim's session resolves to their own pre-existing identity, or the client rejects the callback and never issues a session cookie.
-  - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html> · <https://portswigger.net/web-security/oauth> · <https://www.rfc-editor.org/rfc/rfc9700.html>
 
 ## False-positive rules (when to reject it)
 
```

## 2026-10-01 22:55 — 19 diff lines
- items: 12 (supported 12), FP rules 0, chains 1, state researching
- still missing: methodology, fp_rules

```diff
--- oauth@current
+++ oauth@new
@@ -9,9 +9,13 @@
      Edit the rows (or ingest better research) and re-run:
      python -m wks.skillgen -->
 
-> surface `identity` · CWE — · OWASP —
-> evidence: 12 items, 12 supported, 0 FP rules, 0 chains
-> maturity: **researching** — missing: methodology, fp_rules, chain, skill
+> surface `identity` · CWE CWE-346 · OWASP API8:2023
+> evidence: 12 items, 12 supported, 0 FP rules, 1 chains
+> maturity: **researching** — missing: methodology, fp_rules
+
+The authorization server or client accepts a redirect, scope, token audience or PKCE flow that it should reject.
+
+**Also called:** oauth, oidc, oauth misconfiguration, redirect_uri validation, open redirect in oauth, sso open redirect
 
 
 ## Prerequisites (do not start without these)
```

## 2026-10-01 22:58 — 23 diff lines
- items: 12 (supported 12), FP rules 1, chains 1, state researching
- still missing: methodology, fp_rules

```diff
--- oauth@current
+++ oauth@new
@@ -10,7 +10,7 @@
      python -m wks.skillgen -->
 
 > surface `identity` · CWE CWE-346 · OWASP API8:2023
-> evidence: 12 items, 12 supported, 0 FP rules, 1 chains
+> evidence: 12 items, 12 supported, 1 FP rules, 1 chains
 > maturity: **researching** — missing: methodology, fp_rules
 
 The authorization server or client accepts a redirect, scope, token audience or PKCE flow that it should reject.
@@ -78,5 +78,11 @@
   - **Disproof:** No open redirect exists on the callback host and fragment response_mode is refused, so nothing is ever forwarded to an external domain.
   - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/OAuth2_Cheat_Sheet.html> · <https://portswigger.net/web-security/oauth> · <https://www.rfc-editor.org/rfc/rfc9700.html>
 
+## Rejected before you report
+
+- **Tokens stored in localStorage are readable by any script, therefore account takeover**
+  - Killed by: No script execution was demonstrable on any origin; the token was not readable cross-origin and no XSS existed to read it
+  - Rule: Token storage location is only a finding when a script-execution primitive is separately demonstrable; localStorage alone is a hardening gap, not account takeover
+
 ---
 Full class document: `classes/oauth.md` · retrieve more with `python -m wks.cli search "<query>" --class-id oauth`
```

## 2026-10-01 23:20 — 31 diff lines
- items: 14 (supported 14), FP rules 1, chains 1, state researching
- still missing: methodology, fp_rules

```diff
--- oauth@current
+++ oauth@new
@@ -10,7 +10,7 @@
      python -m wks.skillgen -->
 
 > surface `identity` · CWE CWE-346 · OWASP API8:2023
-> evidence: 12 items, 12 supported, 1 FP rules, 1 chains
+> evidence: 14 items, 14 supported, 1 FP rules, 1 chains
 > maturity: **researching** — missing: methodology, fp_rules
 
 The authorization server or client accepts a redirect, scope, token audience or PKCE flow that it should reject.
@@ -29,6 +29,9 @@
 
 ## Recon signals (where to look)
 
+- The authorization request URL itself is the recon artifact: its parameters reveal client_id, redirect_uri, response_type, scope and whether state/nonce are used.
+  - **Disproof:** The authorization request is a POST-only or fully server-side flow with no browser-visible query parameters and no third-party AS.
+  - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/OAuth2_Cheat_Sheet.html> · <https://portswigger.net/web-security/oauth>
 - response_type=token still being honoured, or a client_secret shipped inside an SPA/mobile bundle, means tokens and client credentials are exposed by design.
   - **Disproof:** response_type=token is rejected with unsupported_response_type, and no client_secret exists in any client-side artifact.
   - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html> · <https://cheatsheetseries.owasp.org/cheatsheets/OAuth2_Cheat_Sheet.html> · <https://www.rfc-editor.org/rfc/rfc9700.html>
@@ -41,6 +44,9 @@
 - Redirect URI allowlists are bypassable via prefix/duplicate/localhost tricks, path traversal on the callback path, or a dangling wildcard subdomain.
   - **Disproof:** Every mutated redirect_uri outside the exact registered string is rejected (invalid_redirect_uri / 400), Location always stays on the registered host, and no dangling subdomain exists.
   - Sources: <https://cwe.mitre.org/data/definitions/346.html> · <https://cheatsheetseries.owasp.org/cheatsheets/OAuth2_Cheat_Sheet.html> · <https://portswigger.net/web-security/oauth>
+- Adding scope= to the /token exchange or to /userinfo returns a token with more privilege than the user ever consented to.
+  - **Disproof:** Both exchanges return invalid_scope, or the issued token's scope claim equals exactly the consented scope.
+  - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/OAuth2_Cheat_Sheet.html> · <https://portswigger.net/web-security/oauth>
 
 ## Validation bar (how to prove it)
 
```

## 2026-10-01 23:46 — 11 diff lines
- items: 14 (supported 14), FP rules 1, chains 1, state researching
- still missing: fp_rules

```diff
--- oauth@current
+++ oauth@new
@@ -11,7 +11,7 @@
 
 > surface `identity` · CWE CWE-346 · OWASP API8:2023
 > evidence: 14 items, 14 supported, 1 FP rules, 1 chains
-> maturity: **researching** — missing: methodology, fp_rules
+> maturity: **researching** — missing: fp_rules
 
 The authorization server or client accepts a redirect, scope, token audience or PKCE flow that it should reject.
 
```

## 2026-10-02 01:36 — 11 diff lines
- items: 14 (supported 14), FP rules 1, chains 1, state researching
- still missing: fp_rules

```diff
--- oauth@current
+++ oauth@new
@@ -7,7 +7,7 @@
 
 <!-- GENERATED from db/wks.db by wks/skillgen.py. DO NOT HAND-EDIT.
      Edit the rows (or ingest better research) and re-run:
-     python -m wks.skillgen -->
+     python -m wks.skillgen -->
 
 > surface `identity` · CWE CWE-346 · OWASP API8:2023
 > evidence: 14 items, 14 supported, 1 FP rules, 1 chains
```

## 2026-10-02 10:30 — 46 diff lines
- items: 16 (supported 16), FP rules 5, chains 1, state mature

```diff
--- oauth@current
+++ oauth@new
@@ -10,8 +10,8 @@
      python -m wks.skillgen -->
 
 > surface `identity` · CWE CWE-346 · OWASP API8:2023
-> evidence: 14 items, 14 supported, 1 FP rules, 1 chains
-> maturity: **researching** — missing: fp_rules
+> evidence: 16 items, 16 supported, 5 FP rules, 1 chains
+> maturity: **mature**
 
 The authorization server or client accepts a redirect, scope, token audience or PKCE flow that it should reject.
 
@@ -68,6 +68,9 @@
 
 ## Impact framing
 
+- An OAuth application authorized on behalf of a signed-in user inherits exactly the scopes the user or admin consented to, so an over-scoped grant is a standing application principal whose authority is bounded by nobody reviewing it again.
+  - **Disproof:** Refuted when every sensitive scope requires administrator consent and is reviewed before grant, or when the tenant revokes existing grants automatically when a sign-in event looks anomalous; then the application never retains a durable principal.
+  - Sources: <https://redcanary.com/blog/threat-detection/oauth-app-attacks/> · <https://www.elastic.co/security-labs/blog/entra-id-oauth-phishing-detection>
 - A leaked OAuth code or access token yields login as the victim on every client application registered with that authorization server, not just the target.
   - **Disproof:** The stolen artifact is single-use, audience-bound, short-lived and yields no authenticated session or API data beyond the attacker's own account.
   - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html> · <https://portswigger.net/web-security/oauth>
@@ -80,6 +83,9 @@
 
 ## Chaining opportunities
 
+- An OAuth consent grant captured or induced for an over-scoped application hands the attacker a durable token-bearing principal whose scopes outlive the login that produced it, turning a single authorization event into persistent application access.
+  - **Disproof:** Refuted if the tenant enforces admin-consent for the granted scopes and the authorization server binds the issued token to a client certificate or device identity the attacker does not hold; a stolen code alone then cannot be redeemed.
+  - Sources: <https://www.elastic.co/security-labs/blog/entra-id-oauth-phishing-detection> · <https://www.wiz.io/blog/detecting-malicious-oauth-applications>
 - An OAuth open redirect on the callback path, chained with implicit/fragment flows, escalates a low-severity redirect bug into token theft and account takeover.
   - **Disproof:** No open redirect exists on the callback host and fragment response_mode is refused, so nothing is ever forwarded to an external domain.
   - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/OAuth2_Cheat_Sheet.html> · <https://portswigger.net/web-security/oauth> · <https://www.rfc-editor.org/rfc/rfc9700.html>
@@ -89,6 +95,12 @@
 - **Tokens stored in localStorage are readable by any script, therefore account takeover**
   - Killed by: No script execution was demonstrable on any origin; the token was not readable cross-origin and no XSS existed to read it
   - Rule: Token storage location is only a finding when a script-execution primitive is separately demonstrable; localStorage alone is a hardening gap, not account takeover
+- **A redirect_uri allowlist entry must match the host EXACTLY: example.com does not permit evil-example.com, example.com.evil.tld, or example.com@evil.tld.**
+  - Killed by: A victim-simulated authorization request returns Location pointing to an attacker-controlled domain carrying code= or access_token=.
+  - Rule: A redirect_uri allowlist entry must match the host EXACTLY: example.com does not permit evil-example.com, example.com.evil.tld, or example.com@evil.tld.
+- **A 'successful' takeover that only reproduces because your own session was already logged in, or tokens in localStorage without demonstrable XSS, is not a finding.**
+  - Killed by: The same result reproduces in an incognito session with no cookies, or no script-execution primitive exists on the origin holding the token.
+  - Rule: A 'successful' takeover that only reproduces because your own session was already logged in, or tokens in localStorage without demonstrable XSS, is not a finding.
 
 ---
 Full class document: `classes/oauth.md` · retrieve more with `python -m wks.cli search "<query>" --class-id oauth`
```

## 2026-10-02 12:21 — 21 diff lines
- items: 16 (supported 16), FP rules 5, chains 3, state mature

```diff
--- oauth@current
+++ oauth@new
@@ -10,7 +10,7 @@
      python -m wks.skillgen -->
 
 > surface `identity` · CWE CWE-346 · OWASP API8:2023
-> evidence: 16 items, 16 supported, 5 FP rules, 1 chains
+> evidence: 16 items, 16 supported, 5 FP rules, 3 chains
 > maturity: **mature**
 
 The authorization server or client accepts a redirect, scope, token audience or PKCE flow that it should reject.
@@ -102,5 +102,9 @@
   - Killed by: The same result reproduces in an incognito session with no cookies, or no script-execution primitive exists on the origin holding the token.
   - Rule: A 'successful' takeover that only reproduces because your own session was already logged in, or tokens in localStorage without demonstrable XSS, is not a finding.
 
+## Chains to
+
+- `authn` (3 shared chain(s))
+
 ---
 Full class document: `classes/oauth.md` · retrieve more with `python -m wks.cli search "<query>" --class-id oauth`
```

## 2026-10-02 13:38 — 8 diff lines
- items: 16 (supported 16), FP rules 5, chains 3, state mature

```diff
--- oauth@current
+++ oauth@new
@@ -107,4 +107,4 @@
 - `authn` (3 shared chain(s))
 
 ---
-Full class document: `classes/oauth.md` · retrieve more with `python -m wks.cli search "<query>" --class-id oauth`
+Full class document: `skills/Web/oauth/EVIDENCE.md` · retrieve more with `python -m wks.cli search "<query>" --class-id oauth`
```
