<!-- GENERATED from db/wks.db — do not edit -->
# Authentication Failures

> surface: `identity` · CWE: 287 · OWASP: A07:2021
> maturity: **mature** — 38 items, 10 supported, 4 FP rules, 1 chains

The mechanism that establishes identity can be bypassed, reused, or subverted end to end.

**Aliases:** authentication bypass, weak login, password reset flaw, mfa bypass, account takeover

## Prerequisite

- **SAML assertions fail to verify when the service provider and identity provider disagree on XML canonicalization, because the hashed byte representation of the same logical content then differs.**  
  `high_confidence` · score 0.857 · disproved by: If an unmodified assertion from the same identity provider validates reliably, canonicalization disagreement is not the cause of the observed failure.
  sources: <https://docs.oasis-open.org/security/saml/v2.0/saml-core-2.0-os.pdf> · <https://blog.trailofbits.com/2026/09/21/saml-a-fractal-of-bad-design/>

## Signal

- **A JSON response body that states whether 2FA authentication succeeded is the field to manipulate, because the client-visible success value is what the 2FA check may be read from.**  
  `high_confidence` · score 0.8515 · disproved by: Editing the success field in the 2FA response body leaves the session unauthenticated because the server records the verified state independently of the returned JSON.
  sources: <https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html> · <https://www.rfc-editor.org/rfc/rfc7235.html> · <https://kathan19.gitbook.io/howtohunt/authentication-bypass/2fa_bypasses.md>

## Technique

- **The password reset response body is worth inspecting for a reset link, token or OTP, because a token handed back in the response is directly replayable instead of only being mailed to the account owner.**  
  `high_confidence` · score 0.879 · disproved by: The reset response carries no link, token or OTP, and the reset step stays gated on out-of-band delivery to the registered mailbox.
  sources: <https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html> · <https://www.rfc-editor.org/rfc/rfc7235.html> · <https://kathan19.gitbook.io/howtohunt/account-takeover-methodology/account_takeovers_methods.md>
- **Some applications decide 2FA authentication success from the HTTP status code of the verification request, so a verification that returns a non-success status can still leave the client treating the second factor as passed.**  
  `high_confidence` · score 0.8515 · disproved by: Changing or suppressing the status code of the verification response does not change client state, which follows a server-set authenticated session flag instead.
  sources: <https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html> · <https://www.rfc-editor.org/rfc/rfc7235.html> · <https://kathan19.gitbook.io/howtohunt/authentication-bypass/2fa_bypasses.md>
- **While the program properly exits if authentication fails, it does not ensure that the message is addressed to the user.**  
  `high_confidence` · score 0.77 · disproved by: Refuted when: the same behaviour is absent when the single named control in the claim is present, and the control is shown to be present rather than assumed. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“While the program properly exits if authentication fails, it does not ensure tha”) does not occur under a test that isolates that control.
  sources: <https://cwe.mitre.org/data/definitions/862.html> · <https://portswigger.net/web-security/access-control>

## Test

- **A mismatch between the character encoding a browser uses to transmit a credential and the encoding the server uses to compare it is a candidate authentication bypass that must be probed with encoded variants of a known-bad password.**  
  `high_confidence` · score 0.948 · disproved by: It is not a bypass if the application normalises the credential to a canonical encoding before hashing or comparing, or if it rejects malformed byte sequences outright, or if the endpoint no longer accepts the legacy scheme. Establish the negative control first - a correctly-encoded known-bad password must fail - and only then attribute any success to the encoding difference, since a variant that succeeds for the wrong reason (a different account, a cached response) would otherwise produce a false finding.
  sources: <https://cwe.mitre.org/data/definitions/287.html> · <https://developer.mozilla.org/en-US/docs/Web/HTTP/Authentication>
- **Where a target enforces a weak password policy, the absence of login throttling can be proven by registering a throwaway account with a very weak password and then issuing unlimited login attempts against it.**  
  `high_confidence` · score 0.824 · disproved by: The login endpoint applies account lockout, login throttling or a challenge after a small number of attempts, so the extra attempts never reach password checking.
  sources: <https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html> · <https://www.rfc-editor.org/rfc/rfc7235.html> · <https://kathan19.gitbook.io/howtohunt/account-takeover-methodology/account_takeovers_methods.md>

## Fp Rule

- **A 403 returned after credentials are accepted is the specified response for valid-but-insufficient credentials and must not be filed as broken authentication, because authentication succeeded and authorization refused.**  
  `high_confidence` · score 0.8355 · disproved by: It IS an authentication defect if the 403 is returned in place of a 401 when the credentials themselves are wrong or absent, because the client is then never invited to supply them and legitimate users are locked out - or if the application reveals the 403 only after it has already established a session, meaning the session was granted and then the response shape confused the test. Distinguish by whether any correct credential for that user can obtain access, not by the status code alone.
  sources: <https://www.rfc-editor.org/rfc/rfc7235.html> · <https://developer.mozilla.org/en-US/docs/Web/HTTP/Authentication>
- **An OAuth device authorization grant that the resource owner completes in person at the verification endpoint the provider printed is the intended flow and is not an authentication bypass, because the grant is authorized by the account holder rather than captured from them.**  
  `high_confidence` · score 0.8055 · disproved by: Refuted when the verification endpoint the grant was completed at is the identity provider's own published URI, and the account that approved is the account whose token was issued; where the approving human is the resource owner acting deliberately, no identity was claimed that the claimant could not already prove.
  sources: <https://cwe.mitre.org/data/definitions/287.html> · <https://portswigger.net/web-security/oauth>

## Bypass

- **Where several parties are hosted under one canonical root URI and separated only by an HTTP Basic realm, a credential accepted for one path is reusable at every other path on that origin, so the protection boundary is the origin rather than the resource.**  
  `high_confidence` · score 0.863 · disproved by: It does not apply where the schemes in use bind the credential to a narrower scope - cookie sessions scoped to a path, a scheme with per-resource tokens, or separate host names or ports per party, which is exactly the mitigation the RFC names. Verify the deployment's actual realm values and host layout before reporting; a site that already separates parties by hostname is not exposed to this, and cookie-based applications do not send a reusable Authorization header at all.
  sources: <https://www.rfc-editor.org/rfc/rfc7235.html> · <https://nginx.org/en/docs/http/ngx_http_auth_basic_module.html>

## False-positive rules

- **Hypothesis:** A session variable set before login and carried into the authenticated session makes the pre-login identity authoritative, so editing it yields an authentication bypass.
  - **Invalidated by:** The mutated variable is overwritten at the authentication transition rather than merged, so both sessions resolve to the credential just presented and the gated action stays denied; the variable was a locale or theme value with no authority.
  - **Rule:** A pre-auth session variable is an authentication bypass only when it survives the login transition with authority: prove the post-login session resolves to a principal you did not authenticate as, or that an authorization-gated action newly succeeds. Presence and editability are not privilege.

- **Hypothesis:** No rate limiting was observed on verification endpoints, therefore account enumeration is possible
  - **Invalidated by:** The credential-issuing endpoints on the in-scope hosts return not found; the real authentication flow lives on a host outside the authorised scope. With no in-scope endpoint performing the check, the absence of throttling there is a fact about scope, not a missing control
  - **Rule:** Absence of rate limiting is only measurable where the operation happens. If the authenticating endpoint is out of scope or unreachable, you have not shown a missing control - you have shown you could not test. Say that instead of reporting the absence

## Related classes (via chains)

- `oauth` OAuth 2.0 / OIDC Misconfiguration (3 chains)
