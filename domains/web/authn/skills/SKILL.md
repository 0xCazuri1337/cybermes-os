---
name: authn-hunting
description: Use when hunting Authentication Failures in a identity target. Ordered prerequisites, signals, techniques, validation bar and false-positive rules.
---

# Authentication Failures — hunting skill

<!-- GENERATED from db/wks.db by wks/skillgen.py. DO NOT HAND-EDIT.
     Edit the rows (or ingest better research) and re-run:
     python -m wks.skillgen -->

> surface `identity` · CWE 287 · OWASP A07:2021
> evidence: 38 items, 10 supported, 4 FP rules, 1 chains
> maturity: **mature**

The mechanism that establishes identity can be bypassed, reused, or subverted end to end.

**Also called:** authentication bypass, weak login, password reset flaw, mfa bypass, account takeover


## Prerequisites (do not start without these)

- SAML assertions fail to verify when the service provider and identity provider disagree on XML canonicalization, because the hashed byte representation of the same logical content then differs.  _(merged 1 duplicate row(s))_
  - **Disproof:** If an unmodified assertion from the same identity provider validates reliably, canonicalization disagreement is not the cause of the observed failure.
  - Sources: <https://docs.oasis-open.org/security/saml/v2.0/saml-core-2.0-os.pdf> · <https://blog.trailofbits.com/2026/09/21/saml-a-fractal-of-bad-design/>

## Recon signals (where to look)

- A JSON response body that states whether 2FA authentication succeeded is the field to manipulate, because the client-visible success value is what the 2FA check may be read from.  _(merged 1 duplicate row(s))_
  - **Disproof:** Editing the success field in the 2FA response body leaves the session unauthenticated because the server records the verified state independently of the returned JSON.
  - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html> · <https://www.rfc-editor.org/rfc/rfc7235.html> · <https://kathan19.gitbook.io/howtohunt/authentication-bypass/2fa_bypasses.md>

## Techniques (what to change)

- A feature of more advanced applications is the ability to require different authentication stages depending on various environmental and contextual attributes (including but not limited to, the sensitivity of the data for which access is being requested, time of day, user location, IP address, or device fingerprint).  _(merged 1 duplicate row(s))_ _(unverified)_
  - **Disproof:** Refuted when: the resolved Location host is the intended origin, so no request ever leaves the application. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“A feature of more advanced applications is the ability to require different auth”) does not occur under a test that isolates that control.
  - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html> · <https://www.microsoft.com/en-us/security/blog/2026/09/02/impersonating-it-support-threat-actors-turn-remote-session-into-enterprise-wide-access/>
- Additionally, if the client is behind an enterprise proxy that performs SSL/TLS decryption, this will break certificate authentication unless the site is allowed on the proxy.  _(merged 1 duplicate row(s))_ _(unverified)_
  - **Disproof:** Refuted when: the same behaviour is absent when the single named control in the claim is present, and the control is shown to be present rather than assumed. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“Additionally, if the client is behind an enterprise proxy that performs SSL/TLS ”) does not occur under a test that isolates that control.
  - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html> · <https://netlas.io/blog/weaponized_rmm/>
- Alternatively, a single sign-on solution may authenticate the user and allow them to remain logged in for a day but require a reauthentication if they try to access their profile page.  _(merged 1 duplicate row(s))_ _(unverified)_
  - **Disproof:** Refuted when: the same behaviour is absent when the single named control in the claim is present, and the control is shown to be present rather than assumed. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“Alternatively, a single sign-on solution may authenticate the user and allow the”) does not occur under a test that isolates that control.
  - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html> · <https://netlas.io/blog/weaponized_rmm/>
- Avoid requiring periodic password changes; instead, encourage users to pick strong passwords and enable Multifactor Authentication Cheat Sheet (MFA) .  _(merged 1 duplicate row(s))_ _(unverified)_
  - **Disproof:** Refuted when: the same behaviour is absent when the single named control in the claim is present, and the control is shown to be present rather than assumed. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“Avoid requiring periodic password changes; instead, encourage users to pick stro”) does not occur under a test that isolates that control.
  - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html> · <https://www.microsoft.com/en-us/security/blog/2026/09/02/impersonating-it-support-threat-actors-turn-remote-session-into-enterprise-wide-access/>
- Failure to utilize TLS or other strong transport for authenticated pages after login enables an attacker to view the unencrypted session ID and compromise the user's authenticated session.  _(merged 1 duplicate row(s))_ _(unverified)_
  - **Disproof:** Refuted when: the same behaviour is absent when the single named control in the claim is present, and the control is shown to be present rather than assumed. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“Failure to utilize TLS or other strong transport for authenticated pages after l”) does not occur under a test that isolates that control.
  - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html> · <https://www.microsoft.com/en-us/security/blog/2026/09/02/impersonating-it-support-threat-actors-turn-remote-session-into-enterprise-wide-access/>
- In return, the response time will be different for the same error, allowing the attacker to differentiate between a wrong username and a wrong password.  _(merged 1 duplicate row(s))_ _(unverified)_
  - **Disproof:** Refuted when: the same behaviour is absent when the single named control in the claim is present, and the control is shown to be present rather than assumed. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“In return, the response time will be different for the same error, allowing the ”) does not occur under a test that isolates that control.
  - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html> · <https://netlas.io/blog/weaponized_rmm/>
- Incorrectly implemented error messages in the case of authentication functionality can be used for the purposes of user ID and password enumeration.  _(merged 1 duplicate row(s))_ _(unverified)_
  - **Disproof:** Refuted when: the same behaviour is absent when the single named control in the claim is present, and the control is shown to be present rather than assumed. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“Incorrectly implemented error messages in the case of authentication functionali”) does not occur under a test that isolates that control.
  - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html> · <https://www.microsoft.com/en-us/security/blog/2026/09/02/impersonating-it-support-threat-actors-turn-remote-session-into-enterprise-wide-access/>
- Indeed, depending on the implementation, the processing time can be significantly different according to the case (success vs failure) allowing an attacker to mount a time-based attack (delta of some seconds for example).  _(merged 1 duplicate row(s))_ _(unverified)_
  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Indeed, depending on the implementation, the processing time can be significantly differen".
  - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html> · <https://www.microsoft.com/en-us/security/blog/2026/09/02/impersonating-it-support-threat-actors-turn-remote-session-into-enterprise-wide-access/>
- More specifically, if a web application uses the host header for authorization checks or to construct absolute links, an attacker may be able to manipulate the host header to bypass these checks or force the construction of malicious links.  _(merged 1 duplicate row(s))_ _(unverified)_
  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "More specifically, if a web application uses the host header for authorization checks or t".
  - Sources: <https://cwe.mitre.org/data/definitions/287.html> · <https://www.proofpoint.com/us/blog/threat-insight/access-granted-phishing-device-code-authorization-account-takeover>
- Regarding the user enumeration itself, protection against brute-force attacks is also effective because it prevents an attacker from applying the enumeration at scale.  _(merged 1 duplicate row(s))_ _(unverified)_
  - **Disproof:** Refuted when: the same behaviour is absent when the single named control in the claim is present, and the control is shown to be present rather than assumed. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“Regarding the user enumeration itself, protection against brute-force attacks is”) does not occur under a test that isolates that control.
  - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html> · <https://www.microsoft.com/en-us/security/blog/2026/09/02/impersonating-it-support-threat-actors-turn-remote-session-into-enterprise-wide-access/>
- Screening passwords against blocklists helps prevent users from selecting passwords that are commonly used or already known to attackers, as recommended by NIST SP 800-63B – Passwords .  _(merged 1 duplicate row(s))_ _(unverified)_
  - **Disproof:** Refuted when: the same behaviour is absent when the single named control in the claim is present, and the control is shown to be present rather than assumed. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“Screening passwords against blocklists helps prevent users from selecting passwo”) does not occur under a test that isolates that control.
  - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html> · <https://www.microsoft.com/en-us/security/blog/2026/09/02/impersonating-it-support-threat-actors-turn-remote-session-into-enterprise-wide-access/> · <https://netlas.io/blog/weaponized_rmm/>
- Some applications decide 2FA authentication success from the HTTP status code of the verification request, so a verification that returns a non-success status can still leave the client treating the second factor as passed.  _(merged 1 duplicate row(s))_
  - **Disproof:** Changing or suppressing the status code of the verification response does not change client state, which follows a server-set authenticated session flag instead.
  - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html> · <https://www.rfc-editor.org/rfc/rfc7235.html> · <https://kathan19.gitbook.io/howtohunt/authentication-bypass/2fa_bypasses.md>
- The application may return a different HTTP Error code depending on the authentication attempt response.  _(merged 1 duplicate row(s))_ _(unverified)_
  - **Disproof:** Refuted when: the same behaviour is absent when the single named control in the claim is present, and the control is shown to be present rather than assumed. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“The application may return a different HTTP Error code depending on the authenti”) does not occur under a test that isolates that control.
  - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html> · <https://netlas.io/blog/weaponized_rmm/>
- The counter of failed logins should be associated with the account itself, rather than the source IP address, in order to prevent an attacker from making login attempts from a large number of different IP addresses.  _(merged 1 duplicate row(s))_ _(unverified)_
  - **Disproof:** Refuted when: the same behaviour is absent when the single named control in the claim is present, and the control is shown to be present rather than assumed. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“The counter of failed logins should be associated with the account itself, rathe”) does not occur under a test that isolates that control.
  - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html> · <https://www.microsoft.com/en-us/security/blog/2026/09/02/impersonating-it-support-threat-actors-turn-remote-session-into-enterprise-wide-access/>
- The objective is to prevent the creation of a discrepancy factor , allowing an attacker to mount a user enumeration action against the application.  _(merged 1 duplicate row(s))_ _(unverified)_
  - **Disproof:** Refuted when: the same behaviour is absent when the single named control in the claim is present, and the control is shown to be present rather than assumed. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“The objective is to prevent the creation of a discrepancy factor , allowing an a”) does not occur under a test that isolates that control.
  - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html> · <https://netlas.io/blog/weaponized_rmm/>
- The password reset response body is worth inspecting for a reset link, token or OTP, because a token handed back in the response is directly replayable instead of only being mailed to the account owner.  _(merged 1 duplicate row(s))_
  - **Disproof:** The reset response carries no link, token or OTP, and the reset step stays gated on out-of-band delivery to the registered mailbox.
  - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html> · <https://www.rfc-editor.org/rfc/rfc7235.html> · <https://kathan19.gitbook.io/howtohunt/account-takeover-methodology/account_takeovers_methods.md>
- While UAF focuses on passwordless authentication, U2F allows the addition of a second factor to existing password-based authentication.  _(merged 1 duplicate row(s))_ _(unverified)_
  - **Disproof:** Refuted when: the same behaviour is absent when the single named control in the claim is present, and the control is shown to be present rather than assumed. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“While UAF focuses on passwordless authentication, U2F allows the addition of a s”) does not occur under a test that isolates that control.
  - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html> · <https://netlas.io/blog/weaponized_rmm/>
- While the program properly exits if authentication fails, it does not ensure that the message is addressed to the user.  _(merged 1 duplicate row(s))_
  - **Disproof:** Refuted when: the same behaviour is absent when the single named control in the claim is present, and the control is shown to be present rather than assumed. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“While the program properly exits if authentication fails, it does not ensure tha”) does not occur under a test that isolates that control.
  - Sources: <https://cwe.mitre.org/data/definitions/862.html> · <https://portswigger.net/web-security/access-control>
- While this technique can prevent the user from having to type a password (thus protecting against an average keylogger from stealing it), it is still considered a good idea to consider using both a password and TLS client authentication combined.  _(merged 1 duplicate row(s))_ _(unverified)_
  - **Disproof:** Refuted when: the same behaviour is absent when the single named control in the claim is present, and the control is shown to be present rather than assumed. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“While this technique can prevent the user from having to type a password (thus p”) does not occur under a test that isolates that control.
  - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html> · <https://www.microsoft.com/en-us/security/blog/2026/09/02/impersonating-it-support-threat-actors-turn-remote-session-into-enterprise-wide-access/>

## Tests

- A mismatch between the character encoding a browser uses to transmit a credential and the encoding the server uses to compare it is a candidate authentication bypass that must be probed with encoded variants of a known-bad password.  _(merged 1 duplicate row(s))_
  - **Disproof:** It is not a bypass if the application normalises the credential to a canonical encoding before hashing or comparing, or if it rejects malformed byte sequences outright, or if the endpoint no longer accepts the legacy scheme. Establish the negative control first - a correctly-encoded known-bad password must fail - and only then attribute any success to the encoding difference, since a variant that succeeds for the wrong reason (a different account, a cached response) would otherwise produce a false finding.
  - Sources: <https://cwe.mitre.org/data/definitions/287.html> · <https://developer.mozilla.org/en-US/docs/Web/HTTP/Authentication>
- To decide this case, observe: So the detection rule is: a device code flow is a phishing signal, an account-takeover signal, or a sanctioned test; it becomes a bypass finding only when a token minted under one authorization context is accepted by an endpoint that declares a different one.  _(merged 1 duplicate row(s))_ _(unverified)_
  - **Disproof:** This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (authn.bypass.device_code_grant_accepted_by_a_non_intended_endpoint) states the full boundary.
  - Sources: <https://www.talosintelligence.com/vulnerability_reports/TALOS-2025-2242> · <https://www.proofpoint.com/us/blog/threat-insight/access-granted-phishing-device-code-authorization-account-takeover>
- To decide this case, observe: What refutes the finding is the case where the pre-login variable is cosmetic (a theme, a locale, a cart id that is re-keyed to the authenticated user) and the post-login session resolves solely from the credential that was just presented.  _(merged 1 duplicate row(s))_ _(unverified)_
  - **Disproof:** This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (authn.fp_rule.preauth_session_variable_is_not_bypass) states the full boundary.
  - Sources: <https://cwe.mitre.org/data/definitions/287.html> · <https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html>
- Where a target enforces a weak password policy, the absence of login throttling can be proven by registering a throwaway account with a very weak password and then issuing unlimited login attempts against it.  _(merged 1 duplicate row(s))_
  - **Disproof:** The login endpoint applies account lockout, login throttling or a challenge after a small number of attempts, so the extra attempts never reach password checking.
  - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html> · <https://www.rfc-editor.org/rfc/rfc7235.html> · <https://kathan19.gitbook.io/howtohunt/account-takeover-methodology/account_takeovers_methods.md>

## Validation bar (how to prove it)

- A session-puzzling candidate is confirmed only when a pre-authentication session variable, set before credentials are supplied, still determines the authenticated identity or an authorization decision after login.  _(merged 1 duplicate row(s))_ _(unverified)_
  - **Disproof:** Refuted when the post-login session resolves to the principal whose credentials were just presented, the mutated variable is overwritten rather than merged at the authentication transition, and the authorization-gated action denied in the baseline remains denied; a session value that cannot survive authentication cannot produce an authority differential.
  - Sources: <https://cwe.mitre.org/data/definitions/287.html> · <https://academy.hackthebox.com/course/preview/abusing-http-misconfigurations>
- An authentication bypass is proven by the credential-free second session carrying the victim's privileges, not by a 200 status, a redirect to a dashboard, or the absence of a login prompt on a single request.  _(merged 1 duplicate row(s))_ _(unverified)_
  - **Disproof:** It is not a bypass if the second session carries a different identity, or if the data returned is identical for every anonymous caller (a public or cached shell), or if the privileged resource re-checks the session server-side and returns 401 or 403 on the fresh jar. Also watch for a pre-seeded anonymous session cookie that the server treats as a guest with no privileges - that is a normal unauthenticated path, not an identity claim the product failed to check.
  - Sources: <https://cwe.mitre.org/data/definitions/287.html> · <https://developer.mozilla.org/en-US/docs/Web/HTTP/Authentication>

## False-positive rules (when to reject it)

- A 403 returned after credentials are accepted is the specified response for valid-but-insufficient credentials and must not be filed as broken authentication, because authentication succeeded and authorization refused.  _(merged 1 duplicate row(s))_
  - **Disproof:** It IS an authentication defect if the 403 is returned in place of a 401 when the credentials themselves are wrong or absent, because the client is then never invited to supply them and legitimate users are locked out - or if the application reveals the 403 only after it has already established a session, meaning the session was granted and then the response shape confused the test. Distinguish by whether any correct credential for that user can obtain access, not by the status code alone.
  - Sources: <https://www.rfc-editor.org/rfc/rfc7235.html> · <https://developer.mozilla.org/en-US/docs/Web/HTTP/Authentication>
- A differential response between a known-nonexistent username and a known-existing username with a wrong password is only username enumeration if the difference is observable by an unauthenticated party, so a difference visible solely in server-side logs does not support the finding.  _(merged 1 duplicate row(s))_ _(unverified)_
  - **Disproof:** It is a real enumeration channel if the two responses differ observably to the unauthenticated requester - a different status, a distinguishable body, a materially different response time after averaging, or a redirect difference. Note also that some differentials are legitimate: RFC 7235 describes 401 responses that carry a possibly new challenge, and browsers handling cross-origin images no longer trigger authentication dialogs, so a differential that depends on browser behaviour is not a server-side enumeration primitive.
  - Sources: <https://www.rfc-editor.org/rfc/rfc7235.html> · <https://developer.mozilla.org/en-US/docs/Web/HTTP/Authentication>
- A session variable populated before login that carries no privilege and is discarded at authentication is session-puzzling surface, not an authentication bypass, and is only a bypass once the pre-login value determines an authenticated identity.  _(merged 1 duplicate row(s))_ _(unverified)_
  - **Disproof:** Refuted when the session variable observed before authentication is never read on any post-login code path, or when the post-login session resolves exclusively from the credential just presented and the edited pre-login value is overwritten rather than merged; a token that carries no principal and confers no authority cannot be an authentication bypass.
  - Sources: <https://cwe.mitre.org/data/definitions/287.html> · <https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html>
- An OAuth device authorization grant that the resource owner completes in person at the verification endpoint the provider printed is the intended flow and is not an authentication bypass, because the grant is authorized by the account holder rather than captured from them.  _(merged 1 duplicate row(s))_
  - **Disproof:** Refuted when the verification endpoint the grant was completed at is the identity provider's own published URI, and the account that approved is the account whose token was issued; where the approving human is the resource owner acting deliberately, no identity was claimed that the claimant could not already prove.
  - Sources: <https://cwe.mitre.org/data/definitions/287.html> · <https://portswigger.net/web-security/oauth>

## Evidence requirements

- A convincing observation for this class is: That pair is what a triager needs and what a status code cannot supply.  _(merged 1 duplicate row(s))_ _(unverified)_
  - **Disproof:** Not evidence when the observable cannot be produced at all -- blind, server-side-only, or identical-in-every-case behaviour leaves nothing to show. The originating rule (authn.validation.prove_broken_authn_with_a_second_session_not_with_a_redirect_status) states the full boundary.
  - Sources: <https://cwe.mitre.org/data/definitions/287.html> · <https://developer.mozilla.org/en-US/docs/Web/HTTP/Authentication>
- A convincing observation for this class is: The weakness requires the product to fail to prove an identity claim; a timing or message difference that the response body and status do not expose is a hardening observation, not a demonstrable enumeration channel.  _(merged 1 duplicate row(s))_ _(unverified)_
  - **Disproof:** Not evidence when the observable cannot be produced at all -- blind, server-side-only, or identical-in-every-case behaviour leaves nothing to show. The originating rule (authn.fp_rule.two_different_responses_to_two_different_credentials_is_not_username_enumeration) states the full boundary.
  - Sources: <https://www.rfc-editor.org/rfc/rfc7235.html> · <https://developer.mozilla.org/en-US/docs/Web/HTTP/Authentication>

## Variants

- A SAML relying party that validates a signature without pinning which element the signature must cover is vulnerable to XML signature wrapping, where a forged unsigned assertion is supplied alongside a legitimately signed one.  _(merged 1 duplicate row(s))_ _(unverified)_
  - **Disproof:** If the relying party rejects any document whose signature does not cover the assertion it consumes, and a wrapped variant yields no session, wrapping is not present.

## Defence bypasses

- An OAuth device authorization grant completed by a user is a legitimate authorization flow unless the resulting token is accepted by an endpoint that was never meant to honour that provisioner, which is the actual bypass condition.  _(merged 1 duplicate row(s))_ _(unverified)_
  - **Disproof:** Every token issued by the device authorization flow is rejected by endpoints configured for a different provisioner, and acceptance is limited to the endpoints that declare that provisioner, showing no endpoint-scope mismatch exists.
  - Sources: <https://www.talosintelligence.com/vulnerability_reports/TALOS-2025-2242> · <https://www.proofpoint.com/us/blog/threat-insight/access-granted-phishing-device-code-authorization-account-takeover>
- Where several parties are hosted under one canonical root URI and separated only by an HTTP Basic realm, a credential accepted for one path is reusable at every other path on that origin, so the protection boundary is the origin rather than the resource.  _(merged 1 duplicate row(s))_
  - **Disproof:** It does not apply where the schemes in use bind the credential to a narrower scope - cookie sessions scoped to a path, a scheme with per-resource tokens, or separate host names or ports per party, which is exactly the mitigation the RFC names. Verify the deployment's actual realm values and host layout before reporting; a site that already separates parties by hostname is not exposed to this, and cookie-based applications do not send a reusable Authorization header at all.
  - Sources: <https://www.rfc-editor.org/rfc/rfc7235.html> · <https://nginx.org/en/docs/http/ngx_http_auth_basic_module.html>

## Chaining opportunities

- A SAML relying party that validates a signed assertion without pinning which assertion in the response it trusts accepts an attacker-injected second assertion, so the session it establishes is bound to an identity the identity provider never asserted.  _(merged 1 duplicate row(s))_ _(unverified)_
  - **Disproof:** Refuted when the relying party rejects any SAML response containing more than one assertion, or when it verifies the signature over the exact assertion element it then consumes rather than over the enclosing response; either control makes the injected assertion unreachable regardless of how many elements the response carries.
  - Sources: <https://cwe.mitre.org/data/definitions/287.html> · <https://academy.hackthebox.com/course/preview/abusing-http-misconfigurations> · <https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html>
- An OAuth login flow that omits the state parameter does not yield account takeover on its own but binds the victim to the attacker's identity through login CSRF, and it is the account binding rather than the token theft that carries the chain.  _(merged 1 duplicate row(s))_ _(unverified)_
  - **Disproof:** Refuted when the client compares the returned state against the value it stored at initiation and rejects a mismatch, or when the site offers a non-OAuth login path the attacker cannot reach; without an unbound callback or a lax redirect_uri there is no login CSRF primitive to chain.
  - Sources: <https://academy.hackthebox.com/course/preview/abusing-http-misconfigurations> · <https://portswigger.net/web-security/oauth>

## Rejected before you report

- **A session variable set before login and carried into the authenticated session makes the pre-login identity authoritative, so editing it yields an authentication bypass.**
  - Killed by: The mutated variable is overwritten at the authentication transition rather than merged, so both sessions resolve to the credential just presented and the gated action stays denied; the variable was a locale or theme value with no authority.
  - Rule: A pre-auth session variable is an authentication bypass only when it survives the login transition with authority: prove the post-login session resolves to a principal you did not authenticate as, or that an authorization-gated action newly succeeds. Presence and editability are not privilege.
- **No rate limiting was observed on verification endpoints, therefore account enumeration is possible**
  - Killed by: The credential-issuing endpoints on the in-scope hosts return not found; the real authentication flow lives on a host outside the authorised scope. With no in-scope endpoint performing the check, the absence of throttling there is a fact about scope, not a missing control
  - Rule: Absence of rate limiting is only measurable where the operation happens. If the authenticating endpoint is out of scope or unreachable, you have not shown a missing control - you have shown you could not test. Say that instead of reporting the absence

## Chains to

- `oauth` (3 shared chain(s))


## Hunt procedure

1. Enumerate the surface before probing: collect every endpoint, parameter and object id the class could plausibly sit on.
2. Establish a CONTROLLED BASELINE first — one unauthenticated and one authenticated low-privilege request per candidate — and diff against the probe. A difference with no baseline proves nothing.
3. Change exactly ONE variable per probe. Two changes produce a difference you cannot attribute.
4. Record raw request and response pairs verbatim, including headers, before you interpret anything.

### What counts as proof

- Two responses that differ in a way the CONTROL did not, produced by a single changed variable.
- An invariant the application is supposed to hold, observed broken.
- A second independent confirmation, or an explicit statement that this is single-account evidence only.

> Ordered prerequisites, the validation bar and the false-positive rules below are the authority: this block is the mechanics, those are the standard.
---
Full class document: `domains/web/authn/knowledge/DIGEST.md` · retrieve more with `python -m wks.cli search "<query>" --class-id authn`

---
Runbook: [`HUNT.md`](HUNT.md) — every promoted technique mapped to an executable procedure with the observables to record.
