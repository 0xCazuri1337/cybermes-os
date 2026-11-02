# Methodology — Authentication Failures

> Derived from 10 verified items. Regenerate with `python -m wks.methodgen --class authn --apply`. Do not hand-edit: this file is a projection of the evidence, and edits are lost on the next cycle.

**Surface.** The mechanism that establishes identity can be bypassed, reused, or subverted end to end.

**References.** CWE-287 · A07:2021

## 1. Preconditions

_Nothing below is reachable until these hold. Confirm each against the target before spending time on the technique._

**SAML assertions fail to verify when the service provider and identity provider disagree on XML canonicalization, because the hashed byte representation of the same logical content then differs.**

Canonicalization turns a document into a stable byte sequence so a hash over signed content is reproducible. When the two parties normalize differently, identical logical content produces different bytes, the digest does not match, and authentication fails. For a hunter this matters because an assertion that will not validate may be an interoperability defect rather than an attack surface, and filing it as a signature-bypass candidate wastes a cycle. The diagnostic is whether the failure is consistent across every request and whether an unmutated assertion from the same provider also fails.

- *Disproof:* If an unmodified assertion from the same identity provider validates reliably, canonicalization disagreement is not the cause of the observed failure.
- *Evidence:* high_confidence — [blog.trailofbits.com](https://blog.trailofbits.com/2026/09/21/saml-a-fractal-of-bad-design/); [docs.oasis-open.org](https://docs.oasis-open.org/security/saml/v2.0/saml-core-2.0-os.pdf)

## 2. Reconnaissance signals

_What to look for while mapping the surface, and where each signal tells you the rest of the procedure is worth running._

**A JSON response body that states whether 2FA authentication succeeded is the field to manipulate, because the client-visible success value is what the 2FA check may be read from.**

A JSON response body that states whether 2FA authentication succeeded is the field to manipulate, because the client-visible success value is what the 2FA check may be read from.

HackTricks reference: 2fa bypasses (https://kathan19.gitbook.io/howtohunt/authentication-bypass/2fa_bypasses.md)

- *Disproof:* Editing the success field in the 2FA response body leaves the session unauthenticated because the server records the verified state independently of the returned JSON.
- *Evidence:* high_confidence — [cheatsheetseries.owasp.org](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html); [kathan19.gitbook.io](https://kathan19.gitbook.io/howtohunt/authentication-bypass/2fa_bypasses.md); [rfc-editor.org](https://www.rfc-editor.org/rfc/rfc7235.html)

## 3. Test sequence

_Concrete mutations to try. Each is written to be executable, not to be a description of the vulnerability._

**The password reset response body is worth inspecting for a reset link, token or OTP, because a token handed back in the response is directly replayable instead of only being mailed to the account owner.**

The password reset response body is worth inspecting for a reset link, token or OTP, because a token handed back in the response is directly replayable instead of only being mailed to the account owner.

HackTricks reference: account takeovers methods (https://kathan19.gitbook.io/howtohunt/account-takeover-methodology/account_takeovers_methods.md)

- *Disproof:* The reset response carries no link, token or OTP, and the reset step stays gated on out-of-band delivery to the registered mailbox.
- *Evidence:* high_confidence — [cheatsheetseries.owasp.org](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html); [kathan19.gitbook.io](https://kathan19.gitbook.io/howtohunt/account-takeover-methodology/account_takeovers_methods.md); [rfc-editor.org](https://www.rfc-editor.org/rfc/rfc7235.html)

**Some applications decide 2FA authentication success from the HTTP status code of the verification request, so a verification that returns a non-success status can still leave the client treating the second factor as passed.**

Some applications decide 2FA authentication success from the HTTP status code of the verification request, so a verification that returns a non-success status can still leave the client treating the second factor as passed.

HackTricks reference: 2fa bypasses (https://kathan19.gitbook.io/howtohunt/authentication-bypass/2fa_bypasses.md)

- *Disproof:* Changing or suppressing the status code of the verification response does not change client state, which follows a server-set authenticated session flag instead.
- *Evidence:* high_confidence — [cheatsheetseries.owasp.org](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html); [kathan19.gitbook.io](https://kathan19.gitbook.io/howtohunt/authentication-bypass/2fa_bypasses.md); [rfc-editor.org](https://www.rfc-editor.org/rfc/rfc7235.html)

**While the program properly exits if authentication fails, it does not ensure that the message is addressed to the user.**

ge->{subject}) . "\n"; print " \n"; print "Body: " . encodeHTML($Message->{body}) . "\n"; } 
 my $q = new CGI; 
 # For purposes of this example, assume that CWE-309 and 
 
 
 
 # CWE-523 do not apply. 
 if (! AuthenticateUser($q->param('username'), $q->param('password'))) { ExitError("invalid username or password"); } 
 my $id = $q->param('id'); DisplayPrivateMessage($id); 
 
 
 
 
 
 
 
 
 
 
 
 While the program properly exits if authentication fails, it does not ensure that the message is addressed to the user. As a result, an authenticated attacker could provide any arbitrary identifier and read private messages that were intended for other users. 
 
 
 
 
 One way to avoid this problem would be to ensure that the "to" field in the message object matches the username of the authenticated user. 
 
 
 
 
 
 
 
 
 
 

 

 
 
 
 Selected Observed
 Examples 
 
 
 Note: this is a curated list of examples for

- *Disproof:* Refuted when: the same behaviour is absent when the single named control in the claim is present, and the control is shown to be present rather than assumed. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“While the program properly exits if authentication fails, it does not ensure tha”) does not occur under a test that isolates that control.
- *Evidence:* high_confidence — [cwe.mitre.org](https://cwe.mitre.org/data/definitions/862.html); [portswigger.net](https://portswigger.net/web-security/access-control)

## Validation

_No verified validation items yet._ Derived from evidence only, so this section is empty rather than plausible.


## 4. False-positive rejection

_The checks that eliminate the most common non-findings. Run these BEFORE reporting, not after a rejection._

**A 403 returned after credentials are accepted is the specified response for valid-but-insufficient credentials and must not be filed as broken authentication, because authentication succeeded and authorization refused.**

The two failure modes are deliberately distinguished in HTTP. MDN states that a server receiving valid credentials that are inadequate to access a given resource should respond 403 Forbidden, and that unlike 401 or 407 the browser will not propose another attempt because authentication is impossible for that user. RFC 7235 draws the same line at the challenge level: a 401 carries a WWW-Authenticate challenge, so the client is invited to retry. CWE-287 also warns against conflating the two, noting that use of 'Auth' as an abbreviation is discouraged precisely because it blurs authentication and authorization. In the field this means a login form returning 403 for a low-privilege account is the control working - reporting it as an authn flaw invites a fix that breaks the authorization model.

- *Disproof:* It IS an authentication defect if the 403 is returned in place of a 401 when the credentials themselves are wrong or absent, because the client is then never invited to supply them and legitimate users are locked out - or if the application reveals the 403 only after it has already established a session, meaning the session was granted and then the response shape confused the test. Distinguish by whether any correct credential for that user can obtain access, not by the status code alone.
- *Evidence:* high_confidence — [developer.mozilla.org](https://developer.mozilla.org/en-US/docs/Web/HTTP/Authentication); [rfc-editor.org](https://www.rfc-editor.org/rfc/rfc7235.html)

**An OAuth device authorization grant that the resource owner completes in person at the verification endpoint the provider printed is the intended flow and is not an authentication bypass, because the grant is authorized by the account holder rather than captured from them.**

The lookalike: you run a device-code flow, the code and user_code are shown to you, you enter them on the identity provider's verification URI, approve, and the token endpoint then returns tokens. Scanners and careless manual testing both record this as an authentication bypass because tokens were minted. The discriminator is who authorized the grant. In the intended flow the human who typed the user_code IS the account holder, acting deliberately at the endpoint the provider printed; the attacker never holds the account and gains nothing they did not already have. The bypass case is different in kind: the same grant is accepted by an endpoint that was never intended to serve it, so the resource owner's approval is laundered through a component that should not have honoured it. Test the discriminator by reading the verification_uri the provider issued and confirming it is the provider's own host, and by confirming the human who approved is the account holder. Report the second case; discard the first.

- *Disproof:* Refuted when the verification endpoint the grant was completed at is the identity provider's own published URI, and the account that approved is the account whose token was issued; where the approving human is the resource owner acting deliberately, no identity was claimed that the claimant could not already prove.
- *Evidence:* high_confidence — [cwe.mitre.org](https://cwe.mitre.org/data/definitions/287.html); [portswigger.net](https://portswigger.net/web-security/oauth)

## 5. Known bypasses

_Filters and controls that have defeated the techniques above. Treat these as the reason a naive test fails, not as proof of safety._

**Where several parties are hosted under one canonical root URI and separated only by an HTTP Basic realm, a credential accepted for one path is reusable at every other path on that origin, so the protection boundary is the origin rather than the resource.**

RFC 7235 states this as a security consideration rather than folklore: schemes relying solely on the realm mechanism expose credentials to all resources on an origin server, and clients that have authenticated to one resource can reuse the same credentials elsewhere on that origin, making it possible for a different resource to harvest credentials for the others. The suggested mitigations are separating protection spaces by host name or port, or restricting direct access to the Authorization header. In hunting terms, this converts an assumed per-path authentication boundary into an origin-wide one, and it changes what a finding means: an injection or XSS on a low-value path becomes a credential-theft path against a high-value sibling. nginx's auth_basic model shows the same shape, since access can be limited by address, by subrequest result, or by JWT rather than by password alone.

- *Disproof:* It does not apply where the schemes in use bind the credential to a narrower scope - cookie sessions scoped to a path, a scheme with per-resource tokens, or separate host names or ports per party, which is exactly the mitigation the RFC names. Verify the deployment's actual realm values and host layout before reporting; a site that already separates parties by hostname is not exposed to this, and cookie-based applications do not send a reusable Authorization header at all.
- *Evidence:* high_confidence — [nginx.org](https://nginx.org/en/docs/http/ngx_http_auth_basic_module.html); [rfc-editor.org](https://www.rfc-editor.org/rfc/rfc7235.html)

## Chaining

_No verified chain_link items yet._ Derived from evidence only, so this section is empty rather than plausible.


## Impact

_No verified impact items yet._ Derived from evidence only, so this section is empty rather than plausible.


## Coverage gap

These stages have no verified evidence and are therefore absent above: Validation, Chaining, Impact.
A procedure with a missing validation stage is not safe to act on — it produces findings rather than proofs.

---

*Generated from the evidence base. Where this file and the database disagree, the database is correct.*
