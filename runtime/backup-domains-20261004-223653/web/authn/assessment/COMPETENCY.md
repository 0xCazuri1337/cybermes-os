# Methodology — Authentication Failures

> Derived from 19 verified items. Regenerate with `python -m wks.methodgen --class authn --apply`. Do not hand-edit: this file is a projection of the evidence, and edits are lost on the next cycle.

**Surface.** The mechanism that establishes identity can be bypassed, reused, or subverted end to end.

**References.** CWE-287 · A07:2021

## Preconditions

_No verified prerequisite items yet._ Derived from evidence only, so this section is empty rather than plausible.


## 1. Reconnaissance signals

_What to look for while mapping the surface, and where each signal tells you the rest of the procedure is worth running._

**A JSON response body that states whether 2FA authentication succeeded is the field to manipulate, because the client-visible success value is what the 2FA check may be read from.**

A JSON response body that states whether 2FA authentication succeeded is the field to manipulate, because the client-visible success value is what the 2FA check may be read from.

HackTricks reference: 2fa bypasses (https://kathan19.gitbook.io/howtohunt/authentication-bypass/2fa_bypasses.md)

- *Disproof:* Editing the success field in the 2FA response body leaves the session unauthenticated because the server records the verified state independently of the returned JSON.
- *Evidence:* high_confidence — [cheatsheetseries.owasp.org](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html); [kathan19.gitbook.io](https://kathan19.gitbook.io/howtohunt/authentication-bypass/2fa_bypasses.md); [rfc-editor.org](https://www.rfc-editor.org/rfc/rfc7235.html)

## 2. Test sequence

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

## 3. Validation

_How to prove the finding rather than infer it. A technique that cannot be validated must not be reported._

**A session-puzzling candidate is confirmed only when a pre-authentication session variable, set before credentials are supplied, still determines the authenticated identity or an authorization decision after login.**

Run the discriminating test in three steps against a session you control end to end. Step 1, baseline: request an authenticated-adjacent page with no cookie at all and record the response, then log in normally and record the post-login identity, so you hold the reference answer for what your own session legitimately resolves to. Step 2, pre-login poisoning: as an anonymous visitor, take the session cookie the server issues, mutate exactly one session variable on the server side (a role, an owner id, a tenant, a user reference) using your own test values, and carry that same cookie into the login POST - do not create a second session at the login step. Step 3, authority read: after the login response, request the same authenticated-adjacent resource and compare the resolved identity and the authorization outcome against the baseline from step 1. The observation that proves the finding is a differential in authority, not in bytes: the post-login session resolves to a principal you did not authenticate as, or an action gated on role or ownership succeeds for your account where the baseline denied it. A cosmetic variable, a locale, a theme, or a cart id that is re-keyed to your authenticated user produces no differential and must be discarded.

- *Disproof:* Refuted when the post-login session resolves to the principal whose credentials were just presented, the mutated variable is overwritten rather than merged at the authentication transition, and the authorization-gated action denied in the baseline remains denied; a session value that cannot survive authentication cannot produce an authority differential.
- *Evidence:* high_confidence — [academy.hackthebox.com](https://academy.hackthebox.com/course/preview/abusing-http-misconfigurations); [cwe.mitre.org](https://cwe.mitre.org/data/definitions/287.html)

**An authentication bypass is proven by the credential-free second session carrying the victim's privileges, not by a 200 status, a redirect to a dashboard, or the absence of a login prompt on a single request.**

CWE-287 defines the weakness as the product not proving or insufficiently proving that an identity claim is correct, which makes the proof obligation about the identity assertion itself. A 302 to the post-login page proves only that the server chose to send a Location header; plenty of applications redirect before completing the session, and plenty of protected pages render a shell that fetches data client-side and fails to fetch. The field evidence that closes the finding is a fresh cookie jar with no credentials submitted that still reaches an authenticated-only resource and returns data scoped to the victim - a distinct session identifier that was never obtained through login, plus the victim-scoped payload. That pair is what a triager needs and what a status code cannot supply.

- *Disproof:* It is not a bypass if the second session carries a different identity, or if the data returned is identical for every anonymous caller (a public or cached shell), or if the privileged resource re-checks the session server-side and returns 401 or 403 on the fresh jar. Also watch for a pre-seeded anonymous session cookie that the server treats as a guest with no privileges - that is a normal unauthenticated path, not an identity claim the product failed to check.
- *Evidence:* high_confidence — [cwe.mitre.org](https://cwe.mitre.org/data/definitions/287.html); [developer.mozilla.org](https://developer.mozilla.org/en-US/docs/Web/HTTP/Authentication)

## 4. False-positive rejection

_The checks that eliminate the most common non-findings. Run these BEFORE reporting, not after a rejection._

**A differential response between a known-nonexistent username and a known-existing username with a wrong password is only username enumeration if the difference is observable by an unauthenticated party, so a difference visible solely in server-side logs does not support the finding.**

The distinction that keeps this honest is between what an attacker can read and what an operator can read. The weakness requires the product to fail to prove an identity claim; a timing or message difference that the response body and status do not expose is a hardening observation, not a demonstrable enumeration channel. Hunt it as a channel test rather than a source-code judgement: submit a valid-format unknown identifier and a known-bad password, then a known-valid identifier with the same bad password, and compare status, body length, and time across many samples to separate a real signal from noise. Single-shot timing comparisons on a noisy network produce findings that do not survive a re-test, which is why the class is under-reported as often as over-reported.

- *Disproof:* It is a real enumeration channel if the two responses differ observably to the unauthenticated requester - a different status, a distinguishable body, a materially different response time after averaging, or a redirect difference. Note also that some differentials are legitimate: RFC 7235 describes 401 responses that carry a possibly new challenge, and browsers handling cross-origin images no longer trigger authentication dialogs, so a differential that depends on browser behaviour is not a server-side enumeration primitive.
- *Evidence:* high_confidence — [developer.mozilla.org](https://developer.mozilla.org/en-US/docs/Web/HTTP/Authentication); [rfc-editor.org](https://www.rfc-editor.org/rfc/rfc7235.html)

**A 403 returned after credentials are accepted is the specified response for valid-but-insufficient credentials and must not be filed as broken authentication, because authentication succeeded and authorization refused.**

The two failure modes are deliberately distinguished in HTTP. MDN states that a server receiving valid credentials that are inadequate to access a given resource should respond 403 Forbidden, and that unlike 401 or 407 the browser will not propose another attempt because authentication is impossible for that user. RFC 7235 draws the same line at the challenge level: a 401 carries a WWW-Authenticate challenge, so the client is invited to retry. CWE-287 also warns against conflating the two, noting that use of 'Auth' as an abbreviation is discouraged precisely because it blurs authentication and authorization. In the field this means a login form returning 403 for a low-privilege account is the control working - reporting it as an authn flaw invites a fix that breaks the authorization model.

- *Disproof:* It IS an authentication defect if the 403 is returned in place of a 401 when the credentials themselves are wrong or absent, because the client is then never invited to supply them and legitimate users are locked out - or if the application reveals the 403 only after it has already established a session, meaning the session was granted and then the response shape confused the test. Distinguish by whether any correct credential for that user can obtain access, not by the status code alone.
- *Evidence:* high_confidence — [developer.mozilla.org](https://developer.mozilla.org/en-US/docs/Web/HTTP/Authentication); [rfc-editor.org](https://www.rfc-editor.org/rfc/rfc7235.html)

**An OAuth device authorization grant that the resource owner completes in person at the verification endpoint the provider printed is the intended flow and is not an authentication bypass, because the grant is authorized by the account holder rather than captured from them.**

The lookalike: you run a device-code flow, the code and user_code are shown to you, you enter them on the identity provider's verification URI, approve, and the token endpoint then returns tokens. Scanners and careless manual testing both record this as an authentication bypass because tokens were minted. The discriminator is who authorized the grant. In the intended flow the human who typed the user_code IS the account holder, acting deliberately at the endpoint the provider printed; the attacker never holds the account and gains nothing they did not already have. The bypass case is different in kind: the same grant is accepted by an endpoint that was never intended to serve it, so the resource owner's approval is laundered through a component that should not have honoured it. Test the discriminator by reading the verification_uri the provider issued and confirming it is the provider's own host, and by confirming the human who approved is the account holder. Report the second case; discard the first.

- *Disproof:* Refuted when the verification endpoint the grant was completed at is the identity provider's own published URI, and the account that approved is the account whose token was issued; where the approving human is the resource owner acting deliberately, no identity was claimed that the claimant could not already prove.
- *Evidence:* high_confidence — [cwe.mitre.org](https://cwe.mitre.org/data/definitions/287.html); [portswigger.net](https://portswigger.net/web-security/oauth)

**A session variable populated before login that carries no privilege and is discarded at authentication is session-puzzling surface, not an authentication bypass, and is only a bypass once the pre-login value determines an authenticated identity.**

The lookalike: you browse as an anonymous visitor, the server issues a session cookie, you edit one session variable (a role, a user id, a cart owner, an isAdmin flag), you then log in, and the response shows an elevated identity or an object that should not be yours. The discriminating test is whether the pre-login value survived the authentication transition with authority, not whether it existed. Two observations settle it. First, whether the variable is present in the session at all before credentials are supplied - if it is only written after authentication, the pre-login edit cannot have influenced anything. Second, whether the post-login identity is the one you authenticated as: the winning case is your own account returning data or actions belonging to a different principal. What refutes the finding is the case where the pre-login variable is cosmetic (a theme, a locale, a cart id that is re-keyed to the authenticated user) and the post-login session resolves solely from the credential that was just presented. Distinguish this from a genuine session-puzzling bug, where improper handling of session variables does lead to authentication bypasses or account takeover: the class of defect is the same, the evidence threshold is not.

- *Disproof:* Refuted when the session variable observed before authentication is never read on any post-login code path, or when the post-login session resolves exclusively from the credential just presented and the edited pre-login value is overwritten rather than merged; a token that carries no principal and confers no authority cannot be an authentication bypass.
- *Evidence:* high_confidence — [cheatsheetseries.owasp.org](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html); [cwe.mitre.org](https://cwe.mitre.org/data/definitions/287.html)

## 5. Known bypasses

_Filters and controls that have defeated the techniques above. Treat these as the reason a naive test fails, not as proof of safety._

**An OAuth device authorization grant completed by a user is a legitimate authorization flow unless the resulting token is accepted by an endpoint that was never meant to honour that provisioner, which is the actual bypass condition.**

The bypass is an endpoint-scope mismatch, not the social engineering. In the device authorization grant flow, an attacker socially engineers someone into logging into an application with legitimate credentials; the service generates a token that is then obtained by the threat actor, giving the attacker control of the account, and the lures typically claim that the device code is a one-time password. Everything up to token issuance is the flow working as designed, and the same flow is available to sanctioned red teams. The failure that constitutes a bypass is downstream, where the authorization is honoured somewhere it does not belong. A documented certificate-authority case is exactly that shape: tokens that specify an ACME provisioner are accepted by non-ACME endpoints, because the ACME-specific endpoints throw an error indicating that token auth is not supported while other endpoints in the service perform token authorization depending on the provisioner used, and it does not seem that those endpoints were intended to work with ACME. The /sign endpoint there uses the provisioners AuthorizeSign method to validate the provided token. So the detection rule is: a device code flow is a phishing signal, an account-takeover signal, or a sanctioned test; it becomes a bypass finding only when a token minted under one authorization context is accepted by an endpoint that declares a different one. Name both the issuing provisioner and the accepting endpoint.

- *Disproof:* Every token issued by the device authorization flow is rejected by endpoints configured for a different provisioner, and acceptance is limited to the endpoints that declare that provisioner, showing no endpoint-scope mismatch exists.
- *Evidence:* high_confidence — [proofpoint.com](https://www.proofpoint.com/us/blog/threat-insight/access-granted-phishing-device-code-authorization-account-takeover); [talosintelligence.com](https://www.talosintelligence.com/vulnerability_reports/TALOS-2025-2242)

**Where several parties are hosted under one canonical root URI and separated only by an HTTP Basic realm, a credential accepted for one path is reusable at every other path on that origin, so the protection boundary is the origin rather than the resource.**

RFC 7235 states this as a security consideration rather than folklore: schemes relying solely on the realm mechanism expose credentials to all resources on an origin server, and clients that have authenticated to one resource can reuse the same credentials elsewhere on that origin, making it possible for a different resource to harvest credentials for the others. The suggested mitigations are separating protection spaces by host name or port, or restricting direct access to the Authorization header. In hunting terms, this converts an assumed per-path authentication boundary into an origin-wide one, and it changes what a finding means: an injection or XSS on a low-value path becomes a credential-theft path against a high-value sibling. nginx's auth_basic model shows the same shape, since access can be limited by address, by subrequest result, or by JWT rather than by password alone.

- *Disproof:* It does not apply where the schemes in use bind the credential to a narrower scope - cookie sessions scoped to a path, a scheme with per-resource tokens, or separate host names or ports per party, which is exactly the mitigation the RFC names. Verify the deployment's actual realm values and host layout before reporting; a site that already separates parties by hostname is not exposed to this, and cookie-based applications do not send a reusable Authorization header at all.
- *Evidence:* high_confidence — [nginx.org](https://nginx.org/en/docs/http/ngx_http_auth_basic_module.html); [rfc-editor.org](https://www.rfc-editor.org/rfc/rfc7235.html)

## 6. Chaining

_How this class escalates when combined with others. Each step is anchored to a promoted item._

**A SAML relying party that validates a signed assertion without pinning which assertion in the response it trusts accepts an attacker-injected second assertion, so the session it establishes is bound to an identity the identity provider never asserted.**

The defect and the escalation are separate findings that are routinely graded as one and one-half. The defect is narrow and entirely inside the relying party: it checks that some signature in the SAML response is valid, but does not bind the signature to the specific assertion it then consumes. CWE-347 states the underlying condition plainly - the product does not verify, or incorrectly verifies, the cryptographic signature for data - and in the SAML case the data is the identity claim. The escalation is what makes it a takeover rather than a parser curiosity: once the relying party will accept an assertion the attacker also controls, the attacker simply adds a second assertion carrying their own subject, and the service provider consumes theirs. The session that results is a genuine, signed, provider-issued session for an account the attacker chose, which is indistinguishable from a real login to every downstream control including the cookie flags. That is why signature verification and audience restriction alone do not close this: both can pass on the legitimate assertion while the code acts on the injected one. Two preconditions decide whether the chain completes - the response must permit a second assertion element without a hard signature-enforcing failure, and the service provider must lack an assertion-consumption pin. Test the chain by asserting the attacker identity end to end and reading back the resolved subject, not by inspecting the response for a second assertion.

- *Disproof:* Refuted when the relying party rejects any SAML response containing more than one assertion, or when it verifies the signature over the exact assertion element it then consumes rather than over the enclosing response; either control makes the injected assertion unreachable regardless of how many elements the response carries.
- *Evidence:* high_confidence — [academy.hackthebox.com](https://academy.hackthebox.com/course/preview/abusing-http-misconfigurations); [cheatsheetseries.owasp.org](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html); [cwe.mitre.org](https://cwe.mitre.org/data/definitions/287.html)

**An OAuth login flow that omits the state parameter does not yield account takeover on its own but binds the victim to the attacker's identity through login CSRF, and it is the account binding rather than the token theft that carries the chain.**

Keep the two outcomes separate, because conflating them is the standard over-claim. Without state, the client cannot prove the callback belongs to the login it initiated. That produces login CSRF: the victim's browser is walked through a flow that ends with the victim's session bound to the attacker's upstream identity. PortSwigger is explicit that where a site allows users to log in exclusively via OAuth the state parameter is arguably less critical, but that not using it can still allow login CSRF attacks whereby the user is tricked into logging in to the attacker's account. The account-takeover branch is a different defect on a different field: redirect_uri validation, where a whitelist of genuine callback URIs registered with the OAuth service is the control, and a code delivered to an attacker endpoint can then be exchanged. Chain the two only when both are proven: login CSRF binds the victim into the attacker's account, and a lax redirect_uri is what lets the attacker control which upstream identity was bound in the first place. Report the binding with two identities observed, not with a decoded token.

- *Disproof:* Refuted when the client compares the returned state against the value it stored at initiation and rejects a mismatch, or when the site offers a non-OAuth login path the attacker cannot reach; without an unbound callback or a lax redirect_uri there is no login CSRF primitive to chain.
- *Evidence:* high_confidence — [academy.hackthebox.com](https://academy.hackthebox.com/course/preview/abusing-http-misconfigurations); [portswigger.net](https://portswigger.net/web-security/oauth)

## Impact

_No verified impact items yet._ Derived from evidence only, so this section is empty rather than plausible.


## Coverage gap

These stages have no verified evidence and are therefore absent above: Preconditions, Impact.
A procedure with a missing validation stage is not safe to act on — it produces findings rather than proofs.

---

*Generated from the evidence base. Where this file and the database disagree, the database is correct.*
