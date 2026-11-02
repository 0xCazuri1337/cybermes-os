# Methodology — Authentication Failures

> Derived from 8 verified items. Regenerate with `python -m wks.methodgen --class authn --apply`. Do not hand-edit: this file is a projection of the evidence, and edits are lost on the next cycle.

**Surface.** The mechanism that establishes identity can be bypassed, reused, or subverted end to end.

**References.** CWE-287 · A07:2021

## 1. Preconditions

_Nothing below is reachable until these hold. Confirm each against the target before spending time on the technique._

**SAML assertions fail to verify when the service provider and identity provider disagree on XML canonicalization, because the hashed byte representation of the same logical content then differs.**

Canonicalization turns a document into a stable byte sequence so a hash over signed content is reproducible. When the two parties normalize differently, identical logical content produces different bytes, the digest does not match, and authentication fails. For a hunter this matters because an assertion that will not validate may be an interoperability defect rather than an attack surface, and filing it as a signature-bypass candidate wastes a cycle. The diagnostic is whether the failure is consistent across every request and whether an unmutated assertion from the same provider also fails.

- *Disproof:* If an unmodified assertion from the same identity provider validates reliably, canonicalization disagreement is not the cause of the observed failure.
- *Evidence:* high_confidence — [blog.trailofbits.com](https://blog.trailofbits.com/2026/09/21/saml-a-fractal-of-bad-design/); [stepsecurity.io](https://www.stepsecurity.io/blog/introducing-deny-list-egress-policies-for-harden-runner)

## Reconnaissance signals

_No verified signal items yet._ Derived from evidence only, so this section is empty rather than plausible.


## Test sequence

_No verified technique items yet._ Derived from evidence only, so this section is empty rather than plausible.


## 2. Validation

_How to prove the finding rather than infer it. A technique that cannot be validated must not be reported._

**A session-puzzling candidate is confirmed only when a pre-authentication session variable, set before credentials are supplied, still determines the authenticated identity or an authorization decision after login.**

Run the discriminating test in three steps against a session you control end to end. Step 1, baseline: request an authenticated-adjacent page with no cookie at all and record the response, then log in normally and record the post-login identity, so you hold the reference answer for what your own session legitimately resolves to. Step 2, pre-login poisoning: as an anonymous visitor, take the session cookie the server issues, mutate exactly one session variable on the server side (a role, an owner id, a tenant, a user reference) using your own test values, and carry that same cookie into the login POST - do not create a second session at the login step. Step 3, authority read: after the login response, request the same authenticated-adjacent resource and compare the resolved identity and the authorization outcome against the baseline from step 1. The observation that proves the finding is a differential in authority, not in bytes: the post-login session resolves to a principal you did not authenticate as, or an action gated on role or ownership succeeds for your account where the baseline denied it. A cosmetic variable, a locale, a theme, or a cart id that is re-keyed to your authenticated user produces no differential and must be discarded.

- *Disproof:* Refuted when the post-login session resolves to the principal whose credentials were just presented, the mutated variable is overwritten rather than merged at the authentication transition, and the authorization-gated action denied in the baseline remains denied; a session value that cannot survive authentication cannot produce an authority differential.
- *Evidence:* high_confidence — [academy.hackthebox.com](https://academy.hackthebox.com/course/preview/abusing-http-misconfigurations); [cwe.mitre.org](https://cwe.mitre.org/data/definitions/287.html)

## 3. False-positive rejection

_The checks that eliminate the most common non-findings. Run these BEFORE reporting, not after a rejection._

**A session variable populated before login that carries no privilege and is discarded at authentication is session-puzzling surface, not an authentication bypass, and is only a bypass once the pre-login value determines an authenticated identity.**

The lookalike: you browse as an anonymous visitor, the server issues a session cookie, you edit one session variable (a role, a user id, a cart owner, an isAdmin flag), you then log in, and the response shows an elevated identity or an object that should not be yours. The discriminating test is whether the pre-login value survived the authentication transition with authority, not whether it existed. Two observations settle it. First, whether the variable is present in the session at all before credentials are supplied - if it is only written after authentication, the pre-login edit cannot have influenced anything. Second, whether the post-login identity is the one you authenticated as: the winning case is your own account returning data or actions belonging to a different principal. What refutes the finding is the case where the pre-login variable is cosmetic (a theme, a locale, a cart id that is re-keyed to the authenticated user) and the post-login session resolves solely from the credential that was just presented. Distinguish this from a genuine session-puzzling bug, where improper handling of session variables does lead to authentication bypasses or account takeover: the class of defect is the same, the evidence threshold is not.

- *Disproof:* Refuted when the session variable observed before authentication is never read on any post-login code path, or when the post-login session resolves exclusively from the credential just presented and the edited pre-login value is overwritten rather than merged; a token that carries no principal and confers no authority cannot be an authentication bypass.
- *Evidence:* high_confidence — [academy.hackthebox.com](https://academy.hackthebox.com/course/preview/abusing-http-misconfigurations); [cheatsheetseries.owasp.org](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html); [cwe.mitre.org](https://cwe.mitre.org/data/definitions/287.html)

**An OAuth device authorization grant that the resource owner completes in person at the verification endpoint the provider printed is the intended flow and is not an authentication bypass, because the grant is authorized by the account holder rather than captured from them.**

The lookalike: you run a device-code flow, the code and user_code are shown to you, you enter them on the identity provider's verification URI, approve, and the token endpoint then returns tokens. Scanners and careless manual testing both record this as an authentication bypass because tokens were minted. The discriminator is who authorized the grant. In the intended flow the human who typed the user_code IS the account holder, acting deliberately at the endpoint the provider printed; the attacker never holds the account and gains nothing they did not already have. The bypass case is different in kind: the same grant is accepted by an endpoint that was never intended to serve it, so the resource owner's approval is laundered through a component that should not have honoured it. Test the discriminator by reading the verification_uri the provider issued and confirming it is the provider's own host, and by confirming the human who approved is the account holder. Report the second case; discard the first.

- *Disproof:* Refuted when the verification endpoint the grant was completed at is the identity provider's own published URI, and the account that approved is the account whose token was issued; where the approving human is the resource owner acting deliberately, no identity was claimed that the claimant could not already prove.
- *Evidence:* high_confidence — [cwe.mitre.org](https://cwe.mitre.org/data/definitions/287.html); [portswigger.net](https://portswigger.net/web-security/oauth)

## 4. Known bypasses

_Filters and controls that have defeated the techniques above. Treat these as the reason a naive test fails, not as proof of safety._

**An OAuth device authorization grant completed by a user is a legitimate authorization flow unless the resulting token is accepted by an endpoint that was never meant to honour that provisioner, which is the actual bypass condition.**

The bypass is an endpoint-scope mismatch, not the social engineering. In the device authorization grant flow, an attacker socially engineers someone into logging into an application with legitimate credentials; the service generates a token that is then obtained by the threat actor, giving the attacker control of the account, and the lures typically claim that the device code is a one-time password. Everything up to token issuance is the flow working as designed, and the same flow is available to sanctioned red teams. The failure that constitutes a bypass is downstream, where the authorization is honoured somewhere it does not belong. A documented certificate-authority case is exactly that shape: tokens that specify an ACME provisioner are accepted by non-ACME endpoints, because the ACME-specific endpoints throw an error indicating that token auth is not supported while other endpoints in the service perform token authorization depending on the provisioner used, and it does not seem that those endpoints were intended to work with ACME. The /sign endpoint there uses the provisioners AuthorizeSign method to validate the provided token. So the detection rule is: a device code flow is a phishing signal, an account-takeover signal, or a sanctioned test; it becomes a bypass finding only when a token minted under one authorization context is accepted by an endpoint that declares a different one. Name both the issuing provisioner and the accepting endpoint.

- *Disproof:* Every token issued by the device authorization flow is rejected by endpoints configured for a different provisioner, and acceptance is limited to the endpoints that declare that provisioner, showing no endpoint-scope mismatch exists.
- *Evidence:* high_confidence — [proofpoint.com](https://www.proofpoint.com/us/blog/threat-insight/access-granted-phishing-device-code-authorization-account-takeover); [talosintelligence.com](https://www.talosintelligence.com/vulnerability_reports/TALOS-2025-2242)

## 5. Chaining

_How this class escalates when combined with others. Each step is anchored to a promoted item._

**A SAML relying party that validates a signed assertion without pinning which assertion in the response it trusts accepts an attacker-injected second assertion, so the session it establishes is bound to an identity the identity provider never asserted.**

The defect and the escalation are separate findings that are routinely graded as one and one-half. The defect is narrow and entirely inside the relying party: it checks that some signature in the SAML response is valid, but does not bind the signature to the specific assertion it then consumes. CWE-347 states the underlying condition plainly - the product does not verify, or incorrectly verifies, the cryptographic signature for data - and in the SAML case the data is the identity claim. The escalation is what makes it a takeover rather than a parser curiosity: once the relying party will accept an assertion the attacker also controls, the attacker simply adds a second assertion carrying their own subject, and the service provider consumes theirs. The session that results is a genuine, signed, provider-issued session for an account the attacker chose, which is indistinguishable from a real login to every downstream control including the cookie flags. That is why signature verification and audience restriction alone do not close this: both can pass on the legitimate assertion while the code acts on the injected one. Two preconditions decide whether the chain completes - the response must permit a second assertion element without a hard signature-enforcing failure, and the service provider must lack an assertion-consumption pin. Test the chain by asserting the attacker identity end to end and reading back the resolved subject, not by inspecting the response for a second assertion.

- *Disproof:* Refuted when the relying party rejects any SAML response containing more than one assertion, or when it verifies the signature over the exact assertion element it then consumes rather than over the enclosing response; either control makes the injected assertion unreachable regardless of how many elements the response carries.
- *Evidence:* high_confidence — [academy.hackthebox.com](https://academy.hackthebox.com/course/preview/abusing-http-misconfigurations); [cwe.mitre.org](https://cwe.mitre.org/data/definitions/347.html)

**An OAuth login flow that omits the state parameter does not yield account takeover on its own but binds the victim to the attacker's identity through login CSRF, and it is the account binding rather than the token theft that carries the chain.**

Keep the two outcomes separate, because conflating them is the standard over-claim. Without state, the client cannot prove the callback belongs to the login it initiated. That produces login CSRF: the victim's browser is walked through a flow that ends with the victim's session bound to the attacker's upstream identity. PortSwigger is explicit that where a site allows users to log in exclusively via OAuth the state parameter is arguably less critical, but that not using it can still allow login CSRF attacks whereby the user is tricked into logging in to the attacker's account. The account-takeover branch is a different defect on a different field: redirect_uri validation, where a whitelist of genuine callback URIs registered with the OAuth service is the control, and a code delivered to an attacker endpoint can then be exchanged. Chain the two only when both are proven: login CSRF binds the victim into the attacker's account, and a lax redirect_uri is what lets the attacker control which upstream identity was bound in the first place. Report the binding with two identities observed, not with a decoded token.

- *Disproof:* Refuted when the client compares the returned state against the value it stored at initiation and rejects a mismatch, or when the site offers a non-OAuth login path the attacker cannot reach; without an unbound callback or a lax redirect_uri there is no login CSRF primitive to chain.
- *Evidence:* high_confidence — [academy.hackthebox.com](https://academy.hackthebox.com/course/preview/abusing-http-misconfigurations); [portswigger.net](https://portswigger.net/web-security/oauth)

## Impact

_No verified impact items yet._ Derived from evidence only, so this section is empty rather than plausible.


## Coverage gap

These stages have no verified evidence and are therefore absent above: Reconnaissance signals, Test sequence, Impact.
A procedure with a missing validation stage is not safe to act on — it produces findings rather than proofs.

---

*Generated from the evidence base. Where this file and the database disagree, the database is correct.*
