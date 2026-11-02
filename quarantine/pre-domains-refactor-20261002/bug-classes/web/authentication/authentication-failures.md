# Authentication Failures

## Definition

The mechanism that establishes identity can be bypassed, reused, or subverted end to end.

- **CWE:** 287
- **OWASP:** A07:2021
- **Surface:** identity
- **Aliases:** ["authentication bypass", "weak login", "password reset flaw", "mfa bypass", "account takeover"]

Canonical home for `authn`. Rendered from `db/wks.db` by `methodology/scripts/build_taxonomy.py` — edit the rows, not this file.

## Root Cause

Not yet researched.

## Preconditions

**SAML assertions fail to verify when the service provider and identity provider disagree on XML canonicalization, because the hashed byte representation of the same logical content then differs.**

Canonicalization turns a document into a stable byte sequence so a hash over signed content is reproducible. When the two parties normalize differently, identical logical content produces different bytes, the digest does not match, and authentication fails. For a hunter this matters because an assertion that will not validate may be an interoperability defect rather than an attack surface, and filing it as a signature-bypass candidate wastes a cycle. The diagnostic is whether the failure is consistent across every request and whether an unmutated assertion from the same provider also fails.

*Disproof:* If an unmodified assertion from the same identity provider validates reliably, canonicalization disagreement is not the cause of the observed failure.

## Attack Surface

Surface: **identity**.

The entry points and enabling conditions for this surface are enumerated under **Preconditions**; the observable signals are under **Detection**.

## Detection

Not yet researched.

## Exploitation

Not yet researched.

## Variations

**An OAuth device authorization grant completed by a user is a legitimate authorization flow unless the resulting token is accepted by an endpoint that was never meant to honour that provisioner, which is the actual bypass condition.**

The bypass is an endpoint-scope mismatch, not the social engineering. In the device authorization grant flow, an attacker socially engineers someone into logging into an application with legitimate credentials; the service generates a token that is then obtained by the threat actor, giving the attacker control of the account, and the lures typically claim that the device code is a one-time password. Everything up to token issuance is the flow working as designed, and the same flow is available to sanctioned red teams. The failure that constitutes a bypass is downstream, where the authorization is honoured somewhere it does not belong. A documented certificate-authority case is exactly that shape: tokens that specify an ACME provisioner are accepted by non-ACME endpoints, because the ACME-specific endpoints throw an error indicating that token auth is not supported while other endpoints in the service perform token authorization depending on the provisioner used, and it does not seem that those endpoints were intended to work with ACME. The /sign endpoint there uses the provisioners AuthorizeSign method to validate the provided token. So the detection rule is: a device code flow is a phishing signal, an account-takeover signal, or a sanctioned test; it becomes a bypass finding only when a token minted under one authorization context is accepted by an endpoint that declares a different one. Name both the issuing provisioner and the accepting endpoint.

*Disproof:* Every token issued by the device authorization flow is rejected by endpoints configured for a different provisioner, and acceptance is limited to the endpoints that declare that provisioner, showing no endpoint-scope mismatch exists.

## Technology / Framework Considerations

Not yet researched.

## API Considerations

Not yet researched.

## Attack Chains

- `saml-assertion-signature-wrapping-to-session-identity-substitution` — SAML assertion signature wrapping to attacker-selected session identity (goal: `account_takeover`)

## Real-World Examples

Not yet researched.

## Common False Positives

**An OAuth device authorization grant that the resource owner completes in person at the verification endpoint the provider printed is the intended flow and is not an authentication bypass, because the grant is authorized by the account holder rather than captured from them.**

The lookalike: you run a device-code flow, the code and user_code are shown to you, you enter them on the identity provider's verification URI, approve, and the token endpoint then returns tokens. Scanners and careless manual testing both record this as an authentication bypass because tokens were minted. The discriminator is who authorized the grant. In the intended flow the human who typed the user_code IS the account holder, acting deliberately at the endpoint the provider printed; the attacker never holds the account and gains nothing they did not already have. The bypass case is different in kind: the same grant is accepted by an endpoint that was never intended to serve it, so the resource owner's approval is laundered through a component that should not have honoured it. Test the discriminator by reading the verification_uri the provider issued and confirming it is the provider's own host, and by confirming the human who approved is the account holder. Report the second case; discard the first.

*Disproof:* Refuted when the verification endpoint the grant was completed at is the identity provider's own published URI, and the account that approved is the account whose token was issued; where the approving human is the resource owner acting deliberately, no identity was claimed that the claimant could not already prove.

**A session variable populated before login that carries no privilege and is discarded at authentication is session-puzzling surface, not an authentication bypass, and is only a bypass once the pre-login value determines an authenticated identity.**

The lookalike: you browse as an anonymous visitor, the server issues a session cookie, you edit one session variable (a role, a user id, a cart owner, an isAdmin flag), you then log in, and the response shows an elevated identity or an object that should not be yours. The discriminating test is whether the pre-login value survived the authentication transition with authority, not whether it existed. Two observations settle it. First, whether the variable is present in the session at all before credentials are supplied - if it is only written after authentication, the pre-login edit cannot have influenced anything. Second, whether the post-login identity is the one you authenticated as: the winning case is your own account returning data or actions belonging to a different principal. What refutes the finding is the case where the pre-login variable is cosmetic (a theme, a locale, a cart id that is re-keyed to the authenticated user) and the post-login session resolves solely from the credential that was just presented. Distinguish this from a genuine session-puzzling bug, where improper handling of session variables does lead to authentication bypasses or account takeover: the class of defect is the same, the evidence threshold is not.

*Disproof:* Refuted when the session variable observed before authentication is never read on any post-login code path, or when the post-login session resolves exclusively from the credential just presented and the edited pre-login value is overwritten rather than merged; a token that carries no principal and confers no authority cannot be an authentication bypass.
**Hypothesis:** A session variable set before login and carried into the authenticated session makes the pre-login identity authoritative, so editing it yields an authentication bypass.
- Invalidated by: The mutated variable is overwritten at the authentication transition rather than merged, so both sessions resolve to the credential just presented and the gated action stays denied; the variable was a locale or theme value with no authority.
- **Rejection rule:** A pre-auth session variable is an authentication bypass only when it survives the login transition with authority: prove the post-login session resolves to a principal you did not authenticate as, or that an authorization-gated action newly succeeds. Presence and editability are not privilege.

## Validation

**A session-puzzling candidate is confirmed only when a pre-authentication session variable, set before credentials are supplied, still determines the authenticated identity or an authorization decision after login.**

Run the discriminating test in three steps against a session you control end to end. Step 1, baseline: request an authenticated-adjacent page with no cookie at all and record the response, then log in normally and record the post-login identity, so you hold the reference answer for what your own session legitimately resolves to. Step 2, pre-login poisoning: as an anonymous visitor, take the session cookie the server issues, mutate exactly one session variable on the server side (a role, an owner id, a tenant, a user reference) using your own test values, and carry that same cookie into the login POST - do not create a second session at the login step. Step 3, authority read: after the login response, request the same authenticated-adjacent resource and compare the resolved identity and the authorization outcome against the baseline from step 1. The observation that proves the finding is a differential in authority, not in bytes: the post-login session resolves to a principal you did not authenticate as, or an action gated on role or ownership succeeds for your account where the baseline denied it. A cosmetic variable, a locale, a theme, or a cart id that is re-keyed to your authenticated user produces no differential and must be discarded.

*Disproof:* Refuted when the post-login session resolves to the principal whose credentials were just presented, the mutated variable is overwritten rather than merged at the authentication transition, and the authorization-gated action denied in the baseline remains denied; a session value that cannot survive authentication cannot produce an authority differential.

## Impact

Not yet researched.

## Related Bug Classes

Not yet researched.

## References

- **academy.hackthebox.com** (docs)
  - <https://academy.hackthebox.com/course/preview/abusing-http-misconfigurations>
- **blog.trailofbits.com** (writeup)
  - <https://blog.trailofbits.com/2026/09/21/saml-a-fractal-of-bad-design/>
- **cheatsheetseries.owasp.org** (cheatsheet)
  - <https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html>
- **cwe.mitre.org** (cwe)
  - <https://cwe.mitre.org/data/definitions/287.html>
  - <https://cwe.mitre.org/data/definitions/347.html>
- **portswigger.net** (cheatsheet)
  - <https://portswigger.net/web-security/oauth>
- **proofpoint.com** (research)
  - <https://www.proofpoint.com/us/blog/threat-insight/access-granted-phishing-device-code-authorization-account-takeover>
- **stepsecurity.io** (writeup)
  - <https://www.stepsecurity.io/blog/introducing-deny-list-egress-policies-for-harden-runner>
- **talosintelligence.com** (vendor_advisory)
  - <https://www.talosintelligence.com/vulnerability_reports/TALOS-2025-2242>
- **unit42.paloaltonetworks.com** (writeup)
  - <https://unit42.paloaltonetworks.com/netscaler-zero-days-exploited/>

Every item above is gated on >= 2 distinct publisher hosts (`wks/quality.py`, rule R1). Publisher diversity, not citation count, is what makes these corroborated.
