# SAML assertion signature wrapping to attacker-selected session identity

## Objective

Goal: **account_takeover**.

A relying party that verifies a signature without pinning which assertion it consumes will act on an attacker-injected second assertion, so the session it establishes is bound to an identity the identity provider never asserted.

## Preconditions

Not yet researched.

## Initial Weakness

**Step 1.** Submit a SAML response carrying the legitimate signed assertion plus an attacker-injected second assertion, and determine whether the response is rejected outright or one assertion is consumed.

- Why: The defect exists only when the relying party verifies that some signature is valid without binding it to the assertion it then reads; a response-level signature check passes on the legitimate assertion while the code acts on the injected one.

## Chain Steps

**1. `authn` — Submit a SAML response carrying the legitimate signed assertion plus an attacker-injected second assertion, and determine whether the response is rejected outright or one assertion is consumed.**

- Why: The defect exists only when the relying party verifies that some signature is valid without binding it to the assertion it then reads; a response-level signature check passes on the legitimate assertion while the code acts on the injected one.

**2. `authn` — Establish that the service provider and identity provider agree on canonicalization and on audience restriction, so neither check rejects the mixed response.**

- Why: Signature verification and audience restriction are exactly the two controls that appear to cover this case and do not: both evaluate the legitimate assertion, so agreement on canonicalization is what lets the response parse far enough for the injected assertion to be reached.

**3. `authn` — Read back the subject the relying party resolved for the session it established after the mixed response, and compare it against the subject the identity provider actually asserted.**

- Why: Only a resolved-identity differential proves the substitution; the presence of a second assertion element in the response is an input observation, not evidence that the service provider consumed the attacker's claim.

**4. `oauth` — Demonstrate that the substituted session performs an action reserved for the asserted identity, and that the session's cookie posture gives no downstream signal that it was forged.**

- Why: The session is signed and provider-issued, so HttpOnly and SameSite posture is unchanged and nothing downstream distinguishes it; an action performed as the substituted identity is the proof that the primitive reached takeover rather than disclosure.

## Required Conditions

Not yet researched.

## Impact

Full account takeover of any federated user, with a signed and provider-issued session indistinguishable from a genuine login to every downstream control.

## Detection Strategy

Not yet researched.

## Validation

Not yet researched.

## Real-World Examples

Not yet researched.

## Related Bug Classes

- `authn` — canonical: [`skills/web/authn/CLASS.md`]
- `oauth` — canonical: [`skills/web/oauth/CLASS.md`]

## References

- **blog.trailofbits.com** — <https://blog.trailofbits.com/2026/09/21/saml-a-fractal-of-bad-design/>
- **cheatsheetseries.owasp.org** — <https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html>
- **docs.oasis-open.org** — <https://docs.oasis-open.org/security/saml/v2.0/saml-core-2.0-os.pdf>
- **portswigger.net** — <https://portswigger.net/web-security/oauth>
- **proofpoint.com** — <https://www.proofpoint.com/us/blog/threat-insight/access-granted-phishing-device-code-authorization-account-takeover>
- **rfc-editor.org** — <https://www.rfc-editor.org/rfc/rfc9700.html>
- **talosintelligence.com** — <https://www.talosintelligence.com/vulnerability_reports/TALOS-2025-2242>
