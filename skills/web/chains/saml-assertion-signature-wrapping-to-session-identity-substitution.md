# SAML assertion signature wrapping to attacker-selected session identity

> goal: `account_takeover`
> generated from `db/wks.db` — edit the rows, not this file

A relying party that verifies a signature without pinning which assertion it consumes will act on an attacker-injected second assertion, so the session it establishes is bound to an identity the identity provider never asserted.

## Impact

Full account takeover of any federated user, with a signed and provider-issued session indistinguishable from a genuine login to every downstream control.

## Sequence

### 1. Submit a SAML response carrying the legitimate signed assertion plus an attacker-injected second assertion, and determine whether the response is rejected outright or one assertion is consumed.

**Why it works:** The defect exists only when the relying party verifies that some signature is valid without binding it to the assertion it then reads; a response-level signature check passes on the legitimate assertion while the code acts on the injected one.

**Backed by:** `authn.variant.xml-signature-wrapping-class`

**This step fails if:** If the relying party rejects any document whose signature does not cover the assertion it consumes, and a wrapped variant yields no session, wrapping is not present.

### 2. Establish that the service provider and identity provider agree on canonicalization and on audience restriction, so neither check rejects the mixed response.

**Why it works:** Signature verification and audience restriction are exactly the two controls that appear to cover this case and do not: both evaluate the legitimate assertion, so agreement on canonicalization is what lets the response parse far enough for the injected assertion to be reached.

**Backed by:** `authn.prerequisite.canonicalization-agreement-failure`

**This step fails if:** If an unmodified assertion from the same identity provider validates reliably, canonicalization disagreement is not the cause of the observed failure.

### 3. Read back the subject the relying party resolved for the session it established after the mixed response, and compare it against the subject the identity provider actually asserted.

**Why it works:** Only a resolved-identity differential proves the substitution; the presence of a second assertion element in the response is an input observation, not evidence that the service provider consumed the attacker's claim.

**Backed by:** `authn.bypass.device_code_grant_accepted_by_a_non_intended_endpoint`

**This step fails if:** Every token issued by the device authorization flow is rejected by endpoints configured for a different provisioner, and acceptance is limited to the endpoints that declare that provisioner, showing no endpoint-scope mismatch exists.

### 4. Demonstrate that the substituted session performs an action reserved for the asserted identity, and that the session's cookie posture gives no downstream signal that it was forged.

**Why it works:** The session is signed and provider-issued, so HttpOnly and SameSite posture is unchanged and nothing downstream distinguishes it; an action performed as the substituted identity is the proof that the primitive reached takeover rather than disclosure.

**Backed by:** `oauth.validation.account_takeover_proof`

**This step fails if:** The victim's session resolves to their own pre-existing identity, or the client rejects the callback and never issues a session cookie.
