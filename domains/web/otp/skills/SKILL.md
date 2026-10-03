---
name: otp-hunting
description: Use when hunting One-time password endpoints in a identity target. Ordered prerequisites, signals, techniques, validation bar and false-positive rules.
---

# One-time password endpoints — hunting skill

<!-- GENERATED from db/wks.db by wks/skillgen.py. DO NOT HAND-EDIT.
     Edit the rows (or ingest better research) and re-run:
     python -m wks.skillgen -->

> surface `identity` · CWE — · OWASP —
> evidence: 11 items, 11 supported, 2 FP rules, 1 chains
> maturity: **researching** — missing: items

OTP issuance, verification, and the stubs and nonces that look like issuance without being it.


## Recon signals (where to look)

- Prompt volume that does not correspond to a user-initiated login is the observable signature of second-factor request generation, and it is what a log review should key on.
  - **Disproof:** If a deployment's second-factor provider shows one prompt per interactive login and never fires prompts that the user did not start, this signal never appears and the detection has nothing to match.
  - Sources: <https://attack.mitre.org/techniques/T1621/> · <https://cheatsheetseries.owasp.org/cheatsheets/Multifactor_Authentication_Cheat_Sheet.html>

## Techniques (what to change)

- Time-based one-time passwords derive every code from one shared seed handed to the user's authenticator at enrolment, so obtaining that seed lets an attacker generate acceptable codes indefinitely.
  - **Disproof:** If the codes cannot be reproduced locally from the seed value alone, because a server-held key or a per-request challenge also contributes to the output, seed theft yields no usable code generator.
  - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/Multifactor_Authentication_Cheat_Sheet.html> · <https://pages.nist.gov/800-63-3/sp800-63b.html>
- Repeatedly triggering an account's second-factor prompts until the user approves one converts a second factor into a denial-of-service lever that ends in account access.
  - **Disproof:** A burst of second-factor prompts appears for an account with no matching user-initiated login, and the requests stop only when an approval lands; if prompts cease without an approval and no access follows, the fatigue attempt failed.
  - Sources: <https://attack.mitre.org/techniques/T1621/> · <https://cheatsheetseries.owasp.org/cheatsheets/Multifactor_Authentication_Cheat_Sheet.html>
- A hardware token in an attacker's hands emits codes on its own, so stealing the device removes the need for the PIN or unlock code that would otherwise gate each request.
  - **Disproof:** A stolen token that refuses to produce a code until a PIN or device unlock code is entered leaves the holder with no usable code and closes this path.
  - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/Multifactor_Authentication_Cheat_Sheet.html> · <https://pages.nist.gov/800-63-3/sp800-63b.html>
- A second factor delivered over SMS or voice can be taken by an attacker who moves the victim's phone number to a carrier SIM they control, without touching the account password.
  - **Disproof:** If the account's second factor never depends on the victim's telephone number, a successful number transfer yields no code and this path produces nothing.
  - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/Multifactor_Authentication_Cheat_Sheet.html> · <https://pages.nist.gov/800-63-3/sp800-63b.html>
- A reverse-proxy phishing relay placed between the user and the real login service passes traffic through untouched, so the one-time code and the resulting session are both captured live rather than replayed later.
  - **Disproof:** If the second factor is a phishing-resistant authenticator that binds to the legitimate origin, the relayed request never produces an accepted assertion and no code or session reaches the operator.
  - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/Multifactor_Authentication_Cheat_Sheet.html> · <https://pages.nist.gov/800-63-3/sp800-63b.html>

## False-positive rules (when to reject it)

- Reject a otp finding until it is distinguished from the adjacent behaviour this class also covers. "A reverse-proxy phishing relay placed between the user and the real login service passes traffic through untouched, so the one-time code and the resulting session are both captured live rather than replayed later." and "An authentication flow whose second factor fails open, or which falls back to a legacy endpoint that does not enforce the same requirement, grants access with a lower-assurance factor than policy assumes." share a surface and a symptom, so a response that matches the first is not evidence for it while the second remains possible.
  - **Disproof:** This rule is wrong if a controlled test shows the two behaviours can never co-occur on the same surface, or if the corpus entry for "An authentication flow whose second factor fails open, or which falls " is out of date. In that case this class needs its false-positive guidance rewritten rather than deleted.
  - Sources: <https://attack.mitre.org/techniques/T1556/006/> · <https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html>
- Reject a otp finding until it is distinguished from the adjacent behaviour this class also covers. "An authentication flow whose second factor fails open, or which falls back to a legacy endpoint that does not enforce the same requirement, grants access with a lower-assurance factor than policy assumes." and "Time-based one-time passwords derive every code from one shared seed handed to the user's authenticator at enrolment, so obtaining that seed lets an attacker generate acceptable codes indefinitely." share a surface and a symptom, so a response that matches the first is not evidence for it while the second remains possible.
  - **Disproof:** This rule is wrong if a controlled test shows the two behaviours can never co-occur on the same surface, or if the corpus entry for "Time-based one-time passwords derive every code from one shared seed h" is out of date. In that case this class needs its false-positive guidance rewritten rather than deleted.
  - Sources: <https://attack.mitre.org/techniques/T1556/006/> · <https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html>

## Defence bypasses

- A verification step that never rate-limits or locks out an account lets an attacker keep guessing the short one-time code until a valid value is accepted.
  - **Disproof:** Submitting a large number of distinct code values against one account's verification step and observing that no lockout, delay or rejection response ever appears: the attacker is not being throttled.
  - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html> · <https://pages.nist.gov/800-63-3/sp800-63b.html>
- A verification endpoint that accepts the same one-time value twice for one nonce can be replayed by anyone who observed that value during its short validity window.
  - **Disproof:** Submit the identical code twice for the same login attempt: if the second submission is refused with a used-code or expired-code response, the value is single-use and no replay window exists.
  - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/Multifactor_Authentication_Cheat_Sheet.html> · <https://pages.nist.gov/800-63-3/sp800-63b.html>
- An authentication flow whose second factor fails open, or which falls back to a legacy endpoint that does not enforce the same requirement, grants access with a lower-assurance factor than policy assumes.
  - **Disproof:** Force the second-factor call to fail (block the endpoint, starve it) and log in: if the session is still established, the flow fails open and the downgrade is real.
  - Sources: <https://attack.mitre.org/techniques/T1556/006/> · <https://cheatsheetseries.owasp.org/cheatsheets/Multifactor_Authentication_Cheat_Sheet.html>

---
Full class document: `domains/web/otp/knowledge/DIGEST.md` · retrieve more with `python -m wks.cli search "<query>" --class-id otp`
