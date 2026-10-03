# Methodology — One-time password endpoints

> Derived from 11 verified items. Regenerate with `python -m wks.methodgen --class otp --apply`. Do not hand-edit: this file is a projection of the evidence, and edits are lost on the next cycle.

**Surface.** OTP issuance, verification, and the stubs and nonces that look like issuance without being it.

## Preconditions

_No verified prerequisite items yet._ Derived from evidence only, so this section is empty rather than plausible.


## 1. Reconnaissance signals

_What to look for while mapping the surface, and where each signal tells you the rest of the procedure is worth running._

**Prompt volume that does not correspond to a user-initiated login is the observable signature of second-factor request generation, and it is what a log review should key on.**

AN0449 Monitor for excessive or anomalous MFA push notifications or token requests, especially when login attempts originate from unusual IPs or geolocations and do not correspond to legitimate user-initiated sessions.

- *Disproof:* If a deployment's second-factor provider shows one prompt per interactive login and never fires prompts that the user did not start, this signal never appears and the detection has nothing to match.
- *Evidence:* high_confidence — [attack.mitre.org](https://attack.mitre.org/techniques/T1621/); [cheatsheetseries.owasp.org](https://cheatsheetseries.owasp.org/cheatsheets/Multifactor_Authentication_Cheat_Sheet.html)

## 2. Test sequence

_Concrete mutations to try. Each is written to be executable, not to be a description of the vulnerability._

**Repeatedly triggering an account's second-factor prompts until the user approves one converts a second factor into a denial-of-service lever that ends in account access.**

In some cases, adversaries may continuously repeat login attempts in order to bombard users with MFA push notifications, SMS messages, and phone calls, potentially resulting in the user finally accepting the authentication request in response to "MFA fatigue."

- *Disproof:* A burst of second-factor prompts appears for an account with no matching user-initiated login, and the requests stop only when an approval lands; if prompts cease without an approval and no access follows, the fatigue attempt failed.
- *Evidence:* high_confidence — [attack.mitre.org](https://attack.mitre.org/techniques/T1621/); [cheatsheetseries.owasp.org](https://cheatsheetseries.owasp.org/cheatsheets/Multifactor_Authentication_Cheat_Sheet.html)

**Time-based one-time passwords derive every code from one shared seed handed to the user's authenticator at enrolment, so obtaining that seed lets an attacker generate acceptable codes indefinitely.**

A cheaper and easier alternative to hardware tokens is using software to generate Time-based One-Time Password (TOTP) codes. This would typically involve the user installing a TOTP application on their mobile phone, and then scanning a QR code provided by the web application which provides the initial seed. The authenticator app then generates a six digit number every 60 seconds, in much the same way as a hardware token.

- *Disproof:* If the codes cannot be reproduced locally from the seed value alone, because a server-held key or a per-request challenge also contributes to the output, seed theft yields no usable code generator.
- *Evidence:* high_confidence — [cheatsheetseries.owasp.org](https://cheatsheetseries.owasp.org/cheatsheets/Multifactor_Authentication_Cheat_Sheet.html); [pages.nist.gov](https://pages.nist.gov/800-63-3/sp800-63b.html)

**A second factor delivered over SMS or voice can be taken by an attacker who moves the victim's phone number to a carrier SIM they control, without touching the account password.**

SIM Swap and Phone Number Takeover ¶ Attackers convince a telecommunications provider to transfer a victim's phone number, allowing interception of SMS or voice-based one-time passwords. Mitigations ¶ Encourage carrier account PINs or port-out protection where available to reduce unauthorized number transfers. Monitor for unexpected phone-number changes or SIM replacement events. Prefer phishing-resistant authenticators or TOTP instead of SMS/voice OTP.

- *Disproof:* If the account's second factor never depends on the victim's telephone number, a successful number transfer yields no code and this path produces nothing.
- *Evidence:* high_confidence — [cheatsheetseries.owasp.org](https://cheatsheetseries.owasp.org/cheatsheets/Multifactor_Authentication_Cheat_Sheet.html); [pages.nist.gov](https://pages.nist.gov/800-63-3/sp800-63b.html)

**A hardware token in an attacker's hands emits codes on its own, so stealing the device removes the need for the PIN or unlock code that would otherwise gate each request.**

Hardware OTP Tokens ¶ Hardware OTP Tokens generate a constantly changing numeric codes, which must be submitted when authenticating. Most well-known of these is the RSA SecureID , which generates a six digit number that changes every 60 seconds. Pros ¶ As the tokens are separate physical devices, they are almost impossible for an attacker to compromise remotely. Tokens can be used without requiring the user to have a mobile phone or other device. Cons ¶ Deploying physical tokens to users is expensive and complicated. If a user loses their token it could take a significant amount of time to purchase and ship them a new one. Some implementations require a backend server, which can introduce new vulnerabilities as well as a single point of failure. Stolen tokens can be used without a PIN or device unlock code.

- *Disproof:* A stolen token that refuses to produce a code until a PIN or device unlock code is entered leaves the holder with no usable code and closes this path.
- *Evidence:* high_confidence — [cheatsheetseries.owasp.org](https://cheatsheetseries.owasp.org/cheatsheets/Multifactor_Authentication_Cheat_Sheet.html); [pages.nist.gov](https://pages.nist.gov/800-63-3/sp800-63b.html)

**A reverse-proxy phishing relay placed between the user and the real login service passes traffic through untouched, so the one-time code and the resulting session are both captured live rather than replayed later.**

Real-Time Phishing Using Reverse Proxies ¶ Attackers use reverse-proxy phishing frameworks (such as Evilginx, Modlishka, and Muraena) to present convincing copies of legitimate login pages. These frameworks relay authentication traffic between the user and the legitimate service, allowing attackers to capture credentials and session tokens in real-time. Mitigations ¶ Monitor for anomalous authentication and session activity that may indicate credential or session compromise (for example, impossible travel, new ASN, or sudden MFA method changes). Use phishing-resistant authenticators (see Passkeys section), which bind authentication to the legitimate origin and are resistant to real-time phishing attacks.

- *Disproof:* If the second factor is a phishing-resistant authenticator that binds to the legitimate origin, the relayed request never produces an accepted assertion and no code or session reaches the operator.
- *Evidence:* high_confidence — [cheatsheetseries.owasp.org](https://cheatsheetseries.owasp.org/cheatsheets/Multifactor_Authentication_Cheat_Sheet.html); [pages.nist.gov](https://pages.nist.gov/800-63-3/sp800-63b.html)

## Validation

_No verified validation items yet._ Derived from evidence only, so this section is empty rather than plausible.


## 3. False-positive rejection

_The checks that eliminate the most common non-findings. Run these BEFORE reporting, not after a rejection._

**Reject a otp finding until it is distinguished from the adjacent behaviour this class also covers. "A reverse-proxy phishing relay placed between the user and the real login service passes traffic through untouched, so the one-time code and the resulting session are both captured live rather than replayed later." and "An authentication flow whose second factor fails open, or which falls back to a legacy endpoint that does not enforce the same requirement, grants access with a lower-assurance factor than policy assumes." share a surface and a symptom, so a response that matches the first is not evidence for it while the second remains possible.**

Hypothesis under test: A reverse-proxy phishing relay placed between the user and the real login service passes traffic through untouched, so the one-time code and the resulting session are both captured live rather than replayed later.

Adjacent behaviour that produces the same observable result: An authentication flow whose second factor fails open, or which falls back to a legacy endpoint that does not enforce the same requirement, grants access with a lower-assurance factor than policy assumes.

Why this is worth checking before reporting: both are recorded in this class as gated knowledge, so a tester who stops at the first match will report one of them. The two differ in what the server actually did with the input, and that difference is observable in the response rather than in the request.

Required before treating this as a finding: capture the response that demonstrates the first behaviour specifically, and confirm the second is not what was observed.

- *Disproof:* This rule is wrong if a controlled test shows the two behaviours can never co-occur on the same surface, or if the corpus entry for "An authentication flow whose second factor fails open, or which falls " is out of date. In that case this class needs its false-positive guidance rewritten rather than deleted.
- *Evidence:* high_confidence — [attack.mitre.org](https://attack.mitre.org/techniques/T1556/006/); [cheatsheetseries.owasp.org](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html)

**Reject a otp finding until it is distinguished from the adjacent behaviour this class also covers. "An authentication flow whose second factor fails open, or which falls back to a legacy endpoint that does not enforce the same requirement, grants access with a lower-assurance factor than policy assumes." and "Time-based one-time passwords derive every code from one shared seed handed to the user's authenticator at enrolment, so obtaining that seed lets an attacker generate acceptable codes indefinitely." share a surface and a symptom, so a response that matches the first is not evidence for it while the second remains possible.**

Hypothesis under test: An authentication flow whose second factor fails open, or which falls back to a legacy endpoint that does not enforce the same requirement, grants access with a lower-assurance factor than policy assumes.

Adjacent behaviour that produces the same observable result: Time-based one-time passwords derive every code from one shared seed handed to the user's authenticator at enrolment, so obtaining that seed lets an attacker generate acceptable codes indefinitely.

Why this is worth checking before reporting: both are recorded in this class as gated knowledge, so a tester who stops at the first match will report one of them. The two differ in what the server actually did with the input, and that difference is observable in the response rather than in the request.

Required before treating this as a finding: capture the response that demonstrates the first behaviour specifically, and confirm the second is not what was observed.

- *Disproof:* This rule is wrong if a controlled test shows the two behaviours can never co-occur on the same surface, or if the corpus entry for "Time-based one-time passwords derive every code from one shared seed h" is out of date. In that case this class needs its false-positive guidance rewritten rather than deleted.
- *Evidence:* high_confidence — [attack.mitre.org](https://attack.mitre.org/techniques/T1556/006/); [cheatsheetseries.owasp.org](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html)

## 4. Known bypasses

_Filters and controls that have defeated the techniques above. Treat these as the reason a naive test fails, not as proof of safety._

**An authentication flow whose second factor fails open, or which falls back to a legacy endpoint that does not enforce the same requirement, grants access with a lower-assurance factor than policy assumes.**

Adversaries may disable or modify multi-factor authentication (MFA) mechanisms to enable persistent access to compromised accounts. Once adversaries have gained access to a network by either compromising an account lacking MFA or by employing an MFA bypass method such as Multi-Factor Authentication Request Generation , adversaries may leverage their access to modify or completely disable MFA defenses. This can be accomplished by abusing legitimate features, such as excluding users from Azure AD Conditional Access Policies, registering a new yet vulnerable/adversary-controlled MFA method, or by manually patching MFA programs and configuration files to bypass expected functionality. [1] [2] For example, modifying the Windows hosts file ( C:\windows\system32\drivers\etc\hosts ) to redirect MFA calls to localhost instead of an MFA server may cause the MFA process to fail. If a "fail open" policy is in place, any otherwise successful authentication attempt may be granted access without enforcing MFA.

- *Disproof:* Force the second-factor call to fail (block the endpoint, starve it) and log in: if the session is still established, the flow fails open and the downgrade is real.
- *Evidence:* high_confidence — [attack.mitre.org](https://attack.mitre.org/techniques/T1556/006/); [cheatsheetseries.owasp.org](https://cheatsheetseries.owasp.org/cheatsheets/Multifactor_Authentication_Cheat_Sheet.html)

**A verification endpoint that accepts the same one-time value twice for one nonce can be replayed by anyone who observed that value during its short validity window.**

5.1.4.1 Single-Factor OTP Authenticators Single-factor OTP authenticators contain two persistent values. The first is a symmetric key that persists for the device's lifetime. The second is a nonce that is either changed each time the authenticator is used or is based on a real-time clock. The secret key and its algorithm SHALL provide at least the minimum security strength specified in the latest revision of SP 800-131A (112 bits as of the date of this publication). The nonce SHALL be of sufficient length to ensure that it is unique for each operation of the device over its lifetime. OTP authenticators - particularly software-based OTP generators - SHOULD discourage and SHALL NOT facilitate the cloning of the secret key onto multiple devices. The authenticator output is obtained by using an approved block cipher or hash function to combine the key and nonce in a secure manner. The authenticator output MAY be truncated to as few as 6 decimal digits (approximately 20 bits of entropy). If the nonce used to generate the authenticator output is based on a real-time clock, the nonce SHALL be changed at least once every 2 minutes. The OTP value associated with a given nonce SHALL be accepted only once.

- *Disproof:* Submit the identical code twice for the same login attempt: if the second submission is refused with a used-code or expired-code response, the value is single-use and no replay window exists.
- *Evidence:* high_confidence — [cheatsheetseries.owasp.org](https://cheatsheetseries.owasp.org/cheatsheets/Multifactor_Authentication_Cheat_Sheet.html); [pages.nist.gov](https://pages.nist.gov/800-63-3/sp800-63b.html)

**A verification step that never rate-limits or locks out an account lets an attacker keep guessing the short one-time code until a valid value is accepted.**

5.2.2 Rate Limiting (Throttling) When required by the authenticator type descriptions in Section 5.1 , the verifier SHALL implement controls to protect against online guessing attacks. Unless otherwise specified in the description of a given authenticator, the verifier SHALL limit consecutive failed authentication attempts on a single account to no more than 100.

- *Disproof:* Submitting a large number of distinct code values against one account's verification step and observing that no lockout, delay or rejection response ever appears: the attacker is not being throttled.
- *Evidence:* high_confidence — [cheatsheetseries.owasp.org](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html); [pages.nist.gov](https://pages.nist.gov/800-63-3/sp800-63b.html)

## Chaining

_No verified chain_link items yet._ Derived from evidence only, so this section is empty rather than plausible.


## Impact

_No verified impact items yet._ Derived from evidence only, so this section is empty rather than plausible.


## Coverage gap

These stages have no verified evidence and are therefore absent above: Preconditions, Validation, Chaining, Impact.
A procedure with a missing validation stage is not safe to act on — it produces findings rather than proofs.

---

*Generated from the evidence base. Where this file and the database disagree, the database is correct.*
