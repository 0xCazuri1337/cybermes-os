# Methodology — NTLM Authentication Weaknesses

> Derived from 6 verified items. Regenerate with `python -m wks.methodgen --class ad_ntlm --apply`. Do not hand-edit: this file is a projection of the evidence, and edits are lost on the next cycle.

**Surface.** An NTLM challenge can be relayed to a second service, or a captured hash replayed, because NTLM authenticates the connection rather than the channel to it.

**References.** CWE-294

## 1. Preconditions

_Nothing below is reachable until these hold. Confirm each against the target before spending time on the technique._

**LDAP signing and Extended Protection for Authentication are target-side controls that can reject a relayed NTLM exchange; a successful relay requires a target service whose signing and channel-binding policy accepts the relayed authentication.**

Before treating a relay attempt as successful, inspect the target's policy. LDAP signing requires each request to be signed, and Extended Protection for Authentication binds the NTLM exchange to the TLS channel so a relayed token from another channel is rejected. A target with either control enforced is not a viable relay destination for that path. The proof is a completed authenticated session on the target, not a captured challenge-response or a reachable listener.

- *Disproof:* A relay can fail after the victim authenticates to the attacker because the target rejects the unsigned or channel-mismatched exchange. Do not report a relay from the capture alone; require the target-side session and confirm the target's signing and channel-binding policy.
- *Evidence:* high_confidence — [microsoft.com](https://www.microsoft.com/en-us/security/blog/2022/05/25/detecting-and-preventing-privilege-escalation-attacks-leveraging-kerberos-relaying-krbrelayup/); [specterops.io](https://specterops.io/blog/2025/04/08/the-renaissance-of-ntlm-relay-attacks-everything-you-need-to-know/)

## Reconnaissance signals

_No verified signal items yet._ Derived from evidence only, so this section is empty rather than plausible.


## 2. Test sequence

_Concrete mutations to try. Each is written to be executable, not to be a description of the vulnerability._

**Pass-the-Hash authenticates as a user using the NT hash without knowing the password, because NTLM treats the hash as the credential.**

The NT hash is an unsalted MD4 hash of the password. Since NTLM uses the hash directly for authentication, an attacker who extracts it from LSASS, SAM, or NTDS.dit can authenticate anywhere NTLM is accepted. This is a core lateral movement technique in Windows networks.

- *Disproof:* NTLM is disabled in favor of Kerberos, or the NT hash cannot be extracted due to Credential Guard or LSA protection.
- *Evidence:* high_confidence — [cyberdefenders.org](https://cyberdefenders.org/cybersecurity-glossary/active-directory-security/); [wizardcyber.com](https://wizardcyber.com/learning-hub/learning-post/what-is-ntlm/)

**NTLM relay forwards a captured authentication in real time to another service, authenticating as the victim without cracking the password.**

Because NTLM lacks mutual authentication, an attacker in the middle can relay a client's authentication to a different server. The attacker never learns the password. Relay succeeds when the target service does not enforce SMB/LDAP signing or channel binding, and the relayed account has useful privileges on the target.

- *Disproof:* SMB signing, LDAP signing, and channel binding are enforced, or no relay path exists.
- *Evidence:* high_confidence — [amandaguglieri.github.io](https://amandaguglieri.github.io/hackinglife/authentication/ntlm/); [cyberdefenders.org](https://cyberdefenders.org/cybersecurity-glossary/active-directory-security/)

## Validation

_No verified validation items yet._ Derived from evidence only, so this section is empty rather than plausible.


## 3. False-positive rejection

_The checks that eliminate the most common non-findings. Run these BEFORE reporting, not after a rejection._

**SMB signing is a target-side control: a successful SMB relay requires a server that does not require signing, while a signing requirement causes the relayed session to fail rather than proving the victim was compromised.**

The victim's NTLM authentication and the attacker's SMB listener do not establish a relay. Check whether the destination SMB server requires signing for inbound sessions. If it does, the relayed authentication should fail even after the victim authenticates to the capture listener. Report the control state and the target-side session result, not the capture artifact. A signing-enabled server can still be a finding for other relay paths, so scope the claim to this target and protocol.

- *Disproof:* A signing-enabled SMB server is a blocked relay target for that path, not proof that a relay succeeded. Do not downgrade the finding to informational without checking the other target protocols, and do not report success from the victim's authentication alone.
- *Evidence:* high_confidence — [learn.microsoft.com](https://learn.microsoft.com/en-us/windows-server/storage/file-server/smb-signing); [specterops.io](https://specterops.io/blog/2025/04/08/the-renaissance-of-ntlm-relay-attacks-everything-you-need-to-know/)

## Known bypasses

_No verified bypass items yet._ Derived from evidence only, so this section is empty rather than plausible.


## Chaining

_No verified chain_link items yet._ Derived from evidence only, so this section is empty rather than plausible.


## 4. Impact

_What is actually demonstrable, and what to stop claiming._

**Relaying NTLM authentication to ADCS web enrollment can obtain a certificate for the relay victim, which the attacker can then use to impersonate that victim; ADCS is a relay target distinct from SMB and LDAP.**

The attacker positions between a victim that initiates NTLM authentication and an ADCS web-enrollment endpoint, then relays the exchange so the CA issues a certificate for the victim identity. The certificate is later used for authentication as that identity. The proof is the issued certificate and a successful authentication with it, not the SMB listener alone. Scope the finding to the CA, template, and enrollment endpoint that accepted the relayed authentication.

- *Disproof:* An ADCS web-enrollment endpoint being reachable is not proof of a relay. Reject the finding unless the CA issued a certificate for the relayed identity and that certificate authenticated to a service outside the engagement's authorized test path, or the certificate's issuance is otherwise demonstrated.
- *Evidence:* high_confidence — [helpnetsecurity.com](https://www.helpnetsecurity.com/2025/07/04/ntlm-relay-attacks/); [specterops.io](https://specterops.io/blog/2025/04/08/the-renaissance-of-ntlm-relay-attacks-everything-you-need-to-know/)

## Coverage gap

These stages have no verified evidence and are therefore absent above: Reconnaissance signals, Validation, Known bypasses, Chaining.
A procedure with a missing validation stage is not safe to act on — it produces findings rather than proofs.

---

*Generated from the evidence base. Where this file and the database disagree, the database is correct.*
