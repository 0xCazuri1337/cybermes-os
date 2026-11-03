<!-- GENERATED from db/wks.db — do not edit -->
# NTLM Authentication Weaknesses

> surface: `ad` · CWE: CWE-294 · OWASP: —
> maturity: **researching** — 12 items, 6 supported, 1 FP rules, 1 chains

An NTLM challenge can be relayed to a second service, or a captured hash replayed, because NTLM authenticates the connection rather than the channel to it.

**Aliases:** ntlm, ntlmv1, relay, ntlm relay, name piping, named pipe, nbns spoofing, smb relay, responder

## Prerequisite

- **LDAP signing and Extended Protection for Authentication are target-side controls that can reject a relayed NTLM exchange; a successful relay requires a target service whose signing and channel-binding policy accepts the relayed authentication.**  
  `high_confidence` · score 0.863 · disproved by: A relay can fail after the victim authenticates to the attacker because the target rejects the unsigned or channel-mismatched exchange. Do not report a relay from the capture alone; require the target-side session and confirm the target's signing and channel-binding policy.
  sources: <https://specterops.io/blog/2025/04/08/the-renaissance-of-ntlm-relay-attacks-everything-you-need-to-know/> · <https://www.microsoft.com/en-us/security/blog/2022/05/25/detecting-and-preventing-privilege-escalation-attacks-leveraging-kerberos-relaying-krbrelayup/>

## Technique

- **Pass-the-Hash authenticates as a user using the NT hash without knowing the password, because NTLM treats the hash as the credential.**  
  `high_confidence` · score 0.779 · disproved by: NTLM is disabled in favor of Kerberos, or the NT hash cannot be extracted due to Credential Guard or LSA protection.
  sources: <https://cyberdefenders.org/cybersecurity-glossary/active-directory-security/> · <https://wizardcyber.com/learning-hub/learning-post/what-is-ntlm/>
- **NTLM relay forwards a captured authentication in real time to another service, authenticating as the victim without cracking the password.**  
  `high_confidence` · score 0.779 · disproved by: SMB signing, LDAP signing, and channel binding are enforced, or no relay path exists.
  sources: <https://amandaguglieri.github.io/hackinglife/authentication/ntlm/> · <https://cyberdefenders.org/cybersecurity-glossary/active-directory-security/>

## Fp Rule

- **SMB signing is a target-side control: a successful SMB relay requires a server that does not require signing, while a signing requirement causes the relayed session to fail rather than proving the victim was compromised.**  
  `high_confidence` · score 0.808 · disproved by: A signing-enabled SMB server is a blocked relay target for that path, not proof that a relay succeeded. Do not downgrade the finding to informational without checking the other target protocols, and do not report success from the victim's authentication alone.
  sources: <https://learn.microsoft.com/en-us/windows-server/storage/file-server/smb-signing> · <https://specterops.io/blog/2025/04/08/the-renaissance-of-ntlm-relay-attacks-everything-you-need-to-know/>

## Impact

- **Relaying NTLM authentication to ADCS web enrollment can obtain a certificate for the relay victim, which the attacker can then use to impersonate that victim; ADCS is a relay target distinct from SMB and LDAP.**  
  `high_confidence` · score 0.8715 · disproved by: An ADCS web-enrollment endpoint being reachable is not proof of a relay. Reject the finding unless the CA issued a certificate for the relayed identity and that certificate authenticated to a service outside the engagement's authorized test path, or the certificate's issuance is otherwise demonstrated.
  sources: <https://specterops.io/blog/2025/04/08/the-renaissance-of-ntlm-relay-attacks-everything-you-need-to-know/> · <https://www.helpnetsecurity.com/2025/07/04/ntlm-relay-attacks/>

## Concept

- **NTLMv1 uses DES-based responses that can be converted back to the NT hash, making it significantly weaker than NTLMv2.**  
  `high_confidence` · score 0.7345 · disproved by: NTLMv1 is disabled via GPO (LmCompatibilityLevel 5), or only Kerberos is permitted.
  sources: <https://media.blackhat.com/us-13/US-13-Duckwall-Pass-the-Hash-WP.pdf> · <https://wizardcyber.com/learning-hub/learning-post/what-is-ntlm/>

## Known gaps

Not yet satisfied: `fp_rules`
