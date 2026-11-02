# NTLM Authentication Weaknesses

> surface: `ad` · CWE: CWE-294 · OWASP: —
> maturity: **researching** — 12 items, 6 supported, 1 FP rules, 1 chains

An NTLM challenge can be relayed to a second service, or a captured hash replayed, because NTLM authenticates the connection rather than the channel to it.

**Aliases:** ntlm, ntlmv1, relay, ntlm relay, name piping, named pipe, nbns spoofing, smb relay, responder

## Prerequisite

- **LDAP signing and Extended Protection for Authentication are target-side controls that can reject a relayed NTLM exchange; a successful relay requires a target service whose signing and channel-binding policy accepts the relayed authentication.**  
  `high_confidence` · score 0.863 · disproved by: A relay can fail after the victim authenticates to the attacker because the target rejects the unsigned or channel-mismatched exchange. Do not report a relay from the capture alone; require the target-side session and confirm the target's signing and channel-binding policy.
  sources: <https://specterops.io/blog/2025/04/08/the-renaissance-of-ntlm-relay-attacks-everything-you-need-to-know/> · <https://www.microsoft.com/en-us/security/blog/2022/05/25/detecting-and-preventing-privilege-escalation-attacks-leveraging-kerberos-relaying-krbrelayup/>
- **NTLM authentication traffic cannot be treated as an anomaly until a per-host baseline of legitimate NTLM authentication has been established for that host.**  
  `under_review` · score 0.8355 · disproved by: If the estate is homogeneous and every domain-joined host is Kerberos-only with NTLM disabled at the DC and on all clients, then any NTLM handshake is by definition outside the baseline and no per-host baseline work is required to call it anomalous.
  sources: <https://securelist.com/tr/network-anomaly-detection-in-kata/120892/> · <https://www.proofpoint.com/us/blog/threat-insight/ta577s-unusual-attack-chain-leads-ntlm-data-theft>

## Technique

- **An NTLM authentication exchange can be relayed rather than cracked: because NTLM authenticates the connection and not the channel to it, a captured challenge-response from one service is replayable against a second service that accepts NTLM.**  
  `under_review` · score 0.9565 · disproved by: If the target service rejects the relayed exchange because message signing or channel binding is mandatory, or if no adversary-controlled authentication can be induced on the path, then NTLM relay cannot succeed and any such report is a false positive.
  sources: <https://attack.mitre.org/techniques/T1557/001/> · <https://www.proofpoint.com/us/blog/threat-insight/ta577s-unusual-attack-chain-leads-ntlm-data-theft>
- **Pass-the-Hash authenticates as a user using the NT hash without knowing the password, because NTLM treats the hash as the credential.**  
  `high_confidence` · score 0.779 · disproved by: NTLM is disabled in favor of Kerberos, or the NT hash cannot be extracted due to Credential Guard or LSA protection.
  sources: <https://cyberdefenders.org/cybersecurity-glossary/active-directory-security/> · <https://wizardcyber.com/learning-hub/learning-post/what-is-ntlm/>
- **NTLM relay forwards a captured authentication in real time to another service, authenticating as the victim without cracking the password.**  
  `high_confidence` · score 0.779 · disproved by: SMB signing, LDAP signing, and channel binding are enforced, or no relay path exists.
  sources: <https://amandaguglieri.github.io/hackinglife/authentication/ntlm/> · <https://cyberdefenders.org/cybersecurity-glossary/active-directory-security/>

## Test

- **To decide this case, observe: Absent those artifacts, and absent any NTLMv2 challenge/response pair relayed onward to a second service, the correct classification is coercion attempt with unconfirmed credential exposure.**  
  `under_review` · score 0.863 · disproved by: This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (ad_ntlm.fp_rule.single_outbound_smb_type3_is_unc_coercion_not_hash_theft) states the full boundary.
  sources: <https://www.proofpoint.com/us/blog/threat-insight/ta577s-unusual-attack-chain-leads-ntlm-data-theft> · <https://www.helpnetsecurity.com/2025/10/21/cisa-warns-of-windows-smb-flaw-under-active-exploitation-cve-2025-33073/>
- **A relay is not proven by the attacker's SMB listener alone: the Impacket challenge and GUID identify the capture point, while a completed relay also requires a target that accepts the relayed credentials without signing or channel binding; the LDAP/RBCD path, for example, requires unsigned LDAP.**  
  `under_review` · score 0.808 · disproved by: The relay claim fails when the capture host shows only the default Impacket challenge/GUID and no second authenticated session, or when the intended target enforces SMB signing, LDAP signing, or EPA and rejects the relayed credentials.
  sources: <https://www.microsoft.com/en-us/security/blog/2022/05/25/detecting-and-preventing-privilege-escalation-attacks-leveraging-kerberos-relaying-krbrelayup/> · <https://www.proofpoint.com/us/blog/threat-insight/ta577s-unusual-attack-chain-leads-ntlm-data-theft>

## Fp Rule

- **One outbound SMB session carrying an NTLM Type-3 authenticate message to an external address is the expected result of a UNC link, not evidence that NTLM hashes were stolen; hash theft requires server-side relay artifacts to be present.**  
  `under_review` · score 0.8715 · disproved by: The external SMB server emits the Impacket default NTLM challenge and default GUID, or the captured Type-3 response is replayed successfully to a second host or service as an authenticated session, which turns the observation from coercion into confirmed credential theft.
  sources: <https://www.proofpoint.com/us/blog/threat-insight/ta577s-unusual-attack-chain-leads-ntlm-data-theft> · <https://www.helpnetsecurity.com/2025/10/21/cisa-warns-of-windows-smb-flaw-under-active-exploitation-cve-2025-33073/>
- **SMB signing is a target-side control: a successful SMB relay requires a server that does not require signing, while a signing requirement causes the relayed session to fail rather than proving the victim was compromised.**  
  `high_confidence` · score 0.808 · disproved by: A signing-enabled SMB server is a blocked relay target for that path, not proof that a relay succeeded. Do not downgrade the finding to informational without checking the other target protocols, and do not report success from the victim's authentication alone.
  sources: <https://learn.microsoft.com/en-us/windows-server/storage/file-server/smb-signing> · <https://specterops.io/blog/2025/04/08/the-renaissance-of-ntlm-relay-attacks-everything-you-need-to-know/>

## Evidence

- **A convincing observation for this class is: Adjacent behaviour that produces the same observable result: NTLM authentication traffic cannot be treated as an anomaly until a per-host baseline of legitimate NTLM authentication has been established for that host.**  
  `under_review` · score 0.8815 · disproved by: Not evidence when the observable cannot be produced at all -- blind, server-side-only, or identical-in-every-case behaviour leaves nothing to show. The originating rule (ad_ntlm.fp_rule.auto.derived) states the full boundary.
  sources: <https://attack.mitre.org/techniques/T1557/001/> · <https://academy.hackthebox.com/course/preview/active-directory-enumeration--attacks> · <https://www.proofpoint.com/us/blog/threat-insight/ta577s-unusual-attack-chain-leads-ntlm-data-theft>

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
