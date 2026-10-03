# LDAP Enumeration

> surface: `net` · CWE: CWE-200 · OWASP: —
> maturity: **mature** — 16 items, 16 supported, 2 FP rules, 1 chains

LDAP returns directory structure to a client, so filter syntax that reaches the query shape turns enumeration into extraction.

**Aliases:** ldap enumeration, ldap search, directory tree walk, anonymous ldap, ldap tree

## Prerequisite

- **Directory enumeration is only possible where a bind is accepted without integrity protection, because a domain controller configured to enforce LDAP signing rejects SASL binds that do not request signing and rejects simple binds over unencrypted connections, which removes the read primitive before any enumeration question arises.**  
  `high_confidence` · score 0.8815 · disproved by: If the domain controller refuses unsigned and simple binds (LDAP signing set to Require signing, channel binding in use), an enumeration primitive never gets a response body and no chain that depends on a directory read can start; a TLS-only anonymous read that still returns data would disprove that specific claim, not the requirement.
  sources: <https://www.rfc-editor.org/rfc/rfc4511.html> · <https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/ldap-signing> · <https://www.microsoft.com/en-us/security/blog/2022/05/25/detecting-and-preventing-privilege-escalation-attacks-leveraging-kerberos-relaying-krbrelayup/>

## Technique

- **LDAP returns directory entries selected by a client-supplied filter, so a permissive base scope lets a client walk the tree and receive attributes without any per-object authorization decision being visible in the protocol.**  
  `high_confidence` · score 0.889 · disproved by: If an (objectClass=*) subtree query from an unprivileged bind returns no entries, or the server rejects it with an insufficient-access error, then the directory structure is not enumerable through that path.
  sources: <https://attack.mitre.org/techniques/T1087/002/> · <https://www.rfc-editor.org/rfc/rfc4511.html>
- **Man-in-the-middle attacks : An attacker captures packets between client and server, modifies them, and forwards altered requests to the domain controller.**  
  `high_confidence` · score 0.827 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Man-in-the-middle attacks : An attacker captures packets between client and server, modifi".
  sources: <https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/ldap-signing> · <https://www.nccgroup.com/research/defending-your-directory-an-expert-guide-to-fortifying-active-directory-against-ldap-injection-threats/>
- **Man-in-the-middle attacks : An attacker captures packets between client and server, modifies them, and forwards altered requests to the domain controller.**  
  `high_confidence` · score 0.827 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Man-in-the-middle attacks : An attacker captures packets between client and server, modifi".
  sources: <https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/ldap-signing> · <https://www.nccgroup.com/research/defending-your-directory-an-expert-guide-to-fortifying-active-directory-against-ldap-injection-threats/>
- **When you enable LDAP signing, both the client and server cryptographically sign their communications.**  
  `high_confidence` · score 0.7995 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "When you enable LDAP signing, both the client and server cryptographically sign their comm".
  sources: <https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/ldap-signing> · <https://www.nccgroup.com/research/defending-your-directory-an-expert-guide-to-fortifying-active-directory-against-ldap-injection-threats/>
- **This binding ensures that even if an attacker intercepts the encrypted session, they can't hijack or downgrade the connection.**  
  `high_confidence` · score 0.7995 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "This binding ensures that even if an attacker intercepts the encrypted session, they can't".
  sources: <https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/ldap-signing> · <https://www.nccgroup.com/research/defending-your-directory-an-expert-guide-to-fortifying-active-directory-against-ldap-injection-threats/>
- **An attacker can potentially crack a captured NTLM exchange, whether it’s NTLMv1 or NTLMv2, to recover the password if it is not sufficiently strong .**  
  `high_confidence` · score 0.7995 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "An attacker can potentially crack a captured NTLM exchange, whether it’s NTLMv1 or NTLMv2,".
  sources: <https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/ldap-signing> · <https://specterops.io/blog/2025/04/08/the-renaissance-of-ntlm-relay-attacks-everything-you-need-to-know/>
- **If it is a computer/service account, the attacker can forge an RC4-encrypted Kerberos silver ticket and impersonate a privileged account to the host or the service.**  
  `high_confidence` · score 0.7995 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "If it is a computer/service account, the attacker can forge an RC4-encrypted Kerberos silv".
  sources: <https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/ldap-signing> · <https://specterops.io/blog/2025/04/08/the-renaissance-of-ntlm-relay-attacks-everything-you-need-to-know/>
- **This binding ensures that even if an attacker intercepts the encrypted session, they can't hijack or downgrade the connection.**  
  `high_confidence` · score 0.7995 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "This binding ensures that even if an attacker intercepts the encrypted session, they can't".
  sources: <https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/ldap-signing> · <https://www.nccgroup.com/research/defending-your-directory-an-expert-guide-to-fortifying-active-directory-against-ldap-injection-threats/>
- **When you enable LDAP signing, both the client and server cryptographically sign their communications.**  
  `high_confidence` · score 0.7995 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "When you enable LDAP signing, both the client and server cryptographically sign their comm".
  sources: <https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/ldap-signing> · <https://www.nccgroup.com/research/defending-your-directory-an-expert-guide-to-fortifying-active-directory-against-ldap-injection-threats/>
- **Additional settings allow restricting or auditing outgoing or incoming NTLM authentication or requiring session security settings, but we won’t elaborate on those.**  
  `high_confidence` · score 0.7995 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Additional settings allow restricting or auditing outgoing or incoming NTLM authentication".
  sources: <https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/ldap-signing> · <https://specterops.io/blog/2025/04/08/the-renaissance-of-ntlm-relay-attacks-everything-you-need-to-know/>
- **The most common way to abuse it is to pass to the icon handler a reference to an attacker-controlled path, which would result in a user authentication attempt as soon as the user browses the folder in which the file is located, even if the user doesn’t even click or highlight the file.**  
  `high_confidence` · score 0.772 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "The most common way to abuse it is to pass to the icon handler a reference to an attacker-".
  sources: <https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/ldap-signing> · <https://specterops.io/blog/2025/04/08/the-renaissance-of-ntlm-relay-attacks-everything-you-need-to-know/>
- **Then, when the remote service attempts to access the specified path, we’d require authentication and kick off a relay attack.**  
  `high_confidence` · score 0.772 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Then, when the remote service attempts to access the specified path, we’d require authenti".
  sources: <https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/ldap-signing> · <https://specterops.io/blog/2025/04/08/the-renaissance-of-ntlm-relay-attacks-everything-you-need-to-know/>
- **These techniques result in an immediate authentication attempt from the victim computer account without user interaction.**  
  `high_confidence` · score 0.772 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "These techniques result in an immediate authentication attempt from the victim computer ac".
  sources: <https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/ldap-signing> · <https://specterops.io/blog/2025/04/08/the-renaissance-of-ntlm-relay-attacks-everything-you-need-to-know/>

## Fp Rule

- **A successful anonymous LDAP query is not expected behaviour; discard the enumeration finding when the bind only succeeded with supplied credentials.**  
  `high_confidence` · score 0.844 · disproved by: Would be wrong in a forest that permits anonymous binds by policy, where the same query without credentials is the anomaly.
  sources: <https://www.thehacker.recipes/ad/recon/ldap> · <https://specterops.io/blog/2025/04/08/the-renaissance-of-ntlm-relay-attacks-everything-you-need-to-know/>
- **A high volume of LDAP queries on a domain controller is a capacity signal, not enumeration evidence, unless the filters are unusual.**  
  `high_confidence` · score 0.8355 · disproved by: Would be wrong for a small forest where any 1644 event is anomalous, since the baseline volume would not make the spike benign.
  sources: <https://www.nccgroup.com/research/defending-your-directory-an-expert-guide-to-fortifying-active-directory-against-ldap-injection-threats/> · <https://www.thehacker.recipes/ad/recon/ldap>
