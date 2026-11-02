# LDAP Enumeration

> surface: `net` · CWE: CWE-200 · OWASP: —
> maturity: **researching** — 9 items, 5 supported, 2 FP rules, 1 chains

LDAP returns directory structure to a client, so filter syntax that reaches the query shape turns enumeration into extraction.

**Aliases:** ldap enumeration, ldap search, directory tree walk, anonymous ldap, ldap tree

## Prerequisite

- **Directory enumeration is only possible where a bind is accepted without integrity protection, because a domain controller configured to enforce LDAP signing rejects SASL binds that do not request signing and rejects simple binds over unencrypted connections, which removes the read primitive before any enumeration question arises.**  
  `high_confidence` · score 0.8815 · disproved by: If the domain controller refuses unsigned and simple binds (LDAP signing set to Require signing, channel binding in use), an enumeration primitive never gets a response body and no chain that depends on a directory read can start; a TLS-only anonymous read that still returns data would disprove that specific claim, not the requirement.
  sources: <https://attack.mitre.org/techniques/T1087/002/> · <https://www.rfc-editor.org/rfc/rfc4511.html> · <https://www.nccgroup.com/research/defending-your-directory-an-expert-guide-to-fortifying-active-directory-against-ldap-injection-threats/>

## Technique

- **LDAP returns directory entries selected by a client-supplied filter, so a permissive base scope lets a client walk the tree and receive attributes without any per-object authorization decision being visible in the protocol.**  
  `high_confidence` · score 0.889 · disproved by: If an (objectClass=*) subtree query from an unprivileged bind returns no entries, or the server rejects it with an insufficient-access error, then the directory structure is not enumerable through that path.
  sources: <https://attack.mitre.org/techniques/T1087/002/> · <https://www.rfc-editor.org/rfc/rfc4511.html>
- **LDAP enumeration with anonymous bind exposes the directory tree, revealing group membership and the service accounts worth targeting.**  
  `high_confidence` · score 0.818 · disproved by: Refuted when anonymous bind is disabled and no credential allows a bind, in which case the directory reveals nothing without prior authentication.
  sources: <https://attack.mitre.org/techniques/T1087/002/> · <https://www.rfc-editor.org/rfc/rfc4511.html> · <https://raw.githubusercontent.com/ajcriado/htb-writeups/main/Academy/CPTS/Content%20Summary/13.%20Active%20Directory%20Enumeration%20%26%20Attacks.md>
- **When you enable LDAP signing, both the client and server cryptographically sign their communications.**  
  `under_review` · score 0.7995 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "When you enable LDAP signing, both the client and server cryptographically sign their comm".
  sources: <https://www.nccgroup.com/research/defending-your-directory-an-expert-guide-to-fortifying-active-directory-against-ldap-injection-threats/> · <https://specterops.io/blog/2025/04/08/the-renaissance-of-ntlm-relay-attacks-everything-you-need-to-know/>
- **This binding ensures that even if an attacker intercepts the encrypted session, they can't hijack or downgrade the connection.**  
  `under_review` · score 0.7995 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "This binding ensures that even if an attacker intercepts the encrypted session, they can't".
  sources: <https://www.nccgroup.com/research/defending-your-directory-an-expert-guide-to-fortifying-active-directory-against-ldap-injection-threats/> · <https://specterops.io/blog/2025/04/08/the-renaissance-of-ntlm-relay-attacks-everything-you-need-to-know/>
- **This binding ensures that even if an attacker intercepts the encrypted session, they can't hijack or downgrade the connection.**  
  `under_review` · score 0.7995 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "This binding ensures that even if an attacker intercepts the encrypted session, they can't".
  sources: <https://www.nccgroup.com/research/defending-your-directory-an-expert-guide-to-fortifying-active-directory-against-ldap-injection-threats/> · <https://specterops.io/blog/2025/04/08/the-renaissance-of-ntlm-relay-attacks-everything-you-need-to-know/>
- **When you enable LDAP signing, both the client and server cryptographically sign their communications.**  
  `under_review` · score 0.7995 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "When you enable LDAP signing, both the client and server cryptographically sign their comm".
  sources: <https://www.nccgroup.com/research/defending-your-directory-an-expert-guide-to-fortifying-active-directory-against-ldap-injection-threats/> · <https://specterops.io/blog/2025/04/08/the-renaissance-of-ntlm-relay-attacks-everything-you-need-to-know/>

## Fp Rule

- **A successful anonymous LDAP query is not expected behaviour; discard the enumeration finding when the bind only succeeded with supplied credentials.**  
  `high_confidence` · score 0.844 · disproved by: Would be wrong in a forest that permits anonymous binds by policy, where the same query without credentials is the anomaly.
  sources: <https://www.thehacker.recipes/ad/recon/ldap> · <https://specterops.io/blog/2025/04/08/the-renaissance-of-ntlm-relay-attacks-everything-you-need-to-know/>
- **A high volume of LDAP queries on a domain controller is a capacity signal, not enumeration evidence, unless the filters are unusual.**  
  `high_confidence` · score 0.8355 · disproved by: Would be wrong for a small forest where any 1644 event is anomalous, since the baseline volume would not make the spike benign.
  sources: <https://www.nccgroup.com/research/defending-your-directory-an-expert-guide-to-fortifying-active-directory-against-ldap-injection-threats/> · <https://www.thehacker.recipes/ad/recon/ldap>

## Known gaps

Not yet satisfied: `items`
