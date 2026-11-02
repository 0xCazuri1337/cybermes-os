# LDAP Enumeration

> surface: `net` · CWE: CWE-200 · OWASP: —
> maturity: **researching** — 4 items, 3 supported, 2 FP rules, 0 chains

LDAP returns directory structure to a client, so filter syntax that reaches the query shape turns enumeration into extraction.

**Aliases:** ldap enumeration, ldap search, directory tree walk, anonymous ldap, ldap tree

## Prerequisite

- **Directory enumeration is only possible where a bind is accepted without integrity protection, because a domain controller configured to enforce LDAP signing rejects SASL binds that do not request signing and rejects simple binds over unencrypted connections, which removes the read primitive before any enumeration question arises.**  
  `under_review` · score 0.8355 · disproved by: If the domain controller refuses unsigned and simple binds (LDAP signing set to Require signing, channel binding in use), an enumeration primitive never gets a response body and no chain that depends on a directory read can start; a TLS-only anonymous read that still returns data would disprove that specific claim, not the requirement.
  sources: <https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/ldap-signing> · <https://www.microsoft.com/en-us/security/blog/2022/05/25/detecting-and-preventing-privilege-escalation-attacks-leveraging-kerberos-relaying-krbrelayup/>

## Technique

- **LDAP returns directory entries selected by a client-supplied filter, so a permissive base scope lets a client walk the tree and receive attributes without any per-object authorization decision being visible in the protocol.**  
  `high_confidence` · score 0.889 · disproved by: If an (objectClass=*) subtree query from an unprivileged bind returns no entries, or the server rejects it with an insufficient-access error, then the directory structure is not enumerable through that path.
  sources: <https://attack.mitre.org/techniques/T1087/002/> · <https://www.rfc-editor.org/rfc/rfc4511.html>

## Fp Rule

- **A successful anonymous LDAP query is not expected behaviour; discard the enumeration finding when the bind only succeeded with supplied credentials.**  
  `high_confidence` · score 0.844 · disproved by: Would be wrong in a forest that permits anonymous binds by policy, where the same query without credentials is the anomaly.
  sources: <https://www.thehacker.recipes/ad/recon/ldap> · <https://specterops.io/blog/2025/04/08/the-renaissance-of-ntlm-relay-attacks-everything-you-need-to-know/>
- **A high volume of LDAP queries on a domain controller is a capacity signal, not enumeration evidence, unless the filters are unusual.**  
  `high_confidence` · score 0.8355 · disproved by: Would be wrong for a small forest where any 1644 event is anomalous, since the baseline volume would not make the spike benign.
  sources: <https://www.nccgroup.com/research/defending-your-directory-an-expert-guide-to-fortifying-active-directory-against-ldap-injection-threats/> · <https://www.thehacker.recipes/ad/recon/ldap>

## Known gaps

Not yet satisfied: `items`, `supported_items`, `chain`
