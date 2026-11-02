---
name: ldap_enum-hunting
description: Use when hunting LDAP Enumeration in a net target. Ordered prerequisites, signals, techniques, validation bar and false-positive rules.
---

# LDAP Enumeration — hunting skill

<!-- GENERATED from db/wks.db by wks/skillgen.py. DO NOT HAND-EDIT.
     Edit the rows (or ingest better research) and re-run:
     python -m wks.skillgen -->

> surface `net` · CWE CWE-200 · OWASP —
> evidence: 4 items, 3 supported, 2 FP rules, 0 chains
> maturity: **researching** — missing: items, supported_items, chain

LDAP returns directory structure to a client, so filter syntax that reaches the query shape turns enumeration into extraction.

**Also called:** ldap enumeration, ldap search, directory tree walk, anonymous ldap, ldap tree


## Prerequisites (do not start without these)

- Directory enumeration is only possible where a bind is accepted without integrity protection, because a domain controller configured to enforce LDAP signing rejects SASL binds that do not request signing and rejects simple binds over unencrypted connections, which removes the read primitive before any enumeration question arises. _(unverified)_
  - **Disproof:** If the domain controller refuses unsigned and simple binds (LDAP signing set to Require signing, channel binding in use), an enumeration primitive never gets a response body and no chain that depends on a directory read can start; a TLS-only anonymous read that still returns data would disprove that specific claim, not the requirement.
  - Sources: <https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/ldap-signing> · <https://www.microsoft.com/en-us/security/blog/2022/05/25/detecting-and-preventing-privilege-escalation-attacks-leveraging-kerberos-relaying-krbrelayup/>

## Techniques (what to change)

- LDAP returns directory entries selected by a client-supplied filter, so a permissive base scope lets a client walk the tree and receive attributes without any per-object authorization decision being visible in the protocol.
  - **Disproof:** If an (objectClass=*) subtree query from an unprivileged bind returns no entries, or the server rejects it with an insufficient-access error, then the directory structure is not enumerable through that path.
  - Sources: <https://attack.mitre.org/techniques/T1087/002/> · <https://www.rfc-editor.org/rfc/rfc4511.html>

## False-positive rules (when to reject it)

- A successful anonymous LDAP query is not expected behaviour; discard the enumeration finding when the bind only succeeded with supplied credentials.
  - **Disproof:** Would be wrong in a forest that permits anonymous binds by policy, where the same query without credentials is the anomaly.
  - Sources: <https://www.thehacker.recipes/ad/recon/ldap> · <https://specterops.io/blog/2025/04/08/the-renaissance-of-ntlm-relay-attacks-everything-you-need-to-know/>
- A high volume of LDAP queries on a domain controller is a capacity signal, not enumeration evidence, unless the filters are unusual.
  - **Disproof:** Would be wrong for a small forest where any 1644 event is anomalous, since the baseline volume would not make the spike benign.
  - Sources: <https://www.nccgroup.com/research/defending-your-directory-an-expert-guide-to-fortifying-active-directory-against-ldap-injection-threats/> · <https://www.thehacker.recipes/ad/recon/ldap>

---
Full class document: `skills/Network + AD/ldap_enum/EVIDENCE.md` · retrieve more with `python -m wks.cli search "<query>" --class-id ldap_enum`
