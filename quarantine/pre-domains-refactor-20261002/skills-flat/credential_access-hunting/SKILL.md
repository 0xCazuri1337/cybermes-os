---
name: credential_access-hunting
description: Use when hunting Windows Credential Access in a ad target. Ordered prerequisites, signals, techniques, validation bar and false-positive rules.
---

# Windows Credential Access — hunting skill

<!-- GENERATED from db/wks.db by wks/skillgen.py. DO NOT HAND-EDIT.
     Edit the rows (or ingest better research) and re-run:
     python -m wks.skillgen -->

> surface `ad` · CWE CWE-522 · OWASP —
> evidence: 5 items, 5 supported, 2 FP rules, 0 chains
> maturity: **researching** — missing: items, chain

Credential material exists in reachable files and process memory, and recovering it converts one authenticated session into many.

**Also called:** credential access, lsass, ntds.dit, sam, sam hive, credential dumping, mimikatz, dpapi, vault


## Recon signals (where to look)

- An inbound NetNTLMv2 hash arriving shortly after files were written to a network share is an early observable for coerced authentication, not proof that the hash was relayed.
  - **Disproof:** If no authentication event follows the capture that uses the captured hash as NTLM credentials against any target service, and the captured user is shown browsing the share normally, then no credential access occurred and the capture remains an unenacted collection artefact.
  - Sources: <https://academy.hackthebox.com/course/preview/active-directory-enumeration--attacks> · <https://securelist.com/tr/network-anomaly-detection-in-kata/120892/>

## Techniques (what to change)

- The directory replication request right (DCSync) lets a principal pull password hashes including KRBTGT from a domain controller without ever touching the NTDS.dit file, so a single misconfigured principal yields the whole domain's credentials.
  - **Disproof:** If no non-Domain-Admin principal holds the three replication rights, and a replication request from a standard account is denied, then no DCSync path exists and the finding is a false positive.
  - Sources: <https://attack.mitre.org/techniques/T1003/006/> · <https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/>

## False-positive rules (when to reject it)

- Hash replay against a Protected Users or sensitive-and-non-delegable account fails, so a blocked replay must not be reported as credential access.
  - **Disproof:** Would be wrong in a domain where the Protected Users group has been emptied, since the group membership check would then pass for everyone.
  - Sources: <https://googleprojectzero.blogspot.com/2022/10/> · <https://www.nccgroup.com/research/defending-your-directory-an-expert-guide-to-combating-kerberoasting-in-active-directory/>
- A secretsdump or lsadump command that returned no hashes is not a credential-access finding even when the tool exited cleanly.
  - **Disproof:** Would be wrong where a backup or a shadow copy of NTDS.dit is readable by the tester without DC access, making the file copy itself sufficient.
  - Sources: <https://www.nccgroup.com/research/defending-your-directory-an-expert-guide-to-securing-active-directory-against-dcsync-attacks/> · <https://www.thehacker.recipes/ad/movement/credentials/dumping/ntds>

## Impact framing

- Dumping one privileged credential converts a single-host compromise into an environment-wide one, because the credential store can hold a domain admin's secrets and that credential is then usable for remote administration of domain controllers.
  - **Disproof:** If the dumped credential is tier-2 and segmentation denies its path to application servers and domain controllers, the blast radius stays at the first host; likewise if privileged credential reuse requires an interactive logon that monitoring would have blocked, the domain-wide claim does not follow from the dump alone.
  - Sources: <https://www.microsoft.com/en-us/security/blog/2022/10/05/detecting-and-preventing-lsass-credential-dumping-attacks/> · <https://www.tenable.com/blog/five-cyber-agencies-sound-alarm-about-active-directory-attacks-beyond-the-basics>

---
Full class document: `skills/Network + AD/credential_access/EVIDENCE.md` · retrieve more with `python -m wks.cli search "<query>" --class-id credential_access`
