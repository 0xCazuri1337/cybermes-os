---
name: pass_the_hash-hunting
description: Use when hunting Pass-the-Hash and Ticket Replay in a ad target. Ordered prerequisites, signals, techniques, validation bar and false-positive rules.
---

# Pass-the-Hash and Ticket Replay — hunting skill

<!-- GENERATED from db/wks.db by wks/skillgen.py. DO NOT HAND-EDIT.
     Edit the rows (or ingest better research) and re-run:
     python -m wks.skillgen -->

> surface `ad` · CWE CWE-294 · OWASP —
> evidence: 7 items, 5 supported, 3 FP rules, 0 chains
> maturity: **researching** — missing: items, chain

A protocol that authenticates the NTLM hash or a service ticket rather than a secret the user holds lets that artefact be replayed verbatim as a credential.

**Also called:** pass the hash, pass-the-hash, pth, pass the ticket, ticket replay, overpass the hash


## Techniques (what to change)

- NTLM and Kerberos protocols accept a key as the credential rather than a secret the user holds, so a captured NTLM hash or service ticket is itself a replayable authentication artifact and needs no password recovery. _(unverified)_
  - **Disproof:** If the hash or ticket is rejected by the target because channel binding, signing, or an authentication level requirement is enforced, then replay does not authenticate and the finding collapses to a failed logon.
  - Sources: <https://attack.mitre.org/techniques/T1550/003/> · <https://cwe.mitre.org/data/definitions/294.html>

## Validation bar (how to prove it)

- A pass-the-hash finding requires a successful authentication made with the obtained hash, and recovering the hash alone - by replication or by capture - is not pass-the-hash.
  - **Disproof:** If every attempt to authenticate with the recovered NT hash against any target service fails and the target logs no NTLM authentication for that account from the operator's host, then no hash was used and the pass-the-hash claim is false even though credential recovery is real.
  - Sources: <https://academy.hackthebox.com/course/preview/active-directory-powerview> · <https://securelist.com/tr/nighteagle-apt-ghostcontainer-and-tunneling/121323/>

## False-positive rules (when to reject it)

- A pass-the-hash attempt that returns access denied for a non-RID-500 local account is the protection WORKING, not a partial authentication bypass; do not file it as a finding unless LocalAccountTokenFilterPolicy is set to 0x1 or the hash authenticates as a RID-500 account, because token creation strips privileges from non-default administrator accounts by design.
  - **Disproof:** The same non-RID-500 hash authenticates successfully against the target, which happens when LocalAccountTokenFilterPolicy is set to 0x1 on that host and means the protection that should have stripped the privileges is disabled.
  - Sources: <https://redcanary.com/threat-detection-report/techniques/os-credential-dumping/> · <https://www.ired.team/offensive-security/privilege-escalation/pass-the-hash-privilege-escalation-with-invoke-wmiexec.md>
- Recovering an NT hash from NTDS.dit or LSA secrets is credential access, not pass-the-hash; reuse on another host must be demonstrated.
  - **Disproof:** Would be wrong where the extracted hash set is domain-wide and immediately usable against every service, making the dump alone equivalent to full access.
  - Sources: <https://www.thehacker.recipes/ad/movement/credentials/dumping/ntds> · <https://www.rapid7.com/blog/post/pentales-exploiting-an-internal-network-loud-and-proud/>
- An NTLM type 3 network logon with no preceding interactive logon is normal for a service account and is not pass-the-hash evidence.
  - **Disproof:** Would be wrong in a domain that forbids all NTLM, where any type 3 NTLM logon is anomalous regardless of account type.
  - Sources: <https://www.nccgroup.com/research/defending-your-directory-an-expert-guide-to-mitigating-pass-the-hash-attacks-in-active-directory/> · <https://blog.marcfredericgomez.com/active-directory-the-2026-revision-of-the-cisa-guide/>

## Chaining opportunities

- Credential-dumping on one host produces NT hashes that are directly reusable as NTLM credentials against every NTLM-accepting service in the reachable network, so the next link in the chain needs no password and no ticket issuance to gain an authenticated channel. _(unverified)_
  - **Disproof:** If the second host refuses NTLM outright (smarthosting, or channel binding with signing enforced), or if the dumped value is a Kerberos ticket rather than an NT hash and the target is domain-joined with Kerberos enforced, the handoff does not produce an authenticated channel and the chain stops at the first host.
  - Sources: <https://learn.microsoft.com/en-us/windows-server/storage/file-server/smb-signing> · <https://www.microsoft.com/en-us/security/blog/2022/10/26/how-to-prevent-lateral-movement-attacks-using-microsoft-365-defender/>
- The NT hash of a machine account is a first-class reusable credential, so a compromised workstation yields lateral movement to whatever the machine account is a member of without ever recovering a user password.
  - **Disproof:** Refuted if machine accounts are not members of any privileged group and network logons are enforced to reject their hashes, or if the host was not compromised to the point where its hash was readable.
  - Sources: <https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/pass-the-hash-with-machine-accounts.md> · <https://www.zscaler.com/blogs/product-insights/active-directory-kerberoasting-deception-detection>

---
Full class document: `skills/Network + AD/pass_the_hash/EVIDENCE.md` · retrieve more with `python -m wks.cli search "<query>" --class-id pass_the_hash`
