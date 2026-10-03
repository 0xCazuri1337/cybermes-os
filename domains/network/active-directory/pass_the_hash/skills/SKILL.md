---
name: pass_the_hash-hunting
description: Use when hunting Pass-the-Hash and Ticket Replay in a ad target. Ordered prerequisites, signals, techniques, validation bar and false-positive rules.
---

# Pass-the-Hash and Ticket Replay — hunting skill

<!-- GENERATED from db/wks.db by wks/skillgen.py. DO NOT HAND-EDIT.
     Edit the rows (or ingest better research) and re-run:
     python -m wks.skillgen -->

> surface `ad` · CWE CWE-294 · OWASP —
> evidence: 28 items, 8 supported, 3 FP rules, 1 chains
> maturity: **mature**

A protocol that authenticates the NTLM hash or a service ticket rather than a secret the user holds lets that artefact be replayed verbatim as a credential.

**Also called:** pass the hash, pass-the-hash, pth, pass the ticket, ticket replay, overpass the hash


## Techniques (what to change)

- For all exercises, we will assume that the target company Inlanefreight has hired us to perform an in-depth penetration test with a heavy focus on AD security, where stealth and bypassing stringent security controls are not a requirement. _(unverified)_
  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "For all exercises, we will assume that the target company Inlanefreight has hired us to pe".
  - Sources: <https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/pass-the-hash-with-machine-accounts.md>
- Second point: MFA is largely ineffective against this technique once initial access has been obtained, because authentication can be made directly to a Domain Controller over NTLM (14), which does not support it. _(unverified)_
  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Second point: MFA is largely ineffective against this technique once initial access has be".
  - Sources: <https://redcanary.com/threat-detection-report/techniques/os-credential-dumping/> · <https://blog.marcfredericgomez.com/active-directory-the-2026-revision-of-the-cisa-guide/>
- The hashes obtained are either cracked or replayed directly in a Pass-the-Hash, since NTLM accepts the hash as a valid authentication token. _(unverified)_
  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "The hashes obtained are either cracked or replayed directly in a Pass-the-Hash, since NTLM".
  - Sources: <https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/pass-the-hash-with-machine-accounts.md>
- The variant applies to user objects configured not to require Kerberos pre-authentication. _(unverified)_
  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "The variant applies to user objects configured not to require Kerberos pre-authentication.".
  - Sources: <https://www.microsoft.com/en-us/security/blog/2022/10/26/how-to-prevent-lateral-movement-attacks-using-microsoft-365-defender/> · <https://blog.marcfredericgomez.com/active-directory-the-2026-revision-of-the-cisa-guide/>
- The KRBTGT object being the root of trust for the domain, its compromise requires a coordinated reset of every user and computer object password, and may lead to rebuilding the domain. _(unverified)_
  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "The KRBTGT object being the root of trust for the domain, its compromise requires a coordi".
  - Sources: <https://securelist.com/tr/nighteagle-apt-ghostcontainer-and-tunneling/121323/> · <https://blog.marcfredericgomez.com/active-directory-the-2026-revision-of-the-cisa-guide/>
- The only approach proposed is to place a canary GPP password belonging to a user object that should never be used, and to monitor any authentication by that object. _(unverified)_
  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "The only approach proposed is to place a canary GPP password belonging to a user object th".
  - Sources: <https://www.nccgroup.com/research/defending-your-directory-an-expert-guide-to-mitigating-pass-the-hash-attacks-in-active-directory/> · <https://blog.marcfredericgomez.com/active-directory-the-2026-revision-of-the-cisa-guide/>
- There is a single mitigating control: require Kerberos pre-authentication on all user objects. _(unverified)_
  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "There is a single mitigating control: require Kerberos pre-authentication on all user obje".
  - Sources: <https://academy.hackthebox.com/course/preview/active-directory-powerview> · <https://blog.marcfredericgomez.com/active-directory-the-2026-revision-of-the-cisa-guide/>
- If the relying party, Microsoft Entra ID for instance, trusts the identity provider’s MFA claims, the forged response bypasses MFA and survives a password change on the impersonated object. _(unverified)_
  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "If the relying party, Microsoft Entra ID for instance, trusts the identity provider’s MFA ".
  - Sources: <https://securelist.com/tr/nighteagle-apt-ghostcontainer-and-tunneling/121323/> · <https://blog.marcfredericgomez.com/active-directory-the-2026-revision-of-the-cisa-guide/>
- Twelve other vulnerable configurations, ESC2 through ESC13, exist and are not detailed in the guidance, which refers readers to work by SpecterOps, Mandiant and Microsoft. _(unverified)_
  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Twelve other vulnerable configurations, ESC2 through ESC13, exist and are not detailed in ".
  - Sources: <https://blog.marcfredericgomez.com/active-directory-the-2026-revision-of-the-cisa-guide/>
- The Sync object holds the Directory Synchronisation Accounts role, which lets it create, modify and delete user objects and set passwords. _(unverified)_
  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "The Sync object holds the Directory Synchronisation Accounts role, which lets it create, m".
  - Sources: <https://blog.marcfredericgomez.com/active-directory-the-2026-revision-of-the-cisa-guide/> · <https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/pass-the-hash-with-machine-accounts.md>
- For all exercises, we will assume that the target company Inlanefreight has hired us to perform an in-depth penetration test with a heavy focus on AD security, where stealth and bypassing stringent security controls are not a requirement. _(unverified)_
  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "For all exercises, we will assume that the target company Inlanefreight has hired us to pe".
  - Sources: <https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/pass-the-hash-with-machine-accounts.md>
- The configuration known as ESC1 combines four conditions: enrolment rights open to user objects, an extended key usage, EKU (21), that enables client authentication, the ability for the requester to supply their own subject alternative name, SAN (22), and the absence of certificate manager approval. _(unverified)_
  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "The configuration known as ESC1 combines four conditions: enrolment rights open to user ob".
  - Sources: <https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/> · <https://blog.marcfredericgomez.com/active-directory-the-2026-revision-of-the-cisa-guide/>
- The badPasswordTime attribute complements these events: if several user objects share the same date and time of last failure, or very close values, spraying is likely. _(unverified)_
  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "The badPasswordTime attribute complements these events: if several user objects share the ".
  - Sources: <https://blog.marcfredericgomez.com/active-directory-the-2026-revision-of-the-cisa-guide/> · <https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/pass-the-hash-with-machine-accounts.md>
- The KRBTGT object’s hash allows arbitrary TGTs to be forged. _(unverified)_
  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "The KRBTGT object’s hash allows arbitrary TGTs to be forged.".
  - Sources: <https://blog.marcfredericgomez.com/active-directory-the-2026-revision-of-the-cisa-guide/>
- Event 4625 adds to it: AS-REP Roasting can be executed before any authentication, without a valid user object, which produces a logon failure while the ticket is still issued. _(unverified)_
  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Event 4625 adds to it: AS-REP Roasting can be executed before any authentication, without ".
  - Sources: <https://academy.hackthebox.com/course/preview/active-directory-powerview> · <https://blog.marcfredericgomez.com/active-directory-the-2026-revision-of-the-cisa-guide/>
- The msDS-KeyCredentialLink attribute, introduced with the Windows Server 2016 Domain Functional Level to support passwordless authentication including Windows Hello for Business, accepts key credentials. _(unverified)_
  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "The msDS-KeyCredentialLink attribute, introduced with the Windows Server 2016 Domain Funct".
  - Sources: <https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/> · <https://blog.marcfredericgomez.com/active-directory-the-2026-revision-of-the-cisa-guide/>
- The first yields the hashes of the whole directory, the second allows the password of an object holding the Global Administrator role to be set, and therefore full control of the cloud estate. _(unverified)_
  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "The first yields the hashes of the whole directory, the second allows the password of an o".
  - Sources: <https://www.thehacker.recipes/ad/movement/credentials/dumping/ntds> · <https://blog.marcfredericgomez.com/active-directory-the-2026-revision-of-the-cisa-guide/>
- On mitigation, the AD FS service account must be a gMSA, which gives it a 120-character password rotated every thirty days and puts it out of reach of both Kerberoasting and cracking, and it must serve no other purpose. _(unverified)_
  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "On mitigation, the AD FS service account must be a gMSA, which gives it a 120-character pa".
  - Sources: <https://www.nccgroup.com/research/defending-your-directory-an-expert-guide-to-mitigating-pass-the-hash-attacks-in-active-directory/> · <https://blog.marcfredericgomez.com/active-directory-the-2026-revision-of-the-cisa-guide/>
- Administrative access to a Microsoft Entra Connect server allows the cleartext passwords of both objects to be extracted, notably with AADInternals. _(unverified)_
  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Administrative access to a Microsoft Entra Connect server allows the cleartext passwords o".
  - Sources: <https://blog.marcfredericgomez.com/active-directory-the-2026-revision-of-the-cisa-guide/>
- Pass-the-hash authenticates with a recovered NTLM hash directly as the password, so no plaintext is needed to open a session.
  - **Disproof:** Refuted when the account is disabled, expired, or restricted so that NTLM authentication is refused, which stops the hash from being usable as a credential.
  - Sources: <https://attack.mitre.org/techniques/T1550/002/> · <https://cwe.mitre.org/data/definitions/294.html> · <https://raw.githubusercontent.com/ajcriado/htb-writeups/main/Academy/CPTS/Content%20Summary/13.%20Active%20Directory%20Enumeration%20%26%20Attacks.md>
- NTLM and Kerberos protocols accept a key as the credential rather than a secret the user holds, so a captured NTLM hash or service ticket is itself a replayable authentication artifact and needs no password recovery.
  - **Disproof:** If the hash or ticket is rejected by the target because channel binding, signing, or an authentication level requirement is enforced, then replay does not authenticate and the finding collapses to a failed logon.
  - Sources: <https://attack.mitre.org/techniques/T1550/003/> · <https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/> · <https://www.nccgroup.com/research/defending-your-directory-an-expert-guide-to-mitigating-pass-the-hash-attacks-in-active-directory/>

## Validation bar (how to prove it)

- A pass-the-hash finding requires a successful authentication made with the obtained hash, and recovering the hash alone - by replication or by capture - is not pass-the-hash.
  - **Disproof:** If every attempt to authenticate with the recovered NT hash against any target service fails and the target logs no NTLM authentication for that account from the operator's host, then no hash was used and the pass-the-hash claim is false even though credential recovery is real.
  - Sources: <https://securelist.com/tr/nighteagle-apt-ghostcontainer-and-tunneling/121323/> · <https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/pass-the-hash-with-machine-accounts.md>

## False-positive rules (when to reject it)

- A pass-the-hash attempt that returns access denied for a non-RID-500 local account is the protection WORKING, not a partial authentication bypass; do not file it as a finding unless LocalAccountTokenFilterPolicy is set to 0x1 or the hash authenticates as a RID-500 account, because token creation strips privileges from non-default administrator accounts by design.
  - **Disproof:** The same non-RID-500 hash authenticates successfully against the target, which happens when LocalAccountTokenFilterPolicy is set to 0x1 on that host and means the protection that should have stripped the privileges is disabled.
  - Sources: <https://redcanary.com/threat-detection-report/techniques/os-credential-dumping/> · <https://www.ired.team/offensive-security/privilege-escalation/pass-the-hash-privilege-escalation-with-invoke-wmiexec.md>
- Recovering an NT hash from NTDS.dit or LSA secrets is credential access, not pass-the-hash; reuse on another host must be demonstrated.
  - **Disproof:** Would be wrong where the extracted hash set is domain-wide and immediately usable against every service, making the dump alone equivalent to full access.
  - Sources: <https://www.thehacker.recipes/ad/movement/credentials/dumping/ntds> · <https://www.rapid7.com/blog/post/pentales-exploiting-an-internal-network-loud-and-proud/>
- An NTLM type 3 network logon with no preceding interactive logon is normal for a service account and is not pass-the-hash evidence.
  - **Disproof:** Would be wrong in a domain that forbids all NTLM, where any type 3 NTLM logon is anomalous regardless of account type.
  - Sources: <https://www.nccgroup.com/research/defending-your-directory-an-expert-guide-to-mitigating-pass-the-hash-attacks-in-active-directory/> · <https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/pass-the-hash-with-machine-accounts.md>

## Evidence requirements

- A convincing observation for this class is: The observable that triggers this false positive is a pass-the-hash attempt returning access denied for a local account that is not RID 500, written up as a partial authentication bypass or a weakened hash policy.
  - **Disproof:** Not evidence when the observable cannot be produced at all -- blind, server-side-only, or identical-in-every-case behaviour leaves nothing to show. The originating rule (pass_the_hash.fp_rule.rid_not_500_hash_denied_is_correct_protection) states the full boundary.
  - Sources: <https://redcanary.com/threat-detection-report/techniques/os-credential-dumping/> · <https://www.ired.team/offensive-security/privilege-escalation/pass-the-hash-privilege-escalation-with-invoke-wmiexec.md>

## Chaining opportunities

- Credential-dumping on one host produces NT hashes that are directly reusable as NTLM credentials against every NTLM-accepting service in the reachable network, so the next link in the chain needs no password and no ticket issuance to gain an authenticated channel.
  - **Disproof:** If the second host refuses NTLM outright (smarthosting, or channel binding with signing enforced), or if the dumped value is a Kerberos ticket rather than an NT hash and the target is domain-joined with Kerberos enforced, the handoff does not produce an authenticated channel and the chain stops at the first host.
  - Sources: <https://attack.mitre.org/techniques/T1550/002/> · <https://learn.microsoft.com/en-us/windows-server/storage/file-server/smb-signing> · <https://www.microsoft.com/en-us/security/blog/2022/10/26/how-to-prevent-lateral-movement-attacks-using-microsoft-365-defender/>
- The NT hash of a machine account is a first-class reusable credential, so a compromised workstation yields lateral movement to whatever the machine account is a member of without ever recovering a user password. _(unverified)_
  - **Disproof:** Refuted if machine accounts are not members of any privileged group and network logons are enforced to reject their hashes, or if the host was not compromised to the point where its hash was readable.
  - Sources: <https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/pass-the-hash-with-machine-accounts.md> · <https://www.zscaler.com/blogs/product-insights/active-directory-kerberoasting-deception-detection>

---
Full class document: `domains/network/active-directory/pass_the_hash/knowledge/DIGEST.md` · retrieve more with `python -m wks.cli search "<query>" --class-id pass_the_hash`
