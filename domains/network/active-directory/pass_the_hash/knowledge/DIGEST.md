# Pass-the-Hash and Ticket Replay

> surface: `ad` · CWE: CWE-294 · OWASP: —
> maturity: **researching** — 13 items, 4 supported, 1 FP rules, 1 chains

A protocol that authenticates the NTLM hash or a service ticket rather than a secret the user holds lets that artefact be replayed verbatim as a credential.

**Aliases:** pass the hash, pass-the-hash, pth, pass the ticket, ticket replay, overpass the hash

## Technique

- **NTLM and Kerberos protocols accept a key as the credential rather than a secret the user holds, so a captured NTLM hash or service ticket is itself a replayable authentication artifact and needs no password recovery.**  
  `high_confidence` · score 0.9175 · disproved by: If the hash or ticket is rejected by the target because channel binding, signing, or an authentication level requirement is enforced, then replay does not authenticate and the finding collapses to a failed logon.
  sources: <https://attack.mitre.org/techniques/T1550/003/> · <https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/> · <https://www.nccgroup.com/research/defending-your-directory-an-expert-guide-to-mitigating-pass-the-hash-attacks-in-active-directory/>
- **Pass-the-hash authenticates with a recovered NTLM hash directly as the password, so no plaintext is needed to open a session.**  
  `high_confidence` · score 0.8455 · disproved by: Refuted when the account is disabled, expired, or restricted so that NTLM authentication is refused, which stops the hash from being usable as a credential.
  sources: <https://attack.mitre.org/techniques/T1550/002/> · <https://cwe.mitre.org/data/definitions/294.html> · <https://raw.githubusercontent.com/ajcriado/htb-writeups/main/Academy/CPTS/Content%20Summary/13.%20Active%20Directory%20Enumeration%20%26%20Attacks.md>
- **The KRBTGT object being the root of trust for the domain, its compromise requires a coordinated reset of every user and computer object password, and may lead to rebuilding the domain.**  
  `under_review` · score 0.8155 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "The KRBTGT object being the root of trust for the domain, its compromise requires a coordi".
  sources: <https://academy.hackthebox.com/course/preview/active-directory-powerview> · <https://securelist.com/tr/nighteagle-apt-ghostcontainer-and-tunneling/121323/> · <https://blog.marcfredericgomez.com/active-directory-the-2026-revision-of-the-cisa-guide/>
- **If the relying party, Microsoft Entra ID for instance, trusts the identity provider’s MFA claims, the forged response bypasses MFA and survives a password change on the impersonated object.**  
  `under_review` · score 0.8155 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "If the relying party, Microsoft Entra ID for instance, trusts the identity provider’s MFA ".
  sources: <https://academy.hackthebox.com/course/preview/active-directory-powerview> · <https://securelist.com/tr/nighteagle-apt-ghostcontainer-and-tunneling/121323/> · <https://blog.marcfredericgomez.com/active-directory-the-2026-revision-of-the-cisa-guide/>
- **The Sync object holds the Directory Synchronisation Accounts role, which lets it create, modify and delete user objects and set passwords.**  
  `under_review` · score 0.788 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "The Sync object holds the Directory Synchronisation Accounts role, which lets it create, m".
  sources: <https://academy.hackthebox.com/course/preview/active-directory-powerview> · <https://blog.marcfredericgomez.com/active-directory-the-2026-revision-of-the-cisa-guide/> · <https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/pass-the-hash-with-machine-accounts.md>
- **The KRBTGT object’s hash allows arbitrary TGTs to be forged.**  
  `under_review` · score 0.772 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "The KRBTGT object’s hash allows arbitrary TGTs to be forged.".
  sources: <https://academy.hackthebox.com/course/preview/active-directory-powerview> · <https://blog.marcfredericgomez.com/active-directory-the-2026-revision-of-the-cisa-guide/>

## Validation

- **A pass-the-hash finding requires a successful authentication made with the obtained hash, and recovering the hash alone - by replication or by capture - is not pass-the-hash.**  
  `under_review` · score 0.8715 · disproved by: If every attempt to authenticate with the recovered NT hash against any target service fails and the target logs no NTLM authentication for that account from the operator's host, then no hash was used and the pass-the-hash claim is false even though credential recovery is real.
  sources: <https://securelist.com/tr/nighteagle-apt-ghostcontainer-and-tunneling/121323/> · <https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/pass-the-hash-with-machine-accounts.md>

## Fp Rule

- **An NTLM type 3 network logon with no preceding interactive logon is normal for a service account and is not pass-the-hash evidence.**  
  `under_review` · score 0.8715 · disproved by: Would be wrong in a domain that forbids all NTLM, where any type 3 NTLM logon is anomalous regardless of account type.
  sources: <https://www.nccgroup.com/research/defending-your-directory-an-expert-guide-to-mitigating-pass-the-hash-attacks-in-active-directory/> · <https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/pass-the-hash-with-machine-accounts.md>
- **A pass-the-hash attempt that returns access denied for a non-RID-500 local account is the protection WORKING, not a partial authentication bypass; do not file it as a finding unless LocalAccountTokenFilterPolicy is set to 0x1 or the hash authenticates as a RID-500 account, because token creation strips privileges from non-default administrator accounts by design.**  
  `under_review` · score 0.844 · disproved by: The same non-RID-500 hash authenticates successfully against the target, which happens when LocalAccountTokenFilterPolicy is set to 0x1 on that host and means the protection that should have stripped the privileges is disabled.
  sources: <https://redcanary.com/threat-detection-report/techniques/os-credential-dumping/> · <https://www.ired.team/offensive-security/privilege-escalation/pass-the-hash-privilege-escalation-with-invoke-wmiexec.md>
- **Recovering an NT hash from NTDS.dit or LSA secrets is credential access, not pass-the-hash; reuse on another host must be demonstrated.**  
  `high_confidence` · score 0.844 · disproved by: Would be wrong where the extracted hash set is domain-wide and immediately usable against every service, making the dump alone equivalent to full access.
  sources: <https://www.thehacker.recipes/ad/movement/credentials/dumping/ntds> · <https://www.rapid7.com/blog/post/pentales-exploiting-an-internal-network-loud-and-proud/>

## Evidence

- **A convincing observation for this class is: The observable that triggers this false positive is a pass-the-hash attempt returning access denied for a local account that is not RID 500, written up as a partial authentication bypass or a weakened hash policy.**  
  `under_review` · score 0.808 · disproved by: Not evidence when the observable cannot be produced at all -- blind, server-side-only, or identical-in-every-case behaviour leaves nothing to show. The originating rule (pass_the_hash.fp_rule.rid_not_500_hash_denied_is_correct_protection) states the full boundary.
  sources: <https://redcanary.com/threat-detection-report/techniques/os-credential-dumping/> · <https://www.ired.team/offensive-security/privilege-escalation/pass-the-hash-privilege-escalation-with-invoke-wmiexec.md>

## Chain Link

- **Credential-dumping on one host produces NT hashes that are directly reusable as NTLM credentials against every NTLM-accepting service in the reachable network, so the next link in the chain needs no password and no ticket issuance to gain an authenticated channel.**  
  `high_confidence` · score 0.9175 · disproved by: If the second host refuses NTLM outright (smarthosting, or channel binding with signing enforced), or if the dumped value is a Kerberos ticket rather than an NT hash and the target is domain-joined with Kerberos enforced, the handoff does not produce an authenticated channel and the chain stops at the first host.
  sources: <https://attack.mitre.org/techniques/T1550/002/> · <https://learn.microsoft.com/en-us/windows-server/storage/file-server/smb-signing> · <https://www.microsoft.com/en-us/security/blog/2022/10/26/how-to-prevent-lateral-movement-attacks-using-microsoft-365-defender/>
- **The NT hash of a machine account is a first-class reusable credential, so a compromised workstation yields lateral movement to whatever the machine account is a member of without ever recovering a user password.**  
  `under_review` · score 0.783 · disproved by: Refuted if machine accounts are not members of any privileged group and network logons are enforced to reject their hashes, or if the host was not compromised to the point where its hash was readable.
  sources: <https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/pass-the-hash-with-machine-accounts.md> · <https://www.zscaler.com/blogs/product-insights/active-directory-kerberoasting-deception-detection>

## Known gaps

Not yet satisfied: `fp_rules`
