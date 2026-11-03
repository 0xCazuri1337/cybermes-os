<!-- GENERATED from db/wks.db — do not edit -->
# Windows Credential Access

> surface: `ad` · CWE: CWE-522 · OWASP: —
> maturity: **researching** — 14 items, 9 supported, 0 FP rules, 1 chains

Credential material exists in reachable files and process memory, and recovering it converts one authenticated session into many.

**Aliases:** credential access, lsass, ntds.dit, sam, sam hive, credential dumping, mimikatz, dpapi, vault

## Signal

- **An inbound NetNTLMv2 hash arriving shortly after files were written to a network share is an early observable for coerced authentication, not proof that the hash was relayed.**  
  `high_confidence` · score 0.8715 · disproved by: If no authentication event follows the capture that uses the captured hash as NTLM credentials against any target service, and the captured user is shown browsing the share normally, then no credential access occurred and the capture remains an unenacted collection artefact.
  sources: <https://academy.hackthebox.com/course/preview/active-directory-enumeration--attacks> · <https://securelist.com/tr/network-anomaly-detection-in-kata/120892/>

## Technique

- **The directory replication request right (DCSync) lets a principal pull password hashes including KRBTGT from a domain controller without ever touching the NTDS.dit file, so a single misconfigured principal yields the whole domain's credentials.**  
  `high_confidence` · score 0.929 · disproved by: If no non-Domain-Admin principal holds the three replication rights, and a replication request from a standard account is denied, then no DCSync path exists and the finding is a false positive.
  sources: <https://attack.mitre.org/techniques/T1003/006/> · <https://www.nccgroup.com/research/defending-your-directory-an-expert-guide-to-securing-active-directory-against-dcsync-attacks/>
- **The current version (v5) was described in RFC1510 back in 1993, although it was updated in RFC4120 in 2005. As Kerberos' core security concept is using encryption to prove knowledge of a user's credentials the design allows for negotiating the encryption and checksum algorithms that the client and server will use.**  
  `high_confidence` · score 0.7995 · disproved by: Refuted when: the same behaviour is absent when the single named control in the claim is present, and the control is shown to be present rather than assumed. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“The current version (v5) was described in RFC1510 back in 1993, although it was ”) does not occur under a test that isolates that control.
  sources: <https://googleprojectzero.blogspot.com/2022/10/> · <https://www.nccgroup.com/research/defending-your-directory-an-expert-guide-to-combating-kerberoasting-in-active-directory/>
- **Also modern versions of Windows Server will try to block this attack by forcing the use of AES keys which are derived from the service user's password over RC4 even if the attacker only requested RC4 support.**  
  `high_confidence` · score 0.7995 · disproved by: Refuted when: the same behaviour is absent when the single named control in the claim is present, and the control is shown to be present rather than assumed. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“Also modern versions of Windows Server will try to block this attack by forcing ”) does not occur under a test that isolates that control.
  sources: <https://googleprojectzero.blogspot.com/2022/10/> · <https://www.nccgroup.com/research/defending-your-directory-an-expert-guide-to-securing-active-directory-against-dcsync-attacks/>
- **This prevents an attacker using Kerberos as an encryption oracle and reusing existing encrypted data in unrelated parts of the protocol.**  
  `high_confidence` · score 0.772 · disproved by: Refuted when: the same behaviour is absent when the single named control in the claim is present, and the control is shown to be present rather than assumed. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“This prevents an attacker using Kerberos as an encryption oracle and reusing exi”) does not occur under a test that isolates that control.
  sources: <https://academy.hackthebox.com/course/preview/active-directory-enumeration--attacks> · <https://googleprojectzero.blogspot.com/2022/10/>

## Test

- **NTDS.dit contains the domain's directory credential material and is located on domain controllers; extracting it requires domain controller access or a directory replication right, and the finding is proven by recovered domain hashes rather than by a copy of the file alone.**  
  `high_confidence` · score 0.905 · disproved by: A copied NTDS.dit file that yields no domain hashes is not a credential-access finding. The database is present on every domain controller; the finding requires a recovered credential or a demonstrated replication response.
  sources: <https://attack.mitre.org/techniques/T1003/003/> · <https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/get-started/virtual-dc/active-directory-domain-services-overview>
- **LSASS memory contains credential material generated by interactive, batch, and service logons; a dump is evidence only when the process memory was read and a credential artifact was recovered, not when a dump file is merely created.**  
  `high_confidence` · score 0.85 · disproved by: A dump file that yields no credential, or a dump attempt blocked by LSA protection, is not a credential-access finding. LSA protection exists specifically to stop nonprotected processes from reading LSASS memory, so a blocked read is the control working.
  sources: <https://attack.mitre.org/techniques/T1003/001/> · <https://learn.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/configuring-additional-lsa-protection>
- **The SAM database stores local account credential material, and extracting it requires reading the SAM and SYSTEM registry hives or equivalent in-memory access on the host; a successful extraction is proven by recovered hashes, not by the presence of the files.**  
  `high_confidence` · score 0.814 · disproved by: A SAM or SYSTEM file that yields no usable hash is not a credential-access finding. The files can be present on every host; the finding requires successful decryption and a recovered credential.
  sources: <https://attack.mitre.org/techniques/T1003/002/> · <https://learn.microsoft.com/en-us/windows-server/security/windows-authentication/credentials-processes-in-windows-authentication>

## Impact

- **Dumping one privileged credential converts a single-host compromise into an environment-wide one, because the credential store can hold a domain admin's secrets and that credential is then usable for remote administration of domain controllers.**  
  `high_confidence` · score 0.844 · disproved by: If the dumped credential is tier-2 and segmentation denies its path to application servers and domain controllers, the blast radius stays at the first host; likewise if privileged credential reuse requires an interactive logon that monitoring would have blocked, the domain-wide claim does not follow from the dump alone.
  sources: <https://www.microsoft.com/en-us/security/blog/2022/10/05/detecting-and-preventing-lsass-credential-dumping-attacks/> · <https://www.tenable.com/blog/five-cyber-agencies-sound-alarm-about-active-directory-attacks-beyond-the-basics>

## Known gaps

Not yet satisfied: `fp_rules`
