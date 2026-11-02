# Windows Credential Access

> surface: `ad` · CWE: CWE-522 · OWASP: —
> maturity: **mature** — 13 items, 5 supported, 2 FP rules, 1 chains

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
  `under_review` · score 0.7995 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "The current version (v5) was described in RFC1510 back in 1993, although it was updated in".
  sources: <https://googleprojectzero.blogspot.com/2022/10/> · <https://www.nccgroup.com/research/defending-your-directory-an-expert-guide-to-combating-kerberoasting-in-active-directory/>
- **Also modern versions of Windows Server will try to block this attack by forcing the use of AES keys which are derived from the service user's password over RC4 even if the attacker only requested RC4 support.**  
  `under_review` · score 0.7995 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Also modern versions of Windows Server will try to block this attack by forcing the use of".
  sources: <https://googleprojectzero.blogspot.com/2022/10/> · <https://www.nccgroup.com/research/defending-your-directory-an-expert-guide-to-securing-active-directory-against-dcsync-attacks/>
- **In June 2022 I found an interesting issue number 2310 with the handling of RC4 encryption that allowed you to authenticate as another user if you could either interpose on the Kerberos network traffic to and from the KDC or directly if the user was configured to disable typical pre-authentication requirements.**  
  `under_review` · score 0.772 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "In June 2022 I found an interesting issue number 2310 with the handling of RC4 encryption ".
  sources: <https://googleprojectzero.blogspot.com/2022/10/> · <https://www.nccgroup.com/research/defending-your-directory-an-expert-guide-to-combating-kerberoasting-in-active-directory/>
- **This prevents an attacker using Kerberos as an encryption oracle and reusing existing encrypted data in unrelated parts of the protocol.**  
  `under_review` · score 0.772 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "This prevents an attacker using Kerberos as an encryption oracle and reusing existing encr".
  sources: <https://academy.hackthebox.com/course/preview/active-directory-enumeration--attacks> · <https://googleprojectzero.blogspot.com/2022/10/>
- **If an attacker has access to ciphertext encrypted using the RC4-HMAC key they can attempt to brute force the key through guessing the password.**  
  `under_review` · score 0.7055 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "If an attacker has access to ciphertext encrypted using the RC4-HMAC key they can attempt ".
  sources: <https://googleprojectzero.blogspot.com/2022/10/>
- **This technique does require the attacker to have an account on the KDC to make the service ticket request.**  
  `under_review` · score 0.7055 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "This technique does require the attacker to have an account on the KDC to make the service".
  sources: <https://googleprojectzero.blogspot.com/2022/10/>
- **Instead of requesting a service ticket this relies on the initial authentication requests to return encrypted data.**  
  `under_review` · score 0.7055 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Instead of requesting a service ticket this relies on the initial authentication requests ".
  sources: <https://googleprojectzero.blogspot.com/2022/10/>
- **At this point the KDC hasn't verified the client knows the user's key before returning the encrypted data, which allows the attacker to brute force the key without needing to have an account themselves on the KDC.**  
  `under_review` · score 0.7055 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "At this point the KDC hasn't verified the client knows the user's key before returning the".
  sources: <https://googleprojectzero.blogspot.com/2022/10/>

## Fp Rule

- **A secretsdump or lsadump command that returned no hashes is not a credential-access finding even when the tool exited cleanly.**  
  `high_confidence` · score 0.844 · disproved by: Would be wrong where a backup or a shadow copy of NTDS.dit is readable by the tester without DC access, making the file copy itself sufficient.
  sources: <https://www.nccgroup.com/research/defending-your-directory-an-expert-guide-to-securing-active-directory-against-dcsync-attacks/> · <https://www.thehacker.recipes/ad/movement/credentials/dumping/ntds>
- **Hash replay against a Protected Users or sensitive-and-non-delegable account fails, so a blocked replay must not be reported as credential access.**  
  `high_confidence` · score 0.8355 · disproved by: Would be wrong in a domain where the Protected Users group has been emptied, since the group membership check would then pass for everyone.
  sources: <https://googleprojectzero.blogspot.com/2022/10/> · <https://www.nccgroup.com/research/defending-your-directory-an-expert-guide-to-combating-kerberoasting-in-active-directory/>

## Impact

- **Dumping one privileged credential converts a single-host compromise into an environment-wide one, because the credential store can hold a domain admin's secrets and that credential is then usable for remote administration of domain controllers.**  
  `high_confidence` · score 0.844 · disproved by: If the dumped credential is tier-2 and segmentation denies its path to application servers and domain controllers, the blast radius stays at the first host; likewise if privileged credential reuse requires an interactive logon that monitoring would have blocked, the domain-wide claim does not follow from the dump alone.
  sources: <https://www.microsoft.com/en-us/security/blog/2022/10/05/detecting-and-preventing-lsass-credential-dumping-attacks/> · <https://www.tenable.com/blog/five-cyber-agencies-sound-alarm-about-active-directory-attacks-beyond-the-basics>
