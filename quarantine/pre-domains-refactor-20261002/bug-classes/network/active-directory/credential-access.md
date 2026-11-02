# Windows Credential Access

## Definition

Credential material exists in reachable files and process memory, and recovering it converts one authenticated session into many.

- **CWE:** CWE-522
- **OWASP:** None
- **Surface:** ad
- **Aliases:** ["credential access", "lsass", "ntds.dit", "sam", "sam hive", "credential dumping", "mimikatz", "dpapi", "vault"]

Canonical home for `credential_access`. Rendered from `db/wks.db` by `methodology/scripts/build_taxonomy.py` — edit the rows, not this file.

## Root Cause

Not yet researched.

## Preconditions

Not yet researched.

## Attack Surface

Surface: **ad**.

The entry points and enabling conditions for this surface are enumerated under **Preconditions**; the observable signals are under **Detection**.

## Detection

**An inbound NetNTLMv2 hash arriving shortly after files were written to a network share is an early observable for coerced authentication, not proof that the hash was relayed.**

The classic collection shape is: obtain write access to a share, drop a file type the OS auto-resolves over the network (SCF, LNK, URL, library-ms), leave a listener running, and wait for the inbound authentication. A hit is a NetNTLMv2 hash of whoever happened to browse the share. It is a signal only, because capture and use are separate acts: the hash must still be replayed against a target to become credential access, and a strong target (full signing, channel binding) can refuse the replay that the capture suggests is available. Hunt the sequence - share write, then inbound NTLM from a workstation, then a NEW authentication from that workstation or a different host - and treat the third element as the discriminating one.

*Disproof:* If no authentication event follows the capture that uses the captured hash as NTLM credentials against any target service, and the captured user is shown browsing the share normally, then no credential access occurred and the capture remains an unenacted collection artefact.

## Exploitation

**The directory replication request right (DCSync) lets a principal pull password hashes including KRBTGT from a domain controller without ever touching the NTDS.dit file, so a single misconfigured principal yields the whole domain's credentials.**

DCSync abuses directory replication: a principal that holds the replication-related rights can request a full credential payload from a domain controller and receive current and historical hashes of accounts including KRBTGT and the Administrators group. The significance is that this is a permission, not an exploit — no memory scraping, no file access, no privileged session on the controller required beyond whatever the right is granted to. The hunt is therefore an ACL review of replication rights across the domain, checked against the specific rights DCSync requires (DS-Replication-Get-Changes, DS-Replication-Get-Changes-All and DS-Replication-Get-Changes-In-Filtered-Set). Detection is on the replication API invocation rather than on credential access, because by the time a hash is dumped the session looks like any other authenticated one.

*Disproof:* If no non-Domain-Admin principal holds the three replication rights, and a replication request from a standard account is denied, then no DCSync path exists and the finding is a false positive.

## Variations

Not yet researched.

## Technology / Framework Considerations

Not yet researched.

## API Considerations

Not yet researched.

## Attack Chains

Not yet researched.

## Real-World Examples

Not yet researched.

## Common False Positives

**Hash replay against a Protected Users or sensitive-and-non-delegable account fails, so a blocked replay must not be reported as credential access.**

Discard when the replayed hash belonged to an account in the Protected Users group, because that group disables NTLM authentication and weak Kerberos encryption for its members. It survives when the replay succeeded against an account outside that group.

*Disproof:* Would be wrong in a domain where the Protected Users group has been emptied, since the group membership check would then pass for everyone.

**A secretsdump or lsadump command that returned no hashes is not a credential-access finding even when the tool exited cleanly.**

Discard when the engagement captured the command line and its output rather than a result: NTDS.dit is in use by the KDC and cannot be copied like an ordinary file, so the dump requires local admin on a DC or replication rights. It survives when hashes for domain accounts were actually returned.

*Disproof:* Would be wrong where a backup or a shadow copy of NTDS.dit is readable by the tester without DC access, making the file copy itself sufficient.

## Validation

Not yet researched.

## Impact

**Dumping one privileged credential converts a single-host compromise into an environment-wide one, because the credential store can hold a domain admin's secrets and that credential is then usable for remote administration of domain controllers.**

The impact claim is about scope, not about the dump itself. Microsoft states that the credential store can hold not only the current user's OS credentials but also a domain admin's, and that obtaining those credentials serves as a gateway to objectives such as lateral movement; the Blackbyte case study shows the consuming step, where compromised domain admin credentials were used over RDP and PowerShell remoting to reach other servers including domain controllers. The environment-level consequence is that domain controllers sit at the centre of these operations, with Microsoft observing in more than 78% of human-operated attacks that actors successfully breached a domain controller. The chain therefore terminates not in data theft but in durable control: privileged accounts can be created or manipulated to keep access after the initial host is remediated. Detection must therefore look for the reuse, not the dump.

*Disproof:* If the dumped credential is tier-2 and segmentation denies its path to application servers and domain controllers, the blast radius stays at the first host; likewise if privileged credential reuse requires an interactive logon that monitoring would have blocked, the domain-wide claim does not follow from the dump alone.

## Related Bug Classes

Not yet researched.

## References

- **academy.hackthebox.com** (docs)
  - <https://academy.hackthebox.com/course/preview/active-directory-enumeration--attacks>
- **attack.mitre.org** (taxonomy)
  - <https://attack.mitre.org/techniques/T1003/006/>
- **googleprojectzero.blogspot.com** (research)
  - <https://googleprojectzero.blogspot.com/2022/10/>
- **learn.microsoft.com** (docs)
  - <https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/>
- **microsoft.com** (research)
  - <https://www.microsoft.com/en-us/security/blog/2022/10/05/detecting-and-preventing-lsass-credential-dumping-attacks/>
- **nccgroup.com** (research)
  - <https://www.nccgroup.com/research/defending-your-directory-an-expert-guide-to-combating-kerberoasting-in-active-directory/>
  - <https://www.nccgroup.com/research/defending-your-directory-an-expert-guide-to-securing-active-directory-against-dcsync-attacks/>
- **securelist.com** (research)
  - <https://securelist.com/tr/network-anomaly-detection-in-kata/120892/>
- **tenable.com** (research)
  - <https://www.tenable.com/blog/five-cyber-agencies-sound-alarm-about-active-directory-attacks-beyond-the-basics>
- **thehacker.recipes** (cheatsheet)
  - <https://www.thehacker.recipes/ad/movement/credentials/dumping/ntds>

Every item above is gated on >= 2 distinct publisher hosts (`wks/quality.py`, rule R1). Publisher diversity, not citation count, is what makes these corroborated.
