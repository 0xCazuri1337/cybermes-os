# Methodology — Windows Credential Access

> Derived from 5 verified items. Regenerate with `python -m wks.methodgen --class credential_access --apply`. Do not hand-edit: this file is a projection of the evidence, and edits are lost on the next cycle.

**Surface.** Credential material exists in reachable files and process memory, and recovering it converts one authenticated session into many.

**References.** CWE-522

## Preconditions

_No verified prerequisite items yet._ Derived from evidence only, so this section is empty rather than plausible.


## 1. Reconnaissance signals

_What to look for while mapping the surface, and where each signal tells you the rest of the procedure is worth running._

**An inbound NetNTLMv2 hash arriving shortly after files were written to a network share is an early observable for coerced authentication, not proof that the hash was relayed.**

The classic collection shape is: obtain write access to a share, drop a file type the OS auto-resolves over the network (SCF, LNK, URL, library-ms), leave a listener running, and wait for the inbound authentication. A hit is a NetNTLMv2 hash of whoever happened to browse the share. It is a signal only, because capture and use are separate acts: the hash must still be replayed against a target to become credential access, and a strong target (full signing, channel binding) can refuse the replay that the capture suggests is available. Hunt the sequence - share write, then inbound NTLM from a workstation, then a NEW authentication from that workstation or a different host - and treat the third element as the discriminating one.

- *Disproof:* If no authentication event follows the capture that uses the captured hash as NTLM credentials against any target service, and the captured user is shown browsing the share normally, then no credential access occurred and the capture remains an unenacted collection artefact.
- *Evidence:* high_confidence — [academy.hackthebox.com](https://academy.hackthebox.com/course/preview/active-directory-enumeration--attacks); [securelist.com](https://securelist.com/tr/network-anomaly-detection-in-kata/120892/)

## 2. Test sequence

_Concrete mutations to try. Each is written to be executable, not to be a description of the vulnerability._

**The directory replication request right (DCSync) lets a principal pull password hashes including KRBTGT from a domain controller without ever touching the NTDS.dit file, so a single misconfigured principal yields the whole domain's credentials.**

DCSync abuses directory replication: a principal that holds the replication-related rights can request a full credential payload from a domain controller and receive current and historical hashes of accounts including KRBTGT and the Administrators group. The significance is that this is a permission, not an exploit — no memory scraping, no file access, no privileged session on the controller required beyond whatever the right is granted to. The hunt is therefore an ACL review of replication rights across the domain, checked against the specific rights DCSync requires (DS-Replication-Get-Changes, DS-Replication-Get-Changes-All and DS-Replication-Get-Changes-In-Filtered-Set). Detection is on the replication API invocation rather than on credential access, because by the time a hash is dumped the session looks like any other authenticated one.

- *Disproof:* If no non-Domain-Admin principal holds the three replication rights, and a replication request from a standard account is denied, then no DCSync path exists and the finding is a false positive.
- *Evidence:* high_confidence — [attack.mitre.org](https://attack.mitre.org/techniques/T1003/006/); [nccgroup.com](https://www.nccgroup.com/research/defending-your-directory-an-expert-guide-to-securing-active-directory-against-dcsync-attacks/)

## Validation

_No verified validation items yet._ Derived from evidence only, so this section is empty rather than plausible.


## 3. False-positive rejection

_The checks that eliminate the most common non-findings. Run these BEFORE reporting, not after a rejection._

**A secretsdump or lsadump command that returned no hashes is not a credential-access finding even when the tool exited cleanly.**

Discard when the engagement captured the command line and its output rather than a result: NTDS.dit is in use by the KDC and cannot be copied like an ordinary file, so the dump requires local admin on a DC or replication rights. It survives when hashes for domain accounts were actually returned.

- *Disproof:* Would be wrong where a backup or a shadow copy of NTDS.dit is readable by the tester without DC access, making the file copy itself sufficient.
- *Evidence:* high_confidence — [nccgroup.com](https://www.nccgroup.com/research/defending-your-directory-an-expert-guide-to-securing-active-directory-against-dcsync-attacks/); [thehacker.recipes](https://www.thehacker.recipes/ad/movement/credentials/dumping/ntds)

**Hash replay against a Protected Users or sensitive-and-non-delegable account fails, so a blocked replay must not be reported as credential access.**

Discard when the replayed hash belonged to an account in the Protected Users group, because that group disables NTLM authentication and weak Kerberos encryption for its members. It survives when the replay succeeded against an account outside that group.

- *Disproof:* Would be wrong in a domain where the Protected Users group has been emptied, since the group membership check would then pass for everyone.
- *Evidence:* high_confidence — [googleprojectzero.blogspot.com](https://googleprojectzero.blogspot.com/2022/10/); [nccgroup.com](https://www.nccgroup.com/research/defending-your-directory-an-expert-guide-to-combating-kerberoasting-in-active-directory/)

## Known bypasses

_No verified bypass items yet._ Derived from evidence only, so this section is empty rather than plausible.


## Chaining

_No verified chain_link items yet._ Derived from evidence only, so this section is empty rather than plausible.


## 4. Impact

_What is actually demonstrable, and what to stop claiming._

**Dumping one privileged credential converts a single-host compromise into an environment-wide one, because the credential store can hold a domain admin's secrets and that credential is then usable for remote administration of domain controllers.**

The impact claim is about scope, not about the dump itself. Microsoft states that the credential store can hold not only the current user's OS credentials but also a domain admin's, and that obtaining those credentials serves as a gateway to objectives such as lateral movement; the Blackbyte case study shows the consuming step, where compromised domain admin credentials were used over RDP and PowerShell remoting to reach other servers including domain controllers. The environment-level consequence is that domain controllers sit at the centre of these operations, with Microsoft observing in more than 78% of human-operated attacks that actors successfully breached a domain controller. The chain therefore terminates not in data theft but in durable control: privileged accounts can be created or manipulated to keep access after the initial host is remediated. Detection must therefore look for the reuse, not the dump.

- *Disproof:* If the dumped credential is tier-2 and segmentation denies its path to application servers and domain controllers, the blast radius stays at the first host; likewise if privileged credential reuse requires an interactive logon that monitoring would have blocked, the domain-wide claim does not follow from the dump alone.
- *Evidence:* high_confidence — [microsoft.com](https://www.microsoft.com/en-us/security/blog/2022/10/05/detecting-and-preventing-lsass-credential-dumping-attacks/); [tenable.com](https://www.tenable.com/blog/five-cyber-agencies-sound-alarm-about-active-directory-attacks-beyond-the-basics)

## Coverage gap

These stages have no verified evidence and are therefore absent above: Preconditions, Validation, Known bypasses, Chaining.
A procedure with a missing validation stage is not safe to act on — it produces findings rather than proofs.

---

*Generated from the evidence base. Where this file and the database disagree, the database is correct.*
