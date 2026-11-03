# Methodology — Windows Credential Access

> Derived from 9 verified items. Regenerate with `python -m wks.methodgen --class credential_access --apply`. Do not hand-edit: this file is a projection of the evidence, and edits are lost on the next cycle.

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

**The current version (v5) was described in RFC1510 back in 1993, although it was updated in RFC4120 in 2005. As Kerberos' core security concept is using encryption to prove knowledge of a user's credentials the design allows for negotiating the encryption and checksum algorithms that the client and server will use.**

more detail on how this vulnerability works and how I was able to exploit it with only a bare minimum of brute forcing required. Note, I'm not going to spend time fully explaining how Kerberos authentication works, there's plenty of resources online. For example this blog post by Steve Syfuhs who works at Microsoft is a good first start. Background Kerberos is a very old authentication protocol. The current version (v5) was described in RFC1510 back in 1993, although it was updated in RFC4120 in 2005. As Kerberos' core security concept is using encryption to prove knowledge of a user's credentials the design allows for negotiating the encryption and checksum algorithms that the client and server will use.  For example when sending the initial authentication service request (AS-REQ) to the Key Distribution Center (KDC) a client can specify a list supported encryption algorithms, as predefined integer identifiers, as shown below in the snippet of the ASN.1 definition from RFC4120. KDC-REQ-BODY    ::= SEQUENCE { ...     etype    [8] SEQUENCE OF Int32 -- EncryptionType

- *Disproof:* Refuted when: the same behaviour is absent when the single named control in the claim is present, and the control is shown to be present rather than assumed. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“The current version (v5) was described in RFC1510 back in 1993, although it was ”) does not occur under a test that isolates that control.
- *Evidence:* high_confidence — [googleprojectzero.blogspot.com](https://googleprojectzero.blogspot.com/2022/10/); [nccgroup.com](https://www.nccgroup.com/research/defending-your-directory-an-expert-guide-to-combating-kerberoasting-in-active-directory/)

**Also modern versions of Windows Server will try to block this attack by forcing the use of AES keys which are derived from the service user's password over RC4 even if the attacker only requested RC4 support.**

d can be encrypted using the RC4-HMAC algorithm. As significant parts of the plain-text is known for the ticket data the attacker can try to brute force the key from that.  This technique does require the attacker to have an account on the KDC to make the service ticket request. It also requires that the user account has a configured Service Principal Name (SPN) so that a ticket can be requested. Also modern versions of Windows Server will try to block this attack by forcing the use of AES keys which are derived from the service user's password over RC4 even if the attacker only requested RC4 support. An alternative form is called AS-REP Roasting . Instead of requesting a service ticket this relies on the initial authentication requests to return encrypted data. When a user sends an AS-REQ structure, the KDC can look up the user, generate the TGT and its associated session key then return that information encrypted using the user's RC4-HMAC key. At this point the KDC hasn't verified the client

- *Disproof:* Refuted when: the same behaviour is absent when the single named control in the claim is present, and the control is shown to be present rather than assumed. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“Also modern versions of Windows Server will try to block this attack by forcing ”) does not occur under a test that isolates that control.
- *Evidence:* high_confidence — [googleprojectzero.blogspot.com](https://googleprojectzero.blogspot.com/2022/10/); [nccgroup.com](https://www.nccgroup.com/research/defending-your-directory-an-expert-guide-to-securing-active-directory-against-dcsync-attacks/)

**This prevents an attacker using Kerberos as an encryption oracle and reusing existing encrypted data in unrelated parts of the protocol.**

The key used for the encryption is derived from the hash and a base key. This, combined with the confounder makes it almost certain the same key is never reused for the encryption. The base key is not the user's key, but instead is derived from a MD5 HMAC keyed with the user's key over a 4 byte message type value. For example the message type is different for the AS-REQ and the AS-REP structures. This prevents an attacker using Kerberos as an encryption oracle and reusing existing encrypted data in unrelated parts of the protocol. Many of the known weaknesses of RC4 are related to gathering a significant quantity of ciphertext encrypted with a known key. Due to the design of the RC4-HMAC algorithm and the general functional principles of Kerberos this is not really a significant concern. However, the biggest weakness of RC4 as defined by Microsoft for Kerberos is not so much the algorithm, but the generation of the user's

- *Disproof:* Refuted when: the same behaviour is absent when the single named control in the claim is present, and the control is shown to be present rather than assumed. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“This prevents an attacker using Kerberos as an encryption oracle and reusing exi”) does not occur under a test that isolates that control.
- *Evidence:* high_confidence — [academy.hackthebox.com](https://academy.hackthebox.com/course/preview/active-directory-enumeration--attacks); [googleprojectzero.blogspot.com](https://googleprojectzero.blogspot.com/2022/10/)

## Validation

_No verified validation items yet._ Derived from evidence only, so this section is empty rather than plausible.


## False-positive rejection

_No verified fp_rule items yet._ Derived from evidence only, so this section is empty rather than plausible.


## Known bypasses

_No verified bypass items yet._ Derived from evidence only, so this section is empty rather than plausible.


## Chaining

_No verified chain_link items yet._ Derived from evidence only, so this section is empty rather than plausible.


## 3. Impact

_What is actually demonstrable, and what to stop claiming._

**Dumping one privileged credential converts a single-host compromise into an environment-wide one, because the credential store can hold a domain admin's secrets and that credential is then usable for remote administration of domain controllers.**

The impact claim is about scope, not about the dump itself. Microsoft states that the credential store can hold not only the current user's OS credentials but also a domain admin's, and that obtaining those credentials serves as a gateway to objectives such as lateral movement; the Blackbyte case study shows the consuming step, where compromised domain admin credentials were used over RDP and PowerShell remoting to reach other servers including domain controllers. The environment-level consequence is that domain controllers sit at the centre of these operations, with Microsoft observing in more than 78% of human-operated attacks that actors successfully breached a domain controller. The chain therefore terminates not in data theft but in durable control: privileged accounts can be created or manipulated to keep access after the initial host is remediated. Detection must therefore look for the reuse, not the dump.

- *Disproof:* If the dumped credential is tier-2 and segmentation denies its path to application servers and domain controllers, the blast radius stays at the first host; likewise if privileged credential reuse requires an interactive logon that monitoring would have blocked, the domain-wide claim does not follow from the dump alone.
- *Evidence:* high_confidence — [microsoft.com](https://www.microsoft.com/en-us/security/blog/2022/10/05/detecting-and-preventing-lsass-credential-dumping-attacks/); [tenable.com](https://www.tenable.com/blog/five-cyber-agencies-sound-alarm-about-active-directory-attacks-beyond-the-basics)

## Coverage gap

These stages have no verified evidence and are therefore absent above: Preconditions, Validation, False-positive rejection, Known bypasses, Chaining.
A procedure with a missing validation stage is not safe to act on — it produces findings rather than proofs.

---

*Generated from the evidence base. Where this file and the database disagree, the database is correct.*
