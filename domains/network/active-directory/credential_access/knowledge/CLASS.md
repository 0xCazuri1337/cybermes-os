# Windows Credential Access

## Definition

Credential material exists in reachable files and process memory, and recovering it converts one authenticated session into many.

- **CWE:** CWE-522
- **OWASP:** None
- **Surface:** ad
- **Aliases:** ["credential access", "lsass", "ntds.dit", "sam", "sam hive", "credential dumping", "mimikatz", "dpapi", "vault"]

Canonical home for `credential_access`. Rendered from `db/wks.db` by `tools/taxonomy/build_taxonomy.py` — edit the rows, not this file.

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

**In June 2022 I found an interesting issue number 2310 with the handling of RC4 encryption that allowed you to authenticate as another user if you could either interpose on the Kerberos network traffic to and from the KDC or directly if the user was configured to disable typical pre-authentication requirements.**

Thursday, October 27, 2022 

 
 
 
 
 
 
 
 
 
 RC4 Is Still Considered Harmful 
 
 
 
 
 

 By James Forshaw, Project Zero I've been spending a lot of time researching Windows authentication implementations, specifically Kerberos. In June 2022 I found an interesting issue number 2310 with the handling of RC4 encryption that allowed you to authenticate as another user if you could either interpose on the Kerberos network traffic to and from the KDC or directly if the user was configured to disable typical pre-authentication requirements. This blog post goes into more detail on how this vulnerability works and how I was able to exploit it with only a bare minimum of brute forcing required. Note, I'm not going to spend time fully explaining how Kerberos authentication works, there's plenty of resources online. For example this blog post by Steve Syfuhs who works at Microsoft is a good first start. Background Kerberos is a very old

*Disproof:* This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "In June 2022 I found an interesting issue number 2310 with the handling of RC4 encryption ".

**The current version (v5) was described in RFC1510 back in 1993, although it was updated in RFC4120 in 2005. As Kerberos' core security concept is using encryption to prove knowledge of a user's credentials the design allows for negotiating the encryption and checksum algorithms that the client and server will use.**

more detail on how this vulnerability works and how I was able to exploit it with only a bare minimum of brute forcing required. Note, I'm not going to spend time fully explaining how Kerberos authentication works, there's plenty of resources online. For example this blog post by Steve Syfuhs who works at Microsoft is a good first start. Background Kerberos is a very old authentication protocol. The current version (v5) was described in RFC1510 back in 1993, although it was updated in RFC4120 in 2005. As Kerberos' core security concept is using encryption to prove knowledge of a user's credentials the design allows for negotiating the encryption and checksum algorithms that the client and server will use.  For example when sending the initial authentication service request (AS-REQ) to the Key Distribution Center (KDC) a client can specify a list supported encryption algorithms, as predefined integer identifiers, as shown below in the snippet of the ASN.1 definition from RFC4120. KDC-REQ-BODY    ::= SEQUENCE { ...     etype    [8] SEQUENCE OF Int32 -- EncryptionType

*Disproof:* This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "The current version (v5) was described in RFC1510 back in 1993, although it was updated in".

**This prevents an attacker using Kerberos as an encryption oracle and reusing existing encrypted data in unrelated parts of the protocol.**

The key used for the encryption is derived from the hash and a base key. This, combined with the confounder makes it almost certain the same key is never reused for the encryption. The base key is not the user's key, but instead is derived from a MD5 HMAC keyed with the user's key over a 4 byte message type value. For example the message type is different for the AS-REQ and the AS-REP structures. This prevents an attacker using Kerberos as an encryption oracle and reusing existing encrypted data in unrelated parts of the protocol. Many of the known weaknesses of RC4 are related to gathering a significant quantity of ciphertext encrypted with a known key. Due to the design of the RC4-HMAC algorithm and the general functional principles of Kerberos this is not really a significant concern. However, the biggest weakness of RC4 as defined by Microsoft for Kerberos is not so much the algorithm, but the generation of the user's

*Disproof:* This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "This prevents an attacker using Kerberos as an encryption oracle and reusing existing encr".

**If an attacker has access to ciphertext encrypted using the RC4-HMAC key they can attempt to brute force the key through guessing the password.**

from the Unicode password using a single pass of the MD4 algorithm. Therefore to make an easy upgrade path Microsoft specified that the RC4-HMAC Kerberos key was this same hash value. As the MD4 output is 16 bytes in size it wouldn't be practical to brute force the entire key. However, the hash algorithm has no protections against brute-force attacks for example no salting or multiple iterations. If an attacker has access to ciphertext encrypted using the RC4-HMAC key they can attempt to brute force the key through guessing the password. As user's will tend to choose weak or trivial passwords this increases the chance that a brute force attack would work to recover the key. And with the key the attacker can then authenticate as that user to any service they like.  To get appropriate cipher text the attacker can make requests to the KDC and specify the encryption type they need. The most well known attack technique is called Kerbe

*Disproof:* This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "If an attacker has access to ciphertext encrypted using the RC4-HMAC key they can attempt ".

**This technique does require the attacker to have an account on the KDC to make the service ticket request.**

que is called Kerberoasting . This technique requests a service ticket for the targeted user and specifies the RC4-HMAC encryption type as their preferred algorithm. If the user has an RC4 key configured then the ticket returned can be encrypted using the RC4-HMAC algorithm. As significant parts of the plain-text is known for the ticket data the attacker can try to brute force the key from that.  This technique does require the attacker to have an account on the KDC to make the service ticket request. It also requires that the user account has a configured Service Principal Name (SPN) so that a ticket can be requested. Also modern versions of Windows Server will try to block this attack by forcing the use of AES keys which are derived from the service user's password over RC4 even if the attacker only requested RC4 support. An alternative form is called AS-REP Roasting . Instead of requesting

*Disproof:* This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "This technique does require the attacker to have an account on the KDC to make the service".

**Also modern versions of Windows Server will try to block this attack by forcing the use of AES keys which are derived from the service user's password over RC4 even if the attacker only requested RC4 support.**

d can be encrypted using the RC4-HMAC algorithm. As significant parts of the plain-text is known for the ticket data the attacker can try to brute force the key from that.  This technique does require the attacker to have an account on the KDC to make the service ticket request. It also requires that the user account has a configured Service Principal Name (SPN) so that a ticket can be requested. Also modern versions of Windows Server will try to block this attack by forcing the use of AES keys which are derived from the service user's password over RC4 even if the attacker only requested RC4 support. An alternative form is called AS-REP Roasting . Instead of requesting a service ticket this relies on the initial authentication requests to return encrypted data. When a user sends an AS-REQ structure, the KDC can look up the user, generate the TGT and its associated session key then return that information encrypted using the user's RC4-HMAC key. At this point the KDC hasn't verified the client

*Disproof:* This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Also modern versions of Windows Server will try to block this attack by forcing the use of".

**Instead of requesting a service ticket this relies on the initial authentication requests to return encrypted data.**

ervice ticket request. It also requires that the user account has a configured Service Principal Name (SPN) so that a ticket can be requested. Also modern versions of Windows Server will try to block this attack by forcing the use of AES keys which are derived from the service user's password over RC4 even if the attacker only requested RC4 support. An alternative form is called AS-REP Roasting . Instead of requesting a service ticket this relies on the initial authentication requests to return encrypted data. When a user sends an AS-REQ structure, the KDC can look up the user, generate the TGT and its associated session key then return that information encrypted using the user's RC4-HMAC key. At this point the KDC hasn't verified the client knows the user's key before returning the encrypted data, which allows the attacker to brute force the key without needing to have an account themselves on the KDC

*Disproof:* This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Instead of requesting a service ticket this relies on the initial authentication requests ".

**At this point the KDC hasn't verified the client knows the user's key before returning the encrypted data, which allows the attacker to brute force the key without needing to have an account themselves on the KDC.**

even if the attacker only requested RC4 support. An alternative form is called AS-REP Roasting . Instead of requesting a service ticket this relies on the initial authentication requests to return encrypted data. When a user sends an AS-REQ structure, the KDC can look up the user, generate the TGT and its associated session key then return that information encrypted using the user's RC4-HMAC key. At this point the KDC hasn't verified the client knows the user's key before returning the encrypted data, which allows the attacker to brute force the key without needing to have an account themselves on the KDC. Fortunately this attack is more rare because Windows's Kerberos implementation requires pre-authentication. For a password based logon the user uses their encryption key to encrypt a timestamp value which is sent to the KDC as part of the AS-REQ. The KDC can decrypt the timestamp, check it's within a small time window and only then return the user's TGT and encrypted session key. This would preve

*Disproof:* This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "At this point the KDC hasn't verified the client knows the user's key before returning the".

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

- `chain.credential_access.auto.01` — credential_access: observe, exercise, confirm (goal: `Establish, exercise and confirm a credential_access condition on an authorised target without relying on anyone else's data.`)

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
