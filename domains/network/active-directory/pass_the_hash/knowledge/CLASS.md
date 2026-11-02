# Pass-the-Hash and Ticket Replay

## Definition

A protocol that authenticates the NTLM hash or a service ticket rather than a secret the user holds lets that artefact be replayed verbatim as a credential.

- **CWE:** CWE-294
- **OWASP:** None
- **Surface:** ad
- **Aliases:** ["pass the hash", "pass-the-hash", "pth", "pass the ticket", "ticket replay", "overpass the hash"]

Canonical home for `pass_the_hash`. Rendered from `db/wks.db` by `tools/taxonomy/build_taxonomy.py` — edit the rows, not this file.

## Root Cause

Not yet researched.

## Preconditions

Not yet researched.

## Attack Surface

Surface: **ad**.

The entry points and enabling conditions for this surface are enumerated under **Preconditions**; the observable signals are under **Detection**.

## Detection

**A convincing observation for this class is: The observable that triggers this false positive is a pass-the-hash attempt returning access denied for a local account that is not RID 500, written up as a partial authentication bypass or a weakened hash policy.**

Derived from pass_the_hash.fp_rule.rid_not_500_hash_denied_is_correct_protection, which states the boundary for this class. The observation above is what a report must contain to be believed: an artifact the reviewer can re-check, not a claim the hunter asserts. A finding without it is an assertion.

*Disproof:* Not evidence when the observable cannot be produced at all -- blind, server-side-only, or identical-in-every-case behaviour leaves nothing to show. The originating rule (pass_the_hash.fp_rule.rid_not_500_hash_denied_is_correct_protection) states the full boundary.

## Exploitation

**For all exercises, we will assume that the target company Inlanefreight has hired us to perform an in-depth penetration test with a heavy focus on AD security, where stealth and bypassing stringent security controls are not a requirement.**

ls of the assessment. The tools listed above will be covered in other modules. 
 
 Next Steps 
 During this module, we will target a fictional company called INLANEFREIGHT with the internal domain INLANEFREIGHT.LOCAL . The module sections will build on each other, culminating in a mock penetration testing skills assessment to showcase our skills before moving on to the next module in this series. For all exercises, we will assume that the target company Inlanefreight has hired us to perform an in-depth penetration test with a heavy focus on AD security, where stealth and bypassing stringent security controls are not a requirement. 
 
 Module Exercises 
 Throughout this module, you will connect to various target hosts via the Remote Desktop Protocol (RDP) to complete the exercises. Any necessary credentials will be provided with each exercise, and the RDP connection can be made via xfreerdp from the Pwnbox as follows: 
 xfreerdp /v: /u:htb-student /p: 
 
 Any necessary tools can be found in the c:\tools directory after logg

*Disproof:* This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "For all exercises, we will assume that the target company Inlanefreight has hired us to pe".

**Second point: MFA is largely ineffective against this technique once initial access has been obtained, because authentication can be made directly to a Domain Controller over NTLM (14), which does not support it.**

Administrator account is not subject to the account lockout threshold. Even when it reports as locked out, it can still be authenticated to if the correct password is supplied, which clears the locked status and resets the bad password count. It should therefore be treated as a break glass account, with a password of at least 30 characters, marked as sensitive and not delegable, and monitored. 

 Second point: MFA is largely ineffective against this technique once initial access has been obtained, because authentication can be made directly to a Domain Controller over NTLM (14), which does not support it. The guidance recommends disabling NTLM and, where that is not possible, enabling LDAP (15) channel binding, extended protection for authentication and SMB (16) signing. 

 
 
 
 Event Source Signal 
 
 
 2889 Domain Controllers Unsigned LDAP bind, one per attempt when the spray runs over LDAP 
 4624 Domain Controllers Successful logon; near-simultaneity with 4625 events marks a successful attempt

*Disproof:* This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Second point: MFA is largely ineffective against this technique once initial access has be".

**The hashes obtained are either cracked or replayed directly in a Pass-the-Hash, since NTLM accepts the hash as a valid authentication token.**

Replicating Directory Changes, Replicating Directory Changes All or Replicating Directory Changes in Filtered Set permissions, or GenericAll or AllExtendedRights on the domain root object. By default those rights belong to the Enterprise Admins and Domain Admins groups and to the Administrators group on Domain Controllers. The prime target is the KRBTGT object, a precondition for a Golden Ticket. The hashes obtained are either cracked or replayed directly in a Pass-the-Hash, since NTLM accepts the hash as a valid authentication token. 

 The guidance flags a preparatory variant: enable reversible encryption storage on the target objects, wait for their next password change, then run DCSync to retrieve the cleartext passwords. This manoeuvre defeats complexity requirements and removes the cracking step altogether. 

 Detection has been rebuilt. The now preferred method rests on auditing the remote procedure calls, RPC (24), ass

*Disproof:* This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "The hashes obtained are either cracked or replayed directly in a Pass-the-Hash, since NTLM".

**The variant applies to user objects configured not to require Kerberos pre-authentication.**

PN; create them as group Managed Service Accounts, gMSA (11), which enforce a 120-character password on automatic rotation, or failing that a password of at least 30 characters, unique and managed; grant them the minimum privileges needed and keep them out of highly privileged groups; enable AES (12) encryption, since Active Directory uses RC4 by default for service tickets. 

 AS-REP Roasting 

 The variant applies to user objects configured not to require Kerberos pre-authentication. The ticket granting ticket, TGT (13), is then returned in the authentication server response, encrypted with the password hash, and cracks in the same way. That configuration exists only to support systems older than Kerberos version 5. 

 Detection rests on event 4768, generated on a TGT request, with the same volume logic over a short window. Event 4625 adds to it: AS-REP Roasting can be execut

*Disproof:* Refuted when: the same behaviour is absent when the single named control in the claim is present, and the control is shown to be present rather than assumed. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“The variant applies to user objects configured not to require Kerberos pre-authe”) does not occur under a test that isolates that control.

**The KRBTGT object being the root of trust for the domain, its compromise requires a coordinated reset of every user and computer object password, and may lead to rebuilding the domain.**

ps encrypted and reserved to backup administrators, no service or application unrelated to security, centralised logging, Print Spooler disabled, SMB version 1 disabled. 

 Golden Ticket 

 The KRBTGT object’s hash allows arbitrary TGTs to be forged. It does not need to be cracked, since it is the hash itself that encrypts the tickets. That hash is obtained through DCSync or by dumping ntds.dit . The KRBTGT object being the root of trust for the domain, its compromise requires a coordinated reset of every user and computer object password, and may lead to rebuilding the domain. 

 The most robust detection is detection by absence. Normal Kerberos authentication produces event 4768 on the TGT request, then 4769 on the TGS request, and the two correspond. A TGT forged offline was never requested from the Key Distribution Center: event 4769 exists, the corresponding 4768 is missing. Inconsistencies visible on 4769 round out the search: a user object that does not exist in

*Disproof:* This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "The KRBTGT object being the root of trust for the domain, its compromise requires a coordi".

**The only approach proposed is to place a canary GPP password belonging to a user object that should never be used, and to monitor any authentication by that object.**

962486, released in 2014 under bulletin MS14-025, removed the ability to create them but did not remove existing cpasswords, whose deletion remains a manual step never carried out in many environments. 

 The guidance is categorical about detection: there is no effective method. There are too many ways to reach SYSVOL and the directory is read constantly as part of normal group policy processing. The only approach proposed is to place a canary GPP password belonging to a user object that should never be used, and to monitor any authentication by that object. 

 Mitigation is simple and carries no operational cost: remove all GPP passwords and apply patch 2962486. 

 AD CS compromise 

 AD CS implements Microsoft’s public key infrastructure. A misconfigured certificate template opens a direct escalation route. The configuration known as ESC1 combines four conditions: enrolment rights open to user objects, an extended key usage, EKU (21), that enables

*Disproof:* This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "The only approach proposed is to place a canary GPP password belonging to a user object th".

**There is a single mitigating control: require Kerberos pre-authentication on all user objects.**

entication setting. 

 
 Point of caution 
 Table 2 of the guidance places the encryption type observation in the row for event 4768, but its text refers twice to event 4769. Since the TGT request is event 4768, that is the identifier on which the Ticket Encryption Type field must be filtered for AS-REP Roasting. A rule written by copying the text of the guidance would watch the wrong event. 
 

 There is a single mitigating control: require Kerberos pre-authentication on all user objects. For the rare cases where it must be waived, the guidance calls for minimum privileges, exclusion from highly privileged groups, and a password of at least 30 characters for service accounts and at least 15 characters for users. 

 Password spraying 

 Password spraying tries a single password, or a small set of passwords, against a wide list of user objects, staying below the lockout threshold. T

*Disproof:* Refuted when: the same behaviour is absent when the single named control in the claim is present, and the control is shown to be present rather than assumed. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“There is a single mitigating control: require Kerberos pre-authentication on all”) does not occur under a test that isolates that control.

**If the relying party, Microsoft Entra ID for instance, trusts the identity provider’s MFA claims, the forged response bypasses MFA and survives a password change on the impersonated object.**

alicious actor who obtains that key forges responses and reaches the services for which AD FS acts as identity provider. The technique requires three elements: the token signing certificate and its private key, the Distributed Key Manager, DKM (29), master key held in AD DS and needed to decrypt the certificate, and the list of services concerned. 

 The effect reaches beyond the internal estate. If the relying party, Microsoft Entra ID for instance, trusts the identity provider’s MFA claims, the forged response bypasses MFA and survives a password change on the impersonated object. The technique was used in the supply chain compromise involving SolarWinds in 2019 and has been used since. The guidance notes that a relying party can be configured to require MFA even in the presence of an identity provider claim, which closes that door. 

 
 
 
 Event Source Signal 
 
 
 70 AD FS servers Certificate private key exported, the first step of the technique 
 307 AD FS servers Fede

*Disproof:* This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "If the relying party, Microsoft Entra ID for instance, trusts the identity provider’s MFA ".

**Twelve other vulnerable configurations, ESC2 through ESC13, exist and are not detailed in the guidance, which refers readers to work by SpecterOps, Mandiant and Microsoft.**

alternative name, SAN (22), and the absence of certificate manager approval. Any user object can then request a certificate on behalf of a privileged object and authenticate as it. 

 The resulting certificate remains valid even if the impersonated object changes its password. It is invalidated only by expiry or revocation, and revocation is not systematically performed during incident response. Twelve other vulnerable configurations, ESC2 through ESC13, exist and are not detailed in the guidance, which refers readers to work by SpecterOps, Mandiant and Microsoft. 

 AD CS auditing is not enabled by default. Object access auditing for Certificate Services must be enabled under Advanced Audit Policy Configuration, then every available option must be selected on the Auditing tab in the certificate authority properties. Once collection is in place, nine events are usable. 

 
 
 
 Event Source Signal 
 
 
 39 Domain Controllers No strong certificate mapping f

*Disproof:* This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Twelve other vulnerable configurations, ESC2 through ESC13, exist and are not detailed in ".

**The Sync object holds the Directory Synchronisation Accounts role, which lets it create, modify and delete user objects and set passwords.**

crosoft Entra Connect compromise 

 Microsoft Entra Connect synchronises Active Directory with Microsoft Entra ID. The default configuration, password hash synchronisation, PHS (30), creates two objects: a user object in Active Directory prefixed MSOL, and an object in Entra ID prefixed Sync. The MSOL object holds replication permissions, which is to say exactly the permissions a DCSync requires. The Sync object holds the Directory Synchronisation Accounts role, which lets it create, modify and delete user objects and set passwords. 

 Administrative access to a Microsoft Entra Connect server allows the cleartext passwords of both objects to be extracted, notably with AADInternals. The first yields the hashes of the whole directory, the second allows the password of an object holding the Global Administrator role to be set, and therefore full control of the cloud estate. The other common configuration, pass-through authentic

*Disproof:* This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "The Sync object holds the Directory Synchronisation Accounts role, which lets it create, m".

**For all exercises, we will assume that the target company Inlanefreight has hired us to perform an in-depth penetration test with a heavy focus on AD security, where stealth and bypassing stringent security controls are not a requirement.**

ls of the assessment. The tools listed above will be covered in other modules. 
 
 Next Steps 
 During this module, we will target a fictional company called INLANEFREIGHT with the internal domain INLANEFREIGHT.LOCAL . The module sections will build on each other, culminating in a mock penetration testing skills assessment to showcase our skills before moving on to the next module in this series. For all exercises, we will assume that the target company Inlanefreight has hired us to perform an in-depth penetration test with a heavy focus on AD security, where stealth and bypassing stringent security controls are not a requirement. 
 
 Module Exercises 
 Throughout this module, you will connect to various target hosts via the Remote Desktop Protocol (RDP) to complete the exercises. Any necessary credentials will be provided with each exercise, and the RDP connection can be made via xfreerdp from the Pwnbox as follows: 
 xfreerdp /v: /u:htb-student /p: 
 
 Any necessary tools can be found in the c:\tools directory after logg

*Disproof:* This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "For all exercises, we will assume that the target company Inlanefreight has hired us to pe".

**The configuration known as ESC1 combines four conditions: enrolment rights open to user objects, an extended key usage, EKU (21), that enables client authentication, the ability for the requester to supply their own subject alternative name, SAN (22), and the absence of certificate manager approval.**

posed is to place a canary GPP password belonging to a user object that should never be used, and to monitor any authentication by that object. 

 Mitigation is simple and carries no operational cost: remove all GPP passwords and apply patch 2962486. 

 AD CS compromise 

 AD CS implements Microsoft’s public key infrastructure. A misconfigured certificate template opens a direct escalation route. The configuration known as ESC1 combines four conditions: enrolment rights open to user objects, an extended key usage, EKU (21), that enables client authentication, the ability for the requester to supply their own subject alternative name, SAN (22), and the absence of certificate manager approval. Any user object can then request a certificate on behalf of a privileged object and authenticate as it. 

 The resulting certificate remains valid even if the impersonated object changes its password. It is invalidated only by expiry or revocation, and revocation is not systematically performed during incident response. Twelve other vulnerable configurations, ESC2 through ESC13, exist and are not

*Disproof:* This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "The configuration known as ESC1 combines four conditions: enrolment rights open to user ob".

**The badPasswordTime attribute complements these events: if several user objects share the same date and time of last failure, or very close values, spraying is likely.**

n failure over SMB, the default protocol of common tools 
 4648 Source workstation or server Logon with explicit credentials; absent if the actor tunnels in from their own infrastructure 
 4740 Domain Controllers Account lockout; several lockouts close together are an indicator 
 4771 Domain Controllers Kerberos pre-authentication failure, with Failure Code 0x18 for an incorrect password 
 
 
 

 The badPasswordTime attribute complements these events: if several user objects share the same date and time of last failure, or very close values, spraying is likely. On the mitigation side, the guidance calls for passwords of at least 30 characters for local administrator, service and break glass accounts, managed through Local Administrator Password Solution, LAPS (17), where possible; four random words and at least 15 characters for single-factor authentication; lockout after at most five failed attempts, except for break glass accounts; randomly generated

*Disproof:* Refuted when: the same behaviour is absent when the single named control in the claim is present, and the control is shown to be present rather than assumed. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“The badPasswordTime attribute complements these events: if several user objects ”) does not occur under a test that isolates that control.

**The KRBTGT object’s hash allows arbitrary TGTs to be forged.**

bypassing the file lock. 

 Mitigation is about hardening Domain Controllers: access limited to the privileged users who need it, access pathways restricted to jump servers and secure admin workstations, backups encrypted and reserved to backup administrators, no service or application unrelated to security, centralised logging, Print Spooler disabled, SMB version 1 disabled. 

 Golden Ticket 

 The KRBTGT object’s hash allows arbitrary TGTs to be forged. It does not need to be cracked, since it is the hash itself that encrypts the tickets. That hash is obtained through DCSync or by dumping ntds.dit . The KRBTGT object being the root of trust for the domain, its compromise requires a coordinated reset of every user and computer object password, and may lead to rebuilding the domain. 

 The most robust detection is detection by absence. Normal Kerb

*Disproof:* This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "The KRBTGT object’s hash allows arbitrary TGTs to be forged.".

**Event 4625 adds to it: AS-REP Roasting can be executed before any authentication, without a valid user object, which produces a logon failure while the ticket is still issued.**

nfigured not to require Kerberos pre-authentication. The ticket granting ticket, TGT (13), is then returned in the authentication server response, encrypted with the password hash, and cracks in the same way. That configuration exists only to support systems older than Kerberos version 5. 

 Detection rests on event 4768, generated on a TGT request, with the same volume logic over a short window. Event 4625 adds to it: AS-REP Roasting can be executed before any authentication, without a valid user object, which produces a logon failure while the ticket is still issued. Correlating 4625 with 4768 establishes whether the technique was executed in the context of a valid user object. Events 4738 and 5136 record changes to the pre-authentication setting. 

 
 Point of caution 
 Table 2 of the guidance places the encryption type observation in the row for event 4768, but its text refers twice to event 4769. Since the TGT request is event 4768, that is the identifier

*Disproof:* Refuted when: the value is bound as a parameter or written through the framework's own encoder, so the interpreter never sees attacker text as syntax. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“Event 4625 adds to it: AS-REP Roasting can be executed before any authentication”) does not occur under a test that isolates that control.

**The msDS-KeyCredentialLink attribute, introduced with the Windows Server 2016 Domain Functional Level to support passwordless authentication including Windows Hello for Business, accepts key credentials.**

uration, removing the Enrollee Supplies Subject flag, restricting standard user object permissions, removing the EDITF_ATTRIBUTESUBJECTALTNAME2 flag on the certificate authority, requiring certificate manager approval, removing EKUs that enable authentication, and the protection of the servers themselves, classified as Tier 0. 

 Shadow Credentials 

 This is the technique added in this revision. The msDS-KeyCredentialLink attribute, introduced with the Windows Server 2016 Domain Functional Level to support passwordless authentication including Windows Hello for Business, accepts key credentials. A malicious actor with sufficient permissions over an object adds their own key credential, authenticates by certificate and obtains a TGT as that object. 

 Two properties make it a persistence technique as much as an escalation one. The key remains valid after the target object’s password changes. Multiple key credentials can coexist on a single object, so a legitimate key and a malicious one s

*Disproof:* This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "The msDS-KeyCredentialLink attribute, introduced with the Windows Server 2016 Domain Funct".

**The first yields the hashes of the whole directory, the second allows the password of an object holding the Global Administrator role to be set, and therefore full control of the cloud estate.**

c. The MSOL object holds replication permissions, which is to say exactly the permissions a DCSync requires. The Sync object holds the Directory Synchronisation Accounts role, which lets it create, modify and delete user objects and set passwords. 

 Administrative access to a Microsoft Entra Connect server allows the cleartext passwords of both objects to be extracted, notably with AADInternals. The first yields the hashes of the whole directory, the second allows the password of an object holding the Global Administrator role to be set, and therefore full control of the cloud estate. The other common configuration, pass-through authentication, PTA (31), is compromised differently: the authentication process between Entra ID and Active Directory is hijacked, which allows authentication as any object without knowing its password, and keeps a cleartext copy of the passwords presented. 

 Detection combines seven events collected on Microsoft Entra Connect servers: 611 for a pass

*Disproof:* Refuted when: the action is unreachable for the lower-privileged identity tested, i.e. the same request returns an authorisation failure rather than the elevated result. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“The first yields the hashes of the whole directory, the second allows the passwo”) does not occur under a test that isolates that control.

**On mitigation, the AD FS service account must be a gMSA, which gives it a 120-character password rotated every thirty days and puts it out of reach of both Kerberoasting and cracking, and it must serve no other purpose.**

er, thumbnailPhoto attribute, GUID {8d3bca50-1d7e-11d0-a081-00aa006c33ed} 
 
 
 

 Access to the DKM container deserves particular attention: that attribute should be read only periodically, and only by the AD FS service account. Every occurrence calls for a check. Configuring directory service access auditing with Read All Properties on the AD FS parent and child containers is a prerequisite. 

 On mitigation, the AD FS service account must be a gMSA, which gives it a 120-character password rotated every thirty days and puts it out of reach of both Kerberoasting and cracking, and it must serve no other purpose. Token signing and encryption certificates must be rotated every twelve months, or sooner on compromise, twice in rapid succession in order to revoke existing tokens. 

 Microsoft Entra Connect compromise 

 Microsoft Entra Connect synchronises Active Directory with Microsoft Entra ID. The default configuration, password hash synchronisation, PHS (30), creates two objects: a user object in Active

*Disproof:* Refuted when: the same behaviour is absent when the single named control in the claim is present, and the control is shown to be present rather than assumed. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“On mitigation, the AD FS service account must be a gMSA, which gives it a 120-ch”) does not occur under a test that isolates that control.

**Administrative access to a Microsoft Entra Connect server allows the cleartext passwords of both objects to be extracted, notably with AADInternals.**

password hash synchronisation, PHS (30), creates two objects: a user object in Active Directory prefixed MSOL, and an object in Entra ID prefixed Sync. The MSOL object holds replication permissions, which is to say exactly the permissions a DCSync requires. The Sync object holds the Directory Synchronisation Accounts role, which lets it create, modify and delete user objects and set passwords. 

 Administrative access to a Microsoft Entra Connect server allows the cleartext passwords of both objects to be extracted, notably with AADInternals. The first yields the hashes of the whole directory, the second allows the password of an object holding the Global Administrator role to be set, and therefore full control of the cloud estate. The other common configuration, pass-through authentication, PTA (31), is compromised differently: the authentication process between Entra ID and Active Directory is hijacked, which allows authentication a

*Disproof:* This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Administrative access to a Microsoft Entra Connect server allows the cleartext passwords o".

**Pass-the-hash authenticates with a recovered NTLM hash directly as the password, so no plaintext is needed to open a session.**

In practice on HTB this shows up as: | ------------------------------------------------------------ | ------------------------------------------------------------ |
| `responder -h`                                               | Used to display the usage instructions and various options available in `Responder` from a Linux-based host. |
| `hashcat -m 5600 forend_ntlmv2 /usr/share/wordlists/rockyou.txt` | Uses `hashcat` to crack `NTLMv2` (`-m`) hashes that were captured by responder and saved in a file (`frond_ntlmv2`). The cracking is done based on a specified wordlist. |
| `Import-Module .\Inveigh.ps1`                                | Using the `Import-Module` PowerShell cmd-let to import the Windows-based tool `Inveigh.ps1`. |
| `(Get-Command Invoke-Inveigh).Parameters`                    | Used to output many of the options & functionality available with `Invoke-Inveigh`. Peformed from a Windows-based host. |

Write-up provenance: ajcriado/htb-writeups :: Academy/CPTS/Content Summary/13. Active Directory Enumeration & Attacks.md (6753 words, classified network).

*Disproof:* Refuted when the account is disabled, expired, or restricted so that NTLM authentication is refused, which stops the hash from being usable as a credential.

**NTLM and Kerberos protocols accept a key as the credential rather than a secret the user holds, so a captured NTLM hash or service ticket is itself a replayable authentication artifact and needs no password recovery.**

Pass-the-hash removes the cracking step entirely. Where the protocol's proof is keyed on the NTLM hash, possessing the hash is possession of the credential, and it can be presented directly to any service accepting that hash. Pass-the-ticket is the same property one layer up: a valid Kerberos service ticket is already a bearer artifact for that service, so capturing and injecting it is a credential use, not a forgery. The practical consequence for hunting is that both techniques leave authentication SUCCESS events with no matching interactive logon — the tell is the absence of a preceding interactive session for that principal, not the presence of anything unusual in the logon itself. This also sets the boundary of the class: a protocol that requires a secret not derivable from the hash (smartcard/PIN, or a key the user holds) is outside it.

*Disproof:* If the hash or ticket is rejected by the target because channel binding, signing, or an authentication level requirement is enforced, then replay does not authenticate and the finding collapses to a failed logon.

## Variations

Not yet researched.

## Technology / Framework Considerations

Not yet researched.

## API Considerations

Not yet researched.

## Attack Chains

- `chain.pass_the_hash.auto.01` — pass_the_hash: observe, exercise, confirm (goal: `Establish, exercise and confirm a pass_the_hash condition on an authorised target without relying on anyone else's data.`)

## Real-World Examples

Not yet researched.

## Common False Positives

**A pass-the-hash attempt that returns access denied for a non-RID-500 local account is the protection WORKING, not a partial authentication bypass; do not file it as a finding unless LocalAccountTokenFilterPolicy is set to 0x1 or the hash authenticates as a RID-500 account, because token creation strips privileges from non-default administrator accounts by design.**

The observable that triggers this false positive is a pass-the-hash attempt returning access denied for a local account that is not RID 500, written up as a partial authentication bypass or a weakened hash policy. It is the opposite: token creation strips administrative privileges from non-default administrator accounts by design, so the refusal is the protection working exactly as intended. The single condition that inverts this is LocalAccountTokenFilterPolicy set to 0x1 on the target, which disables that stripping and lets a non-RID-500 hash authenticate with full local administrative rights. This rule rejects the denied hash as a finding and redirects the check to that one registry value, which turns a noise report into either a clean close or a real policy finding.

*Disproof:* The same non-RID-500 hash authenticates successfully against the target, which happens when LocalAccountTokenFilterPolicy is set to 0x1 on that host and means the protection that should have stripped the privileges is disabled.

**Recovering an NT hash from NTDS.dit or LSA secrets is credential access, not pass-the-hash; reuse on another host must be demonstrated.**

Discard when the report ends at the dump: NTDS.dit and LSA secret extraction only produce hashes, and pass-the-hash additionally requires that hash to be presented to a second service for a session. It survives when the recovered hash authenticated to a remote host and produced an authenticated session there.

*Disproof:* Would be wrong where the extracted hash set is domain-wide and immediately usable against every service, making the dump alone equivalent to full access.

**An NTLM type 3 network logon with no preceding interactive logon is normal for a service account and is not pass-the-hash evidence.**

Discard when the only signal is event 4624 logon type 3 with NTLM from a service account, because the source states legitimate connections normally have an interactive logon first except for service accounts. It survives when the same NTLM logon type follows from a named user account with no interactive session anywhere in the log, or when the hash was replayed to open a session.

*Disproof:* Would be wrong in a domain that forbids all NTLM, where any type 3 NTLM logon is anomalous regardless of account type.

## Validation

**A pass-the-hash finding requires a successful authentication made with the obtained hash, and recovering the hash alone - by replication or by capture - is not pass-the-hash.**

Two distinct acts are routinely collapsed. Obtaining NT hashes is a credential-access result: in a real intrusion the operator replicates directory objects to impersonate the domain controller once an account with sufficient privileges is in hand, which yields password hashes for domain accounts. Using one is the pass-the-hash result. The validation that separates them is a replay: take the hash you recovered and attempt to authenticate with it against a service, then correlate the attempt in the target's own logon events. If the replay fails because the target enforces full signing or channel binding, or because the account's NTLM is disabled, the recovery finding stands on its own and the pass-the-hash finding must be dropped. Reporting the second as established from the first is the single most common inflation in this class.

*Disproof:* If every attempt to authenticate with the recovered NT hash against any target service fails and the target logs no NTLM authentication for that account from the operator's host, then no hash was used and the pass-the-hash claim is false even though credential recovery is real.

## Impact

Not yet researched.

## Related Bug Classes

Not yet researched.

## References

- **academy.hackthebox.com** (docs)
  - <https://academy.hackthebox.com/course/preview/active-directory-powerview>
- **attack.mitre.org** (taxonomy)
  - <https://attack.mitre.org/techniques/T1550/002/>
  - <https://attack.mitre.org/techniques/T1550/003/>
- **blog.marcfredericgomez.com** (writeup)
  - <https://blog.marcfredericgomez.com/active-directory-the-2026-revision-of-the-cisa-guide/>
- **cwe.mitre.org** (cwe)
  - <https://cwe.mitre.org/data/definitions/294.html>
- **ired.team** (writeup)
  - <https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/pass-the-hash-with-machine-accounts.md>
  - <https://www.ired.team/offensive-security/privilege-escalation/pass-the-hash-privilege-escalation-with-invoke-wmiexec.md>
- **learn.microsoft.com** (docs)
  - <https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/>
  - <https://learn.microsoft.com/en-us/windows-server/storage/file-server/smb-signing>
- **microsoft.com** (research)
  - <https://www.microsoft.com/en-us/security/blog/2022/10/26/how-to-prevent-lateral-movement-attacks-using-microsoft-365-defender/>
- **nccgroup.com** (research)
  - <https://www.nccgroup.com/research/defending-your-directory-an-expert-guide-to-mitigating-pass-the-hash-attacks-in-active-directory/>
- **rapid7.com** (writeup)
  - <https://www.rapid7.com/blog/post/pentales-exploiting-an-internal-network-loud-and-proud/>
- **raw.githubusercontent.com** (writeup)
  - <https://raw.githubusercontent.com/ajcriado/htb-writeups/main/Academy/CPTS/Content%20Summary/13.%20Active%20Directory%20Enumeration%20%26%20Attacks.md>
- **redcanary.com** (research)
  - <https://redcanary.com/threat-detection-report/techniques/os-credential-dumping/>
- **securelist.com** (research)
  - <https://securelist.com/tr/nighteagle-apt-ghostcontainer-and-tunneling/121323/>
- **thehacker.recipes** (cheatsheet)
  - <https://www.thehacker.recipes/ad/movement/credentials/dumping/ntds>
- **zscaler.com** (writeup)
  - <https://www.zscaler.com/blogs/product-insights/active-directory-kerberoasting-deception-detection>

Every item above is gated on >= 2 distinct publisher hosts (`wks/quality.py`, rule R1). Publisher diversity, not citation count, is what makes these corroborated.
