<!-- GENERATED from db/wks.db — do not edit -->
# Password Attacks against Active Directory

## Definition

Directory authentication is online and per-account, so many accounts against one password succeeds where many passwords against one account triggers lockout.

- **CWE:** CWE-521
- **OWASP:** None
- **Surface:** ad
- **Aliases:** ["password spraying", "spray", "password attack", "password quality", "credential stuffing", "password reuse", "lockout evasion"]

Canonical home for `password_attacks`. Rendered from `db/wks.db` by `tools/taxonomy/build_taxonomy.py` — edit the rows, not this file.

## Root Cause

Not yet researched.

## Preconditions

Not yet researched.

## Attack Surface

Surface: **ad**.

The entry points and enabling conditions for this surface are enumerated under **Preconditions**; the observable signals are under **Detection**.

## Detection

Not yet researched.

## Exploitation

**The variant applies to user objects configured not to require Kerberos pre-authentication.**

PN; create them as group Managed Service Accounts, gMSA (11), which enforce a 120-character password on automatic rotation, or failing that a password of at least 30 characters, unique and managed; grant them the minimum privileges needed and keep them out of highly privileged groups; enable AES (12) encryption, since Active Directory uses RC4 by default for service tickets. 

 AS-REP Roasting 

 The variant applies to user objects configured not to require Kerberos pre-authentication. The ticket granting ticket, TGT (13), is then returned in the authentication server response, encrypted with the password hash, and cracks in the same way. That configuration exists only to support systems older than Kerberos version 5. 

 Detection rests on event 4768, generated on a TGT request, with the same volume logic over a short window. Event 4625 adds to it: AS-REP Roasting can be execut

*Disproof:* Refuted when: the same behaviour is absent when the single named control in the claim is present, and the control is shown to be present rather than assumed. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“The variant applies to user objects configured not to require Kerberos pre-authe”) does not occur under a test that isolates that control.

**Event 4625 adds to it: AS-REP Roasting can be executed before any authentication, without a valid user object, which produces a logon failure while the ticket is still issued.**

nfigured not to require Kerberos pre-authentication. The ticket granting ticket, TGT (13), is then returned in the authentication server response, encrypted with the password hash, and cracks in the same way. That configuration exists only to support systems older than Kerberos version 5. 

 Detection rests on event 4768, generated on a TGT request, with the same volume logic over a short window. Event 4625 adds to it: AS-REP Roasting can be executed before any authentication, without a valid user object, which produces a logon failure while the ticket is still issued. Correlating 4625 with 4768 establishes whether the technique was executed in the context of a valid user object. Events 4738 and 5136 record changes to the pre-authentication setting. 

 
 Point of caution 
 Table 2 of the guidance places the encryption type observation in the row for event 4768, but its text refers twice to event 4769. Since the TGT request is event 4768, that is the identifier

*Disproof:* This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Event 4625 adds to it: AS-REP Roasting can be executed before any authentication, without ".

**There is a single mitigating control: require Kerberos pre-authentication on all user objects.**

entication setting. 

 
 Point of caution 
 Table 2 of the guidance places the encryption type observation in the row for event 4768, but its text refers twice to event 4769. Since the TGT request is event 4768, that is the identifier on which the Ticket Encryption Type field must be filtered for AS-REP Roasting. A rule written by copying the text of the guidance would watch the wrong event. 
 

 There is a single mitigating control: require Kerberos pre-authentication on all user objects. For the rare cases where it must be waived, the guidance calls for minimum privileges, exclusion from highly privileged groups, and a password of at least 30 characters for service accounts and at least 15 characters for users. 

 Password spraying 

 Password spraying tries a single password, or a small set of passwords, against a wide list of user objects, staying below the lockout threshold. T

*Disproof:* Refuted when: the same behaviour is absent when the single named control in the claim is present, and the control is shown to be present rather than assumed. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“There is a single mitigating control: require Kerberos pre-authentication on all”) does not occur under a test that isolates that control.

**Second point: MFA is largely ineffective against this technique once initial access has been obtained, because authentication can be made directly to a Domain Controller over NTLM (14), which does not support it.**

Administrator account is not subject to the account lockout threshold. Even when it reports as locked out, it can still be authenticated to if the correct password is supplied, which clears the locked status and resets the bad password count. It should therefore be treated as a break glass account, with a password of at least 30 characters, marked as sensitive and not delegable, and monitored. 

 Second point: MFA is largely ineffective against this technique once initial access has been obtained, because authentication can be made directly to a Domain Controller over NTLM (14), which does not support it. The guidance recommends disabling NTLM and, where that is not possible, enabling LDAP (15) channel binding, extended protection for authentication and SMB (16) signing. 

 
 
 
 Event Source Signal 
 
 
 2889 Domain Controllers Unsigned LDAP bind, one per attempt when the spray runs over LDAP 
 4624 Domain Controllers Successful logon; near-simultaneity with 4625 events marks a successful attempt

*Disproof:* This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Second point: MFA is largely ineffective against this technique once initial access has be".

**The badPasswordTime attribute complements these events: if several user objects share the same date and time of last failure, or very close values, spraying is likely.**

n failure over SMB, the default protocol of common tools 
 4648 Source workstation or server Logon with explicit credentials; absent if the actor tunnels in from their own infrastructure 
 4740 Domain Controllers Account lockout; several lockouts close together are an indicator 
 4771 Domain Controllers Kerberos pre-authentication failure, with Failure Code 0x18 for an incorrect password 
 
 
 

 The badPasswordTime attribute complements these events: if several user objects share the same date and time of last failure, or very close values, spraying is likely. On the mitigation side, the guidance calls for passwords of at least 30 characters for local administrator, service and break glass accounts, managed through Local Administrator Password Solution, LAPS (17), where possible; four random words and at least 15 characters for single-factor authentication; lockout after at most five failed attempts, except for break glass accounts; randomly generated

*Disproof:* This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "The badPasswordTime attribute complements these events: if several user objects share the ".

**The only approach proposed is to place a canary GPP password belonging to a user object that should never be used, and to monitor any authentication by that object.**

962486, released in 2014 under bulletin MS14-025, removed the ability to create them but did not remove existing cpasswords, whose deletion remains a manual step never carried out in many environments. 

 The guidance is categorical about detection: there is no effective method. There are too many ways to reach SYSVOL and the directory is read constantly as part of normal group policy processing. The only approach proposed is to place a canary GPP password belonging to a user object that should never be used, and to monitor any authentication by that object. 

 Mitigation is simple and carries no operational cost: remove all GPP passwords and apply patch 2962486. 

 AD CS compromise 

 AD CS implements Microsoft’s public key infrastructure. A misconfigured certificate template opens a direct escalation route. The configuration known as ESC1 combines four conditions: enrolment rights open to user objects, an extended key usage, EKU (21), that enables

*Disproof:* Refuted when: the same behaviour is absent when the single named control in the claim is present, and the control is shown to be present rather than assumed. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“The only approach proposed is to place a canary GPP password belonging to a user”) does not occur under a test that isolates that control.

**The configuration known as ESC1 combines four conditions: enrolment rights open to user objects, an extended key usage, EKU (21), that enables client authentication, the ability for the requester to supply their own subject alternative name, SAN (22), and the absence of certificate manager approval.**

posed is to place a canary GPP password belonging to a user object that should never be used, and to monitor any authentication by that object. 

 Mitigation is simple and carries no operational cost: remove all GPP passwords and apply patch 2962486. 

 AD CS compromise 

 AD CS implements Microsoft’s public key infrastructure. A misconfigured certificate template opens a direct escalation route. The configuration known as ESC1 combines four conditions: enrolment rights open to user objects, an extended key usage, EKU (21), that enables client authentication, the ability for the requester to supply their own subject alternative name, SAN (22), and the absence of certificate manager approval. Any user object can then request a certificate on behalf of a privileged object and authenticate as it. 

 The resulting certificate remains valid even if the impersonated object changes its password. It is invalidated only by expiry or revocation, and revocation is not systematically performed during incident response. Twelve other vulnerable configurations, ESC2 through ESC13, exist and are not

*Disproof:* This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "The configuration known as ESC1 combines four conditions: enrolment rights open to user ob".

**Twelve other vulnerable configurations, ESC2 through ESC13, exist and are not detailed in the guidance, which refers readers to work by SpecterOps, Mandiant and Microsoft.**

alternative name, SAN (22), and the absence of certificate manager approval. Any user object can then request a certificate on behalf of a privileged object and authenticate as it. 

 The resulting certificate remains valid even if the impersonated object changes its password. It is invalidated only by expiry or revocation, and revocation is not systematically performed during incident response. Twelve other vulnerable configurations, ESC2 through ESC13, exist and are not detailed in the guidance, which refers readers to work by SpecterOps, Mandiant and Microsoft. 

 AD CS auditing is not enabled by default. Object access auditing for Certificate Services must be enabled under Advanced Audit Policy Configuration, then every available option must be selected on the Auditing tab in the certificate authority properties. Once collection is in place, nine events are usable. 

 
 
 
 Event Source Signal 
 
 
 39 Domain Controllers No strong certificate mapping f

*Disproof:* Refuted when: the response is byte-identical to the baseline when the same request is made without the crafted input. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“Twelve other vulnerable configurations, ESC2 through ESC13, exist and are not de”) does not occur under a test that isolates that control.

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

**The only approach proposed is to place a canary GPP password belonging to a user object that should never be used, and to monitor any authentication by that object.**

962486, released in 2014 under bulletin MS14-025, removed the ability to create them but did not remove existing cpasswords, whose deletion remains a manual step never carried out in many environments. 

 The guidance is categorical about detection: there is no effective method. There are too many ways to reach SYSVOL and the directory is read constantly as part of normal group policy processing. The only approach proposed is to place a canary GPP password belonging to a user object that should never be used, and to monitor any authentication by that object. 

 Mitigation is simple and carries no operational cost: remove all GPP passwords and apply patch 2962486. 

 AD CS compromise 

 AD CS implements Microsoft’s public key infrastructure. A misconfigured certificate template opens a direct escalation route. The configuration known as ESC1 combines four conditions: enrolment rights open to user objects, an extended key usage, EKU (21), that enables

*Disproof:* Refuted when: the same behaviour is absent when the single named control in the claim is present, and the control is shown to be present rather than assumed. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“The only approach proposed is to place a canary GPP password belonging to a user”) does not occur under a test that isolates that control.

**There is a single mitigating control: require Kerberos pre-authentication on all user objects.**

entication setting. 

 
 Point of caution 
 Table 2 of the guidance places the encryption type observation in the row for event 4768, but its text refers twice to event 4769. Since the TGT request is event 4768, that is the identifier on which the Ticket Encryption Type field must be filtered for AS-REP Roasting. A rule written by copying the text of the guidance would watch the wrong event. 
 

 There is a single mitigating control: require Kerberos pre-authentication on all user objects. For the rare cases where it must be waived, the guidance calls for minimum privileges, exclusion from highly privileged groups, and a password of at least 30 characters for service accounts and at least 15 characters for users. 

 Password spraying 

 Password spraying tries a single password, or a small set of passwords, against a wide list of user objects, staying below the lockout threshold. T

*Disproof:* Refuted when: the same behaviour is absent when the single named control in the claim is present, and the control is shown to be present rather than assumed. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“There is a single mitigating control: require Kerberos pre-authentication on all”) does not occur under a test that isolates that control.

**Twelve other vulnerable configurations, ESC2 through ESC13, exist and are not detailed in the guidance, which refers readers to work by SpecterOps, Mandiant and Microsoft.**

alternative name, SAN (22), and the absence of certificate manager approval. Any user object can then request a certificate on behalf of a privileged object and authenticate as it. 

 The resulting certificate remains valid even if the impersonated object changes its password. It is invalidated only by expiry or revocation, and revocation is not systematically performed during incident response. Twelve other vulnerable configurations, ESC2 through ESC13, exist and are not detailed in the guidance, which refers readers to work by SpecterOps, Mandiant and Microsoft. 

 AD CS auditing is not enabled by default. Object access auditing for Certificate Services must be enabled under Advanced Audit Policy Configuration, then every available option must be selected on the Auditing tab in the certificate authority properties. Once collection is in place, nine events are usable. 

 
 
 
 Event Source Signal 
 
 
 39 Domain Controllers No strong certificate mapping f

*Disproof:* Refuted when: the same behaviour is absent when the single named control in the claim is present, and the control is shown to be present rather than assumed. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“Twelve other vulnerable configurations, ESC2 through ESC13, exist and are not de”) does not occur under a test that isolates that control.

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

**Password spraying succeeds where password brute force fails because it inverts the two axes — one password against many accounts — so per-account lockout thresholds never trigger while the total attempt count stays high.**

The reason spraying works is arithmetic about how the control is written. Account lockout counts failed attempts per account, so trying many passwords against one account trips it and trying one password against many accounts does not. A spray run is therefore invisible to a per-account threshold and visible only as a many-accounts-one-password pattern, or as a low per-account rate sustained for days — which is why throttling to avoid alerting thresholds is part of the technique rather than an afterthought. Two operational consequences: lockout is not an effective control against spraying at all, and alerting must be built on the cross-account view (distinct accounts failing from one source in a window) rather than the per-account view. Defence in depth is multi-factor, which defeats the technique because the sprayed password is only one of the required factors.

*Disproof:* If a spray-shaped run (one password, many distinct accounts, below per-account lockout) produces no successful authentication and every account still enforces multi-factor, then the technique found nothing and must not be reported as a compromise.

## Variations

Not yet researched.

## Technology / Framework Considerations

Not yet researched.

## API Considerations

Not yet researched.

## Attack Chains

- `chain.password_attacks.auto.01` — password_attacks: observe, exercise, confirm (goal: `Establish, exercise and confirm a password_attacks condition on an authorised target without relying on anyone else's data.`)

## Real-World Examples

Not yet researched.

## Common False Positives

**One successful authentication during a spray is not a spraying finding; discard unless the same password hit many accounts.**

Discard when a single account authenticated during the run: spraying is defined as trying a few passwords against a set of usernames to stay under the lockout threshold, so one hit proves nothing about breadth. It survives when the same password succeeded on multiple accounts, or when shared badPasswordTime values show the pattern.

*Disproof:* Would be wrong where the single success landed on an account whose password was already known to the client, for example a documented test account.

**Password spraying that stays under the lockout threshold is expected attack behaviour, not evidence that the password policy is weak.**

Discard when the report cites only that a spray was executed against the domain: spraying deliberately uses one password per account so no account locks, which is the technique's design and not a policy failure. It survives when accounts actually locked out or a real weak password was recovered.

*Disproof:* Would be wrong in a forest with no lockout policy configured at all, where the same spray becomes an unmitigated brute-force path.

## Validation

**Password spraying is detected by correlating failed authentications across many accounts that share a narrow time window and a common source, not by a single failed logon.**

A spray is a pattern across the account population, not a property of one authentication. The technique tries one password, or a small set, against many user objects while staying below the lockout threshold, which produces a cluster of failures across different accounts rather than repeated failures against one account. The test should group failed logons by source address, password, and time window, then compare the affected account count with the domain lockout policy. A single failed logon is noise; repeated failures against one account are brute force; a broad, low-volume cluster from one source is the spray signature.

*Disproof:* The spray finding fails when the failures involve only one account, when each account is tried with many different passwords, or when the failed events have no common source or narrow time window.

## Impact

Not yet researched.

## Related Bug Classes

Not yet researched.

## References

- **attack.mitre.org** (taxonomy)
  - <https://attack.mitre.org/techniques/T1110/003/>
- **blog.marcfredericgomez.com** (writeup)
  - <https://blog.marcfredericgomez.com/active-directory-the-2026-revision-of-the-cisa-guide/>
- **cheatsheetseries.owasp.org** (cheatsheet)
  - <https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html>
- **pentestlab.blog** (writeup)
  - <https://pentestlab.blog/2019/09/05/microsoft-exchange-password-spraying/>
- **thehacker.recipes** (cheatsheet)
  - <https://www.thehacker.recipes/ad/movement/credentials/bruteforcing/spraying>
- **ttp.parzival.sh** (cheatsheet)
  - <https://ttp.parzival.sh/pentesting/infrastructure/active-directory/password-spraying>

Every item above is gated on >= 2 distinct publisher hosts (`wks/quality.py`, rule R1). Publisher diversity, not citation count, is what makes these corroborated.
