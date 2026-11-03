<!-- GENERATED from db/wks.db — do not edit -->
# Remote Monitoring and Management Abuse

## Definition

RMM agents are installed to bypass network controls, so their reachability and credential handling determine their risk.

- **CWE:** CWE-200
- **OWASP:** None
- **Surface:** net
- **Aliases:** ["rmm", "remote monitoring", "teamviewer", "anydesk", "screenconnect", "remote management tool", "vnc"]

Canonical home for `exposed_rmm`. Rendered from `db/wks.db` by `tools/taxonomy/build_taxonomy.py` — edit the rows, not this file.

## Root Cause

Not yet researched.

## Preconditions

**An exposed RMM or remote-management interface is the precondition for the class, because CISA's directive is specifically about getting networked management interfaces off the internet, so exposure of the listener, not the presence of the tool, is what makes the product remotely usable.**

The primitive gives you: an authenticated-or-not remote management channel on a host. Tenable's position is that CISA Binding Operational Directive 23-02 instructs agencies to get management interfaces off the internet in order to mitigate risk, which defines exposure at the network edge rather than at the agent, and that exposed management interfaces are valuable entry points for attackers. The precondition the next link needs is that a management session, once established, is a full command channel rather than a read-only console: Microsoft describes a campaign where remote control established via RMM tools was then used to run PowerShell and silently install a malicious MSI, which is the shape the next link consumes. Observation that proves this segment: the management listener answers from an untrusted network and the established session accepts a command that changes host state.

*Disproof:* If the listener binds only to loopback or a management VLAN and refuses connections from untrusted networks, the interface is not exposed and the RMM agent running on the host is not a finding; the mere presence of the agent, without a reachable listener, disproves this precondition.

## Attack Surface

Surface: **net**.

The entry points and enabling conditions for this surface are enumerated under **Preconditions**; the observable signals are under **Detection**.

## Detection

Not yet researched.

## Exploitation

**Alternatively, a single sign-on solution may authenticate the user and allow them to remain logged in for a day but require a reauthentication if they try to access their profile page.**

require different authentication stages depending on various environmental and contextual attributes (including but not limited to, the sensitivity of the data for which access is being requested, time of day, user location, IP address, or device fingerprint). 
 For example, an application may require MFA for the first login from a particular device but not for subsequent logins from that device. Alternatively, a single sign-on solution may authenticate the user and allow them to remain logged in for a day but require a reauthentication if they try to access their profile page. 
 Another option is the opposite approach where an application allows low risk access with just something that identifies the device (e.g., a specific mobile device fingerprint, a persistent cookie and browser fingerprint, etc. from the previous IP address) and then gradually requires stronger authentication for more sensitive operations. An example might be to allow someone to trigger something

*Disproof:* This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Alternatively, a single sign-on solution may authenticate the user and allow them to remai".

**Indeed, depending on the implementation, the processing time can be significantly different according to the case (success vs failure) allowing an attacker to mount a time-based attack (delta of some seconds for example).**

nsideration, and the same approach of a generic error message can be applied regarding the case in which the user exists. 
 The objective is to prevent the creation of a discrepancy factor , allowing an attacker to mount a user enumeration action against the application. 
 It is interesting to note that the business logic itself can bring a discrepancy factor related to the processing time taken. Indeed, depending on the implementation, the processing time can be significantly different according to the case (success vs failure) allowing an attacker to mount a time-based attack (delta of some seconds for example). 
 Example using pseudo-code for a login feature: 
 
 First implementation using the "quick exit" approach 
 
 IF USER_EXISTS(username) THEN
 password_hash=HASH(password)
 IS_VALID=LOOKUP_CREDENTIALS_IN_STORE(username, password_hash)
 IF NOT IS_VALID THEN
 RETURN Error("Invalid Username or Password!")
 ENDIF
ELSE
 RETURN Error("Invalid Username or Password!")
ENDIF
 
 It can be clearly seen that i

*Disproof:* This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Indeed, depending on the implementation, the processing time can be significantly differen".

**Avoid requiring periodic password changes; instead, encourage users to pick strong passwords and enable Multifactor Authentication Cheat Sheet (MFA) .**

aximum length. 
 Allow usage of all characters including unicode and whitespace. There should be no password composition rules limiting the type of characters permitted. There should be no requirement for upper or lower case or numbers or special characters. 
 Ensure credential rotation when a password leak occurs, at the time of compromise identification or when authenticator technology changes. Avoid requiring periodic password changes; instead, encourage users to pick strong passwords and enable Multifactor Authentication Cheat Sheet (MFA) . According to NIST guidelines, verifiers should not mandate arbitrary password changes (e.g., periodically). 
 Include a password strength meter to help users create a more complex password 
 zxcvbn-ts library can be used for this purpose. 
 Other language implementations of zxcvbn listed here ; however check the age and maturity of each example before use. 
 
 
 Block common and previously breach

*Disproof:* This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Avoid requiring periodic password changes; instead, encourage users to pick strong passwor".

**Failure to utilize TLS or other strong transport for authenticated pages after login enables an attacker to view the unencrypted session ID and compromise the user's authenticated session.**

ds Only Over TLS or Other Strong Transport ¶ 
 See: Transport Layer Security Cheat Sheet 
 The login page and all subsequent authenticated pages must be exclusively accessed over TLS or other strong transport. Failure to utilize TLS or other strong transport for the login page allows an attacker to modify the login form action, causing the user's credentials to be posted to an arbitrary location. Failure to utilize TLS or other strong transport for authenticated pages after login enables an attacker to view the unencrypted session ID and compromise the user's authenticated session. 
 Require Re-authentication for Sensitive Features ¶ 
 In order to mitigate CSRF and session hijacking, it's important to require the current credentials for an account before updating sensitive account information such as the user's password or email address -- or before sensitive transactions, such as shipping a purchase to a new address. Without this countermeasure, an attacker may be able to

*Disproof:* This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Failure to utilize TLS or other strong transport for authenticated pages after login enabl".

**Failure to utilize TLS or other strong transport for the login page allows an attacker to modify the login form action, causing the user's credentials to be posted to an arbitrary location.**

and forgets to log out. Another person could then use that active session. If we don't verify the current password, this other person may be able to change the password. 
 
 Transmit Passwords Only Over TLS or Other Strong Transport ¶ 
 See: Transport Layer Security Cheat Sheet 
 The login page and all subsequent authenticated pages must be exclusively accessed over TLS or other strong transport. Failure to utilize TLS or other strong transport for the login page allows an attacker to modify the login form action, causing the user's credentials to be posted to an arbitrary location. Failure to utilize TLS or other strong transport for authenticated pages after login enables an attacker to view the unencrypted session ID and compromise the user's authenticated session. 
 Require Re-authentication for Sensitive Features ¶ 
 In order to mitigate CSRF and session hijacking, it's important to require the current credentials for an account before updating sensitive account informa

*Disproof:* This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Failure to utilize TLS or other strong transport for the login page allows an attacker to ".

**Incorrectly implemented error messages in the case of authentication functionality can be used for the purposes of user ID and password enumeration.**

ing it), it is still considered a good idea to consider using both a password and TLS client authentication combined. 
 Additionally, if the client is behind an enterprise proxy that performs SSL/TLS decryption, this will break certificate authentication unless the site is allowed on the proxy. 
 For more information, see: Client-authenticated TLS handshake 
 Authentication and Error Messages ¶ 
 Incorrectly implemented error messages in the case of authentication functionality can be used for the purposes of user ID and password enumeration. An application should respond (both HTTP and HTML) in a generic manner. 
 Authentication Responses ¶ 
 Using any of the authentication mechanisms (login, password reset, or password recovery), an application must respond with a generic error message regardless of whether: 
 
 The user ID or password was incorrect. 
 The account does not exist. 
 The account is locked or disabled. 
 
 The account

*Disproof:* This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Incorrectly implemented error messages in the case of authentication functionality can be ".

**While UAF focuses on passwordless authentication, U2F allows the addition of a second factor to existing password-based authentication.**

s an often preferred method for single sign-on implementations whenever enterprise federation is required for web services and web applications. 
 See also: SAML Security Cheat Sheet 
 FIDO ¶ 
 The Fast Identity Online (FIDO) Alliance has created two protocols to facilitate online authentication: the Universal Authentication Framework (UAF) protocol and the Universal Second Factor (U2F) protocol. While UAF focuses on passwordless authentication, U2F allows the addition of a second factor to existing password-based authentication. Both protocols are based on a public key cryptography challenge-response model. 
 UAF takes advantage of existing security technologies present on devices for authentication including fingerprint sensors, cameras (face biometrics), microphones (voice biometrics), Trusted Execution Environments (TEEs), Secure Elements (SEs), and others. The protocol is designed to plug these device capabilities in

*Disproof:* This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "While UAF focuses on passwordless authentication, U2F allows the addition of a second fact".

**A feature of more advanced applications is the ability to require different authentication stages depending on various environmental and contextual attributes (including but not limited to, the sensitivity of the data for which access is being requested, time of day, user location, IP address, or device fingerprint).**

nly email . This method carries risks and requires user vigilance. 
 
 
 Regular social engineering training is crucial. System administrators and help desk staff should be trained to follow the prescribed process and recognize and respond to social engineering attacks. Refer to CISA's "Avoiding Social Engineering and Phishing Attacks" for guidance. 
 
 
 Adaptive or Risk Based Authentication ¶ 
 A feature of more advanced applications is the ability to require different authentication stages depending on various environmental and contextual attributes (including but not limited to, the sensitivity of the data for which access is being requested, time of day, user location, IP address, or device fingerprint). 
 For example, an application may require MFA for the first login from a particular device but not for subsequent logins from that device. Alternatively, a single sign-on solution may authenticate the user and allow them to remain logged in for a day but require a reauthentication if they try to access their profile page. 
 Another option is the opposite approach where an application allows low r

*Disproof:* This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "A feature of more advanced applications is the ability to require different authentication".

**Screening passwords against blocklists helps prevent users from selecting passwords that are commonly used or already known to attackers, as recommended by NIST SP 800-63B – Passwords .**

trative rather than as absolute measures of password strength. 
 Attackers commonly use password guessing techniques that leverage common-password dictionaries and password lists, and may use previously compromised credentials in credential stuffing attacks. These behaviors are reflected in MITRE ATT&CK T1110 – Brute Force , including Password Guessing, Password Spraying, and Credential Stuffing. Screening passwords against blocklists helps prevent users from selecting passwords that are commonly used or already known to attackers, as recommended by NIST SP 800-63B – Passwords . 
 
 
 Do not silently truncate passwords. The Password Storage Cheat Sheet provides further guidance on how to handle passwords that are longer than the maximum length. 
 Allow usage of all characters including unicode and whitespace. There should be no password composition rules limiting the type of characters permitted. There should be no requirement for upper or lower case or numbers or specia

*Disproof:* This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Screening passwords against blocklists helps prevent users from selecting passwords that a".

**While this technique can prevent the user from having to type a password (thus protecting against an average keylogger from stealing it), it is still considered a good idea to consider using both a password and TLS client authentication combined.**

t, who will do this for the user. 
 The website requires an extra step of security. 
 It is also a good thing to use when the website is for an intranet of a company or organization. 
 
 It is generally not a good idea to use this method for widely and publicly available websites that will have an average user. For example, it wouldn't be a good idea to implement this for a website like Facebook. While this technique can prevent the user from having to type a password (thus protecting against an average keylogger from stealing it), it is still considered a good idea to consider using both a password and TLS client authentication combined. 
 Additionally, if the client is behind an enterprise proxy that performs SSL/TLS decryption, this will break certificate authentication unless the site is allowed on the proxy. 
 For more information, see: Client-authenticated TLS handshake 
 Authentication and Error Messages ¶ 
 Incorrectly implemented error messages in the case of authentication functionality can be used for the purposes of us

*Disproof:* This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "While this technique can prevent the user from having to type a password (thus protecting ".

**Ideally, User IDs should be randomly generated to prevent the creation of predictable or sequential IDs, which could pose a security risk, especially in systems where User IDs might be exposed or inferred from external sources.**

ack and forth between the client and server when transmitting and receiving requests. Sessions should be unique per user and computationally very difficult to predict. The Session Management Cheat Sheet contains further guidance on the best practices in this area. 
 Authentication General Guidelines ¶ 
 User IDs ¶ 
 The primary function of a User ID is to uniquely identify a user within a system. Ideally, User IDs should be randomly generated to prevent the creation of predictable or sequential IDs, which could pose a security risk, especially in systems where User IDs might be exposed or inferred from external sources. 
 Usernames ¶ 
 Usernames are easy-to-remember identifiers chosen by the user and used for identifying themselves when logging into a system or service. The terms User ID and username might be used interchangeably if the username chosen by the user also serves as their unique identifier within the system. 
 Users should be permitted to use their email address as a username, provided the email is

*Disproof:* This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Ideally, User IDs should be randomly generated to prevent the creation of predictable or s".

**The application may return a different HTTP Error code depending on the authentication attempt response.**

orrect response example: 
 
 "If that email address is in our database, we will send you an email to reset your password." 
 
 Account creation ¶ 
 Incorrect response examples: 
 
 "This user ID is already in use." 
 "Welcome! You have signed up successfully." 
 
 Correct response example: 
 
 "A link to activate your account has been emailed to the address provided." 
 
 Error Codes and URLs ¶ 
 The application may return a different HTTP Error code depending on the authentication attempt response. It may respond with a 200 for a positive result and a 403 for a negative result. Even though a generic error page is shown to a user, the HTTP response code may differ which can leak information about whether the account is valid or not. 
 Error disclosure can also be used as a discrepancy factor, consult the error handling cheat sheet regarding the global handling of different errors in an appli

*Disproof:* This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "The application may return a different HTTP Error code depending on the authentication att".

**The counter of failed logins should be associated with the account itself, rather than the source IP address, in order to prevent an attacker from making login attempts from a large number of different IP addresses.**

urity mechanism used to prevent an attacker from making too many attempts at guessing a password through normal interactive means, it includes the following controls: 
 
 Maximum number of attempts. 
 
 Account Lockout ¶ 
 The most common protection against these attacks is to implement account lockout, which prevents any more login attempts for a period after a certain number of failed logins. 
 The counter of failed logins should be associated with the account itself, rather than the source IP address, in order to prevent an attacker from making login attempts from a large number of different IP addresses. There are a number of different factors that should be considered when implementing an account lockout policy in order to find a balance between security and usability: 
 
 The number of failed attempts before the account is locked out (lockout threshold). 
 The time period that these attempts must occur within (observation window). 
 How long the account is locked out for (lockout duration).

*Disproof:* This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "The counter of failed logins should be associated with the account itself, rather than the".

**The objective is to prevent the creation of a discrepancy factor , allowing an attacker to mount a user enumeration action against the application.**

password recovery), an application must respond with a generic error message regardless of whether: 
 
 The user ID or password was incorrect. 
 The account does not exist. 
 The account is locked or disabled. 
 
 The account registration feature should also be taken into consideration, and the same approach of a generic error message can be applied regarding the case in which the user exists. 
 The objective is to prevent the creation of a discrepancy factor , allowing an attacker to mount a user enumeration action against the application. 
 It is interesting to note that the business logic itself can bring a discrepancy factor related to the processing time taken. Indeed, depending on the implementation, the processing time can be significantly different according to the case (success vs failure) allowing an attacker to mount a time-based attack (delta of some seconds for example). 
 Example using pseudo-code for a login feature:

*Disproof:* This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "The objective is to prevent the creation of a discrepancy factor , allowing an attacker to".

**This section outlines when and how to trigger re-authentication to protect users and prevent unauthorized access.**

ut needing to know the user's current credentials. Additionally, an attacker may get temporary physical access to a user's browser or steal their session ID to take over the user's session. 
 Re-authentication After Risk Events ¶ 
 Overview: 
Re-authentication is critical when an account has experienced high-risk activity such as account recovery, password resets, or suspicious behavior patterns. This section outlines when and how to trigger re-authentication to protect users and prevent unauthorized access. For further details, see the Require Re-authentication for Sensitive Features section. 
 When to Trigger Re-authentication ¶ 
 
 Suspicious Account Activity 
 When unusual login patterns, IP address changes, or device enrollments occur 
 Account Recovery 
 After users reset their passwords or change sensitive account details 
 Critical Actions 
 For high-risk actions like changing payment details

*Disproof:* This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "This section outlines when and how to trigger re-authentication to protect users and preve".

**Additionally, if the client is behind an enterprise proxy that performs SSL/TLS decryption, this will break certificate authentication unless the site is allowed on the proxy.**

and publicly available websites that will have an average user. For example, it wouldn't be a good idea to implement this for a website like Facebook. While this technique can prevent the user from having to type a password (thus protecting against an average keylogger from stealing it), it is still considered a good idea to consider using both a password and TLS client authentication combined. 
 Additionally, if the client is behind an enterprise proxy that performs SSL/TLS decryption, this will break certificate authentication unless the site is allowed on the proxy. 
 For more information, see: Client-authenticated TLS handshake 
 Authentication and Error Messages ¶ 
 Incorrectly implemented error messages in the case of authentication functionality can be used for the purposes of user ID and password enumeration. An application should respond (both HTTP and HTML) in a generic manner. 
 Authentication Responses ¶ 
 Using any of the authentication mechanisms

*Disproof:* This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Additionally, if the client is behind an enterprise proxy that performs SSL/TLS decryption".

**Regarding the user enumeration itself, protection against brute-force attacks is also effective because it prevents an attacker from applying the enumeration at scale.**

and might after several retries, leave the application because of its complexity. The decision to return a generic error message can be determined based on the criticality of the application and its data. For example, for critical applications, the team can decide that under the failure scenario, a user will always be redirected to the support page and a generic error message will be returned. 
 Regarding the user enumeration itself, protection against brute-force attacks is also effective because it prevents an attacker from applying the enumeration at scale. Usage of CAPTCHA can be applied to a feature for which a generic error message cannot be returned because the user experience must be preserved. 
 Incorrect and correct response examples ¶ 
 Login ¶ 
 Incorrect response examples: 
 
 "Login for User foo: invalid password." 
 "Login failed, invalid user ID." 
 "Login failed; account disabled." 
 "Login failed; this user is not active." 
 
 Correct

*Disproof:* This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Regarding the user enumeration itself, protection against brute-force attacks is also effe".

**In return, the response time will be different for the same error, allowing the attacker to differentiate between a wrong username and a wrong password.**

me, password_hash)
 IF NOT IS_VALID THEN
 RETURN Error("Invalid Username or Password!")
 ENDIF
ELSE
 RETURN Error("Invalid Username or Password!")
ENDIF
 
 It can be clearly seen that if the user doesn't exist, the application will directly throw an error. Otherwise, when the user exists and the password doesn't, it is apparent that there will be more processing before the application errors out. In return, the response time will be different for the same error, allowing the attacker to differentiate between a wrong username and a wrong password. 
 
 Second implementation without relying on the "quick exit" approach: 
 
 password_hash=HASH(password)
IS_VALID=LOOKUP_CREDENTIALS_IN_STORE(username, password_hash)
IF NOT IS_VALID THEN
 RETURN Error("Invalid Username or Password!")
ENDIF
 
 This code will go through the same process no matter what the user or the password is, allowing the application to return in approximately the same respons

*Disproof:* This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "In return, the response time will be different for the same error, allowing the attacker t".

**Remote monitoring and management agents control a host as if local, inheriting the user or software permissions of the session they run in, so an RMM console is a privileged interface whose exposure is governed by its own authentication.**

The defining property of an RMM tool is exactly the security problem: it grants remote control of a computer as if the operator were sitting at it, inheriting that user or software's permissions. So the RMM agent is a privileged access path by design, installed to operate across network controls — which is why it is a high-value target rather than a utility. The two questions to ask are therefore about the console, not the endpoint: is the RMM management interface reachable from where it should not be, and is its authentication strong enough to resist the credential attacks documented as common against remote management surfaces. Vendor and group reporting in ATT&CK (tooling used to deploy malware from an already-compromised host) confirms the operational reality that these consoles are used as distribution and access infrastructure. Multi-factor authentication on the console is the specific control that changes the exposure.

*Disproof:* If the RMM management interface is reachable only from an authorized administrative segment and enforces multi-factor authentication, then console compromise requires a pre-existing privileged foothold and the exposure is correspondingly reduced.

## Variations

Not yet researched.

## Technology / Framework Considerations

Not yet researched.

## API Considerations

Not yet researched.

## Attack Chains

- `ci-credential-to-self-propagating-poisoned-artifact` — CI credential exposure to self-propagating poisoned artifact to re-executing host delivery (goal: `persistent_host_execution`)

## Real-World Examples

Not yet researched.

## Common False Positives

**Finding an RMM or remote-management agent running on a host is not an exposed-RMM finding unless the management listener is reachable from an untrusted network, because software installed by the defender's own deployment is the normal case and the exposure lives at the network edge.**

The reason this is an FP class rather than a real finding: Microsoft observed a campaign distributing a masqueraded RMM installer through meeting invitations and PDF-themed lures, so the presence of the agent is exactly what both a legitimate deployment and an attack look like from the endpoint alone, and the deceptive filename is what distinguishes them rather than the running process. Tenable's exposure framing is the same: the directive is to get management interfaces off the internet, which places the control on reachability, not on the software inventory. The test that resolves it: from an untrusted source network, attempt a protocol handshake against the vendor's management port. A refusal or filtered packet proves there is no exposure and the agent is a false positive; a completed handshake means the exposure is real and the finding stands, regardless of how the agent got there.

*Disproof:* If the management port answers a handshake from an untrusted network, the agent is genuinely exposed and this rule does not apply; conversely a host whose agent is installed, running, and management-tenant-enrolled but whose listener is not reachable is a false positive for this class.

**A legitimately installed RMM agent on a host is not compromise; discard the finding when no unauthorised deployment was shown.**

Discard when the report rests on the tool being present and running: the joint advisory describes abuse of legitimate RMM software, and RMM agents are persistent by design, so installation alone cannot distinguish an administrator's tool from an attacker's. It survives when the agent was installed during the engagement window, or connects to attacker-controlled relay infrastructure.

*Disproof:* Would be wrong where the installed agent version is one of the known-vulnerable builds and is internet-reachable, since that is an exposure in itself.

**An internet-exposed ScreenConnect instance is only exploitable below 23.9.8; a patched instance with MFA is not a finding.**

Discard when the exposed instance was already upgraded: the Rapid7 analysis states all versions before 23.9.8 are vulnerable to the authentication bypass and path traversal issues, so a current build with enforcement enabled has no auth bypass. It survives when the instance answered on a vulnerable version and a new administrative account could be created unauthenticated.

*Disproof:* Would be wrong where an unpatched build sits behind an MFA-enforced control plane, since the bypass then needs the second factor.
**Hypothesis:** An installed remote monitoring and management agent on a workstation is evidence of compromise.
- Invalidated by: The install timestamp falls inside the approved deployment window, the binary matches the vendor-signed package in the software distribution system, and no management listener answered from outside the corporate network; the agent was deployed, not implanted.
- **Rejection rule:** An RMM agent's presence is a deployment fact, not a finding. Report it only when install time or signing identity departs from the deployment record, or when a management interface answers from a network that policy forbids.

## Validation

**To decide this case, observe: Discard when the report rests on the tool being present and running: the joint advisory describes abuse of legitimate RMM software, and RMM agents are persistent by design, so installation alone cannot distinguish an administrator's tool from an attacker's.**

Derived from exposed_rmm.fprule.presence_is_not_compromise, which states the false-positive boundary for this class. The observable above is what separates a real finding from the pattern that only looks like one. A hunter who cannot produce this observation in a request/response pair does not have a finding yet.

*Disproof:* This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (exposed_rmm.fprule.presence_is_not_compromise) states the full boundary.

## Impact

Not yet researched.

## Related Bug Classes

Not yet researched.

## References

- **attack.mitre.org** (taxonomy)
  - <https://attack.mitre.org/techniques/T1219/>
- **cheatsheetseries.owasp.org** (cheatsheet)
  - <https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html>
- **cisa.gov** (advisory)
  - <https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-025a>
- **microsoft.com** (research)
  - <https://www.microsoft.com/en-us/security/blog/2026/09/02/impersonating-it-support-threat-actors-turn-remote-session-into-enterprise-wide-access/>
  - <https://www.microsoft.com/en-us/security/blog/2026/09/29/phishing-abuses-rmm-tools-persistent-access/>
- **netlas.io** (writeup)
  - <https://netlas.io/blog/weaponized_rmm/>
- **rapid7.com** (writeup)
  - <https://www.rapid7.com/blog/post/2024/02/20/etr-high-risk-vulnerabilities-in-connectwise-screenconnect/>
- **tenable.com** (research)
  - <https://www.tenable.com/blog/using-the-service-location-protocol-slp-to-find-exposed-management-interfaces>

Every item above is gated on >= 2 distinct publisher hosts (`wks/quality.py`, rule R1). Publisher diversity, not citation count, is what makes these corroborated.
