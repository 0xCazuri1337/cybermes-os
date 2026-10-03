# Service-Specific Configuration Assessment

## Definition

A service's own configuration — signing, binding, authentication method — determines whether its protocol weaknesses are reachable.

- **CWE:** CWE-16
- **OWASP:** None
- **Surface:** net
- **Aliases:** ["service configuration", "configuration assessment", "service hardening", "protocol configuration", "misconfigured service"]

Canonical home for `service_enumeration_detail`. Rendered from `db/wks.db` by `tools/taxonomy/build_taxonomy.py` — edit the rows, not this file.

## Root Cause

Not yet researched.

## Preconditions

Not yet researched.

## Attack Surface

Surface: **net**.

The entry points and enabling conditions for this surface are enumerated under **Preconditions**; the observable signals are under **Detection**.

## Detection

**A convincing observation for this class is: The observable that triggers this false positive is a TCP banner that reveals the service name and version, escalated from information disclosure into an access-control or authentication finding.**

Derived from service_enumeration_detail.fp_rule.banner_version_disclosure_is_information_not_control_failure, which states the boundary for this class. The observation above is what a report must contain to be believed: an artifact the reviewer can re-check, not a claim the hunter asserts. A finding without it is an assertion.

*Disproof:* Not evidence when the observable cannot be produced at all -- blind, server-side-only, or identical-in-every-case behaviour leaves nothing to show. The originating rule (service_enumeration_detail.fp_rule.banner_version_disclosure_is_information_not_control_failure) states the full boundary.

**A convincing observation for this class is: Adjacent behaviour that produces the same observable result: As a result, it is imperative that organizations implement exposure management, which is the proactive cybersecurity approach of identifying, assessing, and addressing potential vulnerabilities and risks before they can be exploited.**

Derived from service_enumeration_detail.fp_rule.auto.derived, which states the boundary for this class. The observation above is what a report must contain to be believed: an artifact the reviewer can re-check, not a claim the hunter asserts. A finding without it is an assertion.

*Disproof:* Not evidence when the observable cannot be produced at all -- blind, server-side-only, or identical-in-every-case behaviour leaves nothing to show. The originating rule (service_enumeration_detail.fp_rule.auto.derived) states the full boundary.

## Exploitation

**As a result, it is imperative that organizations implement exposure management, which is the proactive cybersecurity approach of identifying, assessing, and addressing potential vulnerabilities and risks before they can be exploited.**

to potential cyber attacks due to vulnerabilities or weaknesses within an organization's CPS environment. Due to a growing attack surface, critical infrastructure organizations have been left with various points of exposure that an adversary can exploit. These entry points may lead to an attacker gaining unauthorized access, disrupting essential services, or causing various other forms of harm.  As a result, it is imperative that organizations implement exposure management, which is the proactive cybersecurity approach of identifying, assessing, and addressing potential vulnerabilities and risks before they can be exploited. The ultimate goal of exposure management is to reduce an organization's exposure or attack surface by locating vulnerabilities within their critical environment in order to minimize risk. Why is Exposure Management Important?  Exposure management is essential for critical infrastructure organizations to implement because the cybersecurity landscape is incredibly dynamic — with new vulnerabilities

*Disproof:* This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "As a result, it is imperative that organizations implement exposure management, which is t".

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

**When designing an account lockout system, care must be taken to prevent it from being used to cause a denial of service by locking out other users' accounts.**

he account is locked out for (lockout duration). 
 
 Rather than implementing a fixed lockout duration (e.g., ten minutes), some applications use an exponential lockout, where the lockout duration starts as a very short period (e.g., one second), but doubles after each failed login attempt. 
 
 Amount of time to delay after each account lockout (max 2-3, after that permanent account lockout). 
 
 When designing an account lockout system, care must be taken to prevent it from being used to cause a denial of service by locking out other users' accounts. One way this could be performed is to allow the use of the forgotten password functionality to log in, even if the account is locked out. 
 CAPTCHA ¶ 
 The use of an effective CAPTCHA can help to prevent automated login attempts against accounts. However, many CAPTCHA implementations have weaknesses that allow them to be solved using automated techniques or can be outsourced to services that can

*Disproof:* This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "When designing an account lockout system, care must be taken to prevent it from being used".

**Failure to utilize TLS or other strong transport for the login page allows an attacker to modify the login form action, causing the user's credentials to be posted to an arbitrary location.**

and forgets to log out. Another person could then use that active session. If we don't verify the current password, this other person may be able to change the password. 
 
 Transmit Passwords Only Over TLS or Other Strong Transport ¶ 
 See: Transport Layer Security Cheat Sheet 
 The login page and all subsequent authenticated pages must be exclusively accessed over TLS or other strong transport. Failure to utilize TLS or other strong transport for the login page allows an attacker to modify the login form action, causing the user's credentials to be posted to an arbitrary location. Failure to utilize TLS or other strong transport for authenticated pages after login enables an attacker to view the unencrypted session ID and compromise the user's authenticated session. 
 Require Re-authentication for Sensitive Features ¶ 
 In order to mitigate CSRF and session hijacking, it's important to require the current credentials for an account before updating sensitive account informa

*Disproof:* This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Failure to utilize TLS or other strong transport for the login page allows an attacker to ".

**As a result, it is imperative that organizations implement exposure management, which is the proactive cybersecurity approach of identifying, assessing, and addressing potential vulnerabilities and risks before they can be exploited.**

to potential cyber attacks due to vulnerabilities or weaknesses within an organization's CPS environment. Due to a growing attack surface, critical infrastructure organizations have been left with various points of exposure that an adversary can exploit. These entry points may lead to an attacker gaining unauthorized access, disrupting essential services, or causing various other forms of harm.  As a result, it is imperative that organizations implement exposure management, which is the proactive cybersecurity approach of identifying, assessing, and addressing potential vulnerabilities and risks before they can be exploited. The ultimate goal of exposure management is to reduce an organization's exposure or attack surface by locating vulnerabilities within their critical environment in order to minimize risk. Why is Exposure Management Important?  Exposure management is essential for critical infrastructure organizations to implement because the cybersecurity landscape is incredibly dynamic — with new vulnerabilities

*Disproof:* This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "As a result, it is imperative that organizations implement exposure management, which is t".

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

**Whether a service's protocol weaknesses are reachable is decided by that service's own configuration — signing requirements, binding, authentication method and lockout policy — so service identification must be followed by configuration assessment before any weakness is asserted.**

This is the step that separates an enumeration report from a finding. The same open port with the same banner is a different risk depending on whether the protocol requires signing, whether the authentication method is replayable, and whether failed attempts are locked out — and the configuration values that decide it are precisely the ones an attacker must get right for their technique to work. The two exemplar controls are authentication policy (multi-factor defeats replayable credential attacks; account lockout is the common protection against brute force but must be balanced so it cannot itself be used to deny service by locking other users out) and the protocol configuration of the service itself. So the assessment procedure is: identify the service, read its authentication and signing configuration, then evaluate the specific weakness against that configuration. A weakness reported without the configuration step is a hypothesis, and its disproof lives in the configuration.

*Disproof:* If the service enforces signing and strong authentication with lockout applied, then the protocol weaknesses that enumeration would suggest are not reachable and the class yields no finding for that service.

## Variations

Not yet researched.

## Technology / Framework Considerations

Not yet researched.

## API Considerations

Not yet researched.

## Attack Chains

- `chain.service_enumeration_detail.auto.01` — service_enumeration_detail: observe, exercise, confirm (goal: `Establish, exercise and confirm a service_enumeration_detail condition on an authorised target without relying on anyone else's data.`)

## Real-World Examples

Not yet researched.

## Common False Positives

**Reject a service_enumeration_detail finding until it is distinguished from the adjacent behaviour this class also covers. "Whether a service's protocol weaknesses are reachable is decided by that service's own configuration — signing requirements, binding, authentication method and lockout policy — so service identification must be followed by configuration..." and "As a result, it is imperative that organizations implement exposure management, which is the proactive cybersecurity approach of identifying, assessing, and addressing potential vulnerabilities and risks before they can be exploited." share a surface and a symptom, so a response that matches the first is not evidence for it while the second remains possible.**

Hypothesis under test: Whether a service's protocol weaknesses are reachable is decided by that service's own configuration — signing requirements, binding, authentication method and lockout policy — so service identification must be followed by configuration...

Adjacent behaviour that produces the same observable result: As a result, it is imperative that organizations implement exposure management, which is the proactive cybersecurity approach of identifying, assessing, and addressing potential vulnerabilities and risks before they can be exploited.

Why this is worth checking before reporting: both are recorded in this class as gated knowledge, so a tester who stops at the first match will report one of them. The two differ in what the server actually did with the input, and that difference is observable in the response rather than in the request.

Required before treating this as a finding: capture the response that demonstrates the first behaviour specifically, and confirm the second is not what was observed.

*Disproof:* This rule is wrong if a controlled test shows the two behaviours can never co-occur on the same surface, or if the corpus entry for "As a result, it is imperative that organizations implement exposure ma" is out of date. In that case this class needs its false-positive guidance rewritten rather than deleted.

**A TCP banner that reveals the service name and version is information disclosure and is not an authorization bypass, an authentication weakness, or a remote-code-execution finding; file it under information disclosure only, and only when the version actually maps to a known-vulnerable build.**

The observable that triggers this false positive is a TCP banner that reveals the service name and version, escalated from information disclosure into an access-control or authentication finding. The banner is read without authenticating, so nothing was bypassed and no trust boundary was crossed; CAPEC rates port-scanning-derived information of this kind as low severity, and exposure management treats an open port as risk only once a vulnerability is located on it. Two conditions lift the banner out of this rule: the disclosed version maps to a published CVE with a demonstrated exploit path, or the banner itself discloses a credential or an internal hostname that was not already inside the assessment scope. Absent those, the banner is reconnaissance output and belongs in neither an authorization nor an authentication finding.

*Disproof:* The disclosed version maps to a published CVE with a working exploit path, or the banner itself carries a credential or internal hostname that was not already known to the assessment scope - in which case the disclosure is materially different from a routine version string.

## Validation

Not yet researched.

## Impact

Not yet researched.

## Related Bug Classes

Not yet researched.

## References

- **attack.mitre.org** (taxonomy)
  - <https://attack.mitre.org/techniques/T1046/>
- **capec.mitre.org** (standard)
  - <https://capec.mitre.org/data/definitions/300.html>
- **cheatsheetseries.owasp.org** (cheatsheet)
  - <https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html>
- **claroty.com** (writeup)
  - <https://claroty.com/blog/a-comprehensive-guide-to-exposure-management-for-cyber-physical-systems>

Every item above is gated on >= 2 distinct publisher hosts (`wks/quality.py`, rule R1). Publisher diversity, not citation count, is what makes these corroborated.
