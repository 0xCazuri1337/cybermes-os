# Authentication Failures

## Definition

The mechanism that establishes identity can be bypassed, reused, or subverted end to end.

- **CWE:** 287
- **OWASP:** A07:2021
- **Surface:** identity
- **Aliases:** ["authentication bypass", "weak login", "password reset flaw", "mfa bypass", "account takeover"]

Canonical home for `authn`. Rendered from `db/wks.db` by `tools/taxonomy/build_taxonomy.py` — edit the rows, not this file.

## Root Cause

Not yet researched.

## Preconditions

**SAML assertions fail to verify when the service provider and identity provider disagree on XML canonicalization, because the hashed byte representation of the same logical content then differs.**

Canonicalization turns a document into a stable byte sequence so a hash over signed content is reproducible. When the two parties normalize differently, identical logical content produces different bytes, the digest does not match, and authentication fails. For a hunter this matters because an assertion that will not validate may be an interoperability defect rather than an attack surface, and filing it as a signature-bypass candidate wastes a cycle. The diagnostic is whether the failure is consistent across every request and whether an unmutated assertion from the same provider also fails.

*Disproof:* If an unmodified assertion from the same identity provider validates reliably, canonicalization disagreement is not the cause of the observed failure.

## Attack Surface

Surface: **identity**.

The entry points and enabling conditions for this surface are enumerated under **Preconditions**; the observable signals are under **Detection**.

## Detection

**A JSON response body that states whether 2FA authentication succeeded is the field to manipulate, because the client-visible success value is what the 2FA check may be read from.**

A JSON response body that states whether 2FA authentication succeeded is the field to manipulate, because the client-visible success value is what the 2FA check may be read from.

HackTricks reference: 2fa bypasses (https://kathan19.gitbook.io/howtohunt/authentication-bypass/2fa_bypasses.md)

*Disproof:* Editing the success field in the 2FA response body leaves the session unauthenticated because the server records the verified state independently of the returned JSON.

**A JSON response body that states whether 2FA authentication succeeded is the field to manipulate, because the client-visible success value is what the 2FA check may be read from.**

A JSON response body that states whether 2FA authentication succeeded is the field to manipulate, because the client-visible success value is what the 2FA check may be read from.

HackTricks reference: 2fa bypasses (https://kathan19.gitbook.io/howtohunt/authentication-bypass/2fa_bypasses.md)

*Disproof:* Editing the success field in the 2FA response body leaves the session unauthenticated because the server records the verified state independently of the returned JSON.

**A convincing observation for this class is: The weakness requires the product to fail to prove an identity claim; a timing or message difference that the response body and status do not expose is a hardening observation, not a demonstrable enumeration channel.**

Derived from authn.fp_rule.two_different_responses_to_two_different_credentials_is_not_username_enumeration, which states the boundary for this class. The observation above is what a report must contain to be believed: an artifact the reviewer can re-check, not a claim the hunter asserts. A finding without it is an assertion.

*Disproof:* Not evidence when the observable cannot be produced at all -- blind, server-side-only, or identical-in-every-case behaviour leaves nothing to show. The originating rule (authn.fp_rule.two_different_responses_to_two_different_credentials_is_not_username_enumeration) states the full boundary.

**A convincing observation for this class is: That pair is what a triager needs and what a status code cannot supply.**

Derived from authn.validation.prove_broken_authn_with_a_second_session_not_with_a_redirect_status, which states the boundary for this class. The observation above is what a report must contain to be believed: an artifact the reviewer can re-check, not a claim the hunter asserts. A finding without it is an assertion.

*Disproof:* Not evidence when the observable cannot be produced at all -- blind, server-side-only, or identical-in-every-case behaviour leaves nothing to show. The originating rule (authn.validation.prove_broken_authn_with_a_second_session_not_with_a_redirect_status) states the full boundary.

## Exploitation

**We will cover how to identify, exploit, and prevent each of these vulnerabilities.**

Misconfigurations 
 
 This module covers three common HTTP vulnerabilities: Web Cache Poisoning, Host Header Vulnerabilities, and Session Puzzling or Session Variable Overloading. These vulnerabilities can arise on the HTTP level due to web server misconfigurations, other systems that have to be considered during real-world deployment such as web caches, or coding mistakes in the web application. We will cover how to identify, exploit, and prevent each of these vulnerabilities. 
 
 4.70 
 
 
 
 
 
 
 
 
 
 
 
 
 
 
 
 
 Created by vautia 
 
 
 
 Start Module 
 
 
 HTB Academy Business 
 
 
 
 
 
 Summary
 
 
 
 Module
 Overview 
 
 
 
 
 
 
 
 Hard
 
 
 Offensive
 
 
 
 
 
 
 
 
 
 
 
 
 
 Summary 
 As the security awareness of administrators is increasing, beginner-level vulnerabilities and low-hanging fruits are (hopefully) often detected and avoided, at least for lar

*Disproof:* This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "We will cover how to identify, exploit, and prevent each of these vulnerabilities.".

**We will discuss these attacks in detail, including how to detect, exploit, and prevent them.**

t vital aspects of Cybersecurity, as it is essential not only to examine a web application in isolation but also to view it holistically in a real-world deployment, which includes systems such as web servers and web caches that introduce additional complexity and, therefore, an increased attack surface. 
 In this module, we will cover three HTTP attacks that are common in modern web applications. We will discuss these attacks in detail, including how to detect, exploit, and prevent them. 
 Web services used by many users use web caches to improve performance by reducing the load on the web server. Web caches sit between the client and the web server. They cache resources locally after retrieving them from the web server, allowing them to serve the same resource from local storage on subsequent requests. Thus, the resources do not need to be requested from the web server, reducing

*Disproof:* This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "We will discuss these attacks in detail, including how to detect, exploit, and prevent the".

**More specifically, if a web application uses the host header for authorization checks or to construct absolute links, an attacker may be able to manipulate the host header to bypass these checks or force the construction of malicious links.**

sed in this module is a Host Header Attack . The HTTP host header contains the domain name of the requested resource and is used to tell the server which domain a user wants to access. This is required when a single server serves multiple domains or subdomains, enabling the server to identify the targeted application. Host header attacks exploit vulnerabilities in the handling of the host header. More specifically, if a web application uses the host header for authorization checks or to construct absolute links, an attacker may be able to manipulate the host header to bypass these checks or force the construction of malicious links. 
 Session Puzzling 
 The third and final attack covered in this module is Session Puzzling . Since HTTP is a stateless protocol, session variables are necessary to keep track of a wide variety of actions commonly performed in web applications, including authentication. Session puzzling is a vulnerability that results from improper handling of session variables and can lead to authentication bypas

*Disproof:* This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "More specifically, if a web application uses the host header for authorization checks or t".

**Session puzzling is a vulnerability that results from improper handling of session variables and can lead to authentication bypasses or account takeover.**

links, an attacker may be able to manipulate the host header to bypass these checks or force the construction of malicious links. 
 Session Puzzling 
 The third and final attack covered in this module is Session Puzzling . Since HTTP is a stateless protocol, session variables are necessary to keep track of a wide variety of actions commonly performed in web applications, including authentication. Session puzzling is a vulnerability that results from improper handling of session variables and can lead to authentication bypasses or account takeover. In particular, session puzzling can result from reusing the same session variable across different processes, prematurely populating session variables, or using insecure default values for session variables. 
 
 
 
 Sign Up / Log In to Unlock the Module 
 Please Sign Up or Log In to unlock the module and access the rest of the sections. 
 
 Start for Free 
 
 
 
 
 
 Sections 
 
 
 
 
 Introducti

*Disproof:* This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Session puzzling is a vulnerability that results from improper handling of session variabl".

**An XSS vulnerability may allow an attacker to execute arbitrary JavaScript code within the target's browser and result in complete web application compromise if chained together with other vulnerabilities.**

of brute-forcing techniques, including the use of tools like Hydra and Medusa, and the importance of strong password practices. It covers various attack scenarios, such as targeting SSH, FTP, and web login forms. 
 
 
 
 Cross-Site Scripting (XSS) 
 
 
 Easy 
 
 
 10 Sections 
 
 Reward: +20 
 
 Cross-Site Scripting (XSS) vulnerabilities are among the most common web application vulnerabilities. An XSS vulnerability may allow an attacker to execute arbitrary JavaScript code within the target's browser and result in complete web application compromise if chained together with other vulnerabilities. This module will teach you how to identify XSS vulnerabilities and exploit them. 
 
 
 
 Session Security 
 
 
 Medium 
 
 
 14 Sections 
 
 Reward: +20 
 
 Maintaining and keeping track of a user's session is an integral part of web applications. It is an area that requires extensive testing to ensure it is set up robustly and securely. This module covers the most common attacks and vulnerabilit

*Disproof:* This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "An XSS vulnerability may allow an attacker to execute arbitrary JavaScript code within the".

**This module covers the most common attacks and vulnerabilities that can affect web application sessions, such as Session Hijacking, Session Fixation, Cross-Site Request Forgery, Cross-Site Scripting, and Open Redirects.**

compromise if chained together with other vulnerabilities. This module will teach you how to identify XSS vulnerabilities and exploit them. 
 
 
 
 Session Security 
 
 
 Medium 
 
 
 14 Sections 
 
 Reward: +20 
 
 Maintaining and keeping track of a user's session is an integral part of web applications. It is an area that requires extensive testing to ensure it is set up robustly and securely. This module covers the most common attacks and vulnerabilities that can affect web application sessions, such as Session Hijacking, Session Fixation, Cross-Site Request Forgery, Cross-Site Scripting, and Open Redirects. 
 
 
 
 SQL Injection Fundamentals 
 
 
 Medium 
 
 
 17 Sections 
 
 Reward: +10 
 
 Databases are an important part of web application infrastructure and SQL (Structured Query Language) to store, retrieve, and manipulate information stored in them. SQL injection is a code injection technique used to take advantage of coding vulnerabilities and inject SQL queries via an application to bypass aut

*Disproof:* This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "This module covers the most common attacks and vulnerabilities that can affect web applica".

**Alternatively, a single sign-on solution may authenticate the user and allow them to remain logged in for a day but require a reauthentication if they try to access their profile page.**

require different authentication stages depending on various environmental and contextual attributes (including but not limited to, the sensitivity of the data for which access is being requested, time of day, user location, IP address, or device fingerprint). 
 For example, an application may require MFA for the first login from a particular device but not for subsequent logins from that device. Alternatively, a single sign-on solution may authenticate the user and allow them to remain logged in for a day but require a reauthentication if they try to access their profile page. 
 Another option is the opposite approach where an application allows low risk access with just something that identifies the device (e.g., a specific mobile device fingerprint, a persistent cookie and browser fingerprint, etc. from the previous IP address) and then gradually requires stronger authentication for more sensitive operations. An example might be to allow someone to trigger something

*Disproof:* Refuted when: the same behaviour is absent when the single named control in the claim is present, and the control is shown to be present rather than assumed. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“Alternatively, a single sign-on solution may authenticate the user and allow the”) does not occur under a test that isolates that control.

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

**While the program properly exits if authentication fails, it does not ensure that the message is addressed to the user.**

ge->{subject}) . "\n"; print " \n"; print "Body: " . encodeHTML($Message->{body}) . "\n"; } 
 my $q = new CGI; 
 # For purposes of this example, assume that CWE-309 and 
 
 
 
 # CWE-523 do not apply. 
 if (! AuthenticateUser($q->param('username'), $q->param('password'))) { ExitError("invalid username or password"); } 
 my $id = $q->param('id'); DisplayPrivateMessage($id); 
 
 
 
 
 
 
 
 
 
 
 
 While the program properly exits if authentication fails, it does not ensure that the message is addressed to the user. As a result, an authenticated attacker could provide any arbitrary identifier and read private messages that were intended for other users. 
 
 
 
 
 One way to avoid this problem would be to ensure that the "to" field in the message object matches the username of the authenticated user. 
 
 
 
 
 
 
 
 
 
 

 

 
 
 
 Selected Observed
 Examples 
 
 
 Note: this is a curated list of examples for

*Disproof:* Refuted when: the same behaviour is absent when the single named control in the claim is present, and the control is shown to be present rather than assumed. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“While the program properly exits if authentication fails, it does not ensure tha”) does not occur under a test that isolates that control.

**Avoid requiring periodic password changes; instead, encourage users to pick strong passwords and enable Multifactor Authentication Cheat Sheet (MFA) .**

aximum length. 
 Allow usage of all characters including unicode and whitespace. There should be no password composition rules limiting the type of characters permitted. There should be no requirement for upper or lower case or numbers or special characters. 
 Ensure credential rotation when a password leak occurs, at the time of compromise identification or when authenticator technology changes. Avoid requiring periodic password changes; instead, encourage users to pick strong passwords and enable Multifactor Authentication Cheat Sheet (MFA) . According to NIST guidelines, verifiers should not mandate arbitrary password changes (e.g., periodically). 
 Include a password strength meter to help users create a more complex password 
 zxcvbn-ts library can be used for this purpose. 
 Other language implementations of zxcvbn listed here ; however check the age and maturity of each example before use. 
 
 
 Block common and previously breach

*Disproof:* Refuted when: the same behaviour is absent when the single named control in the claim is present, and the control is shown to be present rather than assumed. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“Avoid requiring periodic password changes; instead, encourage users to pick stro”) does not occur under a test that isolates that control.

**Failure to utilize TLS or other strong transport for authenticated pages after login enables an attacker to view the unencrypted session ID and compromise the user's authenticated session.**

ds Only Over TLS or Other Strong Transport ¶ 
 See: Transport Layer Security Cheat Sheet 
 The login page and all subsequent authenticated pages must be exclusively accessed over TLS or other strong transport. Failure to utilize TLS or other strong transport for the login page allows an attacker to modify the login form action, causing the user's credentials to be posted to an arbitrary location. Failure to utilize TLS or other strong transport for authenticated pages after login enables an attacker to view the unencrypted session ID and compromise the user's authenticated session. 
 Require Re-authentication for Sensitive Features ¶ 
 In order to mitigate CSRF and session hijacking, it's important to require the current credentials for an account before updating sensitive account information such as the user's password or email address -- or before sensitive transactions, such as shipping a purchase to a new address. Without this countermeasure, an attacker may be able to

*Disproof:* Refuted when: the same behaviour is absent when the single named control in the claim is present, and the control is shown to be present rather than assumed. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“Failure to utilize TLS or other strong transport for authenticated pages after l”) does not occur under a test that isolates that control.

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

*Disproof:* Refuted when: the same behaviour is absent when the single named control in the claim is present, and the control is shown to be present rather than assumed. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“Incorrectly implemented error messages in the case of authentication functionali”) does not occur under a test that isolates that control.

**While UAF focuses on passwordless authentication, U2F allows the addition of a second factor to existing password-based authentication.**

s an often preferred method for single sign-on implementations whenever enterprise federation is required for web services and web applications. 
 See also: SAML Security Cheat Sheet 
 FIDO ¶ 
 The Fast Identity Online (FIDO) Alliance has created two protocols to facilitate online authentication: the Universal Authentication Framework (UAF) protocol and the Universal Second Factor (U2F) protocol. While UAF focuses on passwordless authentication, U2F allows the addition of a second factor to existing password-based authentication. Both protocols are based on a public key cryptography challenge-response model. 
 UAF takes advantage of existing security technologies present on devices for authentication including fingerprint sensors, cameras (face biometrics), microphones (voice biometrics), Trusted Execution Environments (TEEs), Secure Elements (SEs), and others. The protocol is designed to plug these device capabilities in

*Disproof:* Refuted when: the same behaviour is absent when the single named control in the claim is present, and the control is shown to be present rather than assumed. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“While UAF focuses on passwordless authentication, U2F allows the addition of a s”) does not occur under a test that isolates that control.

**A feature of more advanced applications is the ability to require different authentication stages depending on various environmental and contextual attributes (including but not limited to, the sensitivity of the data for which access is being requested, time of day, user location, IP address, or device fingerprint).**

nly email . This method carries risks and requires user vigilance. 
 
 
 Regular social engineering training is crucial. System administrators and help desk staff should be trained to follow the prescribed process and recognize and respond to social engineering attacks. Refer to CISA's "Avoiding Social Engineering and Phishing Attacks" for guidance. 
 
 
 Adaptive or Risk Based Authentication ¶ 
 A feature of more advanced applications is the ability to require different authentication stages depending on various environmental and contextual attributes (including but not limited to, the sensitivity of the data for which access is being requested, time of day, user location, IP address, or device fingerprint). 
 For example, an application may require MFA for the first login from a particular device but not for subsequent logins from that device. Alternatively, a single sign-on solution may authenticate the user and allow them to remain logged in for a day but require a reauthentication if they try to access their profile page. 
 Another option is the opposite approach where an application allows low r

*Disproof:* Refuted when: the resolved Location host is the intended origin, so no request ever leaves the application. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“A feature of more advanced applications is the ability to require different auth”) does not occur under a test that isolates that control.

**Screening passwords against blocklists helps prevent users from selecting passwords that are commonly used or already known to attackers, as recommended by NIST SP 800-63B – Passwords .**

trative rather than as absolute measures of password strength. 
 Attackers commonly use password guessing techniques that leverage common-password dictionaries and password lists, and may use previously compromised credentials in credential stuffing attacks. These behaviors are reflected in MITRE ATT&CK T1110 – Brute Force , including Password Guessing, Password Spraying, and Credential Stuffing. Screening passwords against blocklists helps prevent users from selecting passwords that are commonly used or already known to attackers, as recommended by NIST SP 800-63B – Passwords . 
 
 
 Do not silently truncate passwords. The Password Storage Cheat Sheet provides further guidance on how to handle passwords that are longer than the maximum length. 
 Allow usage of all characters including unicode and whitespace. There should be no password composition rules limiting the type of characters permitted. There should be no requirement for upper or lower case or numbers or specia

*Disproof:* Refuted when: the same behaviour is absent when the single named control in the claim is present, and the control is shown to be present rather than assumed. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“Screening passwords against blocklists helps prevent users from selecting passwo”) does not occur under a test that isolates that control.

**While this technique can prevent the user from having to type a password (thus protecting against an average keylogger from stealing it), it is still considered a good idea to consider using both a password and TLS client authentication combined.**

t, who will do this for the user. 
 The website requires an extra step of security. 
 It is also a good thing to use when the website is for an intranet of a company or organization. 
 
 It is generally not a good idea to use this method for widely and publicly available websites that will have an average user. For example, it wouldn't be a good idea to implement this for a website like Facebook. While this technique can prevent the user from having to type a password (thus protecting against an average keylogger from stealing it), it is still considered a good idea to consider using both a password and TLS client authentication combined. 
 Additionally, if the client is behind an enterprise proxy that performs SSL/TLS decryption, this will break certificate authentication unless the site is allowed on the proxy. 
 For more information, see: Client-authenticated TLS handshake 
 Authentication and Error Messages ¶ 
 Incorrectly implemented error messages in the case of authentication functionality can be used for the purposes of us

*Disproof:* Refuted when: the same behaviour is absent when the single named control in the claim is present, and the control is shown to be present rather than assumed. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“While this technique can prevent the user from having to type a password (thus p”) does not occur under a test that isolates that control.

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

*Disproof:* Refuted when: the same behaviour is absent when the single named control in the claim is present, and the control is shown to be present rather than assumed. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“The application may return a different HTTP Error code depending on the authenti”) does not occur under a test that isolates that control.

**The counter of failed logins should be associated with the account itself, rather than the source IP address, in order to prevent an attacker from making login attempts from a large number of different IP addresses.**

urity mechanism used to prevent an attacker from making too many attempts at guessing a password through normal interactive means, it includes the following controls: 
 
 Maximum number of attempts. 
 
 Account Lockout ¶ 
 The most common protection against these attacks is to implement account lockout, which prevents any more login attempts for a period after a certain number of failed logins. 
 The counter of failed logins should be associated with the account itself, rather than the source IP address, in order to prevent an attacker from making login attempts from a large number of different IP addresses. There are a number of different factors that should be considered when implementing an account lockout policy in order to find a balance between security and usability: 
 
 The number of failed attempts before the account is locked out (lockout threshold). 
 The time period that these attempts must occur within (observation window). 
 How long the account is locked out for (lockout duration).

*Disproof:* Refuted when: the same behaviour is absent when the single named control in the claim is present, and the control is shown to be present rather than assumed. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“The counter of failed logins should be associated with the account itself, rathe”) does not occur under a test that isolates that control.

**The objective is to prevent the creation of a discrepancy factor , allowing an attacker to mount a user enumeration action against the application.**

password recovery), an application must respond with a generic error message regardless of whether: 
 
 The user ID or password was incorrect. 
 The account does not exist. 
 The account is locked or disabled. 
 
 The account registration feature should also be taken into consideration, and the same approach of a generic error message can be applied regarding the case in which the user exists. 
 The objective is to prevent the creation of a discrepancy factor , allowing an attacker to mount a user enumeration action against the application. 
 It is interesting to note that the business logic itself can bring a discrepancy factor related to the processing time taken. Indeed, depending on the implementation, the processing time can be significantly different according to the case (success vs failure) allowing an attacker to mount a time-based attack (delta of some seconds for example). 
 Example using pseudo-code for a login feature:

*Disproof:* Refuted when: the same behaviour is absent when the single named control in the claim is present, and the control is shown to be present rather than assumed. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“The objective is to prevent the creation of a discrepancy factor , allowing an a”) does not occur under a test that isolates that control.

**Additionally, if the client is behind an enterprise proxy that performs SSL/TLS decryption, this will break certificate authentication unless the site is allowed on the proxy.**

and publicly available websites that will have an average user. For example, it wouldn't be a good idea to implement this for a website like Facebook. While this technique can prevent the user from having to type a password (thus protecting against an average keylogger from stealing it), it is still considered a good idea to consider using both a password and TLS client authentication combined. 
 Additionally, if the client is behind an enterprise proxy that performs SSL/TLS decryption, this will break certificate authentication unless the site is allowed on the proxy. 
 For more information, see: Client-authenticated TLS handshake 
 Authentication and Error Messages ¶ 
 Incorrectly implemented error messages in the case of authentication functionality can be used for the purposes of user ID and password enumeration. An application should respond (both HTTP and HTML) in a generic manner. 
 Authentication Responses ¶ 
 Using any of the authentication mechanisms

*Disproof:* Refuted when: the same behaviour is absent when the single named control in the claim is present, and the control is shown to be present rather than assumed. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“Additionally, if the client is behind an enterprise proxy that performs SSL/TLS ”) does not occur under a test that isolates that control.

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

*Disproof:* Refuted when: the same behaviour is absent when the single named control in the claim is present, and the control is shown to be present rather than assumed. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“Regarding the user enumeration itself, protection against brute-force attacks is”) does not occur under a test that isolates that control.

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

*Disproof:* Refuted when: the same behaviour is absent when the single named control in the claim is present, and the control is shown to be present rather than assumed. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“In return, the response time will be different for the same error, allowing the ”) does not occur under a test that isolates that control.

**The password reset response body is worth inspecting for a reset link, token or OTP, because a token handed back in the response is directly replayable instead of only being mailed to the account owner.**

The password reset response body is worth inspecting for a reset link, token or OTP, because a token handed back in the response is directly replayable instead of only being mailed to the account owner.

HackTricks reference: account takeovers methods (https://kathan19.gitbook.io/howtohunt/account-takeover-methodology/account_takeovers_methods.md)

*Disproof:* The reset response carries no link, token or OTP, and the reset step stays gated on out-of-band delivery to the registered mailbox.

**Some applications decide 2FA authentication success from the HTTP status code of the verification request, so a verification that returns a non-success status can still leave the client treating the second factor as passed.**

Some applications decide 2FA authentication success from the HTTP status code of the verification request, so a verification that returns a non-success status can still leave the client treating the second factor as passed.

HackTricks reference: 2fa bypasses (https://kathan19.gitbook.io/howtohunt/authentication-bypass/2fa_bypasses.md)

*Disproof:* Changing or suppressing the status code of the verification response does not change client state, which follows a server-set authenticated session flag instead.

**The password reset response body is worth inspecting for a reset link, token or OTP, because a token handed back in the response is directly replayable instead of only being mailed to the account owner.**

The password reset response body is worth inspecting for a reset link, token or OTP, because a token handed back in the response is directly replayable instead of only being mailed to the account owner.

HackTricks reference: account takeovers methods (https://kathan19.gitbook.io/howtohunt/account-takeover-methodology/account_takeovers_methods.md)

*Disproof:* The reset response carries no link, token or OTP, and the reset step stays gated on out-of-band delivery to the registered mailbox.

**Some applications decide 2FA authentication success from the HTTP status code of the verification request, so a verification that returns a non-success status can still leave the client treating the second factor as passed.**

Some applications decide 2FA authentication success from the HTTP status code of the verification request, so a verification that returns a non-success status can still leave the client treating the second factor as passed.

HackTricks reference: 2fa bypasses (https://kathan19.gitbook.io/howtohunt/authentication-bypass/2fa_bypasses.md)

*Disproof:* Changing or suppressing the status code of the verification response does not change client state, which follows a server-set authenticated session flag instead.

## Variations

**Where several parties are hosted under one canonical root URI and separated only by an HTTP Basic realm, a credential accepted for one path is reusable at every other path on that origin, so the protection boundary is the origin rather than the resource.**

RFC 7235 states this as a security consideration rather than folklore: schemes relying solely on the realm mechanism expose credentials to all resources on an origin server, and clients that have authenticated to one resource can reuse the same credentials elsewhere on that origin, making it possible for a different resource to harvest credentials for the others. The suggested mitigations are separating protection spaces by host name or port, or restricting direct access to the Authorization header. In hunting terms, this converts an assumed per-path authentication boundary into an origin-wide one, and it changes what a finding means: an injection or XSS on a low-value path becomes a credential-theft path against a high-value sibling. nginx's auth_basic model shows the same shape, since access can be limited by address, by subrequest result, or by JWT rather than by password alone.

*Disproof:* It does not apply where the schemes in use bind the credential to a narrower scope - cookie sessions scoped to a path, a scheme with per-resource tokens, or separate host names or ports per party, which is exactly the mitigation the RFC names. Verify the deployment's actual realm values and host layout before reporting; a site that already separates parties by hostname is not exposed to this, and cookie-based applications do not send a reusable Authorization header at all.

**An OAuth device authorization grant completed by a user is a legitimate authorization flow unless the resulting token is accepted by an endpoint that was never meant to honour that provisioner, which is the actual bypass condition.**

The bypass is an endpoint-scope mismatch, not the social engineering. In the device authorization grant flow, an attacker socially engineers someone into logging into an application with legitimate credentials; the service generates a token that is then obtained by the threat actor, giving the attacker control of the account, and the lures typically claim that the device code is a one-time password. Everything up to token issuance is the flow working as designed, and the same flow is available to sanctioned red teams. The failure that constitutes a bypass is downstream, where the authorization is honoured somewhere it does not belong. A documented certificate-authority case is exactly that shape: tokens that specify an ACME provisioner are accepted by non-ACME endpoints, because the ACME-specific endpoints throw an error indicating that token auth is not supported while other endpoints in the service perform token authorization depending on the provisioner used, and it does not seem that those endpoints were intended to work with ACME. The /sign endpoint there uses the provisioners AuthorizeSign method to validate the provided token. So the detection rule is: a device code flow is a phishing signal, an account-takeover signal, or a sanctioned test; it becomes a bypass finding only when a token minted under one authorization context is accepted by an endpoint that declares a different one. Name both the issuing provisioner and the accepting endpoint.

*Disproof:* Every token issued by the device authorization flow is rejected by endpoints configured for a different provisioner, and acceptance is limited to the endpoints that declare that provisioner, showing no endpoint-scope mismatch exists.

**A SAML relying party that validates a signature without pinning which element the signature must cover is vulnerable to XML signature wrapping, where a forged unsigned assertion is supplied alongside a legitimately signed one.**

XML signature wrapping works because the signature is computed over a canonical form of some part of the document, while the consuming code later reads a different part. The attacker moves the signed assertion somewhere the validator ignores and places a forged assertion where the application reads it. The signature still verifies because the signed bytes are genuine; the authorization decision is not. Testing means obtaining a validly signed response and mutating the STRUCTURE rather than the claims, then checking which identity the resulting session is bound to. A tester who only edits the NameID or attributes inside the signed assertion is testing signature enforcement, which is a different and much easier failure to find.

*Disproof:* If the relying party rejects any document whose signature does not cover the assertion it consumes, and a wrapped variant yields no session, wrapping is not present.

## Technology / Framework Considerations

Not yet researched.

## API Considerations

Not yet researched.

## Attack Chains

- `saml-assertion-signature-wrapping-to-session-identity-substitution` — SAML assertion signature wrapping to attacker-selected session identity (goal: `account_takeover`)

## Real-World Examples

Not yet researched.

## Common False Positives

**A 403 returned after credentials are accepted is the specified response for valid-but-insufficient credentials and must not be filed as broken authentication, because authentication succeeded and authorization refused.**

The two failure modes are deliberately distinguished in HTTP. MDN states that a server receiving valid credentials that are inadequate to access a given resource should respond 403 Forbidden, and that unlike 401 or 407 the browser will not propose another attempt because authentication is impossible for that user. RFC 7235 draws the same line at the challenge level: a 401 carries a WWW-Authenticate challenge, so the client is invited to retry. CWE-287 also warns against conflating the two, noting that use of 'Auth' as an abbreviation is discouraged precisely because it blurs authentication and authorization. In the field this means a login form returning 403 for a low-privilege account is the control working - reporting it as an authn flaw invites a fix that breaks the authorization model.

*Disproof:* It IS an authentication defect if the 403 is returned in place of a 401 when the credentials themselves are wrong or absent, because the client is then never invited to supply them and legitimate users are locked out - or if the application reveals the 403 only after it has already established a session, meaning the session was granted and then the response shape confused the test. Distinguish by whether any correct credential for that user can obtain access, not by the status code alone.

**An OAuth device authorization grant that the resource owner completes in person at the verification endpoint the provider printed is the intended flow and is not an authentication bypass, because the grant is authorized by the account holder rather than captured from them.**

The lookalike: you run a device-code flow, the code and user_code are shown to you, you enter them on the identity provider's verification URI, approve, and the token endpoint then returns tokens. Scanners and careless manual testing both record this as an authentication bypass because tokens were minted. The discriminator is who authorized the grant. In the intended flow the human who typed the user_code IS the account holder, acting deliberately at the endpoint the provider printed; the attacker never holds the account and gains nothing they did not already have. The bypass case is different in kind: the same grant is accepted by an endpoint that was never intended to serve it, so the resource owner's approval is laundered through a component that should not have honoured it. Test the discriminator by reading the verification_uri the provider issued and confirming it is the provider's own host, and by confirming the human who approved is the account holder. Report the second case; discard the first.

*Disproof:* Refuted when the verification endpoint the grant was completed at is the identity provider's own published URI, and the account that approved is the account whose token was issued; where the approving human is the resource owner acting deliberately, no identity was claimed that the claimant could not already prove.

**A session variable populated before login that carries no privilege and is discarded at authentication is session-puzzling surface, not an authentication bypass, and is only a bypass once the pre-login value determines an authenticated identity.**

The lookalike: you browse as an anonymous visitor, the server issues a session cookie, you edit one session variable (a role, a user id, a cart owner, an isAdmin flag), you then log in, and the response shows an elevated identity or an object that should not be yours. The discriminating test is whether the pre-login value survived the authentication transition with authority, not whether it existed. Two observations settle it. First, whether the variable is present in the session at all before credentials are supplied - if it is only written after authentication, the pre-login edit cannot have influenced anything. Second, whether the post-login identity is the one you authenticated as: the winning case is your own account returning data or actions belonging to a different principal. What refutes the finding is the case where the pre-login variable is cosmetic (a theme, a locale, a cart id that is re-keyed to the authenticated user) and the post-login session resolves solely from the credential that was just presented. Distinguish this from a genuine session-puzzling bug, where improper handling of session variables does lead to authentication bypasses or account takeover: the class of defect is the same, the evidence threshold is not.

*Disproof:* Refuted when the session variable observed before authentication is never read on any post-login code path, or when the post-login session resolves exclusively from the credential just presented and the edited pre-login value is overwritten rather than merged; a token that carries no principal and confers no authority cannot be an authentication bypass.

**A differential response between a known-nonexistent username and a known-existing username with a wrong password is only username enumeration if the difference is observable by an unauthenticated party, so a difference visible solely in server-side logs does not support the finding.**

The distinction that keeps this honest is between what an attacker can read and what an operator can read. The weakness requires the product to fail to prove an identity claim; a timing or message difference that the response body and status do not expose is a hardening observation, not a demonstrable enumeration channel. Hunt it as a channel test rather than a source-code judgement: submit a valid-format unknown identifier and a known-bad password, then a known-valid identifier with the same bad password, and compare status, body length, and time across many samples to separate a real signal from noise. Single-shot timing comparisons on a noisy network produce findings that do not survive a re-test, which is why the class is under-reported as often as over-reported.

*Disproof:* It is a real enumeration channel if the two responses differ observably to the unauthenticated requester - a different status, a distinguishable body, a materially different response time after averaging, or a redirect difference. Note also that some differentials are legitimate: RFC 7235 describes 401 responses that carry a possibly new challenge, and browsers handling cross-origin images no longer trigger authentication dialogs, so a differential that depends on browser behaviour is not a server-side enumeration primitive.
**Hypothesis:** A session variable set before login and carried into the authenticated session makes the pre-login identity authoritative, so editing it yields an authentication bypass.
- Invalidated by: The mutated variable is overwritten at the authentication transition rather than merged, so both sessions resolve to the credential just presented and the gated action stays denied; the variable was a locale or theme value with no authority.
- **Rejection rule:** A pre-auth session variable is an authentication bypass only when it survives the login transition with authority: prove the post-login session resolves to a principal you did not authenticate as, or that an authorization-gated action newly succeeds. Presence and editability are not privilege.

**Hypothesis:** No rate limiting was observed on verification endpoints, therefore account enumeration is possible
- Invalidated by: The credential-issuing endpoints on the in-scope hosts return not found; the real authentication flow lives on a host outside the authorised scope. With no in-scope endpoint performing the check, the absence of throttling there is a fact about scope, not a missing control
- **Rejection rule:** Absence of rate limiting is only measurable where the operation happens. If the authenticating endpoint is out of scope or unreachable, you have not shown a missing control - you have shown you could not test. Say that instead of reporting the absence

## Validation

**An authentication bypass is proven by the credential-free second session carrying the victim's privileges, not by a 200 status, a redirect to a dashboard, or the absence of a login prompt on a single request.**

CWE-287 defines the weakness as the product not proving or insufficiently proving that an identity claim is correct, which makes the proof obligation about the identity assertion itself. A 302 to the post-login page proves only that the server chose to send a Location header; plenty of applications redirect before completing the session, and plenty of protected pages render a shell that fetches data client-side and fails to fetch. The field evidence that closes the finding is a fresh cookie jar with no credentials submitted that still reaches an authenticated-only resource and returns data scoped to the victim - a distinct session identifier that was never obtained through login, plus the victim-scoped payload. That pair is what a triager needs and what a status code cannot supply.

*Disproof:* It is not a bypass if the second session carries a different identity, or if the data returned is identical for every anonymous caller (a public or cached shell), or if the privileged resource re-checks the session server-side and returns 401 or 403 on the fresh jar. Also watch for a pre-seeded anonymous session cookie that the server treats as a guest with no privileges - that is a normal unauthenticated path, not an identity claim the product failed to check.

**A session-puzzling candidate is confirmed only when a pre-authentication session variable, set before credentials are supplied, still determines the authenticated identity or an authorization decision after login.**

Run the discriminating test in three steps against a session you control end to end. Step 1, baseline: request an authenticated-adjacent page with no cookie at all and record the response, then log in normally and record the post-login identity, so you hold the reference answer for what your own session legitimately resolves to. Step 2, pre-login poisoning: as an anonymous visitor, take the session cookie the server issues, mutate exactly one session variable on the server side (a role, an owner id, a tenant, a user reference) using your own test values, and carry that same cookie into the login POST - do not create a second session at the login step. Step 3, authority read: after the login response, request the same authenticated-adjacent resource and compare the resolved identity and the authorization outcome against the baseline from step 1. The observation that proves the finding is a differential in authority, not in bytes: the post-login session resolves to a principal you did not authenticate as, or an action gated on role or ownership succeeds for your account where the baseline denied it. A cosmetic variable, a locale, a theme, or a cart id that is re-keyed to your authenticated user produces no differential and must be discarded.

*Disproof:* Refuted when the post-login session resolves to the principal whose credentials were just presented, the mutated variable is overwritten rather than merged at the authentication transition, and the authorization-gated action denied in the baseline remains denied; a session value that cannot survive authentication cannot produce an authority differential.

**To decide this case, observe: What refutes the finding is the case where the pre-login variable is cosmetic (a theme, a locale, a cart id that is re-keyed to the authenticated user) and the post-login session resolves solely from the credential that was just presented.**

Derived from authn.fp_rule.preauth_session_variable_is_not_bypass, which states the false-positive boundary for this class. The observable above is what separates a real finding from the pattern that only looks like one. A hunter who cannot produce this observation in a request/response pair does not have a finding yet.

*Disproof:* This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (authn.fp_rule.preauth_session_variable_is_not_bypass) states the full boundary.

**To decide this case, observe: So the detection rule is: a device code flow is a phishing signal, an account-takeover signal, or a sanctioned test; it becomes a bypass finding only when a token minted under one authorization context is accepted by an endpoint that declares a different one.**

Derived from authn.bypass.device_code_grant_accepted_by_a_non_intended_endpoint, which states the false-positive boundary for this class. The observable above is what separates a real finding from the pattern that only looks like one. A hunter who cannot produce this observation in a request/response pair does not have a finding yet.

*Disproof:* This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (authn.bypass.device_code_grant_accepted_by_a_non_intended_endpoint) states the full boundary.

**A mismatch between the character encoding a browser uses to transmit a credential and the encoding the server uses to compare it is a candidate authentication bypass that must be probed with encoded variants of a known-bad password.**

MDN records that browsers use utf-8 for usernames and passwords and that Firefox once used ISO-8859-1 before changing for parity with other browsers and to avoid documented problems. That history is the mechanism: the server compares bytes, and if a legacy or mismatched path encodes a submitted credential differently from the stored hash input, one byte sequence can compare equal where the intended character does not. The field test is a differential encoding probe - submit the known-bad password in a small set of encodings and look for the one that authenticates. Because the failure mode is byte-level, the payloads must be raw requests with explicit encodings; a browser-driven test will simply never generate them.

*Disproof:* It is not a bypass if the application normalises the credential to a canonical encoding before hashing or comparing, or if it rejects malformed byte sequences outright, or if the endpoint no longer accepts the legacy scheme. Establish the negative control first - a correctly-encoded known-bad password must fail - and only then attribute any success to the encoding difference, since a variant that succeeds for the wrong reason (a different account, a cached response) would otherwise produce a false finding.

**Where a target enforces a weak password policy, the absence of login throttling can be proven by registering a throwaway account with a very weak password and then issuing unlimited login attempts against it.**

Where a target enforces a weak password policy, the absence of login throttling can be proven by registering a throwaway account with a very weak password and then issuing unlimited login attempts against it.

HackTricks reference: account takeovers methods (https://kathan19.gitbook.io/howtohunt/account-takeover-methodology/account_takeovers_methods.md)

*Disproof:* The login endpoint applies account lockout, login throttling or a challenge after a small number of attempts, so the extra attempts never reach password checking.

**Where a target enforces a weak password policy, the absence of login throttling can be proven by registering a throwaway account with a very weak password and then issuing unlimited login attempts against it.**

Where a target enforces a weak password policy, the absence of login throttling can be proven by registering a throwaway account with a very weak password and then issuing unlimited login attempts against it.

HackTricks reference: account takeovers methods (https://kathan19.gitbook.io/howtohunt/account-takeover-methodology/account_takeovers_methods.md)

*Disproof:* The login endpoint applies account lockout, login throttling or a challenge after a small number of attempts, so the extra attempts never reach password checking.

## Impact

Not yet researched.

## Related Bug Classes

Not yet researched.

## References

- **academy.hackthebox.com** (docs)
  - <https://academy.hackthebox.com/course/preview/abusing-http-misconfigurations>
- **blog.trailofbits.com** (writeup)
  - <https://blog.trailofbits.com/2026/09/21/saml-a-fractal-of-bad-design/>
- **cheatsheetseries.owasp.org** (cheatsheet)
  - <https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html>
- **cwe.mitre.org** (cwe)
  - <https://cwe.mitre.org/data/definitions/287.html>
  - <https://cwe.mitre.org/data/definitions/862.html>
- **developer.mozilla.org** (writeup)
  - <https://developer.mozilla.org/en-US/docs/Web/HTTP/Authentication>
- **docs.oasis-open.org** (standard)
  - <https://docs.oasis-open.org/security/saml/v2.0/saml-core-2.0-os.pdf>
- **kathan19.gitbook.io** (reference)
  - <https://kathan19.gitbook.io/howtohunt/account-takeover-methodology/account_takeovers_methods.md>
  - <https://kathan19.gitbook.io/howtohunt/authentication-bypass/2fa_bypasses.md>
- **microsoft.com** (research)
  - <https://www.microsoft.com/en-us/security/blog/2026/09/02/impersonating-it-support-threat-actors-turn-remote-session-into-enterprise-wide-access/>
- **netlas.io** (writeup)
  - <https://netlas.io/blog/weaponized_rmm/>
- **nginx.org** (writeup)
  - <https://nginx.org/en/docs/http/ngx_http_auth_basic_module.html>
- **portswigger.net** (taxonomy)
  - <https://portswigger.net/web-security/access-control>
  - <https://portswigger.net/web-security/oauth>
- **proofpoint.com** (research)
  - <https://www.proofpoint.com/us/blog/threat-insight/access-granted-phishing-device-code-authorization-account-takeover>
- **rfc-editor.org** (research)
  - <https://www.rfc-editor.org/rfc/rfc7235.html>
- **talosintelligence.com** (vendor_advisory)
  - <https://www.talosintelligence.com/vulnerability_reports/TALOS-2025-2242>

Every item above is gated on >= 2 distinct publisher hosts (`wks/quality.py`, rule R1). Publisher diversity, not citation count, is what makes these corroborated.
