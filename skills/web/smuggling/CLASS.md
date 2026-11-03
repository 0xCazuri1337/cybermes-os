<!-- GENERATED from db/wks.db — do not edit -->
# Request Smuggling / HTTP Desync

## Definition

Front-end and back-end disagree about where one request ends, so one request becomes two.

- **CWE:** 444
- **OWASP:** A04:2021
- **Surface:** web
- **Aliases:** ["request smuggling", "http desync", "cl te", "te cl"]

Canonical home for `smuggling`. Rendered from `db/wks.db` by `tools/taxonomy/build_taxonomy.py` — edit the rows, not this file.

## Root Cause

Not yet researched.

## Preconditions

**HTTP request smuggling is rooted in the HTTP/1 specification providing two competing ways to declare the end of a message body (Content-Length and Transfer-Encoding); when a front-end server and a back-end server parse these headers differently, a single request can be interpreted as two requests, desyncing the connection.**

Most HTTP request smuggling vulnerabilities arise because the HTTP/1 specification provides two different ways to specify where a request ends: the Content-Length header and the Transfer-Encoding header. The Content-Length header specifies the length of the message body in bytes. The Transfer-Encoding header can specify that the message body uses chunked encoding. As the HTTP/1 specification provides two different methods for specifying the length of HTTP messages, it is possible for a single message to use both methods at once, such that they conflict with each other. If the front-end and back-end servers behave differently in relation to the (possibly obfuscated) Transfer-Encoding header, then they might disagree about the boundaries between successive requests, leading to request smuggling vulnerabilities. Note that websites that use HTTP/2 end-to-end are inherently immune, because the HTTP/2 specification introduces a single, robust mechanism for specifying the length of a request.

*Disproof:* Refuted if an authoritative source shows the ambiguity is not present, e.g., an HTTP/2 end-to-end deployment where the HTTP/2 specification mandates a single request-length mechanism and there is no way for an attacker to introduce the required ambiguity.

**Because HTTP/2 frames carry explicit lengths there is no framing ambiguity for a classic desync to exploit, so any H2 smuggling attempt has to originate at the downgrade boundary rather than in the H2 layer itself.**

Because HTTP/2 frames carry explicit lengths there is no framing ambiguity for a classic desync to exploit, so any H2 smuggling attempt has to originate at the downgrade boundary rather than in the H2 layer itself.

HackTricks reference: Request Smuggling in HTTP/2 Downgrades (pentesting-web/http-request-smuggling/request-smuggling-in-http-2-downgrades.md)

*Disproof:* Refuted if a desync is reproducible entirely within HTTP/2 with no downgrade involved, which would mean frame length is not enforced end to end.

## Attack Surface

Surface: **web**.

The entry points and enabling conditions for this surface are enumerated under **Preconditions**; the observable signals are under **Detection**.

## Detection

**Requests to appliance administrative asset paths act as an early reconnaissance fingerprint for exploitation, and the repetition of an otherwise mundane static-path request from changing infrastructure is itself the signal.**

Exploitation of edge appliances commonly begins with a request for a static administrative asset path that a normal client would not fetch. Because the request is a plain GET for a file, filtering and rate limiting rarely treat it as hostile, which is precisely why it survives to the vulnerable handler. Two properties make it useful to a defender: the path is predictable enough to hunt for in logs, and an attacker probing from rotating infrastructure produces a scattered request pattern for one static path, which is anomalous even though each individual request is unremarkable.

*Disproof:* If the appliance never served that asset path, or the same requests occur steadily from stable client infrastructure with no subsequent exploitation, the traffic is ordinary client behaviour.

**CWE-444 (Inconsistent Interpretation of HTTP Requests, aka 'HTTP Request/Response Smuggling') is the canonical weakness describing how a malformed or unexpected HTTP message can be interpreted differently by the client/server than by intermediary HTTP agents such as load balancers, reverse proxies, web caching proxies, and application firewalls, letting an adversary smuggle a message to the client/server without the intermediary being aware of it.**

HTTP requests or responses (messages) can be malformed or unexpected in ways that cause web servers or clients to interpret the messages in different ways than intermediary HTTP agents such as load balancers, reverse proxies, web caching proxies, application firewalls, etc. For example, an adversary may be able to add duplicate or different header fields that a client or server might interpret as one set of messages, whereas the intermediary might interpret the same sequence of bytes as a different set of messages. The inconsistent parsing and interpretation of messages can allow the adversary to smuggle a message to the client/server without the intermediary being aware of it. This weakness is usually the result of the usage of outdated or incompatible HTTP protocol versions in the HTTP agents. Modern frameworks also expand the attack surface through protocol downgrades (HTTP/2 to HTTP/1.1), cleartext HTTP/2 (H2C) upgrades, header normalization mismatches, and connection reuse across protocol boundaries.

*Disproof:* Refuted if an authoritative source shows that all intermediaries in a chain use a single strict HTTP parsing procedure (e.g., a web server employing a strict HTTP parsing procedure), making interpretation consistent across every agent and preventing the adversary from smuggling a message undetected.

**A convincing observation for this class is: The useful next question is which layer decided, not what the status code was.**

Derived from smuggling.fp_rule.a_400_on_a_conflicting_te_cl_request_is_the_spec_mandated_outcome_not_a_failed_attack, which states the boundary for this class. The observation above is what a report must contain to be believed: an artifact the reviewer can re-check, not a claim the hunter asserts. A finding without it is an assertion.

*Disproof:* Not evidence when the observable cannot be produced at all -- blind, server-side-only, or identical-in-every-case behaviour leaves nothing to show. The originating rule (smuggling.fp_rule.a_400_on_a_conflicting_te_cl_request_is_the_spec_mandated_outcome_not_a_failed_attack) states the full boundary.

**A convincing observation for this class is: Adjacent behaviour that produces the same observable result: It basically enables you to hide a payload in plain sight.**

Derived from smuggling.fp_rule.auto.derived, which states the boundary for this class. The observation above is what a report must contain to be believed: an artifact the reviewer can re-check, not a claim the hunter asserts. A finding without it is an assertion.

*Disproof:* Not evidence when the observable cannot be produced at all -- blind, server-side-only, or identical-in-every-case behaviour leaves nothing to show. The originating rule (smuggling.fp_rule.auto.derived) states the full boundary.

## Exploitation

**The three canonical attack orientations are CL.TE (front-end uses Content-Length, back-end uses Transfer-Encoding), TE.CL (front-end uses Transfer-Encoding, back-end uses Content-Length), and TE.TE (both support Transfer-Encoding but one is induced not to process it).**

Classic request smuggling attacks involve placing both the Content-Length header and the Transfer-Encoding header into a single HTTP/1 request and manipulating these so that the front-end and back-end servers process the request differently. The exact way in which this is done depends on the behavior of the two servers. CL.TE: the front-end server uses the Content-Length header and the back-end server uses the Transfer-Encoding header. TE.CL: the front-end server uses the Transfer-Encoding header and the back-end server uses the Content-Length header. TE.TE: the front-end and back-end servers both support the Transfer-Encoding header, but one of the servers can be induced not to process it by obfuscating the header in some way.

*Disproof:* Refuted if an authoritative source shows the TE.TE orientation cannot be exploited in practice, e.g., a strict parser that rejects every obfuscated Transfer-Encoding variant before it reaches the back-end, eliminating the discrepancy.

**It basically enables you to hide a payload in plain sight.**

or this page to function normally. 
 

 

 
 
 
 
 
 
 

 
 
 
 
 
 
 
 Mirko Zorz , Director of Content, Help Net Security
 
 February 29, 2024 
 
 
 
 
 Share 
 
 
 
 
 
 
 
 
 
 
 
 
 
 
 
 
 
 
 
 
 
 
 
 
 

 BobTheSmuggler: Open-source tool for undetectable payload delivery 
 
 
 BobTheSmuggler is an open-source tool designed to easily compress, encrypt, and securely transport your payload. It basically enables you to hide a payload in plain sight. 
 
 BobTheSmuggler is helpful in phishing campaign assessments, data exfiltration exercises, and assumed breach scenarios. 
 Features 
 
 Hiding the payload inside images and calling it separately from a JavaScript code. 
 Using dynamic XOR encryption to hide the payloads. This helps bypass network firewalls and monitoring tools (including DLPs). 
 Keeping the HTML size to ~1KB. Easy for payload

*Disproof:* Refuted when: the same behaviour is absent when the single named control in the claim is present, and the control is shown to be present rather than assumed. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“It basically enables you to hide a payload in plain sight.”) does not occur under a test that isolates that control.

**It does not indicate successful exploitation on patched devices.**

dating and patching will not remove access for attackers that have already established persistence within a compromise the network. 
 As of Sept. 27, 2026, Palo Alto Networks Cortex Xpanse has identified the presence of 50,277 exposed instances potentially vulnerable to these CVEs based on our telemetry. 
 Unit 42 Managed Threat Hunting Queries 
 This query looks for CVE-2026-88771 log poisoning. It does not indicate successful exploitation on patched devices. Unpatched devices will lead to execution if this log poisoning is present on a system. 

 
 
 
 
 
 
dataset = citrix_adc_raw 
 
| filter _raw_log contains "pitboss" 
 
| alter log_type = arrayindex(regextract(_raw_log, " ]+>(?:[A-Za-z]{3}[ ]+[0-9]{1,2}[ ]+|[ ]+[0-9]{2}/[0-9]{2}/[0-9]{4}:)[0-9]{2}:[0-9]{2}:[0-9]{2}.+default ([\w]+)"), 0), 
 
log_sub_type = arrayindex(regextract(_raw_log, " ]+>(?:

*Disproof:* This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "It does not indicate successful exploitation on patched devices.".

**It does not indicate successful exploitation on patched devices.**

dating and patching will not remove access for attackers that have already established persistence within a compromise the network. 
 As of Sept. 27, 2026, Palo Alto Networks Cortex Xpanse has identified the presence of 50,277 exposed instances potentially vulnerable to these CVEs based on our telemetry. 
 Unit 42 Managed Threat Hunting Queries 
 This query looks for CVE-2026-88771 log poisoning. It does not indicate successful exploitation on patched devices. Unpatched devices will lead to execution if this log poisoning is present on a system. 

 
 
 
 
 
 
dataset = citrix_adc_raw 
 
| filter _raw_log contains "pitboss" 
 
| alter log_type = arrayindex(regextract(_raw_log, " ]+>(?:[A-Za-z]{3}[ ]+[0-9]{1,2}[ ]+|[ ]+[0-9]{2}/[0-9]{2}/[0-9]{4}:)[0-9]{2}:[0-9]{2}:[0-9]{2}.+default ([\w]+)"), 0), 
 
log_sub_type = arrayindex(regextract(_raw_log, " ]+>(?:

*Disproof:* This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "It does not indicate successful exploitation on patched devices.".

**The grep -q guard prevents duplicate injection if the persistence mechanism is run again.**

lias: /logon/LogonPoint/custom/receiver.min.css → web shell 
 Regex alias: /logon/LogonPoint/custom/receiver.min. .css → web shell (any hex suffix) 
 
 
 
 The CSS filename disguise is deliberate. Browser developer tools, web application firewall logs and blue team analysts watching HTTP traffic will see what looks like a versioned CSS asset load, which is completely normal for a web application. The grep -q guard prevents duplicate injection if the persistence mechanism is run again. 
 Enable PHP Engine 
 The perl -pi -e 's/php_flag engine off/php_flag engine on /' /etc/httpd.conf one-liner substitutes php_flag engine off with php_flag engine on in httpd.conf to enable PHP, which is required for the web shell to execute. NetScaler's Apache config ships with php_flag engine off to disable PHP execution globally as a security hardening measure. 
 Reload Apache Using Updated Con

*Disproof:* Refuted when: the value is bound as a parameter or written through the framework's own encoder, so the interpreter never sees attacker text as syntax. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“The grep -q guard prevents duplicate injection if the persistence mechanism is r”) does not occur under a test that isolates that control.

**The grep -q guard prevents duplicate injection if the persistence mechanism is run again.**

lias: /logon/LogonPoint/custom/receiver.min.css → web shell 
 Regex alias: /logon/LogonPoint/custom/receiver.min. .css → web shell (any hex suffix) 
 
 
 
 The CSS filename disguise is deliberate. Browser developer tools, web application firewall logs and blue team analysts watching HTTP traffic will see what looks like a versioned CSS asset load, which is completely normal for a web application. The grep -q guard prevents duplicate injection if the persistence mechanism is run again. 
 Enable PHP Engine 
 The perl -pi -e 's/php_flag engine off/php_flag engine on /' /etc/httpd.conf one-liner substitutes php_flag engine off with php_flag engine on in httpd.conf to enable PHP, which is required for the web shell to execute. NetScaler's Apache config ships with php_flag engine off to disable PHP execution globally as a security hardening measure. 
 Reload Apache Using Updated Con

*Disproof:* Refuted when: the value is bound as a parameter or written through the framework's own encoder, so the interpreter never sees attacker text as syntax. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“The grep -q guard prevents duplicate injection if the persistence mechanism is r”) does not occur under a test that isolates that control.

**It basically enables you to hide a payload in plain sight.**

or this page to function normally. 
 

 

 
 
 
 
 
 
 

 
 
 
 
 
 
 
 Mirko Zorz , Director of Content, Help Net Security
 
 February 29, 2024 
 
 
 
 
 Share 
 
 
 
 
 
 
 
 
 
 
 
 
 
 
 
 
 
 
 
 
 
 
 
 
 

 BobTheSmuggler: Open-source tool for undetectable payload delivery 
 
 
 BobTheSmuggler is an open-source tool designed to easily compress, encrypt, and securely transport your payload. It basically enables you to hide a payload in plain sight. 
 
 BobTheSmuggler is helpful in phishing campaign assessments, data exfiltration exercises, and assumed breach scenarios. 
 Features 
 
 Hiding the payload inside images and calling it separately from a JavaScript code. 
 Using dynamic XOR encryption to hide the payloads. This helps bypass network firewalls and monitoring tools (including DLPs). 
 Keeping the HTML size to ~1KB. Easy for payload

*Disproof:* Refuted when: the same behaviour is absent when the single named control in the claim is present, and the control is shown to be present rather than assumed. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“It basically enables you to hide a payload in plain sight.”) does not occur under a test that isolates that control.

**In this exploit chain, the attacker sends crafted DTLS traffic to a vulnerable NetScaler device, which processes the malicious packet.**

quested the same file, /admin_ui/common/css/ns/ui.css . Nearly two hours after that second request, 77.83.199[.]39 requested /vpn/js/rdx/core/lang/rdx_en.json.gz . These requests are consistent with version fingerprinting. 
 On August 21 and 22, these two hosts and 78.47.24[.]217 sent the same requests to more than 100 other systems. 
 CVE-2026-88772: DTLS Exploitation To .deb Webshell Activity 
 In this exploit chain, the attacker sends crafted DTLS traffic to a vulnerable NetScaler device, which processes the malicious packet. This malicious packet causes memory corruption or a crash that can lead to either code execution or denial of service. 
 Between September 4 and 24, the threat actor repeatedly requested files from the appliance's /vpn/scripts/linux/ folder. This folder normally hosts Citrix client installation packages. The threat actor also used this folder to host their web shells. 
 The threat actor rotated i

*Disproof:* Refuted when: the same behaviour is absent when the single named control in the claim is present, and the control is shown to be present rather than assumed. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“In this exploit chain, the attacker sends crafted DTLS traffic to a vulnerable N”) does not occur under a test that isolates that control.

**In this exploit chain, the attacker sends crafted DTLS traffic to a vulnerable NetScaler device, which processes the malicious packet.**

quested the same file, /admin_ui/common/css/ns/ui.css . Nearly two hours after that second request, 77.83.199[.]39 requested /vpn/js/rdx/core/lang/rdx_en.json.gz . These requests are consistent with version fingerprinting. 
 On August 21 and 22, these two hosts and 78.47.24[.]217 sent the same requests to more than 100 other systems. 
 CVE-2026-88772: DTLS Exploitation To .deb Webshell Activity 
 In this exploit chain, the attacker sends crafted DTLS traffic to a vulnerable NetScaler device, which processes the malicious packet. This malicious packet causes memory corruption or a crash that can lead to either code execution or denial of service. 
 Between September 4 and 24, the threat actor repeatedly requested files from the appliance's /vpn/scripts/linux/ folder. This folder normally hosts Citrix client installation packages. The threat actor also used this folder to host their web shells. 
 The threat actor rotated i

*Disproof:* Refuted when: the same behaviour is absent when the single named control in the claim is present, and the control is shown to be present rather than assumed. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“In this exploit chain, the attacker sends crafted DTLS traffic to a vulnerable N”) does not occur under a test that isolates that control.

**In this exploit chain, the attacker sends crafted DTLS traffic to a vulnerable NetScaler device, which processes the malicious packet.**

quested the same file, /admin_ui/common/css/ns/ui.css . Nearly two hours after that second request, 77.83.199[.]39 requested /vpn/js/rdx/core/lang/rdx_en.json.gz . These requests are consistent with version fingerprinting. 
 On August 21 and 22, these two hosts and 78.47.24[.]217 sent the same requests to more than 100 other systems. 
 CVE-2026-88772: DTLS Exploitation To .deb Webshell Activity 
 In this exploit chain, the attacker sends crafted DTLS traffic to a vulnerable NetScaler device, which processes the malicious packet. This malicious packet causes memory corruption or a crash that can lead to either code execution or denial of service. 
 Between September 4 and 24, the threat actor repeatedly requested files from the appliance's /vpn/scripts/linux/ folder. This folder normally hosts Citrix client installation packages. The threat actor also used this folder to host their web shells. 
 The threat actor rotated i

*Disproof:* Refuted when: the same behaviour is absent when the single named control in the claim is present, and the control is shown to be present rather than assumed. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“In this exploit chain, the attacker sends crafted DTLS traffic to a vulnerable N”) does not occur under a test that isolates that control.

**They should be seen as general hunting guidance until more is known about the exploitation activity identified by Citrix in their advisory.**

he following:
 
 A NetScaler VPX instance snapshot 
 Logs on remote syslog servers and NetScaler Console 
 A technical support bundle 
 A packet engine core dump 
 
 
 Hunt for the following:
 
 Signs of suspicious administrative sessions 
 Unexpected outbound connections 
 Unexplained gaps in logging 
 
 
 
 Note: These are not TTPs we have observed specifically related to these vulnerabilities. They should be seen as general hunting guidance until more is known about the exploitation activity identified by Citrix in their advisory. 
 
 Update and patch to the latest versions 
 
 Note: Updating and patching will not remove access for attackers that have already established persistence within a compromise the network. 
 As of Sept. 27, 2026, Palo Alto Networks Cortex Xpanse has identified the presence of 50,277 exposed instances potentially vulnerable to these CVEs based on our telemetry. 
 Unit 42 Managed Threat Hunting Quer

*Disproof:* Refuted when: the same behaviour is absent when the single named control in the claim is present, and the control is shown to be present rather than assumed. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“They should be seen as general hunting guidance until more is known about the ex”) does not occur under a test that isolates that control.

**They should be seen as general hunting guidance until more is known about the exploitation activity identified by Citrix in their advisory.**

he following:
 
 A NetScaler VPX instance snapshot 
 Logs on remote syslog servers and NetScaler Console 
 A technical support bundle 
 A packet engine core dump 
 
 
 Hunt for the following:
 
 Signs of suspicious administrative sessions 
 Unexpected outbound connections 
 Unexplained gaps in logging 
 
 
 
 Note: These are not TTPs we have observed specifically related to these vulnerabilities. They should be seen as general hunting guidance until more is known about the exploitation activity identified by Citrix in their advisory. 
 
 Update and patch to the latest versions 
 
 Note: Updating and patching will not remove access for attackers that have already established persistence within a compromise the network. 
 As of Sept. 27, 2026, Palo Alto Networks Cortex Xpanse has identified the presence of 50,277 exposed instances potentially vulnerable to these CVEs based on our telemetry. 
 Unit 42 Managed Threat Hunting Quer

*Disproof:* Refuted when: the same behaviour is absent when the single named control in the claim is present, and the control is shown to be present rather than assumed. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“They should be seen as general hunting guidance until more is known about the ex”) does not occur under a test that isolates that control.

**The attacker sends an HTTP request to the NetScaler device with a dropper command encoded as Base64 text in the User-Agent string.**

specified file path with optional append mode 
 info command returns the PHP version in the format php=PHP_VERSION\nns=4 
 
 CVE-2026-88771: Three Stage Command Injection Exploit to Web Shell Execution 
 On September 21, an actor from 77.83.199[.]39 , 78.47.24[.]217 and 139.180.152[.]138 dropped a PHP web shell in a three-stage process against a U.S.-based target’s NetScaler devices. 
 Stage 1 
 The attacker sends an HTTP request to the NetScaler device with a dropper command encoded as Base64 text in the User-Agent string. The NetScaler device sends back a 404 error as expected, but this User-Agent string is added to the /var/log/httpaccess-vpn.log . 
 Stage 2 
 The attacker submits a login request that includes additional text that is logged as a failure message to /var/log/ns.log as: 
 pitboss PPE missed too many heartbeatsNSPPE; 
 Eventually this ns.log file will be processed by the vulnerable Perl script at /ne

*Disproof:* Refuted when: the same behaviour is absent when the single named control in the claim is present, and the control is shown to be present rather than assumed. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“The attacker sends an HTTP request to the NetScaler device with a dropper comman”) does not occur under a test that isolates that control.

**The attacker sends an HTTP request to the NetScaler device with a dropper command encoded as Base64 text in the User-Agent string.**

specified file path with optional append mode 
 info command returns the PHP version in the format php=PHP_VERSION\nns=4 
 
 CVE-2026-88771: Three Stage Command Injection Exploit to Web Shell Execution 
 On September 21, an actor from 77.83.199[.]39 , 78.47.24[.]217 and 139.180.152[.]138 dropped a PHP web shell in a three-stage process against a U.S.-based target’s NetScaler devices. 
 Stage 1 
 The attacker sends an HTTP request to the NetScaler device with a dropper command encoded as Base64 text in the User-Agent string. The NetScaler device sends back a 404 error as expected, but this User-Agent string is added to the /var/log/httpaccess-vpn.log . 
 Stage 2 
 The attacker submits a login request that includes additional text that is logged as a failure message to /var/log/ns.log as: 
 pitboss PPE missed too many heartbeatsNSPPE; 
 Eventually this ns.log file will be processed by the vulnerable Perl script at /ne

*Disproof:* Refuted when: the same behaviour is absent when the single named control in the claim is present, and the control is shown to be present rather than assumed. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“The attacker sends an HTTP request to the NetScaler device with a dropper comman”) does not occur under a test that isolates that control.

**The attacker sends an HTTP request to the NetScaler device with a dropper command encoded as Base64 text in the User-Agent string.**

specified file path with optional append mode 
 info command returns the PHP version in the format php=PHP_VERSION\nns=4 
 
 CVE-2026-88771: Three Stage Command Injection Exploit to Web Shell Execution 
 On September 21, an actor from 77.83.199[.]39 , 78.47.24[.]217 and 139.180.152[.]138 dropped a PHP web shell in a three-stage process against a U.S.-based target’s NetScaler devices. 
 Stage 1 
 The attacker sends an HTTP request to the NetScaler device with a dropper command encoded as Base64 text in the User-Agent string. The NetScaler device sends back a 404 error as expected, but this User-Agent string is added to the /var/log/httpaccess-vpn.log . 
 Stage 2 
 The attacker submits a login request that includes additional text that is logged as a failure message to /var/log/ns.log as: 
 pitboss PPE missed too many heartbeatsNSPPE; 
 Eventually this ns.log file will be processed by the vulnerable Perl script at /ne

*Disproof:* Refuted when: the same behaviour is absent when the single named control in the claim is present, and the control is shown to be present rather than assumed. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“The attacker sends an HTTP request to the NetScaler device with a dropper comman”) does not occur under a test that isolates that control.

**Public writeup evidence for smuggling: HTTP/2 framing WAF bypass.**

HARVESTED FROM bugbountydaily RSS -> https://lab.ctbb.show/research/h2-WAF-Bypasses
Reason it matters: HTTP/2 framing WAF bypass.

The proxy sends a sub-request to an auth service containing only the request headers - because that is where authentication data lives (Authorization headers, cookies, session tokens).

*Disproof:* Refuted if the fetched page no longer contains this exact span, or if the described behaviour is corrected or withdrawn by the publisher.

**The precondition for request smuggling is a front end and back end that read the same bytes under different framing rules, so the test is one request whose Content-Length and Transfer-Encoding disagree, then checking which value the back end uses to find the request boundary.**

The precondition for request smuggling is a front end and back end that read the same bytes under different framing rules, so the test is one request whose Content-Length and Transfer-Encoding disagree, then checking which value the back end uses to find the request boundary.

HackTricks reference: HTTP Request Smuggling / HTTP Desync Attack (pentesting-web/http-request-smuggling/README.md)

*Disproof:* Refuted if both hops resolve the same request boundary for the conflicting message, or if the front end strips the offending header before forwarding so the back end never sees the ambiguity.

**The smuggling-relevant boundary at a downgrade is body-length metadata, so the tester confirms the translating hop rewrites Content-Length and Transfer-Encoding rather than copying the attacker's values into the HTTP/1.1 request.**

The smuggling-relevant boundary at a downgrade is body-length metadata, so the tester confirms the translating hop rewrites Content-Length and Transfer-Encoding rather than copying the attacker's values into the HTTP/1.1 request.

HackTricks reference: Request Smuggling in HTTP/2 Downgrades (pentesting-web/http-request-smuggling/request-smuggling-in-http-2-downgrades.md)

*Disproof:* Refuted if attacker-chosen Content-Length or Transfer-Encoding values survive verbatim into the downgraded request when observed downstream.

**Modern stacks desynchronise in the response direction too, so the audit has to cover the response translation layer and look for one hop that dechunks or strips Transfer-Encoding while another still trusts Content-Length.**

Modern stacks desynchronise in the response direction too, so the audit has to cover the response translation layer and look for one hop that dechunks or strips Transfer-Encoding while another still trusts Content-Length.

HackTricks reference: HTTP Response Smuggling / Desync (pentesting-web/http-response-smuggling-desync.md)

*Disproof:* Refuted if every hop applies identical dechunking and honours a consistent Content-Length on responses, or if the front end rejects the mismatched response before a second hop can re-frame it.

**HTTP request smuggling arises where a front-end and back-end disagree on where a request ends, so a smuggled request is prepended to the next legitimate user's request.**

In practice on HTB this shows up as:  [https://www.cvedetails.com/vulnerability-list/vendor\_id-10410/product\_id-34824/Eclipse-Jetty.html](https://www.cvedetails.com/vulnerability-list/vendor_id-10410/product_id-34824/Eclipse-Jetty.html)
 [https://portswigger.net/web-security/request-smuggling](https://portswigger.net/web-security/request-smuggling)
> Screenshot omitted: the original GitBook asset is not present in this repository.

Write-up provenance: zweilosec/htb-writeups :: linux-machines/hard/quick-write-up.md (7325 words, classified network).

*Disproof:* Refuted when a front end rejects ambiguous framing outright, or when both hops agree on message boundaries for the same request, leaving no request to smuggle.

## Variations

**A Transfer-Encoding whose final coding is not chunked makes the message body length underivable, so a front-end that only special-cases the literal value chunked can be pushed into framing with a different layer than the back-end uses.**

RFC 9112 is explicit about the consequence: if Transfer-Encoding is present in a request and chunked is not the final encoding, the message body length cannot be determined reliably and the server must respond 400 and close. Sending gzip, chunked or an obfuscated variant such as a spaced or otherwise non-canonical spelling of chunked tests whether the front-end's check is a strict comparison against the canonical token or a real parse of the coding list. A front-end that treats an unrecognised coding as 'no transfer encoding' and falls back to Content-Length while the back-end parses the coding list is exactly the CWE-444 pattern. The field probe is small: send one request per coding-list variant and note which status and which framing each tier implies.

*Disproof:* It is blocked when the front-end and back-end both reject the variant, or when the front-end's parser correctly identifies the coding list and either honours the transfer encoding or rejects the message - a 400 at the edge with no forwarded request. Also note that many modern servers normalise or hard-code the strict behaviour; verify the actual version rather than assuming the classic bypass still applies, and confirm the discrepancy with the log-based proof before reporting.

**The TE.TE orientation can be exploited through many Transfer-Encoding header obfuscation variants that cause one server to ignore the header, including: Transfer-Encoding: xchunked, Transfer-Encoding : chunked, Transfer-Encoding: chunked Transfer-Encoding: x, Transfer-Encoding:[tab]chunked, GET / HTTP/1.1 Transfer-Encoding: chunked, X: X[newline]Transfer-Encoding: chunked, and Transfer-Encoding : chunked.**

There are potentially endless ways to obfuscate the Transfer-Encoding header. Each of these techniques involves a subtle departure from the HTTP specification. Real-world code that implements a protocol specification rarely adheres to it with absolute precision, and it is common for different implementations to tolerate different variations from the specification. To uncover a TE.TE vulnerability, it is necessary to find some variation of the Transfer-Encoding header such that only one of the front-end or back-end servers processes it, while the other server ignores it. Each of these obfuscations is harmless if both the front-end and back-end server have it, and a major threat otherwise.

*Disproof:* Refuted if an authoritative source shows that both parsers in a chain normalize every obfuscation variant to the same form, eliminating the discrepancy that makes TE.TE exploitable.

**When a front end and back end disagree about connection reuse rather than message framing, the defect is a connection-state or routing mismatch, so testing for CL.TE and TE.CL header ambiguity will never surface it.**

When a front end and back end disagree about connection reuse rather than message framing, the defect is a connection-state or routing mismatch, so testing for CL.TE and TE.CL header ambiguity will never surface it.

HackTricks reference: HTTP Connection Request Smuggling (pentesting-web/http-connection-request-smuggling.md)

*Disproof:* Refuted if the desync reproduces from a single unambiguous request with consistent framing and no Transfer-Encoding, which puts the cause back in message framing.

**A chain that shows no CL.TE or TE.CL ambiguity still has sub-forms left to test - the ones that rely on connection reuse, connection state, or the client - so a clean header-desync result does not close the hunt.**

A chain that shows no CL.TE or TE.CL ambiguity still has sub-forms left to test - the ones that rely on connection reuse, connection state, or the client - so a clean header-desync result does not close the hunt.

HackTricks reference: HTTP Response Smuggling / Desync (pentesting-web/http-response-smuggling-desync.md)

*Disproof:* Refuted if no desync can be induced by any manipulation of connection reuse or by a client-side mismatch, meaning the reuse-dependent forms are absent from that chain.

**A request carrying Transfer-Encoding: gzip can desynchronise a chain even with no classic CL.TE split, because one hop still honours Content-Length while another treats the message as illegally framed, making the unexpected encoding value a desync probe on its own.**

A request carrying Transfer-Encoding: gzip can desynchronise a chain even with no classic CL.TE split, because one hop still honours Content-Length while another treats the message as illegally framed, making the unexpected encoding value a desync probe on its own.

HackTricks reference: HTTP Request Smuggling / HTTP Desync Attack (pentesting-web/http-request-smuggling/README.md)

*Disproof:* Refuted if both hops reject the gzip-coded message identically with a 400 for attacker and victim alike, or if the intermediary strips the encoding and the back end sees clean framing.

## Technology / Framework Considerations

Not yet researched.

## API Considerations

Not yet researched.

## Attack Chains

- `chain.smuggling.auto.01` — smuggling: observe, exercise, confirm (goal: `Establish, exercise and confirm a smuggling condition on an authorised target without relying on anyone else's data.`)

## Real-World Examples

Not yet researched.

## Common False Positives

**Request smuggling is prevented by using HTTP/2 end to end and disabling HTTP downgrading if possible; making the front-end server normalize ambiguous requests and the back-end server reject any that remain, closing the TCP connection in the process; and never assuming that requests will not have a body.**

To prevent HTTP request smuggling vulnerabilities, we recommend the following high-level measures: Use HTTP/2 end to end and disable HTTP downgrading if possible. HTTP/2 uses a robust mechanism for determining the length of requests and, when used end to end, is inherently protected against request smuggling. If you can't avoid HTTP downgrading, make sure you validate the rewritten request against the HTTP/1.1 specification. Make the front-end server normalize ambiguous requests and make the back-end server reject any that are still ambiguous, closing the TCP connection in the process. Never assume that requests won't have a body. This is the fundamental cause of both CL.0 and client-side desync vulnerabilities. Default to discarding the connection if server-level exceptions are triggered when handling requests.

*Disproof:* Refuted if an authoritative source shows that request tunnelling attacks can bypass these controls, e.g., by keeping the front-end and back-end on separate connections so that request smuggling still reaches the back-end despite HTTP/2 end-to-end and connection-reuse disabled.

**A front-end returning 400 for a request carrying both Transfer-Encoding and Content-Length is behaving exactly as HTTP/1.1 message parsing requires and must be logged as a negative control rather than as an unexploitable smuggling attempt.**

RFC 9112 states that when both fields are present the Transfer-Encoding overrides the Content-Length, that such a message might indicate an attempt to perform request smuggling, and that it ought to be handled as an error. 'Ought to be handled as an error' means the rejection is the correct behaviour, so a 400 tells you the front-end normalises or refuses the ambiguity - it does not tell you the front-end and back-end disagree. The hunter's mistake is to file a 400 as a partial success because it feels like the payload reached something. It did not: it was discarded at the framing layer, before any request was forwarded, so no desynchronisation occurred. The useful next question is which layer decided, not what the status code was.

*Disproof:* It IS a real finding if the front-end accepts the ambiguous request and forwards it while the back-end resolves the conflict the other way - which you demonstrate by smuggling a second request and observing a response the attacker never sent. The disproof is the successful desynchronisation, not the absence of one: a 400 is only a clean negative when the request genuinely never reached the back-end, verifiable by the fact that no second request appears in back-end logs.

**Concluding that a front-end and back-end disagree because one accepts and one drops a malformed header is a false positive unless the request was actually forwarded, since a dropped header at the edge never reaches the tier whose behaviour you are comparing.**

This is the header-name analogue of the CL/TE case and it is the single most over-reported finding in the class. nginx controls whether header fields with invalid names should be ignored, and its underscores handling marks names containing underscores as invalid, making them subject to that directive - so with the default configuration an underscore-bearing header may be dropped or the request rejected at the edge. Tomcat's rejectIllegalHeader default rejects the whole request. In both cases the request stops there. Comparing the front-end's acceptance of a header against a back-end you never reached, or against a log line that shows the header was already stripped, is not evidence of parsing disagreement. Establish forwarding first, then compare.

*Disproof:* It IS a real disagreement if the header demonstrably reaches the back-end - present in the origin's received headers or honoured as a distinct parameter there - and is simultaneously ignored, dropped, or treated as a duplicate by the front-end. Capture both hops or read both logs; if the header exists in only one, the layers never disagreed, and the header-name variant of this finding should be discarded rather than reported.

**Reject a smuggling finding until it is distinguished from the adjacent behaviour this class also covers. "Requests to appliance administrative asset paths act as an early reconnaissance fingerprint for exploitation, and the repetition of an otherwise mundane static-path request from changing infrastructure is itself the signal." and "It basically enables you to hide a payload in plain sight." share a surface and a symptom, so a response that matches the first is not evidence for it while the second remains possible.**

Hypothesis under test: Requests to appliance administrative asset paths act as an early reconnaissance fingerprint for exploitation, and the repetition of an otherwise mundane static-path request from changing infrastructure is itself the signal.

Adjacent behaviour that produces the same observable result: It basically enables you to hide a payload in plain sight.

Why this is worth checking before reporting: both are recorded in this class as gated knowledge, so a tester who stops at the first match will report one of them. The two differ in what the server actually did with the input, and that difference is observable in the response rather than in the request.

Required before treating this as a finding: capture the response that demonstrates the first behaviour specifically, and confirm the second is not what was observed.

*Disproof:* This rule is wrong if a controlled test shows the two behaviours can never co-occur on the same surface, or if the corpus entry for "It basically enables you to hide a payload in plain sight." is out of date. In that case this class needs its false-positive guidance rewritten rather than deleted.

**A roughly 1KB HTML file that downloads an image polyglot and reconstructs an XOR-obfuscated payload in the browser is HTML smuggling, not HTTP request smuggling; smuggling requires two HTTP parsers to disagree on message boundaries.**

The observation is a tiny HTML attachment that appears inert to mail and web filters, contains an encoded blob, and reconstructs a payload client-side, which is filed under smuggling because the payload crosses a boundary unseen by the filter. It is a different class. HTML smuggling operates entirely inside one browser and one origin: the sender hid the payload inside image polyglots, called the PNG or GIF files from remote so the HTML stays small, and added dynamic XOR encryption to the payloads hidden inside the image. No intermediary parses two conflicting request framings. HTTP request smuggling is a disagreement between a front-end and back-end HTTP parser over where one request ends and the next begins; a real instance looks like a server whose REST parser incorrectly handles pipelined HTTP requests, which allows successive requests to overwrite the previously parsed HTTP method, URL and body, and is filed as inconsistent interpretation of HTTP requests (CWE-444). The distinguishing test is where the payload boundary is drawn: for HTML smuggling, one request and one response, and the payload materializes in the DOM; for smuggling, two requests where the victim's request is prefixed to or swallowed by the attacker's. Classify on the parser disagreement, not on the payload being hidden.

*Disproof:* A replayed pair of requests with conflicting Content-Length and Transfer-Encoding framing makes the back-end serve the second request under the first request's connection, showing two HTTP parsers disagreeing rather than a single client-side reconstruction.

## Validation

**Request smuggling is proven only when a request the attacker never sent appears in the back-end access log, because a timing change, an unusual status, or a connection reset is equally consistent with ordinary proxy behaviour.**

CWE-444 defines the weakness as an intermediary failing to interpret malformed messages consistently with the entities at the ultimate destination - the harm is not in the malformed request, it is in the second, unintended request that the disagreement created. So the evidence has to be that second request: a distinctive path or marker showing up in the origin's access log as belonging to a connection the attacker opened for one request. PortSwigger's consequence list separates the two effects, response queue desynchronisation and stealing other users' responses, and both are downstream of the same proof. In the field this is why a proxy that times out on the probe is not a negative: it is the expected first symptom of a persistent-connection poisoning attempt and should be followed by the log check that decides it.

*Disproof:* If the back-end log contains exactly one request for that connection, the connection was not desynchronised and no smuggling occurred regardless of the response the attacker received. Equally, if the marker appears because the attacker genuinely sent a second request on a fresh connection, or because a retrying client resent the original, the log evidence is not attributable to the framing conflict and the claim collapses.

**Request smuggling is confirmed when a subsequent normal request, sent immediately after an attack request that interferes with the next request, receives a response containing the expected interference (e.g., a 404 on an invalid URL), with the attack and normal requests sent over different network connections.**

When a probable request smuggling vulnerability has been detected, you can obtain further evidence for the vulnerability by exploiting it to trigger differences in the contents of the application's responses. This involves sending two requests to the application in quick succession: an attack request that is designed to interfere with the processing of the next request, and a normal request. If the response to the normal request contains the expected interference, then the vulnerability is confirmed. For example, in a CL.TE vulnerability, an attack request causes the subsequent normal request to look like one containing an invalid URL, so the server responds with status code 404, indicating that the attack request did indeed interfere with it. The attack request and the normal request should be sent to the server using different network connections, as sending both through the same connection will not prove the vulnerability exists.

*Disproof:* Refuted if an authoritative source shows the differential-response test is unreliable, e.g., when the back-end shares a single connection with other users or receives many requests simultaneously, producing false negatives that mask the vulnerability.

**An invalid or duplicated Content-Length with no Transfer-Encoding is an unrecoverable framing error that must yield 400, so a 400 on that probe confirms the endpoint's framing validation and closes off the CL.CL variant there.**

RFC 9112 gives the recipient no discretion in this case: a message with no Transfer-Encoding and an invalid Content-Length has invalid framing and must be treated as an unrecoverable error, with a 400 for requests and a connection teardown for responses received by a proxy. That makes it a useful low-noise control in a test sequence - it tells you whether the tier you are probing validates framing at all, before you move to the ambiguous cases. It also keeps a report honest: if the endpoint answers 400 on a plain invalid Content-Length, a claim that it will forward conflicting framing downstream needs its own evidence, because the same validation layer would likely have caught it.

*Disproof:* It is a real finding if the tier accepts the invalid Content-Length and forwards the message with the value intact, because that is precisely the precondition for the two-Content-Length variant. Note the spec's exception: a value that parses as a comma-separated list where every element is valid and all are identical is processed as that single value, so a probe using a consistent list is not invalid framing and a 400 there means something else - retry with a genuinely conflicting list before concluding.

**RFC 9113 makes an HTTP/2 message carrying connection-specific headers such as transfer-encoding or upgrade malformed and requires Content-Length to equal the sum of DATA frame payloads, so a downgrade hop that tolerates these is where H2-to-H1 smuggling hides.**

RFC 9113 makes an HTTP/2 message carrying connection-specific headers such as transfer-encoding or upgrade malformed and requires Content-Length to equal the sum of DATA frame payloads, so a downgrade hop that tolerates these is where H2-to-H1 smuggling hides.

HackTricks reference: Request Smuggling in HTTP/2 Downgrades (pentesting-web/http-request-smuggling/request-smuggling-in-http-2-downgrades.md)

*Disproof:* Refuted if the downgrade path rejects such a message at the first hop exactly as the spec prescribes, since a non-conforming tolerance is the condition being tested for.

## Impact

**Request smuggling vulnerabilities are often critical in nature, allowing an attacker to bypass security controls, gain unauthorized access to sensitive data, and directly compromise other application users.**

Request smuggling vulnerabilities are often critical in nature, allowing an attacker to bypass security controls, gain unauthorized access to sensitive data, and directly compromise other application users. This is possible because the attacker can send an ambiguous request that gets interpreted differently by the front-end and back-end servers, causing part of the front-end request to be interpreted by the back-end as the start of the next request, which can interfere with the way the application processes that request.

*Disproof:* Refuted if an authoritative source demonstrates that the impact is confined to the attacker's own connection, e.g., on a server that closes the TCP connection after every request so no request can be smuggled into another user's session.

**The payoff of a successful smuggle is response control: the attacker makes the shared connection deliver a response computed for their own smuggled request to a different client, which is both the proof of the desync and the theft of the victim's response.**

The payoff of a successful smuggle is response control: the attacker makes the shared connection deliver a response computed for their own smuggled request to a different client, which is both the proof of the desync and the theft of the victim's response.

HackTricks reference: HTTP Response Smuggling / Desync (pentesting-web/http-response-smuggling-desync.md)

*Disproof:* Refuted if the smuggled request's response always returns on the connection that sent it, or if the desync only ever shows up as connection errors with no cross-client response delivery observed.

## Related Bug Classes

Not yet researched.

## References

- **blog.trailofbits.com** (writeup)
  - <https://blog.trailofbits.com/2026/09/21/saml-a-fractal-of-bad-design/>
- **cwe.mitre.org** (taxonomy)
  - <https://cwe.mitre.org/data/definitions/444.html>
- **helpnetsecurity.com** (research)
  - <https://www.helpnetsecurity.com/2024/02/29/bobthesmuggler-open-source-tool-undetectable-payload-delivery/>
- **lab.ctbb.show** (writeup)
  - <https://lab.ctbb.show/research/h2-WAF-Bypasses>
- **nginx.org** (writeup)
  - <https://nginx.org/en/docs/http/ngx_http_core_module.html>
- **portswigger.net** (writeup)
  - <https://portswigger.net/research/request-smuggling>
  - <https://portswigger.net/web-security/request-smuggling>
  - <https://portswigger.net/web-security/request-smuggling/finding>
- **raw.githubusercontent.com** (reference)
  - <https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/pentesting-web/http-connection-request-smuggling.md>
  - <https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/pentesting-web/http-request-smuggling/README.md>
  - <https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/pentesting-web/http-request-smuggling/request-smuggling-in-http-2-downgrades.md>
  - <https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/pentesting-web/http-response-smuggling-desync.md>
  - <https://raw.githubusercontent.com/zweilosec/htb-writeups/master/linux-machines/hard/quick-write-up.md>
- **rfc-editor.org** (writeup)
  - <https://www.rfc-editor.org/rfc/rfc9112.html>
- **talosintelligence.com** (vendor_advisory)
  - <https://www.talosintelligence.com/vulnerability_reports/TALOS-2018-0577>
- **tomcat.apache.org** (research)
  - <https://tomcat.apache.org/tomcat-9.0-doc/config/http.html>
- **unit42.paloaltonetworks.com** (writeup)
  - <https://unit42.paloaltonetworks.com/netscaler-zero-days-exploited/>
- **w3.org** (primary)
  - <https://www.w3.org/Protocols/rfc2616/rfc2616-sec4.html>
- **wstg.owasp.org** (primary)
  - <https://wstg.owasp.org/latest/4-Web_Application_Security_Testing/07-Injection/16-HTTP_Request_Smuggling/>

Every item above is gated on >= 2 distinct publisher hosts (`wks/quality.py`, rule R1). Publisher diversity, not citation count, is what makes these corroborated.
