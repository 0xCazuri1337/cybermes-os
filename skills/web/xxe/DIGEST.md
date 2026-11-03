<!-- GENERATED from db/wks.db — do not edit -->
# XML External Entity Injection

> surface: `web` · CWE: 611 · OWASP: A05:2021
> maturity: **researching** — 42 items, 16 supported, 0 FP rules, 1 chains

An XML parser resolves external or entity-expanded content the attacker controls.

**Aliases:** xxe, xml external entity, blxxe

## Prerequisite

- **XXE arises because the XML specification includes DTD and external-entity features that standard XML parsers support even when the application does not intend to use them.**  
  `high_confidence` · score 0.8715 · disproved by: A parser configured with DOCTYPE and external-entity resolution completely disabled cannot be exploited by XXE; the OWASP cheat sheet states that the safest way to prevent XXE is always to disable DTDs (external entities) completely.
  sources: <https://portswigger.net/web-security/xxe> · <https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html>

## Signal

- **A parser that accepts a DOCTYPE declaration and resolves its entity is the enabling condition for XXE; the submitted payload alone proves nothing.**  
  `high_confidence` · score 0.899 · disproved by: If the parser rejects the DOCTYPE outright or returns a parse error, entity processing is disabled and the XXE signal is absent.
  sources: <https://www.w3.org/TR/2008/REC-xml-20081126/> · <https://snyk.io/blog/nokogiri-xxe-vulnerabilities/>
- **An attacker-controlled out-of-band callback plus entity-derived data arriving on the error channel in the same probe is the positive confirmation that external entity resolution succeeded, not merely that the parser tolerated a DOCTYPE.**  
  `high_confidence` · score 0.8355 · disproved by: Refuted if the out-of-band endpoint never receives a request or the error channel returns no entity-derived data, since a clean rejection or a DOCTYPE-only parse produces neither.
  sources: <https://lxml.de/parsing.html> · <https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/pentesting-web/xxe-xee-xml-external-entity.md>

## Technique

- **XML external entity injection is provable by defining an entity that expands to a known local file and observing that content in the response.**  
  `high_confidence` · score 0.9005 · disproved by: Refuted when a DOCTYPE declaring external entities is rejected by the parser, so the entity is never expanded.
  sources: <https://cwe.mitre.org/data/definitions/611.html> · <https://portswigger.net/web-security/xxe> · <https://raw.githubusercontent.com/Esther7171/HackTheBox-Writeups-Walkthroughs/main/Write-ups/Academy/05.%20Web%20Exploitation/30.%20Web%20Attacks/Web%20Attacks.md> · <https://raw.githubusercontent.com/ajcriado/htb-writeups/main/Cheatsheets/Mix-OSCP-CPTS/Windows/3.%20Lateral%20Movement.md>
- **The risk lives in how the parser resolves external data sources, so the probe is a document that carries a DOCTYPE and an entity declaration; parameter entities are the escalation path once a plain external entity is refused.**  
  `high_confidence` · score 0.863 · disproved by: Refuted if the parser rejects the DOCTYPE outright, or resolves internal entities only and never attempts to retrieve the external identifier - there is then no external resolution to test.
  sources: <https://lxml.de/parsing.html> · <https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/pentesting-web/xxe-xee-xml-external-entity.md>
- **Data retrieval The most common XXE injection vulnerability lets attackers prompt a server to disclose sensitive data or files in an HTTP response.**  
  `high_confidence` · score 0.8295 · disproved by: Refuted when: the value is bound as a parameter or written through the framework's own encoder, so the interpreter never sees attacker text as syntax. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“Data retrieval The most common XXE injection vulnerability lets attackers prompt”) does not occur under a test that isolates that control.
  sources: <https://bishopfox.com/blog/phpspreadsheet-versions1.5.0-xxe-advisory> · <https://snyk.io/blog/find-and-fix-xml-entity-vulnerabilities/>
- **Error-based information disclosure Our server is vulnerable to blind XXE injection methods if an attacker can retrieve valuable data by examining the error messages our server emits.**  
  `high_confidence` · score 0.827 · disproved by: Refuted when: the value is bound as a parameter or written through the framework's own encoder, so the interpreter never sees attacker text as syntax. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“Error-based information disclosure Our server is vulnerable to blind XXE injecti”) does not occur under a test that isolates that control.
  sources: <https://www.w3.org/TR/2008/REC-xml-20081126/> · <https://snyk.io/blog/find-and-fix-xml-entity-vulnerabilities/>
- **In a server-side request forgery (SSRF) attack, an attacker will typically inject a URL or address pointing to the vulnerable server’s local file system instance or other restricted-access resources — especially when user inputs are not properly filtered by the XML parser.**  
  `high_confidence` · score 0.7995 · disproved by: Refuted when: the value is bound as a parameter or written through the framework's own encoder, so the interpreter never sees attacker text as syntax. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“In a server-side request forgery (SSRF) attack, an attacker will typically injec”) does not occur under a test that isolates that control.
  sources: <https://www.w3.org/TR/2008/REC-xml-20081126/> · <https://snyk.io/blog/find-and-fix-xml-entity-vulnerabilities/>
- **9 userInfo > The ifconfig command in this example returns the server’s network configuration when the XML parser evaluates the xxe entity.**  
  `high_confidence` · score 0.7995 · disproved by: Refuted when: the value is bound as a parameter or written through the framework's own encoder, so the interpreter never sees attacker text as syntax. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“9 userInfo > The ifconfig command in this example returns the server’s network c”) does not occur under a test that isolates that control.
  sources: <https://www.w3.org/TR/2008/REC-xml-20081126/> · <https://snyk.io/blog/find-and-fix-xml-entity-vulnerabilities/>
- **However, if a user were to set the DTDLOAD option to true and also set the NONET option to false, then the vulnerability is open to be exploited by any malicious attackers.**  
  `high_confidence` · score 0.788 · disproved by: Refuted when: the same behaviour is absent when the single named control in the claim is present, and the control is shown to be present rather than assumed. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“However, if a user were to set the DTDLOAD option to true and also set the NONET”) does not occur under a test that isolates that control.
  sources: <https://www.w3.org/TR/2008/REC-xml-20081126/> · <https://bishopfox.com/blog/phpspreadsheet-versions1.5.0-xxe-advisory> · <https://snyk.io/blog/nokogiri-xxe-vulnerabilities/>
- **Why XXE represents a security risk XXE injection attacks let attackers take advantage of external entity declarations to gain access to files or infrastructure on their target server or network.**  
  `high_confidence` · score 0.7745 · disproved by: Refuted when: the value is bound as a parameter or written through the framework's own encoder, so the interpreter never sees attacker text as syntax. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“Why XXE represents a security risk XXE injection attacks let attackers take adva”) does not occur under a test that isolates that control.
  sources: <https://bishopfox.com/blog/phpspreadsheet-versions1.5.0-xxe-advisory> · <https://snyk.io/blog/find-and-fix-xml-entity-vulnerabilities/>

## Validation

- **An XXE is proved by the parser resolving an external reference to a resource the submitted document never contained — a request the server issued to an attacker-controlled listener, or file content appearing that only exists on the host — because that is the observable effect entity resolution causes.**  
  `high_confidence` · score 0.9065 · disproved by: The claim is false when the environment blocks resolution so the payload produces a silent parse error or empty result with no outbound request; in that case the finding is a configuration weakness established by the parser defaults rather than a live XXE, and it must be reported as such instead of as a demonstrated read.
  sources: <https://lxml.de/parsing.html> · <https://lxml.de/FAQ.html> · <https://www.php.net/manual/en/function.simplexml-load-string.php>
- **An XXE finding is validated only when an inbound HTTP request to the supplied entity URL was actually observed on a listener you control.**  
  `high_confidence` · score 0.874 · disproved by: No inbound request to the entity URL means entity resolution did not occur and the XXE finding is not reproducible, no matter how alarming the submitted payload looked.
  sources: <https://bishopfox.com/blog/phpspreadsheet-versions1.5.0-xxe-advisory> · <https://snyk.io/blog/nokogiri-xxe-vulnerabilities/>

## Evidence

- **The standard that hardened against this class states the expected safe behaviour directly — entity references are disallowed in the XML stream — which gives the tester a concrete baseline for deciding whether a parser's default is safe rather than an opinion about what looks dangerous.**  
  `high_confidence` · score 0.8655 · disproved by: The claim is false when the surrounding protocol genuinely requires entity references for its correctness, because a parser that honours the disallow rule would break interoperability and the application must accept the risk in a narrower form; the baseline then applies to the untrusted-data boundary only, not to the whole document.
  sources: <https://lxml.de/FAQ.html> · <https://tomcat.apache.org/security-8.html>

## Impact

- **XXE external entities that use http:// URIs force the server to make outbound requests, enabling SSRF against internal systems, internal port scanning, and use of the server's trust relationship to bypass firewalls.**  
  `high_confidence` · score 0.8655 · disproved by: If the parser refuses HTTP(S) external entities and disables file:// entities, or the server lacks outbound network access, the SSRF impact is not exploitable; and if responses to the triggered requests are not observable, blind SSRF becomes a harder signal that requires out-of-band detection.
  sources: <https://cwe.mitre.org/data/definitions/611.html> · <https://portswigger.net/web-security/xxe>

## Variant

- **Any upload surface that accepts SVG inherits the parser exposure, because the format is XML and a crafted image is a delivery channel for external entity resolution inside the backend.**  
  `high_confidence` · score 0.808 · disproved by: Refuted if the SVG upload path rasterises or sanitises the image with no XML parsing of the stored file, or strips the DOCTYPE before any entity resolution is attempted.
  sources: <https://lxml.de/parsing.html> · <https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/pentesting-web/xxe-xee-xml-external-entity.md>

## Known gaps

Not yet satisfied: `fp_rules`
