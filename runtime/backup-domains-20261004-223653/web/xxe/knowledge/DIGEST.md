# XML External Entity Injection

> surface: `web` · CWE: 611 · OWASP: A05:2021
> maturity: **mature** — 39 items, 20 supported, 4 FP rules, 1 chains

An XML parser resolves external or entity-expanded content the attacker controls.

**Aliases:** xxe, xml external entity, blxxe

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
- **Submitting a DOCTYPE with an external SYSTEM or PUBLIC identifier is the probe that reveals whether the parser resolves entities at all.**  
  `high_confidence` · score 0.899 · disproved by: If no callback arrives and the response shows the DOCTYPE passed through unparsed, the parser has external entity resolution disabled and the probe is negative.
  sources: <https://www.w3.org/TR/2008/REC-xml-20081126/> · <https://snyk.io/blog/find-and-fix-xml-entity-vulnerabilities/>
- **The risk lives in how the parser resolves external data sources, so the probe is a document that carries a DOCTYPE and an entity declaration; parameter entities are the escalation path once a plain external entity is refused.**  
  `high_confidence` · score 0.863 · disproved by: Refuted if the parser rejects the DOCTYPE outright, or resolves internal entities only and never attempts to retrieve the external identifier - there is then no external resolution to test.
  sources: <https://lxml.de/parsing.html> · <https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/pentesting-web/xxe-xee-xml-external-entity.md>
- **Data retrieval The most common XXE injection vulnerability lets attackers prompt a server to disclose sensitive data or files in an HTTP response.**  
  `under_review` · score 0.8295 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Data retrieval The most common XXE injection vulnerability lets attackers prompt a server ".
  sources: <https://bishopfox.com/blog/phpspreadsheet-versions1.5.0-xxe-advisory> · <https://snyk.io/blog/find-and-fix-xml-entity-vulnerabilities/>
- **In isolation, this gives an attacker read-only access to data, but it can reveal information useful for escalating to a more damaging attack.**  
  `under_review` · score 0.827 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "In isolation, this gives an attacker read-only access to data, but it can reveal informati".
  sources: <https://www.w3.org/TR/2008/REC-xml-20081126/> · <https://snyk.io/blog/find-and-fix-xml-entity-vulnerabilities/>
- **Error-based information disclosure Our server is vulnerable to blind XXE injection methods if an attacker can retrieve valuable data by examining the error messages our server emits.**  
  `under_review` · score 0.827 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Error-based information disclosure Our server is vulnerable to blind XXE injection methods".
  sources: <https://www.w3.org/TR/2008/REC-xml-20081126/> · <https://snyk.io/blog/find-and-fix-xml-entity-vulnerabilities/>
- **In serious cases, attackers can commit a server-side request forgery , which lets them impersonate a server on their target’s network and may enable them to execute code remotely.**  
  `under_review` · score 0.827 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "In serious cases, attackers can commit a server-side request forgery , which lets them imp".
  sources: <https://www.w3.org/TR/2008/REC-xml-20081126/> · <https://snyk.io/blog/find-and-fix-xml-entity-vulnerabilities/>
- **5 ]> In this code, the targeted server will try to send the HTTP request to the attacker’s server URL.**  
  `under_review` · score 0.802 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "5 ]> In this code, the targeted server will try to send the HTTP request to the attacker’s".
  sources: <https://bishopfox.com/blog/phpspreadsheet-versions1.5.0-xxe-advisory> · <https://snyk.io/blog/find-and-fix-xml-entity-vulnerabilities/>
- **9 userInfo > If the attacker successfully gains administrative privileges, they can impersonate the server to probe their target’s network for additional vulnerabilities.**  
  `under_review` · score 0.802 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "9 userInfo > If the attacker successfully gains administrative privileges, they can impers".
  sources: <https://bishopfox.com/blog/phpspreadsheet-versions1.5.0-xxe-advisory> · <https://snyk.io/blog/find-and-fix-xml-entity-vulnerabilities/>
- **In a payload with ten or more levels of nested entities, the resulting file can be hundreds of gigabytes, typically causing an out-of-memory error for the server attempting to parse the SVG file — and a denial of service for our users.**  
  `under_review` · score 0.802 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "In a payload with ten or more levels of nested entities, the resulting file can be hundred".
  sources: <https://bishopfox.com/blog/phpspreadsheet-versions1.5.0-xxe-advisory> · <https://snyk.io/blog/find-and-fix-xml-entity-vulnerabilities/>
- **In a server-side request forgery (SSRF) attack, an attacker will typically inject a URL or address pointing to the vulnerable server’s local file system instance or other restricted-access resources — especially when user inputs are not properly filtered by the XML parser.**  
  `under_review` · score 0.7995 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "In a server-side request forgery (SSRF) attack, an attacker will typically inject a URL or".
  sources: <https://www.w3.org/TR/2008/REC-xml-20081126/> · <https://snyk.io/blog/find-and-fix-xml-entity-vulnerabilities/>
- **9 userInfo > The ifconfig command in this example returns the server’s network configuration when the XML parser evaluates the xxe entity.**  
  `under_review` · score 0.7995 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "9 userInfo > The ifconfig command in this example returns the server’s network configurati".
  sources: <https://www.w3.org/TR/2008/REC-xml-20081126/> · <https://snyk.io/blog/find-and-fix-xml-entity-vulnerabilities/>
- **However, if a user were to set the DTDLOAD option to true and also set the NONET option to false, then the vulnerability is open to be exploited by any malicious attackers.**  
  `under_review` · score 0.788 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "However, if a user were to set the DTDLOAD option to true and also set the NONET option to".
  sources: <https://www.w3.org/TR/2008/REC-xml-20081126/> · <https://bishopfox.com/blog/phpspreadsheet-versions1.5.0-xxe-advisory> · <https://snyk.io/blog/nokogiri-xxe-vulnerabilities/>
- **9 staffInfo > Implementing a robust data encryption protocol is effective in preventing data retrieval, as it renders the stored data unreadable and unusable — even if an attacker successfully infiltrates the target’s server.**  
  `under_review` · score 0.7745 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "9 staffInfo > Implementing a robust data encryption protocol is effective in preventing da".
  sources: <https://bishopfox.com/blog/phpspreadsheet-versions1.5.0-xxe-advisory> · <https://snyk.io/blog/find-and-fix-xml-entity-vulnerabilities/>
- **Why XXE represents a security risk XXE injection attacks let attackers take advantage of external entity declarations to gain access to files or infrastructure on their target server or network.**  
  `under_review` · score 0.7745 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Why XXE represents a security risk XXE injection attacks let attackers take advantage of e".
  sources: <https://bishopfox.com/blog/phpspreadsheet-versions1.5.0-xxe-advisory> · <https://snyk.io/blog/find-and-fix-xml-entity-vulnerabilities/>
- **Missing authentication lets anyone proxy requests unauthenticated, and a regex bypass defeats the private IP block.**  
  `under_review` · score 0.7745 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Missing authentication lets anyone proxy requests unauthenticated, and a regex bypass defe".
  sources: <https://bishopfox.com/blog/phpspreadsheet-versions1.5.0-xxe-advisory> · <https://snyk.io/blog/nokogiri-xxe-vulnerabilities/>
- **By default you should be set, but if you’ve made those changes you’re currently vulnerable.**  
  `under_review` · score 0.772 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "By default you should be set, but if you’ve made those changes you’re currently vulnerable".
  sources: <https://www.w3.org/TR/2008/REC-xml-20081126/> · <https://snyk.io/blog/nokogiri-xxe-vulnerabilities/>
- **4 EOX If an XML parser is set to include external entities, it opens the door for attackers to execute an XML External Entities attack by injecting a malicous entity.**  
  `under_review` · score 0.772 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "4 EOX If an XML parser is set to include external entities, it opens the door for attacker".
  sources: <https://www.w3.org/TR/2008/REC-xml-20081126/> · <https://snyk.io/blog/nokogiri-xxe-vulnerabilities/>
- **Implement zero trust security The trust relationship between your web applications and other external or third-party services (such as message brokers and user authentication platforms) can be exploited to launch a SSRF on your server infrastructure.**  
  `under_review` · score 0.772 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Implement zero trust security The trust relationship between your web applications and oth".
  sources: <https://www.w3.org/TR/2008/REC-xml-20081126/> · <https://snyk.io/blog/find-and-fix-xml-entity-vulnerabilities/>
- **And, if an attacker does breach security, they should only encounter encrypted data and a network of zero-trust services.**  
  `under_review` · score 0.747 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "And, if an attacker does breach security, they should only encounter encrypted data and a ".
  sources: <https://bishopfox.com/blog/phpspreadsheet-versions1.5.0-xxe-advisory> · <https://snyk.io/blog/find-and-fix-xml-entity-vulnerabilities/>
- **Missing authentication lets anyone proxy requests unauthenticated, and a regex bypass defeats the private IP block.**  
  `under_review` · score 0.6805 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Missing authentication lets anyone proxy requests unauthenticated, and a regex bypass defe".
  sources: <https://snyk.io/blog/nokogiri-xxe-vulnerabilities/>

## Test

- **To decide this case, observe: How to apply it in the field: treat this as the bypass it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable.**  
  `high_confidence` · score 0.8905 · disproved by: This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (xxe.bypass.entities_parsed_by_a_framework_level_xml_pipeline_escape_the_endpoint_level_configuration) states the full boundary.
  sources: <https://lxml.de/parsing.html> · <https://tomcat.apache.org/security-8.html>
- **To decide this case, observe: Hypothesis under test: A parser that accepts a DOCTYPE declaration and resolves its entity is the enabling condition for XXE; the submitted payload alone proves nothing.**  
  `high_confidence` · score 0.8655 · disproved by: This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (xxe.fp_rule.auto.derived) states the full boundary.
  sources: <https://bishopfox.com/blog/phpspreadsheet-versions1.5.0-xxe-advisory> · <https://snyk.io/blog/find-and-fix-xml-entity-vulnerabilities/>
- **To decide this case, observe: How to apply it in the field: treat this as the fp_rule it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable.**  
  `high_confidence` · score 0.863 · disproved by: This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (xxe.fp_rule.blocking_network_access_alone_does_not_prevent_local_file_disclosure) states the full boundary.
  sources: <https://lxml.de/parsing.html> · <https://www.php.net/manual/en/function.simplexml-load-string.php>
- **To decide this case, observe: Mechanism: A parsed document that returned 200 with a defined entity reflected in the output is not an XXE finding; the entity may have been expanded from the document's own internal DTD, which is normal XML processing, and the flaw requires the parser to resolve a reference to an external resource or a local file.**  
  `high_confidence` · score 0.838 · disproved by: This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (xxe.fp_rule.an_expanded_custom_entity_proves_nothing_without_evidence_the_parser_resolved_an_external_reference) states the full boundary.
  sources: <https://lxml.de/FAQ.html> · <https://tomcat.apache.org/security-8.html>
- **To decide this case, observe: How to apply it in the field: treat this as the validation it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable.**  
  `under_review` · score 0.793 · disproved by: This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (xxe.validation.proof_is_a_reference_resolved_to_a_resource_the_submitted_document_did_not_contain) states the full boundary.
  sources: <https://lxml.de/parsing.html> · <https://lxml.de/FAQ.html>

## Validation

- **An XXE is proved by the parser resolving an external reference to a resource the submitted document never contained — a request the server issued to an attacker-controlled listener, or file content appearing that only exists on the host — because that is the observable effect entity resolution causes.**  
  `high_confidence` · score 0.9065 · disproved by: The claim is false when the environment blocks resolution so the payload produces a silent parse error or empty result with no outbound request; in that case the finding is a configuration weakness established by the parser defaults rather than a live XXE, and it must be reported as such instead of as a demonstrated read.
  sources: <https://lxml.de/parsing.html> · <https://lxml.de/FAQ.html> · <https://www.php.net/manual/en/function.simplexml-load-string.php>
- **An XXE finding is validated only when an inbound HTTP request to the supplied entity URL was actually observed on a listener you control.**  
  `high_confidence` · score 0.874 · disproved by: No inbound request to the entity URL means entity resolution did not occur and the XXE finding is not reproducible, no matter how alarming the submitted payload looked.
  sources: <https://bishopfox.com/blog/phpspreadsheet-versions1.5.0-xxe-advisory> · <https://snyk.io/blog/nokogiri-xxe-vulnerabilities/>

## Fp Rule

- **An XXE filter that greps for a keyword in one encoding is a false-negative source, so a single clean probe never proves the target is safe.**  
  `high_confidence` · score 0.899 · disproved by: If both the UTF-8 and alternate-encoding probes are rejected with the entity never resolved, the blocklist holds for the encodings tested and the bypass does not reproduce.
  sources: <https://www.w3.org/TR/2008/REC-xml-20081126/> · <https://bishopfox.com/blog/phpspreadsheet-versions1.5.0-xxe-advisory>
- **A parser configured with network access disabled is not thereby safe against XXE, because a file:// or relative entity reference needs no network and the local-file read is the higher-value impact; a tester who stops at the network probe will miss it.**  
  `high_confidence` · score 0.8905 · disproved by: The rule is wrong when entity resolution is disabled outright — not merely network-restricted — because with resolve_entities off the external entity is never substituted and neither local nor remote disclosure is possible; the network flag alone is the insufficient control, the resolution flag is the effective one.
  sources: <https://lxml.de/parsing.html> · <https://www.php.net/manual/en/function.simplexml-load-string.php>
- **Reject a xxe finding until it is distinguished from the adjacent behaviour this class also covers. "A parser that accepts a DOCTYPE declaration and resolves its entity is the enabling condition for XXE; the submitted payload alone proves nothing." and "An XXE finding is validated only when an inbound HTTP request to the supplied entity URL was actually observed on a listener you control." share a surface and a symptom, so a response that matches the first is not evidence for it while the second remains possible.**  
  `high_confidence` · score 0.8655 · disproved by: This rule is wrong if a controlled test shows the two behaviours can never co-occur on the same surface, or if the corpus entry for "An XXE finding is validated only when an inbound HTTP request to the s" is out of date. In that case this class needs its false-positive guidance rewritten rather than deleted.
  sources: <https://bishopfox.com/blog/phpspreadsheet-versions1.5.0-xxe-advisory> · <https://snyk.io/blog/find-and-fix-xml-entity-vulnerabilities/>
- **A parsed document that returned 200 with a defined entity reflected in the output is not an XXE finding; the entity may have been expanded from the document's own internal DTD, which is normal XML processing, and the flaw requires the parser to resolve a reference to an external resource or a local file.**  
  `high_confidence` · score 0.838 · disproved by: The rule is wrong when the reflected value could only have come from outside the submitted document — a system property, a well-known file path, or a uniquely identifying marker the tester planted out of band — because then the internal-definition explanation is excluded and an external resolution actually occurred.
  sources: <https://lxml.de/FAQ.html> · <https://tomcat.apache.org/security-8.html>

## Evidence

- **The standard that hardened against this class states the expected safe behaviour directly — entity references are disallowed in the XML stream — which gives the tester a concrete baseline for deciding whether a parser's default is safe rather than an opinion about what looks dangerous.**  
  `high_confidence` · score 0.8655 · disproved by: The claim is false when the surrounding protocol genuinely requires entity references for its correctness, because a parser that honours the disallow rule would break interoperability and the application must accept the risk in a narrower form; the baseline then applies to the untrusted-data boundary only, not to the whole document.
  sources: <https://lxml.de/FAQ.html> · <https://tomcat.apache.org/security-8.html>
- **A convincing observation for this class is: If the parser resolves the identifier, the fetch happens and you get either content in the response or an inbound callback to your listener.**  
  `high_confidence` · score 0.863 · disproved by: Not evidence when the observable cannot be produced at all -- blind, server-side-only, or identical-in-every-case behaviour leaves nothing to show. The originating rule (xxe.technique.external_dtd_reference_is_the_core_probe) states the full boundary.
  sources: <https://www.w3.org/TR/2008/REC-xml-20081126/> · <https://snyk.io/blog/find-and-fix-xml-entity-vulnerabilities/>
- **A convincing observation for this class is: Adjacent behaviour that produces the same observable result: An XXE finding is validated only when an inbound HTTP request to the supplied entity URL was actually observed on a listener you control.**  
  `high_confidence` · score 0.8105 · disproved by: Not evidence when the observable cannot be produced at all -- blind, server-side-only, or identical-in-every-case behaviour leaves nothing to show. The originating rule (xxe.fp_rule.auto.derived) states the full boundary.
  sources: <https://bishopfox.com/blog/phpspreadsheet-versions1.5.0-xxe-advisory> · <https://snyk.io/blog/find-and-fix-xml-entity-vulnerabilities/>

## Variant

- **Any upload surface that accepts SVG inherits the parser exposure, because the format is XML and a crafted image is a delivery channel for external entity resolution inside the backend.**  
  `high_confidence` · score 0.808 · disproved by: Refuted if the SVG upload path rasterises or sanitises the image with no XML parsing of the stored file, or strips the DOCTYPE before any entity resolution is attempted.
  sources: <https://lxml.de/parsing.html> · <https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/pentesting-web/xxe-xee-xml-external-entity.md>

## Bypass

- **Configuring the entity policy on the application's own XML parser call does not cover the parsers a framework or container instantiate internally for XSLT, tag library descriptors, JSP documents or configuration files, so those secondary parsers can bypass the entity limits the application believes it set.**  
  `high_confidence` · score 0.8905 · disproved by: The rule is false when the framework's internal parsers are the same configured object the application controls, or when the container or library applies a process-wide default that the application cannot override in either direction; then there is only one parser and the endpoint-level configuration does govern it.
  sources: <https://lxml.de/parsing.html> · <https://tomcat.apache.org/security-8.html>
