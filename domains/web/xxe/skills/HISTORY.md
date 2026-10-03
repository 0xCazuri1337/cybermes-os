# History

Append-only. Each entry records WHY the skill changed, not just that it did. Improvement means better hunting behaviour, not more text.

## 2026-10-02 15:57 — 1 diff lines
- items: 23 (supported 23), FP rules 2, chains 1, state mature

```diff
(initial generation, 2026-10-02)
```

## 2026-10-02 16:07 — 8 diff lines
- items: 23 (supported 23), FP rules 2, chains 1, state mature

```diff
--- xxe@current
+++ xxe@new
@@ -100,4 +100,4 @@
   - Sources: <https://www.w3.org/TR/2008/REC-xml-20081126/> · <https://bishopfox.com/blog/phpspreadsheet-versions1.5.0-xxe-advisory>
 
 ---
-Full class document: `domains/web/xxe/EVIDENCE.md` · retrieve more with `python -m wks.cli search "<query>" --class-id xxe`
+Full class document: `domains/web/xxe/knowledge/DIGEST.md` · retrieve more with `python -m wks.cli search "<query>" --class-id xxe`
```

## 2026-10-02 19:37 — 151 diff lines
- items: 33 (supported 13), FP rules 4, chains 1, state mature

```diff
--- xxe@current
+++ xxe@new
@@ -10,7 +10,7 @@
      python -m wks.skillgen -->
 
 > surface `web` · CWE 611 · OWASP A05:2021
-> evidence: 23 items, 23 supported, 2 FP rules, 1 chains
+> evidence: 33 items, 13 supported, 4 FP rules, 1 chains
 > maturity: **mature**
 
 An XML parser resolves external or entity-expanded content the attacker controls.
@@ -26,78 +26,121 @@
 
 ## Techniques (what to change)
 
-- Missing authentication lets anyone proxy requests unauthenticated, and a regex bypass defeats the private IP block.
+- Missing authentication lets anyone proxy requests unauthenticated, and a regex bypass defeats the private IP block. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Missing authentication lets anyone proxy requests unauthenticated, and a regex bypass defe".
   - Sources: <https://bishopfox.com/blog/phpspreadsheet-versions1.5.0-xxe-advisory> · <https://snyk.io/blog/nokogiri-xxe-vulnerabilities/>
-- By default you should be set, but if you’ve made those changes you’re currently vulnerable.
+- By default you should be set, but if you’ve made those changes you’re currently vulnerable. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "By default you should be set, but if you’ve made those changes you’re currently vulnerable".
   - Sources: <https://www.w3.org/TR/2008/REC-xml-20081126/> · <https://snyk.io/blog/nokogiri-xxe-vulnerabilities/>
-- In a server-side request forgery (SSRF) attack, an attacker will typically inject a URL or address pointing to the vulnerable server’s local file system instance or other restricted-access resources — especially when user inputs are not properly filtered by the XML parser.
+- In a server-side request forgery (SSRF) attack, an attacker will typically inject a URL or address pointing to the vulnerable server’s local file system instance or other restricted-access resources — especially when user inputs are not properly filtered by the XML parser. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "In a server-side request forgery (SSRF) attack, an attacker will typically inject a URL or".
   - Sources: <https://www.w3.org/TR/2008/REC-xml-20081126/> · <https://snyk.io/blog/find-and-fix-xml-entity-vulnerabilities/>
-- However, if a user were to set the DTDLOAD option to true and also set the NONET option to false, then the vulnerability is open to be exploited by any malicious attackers.
+- However, if a user were to set the DTDLOAD option to true and also set the NONET option to false, then the vulnerability is open to be exploited by any malicious attackers. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "However, if a user were to set the DTDLOAD option to true and also set the NONET option to".
   - Sources: <https://www.w3.org/TR/2008/REC-xml-20081126/> · <https://bishopfox.com/blog/phpspreadsheet-versions1.5.0-xxe-advisory> · <https://snyk.io/blog/nokogiri-xxe-vulnerabilities/>
-- 9 staffInfo > Implementing a robust data encryption protocol is effective in preventing data retrieval, as it renders the stored data unreadable and unusable — even if an attacker successfully infiltrates the target’s server.
+- 9 staffInfo > Implementing a robust data encryption protocol is effective in preventing data retrieval, as it renders the stored data unreadable and unusable — even if an attacker successfully infiltrates the target’s server. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "9 staffInfo > Implementing a robust data encryption protocol is effective in preventing da".
   - Sources: <https://bishopfox.com/blog/phpspreadsheet-versions1.5.0-xxe-advisory> · <https://snyk.io/blog/find-and-fix-xml-entity-vulnerabilities/>
-- 5 ]> In this code, the targeted server will try to send the HTTP request to the attacker’s server URL.
+- 5 ]> In this code, the targeted server will try to send the HTTP request to the attacker’s server URL. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "5 ]> In this code, the targeted server will try to send the HTTP request to the attacker’s".
   - Sources: <https://bishopfox.com/blog/phpspreadsheet-versions1.5.0-xxe-advisory> · <https://snyk.io/blog/find-and-fix-xml-entity-vulnerabilities/>
-- Why XXE represents a security risk XXE injection attacks let attackers take advantage of external entity declarations to gain access to files or infrastructure on their target server or network.
+- Why XXE represents a security risk XXE injection attacks let attackers take advantage of external entity declarations to gain access to files or infrastructure on their target server or network. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Why XXE represents a security risk XXE injection attacks let attackers take advantage of e".
   - Sources: <https://bishopfox.com/blog/phpspreadsheet-versions1.5.0-xxe-advisory> · <https://snyk.io/blog/find-and-fix-xml-entity-vulnerabilities/>
-- 4 EOX If an XML parser is set to include external entities, it opens the door for attackers to execute an XML External Entities attack by injecting a malicous entity.
+- 4 EOX If an XML parser is set to include external entities, it opens the door for attackers to execute an XML External Entities attack by injecting a malicous entity. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "4 EOX If an XML parser is set to include external entities, it opens the door for attacker".
   - Sources: <https://www.w3.org/TR/2008/REC-xml-20081126/> · <https://snyk.io/blog/nokogiri-xxe-vulnerabilities/>
-- In isolation, this gives an attacker read-only access to data, but it can reveal information useful for escalating to a more damaging attack.
+- In isolation, this gives an attacker read-only access to data, but it can reveal information useful for escalating to a more damaging attack. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "In isolation, this gives an attacker read-only access to data, but it can reveal informati".
   - Sources: <https://www.w3.org/TR/2008/REC-xml-20081126/> · <https://snyk.io/blog/find-and-fix-xml-entity-vulnerabilities/>
-- 9 userInfo > The ifconfig command in this example returns the server’s network configuration when the XML parser evaluates the xxe entity.
+- 9 userInfo > The ifconfig command in this example returns the server’s network configuration when the XML parser evaluates the xxe entity. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "9 userInfo > The ifconfig command in this example returns the server’s network configurati".
   - Sources: <https://www.w3.org/TR/2008/REC-xml-20081126/> · <https://snyk.io/blog/find-and-fix-xml-entity-vulnerabilities/>
-- Data retrieval The most common XXE injection vulnerability lets attackers prompt a server to disclose sensitive data or files in an HTTP response.
+- Data retrieval The most common XXE injection vulnerability lets attackers prompt a server to disclose sensitive data or files in an HTTP response. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Data retrieval The most common XXE injection vulnerability lets attackers prompt a server ".
   - Sources: <https://bishopfox.com/blog/phpspreadsheet-versions1.5.0-xxe-advisory> · <https://snyk.io/blog/find-and-fix-xml-entity-vulnerabilities/>
-- And, if an attacker does breach security, they should only encounter encrypted data and a network of zero-trust services.
+- And, if an attacker does breach security, they should only encounter encrypted data and a network of zero-trust services. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "And, if an attacker does breach security, they should only encounter encrypted data and a ".
   - Sources: <https://bishopfox.com/blog/phpspreadsheet-versions1.5.0-xxe-advisory> · <https://snyk.io/blog/find-and-fix-xml-entity-vulnerabilities/>
-- Missing authentication lets anyone proxy requests unauthenticated, and a regex bypass defeats the private IP block.
+- Missing authentication lets anyone proxy requests unauthenticated, and a regex bypass defeats the private IP block. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Missing authentication lets anyone proxy requests unauthenticated, and a regex bypass defe".
   - Sources: <https://bishopfox.com/blog/phpspreadsheet-versions1.5.0-xxe-advisory> · <https://snyk.io/blog/nokogiri-xxe-vulnerabilities/>
-- 9 userInfo > If the attacker successfully gains administrative privileges, they can impersonate the server to probe their target’s network for additional vulnerabilities.
+- 9 userInfo > If the attacker successfully gains administrative privileges, they can impersonate the server to probe their target’s network for additional vulnerabilities. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "9 userInfo > If the attacker successfully gains administrative privileges, they can impers".
   - Sources: <https://bishopfox.com/blog/phpspreadsheet-versions1.5.0-xxe-advisory> · <https://snyk.io/blog/find-and-fix-xml-entity-vulnerabilities/>
-- Implement zero trust security The trust relationship between your web applications and other external or third-party services (such as message brokers and user authentication platforms) can be exploited to launch a SSRF on your server infrastructure.
+- Implement zero trust security The trust relationship between your web applications and other external or third-party services (such as message brokers and user authentication platforms) can be exploited to launch a SSRF on your server infrastructure. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Implement zero trust security The trust relationship between your web applications and oth".
   - Sources: <https://www.w3.org/TR/2008/REC-xml-20081126/> · <https://snyk.io/blog/find-and-fix-xml-entity-vulnerabilities/>
-- Error-based information disclosure Our server is vulnerable to blind XXE injection methods if an attacker can retrieve valuable data by examining the error messages our server emits.
+- Error-based information disclosure Our server is vulnerable to blind XXE injection methods if an attacker can retrieve valuable data by examining the error messages our server emits. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Error-based information disclosure Our server is vulnerable to blind XXE injection methods".
   - Sources: <https://www.w3.org/TR/2008/REC-xml-20081126/> · <https://snyk.io/blog/find-and-fix-xml-entity-vulnerabilities/>
-- In a payload with ten or more levels of nested entities, the resulting file can be hundreds of gigabytes, typically causing an out-of-memory error for the server attempting to parse the SVG file — and a denial of service for our users.
+- In a payload with ten or more levels of nested entities, the resulting file can be hundreds of gigabytes, typically causing an out-of-memory error for the server attempting to parse the SVG file — and a denial of service for our users. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "In a payload with ten or more levels of nested entities, the resulting file can be hundred".
   - Sources: <https://bishopfox.com/blog/phpspreadsheet-versions1.5.0-xxe-advisory> · <https://snyk.io/blog/find-and-fix-xml-entity-vulnerabilities/>
-- In serious cases, attackers can commit a server-side request forgery , which lets them impersonate a server on their target’s network and may enable them to execute code remotely.
+- In serious cases, attackers can commit a server-side request forgery , which lets them impersonate a server on their target’s network and may enable them to execute code remotely. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "In serious cases, attackers can commit a server-side request forgery , which lets them imp".
   - Sources: <https://www.w3.org/TR/2008/REC-xml-20081126/> · <https://snyk.io/blog/find-and-fix-xml-entity-vulnerabilities/>
 - Submitting a DOCTYPE with an external SYSTEM or PUBLIC identifier is the probe that reveals whether the parser resolves entities at all.
   - **Disproof:** If no callback arrives and the response shows the DOCTYPE passed through unparsed, the parser has external entity resolution disabled and the probe is negative.
   - Sources: <https://www.w3.org/TR/2008/REC-xml-20081126/> · <https://snyk.io/blog/find-and-fix-xml-entity-vulnerabilities/>
 
+## Tests
+
+- To decide this case, observe: Mechanism: A parsed document that returned 200 with a defined entity reflected in the output is not an XXE finding; the entity may have been expanded from the document's own internal DTD, which is normal XML processing, and the flaw requires the parser to resolve a reference to an external resource or a local file. How to apply
+  - **Disproof:** This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (xxe.fp_rule.an_expanded_custom_entity_proves_nothing_without_evidence_the_parser_resolved_an_external_reference) states the full boundary.
+  - Sources: <https://lxml.de/FAQ.html> · <https://tomcat.apache.org/security-8.html>
+- To decide this case, observe: treat this as the fp_rule it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable. Boundary of the rule: The rule is wrong when entity resolution is disabled outright — not merely network-restricted — because with resolve_entities off the external entity is never substituted and
+  - **Disproof:** This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (xxe.fp_rule.blocking_network_access_alone_does_not_prevent_local_file_disclosure) states the full boundary.
+  - Sources: <https://lxml.de/parsing.html> · <https://www.php.net/manual/en/function.simplexml-load-string.php>
+- To decide this case, observe: eat this as the validation it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable. Boundary of the rule: The claim is false when the environment blocks resolution so the payload produces a silent parse error or empty result with no outbound request; in that case the finding is a _(unverified)_
+  - **Disproof:** This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (xxe.validation.proof_is_a_reference_resolved_to_a_resource_the_submitted_document_did_not_contain) states the full boundary.
+  - Sources: <https://lxml.de/FAQ.html> · <https://lxml.de/parsing.html>
+- To decide this case, observe: : treat this as the bypass it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable. Boundary of the rule: The rule is false when the framework's internal parsers are the same configured object the application controls, or when the container or library applies a process-wide defau _(unverified)_
+  - **Disproof:** This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (xxe.bypass.entities_parsed_by_a_framework_level_xml_pipeline_escape_the_endpoint_level_configuration) states the full boundary.
+  - Sources: <https://lxml.de/parsing.html> · <https://tomcat.apache.org/security-8.html>
+- To decide this case, observe: payload alone proves nothing.
+
+Adjacent behaviour that produces the same observable result: An XXE finding is validated only when an inbound HTTP request to the supplied entity URL was actually observed on a listener you control.
+
+Why this is worth checking before reporting: both are recorded in this class as gated knowledge, so a tester who stops at the first match will report
+  - **Disproof:** This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (xxe.fp_rule.auto.derived) states the full boundary.
+  - Sources: <https://bishopfox.com/blog/phpspreadsheet-versions1.5.0-xxe-advisory> · <https://snyk.io/blog/find-and-fix-xml-entity-vulnerabilities/>
+
 ## Validation bar (how to prove it)
 
 - An XXE finding is validated only when an inbound HTTP request to the supplied entity URL was actually observed on a listener you control.
   - **Disproof:** No inbound request to the entity URL means entity resolution did not occur and the XXE finding is not reproducible, no matter how alarming the submitted payload looked.
   - Sources: <https://bishopfox.com/blog/phpspreadsheet-versions1.5.0-xxe-advisory> · <https://snyk.io/blog/nokogiri-xxe-vulnerabilities/>
+- An XXE is proved by the parser resolving an external reference to a resource the submitted document never contained — a request the server issued to an attacker-controlled listener, or file content appearing that only exists on the host — because that is the observable effect entity resolution causes.
+  - **Disproof:** The claim is false when the environment blocks resolution so the payload produces a silent parse error or empty result with no outbound request; in that case the finding is a configuration weakness established by the parser defaults rather than a live XXE, and it must be reported as such instead of as a demonstrated read.
... (truncated)
```

## 2026-10-03 01:46 — 95 diff lines
- items: 39 (supported 20), FP rules 4, chains 1, state mature

```diff
--- xxe@current
+++ xxe@new
@@ -10,7 +10,7 @@
      python -m wks.skillgen -->
 
 > surface `web` · CWE 611 · OWASP A05:2021
-> evidence: 33 items, 13 supported, 4 FP rules, 1 chains
+> evidence: 39 items, 20 supported, 4 FP rules, 1 chains
 > maturity: **mature**
 
 An XML parser resolves external or entity-expanded content the attacker controls.
@@ -23,12 +23,15 @@
 - A parser that accepts a DOCTYPE declaration and resolves its entity is the enabling condition for XXE; the submitted payload alone proves nothing.
   - **Disproof:** If the parser rejects the DOCTYPE outright or returns a parse error, entity processing is disabled and the XXE signal is absent.
   - Sources: <https://www.w3.org/TR/2008/REC-xml-20081126/> · <https://snyk.io/blog/nokogiri-xxe-vulnerabilities/>
+- An attacker-controlled out-of-band callback plus entity-derived data arriving on the error channel in the same probe is the positive confirmation that external entity resolution succeeded, not merely that the parser tolerated a DOCTYPE.
+  - **Disproof:** Refuted if the out-of-band endpoint never receives a request or the error channel returns no entity-derived data, since a clean rejection or a DOCTYPE-only parse produces neither.
+  - Sources: <https://lxml.de/parsing.html> · <https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/pentesting-web/xxe-xee-xml-external-entity.md>
 
 ## Techniques (what to change)
 
 - Missing authentication lets anyone proxy requests unauthenticated, and a regex bypass defeats the private IP block. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Missing authentication lets anyone proxy requests unauthenticated, and a regex bypass defe".
-  - Sources: <https://bishopfox.com/blog/phpspreadsheet-versions1.5.0-xxe-advisory> · <https://snyk.io/blog/nokogiri-xxe-vulnerabilities/>
+  - Sources: <https://snyk.io/blog/nokogiri-xxe-vulnerabilities/>
 - By default you should be set, but if you’ve made those changes you’re currently vulnerable. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "By default you should be set, but if you’ve made those changes you’re currently vulnerable".
   - Sources: <https://www.w3.org/TR/2008/REC-xml-20081126/> · <https://snyk.io/blog/nokogiri-xxe-vulnerabilities/>
@@ -83,26 +86,28 @@
 - Submitting a DOCTYPE with an external SYSTEM or PUBLIC identifier is the probe that reveals whether the parser resolves entities at all.
   - **Disproof:** If no callback arrives and the response shows the DOCTYPE passed through unparsed, the parser has external entity resolution disabled and the probe is negative.
   - Sources: <https://www.w3.org/TR/2008/REC-xml-20081126/> · <https://snyk.io/blog/find-and-fix-xml-entity-vulnerabilities/>
+- The risk lives in how the parser resolves external data sources, so the probe is a document that carries a DOCTYPE and an entity declaration; parameter entities are the escalation path once a plain external entity is refused.
+  - **Disproof:** Refuted if the parser rejects the DOCTYPE outright, or resolves internal entities only and never attempts to retrieve the external identifier - there is then no external resolution to test.
+  - Sources: <https://lxml.de/parsing.html> · <https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/pentesting-web/xxe-xee-xml-external-entity.md>
+- XML external entity injection is provable by defining an entity that expands to a known local file and observing that content in the response.
+  - **Disproof:** Refuted when a DOCTYPE declaring external entities is rejected by the parser, so the entity is never expanded.
+  - Sources: <https://cwe.mitre.org/data/definitions/611.html> · <https://portswigger.net/web-security/xxe> · <https://raw.githubusercontent.com/Esther7171/HackTheBox-Writeups-Walkthroughs/main/Write-ups/Academy/05.%20Web%20Exploitation/30.%20Web%20Attacks/Web%20Attacks.md>
 
 ## Tests
 
-- To decide this case, observe: Mechanism: A parsed document that returned 200 with a defined entity reflected in the output is not an XXE finding; the entity may have been expanded from the document's own internal DTD, which is normal XML processing, and the flaw requires the parser to resolve a reference to an external resource or a local file. How to apply
+- To decide this case, observe: Mechanism: A parsed document that returned 200 with a defined entity reflected in the output is not an XXE finding; the entity may have been expanded from the document's own internal DTD, which is normal XML processing, and the flaw requires the parser to resolve a reference to an external resource or a local file.
   - **Disproof:** This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (xxe.fp_rule.an_expanded_custom_entity_proves_nothing_without_evidence_the_parser_resolved_an_external_reference) states the full boundary.
   - Sources: <https://lxml.de/FAQ.html> · <https://tomcat.apache.org/security-8.html>
-- To decide this case, observe: treat this as the fp_rule it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable. Boundary of the rule: The rule is wrong when entity resolution is disabled outright — not merely network-restricted — because with resolve_entities off the external entity is never substituted and
+- To decide this case, observe: How to apply it in the field: treat this as the fp_rule it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable.
   - **Disproof:** This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (xxe.fp_rule.blocking_network_access_alone_does_not_prevent_local_file_disclosure) states the full boundary.
   - Sources: <https://lxml.de/parsing.html> · <https://www.php.net/manual/en/function.simplexml-load-string.php>
-- To decide this case, observe: eat this as the validation it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable. Boundary of the rule: The claim is false when the environment blocks resolution so the payload produces a silent parse error or empty result with no outbound request; in that case the finding is a _(unverified)_
+- To decide this case, observe: How to apply it in the field: treat this as the validation it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable. _(unverified)_
   - **Disproof:** This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (xxe.validation.proof_is_a_reference_resolved_to_a_resource_the_submitted_document_did_not_contain) states the full boundary.
-  - Sources: <https://lxml.de/FAQ.html> · <https://lxml.de/parsing.html>
-- To decide this case, observe: : treat this as the bypass it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable. Boundary of the rule: The rule is false when the framework's internal parsers are the same configured object the application controls, or when the container or library applies a process-wide defau _(unverified)_
+  - Sources: <https://lxml.de/parsing.html> · <https://lxml.de/FAQ.html>
+- To decide this case, observe: How to apply it in the field: treat this as the bypass it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable.
   - **Disproof:** This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (xxe.bypass.entities_parsed_by_a_framework_level_xml_pipeline_escape_the_endpoint_level_configuration) states the full boundary.
   - Sources: <https://lxml.de/parsing.html> · <https://tomcat.apache.org/security-8.html>
-- To decide this case, observe: payload alone proves nothing.
-
-Adjacent behaviour that produces the same observable result: An XXE finding is validated only when an inbound HTTP request to the supplied entity URL was actually observed on a listener you control.
-
-Why this is worth checking before reporting: both are recorded in this class as gated knowledge, so a tester who stops at the first match will report
+- To decide this case, observe: Hypothesis under test: A parser that accepts a DOCTYPE declaration and resolves its entity is the enabling condition for XXE; the submitted payload alone proves nothing.
   - **Disproof:** This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (xxe.fp_rule.auto.derived) states the full boundary.
   - Sources: <https://bishopfox.com/blog/phpspreadsheet-versions1.5.0-xxe-advisory> · <https://snyk.io/blog/find-and-fix-xml-entity-vulnerabilities/>
 
@@ -113,7 +118,7 @@
   - Sources: <https://bishopfox.com/blog/phpspreadsheet-versions1.5.0-xxe-advisory> · <https://snyk.io/blog/nokogiri-xxe-vulnerabilities/>
 - An XXE is proved by the parser resolving an external reference to a resource the submitted document never contained — a request the server issued to an attacker-controlled listener, or file content appearing that only exists on the host — because that is the observable effect entity resolution causes.
   - **Disproof:** The claim is false when the environment blocks resolution so the payload produces a silent parse error or empty result with no outbound request; in that case the finding is a configuration weakness established by the parser defaults rather than a live XXE, and it must be reported as such instead of as a demonstrated read.
-  - Sources: <https://lxml.de/FAQ.html> · <https://lxml.de/parsing.html> · <https://www.php.net/manual/en/function.simplexml-load-string.php>
+  - Sources: <https://lxml.de/parsing.html> · <https://lxml.de/FAQ.html> · <https://www.php.net/manual/en/function.simplexml-load-string.php>
 
 ## False-positive rules (when to reject it)
 
@@ -135,6 +140,18 @@
 - The standard that hardened against this class states the expected safe behaviour directly — entity references are disallowed in the XML stream — which gives the tester a concrete baseline for deciding whether a parser's default is safe rather than an opinion about what looks dangerous.
   - **Disproof:** The claim is false when the surrounding protocol genuinely requires entity references for its correctness, because a parser that honours the disallow rule would break interoperability and the application must accept the risk in a narrower form; the baseline then applies to the untrusted-data boundary only, not to the whole document.
   - Sources: <https://lxml.de/FAQ.html> · <https://tomcat.apache.org/security-8.html>
+- A convincing observation for this class is: Adjacent behaviour that produces the same observable result: An XXE finding is validated only when an inbound HTTP request to the supplied entity URL was actually observed on a listener you control.
+  - **Disproof:** Not evidence when the observable cannot be produced at all -- blind, server-side-only, or identical-in-every-case behaviour leaves nothing to show. The originating rule (xxe.fp_rule.auto.derived) states the full boundary.
+  - Sources: <https://bishopfox.com/blog/phpspreadsheet-versions1.5.0-xxe-advisory> · <https://snyk.io/blog/find-and-fix-xml-entity-vulnerabilities/>
+- A convincing observation for this class is: If the parser resolves the identifier, the fetch happens and you get either content in the response or an inbound callback to your listener.
+  - **Disproof:** Not evidence when the observable cannot be produced at all -- blind, server-side-only, or identical-in-every-case behaviour leaves nothing to show. The originating rule (xxe.technique.external_dtd_reference_is_the_core_probe) states the full boundary.
+  - Sources: <https://www.w3.org/TR/2008/REC-xml-20081126/> · <https://snyk.io/blog/find-and-fix-xml-entity-vulnerabilities/>
+
+## Variants
+
+- Any upload surface that accepts SVG inherits the parser exposure, because the format is XML and a crafted image is a delivery channel for external entity resolution inside the backend.
+  - **Disproof:** Refuted if the SVG upload path rasterises or sanitises the image with no XML parsing of the stored file, or strips the DOCTYPE before any entity resolution is attempted.
+  - Sources: <https://lxml.de/parsing.html> · <https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/pentesting-web/xxe-xee-xml-external-entity.md>
 
 ## Defence bypasses
 
```
