# XML External Entity Injection

> surface: `web` · CWE: 611 · OWASP: A05:2021
> maturity: **mature** — 23 items, 23 supported, 2 FP rules, 1 chains

An XML parser resolves external or entity-expanded content the attacker controls.

**Aliases:** xxe, xml external entity, blxxe

## Signal

- **A parser that accepts a DOCTYPE declaration and resolves its entity is the enabling condition for XXE; the submitted payload alone proves nothing.**  
  `high_confidence` · score 0.899 · disproved by: If the parser rejects the DOCTYPE outright or returns a parse error, entity processing is disabled and the XXE signal is absent.
  sources: <https://www.w3.org/TR/2008/REC-xml-20081126/> · <https://snyk.io/blog/nokogiri-xxe-vulnerabilities/>

## Technique

- **Submitting a DOCTYPE with an external SYSTEM or PUBLIC identifier is the probe that reveals whether the parser resolves entities at all.**  
  `high_confidence` · score 0.899 · disproved by: If no callback arrives and the response shows the DOCTYPE passed through unparsed, the parser has external entity resolution disabled and the probe is negative.
  sources: <https://www.w3.org/TR/2008/REC-xml-20081126/> · <https://snyk.io/blog/find-and-fix-xml-entity-vulnerabilities/>
- **Data retrieval The most common XXE injection vulnerability lets attackers prompt a server to disclose sensitive data or files in an HTTP response.**  
  `high_confidence` · score 0.8295 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Data retrieval The most common XXE injection vulnerability lets attackers prompt a server ".
  sources: <https://bishopfox.com/blog/phpspreadsheet-versions1.5.0-xxe-advisory> · <https://snyk.io/blog/find-and-fix-xml-entity-vulnerabilities/>
- **In isolation, this gives an attacker read-only access to data, but it can reveal information useful for escalating to a more damaging attack.**  
  `high_confidence` · score 0.827 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "In isolation, this gives an attacker read-only access to data, but it can reveal informati".
  sources: <https://www.w3.org/TR/2008/REC-xml-20081126/> · <https://snyk.io/blog/find-and-fix-xml-entity-vulnerabilities/>
- **Error-based information disclosure Our server is vulnerable to blind XXE injection methods if an attacker can retrieve valuable data by examining the error messages our server emits.**  
  `high_confidence` · score 0.827 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Error-based information disclosure Our server is vulnerable to blind XXE injection methods".
  sources: <https://www.w3.org/TR/2008/REC-xml-20081126/> · <https://snyk.io/blog/find-and-fix-xml-entity-vulnerabilities/>
- **In serious cases, attackers can commit a server-side request forgery , which lets them impersonate a server on their target’s network and may enable them to execute code remotely.**  
  `high_confidence` · score 0.827 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "In serious cases, attackers can commit a server-side request forgery , which lets them imp".
  sources: <https://www.w3.org/TR/2008/REC-xml-20081126/> · <https://snyk.io/blog/find-and-fix-xml-entity-vulnerabilities/>
- **5 ]> In this code, the targeted server will try to send the HTTP request to the attacker’s server URL.**  
  `high_confidence` · score 0.802 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "5 ]> In this code, the targeted server will try to send the HTTP request to the attacker’s".
  sources: <https://bishopfox.com/blog/phpspreadsheet-versions1.5.0-xxe-advisory> · <https://snyk.io/blog/find-and-fix-xml-entity-vulnerabilities/>
- **9 userInfo > If the attacker successfully gains administrative privileges, they can impersonate the server to probe their target’s network for additional vulnerabilities.**  
  `high_confidence` · score 0.802 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "9 userInfo > If the attacker successfully gains administrative privileges, they can impers".
  sources: <https://bishopfox.com/blog/phpspreadsheet-versions1.5.0-xxe-advisory> · <https://snyk.io/blog/find-and-fix-xml-entity-vulnerabilities/>
- **In a payload with ten or more levels of nested entities, the resulting file can be hundreds of gigabytes, typically causing an out-of-memory error for the server attempting to parse the SVG file — and a denial of service for our users.**  
  `high_confidence` · score 0.802 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "In a payload with ten or more levels of nested entities, the resulting file can be hundred".
  sources: <https://bishopfox.com/blog/phpspreadsheet-versions1.5.0-xxe-advisory> · <https://snyk.io/blog/find-and-fix-xml-entity-vulnerabilities/>
- **In a server-side request forgery (SSRF) attack, an attacker will typically inject a URL or address pointing to the vulnerable server’s local file system instance or other restricted-access resources — especially when user inputs are not properly filtered by the XML parser.**  
  `high_confidence` · score 0.7995 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "In a server-side request forgery (SSRF) attack, an attacker will typically inject a URL or".
  sources: <https://www.w3.org/TR/2008/REC-xml-20081126/> · <https://snyk.io/blog/find-and-fix-xml-entity-vulnerabilities/>
- **9 userInfo > The ifconfig command in this example returns the server’s network configuration when the XML parser evaluates the xxe entity.**  
  `high_confidence` · score 0.7995 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "9 userInfo > The ifconfig command in this example returns the server’s network configurati".
  sources: <https://www.w3.org/TR/2008/REC-xml-20081126/> · <https://snyk.io/blog/find-and-fix-xml-entity-vulnerabilities/>
- **However, if a user were to set the DTDLOAD option to true and also set the NONET option to false, then the vulnerability is open to be exploited by any malicious attackers.**  
  `high_confidence` · score 0.788 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "However, if a user were to set the DTDLOAD option to true and also set the NONET option to".
  sources: <https://www.w3.org/TR/2008/REC-xml-20081126/> · <https://bishopfox.com/blog/phpspreadsheet-versions1.5.0-xxe-advisory> · <https://snyk.io/blog/nokogiri-xxe-vulnerabilities/>
- **Missing authentication lets anyone proxy requests unauthenticated, and a regex bypass defeats the private IP block.**  
  `high_confidence` · score 0.7745 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Missing authentication lets anyone proxy requests unauthenticated, and a regex bypass defe".
  sources: <https://bishopfox.com/blog/phpspreadsheet-versions1.5.0-xxe-advisory> · <https://snyk.io/blog/nokogiri-xxe-vulnerabilities/>
- **9 staffInfo > Implementing a robust data encryption protocol is effective in preventing data retrieval, as it renders the stored data unreadable and unusable — even if an attacker successfully infiltrates the target’s server.**  
  `high_confidence` · score 0.7745 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "9 staffInfo > Implementing a robust data encryption protocol is effective in preventing da".
  sources: <https://bishopfox.com/blog/phpspreadsheet-versions1.5.0-xxe-advisory> · <https://snyk.io/blog/find-and-fix-xml-entity-vulnerabilities/>
- **Why XXE represents a security risk XXE injection attacks let attackers take advantage of external entity declarations to gain access to files or infrastructure on their target server or network.**  
  `high_confidence` · score 0.7745 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Why XXE represents a security risk XXE injection attacks let attackers take advantage of e".
  sources: <https://bishopfox.com/blog/phpspreadsheet-versions1.5.0-xxe-advisory> · <https://snyk.io/blog/find-and-fix-xml-entity-vulnerabilities/>
- **Missing authentication lets anyone proxy requests unauthenticated, and a regex bypass defeats the private IP block.**  
  `high_confidence` · score 0.7745 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Missing authentication lets anyone proxy requests unauthenticated, and a regex bypass defe".
  sources: <https://bishopfox.com/blog/phpspreadsheet-versions1.5.0-xxe-advisory> · <https://snyk.io/blog/nokogiri-xxe-vulnerabilities/>
- **By default you should be set, but if you’ve made those changes you’re currently vulnerable.**  
  `high_confidence` · score 0.772 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "By default you should be set, but if you’ve made those changes you’re currently vulnerable".
  sources: <https://www.w3.org/TR/2008/REC-xml-20081126/> · <https://snyk.io/blog/nokogiri-xxe-vulnerabilities/>
- **4 EOX If an XML parser is set to include external entities, it opens the door for attackers to execute an XML External Entities attack by injecting a malicous entity.**  
  `high_confidence` · score 0.772 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "4 EOX If an XML parser is set to include external entities, it opens the door for attacker".
  sources: <https://www.w3.org/TR/2008/REC-xml-20081126/> · <https://snyk.io/blog/nokogiri-xxe-vulnerabilities/>
- **Implement zero trust security The trust relationship between your web applications and other external or third-party services (such as message brokers and user authentication platforms) can be exploited to launch a SSRF on your server infrastructure.**  
  `high_confidence` · score 0.772 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Implement zero trust security The trust relationship between your web applications and oth".
  sources: <https://www.w3.org/TR/2008/REC-xml-20081126/> · <https://snyk.io/blog/find-and-fix-xml-entity-vulnerabilities/>
- **And, if an attacker does breach security, they should only encounter encrypted data and a network of zero-trust services.**  
  `high_confidence` · score 0.747 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "And, if an attacker does breach security, they should only encounter encrypted data and a ".
  sources: <https://bishopfox.com/blog/phpspreadsheet-versions1.5.0-xxe-advisory> · <https://snyk.io/blog/find-and-fix-xml-entity-vulnerabilities/>

## Validation

- **An XXE finding is validated only when an inbound HTTP request to the supplied entity URL was actually observed on a listener you control.**  
  `high_confidence` · score 0.874 · disproved by: No inbound request to the entity URL means entity resolution did not occur and the XXE finding is not reproducible, no matter how alarming the submitted payload looked.
  sources: <https://bishopfox.com/blog/phpspreadsheet-versions1.5.0-xxe-advisory> · <https://snyk.io/blog/nokogiri-xxe-vulnerabilities/>

## Fp Rule

- **An XXE filter that greps for a keyword in one encoding is a false-negative source, so a single clean probe never proves the target is safe.**  
  `high_confidence` · score 0.899 · disproved by: If both the UTF-8 and alternate-encoding probes are rejected with the entity never resolved, the blocklist holds for the encodings tested and the bypass does not reproduce.
  sources: <https://www.w3.org/TR/2008/REC-xml-20081126/> · <https://bishopfox.com/blog/phpspreadsheet-versions1.5.0-xxe-advisory>
- **Reject a xxe finding until it is distinguished from the adjacent behaviour this class also covers. "A parser that accepts a DOCTYPE declaration and resolves its entity is the enabling condition for XXE; the submitted payload alone proves nothing." and "An XXE finding is validated only when an inbound HTTP request to the supplied entity URL was actually observed on a listener you control." share a surface and a symptom, so a response that matches the first is not evidence for it while the second remains possible.**  
  `high_confidence` · score 0.8655 · disproved by: This rule is wrong if a controlled test shows the two behaviours can never co-occur on the same surface, or if the corpus entry for "An XXE finding is validated only when an inbound HTTP request to the s" is out of date. In that case this class needs its false-positive guidance rewritten rather than deleted.
  sources: <https://bishopfox.com/blog/phpspreadsheet-versions1.5.0-xxe-advisory> · <https://snyk.io/blog/find-and-fix-xml-entity-vulnerabilities/>
