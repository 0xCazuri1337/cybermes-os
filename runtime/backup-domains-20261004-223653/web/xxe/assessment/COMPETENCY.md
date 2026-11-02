# Methodology — XML External Entity Injection

> Derived from 20 verified items. Regenerate with `python -m wks.methodgen --class xxe --apply`. Do not hand-edit: this file is a projection of the evidence, and edits are lost on the next cycle.

**Surface.** An XML parser resolves external or entity-expanded content the attacker controls.

**References.** CWE-611 · A05:2021

## Preconditions

_No verified prerequisite items yet._ Derived from evidence only, so this section is empty rather than plausible.


## 1. Reconnaissance signals

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

## 2. Test sequence

_Concrete mutations to try. Each is written to be executable, not to be a description of the vulnerability._

**XML external entity injection is provable by defining an entity that expands to a known local file and observing that content in the response.**

In practice on HTB this shows up as: - The `TGS - Ticket Granting Service` is requested by users who want to use a service. These tickets allow services to verify the user's identity.
When a user requests a `TGT`, they must authenticate to the domain controller by encrypting the current timestamp with their password hash. Once the domain controller validates the user's identity (because the domain knows the user's password hash, meaning it can decrypt the timestamp), it sends the user a TGT for future requests. Once the user has their ticket, they do not have to prove who they are with their password.
If the user wants to connect to an MSSQL database, it will request a Ticket Granting Service (TGS) to The Key Distribution Center (KDC), presenting its Ticket Granting Ticket (TGT). Then it will give the TGS to the MSSQL database server for authentication.

Write-up provenance: ajcriado/htb-writeups :: Cheatsheets/Mix-OSCP-CPTS/Windows/3. Lateral Movement.md (4337 words, classified network).

- *Disproof:* Refuted when a DOCTYPE declaring external entities is rejected by the parser, so the entity is never expanded.
- *Evidence:* high_confidence — [cwe.mitre.org](https://cwe.mitre.org/data/definitions/611.html); [portswigger.net](https://portswigger.net/web-security/xxe); [raw.githubusercontent.com](https://raw.githubusercontent.com/ajcriado/htb-writeups/main/Cheatsheets/Mix-OSCP-CPTS/Windows/3.%20Lateral%20Movement.md)

**Submitting a DOCTYPE with an external SYSTEM or PUBLIC identifier is the probe that reveals whether the parser resolves entities at all.**

Send a document whose DOCTYPE names a controlled or 127.0.0.1 listener, with an entity referencing it. If the parser resolves the identifier, the fetch happens and you get either content in the response or an inbound callback to your listener. Prefer an out-of-band listener over file content, since the callback proves resolution without disclosing data.

- *Disproof:* If no callback arrives and the response shows the DOCTYPE passed through unparsed, the parser has external entity resolution disabled and the probe is negative.
- *Evidence:* high_confidence — [snyk.io](https://snyk.io/blog/find-and-fix-xml-entity-vulnerabilities/); [w3.org](https://www.w3.org/TR/2008/REC-xml-20081126/)

**The risk lives in how the parser resolves external data sources, so the probe is a document that carries a DOCTYPE and an entity declaration; parameter entities are the escalation path once a plain external entity is refused.**

The risk lives in how the parser resolves external data sources, so the probe is a document that carries a DOCTYPE and an entity declaration; parameter entities are the escalation path once a plain external entity is refused.

HackTricks reference: XXE - XEE - XML External Entity (pentesting-web/xxe-xee-xml-external-entity.md)

- *Disproof:* Refuted if the parser rejects the DOCTYPE outright, or resolves internal entities only and never attempts to retrieve the external identifier - there is then no external resolution to test.
- *Evidence:* high_confidence — [lxml.de](https://lxml.de/parsing.html); [raw.githubusercontent.com](https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/pentesting-web/xxe-xee-xml-external-entity.md)

## 3. Validation

_How to prove the finding rather than infer it. A technique that cannot be validated must not be reported._

**An XXE is proved by the parser resolving an external reference to a resource the submitted document never contained — a request the server issued to an attacker-controlled listener, or file content appearing that only exists on the host — because that is the observable effect entity resolution causes.**

Mechanism: An XXE is proved by the parser resolving an external reference to a resource the submitted document never contained — a request the server issued to an attacker-controlled listener, or file content appearing that only exists on the host — because that is the observable effect entity resolution causes. How to apply it in the field: treat this as the validation it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable. Boundary of the rule: The claim is false when the environment blocks resolution so the payload produces a silent parse error or empty result with no outbound request; in that case the finding is a configuration weakness established by the parser defaults rather than a live XXE, and it must be reported as such instead of as a demonstrated read.

- *Disproof:* The claim is false when the environment blocks resolution so the payload produces a silent parse error or empty result with no outbound request; in that case the finding is a configuration weakness established by the parser defaults rather than a live XXE, and it must be reported as such instead of as a demonstrated read.
- *Evidence:* high_confidence — [lxml.de](https://lxml.de/FAQ.html); [php.net](https://www.php.net/manual/en/function.simplexml-load-string.php)

**An XXE finding is validated only when an inbound HTTP request to the supplied entity URL was actually observed on a listener you control.**

Stand up a listener and treat any inbound GET as the only acceptable proof that resolution occurred. Re-run twice to exclude transient failures, and record the timestamp, requested path and source address. The callback is what separates a real finding from a payload that merely appeared in a request body, and it is evidence an operator can independently reproduce.

- *Disproof:* No inbound request to the entity URL means entity resolution did not occur and the XXE finding is not reproducible, no matter how alarming the submitted payload looked.
- *Evidence:* high_confidence — [bishopfox.com](https://bishopfox.com/blog/phpspreadsheet-versions1.5.0-xxe-advisory); [snyk.io](https://snyk.io/blog/nokogiri-xxe-vulnerabilities/)

## 4. False-positive rejection

_The checks that eliminate the most common non-findings. Run these BEFORE reporting, not after a rejection._

**An XXE filter that greps for a keyword in one encoding is a false-negative source, so a single clean probe never proves the target is safe.**

If the target halts XML processing when an external entity is detected, re-send the same document in a different encoding such as UTF-7 and compare. A filter matching decoded UTF-8 text can be stepped around by an encoding the decoder resolves later, which is exactly how a published advisory's check was bypassed. Run at least two encodings before closing an XXE item as fixed.

- *Disproof:* If both the UTF-8 and alternate-encoding probes are rejected with the entity never resolved, the blocklist holds for the encodings tested and the bypass does not reproduce.
- *Evidence:* high_confidence — [bishopfox.com](https://bishopfox.com/blog/phpspreadsheet-versions1.5.0-xxe-advisory); [w3.org](https://www.w3.org/TR/2008/REC-xml-20081126/)

**A parser configured with network access disabled is not thereby safe against XXE, because a file:// or relative entity reference needs no network and the local-file read is the higher-value impact; a tester who stops at the network probe will miss it.**

Mechanism: A parser configured with network access disabled is not thereby safe against XXE, because a file:// or relative entity reference needs no network and the local-file read is the higher-value impact; a tester who stops at the network probe will miss it. How to apply it in the field: treat this as the fp_rule it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable. Boundary of the rule: The rule is wrong when entity resolution is disabled outright — not merely network-restricted — because with resolve_entities off the external entity is never substituted and neither local nor remote disclosure is possible; the network flag alone is the insufficient control, the resolution flag is the effective one.

- *Disproof:* The rule is wrong when entity resolution is disabled outright — not merely network-restricted — because with resolve_entities off the external entity is never substituted and neither local nor remote disclosure is possible; the network flag alone is the insufficient control, the resolution flag is the effective one.
- *Evidence:* high_confidence — [lxml.de](https://lxml.de/parsing.html); [php.net](https://www.php.net/manual/en/function.simplexml-load-string.php)

**Reject a xxe finding until it is distinguished from the adjacent behaviour this class also covers. "A parser that accepts a DOCTYPE declaration and resolves its entity is the enabling condition for XXE; the submitted payload alone proves nothing." and "An XXE finding is validated only when an inbound HTTP request to the supplied entity URL was actually observed on a listener you control." share a surface and a symptom, so a response that matches the first is not evidence for it while the second remains possible.**

Hypothesis under test: A parser that accepts a DOCTYPE declaration and resolves its entity is the enabling condition for XXE; the submitted payload alone proves nothing.

Adjacent behaviour that produces the same observable result: An XXE finding is validated only when an inbound HTTP request to the supplied entity URL was actually observed on a listener you control.

Why this is worth checking before reporting: both are recorded in this class as gated knowledge, so a tester who stops at the first match will report one of them. The two differ in what the server actually did with the input, and that difference is observable in the response rather than in the request.

Required before treating this as a finding: capture the response that demonstrates the first behaviour specifically, and confirm the second is not what was observed.

- *Disproof:* This rule is wrong if a controlled test shows the two behaviours can never co-occur on the same surface, or if the corpus entry for "An XXE finding is validated only when an inbound HTTP request to the s" is out of date. In that case this class needs its false-positive guidance rewritten rather than deleted.
- *Evidence:* high_confidence — [bishopfox.com](https://bishopfox.com/blog/phpspreadsheet-versions1.5.0-xxe-advisory); [snyk.io](https://snyk.io/blog/find-and-fix-xml-entity-vulnerabilities/)

**A parsed document that returned 200 with a defined entity reflected in the output is not an XXE finding; the entity may have been expanded from the document's own internal DTD, which is normal XML processing, and the flaw requires the parser to resolve a reference to an external resource or a local file.**

Mechanism: A parsed document that returned 200 with a defined entity reflected in the output is not an XXE finding; the entity may have been expanded from the document's own internal DTD, which is normal XML processing, and the flaw requires the parser to resolve a reference to an external resource or a local file. How to apply it in the field: treat this as the fp_rule it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable. Boundary of the rule: The rule is wrong when the reflected value could only have come from outside the submitted document — a system property, a well-known file path, or a uniquely identifying marker the tester planted out of band — because then the internal-definition explanation is excluded and an external resolution actually occurred.

- *Disproof:* The rule is wrong when the reflected value could only have come from outside the submitted document — a system property, a well-known file path, or a uniquely identifying marker the tester planted out of band — because then the internal-definition explanation is excluded and an external resolution actually occurred.
- *Evidence:* high_confidence — [lxml.de](https://lxml.de/FAQ.html); [tomcat.apache.org](https://tomcat.apache.org/security-8.html)

## 5. Known bypasses

_Filters and controls that have defeated the techniques above. Treat these as the reason a naive test fails, not as proof of safety._

**Configuring the entity policy on the application's own XML parser call does not cover the parsers a framework or container instantiate internally for XSLT, tag library descriptors, JSP documents or configuration files, so those secondary parsers can bypass the entity limits the application believes it set.**

Mechanism: Configuring the entity policy on the application's own XML parser call does not cover the parsers a framework or container instantiate internally for XSLT, tag library descriptors, JSP documents or configuration files, so those secondary parsers can bypass the entity limits the application believes it set. How to apply it in the field: treat this as the bypass it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable. Boundary of the rule: The rule is false when the framework's internal parsers are the same configured object the application controls, or when the container or library applies a process-wide default that the application cannot override in either direction; then there is only one parser and the endpoint-level configuration does govern it.

- *Disproof:* The rule is false when the framework's internal parsers are the same configured object the application controls, or when the container or library applies a process-wide default that the application cannot override in either direction; then there is only one parser and the endpoint-level configuration does govern it.
- *Evidence:* high_confidence — [lxml.de](https://lxml.de/parsing.html); [tomcat.apache.org](https://tomcat.apache.org/security-8.html)

## Chaining

_No verified chain_link items yet._ Derived from evidence only, so this section is empty rather than plausible.


## Impact

_No verified impact items yet._ Derived from evidence only, so this section is empty rather than plausible.


## Coverage gap

These stages have no verified evidence and are therefore absent above: Preconditions, Chaining, Impact.
A procedure with a missing validation stage is not safe to act on — it produces findings rather than proofs.

---

*Generated from the evidence base. Where this file and the database disagree, the database is correct.*
