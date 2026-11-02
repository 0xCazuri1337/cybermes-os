# XML External Entity Injection

> surface: `web` · CWE: 611 · OWASP: A05:2021
> maturity: **researching** — 4 items, 4 supported, 1 FP rules, 0 chains

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

## Validation

- **An XXE finding is validated only when an inbound HTTP request to the supplied entity URL was actually observed on a listener you control.**  
  `high_confidence` · score 0.874 · disproved by: No inbound request to the entity URL means entity resolution did not occur and the XXE finding is not reproducible, no matter how alarming the submitted payload looked.
  sources: <https://bishopfox.com/blog/phpspreadsheet-versions1.5.0-xxe-advisory> · <https://snyk.io/blog/nokogiri-xxe-vulnerabilities/>

## Fp Rule

- **An XXE filter that greps for a keyword in one encoding is a false-negative source, so a single clean probe never proves the target is safe.**  
  `high_confidence` · score 0.899 · disproved by: If both the UTF-8 and alternate-encoding probes are rejected with the entity never resolved, the blocklist holds for the encodings tested and the bypass does not reproduce.
  sources: <https://www.w3.org/TR/2008/REC-xml-20081126/> · <https://bishopfox.com/blog/phpspreadsheet-versions1.5.0-xxe-advisory>

## Known gaps

Not yet satisfied: `items`, `fp_rules`, `chain`
