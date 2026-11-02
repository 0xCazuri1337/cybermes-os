---
name: xxe-hunting
description: Use when hunting XML External Entity Injection in a web target. Ordered prerequisites, signals, techniques, validation bar and false-positive rules.
---

# XML External Entity Injection — hunting skill

<!-- GENERATED from db/wks.db by wks/skillgen.py. DO NOT HAND-EDIT.
     Edit the rows (or ingest better research) and re-run:
     python -m wks.skillgen -->

> surface `web` · CWE 611 · OWASP A05:2021
> evidence: 4 items, 4 supported, 1 FP rules, 0 chains
> maturity: **researching** — missing: items, fp_rules, chain

An XML parser resolves external or entity-expanded content the attacker controls.

**Also called:** xxe, xml external entity, blxxe


## Recon signals (where to look)

- A parser that accepts a DOCTYPE declaration and resolves its entity is the enabling condition for XXE; the submitted payload alone proves nothing.
  - **Disproof:** If the parser rejects the DOCTYPE outright or returns a parse error, entity processing is disabled and the XXE signal is absent.
  - Sources: <https://www.w3.org/TR/2008/REC-xml-20081126/> · <https://snyk.io/blog/nokogiri-xxe-vulnerabilities/>

## Techniques (what to change)

- Submitting a DOCTYPE with an external SYSTEM or PUBLIC identifier is the probe that reveals whether the parser resolves entities at all.
  - **Disproof:** If no callback arrives and the response shows the DOCTYPE passed through unparsed, the parser has external entity resolution disabled and the probe is negative.
  - Sources: <https://www.w3.org/TR/2008/REC-xml-20081126/> · <https://snyk.io/blog/find-and-fix-xml-entity-vulnerabilities/>

## Validation bar (how to prove it)

- An XXE finding is validated only when an inbound HTTP request to the supplied entity URL was actually observed on a listener you control.
  - **Disproof:** No inbound request to the entity URL means entity resolution did not occur and the XXE finding is not reproducible, no matter how alarming the submitted payload looked.
  - Sources: <https://bishopfox.com/blog/phpspreadsheet-versions1.5.0-xxe-advisory> · <https://snyk.io/blog/nokogiri-xxe-vulnerabilities/>

## False-positive rules (when to reject it)

- An XXE filter that greps for a keyword in one encoding is a false-negative source, so a single clean probe never proves the target is safe.
  - **Disproof:** If both the UTF-8 and alternate-encoding probes are rejected with the entity never resolved, the blocklist holds for the encodings tested and the bypass does not reproduce.
  - Sources: <https://www.w3.org/TR/2008/REC-xml-20081126/> · <https://bishopfox.com/blog/phpspreadsheet-versions1.5.0-xxe-advisory>

---
Full class document: `skills/Web/xxe/EVIDENCE.md` · retrieve more with `python -m wks.cli search "<query>" --class-id xxe`
