# Methodology — XML External Entity Injection

> Derived from 4 verified items. Regenerate with `python -m wks.methodgen --class xxe --apply`. Do not hand-edit: this file is a projection of the evidence, and edits are lost on the next cycle.

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

## 2. Test sequence

_Concrete mutations to try. Each is written to be executable, not to be a description of the vulnerability._

**Submitting a DOCTYPE with an external SYSTEM or PUBLIC identifier is the probe that reveals whether the parser resolves entities at all.**

Send a document whose DOCTYPE names a controlled or 127.0.0.1 listener, with an entity referencing it. If the parser resolves the identifier, the fetch happens and you get either content in the response or an inbound callback to your listener. Prefer an out-of-band listener over file content, since the callback proves resolution without disclosing data.

- *Disproof:* If no callback arrives and the response shows the DOCTYPE passed through unparsed, the parser has external entity resolution disabled and the probe is negative.
- *Evidence:* high_confidence — [snyk.io](https://snyk.io/blog/find-and-fix-xml-entity-vulnerabilities/); [w3.org](https://www.w3.org/TR/2008/REC-xml-20081126/)

## 3. Validation

_How to prove the finding rather than infer it. A technique that cannot be validated must not be reported._

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

## Known bypasses

_No verified bypass items yet._ Derived from evidence only, so this section is empty rather than plausible.


## Chaining

_No verified chain_link items yet._ Derived from evidence only, so this section is empty rather than plausible.


## Impact

_No verified impact items yet._ Derived from evidence only, so this section is empty rather than plausible.


## Coverage gap

These stages have no verified evidence and are therefore absent above: Preconditions, Known bypasses, Chaining, Impact.
A procedure with a missing validation stage is not safe to act on — it produces findings rather than proofs.

---

*Generated from the evidence base. Where this file and the database disagree, the database is correct.*
