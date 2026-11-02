# XML External Entity Injection

## Definition

An XML parser resolves external or entity-expanded content the attacker controls.

- **CWE:** 611
- **OWASP:** A05:2021
- **Surface:** web
- **Aliases:** ["xxe", "xml external entity", "blxxe"]

Canonical home for `xxe`. Rendered from `db/wks.db` by `methodology/scripts/build_taxonomy.py` — edit the rows, not this file.

## Root Cause

Not yet researched.

## Preconditions

Not yet researched.

## Attack Surface

Surface: **web**.

The entry points and enabling conditions for this surface are enumerated under **Preconditions**; the observable signals are under **Detection**.

## Detection

**A parser that accepts a DOCTYPE declaration and resolves its entity is the enabling condition for XXE; the submitted payload alone proves nothing.**

Submit a minimal document with an internal DTD declaring one entity and referencing it, and observe whether the parser expands it. Acceptance of the DOCTYPE plus expansion shows the parser is processing declarations rather than rejecting them wholesale. This is the signal to escalate to; a rejected DOCTYPE ends the investigation for that endpoint.

*Disproof:* If the parser rejects the DOCTYPE outright or returns a parse error, entity processing is disabled and the XXE signal is absent.

## Exploitation

**Submitting a DOCTYPE with an external SYSTEM or PUBLIC identifier is the probe that reveals whether the parser resolves entities at all.**

Send a document whose DOCTYPE names a controlled or 127.0.0.1 listener, with an entity referencing it. If the parser resolves the identifier, the fetch happens and you get either content in the response or an inbound callback to your listener. Prefer an out-of-band listener over file content, since the callback proves resolution without disclosing data.

*Disproof:* If no callback arrives and the response shows the DOCTYPE passed through unparsed, the parser has external entity resolution disabled and the probe is negative.

## Variations

Not yet researched.

## Technology / Framework Considerations

Not yet researched.

## API Considerations

Not yet researched.

## Attack Chains

Not yet researched.

## Real-World Examples

Not yet researched.

## Common False Positives

**An XXE filter that greps for a keyword in one encoding is a false-negative source, so a single clean probe never proves the target is safe.**

If the target halts XML processing when an external entity is detected, re-send the same document in a different encoding such as UTF-7 and compare. A filter matching decoded UTF-8 text can be stepped around by an encoding the decoder resolves later, which is exactly how a published advisory's check was bypassed. Run at least two encodings before closing an XXE item as fixed.

*Disproof:* If both the UTF-8 and alternate-encoding probes are rejected with the entity never resolved, the blocklist holds for the encodings tested and the bypass does not reproduce.

## Validation

**An XXE finding is validated only when an inbound HTTP request to the supplied entity URL was actually observed on a listener you control.**

Stand up a listener and treat any inbound GET as the only acceptable proof that resolution occurred. Re-run twice to exclude transient failures, and record the timestamp, requested path and source address. The callback is what separates a real finding from a payload that merely appeared in a request body, and it is evidence an operator can independently reproduce.

*Disproof:* No inbound request to the entity URL means entity resolution did not occur and the XXE finding is not reproducible, no matter how alarming the submitted payload looked.

## Impact

Not yet researched.

## Related Bug Classes

Not yet researched.

## References

- **bishopfox.com** (report)
  - <https://bishopfox.com/blog/phpspreadsheet-versions1.5.0-xxe-advisory>
- **snyk.io** (writeup)
  - <https://snyk.io/blog/find-and-fix-xml-entity-vulnerabilities/>
  - <https://snyk.io/blog/nokogiri-xxe-vulnerabilities/>
- **w3.org** (docs)
  - <https://www.w3.org/TR/2008/REC-xml-20081126/>

Every item above is gated on >= 2 distinct publisher hosts (`wks/quality.py`, rule R1). Publisher diversity, not citation count, is what makes these corroborated.
