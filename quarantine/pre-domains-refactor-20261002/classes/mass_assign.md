# Mass Assignment / Excessive Data Exposure

> surface: `api` · CWE: CWE-915 · OWASP: API3:2023
> maturity: **researching** — 3 items, 3 supported, 2 FP rules, 0 chains

The server binds client-supplied fields straight onto a model, so a client can set properties the UI never exposes — including privilege fields.

**Aliases:** mass assignment, excessive data exposure, over posting, unintended json properties, graphql over fetch

## Signal

- **A registration or update POST whose body is bound wholesale to the model is exploitable the moment the body carries an extra role or flag field.**  
  `high_confidence` · score 0.929 · disproved by: If the added field is silently dropped on write and never appears in any later authenticated read of the record, the endpoint filters the input and mass assignment is not present.
  sources: <https://bishopfox.com/blog/design-considerations-for-secure-graphql-apis> · <https://snyk.io/blog/avoiding-mass-assignment-node-js/>

## Fp Rule

- **Sending a privileged field and seeing it unchanged is a false mass assignment: the request schema whitelist dropped the field before the handler ran.**  
  `high_confidence` · score 0.929 · disproved by: If the response echoes your submitted privileged value while the database column is untouched, the 200 you saw is your own input reflected, not confirmation of assignment, and the report must be re-run against committed state before it counts.
  sources: <https://httpwg.org/specs/rfc9110.html> · <https://projectdiscovery.io/blog/inside-the-benchmark-pp-architectures-finding-walkthroughs-and-what-each-scanner-actually-caught>
- **Filtering a known list of role field names such as isAdmin, admin or role is not a mass-assignment fix; an allowlist must be enforced server-side.**  
  `high_confidence` · score 0.783 · disproved by: If every alternate field name is rejected by strict schema validation that errors on unknown keys, and only allowlisted fields ever reach the model, the blocklist concern is moot.
  sources: <https://bishopfox.com/blog/design-considerations-for-secure-graphql-apis> · <https://snyk.io/blog/avoiding-mass-assignment-node-js/>

## Known gaps

Not yet satisfied: `items`, `supported_items`, `chain`
