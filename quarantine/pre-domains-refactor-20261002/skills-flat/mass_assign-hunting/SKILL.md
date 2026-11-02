---
name: mass_assign-hunting
description: Use when hunting Mass Assignment / Excessive Data Exposure in a api target. Ordered prerequisites, signals, techniques, validation bar and false-positive rules.
---

# Mass Assignment / Excessive Data Exposure — hunting skill

<!-- GENERATED from db/wks.db by wks/skillgen.py. DO NOT HAND-EDIT.
     Edit the rows (or ingest better research) and re-run:
     python -m wks.skillgen -->

> surface `api` · CWE CWE-915 · OWASP API3:2023
> evidence: 3 items, 3 supported, 2 FP rules, 0 chains
> maturity: **researching** — missing: items, supported_items, chain

The server binds client-supplied fields straight onto a model, so a client can set properties the UI never exposes — including privilege fields.

**Also called:** mass assignment, excessive data exposure, over posting, unintended json properties, graphql over fetch


## Recon signals (where to look)

- A registration or update POST whose body is bound wholesale to the model is exploitable the moment the body carries an extra role or flag field.
  - **Disproof:** If the added field is silently dropped on write and never appears in any later authenticated read of the record, the endpoint filters the input and mass assignment is not present.
  - Sources: <https://bishopfox.com/blog/design-considerations-for-secure-graphql-apis> · <https://snyk.io/blog/avoiding-mass-assignment-node-js/>

## False-positive rules (when to reject it)

- Filtering a known list of role field names such as isAdmin, admin or role is not a mass-assignment fix; an allowlist must be enforced server-side.
  - **Disproof:** If every alternate field name is rejected by strict schema validation that errors on unknown keys, and only allowlisted fields ever reach the model, the blocklist concern is moot.
  - Sources: <https://bishopfox.com/blog/design-considerations-for-secure-graphql-apis> · <https://snyk.io/blog/avoiding-mass-assignment-node-js/>
- Sending a privileged field and seeing it unchanged is a false mass assignment: the request schema whitelist dropped the field before the handler ran.
  - **Disproof:** If the response echoes your submitted privileged value while the database column is untouched, the 200 you saw is your own input reflected, not confirmation of assignment, and the report must be re-run against committed state before it counts.
  - Sources: <https://httpwg.org/specs/rfc9110.html> · <https://projectdiscovery.io/blog/inside-the-benchmark-pp-architectures-finding-walkthroughs-and-what-each-scanner-actually-caught>

---
Full class document: `skills/Web/mass_assign/EVIDENCE.md` · retrieve more with `python -m wks.cli search "<query>" --class-id mass_assign`
