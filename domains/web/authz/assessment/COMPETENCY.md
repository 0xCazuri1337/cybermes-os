# Methodology — Missing Function-Level Authorization

> Derived from 4 verified items. Regenerate with `python -m wks.methodgen --class authz --apply`. Do not hand-edit: this file is a projection of the evidence, and edits are lost on the next cycle.

**Surface.** An endpoint checks that a caller is authenticated but not that they hold the role or permission the operation requires.

**References.** CWE-862 · API5:2023

## Preconditions

_No verified prerequisite items yet._ Derived from evidence only, so this section is empty rather than plausible.


## Reconnaissance signals

_No verified signal items yet._ Derived from evidence only, so this section is empty rather than plausible.


## Test sequence

_No verified technique items yet._ Derived from evidence only, so this section is empty rather than plausible.


## Validation

_No verified validation items yet._ Derived from evidence only, so this section is empty rather than plausible.


## 1. False-positive rejection

_The checks that eliminate the most common non-findings. Run these BEFORE reporting, not after a rejection._

**A response that differs between anonymous and authenticated callers but returns the same object body is a session-gate artefact, not an authorization bypass.**

Discard the finding when the differential is confined to the shell: an anonymous call returns a login redirect, a 401, or an empty shell page, while the authenticated call returns the same resource you could already read as that user. The finding survives only when the authenticated response contains object data the same user was never entitled to, or when the status flips because the endpoint skipped its ownership predicate entirely.

- *Disproof:* If the anonymous body contains any record beyond the public fields, or if swapping only the session cookie between two accounts of equal role yields the other account's object, the gate was not an auth gate and the report is real.
- *Evidence:* high_confidence — [blog.qualys.com](https://blog.qualys.com/vulnerabilities-threat-research/2023/11/15/atlassian-confluence-broken-access-control-vulnerability-cve-2023-22515); [httpwg.org](https://httpwg.org/specs/rfc9110.html)

**A cross-tenant action that succeeded because the endpoint checked role but never checked tenant scope is a real authorization bug, not a false positive.**

Do not discard the report because the handler contains an explicit role or permission check that passed: a check that confirms the caller is a manager without confirming the manager owns that branch is exactly the defect. The report is a false positive instead when the resource returned is one the caller was already entitled to see, when the scope was enforced in a layer you did not exercise, or when your cross-tenant request was rejected and the 200 you saw came from a cached or default response.

- *Disproof:* If the same frozen session that was denied on a cross-branch target is also denied on a same-branch control target, the finding is an artefact of your setup (session, cache, or fixture) rather than a missing scope check.
- *Evidence:* high_confidence — [httpwg.org](https://httpwg.org/specs/rfc9110.html); [projectdiscovery.io](https://projectdiscovery.io/blog/inside-the-benchmark-pp-architectures-finding-walkthroughs-and-what-each-scanner-actually-caught)

## Known bypasses

_No verified bypass items yet._ Derived from evidence only, so this section is empty rather than plausible.


## Chaining

_No verified chain_link items yet._ Derived from evidence only, so this section is empty rather than plausible.


## 2. Impact

_What is actually demonstrable, and what to stop claiming._

**An unauthenticated injection point that can write application-database records gains administrative authority over the application, because privilege lives in the data layer.**

Step: prove the write primitive by comparing a response that differs from a baseline read of the same record set before and after a single injected statement, then escalate only if the changed row is a role or ownership field. The attacker actually gains full administrative access to the application rather than a single record, because the authorization decision is read back out of the database the injection can write; from there application settings, stored data, and secrets reachable by the service are all in scope. Note that an unauthenticated write primitive needs no stolen credential to reach this ceiling, which is what makes the endpoint being unauthenticated by design the multiplier.

- *Disproof:* If the injected write cannot alter a role, ownership, or password field, or if the application re-derives privilege from a signed token the write cannot reach, then administrative authority is not gained.
- *Evidence:* high_confidence — [bishopfox.com](https://bishopfox.com/blog/critical-sql-injection-in-metabase-via-password-reset-cve-2026-72898); [blog.qualys.com](https://blog.qualys.com/vulnerabilities-threat-research/2015/10/28/obtain-admin-rights-on-joomla-with-sql-injection)

## Coverage gap

These stages have no verified evidence and are therefore absent above: Preconditions, Reconnaissance signals, Test sequence, Validation, Known bypasses, Chaining.
A procedure with a missing validation stage is not safe to act on — it produces findings rather than proofs.

---

*Generated from the evidence base. Where this file and the database disagree, the database is correct.*
