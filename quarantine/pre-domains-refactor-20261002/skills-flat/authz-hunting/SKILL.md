---
name: authz-hunting
description: Use when hunting Missing Function-Level Authorization in a api target. Ordered prerequisites, signals, techniques, validation bar and false-positive rules.
---

# Missing Function-Level Authorization — hunting skill

<!-- GENERATED from db/wks.db by wks/skillgen.py. DO NOT HAND-EDIT.
     Edit the rows (or ingest better research) and re-run:
     python -m wks.skillgen -->

> surface `api` · CWE CWE-862 · OWASP API5:2023
> evidence: 5 items, 4 supported, 2 FP rules, 0 chains
> maturity: **researching** — missing: items, chain

An endpoint checks that a caller is authenticated but not that they hold the role or permission the operation requires.

**Also called:** missing function level authorization, bfla, admin endpoint exposure, unauthorized access to administrative function


## Techniques (what to change)

- The product does not perform an authorization check when an actor attempts to access a resource or perform an action.
  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "The product does not perform an authorization check when an actor attempts to access a res".
  - Sources: <https://cwe.mitre.org/data/definitions/862.html> · <https://owasp.org/API-Security/editions/2023/en/0xa5-broken-function-level-authorization/>

## False-positive rules (when to reject it)

- A response that differs between anonymous and authenticated callers but returns the same object body is a session-gate artefact, not an authorization bypass.
  - **Disproof:** If the anonymous body contains any record beyond the public fields, or if swapping only the session cookie between two accounts of equal role yields the other account's object, the gate was not an auth gate and the report is real.
  - Sources: <https://httpwg.org/specs/rfc9110.html> · <https://blog.qualys.com/vulnerabilities-threat-research/2023/11/15/atlassian-confluence-broken-access-control-vulnerability-cve-2023-22515>
- A cross-tenant action that succeeded because the endpoint checked role but never checked tenant scope is a real authorization bug, not a false positive.
  - **Disproof:** If the same frozen session that was denied on a cross-branch target is also denied on a same-branch control target, the finding is an artefact of your setup (session, cache, or fixture) rather than a missing scope check.
  - Sources: <https://httpwg.org/specs/rfc9110.html> · <https://projectdiscovery.io/blog/inside-the-benchmark-pp-architectures-finding-walkthroughs-and-what-each-scanner-actually-caught>

## Impact framing

- An unauthenticated injection point that can write application-database records gains administrative authority over the application, because privilege lives in the data layer.
  - **Disproof:** If the injected write cannot alter a role, ownership, or password field, or if the application re-derives privilege from a signed token the write cannot reach, then administrative authority is not gained.
  - Sources: <https://bishopfox.com/blog/critical-sql-injection-in-metabase-via-password-reset-cve-2026-72898> · <https://blog.qualys.com/vulnerabilities-threat-research/2015/10/28/obtain-admin-rights-on-joomla-with-sql-injection>

## Chaining opportunities

- Compromise of an internet-facing web application hands the next link whatever cloud scope that application's own identity carries, because application-held credentials and workload identity tokens are authorized independently of the user who reached the application. _(unverified)_
  - **Disproof:** If the application's identity is scoped to nothing outside its own resource, or the identity endpoint is unreachable from the compromised context, or the token is rejected for the target resource, then authentication alone did not grant broader authorization and the chain stops inside the application.
  - Sources: <https://learn.microsoft.com/en-us/aspnet/core/security/authorization> · <https://www.microsoft.com/en-us/security/blog/2026/09/09/threat-matrix-mapping-threats-across-cloud-web-applications/>

---
Full class document: `skills/Web/authz/EVIDENCE.md` · retrieve more with `python -m wks.cli search "<query>" --class-id authz`
