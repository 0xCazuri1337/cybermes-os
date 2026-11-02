# Missing Function-Level Authorization

## Definition

An endpoint checks that a caller is authenticated but not that they hold the role or permission the operation requires.

- **CWE:** CWE-862
- **OWASP:** API5:2023
- **Surface:** api
- **Aliases:** ["missing function level authorization", "bfla", "admin endpoint exposure", "unauthorized access to administrative function"]

Canonical home for `authz`. Rendered from `db/wks.db` by `methodology/scripts/build_taxonomy.py` — edit the rows, not this file.

## Root Cause

Not yet researched.

## Preconditions

Not yet researched.

## Attack Surface

Surface: **api**.

The entry points and enabling conditions for this surface are enumerated under **Preconditions**; the observable signals are under **Detection**.

## Detection

Not yet researched.

## Exploitation

Not yet researched.

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

**A response that differs between anonymous and authenticated callers but returns the same object body is a session-gate artefact, not an authorization bypass.**

Discard the finding when the differential is confined to the shell: an anonymous call returns a login redirect, a 401, or an empty shell page, while the authenticated call returns the same resource you could already read as that user. The finding survives only when the authenticated response contains object data the same user was never entitled to, or when the status flips because the endpoint skipped its ownership predicate entirely.

*Disproof:* If the anonymous body contains any record beyond the public fields, or if swapping only the session cookie between two accounts of equal role yields the other account's object, the gate was not an auth gate and the report is real.

**A cross-tenant action that succeeded because the endpoint checked role but never checked tenant scope is a real authorization bug, not a false positive.**

Do not discard the report because the handler contains an explicit role or permission check that passed: a check that confirms the caller is a manager without confirming the manager owns that branch is exactly the defect. The report is a false positive instead when the resource returned is one the caller was already entitled to see, when the scope was enforced in a layer you did not exercise, or when your cross-tenant request was rejected and the 200 you saw came from a cached or default response.

*Disproof:* If the same frozen session that was denied on a cross-branch target is also denied on a same-branch control target, the finding is an artefact of your setup (session, cache, or fixture) rather than a missing scope check.

## Validation

Not yet researched.

## Impact

**An unauthenticated injection point that can write application-database records gains administrative authority over the application, because privilege lives in the data layer.**

Step: prove the write primitive by comparing a response that differs from a baseline read of the same record set before and after a single injected statement, then escalate only if the changed row is a role or ownership field. The attacker actually gains full administrative access to the application rather than a single record, because the authorization decision is read back out of the database the injection can write; from there application settings, stored data, and secrets reachable by the service are all in scope. Note that an unauthenticated write primitive needs no stolen credential to reach this ceiling, which is what makes the endpoint being unauthenticated by design the multiplier.

*Disproof:* If the injected write cannot alter a role, ownership, or password field, or if the application re-derives privilege from a signed token the write cannot reach, then administrative authority is not gained.

## Related Bug Classes

Not yet researched.

## References

- **bishopfox.com** (writeup)
  - <https://bishopfox.com/blog/critical-sql-injection-in-metabase-via-password-reset-cve-2026-72898>
- **blog.qualys.com** (writeup)
  - <https://blog.qualys.com/vulnerabilities-threat-research/2015/10/28/obtain-admin-rights-on-joomla-with-sql-injection>
  - <https://blog.qualys.com/vulnerabilities-threat-research/2023/11/15/atlassian-confluence-broken-access-control-vulnerability-cve-2023-22515>
- **httpwg.org** (standard)
  - <https://httpwg.org/specs/rfc9110.html>
- **learn.microsoft.com** (docs)
  - <https://learn.microsoft.com/en-us/aspnet/core/security/authorization>
- **microsoft.com** (research)
  - <https://www.microsoft.com/en-us/security/blog/2026/09/09/threat-matrix-mapping-threats-across-cloud-web-applications/>
- **projectdiscovery.io** (writeup)
  - <https://projectdiscovery.io/blog/inside-the-benchmark-pp-architectures-finding-walkthroughs-and-what-each-scanner-actually-caught>

Every item above is gated on >= 2 distinct publisher hosts (`wks/quality.py`, rule R1). Publisher diversity, not citation count, is what makes these corroborated.
