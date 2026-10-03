# Missing Function-Level Authorization

> surface: `api` · CWE: CWE-862 · OWASP: API5:2023
> maturity: **mature** — 18 items, 18 supported, 2 FP rules, 1 chains

An endpoint checks that a caller is authenticated but not that they hold the role or permission the operation requires.

**Aliases:** missing function level authorization, bfla, admin endpoint exposure, unauthorized access to administrative function

## Technique

- **ACL-based protection mechanism treats negative access rights as if they are positive, allowing bypass of intended restrictions.**  
  `high_confidence` · score 0.8055 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "ACL-based protection mechanism treats negative access rights as if they are positive, allo".
  sources: <https://cwe.mitre.org/data/definitions/862.html> · <https://portswigger.net/web-security/access-control>
- **System monitoring software allows users to bypass authorization by creating custom forms.**  
  `high_confidence` · score 0.8055 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "System monitoring software allows users to bypass authorization by creating custom forms.".
  sources: <https://cwe.mitre.org/data/definitions/862.html> · <https://portswigger.net/web-security/access-control>
- **Chain: product does not properly check the result of a reverse DNS lookup because of operator precedence ( CWE-783 ), allowing bypass of DNS-based access restrictions.**  
  `high_confidence` · score 0.8055 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Chain: product does not properly check the result of a reverse DNS lookup because of opera".
  sources: <https://cwe.mitre.org/data/definitions/862.html> · <https://portswigger.net/web-security/access-control>
- **Terminal server does not check authorization for guest access.**  
  `high_confidence` · score 0.8055 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Terminal server does not check authorization for guest access.".
  sources: <https://cwe.mitre.org/data/definitions/862.html> · <https://portswigger.net/web-security/access-control>
- **The product does not perform an authorization check when an actor attempts to access a resource or perform an action.**  
  `high_confidence` · score 0.794 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "The product does not perform an authorization check when an actor attempts to access a res".
  sources: <https://cwe.mitre.org/data/definitions/862.html> · <https://owasp.org/API-Security/editions/2023/en/0xa5-broken-function-level-authorization/> · <https://portswigger.net/web-security/access-control>
- **An attacker could read sensitive data, either by reading the data directly from a data store that is not restricted, or by accessing insufficiently-protected, privileged functionality to read the data.**  
  `high_confidence` · score 0.794 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "An attacker could read sensitive data, either by reading the data directly from a data sto".
  sources: <https://cwe.mitre.org/data/definitions/862.html> · <https://owasp.org/API-Security/editions/2023/en/0xa5-broken-function-level-authorization/> · <https://portswigger.net/web-security/access-control>
- **While the program properly exits if authentication fails, it does not ensure that the message is addressed to the user.**  
  `high_confidence` · score 0.778 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "While the program properly exits if authentication fails, it does not ensure that the mess".
  sources: <https://cwe.mitre.org/data/definitions/862.html> · <https://portswigger.net/web-security/access-control>
- **Chain: reliance on client-side security ( CWE-602 ) allows attackers to bypass authorization using a custom client.**  
  `high_confidence` · score 0.778 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Chain: reliance on client-side security ( CWE-602 ) allows attackers to bypass authorizati".
  sources: <https://cwe.mitre.org/data/definitions/862.html> · <https://portswigger.net/web-security/access-control>
- **Chain: product does not properly handle wildcards in an authorization policy list, allowing unintended access.**  
  `high_confidence` · score 0.778 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Chain: product does not properly handle wildcards in an authorization policy list, allowin".
  sources: <https://cwe.mitre.org/data/definitions/862.html> · <https://portswigger.net/web-security/access-control>
- **While this code is careful to avoid SQL Injection, the function does not confirm the user sending the query is authorized to do so.**  
  `high_confidence` · score 0.778 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "While this code is careful to avoid SQL Injection, the function does not confirm the user ".
  sources: <https://cwe.mitre.org/data/definitions/862.html> · <https://portswigger.net/web-security/access-control>
- **An attacker could modify sensitive data, either by writing the data directly to a data store that is not restricted, or by accessing insufficiently-protected, privileged functionality to write the data.**  
  `high_confidence` · score 0.778 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "An attacker could modify sensitive data, either by writing the data directly to a data sto".
  sources: <https://cwe.mitre.org/data/definitions/862.html> · <https://portswigger.net/web-security/access-control>
- **Product does not check the ACL of a page accessed using an "include" directive, allowing attackers to read unauthorized files.**  
  `high_confidence` · score 0.778 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Product does not check the ACL of a page accessed using an "include" directive, allowing a".
  sources: <https://cwe.mitre.org/data/definitions/862.html> · <https://portswigger.net/web-security/access-control>
- **The product does not perform an authorization check when an actor attempts to access a resource or perform an action.**  
  `high_confidence` · score 0.77 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "The product does not perform an authorization check when an actor attempts to access a res".
  sources: <https://cwe.mitre.org/data/definitions/862.html> · <https://owasp.org/API-Security/editions/2023/en/0xa5-broken-function-level-authorization/>
- **An attacker could read sensitive data, either by reading the data directly from a data store that is not restricted, or by accessing insufficiently-protected, privileged functionality to read the data.**  
  `high_confidence` · score 0.77 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "An attacker could read sensitive data, either by reading the data directly from a data sto".
  sources: <https://cwe.mitre.org/data/definitions/862.html> · <https://owasp.org/API-Security/editions/2023/en/0xa5-broken-function-level-authorization/>

## Fp Rule

- **A response that differs between anonymous and authenticated callers but returns the same object body is a session-gate artefact, not an authorization bypass.**  
  `high_confidence` · score 0.9565 · disproved by: If the anonymous body contains any record beyond the public fields, or if swapping only the session cookie between two accounts of equal role yields the other account's object, the gate was not an auth gate and the report is real.
  sources: <https://httpwg.org/specs/rfc9110.html> · <https://blog.qualys.com/vulnerabilities-threat-research/2023/11/15/atlassian-confluence-broken-access-control-vulnerability-cve-2023-22515>
- **A cross-tenant action that succeeded because the endpoint checked role but never checked tenant scope is a real authorization bug, not a false positive.**  
  `high_confidence` · score 0.9565 · disproved by: If the same frozen session that was denied on a cross-branch target is also denied on a same-branch control target, the finding is an artefact of your setup (session, cache, or fixture) rather than a missing scope check.
  sources: <https://httpwg.org/specs/rfc9110.html> · <https://projectdiscovery.io/blog/inside-the-benchmark-pp-architectures-finding-walkthroughs-and-what-each-scanner-actually-caught>

## Impact

- **An unauthenticated injection point that can write application-database records gains administrative authority over the application, because privilege lives in the data layer.**  
  `high_confidence` · score 0.9015 · disproved by: If the injected write cannot alter a role, ownership, or password field, or if the application re-derives privilege from a signed token the write cannot reach, then administrative authority is not gained.
  sources: <https://bishopfox.com/blog/critical-sql-injection-in-metabase-via-password-reset-cve-2026-72898> · <https://blog.qualys.com/vulnerabilities-threat-research/2015/10/28/obtain-admin-rights-on-joomla-with-sql-injection>

## Chain Link

- **Compromise of an internet-facing web application hands the next link whatever cloud scope that application's own identity carries, because application-held credentials and workload identity tokens are authorized independently of the user who reached the application.**  
  `high_confidence` · score 0.9175 · disproved by: If the application's identity is scoped to nothing outside its own resource, or the identity endpoint is unreachable from the compromised context, or the token is rejected for the target resource, then authentication alone did not grant broader authorization and the chain stops inside the application.
  sources: <https://cwe.mitre.org/data/definitions/862.html> · <https://learn.microsoft.com/en-us/aspnet/core/security/authorization> · <https://www.microsoft.com/en-us/security/blog/2026/09/09/threat-matrix-mapping-threats-across-cloud-web-applications/>
