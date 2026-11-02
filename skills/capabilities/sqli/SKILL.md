---
name: sqli
description: "Canonical SQL injection (SQLi) capability: error-, union-, blind boolean-, time-based-, stacked-query-, second-order-, ORM/raw-fragment-, and NoSQL-adjacent SQLi across MySQL, PostgreSQL, MSSQL, Oracle, SQLite, BigQuery. Covers detection, fingerprinting, exploitation, sqlmap automation, WAF bypass, and reporting. Consolidates 4 sub-skills: exploiting-sql-injection-vulnerabilities, exploiting-sql-injection-with-sqlmap, hunt-sqli, performing-second-order-sql-injection. Use when hunting or validating SQLi-related vulnerabilities."
sources: github, hackerone_public, portswigger_research, owasp_wstg
report_count: 29
---

# SQLI — Canonical Capability

## 1. Identity and purpose

This is the single primary executable capability for SQL injection (SQLi) testing across relational backends (MySQL, PostgreSQL, MSSQL, Oracle, SQLite, BigQuery) and adjacent ORM/raw-fragment injection surfaces. It consolidates 4 previously separate sub-skills into one operational entry point while preserving all source content in `references/` and the original sub-skill directories for rollback.

Primary objectives:
- Discover every input vector that reaches a SQL query unsanitized (GET/POST params, headers, cookies, JSON/XML bodies, path segments, GraphQL, second-order storage).
- Fingerprint the database engine and select the fastest working technique (UNION when results reflect; blind only as last resort).
- Prove exploitation with data extraction, auth bypass, or RCE where authorized; produce reproducible, impact-rated findings.
- Handle modern surfaces: ORM raw fragments (Django, Sequelize), GraphQL resolvers, OIDC-proxy backends, WAF bypass.
- Produce remediation guidance (parameterized queries, least privilege, WAF as defense-in-depth).

## 2. Scope

In scope:
- Error-based, union-based, blind boolean, time-based blind, stacked-query, out-of-band (OOB) SQLi.
- Second-order SQLi (stored payload executed in a later query).
- Database fingerprinting (MySQL, PostgreSQL, MSSQL, Oracle, SQLite, BigQuery).
- Automated exploitation with sqlmap (detection, enumeration, dump, tamper scripts, OS shell).
- WAF/filter bypass via encoding, alternate syntax, fragmentation, tamper scripts.
- ORM/raw-fragment SQLi (Django CVE-2024-42005, Sequelize GHSA-wrh9-cjv3-2hpw) and SOQL (Salesforce) injection.
- Time-based blind SQLi in GraphQL resolvers; SQLi on OIDC-proxy backends.
- NoSQL appears only as adjacent ORM/WAF context; dedicated NoSQL operator injection is owned by `nosqli`.

Out of scope (hand off):
- Dedicated NoSQL operator injection ($ne/$gt/$regex/$where) -> `nosqli` capability.
- Server-side template injection -> `ssti` capability.
- Command injection on the host outside DB context -> `command-injection` capability.
- Cross-site scripting -> `xss` capability.
- Authentication/authorization logic flaws without injection -> `auth`/`identity` capabilities.
- Pure request smuggling / HPP -> `request-smuggling` capability.

## 3. Invocation and routing

Use this capability when:
- A parameter, header, cookie, or JSON field is suspected to reach a SQL query.
- Database error messages leak in responses, or response length/status/time changes on injection.
- You are bug-bounty hunting or pentesting any web/API/GraphQL/OIDC surface.
- A prior scanner (Burp/ZAP/Nuclei) flagged a potential SQLi.
- You need to validate and demonstrate impact of a suspected SQLi.

Routing notes:
- Start with `references/hunt-sqli.md` for hunting methodology, attack-surface signals, modern vectors, and chains.
- Use `references/exploiting-sql-injection-vulnerabilities.md` for manual detection, fingerprinting, UNION/error/blind exploitation, and reporting template.
- Use `references/exploiting-sql-injection-with-sqlmap.md` for sqlmap workflows, enumeration, tamper scripts, and OS shell.
- Use `references/performing-second-order-sql-injection.md` for second-order discovery, storage/trigger mapping, and sqlmap `--second-url`.
- Chain to `nosqli` when a NoSQL backend is involved, `ssti`/`command-injection` for chained RCE, `idor`/`authz` for post-bypass access.

## 4. Inputs and outputs

Inputs:
- Target base URLs, endpoints, parameters, headers, cookies, and request templates.
- Session cookies / authentication material for credentialed tests.
- Sample request bodies (form-encoded, JSON, XML, GraphQL) and content types.
- Optional: Burp Suite project, browser automation, wordlists, OOB endpoint (Burp Collaborator / interactsh).

Outputs:
- Confirmed or refuted SQLi findings with request/response proof.
- Database engine/version fingerprint and injection type classification.
- Extracted schema/data proof (redacted PII) or auth-bypass demonstration.
- Reproduction steps, impact assessment, and remediation guidance.
- False-positive rulings with disproof rationale.

## 5. Preconditions and authorization

- Confirm written authorization and scope before testing; include DB exploitation depth (detection only vs. full dump).
- Use only test accounts and non-production data unless explicitly authorized.
- Avoid destructive operations (no INSERT/UPDATE/DELETE/DROP) on shared resources; prefer read-only proof (`id`, `@@version`, record counts).
- Do not exfiltrate real customer PII beyond proof of control; redact in reports.
- Respect rate limits; coordinate test windows for time-based tests.
- Document any out-of-scope endpoint discovered and hand off rather than exploit.

## 6. Reconnaissance

Recon steps:
1. Collect endpoints, parameters, headers, cookies, and request templates from proxy logs, JS bundles, source maps, OpenAPI/Swagger, mobile traffic.
2. Identify tech stack and DB engine from response headers, error messages, framework fingerprints (`X-Powered-By`, `Server`).
3. Map all input vectors: URL params, POST body, JSON/XML fields, HTTP headers (Cookie, Referer, User-Agent, X-Forwarded-For), path segments, GraphQL variables.
4. Identify high-value endpoints: `/search`, `/filter`, `/sort`, `/report`, `/login`, `/api/*`, admin panels, export/download.
5. Check for second-order surfaces: registration, profile update, comments, reviews, file metadata, preferences.
6. Note WAF presence and behavior (block pages, 403s, normalized responses).
7. Harvest JS bundles for dynamic query construction and API routes.

See `references/hunt-sqli.md` (Attack Surface Signals, Crown Jewel Targets).

## 7. Detection methodology

Core detection flow:
1. Send a single `'` (and `"`, backtick) to each parameter; look for DB errors, length/status changes, or 500s.
2. Boolean-based: compare `' AND 1=1--` vs `' AND 1=2--` responses (length, status, content).
3. Time-based: inject `SLEEP(5)`/`pg_sleep(5)`/`WAITFOR DELAY` and measure response time delta.
4. Out-of-band: trigger DNS/HTTP callbacks to a collaborator domain when responses are not observable.
5. For JSON/NoSQL-adjacent: test object injection (`{"$gt":""}`) and array notation (`param[$ne]=x`).
6. Second-order: store payload at input point, then trigger execution at a different endpoint; compare responses.
7. ORM/raw-fragment: test filter/sort/order parameters for raw SQL fragment injection (Django `__raw`, Sequelize `where` raw).
8. GraphQL: test variables and arguments in resolvers for time-based blind SQLi.
9. Confirm with a second independent request; rule out caching/localization.

Fastest-technique rule (from hunt-sqli): if the endpoint reflects query results, use UNION to dump data directly into the visible output; reserve blind boolean extraction only when no data is reflected.

Column-count establishment (UNION): exhaustively increment `ORDER BY n` / `UNION SELECT NULL,...` until the error clears; do not guess. Then replace NULLs with markers to find reflected columns, then dump data into reflected positions.

References by phase:
- Hunting: `references/hunt-sqli.md`.
- Manual exploitation: `references/exploiting-sql-injection-vulnerabilities.md`.
- sqlmap automation: `references/exploiting-sql-injection-with-sqlmap.md`.
- Second-order: `references/performing-second-order-sql-injection.md`.

## 8. Technique selection

Select by observed behavior:
- Reflected results available -> UNION-based dump (fastest; data appears in response).
- Error messages leak -> error-based extraction (`EXTRACTVALUE`, `UPDATEXML`, `CAST`).
- No reflection, boolean difference -> blind boolean extraction (char-by-char).
- No visible difference at all -> time-based blind extraction.
- Stored input later used in query -> second-order SQLi (map storage + trigger points).
- WAF blocks common payloads -> tamper scripts (`space2comment`, `between`, `charencode`), encoding, fragmentation, alternate comment syntax.
- Need mass enumeration/automation -> sqlmap with appropriate level/risk and tamper scripts.
- ORM/raw-fragment surface -> target filter/sort/order/raw query parameters.
- GraphQL resolver -> time-based blind on variables.
- OIDC-proxy backend -> inject in forwarded claims/parameters.
- High-privilege DB user suspected -> test stacked queries / OS shell (only if authorized).

## 9. Execution steps

1. Establish baseline response (status, length, time) for a clean request.
2. Inject error/boolean/time probes one change at a time; record deltas.
3. Fingerprint DB engine via error messages and function injection.
4. If injectable, determine injection type and column count (for UNION) exhaustively.
5. Find reflected columns; dump schema/data into reflected positions.
6. For blind, extract data char-by-char with boolean or time oracle.
7. For second-order, map storage and trigger points; store payload; trigger; compare.
8. Use sqlmap for automation once a manual vector is confirmed; tune level/risk/tamper.
9. Test WAF bypass variants if blocked.
10. Validate each candidate with a second independent request/account; mark refuted if not proven.
11. Stop and document when a vector is not exploitable or out of scope.

## 10. Tool usage

- Proxy: Burp Suite Professional (Repeater, Intruder, Comparer, Logger++), OWASP ZAP.
- Automation: sqlmap (detection, `--dbs`, `--tables`, `--columns`, `--dump`, `--tamper`, `--second-url`, `--os-shell`), NoSQLMap (adjacent).
- Scanners: Nuclei SQLi templates, sqlmap crawl mode.
- Clients: curl with precise byte control, httpx, Python requests.
- OOB: Burp Collaborator, interactsh.
- Evidence: saved raw requests/responses, timing captures, screenshots, sqlmap output.

See `references/exploiting-sql-injection-with-sqlmap.md` (Tools & Systems) and `references/exploiting-sql-injection-vulnerabilities.md` (Tools & Systems).

## 11. Payloads and test cases

Representative payloads (adapt to DB engine and context):

Error/boolean probes:
```
'
"
`
' AND 1=1--
' AND 1=2--
' OR '1'='1
```

Time-based:
```
' AND SLEEP(5)--          (MySQL)
'; SELECT pg_sleep(5)--   (PostgreSQL)
'; WAITFOR DELAY '0:0:5'-- (MSSQL)
' AND DBMS_PIPE.RECEIVE_MESSAGE('a',5)-- (Oracle)
```

UNION column discovery:
```
' ORDER BY 1--
' ORDER BY 2--
...
' UNION SELECT NULL--
' UNION SELECT NULL,NULL--
' UNION SELECT 1,2,3,4,5--
```

Extraction:
```
' UNION SELECT NULL,username,password,NULL FROM users--
' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT @@version),0x7e))--
' AND SUBSTRING((SELECT password FROM users WHERE username='admin'),1,1)='a'--
' AND IF(SUBSTRING((SELECT password FROM users WHERE username='admin'),1,1)='a',SLEEP(5),0)--
```

Stacked queries:
```
'; INSERT INTO users(username,password,role) VALUES('attacker','password','admin')--
```

Auth bypass:
```
admin' OR 1=1--
admin' OR '1'='1'--
```

Second-order (stored):
```
username: admin'--   (stored at registration, triggered at password change/profile)
```

ORM/raw-fragment:
```
?sort=id;SELECT ...
?filter={"$where":"..."}   (adjacent NoSQL; hand off to nosqli)
```

WAF bypass variants: encoding, `/**/`, `space2comment`, alternate comment (`#`, `-- `, `/*`), case variation, double URL-encoding.

## 12. Evidence

Each finding must include:
- Exact request and response (raw HTTP or proxy capture), with injected payload highlighted.
- Database engine/version fingerprint and injection type.
- Detection method (error message, boolean diff, time delta, OOB callback).
- For exploitation: extracted schema/data proof (redacted PII), auth-bypass demonstration, or RCE proof.
- For second-order: storage point, trigger point, and observed execution.
- For sqlmap: command, level/risk, tamper scripts, and output excerpt.
- Authentication context and account/role used.
- Impact assessment and affected data scope.

## 13. Reproduction and validation

- Reproduce with a minimal request in Burp Repeater or scripted client with precise byte control.
- Validate boolean/time oracles across multiple trials; confirm consistency and absence on non-vulnerable endpoints.
- Validate UNION dumps by re-running with a different column marker; confirm data appears in response.
- For second-order, reproduce storage + trigger sequence end-to-end.
- For sqlmap, reproduce with the documented command and confirm output.
- Mark as refuted if timing is inconsistent, oracle is unstable, or no exploitation demonstrated.

## 14. False-positive rejection

Reject or downgrade when:
- Single-quote causes a generic 500 without DB error and no differential behavior (may be input validation, not SQLi).
- Boolean responses differ due to caching, localization, or benign metadata.
- Time delay caused by server load, not injection (inconsistent across trials).
- Automated scanner reports without manual confirmation.
- Injection point is in a non-production/dev-only route not reachable in scope.
- WAF blocks but no bypass achieved; parser disagreement without data access.
- ORM parameter safely parameterized; raw fragment not reachable.
- Second-order payload stored but never executed in a query.

## 15. Impact

Impact guidance:
- Critical: SQLi enabling full database dump (PII/credentials), auth bypass to admin, or RCE via stacked queries/OS shell on production.
- High: SQLi exposing sensitive tables or enabling privilege escalation; second-order on admin panels.
- Medium: blind SQLi with limited data access; error-based info disclosure enabling further attacks.
- Low: SQLi confirmed but read-only on non-sensitive data; injection in low-value endpoint.
- Informational: suspicious input handling without confirmed injection.

Always tie impact to business risk and data scope; avoid severity inflation from error messages alone.

## 16. Reporting

Report template:
- Summary: vulnerability type (error/union/blind/time/stacked/second-order/ORM), endpoint, DB engine, impact.
- Preconditions/authorization: test accounts used.
- Steps to reproduce: numbered, minimal, with raw request.
- Proof of concept: extracted data (redacted), auth bypass, or timing evidence.
- Impact: business and data scope, affected users/records.
- Remediation: parameterized queries/prepared statements, ORM safe APIs, input validation (type/allowlist), least-privilege DB user, disable stacked queries where possible, WAF as defense-in-depth, error handling without DB details.

## 17. Failure modes

- Surface not fully discovered -> expand recon, check mobile/SPA, versions, content types, GraphQL.
- No test account -> request credentials or scope clarification; do not exploit without authorization.
- WAF blocks payloads -> try encoding, tamper scripts, alternate syntax, fragmentation; document bypass attempts.
- Rate limiting stops testing -> coordinate throttling, use allowed test windows, or hand off.
- Time-based tests flaky -> increase delay, reduce concurrency, run off-peak.
- Inconclusive result -> repeat with fresh sessions and diff responses; mark as not confirmed if ambiguous.
- No manual vector but scanner hit -> manually verify; do not report unconfirmed.

## 18. References

All 4 sub-skill references are preserved and must resolve:

| Reference | Sub-capability | Load when |
|---|---|---|
| `references/exploiting-sql-injection-vulnerabilities.md` | `exploiting-sql-injection-vulnerabilities` | Manual detection, fingerprinting, UNION/error/blind exploitation, reporting template |
| `references/exploiting-sql-injection-with-sqlmap.md` | `exploiting-sql-injection-with-sqlmap` | sqlmap workflows, enumeration, tamper scripts, OS shell |
| `references/hunt-sqli.md` | `hunt-sqli` | Hunting methodology, attack-surface signals, modern vectors, chains |
| `references/performing-second-order-sql-injection.md` | `performing-second-order-sql-injection` | Second-order discovery, storage/trigger mapping, sqlmap `--second-url` |

Original sub-skills remain intact under `exploiting-sql-injection-vulnerabilities/`, `exploiting-sql-injection-with-sqlmap/`, `hunt-sqli/`, and `performing-second-order-sql-injection/`.

## 19. Testing and mastery

- Validate with the capability tests in `tests/test_sqli_capability.py`.
- Confirm all referenced files resolve and are non-empty.
- Confirm migration map paths/hashes/status are accurate.
- Practice on authorized labs: PortSwigger SQL injection labs, sqli-labs, DVWA, HackTheBox.
- Mastery criteria: independently fingerprint DB engine, select fastest working technique, prove extraction/auth bypass, handle WAF and second-order cases, and report with full reproduction, impact, and remediation.


## Knowledge sources

- WKS bug classes: sqli
- Domain knowledge: sqli
- WKS remains the structured source of truth; retrieve and validate items through WKS rather than duplicating the full corpus in this skill.
- Research and learning material is mapped in `stage-a/knowledge-source-map.json` and must be validated before promotion.
