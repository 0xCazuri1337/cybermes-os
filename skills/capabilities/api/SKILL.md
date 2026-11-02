---
name: api
description: "Canonical API security capability: REST/GraphQL/gRPC/SOAP/WebSocket API discovery, authorization, injection, business logic, and framework-specific hunting. Consolidates 35 sub-skills. Use when hunting or validating API-related vulnerabilities."
sources: consolidated
---

# API — Canonical Capability

## 1. Identity and purpose

This is the single primary executable capability for API security testing across REST, GraphQL, gRPC, SOAP, and WebSocket surfaces. It consolidates 35 previously separate sub-skills into one operational entry point while preserving all source content in `references/` and the original sub-skill directories for rollback.

Primary objectives:
- Discover every API surface (documented, shadow, legacy, framework-specific).
- Validate authentication, authorization, and business-logic controls at object and function level.
- Exploit injection, mass assignment, excessive data exposure, rate-limit, and protocol-level weaknesses only with proof.
- Produce reproducible, impact-rated findings with remediation guidance.

## 2. Scope

In scope:
- REST/HTTP APIs, GraphQL, gRPC, SOAP/WSDL, WebSocket APIs.
- API gateways, mobile/SPA backends, framework-specific endpoints (ASP.NET, Laravel, Spring Boot, Node.js, Next.js).
- Authentication, authorization, input validation, business logic, rate limiting, inventory, fuzzing, and misconfiguration.

Out of scope (hand off):
- Pure HTML reflection without script execution -> `hunt-html-injection` (escalate to XSS once execution is possible).
- Non-API web vulnerabilities handled by their own capabilities (SQLi, SSRF, SSTI, etc.) unless reached through an API parameter.
- Infrastructure-only findings without an API exploit path -> cloud/network capabilities.

## 3. Invocation and routing

Use this capability when:
- A target exposes API endpoints, SDKs, mobile app traffic, or SPA network calls.
- You need to enumerate, authenticate to, or fuzz an API.
- A finding involves object/function-level authorization, mass assignment, excessive data exposure, or API-specific injection.

Routing notes:
- Start with `references/performing-api-inventory-and-discovery.md` and `references/detecting-shadow-api-endpoints.md` when the surface is unknown.
- Use framework-specific references (`hunt-aspnet`, `hunt-laravel`, `hunt-springboot`, `hunt-nextjs`, `hunt-nodejs`) only after fingerprinting.
- GraphQL-specific work routes to `references/hunt-graphql.md`, `references/performing-graphql-security-assessment.md`, and related GraphQL references.
- WebSocket work routes to `references/exploiting-websocket-vulnerabilities.md`, `references/hunt-websocket.md`, `references/testing-websocket-api-security.md`.

## 4. Inputs and outputs

Inputs:
- Target base URLs, API versions, documentation (OpenAPI/Swagger/WSDL/GraphQL schema), mobile/SPA artifacts.
- Authentication material (test accounts, tokens, API keys) and request templates.
- Optional: Burp Suite project, proxy captures, wordlists, fuzzing dictionaries, CI/CD artifacts.

Outputs:
- Confirmed or refuted API findings with request/response proof.
- Endpoint inventory and shadow/legacy endpoint list.
- Reproduction steps, impact assessment, and remediation guidance.
- False-positive rulings with disproof rationale.

## 5. Preconditions and authorization

- Confirm written authorization and scope before testing; include API hosts, versions, and test accounts.
- Use only test accounts and non-production data unless explicitly authorized.
- Respect rate limits and avoid destructive operations on shared resources.
- Stop at account/tenant boundaries; do not access other users' data beyond proof of control.
- Document any out-of-scope endpoint discovered and hand off rather than exploit.

## 6. Reconnaissance

Recon steps:
1. Collect documentation: OpenAPI/Swagger, Postman collections, WSDL, GraphQL introspection, SDKs, mobile app traffic.
2. Harvest endpoints from JS bundles, source maps, mobile binaries, and proxy logs; grep for `api`, `v1`, `token`, `secret`, `graphql`.
3. Probe versions and paths: `/v0/`, `/v1/`, `/v1.1/`, `/beta/`, `/internal/`, `/admin/`, `/debug/`, and alternate content types (`.json`, `.xml`, `.yaml`).
4. Identify authentication mechanisms and token scopes; map role/tenant boundaries.
5. Detect shadow/zombie endpoints via wordlists (KiteRunner, ffuf) and response diffing.
6. Fingerprint framework and gateway (ASP.NET, Laravel, Spring Boot, Node/Express, Next.js) to select framework references.

See `references/performing-api-inventory-and-discovery.md`, `references/detecting-shadow-api-endpoints.md`, `references/hunt-spa-api.md`, `references/hunt-shadow-api.md`.

## 7. Detection methodology

Core detection flow:
1. Inventory endpoints and parameters; classify by auth requirement and data sensitivity.
2. Test authentication weaknesses (missing auth, weak tokens, scope confusion, version downgrade).
3. Test authorization at object and function level (IDOR/BOLA/BFLA) with two accounts.
4. Test input handling (injection, mass assignment, content-type confusion, parser differentials).
5. Test business logic (race conditions, workflow bypass, price/quantity manipulation).
6. Test availability controls (rate limiting, query complexity, aliasing, resource exhaustion).
7. Validate each candidate with a second, independent request and, where possible, a second account/role.

References by phase:
- Auth: `references/testing-api-authentication-weaknesses.md`, `references/testing-api-security-with-owasp-top-10.md`.
- Authorization: `references/api-authorization.md`, `references/api-idor-bola.md`, `references/api-bfla.md`, `references/api-business-flow-abuse.md`, `references/exploiting-mass-assignment-in-rest-apis.md`, `references/testing-api-for-mass-assignment-vulnerability.md`.
- Injection: `references/exploiting-api-injection-vulnerabilities.md`, `references/hunt-ldap.md`.
- Enumeration/shadow: `references/detecting-api-enumeration-attacks.md`, `references/detecting-shadow-api-endpoints.md`, `references/hunt-shadow-api.md`, `references/hunt-spa-api.md`.
- Misconfig: `references/hunt-api-misconfig.md`, `references/hunt-aspnet.md`, `references/hunt-laravel.md`, `references/hunt-nextjs.md`, `references/hunt-nodejs.md`, `references/hunt-springboot.md`.

## 8. Technique selection

Select techniques by surface and observed behavior:
- Unknown surface -> inventory + shadow endpoint discovery + JS harvesting.
- Authenticated JSON API -> test mass assignment, excessive data exposure, IDOR, and function-level authorization.
- GraphQL -> introspection, query depth/complexity, aliasing, directive injection, and mutation authorization.
- gRPC -> reflection, method enumeration, metadata/auth bypass.
- SOAP -> WSDL parsing, XXE, method enumeration, auth bypass.
- WebSocket -> origin validation, CSWSH, message injection, authorization on messages.
- Framework-specific -> apply the matching framework reference and its known misconfigurations.

See `references/performing-api-fuzzing-with-restler.md`, `references/performing-api-rate-limiting-bypass.md`, `references/performing-api-security-testing-with-postman.md`, `references/implementing-api-security-testing-with-42crunch.md`.

## 9. Execution steps

1. Establish a baseline request for each endpoint (method, headers, body, auth).
2. Replay with one controlled change at a time; record status, body, timing, and headers.
3. For authorization tests, use two accounts/roles and compare responses (diffing).
4. For injection, use unique canaries and confirm execution/data access, not just reflection.
5. For mass assignment, add privileged fields and confirm server-side acceptance/persistence.
6. For excessive data exposure, diff response fields against the UI and document sensitive fields.
7. For rate limiting, test thresholds, bypass headers, and GraphQL aliasing/depth.
8. For shadow endpoints, validate existence and auth requirements before claiming.
9. Confirm exploitability with a clean reproduction (curl or raw HTTP).
10. Stop and document when a vector is not exploitable or out of scope.

## 10. Tool usage

- Proxy: Burp Suite (Repeater, Intruder, Comparer, Logger++), mitmproxy.
- Discovery: ffuf, KiteRunner, dirsearch, subfinder, httpx.
- API-specific: Postman, RESTler, 42Crunch, GraphQL Voyager/Altair, grpcurl, wsrepl.
- Automation: Python requests/httpx, curl, jq, nuclei (in-scope templates only).
- Evidence: screenshots, saved requests/responses, canary values, timing data.

See `references/conducting-api-security-testing.md`, `references/performing-api-security-testing-with-postman.md`, `references/performing-soap-web-service-security-testing.md`.

## 11. Payloads and test cases

Representative test cases (adapt to target):
- Auth bypass: remove `Authorization` header; try `X-Admin: true`, `X-Internal-IP: 127.0.0.1`, `X-Forwarded-For: 127.0.0.1`.
- Version downgrade: `/v3/users` -> `/v1/users`.
- Method override: `POST /api/delete_user` with `X-HTTP-Method-Override: DELETE`.
- Content-type confusion: `application/json` -> `application/xml` / `text/plain`.
- Mass assignment: add `role`, `isAdmin`, `verified`, `balance`, `price` to request body.
- Excessive data exposure: inspect `/v1/me`, `/v1/profile`, nested objects for tokens/PII.
- IDOR: replace object IDs/UUIDs; probe sequential ranges.
- GraphQL introspection: `query { __schema { queryType { name } } }`.
- GraphQL depth: deeply nested `user { friends { friends { ... } } }`.
- GraphQL aliasing: batched mutations (`a: verifyPhoneNumber(...)`, `b: ...`).
- Rate limit: repeat auth endpoint; test `X-Forwarded-For` rotation.
- WebSocket: cross-site WebSocket hijacking with origin check bypass; message injection.
- Shadow endpoints: append `.json`, `.xml`, `.yaml`; probe `/internal/`, `/debug/`, `/beta/`.

Framework and variant details live in the corresponding references.

## 12. Evidence

Each finding must include:
- Exact request and response (raw HTTP or GraphQL operation).
- Authentication context and account/role used.
- Canary values or modified fields and server-side effect.
- For authorization: paired requests showing cross-account/cross-role access.
- For injection: proof of execution or data access, not reflection alone.
- Impact assessment and affected data scope.

## 13. Reproduction and validation

- Reproduce with curl or a saved raw request in a clean session.
- Validate with a second account/role where applicable.
- Confirm persistence for mass assignment and stored issues.
- For race conditions, repeat multiple times and document success rate.
- For blind/async issues, provide callback or timing proof.
- Mark as refuted if execution or unauthorized access cannot be demonstrated.

## 14. False-positive rejection

Reject or downgrade when:
- A field is reflected but not executed or persisted.
- An endpoint returns 401/403/404 without data leakage.
- A privileged field is echoed but not stored or enforced server-side.
- A GraphQL introspection result is disabled or returns only public schema.
- A WebSocket connects but messages are not accepted or authorized actions fail.
- Response differences are due to caching, localization, or benign metadata.
- Framework defaults or dev-only routes are not reachable in production.

## 15. Impact

Impact guidance:
- Critical: unauthenticated RCE, full DB/infrastructure access, global account takeover, payment manipulation.
- High: account takeover, cross-tenant data access, SSRF to internal network, mass PII exposure.
- Medium: IDOR on sensitive data, function-level authorization bypass, rate-limit bypass on auth.
- Low: non-sensitive metadata disclosure, missing hardening without exploit path.

Always tie impact to business risk and data scope; avoid severity inflation from configuration presence alone.

## 16. Reporting

Report template:
- Summary: endpoint, vulnerability type, action, impact.
- Scope/authorization: target, accounts, test window.
- Steps to reproduce: numbered, minimal.
- Proof of concept: raw request/response or script.
- Impact: business and data scope.
- Remediation: specific control (object-level authz, allow-list fields, schema hardening, rate limits, gateway policy).
- References: relevant OWASP API Top 10 category and framework notes.

## 17. Failure modes

- Surface not fully discovered -> expand recon, check mobile/SPA, versions, content types.
- Auth required but no test account -> request credentials or scope clarification; do not bypass without authorization.
- WAF/gateway blocks payloads -> try content-type confusion, encoding, version downgrade, or parser differentials.
- Rate limiting stops testing -> coordinate throttling, use allowed test windows, or hand off.
- GraphQL depth limits -> use aliasing, field selection, or persisted queries.
- Inconclusive authorization result -> repeat with fresh sessions and diff responses; mark as not confirmed if ambiguous.

## 18. References

All 35 sub-skill references are preserved and must resolve:

| Reference | Sub-capability | Load when |
|---|---|---|
| `references/api-hunter.md` | `api-hunter` | Advanced hunting patterns and chaining |
| `references/conducting-api-security-testing.md` | `conducting-api-security-testing` | General API testing methodology |
| `references/detecting-api-enumeration-attacks.md` | `detecting-api-enumeration-attacks` | Enumeration and scraping detection |
| `references/detecting-shadow-api-endpoints.md` | `detecting-shadow-api-endpoints` | Shadow/zombie endpoint discovery |
| `references/exploiting-api-injection-vulnerabilities.md` | `exploiting-api-injection-vulnerabilities` | API injection |
| `references/exploiting-excessive-data-exposure-in-api.md` | `exploiting-excessive-data-exposure-in-api` | Excessive data exposure |
| `references/exploiting-mass-assignment-in-rest-apis.md` | `exploiting-mass-assignment-in-rest-apis` | Mass assignment |
| `references/exploiting-websocket-vulnerabilities.md` | `exploiting-websocket-vulnerabilities` | WebSocket exploitation |
| `references/hunt-api-misconfig.md` | `hunt-api-misconfig` | API misconfiguration |
| `references/hunt-aspnet.md` | `hunt-aspnet` | ASP.NET APIs |
| `references/hunt-fintech-graphql.md` | `hunt-fintech-graphql` | Fintech GraphQL |
| `references/hunt-graphql.md` | `hunt-graphql` | GraphQL hunting |
| `references/hunt-grpc.md` | `hunt-grpc` | gRPC |
| `references/hunt-laravel.md` | `hunt-laravel` | Laravel APIs |
| `references/hunt-ldap.md` | `hunt-ldap` | LDAP/XPath injection |
| `references/hunt-nextjs.md` | `hunt-nextjs` | Next.js APIs |
| `references/hunt-nodejs.md` | `hunt-nodejs` | Node.js APIs |
| `references/hunt-shadow-api.md` | `hunt-shadow-api` | Shadow API hunting |
| `references/hunt-spa-api.md` | `hunt-spa-api` | SPA API discovery |
| `references/hunt-springboot.md` | `hunt-springboot` | Spring Boot APIs |
| `references/hunt-websocket.md` | `hunt-websocket` | WebSocket hunting |
| `references/implementing-api-security-testing-with-42crunch.md` | `implementing-api-security-testing-with-42crunch` | 42Crunch |
| `references/performing-api-fuzzing-with-restler.md` | `performing-api-fuzzing-with-restler` | RESTler fuzzing |
| `references/performing-api-inventory-and-discovery.md` | `performing-api-inventory-and-discovery` | Inventory/discovery |
| `references/performing-api-rate-limiting-bypass.md` | `performing-api-rate-limiting-bypass` | Rate-limit bypass |
| `references/performing-api-security-testing-with-postman.md` | `performing-api-security-testing-with-postman` | Postman testing |
| `references/performing-graphql-depth-limit-attack.md` | `performing-graphql-depth-limit-attack` | GraphQL depth |
| `references/performing-graphql-introspection-attack.md` | `performing-graphql-introspection-attack` | GraphQL introspection |
| `references/performing-graphql-security-assessment.md` | `performing-graphql-security-assessment` | GraphQL assessment |
| `references/performing-soap-web-service-security-testing.md` | `performing-soap-web-service-security-testing` | SOAP testing |
| `references/testing-api-authentication-weaknesses.md` | `testing-api-authentication-weaknesses` | Auth weaknesses |
| `references/testing-api-for-mass-assignment-vulnerability.md` | `testing-api-for-mass-assignment-vulnerability` | Mass assignment testing |
| `references/testing-api-security-with-owasp-top-10.md` | `testing-api-security-with-owasp-top-10` | OWASP API Top 10 |
| `references/testing-for-sensitive-data-exposure.md` | `testing-for-sensitive-data-exposure` | Sensitive data exposure |
| `references/testing-websocket-api-security.md` | `testing-websocket-api-security` | WebSocket API security |

| `references/api-authorization.md` | `api-authorization` | API authorization (BOLA/BFLA/BOPLA/business flow) |
| `references/api-idor-bola.md` | `api-idor-bola` | IDOR/BOLA testing |
| `references/api-bfla.md` | `api-bfla` | Broken function-level authorization |
| `references/api-business-flow-abuse.md` | `api-business-flow-abuse` | Business-flow abuse |
| `references/api-scripts.md` | `api-scripts` | Promoted script inventory and usage |
| `references/nested-api-references.md` | `nested-api-references` | Preserved nested API references |

Original sub-skills remain intact under `api-authorization/`, `graphql/`, `grpc/`, `rest/`, and `websocket/`.

## 19. Testing and mastery

- Validate with the capability tests in `tests/test_api_capability.py`.
- Confirm all referenced files resolve and are non-empty.
- Confirm migration map paths/hashes/status are accurate.
- Practice on authorized labs: PortSwigger API testing, OWASP crAPI, vAPI, and DVGA.
- Mastery criteria: independently discover, validate, and report an API finding with full reproduction and impact.

---

Original sub-skills remain intact for reversibility. See `migration_map.json`.


## Knowledge sources

- WKS bug classes: api_trust, authz, graphql, idor, mass_assign
- Domain knowledge: api_trust, authz, graphql, idor, mass_assign
- WKS remains the structured source of truth; retrieve and validate items through WKS rather than duplicating the full corpus in this skill.
- Research and learning material is mapped in `stage-a/knowledge-source-map.json` and must be validated before promotion.
