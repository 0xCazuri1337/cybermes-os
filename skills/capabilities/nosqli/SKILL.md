---
name: nosqli
description: "Canonical NoSQL injection capability: MongoDB operator injection ($ne, $gt, $regex, $exists, $in), $where JavaScript injection, URL/parameter injection, blind regex data extraction, CouchDB/Redis/Elasticsearch abuse, and auth bypass. Consolidates 2 sub-skills: exploiting-nosql-injection-vulnerabilities, hunt-nosqli. Use when hunting or validating NoSQLi-related vulnerabilities."
sources: consolidated
report_count: 14
---

# NOSQLI — Canonical Capability

## 1. Identity and purpose

This is the single primary executable capability for NoSQL injection (NoSQLi) testing across MongoDB, CouchDB, Redis, and Elasticsearch backends. It consolidates 2 previously separate sub-skills into one operational entry point while preserving all source content in `references/` and the original sub-skill directories for rollback.

Primary objectives:
- Discover endpoints that accept JSON bodies or query parameters consumed by a NoSQL backend.
- Prove authentication bypass, data extraction, and JavaScript execution via operator injection.
- Identify $where-enabled JavaScript injection and time-based blind channels.
- Audit Redis/Elasticsearch exposure reachable via SSRF or direct access.
- Produce reproducible, impact-rated findings with remediation guidance.

## 2. Scope

In scope:
- MongoDB operator injection: `$ne`, `$gt`, `$regex`, `$exists`, `$in`, `$nin`, `$lt`, `$lte`, `$gte`.
- $where JavaScript injection (operator-object and string-context breakout).
- URL/parameter array notation (`username[$gt]=`) and form-data injection.
- Boolean/time-based blind data extraction via `$regex`.
- CouchDB, Redis command injection, Elasticsearch script injection.
- Auth bypass, user enumeration, privilege escalation, data dump.
- Automated testing with NoSQLMap/nosqli/Nuclei.

Out of scope (hand off):
- SQL injection on relational backends -> `sqli` capability.
- Server-side request forgery discovery -> `ssrf` capability (chain here for Redis via SSRF).
- Command injection on the host -> `command-injection` capability.
- Pure authentication logic flaws without injection -> `auth`/`identity` capabilities.

## 3. Invocation and routing

Use this capability when:
- The target uses MongoDB/Mongoose, CouchDB, Redis, or Elasticsearch.
- Endpoints accept JSON bodies with username/password or query filters.
- NoSQL error messages appear in responses.
- `X-Powered-By: Express`, mongoose/monk present in JS bundles.
- You are bug-bounty hunting or pentesting NoSQL-backed APIs.

Routing notes:
- Start with `references/hunt-nosqli.md` for hunting methodology, attack-surface signals, and chain tables.
- Use `references/exploiting-nosql-injection-vulnerabilities.md` for exploitation workflow, payloads, tools, and reporting templates.
- Chain to `ssrf` for Redis via SSRF, `sqli` only if a relational backend is involved, and `idor`/`authz` for post-bypass access control.

## 4. Inputs and outputs

Inputs:
- Target base URLs, API endpoints, and request templates.
- Session cookies / authentication material for credentialed tests.
- Sample JSON request bodies and parameter names.
- Optional: Burp Suite project, browser automation, wordlists, OOB endpoint.

Outputs:
- Confirmed or refuted NoSQLi findings with request/response proof.
- Operator-injection matrix (tested operators vs reflected behavior).
- Auth-bypass and data-extraction results.
- $where/JS injection confirmation (time-based oracle).
- Reproduction steps, impact assessment, and remediation guidance.
- False-positive rulings with disproof rationale.

## 5. Preconditions and authorization

- Confirm written authorization and scope before testing; include API hosts and test accounts.
- Use only test accounts and non-production data unless explicitly authorized.
- Respect rate limits and avoid destructive operations (no `flushall`, no data deletion) on shared resources.
- Do not access other users' data beyond proof of control.
- Document any out-of-scope endpoint discovered and hand off rather than exploit.

## 6. Reconnaissance

Recon steps:
1. Collect endpoints from OpenAPI/Swagger, Postman collections, JS bundles, source maps, mobile traffic, and proxy logs; grep for `api`, `login`, `search`, `find`, `query`, `users`.
2. Probe API versions and paths: `/api/`, `/v1/`, `/v2/`, `/internal/`, `/admin/`, plus alternate content types (`.json`).
3. Identify session/auth mechanisms and role/tenant boundaries.
4. Detect NoSQL-backed stacks: MongoDB error messages, mongoose/monk in bundles, Express, CouchDB `/_utils`, Redis port 6379, Elasticsearch `:9200`.
5. Harvest parameter names from JS and HTML forms; test both JSON bodies and URL parameters.
6. Fingerprint framework/gateway to select framework-specific references when applicable.

See `references/hunt-nosqli.md` (Attack Surface Signals) and `references/exploiting-nosql-injection-vulnerabilities.md` (Step 1).

## 7. Detection methodology

Core detection flow:
1. Discover JSON-accepting and query-parameter endpoints; record baseline responses.
2. Test operator injection in JSON bodies (`{"$ne": "invalid"}`) and URL parameters (`username[$ne]=`).
3. Test authentication bypass with `$gt`, `$ne`, `$regex`, `$exists`, `$in`.
4. Test $where JavaScript injection (operator-object and string-context breakout) with time-based oracle.
5. Test boolean/blind data extraction via `$regex` character-by-character.
6. Test CouchDB/Redis/Elasticsearch surfaces when in scope.
7. Validate each candidate with a second independent request/account and mark refuted if not proven.

References by phase:
- Hunting: `references/hunt-nosqli.md`.
- Exploitation: `references/exploiting-nosql-injection-vulnerabilities.md`.

## 8. Technique selection

Select techniques by observed behavior:
- JSON login body -> operator injection auth bypass (`$gt`, `$ne`, `$regex`, `$exists`).
- URL parameters parsed into objects -> array notation injection.
- Search/filter endpoint -> `$where` JS injection and blind `$regex` extraction.
- Error-based signals -> refine operator and database type.
- Time-delay response -> confirm $where JavaScript execution.
- SSRF present -> Redis command injection chain.
- Elasticsearch open -> script injection (pre-5.0).

## 9. Execution steps

1. Establish a baseline request per endpoint (method, headers, body, auth) and record response.
2. Replay with one controlled change at a time (operator variants); record status, headers, body, timing.
3. Use the bypass table to choose the correct bypass when defenses are present; do not guess.
4. Test $where with a time-based oracle (5s delay) to confirm JavaScript execution.
5. Prove auth bypass by obtaining a valid session/token without valid credentials.
6. Confirm data extraction with a controlled, known value.
7. Confirm exploitability with a clean reproduction (request + response + timing).
8. Stop and document when a vector is not exploitable or out of scope.

## 10. Tool usage

- Proxy: Burp Suite (Repeater, Intruder, Comparer, Logger++).
- Scanners: NoSQLMap, nosqli, Nuclei NoSQL templates, OWASP ZAP.
- Discovery: ffuf, httpx, KiteRunner, dirsearch.
- Database clients: MongoDB Shell, redis-cli, CouchDB Fauxton.
- Automation: Python requests/httpx, curl, jq.
- Evidence: saved requests/responses, timing captures, session tokens.

See `references/exploiting-nosql-injection-vulnerabilities.md` (Tools & Systems) and `references/hunt-nosqli.md` (Phase 5).

## 11. Payloads and test cases

Representative test cases (adapt to target):
- Auth bypass: `{"username": {"$gt": ""}, "password": {"$gt": ""}}`.
- Regex wildcard: `{"username": {"$regex": ".*"}, "password": {"$regex": ".*"}}`.
- ne bypass: `{"username": "admin", "password": {"$ne": "wrong"}}`.
- exists: `{"username": {"$exists": true}, "password": {"$exists": true}}`.
- in array: `{"username": {"$in": ["admin","root"]}, "password": {"$ne": "x"}}`.
- URL params: `username[$gt]=&password[$gt]=`.
- $where time oracle: `{"$where": "function(){var d=new Date();while(new Date()-d<5000){}; return true;}"}`.
- String-context breakout: `' || '1'=='1`.
- Blind regex: `{"username": "admin", "password": {"$regex": "^a"}}`.
- Redis via SSRF: `gopher://127.0.0.1:6379/`.

Framework and variant details live in the corresponding references.

## 12. Evidence

Each finding must include:
- Exact request and response (raw HTTP or proxy capture).
- Authentication context and account/role used.
- Operator or payload tested and observed behavior.
- Timing evidence for blind/$where (>=4s consistent delay).
- Session token or data obtained (redacted appropriately).
- Impact assessment and affected data scope.

## 13. Reproduction and validation

- Reproduce with a clean request (curl or Burp) against the target.
- Validate auth bypass by accessing a protected resource with the obtained session.
- Validate blind extraction with a known value and consistent timing.
- Validate $where only if the time oracle is reproducible (>=4s, repeated).
- Mark as refuted if the response does not change or timing is inconsistent.

## 14. False-positive rejection

Reject or downgrade when:
- The endpoint does not actually reach a NoSQL backend (mock/static response).
- Operator keys are stripped/ignored and behavior is unchanged.
- Auth bypass returns a session but no protected resource is accessible.
- Timing differences are due to network jitter, not server-side execution.
- `$where` is disabled or the query uses a different field context.
- Redis/Elasticsearch surface is not reachable or is read-only without impact.
- Response differences are due to caching, localization, or benign metadata.

## 15. Impact

Impact guidance:
- Critical: authentication bypass as admin; $where enabling arbitrary JS/RCE; Redis command injection leading to webshell/RCE.
- High: user collection dump; privilege escalation; Elasticsearch script injection.
- Medium: blind injection with limited data exfiltration; user enumeration.
- Low: information disclosure or error-based fingerprinting without data access.
- Informational: defense bypass observations without exploitable impact.

Always tie impact to business risk and data scope; avoid severity inflation from header/operator presence alone.

## 16. Reporting

Report template:
- Summary: endpoint, vulnerability type, operator/payload, impact.
- Scope/authorization: test window, accounts.
- Steps to reproduce: numbered, minimal; include raw request.
- Proof of concept: request/response, timing, session token (redacted).
- Impact: business and data scope.
- Remediation: parameterized queries with driver sanitization; input type validation (reject objects where strings expected); disable server-side JS ($where); least-privilege DB access; validate/allowlist query operators; secure Redis/Elasticsearch (auth, bind, firewall).

## 17. Failure modes

- Surface not fully discovered -> expand recon, check mobile/SPA, versions, content types.
- No test account -> request credentials or scope clarification; do not bypass without authorization.
- WAF/gateway blocks payloads -> try content-type confusion, encoding, version downgrade, or parser differentials.
- Rate limiting stops testing -> coordinate throttling, use allowed test windows, or hand off.
- Blind oracle noisy -> increase samples, use larger delay, or switch to boolean (response diff).
- Inconclusive authorization/origin result -> repeat with fresh sessions and diff responses; mark as not confirmed if ambiguous.

## 18. References

All 2 sub-skill references are preserved and must resolve:

| Reference | Sub-capability | Load when |
|---|---|---|
| `references/hunt-nosqli.md` | `hunt-nosqli` | Hunting methodology, attack-surface signals, bypass/chain tables |
| `references/exploiting-nosql-injection-vulnerabilities.md` | `exploiting-nosql-injection-vulnerabilities` | Exploitation workflow, payloads, tools, reporting |

Original sub-skills remain intact under `exploiting-nosql-injection-vulnerabilities/` and `hunt-nosqli/`.

## 19. Testing and mastery

- Validate with the capability tests in `tests/test_nosqli_capability.py`.
- Confirm all referenced files resolve and are non-empty.
- Confirm migration map paths/hashes/status are accurate.
- Practice on authorized labs: PortSwigger NoSQL injection labs, OWASP crAPI, HackTheBox.
- Mastery criteria: independently discover, prove, and report a NoSQLi finding with full reproduction, impact, and remediation.


## Knowledge sources

- WKS bug classes: nosql
- Domain knowledge: nosql
- WKS remains the structured source of truth; retrieve and validate items through WKS rather than duplicating the full corpus in this skill.
- Research and learning material is mapped in `stage-a/knowledge-source-map.json` and must be validated before promotion.
