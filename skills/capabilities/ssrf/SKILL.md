---
name: ssrf
description: "Canonical SSRF capability: hunting, validating, and exploiting Server-Side Request Forgery across cloud metadata (AWS/GCP/Azure), internal networks, blind/OOB cases, protocol handlers, filter bypasses, and SSRF-to-RCE chains. Consolidates 4 sub-skills: exploiting-server-side-request-forgery, hunt-ssrf, performing-blind-ssrf-exploitation, performing-ssrf-vulnerability-exploitation. Use when hunting or validating SSRF-related vulnerabilities."
sources: consolidated
report_count: 34
---

# SSRF — Canonical Capability

## 1. Identity and purpose

This is the single primary executable capability for Server-Side Request Forgery (SSRF) security testing. It consolidates 4 previously separate sub-skills (`exploiting-server-side-request-forgery`, `hunt-ssrf`, `performing-blind-ssrf-exploitation`, `performing-ssrf-vulnerability-exploitation`) into one operational entry point while preserving all source content in `references/` and the original sub-skill directories for rollback.

Primary objectives:
- Discover endpoints that cause the server to fetch attacker-controlled URLs (webhooks, URL previews, imports, PDF/image generators, proxies).
- Prove the server actually makes an outbound request (OOB confirmation mandatory for blind cases).
- Determine whether the upstream response body is returned (full-read vs blind).
- Reach cloud instance metadata (AWS/GCP/Azure) and internal services; escalate to credential theft or RCE where authorized.
- Bypass SSRF filters (IP encoding, DNS rebinding, redirects, URL parsing, protocol handlers).
- Produce reproducible, impact-rated findings with remediation guidance.

## 2. Scope

In scope:
- Direct (full-read) SSRF: upstream response body returned to attacker.
- Blind SSRF: OOB-confirmed requests with no body; timing/port differentiation.
- Cloud metadata abuse: AWS IMDSv1/v2, GCP metadata, Azure IMDS, Kubernetes service accounts.
- Internal network scanning/pivoting via SSRF: localhost, RFC1918, link-local, internal hostnames.
- Protocol handlers: `file://`, `gopher://`, `dict://`, `sftp://`, `ldap://`, etc.
- Filter bypasses: IP encoding (decimal/octal/hex/short/IPv6), DNS rebinding, redirect chains, URL parsing confusion, app-layer encoding, path normalization.
- SSRF in headless-browser/PDF-generator contexts (JavaScript execution).
- SSRF chains to internal services: Redis, Elasticsearch, Memcached, Jenkins, internal admin APIs, Kubernetes API.

Out of scope (hand off):
- Pure XSS discovery without SSRF -> `hunt-xss` / `xss` capability.
- OAuth provider-side redirect/state flaws unrelated to SSRF -> `hunt-oauth`.
- Subdomain takeover execution details -> `hunt-subdomain` (chain here once a trusted origin is controlled).
- Cloud IAM privilege escalation after credential theft -> `cloud-iam-deep` / `hunt-cloud-misconfig`.
- RCE exploitation details beyond SSRF primitive -> `hunt-rce`.
- General API authorization (BOLA/IDOR) -> `hunt-idor` / `hunt-authz`.

## 3. Invocation and routing

Use this capability when:
- A target has features that fetch URLs server-side (webhooks, URL previews/unfurling, file import from URL, PDF/screenshot generation, avatar/image fetching, RSS/feed aggregation, OAuth callbacks, API proxies/gateways).
- A parameter accepts a URL/URI/host and the server behaves differently based on it.
- You need to test for cloud metadata access or internal network reachability.
- You are assessing webhook functionality and URL validation implementations.
- A finding involves server-side outbound requests, internal service access, or metadata credential theft.

Routing notes:
- General hunting methodology, OOB gate, disclosed cases -> `references/hunt-ssrf.md`.
- Structured exploitation workflow (identify -> metadata -> internal scan -> bypass -> escalate) -> `references/exploiting-server-side-request-forgery.md`.
- Blind SSRF detection/exploitation (Collaborator, timing, gopher) -> `references/performing-blind-ssrf-exploitation.md`.
- Scripted vulnerability exploitation and reporting -> `references/performing-ssrf-vulnerability-exploitation.md`.
- Chain to `cloud-iam-deep` for credential escalation, `hunt-rce` for Redis/gopher RCE, `hunt-cloud-misconfig` for internal endpoints.

## 4. Inputs and outputs

Inputs:
- Target base URLs, endpoints, and request templates (Burp/Proxy history).
- URL-accepting parameters and headers (url, uri, link, href, src, dest, redirect, callback, webhook, feed, import, image_url, avatar_url, etc.).
- Session cookies / authentication material for credentialed tests.
- Optional: Burp Suite Professional with Collaborator, interactsh, OOB callback domain, VPS/redirect server, SSRFmap, Gopherus, wordlists, cloud provider signals.

Outputs:
- Confirmed or refuted SSRF findings with raw request/response proof or OOB callback evidence.
- Classification as full-read vs blind, plus internal target reached and data returned.
- Origin/parameter attribution (which field is the live sink).
- Internal network map and cloud metadata access results.
- Bypass technique inventory and redirect chain details.
- Reproduction steps, impact assessment, and remediation guidance.
- False-positive rulings with disproof rationale.

## 5. Preconditions and authorization

- Confirm written authorization and scope before testing; include SSRF testing, internal network scanning, and cloud metadata access in scope.
- Use only test accounts and non-production data unless explicitly authorized.
- Respect rate limits and avoid destructive operations on internal services (do not FLUSHALL Redis in production).
- Do not access other users' data beyond proof of control; treat retrieved credentials as sensitive and report, do not use.
- Host PoC/callback infrastructure only on attacker-controlled systems you own.
- Document any out-of-scope endpoint discovered and hand off rather than exploit.
- For cloud metadata, confirm the environment is in scope (authorized pentest of a cloud-hosted app).

## 6. Reconnaissance

Recon steps:
1. Collect endpoints from OpenAPI/Swagger, Postman collections, JS bundles, source maps, mobile traffic, and proxy logs; grep for fetch/proxy/import/preview/webhook/callback.
2. Identify all URL-accepting parameters and headers; use parameter name wordlists (burp-parameter-names) and ffuf.
3. Identify session/auth mechanisms and role/tenant boundaries; note cloud provider signals (AWS/GCP/Azure headers, IMDS hints).
4. Detect SSRF-prone functionality: URL preview/unfurling, webhook config, file import from URL, PDF/screenshot generation, image/avatar fetching, RSS/feed aggregation, OAuth callbacks, API proxy/gateway.
5. Fingerprint framework/gateway and internal IP ranges from error messages, headers, or docs.
6. Harvest internal hostnames/service names from JS, configs, or leaked docs.
7. Check whether the app returns upstream body (full-read) or only status (blind) by fetching a known external URL with a recognizable body.

See `references/hunt-ssrf.md` (Crown Jewel Targets, Attack Surface) and `references/exploiting-server-side-request-forgery.md` (Step 1).

## 7. Detection methodology

Core detection flow:
1. Plant an OOB payload first for every candidate sink (unique Collaborator/interactsh per parameter when attribution matters).
2. Send one request per parameter; poll OOB listener 30-120s.
3. Only after a confirmed callback claim SSRF (OOB-Or-It-Didn't-Happen gate).
4. Determine full-read vs blind by fetching a known external URL with a recognizable body.
5. If full-read, escalate to cloud metadata and internal services.
6. If blind, use timing/port differentiation and gopher payloads for internal interaction.
7. Test filter bypasses when direct payloads are blocked (IP encoding, DNS rebinding, redirects, URL parsing, protocol handlers, app-layer encoding).
8. Attribute the callback to ONE parameter before reporting; run negative controls.
9. Validate each candidate with a second independent request/account and mark refuted if not proven.

References by phase:
- Hunting/OOB gate/disclosed cases: `references/hunt-ssrf.md`.
- Exploitation workflow: `references/exploiting-server-side-request-forgery.md`.
- Blind SSRF: `references/performing-blind-ssrf-exploitation.md`.
- Scripted exploitation/reporting: `references/performing-ssrf-vulnerability-exploitation.md`.

## 8. Technique selection

Select techniques by observed behavior:
- Unknown surface -> endpoint discovery + URL parameter fuzzing + OOB payload planting.
- Callback confirmed, body returned -> full-read SSRF; escalate to metadata/internal endpoints.
- Callback confirmed, no body -> blind SSRF; use timing/port differentiation and internal service interaction.
- Direct payload blocked -> IP-encoding bypass, DNS rebinding, redirect chain, URL parsing confusion, protocol confusion, app-layer encoding, path normalization.
- Cloud-hosted target -> metadata endpoints (AWS/GCP/Azure) and IMDSv1/v2 checks.
- Headless browser/PDF generator -> JavaScript-based SSRF and iframe injection.
- Internal service reached -> gopher payloads for Redis/Memcached, HTTP for Elasticsearch/Jenkins/Kubernetes.
- Echoed URL in error without callback -> NOT SSRF; retract claim (see OOB gate).

## 9. Execution steps

1. Establish baseline request per endpoint/parameter; record response body, status, timing.
2. Plant a unique OOB payload per candidate parameter; send exactly one request per payload.
3. Poll OOB listener; only claim SSRF after a confirmed DNS/HTTP callback.
4. Attribute the callback to the specific parameter; document negative controls.
5. Determine full-read vs blind by fetching a known external URL with a recognizable body.
6. If full-read, test cloud metadata endpoints and internal services; capture returned data.
7. If blind, use timing differences for host/port enumeration and gopher for internal interaction.
8. Test filter bypasses one technique at a time when direct payloads fail; record which succeed.
9. For headless-browser contexts, inject iframe/script payloads targeting metadata or internal services.
10. Confirm exploitability with a clean reproduction (OOB hit reliably, or returned body).
11. Stop and document when a vector is not exploitable or out of scope.

## 10. Tool usage

- Proxy: Burp Suite Professional (Repeater, Collaborator for blind SSRF), OWASP ZAP.
- OOB: Burp Collaborator, interactsh, webhook.site, canarytokens.
- Automation: SSRFmap, Gopherus, ffuf, httpx, curl, Python requests.
- DNS rebinding: rbndr.us, lock.cmpxchg8b.com/rebinder, singularity.
- Scanners (triage only): nuclei SSRF templates, CORScanner (not primary).
- Evidence: screenshots, saved requests/responses, OOB interaction logs, timing data.
- Cloud: AWS/GCP/Azure CLIs for validating retrieved credentials (report only, do not abuse).

See `references/exploiting-server-side-request-forgery.md` (Tools & Systems), `references/hunt-ssrf.md` (Automation), `references/performing-blind-ssrf-exploitation.md` (Tools & Systems).

## 11. Payloads and test cases

Representative test cases (adapt to target):

OOB detection:
- `http://<unique>.oastify.com/` per candidate parameter; poll Collaborator/interactsh.

Cloud metadata:
- AWS IMDSv1: `http://169.254.169.254/latest/meta-data/`, `.../iam/security-credentials/`, `.../user-data`.
- AWS ECS: `http://169.254.170.2${AWS_CONTAINER_CREDENTIALS_RELATIVE_URI}`.
- GCP: `http://metadata.google.internal/computeMetadata/v1/` (often needs `Metadata-Flavor: Google`), `http://metadata/computeMetadata/v1/`.
- Azure: `http://169.254.169.254/metadata/instance?api-version=2021-02-01` (needs `Metadata: true`), `.../metadata/identity/oauth2/token?...`.
- Kubernetes: `file:///var/run/secrets/kubernetes.io/serviceaccount/token`, `http://127.0.0.1:6443/api/v1/secrets`, `http://127.0.0.1:10250/pods`, `http://127.0.0.1:2379/v2/keys`.

Internal services:
- `http://127.0.0.1:6379/` (Redis), `http://127.0.0.1:9200/_cat/indices` (Elasticsearch), `http://127.0.0.1:5601/` (Kibana), `http://127.0.0.1:8500/v1/catalog/services` (Consul), `http://127.0.0.1:8080/script` (Jenkins).

IP-encoding bypasses for 127.0.0.1 / 169.254.169.254:
- IPv6: `http://[::1]/`, `http://[::ffff:127.0.0.1]/`, `http://[::ffff:169.254.169.254]/`.
- Decimal: `http://2130706433/`, octal: `http://0177.0.0.1/`, hex: `http://0x7f000001/`, short: `http://127.1/`, zero: `http://0/`.
- DNS: `http://localtest.me/`, `http://127.0.0.1.nip.io/`, `http://customer.attacker.com/` (A -> internal).
- URL parsing: `http://***@127.0.0.1/`, `http://127.0.0.1#evil.com`, `http://evil.com\\.127.0.0.1/`.
- Protocols: `file:///etc/passwd`, `gopher://127.0.0.1:6379/_INFO`, `dict://127.0.0.1:6379/info`, `sftp://attacker.com:11111/`, `ldap://127.0.0.1/`.

Redirect chain:
- Attacker host returns 301/302 to `http://169.254.169.254/latest/meta-data/`.

App-layer encoding:
- Base64 path: `/proxy/aHR0cDovLzE2OS4yNTQuMTY5LjI1NC8=/x.js`; double URL-encode host.

Path normalization:
- `GET /;/;/resource/md/get/url?url=http://oast.example/`.

DNS rebinding:
- `http://7f000001.c0a80001.rbndr.us/` (alternates IPs).

Timing/port scan (blind):
- Compare response times for `http://127.0.0.1:22/` vs `http://127.0.0.1:12345/`.

Framework and variant details live in the corresponding references.

## 12. Evidence

Each finding must include:
- Exact request and response (raw HTTP) or OOB interaction log (DNS/HTTP callback with timestamp/source IP/User-Agent).
- Authentication context and account/role used.
- Parameter/field attribution (which sink caused the callback), including negative controls.
- Classification: full-read vs blind; body returned or not.
- Internal target reached and data returned (metadata token, internal API response, port differentiation).
- Bypass technique used and why direct payload failed.
- Impact assessment and affected data scope / blast radius.
- For blind cases: timing data or confirmed OOB callback tied to a specific internal address.

## 13. Reproduction and validation

- Reproduce with a fresh, unique OOB payload per parameter; confirm callback reliably (not intermittently).
- Confirm full-read by fetching a known external URL with a recognizable body.
- Validate attribution by testing each candidate parameter in isolation.
- Run negative controls (parameters that produce no callback) and document them.
- Confirm cloud metadata access only in authorized scope; do not retain/use credentials.
- Mark as refuted if no callback across all sinks, or if echoed URL is only string formatting.
- Mark as refuted if timing differences cannot be distinguished from normal variance.

## 14. False-positive rejection

Reject or downgrade when:
- The server echoes your URL in an error message but no OOB callback occurs (string formatting, not a fetch).
- Different status codes for external vs localhost come from validators, not actual fetches.
- Delayed response without a completed HTTP fetch (DNS resolution only).
- Blind SSRF with only a callback and no internal service reached or data returned (low severity; never submit standalone).
- Attribution is ambiguous (batched payloads); retest per-parameter.
- Timing differences are within normal variance or caused by DNS only.
- Filter bypass claim without showing the filter was actually applied and bypassed.
- Cloud metadata not reachable (IMDSv2 enforced, metadata host blocked) -> downgrade to internal scan only.
- Framework defaults or dev-only routes not reachable in production.

## 15. Impact

Impact guidance:
- Critical: SSRF to cloud metadata returning IAM credentials enabling account takeover; SSRF-to-RCE via internal Redis/gopher; full internal admin API access with sensitive data.
- High: full-read SSRF to internal services exposing PII/secrets/API keys; SSRF reaching Kubernetes API secrets.
- Medium: blind SSRF with confirmed internal reach and port differentiation; SSRF to internal services without data exfil; filter bypass demonstrating internal reach.
- Low: blind SSRF with only OOB callback and no internal reach/data; SSRF to public URLs only.
- Informational: suspected SSRF without OOB confirmation; echoed URLs without fetch.

Always tie impact to business risk and blast radius (cloud account, internal data, RCE potential); avoid severity inflation from request-making alone. Apply the Gate 0 validation: what can the attacker do right now, what does the victim lose, reproducible in 10 minutes.

## 16. Reporting

Report template:
- Summary: endpoint, vulnerability type (full-read/blind), parameter attribution, impact.
- Scope/authorization: test account, window, attacker origin/callback domain.
- Steps to reproduce: numbered, minimal; one request per sink.
- Proof: OOB callback log (DNS/HTTP with source IP) or returned body; timing data for blind.
- Internal reach: targets tested, responses, credentials redacted appropriately.
- Bypass details: technique, why direct failed.
- Impact: business and data scope, blast radius, chain potential.
- Remediation: strict URL allowlist; block private/link-local/metadata ranges; disable dangerous schemes (gopher, file, dict, ftp); enforce IMDSv2 (AWS) and `Metadata-Flavor` (GCP) and `Metadata: true` (Azure); validate then fetch with DNS pinning (no TOCTOU); disable redirect following or re-validate redirects; network segmentation/egress proxy; sandbox headless renderers.

## 17. Failure modes

- Surface not fully discovered -> expand recon, check mobile/SPA, versions, content types, hidden params.
- No OOB callback -> retract SSRF claim; check if echoed URL is just formatting; try different schemes/params.
- WAF/gateway blocks payloads -> try content-type confusion, encoding, version downgrade, parser differentials, app-layer encoding.
- Rate limiting stops testing -> coordinate throttling, use allowed test windows, or hand off.
- Attribution ambiguous -> retest per-parameter with fresh payloads.
- Cloud metadata blocked (IMDSv2) -> document as defense; focus on internal services.
- Blind timing inconclusive -> increase samples, use distinct ports, or switch to OOB-only.
- Inconclusive authorization/origin result -> repeat with fresh sessions and diff responses; mark not confirmed if ambiguous.

## 18. References

All 4 sub-skill references are preserved and must resolve:

| Reference | Sub-capability | Load when |
|---|---|---|
| `references/exploiting-server-side-request-forgery.md` | `exploiting-server-side-request-forgery` | Structured exploitation workflow, cloud metadata, internal scanning, bypasses |
| `references/hunt-ssrf.md` | `hunt-ssrf` | Hunting methodology, OOB gate, disclosed cases, bypass techniques |
| `references/performing-blind-ssrf-exploitation.md` | `performing-blind-ssrf-exploitation` | Blind SSRF detection, timing, gopher, exfiltration |
| `references/performing-ssrf-vulnerability-exploitation.md` | `performing-ssrf-vulnerability-exploitation` | Scripted exploitation and reporting |

Original sub-skills remain intact under `exploiting-server-side-request-forgery/`, `hunt-ssrf/`, `performing-blind-ssrf-exploitation/`, and `performing-ssrf-vulnerability-exploitation/`.

## 19. Testing and mastery

- Validate with the capability tests in `tests/test_ssrf_capability.py`.
- Confirm all referenced files resolve and are non-empty.
- Confirm migration map paths/hashes/status are accurate.
- Practice on authorized labs: PortSwigger SSRF labs, OWASP crAPI, cloud metadata labs, blind SSRF challenges.
- Mastery criteria: independently discover, OOB-confirm, attribute, and report an SSRF finding (full-read or blind) with reproduction, impact, and remediation; correctly retract non-findings per the OOB gate.


## Knowledge sources

- WKS bug classes: ssrf
- Domain knowledge: ssrf
- WKS remains the structured source of truth; retrieve and validate items through WKS rather than duplicating the full corpus in this skill.
- Research and learning material is mapped in `stage-a/knowledge-source-map.json` and must be validated before promotion.
