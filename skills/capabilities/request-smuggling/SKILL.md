---
name: request-smuggling
description: "Canonical request-smuggling capability: HTTP request smuggling (CL.TE, TE.CL, TE.TE, H2.CL, H2.TE desync) and HTTP Parameter Pollution (HPP) for WAF/validation bypass. Consolidates 3 sub-skills: exploiting-http-request-smuggling, hunt-http-smuggling, performing-http-parameter-pollution-attack. Use when hunting or validating request-smuggling/HPP vulnerabilities."
sources: consolidated
report_count: 12
---

# REQUEST-SMUGGLING — Canonical Capability

## 1. Identity and purpose

This is the single primary executable capability for HTTP request smuggling and HTTP Parameter Pollution (HPP) testing. It consolidates 3 previously separate sub-skills into one operational entry point while preserving all source content in `references/` and the original sub-skill directories for rollback.

Primary objectives:
- Detect desync between front-end proxy/CDN and back-end server caused by Content-Length vs Transfer-Encoding parsing discrepancies (CL.TE, TE.CL, TE.TE, H2.CL, H2.TE).
- Prove exploitation: front-end access-control bypass, request capture/credential theft, cache poisoning, XSS escalation.
- Assess HTTP Parameter Pollution: duplicate-parameter parsing inconsistencies across stacks for WAF/validation bypass, payment/OAuth manipulation.
- Produce reproducible, impact-rated findings with remediation guidance.

## 2. Scope

In scope:
- HTTP request smuggling on multi-tier architectures behind a reverse proxy, load balancer, or CDN.
- CL.TE, TE.CL, TE.TE, H2.CL (HTTP/2 downgrade), H2.TE, HTTP/2 header injection/tunneling.
- Time-delay detection, differential-response detection, automated scanning (smuggler.py, Burp HTTP Request Smuggler, h2csmuggler).
- Impact chains: admin/access-control bypass, cross-user request capture and credential harvesting, cache poisoning, reflected XSS escalation, AJP cross-protocol desync.
- HTTP Parameter Pollution: server-side and client-side HPP, WAF bypass via split payloads, OAuth redirect_uri duplication, payment amount manipulation, header pollution.
- Target suitability fingerprinting (RFC 9112 strict front-ends vs legacy/vulnerable proxies).

Out of scope (hand off):
- Pure cache poisoning without a smuggling primitive -> `hunt-cache-poison`.
- Pure authentication/authorization bypass without smuggling -> `hunt-auth-bypass` / `hunt-idor`.
- Pure XSS discovery without smuggling -> `xss` capability.
- Subdomain takeover of trusted origins -> `hunt-subdomain`.
- Account takeover via stolen credentials -> `hunt-ato`.
- OAuth misconfiguration beyond HPP -> `hunt-oauth`.

## 3. Invocation and routing

Use this capability when:
- The application sits behind a reverse proxy, load balancer, CDN, or WAF.
- You observe `Server`/`Via`/`X-Served-By`/`CF-Ray` headers or multi-tier architecture.
- You need to test whether front-end and back-end disagree on request boundaries.
- You are testing WAF/input-validation bypass via duplicate HTTP parameters.
- You are assessing OAuth/payment flows for parameter manipulation.
- You are targeting H1 paid programs running CDN+origin stacks.

Routing notes:
- Start with `references/hunt-http-smuggling.md` for hunting methodology, target-suitability matrix, modern H2.CL/H2.TE vectors, and chains.
- Use `references/exploiting-http-request-smuggling.md` for step-by-step CL.TE/TE.CL/TE.TE/H2 testing, Burp procedures, payloads, and reporting template.
- Use `references/performing-http-parameter-pollution-attack.md` for HPP methodology, server parsing behaviors, and automation.
- Chain to `hunt-cache-poison`, `hunt-auth-bypass`, `hunt-idor`, `hunt-xss`, `hunt-ato`, `hunt-oauth` as applicable.

## 4. Inputs and outputs

Inputs:
- Target base URLs, endpoints, and request templates.
- Knowledge or fingerprint of the proxy/server chain (front-end and back-end).
- Session cookies / authentication material for impact demonstration.
- Optional: Burp Suite Professional (Repeater, Turbo Intruder), HTTP Request Smuggler extension, smuggler.py, h2csmuggler, param-miner, attacker-controlled origin/host, OOB endpoint.

Outputs:
- Confirmed or refuted smuggling/HPP findings with request/response proof.
- Architecture and proxy fingerprint notes.
- Detection results (time-delay / differential-response / tool output).
- Impact demonstration (admin bypass, request capture, cache poisoning, XSS, credential harvest, payment/OAuth manipulation).
- Reproduction steps, impact assessment, and remediation guidance.
- False-positive rulings with disproof rationale.

## 5. Preconditions and authorization

- Confirm written authorization explicitly covering request smuggling (high-risk test) and HPP; smuggling can affect other users' requests.
- Use only test accounts and non-production data unless explicitly authorized.
- Respect rate limits; coordinate test windows; avoid destructive operations on shared resources.
- Do not capture or store other users' real credentials beyond proof of control; disclose immediately.
- Document any out-of-scope endpoint discovered and hand off rather than exploit.
- Caution: request smuggling can affect other users' requests; test carefully on shared infrastructure.

## 6. Reconnaissance

Recon steps:
1. Fingerprint the front-end proxy/CDN and back-end: `curl -sI https://target/` and grep `Server`, `Via`, `X-Served-By`, `X-Cache`, `CF-Ray`, `X-Amz`, `X-Varnish`.
2. Determine HTTP version support (`--http1.1`, `--http2`) and whether Transfer-Encoding is accepted.
3. Map common architectures: Cloudflare→Nginx→App, AWS ALB→Apache→App, HAProxy→Gunicorn, Nginx→Node.js, Akamai→IIS.
4. Identify endpoints, API versions, paths (`/admin`, `/internal`, `/api/*`), content types, auth mechanisms.
5. For HPP: identify server technology (Apache/PHP, IIS/ASP.NET, Tomcat/JSP, Node.js/Express, Python/Flask) to predict duplicate-parameter handling.
6. Check for HTTP/2 downgrade (front-end accepts H2, forwards H1.1 to origin).
7. Harvest JS bundles and API specs for endpoints and parameter names.

See `references/hunt-http-smuggling.md` (Target-Suitability Matrix, Operator fingerprint quick-check) and `references/performing-http-parameter-pollution-attack.md` (Step 1).

## 7. Detection methodology

Core detection flow (smuggling):
1. Fingerprint front-end; if Nginx≥1.21/Caddy/Envoy, classic CL.TE/TE.CL likely dead — pivot to H2.CL/H2.TE or legacy upstream proxies.
2. Test CL.TE: send both `Content-Length` and `Transfer-Encoding: chunked`; front-end uses CL, back-end uses TE. Use time-delay probe (incomplete chunk -> ~5-10s delay).
3. Test TE.CL: front-end uses TE, back-end uses CL. Use differential-response probe.
4. Test TE.TE: both use TE but parse obfuscated TE headers differently (space-before-colon, casing, etc.).
5. Test H2.CL / H2.TE: HTTP/2 front-end downgrading to HTTP/1.1 back-end; requires HTTP/2-capable tooling (Burp Pro, h2csmuggler).
6. Test HTTP/2 header injection / tunneling (CRLF in header values, CONNECT).
7. Run automated detection: smuggler.py, Burp HTTP Request Smuggler extension, h2csmuggler; Turbo Intruder for time-sensitive tests.
8. Confirm with time-delay technique on a request issued by a different client/session (not your own follow-up).

HPP detection flow:
1. Identify parameter handling behavior by sending duplicate parameters (`?q=first&q=second`) and observing which value is used.
2. Test POST body duplicates and header duplicates.
3. Attempt WAF bypass by splitting payloads across duplicates.
4. Test OAuth redirect_uri and payment amount manipulation via duplicates.
5. Automate with Burp Intruder/param-miner, OWASP ZAP, Arjun, ffuf.

References by phase:
- Hunting: `references/hunt-http-smuggling.md`.
- Exploitation: `references/exploiting-http-request-smuggling.md`.
- HPP: `references/performing-http-parameter-pollution-attack.md`.

## 8. Technique selection

Select techniques by observed behavior:
- Hardened front-end (Nginx≥1.21/Caddy/Envoy) -> pivot to H2.CL/H2.TE or hunt legacy upstream proxies; run a single quick `space-before-colon` probe first.
- Legacy/vulnerable proxy (HAProxy≤2.4, older F5, Citrix ADC, Squid 3.x, Apache Traffic Server, custom Python/Go proxies) -> run full CL.TE/TE.CL/TE.TE matrix.
- CDN-fronted target -> use HTTP/2-aware tools; avoid HTTP/1.1-only clients against H2 front-ends.
- Need impact without per-victim interaction -> use collector gadget (smuggle request to a handler that echoes full request headers).
- Cache present -> chain smuggling + cache poisoning for stored XSS at scale.
- Internal admin paths blocked at front-end -> smuggle internal-routed request.
- WAF blocks individual parameter -> HPP split payload across duplicate parameters.
- OAuth/payment flow -> duplicate redirect_uri / price / amount parameters.
- Custom/unknown proxy -> run full matrix including obfuscated TE variants.

## 9. Execution steps

1. Establish target architecture fingerprint and HTTP version support.
2. For each candidate vector, send one controlled request change at a time; record status, headers, body, timing.
3. Disable auto Content-Length in Burp Repeater when crafting manual CL/TE requests.
4. Use time-delay probes first (low risk) to confirm parsing disagreement.
5. Confirm exploitation with a request issued by a different client/session (Pre-Severity Gate).
6. For H2 vectors, use HTTP/2-capable tooling only.
7. For HPP, test duplicate parameters across query string, body, and headers; record server precedence behavior.
8. Validate each candidate with a second independent request/account; mark refuted if not proven.
9. Stop and document when a vector is not exploitable or out of scope.

## 10. Tool usage

- Proxy: Burp Suite Professional (Repeater with auto Content-Length disabled, Intruder, Turbo Intruder, Comparer, Logger++).
- Extensions: HTTP Request Smuggler (James Kettle), param-miner.
- Scanners: smuggler.py, h2csmuggler, OWASP ZAP, nuclei smuggling templates.
- Clients: curl with precise byte control, httpx, Python requests.
- HPP discovery: Arjun, ffuf, Wfuzz.
- Evidence: saved raw requests/responses, timing captures, screenshots, OOB/canary interactions.

See `references/exploiting-http-request-smuggling.md` (Tools & Systems) and `references/performing-http-parameter-pollution-attack.md` (Tools & Systems).

## 11. Payloads and test cases

Representative smuggling payloads (adapt to target):

CL.TE:
```
POST / HTTP/1.1
Host: target.example.com
Content-Length: 13
Transfer-Encoding: chunked

0

SMUGGLED
```

CL.TE time-delay probe:
```
POST / HTTP/1.1
Host: target.example.com
Content-Length: 4
Transfer-Encoding: chunked

1
A
X
```

TE.CL:
```
POST / HTTP/1.1
Host: target.example.com
Content-Length: 3
Transfer-Encoding: chunked

8
SMUGGLED
0


```

Admin bypass (CL.TE):
```
POST / HTTP/1.1
Host: target.example.com
Content-Length: 56
Transfer-Encoding: chunked

0

GET /admin HTTP/1.1
Host: target.example.com
Foo: x
```

Request capture (CL.TE):
```
POST / HTTP/1.1
Host: target.example.com
Content-Length: 130
Transfer-Encoding: chunked

0

POST /api/comments HTTP/1.1
Host: target.example.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 400

body=
```

TE.TE obfuscation examples: `Transfer-Encoding: xchunked`, `Transfer-Encoding : chunked`, `Transfer-Encoding: chunked, identity`, casing variants, space-before-colon.

H2.CL / H2.TE: craft via Burp HTTP/2 or h2csmuggler; avoid HTTP/1.1-only clients against H2 front-ends.

HPP test cases:
- Duplicate query param: `?q=first&q=second` to determine first/last/array/concat precedence.
- Split payload: `?id=1%20OR&id=1%3D1`.
- POST body: `amount=100&amount=1`.
- OAuth: `redirect_uri=https://legit.com/callback&redirect_uri=https://evil.com/steal`.
- Payment: `price=99.99&currency=USD&price=0.01`.
- Header pollution: duplicate `X-Forwarded-For`.

Framework and variant details live in the corresponding references.

## 12. Evidence

Each finding must include:
- Exact request and response (raw HTTP or proxy capture), including both CL and TE headers.
- Architecture fingerprint (front-end/back-end/protocol).
- Detection method (time-delay duration, differential response, tool output).
- For exploitation: proof of effect on a different client/session (admin access, captured request/cookie, cache entry, XSS delivery).
- For HPP: parameter handling matrix, tested technology, precedence observed, impact demonstration.
- Authentication context and account/role used.
- Impact assessment and affected data scope.

## 13. Reproduction and validation

- Reproduce with a minimal raw request in Burp Repeater (auto Content-Length disabled) or a scripted client with precise byte control.
- Validate smuggling effect on a request issued by a different client/session, not your own follow-up (Pre-Severity Gate).
- For time-delay, confirm consistent delay across multiple trials and absence on non-vulnerable endpoints.
- For H2, reproduce with HTTP/2-capable tooling and confirm front-end speaks H2.
- For HPP, reproduce with curl/Python and confirm precedence and impact.
- Mark as refuted if timing is inconsistent, effect only on own session, or no exploitation demonstrated.

## 14. False-positive rejection

Reject or downgrade when:
- Timing delta occurs only in your own browser/session (parser disagreement, not exploitable smuggling).
- Front-end is RFC 9112 strict (Nginx≥1.21/Caddy/Envoy) and rejects CL+TE with 400; classic CL.TE/TE.CL not viable.
- No effect on a different client/session; cannot demonstrate cross-user impact.
- H2 tooling used against an HTTP/1.1-only front-end (wrong protocol).
- HPP duplicate parameter is ignored server-side or has no security impact.
- Response differences due to caching, localization, or benign metadata.
- Framework defaults or dev-only routes not reachable in production.
- Automated scanner reports without manual confirmation.

## 15. Impact

Impact guidance:
- Critical: request smuggling enabling cross-user credential theft at scale (collector gadget), cache poisoning with stored XSS affecting all users, or admin/access-control bypass on sensitive systems.
- High: smuggling reaching internal/admin endpoints; HPP enabling payment amount manipulation or OAuth code theft.
- Medium: smuggling with limited cross-user impact; HPP WAF bypass leading to injection; cache poisoning without XSS.
- Low: parsing discrepancy confirmed but no exploitable impact; HPP information disclosure.
- Informational: RFC ambiguity without demonstrable desync.

Always tie impact to business risk and data scope; avoid severity inflation from parser disagreement alone.

## 16. Reporting

Report template:
- Summary: vulnerability type (CL.TE/TE.CL/TE.TE/H2.CL/H2.TE/HPP), endpoint, impact.
- Architecture: front-end, back-end, protocol, HTTP versions.
- Preconditions/authorization: test window, accounts.
- Steps to reproduce: numbered, minimal, with raw request (byte-precise).
- Proof of concept: timing captures, cross-user effect, cache entry, credential harvest, or HPP impact.
- Target suitability / fingerprint notes.
- Impact: business and data scope, affected users.
- Remediation: consistent HTTP parsing (reject ambiguous requests with both CL and TE), normalize at front-end, end-to-end HTTP/2, upgrade proxies, strict parameter validation rejecting duplicates, first-occurrence-wins, WAF duplicate detection.

## 17. Failure modes

- Surface not fully discovered -> expand recon, check mobile/SPA, versions, content types, HTTP/2 support.
- No test account -> request credentials or scope clarification; do not exploit without authorization.
- WAF/gateway blocks payloads -> try content-type confusion, encoding, version downgrade, or parser differentials; pivot to HPP split payloads.
- Rate limiting stops testing -> coordinate throttling, use allowed test windows, or hand off.
- Hardened front-end kills classic vectors -> pivot to H2.CL/H2.TE or legacy upstream.
- Automated scanner false positives -> manually confirm with time-delay and cross-user proof.
- HPP precedence unclear -> test all stacks systematically and record responses.
- Inconclusive result -> repeat with fresh sessions and diff responses; mark as not confirmed if ambiguous.

## 18. References

All 3 sub-skill references are preserved and must resolve:

| Reference | Sub-capability | Load when |
|---|---|---|
| `references/exploiting-http-request-smuggling.md` | `exploiting-http-request-smuggling` | Step-by-step CL.TE/TE.CL/TE.TE/H2 testing, Burp procedures, payloads, reporting |
| `references/hunt-http-smuggling.md` | `hunt-http-smuggling` | Hunting methodology, target-suitability matrix, modern vectors, chains |
| `references/performing-http-parameter-pollution-attack.md` | `performing-http-parameter-pollution-attack` | HPP methodology, server parsing behaviors, automation |

Original sub-skills remain intact under `exploiting-http-request-smuggling/`, `hunt-http-smuggling/`, and `performing-http-parameter-pollution-attack/`.

## 19. Testing and mastery

- Validate with the capability tests in `tests/test_request_smuggling_capability.py`.
- Confirm all referenced files resolve and are non-empty.
- Confirm migration map paths/hashes/status are accurate.
- Practice on authorized labs: PortSwigger HTTP request smuggling labs, HTTP/2 smuggling labs, HPP challenges.
- Mastery criteria: independently fingerprint architecture, detect desync, prove cross-user impact (or HPP impact), and report with full reproduction, impact, and remediation.


## Knowledge sources

- WKS bug classes: smuggling
- Domain knowledge: smuggling
- WKS remains the structured source of truth; retrieve and validate items through WKS rather than duplicating the full corpus in this skill.
- Research and learning material is mapped in `stage-a/knowledge-source-map.json` and must be validated before promotion.
