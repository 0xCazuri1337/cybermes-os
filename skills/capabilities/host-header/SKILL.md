---
name: host-header
description: "Canonical host-header capability: Host Header Injection hunting and validation — password reset poisoning, cache poisoning, SSRF/routing, path-override ACL bypass, OAuth/OIDC poisoning, virtual host enumeration. Consolidates 2 sub-skills. Use when hunting or validating host-header-related vulnerabilities."
sources: consolidated
---

# HOST-HEADER — Canonical Capability

## 1. Identity and purpose

This is the single primary executable capability for Host Header Injection security testing across web applications, reverse proxies, CDNs, and OAuth/OIDC endpoints. It consolidates 2 previously separate sub-skills (`hunt-host-header`, `testing-for-host-header-injection`) into one operational entry point while preserving all source content in `references/` and the original sub-skill directories for rollback.

Primary objectives:
- Detect and validate Host header injection: password reset poisoning → ATO, web cache poisoning via unkeyed Host/X-Forwarded-Host, routing-based SSRF, path-override SSRF/ACL bypass, OAuth/OIDC poisoning, virtual host routing manipulation.
- Distinguish two distinct SSRF mechanisms (routing vs path-override) and never conflate them.
- Produce reproducible, impact-rated findings with remediation guidance.

## 2. Scope

In scope:
- Host header and alternative host headers (`X-Forwarded-Host`, `X-Host`, `X-Forwarded-Server`, `X-HTTP-Host-Override`, `Forwarded`, `X-Original-URL`, `X-Rewrite-URL`, `X-Override-URL`).
- Password reset / forgot-password / email-verification / invite endpoints.
- CDN/reverse proxy cache poisoning via unkeyed Host.
- Routing-based SSRF (Host steers upstream) and path-override ACL bypass.
- OAuth/OIDC/SAML discovery and authorization endpoint poisoning.
- Virtual host enumeration and routing manipulation.
- Connection-state / HTTP-reuse attacks are NOT tested here; differential Host handling on a reused connection is a request-smuggling concern (see request-smuggling capability).

Out of scope (hand off):
- Pure HTML reflection without script execution -> `hunt-html-injection` (escalate to XSS once execution is possible).
- Generic SQLi/SSRF/XXE reached through non-Host parameters -> their own capabilities.
- Infrastructure-only findings without a Host header exploit path -> cloud/network capabilities.

## 3. Invocation and routing

Use this capability when:
- A target has password reset, email verification, invite, or absolute-URL-in-email features.
- The app sits behind a CDN/reverse proxy (Cloudflare, Varnish, Fastly, Akamai, Nginx, HAProxy).
- OAuth/OIDC endpoints or `/.well-known/openid-configuration` exist.
- You need to test virtual host routing, host reflection, or SSRF via Host.
- A finding involves unkeyed Host headers, routing-based SSRF, or path override.

Routing notes:
- Password reset / ATO paths -> Phase 1 methodology in `references/hunt-host-header.md`.
- Cache poisoning -> Phase 2 and `references/testing-for-host-header-injection.md`.
- SSRF -> Phase 3 (3A routing, 3B path-override) separately.
- OAuth/OIDC -> Phase 4.
- Header fuzzing / Param Miner -> Phase 5.
- General validation workflow -> `references/testing-for-host-header-injection.md`.

## 4. Inputs and outputs

Inputs:
- Target base URLs, OAuth/OIDC endpoints, password reset URLs.
- Test accounts (your own) and an attacker-controlled domain / Burp Collaborator / interact.sh.
- Proxy captures, CDN cache headers, wordlists for virtual host enumeration.

Outputs:
- Confirmed or refuted Host header findings with request/response proof.
- OOB capture evidence (Collaborator hits) for token/SSRF proof.
- Cache poisoning proof (clean fetch returns payload).
- Reproduction steps, impact assessment, and remediation guidance.
- False-positive rulings with disproof rationale.

## 5. Preconditions and authorization

- Confirm written authorization and scope before testing; include hosts, CDNs, and test accounts.
- Test only against your own registered test account; never request another user's reset.
- Use an attacker-controlled domain / Collaborator for OOB proof; do not exfiltrate real user tokens.
- Respect rate limits and avoid destructive operations on shared caches.
- Stop at account/tenant boundaries; document out-of-scope endpoints and hand off.

## 6. Reconnaissance

Recon steps:
1. Identify password reset / forgot-password / email-verification / invite endpoints.
2. Fingerprint reverse proxy/CDN (Cloudflare, Varnish, Fastly, Akamai, Nginx, HAProxy) via headers (`Via`, `X-Cache`, `CF-Cache-Status`, `Age`).
3. Check `Vary` header for Host/X-Forwarded-Host keying.
4. Enumerate virtual hosts (`admin`, `staging`, `dev`, `test`, `api`, `internal`, `backend`).
5. Locate OAuth/OIDC discovery docs and authorization endpoints.
6. Find absolute URLs constructed from request Host (set-password links, share links, webhooks).
7. Map dangerous header candidates: `Host`, `X-Forwarded-Host`, `X-Host`, `X-Forwarded-Server`, `X-HTTP-Host-Override`, `Forwarded`, `X-Original-URL`, `X-Rewrite-URL`, `X-Override-URL`.

See `references/hunt-host-header.md` and `references/testing-for-host-header-injection.md`.

## 7. Detection methodology

Core detection flow:
1. Test basic Host header reflection (arbitrary Host, double Host, port injection, absolute URL).
2. Test password reset poisoning with direct Host and forwarding headers; verify reset email link host.
3. Test cache poisoning: reflection + cacheability + unkeyed header; prove with clean fetch.
4. Test SSRF: routing-based (Host steers upstream, path on request line) and path-override (X-Original-URL/X-Rewrite-URL) separately.
5. Test OAuth/OIDC poisoning: redirect_uri/issuer reflection; confirm code/token delivery.
6. Fuzz unkeyed headers (Param Miner / manual sweep).
7. Validate each candidate with independent request and, where possible, second egress IP/account.

References by phase:
- Hunting: `references/hunt-host-header.md`.
- Validation workflow: `references/testing-for-host-header-injection.md`.
- API details: `testing-for-host-header-injection/references/api-reference.md`.

## 8. Technique selection

Select techniques by surface and observed behavior:
- Password reset flow -> Phase 1 (direct Host, X-Forwarded-Host, dual Host, absolute URL, port/userinfo confusion).
- CDN/reverse proxy present -> Phase 2 cache poisoning (reflection + cache key + unkeyed).
- Front-end routes by Host -> Phase 3A routing SSRF (metadata/internal hosts).
- Edge path ACL present (IIS/ASP.NET/Spring) -> Phase 3B path-override.
- OAuth/OIDC endpoints -> Phase 4 (redirect_uri/issuer poisoning).
- Unknown unkeyed headers -> Phase 5 (Param Miner / manual sweep).
- Virtual host routing -> vhost enumeration.

## 9. Execution steps

1. Establish baseline request for each endpoint (method, headers, body, auth).
2. Replay with one controlled change at a time; record status, body, timing, headers.
3. For password reset, inject attacker Host and inspect the reset email link host (own test inbox).
4. For cache poisoning, poison once then fetch clean (no injected header) on same key; confirm payload persists.
5. For routing SSRF, put path on request line and steer Host to metadata/internal host; confirm body or OOB hit.
6. For path-override, keep real Host and send X-Original-URL/X-Rewrite-URL; diff against edge-blocked direct request.
7. For OAuth/OIDC, inject Host into authorize/discovery and confirm code/token delivery to attacker host.
8. For vhost enumeration, compare status/size across candidate hosts.
9. Confirm exploitability with clean reproduction (curl or raw HTTP).
10. Stop and document when a vector is not exploitable or out of scope.

## 10. Tool usage

- Proxy: Burp Suite (Repeater, Intruder, Comparer, Logger++), mitmproxy.
- OOB: Burp Collaborator, interact.sh.
- Fuzzing: Param Miner (Guess headers), ffuf, gobuster vhost, nuclei templates.
- Enumeration: ffuf, gobuster vhost for virtual hosts.
- Automation: curl, Python requests/httpx, openssl s_client for raw HTTP.
- Evidence: saved requests/responses, email captures, OOB hits, cache headers.

See `references/testing-for-host-header-injection.md` (Tools & Systems) and `references/hunt-host-header.md`.

## 11. Payloads and test cases

Representative test cases (adapt to target):

Host header basics:
- `Host: evil.com`
- Double Host: `Host: target.com` + `Host: evil.com`
- Port injection: `Host: target.com:evil.com`, `Host: target.com:@evil.com`
- Absolute URL with different Host.

Password reset poisoning:
- `Host: evil.com` on POST /forgot-password
- `X-Forwarded-Host: evil.com`
- `Host: target.com` + `X-Host: evil.com`
- Dual Host smuggling (second Host)
- `Host: target.com.evil.com` (absolute-URL injection)
- `Host: target.com:1@evil.com` (userinfo confusion)

Cache poisoning:
- `X-Forwarded-Host: canary-<random>.example` reflected in body?
- Poison key then clean fetch returns payload.

Routing SSRF:
- `Host: 169.254.169.254` with path `/latest/meta-data/`
- `Host: metadata.google.internal` with `Metadata-Flavor: Google`
- `Host: 169.254.169.254` with `Metadata: true` (Azure)
- `Host: localhost:6379`, `Host: internal-admin.svc.cluster.local`
- Blind: `Host: <collaborator>` and watch OOB.

Path-override:
- `X-Original-URL: /admin`, `X-Rewrite-URL: /internal/metrics` (real Host stays).

OAuth/OIDC:
- `Host: evil.com` on /oauth/authorize; check redirect_uri/Location.
- `X-Forwarded-Host: evil.com` on /.well-known/openid-configuration; check issuer/endpoints.

Virtual host enumeration:
- `Host: admin.target.com`, `staging`, `dev`, `test`, `api`, `internal`, `backend`, `localhost`.

Header fuzzing:
- Sweep `X-Forwarded-Host`, `X-Host`, `X-Forwarded-Server`, `X-HTTP-Host-Override`, `Forwarded`, `X-Original-URL`, `X-Rewrite-URL`, `X-Override-URL`, `X-Forwarded-Scheme`.

## 12. Evidence

Each finding must include:
- Exact request and response (raw HTTP).
- Authentication context and account used (own test account).
- For password reset: reset email link host / OOB Collaborator hit carrying token.
- For cache poisoning: poison request + clean fetch showing payload; `Vary` and cache status.
- For SSRF: response body from internal target OR OOB DNS/HTTP hit.
- For path-override: status/body diff vs edge-blocked direct request.
- For OAuth/OIDC: code/token delivered to attacker host (captured).
- Impact assessment and affected scope.

## 13. Reproduction and validation

- Reproduce with curl or saved raw request in a clean session.
- Validate cache poisoning from a second machine/fresh egress IP/incognito.
- Validate SSRF with real response body or OOB hit; reflection alone is not SSRF.
- Validate password reset by inspecting your own test inbox email body (some mailers rewrite links).
- Validate OAuth by capturing code/token on Collaborator.
- Mark as refuted if execution/unauthorized access cannot be demonstrated.

## 14. False-positive rejection

Reject or downgrade when:
- Reflected Host is not cached or is keyed (`Vary` includes Host/X-Forwarded-Host).
- `Age: 0` + `MISS` every time (no shared cache) -> demote to self-only/Low.
- Cached-for-you but not cached-for-others (per-edge/per-cookie/per-geo) -> not mass.
- A 200 echoing Host string is not SSRF unless response content came from internal target or Collaborator fired.
- Some mailers rewrite links to fixed `SITE_URL` regardless of Host -> verify email body.
- Reflected ≠ cached; cached-for-you ≠ cached-for-others.
- Routing SSRF and path-override do not compose in one request.
- A Host swap across a reused HTTP/1.1 connection is not Host header injection; route to request-smuggling.
- Framework defaults or dev-only vhosts not reachable in production.

## 15. Impact

Impact guidance:
- Critical: password reset poisoning → ATO for any user; routing SSRF → cloud metadata creds (usable); OAuth code/token theft → ATO.
- High: shared cache poisoning → mass XSS/redirect (shared key proven); path-override → internal/admin reach; routing SSRF → internal service access.
- Medium: reflected Host in uncacheable response; vhost exposes non-sensitive internal panel.
- Low: reflected only, uncacheable, not in email, no internal reach; self-only cache.

Always tie impact to business risk and data scope; avoid severity inflation from configuration presence alone.

## 16. Reporting

Report template:
- Summary: endpoint, vulnerability type, header, impact.
- Scope/authorization: test accounts, test window, attacker domain.
- Steps to reproduce: numbered, minimal.
- Proof of concept: raw request/response or script; email/OOB captures.
- Impact: business and data scope.
- Remediation: validate Host against allowlist; do not derive URLs from Host; configure server to reject unrecognized Host; set absolute URLs in config; key caches on full Host; disable path-override headers at edge.
- References: PortSwigger research, framework docs; cite exact observed behaviour, never unverified CVE/H1 IDs.

## 17. Failure modes

- Surface not fully discovered -> expand recon, check mobile/SPA, versions, content types, vhosts.
- Auth required but no test account -> request credentials or scope clarification; do not bypass without authorization.
- WAF/gateway blocks payloads -> try forwarding headers, encoding, HTTP/2, raw requests via openssl.
- Rate limiting stops testing -> coordinate throttling, use allowed test windows.
- Cache not shared -> demote severity; document.
- Inconclusive authorization/SSRF result -> repeat with fresh sessions; mark not confirmed if ambiguous.
- OOB not firing -> check collaborator domain, DNS, and whether link is actually clicked/previewed.

## 18. References

All 2 sub-skill references are preserved and must resolve:

| Reference | Sub-capability | Load when |
|---|---|---|
| `references/hunt-host-header.md` | `hunt-host-header` | Hunting Host header injection |
| `references/testing-for-host-header-injection.md` | `testing-for-host-header-injection` | Validation workflow and test cases |

Additional preserved material:
- `references/api-reference.md` — API reference for the testing sub-skill (mirrored from the sub-skill).
- `testing-for-host-header-injection/scripts/agent.py` — helper script.

Original sub-skills remain intact under `hunt-host-header/` and `testing-for-host-header-injection/`.

## 19. Testing and mastery

- Validate with the capability tests in `tests/test_host_header_capability.py`.
- Confirm all referenced files resolve and are non-empty.
- Confirm migration map paths/hashes/status are accurate.
- Practice on authorized labs: PortSwigger Host header labs, OWASP crAPI (where applicable).
- Mastery criteria: independently discover, validate, and report a Host header finding (reset poisoning, cache poisoning, or SSRF) with full reproduction and impact.

---

Original sub-skills remain intact for reversibility. See `migration_map.json`.


## Knowledge sources

- WKS bug classes: host_header
- Domain knowledge: host_header
- WKS remains the structured source of truth; retrieve and validate items through WKS rather than duplicating the full corpus in this skill.
- Research and learning material is mapped in `stage-a/knowledge-source-map.json` and must be validated before promotion.
