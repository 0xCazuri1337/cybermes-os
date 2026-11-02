---
name: cache-poisoning
description: "Canonical cache-poisoning capability consolidating 4 sub-skills: hunt-cache-poison, performing-web-cache-deception-attack, performing-web-cache-poisoning-attack, webcache-hunter. Use when hunting or validating cache-poisoning, web cache deception, CDN cache-key misconfiguration, or cache-based DoS/XSS/ATO."
sources: consolidated
---

# CACHE-POISONING — Canonical Capability

## 1. Identity and purpose

This is the single primary executable capability for web cache poisoning and web cache deception testing across CDN, reverse-proxy, and origin caching layers. It consolidates 4 previously separate sub-skills (`hunt-cache-poison`, `performing-web-cache-deception-attack`, `performing-web-cache-poisoning-attack`, `webcache-hunter`) into one operational entry point while preserving all source content in `references/` and the original sub-skill directories for rollback.

Primary objectives:
- Map cache infrastructure, cache keys, and unkeyed inputs (headers, parameters, paths).
- Validate cache poisoning (attacker-controlled cached response served to victims) and cache deception (victim's private response cached and served to attacker).
- Confirm exploitability with a separate client/IP and measure blast radius (edge/region/server) and TTL exposure window.
- Produce reproducible, impact-rated findings with remediation guidance.
- Chain into XSS/ATO/DoS where impact is demonstrated, never from configuration presence alone.

## 2. Scope

In scope:
- Web cache poisoning via unkeyed headers (X-Forwarded-Host, X-Forwarded-Port, X-HTTP-Method-Override, Origin, etc.), unkeyed query parameters, HTTP parameter pollution, fat GET, Host/port manipulation.
- Web cache deception via path normalization discrepancies, static-extension appending, delimiter confusion, and cache-key manipulation on authenticated endpoints.
- CDN-specific variants: Cloudflare Cache Deception Armor bypass, Akamai hop-by-hop smuggling edge poisoning, Fastly/GCP path-normalization WCD, GCS cache-key bleed.
- Cache-based DoS via poisoned error responses (4xx/5xx) stored under high-traffic asset keys.
- Cache amplification into XSS (poisoned script src) and account takeover (cached tokens/PII).

Out of scope (hand off):
- Host/X-Forwarded-Host injection that reaches app logic (reset-link poisoning, routing SSRF, OAuth issuer) without a cached poisoned response -> `hunt-host-header`.
- HTTP request smuggling as a standalone primitive -> `hunt-http-smuggling` (use here only when smuggling is the delivery mechanism into a cache).
- Pure reflected XSS without a cache store -> `hunt-xss`.
- Non-cache auth/session flaws -> `hunt-auth-bypass` / `hunt-session`.

## 3. Invocation and routing

Use this capability when:
- A target is behind a CDN/reverse proxy (Cloudflare, Fastly, Akamai, Varnish, Nginx proxy_cache, CloudFront) and exposes cache headers.
- You need to test whether unkeyed headers/parameters are reflected and cached.
- You need to test authenticated endpoints for cache deception.
- A finding involves cache-key misconfiguration, path normalization, or cached error responses.

Routing notes:
- Start with `references/hunt-cache-poison.md` for the consolidated hunting methodology, payload banks, disclosed report citations, and chain primitives.
- Use `references/performing-web-cache-poisoning-attack.md` for the step-by-step Burp/Param Miner poisoning workflow and output template.
- Use `references/performing-web-cache-deception-attack.md` for path/delimiter/normalization deception workflows.
- Use `references/webcache-hunter.md` for quick pattern bank, recon checklist, bypass list, triage, and report template.
- Host-header-only injection (no cache store) routes to `hunt-host-header`; smuggling-only routes to `hunt-http-smuggling`.

## 4. Inputs and outputs

Inputs:
- Target base URLs, CDN hostnames, subdomains (`cdn.`, `assets.`, `static.`, `updates.`, `downloads.`), and authenticated endpoints.
- Authentication material (victim session cookies/tokens) for deception tests; two browser sessions (victim + attacker).
- Proxy captures, Burp Suite project, Param Miner extension, curl with precise header control.
- Cache-busting query parameter strategy (`?cb=<random>`) to isolate test requests.

Outputs:
- Confirmed or refuted cache findings with raw request/response proof.
- Cache infrastructure map (provider, headers, TTL, edge scope) and unkeyed input list.
- Reproduction steps, exposure window, blast radius, and remediation guidance.
- False-positive rulings (self-cache only, no cross-client store) with disproof rationale.

## 5. Preconditions and authorization

- Confirm written authorization and scope before testing; include CDN hosts, cacheable paths, and test accounts.
- Cache poisoning affects all users; test with cache-busting parameters first and only poison the real cache with explicit authorization.
- Use only test accounts and non-production data unless explicitly authorized; do not read other users' cached private data beyond proof of control.
- Respect rate limits and CDN fair-use; avoid mass re-poisoning loops without approval.
- Stop at tenant boundaries; document out-of-scope endpoints and hand off rather than exploit.
- Clean up poisoned cache entries (PURGE or wait for TTL) after validation.

## 6. Reconnaissance

Recon steps:
1. Send a baseline GET and inspect response headers for cache signals: `X-Cache`, `X-Cache-Status`, `CF-Cache-Status`, `Age`, `Via`, `X-Served-By`, `Cache-Control`, `Surrogate-Control`, `Vary`.
2. Identify the caching layer (Cloudflare, Fastly, Akamai, Varnish, Nginx proxy_cache, CloudFront) and TTL (`max-age`, `s-maxage`, `Age`).
3. Confirm caching is active: send two identical requests and check that `Age` increments / status flips MISS->HIT.
4. Map cache key components: vary headers one at a time (Host, X-Forwarded-Host, etc.) and query string to determine what is keyed vs unkeyed.
5. Discover candidate unkeyed headers via Param Miner "Guess headers" and the Burp Intruder wordlist (X-Forwarded-Host, X-Host, X-Forwarded-Server, X-HTTP-Host-Override, Forwarded, X-Original-URL, X-Rewrite-URL, X-Forwarded-Scheme, X-Forwarded-Proto, True-Client-IP, Origin, Referer).
6. Identify authenticated/dynamic endpoints served through caches and path patterns with static-looking extensions.
7. Fingerprint framework/origin routing behavior (Rails, Express, normalization) to select deception payloads.
8. Check `Vary` header implementation and whether the CDN strips/ignores it.

See `references/hunt-cache-poison.md` (Attack Surface Signals), `references/performing-web-cache-poisoning-attack.md` (Step 1), `references/performing-web-cache-deception-attack.md` (Step 1), `references/webcache-hunter.md` (Recon Checklist).

## 7. Detection methodology

Core detection flow:
1. Confirm cache is active and identify provider/TTL/edge scope (Reconnaissance).
2. Discover unkeyed inputs: for each candidate header/parameter, send with a unique cache-busting query param and check reflection in body/redirects/CSP/JS src/meta tags.
3. Test unkeyed header reflection safely under throwaway keys (`?cb=<random>`) before touching the real cache.
4. Test Web Cache Deception: append static extensions (`.css`, `.js`, `.jpg`, `.png`, `.ico`, `.svg`, `.woff2`) to authenticated dynamic URLs; check if origin serves dynamic content and cache stores it.
5. Test delimiter/normalization discrepancies: semicolons, encoded slashes, dot segments, case, double-encoding, null bytes, fragments.
6. Test DoS: send headers that trigger 4xx/5xx (malformed Host, invalid X-Forwarded-Host, oversized headers) and check if the error response is cached.
7. Test parameter-based poisoning: UTM params, HTTP parameter pollution, fat GET, query-string normalization differences, port-based Host manipulation.
8. Validate each candidate with a second, independent client (different IP/User-Agent/session, incognito) receiving the poisoned response without poison headers.
9. Measure exposure: TTL, re-poisoning feasibility, edge scope (global/regional/server).
10. Mark as refuted if only the attacker's own browser sees the effect (self-cache) or no cross-client store is demonstrated.

References by phase:
- Hunting methodology and disclosed cases: `references/hunt-cache-poison.md`.
- Poisoning workflow (Param Miner, X-Forwarded-Host, parameter cloaking, cleanup): `references/performing-web-cache-poisoning-attack.md`.
- Deception workflow (path, delimiter, normalization, cache-key manipulation): `references/performing-web-cache-deception-attack.md`.
- Pattern bank, bypasses, triage, report template: `references/webcache-hunter.md`.

## 8. Technique selection

Select techniques by observed behavior:
- Cache headers present but no reflection -> focus on cache deception (path/extension/delimiter) and DoS via error responses.
- Unkeyed header reflected (X-Forwarded-Host etc.) -> cache poisoning with header injection; escalate to XSS if script src/redirect affected.
- Authenticated pages cached under static extensions -> cache deception; extract PII/tokens.
- CDN-specific features (Cloudflare Cache Deception Armor) -> test allowlist gaps (`.avif`, obscure extensions).
- Smuggling available -> test desync into cache poisoning (highest payout variant).
- Origin/CDN normalization disagreement -> path-normalization WCD (Kettle 2024 methodology).
- Origin header -> ACAO reflection cached -> CORS cache poisoning.

See `references/hunt-cache-poison.md` (Bypass Techniques, Real Impact Examples), `references/webcache-hunter.md` (Bypass Techniques, Chaining Playbook).

## 9. Execution steps

1. Establish a baseline request for each candidate URL (method, headers, body, auth); record cache status.
2. Replay with one controlled change at a time (add X-Forwarded-Host, append extension, change port); record status, body, timing, headers.
3. For reflection tests, use a unique canary value and a cache-busting query param so the probe lands on a throwaway key.
4. For deception tests, use two sessions: victim (authenticated) requests the crafted URL, then attacker (unauthenticated) requests the same URL and checks for victim data.
5. For poisoning, send the poison request, then fetch the same URL without poison headers from a different client/IP to confirm the store.
6. Confirm exploitability with a clean reproduction (curl or raw HTTP) and document cache TTL/exposure window.
7. Test cleanup: PURGE or wait for TTL; verify cache returns clean response.
8. Stop and document when a vector is not exploitable, out of scope, or only self-cached.

## 10. Tool usage

- Proxy: Burp Suite (Repeater, Intruder, Comparer, Logger++), mitmproxy.
- Discovery: Param Miner (Guess headers), Web Cache Vulnerability Scanner, ffuf, curl.
- Cache diagnostics: Varnishlog, Cloudflare Analytics, Akamai Pragma headers, CDN-specific debug headers.
- Evidence: saved requests/responses, canary values, screenshots, timing data, cross-client verification.
- Automation: Python requests/httpx, curl loops, ffuf with extension wordlists.

See `references/performing-web-cache-poisoning-attack.md` (Tools & Systems), `references/performing-web-cache-deception-attack.md` (Tools & Systems), `references/webcache-hunter.md` (Automation).

## 11. Payloads and test cases

Representative test cases (adapt to target):
- Cache probe: `curl -s -I URL | grep -i "age\|x-cache\|cf-cache"`.
- Unkeyed X-Forwarded-Host: `curl -s -H "X-Forwarded-Host: evil.attacker.com" "URL?cb=$RANDOM" | grep evil.attacker.com`.
- Web Cache Deception: `curl -s -b "session=VICTIM" "URL/account/profile/x.css"` then fetch unauthenticated.
- DoS via error: `curl -s -H "X-Forwarded-Host: aaaaaaaaaaa.invalid" "URL/js/app.js" -I`.
- Parameter pollution: `curl -s "URL/page?cb=1&param=CANARY_VALUE"`.
- Port manipulation: `curl -s -H "Host: target.com:1337" "URL?cb=$RANDOM"`.
- Delimiter confusion: `URL/account/profile;anything.css`, `URL/account/profile%2Fstatic.css`, `URL/account/profile%00.css`.
- Normalization: `URL/static/../account/profile`, `URL/account/profile/X.CSS`, double-encoded variants.
- Origin header -> ACAO: `curl -H "Origin: evil.example" URL -I` on two consecutive hits.
- Header variants/bypasses: X-Host, X-Forwarded-Server, X-HTTP-Host-Override, Forwarded: host=evil.com, X-Original-URL, case variation, URL encoding.

Full payload banks and disclosed report citations live in `references/hunt-cache-poison.md` and `references/webcache-hunter.md`.

## 12. Evidence

Each finding must include:
- Exact request and response (raw HTTP) for both the poison/deception request and the cross-client verification request.
- Authentication context and sessions used (victim vs attacker).
- Canary values or modified fields and the server-side effect (cached response served to a second client).
- Cache headers proving store: `X-Cache: HIT`, `CF-Cache-Status: HIT`, `Age: <nonzero>`, `Via`.
- TTL/exposure window and edge scope (global/regional/server).
- Impact assessment and affected user scope.
- For chains (XSS/ATO/DoS): proof of execution or data access, not reflection alone.

## 13. Reproduction and validation

- Reproduce with curl or a saved raw request in a clean session/incognito.
- Validate with a second client (different IP/User-Agent) without poison headers; confirm it receives the poisoned response.
- Confirm persistence for the full TTL window; document re-poisoning feasibility.
- For deception, confirm victim data is served to an unauthenticated requester from a different session.
- For DoS, confirm legitimate requests return the cached error after the poison request.
- Mark as refuted if the effect is only visible to the original requester (self-cache) or cannot be reproduced cross-client.

## 14. False-positive rejection

Reject or downgrade when:
- The injected value is reflected but the response is not actually cached (no HIT/Age on a second request).
- Only the attacker's own browser/session sees the effect (self-cache / browser cache, not shared cache).
- A path returns dynamic content but the cache does not store it (no Cache-Control public / no HIT).
- An authenticated endpoint returns 401/403/404 without data leakage or cache store.
- Response differences are due to localization, A/B testing, or benign metadata rather than cache poisoning.
- The CDN respects `Cache-Control: private`/`no-store` and excludes the endpoint from caching.
- A header is echoed but not used in response generation or cache key.
- Cache deception shows only the attacker's own data, not another user's.

## 15. Impact

Impact guidance:
- Critical: mass XSS via poisoned CDN asset affecting all visitors; site-wide DoS on high-traffic assets; global account takeover via cached tokens/PII; region-wide edge poisoning with smuggling.
- High: account takeover via cache deception exposing session tokens/PII; persistent defacement; cross-tenant cache bleed.
- Medium: single-user information leakage; limited asset poisoning; affiliate link hijacking.
- Low: temporary cache-based defacement; non-sensitive information leakage; minor cache misconfiguration without exploit path.

Always tie impact to business risk, affected user count, and exposure window; avoid severity inflation from configuration presence or reflection alone.

## 16. Reporting

Report template:
- Summary: endpoint/asset, vulnerability type (poisoning vs deception), mechanism, impact.
- Scope/authorization: test accounts, test window, cleanup performed.
- Steps to reproduce: numbered, minimal, including poison request and cross-client verification.
- Proof of concept: raw requests/responses, cache headers, canary values.
- Impact: business and data scope, affected user count, exposure window, blast radius.
- Remediation: include unkeyed headers in cache key via Vary; do not reflect unkeyed headers; normalize paths consistently between cache and origin; respect Cache-Control: no-store/private; strip unknown headers at edge; use hardcoded base URLs; exclude error responses from caching.
- References: relevant OWASP category and disclosed report citations.

## 17. Failure modes

- Cache not detected -> expand recon, check alternate hosts/content types, inspect full response headers including Via.
- No reflection under unkeyed headers -> try header variants, case variation, encoding, Param Miner full wordlist, or hand off to `hunt-host-header`.
- CDN blocks poison headers at edge -> try smuggling delivery (`hunt-http-smuggling`), HTTP/2 pseudo-header manipulation, or less-common header variants.
- Deception not cached -> test more extensions/delimiters/normalization variants; check CDN cache rules and whether origin rejects unknown paths.
- Cross-client verification fails -> re-check cache key, TTL, edge routing/PoP; the effect may be self-cache only (refute).
- Rate limiting/CDN fair-use stops testing -> coordinate throttling, use allowed test windows, or hand off.
- Inconclusive result -> repeat with fresh keys and diff responses; mark as not confirmed if ambiguous.

## 18. References

All 4 sub-skill references are preserved and must resolve:

| Reference | Sub-capability | Load when |
|---|---|---|
| `references/hunt-cache-poison.md` | `hunt-cache-poison` | Hunting methodology, payloads, disclosed cases, chains |
| `references/performing-web-cache-deception-attack.md` | `performing-web-cache-deception-attack` | Path/delimiter/normalization deception workflow |
| `references/performing-web-cache-poisoning-attack.md` | `performing-web-cache-poisoning-attack` | Burp/Param Miner poisoning workflow |
| `references/webcache-hunter.md` | `webcache-hunter` | Pattern bank, recon, bypasses, triage, report template |

Original sub-skills remain intact under `hunt-cache-poison/`, `performing-web-cache-deception-attack/`, `performing-web-cache-poisoning-attack/`, and `webcache-hunter/`.

## 19. Testing and mastery

- Validate with the capability tests in `tests/test_cache_poisoning_capability.py`.
- Confirm all referenced files resolve and are non-empty.
- Confirm migration map paths/hashes/status are accurate.
- Practice on authorized labs: PortSwigger Web Cache Poisoning labs, Cloudflare/Akamai test tenants, OWASP Juice Shop behind a cache.
- Mastery criteria: independently discover, validate (cross-client), and report a cache poisoning or deception finding with full reproduction, exposure window, blast radius, and impact.

---

Original sub-skills remain intact for reversibility. See `migration_map.json`.


## Knowledge sources

- WKS bug classes: cache_poisoning, cache_deception
- Domain knowledge: cache_poisoning, cache_deception
- WKS remains the structured source of truth; retrieve and validate items through WKS rather than duplicating the full corpus in this skill.
- Research and learning material is mapped in `stage-a/knowledge-source-map.json` and must be validated before promotion.
