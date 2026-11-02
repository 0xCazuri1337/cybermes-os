# bot-mitigated-spa-recon

Source: `attack-surface/bot-mitigated-spa-recon/SKILL.md` (preserved verbatim during consolidation).

---

---
name: bot-mitigated-spa-recon
description: Recon bot-walled SPAs via browser when curl is blocked.
version: 1.0.0
platforms: [linux, macos, windows]
category: cybersecurity
tags: [bug-bounty, pentest, recon, kasada, akamai, bot-mitigation, spa, idor, waf, nextjs]
triggers:
  - "recon against [target] with bot protection"
  - "target returns 429/503 to curl but loads in browser"
  - "enumerate API behind Kasada/Akamai"
  - "find IDOR on a bot-walled SPA"
  - "hunt [target] that uses Kasada"
---

# Bot-Mitigated SPA Recon

A workflow for security recon against web apps protected by bot-mitigation
(Kasada, Akamai, PerimeterX/HUMAN, Cloudflare Bot Management). The defining
symptom: `curl`/terminal requests get `429`/`503`/`403` while the same page
loads fine in a real browser. That means the JS challenge is solved by the
browser at runtime — so drive recon through a JS-executing browser, not curl.

This is a RECON/HUNTING addendum. Pair it with the `web-pentest` phased
workflow (authorization gate, scope allowlist, no-exploit-no-report). The
bot wall changes *how you reach the surface*, not the rules of engagement.

## Step 0 — Confirm it's a bot wall (not a hard block)

```
curl -sI -A "Mozilla/5.0" https://TARGET/        # note status
# then load the same URL in the browser tool and compare
```

Bot-wall tells: a `429`/`503` on terminal but `200` + full DOM in browser.
Also look for these cookie/header fingerprints in the terminal response:
- **Kasada**: `x-kpsdk-ct`, `x-kpsdk-r`, `x-kpsdk-c`, `KP_UIDz`, `KP_UIDz-ssn`, `akaalb_*`
- **Akamai**: `akamai-request-bc`, `akamai-grn`, `bm_so`/`bm_lso` (Bot Manager)
- **PerimeterX/HUMAN**: `_px`, `pxsid`, `pxvid`
- **Cloudflare**: `cf_clearance`, `__cf_bm`

If the browser also 503s on a *static asset path* (e.g. `/_next/static/...`),
the bot wall is path-based — static bundle analysis is blocked too (see Step 3).

## Step 1 — Do all traffic through the browser

Once the browser tool loads the homepage (Kasada challenge solved in-page),
keep using it for recon. Use `browser_console` with `fetch(...)` calls that
carry `credentials:'include'` so the session cookie travels. Same-origin
`fetch` from the page context is NOT CORS-blocked (unlike cross-origin
terminal/curl). This is the key trick: **mine the live app from inside its own
page context.**

Capture the mandatory program header if required (e.g. `X-Inspectiv-Tester`):
send it on every `fetch` so requests are program-compliant.

## Step 2 — Enumerate the real API surface

The SPA's client bundles are usually bot-gated, so you can't read them. Find
the backend another way:

1. **Server-rendered route maps.** Next.js / SSR pages embed their nav routes
   in the HTML/`__NEXT_DATA__`. Mine the *logged-in* dashboard HTML for
   `/app/account/...` style paths — these reveal the feature surface
   (addresses, orders, wallet, pets, prescriptions, profile, autoship).

2. **Probe for the API gateway.** Modern SPAs front everything through a
   gateway. Brute a short list of gateway path shapes and read the structured
   error bodies — they leak the internal route:
   ```
   /api/v1/account/addresses        -> often 503 (bot wall on /api) or 404
   /api/account/addresses           -> 503/404
   /gateway/account/addresses       -> 401 JSON: {"status":"UNAUTHORIZED",
                                                "path":"/eks/app/chewy-api-gateway/account/addresses",...}
   ```
   The 401 JSON's `path` field tells you the real internal gateway prefix
   (`/eks/app/<service>/...`). Sibling resources (orders, wallet, pets,
   prescriptions, profile, autoship, payment-methods) usually share the prefix.

3. **`__NEXT_DATA__` mining.** For SSR pages, `document.querySelector
   ('#__NEXT_DATA__').textContent` holds server props — grep it for
   `/api/`, `graphql`, `https://<subdomain>.chewy.com/...` to find hosts
   and endpoints the bundle would have hidden.

4. **Internal hostnames leak.** Client JS / loader files often hardcode
   internal infra: `*.svc.cluster.local` (Kubernetes), `*-dev/-qat/-stg`
   env hosts, `demm.dev.chewy.com`. These are info-disclosure notes
   (usually unroutable externally → low severity) — and dev/staging hosts
   are typically OUT OF SCOPE, so don't pivot to them.

## Step 3 — Test session-scoped IDOR on the one readable endpoint

Bot-gated bundles mean you often can't reach object-level APIs. But the app
almost always exposes at least one *session-derived* endpoint (e.g.
`/app/rest/user-context?pageType=home`). Test it as the IDOR control:

```
GET /app/rest/user-context?pageType=home            -> 200 JSON
     userContextData.userId = 980935950  (your real id)
     callerLogonId = you@example.com
# Now tamper the identifier params:
GET ...?userId=980935951
GET ...?callerId=980935951
GET ...?personId=00000000-0000-0000-0000-000000000001
# If userId STILL returns 980935950 -> server derives identity from the
# session, not the param. NOT vulnerable. Record as ruled-out with PoC.
```

This is the decisive IDOR test when you can't reach object APIs: prove the
readable endpoint is session-scoped, then state object-level IDOR was
*not exercised* (not *not vulnerable*) due to bundle inaccessibility.

## Step 4 — Probe WAF/input handling on the readable param

Use the same readable endpoint's free-text param (e.g. `pageType`) as a WAF
probe. Send a battery and read status + whether your payload is reflected:
```
?pageType=<script>alert(1)</script>     -> expect 403 (WAF block), NOT 200-with-reflection
?pageType=../../etc/passwd              -> 403
?pageType=';DROP TABLE x;--            -> 403
?pageType=${jndi:ldap://x}             -> 403
?pageType=                             -> 200 (empty ok)
?pageType=home&extra=1                -> 200 (unknown param ignored)
```
A `403` on all malicious values + no reflection = input validation working.
A `200` that echoes your payload into the response body = reflection bug.

## Step 5 — Capture the auth token (gateway auth)

The gateway 401s because it wants a token the browser derives at runtime.
Look in the page context:
```
document.cookie  -> find a JWT cookie, e.g. ticket=eyJhbGciO...
localStorage / sessionStorage -> keys containing token|auth|kc-|jwt|access
```
Try replaying it: `Authorization: Bearer <ticket>` against the gateway. If it
still 401s, the gateway expects an *internal* service token you can't extract
from the browser — record "gateway auth not replayable from headless context"
as a limitation, not a finding.

## Pitfalls (learned the hard way)

- **Don't claim a finding without reproducible PoC.** A bot wall that returns
  503 to curl is NOT a vulnerability. A leaked `*.svc.cluster.local` hostname
  with no external route is low-sev info-disclosure at best.
- **Headless gateway tokens often won't replay.** Next.js apps may use
  Server Actions (RSC) for form submits — your `fetch`/`XHR` hooks won't
  capture them, and the gateway may reject browser-extracted JWTs. That's an
  environment limit, not a bug. Say so in the report's "Limitations" section.
- **Empty test accounts have no objects.** A fresh self-reg account has zero
  addresses/orders/pets, so object-level IDOR (swap address/order IDs) can't
  be exercised. To test IDOR properly you need TWO accounts (or the program's
  "second organization") with objects on each, then attempt cross-account read.
- **Auth sessions expire fast.** Keycloak SSO tokens are short-lived; rapid
  `about:blank`/navigation churn drops the session and forces re-login. Batch
  all in-page `fetch` work into ONE `browser_console` call per page load;
  avoid extra snapshots between fetch and read.
- **Kasada re-challenges on navigation.** Clicking through forms can reset the
  page to `about:blank`. Re-navigate to the live page, then re-run. Don't burn
  round-trips on repeated snapshots of the same state.
- **`browser_console` evals run in ISOLATED contexts — globals do NOT persist
  between separate calls.** Verified: `window.__x=(window.__x||0)+1` returns 1 on
  two consecutive calls. So the classic "hook `fetch`/`XHR` in call A, click to
  trigger in call B, read `window.__caps` in call C" pattern silently fails — each
  call starts with a fresh `window`, so the hook is gone by the time you read.
  FIX: do hook + trigger + read in ONE call — override `fetch`/`XHR.prototype.send`,
  programmatically click the data link (or refetch), `await` a short delay, then
  `return` the captured record, all inside a single async IIFE. Keep the delay well
  under the eval timeout (a 12s wait errored out; ~3-4s is safe). If the trigger
  navigates the top frame to `about:blank` the call errors ("page URL targets a
  private or internal address") — prefer in-place refetch triggers (pagination/sort
  controls, SPA router pushState) over ones that reload the top frame.
- **When a CSRF replay fails but the SPA's identical request succeeds:** if the
  server returns "CSRF failed" (e.g. Make's `IM023`) rather than "not logged in",
  your session cookie IS arriving — only the CSRF header is not honored. First grep
  the app's main JS bundle for the header name
  (`fetch(scriptSrc).then(r=>r.text()).then(t=>t.match(/["'][a-z-]*x?csrf[a-z-]*["']/ig))`),
  then capture ONE genuine SPA request's exact header/value in a single-call hook
  and compare. Only after a genuine token still fails should you suspect the
  automation layer is dropping custom headers — report that as a TOOLING limitation,
  not a target finding, and pivot to a browser you fully control.
- **Stay in scope.** Program rules often EXCLUDE specific classes (e.g.
  PetProfile GraphQL BAC, CSRF from a specific SPA path, missing security
  headers, rate-limiting, self-XSS). Honor every exclusion; "don't stop until
  you find a bug" means keep searching, NOT bend the scope.
- **Stop immediately if you reach another account.** If an account already
  exists for an email you were given, do NOT log in unless the user confirms
  it's theirs. Accessing another person's account is a hard authorization
  violation.

## When this skill is the right tool

- `curl` gets 429/503 but the browser renders the page.
- You need to enumerate an API whose client bundles are bot-gated.
- You're testing session-scoped IDOR with only one readable endpoint.
- You must prove "tested and ruled out" for a bug-bounty report when the
  vulnerable-surface APIs are unreachable from your tooling.

## See also

- `web-pentest` — the phased engagement workflow (authz gate, scope, reporting).
- `cybersecurity/bug-hunter-workflow` — hunter workflow + bug-class library.
- `references/bot-wall-indicators.md` — cookie/header fingerprints per vendor.
- `references/enumeration-recipes.md` — copy-paste `browser_console` fetch recipes.

