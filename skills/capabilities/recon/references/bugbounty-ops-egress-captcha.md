# bugbounty-ops-egress-captcha

Source: `attack-surface/bugbounty-ops-egress-captcha/SKILL.md` (preserved verbatim during consolidation).

---

---
name: bugbounty-ops-egress-captcha
description: Hunt captcha-gated web targets via browser proxy.
sources: authorized-engagement
report_count: 1
---

# Bug-bounty ops — egress-blocked + captcha-gated targets

## When this fires
Authorized web target (bug-bounty / VDP) where:
- `curl https://<in-scope-host>/` returns `000` (connection refused at edge) or `403` from a WAF (Akamai "Access Denied") for EVERYTHING — but the **browser tool navigates the same host fine**. The WAF key-matches the agent's egress (datacenter IP / no residential proxy), not the host.
- Login is behind hCaptcha / reCAPTCHA, so the agent cannot complete self-registration or log in to obtain a session.
This is the exact shape of the BMW Group / MINI hunt (www.mini.de, customer.bmwgroup.com OneID, hCaptcha).

## Core pattern: browser-as-proxy + SSO-token injection
The browser tool is your only channel to the host. Use it as the request executor.

1. **Reach the host via the browser** (navigate to a known-good in-scope URL). The browser session bypasses the curl egress block.
2. **Get an authenticated session from the user.** You cannot solve image captcha. Ask the user to (a) self-register / log in via the browser, solving captcha; (b) paste the session cookie(s). For BMW, the SSO token is `gcdmToken` (e.g. `gcdmToken=iRjAyp9YIkWyJ6Sd2Nld65QZg0Y`) — a cross-subdomain BMW SSO token valid on `*.mini.de`.
3. **Inject the token in the browser** so the agent can call APIs same-origin:
   ```js
   document.cookie = "gcdmToken=<PASTED_TOKEN>; path=/; domain=.mini.de";
   await fetch('/de_DE/shop/ls/wishlist/api/v1/wishlists/items?info_level=minimal&limit=1',
     {credentials:'include', headers:{'accept':'application/json','x-caller-name':'wishlist'}});
   ```
   **PITFALL — injected token drops on cross-origin navigation.** Navigating the browser to a DIFFERENT origin (e.g. `customer.bmwgroup.com` for the OAuth authorize endpoint) evicts the `www.mini.de` session cookie context. After any such navigation, RE-INJECT the token before authenticated calls, or navigate back to the in-scope origin first. Verify with a known-good 200 call before assuming auth works.
4. **Test authenticated APIs** from the browser console (same-origin `fetch` with `credentials:'include'`), capturing `status`, `Location`, `access-control-*`, and body.

## Honest ruled-out reporting (mandatory)
The user's standing rule: **document ruled-out candidates WITH proof, never fabricate a confirmed bug.** For every class you test, record the actual response that disproves the bug (status code + body excerpt). A "weakness" that can't be completed to a PoC is downgraded/reported as a candidate, not a confirmed finding. Examples from the BMW hunt (all RULED OUT with proof):
- Wishlist IDOR: spoofed `legacyOcpRequestData.gcid` in POST body → server DISCARDED it, stored under session-derived gcid (201). `GET /items/{id}` → 405. Spoofed `?gcid=` query → ignored. → no IDOR.
- OAuth `redirect_uri`: unauthenticated authorize w/ foreign URI → 200 (login page, normal). Authenticated (valid session cookie) → **403**, no redirect to foreign URI. → server enforces allowlist; not exploitable.
- CORS: no `access-control-allow-origin` / no `allow-credentials` for external Origin → safe.
- CSRF on wishlist: no anti-CSRF token, but requires custom `x-caller-name` header + JSON body → forces CORS preflight a cross-site form can't send → mitigated.
- Open redirect (`?destination=/redirect=/return=/next=/url=`): param stripped / no redirect.
- AEM (`/bin/querybuilder.json`, `/content/*.json`): 404.
- GraphQL introspection (`/graphql` etc.): WAF 403, no server.
- Sensitive files (`/.env`, `/.git/HEAD`): generic Akamai "Access Denied" 403 = WAF path block, NOT real files (see soft-404 below).

## WAF soft-404 disambiguation (avoid false positives)
A path like `/.env` returning 403 is usually a **WAF block on the pattern**, not a real exposed file. Prove it with the junk-path control (from `recon-scope-triage`):
```bash
curl -s -o /tmp/a -w "%{http_code} %{size_download}\n" https://host/.env
curl -s -o /tmp/b -w "%{http_code} %{size_download}\n" https://host/zzz-nonsense-$RANDOM
cmp -s /tmp/a /tmp/b && echo "SOFT-404 false positive (catch-all)" || echo "differs — investigate"
```
Real exposures have a content-type + body signature differing from the catch-all.

## Phase loop (pentestcode-style, broaden beyond IDOR/BAC)
Work every class, re-loop. For each: Detect → Exploit → PROVE IMPACT.
1. Recon/scope-triage (ownership + soft-404 first).
2. Vuln-assessment: nuclei (crit/high/misconfig/exposures), dalfox XSS, ffuf content discovery, manually drive each `hunt-*` class from the skill bundle.
3. Exploitation: confirm with a browser PoC; for auth/cookie APIs use the token-injection pattern above.
4. Reporting: one FINDING.md per confirmed bug with repro + impact; ruled-outs logged with proof.
Do NOT stop at IDOR/BAC — cover info-disclosure, SSRF, SQLi, XSS, JWT, OAuth, open-redirect, CORS, CSRF, GraphQL, LFI/XXE/SSTI, race, business-logic, cache-poisoning, host-header.

## Pitfalls
- **Egress block is per-host/WAF, not a tool failure.** Don't conclude "host down" from curl 000 — try the browser. Conversely don't trust curl 403 as "file exists" — run the soft-404 control.
- **Injected session token is fragile** — re-inject after any cross-origin navigation; verify with a known-good call.
- **Captcha can't be solved by the agent** — the user must supply the logged-in session cookie. State this as a factual blocker, never fabricate a post-login PoC.
- **Scope discipline**: out-of-scope hosts (e.g. `*.bmwgroup.com`, `*.bmw.cloud` hosting the sensitive cardata API) must not be tested as findings even if reachable.
- **Only self-reg test accounts** — never touch another user's data; for cross-account IDOR PoC, use two owner-provided accounts and create/read across them.

## Support files
- `references/proven_recipes.md` — copy-paste snippets: gcdmToken injection, WAF soft-404 control, OAuth 403-with-session test, wishlist IDOR attempts, CORS probe, env tooling list.

## Related skills & chains
- `skill-folder-claude-bughunter-layout` — the `skills/<name>/SKILL.md` bundle this hunts from (hunt-idor, hunt-ssrf, hunt-oauth, …).
- `recon-scope-triage` (in the bundle) — ownership + soft-404 control.
- `redteam-mindset` — "don't stop, don't ask, dive deep, honest reporting" operating stance.

