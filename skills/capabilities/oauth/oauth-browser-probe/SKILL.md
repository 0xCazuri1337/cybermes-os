---
name: oauth-browser-probe
description: OAuth redirect_uri probe via browser when curl blocked.
version: 1.0.0
category: cybersecurity
tags: [cybersecurity, oauth2, oidc, redirect-uri, browser-probe, auth-bypass]
---

# OAuth IdP probing via browser when curl is edge-blocked

## When to use
- The target's authorization server (`/authorize`, `/oneid/...`) returns 000/403
  to `curl`/`requests` but the login page loads fine in `browser_navigate`.
- You need to test `redirect_uri` validation but cannot complete a real login
  (captcha / no session), so you must prove the weakness at the authorize stage.

## Core technique: probe the authorize endpoint from the browser console
Same-origin `fetch` from a page the browser can reach bypasses the curl egress
block. Compare GOOD (registered) vs BAD (foreign) `redirect_uri`:

```javascript
(async () => {
  const base = location.origin; // e.g. https://customer.bmwgroup.com
  const mk = (ru) => `${base}/oneid/authorize/?client=miniwebcom&response_type=code`
    + `&redirect_uri=${encodeURIComponent(ru)}&scope=svds&state=test`;
  const test = async (ru) => {
    const r = await fetch(mk(ru), {redirect:'manual', credentials:'include'});
    return {status:r.status, location:r.headers.get('location'),
            title:(await r.text()).slice(0,80)};
  };
  // Use a PUBLIC hostname as the "bad" value. The browser console REFUSES to
  // fetch obviously-internal names like evil.example.com (private/internal guard);
  // example.com is accepted. Avoid subdomain-confusion variants in fetch (also blocked).
  return JSON.stringify({
    good: await test('https://www.mini.de/static/login/token-handler'),
    bad:  await test('https://example.com'),
  }, null, 1);
})();
```

## Detection nuance (standard tooling misses this)
A compliant server rejects an unregistered `redirect_uri` with an error
(`400`/`invalid_redirect_uri`) BEFORE rendering login. But some IdPs render the
login page with **HTTP 200 for ANY `redirect_uri`**, deferring validation to the
token step. That 200-render for a foreign URI IS a weakness — do NOT only look
for a `302` to the attacker host. If GOOD and BAD both return 200 / same login
page, authorize-stage validation is absent. (Real hit: BMW OneID returned
identical 200 hCaptcha page for `www.mini.de` and `example.com`.)

## Gotchas
- Captcha/consent iframe can sandbox `browser_console` in `about:blank`. Navigate
  the MAIN window to a clean in-scope page FIRST, then run the probe from that
  context. If console says "Blocked: ... about:blank", re-navigate and retry.
- hCaptcha on login blocks completing a real login. You can prove the authorize
  stage accepts a foreign `redirect_uri` but CANNOT show the code delivered to it
  without solving captcha or holding a pre-authenticated session. Document that
  gap honestly: confirmed weakness, not yet a confirmed code-leak. Do NOT
  fabricate the final hop.
- Use `fetch(..., {redirect:'manual'})` + AbortController (6s) per request so one
  hung call doesn't time out the whole console invocation.

## Captcha wall — what does NOT work here (do not re-chase)
- Image puzzle: unsolvable without a vision/solver.
- "Accessibility: get cookie" link: opens in `about:blank` sandboxed frame;
  clicking blocked by the browser tool.
- "Skip"/"Überspringen": only refreshes the challenge.
If login is gated behind hCaptcha and you hold no session/cookie, you cannot get
an authenticated session from this environment. Report that as the PoC blocker.

## Related / richer corpus
The `oauth-misconfiguration` skill (user-owned; run `hermes curator adopt
oauth-misconfiguration` to enable writes) has a large report corpus and
hunting-methodology. This skill covers ONLY the browser-when-curl-blocked probe
pattern; defer to that one for full OAuth theory, payloads, and chaining.
