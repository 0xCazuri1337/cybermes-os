---
name: oauth-fragment-redirect
description: 'Use when OAuth login reflects redirects into URL fragment.'
domain: cybersecurity
subdomain: web-application-security
tags:
- oauth
- oidc
- open-redirect
- spa
- fragment
- redirect_uri
- authorization-code-flow
version: '1.0'
license: Apache-2.0
---

# OAuth Fragment Redirect Testing

## When to Use
- Testing OAuth/OIDC login endpoints where `redirect`/`returnTo` params are accepted
- SPA-based authentication flows that use URL fragments for post-login routing
- Descope, Auth0, Okta, or similar CIAM platforms with SPA wrappers
- When `redirect_uri` whitelist validation appears strict but the login wrapper accepts redirect params

## Core Pattern

Some OAuth/OIDC frontends reflect attacker-controlled redirects into the **URL fragment** (after `#`) rather than into the `redirect_uri` query parameter. The fragment is client-side only, so server-side `redirect_uri` whitelist validation may not catch it. The SPA router then navigates to the attacker URL post-login.

### Typical Flow
```
1. Attacker: GET /login?redirect=https://evil.com
2. Server: 302 Location: https://ciam.target.com/oauth2/v1/authorize?...
   redirect_uri=https%3A%2F%2Ftarget.com%2Fconnect%2Fservice%2Fdescope
   #/login?redirect=https%3A%2F%2Fevil.com
3. Victim authenticates via OAuth provider
4. Provider redirects back to target.com with auth code in fragment
5. SPA reads fragment, sees redirect=https://evil.com, navigates there
```

## Detection

### Step 1: Identify candidate parameters
Test these params on the login endpoint:
- `redirect`
- `returnTo`
- `return_url` / `returnUrl`
- `next`
- `to`
- `url`

### Step 2: Capture the Location header
```bash
curl -sI "https://target.com/login?redirect=https://evil.com" \
  | grep -i "^location:"
```

### Step 3: Check for fragment reflection
Look for these patterns in the `Location` header:
- `...#/login?redirect=https%3A%2F%2Fevil.com`
- `...#/login?returnTo=https%3A%2F%2Fevil.com`
- `...#redirect=https%3A%2F%2Fevil.com`

If the attacker URL appears **after the `#`** in the authorization URL, this is a fragment-based redirect reflection.

## Validation Checklist

1. **Confirm fragment reflection**: Attacker URL appears after `#` in OAuth authorization URL.
2. **Confirm param name**: Fragment contains `redirect=`, `returnTo=`, or similar param with attacker URL URL-encoded.
3. **Document PoC**: Full OAuth authorization URL in the report is sufficient for reproduction.
4. **Test SPA behavior**: Complete the OAuth flow in a browser and confirm post-auth navigation to attacker URL.
5. **Assess impact**: Chain to OAuth code theft or phishing depending on SPA behavior.

## Impact Assessment

### High Impact: OAuth Code Theft
If the OAuth provider sends the authorization code in the URL fragment after redirect, and the fragment is forwarded to the attacker domain, the attacker can exchange the code for a token.

**Chain:** Fragment redirect → victim authenticates → auth code sent to attacker-controlled URL → attacker exchanges code for token → ATO.

### Medium Impact: Phishing
If the SPA navigates to attacker URL post-login, attacker can host a fake SSO continuation page to harvest credentials or session tokens.

## Bypassing redirect_uri Whitelist

The fragment-based reflection bypasses server-side `redirect_uri` validation because:
1. The `redirect_uri` parameter in the OAuth authorization request is usually hardcoded to the legitimate callback URL.
2. The attacker-controlled redirect is in the fragment, which the server never validates.
3. The SPA client-side router decides navigation based on the fragment after the OAuth callback.

## Platform-Specific Notes

### Descope
- Project ID is exposed in page source: `window.__standalone.DESCOPE_PROJECT_ID`
- Universal login flow uses `#/login?redirect=` fragment pattern
- Test params: `redirect`, `returnTo`, `return_url`, `next`

### Auth0
- Lock.js and Auth0.js may reflect redirects into `#/login?redirect=`
- Test with `/login?redirect=` and `/authorize?redirect_uri=` separately

### Okta
- Okta Sign-In Widget may use `#/login?redirect=` or `?redirectUrl=`
- Check both query and fragment for reflection

## False Positives

- **Fragment contains attacker URL but SPA ignores it**: If the SPA ignores the fragment and redirects to a hardcoded post-login page, this is informational unless chained.
- **Only query parameter reflection**: If the attacker URL is in the query string and the server validates it, this is not a bypass.
- **Self-redirect only**: If the redirect only goes to the same domain, this is not a vulnerability.

## Remediation

1. **Whitelist on the wrapper**: Validate `redirect`/`returnTo` params against allowed paths server-side before building the OAuth authorization URL.
2. **SPA router check**: After OAuth callback, validate the fragment's redirect target against allowed paths before navigating.
3. **Remove fragment-based routing**: Use query parameters with server-side validation instead of fragments for post-login routing.
4. **OAuth state binding**: Bind the `redirect` param value to the OAuth `state` parameter server-side to prevent tampering.

## References

- `bug-bounty/web/open-redirect` — Open redirect hunting methodology
- `bug-bounty/oauth-sso/exploiting-oauth-misconfiguration` — OAuth misconfiguration testing
- `bug-bounty/recon/attack-surface/bb-methodology` — Bug bounty workflow

## Evidence Template

```
## Finding: Open Redirect in OAuth Login Flow
**Severity:** Medium/High
**Target:** https://target.com/login
**Type:** Open Redirect / OAuth redirect_uri manipulation

### Description
The `/login` endpoint accepts a `redirect` query parameter and reflects it into the OAuth authorization URL fragment.

### Evidence
GET /login?redirect=https://evil.com HTTP/1.1
Host: target.com

HTTP/1.1 302 Found
Location: https://ciam.target.com/oauth2/v1/authorize?response_type=code&client_id=...
&redirect_uri=https%3A%2F%2Ftarget.com%2Fconnect%2Fservice%2Fdescope
#/login?redirect=https%3A%2F%2Fevil.com

### Attack Scenario
1. Attacker sends victim: https://target.com/login?redirect=https://evil.com
2. Victim authenticates via OAuth
3. Post-auth SPA fragment contains attacker-controlled redirect
4. Victim is redirected to attacker-controlled site
```
