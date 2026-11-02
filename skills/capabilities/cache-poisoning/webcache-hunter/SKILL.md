---
name: webcache
description: "Web Cache Deception and Poisoning: keyed/unkeyed headers, cache key manipulation, and cookie-based poisoning."
---

# SKILL: Web Cache Exploitation (WEBCACHE)

Mastery of Web Cache vulnerabilities involves manipulating caching proxies (CDNs) to store malicious responses (Poisoning) or tricking them into caching sensitive user data (Deception).

## 1. Core Patterns

### CDN Error Caching DoS
*   **Architectural Cause:** CDN (Akamai) configured to cache `501 Not Implemented` responses for static assets.
*   **H1 Report:** [#622122](https://hackerone.com/reports/622122) - $9,700
*   **Endpoint:** `https://www.paypalobjects.com/en_US/i/scr/sm_main.js`
*   **Payload:** `Transfer-Encoding: x` (triggers 501 error which is then cached for all users).

### Unkeyed Host Port Poisoning (DoS)
*   **Architectural Cause:** Application reflects `Host` header port in canonical links, but the cache key only includes the hostname.
*   **H1 Report:** [#1096609](https://hackerone.com/reports/1096609) - $2,900
*   **Endpoint:** `https://themes.shopify.com/`
*   **Payload:** `Host: themes.shopify.com:1337` (forces canonical links to invalid port).

### Unkeyed Header Token Theft
*   **Architectural Cause:** Backend uses `X-Forwarded-Host` to generate absolute URLs in forms/links without including it in the cache key.
*   **H1 Report:** [#504514](https://hackerone.com/reports/504514) - Smule
*   **Endpoint:** `https://www.smule.com/s/smule_groups/user_groups/[user]`
*   **Payload:** `X-Forwarded-Host: attacker.com` (leaks CSRF tokens via poisoned form actions).

### CL.TE Smuggling to Cache Poisoning
*   **Architectural Cause:** Frontend/Backend desync allowing a smuggled request for a static asset to be answered with a redirect.
*   **H1 Report:** [#919175](https://hackerone.com/reports/919175) - $1,700
*   **Endpoint:** `https://basecamp.com/static_asset.js`
*   **Payload:** `Transfer-Encoding: chunked` + `Content-Length` (smuggling a request that uses `X-Forwarded-Host` to redirect to malicious JS).

### Path Confusion (Web Cache Deception)
*   **Architectural Cause:** Cache rules match extensions (`.css`), but the origin server ignores them and serves dynamic HTML.
*   **H1 Report:** [#1343086](https://hackerone.com/reports/1343086) - $1,600
*   **Endpoint:** `https://www.glassdoor.com/member/profile.css`
*   **Payload:** Appending `.css` to a sensitive page to force the cache to store private data (`gdtoken`).

### Personalized 404 Deception
*   **Architectural Cause:** Cache stores 404 responses for static extensions, but the 404 page contains authenticated user data.
*   **H1 Report:** [#1271944](https://hackerone.com/reports/1271944) - $800
*   **Endpoint:** `https://help.shopify.com/es/manual/<RANDOM>.css`
*   **Payload:** Appending `.css` to trigger a personalized 404 page that leaks CSRF tokens.

## 2. Recon Checklist
- [ ] **Identify Caching Headers:** Look for `X-Cache`, `CF-Cache-Status`, `Age`, `X-Akamai-Staging`.
- [ ] **Param/Header Reflection:** Check if `X-Forwarded-Host` or `Host` values appear in the response.
- [ ] **Unkeyed Header Fuzzing:** Use Burp **Param Miner** to find hidden unkeyed headers.
- [ ] **Extension Probing:** Test endpoints with `.css`, `.js`, `.jpg` to see if the origin serves HTML while the cache stores it.
- [ ] **Cache Key Testing:** Change the `Host` port or add `X-Forwarded-Scheme: http` to see if the response changes but the `X-Cache: HIT` remains.

## 3. ID/Target Discovery
- **High-Traffic JS/CSS:** Target libraries like `jquery.min.js` or `main.css` for poisoning to maximize DoS/XSS impact.
- **CSRF Token Locations:** Find pages reflecting anti-forgery tokens (e.g., `gdtoken`, `authenticity_token`).
- **Personalized Static Paths:** Discover if `/favicon.ico` or `/robots.txt` can be tricked into reflecting user data.

## 4. Bypass Techniques
- **Line-Wrapped Headers:** Use `X-Forwarded-Host:\n attacker.com` to bypass simple string-matching filters (#622122).
- **Dot-Segment Confusion:** `GET /account/settings/.css` vs `GET /account/settings/.%2e/favicon.ico`.
- **Double Encoding:** `GET /profile%2f.css` to trick some proxies into ignoring the extension.
- **Internal Cache Poisoning:** Target internal caching mechanisms (like Memcached) via Request Smuggling (#919175).
- **Fragment Injection:** `GET /profile#.css` - The cache sees the extension, but the browser may ignore the fragment.
- **Port Manipulation:** Adding `:80` or `:443` to the `Host` header to bypass keys that only expect the domain string (#1096609).

## 5. High-Value Targets
1.  **PayPal/Payment Gateways:** ($10k+) DoS via critical JS assets.
2.  **SaaS Settings Pages:** Web Cache Deception for CSRF tokens/PII.
3.  **Login Endpoints:** Poisoning redirects to steal credentials.
4.  **Admin Dashboards:** Deception for internal management tokens.

## 6. Chaining Playbook
- **Cache Poisoning + XSS → ATO:** Poison a JS file to execute XSS, then steal session cookies.
- **Web Cache Deception + CSRF → Email Change:** Leak a CSRF token (#1343086), then use it to change the victim's email.
- **Request Smuggling + Cache Poisoning → Region-Wide DoS:** Smuggle a 404/501 response into a static asset's cache entry for an entire CDN edge (#919175).
- **Host Header Poisoning + Open Redirect → Credential Theft:** Poison the `Host` header to redirect the login form to an attacker domain.

## 7. Variant-Specific: HTTP Desync Cache Poisoning (Highest Payout)
The fusion of **Request Smuggling** and **Cache Poisoning** represents the highest-paying variant ($20k+ potential).
- **Mechanism:** Using a desync (CL.TE or TE.CL) to make the frontend cache believe a 404 or a redirect response belongs to a high-traffic static asset.
- **Case Study:** James Kettle's PayPal research (#622122) used `Transfer-Encoding` desync to poison the CDN, earning massive bounties.

## 8. Automation
- **Burp Intruder:** Cluster bomb `Host` header values with standard and non-standard ports.
- **ffuf Command:**
  ```bash
  ffuf -w extensions.txt -u https://target.com/api/user_info/FUZZ -mc 200 -H "X-Cache-Probing: 1"
  ```
- **Response Diffing:** Use the **Param Miner** "Guess headers" feature to automatically detect unkeyed headers by observing subtle response changes while maintaining a cache hit.

## 9. Triage
- **Confirmation:** Verify the vulnerability persists across different IP addresses (CDN cache hit).
- **Severity Scoring:**
    - **Critical ($10k+):** Mass XSS or persistent site-wide DoS on major platforms.
    - **High ($3k - $8k):** Account takeover via CSRF token leakage or PII exposure for many users.
    - **Medium ($1k - $2k):** Single-user information leakage or minor asset poisoning.
    - **Low ($100 - $500):** Temporary cache-based defacement or non-sensitive information leakage.

## 10. Report Template
```markdown
### Summary
A web cache [poisoning/deception] vulnerability exists on `[ENDPOINT]`. An attacker can [poison/deceive] the cache by [EXPLAIN_METHOD], leading to [IMPACT].

### Steps to Reproduce
1. (For Poisoning) Send a request with the header `[HEADER]: [VALUE]`.
2. Observe that the response [REDIRECTS/ERRORS/REFLECTS] the payload.
3. Confirm the response is cached by checking the `X-Cache: HIT` header in a subsequent request from a different IP.

### Impact
This allows an attacker to [EXPLAIN_ATO_DOS_XSS], affecting all users served by the caching edge.

### Affected Parameter
Header: `[UNKEYED_HEADER]` or Path Extension: `[EXTENSION]`

### Suggested Mitigation
Disable caching for dynamic responses, implement `Cache-Control: no-store, private`, and include all influential headers in the cache key.
```
