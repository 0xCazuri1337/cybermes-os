---
name: authorization
description: "Deep-dive into Broken Access Control: IDOR, vertical privilege escalation, and cross-tenant leakage."
---

# Authorization Bug Hunting (Broken Access Control)

Expert playbook for identifying, bypassing, and escalating Authorization vulnerabilities based on top-tier HackerOne findings ($10k+ payouts).

## 1. Core Patterns
*   **Trusting Unverified Partner Email (Shopify #300305 - $15,250):**
    *   **Architectural Cause:** Granting "Collaborator" access to any store based on an unverified employee email registration in a separate partner portal.
    *   **Endpoint:** `partners.shopify.com/registration`
    *   **Payload:** Registering with `victim_employee@target.com` and bypassing the verification link to inherit permissions on the target's internal stores.
*   **Direct Admin Endpoint Exposure (Oracle #170532 - $18,000):**
    *   **Architectural Cause:** Internal administrative interfaces (`/cs/Satellite`) exposed to the public internet without IP-based or secondary authentication.
    *   **Endpoint:** `/cs/Satellite?pagename=OpenMarket/Xcelerate/Admin/Welcome`
    *   **Payload:** Direct GET request to the admin portal URL, bypassing the main application's login flow.
*   **Internal Service Token Leakage (TikTok #1328546 - $15,000):**
    *   **Architectural Cause:** Use of guessable or leaked service tokens to access internal microservices (intelbot) that handle sensitive ticket data.
    *   **Endpoint:** `intelbot.tiktok.com/api/v1/ticket/detail`
    *   **Payload:** `GET /api/v1/ticket/detail?id=[TICKET_ID]` using a hardcoded or leaked internal service token.
*   **GraphQL Direct Node Access (GitHub #3124517 - $10,000):**
    *   **Architectural Cause:** Missing authorization checks when fetching objects directly via their Global ID (`gid://`) through the `node()` query.
    *   **Endpoint:** `/graphql`
    *   **Payload:** `query { node(id: "[PRIVATE_BLOB_GID]") { ... on Blob { text } } }`
*   **SSO/SAML Enforcement Trapdoor (Superhuman #976603 - $10,500):**
    *   **Architectural Cause:** Maintenance of a legacy password-based login or password-reset flow that bypasses the mandatory SSO enforcement for organizations.
    *   **Endpoint:** `/auth/password_reset`
    *   **Payload:** Triggering a password reset on an account belonging to an SSO-only organization and using the reset token to log in, skipping the SAML flow.

## 2. Recon Checklist
*   **JS File Targets:** Scrape for keywords: `isAdmin`, `isStaff`, `role_id`, `permissions`, `can_manage`, `tenant_id`, `X-Internal-Secret`.
*   **Parameter Names:** `role`, `access_level`, `privilege`, `membership`, `is_admin`, `staff_only`, `impersonate_id`.
*   **Hidden Endpoint Discovery:** Fuzz for prefixes like `/_admin`, `/internal-api`, `/debug/auth`, `/api/v1/management`.
*   **Burp Extensions:** 
    *   **Authorize:** Mandatory for testing horizontal/vertical escalation in real-time.
    *   **Auth Analyzer:** To track session tokens across multiple roles.
*   **ID Enumeration Types:** Sequential IDs in "Add Member" or "Invite" flows. Check if `org_id` or `workspace_id` can be guessed to join other organizations (Slack #1716016).

## 3. ID/Target Discovery
*   **Invite Token Manipulation:** Intercept and modify invite links to change the `target_org_id` before accepting (Slack #1716016).
*   **GraphQL Introspection:** Query `__schema` to find types like `AdminMutation` or fields like `internal_notes`.
*   **Metadata Leakage:** Scrape CSV export links (HackerOne #2381253) to find IDs of private programs or users.

## 4. Bypass Techniques
*   **Path/Header Confusion:** Use `X-Original-URL: /admin` to bypass frontend filters while hitting the backend.
*   **Parameter Overriding:** `POST /api/user/me?role=admin` (appending administrative parameters to user-level requests).
*   **API Version Downgrade:** Try `/api/v1/` if `/api/v2/` is secure (Zendesk #2188569).
*   **JSON Property Injection:** Add `"is_admin": true` to a profile update JSON body.
*   **HTTP Method Manipulation:** Change `GET` to `POST` or `PUT` for restricted endpoints.
*   **Context-Dependent Access Control (CDCA):** Bypass password confirmations by changing the email address via a different "unprotected" profile endpoint (Nextcloud #2120667).

## 5. High-Value Targets
1.  **Organization SSO/SAML Settings:** Bypassing mandatory SSO is a $10k+ finding (Superhuman #976603).
2.  **Payment/Payout Management:** Modifying bank details (Razer #757095) or publishing paid content for free (Shopify #953083).
3.  **Internal Helpdesk/Ticketing:** Accessing PII via "intelbots" or support portals (TikTok #1328546).
4.  **Admin Impersonation Flows:** Escalating privileges when an admin impersonates a user (GitLab #493324).
5.  **Sensitive Data Exports:** Hijacking JSON/CSV report generators (HackerOne #2516250).

## 6. Chaining Playbook
*   **Auth Bypass + XSS → Full ATO:** Use a broken admin panel access to inject Stored XSS that targets the Owner's browser (Zomato #724889).
*   **IDOR + SSO Bypass → Mass Organization Takeover:** Find a workspace ID via IDOR, then use the SSO trapdoor to reset the admin password.
*   **PrivEsc + Command Injection → RCE:** Escalating from `user` to `SYSTEM` via unauthenticated command execution (Ubiquiti #544928).
*   **Auth Bypass + SQLi → Database Dump:** Access an administrative search page that is vulnerable to SQLi (Revive Adserver #3395221).

## 7. Variant-Specific: SSO Enforcement Bypass
The highest payouts in Authorization often come from breaking "SSO Only" policies.
*   **The Flaw:** When an organization mandates "Login with Google/Okta", the application often fails to disable the original `/login` or `/password_reset` routes for those specific users.
*   **Escalation:** An attacker triggers a password reset for a target user. If the reset token allows login without hitting the SAML flow, the "SSO Enforcement" is completely negated.
*   **Report Reference:** Superhuman #976603 ($10,500).

## 8. Automation
*   **Burp Intruder:** Fuzz `role` or `permissions` parameters with a list of known administrative titles.
*   **ffuf:** `ffuf -u https://target/api/user -d "role=FUZZ" -w roles.txt -H "Cookie: session=user_cookie"`
*   **Response Diffing:** Focus on `Content-Length` and `Status Code` changes when toggling from a user session to an unauthenticated/different session.

## 9. Triage
*   **Critical ($10k+):** Unauthenticated Admin Access, SSO Bypass, or Privilege Escalation to Global Admin/Owner (Oracle #170532, Superhuman #976603).
*   **High ($3k-$9k):** Vertical Privilege Escalation (User to Admin), Cross-Tenant IDOR (Shopify #300305, Stripe #1677541).
*   **Medium ($500-$2k):** Horizontal Privilege Escalation, unauthorized access to sensitive but non-administrative data.
*   **Low ($100-$400):** Authorization bypass on non-sensitive metadata or development assets.

## 10. Report Template
```markdown
## Summary
A Broken Access Control (Authorization) vulnerability was found in the `[ENDPOINT]`. An attacker can [IMPACT - e.g., escalate their privileges to Admin] by manipulating the `[PARAMETER]` parameter.

## Steps to Reproduce
1. Log in as a low-privileged user.
2. Navigate to `[URL]`.
3. Intercept the request to `[ENDPOINT]`.
4. Add/Modify the parameter `[PARAMETER]` to `[VALUE]`.
5. Observe the successful [ACTION] and the response indicating elevated permissions.

## Supporting Evidence
- **Vulnerable Endpoint:** `[ENDPOINT]`
- **Payload:** `[PAYLOAD]`
- **HackerOne Reference:** Based on patterns in Report #[ID] (e.g., #300305)

## Impact
[Detailed impact: e.g., Full control over organization settings and user data.]
```
