---
name: api
description: "Advanced API hunting: REST/GraphQL introspection, mass assignment, and hidden endpoint discovery."
---

# API Hunting Skill

Expert guide for hunting API vulnerabilities based on top-tier HackerOne reports. Focuses on architectural flaws, logic bypasses, and infrastructure misconfigurations.

## 1. Core Patterns

### A. Exposed Infrastructure Management APIs
*   **Architectural Cause:** Infrastructure control planes (Kubernetes, Docker, Cortex) exposed without authentication or with default credentials.
*   **H1 Report ID:** [#455645](https://hackerone.com/reports/455645) (Snapchat), [#1258871](https://hackerone.com/reports/1258871) (Shopify).
*   **Exact Endpoint:** `https://k8s-api.snapchat.com/api/v1/pods`, `https://cortex-ingest.shopifycloud.com/`.
*   **Payload:** Direct GET request to `/api/v1/namespaces/default/pods` to list all pods and extract secrets.

### B. GraphQL Mutation Aliasing (Resource Exhaustion)
*   **Architectural Cause:** Failure to implement query complexity analysis or mutation limits, allowing batching of thousands of operations in one request.
*   **H1 Report ID:** [#3287208](https://hackerone.com/reports/3287208) (HackerOne).
*   **Exact Payload:** 
    ```graphql
    mutation {
      a: verifyPhoneNumber(number: "1") { success }
      b: verifyPhoneNumber(number: "2") { success }
      # ... repeat 1000x ...
    }
    ```
*   **Impact:** Complete DoS or bypass of rate limits for brute-force attacks.

### C. Shadow API / Undocumented Endpoints
*   **Architectural Cause:** Internal-only or legacy endpoints left active and accessible via production gateways.
*   **H1 Report ID:** [#981472](https://hackerone.com/reports/981472) (Shopify).
*   **Exact Endpoint:** `mutation { fileCopy( ... ) }` (Undocumented GraphQL mutation).
*   **Payload:** Calling `fileCopy` with an external URL to trigger SSRF or unauthorized data movement.

### D. Race Conditions in Heterogeneous API Architectures
*   **Architectural Cause:** Inconsistent state management when the same resource is accessed or modified via different API protocols (REST vs. GraphQL) simultaneously.
*   **H1 Report ID:** [#2216036](https://hackerone.com/reports/2216036) (GitHub).
*   **Technique:** Triggering a REST `Repo Transfer` while simultaneously calling a GraphQL `updateTeamsRepository` mutation to retain persistent admin access.

### E. API Post-Ban/Deletion Persistence
*   **Architectural Cause:** Authentication token revocation logic is decoupled from account lifecycle management (ban/deletion).
*   **H1 Report ID:** [#1577940](https://hackerone.com/reports/1577940) (HackerOne).
*   **Payload:** Utilizing an existing API key on the `/v1/reports` endpoint after the account has been officially banned or deleted.

### F. Information Disclosure via "Test" APIs
*   **Architectural Cause:** Non-production environments (test/dev/beta) exposed to the internet, often sharing infrastructure or data with production.
*   **H1 Report ID:** [#592400](https://hackerone.com/reports/592400) (Starbucks).
*   **Technique:** Unauthenticated access to a test API webservice leading to Blind SQLi and RCE.

## 2. Recon Checklist

### Target JS File Discovery
- Search for `vendor.js`, `app.js`, and `manifest.js`.
- Grep for: `apiKey`, `client_secret`, `Bearer`, `X-API-Key`, `api_version`.

### Parameter Discovery
- High-value parameters: `user_id`, `org_id`, `account_uuid`, `scope`, `grant_type`, `redirect_uri`.
- Hidden parameters: `admin=true`, `debug=1`, `test=true`, `internal=1`.

### Hidden Endpoint Discovery
- Append `.json`, `.xml`, `.yaml` to existing endpoints.
- Check for versioning: `/v0/`, `/v1/`, `/v1.1/`, `/beta/`, `/internal/`.
- Use `KiteRunner` with the `apis.json` wordlist.

### Burp Extensions
- **GraphQL Raider:** For intercepting and modifying GraphQL queries.
- **AutoRepeater:** For testing IDOR by swapping session tokens across all requests.
- **Logger++:** For monitoring background API calls made by mobile apps.

## 3. ID/Target Discovery

### Harvesting Victim Data
- **Public Profile URLs:** Extract `user_id` or `uuid` from URLs like `example.com/profile/12345`.
- **JS Source Maps:** Look for `config` objects in JS files that map environment variables or internal IDs.
- **API Response Over-exposure:** Capture responses from `/v1/me` or `/v1/profile` and look for IDs of related objects (orgs, teams, projects) in the JSON body ([#473742](https://hackerone.com/reports/473742)).
- **Sequential ID Probing:** If IDs are integers, use Burp Intruder to find valid ranges.

## 4. Bypass Techniques

### A. HTTP Method Tunneling
Try overriding the method if direct access is blocked.
- **Example:** `POST /api/v1/delete_user HTTP/1.1` with header `X-HTTP-Method-Override: DELETE`.

### B. API Version Downgrade
Switch to older versions where security controls might be weaker.
- **Example:** Change `https://api.example.com/v3/users` to `https://api.example.com/v1/users` ([#2846011](https://hackerone.com/reports/2846011)).

### C. Content-Type Confusion
Submit data in an unexpected format to bypass WAFs or validation logic.
- **Example:** Change `Content-Type: application/json` to `application/xml` or `text/plain`.

### D. Header-Based Authorization Bypass
Add internal headers to spoof authorization.
- **Example:** `X-Admin: true`, `X-Internal-IP: 127.0.0.1`, `X-Forwarded-For: 127.0.0.1`.

### E. Path Normalization Bypasses
Use directory traversal to reach restricted endpoints.
- **Example:** `GET /api/v1/user/settings/../../admin/stats`.

### F. Scoped Token Misuse
Use a token generated for a low-privilege "App" or "Integration" to access high-privilege APIs.
- **Example:** Using `Scoped-User-To-Server Tokens` for full project access in GraphQL ([#1711938](https://hackerone.com/reports/1711938)).

## 5. High-Value Targets (Ranked by Payout)

1.  **Infrastructure Control Planes:** `/api/v1/pods`, `/docker/containers`, `/cortex/ingest`. (Max Payout: $25k+).
2.  **Authentication/Token Endpoints:** `/oauth/token`, `/auth/refresh`, `/api/v1/keys`. (Max Payout: $15k+).
3.  **Billing & Payment APIs:** `/v1/payments`, `/billing/subscriptions`, `/v1/cards`. (Max Payout: $10k+).
4.  **Administrative GraphQL Mutations:** `mutation { deleteAccount(...) }`, `mutation { upgradeUser(...) }`. (Max Payout: $7k+).
5.  **PII Leakage via IDOR:** `/v1/users/{id}/details`, `/api/orders/{uuid}`. (Max Payout: $3k+).

## 6. Chaining Playbook

### A. Unauth API Access + Blind SQLi → RCE
Find an unauthenticated test API, identify a parameter vulnerable to SQLi, and escalate to RCE via `xp_cmdshell` or similar.
- **Base Report:** [#592400](https://hackerone.com/reports/592400).

### B. Stored XSS + Backend API Leak → Admin Takeover
Inject XSS into a profile field that is rendered in an admin dashboard. Use the XSS to call internal APIs and leak administrator cookies or keys.
- **Base Report:** [#3037447](https://hackerone.com/reports/3037447).

### C. IDOR + Sensitive Data Leak → Account Takeover
Use an IDOR to leak a password reset token or a session secret from an API response, then use it to take over the account.
- **Base Report:** [#1342088](https://hackerone.com/reports/1342088).

### D. Mutation Aliasing + Rate Limit Bypass → DoS
Chain multiple resource-intensive GraphQL mutations into a single request to bypass per-request rate limits and exhaust server resources.
- **Base Report:** [#3287208](https://hackerone.com/reports/3287208).

## 7. Variant-Specific Section: GraphQL Vulnerabilities

### Deep Dive: GraphQL Introspection & Abuse
GraphQL is often the highest-paying API variant due to its complex logic and "auto-documentation" features.

#### 1. Introspection Disclosure
If `__schema` queries are enabled, you can reconstruct the entire API surface.
- **Payload:** `query { __schema { queryType { name } } }`

#### 2. Query Complexity Exhaustion
Deeply nested queries can crash the backend.
- **Payload:**
    ```graphql
    query {
      user {
        friends {
          friends {
            friends { # ... repeat 100x ...
              name
            }
          }
        }
      }
    }
    ```

#### 3. Directive Injection
Injecting directives like `@skip` or `@include` to alter logic.
- **Pattern:** Using directives to bypass boolean checks in mutations.

## 8. Automation

### Endpoint Discovery (ffuf)
```bash
ffuf -w api_wordlist.txt -u https://api.example.com/FUZZ -mc 200,401,403
```

### Burp Intruder Strategy for IDOR
1. Capture a request to `/api/v1/user/1234/data`.
2. Set payload positions on `1234`.
3. Use a "Numbers" payload type from `1000` to `9999`.
4. Add a "Grep - Extract" for sensitive fields like `email` or `token`.

### Response Diffing
Use the `Compare Responses` feature in Burp to identify subtle differences (e.g., response time or byte size) when testing for Blind SQLi or Race Conditions.

## 9. Triage

### Confirmation Steps
1.  **Reproduce with CURL:** Ensure the vulnerability is not a browser artifact.
2.  **Verify Impact:** Can you access *other* users' data? Can you perform actions without auth?
3.  **Check Scope:** Is the API endpoint explicitly in scope?

### Severity Scoring
- **Critical ($10k+):** Unauthenticated RCE, Full DB access, Infrastructure takeover.
- **High ($3k - $10k):** Full Account Takeover, PII leak of all users, SSRF to internal network.
- **Medium ($500 - $3k):** IDOR on sensitive data, Rate limit bypass on auth endpoints.
- **Low ($100 - $500):** Information disclosure of non-sensitive metadata, Lack of rate limiting on low-impact endpoints.

## 10. Report Template

```markdown
### Summary
An insecure API endpoint at `[ENDPOINT]` allows `[VULNERABILITY TYPE]` by `[ACTION]`. This leads to `[IMPACT]`.

### Steps to Reproduce
1. Intercept the request to `[ENDPOINT]`.
2. Modify the `[PARAMETER/HEADER]` to `[PAYLOAD]`.
3. Observe the response containing `[SENSITIVE DATA/SUCCESS MESSAGE]`.

### Proof of Concept
`[INSERT CURL COMMAND OR HTTP REQUEST/RESPONSE]`

### Impact
`[DETAILED DESCRIPTION OF BUSINESS IMPACT AND DATA EXPOSURE]`

### Recommended Mitigation
`[SPECIFIC REMEDIATION ADVICE E.G., IMPLEMENT ACCESS CONTROL CHECKS ON OBJECT IDS]`
```
