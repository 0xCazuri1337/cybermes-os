# idor-hunter

Source: `authorization/idor-hunter/SKILL.md` (preserved verbatim during consolidation).

---

---
name: idor-master
description: "Focused IDOR hunting: UUID prediction, GID manipulation, and automated authorization diffing."
---

# IDOR Master Skill

## 1. Core Patterns (with real examples)

- **GID Manipulation & Base64 Decoding**
  - **Architectural Cause:** The backend validates the format of the Global Identifier (GID) but fails to verify if the underlying object belongs to the user or team making the request.
  - **Real Example (HackerOne #1969141):** `POST /graphql` with the `UpdateCampaign` mutation. Researchers base64-decoded the `campaign_id` parameter `Z2lkOi8vaGFja2Vyb25lL0NhbXBhaWduLzI0NA==` to reveal `gid://hackerone/Campaign/244`. They incremented the integer to `245`, re-encoded it, and sent it to modify another user's campaign.

- **Object Deletion via ID Substitution**
  - **Architectural Cause:** Missing authorization checks on child objects during mutation queries. The system trusts the provided ID without verifying object ownership.
  - **Real Example (HackerOne #2122671):** `POST /graphql` using the `CreateOrUpdateHackerCertification` query. By changing the `id` parameter within the certification update request, researchers deleted certifications belonging to other users.

- **Cross-Organizational Data Dumping**
  - **Architectural Cause:** A parameter intended as a database filter is implicitly trusted without a preceding check verifying the user's membership in the target organization.
  - **Real Example (HackerOne #2487889):** `POST /bugs.json` with payload `text_query=1&organization_id=58579&limit=1000&page=1`. Appending the `limit` and `page` parameters alongside an arbitrary `organization_id` allowed the dumping of all private report titles and severities for that organization.

- **Unauthenticated Payment Data Leak**
  - **Architectural Cause:** The endpoint completely lacks session authentication and blindly trusts the `user_id` provided in the JSON body payload.
  - **Real Example (Nord Security #751577):** `POST /api/v1/orders` with payload `{"payment":{...},"action":"order","plan_id":653,"user_id":20027039}`. Changing the `user_id` returned the victim's payment redirect URL containing sensitive tokens and PII.

- **Session Misbinding (SSO Bypass)**
  - **Architectural Cause:** Deletion/Modification logic relies on JSON body parameters (like email) rather than extracting the user context directly from the authenticated session token.
  - **Real Example (Mozilla #3154983):** `POST /v1/account/destroy`. The server normally requires `email` and `authPW` (password hash). For accounts created via SSO (which have no password), the `authPW` check was bypassed, allowing deletion of any SSO-only account using just the victim's email.

- **Secondary User Addition via ID Injection**
  - **Architectural Cause:** Endpoint allows linking an account to a parent company but fails to validate if the active session matches the targeted parent `merchant_id`.
  - **Real Example (PayPal #415081):** POST to `www.paypal.com/businessmanage/users/api/v1/users` manipulating the `merchant_id` to add secondary users (attacker) to a victim's PayPal business account.

## 2. Recon Checklist

Specific steps to find IDOR candidates on a new target:
- **What to look for in JS files:** Search for `.js` endpoints handling object identifiers. Look for variables named `id`, `user_id`, `uuid`, `org_id`, `guid`, `merchant_id`, or `campaign_id`. Hunt for hidden REST versions like `/api/v1/` or `/v2/` and hidden `/graphql` endpoints.
- **What parameters to log while browsing as a normal user:** Actively monitor and log `id`, `user`, `account`, `number`, `order`, `email`, `doc`, `key`, and `token` across all HTTP methods.
- **How to find hidden/undocumented endpoints:** Use tools like `waybackurls`, `gau`, or `paramspider` to scrape historical endpoints. Append `.json`, `.xml`, or API versioning (`/v3/`) to paths that currently return 404s or 403s.
- **What Burp Suite extensions help:** 
  - **Autorize:** To automate authorization enforcement checks (tests endpoints with a low-privileged cookie).
  - **AutoRepeater:** To automatically swap UUIDs/IDs in requests.
  - **GraphQL Raider:** To discover and manipulate GraphQL endpoints.
- **How to enumerate IDs:**
  - *Sequential:* Check if IDs simply increment (e.g., 1001 to 1002).
  - *UUID:* Check if it's UUIDv1 (timestamp-based and predictable). UUIDv4 cannot be predicted and must be leaked.
  - *Encoded:* Try decoding Base64 strings or checking if the ID is a simple MD5 hash of an integer.

## 3. ID Discovery Techniques

How to actually get victim IDs to test with:
- **From public profiles:** Harvest IDs from public-facing URLs (e.g., `/user/12345`) or directly from avatar image URLs (e.g., `images.target.com/avatar/12345.png`).
- **From API responses leaking other users data:** Inspect all JSON responses meticulously. An endpoint like `GET /api/users/me` might return an array of team members, leaking `{ "id": 777, "role": "admin" }`.
- **From referrer headers:** Trigger a password reset or click a link from an application email. The resulting HTTP request often leaks the token or user ID in the `Referer` header sent to third-party analytics or support platforms.
- **From email links:** Look at the raw source of Unsubscribe links or Receipt viewing links in your inbox; they frequently contain non-expiring IDs.
- **From GraphQL introspection:** Run the `__schema` query to find related types and fields that require IDs, which might inadvertently list all available objects.

## 4. Bypass Techniques

What to try when basic IDOR is blocked:
- **HTTP method switching:** If `GET /api/users/123` is protected, try `POST`, `PUT`, `PATCH`, or `DELETE` on the exact same endpoint with the same ID.
- **Parameter pollution:** Supply the parameter multiple times.
  - `?user_id=victim&user_id=attacker`
  - `?user_id=attacker&user_id=victim`
- **JSON parameter wrapping:** Change the structure of the JSON payload.
  - Array wrapping: `{"id": [1234]}` or `{"id": [1234, 5678]}`
  - Object wrapping: `{"id": {"id": 1234}}`
- **Adding extensions:** Bypass regex or WAF filters by appending extensions: `/api/users/1234.json`, `/api/users/1234.xml`, `/api/users/1234.csv`.
- **Wildcard/null values:** Try bypassing checks with `id=*`, `id=%`, `id=null`, `id=0`, or `id=-1`.
- **UUID prediction or pattern analysis:** If UUIDv1 is used, generate multiple IDs and find the timestamp differential to predict the next user's UUID.
- **Changing Content-Type header:** Switch from `application/x-www-form-urlencoded` to `application/json` (or vice-versa) to see if a different, misconfigured parser handles the backend logic.
- **Path traversal variant:** Force the backend to traverse away from your ID. Example: `/api/users/myID/../victimID`.

## 5. High-Value Targets (Priority Order)

Rank which IDOR locations give highest severity findings:
1. **Payment/billing endpoints:** `/orders`, `/checkout`, `/cashier/transaction-history` (Highest impact; leaks full names, addresses, and partial CCs).
2. **PII endpoints:** `/profile`, `/users/me`, `/bugs.json` (Directly exposes sensitive personal data).
3. **Admin actions:** `/admin/users/delete`, `/businessmanage/users/api/v1/users` (Allows privilege escalation or unauthorized access grants).
4. **Delete/modify actions:** `/v1/account/destroy`, `POST /graphql CreateOrUpdateHackerCertification` (Permanent destructive actions).
5. **Analytics/Statistics:** `/analytics/restaurant`, `/internal/stats` (Corporate data leakage).

## 6. Chaining Playbook

How to escalate IDOR to higher severity:
- **IDOR + Info Disclosure → Account Takeover (ATO):** Use an IDOR on a legacy/alternate endpoint to leak a valid `PHPSESSID` or password reset token, then apply that token to the main application (e.g., Starbucks #876300).
- **IDOR + Self-XSS → Stored XSS on Victim:** Update another user's profile or bio via IDOR and inject an XSS payload. When the victim views their own profile, the XSS fires.
- **IDOR + File Upload → RCE:** If you find an IDOR that allows modifying other users' avatar files, overwrite an admin's avatar with a web shell and execute it.
- **IDOR Read → IDOR Write Escalation Path:** Use an unauthenticated read IDOR to dump hidden object IDs or private metadata, then feed those leaked IDs into an authenticated state-changing endpoint to delete or modify them.

## 7. GraphQL-Specific IDOR

- **How to do introspection to find mutations:** Send the introspection payload `{"query":"{__schema{types{name,fields{name}}}}"}`. Map out every mutation that accepts an `ID!` or `String!` input.
- **How to find IDs through `__typename` queries:** Add `__typename` to your query fields. This reveals the exact internal object model the backend expects, which often correlates directly to GID formats (e.g., `__typename: "User"` implies `gid://app/User/123`).
- **Common GraphQL IDOR patterns:**
  - Base64 encoded Global IDs (`Z2lkOi8v...`).
  - Mutations that check the parent `organization_id` but ignore the `id` of the child object being modified.
- **Tools:** Use **InQL** (Burp extension) to extract queries and **GraphQL Voyager** to visualize the relationship between objects, making it easier to spot where IDs are reused across types.

## 8. Automation

- **Burp Suite Intruder payload strategy for ID fuzzing:** Use the **Sniper** attack type for single parameters. Set payloads to "Numbers", sequential from 1 to 5000. For UUIDs, if you control multiple accounts, use Intruder to fuzz the last few bytes of a UUID to find close neighbors.
- **ffuf command for endpoint fuzzing:** Fuzz for valid IDs rapidly:
  `ffuf -w wordlists/ids.txt -u https://api.target.com/v1/users/FUZZ -H "Authorization: Bearer YOUR_TOKEN_HERE" -mc 200,201 -fs 42` (Filter size 42 to ignore empty default responses).
- **How to use Burp Comparer to spot differences in responses:** Send a baseline request (your own ID) and a targeted request (victim's ID) to Comparer. Strip out CSRF tokens, nonces, and timestamps. Look strictly for data differences (e.g., changed names, leaked emails).

## 9. Triage: Is it actually an IDOR?

How to confirm it's a valid finding vs intended behavior:
- **What response differences confirm exploitation:** The response MUST return the victim's private data or definitively confirm a state change. A `200 OK` with an empty array `[]` or a generic `{"success": true}` (when the backend actually failed) is often a false positive. **Always test with two accounts you own (Account A modifying Account B).**
- **How to document it properly for a report:** Provide step-by-step reproduction instructions. Include the raw HTTP request showing Account A's authorization token with Account B's ID, followed by the raw HTTP response proving Account B's data was retrieved or altered.
- **Severity scoring guide:**
  - **Critical (9.0+):** Full Account Takeover, reading credit card info, adding unauthorized secondary admins.
  - **High (7.0-8.9):** Deleting major user assets (campaigns, tickets), modifying user profiles, dumping private report data.
  - **Medium (4.0-6.9):** Leaking secondary emails, phone numbers, or metadata (like issue dates/certifications).
  - **Low (0.0-3.9):** Leaking non-sensitive object IDs, reading data that is otherwise functionally public.

## 10. Report Template

```markdown
**Title:** Insecure Direct Object Reference (IDOR) in `[Endpoint/Mutation]` allows `[Impact, e.g., reading other users' payment data]`

**Description:**
Hello `[Company Name]` Security Team,

I have discovered an Insecure Direct Object Reference (IDOR) vulnerability on the `[Endpoint/Mutation]` endpoint. This endpoint fails to validate whether the `[Parameter Name]` belongs to the authenticated user making the request. As a result, an attacker can `[Read/Modify/Delete]` data belonging to any other user on the platform.

**Vulnerable Endpoint / Mutation:**
`[GET/POST/PUT] https://api.target.com/v1/example/endpoint`
Parameter: `[id/user_id/campaign_id]`

**Steps to Reproduce:**
1. Create two accounts on the platform: Attacker (Account A) and Victim (Account B).
2. Log into Account B, navigate to `[Feature]`, and create a new `[Object]`. Note the `[Object ID]` (e.g., `12345`).
3. Log into Account A and intercept the web traffic using Burp Suite.
4. Perform `[Action]` on Account A's own `[Object]`.
5. Send the intercepted request to Burp Repeater.
6. Replace Account A's `[Object ID]` with Account B's `[Object ID]` (`12345`).
7. Send the request. Observe the `200 OK` response containing Account B's sensitive data: `[Insert snippet of leaked data]`.

**Impact:**
An attacker can maliciously `[Read/Modify/Delete]` the `[Object]` of any user. This leads to a severe breach of confidentiality and integrity, potentially exposing PII `[or causing financial damage/account takeover]`.

**Remediation:**
Implement strict access control checks on the server side. Ensure that the object corresponding to the provided ID explicitly belongs to the user context established by the authenticated session token before returning or modifying any data.

**Attachments:**
- `poc_request.txt`
- `poc_response_leak.txt`
- `video_poc.mp4`
```

