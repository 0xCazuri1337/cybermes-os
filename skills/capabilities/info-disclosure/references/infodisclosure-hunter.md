# infodisclosure-hunter

Source: `infodisclosure-hunter/SKILL.md` (preserved verbatim during consolidation).

---

---
name: infodisclosure
description: "Identifying sensitive data leaks: PII, source code, debug endpoints, and cloud metadata exposure."
---

# SKILL: Information Disclosure (INFODISCLOSURE)

Mastery of Information Disclosure involves identifying endpoints that leak sensitive metadata, internal configurations, or PII (Personally Identifiable Information) due to architectural oversights or misconfigurations.

## 1. Core Patterns

### Over-privileged API Response (IDOR/Join Leak)
*   **Architectural Cause:** Failure to filter sensitive fields during JSON serialization of a many-to-many relationship.
*   **H1 Report:** [#188719](https://hackerone.com/reports/188719) - $10,000
*   **Endpoint:** `GET /skills`
*   **Payload:** Accessing the endpoint returned a list of skills with an `evidence` field containing private report titles of other users.

### Apache Tomcat Default Servlet (CVE-2025-24813)
*   **Architectural Cause:** Combination of write-enabled Default Servlet and partial PUT support leading to source code disclosure.
*   **H1 Report:** [#3031518](https://hackerone.com/reports/3031518) - $4,323
*   **Endpoint:** `PUT /index.jsp` (with `Range` headers)
*   **Payload:** Exploiting the default servlet to read JSP source or write malicious files.

### Stack Trace Leak via Encoding Bypass
*   **Architectural Cause:** Web framework fails to decode parameters with malformed encodings, triggering a debug error page in production.
*   **H1 Report:** [#460545](https://hackerone.com/reports/460545) - $3,500
*   **Endpoint:** `https://customers.gitlab.com/admin/users?utf8=%E2%9C%93&search=%ff`
*   **Payload:** Using `%ff` to force an `Encoding::CompatibilityError` and leak `secret_key_base`.

### Public Cloud Storage (S3) ACL Misconfig
*   **Architectural Cause:** IAM/Bucket Policy set to `PublicRead` for user-generated content instead of using Signed URLs.
*   **H1 Report:** [#1021906](https://hackerone.com/reports/1021906) - $2,900
*   **Endpoint:** `https://[bucket-name].s3.amazonaws.com/[UUID]/[FILENAME].png`
*   **Payload:** Direct browsing of user-uploaded images via leaked or guessed UUIDs.

### Marketplace RPC Metadata Leak
*   **Architectural Cause:** Internal RPC calls exposed via a gateway without proper field masking.
*   **H1 Report:** [#128911](https://hackerone.com/reports/128911) - $1,500
*   **Endpoint:** `POST /marketplace/_rpc`
*   **Payload:** Calling `getPopulousUser` with a valid `userId` to leak full PII including internal employee flags.

### Exposed Framework Actuators (Spring Boot)
*   **Architectural Cause:** Default configuration of Spring Boot management endpoints exposed without authentication.
*   **H1 Report:** [#231389](https://hackerone.com/reports/231389) - $1,500
*   **Endpoint:** `GET /manage/env` or `GET /actuator/heapdump`
*   **Payload:** Extracting database credentials from the `/env` endpoint.

## 2. Recon Checklist
- [ ] **JS File Analysis:** Search for `API_KEY`, `SECRET`, `internal_url`, and hardcoded `UUID` patterns.
- [ ] **Hidden Parameter Discovery:** Fuzz for `?debug=true`, `?admin=1`, `?source=1`, `?env=prod`.
- [ ] **Endpoint Discovery:** Use `ffuf` with `raft-large-files.txt` specifically for `.env`, `.git`, `.bak`, and `.php~`.
- [ ] **Burp Extensions:** Use **SecretFinder** (for JS leaks) and **Cloud Storage Sifter** (for S3/GCP/Azure buckets).
- [ ] **ID Enumeration:** Test for sequential vs UUID-based IDs in paths like `/api/v1/user/{id}/profile`.

## 3. ID/Target Discovery
- **Predictable UUIDs:** Check if the application uses `v1` UUIDs (time-based) which can be predicted if you know the creation time.
- **Leaked IDs in Metadata:** Check `X-Request-Id` headers or `meta` tags in the HTML source for internal IDs.
- **Social Engineering ID Harvest:** Use publicly available profiles to find `username` or `uid` to use as targets in API calls.
- **Error-based ID Discovery:** Trigger errors (e.g., sending an array instead of a string) to see if the error message leaks valid IDs.

## 4. Bypass Techniques
- **Spring Path Normalization:** `GET /api/v1/..;/..;/manage/env` - Using the semicolon to trick the front-end proxy.
- **GraphQL Introspection Bypass:** `POST /graphql` with payload `{"query": "query { __schema { queryType { name } } }"}`.
- **Source Map Reconstruction:** Append `.map` to any JS file path (e.g., `app.min.js.map`) to reconstruct original source.
- **Cloud Metadata IMDSv2 Bypass:** Forcing `PUT` requests to `http://169.254.169.254/latest/api/token` then accessing meta-data.
- **Content-Type Confusion:** Requesting `Accept: application/xml` on a JSON endpoint to trigger verbose error dumps.
- **Double Encoding:** Using `%252e%252e%252f` to bypass WAFs that only decode the first layer of URL encoding.

## 5. High-Value Targets
1.  **Cloud Credentials:** `/env`, `/.aws/credentials`, `/metadata/v1/` (EC2/GCP).
2.  **App Secrets:** `secret_key_base`, `JWT_SECRET`, `IDP_CERT`.
3.  **PII:** Full name, phone, address, and SSN in API responses.
4.  **Database Dumps:** `/backup.sql`, `/dump.gz`, `/db_backup/`.
5.  **Internal Network Maps:** `/server-status`, `/netstat`, `/proc/net/tcp`.

## 6. Chaining Playbook
- **Info Disclosure + IDOR → Account Takeover:** Leak user IDs via `/users/search` and use them in `/password-reset` endpoint.
- **Secret Key Leak + Cookie Forge → RCE:** Leak `secret_key_base` (#460545) and use it to sign a malicious session cookie.
- **Heapdump Disclosure + Credential Extraction → Database Access:** Download `/heapdump` (#231389) and use `jhat` to find DB passwords.
- **S3 Public Read + File Upload → XSS/Stored XSS:** Find a public S3 bucket (#1021906), upload an `.html` file with JS.

## 7. Variant-Specific: Application Secret Leaks (Highest Payout)
The leak of Application Secrets (like `secret_key_base` in Ruby on Rails) is the highest-paying Information Disclosure variant. 
- **Impact:** It allows attackers to sign their own session cookies, potentially leading to **full RCE**.
- **Detection:** Look for error pages (especially `404` or `500`) that dump the entire environment (`ENV` hash).
- **Payload:** Fuzzing with `%E2%9C%93` (UTF-8 checkmark) or `%ff` (malformed UTF-8) in Rails.

## 8. Automation
- **Burp Intruder Strategy:** Use "Cluster Bomb" with config file names and common subdirectories.
- **ffuf Command:**
  ```bash
  ffuf -w wordlists/common_configs.txt -u https://TARGET/FUZZ -mr "DB_PASSWORD|AWS_ACCESS_KEY"
  ```
- **Response Diffing:** Identify responses that contain "Sensitive" keywords or significantly larger byte counts.

## 9. Triage
- **Confirmation:** Verify the data is not public and contains actionable secrets or PII.
- **Severity Scoring:**
    - **Critical ($10k+):** Cloud root credentials, App secret keys leading to RCE.
    - **High ($3k - $7k):** Bulk PII, Database credentials, CVE-based source leaks.
    - **Medium ($1k - $2k):** Internal IP addresses, RPC metadata leaks.
    - **Low ($100 - $500):** Software versions, verbose error messages.

## 10. Report Template
```markdown
### Summary
The endpoint `[ENDPOINT]` is disclosing sensitive information `[TYPE]` due to `[CAUSE]`.

### Steps to Reproduce
1. Navigate to `[URL]`.
2. Intercept the request and add the payload `[PAYLOAD]`.
3. Observe the response containing `[SENSITIVE_DATA]`.

### Impact
An attacker can use this information to `[ESCALATION_PATH]`, leading to `[FINAL_IMPACT]`.

### Affected Component
`[URL/API/S3_BUCKET]`

### Suggested Mitigation
Restrict access to the endpoint and ensure sensitive fields are filtered during serialization.
```

