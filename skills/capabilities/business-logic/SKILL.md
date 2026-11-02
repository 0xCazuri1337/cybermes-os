---
name: business-logic
description: "Canonical business-logic capability: price/quantity manipulation, workflow bypass, race conditions, privilege escalation via business processes, and CAPTCHA bypass. Consolidates 4 sub-skills. Use when hunting or validating business-logic-related vulnerabilities."
sources: consolidated
---

# BUSINESS-LOGIC — Canonical Capability

## 1. Identity and purpose

This is the single primary executable capability for business-logic security testing. It consolidates 4 previously separate sub-skills into one operational entry point while preserving all source content in `references/` and the original sub-skill directories for rollback.

Primary objectives:
- Discover business-rule flaws in pricing, quantity, workflow, authorization, referral/reward, and verification flows.
- Validate price/quantity manipulation, multi-step workflow bypass, race conditions, privilege escalation, and CAPTCHA bypass with proof.
- Produce reproducible, impact-rated findings with remediation guidance.
- Reject findings that are purely theoretical or scanner-derived without demonstrated business impact.

## 2. Scope

In scope:
- Price and quantity manipulation in carts, checkout, orders, invoices, and billing.
- Multi-step workflow bypass (registration, verification, checkout, approval, password reset, MFA).
- Race conditions in coupons, rewards, transfers, withdrawals, and inventory.
- Privilege escalation via business processes (role assignment, tenant boundaries, invitations).
- Referral/reward/credit abuse and free-trial abuse.
- CAPTCHA bypass (client-side-only validation, replay, cross-endpoint, reactive enforcement, static/predictable).
- Currency/rounding arbitrage and archived-price swaps.

Out of scope (hand off):
- Pure IDOR/object-level authorization without a business-rule angle -> `hunt-idor` / `authorization`.
- Pure SQL injection, SSRF, SSTI, XSS, etc. -> their own capabilities unless reached through a business-logic parameter.
- Infrastructure-only findings without a business-logic exploit path -> cloud/network capabilities.
- Generic rate-limit bypass without business impact -> `hunt-brute-force` / `rate_limit-hunting`.

## 3. Invocation and routing

Use this capability when:
- A target exposes checkout, cart, order, subscription, payment, verification, referral, reward, or coupon flows.
- You need to test business rules that automated scanners cannot detect.
- A finding involves price/quantity manipulation, workflow step skip, race condition, or privilege escalation via business process.
- A CAPTCHA gate protects a login, registration, payment, or reset endpoint.

Routing notes:
- Price/quantity and cart manipulation -> `references/businesslogic-hunter.md`, `references/testing-for-business-logic-vulnerabilities.md`.
- Hunting methodology with disclosed cases -> `references/hunt-business-logic.md`.
- CAPTCHA bypass -> `references/hunt-captcha-bypass.md`.
- Multi-step workflow and Burp-based testing -> `references/testing-for-business-logic-vulnerabilities.md`.
- Race-heavy flows -> also consult `hunt-race-condition`.

## 4. Inputs and outputs

Inputs:
- Target base URLs, account credentials (multiple roles/privilege levels), business requirements/user stories.
- Proxy captures (Burp Suite), request templates, product/cart identifiers, coupon codes.
- Optional: OpenAPI/Postman collections, mobile/SPA artifacts, payment provider sandbox.

Outputs:
- Confirmed or refuted business-logic findings with request/response proof.
- Reproduction steps, impact assessment (financial/privacy/state), and remediation guidance.
- False-positive rulings with disproof rationale.
- Business-rules-violated table (expected vs. actual).

## 5. Preconditions and authorization

- Confirm written authorization and scope before testing; include payment/checkout endpoints and test accounts.
- Use only test accounts and non-production data; never place real orders or charge real cards without explicit authorization.
- Respect rate limits; coordinate throttling for race-condition tests.
- Stop at account/tenant boundaries; do not access other users' orders/data beyond proof of control.
- Document any out-of-scope endpoint discovered and hand off rather than exploit.
- Do not perform real financial theft; demonstrate with $0.01/minimal-impact proofs in sandbox/test mode.

## 6. Reconnaissance

Recon steps:
1. Map all critical business workflows and their expected constraints (registration, checkout, auth, financial transactions).
2. Identify price/quantity/amount/currency/discount/coupon parameters in requests and JS bundles.
3. Discover hidden/internal endpoints: `/api/admin/debug/override`, `/api/v1/internal/payouts`, `/api/v1/billing/preview`, `/employee/`, `/staff/`, `/internal/`, `/summit/`.
4. Grep JS for `onSuccess`, `validatePayment`, `applyDiscount`, `checkSubscription`, `isTrial`, `canAccess`, `price`, `amount`, `total`.
5. Identify payment providers (Stripe, PayPal, Braintree, Smart2Pay) and webhook/callback endpoints.
6. Detect IP-based rate limiting and spoofable headers (`X-Forwarded-For`, `X-Real-IP`, `CF-Connecting-IP`).
7. Enumerate verification flows (email, phone/SMS, payment, CAPTCHA, age gates) and test skipping/replay.
8. Check for CAPTCHA field names: `g-recaptcha-response`, `captcha`, `captcha_token`, `captcha_answer`, `h-captcha-response`.

See `references/businesslogic-hunter.md` (recon checklist), `references/hunt-business-logic.md` (attack surface signals).

## 7. Detection methodology

Core detection flow:
1. Map workflows and document expected business rules/constraints.
2. Test price and quantity manipulation (negative, zero, fractional, extreme, overflow).
3. Test workflow step bypass (skip verification, payment, MFA, approval).
4. Test race conditions (coupon, transfer, reward, withdrawal) with concurrent requests.
5. Test referral/reward/credit abuse (self-referral, stacking, reuse, circular gift cards).
6. Test role/permission logic (mass assignment on role, tenant boundaries, invitation abuse, privilege retention).
7. Test CAPTCHA bypass (omit field, empty/null, replay, cross-endpoint, reactive threshold).
8. Validate each candidate with a second, independent request and, where possible, a second account/role.

References by phase:
- Price/quantity/workflow: `references/testing-for-business-logic-vulnerabilities.md`.
- Hunting/cases: `references/hunt-business-logic.md`, `references/businesslogic-hunter.md`.
- CAPTCHA: `references/hunt-captcha-bypass.md`.

## 8. Technique selection

Select techniques by flow and observed behavior:
- Cart/checkout with client-submitted totals -> price manipulation, currency swap, negative quantity.
- Multi-step flow with verification gates -> step skip via direct API call, token replay.
- Coupon/reward/transfer endpoints -> race condition via concurrent requests (Turbo Intruder).
- Role/invitation endpoints -> mass assignment (`role`, `isAdmin`, `verified`), privilege retention.
- CAPTCHA-protected endpoints -> omit field, empty/null, replay token, cross-endpoint, threshold bypass.
- Payment webhooks -> missing HMAC validation, fake success POST.
- Internal/employee surfaces -> unauthenticated access, path traversal variants.

See `references/hunt-business-logic.md` (bypass techniques table), `references/hunt-captcha-bypass.md`.

## 9. Execution steps

1. Establish a baseline request for each flow (method, headers, body, auth, expected response).
2. Map expected business rules; document constraints (min/max quantity, coupon single-use, withdrawal limits).
3. Replay with one controlled change at a time; record status, body, timing, and headers.
4. For authorization/tenant tests, use two accounts/roles and compare responses (diffing).
5. For race conditions, send N concurrent requests (Turbo Intruder or background `&`); document success rate.
6. For CAPTCHA, omit the field entirely first; then empty/null; then replay; then cross-endpoint.
7. Confirm exploitability with a clean reproduction (curl or raw HTTP) in a fresh session.
8. Stop and document when a vector is not exploitable or out of scope.

## 10. Tool usage

- Proxy: Burp Suite (Repeater, Intruder, Comparer, Turbo Intruder, Logger++), mitmproxy.
- Discovery: ffuf, dirsearch, httpx, grep over JS bundles.
- Automation: Python requests/httpx, curl, jq, concurrent request scripts.
- Evidence: screenshots, saved requests/responses, canary values, timing data, order IDs.
- CAPTCHA: browser DevTools, Burp Repeater for field omission/replay.

See `references/testing-for-business-logic-vulnerabilities.md` (tools table), `references/hunt-business-logic.md`.

## 11. Payloads and test cases

Representative test cases (adapt to target):

Price/quantity:
- `quantity=-1`, `quantity=0`, `quantity=0.001`, `quantity=999999999`, `quantity=2147483647`.
- `price=0`, `price=0.01`, `amount=0.01`, `total=0.01`.
- Currency swap: USD -> ARS/low-value currency at final step.
- Mass assignment: add `price`, `amount`, `total`, `discount`, `role`, `isAdmin`, `verified` to body.

Workflow bypass:
- Skip email/phone verification: hit post-verification API directly with unverified session.
- Skip payment: cart -> confirm (omit payment step).
- Skip MFA: login -> protected resource directly.
- Replay verification token on different account/email.
- Repeat one-time action (coupon, reward) N times.

Race conditions:
- Concurrent coupon application (N parallel POSTs).
- Concurrent transfer of full balance to two recipients.
- Concurrent reward claim.

Referral/reward:
- Self-referral with own email/alternate addresses.
- Coupon stacking: `["SAVE10","WELCOME20","VIP50"]`.
- Circular gift card purchase; partial refund abuse.
- Earn points on order -> cancel order -> check points retained.

CAPTCHA:
- Omit CAPTCHA field entirely.
- Empty/null/`0`/`undefined` value.
- Replay previously solved token.
- Same token on different endpoint/action.
- Before threshold N (first N-1 requests bypass).

Internal surfaces:
- Unauthenticated GET to `/employee/`, `/internal/`, `/staff/`, `/summit/`, `/admin/`.
- Path traversal: `/employee/../employee/`.

## 12. Evidence

Each finding must include:
- Exact request and response (raw HTTP).
- Authentication context and account/role used.
- Canary values or modified fields and server-side effect (order ID, balance change, access granted).
- For race conditions: success count, timing, and reproducibility rate.
- For CAPTCHA: successful state-changing action without valid token.
- Business rules violated (expected vs. actual table).
- Impact assessment and affected data/financial scope.

## 13. Reproduction and validation

- Reproduce with curl or a saved raw request in a clean session.
- Validate with a second account/role where applicable.
- Confirm persistence for mass assignment and stored issues.
- For race conditions, repeat multiple times and document success rate.
- For blind/async issues, provide callback or timing proof.
- Mark as refuted if execution or unauthorized access cannot be demonstrated.
- Gate 0: attacker can DO it now; victim LOSES something concrete; reproducible in 10 minutes.

## 14. False-positive rejection

Reject or downgrade when:
- A field is reflected/echoed but not persisted or enforced server-side.
- An endpoint returns 401/403/404 without data leakage or state change.
- A privileged field is accepted in the response but not stored or enforced.
- A CAPTCHA is bypassable only in the UI but server validates.
- Race condition succeeds only under unrealistic concurrency or doesn't change state.
- Price manipulation only affects display, not charged amount.
- Internal pages return 404/redirect without data.
- Response differences are due to caching, localization, or benign metadata.
- Impact is purely theoretical with no concrete financial/privacy/state loss.

## 15. Impact

Impact guidance:
- Critical: direct financial theft, free goods at scale, mass exfiltration of tenant data, payment gateway bypass, account takeover via OTP/verification bypass.
- High: premium features for free, unauthorized access to other users' orders/PII, brute-force gate removal, race-condition double-spend.
- Medium: individual price manipulation, referral credit abuse, CAPTCHA bypass enabling automation, unauthorized monitoring.
- Low: minor UI inconsistencies, cosmetic restriction bypass, non-exploitable anomalies.

Always tie impact to business risk and data scope; avoid severity inflation from configuration presence alone.

## 16. Reporting

Report template:
- Summary: endpoint, vulnerability type, action, impact.
- Scope/authorization: test accounts, test window.
- Steps to reproduce: numbered, minimal.
- Proof of concept: raw request/response or script.
- Business rules violated: expected vs. actual table.
- Impact: business and data/financial scope.
- Remediation: server-side validation, atomic transactions, idempotency keys, rate limiting, CAPTCHA server-side enforcement, access control.
- References: OWASP A04:2021 Insecure Design, disclosed report IDs.

## 17. Failure modes

- Surface not fully discovered -> expand recon, check mobile/SPA, versions, content types, JS bundles.
- Auth required but no test account -> request credentials or scope clarification; do not bypass without authorization.
- WAF/gateway blocks payloads -> try content-type confusion, encoding, or parser differentials.
- Rate limiting stops testing -> coordinate throttling, use allowed test windows, or hand off.
- Race condition inconclusive -> repeat with higher concurrency and precise timing (Turbo Intruder).
- CAPTCHA bypass unclear -> verify server-side validation by direct API call, not UI.
- Inconclusive authorization result -> repeat with fresh sessions and diff responses; mark as not confirmed if ambiguous.

## 18. References

All 4 sub-skill references are preserved and must resolve:

| Reference | Sub-capability | Load when |
|---|---|---|
| `references/businesslogic-hunter.md` | `businesslogic-hunter` | Core patterns, recon, bypass techniques, triage |
| `references/hunt-business-logic.md` | `hunt-business-logic` | Hunting methodology, disclosed cases, root causes |
| `references/hunt-captcha-bypass.md` | `hunt-captcha-bypass` | CAPTCHA bypass patterns and impact chains |
| `references/testing-for-business-logic-vulnerabilities.md` | `testing-for-business-logic-vulnerabilities` | Burp-based testing workflow and output format |

Original sub-skills remain intact under `businesslogic-hunter/`, `hunt-business-logic/`, `hunt-captcha-bypass/`, and `testing-for-business-logic-vulnerabilities/`.

## 19. Testing and mastery

- Validate with the capability tests in `tests/test_business_logic_capability.py`.
- Confirm all referenced files resolve and are non-empty.
- Confirm migration map paths/hashes/status are accurate.
- Practice on authorized labs: PortSwigger business logic labs, OWASP crAPI, Juice Shop.
- Mastery criteria: independently discover, validate, and report a business-logic finding with full reproduction, impact, and remediation.

---

Original sub-skills remain intact for reversibility. See `migration_map.json`.


## Knowledge sources

- WKS bug classes: bizlogic, race
- Domain knowledge: bizlogic, race
- WKS remains the structured source of truth; retrieve and validate items through WKS rather than duplicating the full corpus in this skill.
- Research and learning material is mapped in `stage-a/knowledge-source-map.json` and must be validated before promotion.
