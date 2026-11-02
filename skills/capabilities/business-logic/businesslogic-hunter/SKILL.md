---
name: businesslogic
description: "Exploiting logic flaws: price manipulation, state machine bypass, and race conditions in financial flows."
---

# Business Logic Bug Hunting

Expert playbook for identifying, bypassing, and escalating Business Logic vulnerabilities based on top-tier HackerOne findings ($10k+ payouts).

## 1. Core Patterns
*   **Recursive Resource Copying (GitLab #689314 - $12,000):**
    *   **Architectural Cause:** Logic allowing "Project Templates" to copy data from any project the user has access to, including private ones, into a new public project.
    *   **Endpoint:** `/api/v4/projects` (using `template_name`)
    *   **Payload:** Creating a project with `template_project_id=[PRIVATE_PROJECT_ID]` to exfiltrate confidential issues and code.
*   **Response Manipulation for Premium Access (Logitech #1070510):**
    *   **Architectural Cause:** Client-side validation of subscription status that trusts a boolean flag in the server response without re-verifying on the backend for every request.
    *   **Endpoint:** `/api/v1/user/profile`
    *   **Payload:** Intercepting the response and changing `"is_prime": false` to `"is_prime": true`.
*   **Total Price Manipulation (Upserve #364843):**
    *   **Architectural Cause:** Lack of validation for negative quantities or fractional values in the "Add to Cart" or "Update Quantity" logic.
    *   **Endpoint:** `/api/v1/cart/items`
    *   **Payload:** `quantity=-1` or `quantity=0.0001` to reduce the total bill to $0.01 or negative values.
*   **OTP/Verification Logic Bypass (Eternal #1330529 - $3,250):**
    *   **Architectural Cause:** Decoupling the "OTP Request" and "Action Execution" steps, allowing an attacker to use a valid OTP for one entity (e.g., their own account) to verify an action on another entity.
    *   **Endpoint:** `/api/v1/verify_otp`
    *   **Payload:** Supplying `entity_id=[VICTIM_ID]` with a `code` generated for `[ATTACKER_ID]`.
*   **Currency Arbitrage / Precision Rounding (PortSwigger #1677155):**
    *   **Architectural Cause:** Inconsistent exchange rate application or rounding errors when converting between multiple supported currencies.
    *   **Endpoint:** `/checkout/payment`
    *   **Payload:** Switching between USD and a weaker currency (e.g., ARS) at the final step where the exchange rate is stale or rounded in the user's favor.

## 2. Recon Checklist
*   **JS File Targets:** Search for `onSuccess`, `validatePayment`, `applyDiscount`, `checkSubscription`, `isTrial`, `canAccess`.
*   **Parameter Names:** `quantity`, `amount`, `price`, `currency`, `discount_code`, `is_premium`, `trial_end`, `seats`, `license_type`.
*   **Hidden Endpoint Discovery:** Check for `/api/admin/debug/override`, `/api/v1/internal/payouts`, `/api/v1/billing/preview`.
*   **Burp Extensions:** 
    *   **Turbo Intruder:** For testing race conditions in "Add Seat" or "Claim Reward" flows.
    *   **Match and Replace:** To automate response manipulation (e.g., replacing `false` with `true` for admin flags).
*   **ID Enumeration Types:** Check if sequential `order_id` or `invoice_id` allows viewing other users' sensitive billing data (Starbucks #141090).

## 3. ID/Target Discovery
*   **Trial Period Abuse:** Register multiple accounts to extend "one-time" trial benefits indefinitely.
*   **Referral Loop:** Invite your own alternate email addresses to earn referral credits (Shopify #1457471).
*   **Metadata in Invoices:** Extract `user_id` or `internal_id` from PDF invoices to target other API endpoints.

## 4. Bypass Techniques
*   **Negative/Zero Values (#364843):** Try `quantity=-1`, `amount=0`, or `price=0.01`.
*   **Parameter Overriding:** Add `?free_trial=true` or `&is_admin=1` to requests that handle user state updates.
*   **Response Manipulation (#1070510):** Change `403 Forbidden` to `200 OK` or modify JSON body flags: `"access": "denied"` -> `"access": "granted"`.
*   **Race Conditions (#2682392):** Send multiple concurrent requests to "Redeem Coupon" or "Withdraw Balance" to exceed limits.
*   **Stale State Abuse:** Open two tabs: one to initiate a purchase and another to cancel the subscription. Complete the purchase in the first tab.
*   **OTP Parameter Swap (#1330529):** Request OTP for your phone, but submit it to the endpoint along with the victim's email/ID.

## 5. High-Value Targets
1.  **Payment and Billing Gateways:** Price tampering and free upgrades.
2.  **Referral and Reward Systems:** Infinite credit loops.
3.  **Subscription/Plan Management:** Accessing "Pro" features on a "Free" plan (Lovable #3591764).
4.  **Order Fulfillment Workflows:** Changing shipping addresses for orders you don't own (Starbucks #141120).
5.  **Multi-Tenant Data Copying:** Exfiltrating data via "Import/Export" or "Template" functions (GitLab #689314).

## 6. Chaining Playbook
*   **IDOR + Business Logic → Full Data Leak:** Use IDOR to find a private project ID, then use the Template Copy logic to exfiltrate it (GitLab #689314).
*   **Response Manipulation + XSS → Admin ATO:** Bypass the login check via response manipulation, then use an admin-only feature to trigger a Stored XSS.
*   **Race Condition + Payout Logic → Financial Theft:** Trigger multiple concurrent "Withdraw" requests to drain a wallet beyond its balance.
*   **SSRF + Webhook Logic → Internal Network Pivot:** Use the "Test Webhook" feature to send requests to internal metadata services (HackerOne #2301565).

## 7. Variant-Specific: Multi-Tenant Data Exfiltration
The most critical Business Logic bugs often involve the accidental "flattening" of tenant boundaries during complex operations.
*   **The Flaw:** Functions that perform batch actions (like "Bulk Import" or "Project Templates") often use a system-level service account that has access to all data, failing to check if the *requesting user* has access to the *source data*.
*   **Report Reference:** GitLab #689314 ($12,000).

## 8. Automation
*   **Burp Intruder:** Fuzz `quantity` with values: `-1`, `0`, `0.5`, `999999999`, `null`, `false`.
*   **Turbo Intruder Script (Race Condition):**
    ```python
    def queueRequests(target, wordlist):
        engine = RequestEngine(endpoint=target.endpoint, concurrentConnections=30)
        for i in range(30):
            engine.queue(target.req, i)
    def handleResponse(req, interesting):
        table.add(req)
    ```
*   **Response Diffing:** Compare responses when the `is_trial` or `plan_level` parameters are modified.

## 9. Triage
*   **Critical ($10k+):** Direct financial theft, mass exfiltration of private tenant data, or full bypass of payment gateways (GitLab #689314).
*   **High ($3k-$7k):** Access to all "Premium" features for free, OTP bypass leading to account takeover (Eternal #1330529).
*   **Medium ($500-$2k):** Individual price manipulation, referral credit abuse, unauthorized access to other users' order history.
*   **Low ($100-$400):** Minor UI inconsistencies, bypassing cosmetic restrictions.

## 10. Report Template
```markdown
## Summary
A Business Logic vulnerability was identified in the `[FUNCTIONALITY - e.g., Project Templates]` of `[APPLICATION]`. An attacker can [IMPACT - e.g., exfiltrate private project data] due to [CAUSE - e.g., a lack of authorization checks during the cloning process].

## Steps to Reproduce
1. Log in as a low-privileged user.
2. Identify a private [RESOURCE ID] that you do not own.
3. Trigger the `[VULNERABLE ENDPOINT]` with the following payload: `[PAYLOAD]`.
4. Observe that the private data has been [ACTION - e.g., copied into your public workspace].

## Supporting Evidence
- **Vulnerable Endpoint:** `[ENDPOINT]`
- **Payload:** `[PAYLOAD]`
- **HackerOne Reference:** Based on patterns in Report #[ID] (e.g., #689314)

## Impact
[Detailed impact: e.g., Unauthorized access to confidential source code and internal issues of any organization.]
```
