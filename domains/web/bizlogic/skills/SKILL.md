---
name: bizlogic-hunting
description: Use when hunting Business Logic Flaws in a business target. Ordered prerequisites, signals, techniques, validation bar and false-positive rules.
---

# Business Logic Flaws — hunting skill

<!-- GENERATED from db/wks.db by wks/skillgen.py. DO NOT HAND-EDIT.
     Edit the rows (or ingest better research) and re-run:
     python -m wks.skillgen -->

> surface `business` · CWE CWE-840 · OWASP A04:2021
> evidence: 26 items, 21 supported, 6 FP rules, 2 chains
> maturity: **mature**

The application performs each step correctly in isolation but enforces no invariant across the sequence, so the sequence itself is the attack.

**Also called:** business logic, workflow bypass, price manipulation, coupon abuse, purchase flow manipulation


## Prerequisites (do not start without these)

- A business-logic flaw in a multi-step workflow exists when the server does not require the steps in order and does not roll back the actions a partially completed step already spawned.
  - **Disproof:** The server rejects any out-of-order or out-of-sequence request to a later step, and every effect produced by an incomplete step is reverted when the step is abandoned, cancelled or its transaction is rolled back.
  - Sources: <https://cwe.mitre.org/data/definitions/841.html> · <https://wstg.owasp.org/v4.2/4-Web_Application_Security_Testing/10-Business_Logic_Testing/06-Testing_for_the_Circumvention_of_Work_Flows>

## Techniques (what to change)

- Weaknesses in this category identify some of the underlying problems that commonly allow attackers to manipulate the business logic of an application. _(unverified)_
  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Weaknesses in this category identify some of the underlying problems that commonly allow a".
  - Sources: <https://cwe.mitre.org/data/definitions/840.html> · <https://wstg.owasp.org/v4.2/4-Web_Application_Security_Testing/10-Business_Logic_Testing/06-Testing_for_the_Circumvention_of_Work_Flows>
- Comments: The "Business Logic" term generally reflects product-specific logic errors that can be characterized by various weaknesses related to issues such as access control, workflow, input validation, etc. _(unverified)_
  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Comments: The "Business Logic" term generally reflects product-specific logic errors that ".
  - Sources: <https://cwe.mitre.org/data/definitions/840.html> · <https://wstg.owasp.org/v4.2/4-Web_Application_Security_Testing/10-Business_Logic_Testing/06-Testing_for_the_Circumvention_of_Work_Flows>
- The "Business Logic" term is generally used to describe issues that require domain-specific knowledge or "business rules" to determine if they are weaknesses or vulnerabilities, instead of legitimate behavior. _(unverified)_
  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "The "Business Logic" term is generally used to describe issues that require domain-specifi".
  - Sources: <https://cwe.mitre.org/data/definitions/840.html> · <https://wstg.owasp.org/v4.2/4-Web_Application_Security_Testing/10-Business_Logic_Testing/06-Testing_for_the_Circumvention_of_Work_Flows>
- A once-per-transaction limit enforced only in the forward UI flow is bypassed by navigating back to the discount step, because the server-side count is not tied to the transaction.
  - **Disproof:** The applied-discount set is stored server-side against the transaction id and the checkout step recomputes it, so returning to the discount page cannot add a second entry and the tendered total reflects only the permitted one.
  - Sources: <https://cwe.mitre.org/data/definitions/837.html> · <https://wstg.owasp.org/v4.2/4-Web_Application_Security_Testing/10-Business_Logic_Testing/05-Test_Number_of_Times_a_Function_Can_Be_Used_Limits>
- When the application authorises on the domain extracted from an email address, differing parsers let an address that passes validation be interpreted as a different domain, granting access to the restricted area.
  - **Disproof:** A single canonical, RFC-conformant parser is used for both registration-time validation and every later authorisation decision, so the domain used for the access decision is byte-identical to the one that was validated.
  - Sources: <https://cwe.mitre.org/data/definitions/178.html> · <https://portswigger.net/web-security/logic-flaws/examples>
- An endpoint that encrypts attacker-controlled input with the server's key and returns the ciphertext becomes an oracle whenever another endpoint accepts ciphertext under the same algorithm.
  - **Disproof:** No other input in the application accepts data encrypted under the same key and algorithm, or the encryption is bound to a per-session or per-record context so a ciphertext produced by the oracle is not accepted elsewhere.
  - Sources: <https://cwe.mitre.org/data/definitions/840.html> · <https://portswigger.net/web-security/logic-flaws/examples>
- A numeric business rule validated only as within-an-upper-bound passes for a negative input, so a balance check approves a transfer that moves funds in the opposite direction to the one requested.
  - **Disproof:** The server rejects values below a stated lower bound, coerces the amount to an unsigned or fixed-point type before the comparison, or re-derives the amount server-side rather than trusting the submitted parameter.
  - Sources: <https://cwe.mitre.org/data/definitions/840.html> · <https://portswigger.net/web-security/logic-flaws/examples>
- Where one server-side script dispatches on the presence of a parameter, deleting the parameter name selects a different branch, so an attacker reaches code paths the UI never exposes. _(unverified)_
  - **Disproof:** Every branch is selected by an explicit, validated parameter value rather than by parameter presence, and omitting a mandatory field is rejected with a validation error before any state is read or written.
  - Sources: <https://portswigger.net/web-security/logic-flaws/examples> · <https://wstg.owasp.org/v4.2/4-Web_Application_Security_Testing/10-Business_Logic_Testing/02-Test_Ability_to_Forge_Requests>
- When a workflow grants a durable credit at an intermediate step and does not roll it back on cancellation, an attacker accumulates credit by repeatedly starting a transaction and abandoning it without ever paying.
  - **Disproof:** The intermediate step reserves rather than grants the credit, and the reservation is released when the transaction is cancelled, so the account balance is unchanged after a start-then-abandon cycle.
  - Sources: <https://portswigger.net/web-security/logic-flaws> · <https://wstg.owasp.org/v4.2/4-Web_Application_Security_Testing/10-Business_Logic_Testing/06-Testing_for_the_Circumvention_of_Work_Flows>

## Tests

- To decide this case, observe: Discard the race-condition report when the double effect appeared in a single interleaved pair and does not recur over dozens of repetitions, because one anomalous outcome is indistinguishable from scheduler noise and from your own client's retry. _(unverified)_
  - **Disproof:** This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (bizlogic.fprule.single_interleaved_pair_is_not_a_race) states the full boundary.
  - Sources: <https://httpwg.org/specs/rfc9110.html> · <https://projectdiscovery.io/blog/inside-the-benchmark-pp-architectures-finding-walkthroughs-and-what-each-scanner-actually-caught>
- To decide this case, observe: Now issue multiple requests to that same endpoint in quick succession and see whether you can overrun the limit, which is the procedure the web-security curriculum describes.
  - **Disproof:** This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (bizlogic.validation.single_use_redemption_sequential_then_parallel) states the full boundary.
  - Sources: <https://cwe.mitre.org/data/definitions/840.html> · <https://portswigger.net/web-security/race-conditions>
- To decide this case, observe: A reportable finding needs three things together: a stated rule the application is supposed to enforce, an observed deviation from it, and a consequence.
  - **Disproof:** This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (bizlogic.fp_rule.scanner_output_alone_is_not_a_logic_finding) states the full boundary.
  - Sources: <https://cwe.mitre.org/data/definitions/840.html> · <https://portswigger.net/web-security/logic-flaws>
- To decide this case, observe: The lookalike: you submit an order with quantity 99 or a 90 percent discount field, the response body echoes your figure back in a price or total field, and it is filed as business-logic manipulation.
  - **Disproof:** This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (bizlogic.fp_rule.client_supplied_price_displayed_back_is_not_bypass) states the full boundary.
  - Sources: <https://cwe.mitre.org/data/definitions/840.html> · <https://portswigger.net/web-security/race-conditions>
- To decide this case, observe: Discard the report that says the endpoint validates nothing only when you could not establish the intended rule: without a stated cap, a documented maximum, or a control request showing the server enforces one, a large accepted amount proves nothing about a missing check.
  - **Disproof:** This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (bizlogic.fprule.absent_business_rule_needs_a_stated_rule) states the full boundary.
  - Sources: <https://httpwg.org/specs/rfc9110.html> · <https://projectdiscovery.io/blog/inside-the-benchmark-pp-architectures-finding-walkthroughs-and-what-each-scanner-actually-caught>

## Validation bar (how to prove it)

- A limit-overrun or single-use business-logic claim is confirmed only when parallel requests to the same single-use endpoint succeed where an identical sequential sequence fails, proving the limit was overrun rather than merely exercised twice.
  - **Disproof:** Refuted when a sequential two-request baseline produces the identical rejection as the parallel burst, or when the read-back counter advanced by exactly one across the concurrent burst with origin timestamps showing the requests were serialised; without a sequential-versus-parallel differential there is no overrun.
  - Sources: <https://cwe.mitre.org/data/definitions/840.html> · <https://portswigger.net/web-security/race-conditions>

## False-positive rules (when to reject it)

- A price, discount, or total that the server echoes back from the client request body without independently recomputing it is a finding only when the echoed figure is the figure that is charged, otherwise it is a display-only reflection of untrusted input.
  - **Disproof:** Refuted when the authoritative charge, credit, or entitlement is computed server-side from a stored price or entitlement table and the echoed client figure is never read by the settlement path; a reflection that no downstream consumer trusts cannot move money.
  - Sources: <https://cwe.mitre.org/data/definitions/840.html> · <https://portswigger.net/web-security/race-conditions>
- A logic flaw reported by an automated scanner with no stated business rule and no reproduced invariant violation is not a finding, because the weakness class is defined as not automatically detectable.
  - **Disproof:** The report supplies a stated business rule, a concrete request sequence that violates it, and evidence the violation persisted, so the claim rests on reproduced invariant violation rather than on tool output.
  - Sources: <https://cwe.mitre.org/data/definitions/840.html> · <https://portswigger.net/web-security/logic-flaws>
- Submitting a value outside the range a legitimate user would enter is a probe, not a finding, unless it changes a persisted outcome or reaches a code path the UI does not expose.
  - **Disproof:** The server normalises, clamps or type-coerces the out-of-range value to a semantically in-range value, and no persisted record, balance, or reached code path differs from the one produced by the corresponding legal input.
  - Sources: <https://cwe.mitre.org/data/definitions/840.html> · <https://portswigger.net/web-security/logic-flaws/examples>
- An oversized refund, credit, or payout accepted without a domain rule is a hypothesis, not a finding, until you state the rule the server should have enforced.
  - **Disproof:** If the same over-limit request is rejected with 4xx on a second attempt, or the amount was clamped to a documented maximum and the difference is only in what the response echoes back, there is no missing rule and the original report was a false positive after all.
  - Sources: <https://httpwg.org/specs/rfc9110.html> · <https://projectdiscovery.io/blog/inside-the-benchmark-pp-architectures-finding-walkthroughs-and-what-each-scanner-actually-caught> · <https://projectdiscovery.io/blog/from-detection-to-validation-fixing-broken-vulnerability-workflows>
- A concurrent-request test showing a duplicated result once, with no repeated-sample baseline, is a hypothesis; it survives only when the effect reproduces across many trials.
  - **Disproof:** If the server enforces a uniqueness constraint or an idempotency key on the endpoint, the second request returning 409 Conflict is the control working, and the race claim is a false positive produced by a client that did not read the rejection as a rejection.
  - Sources: <https://httpwg.org/specs/rfc9110.html> · <https://projectdiscovery.io/blog/inside-the-benchmark-pp-architectures-finding-walkthroughs-and-what-each-scanner-actually-caught>

## Evidence requirements

- A convincing observation for this class is: Read the outcome back from an independent session rather than trusting the response body: query the code's used counter, the account's credit balance, or the reservation table.
  - **Disproof:** Not evidence when the observable cannot be produced at all -- blind, server-side-only, or identical-in-every-case behaviour leaves nothing to show. The originating rule (bizlogic.validation.single_use_redemption_sequential_then_parallel) states the full boundary.
  - Sources: <https://cwe.mitre.org/data/definitions/840.html> · <https://portswigger.net/web-security/race-conditions>
- A convincing observation for this class is: What legitimately does not clear the bar is a response difference, a status code, or a parameter a scanner rated unusual, with no invariant shown to be violated.
  - **Disproof:** Not evidence when the observable cannot be produced at all -- blind, server-side-only, or identical-in-every-case behaviour leaves nothing to show. The originating rule (bizlogic.fp_rule.scanner_output_alone_is_not_a_logic_finding) states the full boundary.
  - Sources: <https://cwe.mitre.org/data/definitions/840.html> · <https://portswigger.net/web-security/logic-flaws>
- A convincing observation for this class is: The lookalike: you submit an order with quantity 99 or a 90 percent discount field, the response body echoes your figure back in a price or total field, and it is filed as business-logic manipulation.
  - **Disproof:** Not evidence when the observable cannot be produced at all -- blind, server-side-only, or identical-in-every-case behaviour leaves nothing to show. The originating rule (bizlogic.fp_rule.client_supplied_price_displayed_back_is_not_bypass) states the full boundary.
  - Sources: <https://cwe.mitre.org/data/definitions/840.html> · <https://portswigger.net/web-security/race-conditions>

## Chaining opportunities

- A workflow that grants a durable credit at an intermediate step without rollback, combined with a redemption endpoint that trusts the resulting balance, turns a repeatable start-then-abandon loop into realised financial loss.
  - **Disproof:** The credit is reserved rather than granted at the intermediate step and released on cancellation, or redemption recomputes entitlement from committed transactions, so the accumulated balance never becomes redeemable.
  - Sources: <https://cwe.mitre.org/data/definitions/841.html> · <https://wstg.owasp.org/v4.2/4-Web_Application_Security_Testing/10-Business_Logic_Testing/06-Testing_for_the_Circumvention_of_Work_Flows>
- A limit-overrun race on a single-use entitlement becomes realised financial loss only when the duplicated effect is quantified at settlement, so the chain runs from the check-then-act window to the amount actually over-issued.
  - **Disproof:** Refuted if a sequential baseline of the same requests already yields the duplicate effect, or if the read-back counter advanced by exactly one across the concurrent burst; without a parallel-versus-sequential differential and a quantified settlement over-issue, only a check-then-act code path has been shown, not financial impact.
  - Sources: <https://cwe.mitre.org/data/definitions/840.html> · <https://portswigger.net/web-security/race-conditions>

## Rejected before you report

- **An order endpoint that echoes a client-supplied discount or total in the response body allows business-logic manipulation of the charge.**
  - Killed by: The authoritative total is recomputed server-side at settlement from the stored price table; the echoed client figure is rendered for display and never read by the ledger, so the money charged was unaffected.
  - Rule: A client figure echoed back is not a business-logic flaw until you show it is the value that is charged, credited, or debited. Find the authoritative computation in the settlement or ledger path first; a reflection no downstream consumer trusts is a UI-integrity issue at most.

## Chains to

- `race` (3 shared chain(s))

---
Full class document: `domains/web/bizlogic/knowledge/DIGEST.md` · retrieve more with `python -m wks.cli search "<query>" --class-id bizlogic`
