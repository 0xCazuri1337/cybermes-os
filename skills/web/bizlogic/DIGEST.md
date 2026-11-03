<!-- GENERATED from db/wks.db — do not edit -->
# Business Logic Flaws

> surface: `business` · CWE: CWE-840 · OWASP: A04:2021
> maturity: **mature** — 26 items, 14 supported, 2 FP rules, 2 chains

The application performs each step correctly in isolation but enforces no invariant across the sequence, so the sequence itself is the attack.

**Aliases:** business logic, workflow bypass, price manipulation, coupon abuse, purchase flow manipulation

## Technique

- **A numeric business rule validated only as within-an-upper-bound passes for a negative input, so a balance check approves a transfer that moves funds in the opposite direction to the one requested.**  
  `high_confidence` · score 0.96 · disproved by: The server rejects values below a stated lower bound, coerces the amount to an unsigned or fixed-point type before the comparison, or re-derives the amount server-side rather than trusting the submitted parameter.
  sources: <https://cwe.mitre.org/data/definitions/840.html> · <https://portswigger.net/web-security/logic-flaws/examples>
- **A once-per-transaction limit enforced only in the forward UI flow is bypassed by navigating back to the discount step, because the server-side count is not tied to the transaction.**  
  `high_confidence` · score 0.9015 · disproved by: The applied-discount set is stored server-side against the transaction id and the checkout step recomputes it, so returning to the discount page cannot add a second entry and the tendered total reflects only the permitted one.
  sources: <https://cwe.mitre.org/data/definitions/837.html> · <https://wstg.owasp.org/v4.2/4-Web_Application_Security_Testing/10-Business_Logic_Testing/05-Test_Number_of_Times_a_Function_Can_Be_Used_Limits>
- **An endpoint that encrypts attacker-controlled input with the server's key and returns the ciphertext becomes an oracle whenever another endpoint accepts ciphertext under the same algorithm.**  
  `high_confidence` · score 0.869 · disproved by: No other input in the application accepts data encrypted under the same key and algorithm, or the encryption is bound to a per-session or per-record context so a ciphertext produced by the oracle is not accepted elsewhere.
  sources: <https://cwe.mitre.org/data/definitions/840.html> · <https://portswigger.net/web-security/logic-flaws/examples>
- **When a workflow grants a durable credit at an intermediate step and does not roll it back on cancellation, an attacker accumulates credit by repeatedly starting a transaction and abandoning it without ever paying.**  
  `high_confidence` · score 0.844 · disproved by: The intermediate step reserves rather than grants the credit, and the reservation is released when the transaction is cancelled, so the account balance is unchanged after a start-then-abandon cycle.
  sources: <https://portswigger.net/web-security/logic-flaws> · <https://wstg.owasp.org/v4.2/4-Web_Application_Security_Testing/10-Business_Logic_Testing/06-Testing_for_the_Circumvention_of_Work_Flows>
- **When the application authorises on the domain extracted from an email address, differing parsers let an address that passes validation be interpreted as a different domain, granting access to the restricted area.**  
  `high_confidence` · score 0.814 · disproved by: A single canonical, RFC-conformant parser is used for both registration-time validation and every later authorisation decision, so the domain used for the access decision is byte-identical to the one that was validated.
  sources: <https://cwe.mitre.org/data/definitions/178.html> · <https://portswigger.net/web-security/logic-flaws/examples>
- **Weaknesses in this category identify some of the underlying problems that commonly allow attackers to manipulate the business logic of an application.**  
  `high_confidence` · score 0.802 · disproved by: Refuted when: the same behaviour is absent when the single named control in the claim is present, and the control is shown to be present rather than assumed. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“Weaknesses in this category identify some of the underlying problems that common”) does not occur under a test that isolates that control.
  sources: <https://cwe.mitre.org/data/definitions/840.html> · <https://wstg.owasp.org/v4.2/4-Web_Application_Security_Testing/10-Business_Logic_Testing/06-Testing_for_the_Circumvention_of_Work_Flows>
- **Comments: The "Business Logic" term generally reflects product-specific logic errors that can be characterized by various weaknesses related to issues such as access control, workflow, input validation, etc.**  
  `high_confidence` · score 0.802 · disproved by: Refuted when: the same behaviour is absent when the single named control in the claim is present, and the control is shown to be present rather than assumed. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“Comments: The "Business Logic" term generally reflects product-specific logic er”) does not occur under a test that isolates that control.
  sources: <https://cwe.mitre.org/data/definitions/840.html> · <https://wstg.owasp.org/v4.2/4-Web_Application_Security_Testing/10-Business_Logic_Testing/06-Testing_for_the_Circumvention_of_Work_Flows>
- **The "Business Logic" term is generally used to describe issues that require domain-specific knowledge or "business rules" to determine if they are weaknesses or vulnerabilities, instead of legitimate behavior.**  
  `high_confidence` · score 0.802 · disproved by: Refuted when: the same behaviour is absent when the single named control in the claim is present, and the control is shown to be present rather than assumed. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“The "Business Logic" term is generally used to describe issues that require doma”) does not occur under a test that isolates that control.
  sources: <https://cwe.mitre.org/data/definitions/840.html> · <https://wstg.owasp.org/v4.2/4-Web_Application_Security_Testing/10-Business_Logic_Testing/06-Testing_for_the_Circumvention_of_Work_Flows>

## Test

- **To decide this case, observe: Now issue multiple requests to that same endpoint in quick succession and see whether you can overrun the limit, which is the procedure the web-security curriculum describes.**  
  `high_confidence` · score 0.8885 · disproved by: This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (bizlogic.validation.single_use_redemption_sequential_then_parallel) states the full boundary.
  sources: <https://cwe.mitre.org/data/definitions/840.html> · <https://portswigger.net/web-security/race-conditions>

## Validation

- **A limit-overrun or single-use business-logic claim is confirmed only when parallel requests to the same single-use endpoint succeed where an identical sequential sequence fails, proving the limit was overrun rather than merely exercised twice.**  
  `high_confidence` · score 0.952 · disproved by: Refuted when a sequential two-request baseline produces the identical rejection as the parallel burst, or when the read-back counter advanced by exactly one across the concurrent burst with origin timestamps showing the requests were serialised; without a sequential-versus-parallel differential there is no overrun.
  sources: <https://cwe.mitre.org/data/definitions/840.html> · <https://portswigger.net/web-security/race-conditions>

## Fp Rule

- **Submitting a value outside the range a legitimate user would enter is a probe, not a finding, unless it changes a persisted outcome or reaches a code path the UI does not expose.**  
  `high_confidence` · score 0.8055 · disproved by: The server normalises, clamps or type-coerces the out-of-range value to a semantically in-range value, and no persisted record, balance, or reached code path differs from the one produced by the corresponding legal input.
  sources: <https://cwe.mitre.org/data/definitions/840.html> · <https://portswigger.net/web-security/logic-flaws/examples>

## Evidence

- **A convincing observation for this class is: Read the outcome back from an independent session rather than trusting the response body: query the code's used counter, the account's credit balance, or the reservation table.**  
  `high_confidence` · score 0.8335 · disproved by: Not evidence when the observable cannot be produced at all -- blind, server-side-only, or identical-in-every-case behaviour leaves nothing to show. The originating rule (bizlogic.validation.single_use_redemption_sequential_then_parallel) states the full boundary.
  sources: <https://cwe.mitre.org/data/definitions/840.html> · <https://portswigger.net/web-security/race-conditions>

## Chain Link

- **A workflow that grants a durable credit at an intermediate step without rollback, combined with a redemption endpoint that trusts the resulting balance, turns a repeatable start-then-abandon loop into realised financial loss.**  
  `high_confidence` · score 0.929 · disproved by: The credit is reserved rather than granted at the intermediate step and released on cancellation, or redemption recomputes entitlement from committed transactions, so the accumulated balance never becomes redeemable.
  sources: <https://cwe.mitre.org/data/definitions/841.html> · <https://wstg.owasp.org/v4.2/4-Web_Application_Security_Testing/10-Business_Logic_Testing/06-Testing_for_the_Circumvention_of_Work_Flows>
- **A limit-overrun race on a single-use entitlement becomes realised financial loss only when the duplicated effect is quantified at settlement, so the chain runs from the check-then-act window to the amount actually over-issued.**  
  `high_confidence` · score 0.842 · disproved by: Refuted if a sequential baseline of the same requests already yields the duplicate effect, or if the read-back counter advanced by exactly one across the concurrent burst; without a parallel-versus-sequential differential and a quantified settlement over-issue, only a check-then-act code path has been shown, not financial impact.
  sources: <https://cwe.mitre.org/data/definitions/840.html> · <https://portswigger.net/web-security/race-conditions>

## False-positive rules

- **Hypothesis:** An order endpoint that echoes a client-supplied discount or total in the response body allows business-logic manipulation of the charge.
  - **Invalidated by:** The authoritative total is recomputed server-side at settlement from the stored price table; the echoed client figure is rendered for display and never read by the ledger, so the money charged was unaffected.
  - **Rule:** A client figure echoed back is not a business-logic flaw until you show it is the value that is charged, credited, or debited. Find the authoritative computation in the settlement or ledger path first; a reflection no downstream consumer trusts is a UI-integrity issue at most.

## Related classes (via chains)

- `race` Race Conditions / TOCTOU (3 chains)
