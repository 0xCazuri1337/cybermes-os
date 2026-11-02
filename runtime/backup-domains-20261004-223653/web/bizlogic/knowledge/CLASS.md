# Business Logic Flaws

## Definition

The application performs each step correctly in isolation but enforces no invariant across the sequence, so the sequence itself is the attack.

- **CWE:** CWE-840
- **OWASP:** A04:2021
- **Surface:** business
- **Aliases:** ["business logic", "workflow bypass", "price manipulation", "coupon abuse", "purchase flow manipulation"]

Canonical home for `bizlogic`. Rendered from `db/wks.db` by `tools/taxonomy/build_taxonomy.py` — edit the rows, not this file.

## Root Cause

Not yet researched.

## Preconditions

**A business-logic flaw in a multi-step workflow exists when the server does not require the steps in order and does not roll back the actions a partially completed step already spawned.**

WSTG's workflow-circumvention test case states both halves of the invariant, and a workflow is only safe when both hold. The application's business logic must require that the user complete specific steps in the correct/specific order, and if the workflow is terminated without correctly completing, all actions and spawned actions are rolled back or canceled. The applications business process must have checks to ensure that the user's transactions/actions are proceeding in the correct/acceptable order and if a transaction triggers some sort of action, that action will be rolled back and removed if the transaction is not successfully completed. CWE-841 is the taxonomy counterpart: the product supports a session in which more than one behavior must be performed by an actor, but it does not properly ensure that the actor performs the behaviors in the required sequence, and by performing actions in an unexpected order, or by omitting steps, an attacker could manipulate the business logic of the product or cause it to enter an invalid state. Hunt this by driving the UI to a mid-workflow state, then abandoning it and checking whether the spawned effects persisted.

*Disproof:* The server rejects any out-of-order or out-of-sequence request to a later step, and every effect produced by an incomplete step is reverted when the step is abandoned, cancelled or its transaction is rolled back.

## Attack Surface

Surface: **business**.

The entry points and enabling conditions for this surface are enumerated under **Preconditions**; the observable signals are under **Detection**.

## Detection

**A convincing observation for this class is: Read the outcome back from an independent session rather than trusting the response body: query the code's used counter, the account's credit balance, or the reservation table.**

Derived from bizlogic.validation.single_use_redemption_sequential_then_parallel, which states the boundary for this class. The observation above is what a report must contain to be believed: an artifact the reviewer can re-check, not a claim the hunter asserts. A finding without it is an assertion.

*Disproof:* Not evidence when the observable cannot be produced at all -- blind, server-side-only, or identical-in-every-case behaviour leaves nothing to show. The originating rule (bizlogic.validation.single_use_redemption_sequential_then_parallel) states the full boundary.

**A convincing observation for this class is: What legitimately does not clear the bar is a response difference, a status code, or a parameter a scanner rated unusual, with no invariant shown to be violated.**

Derived from bizlogic.fp_rule.scanner_output_alone_is_not_a_logic_finding, which states the boundary for this class. The observation above is what a report must contain to be believed: an artifact the reviewer can re-check, not a claim the hunter asserts. A finding without it is an assertion.

*Disproof:* Not evidence when the observable cannot be produced at all -- blind, server-side-only, or identical-in-every-case behaviour leaves nothing to show. The originating rule (bizlogic.fp_rule.scanner_output_alone_is_not_a_logic_finding) states the full boundary.

**A convincing observation for this class is: The lookalike: you submit an order with quantity 99 or a 90 percent discount field, the response body echoes your figure back in a price or total field, and it is filed as business-logic manipulation.**

Derived from bizlogic.fp_rule.client_supplied_price_displayed_back_is_not_bypass, which states the boundary for this class. The observation above is what a report must contain to be believed: an artifact the reviewer can re-check, not a claim the hunter asserts. A finding without it is an assertion.

*Disproof:* Not evidence when the observable cannot be produced at all -- blind, server-side-only, or identical-in-every-case behaviour leaves nothing to show. The originating rule (bizlogic.fp_rule.client_supplied_price_displayed_back_is_not_bypass) states the full boundary.

## Exploitation

**Weaknesses in this category identify some of the underlying problems that commonly allow attackers to manipulate the business logic of an application.**

rowserheight(); 
 
 
 
 
 
 

 
 
 
 
 
 
 
 
 
 
 
 
 CWE Glossary Definition 
 
 
 
 
 
 
 

 
 
 div.collapseblock { display:inline} 
 

 
 
 
 
 
 CWE CATEGORY: Business Logic Errors 
 
 
 
 
 
 
 
 
 
 
 Category ID: 840
 
 

 
 
 Vulnerability Mapping : 
 PROHIBITED 
 This CWE ID must not be used to map to real-world vulnerabilities 
 
 
 
 
 
 
 

 

 
 
 
 
 
 

 
 
 
 
 
 
 Summary 
 
 
 Weaknesses in this category identify some of the underlying problems that commonly allow attackers to manipulate the business logic of an application. Errors in business logic can be devastating to an entire application. They can be difficult to find automatically, since they typically involve legitimate use of the application's functionality. However, many business logic errors can exhibit patterns that are similar to well-understood implementation and design weaknesses.
 
 
 
 

 
 
 

 
 Membership 
 
 
 
 
 
 
 Nature 
 Type 
 ID 
 Name

*Disproof:* This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Weaknesses in this category identify some of the underlying problems that commonly allow a".

**Comments: The "Business Logic" term generally reflects product-specific logic errors that can be characterized by various weaknesses related to issues such as access control, workflow, input validation, etc.**

d vulnerabilities)
 

 
 
 
 
 
 
 
 
 Reasons: 
 
 
 Category,
 
 
 
 Frequent Misuse
 
 
 
 
 
 
 
 
 
 Rationale: 
 This entry is a Category. Using categories for mapping has been discouraged since 2019. Categories are informal organizational groupings of weaknesses that can help CWE users with data aggregation, navigation, and browsing. However, they are not weaknesses in themselves.
 
 
 
 
 Comments: The "Business Logic" term generally reflects product-specific logic errors that can be characterized by various weaknesses related to issues such as access control, workflow, input validation, etc. Perform root cause analysis to determine what mistake led to the logic error. Consult the member weaknesses of this category.
 
 
 
 
 
 
 
 
 

 
 
 
 
 Notes 
 
 
 
 
 
 
 
 
 
 
 
 
 Terminology 
 
 
 The "Business Logic" term is generally used to describe issues that require domain-specific knowledge or "business rules" to determine if they are weaknesses or vulnerabilities, instead of legiti

*Disproof:* This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Comments: The "Business Logic" term generally reflects product-specific logic errors that ".

**The "Business Logic" term is generally used to describe issues that require domain-specific knowledge or "business rules" to determine if they are weaknesses or vulnerabilities, instead of legitimate behavior.**

e "Business Logic" term generally reflects product-specific logic errors that can be characterized by various weaknesses related to issues such as access control, workflow, input validation, etc. Perform root cause analysis to determine what mistake led to the logic error. Consult the member weaknesses of this category.
 
 
 
 
 
 
 
 
 

 
 
 
 
 Notes 
 
 
 
 
 
 
 
 
 
 
 
 
 Terminology 
 
 
 The "Business Logic" term is generally used to describe issues that require domain-specific knowledge or "business rules" to determine if they are weaknesses or vulnerabilities, instead of legitimate behavior. Such issues might not be easily detectable via automatic code analysis, because the associated operations do not produce clear errors or undefined behavior at the code level. However, many such "business logic" issues can be understood as instances of other weaknesses such as input validation, access control, numeric computation, order of operations, etc. 
 
 
 
 
 
 
 
 
 
 
 
 
 
 
 Research Ga

*Disproof:* This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "The "Business Logic" term is generally used to describe issues that require domain-specifi".

**A once-per-transaction limit enforced only in the forward UI flow is bypassed by navigating back to the discount step, because the server-side count is not tied to the transaction.**

WSTG's function-limits test case names the mechanism in both the shop and the cart. A site that allows users to take advantage of any one of many discounts on their total purchase and then proceed to checkout and tendering: what happens if the attacker navigates back to the discounts page after taking and applying the one allowable discount, and can they take advantage of another discount, or the same discount multiple times. The test guidance generalises it into a repeatable probe: can a user navigate back and forth through the pages multiple times executing a function that should only execute once, or can a user load and unload shopping carts allowing for additional discounts. The same page states the general claim, that many of the problems applications are solving require limits to the number of times a function can be used, and attackers may be able to circumvent the business logic and execute a function more times than allowable. The distinguishing feature versus a plain coupon-stacking bug is that the attacker is not changing a value, they are re-entering a step the server believes is single-use.

*Disproof:* The applied-discount set is stored server-side against the transaction id and the checkout step recomputes it, so returning to the discount page cannot add a second entry and the tendered total reflects only the permitted one.

**When the application authorises on the domain extracted from an email address, differing parsers let an address that passes validation be interpreted as a different domain, granting access to the restricted area.**

PortSwigger: some websites parse email addresses to extract the domain and determine which organization the email owner belongs to, a process that may initially seem straightforward but is actually very complex even for valid RFC-compliant addresses. Discrepancies in how email addresses are parsed can undermine this logic, and they arise when different parts of the application handle email addresses differently. An attacker exploits the discrepancies using encoding techniques to disguise parts of the email address, creating addresses that pass initial validation checks but are interpreted differently by the server's parsing logic. The main impact is unauthorized access: attackers register accounts using seemingly valid email addresses from restricted domains, gaining access to sensitive areas such as admin panels or restricted user functions. The control that prevents it is a single canonical parser plus a strict accept-list, and CWE-178 supplies both halves: use an accept known good input validation strategy, i.e., use a list of acceptable inputs that strictly conform to specifications, and make sure that the application does not decode the same input twice. Hunt it by locating every place a domain is derived from an email address, then feeding one address through each component and comparing the extracted domain rather than comparing the addresses.

*Disproof:* A single canonical, RFC-conformant parser is used for both registration-time validation and every later authorisation decision, so the domain used for the access decision is byte-identical to the one that was validated.

**An endpoint that encrypts attacker-controlled input with the server's key and returns the ciphertext becomes an oracle whenever another endpoint accepts ciphertext under the same algorithm.**

PortSwigger: dangerous scenarios can occur when user-controllable input is encrypted and the resulting ciphertext is then made available to the user in some way, and the attacker can use this input to encrypt arbitrary data using the correct algorithm and asymmetric key. It becomes dangerous when there are other user-controllable inputs in the application that expect data encrypted with the same algorithm, since the attacker could use the encryption oracle to generate valid, encrypted input and then pass it into other sensitive functions. The severity depends on what functionality also uses the same algorithm as the oracle. The issue is compounded if another user-controllable input provides the reverse function, which lets the attacker decrypt other data to identify the expected structure, saving work but not being strictly required to craft the exploit. Hunt the pair, not the endpoint: enumerate every input the application decrypts with a server-side key, then look for any input it will encrypt on request.

*Disproof:* No other input in the application accepts data encrypted under the same key and algorithm, or the encryption is bound to a per-session or per-record context so a ciphertext produced by the oracle is not accepted elsewhere.

**A numeric business rule validated only as within-an-upper-bound passes for a negative input, so a balance check approves a transfer that moves funds in the opposite direction to the one requested.**

PortSwigger's funds-transfer example is the shortest complete proof. The functionality checks whether the sender has sufficient funds, comparing transferAmount <= currentBalance, but if the logic doesn't sufficiently prevent users from supplying a negative value in the amount parameter, this could be exploited to both bypass the balance check and transfer funds in the wrong direction: sending -$1000 to the victim's account might result in the attacker receiving $1000 from the victim, because the logic would always evaluate that -1000 is less than the current balance and approve the transfer. The root cause is stated as a class, not a one-off: a numeric data type might accept negative values, and depending on the related functionality it may not make sense for the business logic to allow this, but if the application doesn't perform adequate server-side validation and reject this input, an attacker may be able to pass in a negative value and induce unwanted behavior. Hunt for the shape rather than the endpoint: any comparison using a client-supplied numeric field is a candidate, and the probe is a negative value in ranges a legitimate user would never enter.

*Disproof:* The server rejects values below a stated lower bound, coerces the amount to an unsigned or fixed-point type before the comparison, or re-derives the amount server-side rather than trusting the submitted parameter.

**Where one server-side script dispatches on the presence of a parameter, deleting the parameter name selects a different branch, so an attacker reaches code paths the UI never exposes.**

PortSwigger names the mistaken assumption and the reachability consequence. One misconception is that users will always supply values for mandatory input fields; browsers may prevent ordinary users from submitting a form without a required input, but attackers can tamper with parameters in transit, and this even extends to removing parameters entirely. This is a particular issue in cases where multiple functions are implemented within the same server-side script, in which case the presence or absence of a particular parameter may determine which code is executed; removing parameter values may allow an attacker to access code paths that are supposed to be out of reach. The test procedure matters because the two deletions behave differently: remove one parameter at a time so all relevant code paths are reached, and try deleting the name of the parameter as well as the value, because the server will typically handle both cases differently. Follow multi-stage processes to completion, because tampering with a parameter in one step may have an effect on another step further along in the workflow. Include cookies in the sweep.

*Disproof:* Every branch is selected by an explicit, validated parameter value rather than by parameter presence, and omitting a mandatory field is rejected with a validation error before any state is read or written.

**When a workflow grants a durable credit at an intermediate step and does not roll it back on cancellation, an attacker accumulates credit by repeatedly starting a transaction and abandoning it without ever paying.**

WSTG's loyalty-points example is the canonical shape: a user starts a transaction linked to their account, points are added to the account, and the user then cancels out of the transaction or removes items from the basket and tenders. The system either should not apply points/credits to the account until it is tendered, or points/credits should be rolled back if the point/credit increment does not match the final tender. The attack is to start transactions and cancel them to build their point levels without actually buying anything. This differs from a price or coupon manipulation, which corrupts one transaction; here the credit is granted by a step the attacker is free to abandon, so the balance accumulates monotonically across attempts and the loss is real money at redemption. Detection shape: a long series of abandoned carts or orders correlated with a rising points, credit, or reservation balance on one account is the signal, and the confirming test is a single start-then-cancel followed by a balance read that shows the credit persisted.

*Disproof:* The intermediate step reserves rather than grants the credit, and the reservation is released when the transaction is cancelled, so the account balance is unchanged after a start-then-abandon cycle.

## Variations

Not yet researched.

## Technology / Framework Considerations

Not yet researched.

## API Considerations

Not yet researched.

## Attack Chains

- `bizlogic-intermediate-credit-to-realised-loss` — Un-rolled-back workflow credit to redeemable financial loss (goal: `Accumulate a durable credit through repeated start-then-abandon workflow cycles and redeem it against a real order, producing realised financial loss without ever tendering payment.`)
- `limit-overrun-to-quantified-financial-loss` — Single-use entitlement limit overrun to quantified settlement over-issue (goal: `financial_loss`)

## Real-World Examples

Not yet researched.

## Common False Positives

**A price, discount, or total that the server echoes back from the client request body without independently recomputing it is a finding only when the echoed figure is the figure that is charged, otherwise it is a display-only reflection of untrusted input.**

The lookalike: you submit an order with quantity 99 or a 90 percent discount field, the response body echoes your figure back in a price or total field, and it is filed as business-logic manipulation. The discriminator is where the number is consumed. If the echoed value is recomputed server-side at settlement - the authoritative total comes from a price table joined at checkout - then the echo is an unvalidated-input reflection, at most a UI-integrity issue, and the money never moved. If the echoed value IS the value debited, charged, or credited, the invariant that the server must not accept a client-stated economic quantity has been broken and the finding is real. CWE-840 frames why this class is easy to over-report: business logic errors typically involve legitimate use of the application's functionality, so an endpoint that behaves correctly for every value the attacker supplies is not a flaw until a stated rule is broken. Test it by finding the authoritative source of the figure in the checkout or ledger path, then comparing it against the field the client controlled. Report the authoritative-versus-echoed mismatch, not the echo.

*Disproof:* Refuted when the authoritative charge, credit, or entitlement is computed server-side from a stored price or entitlement table and the echoed client figure is never read by the settlement path; a reflection that no downstream consumer trusts cannot move money.

**A logic flaw reported by an automated scanner with no stated business rule and no reproduced invariant violation is not a finding, because the weakness class is defined as not automatically detectable.**

CWE-840 says the errors can be devastating to an entire application and are difficult to find automatically, since they typically involve legitimate use of the application's functionality. PortSwigger makes the operational consequence explicit: identifying them often requires a certain amount of human knowledge, such as an understanding of the business domain or what goals an attacker might have in a given context, which makes them difficult to detect using automated vulnerability scanners. So a scanner hit on this class carries no weight on its own. A reportable finding needs three things together: a stated rule the application is supposed to enforce, an observed deviation from it, and a consequence. What legitimately does not clear the bar is a response difference, a status code, or a parameter a scanner rated unusual, with no invariant shown to be violated. What would clear it is a reproduced violation, such as two coupons applied where the documented policy permits one, with the excess confirmed in the persisted order total.

*Disproof:* The report supplies a stated business rule, a concrete request sequence that violates it, and evidence the violation persisted, so the claim rests on reproduced invariant violation rather than on tool output.

**Submitting a value outside the range a legitimate user would enter is a probe, not a finding, unless it changes a persisted outcome or reaches a code path the UI does not expose.**

PortSwigger is explicit that unconventional input is the method, not the finding: use tools such as Burp Proxy and Repeater to try submitting unconventional values, in input ranges that legitimate users are unlikely to ever enter, including exceptionally high or exceptionally low numeric inputs and abnormally long strings for text-based fields, and even unexpected data types. It then names what that is looking for: are there any limits imposed on the data, what happens when you reach those limits, is any transformation or normalization being performed on the input. A negative number that the server coerces to zero, or a value that is normalised into range, satisfies the rule and is not a vulnerability. A negative that flips the direction of a transfer, or one that reaches an administrative branch, is. The disproof that clears the item is server-side normalisation or clamping that makes the out-of-range value semantically equal to an in-range one, with no divergent persisted state.

*Disproof:* The server normalises, clamps or type-coerces the out-of-range value to a semantically in-range value, and no persisted record, balance, or reached code path differs from the one produced by the corresponding legal input.

**An oversized refund, credit, or payout accepted without a domain rule is a hypothesis, not a finding, until you state the rule the server should have enforced.**

Discard the report that says the endpoint validates nothing only when you could not establish the intended rule: without a stated cap, a documented maximum, or a control request showing the server enforces one, a large accepted amount proves nothing about a missing check. The finding survives the moment you send a request that violates the domain invariant and the server completes the action anyway, which separates a missing business rule from an endpoint that was permissive by design.

*Disproof:* If the same over-limit request is rejected with 4xx on a second attempt, or the amount was clamped to a documented maximum and the difference is only in what the response echoes back, there is no missing rule and the original report was a false positive after all.

**A concurrent-request test showing a duplicated result once, with no repeated-sample baseline, is a hypothesis; it survives only when the effect reproduces across many trials.**

Discard the race-condition report when the double effect appeared in a single interleaved pair and does not recur over dozens of repetitions, because one anomalous outcome is indistinguishable from scheduler noise and from your own client's retry. The finding survives when the duplicate credit, double spend, or double fulfilment reproduces at a rate well above your baseline and when server state, read back from a fresh session, confirms both effects were committed.

*Disproof:* If the server enforces a uniqueness constraint or an idempotency key on the endpoint, the second request returning 409 Conflict is the control working, and the race claim is a false positive produced by a client that did not read the rejection as a rejection.
**Hypothesis:** An order endpoint that echoes a client-supplied discount or total in the response body allows business-logic manipulation of the charge.
- Invalidated by: The authoritative total is recomputed server-side at settlement from the stored price table; the echoed client figure is rendered for display and never read by the ledger, so the money charged was unaffected.
- **Rejection rule:** A client figure echoed back is not a business-logic flaw until you show it is the value that is charged, credited, or debited. Find the authoritative computation in the settlement or ledger path first; a reflection no downstream consumer trusts is a UI-integrity issue at most.

## Validation

**A limit-overrun or single-use business-logic claim is confirmed only when parallel requests to the same single-use endpoint succeed where an identical sequential sequence fails, proving the limit was overrun rather than merely exercised twice.**

The control comes first and it is the whole test. Take the single-use or rate-limited endpoint - a promotional code, a one-time credit, a single-slot reservation - and run it twice sequentially from one session. If the second sequential attempt is rejected, the rule is enforced and you have your control: the endpoint has a limit and it holds under ordinary use. Now issue multiple requests to that same endpoint in quick succession and see whether you can overrun the limit, which is the procedure the web-security curriculum describes. Read the outcome back from an independent session rather than trusting the response body: query the code's used counter, the account's credit balance, or the reservation table. The winning observation is a counter that moved by more than one across the concurrent burst while the sequential baseline moved by exactly one, with distinct origin timestamps proving the requests actually overlapped at the server rather than being serialised by your own connection pool. Corroborate from the other side: a database uniqueness constraint is the reliable control, and relying on session state or an application cache instead is what leaves the overrun open. If the parallel burst produces the same result as the sequential baseline, you measured your tooling, not the application.

*Disproof:* Refuted when a sequential two-request baseline produces the identical rejection as the parallel burst, or when the read-back counter advanced by exactly one across the concurrent burst with origin timestamps showing the requests were serialised; without a sequential-versus-parallel differential there is no overrun.

**To decide this case, observe: Discard the race-condition report when the double effect appeared in a single interleaved pair and does not recur over dozens of repetitions, because one anomalous outcome is indistinguishable from scheduler noise and from your own client's retry.**

Derived from bizlogic.fprule.single_interleaved_pair_is_not_a_race, which states the false-positive boundary for this class. The observable above is what separates a real finding from the pattern that only looks like one. A hunter who cannot produce this observation in a request/response pair does not have a finding yet.

*Disproof:* This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (bizlogic.fprule.single_interleaved_pair_is_not_a_race) states the full boundary.

**To decide this case, observe: Now issue multiple requests to that same endpoint in quick succession and see whether you can overrun the limit, which is the procedure the web-security curriculum describes.**

Derived from bizlogic.validation.single_use_redemption_sequential_then_parallel, which states the false-positive boundary for this class. The observable above is what separates a real finding from the pattern that only looks like one. A hunter who cannot produce this observation in a request/response pair does not have a finding yet.

*Disproof:* This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (bizlogic.validation.single_use_redemption_sequential_then_parallel) states the full boundary.

**To decide this case, observe: A reportable finding needs three things together: a stated rule the application is supposed to enforce, an observed deviation from it, and a consequence.**

Derived from bizlogic.fp_rule.scanner_output_alone_is_not_a_logic_finding, which states the false-positive boundary for this class. The observable above is what separates a real finding from the pattern that only looks like one. A hunter who cannot produce this observation in a request/response pair does not have a finding yet.

*Disproof:* This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (bizlogic.fp_rule.scanner_output_alone_is_not_a_logic_finding) states the full boundary.

**To decide this case, observe: The lookalike: you submit an order with quantity 99 or a 90 percent discount field, the response body echoes your figure back in a price or total field, and it is filed as business-logic manipulation.**

Derived from bizlogic.fp_rule.client_supplied_price_displayed_back_is_not_bypass, which states the false-positive boundary for this class. The observable above is what separates a real finding from the pattern that only looks like one. A hunter who cannot produce this observation in a request/response pair does not have a finding yet.

*Disproof:* This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (bizlogic.fp_rule.client_supplied_price_displayed_back_is_not_bypass) states the full boundary.

**To decide this case, observe: Discard the report that says the endpoint validates nothing only when you could not establish the intended rule: without a stated cap, a documented maximum, or a control request showing the server enforces one, a large accepted amount proves nothing about a missing check.**

Derived from bizlogic.fprule.absent_business_rule_needs_a_stated_rule, which states the false-positive boundary for this class. The observable above is what separates a real finding from the pattern that only looks like one. A hunter who cannot produce this observation in a request/response pair does not have a finding yet.

*Disproof:* This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (bizlogic.fprule.absent_business_rule_needs_a_stated_rule) states the full boundary.

## Impact

Not yet researched.

## Related Bug Classes

Not yet researched.

## References

- **cwe.mitre.org** (taxonomy)
  - <https://cwe.mitre.org/data/definitions/178.html>
  - <https://cwe.mitre.org/data/definitions/837.html>
  - <https://cwe.mitre.org/data/definitions/840.html>
  - <https://cwe.mitre.org/data/definitions/841.html>
- **httpwg.org** (standard)
  - <https://httpwg.org/specs/rfc9110.html>
- **portswigger.net** (cheatsheet)
  - <https://portswigger.net/web-security/logic-flaws>
  - <https://portswigger.net/web-security/logic-flaws/examples>
  - <https://portswigger.net/web-security/race-conditions>
- **projectdiscovery.io** (writeup)
  - <https://projectdiscovery.io/blog/from-detection-to-validation-fixing-broken-vulnerability-workflows>
  - <https://projectdiscovery.io/blog/inside-the-benchmark-pp-architectures-finding-walkthroughs-and-what-each-scanner-actually-caught>
- **wstg.owasp.org** (research)
  - <https://wstg.owasp.org/v4.2/4-Web_Application_Security_Testing/10-Business_Logic_Testing/02-Test_Ability_to_Forge_Requests>
  - <https://wstg.owasp.org/v4.2/4-Web_Application_Security_Testing/10-Business_Logic_Testing/05-Test_Number_of_Times_a_Function_Can_Be_Used_Limits>
  - <https://wstg.owasp.org/v4.2/4-Web_Application_Security_Testing/10-Business_Logic_Testing/06-Testing_for_the_Circumvention_of_Work_Flows>

Every item above is gated on >= 2 distinct publisher hosts (`wks/quality.py`, rule R1). Publisher diversity, not citation count, is what makes these corroborated.
