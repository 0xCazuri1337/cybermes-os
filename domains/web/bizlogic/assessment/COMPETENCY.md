# Methodology — Business Logic Flaws

> Derived from 14 verified items. Regenerate with `python -m wks.methodgen --class bizlogic --apply`. Do not hand-edit: this file is a projection of the evidence, and edits are lost on the next cycle.

**Surface.** The application performs each step correctly in isolation but enforces no invariant across the sequence, so the sequence itself is the attack.

**References.** CWE-840 · A04:2021

## Preconditions

_No verified prerequisite items yet._ Derived from evidence only, so this section is empty rather than plausible.


## Reconnaissance signals

_No verified signal items yet._ Derived from evidence only, so this section is empty rather than plausible.


## 1. Test sequence

_Concrete mutations to try. Each is written to be executable, not to be a description of the vulnerability._

**A numeric business rule validated only as within-an-upper-bound passes for a negative input, so a balance check approves a transfer that moves funds in the opposite direction to the one requested.**

PortSwigger's funds-transfer example is the shortest complete proof. The functionality checks whether the sender has sufficient funds, comparing transferAmount <= currentBalance, but if the logic doesn't sufficiently prevent users from supplying a negative value in the amount parameter, this could be exploited to both bypass the balance check and transfer funds in the wrong direction: sending -$1000 to the victim's account might result in the attacker receiving $1000 from the victim, because the logic would always evaluate that -1000 is less than the current balance and approve the transfer. The root cause is stated as a class, not a one-off: a numeric data type might accept negative values, and depending on the related functionality it may not make sense for the business logic to allow this, but if the application doesn't perform adequate server-side validation and reject this input, an attacker may be able to pass in a negative value and induce unwanted behavior. Hunt for the shape rather than the endpoint: any comparison using a client-supplied numeric field is a candidate, and the probe is a negative value in ranges a legitimate user would never enter.

- *Disproof:* The server rejects values below a stated lower bound, coerces the amount to an unsigned or fixed-point type before the comparison, or re-derives the amount server-side rather than trusting the submitted parameter.
- *Evidence:* high_confidence — [cwe.mitre.org](https://cwe.mitre.org/data/definitions/840.html); [portswigger.net](https://portswigger.net/web-security/logic-flaws/examples)

**A once-per-transaction limit enforced only in the forward UI flow is bypassed by navigating back to the discount step, because the server-side count is not tied to the transaction.**

WSTG's function-limits test case names the mechanism in both the shop and the cart. A site that allows users to take advantage of any one of many discounts on their total purchase and then proceed to checkout and tendering: what happens if the attacker navigates back to the discounts page after taking and applying the one allowable discount, and can they take advantage of another discount, or the same discount multiple times. The test guidance generalises it into a repeatable probe: can a user navigate back and forth through the pages multiple times executing a function that should only execute once, or can a user load and unload shopping carts allowing for additional discounts. The same page states the general claim, that many of the problems applications are solving require limits to the number of times a function can be used, and attackers may be able to circumvent the business logic and execute a function more times than allowable. The distinguishing feature versus a plain coupon-stacking bug is that the attacker is not changing a value, they are re-entering a step the server believes is single-use.

- *Disproof:* The applied-discount set is stored server-side against the transaction id and the checkout step recomputes it, so returning to the discount page cannot add a second entry and the tendered total reflects only the permitted one.
- *Evidence:* high_confidence — [cwe.mitre.org](https://cwe.mitre.org/data/definitions/837.html); [wstg.owasp.org](https://wstg.owasp.org/v4.2/4-Web_Application_Security_Testing/10-Business_Logic_Testing/05-Test_Number_of_Times_a_Function_Can_Be_Used_Limits)

**An endpoint that encrypts attacker-controlled input with the server's key and returns the ciphertext becomes an oracle whenever another endpoint accepts ciphertext under the same algorithm.**

PortSwigger: dangerous scenarios can occur when user-controllable input is encrypted and the resulting ciphertext is then made available to the user in some way, and the attacker can use this input to encrypt arbitrary data using the correct algorithm and asymmetric key. It becomes dangerous when there are other user-controllable inputs in the application that expect data encrypted with the same algorithm, since the attacker could use the encryption oracle to generate valid, encrypted input and then pass it into other sensitive functions. The severity depends on what functionality also uses the same algorithm as the oracle. The issue is compounded if another user-controllable input provides the reverse function, which lets the attacker decrypt other data to identify the expected structure, saving work but not being strictly required to craft the exploit. Hunt the pair, not the endpoint: enumerate every input the application decrypts with a server-side key, then look for any input it will encrypt on request.

- *Disproof:* No other input in the application accepts data encrypted under the same key and algorithm, or the encryption is bound to a per-session or per-record context so a ciphertext produced by the oracle is not accepted elsewhere.
- *Evidence:* high_confidence — [cwe.mitre.org](https://cwe.mitre.org/data/definitions/840.html); [portswigger.net](https://portswigger.net/web-security/logic-flaws/examples)

**When a workflow grants a durable credit at an intermediate step and does not roll it back on cancellation, an attacker accumulates credit by repeatedly starting a transaction and abandoning it without ever paying.**

WSTG's loyalty-points example is the canonical shape: a user starts a transaction linked to their account, points are added to the account, and the user then cancels out of the transaction or removes items from the basket and tenders. The system either should not apply points/credits to the account until it is tendered, or points/credits should be rolled back if the point/credit increment does not match the final tender. The attack is to start transactions and cancel them to build their point levels without actually buying anything. This differs from a price or coupon manipulation, which corrupts one transaction; here the credit is granted by a step the attacker is free to abandon, so the balance accumulates monotonically across attempts and the loss is real money at redemption. Detection shape: a long series of abandoned carts or orders correlated with a rising points, credit, or reservation balance on one account is the signal, and the confirming test is a single start-then-cancel followed by a balance read that shows the credit persisted.

- *Disproof:* The intermediate step reserves rather than grants the credit, and the reservation is released when the transaction is cancelled, so the account balance is unchanged after a start-then-abandon cycle.
- *Evidence:* high_confidence — [portswigger.net](https://portswigger.net/web-security/logic-flaws); [wstg.owasp.org](https://wstg.owasp.org/v4.2/4-Web_Application_Security_Testing/10-Business_Logic_Testing/06-Testing_for_the_Circumvention_of_Work_Flows)

**When the application authorises on the domain extracted from an email address, differing parsers let an address that passes validation be interpreted as a different domain, granting access to the restricted area.**

PortSwigger: some websites parse email addresses to extract the domain and determine which organization the email owner belongs to, a process that may initially seem straightforward but is actually very complex even for valid RFC-compliant addresses. Discrepancies in how email addresses are parsed can undermine this logic, and they arise when different parts of the application handle email addresses differently. An attacker exploits the discrepancies using encoding techniques to disguise parts of the email address, creating addresses that pass initial validation checks but are interpreted differently by the server's parsing logic. The main impact is unauthorized access: attackers register accounts using seemingly valid email addresses from restricted domains, gaining access to sensitive areas such as admin panels or restricted user functions. The control that prevents it is a single canonical parser plus a strict accept-list, and CWE-178 supplies both halves: use an accept known good input validation strategy, i.e., use a list of acceptable inputs that strictly conform to specifications, and make sure that the application does not decode the same input twice. Hunt it by locating every place a domain is derived from an email address, then feeding one address through each component and comparing the extracted domain rather than comparing the addresses.

- *Disproof:* A single canonical, RFC-conformant parser is used for both registration-time validation and every later authorisation decision, so the domain used for the access decision is byte-identical to the one that was validated.
- *Evidence:* high_confidence — [cwe.mitre.org](https://cwe.mitre.org/data/definitions/178.html); [portswigger.net](https://portswigger.net/web-security/logic-flaws/examples)

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

- *Disproof:* Refuted when: the same behaviour is absent when the single named control in the claim is present, and the control is shown to be present rather than assumed. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“Weaknesses in this category identify some of the underlying problems that common”) does not occur under a test that isolates that control.
- *Evidence:* high_confidence — [cwe.mitre.org](https://cwe.mitre.org/data/definitions/840.html); [wstg.owasp.org](https://wstg.owasp.org/v4.2/4-Web_Application_Security_Testing/10-Business_Logic_Testing/06-Testing_for_the_Circumvention_of_Work_Flows)

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

- *Disproof:* Refuted when: the same behaviour is absent when the single named control in the claim is present, and the control is shown to be present rather than assumed. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“Comments: The "Business Logic" term generally reflects product-specific logic er”) does not occur under a test that isolates that control.
- *Evidence:* high_confidence — [cwe.mitre.org](https://cwe.mitre.org/data/definitions/840.html); [wstg.owasp.org](https://wstg.owasp.org/v4.2/4-Web_Application_Security_Testing/10-Business_Logic_Testing/06-Testing_for_the_Circumvention_of_Work_Flows)

**The "Business Logic" term is generally used to describe issues that require domain-specific knowledge or "business rules" to determine if they are weaknesses or vulnerabilities, instead of legitimate behavior.**

e "Business Logic" term generally reflects product-specific logic errors that can be characterized by various weaknesses related to issues such as access control, workflow, input validation, etc. Perform root cause analysis to determine what mistake led to the logic error. Consult the member weaknesses of this category.
 
 
 
 
 
 
 
 
 

 
 
 
 
 Notes 
 
 
 
 
 
 
 
 
 
 
 
 
 Terminology 
 
 
 The "Business Logic" term is generally used to describe issues that require domain-specific knowledge or "business rules" to determine if they are weaknesses or vulnerabilities, instead of legitimate behavior. Such issues might not be easily detectable via automatic code analysis, because the associated operations do not produce clear errors or undefined behavior at the code level. However, many such "business logic" issues can be understood as instances of other weaknesses such as input validation, access control, numeric computation, order of operations, etc. 
 
 
 
 
 
 
 
 
 
 
 
 
 
 
 Research Ga

- *Disproof:* Refuted when: the same behaviour is absent when the single named control in the claim is present, and the control is shown to be present rather than assumed. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“The "Business Logic" term is generally used to describe issues that require doma”) does not occur under a test that isolates that control.
- *Evidence:* high_confidence — [cwe.mitre.org](https://cwe.mitre.org/data/definitions/840.html); [wstg.owasp.org](https://wstg.owasp.org/v4.2/4-Web_Application_Security_Testing/10-Business_Logic_Testing/06-Testing_for_the_Circumvention_of_Work_Flows)

## 2. Validation

_How to prove the finding rather than infer it. A technique that cannot be validated must not be reported._

**A limit-overrun or single-use business-logic claim is confirmed only when parallel requests to the same single-use endpoint succeed where an identical sequential sequence fails, proving the limit was overrun rather than merely exercised twice.**

The control comes first and it is the whole test. Take the single-use or rate-limited endpoint - a promotional code, a one-time credit, a single-slot reservation - and run it twice sequentially from one session. If the second sequential attempt is rejected, the rule is enforced and you have your control: the endpoint has a limit and it holds under ordinary use. Now issue multiple requests to that same endpoint in quick succession and see whether you can overrun the limit, which is the procedure the web-security curriculum describes. Read the outcome back from an independent session rather than trusting the response body: query the code's used counter, the account's credit balance, or the reservation table. The winning observation is a counter that moved by more than one across the concurrent burst while the sequential baseline moved by exactly one, with distinct origin timestamps proving the requests actually overlapped at the server rather than being serialised by your own connection pool. Corroborate from the other side: a database uniqueness constraint is the reliable control, and relying on session state or an application cache instead is what leaves the overrun open. If the parallel burst produces the same result as the sequential baseline, you measured your tooling, not the application.

- *Disproof:* Refuted when a sequential two-request baseline produces the identical rejection as the parallel burst, or when the read-back counter advanced by exactly one across the concurrent burst with origin timestamps showing the requests were serialised; without a sequential-versus-parallel differential there is no overrun.
- *Evidence:* high_confidence — [cwe.mitre.org](https://cwe.mitre.org/data/definitions/840.html); [portswigger.net](https://portswigger.net/web-security/race-conditions)

## 3. False-positive rejection

_The checks that eliminate the most common non-findings. Run these BEFORE reporting, not after a rejection._

**Submitting a value outside the range a legitimate user would enter is a probe, not a finding, unless it changes a persisted outcome or reaches a code path the UI does not expose.**

PortSwigger is explicit that unconventional input is the method, not the finding: use tools such as Burp Proxy and Repeater to try submitting unconventional values, in input ranges that legitimate users are unlikely to ever enter, including exceptionally high or exceptionally low numeric inputs and abnormally long strings for text-based fields, and even unexpected data types. It then names what that is looking for: are there any limits imposed on the data, what happens when you reach those limits, is any transformation or normalization being performed on the input. A negative number that the server coerces to zero, or a value that is normalised into range, satisfies the rule and is not a vulnerability. A negative that flips the direction of a transfer, or one that reaches an administrative branch, is. The disproof that clears the item is server-side normalisation or clamping that makes the out-of-range value semantically equal to an in-range one, with no divergent persisted state.

- *Disproof:* The server normalises, clamps or type-coerces the out-of-range value to a semantically in-range value, and no persisted record, balance, or reached code path differs from the one produced by the corresponding legal input.
- *Evidence:* high_confidence — [cwe.mitre.org](https://cwe.mitre.org/data/definitions/840.html); [portswigger.net](https://portswigger.net/web-security/logic-flaws/examples)

## Known bypasses

_No verified bypass items yet._ Derived from evidence only, so this section is empty rather than plausible.


## 4. Chaining

_How this class escalates when combined with others. Each step is anchored to a promoted item._

**A workflow that grants a durable credit at an intermediate step without rollback, combined with a redemption endpoint that trusts the resulting balance, turns a repeatable start-then-abandon loop into realised financial loss.**

Both halves are published and they compose. The first is WSTG's workflow-circumvention case: the application's business logic must require that the user complete specific steps in the correct/specific order and if the workflow is terminated without correctly completing, all actions and spawned actions are rolled back, and the worked attack is that an attacker may start transactions and cancel them to build their point levels without actually buying anything. The second is CWE-841: by performing actions in an unexpected order, or by omitting steps, an attacker could manipulate the business logic of the product or cause it to enter an invalid state. The chain closes on the credit being worth money: once the accumulated balance is redeemable against a real order, the loop converts into loss, and the amplification is why this outranks a single mispriced item, because each iteration is a legal-looking start and cancel rather than a malformed request. The disproof is rollback on cancellation, or a redemption path that recomputes the entitlement from committed transactions rather than reading a stored balance.

- *Disproof:* The credit is reserved rather than granted at the intermediate step and released on cancellation, or redemption recomputes entitlement from committed transactions, so the accumulated balance never becomes redeemable.
- *Evidence:* high_confidence — [cwe.mitre.org](https://cwe.mitre.org/data/definitions/841.html); [wstg.owasp.org](https://wstg.owasp.org/v4.2/4-Web_Application_Security_Testing/10-Business_Logic_Testing/06-Testing_for_the_Circumvention_of_Work_Flows)

**A limit-overrun race on a single-use entitlement becomes realised financial loss only when the duplicated effect is quantified at settlement, so the chain runs from the check-then-act window to the amount actually over-issued.**

The primitive is a check-then-act window and it is well documented: an online store that accepts a promotional code at checkout typically checks that you have not already used it, applies the discount to the order total, then updates the database record to reflect that the code is now used. Those three steps are the window - a concurrent pair can pass the check before either writes. Chained to the impact, the finding stops being a race and becomes money: escalate the primitive to quantify the payout. Twenty parallel checkouts each receiving the same fifty percent code is the discount issued twenty times on orders that all shipped, and that realised figure - discount dollars, item count, credit balance - belongs in the report rather than the HTTP trace. The escalation variants are inventory and control rather than discount: buy all stock of a limited item then resell it, hold every reservation slot so nobody else can complete checkout, or automate a referral flow so each new account adds wallet credit. Read the result from an independent session so the counter you believe you overran is the one you observe. The ceiling is whatever single-use record backs the entitlement, and a database uniqueness constraint is the control that closes it.

- *Disproof:* Refuted if a sequential baseline of the same requests already yields the duplicate effect, or if the read-back counter advanced by exactly one across the concurrent burst; without a parallel-versus-sequential differential and a quantified settlement over-issue, only a check-then-act code path has been shown, not financial impact.
- *Evidence:* high_confidence — [cwe.mitre.org](https://cwe.mitre.org/data/definitions/840.html); [portswigger.net](https://portswigger.net/web-security/race-conditions)

## Impact

_No verified impact items yet._ Derived from evidence only, so this section is empty rather than plausible.


## Coverage gap

These stages have no verified evidence and are therefore absent above: Preconditions, Reconnaissance signals, Known bypasses, Impact.
A procedure with a missing validation stage is not safe to act on — it produces findings rather than proofs.

---

*Generated from the evidence base. Where this file and the database disagree, the database is correct.*
