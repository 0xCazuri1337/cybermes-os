# Methodology — NoSQL / Operator Injection

> Derived from 24 verified items. Regenerate with `python -m wks.methodgen --class nosql --apply`. Do not hand-edit: this file is a projection of the evidence, and edits are lost on the next cycle.

**Surface.** A document query is built from a parsed structure so type and operator semantics become attacker-controlled.

**References.** CWE-943 · A03:2021

## Preconditions

_No verified prerequisite items yet._ Derived from evidence only, so this section is empty rather than plausible.


## 1. Reconnaissance signals

_What to look for while mapping the surface, and where each signal tells you the rest of the procedure is worth running._

**A JSON request field documented as a string that returns a structurally different response when sent as an object ({$ne:null}, {$exists:true}) is a NoSQL injection signal, because the value type changed the query's behaviour rather than being rejected.**

The signal is a differential on the request TYPE, not on the request content. Baseline the endpoint three ways with an otherwise identical request: field as a documented scalar (string), field as an empty object {}, and field as an operator object {"$ne":null}. Compare status, body length, and which fields come back. A type error (400/422 with a validation message) means the guard held; a 200 whose body differs from the scalar baseline means the object reached the query layer as query structure. Sonar's Rocket.Chat research makes this the practical test of the vulnerable shape - the endpoints affected were those that pass user input into MongoDB queries without schema validation, and the fix is strict input typing at each location that handles JSON user input: the input should only be a string, so adding a type check is the way to go. Treat anything user-supplied as hostile until proven otherwise, and log the type-anomaly as the signal, not the payload.

- *Disproof:* If the object, integer and boolean forms of the field all return the same 400/422 validation error and only the documented string form reaches the handler, the field is type-guarded and there is no injection signal on that endpoint.
- *Evidence:* high_confidence — [blog.sonarsource.com](https://blog.sonarsource.com/nosql-injections-in-rocket-chat/); [sourcegraph.com](https://sourcegraph.com/blog/code-review-checklist)

## 2. Test sequence

_Concrete mutations to try. Each is written to be executable, not to be a description of the vulnerability._

**Sending {"$ne":1} or {"$ne":null} as a credential or token field in a JSON login body bypasses the equality check, because the field is compared as an always-true query operator rather than as a literal string.**

Baseline first: POST /api/login with {"user":"known@x","password":"wrongpass"} and record the exact status and body. Then POST the same endpoint with {"user":"known@x","password":{"$ne":1}}. A 200 with a session cookie where the baseline returned 401 is the authentication bypass. Sonar's Rocket.Chat writeup gives the canonical form: an attacker can bypass a login by specifying an object as the password parameter which contains an operator expression that is always true, like {"$ne":1}. Note the constraint that makes this a technique rather than a certainty - it only works where the sink is a query lookup rather than a bcrypt compare, so a $ne success with a wrong password is itself proof the credential is not hashed before comparison. Test $ne:1, $ne:null and $gt:"" variants; if all are rejected as bad types the endpoint is type-guarded. The finding must be reproduced against a real endpoint rather than inferred from a code path.

- *Disproof:* If {"password":{"$ne":1}} returns the same 401 and body as the wrong-password baseline while a correct password still returns 200, the credential is not compared through a query operator and the operator-injection auth bypass does not exist on that endpoint.
- *Evidence:* high_confidence — [blog.sonarsource.com](https://blog.sonarsource.com/nosql-injections-in-rocket-chat/); [firebase.google.com](https://firebase.google.com/docs/firestore/security/rules-query)

**A $regex operator object in a lookup field turns the response into a boolean oracle, letting an attacker recover a secret token one character at a time by repeated prefix guesses against an unauthenticated endpoint.**

Send {"token":{"$regex":"^A"}} then {"token":{"$regex":"^B"}}; the prefix that changes the response (200 with data vs error or empty) is the first character. Extend the confirmed prefix and repeat until the whole value is recovered. Sonar describes exactly this loop on Rocket.Chat's getPasswordPolicy, reachable without authentication because the frontend needs the policy at registration: the token parameter is user-controlled JSON, so MongoDB's $regex operator can be used to check whether a token begins with a certain character, and an attacker repeatedly makes guesses and observes the oracle's response until the whole token is known. Cost control: keep each probe to a bounded character class over the prefix you have already confirmed, and stop as soon as you hold a reset token rather than a password. This is hand-iterated work by nature, not a scanner pass. An endpoint that returns a byte-identical response for matching and non-matching prefixes has no oracle.

- *Disproof:* If {"token":{"$regex":"^A"}} and {"token":{"$regex":"^ZZZZ"}} produce byte-identical responses, and the same for every prefix tried, there is no observable difference to build an oracle from and the blind character-leak technique does not work against this endpoint.
- *Evidence:* high_confidence — [blog.sonarsource.com](https://blog.sonarsource.com/nosql-injections-in-rocket-chat/); [firebase.google.com](https://firebase.google.com/docs/firestore/security/rules-query)

## 3. Validation

_How to prove the finding rather than infer it. A technique that cannot be validated must not be reported._

**A NoSQL endpoint counts as validated-guarded only when a field-level operator object, a top-level operator such as $where, and a non-allowlisted field name are each rejected, because any one of the three passing leaves an injection path.**

Three probes, in order. (1) {"field":{"$ne":null}} - field-level operator. (2) {"$where":"1"} - top-level operator. (3) A field name not on the allowlist, e.g. {"admin":true}. A pass requires all three rejected, and the report should record the exact status and body of each rejection so the next tester can tell a type error from a filter. Sonar's Rocket.Chat finding is the reason probe 2 is mandatory: the endpoint's blocklist of fields did not stop $where, and the general drawback of a blocklist approach is that it is easy to miss something, whereas an allowlist that explicitly permits known values is more effective. Re-run the probes after any dependency or database version bump, because a correct blocklist can become insufficient when new operators are added in a future version of the database or when the application's data structures change. Also verify user input is validated server-side against an allowlist where possible - client-side validation is not a control here.

- *Disproof:* If {"field":{"$ne":null}} is rejected with a 400 while {"$where":"1"} still changes the result set, the field blocklist is bypassable and the endpoint is NOT guarded; the validation only passes when both the field-level and the top-level operator probes are rejected.
- *Evidence:* high_confidence — [blog.sonarsource.com](https://blog.sonarsource.com/nosql-injections-in-rocket-chat/); [portswigger.net](https://portswigger.net/web-security/nosql-injection)

**The convincing NoSQL-injection observation is a response whose document set or status code changes between two otherwise identical requests that differ only in the type of the submitted field (a scalar string versus a JSON object or array such as {"$ne": null}), because a normal filter cannot produce that difference.**

Mechanism: The convincing NoSQL-injection observation is a response whose document set or status code changes between two otherwise identical requests that differ only in the type of the submitted field (a scalar string versus a JSON object or array such as {"$ne": null}), because a normal filter cannot produce that difference. How to apply it in the field: treat this as the validation it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable. Boundary of the rule: The claim is false when the endpoint legitimately accepts a structured filter and applies the same type coercion to every caller, so the operator-shaped value is treated as a literal and the result set difference comes from the intended filter semantics; in that case the difference is documented behaviour and needs a second probe (a negative operator such as $where or $regex with a measurable side effect) to show attacker control.

- *Disproof:* The claim is false when the endpoint legitimately accepts a structured filter and applies the same type coercion to every caller, so the operator-shaped value is treated as a literal and the result set difference comes from the intended filter semantics; in that case the difference is documented behaviour and needs a second probe (a negative operator such as $where or $regex with a measurable side effect) to show attacker control.
- *Evidence:* high_confidence — [firebase.google.com](https://firebase.google.com/docs/firestore/security/rules-query); [mongodb.com](https://www.mongodb.com/docs/manual/reference/operator/query/)

## 4. False-positive rejection

_The checks that eliminate the most common non-findings. Run these BEFORE reporting, not after a rejection._

**A JSON list endpoint that returns every record to an anonymous caller because it is a public list is NOT NoSQL injection; the separating observation is whether an operator object changes the result set relative to a documented-field request.**

This LOOKS like a NoSQL injection because the response body contains every document including fields the app normally treats as sensitive, which reads exactly like a $ne-null bypass. It is actually the endpoint's intended contract: a public listing API with no authorization boundary. The observation that separates them is differential, not volume. Send three requests with identical authentication: (a) a documented filter field, {"status":"active"}; (b) an operator object on that same field, {"status":{"$ne":"deleted"}}; (c) an empty query {}. If (a), (b) and (c) return the same document set, no operator was interpreted - the endpoint simply has no filter, and the report is an access-control question (test it as every role you have), not a query-injection question. If (b) returns strictly more documents than (a), the operator was parsed by the query layer and this really is injection. Count documents rather than eyeballing fields: a large public list and a successful $ne differ only in whether the operator changes the set.

- *Disproof:* If {"status":{"$ne":"deleted"}} returns a different or larger document set than {"status":"active"} on the same endpoint and credential, the operator changed the query and the finding is genuine NoSQL injection, not a public list.
- *Evidence:* high_confidence — [blog.sonarsource.com](https://blog.sonarsource.com/nosql-injections-in-rocket-chat/); [hackprosec.com](https://www.hackprosec.com/penetration-testing.html)

**Sending the operator payload as a plain string and getting a normal 'no results' response proves only that the value stayed a string, not that the endpoint is safe, because operator injection requires the parameter to arrive as a parsed object.**

The most common wasted hour in this class. $ne and $in are not magic sequences inside a string - MongoDB's $ne matches all values not equal to a specified value, and it does so because it is a query operator object in the query document, not because the text '$ne' appeared. Whether the payload works depends entirely on how the HTTP parameter was decoded into the query: with a framework that parses nested query syntax into objects, 'password[$ne]=' becomes {password:{$ne:''}}; with one that produces flat strings, the same bytes stay the literal string 'password[$ne]='. A hunter who tests only the flat-string form and records 'no injection, rejected cleanly' has established nothing. The same payload must be retried in the structured form the framework actually supports.

- *Disproof:* It IS a real negative result if the application type-checks the parameter before it reaches the store - OWASP lists type conversion with strict exception handling as a validation technique - so that the structured payload is coerced or rejected and the query runs with a scalar value. Prove it by showing the value arrives at the query builder as a string or is rejected with a type error; that makes the flat-string test sufficient and this fp_rule not applicable to that endpoint.
- *Evidence:* high_confidence — [cheatsheetseries.owasp.org](https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html); [mongodb.com](https://www.mongodb.com/docs/manual/reference/operator/query/)

**Reject a nosql finding until it is distinguished from the adjacent behaviour this class also covers. "An endpoint that blocklists disallowed MongoDB field names but leaves top-level operators enabled is bypassed with {"$where":"..."}, which executes a JavaScript expression per document, is not covered by a field blocklist, and turns a..." and "A JSON request field documented as a string that returns a structurally different response when sent as an object ({$ne:null}, {$exists:true}) is a NoSQL injection signal, because the value type changed the query's behaviour rather than..." share a surface and a symptom, so a response that matches the first is not evidence for it while the second remains possible.**

Hypothesis under test: An endpoint that blocklists disallowed MongoDB field names but leaves top-level operators enabled is bypassed with {"$where":"..."}, which executes a JavaScript expression per document, is not covered by a field blocklist, and turns a...

Adjacent behaviour that produces the same observable result: A JSON request field documented as a string that returns a structurally different response when sent as an object ({$ne:null}, {$exists:true}) is a NoSQL injection signal, because the value type changed the query's behaviour rather than...

Why this is worth checking before reporting: both are recorded in this class as gated knowledge, so a tester who stops at the first match will report one of them. The two differ in what the server actually did with the input, and that difference is observable in the response rather than in the request.

Required before treating this as a finding: capture the response that demonstrates the first behaviour specifically, and confirm the second is not what was observed.

- *Disproof:* This rule is wrong if a controlled test shows the two behaviours can never co-occur on the same surface, or if the corpus entry for "A JSON request field documented as a string that returns a structurall" is out of date. In that case this class needs its false-positive guidance rewritten rather than deleted.
- *Evidence:* high_confidence — [blog.sonarsource.com](https://blog.sonarsource.com/nosql-injections-in-rocket-chat/); [portswigger.net](https://portswigger.net/web-security/nosql-injection)

**Returning more documents than the caller should see is by itself an access-control or pagination bug, not NoSQL injection; it becomes injection only when the widening was produced by an operator the caller supplied.**

Mechanism: Returning more documents than the caller should see is by itself an access-control or pagination bug, not NoSQL injection; it becomes injection only when the widening was produced by an operator the caller supplied. How to apply it in the field: treat this as the fp_rule it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable. Boundary of the rule: The rule is wrong when the widening traces to a server-side query construction that merges the whole request body into the filter — even without an explicit `$`-prefixed payload, a body that legitimately carries an `owner` or `role` field is attacker-controlled and drives the operator-equivalent behaviour, so the two findings collapse into one injection with a non-`$` payload.

- *Disproof:* The rule is wrong when the widening traces to a server-side query construction that merges the whole request body into the filter — even without an explicit `$`-prefixed payload, a body that legitimately carries an `owner` or `role` field is attacker-controlled and drives the operator-equivalent behaviour, so the two findings collapse into one injection with a non-`$` payload.
- *Evidence:* high_confidence — [firebase.google.com](https://firebase.google.com/docs/firestore/security/rules-query); [mongodb.com](https://www.mongodb.com/docs/manual/reference/operator/query/)

**A NoSQL injection finding requires the attacker-supplied operator object to reach the query and change which documents match; an application that coerces the request body to a typed or validated model, or that strips keys beginning with `$`, produces a 400 or an unchanged result set and is not vulnerable.**

Mechanism: A NoSQL injection finding requires the attacker-supplied operator object to reach the query and change which documents match; an application that coerces the request body to a typed or validated model, or that strips keys beginning with `$`, produces a 400 or an unchanged result set and is not vulnerable. How to apply it in the field: treat this as the fp_rule it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable. Boundary of the rule: The rule is wrong when the operator reaches a secondary sink the coercion does not cover — a count, aggregation, sort, or projection stage, or a second query built from a value taken out of the same body — because the primary query can be fully validated while the derived one still honours the injected operator.

- *Disproof:* The rule is wrong when the operator reaches a secondary sink the coercion does not cover — a count, aggregation, sort, or projection stage, or a second query built from a value taken out of the same body — because the primary query can be fully validated while the derived one still honours the injected operator.
- *Evidence:* high_confidence — [firebase.google.com](https://firebase.google.com/docs/firestore/security/rules-query); [mongodb.com](https://www.mongodb.com/docs/manual/reference/operator/query/)

**String concatenation of user input into a JSON document handed to a MongoDB driver is a code smell but not, by itself, NoSQL injection, because the driver serialises the value as data and operator injection requires the attacker to control the structure of the parsed document.**

This is the mirror-image false positive and it is expensive in reviewer time. If the application builds a document like {'username': untrusted} and passes it to the driver's find method, the driver JSON-encodes it; an input of { '$ne': '' } becomes the string '{ "$ne": "" }' and matches nothing. The injection surface only opens where the untrusted value is used as a KEY rather than a value, or is parsed back out of a string into a structure before the query runs. A hunter should therefore ask one question before filing: did the attacker's bytes land in a key position, or did the application parse a string into a document with the attacker controlling the parse? If the answer is no, the finding is a robustness issue at most.

- *Disproof:* It IS injection if the untrusted value becomes a key - a field name, an operator name, or a nested path segment - because a key cannot be escaped by value serialisation. It is also injection where a framework's parameter parser turns bracket syntax into nested objects before the application sees them, or where the application calls something like eval or JSON.parse on attacker input to build the filter. Show the attacker-controlled key or the parse step and the finding stands.
- *Evidence:* high_confidence — [cwe.mitre.org](https://cwe.mitre.org/data/definitions/943.html); [mongodb.com](https://www.mongodb.com/docs/manual/reference/operator/query/)

## 5. Known bypasses

_Filters and controls that have defeated the techniques above. Treat these as the reason a naive test fails, not as proof of safety._

**An endpoint that blocklists disallowed MongoDB field names but leaves top-level operators enabled is bypassed with {"$where":"..."}, which executes a JavaScript expression per document, is not covered by a field blocklist, and turns a stripped result set into an error-based exfiltration channel.**

Find the blocklist by diffing which fields a free-form filter accepts, then send a payload with no disallowed field at all: {"$where":"this.role==='admin'"}. If the result set changes, the blocklist only considers actual fields that could be queried and not top level MongoDB operators - exactly the gap Sonar found in Rocket.Chat's users.list endpoint, where a blocklist removed sensitive fields from query and result but left $where usable as a bypass. Two consequences make this more than a read primitive: $where runs inside the MongoDB process with access to the current document's fields, and by throwing an exception inside the expression the error is passed back to the user in the API response with the full error message, turning a stripped result set into full exfiltration of an admin's fields. So response-side filtering is not a control either: it is not enough to simply restrict the projection, i.e. the data that is returned from the query, because blind or error-based NoSQL Injections can still be used to leak that data. Try $where, $expr and $function in turn; any that changes behaviour is a working bypass. CouchDB, which Orange Tsai lists as a real-world RCE target, is the same document-store class of target if you need a second worked example.

- *Disproof:* If {"$where":"1==1"}, {"$expr":true} and a throwing expression inside $where are all rejected with a validation error before the query runs, and $where never appears to change the result set, then top-level operators are denied and the field blocklist is not bypassable this way.
- *Evidence:* high_confidence — [blog.orange.tw](https://blog.orange.tw/posts/2023-08-2023-webconf-the-evolution-of-web-security/); [blog.sonarsource.com](https://blog.sonarsource.com/nosql-injections-in-rocket-chat/)

**Adding a server-side filter clause such as `owner: session.user` to a query does not stop NoSQL injection if the request body is merged into the same filter object afterwards, because a duplicate key in the merged object replaces the server's clause rather than intersecting with it.**

Mechanism: Adding a server-side filter clause such as `owner: session.user` to a query does not stop NoSQL injection if the request body is merged into the same filter object afterwards, because a duplicate key in the merged object replaces the server's clause rather than intersecting with it. How to apply it in the field: treat this as the bypass it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable. Boundary of the rule: The rule is false when the merge is implemented so the server clause cannot be overwritten — the filter is built with the trusted key last, the body is projected through an allowlist of permitted fields, or the store applies the trusted clause separately from the user predicate — in which case the injected duplicate is dropped and the query is not widened.

- *Disproof:* The rule is false when the merge is implemented so the server clause cannot be overwritten — the filter is built with the trusted key last, the body is projected through an allowlist of permitted fields, or the store applies the trusted clause separately from the user predicate — in which case the injected duplicate is dropped and the query is not widened.
- *Evidence:* high_confidence — [firebase.google.com](https://firebase.google.com/docs/firestore/security/rules-query); [mongodb.com](https://www.mongodb.com/docs/manual/reference/operator/query/)

**A filter that only ever compares one scalar against one submitted value is bypassable with array-valued and negated operators such as $nin and $ne, which change the comparison's shape rather than its content.**

MongoDB's own operator inventory is the reason: $nin matches if the value is not equal to any of a given list of values, and $ne matches all values not equal to a specified value. An application that validates 'the submitted password is a plausible string' and then writes an equality filter is testing the syntax of the attacker's input, not the shape of its query. The field technique is to submit the same field twice, as an array, or with a negated operator key, so that the comparison the developer intended is replaced by one they never wrote. A denylist aimed at apostrophes and 1=1 strings is the OWASP-documented failure mode here - such filters are trivially bypassed and should supplement allowlisting rather than replace it.

- *Disproof:* It is blocked if the application coerces the parameter to a scalar of declared type before building the filter, or allowlists the exact set of accepted operators for a queryable field, or uses a driver API that accepts only typed values. It also fails as a bypass if the store is not MongoDB or a compatible document database and does not implement the operator - check the actual backend before assuming operator semantics.
- *Evidence:* high_confidence — [cheatsheetseries.owasp.org](https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html); [mongodb.com](https://www.mongodb.com/docs/manual/reference/operator/query/)

## Chaining

_No verified chain_link items yet._ Derived from evidence only, so this section is empty rather than plausible.


## 6. Impact

_What is actually demonstrable, and what to stop claiming._

**A single blind NoSQL injection that leaks a password reset token escalates to full account takeover of an administrator, because the leaked token authorises a password reset and the admin session then exposes far more attack surface.**

Chain it explicitly and record each step's evidence. Step 1: use the $regex oracle against an unauthenticated password-policy endpoint to recover any user's reset token character by character. Step 2: request the reset for that email, replay the leaked token, set a new password. Step 3: note that the takeover is loud - the victim is logged out and the password no longer works - so prefer the quiet path when hunting: target the account that will not notice. Step 4: from the authenticated session, enumerate what the role unlocks; Sonar's chain went on to leak an admin's email, password hash and 2FA secret via $where, then generated valid 2FA codes. Report the impact as the chain, not the injection: a single operator leak is medium on its own, an admin session with working 2FA codes is full compromise. Say plainly in the write-up which steps are proven and which are inferred.

- *Disproof:* If the recovered token is rejected by the reset endpoint (invalid/expired), or the resulting session is denied every privileged route, then the leak does not convert into account takeover and the impact claim reduces to a single blind token disclosure.
- *Evidence:* high_confidence — [blog.sonarsource.com](https://blog.sonarsource.com/nosql-injections-in-rocket-chat/); [hackprosec.com](https://www.hackprosec.com/penetration-testing.html)

## Coverage gap

These stages have no verified evidence and are therefore absent above: Preconditions, Chaining.
A procedure with a missing validation stage is not safe to act on — it produces findings rather than proofs.

---

*Generated from the evidence base. Where this file and the database disagree, the database is correct.*
