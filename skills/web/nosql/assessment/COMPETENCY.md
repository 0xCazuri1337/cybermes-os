# Methodology — NoSQL / Operator Injection

> Derived from 18 verified items. Regenerate with `python -m wks.methodgen --class nosql --apply`. Do not hand-edit: this file is a projection of the evidence, and edits are lost on the next cycle.

**Surface.** A document query is built from a parsed structure so type and operator semantics become attacker-controlled.

**References.** CWE-943 · A03:2021

## Preconditions

_No verified prerequisite items yet._ Derived from evidence only, so this section is empty rather than plausible.


## Reconnaissance signals

_No verified signal items yet._ Derived from evidence only, so this section is empty rather than plausible.


## 1. Test sequence

_Concrete mutations to try. Each is written to be executable, not to be a description of the vulnerability._

**Sending {"$ne":1} or {"$ne":null} as a credential or token field in a JSON login body bypasses the equality check, because the field is compared as an always-true query operator rather than as a literal string.**

Baseline first: POST /api/login with {"user":"known@x","password":"wrongpass"} and record the exact status and body. Then POST the same endpoint with {"user":"known@x","password":{"$ne":1}}. A 200 with a session cookie where the baseline returned 401 is the authentication bypass. Sonar's Rocket.Chat writeup gives the canonical form: an attacker can bypass a login by specifying an object as the password parameter which contains an operator expression that is always true, like {"$ne":1}. Note the constraint that makes this a technique rather than a certainty - it only works where the sink is a query lookup rather than a bcrypt compare, so a $ne success with a wrong password is itself proof the credential is not hashed before comparison. Test $ne:1, $ne:null and $gt:"" variants; if all are rejected as bad types the endpoint is type-guarded. The finding must be reproduced against a real endpoint rather than inferred from a code path.

- *Disproof:* If {"password":{"$ne":1}} returns the same 401 and body as the wrong-password baseline while a correct password still returns 200, the credential is not compared through a query operator and the operator-injection auth bypass does not exist on that endpoint.
- *Evidence:* high_confidence — [blog.sonarsource.com](https://blog.sonarsource.com/nosql-injections-in-rocket-chat/); [firebase.google.com](https://firebase.google.com/docs/firestore/security/rules-query)

**"abstract": "Sonar's research uncovered NoSQL injection vulnerabilities in Rocket.Chat that allow attackers to bypass authentication or extract data by injecting MongoDB query operators into user-controlled input fields.**

ce.com/blog/nosql-injections-in-rocket-chat/"
 },
 "headline": "NoSQL Injections in Rocket.Chat 3.12.1: How A Small Leak Grounds A Rocket",
 "description": "This article analyzes critical NoSQL injection vulnerabilities in Rocket.Chat 3.12.1, showing how attackers can exploit MongoDB query manipulation to escalate privileges, access sensitive data, and ultimately achieve remote code execution.",
 "abstract": "Sonar's research uncovered NoSQL injection vulnerabilities in Rocket.Chat that allow attackers to bypass authentication or extract data by injecting MongoDB query operators into user-controlled input fields. Unlike SQL injection, NoSQL injection exploits JSON-based query structures—passing objects like {\"$gt\": \"\"} instead of strings bypasses equality checks entirely, a pattern that standard input sanitization often misses. The findings affect versions of Rocket.Chat that directly pass user input into MongoDB queries without schema validation, emphasizing the need for strict input typing in Node.j

- *Disproof:* Refuted when: the payload is rejected when the same check runs with the defensive control ENABLED (a strict allowlist, a normalisation pass, or a WAF rule) rather than disabled. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“"abstract": "Sonar's research uncovered NoSQL injection vulnerabilities in Rocke”) does not occur under a test that isolates that control.
- *Evidence:* high_confidence — [blog.sonarsource.com](https://blog.sonarsource.com/nosql-injections-in-rocket-chat/); [portswigger.net](https://portswigger.net/web-security/nosql-injection)

**These can allow attackers to escalate their privileges, to execute arbitrary system commands on the host server, and to steal confidential user data and chat messages.**

t we investigate these vulnerabilities by first taking a quick look at NoSQL databases, then explaining how injections look like in that context. We then analyze the found vulnerabilities and how they can be chained for an exploit. Finally we give advice on how to prevent such bugs in your applications. Impact During the analysis of Rocket.Chat 3.12.1 we found two NoSQL Injection vulnerabilities. These can allow attackers to escalate their privileges, to execute arbitrary system commands on the host server, and to steal confidential user data and chat messages. Both vulnerabilities are fixed in version 3.13.2 and backported to older branches in versions 3.12.4 and 3.11.4. To attack a Rocket.Chat instance, an attacker either needs an account or has to know the email address of any user that has 2-factor authentication (2FA) disabled. Some open source communities use public Rocket.Chat instances with open registration, which would be vulnerable. In other

- *Disproof:* Refuted when: the value is bound as a parameter or written through the framework's own encoder, so the interpreter never sees attacker text as syntax. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“These can allow attackers to escalate their privileges, to execute arbitrary sys”) does not occur under a test that isolates that control.
- *Evidence:* high_confidence — [blog.sonarsource.com](https://blog.sonarsource.com/nosql-injections-in-rocket-chat/); [cwe.mitre.org](https://cwe.mitre.org/data/definitions/943.html)

## 2. Validation

_How to prove the finding rather than infer it. A technique that cannot be validated must not be reported._

**A NoSQL endpoint counts as validated-guarded only when a field-level operator object, a top-level operator such as $where, and a non-allowlisted field name are each rejected, because any one of the three passing leaves an injection path.**

Three probes, in order. (1) {"field":{"$ne":null}} - field-level operator. (2) {"$where":"1"} - top-level operator. (3) A field name not on the allowlist, e.g. {"admin":true}. A pass requires all three rejected, and the report should record the exact status and body of each rejection so the next tester can tell a type error from a filter. Sonar's Rocket.Chat finding is the reason probe 2 is mandatory: the endpoint's blocklist of fields did not stop $where, and the general drawback of a blocklist approach is that it is easy to miss something, whereas an allowlist that explicitly permits known values is more effective. Re-run the probes after any dependency or database version bump, because a correct blocklist can become insufficient when new operators are added in a future version of the database or when the application's data structures change. Also verify user input is validated server-side against an allowlist where possible - client-side validation is not a control here.

- *Disproof:* If {"field":{"$ne":null}} is rejected with a 400 while {"$where":"1"} still changes the result set, the field blocklist is bypassable and the endpoint is NOT guarded; the validation only passes when both the field-level and the top-level operator probes are rejected.
- *Evidence:* high_confidence — [blog.sonarsource.com](https://blog.sonarsource.com/nosql-injections-in-rocket-chat/); [portswigger.net](https://portswigger.net/web-security/nosql-injection)

## 3. False-positive rejection

_The checks that eliminate the most common non-findings. Run these BEFORE reporting, not after a rejection._

**Sending the operator payload as a plain string and getting a normal 'no results' response proves only that the value stayed a string, not that the endpoint is safe, because operator injection requires the parameter to arrive as a parsed object.**

The most common wasted hour in this class. $ne and $in are not magic sequences inside a string - MongoDB's $ne matches all values not equal to a specified value, and it does so because it is a query operator object in the query document, not because the text '$ne' appeared. Whether the payload works depends entirely on how the HTTP parameter was decoded into the query: with a framework that parses nested query syntax into objects, 'password[$ne]=' becomes {password:{$ne:''}}; with one that produces flat strings, the same bytes stay the literal string 'password[$ne]='. A hunter who tests only the flat-string form and records 'no injection, rejected cleanly' has established nothing. The same payload must be retried in the structured form the framework actually supports.

- *Disproof:* It IS a real negative result if the application type-checks the parameter before it reaches the store - OWASP lists type conversion with strict exception handling as a validation technique - so that the structured payload is coerced or rejected and the query runs with a scalar value. Prove it by showing the value arrives at the query builder as a string or is rejected with a type error; that makes the flat-string test sufficient and this fp_rule not applicable to that endpoint.
- *Evidence:* high_confidence — [cheatsheetseries.owasp.org](https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html); [mongodb.com](https://www.mongodb.com/docs/manual/reference/operator/query/)

**String concatenation of user input into a JSON document handed to a MongoDB driver is a code smell but not, by itself, NoSQL injection, because the driver serialises the value as data and operator injection requires the attacker to control the structure of the parsed document.**

This is the mirror-image false positive and it is expensive in reviewer time. If the application builds a document like {'username': untrusted} and passes it to the driver's find method, the driver JSON-encodes it; an input of { '$ne': '' } becomes the string '{ "$ne": "" }' and matches nothing. The injection surface only opens where the untrusted value is used as a KEY rather than a value, or is parsed back out of a string into a structure before the query runs. A hunter should therefore ask one question before filing: did the attacker's bytes land in a key position, or did the application parse a string into a document with the attacker controlling the parse? If the answer is no, the finding is a robustness issue at most.

- *Disproof:* It IS injection if the untrusted value becomes a key - a field name, an operator name, or a nested path segment - because a key cannot be escaped by value serialisation. It is also injection where a framework's parameter parser turns bracket syntax into nested objects before the application sees them, or where the application calls something like eval or JSON.parse on attacker input to build the filter. Show the attacker-controlled key or the parse step and the finding stands.
- *Evidence:* high_confidence — [cwe.mitre.org](https://cwe.mitre.org/data/definitions/943.html); [mongodb.com](https://www.mongodb.com/docs/manual/reference/operator/query/)

## 4. Known bypasses

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

**Authentication can be bypassed in a NoSQL login by supplying a query operator that always matches (e.g., {"$ne": null} or {"$gt": ""}) in the password or credential field, so the query returns the target user's document and the application logs the attacker in without a valid password.**

1) Target a login form that queries the users collection by username and password. 2) Substitute the password value with {"$ne": null} (or {"$gt": ""}); the query becomes {"username": {"$eq": "admin"}, "password": {"$ne": null}}. 3) The query now matches any document where the password field exists and is not null, which is true for the admin document. 4) The application authenticates the attacker as the first matching user. Because the driver parses the input as a query object, the JSON meta-characters are interpreted as operators rather than literal string content.

- *Disproof:* If the application uses parameterized queries / a query builder that escapes or type-coerces input (e.g., passing input as a string value), $ne/$gt are never evaluated as operators and the bypass fails.
- *Evidence:* high_confidence — [cheatsheetseries.owasp.org](https://cheatsheetseries.owasp.org/cheatsheets/NoSQL_Injection_Prevention_Cheat_Sheet.html); [cwe.mitre.org](https://cwe.mitre.org/data/definitions/943.html); [github.com](https://github.com/cr0hn/vulnerable-node-mongo)

## 5. Chaining

_How this class escalates when combined with others. Each step is anchored to a promoted item._

**NoSQL operator injection in a search or filter endpoint, when combined with broken object-level authorization (BOLA/IDOR, CWE-639), allows an attacker to escalate a query from one user's view to a broader dataset, and eventually to full data exposure of the collection.**

1) Inject an operator such as {"$gt": ""} or {"$ne": null} in a search filter to bypass the application's intended access control on a per-user query. 2) Because the query now matches documents across the whole collection, the attacker reads records belonging to other users (BOLA). 3) Repeat with $regex or $or to enumerate all users, or use $where/$function for full extraction. 4) Chain: NoSQL injection (operator bypass) -> BOLA (cross-user data access) -> full collection dump. The operator injection removes the per-user scoping, and missing object-level authorization allows horizontal escalation.

- *Disproof:* If the query is anchored to a fixed user ID (e.g., {"user_id": ObjectId(session_user)}) and input cannot alter that subfield, the operator injection cannot change the scoping; if the application enforces per-object ownership checks after the query, the BOLA step fails.
- *Evidence:* high_confidence — [cheatsheetseries.owasp.org](https://cheatsheetseries.owasp.org/cheatsheets/NoSQL_Injection_Prevention_Cheat_Sheet.html); [cwe.mitre.org](https://cwe.mitre.org/data/definitions/943.html); [github.com](https://github.com/cr0hn/vulnerable-node-mongo)

## 6. Impact

_What is actually demonstrable, and what to stop claiming._

**A single blind NoSQL injection that leaks a password reset token escalates to full account takeover of an administrator, because the leaked token authorises a password reset and the admin session then exposes far more attack surface.**

Chain it explicitly and record each step's evidence. Step 1: use the $regex oracle against an unauthenticated password-policy endpoint to recover any user's reset token character by character. Step 2: request the reset for that email, replay the leaked token, set a new password. Step 3: note that the takeover is loud - the victim is logged out and the password no longer works - so prefer the quiet path when hunting: target the account that will not notice. Step 4: from the authenticated session, enumerate what the role unlocks; Sonar's chain went on to leak an admin's email, password hash and 2FA secret via $where, then generated valid 2FA codes. Report the impact as the chain, not the injection: a single operator leak is medium on its own, an admin session with working 2FA codes is full compromise. Say plainly in the write-up which steps are proven and which are inferred.

- *Disproof:* If the recovered token is rejected by the reset endpoint (invalid/expired), or the resulting session is denied every privileged route, then the leak does not convert into account takeover and the impact claim reduces to a single blind token disclosure.
- *Evidence:* high_confidence — [blog.sonarsource.com](https://blog.sonarsource.com/nosql-injections-in-rocket-chat/); [hackprosec.com](https://www.hackprosec.com/penetration-testing.html)

**NoSQL injection impact extends beyond authentication bypass: it can yield unauthorized data disclosure, data modification, privilege escalation at the application layer, and in the worst case remote code execution on the database server, exposing the entire backend data store.**

CWE-943 (Missing Normalization of Input During Specification) and OWASP A03:2021 (Injection) rank NoSQL operator injection as a high-severity risk. Impact depends on the database and reachable operators: authentication bypass for identity takeover; read access to all collection documents; write access to modify records (e.g., change roles/permissions); and JavaScript evaluation for full server compromise. The MongoDB $where and $function operators in particular can convert a query manipulation into OS-level code execution.

- *Disproof:* If all inputs are type-validated to scalars and the query engine rejects operator keys, impact is limited to reflected content only; if the database has dropped JS execution capability, OS-level compromise is not achievable.
- *Evidence:* high_confidence — [cheatsheetseries.owasp.org](https://cheatsheetseries.owasp.org/cheatsheets/NoSQL_Injection_Prevention_Cheat_Sheet.html); [cwe.mitre.org](https://cwe.mitre.org/data/definitions/943.html); [github.com](https://github.com/cr0hn/vulnerable-node-mongo)

## Coverage gap

These stages have no verified evidence and are therefore absent above: Preconditions, Reconnaissance signals.
A procedure with a missing validation stage is not safe to act on — it produces findings rather than proofs.

---

*Generated from the evidence base. Where this file and the database disagree, the database is correct.*
