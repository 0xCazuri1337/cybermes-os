<!-- GENERATED from db/wks.db — do not edit -->
# NoSQL / Operator Injection

## Definition

A document query is built from a parsed structure so type and operator semantics become attacker-controlled.

- **CWE:** 943
- **OWASP:** A03:2021
- **Surface:** web
- **Aliases:** ["nosql injection", "mongo injection", "operator injection"]

Canonical home for `nosql`. Rendered from `db/wks.db` by `tools/taxonomy/build_taxonomy.py` — edit the rows, not this file.

## Root Cause

Not yet researched.

## Preconditions

Not yet researched.

## Attack Surface

Surface: **web**.

The entry points and enabling conditions for this surface are enumerated under **Preconditions**; the observable signals are under **Detection**.

## Detection

**A JSON request field documented as a string that returns a structurally different response when sent as an object ({$ne:null}, {$exists:true}) is a NoSQL injection signal, because the value type changed the query's behaviour rather than being rejected.**

The signal is a differential on the request TYPE, not on the request content. Baseline the endpoint three ways with an otherwise identical request: field as a documented scalar (string), field as an empty object {}, and field as an operator object {"$ne":null}. Compare status, body length, and which fields come back. A type error (400/422 with a validation message) means the guard held; a 200 whose body differs from the scalar baseline means the object reached the query layer as query structure. Sonar's Rocket.Chat research makes this the practical test of the vulnerable shape - the endpoints affected were those that pass user input into MongoDB queries without schema validation, and the fix is strict input typing at each location that handles JSON user input: the input should only be a string, so adding a type check is the way to go. Treat anything user-supplied as hostile until proven otherwise, and log the type-anomaly as the signal, not the payload.

*Disproof:* If the object, integer and boolean forms of the field all return the same 400/422 validation error and only the documented string form reaches the handler, the field is type-guarded and there is no injection signal on that endpoint.

**A convincing observation for this class is: This LOOKS like a NoSQL injection because the response body contains every document including fields the app normally treats as sensitive, which reads exactly like a $ne-null bypass.**

Derived from nosql.fp_rule.public_list_endpoint_returning_everything_is_not_injection, which states the boundary for this class. The observation above is what a report must contain to be believed: an artifact the reviewer can re-check, not a claim the hunter asserts. A finding without it is an assertion.

*Disproof:* Not evidence when the observable cannot be produced at all -- blind, server-side-only, or identical-in-every-case behaviour leaves nothing to show. The originating rule (nosql.fp_rule.public_list_endpoint_returning_everything_is_not_injection) states the full boundary.

**A convincing observation for this class is: An endpoint that returns a byte-identical response for matching and non-matching prefixes has no oracle.**

Derived from nosql.technique.regex_oracle_character_by_character_leak, which states the boundary for this class. The observation above is what a report must contain to be believed: an artifact the reviewer can re-check, not a claim the hunter asserts. A finding without it is an assertion.

*Disproof:* Not evidence when the observable cannot be produced at all -- blind, server-side-only, or identical-in-every-case behaviour leaves nothing to show. The originating rule (nosql.technique.regex_oracle_character_by_character_leak) states the full boundary.

**Reaching `$where` means a JavaScript expression is evaluated server-side, which is strictly stronger than reaching `$regex`, and MongoDB implements regex pattern matching with PCRE2, so a successful pattern probe is evidence of a ReDoS-capable sink rather than of arbitrary server-side code execution.**

Mechanism: Reaching `$where` means a JavaScript expression is evaluated server-side, which is strictly stronger than reaching `$regex`, and MongoDB implements regex pattern matching with PCRE2, so a successful pattern probe is evidence of a ReDoS-capable sink rather than of arbitrary server-side code execution. How to apply it in the field: treat this as the evidence it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable. Boundary of the rule: The claim is false on a deployment that disables `$where` (server-side JS execution is off by default in several managed configurations) while leaving `$regex` enabled, in which case only the pattern-level injection is reachable and the two must not be conflated; equally, a server that has disabled both operators shows neither.

*Disproof:* The claim is false on a deployment that disables `$where` (server-side JS execution is off by default in several managed configurations) while leaving `$regex` enabled, in which case only the pattern-level injection is reachable and the two must not be conflated; equally, a server that has disabled both operators shows neither.

**Any claim that a NoSQL injection yields server-side JavaScript execution must first show the query used $where or mapReduce, because the ordinary comparison operators return data and never evaluate attacker-supplied code.**

This separates two very different findings that get filed as one. $where takes a string containing a JavaScript expression or a full JavaScript function and the database processes that expression for each document in the collection - that is the condition for code evaluation, and it also explains the performance cliff that gives the bug away. Everything else in the operator set, $ne, $in, $nin, $regex, $or, $not, is a predicate over stored data: an attacker who injects those gets unauthorized records, which is a serious access-control failure but not execution. In a report, the evidence for the execution claim has to be the constructed query containing $where, not a widened result set; the widened result set proves only the access-control half.

*Disproof:* The access-control claim survives regardless of $where - if $ne widened the result set, records were disclosed whether or not any code ran. And $where being available is not by itself reachable injection: it must be in the query the attacker can influence. Show the query text and the widened result set separately and label each for the impact it actually supports.

**A convincing observation for this class is: Adjacent behaviour that produces the same observable result: A JSON request field documented as a string that returns a structurally different response when sent as an object ({$ne:null}, {$exists:true}) is a NoSQL injection signal, because the value type changed the query's behaviour rather than...**

Derived from nosql.fp_rule.auto.derived, which states the boundary for this class. The observation above is what a report must contain to be believed: an artifact the reviewer can re-check, not a claim the hunter asserts. A finding without it is an assertion.

*Disproof:* Not evidence when the observable cannot be produced at all -- blind, server-side-only, or identical-in-every-case behaviour leaves nothing to show. The originating rule (nosql.fp_rule.auto.derived) states the full boundary.

## Exploitation

**When exploiting SQL Injections, joins and subqueries are often used to leak data from different tables.**

: "admin" 
 } A classic injection in this scenario occurs when a program expects a certain user-provided value to be a string, but it can also be an object. This happens often when user input comes in JSON format. In such a case, an attacker can for example bypass a login by specifying an object as the password parameter which contains an operator expression that is always true, like  {"$ne":1} . When exploiting SQL Injections, joins and subqueries are often used to leak data from different tables. There are equivalents of this in MongoDB, but they cannot be used in every scenario. Attackers have to get creative when they find a NoSQL Injection, because it usually does not give them the same capabilities that an SQL Injection would. NoSQL Injection #1: Taking Over a Regular User  During our research we managed to execute arbitrary code on the server, but we had to take small steps to get th

*Disproof:* This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "When exploiting SQL Injections, joins and subqueries are often used to leak data from diff".

**Exploitation of this vulnerability works like this: an attacker requests a password reset for a user using their email address, uses the oracle to leak the newly created token, and finally uses that token to change the user’s password.**

This can be used to create an oracle that can tell whether a token begins with a certain sequence of characters or not. When the query matches a user, the server’s password policy is returned, but when it does not return any result the method returns an error. An attacker can repeatedly make guesses and observe the oracle’s response to see if our guess was correct, until the whole token is known. Exploitation of this vulnerability works like this: an attacker requests a password reset for a user using their email address, uses the oracle to leak the newly created token, and finally uses that token to change the user’s password. This enables access to more attack surface because authenticated users, while having no special privileges, can use a lot more of Rocket.Chat’s features. NoSQL Injection #2: Elevating Privileges Taking over a user account with the previously described NoSQL injection was noisy: the user got a password reset email, was logged out, and cannot log in because the password was changed. If that happens

*Disproof:* This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Exploitation of this vulnerability works like this: an attacker requests a password reset ".

**The first vulnerability is CVE-2021-22911: a Blind NoSQL Injection that allows to leak a user’s password reset token.**

aking Over a Regular User  During our research we managed to execute arbitrary code on the server, but we had to take small steps to get there. The first step for an attacker is to take over an unprivileged user account. One of the NoSQL Injections can be used without authentication, but it requires us to know the email address of a user that does not have two-factor authentication (2FA) enabled. The first vulnerability is CVE-2021-22911: a Blind NoSQL Injection that allows to leak a user’s password reset token. The vulnerable part of the code is located in the  getPasswordPolicy()  method. This method can be called without being authenticated, which makes sense because the frontend needs to know the password policy when users are registering. Its parameter  params  is coming from a user-controlled JSON value but is not validated in any way: server/methods/getPasswordPolicy.js Copy to clipboard 7 getPass

*Disproof:* This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "The first vulnerability is CVE-2021-22911: a Blind NoSQL Injection that allows to leak a u".

**To escape a VM context, the attacker has to get access to objects from the parent context.**

ng incoming and outgoing web hooks. These web hooks can have scripts associated with them that are executed when the web hook is triggered. They are run using the  vm  module  of Node.js which might sound safe to use but is explicitly declared to not be a security mechanism. A script that runs inside a VM context has no access to system resources per default, but there are easy ways to break out. To escape a VM context, the attacker has to get access to objects from the parent context. In this case there are multiple objects and functions passed to the script as arguments which can be used to access the parent context’s function constructor to create a new function. Any functions created with that constructor will inherit its context, regardless of the context they are executed in. In order to execute system commands on the server the attacker creates a script that will get the

*Disproof:* This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "To escape a VM context, the attacker has to get access to objects from the parent context.".

**But it still allows for more flexibility when exploiting this injection.**

ch takes a JavaScript expression and executes it for each document in a collection to decide if the document should be contained in the result set or not.  This sounds like Remote Code Execution (RCE) but the code is executed inside the MongoDB process and is very restricted, it can only access the fields of the current document and there are no APIs that allow interaction with the outside world. But it still allows for more flexibility when exploiting this injection. At first we thought this would be another case of a Blind NoSQL Injection where we would make incremental guesses to observe responses, because the result set is always stripped of any sensitive fields. But then we realized that we could leak values by throwing an error inside the  $where  operator’s JavaScript expression! The error is then passed back to the user in the API response with the ful

*Disproof:* This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "But it still allows for more flexibility when exploiting this injection.".

**We outlined how NoSQL Injections can be exploited, and how they can lead to a complete takeover of a Rocket.Chat instance.**

report detailed advisories for the NoSQL Injection issues via HackerOne 2021-03-22 Vendor confirms the vulnerabilities 2021-04-14 Vendor fixes the NoSQL Injection issues and releases new versions (3.13.2, 3.12.4, 3.11.4) Summary In this blog post we analyzed two code vulnerabilities found in  Rocket.Chat (3.12.1) , a widely used open source solution for team communications written in JavaScript. We outlined how NoSQL Injections can be exploited, and how they can lead to a complete takeover of a Rocket.Chat instance. We also explained how to prevent these kinds of vulnerabilities. We reported these vulnerabilities to the vendor in March 2021. They confirmed and fixed the vulnerabilities quickly and the communication with them went smoothly, so kudos to Rocket.Chat security team! If you are running Rocket.Chat, we highly recommend updating to the latest version. Share this blog X Facebook LinkedIn Email Share

*Disproof:* This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "We outlined how NoSQL Injections can be exploited, and how they can lead to a complete tak".

**"abstract": "Sonar's research uncovered NoSQL injection vulnerabilities in Rocket.Chat that allow attackers to bypass authentication or extract data by injecting MongoDB query operators into user-controlled input fields.**

ce.com/blog/nosql-injections-in-rocket-chat/"
 },
 "headline": "NoSQL Injections in Rocket.Chat 3.12.1: How A Small Leak Grounds A Rocket",
 "description": "This article analyzes critical NoSQL injection vulnerabilities in Rocket.Chat 3.12.1, showing how attackers can exploit MongoDB query manipulation to escalate privileges, access sensitive data, and ultimately achieve remote code execution.",
 "abstract": "Sonar's research uncovered NoSQL injection vulnerabilities in Rocket.Chat that allow attackers to bypass authentication or extract data by injecting MongoDB query operators into user-controlled input fields. Unlike SQL injection, NoSQL injection exploits JSON-based query structures—passing objects like {\"$gt\": \"\"} instead of strings bypasses equality checks entirely, a pattern that standard input sanitization often misses. The findings affect versions of Rocket.Chat that directly pass user input into MongoDB queries without schema validation, emphasizing the need for strict input typing in Node.j

*Disproof:* Refuted when: the payload is rejected when the same check runs with the defensive control ENABLED (a strict allowlist, a normalisation pass, or a WAF rule) rather than disabled. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“"abstract": "Sonar's research uncovered NoSQL injection vulnerabilities in Rocke”) does not occur under a test that isolates that control.

**These can allow attackers to escalate their privileges, to execute arbitrary system commands on the host server, and to steal confidential user data and chat messages.**

t we investigate these vulnerabilities by first taking a quick look at NoSQL databases, then explaining how injections look like in that context. We then analyze the found vulnerabilities and how they can be chained for an exploit. Finally we give advice on how to prevent such bugs in your applications. Impact During the analysis of Rocket.Chat 3.12.1 we found two NoSQL Injection vulnerabilities. These can allow attackers to escalate their privileges, to execute arbitrary system commands on the host server, and to steal confidential user data and chat messages. Both vulnerabilities are fixed in version 3.13.2 and backported to older branches in versions 3.12.4 and 3.11.4. To attack a Rocket.Chat instance, an attacker either needs an account or has to know the email address of any user that has 2-factor authentication (2FA) disabled. Some open source communities use public Rocket.Chat instances with open registration, which would be vulnerable. In other

*Disproof:* Refuted when: the value is bound as a parameter or written through the framework's own encoder, so the interpreter never sees attacker text as syntax. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“These can allow attackers to escalate their privileges, to execute arbitrary sys”) does not occur under a test that isolates that control.

**Sending {"$ne":1} or {"$ne":null} as a credential or token field in a JSON login body bypasses the equality check, because the field is compared as an always-true query operator rather than as a literal string.**

Baseline first: POST /api/login with {"user":"known@x","password":"wrongpass"} and record the exact status and body. Then POST the same endpoint with {"user":"known@x","password":{"$ne":1}}. A 200 with a session cookie where the baseline returned 401 is the authentication bypass. Sonar's Rocket.Chat writeup gives the canonical form: an attacker can bypass a login by specifying an object as the password parameter which contains an operator expression that is always true, like {"$ne":1}. Note the constraint that makes this a technique rather than a certainty - it only works where the sink is a query lookup rather than a bcrypt compare, so a $ne success with a wrong password is itself proof the credential is not hashed before comparison. Test $ne:1, $ne:null and $gt:"" variants; if all are rejected as bad types the endpoint is type-guarded. The finding must be reproduced against a real endpoint rather than inferred from a code path.

*Disproof:* If {"password":{"$ne":1}} returns the same 401 and body as the wrong-password baseline while a correct password still returns 200, the credential is not compared through a query operator and the operator-injection auth bypass does not exist on that endpoint.

**A $regex operator object in a lookup field turns the response into a boolean oracle, letting an attacker recover a secret token one character at a time by repeated prefix guesses against an unauthenticated endpoint.**

Send {"token":{"$regex":"^A"}} then {"token":{"$regex":"^B"}}; the prefix that changes the response (200 with data vs error or empty) is the first character. Extend the confirmed prefix and repeat until the whole value is recovered. Sonar describes exactly this loop on Rocket.Chat's getPasswordPolicy, reachable without authentication because the frontend needs the policy at registration: the token parameter is user-controlled JSON, so MongoDB's $regex operator can be used to check whether a token begins with a certain character, and an attacker repeatedly makes guesses and observes the oracle's response until the whole token is known. Cost control: keep each probe to a bounded character class over the prefix you have already confirmed, and stop as soon as you hold a reset token rather than a password. This is hand-iterated work by nature, not a scanner pass. An endpoint that returns a byte-identical response for matching and non-matching prefixes has no oracle.

*Disproof:* If {"token":{"$regex":"^A"}} and {"token":{"$regex":"^ZZZZ"}} produce byte-identical responses, and the same for every prefix tried, there is no observable difference to build an oracle from and the blind character-leak technique does not work against this endpoint.

## Variations

**Authentication can be bypassed in a NoSQL login by supplying a query operator that always matches (e.g., {"$ne": null} or {"$gt": ""}) in the password or credential field, so the query returns the target user's document and the application logs the attacker in without a valid password.**

1) Target a login form that queries the users collection by username and password. 2) Substitute the password value with {"$ne": null} (or {"$gt": ""}); the query becomes {"username": {"$eq": "admin"}, "password": {"$ne": null}}. 3) The query now matches any document where the password field exists and is not null, which is true for the admin document. 4) The application authenticates the attacker as the first matching user. Because the driver parses the input as a query object, the JSON meta-characters are interpreted as operators rather than literal string content.

*Disproof:* If the application uses parameterized queries / a query builder that escapes or type-coerces input (e.g., passing input as a string value), $ne/$gt are never evaluated as operators and the bypass fails.

**If user input reaches the $where operator or a server-side JavaScript string that is evaluated (db.eval / $function), an attacker can inject JavaScript that executes on the database server, achieving remote code execution at the DB tier.**

1) Identify a field or search parameter passed into a $where clause or an eval() call in the application code or database query. 2) Inject a JavaScript expression such as {"$where": "this.username.equals('admin')"} or, for code execution, {"$where": "this.password.match(/.*/)"}. 3) The database evaluates the injected JavaScript within its server context. 4) Combine with $function or db.eval to execute arbitrary JavaScript. MongoDB deprecated server-side JS but it can still be reachable via legacy deployments, $where on user-supplied data, or aggregation stages like $function/$accumulator.

*Disproof:* If $where receives a hardcoded/allowlisted expression or the input is type-checked to a plain string, JavaScript is never executed. If the deployment has dropped $function/$accumulator and db.eval, server-side JS execution is not available.

**A filter that only ever compares one scalar against one submitted value is bypassable with array-valued and negated operators such as $nin and $ne, which change the comparison's shape rather than its content.**

MongoDB's own operator inventory is the reason: $nin matches if the value is not equal to any of a given list of values, and $ne matches all values not equal to a specified value. An application that validates 'the submitted password is a plausible string' and then writes an equality filter is testing the syntax of the attacker's input, not the shape of its query. The field technique is to submit the same field twice, as an array, or with a negated operator key, so that the comparison the developer intended is replaced by one they never wrote. A denylist aimed at apostrophes and 1=1 strings is the OWASP-documented failure mode here - such filters are trivially bypassed and should supplement allowlisting rather than replace it.

*Disproof:* It is blocked if the application coerces the parameter to a scalar of declared type before building the filter, or allowlists the exact set of accepted operators for a queryable field, or uses a driver API that accepts only typed values. It also fails as a bypass if the store is not MongoDB or a compatible document database and does not implement the operator - check the actual backend before assuming operator semantics.

**Adding a server-side filter clause such as `owner: session.user` to a query does not stop NoSQL injection if the request body is merged into the same filter object afterwards, because a duplicate key in the merged object replaces the server's clause rather than intersecting with it.**

Mechanism: Adding a server-side filter clause such as `owner: session.user` to a query does not stop NoSQL injection if the request body is merged into the same filter object afterwards, because a duplicate key in the merged object replaces the server's clause rather than intersecting with it. How to apply it in the field: treat this as the bypass it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable. Boundary of the rule: The rule is false when the merge is implemented so the server clause cannot be overwritten — the filter is built with the trusted key last, the body is projected through an allowlist of permitted fields, or the store applies the trusted clause separately from the user predicate — in which case the injected duplicate is dropped and the query is not widened.

*Disproof:* The rule is false when the merge is implemented so the server clause cannot be overwritten — the filter is built with the trusted key last, the body is projected through an allowlist of permitted fields, or the store applies the trusted clause separately from the user predicate — in which case the injected duplicate is dropped and the query is not widened.

**An endpoint that blocklists disallowed MongoDB field names but leaves top-level operators enabled is bypassed with {"$where":"..."}, which executes a JavaScript expression per document, is not covered by a field blocklist, and turns a stripped result set into an error-based exfiltration channel.**

Find the blocklist by diffing which fields a free-form filter accepts, then send a payload with no disallowed field at all: {"$where":"this.role==='admin'"}. If the result set changes, the blocklist only considers actual fields that could be queried and not top level MongoDB operators - exactly the gap Sonar found in Rocket.Chat's users.list endpoint, where a blocklist removed sensitive fields from query and result but left $where usable as a bypass. Two consequences make this more than a read primitive: $where runs inside the MongoDB process with access to the current document's fields, and by throwing an exception inside the expression the error is passed back to the user in the API response with the full error message, turning a stripped result set into full exfiltration of an admin's fields. So response-side filtering is not a control either: it is not enough to simply restrict the projection, i.e. the data that is returned from the query, because blind or error-based NoSQL Injections can still be used to leak that data. Try $where, $expr and $function in turn; any that changes behaviour is a working bypass. CouchDB, which Orange Tsai lists as a real-world RCE target, is the same document-store class of target if you need a second worked example.

*Disproof:* If {"$where":"1==1"}, {"$expr":true} and a throwing expression inside $where are all rejected with a validation error before the query runs, and $where never appears to change the result set, then top-level operators are denied and the field blocklist is not bypassable this way.

## Technology / Framework Considerations

Not yet researched.

## API Considerations

Not yet researched.

## Attack Chains

- `chain.nosql.auto.01` — nosql: observe, exercise, confirm (goal: `Establish, exercise and confirm a nosql condition on an authorised target without relying on anyone else's data.`)

## Real-World Examples

Not yet researched.

## Common False Positives

**String concatenation of user input into a JSON document handed to a MongoDB driver is a code smell but not, by itself, NoSQL injection, because the driver serialises the value as data and operator injection requires the attacker to control the structure of the parsed document.**

This is the mirror-image false positive and it is expensive in reviewer time. If the application builds a document like {'username': untrusted} and passes it to the driver's find method, the driver JSON-encodes it; an input of { '$ne': '' } becomes the string '{ "$ne": "" }' and matches nothing. The injection surface only opens where the untrusted value is used as a KEY rather than a value, or is parsed back out of a string into a structure before the query runs. A hunter should therefore ask one question before filing: did the attacker's bytes land in a key position, or did the application parse a string into a document with the attacker controlling the parse? If the answer is no, the finding is a robustness issue at most.

*Disproof:* It IS injection if the untrusted value becomes a key - a field name, an operator name, or a nested path segment - because a key cannot be escaped by value serialisation. It is also injection where a framework's parameter parser turns bracket syntax into nested objects before the application sees them, or where the application calls something like eval or JSON.parse on attacker input to build the filter. Show the attacker-controlled key or the parse step and the finding stands.

**A NoSQL injection finding requires the attacker-supplied operator object to reach the query and change which documents match; an application that coerces the request body to a typed or validated model, or that strips keys beginning with `$`, produces a 400 or an unchanged result set and is not vulnerable.**

Mechanism: A NoSQL injection finding requires the attacker-supplied operator object to reach the query and change which documents match; an application that coerces the request body to a typed or validated model, or that strips keys beginning with `$`, produces a 400 or an unchanged result set and is not vulnerable. How to apply it in the field: treat this as the fp_rule it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable. Boundary of the rule: The rule is wrong when the operator reaches a secondary sink the coercion does not cover — a count, aggregation, sort, or projection stage, or a second query built from a value taken out of the same body — because the primary query can be fully validated while the derived one still honours the injected operator.

*Disproof:* The rule is wrong when the operator reaches a secondary sink the coercion does not cover — a count, aggregation, sort, or projection stage, or a second query built from a value taken out of the same body — because the primary query can be fully validated while the derived one still honours the injected operator.

**Sending the operator payload as a plain string and getting a normal 'no results' response proves only that the value stayed a string, not that the endpoint is safe, because operator injection requires the parameter to arrive as a parsed object.**

The most common wasted hour in this class. $ne and $in are not magic sequences inside a string - MongoDB's $ne matches all values not equal to a specified value, and it does so because it is a query operator object in the query document, not because the text '$ne' appeared. Whether the payload works depends entirely on how the HTTP parameter was decoded into the query: with a framework that parses nested query syntax into objects, 'password[$ne]=' becomes {password:{$ne:''}}; with one that produces flat strings, the same bytes stay the literal string 'password[$ne]='. A hunter who tests only the flat-string form and records 'no injection, rejected cleanly' has established nothing. The same payload must be retried in the structured form the framework actually supports.

*Disproof:* It IS a real negative result if the application type-checks the parameter before it reaches the store - OWASP lists type conversion with strict exception handling as a validation technique - so that the structured payload is coerced or rejected and the query runs with a scalar value. Prove it by showing the value arrives at the query builder as a string or is rejected with a type error; that makes the flat-string test sufficient and this fp_rule not applicable to that endpoint.

**Returning more documents than the caller should see is by itself an access-control or pagination bug, not NoSQL injection; it becomes injection only when the widening was produced by an operator the caller supplied.**

Mechanism: Returning more documents than the caller should see is by itself an access-control or pagination bug, not NoSQL injection; it becomes injection only when the widening was produced by an operator the caller supplied. How to apply it in the field: treat this as the fp_rule it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable. Boundary of the rule: The rule is wrong when the widening traces to a server-side query construction that merges the whole request body into the filter — even without an explicit `$`-prefixed payload, a body that legitimately carries an `owner` or `role` field is attacker-controlled and drives the operator-equivalent behaviour, so the two findings collapse into one injection with a non-`$` payload.

*Disproof:* The rule is wrong when the widening traces to a server-side query construction that merges the whole request body into the filter — even without an explicit `$`-prefixed payload, a body that legitimately carries an `owner` or `role` field is attacker-controlled and drives the operator-equivalent behaviour, so the two findings collapse into one injection with a non-`$` payload.

**Reject a nosql finding until it is distinguished from the adjacent behaviour this class also covers. "An endpoint that blocklists disallowed MongoDB field names but leaves top-level operators enabled is bypassed with {"$where":"..."}, which executes a JavaScript expression per document, is not covered by a field blocklist, and turns a..." and "A JSON request field documented as a string that returns a structurally different response when sent as an object ({$ne:null}, {$exists:true}) is a NoSQL injection signal, because the value type changed the query's behaviour rather than..." share a surface and a symptom, so a response that matches the first is not evidence for it while the second remains possible.**

Hypothesis under test: An endpoint that blocklists disallowed MongoDB field names but leaves top-level operators enabled is bypassed with {"$where":"..."}, which executes a JavaScript expression per document, is not covered by a field blocklist, and turns a...

Adjacent behaviour that produces the same observable result: A JSON request field documented as a string that returns a structurally different response when sent as an object ({$ne:null}, {$exists:true}) is a NoSQL injection signal, because the value type changed the query's behaviour rather than...

Why this is worth checking before reporting: both are recorded in this class as gated knowledge, so a tester who stops at the first match will report one of them. The two differ in what the server actually did with the input, and that difference is observable in the response rather than in the request.

Required before treating this as a finding: capture the response that demonstrates the first behaviour specifically, and confirm the second is not what was observed.

*Disproof:* This rule is wrong if a controlled test shows the two behaviours can never co-occur on the same surface, or if the corpus entry for "A JSON request field documented as a string that returns a structurall" is out of date. In that case this class needs its false-positive guidance rewritten rather than deleted.

**A JSON list endpoint that returns every record to an anonymous caller because it is a public list is NOT NoSQL injection; the separating observation is whether an operator object changes the result set relative to a documented-field request.**

This LOOKS like a NoSQL injection because the response body contains every document including fields the app normally treats as sensitive, which reads exactly like a $ne-null bypass. It is actually the endpoint's intended contract: a public listing API with no authorization boundary. The observation that separates them is differential, not volume. Send three requests with identical authentication: (a) a documented filter field, {"status":"active"}; (b) an operator object on that same field, {"status":{"$ne":"deleted"}}; (c) an empty query {}. If (a), (b) and (c) return the same document set, no operator was interpreted - the endpoint simply has no filter, and the report is an access-control question (test it as every role you have), not a query-injection question. If (b) returns strictly more documents than (a), the operator was parsed by the query layer and this really is injection. Count documents rather than eyeballing fields: a large public list and a successful $ne differ only in whether the operator changes the set.

*Disproof:* If {"status":{"$ne":"deleted"}} returns a different or larger document set than {"status":"active"} on the same endpoint and credential, the operator changed the query and the finding is genuine NoSQL injection, not a public list.

## Validation

**The convincing NoSQL-injection observation is a response whose document set or status code changes between two otherwise identical requests that differ only in the type of the submitted field (a scalar string versus a JSON object or array such as {"$ne": null}), because a normal filter cannot produce that difference.**

Mechanism: The convincing NoSQL-injection observation is a response whose document set or status code changes between two otherwise identical requests that differ only in the type of the submitted field (a scalar string versus a JSON object or array such as {"$ne": null}), because a normal filter cannot produce that difference. How to apply it in the field: treat this as the validation it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable. Boundary of the rule: The claim is false when the endpoint legitimately accepts a structured filter and applies the same type coercion to every caller, so the operator-shaped value is treated as a literal and the result set difference comes from the intended filter semantics; in that case the difference is documented behaviour and needs a second probe (a negative operator such as $where or $regex with a measurable side effect) to show attacker control.

*Disproof:* The claim is false when the endpoint legitimately accepts a structured filter and applies the same type coercion to every caller, so the operator-shaped value is treated as a literal and the result set difference comes from the intended filter semantics; in that case the difference is documented behaviour and needs a second probe (a negative operator such as $where or $regex with a measurable side effect) to show attacker control.

**The canonical proof is a login query in which the username predicate is a real record and the password predicate is $ne with an empty value, because a successful login then demonstrates that the server-side filter's boolean logic was attacker-shaped rather than merely loose.**

CWE-943 states the consequence that matters most: if the query expects to return exactly one administrative entity and an attacker changes which entities are returned, the application logic can pick a regular user's record and wrongly conclude the caller is an administrator. The $ne proof attacks exactly that. Because $ne matches all values that are not equal to a specified value, a filter of {username:'admin', password:{$ne:''}} authenticates as long as the admin's password field is non-empty - which it always is, since it is a hash. The evidence in a report is the returned session, the cookies, and the absence of any supplied password, together with the login-status differential between the operator payload and a wrong password. That combination, not the payload string itself, is the finding.

*Disproof:* It is not exploitable if the application performs the credential check outside the database - a fetch-then-compare in application code, or an LDAP/AD bind - so the filter never encodes the password condition. It also fails if the account has no password field at all, in which case $ne matches every user rather than confirming anything about this one, and the returned identity must be verified before the claim is made.

**A NoSQL endpoint counts as validated-guarded only when a field-level operator object, a top-level operator such as $where, and a non-allowlisted field name are each rejected, because any one of the three passing leaves an injection path.**

Three probes, in order. (1) {"field":{"$ne":null}} - field-level operator. (2) {"$where":"1"} - top-level operator. (3) A field name not on the allowlist, e.g. {"admin":true}. A pass requires all three rejected, and the report should record the exact status and body of each rejection so the next tester can tell a type error from a filter. Sonar's Rocket.Chat finding is the reason probe 2 is mandatory: the endpoint's blocklist of fields did not stop $where, and the general drawback of a blocklist approach is that it is easy to miss something, whereas an allowlist that explicitly permits known values is more effective. Re-run the probes after any dependency or database version bump, because a correct blocklist can become insufficient when new operators are added in a future version of the database or when the application's data structures change. Also verify user input is validated server-side against an allowlist where possible - client-side validation is not a control here.

*Disproof:* If {"field":{"$ne":null}} is rejected with a 400 while {"$where":"1"} still changes the result set, the field blocklist is bypassable and the endpoint is NOT guarded; the validation only passes when both the field-level and the top-level operator probes are rejected.

**To decide this case, observe: This LOOKS like a NoSQL injection because the response body contains every document including fields the app normally treats as sensitive, which reads exactly like a $ne-null bypass.**

Derived from nosql.fp_rule.public_list_endpoint_returning_everything_is_not_injection, which states the false-positive boundary for this class. The observable above is what separates a real finding from the pattern that only looks like one. A hunter who cannot produce this observation in a request/response pair does not have a finding yet.

*Disproof:* This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (nosql.fp_rule.public_list_endpoint_returning_everything_is_not_injection) states the full boundary.

**To decide this case, observe: How to apply it in the field: treat this as the fp_rule it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable.**

Derived from nosql.fp_rule.a_rejected_operator_object_is_not_injection, which states the false-positive boundary for this class. The observable above is what separates a real finding from the pattern that only looks like one. A hunter who cannot produce this observation in a request/response pair does not have a finding yet.

*Disproof:* This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (nosql.fp_rule.a_rejected_operator_object_is_not_injection) states the full boundary.

**To decide this case, observe: How to apply it in the field: treat this as the bypass it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable.**

Derived from nosql.bypass.a_server_side_filter_is_not_a_defence_against_client_supplied_operators, which states the false-positive boundary for this class. The observable above is what separates a real finding from the pattern that only looks like one. A hunter who cannot produce this observation in a request/response pair does not have a finding yet.

*Disproof:* This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (nosql.bypass.a_server_side_filter_is_not_a_defence_against_client_supplied_operators) states the full boundary.

**To decide this case, observe: Two consequences make this more than a read primitive: $where runs inside the MongoDB process with access to the current document's fields, and by throwing an exception inside the expression the error is passed back to the user in the API response with the full error message, turning a stripped result set into full exfiltration of an admin's fields.**

Derived from nosql.bypass.blocklist_bypass_via_top_level_where_operator, which states the false-positive boundary for this class. The observable above is what separates a real finding from the pattern that only looks like one. A hunter who cannot produce this observation in a request/response pair does not have a finding yet.

*Disproof:* This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (nosql.bypass.blocklist_bypass_via_top_level_where_operator) states the full boundary.

**To decide this case, observe: Mechanism: Returning more documents than the caller should see is by itself an access-control or pagination bug, not NoSQL injection; it becomes injection only when the widening was produced by an operator the caller supplied.**

Derived from nosql.fp_rule.an_unauthorized_document_returned_because_the_query_matched_more_is_still_injection_only_if_the_operator_was_attacker_controlled, which states the false-positive boundary for this class. The observable above is what separates a real finding from the pattern that only looks like one. A hunter who cannot produce this observation in a request/response pair does not have a finding yet.

*Disproof:* This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (nosql.fp_rule.an_unauthorized_document_returned_because_the_query_matched_more_is_still_injection_only_if_the_operator_was_attacker_controlled) states the full boundary.

**To decide this case, observe: Mechanism: The convincing NoSQL-injection observation is a response whose document set or status code changes between two otherwise identical requests that differ only in the type of the submitted field (a scalar string versus a JSON object or array such as {"$ne": null}), because a normal filter cannot produce that difference. How to apply it in t**

Derived from nosql.validation.boolean_operator_probe_is_the_observation_that_distinguishes_injection_from_normal_filtering, which states the false-positive boundary for this class. The observable above is what separates a real finding from the pattern that only looks like one. A hunter who cannot produce this observation in a request/response pair does not have a finding yet.

*Disproof:* This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (nosql.validation.boolean_operator_probe_is_the_observation_that_distinguishes_injection_from_normal_filtering) states the full boundary.

## Impact

**NoSQL injection impact extends beyond authentication bypass: it can yield unauthorized data disclosure, data modification, privilege escalation at the application layer, and in the worst case remote code execution on the database server, exposing the entire backend data store.**

CWE-943 (Missing Normalization of Input During Specification) and OWASP A03:2021 (Injection) rank NoSQL operator injection as a high-severity risk. Impact depends on the database and reachable operators: authentication bypass for identity takeover; read access to all collection documents; write access to modify records (e.g., change roles/permissions); and JavaScript evaluation for full server compromise. The MongoDB $where and $function operators in particular can convert a query manipulation into OS-level code execution.

*Disproof:* If all inputs are type-validated to scalars and the query engine rejects operator keys, impact is limited to reflected content only; if the database has dropped JS execution capability, OS-level compromise is not achievable.

**A single blind NoSQL injection that leaks a password reset token escalates to full account takeover of an administrator, because the leaked token authorises a password reset and the admin session then exposes far more attack surface.**

Chain it explicitly and record each step's evidence. Step 1: use the $regex oracle against an unauthenticated password-policy endpoint to recover any user's reset token character by character. Step 2: request the reset for that email, replay the leaked token, set a new password. Step 3: note that the takeover is loud - the victim is logged out and the password no longer works - so prefer the quiet path when hunting: target the account that will not notice. Step 4: from the authenticated session, enumerate what the role unlocks; Sonar's chain went on to leak an admin's email, password hash and 2FA secret via $where, then generated valid 2FA codes. Report the impact as the chain, not the injection: a single operator leak is medium on its own, an admin session with working 2FA codes is full compromise. Say plainly in the write-up which steps are proven and which are inferred.

*Disproof:* If the recovered token is rejected by the reset endpoint (invalid/expired), or the resulting session is denied every privileged route, then the leak does not convert into account takeover and the impact claim reduces to a single blind token disclosure.

## Related Bug Classes

Not yet researched.

## References

- **blog.orange.tw** (writeup)
  - <https://blog.orange.tw/posts/2023-08-2023-webconf-the-evolution-of-web-security/>
- **blog.sonarsource.com** (research)
  - <https://blog.sonarsource.com/nosql-injections-in-rocket-chat/>
- **cheatsheetseries.owasp.org** (writeup)
  - <https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html>
  - <https://cheatsheetseries.owasp.org/cheatsheets/NoSQL_Injection_Prevention_Cheat_Sheet.html>
- **cwe.mitre.org** (writeup)
  - <https://cwe.mitre.org/data/definitions/943.html>
- **firebase.google.com** (writeup)
  - <https://firebase.google.com/docs/firestore/security/rules-fields>
  - <https://firebase.google.com/docs/firestore/security/rules-query>
- **github.com** (practitioner)
  - <https://github.com/cr0hn/vulnerable-node-mongo>
- **hackprosec.com** (vendor)
  - <https://www.hackprosec.com/penetration-testing.html>
- **invicti.com** (web)
  - <https://www.invicti.com/blog/web-security/nosql-injection-cheat-sheet>
- **mongodb.com** (primary)
  - <https://www.mongodb.com/docs/manual/core/query-operators/>
  - <https://www.mongodb.com/docs/manual/reference/operator/aggregation/function/>
  - <https://www.mongodb.com/docs/manual/reference/operator/query/>
  - <https://www.mongodb.com/docs/manual/reference/operator/query/regex/>
  - <https://www.mongodb.com/docs/manual/reference/operator/query/where/>
- **owasp.org** (primary)
  - <https://owasp.org/Top10/A03_2021-Injection/>
- **portswigger.net** (writeup)
  - <https://portswigger.net/web-security/nosql-injection>
  - <https://portswigger.net/web-security/nosql-injection/advanced>
- **sourcegraph.com** (writeup)
  - <https://sourcegraph.com/blog/code-review-checklist>

Every item above is gated on >= 2 distinct publisher hosts (`wks/quality.py`, rule R1). Publisher diversity, not citation count, is what makes these corroborated.
