# NoSQL / Operator Injection

> surface: `web` · CWE: 943 · OWASP: A03:2021
> maturity: **mature** — 16 items, 16 supported, 2 FP rules, 1 chains

A document query is built from a parsed structure so type and operator semantics become attacker-controlled.

**Aliases:** nosql injection, mongo injection, operator injection

## Signal

- **A JSON request field documented as a string that returns a structurally different response when sent as an object ({$ne:null}, {$exists:true}) is a NoSQL injection signal, because the value type changed the query's behaviour rather than being rejected.**  
  `high_confidence` · score 0.954 · disproved by: If the object, integer and boolean forms of the field all return the same 400/422 validation error and only the documented string form reaches the handler, the field is type-guarded and there is no injection signal on that endpoint.
  sources: <https://blog.sonarsource.com/nosql-injections-in-rocket-chat/> · <https://sourcegraph.com/blog/code-review-checklist>

## Technique

- **Sending {"$ne":1} or {"$ne":null} as a credential or token field in a JSON login body bypasses the equality check, because the field is compared as an always-true query operator rather than as a literal string.**  
  `high_confidence` · score 0.954 · disproved by: If {"password":{"$ne":1}} returns the same 401 and body as the wrong-password baseline while a correct password still returns 200, the credential is not compared through a query operator and the operator-injection auth bypass does not exist on that endpoint.
  sources: <https://blog.sonarsource.com/nosql-injections-in-rocket-chat/> · <https://sourcegraph.com/blog/sast-vs-dast>
- **A $regex operator object in a lookup field turns the response into a boolean oracle, letting an attacker recover a secret token one character at a time by repeated prefix guesses against an unauthenticated endpoint.**  
  `high_confidence` · score 0.954 · disproved by: If {"token":{"$regex":"^A"}} and {"token":{"$regex":"^ZZZZ"}} produce byte-identical responses, and the same for every prefix tried, there is no observable difference to build an oracle from and the blind character-leak technique does not work against this endpoint.
  sources: <https://blog.sonarsource.com/nosql-injections-in-rocket-chat/> · <https://www.hackprosec.com/penetration-testing.html>
- **Exploitation of this vulnerability works like this: an attacker requests a password reset for a user using their email address, uses the oracle to leak the newly created token, and finally uses that token to change the user’s password.**  
  `high_confidence` · score 0.827 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Exploitation of this vulnerability works like this: an attacker requests a password reset ".
  sources: <https://blog.sonarsource.com/nosql-injections-in-rocket-chat/> · <https://sourcegraph.com/blog/code-review-checklist>
- **When exploiting SQL Injections, joins and subqueries are often used to leak data from different tables.**  
  `high_confidence` · score 0.7995 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "When exploiting SQL Injections, joins and subqueries are often used to leak data from diff".
  sources: <https://blog.sonarsource.com/nosql-injections-in-rocket-chat/> · <https://sourcegraph.com/blog/code-review-checklist>
- **The first vulnerability is CVE-2021-22911: a Blind NoSQL Injection that allows to leak a user’s password reset token.**  
  `high_confidence` · score 0.7995 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "The first vulnerability is CVE-2021-22911: a Blind NoSQL Injection that allows to leak a u".
  sources: <https://blog.sonarsource.com/nosql-injections-in-rocket-chat/> · <https://sourcegraph.com/blog/code-review-checklist>
- **But it still allows for more flexibility when exploiting this injection.**  
  `high_confidence` · score 0.7995 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "But it still allows for more flexibility when exploiting this injection.".
  sources: <https://blog.sonarsource.com/nosql-injections-in-rocket-chat/> · <https://sourcegraph.com/blog/code-review-checklist>
- **To escape a VM context, the attacker has to get access to objects from the parent context.**  
  `high_confidence` · score 0.772 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "To escape a VM context, the attacker has to get access to objects from the parent context.".
  sources: <https://blog.sonarsource.com/nosql-injections-in-rocket-chat/> · <https://sourcegraph.com/blog/code-review-checklist>
- **We outlined how NoSQL Injections can be exploited, and how they can lead to a complete takeover of a Rocket.Chat instance.**  
  `high_confidence` · score 0.772 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "We outlined how NoSQL Injections can be exploited, and how they can lead to a complete tak".
  sources: <https://blog.sonarsource.com/nosql-injections-in-rocket-chat/> · <https://sourcegraph.com/blog/code-review-checklist>
- **"abstract": "Sonar's research uncovered NoSQL injection vulnerabilities in Rocket.Chat that allow attackers to bypass authentication or extract data by injecting MongoDB query operators into user-controlled input fields.**  
  `high_confidence` · score 0.772 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: ""abstract": "Sonar's research uncovered NoSQL injection vulnerabilities in Rocket.Chat tha".
  sources: <https://blog.sonarsource.com/nosql-injections-in-rocket-chat/> · <https://sourcegraph.com/blog/code-review-checklist>
- **These can allow attackers to escalate their privileges, to execute arbitrary system commands on the host server, and to steal confidential user data and chat messages.**  
  `high_confidence` · score 0.772 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "These can allow attackers to escalate their privileges, to execute arbitrary system comman".
  sources: <https://blog.sonarsource.com/nosql-injections-in-rocket-chat/> · <https://sourcegraph.com/blog/code-review-checklist>

## Validation

- **A NoSQL endpoint counts as validated-guarded only when a field-level operator object, a top-level operator such as $where, and a non-allowlisted field name are each rejected, because any one of the three passing leaves an injection path.**  
  `high_confidence` · score 0.9265 · disproved by: If {"field":{"$ne":null}} is rejected with a 400 while {"$where":"1"} still changes the result set, the field blocklist is bypassable and the endpoint is NOT guarded; the validation only passes when both the field-level and the top-level operator probes are rejected.
  sources: <https://blog.sonarsource.com/nosql-injections-in-rocket-chat/> · <https://sourcegraph.com/blog/code-review-checklist>

## Fp Rule

- **A JSON list endpoint that returns every record to an anonymous caller because it is a public list is NOT NoSQL injection; the separating observation is whether an operator object changes the result set relative to a documented-field request.**  
  `high_confidence` · score 0.954 · disproved by: If {"status":{"$ne":"deleted"}} returns a different or larger document set than {"status":"active"} on the same endpoint and credential, the operator changed the query and the finding is genuine NoSQL injection, not a public list.
  sources: <https://blog.sonarsource.com/nosql-injections-in-rocket-chat/> · <https://www.hackprosec.com/penetration-testing.html>
- **Reject a nosql finding until it is distinguished from the adjacent behaviour this class also covers. "An endpoint that blocklists disallowed MongoDB field names but leaves top-level operators enabled is bypassed with {"$where":"..."}, which executes a JavaScript expression per document, is not covered by a field blocklist, and turns a..." and "A JSON request field documented as a string that returns a structurally different response when sent as an object ({$ne:null}, {$exists:true}) is a NoSQL injection signal, because the value type changed the query's behaviour rather than..." share a surface and a symptom, so a response that matches the first is not evidence for it while the second remains possible.**  
  `high_confidence` · score 0.8905 · disproved by: This rule is wrong if a controlled test shows the two behaviours can never co-occur on the same surface, or if the corpus entry for "A JSON request field documented as a string that returns a structurall" is out of date. In that case this class needs its false-positive guidance rewritten rather than deleted.
  sources: <https://blog.sonarsource.com/nosql-injections-in-rocket-chat/> · <https://blog.orange.tw/posts/2023-08-2023-webconf-the-evolution-of-web-security/>

## Impact

- **A single blind NoSQL injection that leaks a password reset token escalates to full account takeover of an administrator, because the leaked token authorises a password reset and the admin session then exposes far more attack surface.**  
  `high_confidence` · score 0.9265 · disproved by: If the recovered token is rejected by the reset endpoint (invalid/expired), or the resulting session is denied every privileged route, then the leak does not convert into account takeover and the impact claim reduces to a single blind token disclosure.
  sources: <https://blog.sonarsource.com/nosql-injections-in-rocket-chat/> · <https://www.hackprosec.com/penetration-testing.html>

## Bypass

- **An endpoint that blocklists disallowed MongoDB field names but leaves top-level operators enabled is bypassed with {"$where":"..."}, which executes a JavaScript expression per document, is not covered by a field blocklist, and turns a stripped result set into an error-based exfiltration channel.**  
  `high_confidence` · score 0.9265 · disproved by: If {"$where":"1==1"}, {"$expr":true} and a throwing expression inside $where are all rejected with a validation error before the query runs, and $where never appears to change the result set, then top-level operators are denied and the field blocklist is not bypassable this way.
  sources: <https://blog.sonarsource.com/nosql-injections-in-rocket-chat/> · <https://blog.orange.tw/posts/2023-08-2023-webconf-the-evolution-of-web-security/>
