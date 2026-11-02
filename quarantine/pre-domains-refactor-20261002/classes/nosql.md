# NoSQL / Operator Injection

> surface: `web` · CWE: 943 · OWASP: A03:2021
> maturity: **researching** — 7 items, 7 supported, 1 FP rules, 0 chains

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

## Validation

- **A NoSQL endpoint counts as validated-guarded only when a field-level operator object, a top-level operator such as $where, and a non-allowlisted field name are each rejected, because any one of the three passing leaves an injection path.**  
  `high_confidence` · score 0.9265 · disproved by: If {"field":{"$ne":null}} is rejected with a 400 while {"$where":"1"} still changes the result set, the field blocklist is bypassable and the endpoint is NOT guarded; the validation only passes when both the field-level and the top-level operator probes are rejected.
  sources: <https://blog.sonarsource.com/nosql-injections-in-rocket-chat/> · <https://sourcegraph.com/blog/code-review-checklist>

## Fp Rule

- **A JSON list endpoint that returns every record to an anonymous caller because it is a public list is NOT NoSQL injection; the separating observation is whether an operator object changes the result set relative to a documented-field request.**  
  `high_confidence` · score 0.954 · disproved by: If {"status":{"$ne":"deleted"}} returns a different or larger document set than {"status":"active"} on the same endpoint and credential, the operator changed the query and the finding is genuine NoSQL injection, not a public list.
  sources: <https://blog.sonarsource.com/nosql-injections-in-rocket-chat/> · <https://www.hackprosec.com/penetration-testing.html>

## Impact

- **A single blind NoSQL injection that leaks a password reset token escalates to full account takeover of an administrator, because the leaked token authorises a password reset and the admin session then exposes far more attack surface.**  
  `high_confidence` · score 0.9265 · disproved by: If the recovered token is rejected by the reset endpoint (invalid/expired), or the resulting session is denied every privileged route, then the leak does not convert into account takeover and the impact claim reduces to a single blind token disclosure.
  sources: <https://blog.sonarsource.com/nosql-injections-in-rocket-chat/> · <https://www.hackprosec.com/penetration-testing.html>

## Bypass

- **An endpoint that blocklists disallowed MongoDB field names but leaves top-level operators enabled is bypassed with {"$where":"..."}, which executes a JavaScript expression per document, is not covered by a field blocklist, and turns a stripped result set into an error-based exfiltration channel.**  
  `high_confidence` · score 0.9265 · disproved by: If {"$where":"1==1"}, {"$expr":true} and a throwing expression inside $where are all rejected with a validation error before the query runs, and $where never appears to change the result set, then top-level operators are denied and the field blocklist is not bypassable this way.
  sources: <https://blog.sonarsource.com/nosql-injections-in-rocket-chat/> · <https://blog.orange.tw/posts/2023-08-2023-webconf-the-evolution-of-web-security/>

## Known gaps

Not yet satisfied: `items`, `fp_rules`, `chain`
