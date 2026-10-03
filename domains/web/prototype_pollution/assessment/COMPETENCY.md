# Methodology — Prototype Pollution

> Derived from 16 verified items. Regenerate with `python -m wks.methodgen --class prototype_pollution --apply`. Do not hand-edit: this file is a projection of the evidence, and edits are lost on the next cycle.

**Surface.** Caller input reaches a property write path that mutates a shared prototype.

**References.** CWE-1321 · A08:2021

## 1. Preconditions

_Nothing below is reachable until these hold. Confirm each against the target before spending time on the technique._

**Prototype pollution requires an untrusted JSON body or query object to reach a sink that merges, extends, clones or deep-assigns it into a server-side object; where user input is only read as a scalar and never merged, no payload can pollute Object.prototype.**

Hunt for the sink, not the payload. Look for endpoints whose handler passes a request-body object (req.body, ctx.request.body, the parsed JSON of an RPC call) into Object.assign, a spread into an options object, lodash.merge / _.extend / deepmerge, or a custom deserializer that walks a caller-supplied path string and performs assignments. Test: send a body whose keys are absent from the app's own schema and observe whether the response reflects an extra property or an altered default. Sonar's Blitz.js research frames the condition exactly this way: pollution arises when user-controlled input is merged into objects without sufficient sanitization, and frameworks that handle user input through object merging or deep cloning operations are the ones that are susceptible. A request rejected by schema validation, or whose body is only ever read field-by-field as a string, is a dead end for this class.

- *Disproof:* Post {"__proto__":{"polluted":"yes"}} and then, in a SEPARATE request to an unrelated endpoint, read the value back on a fresh object: if ({}).polluted is undefined and no observable behaviour anywhere changes, there is no reachable merge sink and the prerequisite claim is false for that endpoint.
- *Evidence:* high_confidence — [blog.sonarsource.com](https://blog.sonarsource.com/blitzjs-prototype-pollution/); [sourcegraph.com](https://sourcegraph.com/blog/code-review-checklist)

**A deserializer that applies assignments addressed by a caller-supplied path string is prototype-pollutable even when the path is validated as a string, because the destination path may itself contain __proto__ or constructor.prototype segments.**

Two distinct conditions must both hold: the attacker controls the assignment destination path AND controls the value assigned there. Sonar's superjson case in Blitz.js is the canonical shape: referentialEqualities carried a mapping such as "brands.0": ["products.0.brand"], and because the path of the assignment's destination can contain any property names, this introduces a Prototype Pollution vulnerability; the path __proto__.x sets x on Object.prototype to a value the attacker also controls. To test: send a deserialization payload whose referential-equality/metadata destination path is __proto__.<key> and whose source is a field you control, then probe a second request for <key> on a fresh object. If the sink rejects the path outright, or the path is fixed to numeric indices only, the prerequisite is absent.

- *Disproof:* Send the same payload with the destination path rewritten to a benign key such as user.name; if the destination path is validated against a pattern that excludes __proto__ and constructor, or the assignment is performed with a key that cannot address a prototype, then caller-controlled path addressing does not exist here and the claim is false.
- *Evidence:* high_confidence — [blog.sonarsource.com](https://blog.sonarsource.com/blitzjs-prototype-pollution/); [sourcegraph.com](https://sourcegraph.com/blog/code-review-checklist)

## 2. Reconnaissance signals

_What to look for while mapping the surface, and where each signal tells you the rest of the procedure is worth running._

**After a request carrying a __proto__ key, a later request that never repeats the payload shows an inherited property the application never set, which indicates real prototype pollution rather than a rejected input.**

The signal is state that outlives the payload. Because an object inherits everything from its prototype, a polluted key becomes visible on objects created later, in code that never saw the attacker's request; Sonar describes this as setting a new property on the Object prototype so that all argument objects have that new property, changing the program's behavior. Practical probe: (1) baseline GET /api/ping and note the exact JSON; (2) POST the pollution payload to any endpoint on the same origin; (3) repeat the baseline GET with no cookie change and diff. A changed default, an extra key in an unrelated response, or a behaviour switch in a handler you did not target is the signal. Use a property name no legitimate default could produce, and confirm it survives a fresh session and a different worker process, otherwise it is per-request state.

- *Disproof:* If the extra property is visible only in the response to the payload request itself, disappears on the next request, and never appears on an object the application builds independently, then the payload was accepted as ordinary data and nothing was written to Object.prototype: the signal is per-request echo, not pollution.
- *Evidence:* high_confidence — [blog.sonarsource.com](https://blog.sonarsource.com/blitzjs-prototype-pollution/); [hackprosec.com](https://www.hackprosec.com/penetration-testing.html)

## 3. Test sequence

_Concrete mutations to try. Each is written to be executable, not to be a description of the vulnerability._

**When an app strips the literal key __proto__ from request bodies, the same pollution succeeds via {"constructor":{"prototype":{"<key>":"<value>"}}} because the prototype is still reachable as obj.constructor.prototype.**

Step 1: send {"__proto__":{"pp1":"x"}} and check for cross-request inheritance to establish a baseline. Step 2: send {"constructor":{"prototype":{"pp2":"x"}}} to the same endpoint. Step 3: on a fresh request, read pp2 and pp1 on a new object. Sonar's hardening notes state the bypass explicitly: disabling __proto__ with --disable-proto=delete does not close the hole, because it is still possible to reach an object's prototype via obj.constructor.prototype, so those property names should still be blocked when validating user-controlled property names. Testing both spellings is therefore the minimum; a filter that only greps for the seven characters of __proto__ is a bypassable filter, and the constructor spelling is the observation that separates "filtered" from "actually safe".

- *Disproof:* If the constructor spelling is stripped, coerced to a string, or the merge sink copies own properties only into a null-prototype target, then neither payload reaches a prototype and no inherited key appears on a fresh object: the bypass claim is false for that sink.
- *Evidence:* high_confidence — [blog.orange.tw](https://blog.orange.tw/posts/2023-08-2023-webconf-the-evolution-of-web-security/); [blog.sonarsource.com](https://blog.sonarsource.com/blitzjs-prototype-pollution/)

## 4. Validation

_How to prove the finding rather than infer it. A technique that cannot be validated must not be reported._

**A prototype pollution report is validated only when a probe sent in one request changes an object built by a different, later request; a change reproduced only within the payload's own request does not demonstrate prototype pollution.**

The validation is a differential test with a clean baseline. Record the response of an unrelated read endpoint before any payload; send the pollution payload; re-run the identical read with no payload and no session change; the finding holds only if the second read differs in a way attributable to an inherited property. This mirrors the property that makes a dynamic finding credible in the first place - a finding is reproduced against a real endpoint rather than inferred from a code path - and it is what separates a hand-verified report from the alerts a static tool emits, whose false-positive rate varies by language, rule set, framework support and tuning. Save both raw responses in the report. If you cannot reproduce the cross-request delta on a second run, the finding is a per-request artefact and belongs in the false-positive queue, not the corpus.

- *Disproof:* Re-run the read-only baseline three times with no payload in between and confirm the response is byte-identical every time; if the suspected inherited property disappears on the second read, or never appears without the payload in the same request, there is no cross-request state change and the pollution claim is not validated.
- *Evidence:* high_confidence — [blog.sonarsource.com](https://blog.sonarsource.com/scripting-outside-the-box-api-client-security-risks-part-1/); [sourcegraph.com](https://sourcegraph.com/blog/sast-vs-dast)

**Prototype pollution is proved by a property that is visible on an object the test never sent any payload to — a freshly constructed `({})` in the same process returning the injected key — because a successful assignment to the prototype is by definition visible through the whole prototype chain.**

Mechanism: Prototype pollution is proved by a property that is visible on an object the test never sent any payload to — a freshly constructed `({})` in the same process returning the injected key — because a successful assignment to the prototype is by definition visible through the whole prototype chain. How to apply it in the field: treat this as the validation it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable. Boundary of the rule: The claim is false when the visible property is actually an own property of that object (a framework merged the request body into a shared singleton config, a middleware cached the parsed body on the object, or a test harness reused the same object reference), in which case the value is local, not inherited, and must be distinguished by checking the own-property descriptor rather than the value alone.

- *Disproof:* The claim is false when the visible property is actually an own property of that object (a framework merged the request body into a shared singleton config, a middleware cached the parsed body on the object, or a test harness reused the same object reference), in which case the value is local, not inherited, and must be distinguished by checking the own-property descriptor rather than the value alone.
- *Evidence:* high_confidence — [developer.mozilla.org](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Object/proto); [semgrep.dev](https://semgrep.dev/docs/writing-rules/data-flow/taint-mode/)

## 5. False-positive rejection

_The checks that eliminate the most common non-findings. Run these BEFORE reporting, not after a rejection._

**A JSON body containing __proto__ that round-trips through the attacker's own browser or a client-side merge, with no server-side state change, is NOT server-side prototype pollution and must not be filed as this class.**

This looks like prototype pollution because the payload is textbook and the string __proto__ appears in the request, but the observable effect happens entirely client-side, in the attacker's own session. The separating observation is WHO holds the polluted prototype and WHEN: client-side, the injected key is visible only in that browser's DOM/JS context and vanishes on reload; server-side, the key appears in a later request handled by the server and survives a new session. Concretely: fire {"__proto__":{"polluted":"yes"}} at an endpoint, then read the value with a clean second request from a different client with no cookies. If the value appears only in the first browser's document, the finding is a client-side DOM/merge artefact (real, but a different class and much lower impact). The same separation applies to a static-analysis hit on a merge call with no attacker-controlled path: a tool that floods pull requests with low-confidence findings trains developers to ignore it, so the sink alone is never a finding without a reachable path.

- *Disproof:* Send the identical payload from a fresh HTTP client that never loaded the app's JavaScript, then request an unrelated endpoint; if the inherited key appears in that server response the pollution is server-side after all and this fp_rule does not apply to it.
- *Evidence:* high_confidence — [blog.sonarsource.com](https://blog.sonarsource.com/etherpad-code-execution-vulnerabilities/); [sourcegraph.com](https://sourcegraph.com/blog/static-code-analysis-tools)

**Reject a prototype_pollution finding until it is distinguished from the adjacent behaviour this class also covers. "Prototype pollution requires an untrusted JSON body or query object to reach a sink that merges, extends, clones or deep-assigns it into a server-side object; where user input is only read as a scalar and never merged, no payload can..." and "A prototype pollution report is validated only when a probe sent in one request changes an object built by a different, later request; a change reproduced only within the payload's own request does not demonstrate prototype pollution." share a surface and a symptom, so a response that matches the first is not evidence for it while the second remains possible.**

Hypothesis under test: Prototype pollution requires an untrusted JSON body or query object to reach a sink that merges, extends, clones or deep-assigns it into a server-side object; where user input is only read as a scalar and never merged, no payload can...

Adjacent behaviour that produces the same observable result: A prototype pollution report is validated only when a probe sent in one request changes an object built by a different, later request; a change reproduced only within the payload's own request does not demonstrate prototype pollution.

Why this is worth checking before reporting: both are recorded in this class as gated knowledge, so a tester who stops at the first match will report one of them. The two differ in what the server actually did with the input, and that difference is observable in the response rather than in the request.

Required before treating this as a finding: capture the response that demonstrates the first behaviour specifically, and confirm the second is not what was observed.

- *Disproof:* This rule is wrong if a controlled test shows the two behaviours can never co-occur on the same surface, or if the corpus entry for "A prototype pollution report is validated only when a probe sent in on" is out of date. In that case this class needs its false-positive guidance rewritten rather than deleted.
- *Evidence:* high_confidence — [blog.orange.tw](https://blog.orange.tw/posts/2023-08-2023-webconf-the-evolution-of-web-security/); [blog.sonarsource.com](https://blog.sonarsource.com/blitzjs-prototype-pollution/)

**A payload delivered as a JSON request body and parsed with JSON.parse does not pollute the prototype on its own: the parsed object gets `__proto__` as an ordinary own property, so the absence of inherited state on a fresh object is proof the parser was not the vulnerable step.**

Mechanism: A payload delivered as a JSON request body and parsed with JSON.parse does not pollute the prototype on its own: the parsed object gets `__proto__` as an ordinary own property, so the absence of inherited state on a fresh object is proof the parser was not the vulnerable step. How to apply it in the field: treat this as the fp_rule it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable. Boundary of the rule: The rule is wrong when the parsed object is afterwards merged or assigned into another object by a recursive merge or setter-based copy that walks own keys, because at that point the own `__proto__` key is written through the setter and does mutate the prototype; the parser is innocent but the copy is the sink.

- *Disproof:* The rule is wrong when the parsed object is afterwards merged or assigned into another object by a recursive merge or setter-based copy that walks own keys, because at that point the own `__proto__` key is written through the setter and does mutate the prototype; the parser is innocent but the copy is the sink.
- *Evidence:* high_confidence — [developer.mozilla.org](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/JSON/parse); [semgrep.dev](https://semgrep.dev/docs/writing-rules/data-flow/taint-mode/)

**An application that explicitly defines `__proto__` as an own property on one object via Object.defineProperty has not polluted anything: the accessor is shadowed for that object only, and the prototype chain of every other object is unchanged.**

Mechanism: An application that explicitly defines `__proto__` as an own property on one object via Object.defineProperty has not polluted anything: the accessor is shadowed for that object only, and the prototype chain of every other object is unchanged. How to apply it in the field: treat this as the fp_rule it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable. Boundary of the rule: The claim is false when the same call is made on `Object.prototype` itself rather than on an instance, or when the application assigns through the accessor on a shared prototype object; those two cases mutate the chain globally and are genuine pollution despite the identical call syntax.

- *Disproof:* The claim is false when the same call is made on `Object.prototype` itself rather than on an instance, or when the application assigns through the accessor on a shared prototype object; those two cases mutate the chain globally and are genuine pollution despite the identical call syntax.
- *Evidence:* high_confidence — [developer.mozilla.org](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Object/proto); [semgrep.dev](https://semgrep.dev/docs/writing-rules/data-flow/taint-mode/)

## 6. Known bypasses

_Filters and controls that have defeated the techniques above. Treat these as the reason a naive test fails, not as proof of safety._

**A validation control that only checks the top-level keys of a request body is bypassed by prototype pollution, because a recursive merge descends into nested objects and the dangerous key can sit several levels down where the allowlist never looked.**

Mechanism: A validation control that only checks the top-level keys of a request body is bypassed by prototype pollution, because a recursive merge descends into nested objects and the dangerous key can sit several levels down where the allowlist never looked. How to apply it in the field: treat this as the bypass it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable. Boundary of the rule: The rule is false when the check is applied recursively at every depth and the merge refuses to recurse into any key that is not a plain string-keyed object, or when the merge never treats `__proto__`/`constructor`/`prototype` as writable slots; then the nested payload cannot reach the prototype and the shallow-check bypass does not exist.

- *Disproof:* The rule is false when the check is applied recursively at every depth and the merge refuses to recurse into any key that is not a plain string-keyed object, or when the merge never treats `__proto__`/`constructor`/`prototype` as writable slots; then the nested payload cannot reach the prototype and the shallow-check bypass does not exist.
- *Evidence:* high_confidence — [developer.mozilla.org](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Object/proto); [semgrep.dev](https://semgrep.dev/docs/writing-rules/data-flow/taint-mode/)

## 7. Chaining

_How this class escalates when combined with others. Each step is anchored to a promoted item._

**Prototype pollution alone is only a foothold: RCE requires a second gadget that consumes a polluted key, such as a child-process spawn whose env object inherits a NODE_OPTIONS value that adds --require.**

Establish pollution first (a key appears on a fresh object in a later request), then look for a consumer. Sonar's Blitz.js chain used exactly this: spawning a new process is a known Prototype Pollution gadget, made popular by Michał Bentkowski when he exploited Kibana, because spawn() receives optional arguments via an object, so a polluted env property can set NODE_OPTIONS to add command-line arguments for the node process and --require can include any file. Orange Tsai's WebConf 2023 deck lists Exploiting prototype pollution - RCE in Kibana (CVE-2019-7609) as the real-world case behind that gadget, which is why this belongs in the chain set rather than as a standalone RCE claim. Test by polluting the env key (or any option object a spawn wrapper reads) and observing whether a subsequent unrelated operation spawns a process with your injected environment; the observation that separates the chain from plain pollution is a NEW process or module load that your key caused.

- *Disproof:* If the polluted key is never read by any code path - verified by an unchanged child-process environment and no additional module load in the request logs - then no gadget consumes it and the pollution stops at a DoS-or-nothing level, so the chain to RCE is false.
- *Evidence:* high_confidence — [blog.orange.tw](https://blog.orange.tw/posts/2023-08-2023-webconf-the-evolution-of-web-security/); [blog.sonarsource.com](https://blog.sonarsource.com/blitzjs-prototype-pollution/)

## Impact

_No verified impact items yet._ Derived from evidence only, so this section is empty rather than plausible.


## Coverage gap

These stages have no verified evidence and are therefore absent above: Impact.
A procedure with a missing validation stage is not safe to act on — it produces findings rather than proofs.

---

*Generated from the evidence base. Where this file and the database disagree, the database is correct.*
