# Methodology — Prototype Pollution

> Derived from 15 verified items. Regenerate with `python -m wks.methodgen --class prototype_pollution --apply`. Do not hand-edit: this file is a projection of the evidence, and edits are lost on the next cycle.

**Surface.** Caller input reaches a property write path that mutates a shared prototype.

**References.** CWE-1321 · A08:2021

## 1. Preconditions

_Nothing below is reachable until these hold. Confirm each against the target before spending time on the technique._

**A deserializer that applies assignments addressed by a caller-supplied path string is prototype-pollutable even when the path is validated as a string, because the destination path may itself contain __proto__ or constructor.prototype segments.**

Two distinct conditions must both hold: the attacker controls the assignment destination path AND controls the value assigned there. Sonar's superjson case in Blitz.js is the canonical shape: referentialEqualities carried a mapping such as "brands.0": ["products.0.brand"], and because the path of the assignment's destination can contain any property names, this introduces a Prototype Pollution vulnerability; the path __proto__.x sets x on Object.prototype to a value the attacker also controls. To test: send a deserialization payload whose referential-equality/metadata destination path is __proto__.<key> and whose source is a field you control, then probe a second request for <key> on a fresh object. If the sink rejects the path outright, or the path is fixed to numeric indices only, the prerequisite is absent.

- *Disproof:* Send the same payload with the destination path rewritten to a benign key such as user.name; if the destination path is validated against a pattern that excludes __proto__ and constructor, or the assignment is performed with a key that cannot address a prototype, then caller-controlled path addressing does not exist here and the claim is false.
- *Evidence:* high_confidence — [blog.sonarsource.com](https://blog.sonarsource.com/blitzjs-prototype-pollution/); [cwe.mitre.org](https://cwe.mitre.org/data/definitions/1321.html)

**Prototype pollution requires an untrusted JSON body or query object to reach a sink that merges, extends, clones or deep-assigns it into a server-side object; where user input is only read as a scalar and never merged, no payload can pollute Object.prototype.**

Hunt for the sink, not the payload. Look for endpoints whose handler passes a request-body object (req.body, ctx.request.body, the parsed JSON of an RPC call) into Object.assign, a spread into an options object, lodash.merge / _.extend / deepmerge, or a custom deserializer that walks a caller-supplied path string and performs assignments. Test: send a body whose keys are absent from the app's own schema and observe whether the response reflects an extra property or an altered default. Sonar's Blitz.js research frames the condition exactly this way: pollution arises when user-controlled input is merged into objects without sufficient sanitization, and frameworks that handle user input through object merging or deep cloning operations are the ones that are susceptible. A request rejected by schema validation, or whose body is only ever read field-by-field as a string, is a dead end for this class.

- *Disproof:* Post {"__proto__":{"polluted":"yes"}} and then, in a SEPARATE request to an unrelated endpoint, read the value back on a fresh object: if ({}).polluted is undefined and no observable behaviour anywhere changes, there is no reachable merge sink and the prerequisite claim is false for that endpoint.
- *Evidence:* high_confidence — [blog.sonarsource.com](https://blog.sonarsource.com/blitzjs-prototype-pollution/); [portswigger.net](https://portswigger.net/web-security/prototype-pollution)

**Prototype pollution is a JavaScript vulnerability that enables an attacker to add arbitrary properties to global object prototypes, which may then be inherited by user-defined objects.**

The vulnerability arises when a JavaScript function recursively merges an object containing user-controllable properties into an existing object without first sanitizing the keys. Due to the special meaning of __proto__ in JavaScript, the merge can assign nested properties to the object's prototype instead of the target object; the merge may use targetObject.__proto__.evilProperty = 'payload', which, when the target uses the default Object.prototype, leaves every object in the runtime inheriting the injected property. Any prototype can be polluted, but the built-in global Object.prototype is the most common target. The pollution applies to both client-side JavaScript and server-side Node.js runtimes. Exploitation depends on a sink (a function or DOM element that executes code) and a gadget (an attacker-controllable property passed to that sink). Key components: a prototype pollution source (URL query/fragment, JSON input, web messages) and a sink/gadget combination that turns the polluted property into code execution. Since prototype pollution is often unexploitable as a standalone vulnerability, it is usually chained with other vulnerabilities (e.g., client-side -> DOM XSS; server-side -> RCE).

- *Disproof:* The claim is false if the application rejects or recursively sanitizes '__proto__', 'constructor', and 'prototype' keys before merging, if untrusted input is never merged into shared objects, or if targets use Object.create(null) with frozen prototypes so that no object inherits from Object.prototype.
- *Evidence:* high_confidence — [cwe.mitre.org](https://cwe.mitre.org/data/definitions/1321.html); [portswigger.net](https://portswigger.net/web-security/prototype-pollution)

## 2. Reconnaissance signals

_What to look for while mapping the surface, and where each signal tells you the rest of the procedure is worth running._

**After a request carrying a __proto__ key, a later request that never repeats the payload shows an inherited property the application never set, which indicates real prototype pollution rather than a rejected input.**

The signal is state that outlives the payload. Because an object inherits everything from its prototype, a polluted key becomes visible on objects created later, in code that never saw the attacker's request; Sonar describes this as setting a new property on the Object prototype so that all argument objects have that new property, changing the program's behavior. Practical probe: (1) baseline GET /api/ping and note the exact JSON; (2) POST the pollution payload to any endpoint on the same origin; (3) repeat the baseline GET with no cookie change and diff. A changed default, an extra key in an unrelated response, or a behaviour switch in a handler you did not target is the signal. Use a property name no legitimate default could produce, and confirm it survives a fresh session and a different worker process, otherwise it is per-request state.

- *Disproof:* If the extra property is visible only in the response to the payload request itself, disappears on the next request, and never appears on an object the application builds independently, then the payload was accepted as ordinary data and nothing was written to Object.prototype: the signal is per-request echo, not pollution.
- *Evidence:* high_confidence — [blog.sonarsource.com](https://blog.sonarsource.com/blitzjs-prototype-pollution/); [developer.mozilla.org](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Object/proto)

**Observable signals that a source is pollutable: sending crafted input (query/fragment with __proto__[prop], JSON with an '__proto__' key, or a web message) and observing Object.prototype in the browser console gain a new property; on the server, the same input should not change Object.prototype, so a comparison of object graphs or a forced prototype-key resolution confirms the vector.**

Manual detection: (1) try injecting an arbitrary property via the query string, URL fragment, and any JSON input (e.g., ?__proto__[foo]=bar); (2) in the browser console, check Object.prototype.foo - 'bar' means pollution worked, undefined means it did not; (3) if the first technique fails, try dot notation versus bracket notation and different serialization variants. For server-side apps, review source for recursive merge/extend(true)/merge/mergeWith calls that reach request data, and for code that reads prototype attributes (hasOwnProperty, toString) in security checks. Runtime confirmation: send the crafted input to the application, then compare a fresh object's prototype properties before and after; a polluted Object.prototype shows the injected key.

- *Disproof:* The claim is false if the application never merges untrusted input into shared objects, if all merges are schema-validated, or if the target uses Object.create(null).
- *Evidence:* high_confidence — [cwe.mitre.org](https://cwe.mitre.org/data/definitions/1321.html); [portswigger.net](https://portswigger.net/web-security/prototype-pollution/client-side)

## 3. Test sequence

_Concrete mutations to try. Each is written to be executable, not to be a description of the vulnerability._

**When an app strips the literal key __proto__ from request bodies, the same pollution succeeds via {"constructor":{"prototype":{"<key>":"<value>"}}} because the prototype is still reachable as obj.constructor.prototype.**

Step 1: send {"__proto__":{"pp1":"x"}} and check for cross-request inheritance to establish a baseline. Step 2: send {"constructor":{"prototype":{"pp2":"x"}}} to the same endpoint. Step 3: on a fresh request, read pp2 and pp1 on a new object. Sonar's hardening notes state the bypass explicitly: disabling __proto__ with --disable-proto=delete does not close the hole, because it is still possible to reach an object's prototype via obj.constructor.prototype, so those property names should still be blocked when validating user-controlled property names. Testing both spellings is therefore the minimum; a filter that only greps for the seven characters of __proto__ is a bypassable filter, and the constructor spelling is the observation that separates "filtered" from "actually safe".

- *Disproof:* If the constructor spelling is stripped, coerced to a string, or the merge sink copies own properties only into a null-prototype target, then neither payload reaches a prototype and no inherited key appears on a fresh object: the bypass claim is false for that sink.
- *Evidence:* high_confidence — [blog.sonarsource.com](https://blog.sonarsource.com/blitzjs-prototype-pollution/); [developer.mozilla.org](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/JSON/parse)

**Prototype Pollution occurs when attackers can gain control over properties of a prototype.**

it first looks for x in obj itself, then in obj.__proto__ , then in obj.__proto__.__proto__ , and so on. It uses the first one it finds and throws an error if it can't find x in any of obj 's prototypes. As this demonstrates, prototypes can be chained, just like classes can have multiple levels of ancestors. This MDN article explains JavaScript's inheritance in more detail if you are interested. Prototype Pollution occurs when attackers can gain control over properties of a prototype. A vulnerable code pattern where this can happen is, for instance, obj[a][b] = c : if the attacker controls the values of a , b and c , they can set " __proto__ " for a , the property name for b , and the property value for c . This will cause all objects to have a new property, which can significantly influence the target application. A common pattern in JavaScript code is to use plain objects to

- *Disproof:* Refuted when: the same behaviour is absent when the single named control in the claim is present, and the control is shown to be present rather than assumed. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“Prototype Pollution occurs when attackers can gain control over properties of a ”) does not occur under a test that isolates that control.
- *Evidence:* high_confidence — [blog.orange.tw](https://blog.orange.tw/posts/2023-08-2023-webconf-the-evolution-of-web-security/); [blog.sonarsource.com](https://blog.sonarsource.com/blitzjs-prototype-pollution/)

**A vulnerable code pattern where this can happen is, for instance, obj[a][b] = c : if the attacker controls the values of a , b and c , they can set " __proto__ " for a , the property name for b , and the property value for c .**

_ , and so on. It uses the first one it finds and throws an error if it can't find x in any of obj 's prototypes. As this demonstrates, prototypes can be chained, just like classes can have multiple levels of ancestors. This MDN article explains JavaScript's inheritance in more detail if you are interested. Prototype Pollution occurs when attackers can gain control over properties of a prototype. A vulnerable code pattern where this can happen is, for instance, obj[a][b] = c : if the attacker controls the values of a , b and c , they can set " __proto__ " for a , the property name for b , and the property value for c . This will cause all objects to have a new property, which can significantly influence the target application. A common pattern in JavaScript code is to use plain objects to pass optional arguments to a function. In the following example, the function doTask receives an object that can contain several optional arguments: Copy to clipboard function doTask(name, options) { 
 if (options.delay) { 
 /

- *Disproof:* Refuted when: the same behaviour is absent when the single named control in the claim is present, and the control is shown to be present rather than assumed. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“A vulnerable code pattern where this can happen is, for instance, obj[a][b] = c ”) does not occur under a test that isolates that control.
- *Evidence:* high_confidence — [blog.sonarsource.com](https://blog.sonarsource.com/blitzjs-prototype-pollution/); [developer.mozilla.org](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/JSON/parse)

## 4. Validation

_How to prove the finding rather than infer it. A technique that cannot be validated must not be reported._

**Prototype pollution is proved by a property that is visible on an object the test never sent any payload to — a freshly constructed `({})` in the same process returning the injected key — because a successful assignment to the prototype is by definition visible through the whole prototype chain.**

Mechanism: Prototype pollution is proved by a property that is visible on an object the test never sent any payload to — a freshly constructed `({})` in the same process returning the injected key — because a successful assignment to the prototype is by definition visible through the whole prototype chain. How to apply it in the field: treat this as the validation it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable. Boundary of the rule: The claim is false when the visible property is actually an own property of that object (a framework merged the request body into a shared singleton config, a middleware cached the parsed body on the object, or a test harness reused the same object reference), in which case the value is local, not inherited, and must be distinguished by checking the own-property descriptor rather than the value alone.

- *Disproof:* The claim is false when the visible property is actually an own property of that object (a framework merged the request body into a shared singleton config, a middleware cached the parsed body on the object, or a test harness reused the same object reference), in which case the value is local, not inherited, and must be distinguished by checking the own-property descriptor rather than the value alone.
- *Evidence:* high_confidence — [developer.mozilla.org](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Object/proto); [semgrep.dev](https://semgrep.dev/docs/writing-rules/data-flow/taint-mode/)

## 5. False-positive rejection

_The checks that eliminate the most common non-findings. Run these BEFORE reporting, not after a rejection._

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

**Chain: server-side prototype pollution (source = route 1) is the precondition for remote code execution via library/Node.js universal gadgets; the pollution step alone is usually insufficient without a gadget that reads the attacker-controlled prototype property.**

In the 'Silent Spring' study, prototype pollution was detected in libraries and applications with multi-label static taint analysis, and universal gadgets were detected by hybrid analysis of Node.js source code; the end-to-end exploit path required pollution of the prototype (pp.002) followed by a gadget consuming the polluted property, which then executed code (pp.006). The 'Silent Spring' paper reports eight RCEs across NPM CLI, Parse Server, and Rocket.Chat. Note the dependency direction: the pollution is a means to reach a gadget; removing the sink/gadget removes the RCE, which is why gadget hunting is as important as finding the pollution source.

- *Disproof:* The chain fails if the merge is sanitized, if the polluted property never reaches a sink, or if the application uses frozen prototypes / Object.create(null) objects.
- *Evidence:* high_confidence — [portswigger.net](https://portswigger.net/web-security/prototype-pollution); [usenix.org](https://www.usenix.org/conference/usenixsecurity23/presentation/shcherbakov)

## Impact

_No verified impact items yet._ Derived from evidence only, so this section is empty rather than plausible.


## Coverage gap

These stages have no verified evidence and are therefore absent above: Impact.
A procedure with a missing validation stage is not safe to act on — it produces findings rather than proofs.

---

*Generated from the evidence base. Where this file and the database disagree, the database is correct.*
