# Prototype Pollution

> surface: `web` · CWE: 1321 · OWASP: A08:2021
> maturity: **mature** — 37 items, 17 supported, 3 FP rules, 1 chains

Caller input reaches a property write path that mutates a shared prototype.

**Aliases:** prototype pollution, pp, object prototype pollution

## Prerequisite

- **Prototype pollution requires an untrusted JSON body or query object to reach a sink that merges, extends, clones or deep-assigns it into a server-side object; where user input is only read as a scalar and never merged, no payload can pollute Object.prototype.**  
  `under_review` · score 0.884 · disproved by: Post {"__proto__":{"polluted":"yes"}} and then, in a SEPARATE request to an unrelated endpoint, read the value back on a fresh object: if ({}).polluted is undefined and no observable behaviour anywhere changes, there is no reachable merge sink and the prerequisite claim is false for that endpoint.
  sources: <https://blog.sonarsource.com/blitzjs-prototype-pollution/> · <https://blog.sonarsource.com/etherpad-code-execution-vulnerabilities/>
- **A deserializer that applies assignments addressed by a caller-supplied path string is prototype-pollutable even when the path is validated as a string, because the destination path may itself contain __proto__ or constructor.prototype segments.**  
  `under_review` · score 0.8565 · disproved by: Send the same payload with the destination path rewritten to a benign key such as user.name; if the destination path is validated against a pattern that excludes __proto__ and constructor, or the assignment is performed with a key that cannot address a prototype, then caller-controlled path addressing does not exist here and the claim is false.
  sources: <https://blog.sonarsource.com/blitzjs-prototype-pollution/> · <https://blog.sonarsource.com/scripting-outside-the-box-api-client-security-risks-part-1/>

## Signal

- **After a request carrying a __proto__ key, a later request that never repeats the payload shows an inherited property the application never set, which indicates real prototype pollution rather than a rejected input.**  
  `high_confidence` · score 0.954 · disproved by: If the extra property is visible only in the response to the payload request itself, disappears on the next request, and never appears on an object the application builds independently, then the payload was accepted as ordinary data and nothing was written to Object.prototype: the signal is per-request echo, not pollution.
  sources: <https://blog.sonarsource.com/blitzjs-prototype-pollution/> · <https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Object/proto>

## Technique

- **When an app strips the literal key __proto__ from request bodies, the same pollution succeeds via {"constructor":{"prototype":{"<key>":"<value>"}}} because the prototype is still reachable as obj.constructor.prototype.**  
  `high_confidence` · score 0.9425 · disproved by: If the constructor spelling is stripped, coerced to a string, or the merge sink copies own properties only into a null-prototype target, then neither payload reaches a prototype and no inherited key appears on a fresh object: the bypass claim is false for that sink.
  sources: <https://blog.sonarsource.com/blitzjs-prototype-pollution/> · <https://blog.sonarsource.com/scripting-outside-the-box-api-client-security-risks-part-1/> · <https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/JSON/parse>
- **Prototype Pollution occurs when attackers can gain control over properties of a prototype.**  
  `under_review` · score 0.772 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Prototype Pollution occurs when attackers can gain control over properties of a prototype.".
  sources: <https://blog.sonarsource.com/blitzjs-prototype-pollution/> · <https://blog.orange.tw/posts/2023-08-2023-webconf-the-evolution-of-web-security/>
- **A vulnerable code pattern where this can happen is, for instance, obj[a][b] = c : if the attacker controls the values of a , b and c , they can set " __proto__ " for a , the property name for b , and the property value for c .**  
  `under_review` · score 0.772 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "A vulnerable code pattern where this can happen is, for instance, obj[a][b] = c : if the a".
  sources: <https://blog.sonarsource.com/blitzjs-prototype-pollution/> · <https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/JSON/parse>
- **This causes the CLI wrapper script to be executed, spawning a new process with the attacker-controlled argv0 , env , and shell options.**  
  `under_review` · score 0.733 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "This causes the CLI wrapper script to be executed, spawning a new process with the attacke".
  sources: <https://blog.sonarsource.com/blitzjs-prototype-pollution/>
- **If the attacker changes the value of NODE_OPTIONS to --require /proc/self/cmdline and puts their payload in argv0 , this should work, right?**  
  `under_review` · score 0.7055 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "If the attacker changes the value of NODE_OPTIONS to --require /proc/self/cmdline and puts".
  sources: <https://blog.sonarsource.com/blitzjs-prototype-pollution/>
- **This can be bypassed with the shell option of the spawn() function.**  
  `under_review` · score 0.7055 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "This can be bypassed with the shell option of the spawn() function.".
  sources: <https://blog.sonarsource.com/blitzjs-prototype-pollution/>
- **console.log(obj.__proto__); // undefined If you want to harden your code base and make the exploitation of Prototype Pollution issues more difficult, there are some ways to do so, but they each come with their drawbacks.**  
  `under_review` · score 0.702 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "console.log(obj.__proto__); // undefined If you want to harden your code base and make the".
  sources: <https://blog.sonarsource.com/blitzjs-prototype-pollution/> · <https://blog.sonarsource.com/scripting-outside-the-box-api-client-security-risks-part-1/>
- **This makes the page routing functionality a Prototype Pollution gadget that allows executing any local JavaScript file by inserting a new mapping into the manifest.**  
  `under_review` · score 0.702 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "This makes the page routing functionality a Prototype Pollution gadget that allows executi".
  sources: <https://blog.sonarsource.com/blitzjs-prototype-pollution/> · <https://blog.sonarsource.com/etherpad-code-execution-vulnerabilities/>
- **Prototype pollution occurs when user-controlled input is merged into objects without sufficient sanitization, potentially enabling privilege escalation, denial of service, or remote code execution depending on the application context.**  
  `under_review` · score 0.702 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Prototype pollution occurs when user-controlled input is merged into objects without suffi".
  sources: <https://blog.sonarsource.com/blitzjs-prototype-pollution/> · <https://blog.sonarsource.com/etherpad-code-execution-vulnerabilities/>
- **"abstract": "Sonar's security research team discovered a prototype pollution vulnerability in Blitz.js, a popular full-stack React framework, which could allow attackers to manipulate JavaScript object prototypes and alter application behavior.**  
  `under_review` · score 0.702 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: ""abstract": "Sonar's security research team discovered a prototype pollution vulnerability".
  sources: <https://blog.sonarsource.com/blitzjs-prototype-pollution/> · <https://blog.sonarsource.com/etherpad-code-execution-vulnerabilities/>
- **Also, it is still possible to reach an object's prototype via obj.constructor.prototype , so these property names should still be blocked when validating user-controlled property names.**  
  `under_review` · score 0.702 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Also, it is still possible to reach an object's prototype via obj.constructor.prototype , ".
  sources: <https://blog.sonarsource.com/blitzjs-prototype-pollution/> · <https://blog.sonarsource.com/scripting-outside-the-box-api-client-security-risks-part-1/>
- **Finally, we will give recommendations on how to avoid Prototype Pollution vulnerabilities in your JavaScript code.**  
  `under_review` · score 0.702 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Finally, we will give recommendations on how to avoid Prototype Pollution vulnerabilities ".
  sources: <https://blog.sonarsource.com/blitzjs-prototype-pollution/> · <https://blog.sonarsource.com/etherpad-code-execution-vulnerabilities/>
- **This finding highlights how JavaScript frameworks that handle user input through object merging or deep cloning operations are particularly susceptible to prototype pollution if input is not rigorously validated.**  
  `under_review` · score 0.702 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "This finding highlights how JavaScript frameworks that handle user input through object me".
  sources: <https://blog.sonarsource.com/blitzjs-prototype-pollution/> · <https://blog.sonarsource.com/etherpad-code-execution-vulnerabilities/>
- **Gadget 2: From require() to spawn() To turn this into arbitrary code execution, an attacker either needs the ability to create files on the server or another gadget to chain with the first one.**  
  `under_review` · score 0.678 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Gadget 2: From require() to spawn() To turn this into arbitrary code execution, an attacke".
  sources: <https://blog.sonarsource.com/blitzjs-prototype-pollution/>
- **A Blitz.js-based application is vulnerable if it implements at least one RPC call.**  
  `under_review` · score 0.678 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "A Blitz.js-based application is vulnerable if it implements at least one RPC call.".
  sources: <https://blog.sonarsource.com/blitzjs-prototype-pollution/>
- **However, the command is fixed, and the arguments are not controllable, so how can attackers use this?**  
  `under_review` · score 0.678 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "However, the command is fixed, and the arguments are not controllable, so how can attacker".
  sources: <https://blog.sonarsource.com/blitzjs-prototype-pollution/>

## Test

- **To decide this case, observe: Hypothesis under test: Prototype pollution requires an untrusted JSON body or query object to reach a sink that merges, extends, clones or deep-assigns it into a server-side object; where user input is only read as a scalar and never merged, no payload can...**  
  `high_confidence` · score 0.9065 · disproved by: This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (prototype_pollution.fp_rule.auto.derived) states the full boundary.
  sources: <https://blog.sonarsource.com/blitzjs-prototype-pollution/> · <https://blog.sonarsource.com/scripting-outside-the-box-api-client-security-risks-part-1/> · <https://blog.orange.tw/posts/2023-08-2023-webconf-the-evolution-of-web-security/>
- **To decide this case, observe: How to apply it in the field: treat this as the bypass it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable.**  
  `high_confidence` · score 0.838 · disproved by: This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (prototype_pollution.bypass.a_recursive_merge_that_walks_own_keys_defeats_a_shallow_key_allowlist) states the full boundary.
  sources: <https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Object/proto> · <https://semgrep.dev/docs/writing-rules/data-flow/taint-mode/>
- **To decide this case, observe: How to apply it in the field: treat this as the fp_rule it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable.**  
  `high_confidence` · score 0.838 · disproved by: This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (prototype_pollution.fp_rule.defining_an_own_proto_property_is_not_pollution) states the full boundary.
  sources: <https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Object/proto> · <https://semgrep.dev/docs/writing-rules/data-flow/taint-mode/>
- **To decide this case, observe: How to apply it in the field: treat this as the validation it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable.**  
  `high_confidence` · score 0.838 · disproved by: This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (prototype_pollution.validation.proof_is_inherited_property_visibility_on_an_object_you_never_touched) states the full boundary.
  sources: <https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Object/proto> · <https://semgrep.dev/docs/writing-rules/data-flow/taint-mode/>
- **To decide this case, observe: How to apply it in the field: treat this as the fp_rule it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable.**  
  `under_review` · score 0.768 · disproved by: This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (prototype_pollution.fp_rule.json_parse_creates_an_own_proto_key_not_a_polluted_prototype) states the full boundary.
  sources: <https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/JSON/parse> · <https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Object/proto>

## Validation

- **A prototype pollution report is validated only when a probe sent in one request changes an object built by a different, later request; a change reproduced only within the payload's own request does not demonstrate prototype pollution.**  
  `high_confidence` · score 0.97 · disproved by: Re-run the read-only baseline three times with no payload in between and confirm the response is byte-identical every time; if the suspected inherited property disappears on the second read, or never appears without the payload in the same request, there is no cross-request state change and the pollution claim is not validated.
  sources: <https://blog.sonarsource.com/blitzjs-prototype-pollution/> · <https://blog.sonarsource.com/scripting-outside-the-box-api-client-security-risks-part-1/> · <https://sourcegraph.com/blog/static-code-analysis-tools>
- **Prototype pollution is proved by a property that is visible on an object the test never sent any payload to — a freshly constructed `({})` in the same process returning the injected key — because a successful assignment to the prototype is by definition visible through the whole prototype chain.**  
  `high_confidence` · score 0.8815 · disproved by: The claim is false when the visible property is actually an own property of that object (a framework merged the request body into a shared singleton config, a middleware cached the parsed body on the object, or a test harness reused the same object reference), in which case the value is local, not inherited, and must be distinguished by checking the own-property descriptor rather than the value alone.
  sources: <https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Object/create> · <https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Object/proto> · <https://semgrep.dev/docs/writing-rules/data-flow/taint-mode/>

## Fp Rule

- **A JSON body containing __proto__ that round-trips through the attacker's own browser or a client-side merge, with no server-side state change, is NOT server-side prototype pollution and must not be filed as this class.**  
  `high_confidence` · score 0.9265 · disproved by: Send the identical payload from a fresh HTTP client that never loaded the app's JavaScript, then request an unrelated endpoint; if the inherited key appears in that server response the pollution is server-side after all and this fp_rule does not apply to it.
  sources: <https://blog.sonarsource.com/etherpad-code-execution-vulnerabilities/> · <https://sourcegraph.com/blog/static-code-analysis-tools>
- **A payload delivered as a JSON request body and parsed with JSON.parse does not pollute the prototype on its own: the parsed object gets `__proto__` as an ordinary own property, so the absence of inherited state on a fresh object is proof the parser was not the vulnerable step.**  
  `high_confidence` · score 0.8815 · disproved by: The rule is wrong when the parsed object is afterwards merged or assigned into another object by a recursive merge or setter-based copy that walks own keys, because at that point the own `__proto__` key is written through the setter and does mutate the prototype; the parser is innocent but the copy is the sink.
  sources: <https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/JSON/parse> · <https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Object/proto> · <https://semgrep.dev/docs/writing-rules/data-flow/taint-mode/>
- **An application that explicitly defines `__proto__` as an own property on one object via Object.defineProperty has not polluted anything: the accessor is shadowed for that object only, and the prototype chain of every other object is unchanged.**  
  `high_confidence` · score 0.854 · disproved by: The claim is false when the same call is made on `Object.prototype` itself rather than on an instance, or when the application assigns through the accessor on a shared prototype object; those two cases mutate the chain globally and are genuine pollution despite the identical call syntax.
  sources: <https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Object/create> · <https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Object/proto> · <https://semgrep.dev/docs/writing-rules/data-flow/taint-mode/>
- **Reject a prototype_pollution finding until it is distinguished from the adjacent behaviour this class also covers. "Prototype pollution requires an untrusted JSON body or query object to reach a sink that merges, extends, clones or deep-assigns it into a server-side object; where user input is only read as a scalar and never merged, no payload can..." and "A prototype pollution report is validated only when a probe sent in one request changes an object built by a different, later request; a change reproduced only within the payload's own request does not demonstrate prototype pollution." share a surface and a symptom, so a response that matches the first is not evidence for it while the second remains possible.**  
  `under_review` · score 0.848 · disproved by: This rule is wrong if a controlled test shows the two behaviours can never co-occur on the same surface, or if the corpus entry for "A prototype pollution report is validated only when a probe sent in on" is out of date. In that case this class needs its false-positive guidance rewritten rather than deleted.
  sources: <https://blog.sonarsource.com/blitzjs-prototype-pollution/> · <https://blog.sonarsource.com/etherpad-code-execution-vulnerabilities/>

## Evidence

- **A convincing observation for this class is: This looks like prototype pollution because the payload is textbook and the string __proto__ appears in the request, but the observable effect happens entirely client-side, in the attacker's own session.**  
  `high_confidence` · score 0.863 · disproved by: Not evidence when the observable cannot be produced at all -- blind, server-side-only, or identical-in-every-case behaviour leaves nothing to show. The originating rule (prototype_pollution.fp_rule.client_side_roundtrip_is_not_server_pollution) states the full boundary.
  sources: <https://blog.sonarsource.com/etherpad-code-execution-vulnerabilities/> · <https://sourcegraph.com/blog/static-code-analysis-tools>
- **The evidence that identifies a prototype-pollution vulnerability is the specific merge, deep-assign or setter use on the tainted value, not the input format, because the same JSON body is inert without that sink and a different body format is equally exploitable against it.**  
  `high_confidence` · score 0.838 · disproved by: The claim is false when the vulnerable component itself performs the merge internally on raw bytes — a framework's own body-parsing middleware, an ORM deserialising into a typed model — because there the input format is the entire attack surface and no distinct sink code exists to point at.
  sources: <https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/JSON/parse> · <https://semgrep.dev/docs/writing-rules/data-flow/taint-mode/>
- **A convincing observation for this class is: Adjacent behaviour that produces the same observable result: A prototype pollution report is validated only when a probe sent in one request changes an object built by a different, later request; a change reproduced only within the payload's own request does not demonstrate prototype pollution.**  
  `under_review` · score 0.8205 · disproved by: Not evidence when the observable cannot be produced at all -- blind, server-side-only, or identical-in-every-case behaviour leaves nothing to show. The originating rule (prototype_pollution.fp_rule.auto.derived) states the full boundary.
  sources: <https://blog.sonarsource.com/blitzjs-prototype-pollution/> · <https://blog.sonarsource.com/scripting-outside-the-box-api-client-security-risks-part-1/>
- **A convincing observation for this class is: The whole list of arguments is reflected in the file /proc/self/cmdline so the first element will be at the beginning.**  
  `high_confidence` · score 0.808 · disproved by: Not evidence when the observable cannot be produced at all -- blind, server-side-only, or identical-in-every-case behaviour leaves nothing to show. The originating rule (prototype_pollution.auto.t.228bc545) states the full boundary.
  sources: <https://blog.sonarsource.com/blitzjs-prototype-pollution/> · <https://sourcegraph.com/blog/code-review-checklist>
- **A convincing observation for this class is: arguments is reflected in the file /proc/self/cmdline so the first element will be at the beginning.**  
  `high_confidence` · score 0.808 · disproved by: Not evidence when the observable cannot be produced at all -- blind, server-side-only, or identical-in-every-case behaviour leaves nothing to show. The originating rule (prototype_pollution.auto.t.b79a541e) states the full boundary.
  sources: <https://blog.sonarsource.com/blitzjs-prototype-pollution/> · <https://sourcegraph.com/blog/code-review-checklist>

## Bypass

- **A validation control that only checks the top-level keys of a request body is bypassed by prototype pollution, because a recursive merge descends into nested objects and the dangerous key can sit several levels down where the allowlist never looked.**  
  `high_confidence` · score 0.8655 · disproved by: The rule is false when the check is applied recursively at every depth and the merge refuses to recurse into any key that is not a plain string-keyed object, or when the merge never treats `__proto__`/`constructor`/`prototype` as writable slots; then the nested payload cannot reach the prototype and the shallow-check bypass does not exist.
  sources: <https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Object/proto> · <https://semgrep.dev/docs/writing-rules/data-flow/taint-mode/>

## Chain Link

- **Prototype pollution alone is only a foothold: RCE requires a second gadget that consumes a polluted key, such as a child-process spawn whose env object inherits a NODE_OPTIONS value that adds --require.**  
  `high_confidence` · score 0.8715 · disproved by: If the polluted key is never read by any code path - verified by an unchanged child-process environment and no additional module load in the request logs - then no gadget consumes it and the pollution stops at a DoS-or-nothing level, so the chain to RCE is false.
  sources: <https://blog.sonarsource.com/blitzjs-prototype-pollution/> · <https://blog.orange.tw/posts/2023-08-2023-webconf-the-evolution-of-web-security/>
