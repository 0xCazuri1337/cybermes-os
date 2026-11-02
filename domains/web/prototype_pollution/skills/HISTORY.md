# History

Append-only. Each entry records WHY the skill changed, not just that it did. Improvement means better hunting behaviour, not more text.

## 2026-10-02 15:57 — 1 diff lines
- items: 23 (supported 23), FP rules 2, chains 1, state mature

```diff
(initial generation, 2026-10-02)
```

## 2026-10-02 16:07 — 8 diff lines
- items: 23 (supported 23), FP rules 2, chains 1, state mature

```diff
--- prototype_pollution@current
+++ prototype_pollution@new
@@ -106,4 +106,4 @@
   - Sources: <https://blog.sonarsource.com/blitzjs-prototype-pollution/> · <https://blog.orange.tw/posts/2023-08-2023-webconf-the-evolution-of-web-security/>
 
 ---
-Full class document: `domains/web/prototype_pollution/EVIDENCE.md` · retrieve more with `python -m wks.cli search "<query>" --class-id prototype_pollution`
+Full class document: `domains/web/prototype_pollution/knowledge/DIGEST.md` · retrieve more with `python -m wks.cli search "<query>" --class-id prototype_pollution`
```

## 2026-10-02 19:37 — 134 diff lines
- items: 33 (supported 16), FP rules 4, chains 1, state mature

```diff
--- prototype_pollution@current
+++ prototype_pollution@new
@@ -10,7 +10,7 @@
      python -m wks.skillgen -->
 
 > surface `web` · CWE 1321 · OWASP A08:2021
-> evidence: 23 items, 23 supported, 2 FP rules, 1 chains
+> evidence: 33 items, 16 supported, 4 FP rules, 1 chains
 > maturity: **mature**
 
 Caller input reaches a property write path that mutates a shared prototype.
@@ -35,57 +35,82 @@
 
 ## Techniques (what to change)
 
-- If the attacker changes the value of NODE_OPTIONS to --require /proc/self/cmdline and puts their payload in argv0 , this should work, right?
+- If the attacker changes the value of NODE_OPTIONS to --require /proc/self/cmdline and puts their payload in argv0 , this should work, right? _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "If the attacker changes the value of NODE_OPTIONS to --require /proc/self/cmdline and puts".
   - Sources: <https://blog.sonarsource.com/blitzjs-prototype-pollution/> · <https://sourcegraph.com/blog/code-review-checklist>
-- Prototype Pollution occurs when attackers can gain control over properties of a prototype.
+- Prototype Pollution occurs when attackers can gain control over properties of a prototype. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Prototype Pollution occurs when attackers can gain control over properties of a prototype.".
   - Sources: <https://blog.sonarsource.com/blitzjs-prototype-pollution/> · <https://sourcegraph.com/blog/code-review-checklist>
-- console.log(obj.__proto__); // undefined If you want to harden your code base and make the exploitation of Prototype Pollution issues more difficult, there are some ways to do so, but they each come with their drawbacks.
+- console.log(obj.__proto__); // undefined If you want to harden your code base and make the exploitation of Prototype Pollution issues more difficult, there are some ways to do so, but they each come with their drawbacks. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "console.log(obj.__proto__); // undefined If you want to harden your code base and make the".
   - Sources: <https://blog.sonarsource.com/blitzjs-prototype-pollution/> · <https://sourcegraph.com/blog/code-review-checklist>
-- Gadget 2: From require() to spawn() To turn this into arbitrary code execution, an attacker either needs the ability to create files on the server or another gadget to chain with the first one.
+- Gadget 2: From require() to spawn() To turn this into arbitrary code execution, an attacker either needs the ability to create files on the server or another gadget to chain with the first one. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Gadget 2: From require() to spawn() To turn this into arbitrary code execution, an attacke".
   - Sources: <https://blog.sonarsource.com/blitzjs-prototype-pollution/> · <https://sourcegraph.com/blog/code-review-checklist>
-- This makes the page routing functionality a Prototype Pollution gadget that allows executing any local JavaScript file by inserting a new mapping into the manifest.
+- This makes the page routing functionality a Prototype Pollution gadget that allows executing any local JavaScript file by inserting a new mapping into the manifest. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "This makes the page routing functionality a Prototype Pollution gadget that allows executi".
   - Sources: <https://blog.sonarsource.com/blitzjs-prototype-pollution/> · <https://sourcegraph.com/blog/code-review-checklist>
-- This causes the CLI wrapper script to be executed, spawning a new process with the attacker-controlled argv0 , env , and shell options.
+- This causes the CLI wrapper script to be executed, spawning a new process with the attacker-controlled argv0 , env , and shell options. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "This causes the CLI wrapper script to be executed, spawning a new process with the attacke".
   - Sources: <https://blog.sonarsource.com/blitzjs-prototype-pollution/> · <https://sourcegraph.com/blog/code-review-checklist>
-- A vulnerable code pattern where this can happen is, for instance, obj[a][b] = c : if the attacker controls the values of a , b and c , they can set " __proto__ " for a , the property name for b , and the property value for c .
+- A vulnerable code pattern where this can happen is, for instance, obj[a][b] = c : if the attacker controls the values of a , b and c , they can set " __proto__ " for a , the property name for b , and the property value for c . _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "A vulnerable code pattern where this can happen is, for instance, obj[a][b] = c : if the a".
   - Sources: <https://blog.sonarsource.com/blitzjs-prototype-pollution/> · <https://sourcegraph.com/blog/code-review-checklist>
-- A Blitz.js-based application is vulnerable if it implements at least one RPC call.
+- A Blitz.js-based application is vulnerable if it implements at least one RPC call. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "A Blitz.js-based application is vulnerable if it implements at least one RPC call.".
   - Sources: <https://blog.sonarsource.com/blitzjs-prototype-pollution/> · <https://sourcegraph.com/blog/code-review-checklist>
-- This can be bypassed with the shell option of the spawn() function.
+- This can be bypassed with the shell option of the spawn() function. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "This can be bypassed with the shell option of the spawn() function.".
   - Sources: <https://blog.sonarsource.com/blitzjs-prototype-pollution/> · <https://sourcegraph.com/blog/code-review-checklist>
-- Prototype pollution occurs when user-controlled input is merged into objects without sufficient sanitization, potentially enabling privilege escalation, denial of service, or remote code execution depending on the application context.
+- Prototype pollution occurs when user-controlled input is merged into objects without sufficient sanitization, potentially enabling privilege escalation, denial of service, or remote code execution depending on the application context. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Prototype pollution occurs when user-controlled input is merged into objects without suffi".
   - Sources: <https://blog.sonarsource.com/blitzjs-prototype-pollution/> · <https://sourcegraph.com/blog/code-review-checklist>
-- "abstract": "Sonar's security research team discovered a prototype pollution vulnerability in Blitz.js, a popular full-stack React framework, which could allow attackers to manipulate JavaScript object prototypes and alter application behavior.
+- "abstract": "Sonar's security research team discovered a prototype pollution vulnerability in Blitz.js, a popular full-stack React framework, which could allow attackers to manipulate JavaScript object prototypes and alter application behavior. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: ""abstract": "Sonar's security research team discovered a prototype pollution vulnerability".
   - Sources: <https://blog.sonarsource.com/blitzjs-prototype-pollution/> · <https://sourcegraph.com/blog/code-review-checklist>
-- Also, it is still possible to reach an object's prototype via obj.constructor.prototype , so these property names should still be blocked when validating user-controlled property names.
+- Also, it is still possible to reach an object's prototype via obj.constructor.prototype , so these property names should still be blocked when validating user-controlled property names. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Also, it is still possible to reach an object's prototype via obj.constructor.prototype , ".
   - Sources: <https://blog.sonarsource.com/blitzjs-prototype-pollution/> · <https://sourcegraph.com/blog/code-review-checklist>
-- Finally, we will give recommendations on how to avoid Prototype Pollution vulnerabilities in your JavaScript code.
+- Finally, we will give recommendations on how to avoid Prototype Pollution vulnerabilities in your JavaScript code. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Finally, we will give recommendations on how to avoid Prototype Pollution vulnerabilities ".
   - Sources: <https://blog.sonarsource.com/blitzjs-prototype-pollution/> · <https://sourcegraph.com/blog/code-review-checklist>
-- This finding highlights how JavaScript frameworks that handle user input through object merging or deep cloning operations are particularly susceptible to prototype pollution if input is not rigorously validated.
+- This finding highlights how JavaScript frameworks that handle user input through object merging or deep cloning operations are particularly susceptible to prototype pollution if input is not rigorously validated. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "This finding highlights how JavaScript frameworks that handle user input through object me".
   - Sources: <https://blog.sonarsource.com/blitzjs-prototype-pollution/> · <https://sourcegraph.com/blog/code-review-checklist>
-- However, the command is fixed, and the arguments are not controllable, so how can attackers use this?
+- However, the command is fixed, and the arguments are not controllable, so how can attackers use this? _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "However, the command is fixed, and the arguments are not controllable, so how can attacker".
   - Sources: <https://blog.sonarsource.com/blitzjs-prototype-pollution/> · <https://sourcegraph.com/blog/code-review-checklist>
 - When an app strips the literal key __proto__ from request bodies, the same pollution succeeds via {"constructor":{"prototype":{"<key>":"<value>"}}} because the prototype is still reachable as obj.constructor.prototype.
   - **Disproof:** If the constructor spelling is stripped, coerced to a string, or the merge sink copies own properties only into a null-prototype target, then neither payload reaches a prototype and no inherited key appears on a fresh object: the bypass claim is false for that sink.
   - Sources: <https://blog.sonarsource.com/blitzjs-prototype-pollution/> · <https://blog.sonarsource.com/scripting-outside-the-box-api-client-security-risks-part-1/> · <https://blog.orange.tw/posts/2023-08-2023-webconf-the-evolution-of-web-security/>
 
+## Tests
+
+- To decide this case, observe: treat this as the fp_rule it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable. Boundary of the rule: The rule is wrong when the parsed object is afterwards merged or assigned into another object by a recursive merge or setter-based copy that walks own keys, because at that p _(unverified)_
+  - **Disproof:** This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (prototype_pollution.fp_rule.json_parse_creates_an_own_proto_key_not_a_polluted_prototype) states the full boundary.
+  - Sources: <https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/JSON/parse> · <https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Object/proto>
+- To decide this case, observe: : treat this as the bypass it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable. Boundary of the rule: The rule is false when the check is applied recursively at every depth and the merge refuses to recurse into any key that is not a plain string-keyed object, or when the merg
+  - **Disproof:** This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (prototype_pollution.bypass.a_recursive_merge_that_walks_own_keys_defeats_a_shallow_key_allowlist) states the full boundary.
+  - Sources: <https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Object/proto> · <https://semgrep.dev/docs/writing-rules/data-flow/taint-mode/>
+- To decide this case, observe: treat this as the fp_rule it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable. Boundary of the rule: The claim is false when the same call is made on `Object.prototype` itself rather than on an instance, or when the application assigns through the accessor on a shared protot _(unverified)_
+  - **Disproof:** This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (prototype_pollution.fp_rule.defining_an_own_proto_property_is_not_pollution) states the full boundary.
+  - Sources: <https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Object/proto> · <https://semgrep.dev/docs/writing-rules/data-flow/taint-mode/>
+- To decide this case, observe: eat this as the validation it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable. Boundary of the rule: The claim is false when the visible property is actually an own property of that object (a framework merged the request body into a shared singleton config, a middleware cach
+  - **Disproof:** This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (prototype_pollution.validation.proof_is_inherited_property_visibility_on_an_object_you_never_touched) states the full boundary.
+  - Sources: <https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Object/proto> · <https://semgrep.dev/docs/writing-rules/data-flow/taint-mode/>
+- To decide this case, observe: payload can...
+
+Adjacent behaviour that produces the same observable result: A prototype pollution report is validated only when a probe sent in one request changes an object built by a different, later request; a change reproduced only within the payload's own request does not demonstrate prototype pollution.
+
+Why this is worth checking before reporting: both are recorded in
+  - **Disproof:** This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (prototype_pollution.fp_rule.auto.derived) states the full boundary.
+  - Sources: <https://blog.sonarsource.com/blitzjs-prototype-pollution/> · <https://blog.orange.tw/posts/2023-08-2023-webconf-the-evolution-of-web-security/>
+
 ## Validation bar (how to prove it)
 
+- Prototype pollution is proved by a property that is visible on an object the test never sent any payload to — a freshly constructed `({})` in the same process returning the injected key — because a successful assignment to the prototype is by definition visible through the whole prototype chain.
+  - **Disproof:** The claim is false when the visible property is actually an own property of that object (a framework merged the request body into a shared singleton config, a middleware cached the parsed body on the object, or a test harness reused the same object reference), in which case the value is local, not inherited, and must be distinguished by checking the own-property descriptor rather than the value alone.
+  - Sources: <https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Object/create> · <https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Object/proto> · <https://semgrep.dev/docs/writing-rules/data-flow/taint-mode/>
 - A prototype pollution report is validated only when a probe sent in one request changes an object built by a different, later request; a change reproduced only within the payload's own request does not demonstrate prototype pollution.
   - **Disproof:** Re-run the read-only baseline three times with no payload in between and confirm the response is byte-identical every time; if the suspected inherited property disappears on the second read, or never appears without the payload in the same request, there is no cross-request state change and the pollution claim is not validated.
   - Sources: <https://blog.sonarsource.com/scripting-outside-the-box-api-client-security-risks-part-1/> · <https://sourcegraph.com/blog/sast-vs-dast> · <https://sourcegraph.com/blog/static-code-analysis-tools>
@@ -98,6 +123,24 @@
 - A JSON body containing __proto__ that round-trips through the attacker's own browser or a client-side merge, with no server-side state change, is NOT server-side prototype pollution and must not be filed as this class.
   - **Disproof:** Send the identical payload from a fresh HTTP client that never loaded the app's JavaScript, then request an unrelated endpoint; if the inherited key appears in that server response the pollution is server-side after all and this fp_rule does not apply to it.
   - Sources: <https://blog.sonarsource.com/etherpad-code-execution-vulnerabilities/> · <https://sourcegraph.com/blog/static-code-analysis-tools>
+- An application that explicitly defines `__proto__` as an own property on one object via Object.defineProperty has not polluted anything: the accessor is shadowed for that object only, and the prototype chain of every other object is unchanged.
+  - **Disproof:** The claim is false when the same call is made on `Object.prototype` itself rather than on an instance, or when the application assigns through the accessor on a shared prototype object; those two cases mutate the chain globally and are genuine pollution despite the identical call syntax.
+  - Sources: <https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Object/create> · <https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Object/proto> · <https://semgrep.dev/docs/writing-rules/data-flow/taint-mode/>
+- A payload delivered as a JSON request body and parsed with JSON.parse does not pollute the prototype on its own: the parsed object gets `__proto__` as an ordinary own property, so the absence of inherited state on a fresh object is proof the parser was not the vulnerable step.
+  - **Disproof:** The rule is wrong when the parsed object is afterwards merged or assigned into another object by a recursive merge or setter-based copy that walks own keys, because at that point the own `__proto__` key is written through the setter and does mutate the prototype; the parser is innocent but the copy is the sink.
+  - Sources: <https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/JSON/parse> · <https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Object/proto> · <https://semgrep.dev/docs/writing-rules/data-flow/taint-mode/>
+
... (truncated)
```

## 2026-10-03 01:46 — 169 diff lines
- items: 37 (supported 16), FP rules 3, chains 1, state mature

```diff
--- prototype_pollution@current
+++ prototype_pollution@new
@@ -10,7 +10,7 @@
      python -m wks.skillgen -->
 
 > surface `web` · CWE 1321 · OWASP A08:2021
-> evidence: 33 items, 16 supported, 4 FP rules, 1 chains
+> evidence: 37 items, 16 supported, 3 FP rules, 1 chains
 > maturity: **mature**
 
 Caller input reaches a property write path that mutates a shared prototype.
@@ -20,91 +20,87 @@
 
 ## Prerequisites (do not start without these)
 
-- A deserializer that applies assignments addressed by a caller-supplied path string is prototype-pollutable even when the path is validated as a string, because the destination path may itself contain __proto__ or constructor.prototype segments.
+- A deserializer that applies assignments addressed by a caller-supplied path string is prototype-pollutable even when the path is validated as a string, because the destination path may itself contain __proto__ or constructor.prototype segments. _(unverified)_
   - **Disproof:** Send the same payload with the destination path rewritten to a benign key such as user.name; if the destination path is validated against a pattern that excludes __proto__ and constructor, or the assignment is performed with a key that cannot address a prototype, then caller-controlled path addressing does not exist here and the claim is false.
-  - Sources: <https://blog.sonarsource.com/blitzjs-prototype-pollution/> · <https://sourcegraph.com/blog/code-review-checklist>
-- Prototype pollution requires an untrusted JSON body or query object to reach a sink that merges, extends, clones or deep-assigns it into a server-side object; where user input is only read as a scalar and never merged, no payload can pollute Object.prototype.
+  - Sources: <https://blog.sonarsource.com/blitzjs-prototype-pollution/> · <https://blog.sonarsource.com/scripting-outside-the-box-api-client-security-risks-part-1/>
+- Prototype pollution requires an untrusted JSON body or query object to reach a sink that merges, extends, clones or deep-assigns it into a server-side object; where user input is only read as a scalar and never merged, no payload can pollute Object.prototype. _(unverified)_
   - **Disproof:** Post {"__proto__":{"polluted":"yes"}} and then, in a SEPARATE request to an unrelated endpoint, read the value back on a fresh object: if ({}).polluted is undefined and no observable behaviour anywhere changes, there is no reachable merge sink and the prerequisite claim is false for that endpoint.
-  - Sources: <https://blog.sonarsource.com/blitzjs-prototype-pollution/> · <https://sourcegraph.com/blog/code-review-checklist>
+  - Sources: <https://blog.sonarsource.com/blitzjs-prototype-pollution/> · <https://blog.sonarsource.com/etherpad-code-execution-vulnerabilities/>
 
 ## Recon signals (where to look)
 
 - After a request carrying a __proto__ key, a later request that never repeats the payload shows an inherited property the application never set, which indicates real prototype pollution rather than a rejected input.
   - **Disproof:** If the extra property is visible only in the response to the payload request itself, disappears on the next request, and never appears on an object the application builds independently, then the payload was accepted as ordinary data and nothing was written to Object.prototype: the signal is per-request echo, not pollution.
-  - Sources: <https://blog.sonarsource.com/blitzjs-prototype-pollution/> · <https://www.hackprosec.com/penetration-testing.html>
+  - Sources: <https://blog.sonarsource.com/blitzjs-prototype-pollution/> · <https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Object/proto>
 
 ## Techniques (what to change)
 
 - If the attacker changes the value of NODE_OPTIONS to --require /proc/self/cmdline and puts their payload in argv0 , this should work, right? _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "If the attacker changes the value of NODE_OPTIONS to --require /proc/self/cmdline and puts".
-  - Sources: <https://blog.sonarsource.com/blitzjs-prototype-pollution/> · <https://sourcegraph.com/blog/code-review-checklist>
+  - Sources: <https://blog.sonarsource.com/blitzjs-prototype-pollution/>
 - Prototype Pollution occurs when attackers can gain control over properties of a prototype. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Prototype Pollution occurs when attackers can gain control over properties of a prototype.".
-  - Sources: <https://blog.sonarsource.com/blitzjs-prototype-pollution/> · <https://sourcegraph.com/blog/code-review-checklist>
+  - Sources: <https://blog.sonarsource.com/blitzjs-prototype-pollution/> · <https://blog.orange.tw/posts/2023-08-2023-webconf-the-evolution-of-web-security/>
 - console.log(obj.__proto__); // undefined If you want to harden your code base and make the exploitation of Prototype Pollution issues more difficult, there are some ways to do so, but they each come with their drawbacks. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "console.log(obj.__proto__); // undefined If you want to harden your code base and make the".
-  - Sources: <https://blog.sonarsource.com/blitzjs-prototype-pollution/> · <https://sourcegraph.com/blog/code-review-checklist>
+  - Sources: <https://blog.sonarsource.com/blitzjs-prototype-pollution/> · <https://blog.sonarsource.com/scripting-outside-the-box-api-client-security-risks-part-1/>
 - Gadget 2: From require() to spawn() To turn this into arbitrary code execution, an attacker either needs the ability to create files on the server or another gadget to chain with the first one. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Gadget 2: From require() to spawn() To turn this into arbitrary code execution, an attacke".
-  - Sources: <https://blog.sonarsource.com/blitzjs-prototype-pollution/> · <https://sourcegraph.com/blog/code-review-checklist>
+  - Sources: <https://blog.sonarsource.com/blitzjs-prototype-pollution/>
 - This makes the page routing functionality a Prototype Pollution gadget that allows executing any local JavaScript file by inserting a new mapping into the manifest. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "This makes the page routing functionality a Prototype Pollution gadget that allows executi".
-  - Sources: <https://blog.sonarsource.com/blitzjs-prototype-pollution/> · <https://sourcegraph.com/blog/code-review-checklist>
+  - Sources: <https://blog.sonarsource.com/blitzjs-prototype-pollution/> · <https://blog.sonarsource.com/etherpad-code-execution-vulnerabilities/>
 - This causes the CLI wrapper script to be executed, spawning a new process with the attacker-controlled argv0 , env , and shell options. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "This causes the CLI wrapper script to be executed, spawning a new process with the attacke".
-  - Sources: <https://blog.sonarsource.com/blitzjs-prototype-pollution/> · <https://sourcegraph.com/blog/code-review-checklist>
+  - Sources: <https://blog.sonarsource.com/blitzjs-prototype-pollution/>
 - A vulnerable code pattern where this can happen is, for instance, obj[a][b] = c : if the attacker controls the values of a , b and c , they can set " __proto__ " for a , the property name for b , and the property value for c . _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "A vulnerable code pattern where this can happen is, for instance, obj[a][b] = c : if the a".
-  - Sources: <https://blog.sonarsource.com/blitzjs-prototype-pollution/> · <https://sourcegraph.com/blog/code-review-checklist>
+  - Sources: <https://blog.sonarsource.com/blitzjs-prototype-pollution/> · <https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/JSON/parse>
 - A Blitz.js-based application is vulnerable if it implements at least one RPC call. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "A Blitz.js-based application is vulnerable if it implements at least one RPC call.".
-  - Sources: <https://blog.sonarsource.com/blitzjs-prototype-pollution/> · <https://sourcegraph.com/blog/code-review-checklist>
+  - Sources: <https://blog.sonarsource.com/blitzjs-prototype-pollution/>
 - This can be bypassed with the shell option of the spawn() function. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "This can be bypassed with the shell option of the spawn() function.".
-  - Sources: <https://blog.sonarsource.com/blitzjs-prototype-pollution/> · <https://sourcegraph.com/blog/code-review-checklist>
+  - Sources: <https://blog.sonarsource.com/blitzjs-prototype-pollution/>
 - Prototype pollution occurs when user-controlled input is merged into objects without sufficient sanitization, potentially enabling privilege escalation, denial of service, or remote code execution depending on the application context. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Prototype pollution occurs when user-controlled input is merged into objects without suffi".
-  - Sources: <https://blog.sonarsource.com/blitzjs-prototype-pollution/> · <https://sourcegraph.com/blog/code-review-checklist>
+  - Sources: <https://blog.sonarsource.com/blitzjs-prototype-pollution/> · <https://blog.sonarsource.com/etherpad-code-execution-vulnerabilities/>
 - "abstract": "Sonar's security research team discovered a prototype pollution vulnerability in Blitz.js, a popular full-stack React framework, which could allow attackers to manipulate JavaScript object prototypes and alter application behavior. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: ""abstract": "Sonar's security research team discovered a prototype pollution vulnerability".
-  - Sources: <https://blog.sonarsource.com/blitzjs-prototype-pollution/> · <https://sourcegraph.com/blog/code-review-checklist>
+  - Sources: <https://blog.sonarsource.com/blitzjs-prototype-pollution/> · <https://blog.sonarsource.com/etherpad-code-execution-vulnerabilities/>
 - Also, it is still possible to reach an object's prototype via obj.constructor.prototype , so these property names should still be blocked when validating user-controlled property names. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Also, it is still possible to reach an object's prototype via obj.constructor.prototype , ".
-  - Sources: <https://blog.sonarsource.com/blitzjs-prototype-pollution/> · <https://sourcegraph.com/blog/code-review-checklist>
+  - Sources: <https://blog.sonarsource.com/blitzjs-prototype-pollution/> · <https://blog.sonarsource.com/scripting-outside-the-box-api-client-security-risks-part-1/>
 - Finally, we will give recommendations on how to avoid Prototype Pollution vulnerabilities in your JavaScript code. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Finally, we will give recommendations on how to avoid Prototype Pollution vulnerabilities ".
-  - Sources: <https://blog.sonarsource.com/blitzjs-prototype-pollution/> · <https://sourcegraph.com/blog/code-review-checklist>
+  - Sources: <https://blog.sonarsource.com/blitzjs-prototype-pollution/> · <https://blog.sonarsource.com/etherpad-code-execution-vulnerabilities/>
 - This finding highlights how JavaScript frameworks that handle user input through object merging or deep cloning operations are particularly susceptible to prototype pollution if input is not rigorously validated. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "This finding highlights how JavaScript frameworks that handle user input through object me".
-  - Sources: <https://blog.sonarsource.com/blitzjs-prototype-pollution/> · <https://sourcegraph.com/blog/code-review-checklist>
+  - Sources: <https://blog.sonarsource.com/blitzjs-prototype-pollution/> · <https://blog.sonarsource.com/etherpad-code-execution-vulnerabilities/>
 - However, the command is fixed, and the arguments are not controllable, so how can attackers use this? _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "However, the command is fixed, and the arguments are not controllable, so how can attacker".
-  - Sources: <https://blog.sonarsource.com/blitzjs-prototype-pollution/> · <https://sourcegraph.com/blog/code-review-checklist>
+  - Sources: <https://blog.sonarsource.com/blitzjs-prototype-pollution/>
 - When an app strips the literal key __proto__ from request bodies, the same pollution succeeds via {"constructor":{"prototype":{"<key>":"<value>"}}} because the prototype is still reachable as obj.constructor.prototype.
   - **Disproof:** If the constructor spelling is stripped, coerced to a string, or the merge sink copies own properties only into a null-prototype target, then neither payload reaches a prototype and no inherited key appears on a fresh object: the bypass claim is false for that sink.
-  - Sources: <https://blog.sonarsource.com/blitzjs-prototype-pollution/> · <https://blog.sonarsource.com/scripting-outside-the-box-api-client-security-risks-part-1/> · <https://blog.orange.tw/posts/2023-08-2023-webconf-the-evolution-of-web-security/>
+  - Sources: <https://blog.sonarsource.com/blitzjs-prototype-pollution/> · <https://blog.sonarsource.com/scripting-outside-the-box-api-client-security-risks-part-1/> · <https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/JSON/parse>
 
 ## Tests
 
-- To decide this case, observe: treat this as the fp_rule it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable. Boundary of the rule: The rule is wrong when the parsed object is afterwards merged or assigned into another object by a recursive merge or setter-based copy that walks own keys, because at that p _(unverified)_
+- To decide this case, observe: How to apply it in the field: treat this as the fp_rule it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable. _(unverified)_
   - **Disproof:** This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (prototype_pollution.fp_rule.json_parse_creates_an_own_proto_key_not_a_polluted_prototype) states the full boundary.
   - Sources: <https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/JSON/parse> · <https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Object/proto>
-- To decide this case, observe: : treat this as the bypass it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable. Boundary of the rule: The rule is false when the check is applied recursively at every depth and the merge refuses to recurse into any key that is not a plain string-keyed object, or when the merg
+- To decide this case, observe: How to apply it in the field: treat this as the bypass it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable.
   - **Disproof:** This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (prototype_pollution.bypass.a_recursive_merge_that_walks_own_keys_defeats_a_shallow_key_allowlist) states the full boundary.
   - Sources: <https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Object/proto> · <https://semgrep.dev/docs/writing-rules/data-flow/taint-mode/>
-- To decide this case, observe: treat this as the fp_rule it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable. Boundary of the rule: The claim is false when the same call is made on `Object.prototype` itself rather than on an instance, or when the application assigns through the accessor on a shared protot _(unverified)_
+- To decide this case, observe: How to apply it in the field: treat this as the fp_rule it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable.
   - **Disproof:** This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (prototype_pollution.fp_rule.defining_an_own_proto_property_is_not_pollution) states the full boundary.
   - Sources: <https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Object/proto> · <https://semgrep.dev/docs/writing-rules/data-flow/taint-mode/>
-- To decide this case, observe: eat this as the validation it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable. Boundary of the rule: The claim is false when the visible property is actually an own property of that object (a framework merged the request body into a shared singleton config, a middleware cach
+- To decide this case, observe: How to apply it in the field: treat this as the validation it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable.
   - **Disproof:** This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (prototype_pollution.validation.proof_is_inherited_property_visibility_on_an_object_you_never_touched) states the full boundary.
   - Sources: <https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Object/proto> · <https://semgrep.dev/docs/writing-rules/data-flow/taint-mode/>
-- To decide this case, observe: payload can...
-
... (truncated)
```

## 2026-10-04 00:43 — 236 diff lines
- items: 37 (supported 16), FP rules 3, chains 1, state mature

```diff
--- prototype_pollution@current
+++ prototype_pollution@new
@@ -20,141 +20,153 @@
 
 ## Prerequisites (do not start without these)
 
-- A deserializer that applies assignments addressed by a caller-supplied path string is prototype-pollutable even when the path is validated as a string, because the destination path may itself contain __proto__ or constructor.prototype segments. _(unverified)_
+- A deserializer that applies assignments addressed by a caller-supplied path string is prototype-pollutable even when the path is validated as a string, because the destination path may itself contain __proto__ or constructor.prototype segments.  _(merged 1 duplicate row(s))_ _(unverified)_
   - **Disproof:** Send the same payload with the destination path rewritten to a benign key such as user.name; if the destination path is validated against a pattern that excludes __proto__ and constructor, or the assignment is performed with a key that cannot address a prototype, then caller-controlled path addressing does not exist here and the claim is false.
   - Sources: <https://blog.sonarsource.com/blitzjs-prototype-pollution/> · <https://blog.sonarsource.com/scripting-outside-the-box-api-client-security-risks-part-1/>
-- Prototype pollution requires an untrusted JSON body or query object to reach a sink that merges, extends, clones or deep-assigns it into a server-side object; where user input is only read as a scalar and never merged, no payload can pollute Object.prototype. _(unverified)_
+- Prototype pollution requires an untrusted JSON body or query object to reach a sink that merges, extends, clones or deep-assigns it into a server-side object; where user input is only read as a scalar and never merged, no payload can pollute Object.prototype.  _(merged 1 duplicate row(s))_ _(unverified)_
   - **Disproof:** Post {"__proto__":{"polluted":"yes"}} and then, in a SEPARATE request to an unrelated endpoint, read the value back on a fresh object: if ({}).polluted is undefined and no observable behaviour anywhere changes, there is no reachable merge sink and the prerequisite claim is false for that endpoint.
   - Sources: <https://blog.sonarsource.com/blitzjs-prototype-pollution/> · <https://blog.sonarsource.com/etherpad-code-execution-vulnerabilities/>
 
 ## Recon signals (where to look)
 
-- After a request carrying a __proto__ key, a later request that never repeats the payload shows an inherited property the application never set, which indicates real prototype pollution rather than a rejected input.
+- After a request carrying a __proto__ key, a later request that never repeats the payload shows an inherited property the application never set, which indicates real prototype pollution rather than a rejected input.  _(merged 1 duplicate row(s))_
   - **Disproof:** If the extra property is visible only in the response to the payload request itself, disappears on the next request, and never appears on an object the application builds independently, then the payload was accepted as ordinary data and nothing was written to Object.prototype: the signal is per-request echo, not pollution.
   - Sources: <https://blog.sonarsource.com/blitzjs-prototype-pollution/> · <https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Object/proto>
 
 ## Techniques (what to change)
 
-- If the attacker changes the value of NODE_OPTIONS to --require /proc/self/cmdline and puts their payload in argv0 , this should work, right? _(unverified)_
+- "abstract": "Sonar's security research team discovered a prototype pollution vulnerability in Blitz.js, a popular full-stack React framework, which could allow attackers to manipulate JavaScript object prototypes and alter application behavior.  _(merged 1 duplicate row(s))_ _(unverified)_
+  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: ""abstract": "Sonar's security research team discovered a prototype pollution vulnerability".
+  - Sources: <https://blog.sonarsource.com/blitzjs-prototype-pollution/> · <https://blog.sonarsource.com/etherpad-code-execution-vulnerabilities/>
+- A Blitz.js-based application is vulnerable if it implements at least one RPC call.  _(merged 1 duplicate row(s))_ _(unverified)_
+  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "A Blitz.js-based application is vulnerable if it implements at least one RPC call.".
+  - Sources: <https://blog.sonarsource.com/blitzjs-prototype-pollution/>
+- A vulnerable code pattern where this can happen is, for instance, obj[a][b] = c : if the attacker controls the values of a , b and c , they can set " __proto__ " for a , the property name for b , and the property value for c .  _(merged 1 duplicate row(s))_ _(unverified)_
+  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "A vulnerable code pattern where this can happen is, for instance, obj[a][b] = c : if the a".
+  - Sources: <https://blog.sonarsource.com/blitzjs-prototype-pollution/> · <https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/JSON/parse>
+- Also, it is still possible to reach an object's prototype via obj.constructor.prototype , so these property names should still be blocked when validating user-controlled property names.  _(merged 1 duplicate row(s))_ _(unverified)_
+  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Also, it is still possible to reach an object's prototype via obj.constructor.prototype , ".
+  - Sources: <https://blog.sonarsource.com/blitzjs-prototype-pollution/> · <https://blog.sonarsource.com/scripting-outside-the-box-api-client-security-risks-part-1/>
+- Finally, we will give recommendations on how to avoid Prototype Pollution vulnerabilities in your JavaScript code.  _(merged 1 duplicate row(s))_ _(unverified)_
+  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Finally, we will give recommendations on how to avoid Prototype Pollution vulnerabilities ".
+  - Sources: <https://blog.sonarsource.com/blitzjs-prototype-pollution/> · <https://blog.sonarsource.com/etherpad-code-execution-vulnerabilities/>
+- Gadget 2: From require() to spawn() To turn this into arbitrary code execution, an attacker either needs the ability to create files on the server or another gadget to chain with the first one.  _(merged 1 duplicate row(s))_ _(unverified)_
+  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Gadget 2: From require() to spawn() To turn this into arbitrary code execution, an attacke".
+  - Sources: <https://blog.sonarsource.com/blitzjs-prototype-pollution/>
+- However, the command is fixed, and the arguments are not controllable, so how can attackers use this?  _(merged 1 duplicate row(s))_ _(unverified)_
+  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "However, the command is fixed, and the arguments are not controllable, so how can attacker".
+  - Sources: <https://blog.sonarsource.com/blitzjs-prototype-pollution/>
+- If the attacker changes the value of NODE_OPTIONS to --require /proc/self/cmdline and puts their payload in argv0 , this should work, right?  _(merged 1 duplicate row(s))_ _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "If the attacker changes the value of NODE_OPTIONS to --require /proc/self/cmdline and puts".
   - Sources: <https://blog.sonarsource.com/blitzjs-prototype-pollution/>
-- Prototype Pollution occurs when attackers can gain control over properties of a prototype. _(unverified)_
+- Prototype Pollution occurs when attackers can gain control over properties of a prototype.  _(merged 1 duplicate row(s))_ _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Prototype Pollution occurs when attackers can gain control over properties of a prototype.".
   - Sources: <https://blog.sonarsource.com/blitzjs-prototype-pollution/> · <https://blog.orange.tw/posts/2023-08-2023-webconf-the-evolution-of-web-security/>
-- console.log(obj.__proto__); // undefined If you want to harden your code base and make the exploitation of Prototype Pollution issues more difficult, there are some ways to do so, but they each come with their drawbacks. _(unverified)_
+- Prototype pollution occurs when user-controlled input is merged into objects without sufficient sanitization, potentially enabling privilege escalation, denial of service, or remote code execution depending on the application context.  _(merged 1 duplicate row(s))_ _(unverified)_
+  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Prototype pollution occurs when user-controlled input is merged into objects without suffi".
+  - Sources: <https://blog.sonarsource.com/blitzjs-prototype-pollution/> · <https://blog.sonarsource.com/etherpad-code-execution-vulnerabilities/>
+- This can be bypassed with the shell option of the spawn() function.  _(merged 1 duplicate row(s))_ _(unverified)_
+  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "This can be bypassed with the shell option of the spawn() function.".
+  - Sources: <https://blog.sonarsource.com/blitzjs-prototype-pollution/>
+- This causes the CLI wrapper script to be executed, spawning a new process with the attacker-controlled argv0 , env , and shell options.  _(merged 1 duplicate row(s))_ _(unverified)_
+  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "This causes the CLI wrapper script to be executed, spawning a new process with the attacke".
+  - Sources: <https://blog.sonarsource.com/blitzjs-prototype-pollution/>
+- This finding highlights how JavaScript frameworks that handle user input through object merging or deep cloning operations are particularly susceptible to prototype pollution if input is not rigorously validated.  _(merged 1 duplicate row(s))_ _(unverified)_
+  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "This finding highlights how JavaScript frameworks that handle user input through object me".
+  - Sources: <https://blog.sonarsource.com/blitzjs-prototype-pollution/> · <https://blog.sonarsource.com/etherpad-code-execution-vulnerabilities/>
+- This makes the page routing functionality a Prototype Pollution gadget that allows executing any local JavaScript file by inserting a new mapping into the manifest.  _(merged 1 duplicate row(s))_ _(unverified)_
+  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "This makes the page routing functionality a Prototype Pollution gadget that allows executi".
+  - Sources: <https://blog.sonarsource.com/blitzjs-prototype-pollution/> · <https://blog.sonarsource.com/etherpad-code-execution-vulnerabilities/>
+- When an app strips the literal key __proto__ from request bodies, the same pollution succeeds via {"constructor":{"prototype":{"<key>":"<value>"}}} because the prototype is still reachable as obj.constructor.prototype.  _(merged 1 duplicate row(s))_
+  - **Disproof:** If the constructor spelling is stripped, coerced to a string, or the merge sink copies own properties only into a null-prototype target, then neither payload reaches a prototype and no inherited key appears on a fresh object: the bypass claim is false for that sink.
+  - Sources: <https://blog.sonarsource.com/blitzjs-prototype-pollution/> · <https://blog.sonarsource.com/scripting-outside-the-box-api-client-security-risks-part-1/> · <https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/JSON/parse>
+- console.log(obj.__proto__); // undefined If you want to harden your code base and make the exploitation of Prototype Pollution issues more difficult, there are some ways to do so, but they each come with their drawbacks.  _(merged 1 duplicate row(s))_ _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "console.log(obj.__proto__); // undefined If you want to harden your code base and make the".
   - Sources: <https://blog.sonarsource.com/blitzjs-prototype-pollution/> · <https://blog.sonarsource.com/scripting-outside-the-box-api-client-security-risks-part-1/>
-- Gadget 2: From require() to spawn() To turn this into arbitrary code execution, an attacker either needs the ability to create files on the server or another gadget to chain with the first one. _(unverified)_
-  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Gadget 2: From require() to spawn() To turn this into arbitrary code execution, an attacke".
-  - Sources: <https://blog.sonarsource.com/blitzjs-prototype-pollution/>
-- This makes the page routing functionality a Prototype Pollution gadget that allows executing any local JavaScript file by inserting a new mapping into the manifest. _(unverified)_
-  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "This makes the page routing functionality a Prototype Pollution gadget that allows executi".
-  - Sources: <https://blog.sonarsource.com/blitzjs-prototype-pollution/> · <https://blog.sonarsource.com/etherpad-code-execution-vulnerabilities/>
-- This causes the CLI wrapper script to be executed, spawning a new process with the attacker-controlled argv0 , env , and shell options. _(unverified)_
-  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "This causes the CLI wrapper script to be executed, spawning a new process with the attacke".
-  - Sources: <https://blog.sonarsource.com/blitzjs-prototype-pollution/>
-- A vulnerable code pattern where this can happen is, for instance, obj[a][b] = c : if the attacker controls the values of a , b and c , they can set " __proto__ " for a , the property name for b , and the property value for c . _(unverified)_
-  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "A vulnerable code pattern where this can happen is, for instance, obj[a][b] = c : if the a".
-  - Sources: <https://blog.sonarsource.com/blitzjs-prototype-pollution/> · <https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/JSON/parse>
-- A Blitz.js-based application is vulnerable if it implements at least one RPC call. _(unverified)_
-  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "A Blitz.js-based application is vulnerable if it implements at least one RPC call.".
-  - Sources: <https://blog.sonarsource.com/blitzjs-prototype-pollution/>
-- This can be bypassed with the shell option of the spawn() function. _(unverified)_
-  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "This can be bypassed with the shell option of the spawn() function.".
-  - Sources: <https://blog.sonarsource.com/blitzjs-prototype-pollution/>
-- Prototype pollution occurs when user-controlled input is merged into objects without sufficient sanitization, potentially enabling privilege escalation, denial of service, or remote code execution depending on the application context. _(unverified)_
-  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Prototype pollution occurs when user-controlled input is merged into objects without suffi".
-  - Sources: <https://blog.sonarsource.com/blitzjs-prototype-pollution/> · <https://blog.sonarsource.com/etherpad-code-execution-vulnerabilities/>
-- "abstract": "Sonar's security research team discovered a prototype pollution vulnerability in Blitz.js, a popular full-stack React framework, which could allow attackers to manipulate JavaScript object prototypes and alter application behavior. _(unverified)_
-  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: ""abstract": "Sonar's security research team discovered a prototype pollution vulnerability".
-  - Sources: <https://blog.sonarsource.com/blitzjs-prototype-pollution/> · <https://blog.sonarsource.com/etherpad-code-execution-vulnerabilities/>
-- Also, it is still possible to reach an object's prototype via obj.constructor.prototype , so these property names should still be blocked when validating user-controlled property names. _(unverified)_
-  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Also, it is still possible to reach an object's prototype via obj.constructor.prototype , ".
-  - Sources: <https://blog.sonarsource.com/blitzjs-prototype-pollution/> · <https://blog.sonarsource.com/scripting-outside-the-box-api-client-security-risks-part-1/>
-- Finally, we will give recommendations on how to avoid Prototype Pollution vulnerabilities in your JavaScript code. _(unverified)_
-  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Finally, we will give recommendations on how to avoid Prototype Pollution vulnerabilities ".
-  - Sources: <https://blog.sonarsource.com/blitzjs-prototype-pollution/> · <https://blog.sonarsource.com/etherpad-code-execution-vulnerabilities/>
-- This finding highlights how JavaScript frameworks that handle user input through object merging or deep cloning operations are particularly susceptible to prototype pollution if input is not rigorously validated. _(unverified)_
-  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "This finding highlights how JavaScript frameworks that handle user input through object me".
-  - Sources: <https://blog.sonarsource.com/blitzjs-prototype-pollution/> · <https://blog.sonarsource.com/etherpad-code-execution-vulnerabilities/>
-- However, the command is fixed, and the arguments are not controllable, so how can attackers use this? _(unverified)_
-  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "However, the command is fixed, and the arguments are not controllable, so how can attacker".
-  - Sources: <https://blog.sonarsource.com/blitzjs-prototype-pollution/>
-- When an app strips the literal key __proto__ from request bodies, the same pollution succeeds via {"constructor":{"prototype":{"<key>":"<value>"}}} because the prototype is still reachable as obj.constructor.prototype.
-  - **Disproof:** If the constructor spelling is stripped, coerced to a string, or the merge sink copies own properties only into a null-prototype target, then neither payload reaches a prototype and no inherited key appears on a fresh object: the bypass claim is false for that sink.
-  - Sources: <https://blog.sonarsource.com/blitzjs-prototype-pollution/> · <https://blog.sonarsource.com/scripting-outside-the-box-api-client-security-risks-part-1/> · <https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/JSON/parse>
 
 ## Tests
 
-- To decide this case, observe: How to apply it in the field: treat this as the fp_rule it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable. _(unverified)_
-  - **Disproof:** This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (prototype_pollution.fp_rule.json_parse_creates_an_own_proto_key_not_a_polluted_prototype) states the full boundary.
-  - Sources: <https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/JSON/parse> · <https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Object/proto>
... (truncated)
```

## 2026-10-04 13:20 — 23 diff lines
- items: 37 (supported 17), FP rules 3, chains 1, state mature

```diff
--- prototype_pollution@current
+++ prototype_pollution@new
@@ -10,7 +10,7 @@
      python -m wks.skillgen -->
 
 > surface `web` · CWE 1321 · OWASP A08:2021
-> evidence: 37 items, 16 supported, 3 FP rules, 1 chains
+> evidence: 37 items, 17 supported, 3 FP rules, 1 chains
 > maturity: **mature**
 
 Caller input reaches a property write path that mutates a shared prototype.
@@ -95,9 +95,9 @@
 - To decide this case, observe: How to apply it in the field: treat this as the validation it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable.  _(merged 1 duplicate row(s))_
   - **Disproof:** This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (prototype_pollution.validation.proof_is_inherited_property_visibility_on_an_object_you_never_touched) states the full boundary.
   - Sources: <https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Object/proto> · <https://semgrep.dev/docs/writing-rules/data-flow/taint-mode/>
-- To decide this case, observe: Hypothesis under test: Prototype pollution requires an untrusted JSON body or query object to reach a sink that merges, extends, clones or deep-assigns it into a server-side object; where user input is only read as a scalar and never merged, no payload can...  _(merged 1 duplicate row(s))_ _(unverified)_
+- To decide this case, observe: Hypothesis under test: Prototype pollution requires an untrusted JSON body or query object to reach a sink that merges, extends, clones or deep-assigns it into a server-side object; where user input is only read as a scalar and never merged, no payload can...  _(merged 1 duplicate row(s))_
   - **Disproof:** This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (prototype_pollution.fp_rule.auto.derived) states the full boundary.
-  - Sources: <https://blog.sonarsource.com/blitzjs-prototype-pollution/> · <https://blog.sonarsource.com/scripting-outside-the-box-api-client-security-risks-part-1/>
+  - Sources: <https://blog.sonarsource.com/blitzjs-prototype-pollution/> · <https://blog.sonarsource.com/scripting-outside-the-box-api-client-security-risks-part-1/> · <https://blog.orange.tw/posts/2023-08-2023-webconf-the-evolution-of-web-security/>
 
 ## Validation bar (how to prove it)
 
```

## 2026-10-04 19:46 — 9 diff lines
- items: 37 (supported 17), FP rules 3, chains 1, state mature

```diff
--- prototype_pollution@current
+++ prototype_pollution@new
@@ -170,6 +170,3 @@
 > Ordered prerequisites, the validation bar and the false-positive rules below are the authority: this block is the mechanics, those are the standard.
 ---
 Full class document: `domains/web/prototype_pollution/knowledge/DIGEST.md` · retrieve more with `python -m wks.cli search "<query>" --class-id prototype_pollution`
-
----
-Runbook: [`HUNT.md`](HUNT.md) — every promoted technique mapped to an executable procedure with the observables to record.
```

## 2026-10-04 21:29 — 33 diff lines
- items: 37 (supported 19), FP rules 3, chains 1, state mature

```diff
--- prototype_pollution@current
+++ prototype_pollution@new
@@ -10,7 +10,7 @@
      python -m wks.skillgen -->
 
 > surface `web` · CWE 1321 · OWASP A08:2021
-> evidence: 37 items, 17 supported, 3 FP rules, 1 chains
+> evidence: 37 items, 19 supported, 3 FP rules, 1 chains
 > maturity: **mature**
 
 Caller input reaches a property write path that mutates a shared prototype.
@@ -41,8 +41,8 @@
 - A Blitz.js-based application is vulnerable if it implements at least one RPC call.  _(merged 1 duplicate row(s))_ _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "A Blitz.js-based application is vulnerable if it implements at least one RPC call.".
   - Sources: <https://blog.sonarsource.com/blitzjs-prototype-pollution/>
-- A vulnerable code pattern where this can happen is, for instance, obj[a][b] = c : if the attacker controls the values of a , b and c , they can set " __proto__ " for a , the property name for b , and the property value for c .  _(merged 1 duplicate row(s))_ _(unverified)_
-  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "A vulnerable code pattern where this can happen is, for instance, obj[a][b] = c : if the a".
+- A vulnerable code pattern where this can happen is, for instance, obj[a][b] = c : if the attacker controls the values of a , b and c , they can set " __proto__ " for a , the property name for b , and the property value for c .  _(merged 1 duplicate row(s))_
+  - **Disproof:** Refuted when: the same behaviour is absent when the single named control in the claim is present, and the control is shown to be present rather than assumed. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“A vulnerable code pattern where this can happen is, for instance, obj[a][b] = c ”) does not occur under a test that isolates that control.
   - Sources: <https://blog.sonarsource.com/blitzjs-prototype-pollution/> · <https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/JSON/parse>
 - Also, it is still possible to reach an object's prototype via obj.constructor.prototype , so these property names should still be blocked when validating user-controlled property names.  _(merged 1 duplicate row(s))_ _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Also, it is still possible to reach an object's prototype via obj.constructor.prototype , ".
@@ -59,8 +59,8 @@
 - If the attacker changes the value of NODE_OPTIONS to --require /proc/self/cmdline and puts their payload in argv0 , this should work, right?  _(merged 1 duplicate row(s))_ _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "If the attacker changes the value of NODE_OPTIONS to --require /proc/self/cmdline and puts".
   - Sources: <https://blog.sonarsource.com/blitzjs-prototype-pollution/>
-- Prototype Pollution occurs when attackers can gain control over properties of a prototype.  _(merged 1 duplicate row(s))_ _(unverified)_
-  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Prototype Pollution occurs when attackers can gain control over properties of a prototype.".
+- Prototype Pollution occurs when attackers can gain control over properties of a prototype.  _(merged 1 duplicate row(s))_
+  - **Disproof:** Refuted when: the same behaviour is absent when the single named control in the claim is present, and the control is shown to be present rather than assumed. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“Prototype Pollution occurs when attackers can gain control over properties of a ”) does not occur under a test that isolates that control.
   - Sources: <https://blog.sonarsource.com/blitzjs-prototype-pollution/> · <https://blog.orange.tw/posts/2023-08-2023-webconf-the-evolution-of-web-security/>
 - Prototype pollution occurs when user-controlled input is merged into objects without sufficient sanitization, potentially enabling privilege escalation, denial of service, or remote code execution depending on the application context.  _(merged 1 duplicate row(s))_ _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Prototype pollution occurs when user-controlled input is merged into objects without suffi".
```

## 2026-10-28 14:45 — 44 diff lines
- items: 33 (supported 18), FP rules 3, chains 1, state mature

```diff
--- prototype_pollution@current
+++ prototype_pollution@new
@@ -10,7 +10,7 @@
      python -m wks.skillgen -->
 
 > surface `web` · CWE 1321 · OWASP A08:2021
-> evidence: 37 items, 19 supported, 3 FP rules, 1 chains
+> evidence: 33 items, 18 supported, 3 FP rules, 1 chains
 > maturity: **mature**
 
 Caller input reaches a property write path that mutates a shared prototype.
@@ -20,12 +20,12 @@
 
 ## Prerequisites (do not start without these)
 
-- A deserializer that applies assignments addressed by a caller-supplied path string is prototype-pollutable even when the path is validated as a string, because the destination path may itself contain __proto__ or constructor.prototype segments.  _(merged 1 duplicate row(s))_ _(unverified)_
+- A deserializer that applies assignments addressed by a caller-supplied path string is prototype-pollutable even when the path is validated as a string, because the destination path may itself contain __proto__ or constructor.prototype segments.  _(merged 1 duplicate row(s))_
   - **Disproof:** Send the same payload with the destination path rewritten to a benign key such as user.name; if the destination path is validated against a pattern that excludes __proto__ and constructor, or the assignment is performed with a key that cannot address a prototype, then caller-controlled path addressing does not exist here and the claim is false.
-  - Sources: <https://blog.sonarsource.com/blitzjs-prototype-pollution/> · <https://blog.sonarsource.com/scripting-outside-the-box-api-client-security-risks-part-1/>
-- Prototype pollution requires an untrusted JSON body or query object to reach a sink that merges, extends, clones or deep-assigns it into a server-side object; where user input is only read as a scalar and never merged, no payload can pollute Object.prototype.  _(merged 1 duplicate row(s))_ _(unverified)_
+  - Sources: <https://cwe.mitre.org/data/definitions/1321.html> · <https://blog.sonarsource.com/blitzjs-prototype-pollution/> · <https://blog.sonarsource.com/scripting-outside-the-box-api-client-security-risks-part-1/>
+- Prototype pollution requires an untrusted JSON body or query object to reach a sink that merges, extends, clones or deep-assigns it into a server-side object; where user input is only read as a scalar and never merged, no payload can pollute Object.prototype.  _(merged 1 duplicate row(s))_
   - **Disproof:** Post {"__proto__":{"polluted":"yes"}} and then, in a SEPARATE request to an unrelated endpoint, read the value back on a fresh object: if ({}).polluted is undefined and no observable behaviour anywhere changes, there is no reachable merge sink and the prerequisite claim is false for that endpoint.
-  - Sources: <https://blog.sonarsource.com/blitzjs-prototype-pollution/> · <https://blog.sonarsource.com/etherpad-code-execution-vulnerabilities/>
+  - Sources: <https://blog.sonarsource.com/blitzjs-prototype-pollution/> · <https://blog.sonarsource.com/etherpad-code-execution-vulnerabilities/> · <https://portswigger.net/web-security/prototype-pollution>
 
 ## Recon signals (where to look)
 
@@ -86,15 +86,6 @@
 
 ## Tests
 
-- To decide this case, observe: How to apply it in the field: treat this as the bypass it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable.  _(merged 1 duplicate row(s))_
-  - **Disproof:** This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (prototype_pollution.bypass.a_recursive_merge_that_walks_own_keys_defeats_a_shallow_key_allowlist) states the full boundary.
-  - Sources: <https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Object/proto> · <https://semgrep.dev/docs/writing-rules/data-flow/taint-mode/>
-- To decide this case, observe: How to apply it in the field: treat this as the fp_rule it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable.  _(merged 2 duplicate row(s))_ _(unverified)_
-  - **Disproof:** This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (prototype_pollution.fp_rule.json_parse_creates_an_own_proto_key_not_a_polluted_prototype) states the full boundary.
-  - Sources: <https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Object/proto> · <https://semgrep.dev/docs/writing-rules/data-flow/taint-mode/> · <https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/JSON/parse>
-- To decide this case, observe: How to apply it in the field: treat this as the validation it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable.  _(merged 1 duplicate row(s))_
-  - **Disproof:** This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (prototype_pollution.validation.proof_is_inherited_property_visibility_on_an_object_you_never_touched) states the full boundary.
-  - Sources: <https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Object/proto> · <https://semgrep.dev/docs/writing-rules/data-flow/taint-mode/>
 - To decide this case, observe: Hypothesis under test: Prototype pollution requires an untrusted JSON body or query object to reach a sink that merges, extends, clones or deep-assigns it into a server-side object; where user input is only read as a scalar and never merged, no payload can...  _(merged 1 duplicate row(s))_
   - **Disproof:** This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (prototype_pollution.fp_rule.auto.derived) states the full boundary.
   - Sources: <https://blog.sonarsource.com/blitzjs-prototype-pollution/> · <https://blog.sonarsource.com/scripting-outside-the-box-api-client-security-risks-part-1/> · <https://blog.orange.tw/posts/2023-08-2023-webconf-the-evolution-of-web-security/>
```

## 2026-10-28 17:55 — 84 diff lines
- items: 19 (supported 19), FP rules 3, chains 1, state mature

```diff
--- prototype_pollution@current
+++ prototype_pollution@new
@@ -10,7 +10,7 @@
      python -m wks.skillgen -->
 
 > surface `web` · CWE 1321 · OWASP A08:2021
-> evidence: 33 items, 18 supported, 3 FP rules, 1 chains
+> evidence: 19 items, 19 supported, 3 FP rules, 1 chains
 > maturity: **mature**
 
 Caller input reaches a property write path that mutates a shared prototype.
@@ -35,54 +35,15 @@
 
 ## Techniques (what to change)
 
-- "abstract": "Sonar's security research team discovered a prototype pollution vulnerability in Blitz.js, a popular full-stack React framework, which could allow attackers to manipulate JavaScript object prototypes and alter application behavior.  _(merged 1 duplicate row(s))_ _(unverified)_
-  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: ""abstract": "Sonar's security research team discovered a prototype pollution vulnerability".
-  - Sources: <https://blog.sonarsource.com/blitzjs-prototype-pollution/> · <https://blog.sonarsource.com/etherpad-code-execution-vulnerabilities/>
-- A Blitz.js-based application is vulnerable if it implements at least one RPC call.  _(merged 1 duplicate row(s))_ _(unverified)_
-  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "A Blitz.js-based application is vulnerable if it implements at least one RPC call.".
-  - Sources: <https://blog.sonarsource.com/blitzjs-prototype-pollution/>
 - A vulnerable code pattern where this can happen is, for instance, obj[a][b] = c : if the attacker controls the values of a , b and c , they can set " __proto__ " for a , the property name for b , and the property value for c .  _(merged 1 duplicate row(s))_
   - **Disproof:** Refuted when: the same behaviour is absent when the single named control in the claim is present, and the control is shown to be present rather than assumed. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“A vulnerable code pattern where this can happen is, for instance, obj[a][b] = c ”) does not occur under a test that isolates that control.
   - Sources: <https://blog.sonarsource.com/blitzjs-prototype-pollution/> · <https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/JSON/parse>
-- Also, it is still possible to reach an object's prototype via obj.constructor.prototype , so these property names should still be blocked when validating user-controlled property names.  _(merged 1 duplicate row(s))_ _(unverified)_
-  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Also, it is still possible to reach an object's prototype via obj.constructor.prototype , ".
-  - Sources: <https://blog.sonarsource.com/blitzjs-prototype-pollution/> · <https://blog.sonarsource.com/scripting-outside-the-box-api-client-security-risks-part-1/>
-- Finally, we will give recommendations on how to avoid Prototype Pollution vulnerabilities in your JavaScript code.  _(merged 1 duplicate row(s))_ _(unverified)_
-  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Finally, we will give recommendations on how to avoid Prototype Pollution vulnerabilities ".
-  - Sources: <https://blog.sonarsource.com/blitzjs-prototype-pollution/> · <https://blog.sonarsource.com/etherpad-code-execution-vulnerabilities/>
-- Gadget 2: From require() to spawn() To turn this into arbitrary code execution, an attacker either needs the ability to create files on the server or another gadget to chain with the first one.  _(merged 1 duplicate row(s))_ _(unverified)_
-  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Gadget 2: From require() to spawn() To turn this into arbitrary code execution, an attacke".
-  - Sources: <https://blog.sonarsource.com/blitzjs-prototype-pollution/>
-- However, the command is fixed, and the arguments are not controllable, so how can attackers use this?  _(merged 1 duplicate row(s))_ _(unverified)_
-  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "However, the command is fixed, and the arguments are not controllable, so how can attacker".
-  - Sources: <https://blog.sonarsource.com/blitzjs-prototype-pollution/>
-- If the attacker changes the value of NODE_OPTIONS to --require /proc/self/cmdline and puts their payload in argv0 , this should work, right?  _(merged 1 duplicate row(s))_ _(unverified)_
-  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "If the attacker changes the value of NODE_OPTIONS to --require /proc/self/cmdline and puts".
-  - Sources: <https://blog.sonarsource.com/blitzjs-prototype-pollution/>
 - Prototype Pollution occurs when attackers can gain control over properties of a prototype.  _(merged 1 duplicate row(s))_
   - **Disproof:** Refuted when: the same behaviour is absent when the single named control in the claim is present, and the control is shown to be present rather than assumed. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“Prototype Pollution occurs when attackers can gain control over properties of a ”) does not occur under a test that isolates that control.
   - Sources: <https://blog.sonarsource.com/blitzjs-prototype-pollution/> · <https://blog.orange.tw/posts/2023-08-2023-webconf-the-evolution-of-web-security/>
-- Prototype pollution occurs when user-controlled input is merged into objects without sufficient sanitization, potentially enabling privilege escalation, denial of service, or remote code execution depending on the application context.  _(merged 1 duplicate row(s))_ _(unverified)_
-  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Prototype pollution occurs when user-controlled input is merged into objects without suffi".
-  - Sources: <https://blog.sonarsource.com/blitzjs-prototype-pollution/> · <https://blog.sonarsource.com/etherpad-code-execution-vulnerabilities/>
-- This can be bypassed with the shell option of the spawn() function.  _(merged 1 duplicate row(s))_ _(unverified)_
-  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "This can be bypassed with the shell option of the spawn() function.".
-  - Sources: <https://blog.sonarsource.com/blitzjs-prototype-pollution/>
-- This causes the CLI wrapper script to be executed, spawning a new process with the attacker-controlled argv0 , env , and shell options.  _(merged 1 duplicate row(s))_ _(unverified)_
-  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "This causes the CLI wrapper script to be executed, spawning a new process with the attacke".
-  - Sources: <https://blog.sonarsource.com/blitzjs-prototype-pollution/>
-- This finding highlights how JavaScript frameworks that handle user input through object merging or deep cloning operations are particularly susceptible to prototype pollution if input is not rigorously validated.  _(merged 1 duplicate row(s))_ _(unverified)_
-  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "This finding highlights how JavaScript frameworks that handle user input through object me".
-  - Sources: <https://blog.sonarsource.com/blitzjs-prototype-pollution/> · <https://blog.sonarsource.com/etherpad-code-execution-vulnerabilities/>
-- This makes the page routing functionality a Prototype Pollution gadget that allows executing any local JavaScript file by inserting a new mapping into the manifest.  _(merged 1 duplicate row(s))_ _(unverified)_
-  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "This makes the page routing functionality a Prototype Pollution gadget that allows executi".
-  - Sources: <https://blog.sonarsource.com/blitzjs-prototype-pollution/> · <https://blog.sonarsource.com/etherpad-code-execution-vulnerabilities/>
 - When an app strips the literal key __proto__ from request bodies, the same pollution succeeds via {"constructor":{"prototype":{"<key>":"<value>"}}} because the prototype is still reachable as obj.constructor.prototype.  _(merged 1 duplicate row(s))_
   - **Disproof:** If the constructor spelling is stripped, coerced to a string, or the merge sink copies own properties only into a null-prototype target, then neither payload reaches a prototype and no inherited key appears on a fresh object: the bypass claim is false for that sink.
   - Sources: <https://blog.sonarsource.com/blitzjs-prototype-pollution/> · <https://blog.sonarsource.com/scripting-outside-the-box-api-client-security-risks-part-1/> · <https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/JSON/parse>
-- console.log(obj.__proto__); // undefined If you want to harden your code base and make the exploitation of Prototype Pollution issues more difficult, there are some ways to do so, but they each come with their drawbacks.  _(merged 1 duplicate row(s))_ _(unverified)_
-  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "console.log(obj.__proto__); // undefined If you want to harden your code base and make the".
-  - Sources: <https://blog.sonarsource.com/blitzjs-prototype-pollution/> · <https://blog.sonarsource.com/scripting-outside-the-box-api-client-security-risks-part-1/>
 
 ## Tests
 
@@ -110,15 +71,12 @@
 - An application that explicitly defines `__proto__` as an own property on one object via Object.defineProperty has not polluted anything: the accessor is shadowed for that object only, and the prototype chain of every other object is unchanged.  _(merged 1 duplicate row(s))_
   - **Disproof:** The claim is false when the same call is made on `Object.prototype` itself rather than on an instance, or when the application assigns through the accessor on a shared prototype object; those two cases mutate the chain globally and are genuine pollution despite the identical call syntax.
   - Sources: <https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Object/create> · <https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Object/proto> · <https://semgrep.dev/docs/writing-rules/data-flow/taint-mode/>
-- Reject a prototype_pollution finding until it is distinguished from the adjacent behaviour this class also covers. "Prototype pollution requires an untrusted JSON body or query object to reach a sink that merges, extends, clones or deep-assigns it into a server-side object; where user input is only read as a scalar and never merged, no payload can..." and "A prototype pollution report is validated only when a probe sent in one request changes an object built by a different, later request; a change reproduced only within the payload's own request does not demonstrate prototype pollution." share a surface and a symptom, so a response that matches the first is not evidence for it while the second remains possible.  _(merged 1 duplicate row(s))_ _(unverified)_
-  - **Disproof:** This rule is wrong if a controlled test shows the two behaviours can never co-occur on the same surface, or if the corpus entry for "A prototype pollution report is validated only when a probe sent in on" is out of date. In that case this class needs its false-positive guidance rewritten rather than deleted.
-  - Sources: <https://blog.sonarsource.com/blitzjs-prototype-pollution/> · <https://blog.sonarsource.com/etherpad-code-execution-vulnerabilities/>
 
 ## Evidence requirements
 
-- A convincing observation for this class is: Adjacent behaviour that produces the same observable result: A prototype pollution report is validated only when a probe sent in one request changes an object built by a different, later request; a change reproduced only within the payload's own request does not demonstrate prototype pollution.  _(merged 1 duplicate row(s))_ _(unverified)_
+- A convincing observation for this class is: Adjacent behaviour that produces the same observable result: A prototype pollution report is validated only when a probe sent in one request changes an object built by a different, later request; a change reproduced only within the payload's own request does not demonstrate prototype pollution.  _(merged 1 duplicate row(s))_
   - **Disproof:** Not evidence when the observable cannot be produced at all -- blind, server-side-only, or identical-in-every-case behaviour leaves nothing to show. The originating rule (prototype_pollution.fp_rule.auto.derived) states the full boundary.
-  - Sources: <https://blog.sonarsource.com/blitzjs-prototype-pollution/> · <https://blog.sonarsource.com/scripting-outside-the-box-api-client-security-risks-part-1/>
+  - Sources: <https://blog.sonarsource.com/blitzjs-prototype-pollution/> · <https://blog.sonarsource.com/scripting-outside-the-box-api-client-security-risks-part-1/> · <https://portswigger.net/web-security/prototype-pollution/server-side>
 - A convincing observation for this class is: The whole list of arguments is reflected in the file /proc/self/cmdline so the first element will be at the beginning.  _(merged 1 duplicate row(s))_
   - **Disproof:** Not evidence when the observable cannot be produced at all -- blind, server-side-only, or identical-in-every-case behaviour leaves nothing to show. The originating rule (prototype_pollution.auto.t.228bc545) states the full boundary.
   - Sources: <https://blog.sonarsource.com/blitzjs-prototype-pollution/> · <https://sourcegraph.com/blog/code-review-checklist>
```

## 2026-10-28 21:43 — 75 diff lines
- items: 27 (supported 23), FP rules 3, chains 1, state mature

```diff
--- prototype_pollution@current
+++ prototype_pollution@new
@@ -10,7 +10,7 @@
      python -m wks.skillgen -->
 
 > surface `web` · CWE 1321 · OWASP A08:2021
-> evidence: 19 items, 19 supported, 3 FP rules, 1 chains
+> evidence: 27 items, 23 supported, 3 FP rules, 1 chains
 > maturity: **mature**
 
 Caller input reaches a property write path that mutates a shared prototype.
@@ -23,6 +23,9 @@
 - A deserializer that applies assignments addressed by a caller-supplied path string is prototype-pollutable even when the path is validated as a string, because the destination path may itself contain __proto__ or constructor.prototype segments.  _(merged 1 duplicate row(s))_
   - **Disproof:** Send the same payload with the destination path rewritten to a benign key such as user.name; if the destination path is validated against a pattern that excludes __proto__ and constructor, or the assignment is performed with a key that cannot address a prototype, then caller-controlled path addressing does not exist here and the claim is false.
   - Sources: <https://cwe.mitre.org/data/definitions/1321.html> · <https://blog.sonarsource.com/blitzjs-prototype-pollution/> · <https://blog.sonarsource.com/scripting-outside-the-box-api-client-security-risks-part-1/>
+- Prototype pollution is a JavaScript vulnerability that enables an attacker to add arbitrary properties to global object prototypes, which may then be inherited by user-defined objects.  _(merged 1 duplicate row(s))_
+  - **Disproof:** The claim is false if the application rejects or recursively sanitizes '__proto__', 'constructor', and 'prototype' keys before merging, if untrusted input is never merged into shared objects, or if targets use Object.create(null) with frozen prototypes so that no object inherits from Object.prototype.
+  - Sources: <https://cwe.mitre.org/data/definitions/1321.html> · <https://portswigger.net/web-security/prototype-pollution>
 - Prototype pollution requires an untrusted JSON body or query object to reach a sink that merges, extends, clones or deep-assigns it into a server-side object; where user input is only read as a scalar and never merged, no payload can pollute Object.prototype.  _(merged 1 duplicate row(s))_
   - **Disproof:** Post {"__proto__":{"polluted":"yes"}} and then, in a SEPARATE request to an unrelated endpoint, read the value back on a fresh object: if ({}).polluted is undefined and no observable behaviour anywhere changes, there is no reachable merge sink and the prerequisite claim is false for that endpoint.
   - Sources: <https://blog.sonarsource.com/blitzjs-prototype-pollution/> · <https://blog.sonarsource.com/etherpad-code-execution-vulnerabilities/> · <https://portswigger.net/web-security/prototype-pollution>
@@ -32,6 +35,9 @@
 - After a request carrying a __proto__ key, a later request that never repeats the payload shows an inherited property the application never set, which indicates real prototype pollution rather than a rejected input.  _(merged 1 duplicate row(s))_
   - **Disproof:** If the extra property is visible only in the response to the payload request itself, disappears on the next request, and never appears on an object the application builds independently, then the payload was accepted as ordinary data and nothing was written to Object.prototype: the signal is per-request echo, not pollution.
   - Sources: <https://blog.sonarsource.com/blitzjs-prototype-pollution/> · <https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Object/proto>
+- Observable signals that a source is pollutable: sending crafted input (query/fragment with __proto__[prop], JSON with an '__proto__' key, or a web message) and observing Object.prototype in the browser console gain a new property; on the server, the same input should not change Object.prototype, so a comparison of object graphs or a forced prototype-key resolution confirms the vector.  _(merged 1 duplicate row(s))_
+  - **Disproof:** The claim is false if the application never merges untrusted input into shared objects, if all merges are schema-validated, or if the target uses Object.create(null).
+  - Sources: <https://cwe.mitre.org/data/definitions/1321.html> · <https://portswigger.net/web-security/prototype-pollution/client-side>
 
 ## Techniques (what to change)
 
@@ -41,6 +47,9 @@
 - Prototype Pollution occurs when attackers can gain control over properties of a prototype.  _(merged 1 duplicate row(s))_
   - **Disproof:** Refuted when: the same behaviour is absent when the single named control in the claim is present, and the control is shown to be present rather than assumed. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“Prototype Pollution occurs when attackers can gain control over properties of a ”) does not occur under a test that isolates that control.
   - Sources: <https://blog.sonarsource.com/blitzjs-prototype-pollution/> · <https://blog.orange.tw/posts/2023-08-2023-webconf-the-evolution-of-web-security/>
+- Prototype pollution sources include the URL query string and fragment (hash) via keys such as __proto__[prop] or __proto__.prop, JSON input parsed by JSON.parse (whose keys are arbitrary strings), and web messages; any of these can write to a prototype when merged recursively.  _(merged 1 duplicate row(s))_ _(unverified)_
+  - **Disproof:** The claim is false if the merge never uses controller-supplied keys, if keys are strictly allowlisted, if the merge targets an Object.create(null) object, or if the merge validates that '__proto__' and 'constructor' resolve to the object itself rather than the prototype.
+  - Sources: <https://portswigger.net/web-security/prototype-pollution>
 - When an app strips the literal key __proto__ from request bodies, the same pollution succeeds via {"constructor":{"prototype":{"<key>":"<value>"}}} because the prototype is still reachable as obj.constructor.prototype.  _(merged 1 duplicate row(s))_
   - **Disproof:** If the constructor spelling is stripped, coerced to a string, or the merge sink copies own properties only into a null-prototype target, then neither payload reaches a prototype and no inherited key appears on a fresh object: the bypass claim is false for that sink.
   - Sources: <https://blog.sonarsource.com/blitzjs-prototype-pollution/> · <https://blog.sonarsource.com/scripting-outside-the-box-api-client-security-risks-part-1/> · <https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/JSON/parse>
@@ -86,18 +95,33 @@
 - A convincing observation for this class is: arguments is reflected in the file /proc/self/cmdline so the first element will be at the beginning.  _(merged 1 duplicate row(s))_
   - **Disproof:** Not evidence when the observable cannot be produced at all -- blind, server-side-only, or identical-in-every-case behaviour leaves nothing to show. The originating rule (prototype_pollution.auto.t.b79a541e) states the full boundary.
   - Sources: <https://blog.sonarsource.com/blitzjs-prototype-pollution/> · <https://sourcegraph.com/blog/code-review-checklist>
+- Prototype pollution can escalate to remote code execution in server-side Node.js applications: polluted properties are consumed by legitimate code gadgets, and research has demonstrated end-to-end RCE in high-profile applications (NPM CLI, Parse Server, Rocket.Chat) and universal gadgets in core Node.js APIs.  _(merged 1 duplicate row(s))_
+  - **Disproof:** The claim is false if the polluted property never reaches a sink/gadget and the application does not process it in an unsafe way, or if the target application has no exploitable gadget chain reaching a code-execution primitive.
+  - Sources: <https://portswigger.net/web-security/prototype-pollution> · <https://www.usenix.org/conference/usenixsecurity23/presentation/shcherbakov>
+- Prototype pollution causes denial of service and can break authentication or authorization checks: overriding pre-defined prototype attributes such as hasOwnProperty, toString, or valueOf can break code that depends on them, and overriding an attribute with an incompatible type can crash the application.  _(merged 1 duplicate row(s))_ _(unverified)_
+  - **Disproof:** The claim is false if the application never reads pre-defined prototype attributes in security-sensitive paths, if all objects are created with Object.create(null), or if prototypes are frozen.
+  - Sources: <https://cwe.mitre.org/data/definitions/1321.html>
 - The evidence that identifies a prototype-pollution vulnerability is the specific merge, deep-assign or setter use on the tainted value, not the input format, because the same JSON body is inert without that sink and a different body format is equally exploitable against it.  _(merged 1 duplicate row(s))_
   - **Disproof:** The claim is false when the vulnerable component itself performs the merge internally on raw bytes — a framework's own body-parsing middleware, an ORM deserialising into a typed model — because there the input format is the entire attack surface and no distinct sink code exists to point at.
   - Sources: <https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/JSON/parse> · <https://semgrep.dev/docs/writing-rules/data-flow/taint-mode/>
 
 ## Defence bypasses
 
+- A sanitizer that removes only the first occurrence of the literal '__proto__' substring is bypassable: a key such as '__pro__proto__to__' survives a single strip and resolves to '__proto__' when the merge follows the dotted name, polluting the prototype.  _(merged 1 duplicate row(s))_ _(unverified)_
+  - **Disproof:** The claim is false if the sanitizer loops until all '__proto__' substrings are removed, or if the merge library ignores keys that contain '__proto__' as a substring.
+  - Sources: <https://portswigger.net/web-security/prototype-pollution/client-side>
 - A validation control that only checks the top-level keys of a request body is bypassed by prototype pollution, because a recursive merge descends into nested objects and the dangerous key can sit several levels down where the allowlist never looked.  _(merged 1 duplicate row(s))_
   - **Disproof:** The rule is false when the check is applied recursively at every depth and the merge refuses to recurse into any key that is not a plain string-keyed object, or when the merge never treats `__proto__`/`constructor`/`prototype` as writable slots; then the nested payload cannot reach the prototype and the shallow-check bypass does not exist.
   - Sources: <https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Object/proto> · <https://semgrep.dev/docs/writing-rules/data-flow/taint-mode/>
+- If an application strips the literal '__proto__' key from input, the '__proto__' accessor can be avoided entirely by using 'constructor.prototype': for any object created by a constructor, myObject.constructor.prototype resolves to the same prototype as myObject.__proto__, so keys 'constructor' and 'prototype' provide an alternative route to pollute Object.prototype (or String.prototype/Array.prototype).  _(merged 1 duplicate row(s))_ _(unverified)_
+  - **Disproof:** The claim is false if the merge validates that the constructor key equals the object's own constructor, if the target has no constructor (Object.create(null)), or if prototypes are frozen after initialization.
+  - Sources: <https://portswigger.net/web-security/prototype-pollution/client-side>
 
 ## Chaining opportunities
 
+- Chain: server-side prototype pollution (source = route 1) is the precondition for remote code execution via library/Node.js universal gadgets; the pollution step alone is usually insufficient without a gadget that reads the attacker-controlled prototype property.  _(merged 1 duplicate row(s))_
+  - **Disproof:** The chain fails if the merge is sanitized, if the polluted property never reaches a sink, or if the application uses frozen prototypes / Object.create(null) objects.
+  - Sources: <https://portswigger.net/web-security/prototype-pollution> · <https://www.usenix.org/conference/usenixsecurity23/presentation/shcherbakov>
 - Prototype pollution alone is only a foothold: RCE requires a second gadget that consumes a polluted key, such as a child-process spawn whose env object inherits a NODE_OPTIONS value that adds --require.  _(merged 1 duplicate row(s))_
   - **Disproof:** If the polluted key is never read by any code path - verified by an unchanged child-process environment and no additional module load in the request logs - then no gadget consumes it and the pollution stops at a DoS-or-nothing level, so the chain to RCE is false.
   - Sources: <https://blog.sonarsource.com/blitzjs-prototype-pollution/> · <https://blog.orange.tw/posts/2023-08-2023-webconf-the-evolution-of-web-security/>
```

## 2026-10-31 06:41 — 61 diff lines
- items: 27 (supported 16), FP rules 1, chains 1, state researching
- still missing: fp_rules

```diff
--- prototype_pollution@current
+++ prototype_pollution@new
@@ -10,8 +10,8 @@
      python -m wks.skillgen -->
 
 > surface `web` · CWE 1321 · OWASP A08:2021
-> evidence: 27 items, 23 supported, 3 FP rules, 1 chains
-> maturity: **mature**
+> evidence: 27 items, 16 supported, 1 FP rules, 1 chains
+> maturity: **researching** — missing: fp_rules
 
 Caller input reaches a property write path that mutates a shared prototype.
 
@@ -62,7 +62,7 @@
 
 ## Validation bar (how to prove it)
 
-- A prototype pollution report is validated only when a probe sent in one request changes an object built by a different, later request; a change reproduced only within the payload's own request does not demonstrate prototype pollution.  _(merged 1 duplicate row(s))_
+- A prototype pollution report is validated only when a probe sent in one request changes an object built by a different, later request; a change reproduced only within the payload's own request does not demonstrate prototype pollution.  _(merged 1 duplicate row(s))_ _(unverified)_
   - **Disproof:** Re-run the read-only baseline three times with no payload in between and confirm the response is byte-identical every time; if the suspected inherited property disappears on the second read, or never appears without the payload in the same request, there is no cross-request state change and the pollution claim is not validated.
   - Sources: <https://blog.sonarsource.com/blitzjs-prototype-pollution/> · <https://blog.sonarsource.com/scripting-outside-the-box-api-client-security-risks-part-1/> · <https://sourcegraph.com/blog/static-code-analysis-tools>
 - Prototype pollution is proved by a property that is visible on an object the test never sent any payload to — a freshly constructed `({})` in the same process returning the injected key — because a successful assignment to the prototype is by definition visible through the whole prototype chain.  _(merged 1 duplicate row(s))_
@@ -71,10 +71,10 @@
 
 ## False-positive rules (when to reject it)
 
-- A JSON body containing __proto__ that round-trips through the attacker's own browser or a client-side merge, with no server-side state change, is NOT server-side prototype pollution and must not be filed as this class.  _(merged 1 duplicate row(s))_
+- A JSON body containing __proto__ that round-trips through the attacker's own browser or a client-side merge, with no server-side state change, is NOT server-side prototype pollution and must not be filed as this class.  _(merged 1 duplicate row(s))_ _(unverified)_
   - **Disproof:** Send the identical payload from a fresh HTTP client that never loaded the app's JavaScript, then request an unrelated endpoint; if the inherited key appears in that server response the pollution is server-side after all and this fp_rule does not apply to it.
   - Sources: <https://blog.sonarsource.com/etherpad-code-execution-vulnerabilities/> · <https://sourcegraph.com/blog/static-code-analysis-tools>
-- A payload delivered as a JSON request body and parsed with JSON.parse does not pollute the prototype on its own: the parsed object gets `__proto__` as an ordinary own property, so the absence of inherited state on a fresh object is proof the parser was not the vulnerable step.  _(merged 1 duplicate row(s))_
+- A payload delivered as a JSON request body and parsed with JSON.parse does not pollute the prototype on its own: the parsed object gets `__proto__` as an ordinary own property, so the absence of inherited state on a fresh object is proof the parser was not the vulnerable step.  _(merged 1 duplicate row(s))_ _(unverified)_
   - **Disproof:** The rule is wrong when the parsed object is afterwards merged or assigned into another object by a recursive merge or setter-based copy that walks own keys, because at that point the own `__proto__` key is written through the setter and does mutate the prototype; the parser is innocent but the copy is the sink.
   - Sources: <https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/JSON/parse> · <https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Object/proto> · <https://semgrep.dev/docs/writing-rules/data-flow/taint-mode/>
 - An application that explicitly defines `__proto__` as an own property on one object via Object.defineProperty has not polluted anything: the accessor is shadowed for that object only, and the prototype chain of every other object is unchanged.  _(merged 1 duplicate row(s))_
@@ -86,13 +86,13 @@
 - A convincing observation for this class is: Adjacent behaviour that produces the same observable result: A prototype pollution report is validated only when a probe sent in one request changes an object built by a different, later request; a change reproduced only within the payload's own request does not demonstrate prototype pollution.  _(merged 1 duplicate row(s))_
   - **Disproof:** Not evidence when the observable cannot be produced at all -- blind, server-side-only, or identical-in-every-case behaviour leaves nothing to show. The originating rule (prototype_pollution.fp_rule.auto.derived) states the full boundary.
   - Sources: <https://blog.sonarsource.com/blitzjs-prototype-pollution/> · <https://blog.sonarsource.com/scripting-outside-the-box-api-client-security-risks-part-1/> · <https://portswigger.net/web-security/prototype-pollution/server-side>
-- A convincing observation for this class is: The whole list of arguments is reflected in the file /proc/self/cmdline so the first element will be at the beginning.  _(merged 1 duplicate row(s))_
+- A convincing observation for this class is: The whole list of arguments is reflected in the file /proc/self/cmdline so the first element will be at the beginning.  _(merged 1 duplicate row(s))_ _(unverified)_
   - **Disproof:** Not evidence when the observable cannot be produced at all -- blind, server-side-only, or identical-in-every-case behaviour leaves nothing to show. The originating rule (prototype_pollution.auto.t.228bc545) states the full boundary.
   - Sources: <https://blog.sonarsource.com/blitzjs-prototype-pollution/> · <https://sourcegraph.com/blog/code-review-checklist>
-- A convincing observation for this class is: This looks like prototype pollution because the payload is textbook and the string __proto__ appears in the request, but the observable effect happens entirely client-side, in the attacker's own session.  _(merged 1 duplicate row(s))_
+- A convincing observation for this class is: This looks like prototype pollution because the payload is textbook and the string __proto__ appears in the request, but the observable effect happens entirely client-side, in the attacker's own session.  _(merged 1 duplicate row(s))_ _(unverified)_
   - **Disproof:** Not evidence when the observable cannot be produced at all -- blind, server-side-only, or identical-in-every-case behaviour leaves nothing to show. The originating rule (prototype_pollution.fp_rule.client_side_roundtrip_is_not_server_pollution) states the full boundary.
   - Sources: <https://blog.sonarsource.com/etherpad-code-execution-vulnerabilities/> · <https://sourcegraph.com/blog/static-code-analysis-tools>
-- A convincing observation for this class is: arguments is reflected in the file /proc/self/cmdline so the first element will be at the beginning.  _(merged 1 duplicate row(s))_
+- A convincing observation for this class is: arguments is reflected in the file /proc/self/cmdline so the first element will be at the beginning.  _(merged 1 duplicate row(s))_ _(unverified)_
   - **Disproof:** Not evidence when the observable cannot be produced at all -- blind, server-side-only, or identical-in-every-case behaviour leaves nothing to show. The originating rule (prototype_pollution.auto.t.b79a541e) states the full boundary.
   - Sources: <https://blog.sonarsource.com/blitzjs-prototype-pollution/> · <https://sourcegraph.com/blog/code-review-checklist>
 - Prototype pollution can escalate to remote code execution in server-side Node.js applications: polluted properties are consumed by legitimate code gadgets, and research has demonstrated end-to-end RCE in high-profile applications (NPM CLI, Parse Server, Rocket.Chat) and universal gadgets in core Node.js APIs.  _(merged 1 duplicate row(s))_
@@ -101,7 +101,7 @@
 - Prototype pollution causes denial of service and can break authentication or authorization checks: overriding pre-defined prototype attributes such as hasOwnProperty, toString, or valueOf can break code that depends on them, and overriding an attribute with an incompatible type can crash the application.  _(merged 1 duplicate row(s))_ _(unverified)_
   - **Disproof:** The claim is false if the application never reads pre-defined prototype attributes in security-sensitive paths, if all objects are created with Object.create(null), or if prototypes are frozen.
   - Sources: <https://cwe.mitre.org/data/definitions/1321.html>
-- The evidence that identifies a prototype-pollution vulnerability is the specific merge, deep-assign or setter use on the tainted value, not the input format, because the same JSON body is inert without that sink and a different body format is equally exploitable against it.  _(merged 1 duplicate row(s))_
+- The evidence that identifies a prototype-pollution vulnerability is the specific merge, deep-assign or setter use on the tainted value, not the input format, because the same JSON body is inert without that sink and a different body format is equally exploitable against it.  _(merged 1 duplicate row(s))_ _(unverified)_
   - **Disproof:** The claim is false when the vulnerable component itself performs the merge internally on raw bytes — a framework's own body-parsing middleware, an ORM deserialising into a typed model — because there the input format is the entire attack surface and no distinct sink code exists to point at.
   - Sources: <https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/JSON/parse> · <https://semgrep.dev/docs/writing-rules/data-flow/taint-mode/>
 
```

## 2026-10-31 08:23 — 20 diff lines
- items: 27 (supported 15), FP rules 1, chains 1, state researching
- still missing: fp_rules

```diff
--- prototype_pollution@current
+++ prototype_pollution@new
@@ -10,7 +10,7 @@
      python -m wks.skillgen -->
 
 > surface `web` · CWE 1321 · OWASP A08:2021
-> evidence: 27 items, 16 supported, 1 FP rules, 1 chains
+> evidence: 27 items, 15 supported, 1 FP rules, 1 chains
 > maturity: **researching** — missing: fp_rules
 
 Caller input reaches a property write path that mutates a shared prototype.
@@ -56,7 +56,7 @@
 
 ## Tests
 
-- To decide this case, observe: Hypothesis under test: Prototype pollution requires an untrusted JSON body or query object to reach a sink that merges, extends, clones or deep-assigns it into a server-side object; where user input is only read as a scalar and never merged, no payload can...  _(merged 1 duplicate row(s))_
+- To decide this case, observe: Hypothesis under test: Prototype pollution requires an untrusted JSON body or query object to reach a sink that merges, extends, clones or deep-assigns it into a server-side object; where user input is only read as a scalar and never merged, no payload can...  _(merged 1 duplicate row(s))_ _(unverified)_
   - **Disproof:** This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (prototype_pollution.fp_rule.auto.derived) states the full boundary.
   - Sources: <https://blog.sonarsource.com/blitzjs-prototype-pollution/> · <https://blog.sonarsource.com/scripting-outside-the-box-api-client-security-risks-part-1/> · <https://blog.orange.tw/posts/2023-08-2023-webconf-the-evolution-of-web-security/>
 
```
