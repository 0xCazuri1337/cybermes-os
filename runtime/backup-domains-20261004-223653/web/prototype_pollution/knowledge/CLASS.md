# Prototype Pollution

## Definition

Caller input reaches a property write path that mutates a shared prototype.

- **CWE:** 1321
- **OWASP:** A08:2021
- **Surface:** web
- **Aliases:** ["prototype pollution", "pp", "object prototype pollution"]

Canonical home for `prototype_pollution`. Rendered from `db/wks.db` by `tools/taxonomy/build_taxonomy.py` — edit the rows, not this file.

## Root Cause

Not yet researched.

## Preconditions

**A deserializer that applies assignments addressed by a caller-supplied path string is prototype-pollutable even when the path is validated as a string, because the destination path may itself contain __proto__ or constructor.prototype segments.**

Two distinct conditions must both hold: the attacker controls the assignment destination path AND controls the value assigned there. Sonar's superjson case in Blitz.js is the canonical shape: referentialEqualities carried a mapping such as "brands.0": ["products.0.brand"], and because the path of the assignment's destination can contain any property names, this introduces a Prototype Pollution vulnerability; the path __proto__.x sets x on Object.prototype to a value the attacker also controls. To test: send a deserialization payload whose referential-equality/metadata destination path is __proto__.<key> and whose source is a field you control, then probe a second request for <key> on a fresh object. If the sink rejects the path outright, or the path is fixed to numeric indices only, the prerequisite is absent.

*Disproof:* Send the same payload with the destination path rewritten to a benign key such as user.name; if the destination path is validated against a pattern that excludes __proto__ and constructor, or the assignment is performed with a key that cannot address a prototype, then caller-controlled path addressing does not exist here and the claim is false.

**Prototype pollution requires an untrusted JSON body or query object to reach a sink that merges, extends, clones or deep-assigns it into a server-side object; where user input is only read as a scalar and never merged, no payload can pollute Object.prototype.**

Hunt for the sink, not the payload. Look for endpoints whose handler passes a request-body object (req.body, ctx.request.body, the parsed JSON of an RPC call) into Object.assign, a spread into an options object, lodash.merge / _.extend / deepmerge, or a custom deserializer that walks a caller-supplied path string and performs assignments. Test: send a body whose keys are absent from the app's own schema and observe whether the response reflects an extra property or an altered default. Sonar's Blitz.js research frames the condition exactly this way: pollution arises when user-controlled input is merged into objects without sufficient sanitization, and frameworks that handle user input through object merging or deep cloning operations are the ones that are susceptible. A request rejected by schema validation, or whose body is only ever read field-by-field as a string, is a dead end for this class.

*Disproof:* Post {"__proto__":{"polluted":"yes"}} and then, in a SEPARATE request to an unrelated endpoint, read the value back on a fresh object: if ({}).polluted is undefined and no observable behaviour anywhere changes, there is no reachable merge sink and the prerequisite claim is false for that endpoint.

## Attack Surface

Surface: **web**.

The entry points and enabling conditions for this surface are enumerated under **Preconditions**; the observable signals are under **Detection**.

## Detection

**After a request carrying a __proto__ key, a later request that never repeats the payload shows an inherited property the application never set, which indicates real prototype pollution rather than a rejected input.**

The signal is state that outlives the payload. Because an object inherits everything from its prototype, a polluted key becomes visible on objects created later, in code that never saw the attacker's request; Sonar describes this as setting a new property on the Object prototype so that all argument objects have that new property, changing the program's behavior. Practical probe: (1) baseline GET /api/ping and note the exact JSON; (2) POST the pollution payload to any endpoint on the same origin; (3) repeat the baseline GET with no cookie change and diff. A changed default, an extra key in an unrelated response, or a behaviour switch in a handler you did not target is the signal. Use a property name no legitimate default could produce, and confirm it survives a fresh session and a different worker process, otherwise it is per-request state.

*Disproof:* If the extra property is visible only in the response to the payload request itself, disappears on the next request, and never appears on an object the application builds independently, then the payload was accepted as ordinary data and nothing was written to Object.prototype: the signal is per-request echo, not pollution.

**A convincing observation for this class is: This looks like prototype pollution because the payload is textbook and the string __proto__ appears in the request, but the observable effect happens entirely client-side, in the attacker's own session.**

Derived from prototype_pollution.fp_rule.client_side_roundtrip_is_not_server_pollution, which states the boundary for this class. The observation above is what a report must contain to be believed: an artifact the reviewer can re-check, not a claim the hunter asserts. A finding without it is an assertion.

*Disproof:* Not evidence when the observable cannot be produced at all -- blind, server-side-only, or identical-in-every-case behaviour leaves nothing to show. The originating rule (prototype_pollution.fp_rule.client_side_roundtrip_is_not_server_pollution) states the full boundary.

**A convincing observation for this class is: The whole list of arguments is reflected in the file /proc/self/cmdline so the first element will be at the beginning.**

Derived from prototype_pollution.auto.t.228bc545, which states the boundary for this class. The observation above is what a report must contain to be believed: an artifact the reviewer can re-check, not a claim the hunter asserts. A finding without it is an assertion.

*Disproof:* Not evidence when the observable cannot be produced at all -- blind, server-side-only, or identical-in-every-case behaviour leaves nothing to show. The originating rule (prototype_pollution.auto.t.228bc545) states the full boundary.

**A convincing observation for this class is: Adjacent behaviour that produces the same observable result: A prototype pollution report is validated only when a probe sent in one request changes an object built by a different, later request; a change reproduced only within the payload's own request does not demonstrate prototype pollution.**

Derived from prototype_pollution.fp_rule.auto.derived, which states the boundary for this class. The observation above is what a report must contain to be believed: an artifact the reviewer can re-check, not a claim the hunter asserts. A finding without it is an assertion.

*Disproof:* Not evidence when the observable cannot be produced at all -- blind, server-side-only, or identical-in-every-case behaviour leaves nothing to show. The originating rule (prototype_pollution.fp_rule.auto.derived) states the full boundary.

**The evidence that identifies a prototype-pollution vulnerability is the specific merge, deep-assign or setter use on the tainted value, not the input format, because the same JSON body is inert without that sink and a different body format is equally exploitable against it.**

Mechanism: The evidence that identifies a prototype-pollution vulnerability is the specific merge, deep-assign or setter use on the tainted value, not the input format, because the same JSON body is inert without that sink and a different body format is equally exploitable against it. How to apply it in the field: treat this as the evidence it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable. Boundary of the rule: The claim is false when the vulnerable component itself performs the merge internally on raw bytes — a framework's own body-parsing middleware, an ORM deserialising into a typed model — because there the input format is the entire attack surface and no distinct sink code exists to point at.

*Disproof:* The claim is false when the vulnerable component itself performs the merge internally on raw bytes — a framework's own body-parsing middleware, an ORM deserialising into a typed model — because there the input format is the entire attack surface and no distinct sink code exists to point at.

**A convincing observation for this class is: arguments is reflected in the file /proc/self/cmdline so the first element will be at the beginning.**

Derived from prototype_pollution.auto.t.b79a541e, which states the boundary for this class. The observation above is what a report must contain to be believed: an artifact the reviewer can re-check, not a claim the hunter asserts. A finding without it is an assertion.

*Disproof:* Not evidence when the observable cannot be produced at all -- blind, server-side-only, or identical-in-every-case behaviour leaves nothing to show. The originating rule (prototype_pollution.auto.t.b79a541e) states the full boundary.

## Exploitation

**If the attacker changes the value of NODE_OPTIONS to --require /proc/self/cmdline and puts their payload in argv0 , this should work, right?**

file. Improving gadget 3 To bypass this, attackers can use two more options of the spawn() function: argv0 and shell . The first one, argv0 , controls the first element in the list of arguments passed to the new process. Usually, this is equivalent to the binary that is executed. The whole list of arguments is reflected in the file /proc/self/cmdline so the first element will be at the beginning. If the attacker changes the value of NODE_OPTIONS to --require /proc/self/cmdline and puts their payload in argv0 , this should work, right? Almost, but there is one final hurdle. Because the first argument was changed, the process can not be spawned because it is not a valid command or file path. This can be bypassed with the shell option of the spawn() function. It can be set to the path of a binary that will then be used to spawn the command within a shell. On Linux, the shell is prepended to the command and its arguments like this

*Disproof:* This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "If the attacker changes the value of NODE_OPTIONS to --require /proc/self/cmdline and puts".

**Prototype Pollution occurs when attackers can gain control over properties of a prototype.**

it first looks for x in obj itself, then in obj.__proto__ , then in obj.__proto__.__proto__ , and so on. It uses the first one it finds and throws an error if it can't find x in any of obj 's prototypes. As this demonstrates, prototypes can be chained, just like classes can have multiple levels of ancestors. This MDN article explains JavaScript's inheritance in more detail if you are interested. Prototype Pollution occurs when attackers can gain control over properties of a prototype. A vulnerable code pattern where this can happen is, for instance, obj[a][b] = c : if the attacker controls the values of a , b and c , they can set " __proto__ " for a , the property name for b , and the property value for c . This will cause all objects to have a new property, which can significantly influence the target application. A common pattern in JavaScript code is to use plain objects to

*Disproof:* This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Prototype Pollution occurs when attackers can gain control over properties of a prototype.".

**console.log(obj.__proto__); // undefined If you want to harden your code base and make the exploitation of Prototype Pollution issues more difficult, there are some ways to do so, but they each come with their drawbacks.**

d. Another option is to use Object.create(null) instead of a plain object literal ( {} ) where possible. The returned object does not inherit from Object.prototype , so it is also not possible to reach that prototype, regardless of any untrusted property names being used for access: Copy to clipboard const obj = Object.create(null); 
 Object.prototype.x = 1; 
 console.log(obj.x === 1); // false 
 console.log(obj.__proto__); // undefined If you want to harden your code base and make the exploitation of Prototype Pollution issues more difficult, there are some ways to do so, but they each come with their drawbacks. The first measure is to make Object.prototype immutable by calling Object.freeze(Object.prototype) as early as possible. The disadvantages are that you would have to repeat that for every class and that some older libraries would break because they modify prototypes. The second measure only applies to Node.js, not JavaScript running in a browser. If you start the Node.js process with the --disabl

*Disproof:* This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "console.log(obj.__proto__); // undefined If you want to harden your code base and make the".

**Gadget 2: From require() to spawn() To turn this into arbitrary code execution, an attacker either needs the ability to create files on the server or another gadget to chain with the first one.**

The file is loaded using the require() function of Node.js, and the file path is not checked to be within a certain directory. The manifest is loaded from a JSON file, meaning that the resulting object inherits from Object.prototype . This makes the page routing functionality a Prototype Pollution gadget that allows executing any local JavaScript file by inserting a new mapping into the manifest. Gadget 2: From require() to spawn() To turn this into arbitrary code execution, an attacker either needs the ability to create files on the server or another gadget to chain with the first one. Since Blitz.js does not have any upload functionality by default, we need to look for existing files with interesting behavior. The file has to be present in every Blitz.js instance, so looking at Blitz.js itself and its dependencies makes the most sense. One interesting file is the Blitz.js CLI wrapper script. It will spawn the actual CLI script in a new process and exit. However, the command is

*Disproof:* This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Gadget 2: From require() to spawn() To turn this into arbitrary code execution, an attacke".

**This makes the page routing functionality a Prototype Pollution gadget that allows executing any local JavaScript file by inserting a new mapping into the manifest.**

owing is an example pages-manifest.json : Copy to clipboard { 
 "/api/rpc/signup": "pages/api/rpc/signup.js", 
 "/forgot-password": "pages/forgot-password.html" 
 } The file is loaded using the require() function of Node.js, and the file path is not checked to be within a certain directory. The manifest is loaded from a JSON file, meaning that the resulting object inherits from Object.prototype . This makes the page routing functionality a Prototype Pollution gadget that allows executing any local JavaScript file by inserting a new mapping into the manifest. Gadget 2: From require() to spawn() To turn this into arbitrary code execution, an attacker either needs the ability to create files on the server or another gadget to chain with the first one. Since Blitz.js does not have any upload functionality by default, we need to look for existing files with interesting behavior. The file has to be present in every Blitz.js instance, so looking at Blitz.js

*Disproof:* This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "This makes the page routing functionality a Prototype Pollution gadget that allows executi".

**This causes the CLI wrapper script to be executed, spawning a new process with the attacker-controlled argv0 , env , and shell options.**

The attacker sends a request that abuses the Prototype Pollution issue in the RPC layer to add properties to the Object prototype. This creates a new entry pointing to the Blitz.js CLI wrapper script in the pages manifest. It also sets argv0 , env , and shell for the spawn() call in step 3. The attacker triggers the chain by sending a request to the URL of the newly created pages manifest entry. This causes the CLI wrapper script to be executed, spawning a new process with the attacker-controlled argv0 , env , and shell options. This finally executes the attacker's payload in a new process. Patch To fix the root cause of this issue, Blitz.js blocked some property names from being used in a path, namely __proto__ , constructor , and prototype . Without these properties, it is not possible to reach and poison a prototype object. This can be generalized to a JavaScript security rule of thumb: when using untrusted inputs to

*Disproof:* This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "This causes the CLI wrapper script to be executed, spawning a new process with the attacke".

**A vulnerable code pattern where this can happen is, for instance, obj[a][b] = c : if the attacker controls the values of a , b and c , they can set " __proto__ " for a , the property name for b , and the property value for c .**

_ , and so on. It uses the first one it finds and throws an error if it can't find x in any of obj 's prototypes. As this demonstrates, prototypes can be chained, just like classes can have multiple levels of ancestors. This MDN article explains JavaScript's inheritance in more detail if you are interested. Prototype Pollution occurs when attackers can gain control over properties of a prototype. A vulnerable code pattern where this can happen is, for instance, obj[a][b] = c : if the attacker controls the values of a , b and c , they can set " __proto__ " for a , the property name for b , and the property value for c . This will cause all objects to have a new property, which can significantly influence the target application. A common pattern in JavaScript code is to use plain objects to pass optional arguments to a function. In the following example, the function doTask receives an object that can contain several optional arguments: Copy to clipboard function doTask(name, options) { 
 if (options.delay) { 
 /

*Disproof:* This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "A vulnerable code pattern where this can happen is, for instance, obj[a][b] = c : if the a".

**A Blitz.js-based application is vulnerable if it implements at least one RPC call.**

Pollution. Then we describe the technical details of the vulnerability we discovered, its impact, and how you can prevent it in your code. Impact We discovered a Prototype Pollution vulnerability (CVE-2022-23631) in the serialization library superjson used in the RPC layer of Blitz.js. It leads to Remote Code Execution on the server, and unauthenticated attackers can exploit it over the internet. A Blitz.js-based application is vulnerable if it implements at least one RPC call. The issue has been fixed in superjson 1.8.1 and Blitz.js 0.45.3, so we recommend updating your dependencies to these versions or higher. Technical Details In this section, we will first explain how prototypes work in JavaScript and what Prototype Pollution is. Then will show a real-world example of this in Blitz.js. Finally, we will give recommendations on how to avoid Prototype Pollution vulnera

*Disproof:* This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "A Blitz.js-based application is vulnerable if it implements at least one RPC call.".

**This can be bypassed with the shell option of the spawn() function.**

arguments is reflected in the file /proc/self/cmdline so the first element will be at the beginning. If the attacker changes the value of NODE_OPTIONS to --require /proc/self/cmdline and puts their payload in argv0 , this should work, right? Almost, but there is one final hurdle. Because the first argument was changed, the process can not be spawned because it is not a valid command or file path. This can be bypassed with the shell option of the spawn() function. It can be set to the path of a binary that will then be used to spawn the command within a shell. On Linux, the shell is prepended to the command and its arguments like this: /bin/myshell -c "command arg1 arg2 arg3" To set shell to the path of the node executable, the attacker can use /proc/self/exe without knowing the actual path. The final result is that a node process will be spawned as follow

*Disproof:* This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "This can be bypassed with the shell option of the spawn() function.".

**Prototype pollution occurs when user-controlled input is merged into objects without sufficient sanitization, potentially enabling privilege escalation, denial of service, or remote code execution depending on the application context.**

iscovered a Prototype Pollution vulnerability in Blitz.js leading to Remote Code Execution. Learn about this bug class and how to avoid it in your code!",
"abstract": "Sonar's security research team discovered a prototype pollution vulnerability in Blitz.js, a popular full-stack React framework, which could allow attackers to manipulate JavaScript object prototypes and alter application behavior. Prototype pollution occurs when user-controlled input is merged into objects without sufficient sanitization, potentially enabling privilege escalation, denial of service, or remote code execution depending on the application context. The vulnerability was responsibly disclosed to the Blitz.js maintainers, and developers using the framework should upgrade to the patched version promptly. This finding underscores that JavaScript frameworks handling user input through object merging or deep cloning operations are particularly susceptible to prototype pollution when input validation is not rigorously enforced.",
"mainEntityOfPage

*Disproof:* This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Prototype pollution occurs when user-controlled input is merged into objects without suffi".

**"abstract": "Sonar's security research team discovered a prototype pollution vulnerability in Blitz.js, a popular full-stack React framework, which could allow attackers to manipulate JavaScript object prototypes and alter application behavior.**

nkedin.com/company/sonarsource/","https://twitter.com/sonarsource"]} {
"@context": "https://schema.org",
"@graph": [
{
"@type": "WebPage",
"name": "Remote Code Execution via Prototype Pollution in Blitz.js | Sonar",
"description": "We recently discovered a Prototype Pollution vulnerability in Blitz.js leading to Remote Code Execution. Learn about this bug class and how to avoid it in your code!",
"abstract": "Sonar's security research team discovered a prototype pollution vulnerability in Blitz.js, a popular full-stack React framework, which could allow attackers to manipulate JavaScript object prototypes and alter application behavior. Prototype pollution occurs when user-controlled input is merged into objects without sufficient sanitization, potentially enabling privilege escalation, denial of service, or remote code execution depending on the application context. The vulnerability was responsibly disclosed to the Blitz.js maintainers, and developers using the framework should upgrade to the patched version promptly. This fin

*Disproof:* This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: ""abstract": "Sonar's security research team discovered a prototype pollution vulnerability".

**Also, it is still possible to reach an object's prototype via obj.constructor.prototype , so these property names should still be blocked when validating user-controlled property names.**

use they modify prototypes. The second measure only applies to Node.js, not JavaScript running in a browser. If you start the Node.js process with the --disable-proto=delete flag , then the __proto__ property will not exist anymore, and the only way to set an object's prototype is via functions such as Reflect.setPrototypeOf() . As with the previous measure, libraries could break because of this. Also, it is still possible to reach an object's prototype via obj.constructor.prototype , so these property names should still be blocked when validating user-controlled property names. Timeline Date Action 2022-02-07 We report the issue to the Blitz.js maintainers 2022-02-07 The maintainers confirm the issue 2022-02-10 A patch is released with superjson 1.8.1 and Blitz.js 0.45.3 Summary In this publication, we covered the technical details behind a Prototype Pollution vulnerability in Blitz.js; a full-stack React framework. Attackers can use the vulnerability to execute code on

*Disproof:* This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Also, it is still possible to reach an object's prototype via obj.constructor.prototype , ".

**Finally, we will give recommendations on how to avoid Prototype Pollution vulnerabilities in your JavaScript code.**

Blitz.js-based application is vulnerable if it implements at least one RPC call. The issue has been fixed in superjson 1.8.1 and Blitz.js 0.45.3, so we recommend updating your dependencies to these versions or higher. Technical Details In this section, we will first explain how prototypes work in JavaScript and what Prototype Pollution is. Then will show a real-world example of this in Blitz.js. Finally, we will give recommendations on how to avoid Prototype Pollution vulnerabilities in your JavaScript code. What is Prototype Pollution? In JavaScript, classes are implemented using so-called prototypes . Any object's prototype is accessible via the __proto__ property, e.g. the following is true: "abc".__proto__ === String.prototype . An object inherits all properties from its prototype, which is why "abc".substring(1) works: the string inherits the substring function from its prototype, String.prototy

*Disproof:* This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Finally, we will give recommendations on how to avoid Prototype Pollution vulnerabilities ".

**This finding highlights how JavaScript frameworks that handle user input through object merging or deep cloning operations are particularly susceptible to prototype pollution if input is not rigorously validated.**

plication behavior. Prototype pollution vulnerabilities arise when user-controlled input is merged into objects without sufficient sanitization, potentially enabling privilege escalation, denial of service, or remote code execution depending on the application. The vulnerability was responsibly disclosed to the Blitz.js maintainers; developers using Blitz.js should upgrade to the patched version. This finding highlights how JavaScript frameworks that handle user input through object merging or deep cloning operations are particularly susceptible to prototype pollution if input is not rigorously validated. Third-party dependencies are an easy way for developers to add functionality to their applications. This is great for productivity, but it also adds more attack surface and potential for bugs. While relying on battle-proven libraries is better than re-inventing the wheel, it is also important to check this hidden part of your code base for security vulnerabilities. As part of our commitment to he

*Disproof:* This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "This finding highlights how JavaScript frameworks that handle user input through object me".

**However, the command is fixed, and the arguments are not controllable, so how can attackers use this?**

ain with the first one. Since Blitz.js does not have any upload functionality by default, we need to look for existing files with interesting behavior. The file has to be present in every Blitz.js instance, so looking at Blitz.js itself and its dependencies makes the most sense. One interesting file is the Blitz.js CLI wrapper script. It will spawn the actual CLI script in a new process and exit. However, the command is fixed, and the arguments are not controllable, so how can attackers use this? Gadget 3: From spawn() to arbitrary code execution Spawning a new process is a known Prototype Pollution gadget that was made popular by Michał Bentkowski when he used it to exploit Kibana . Indeed, the spawn() function receives optional arguments via an object: This can be used to set the environment variables for the child process with the env property. This can be used to set NODE_OPTIONS to s

*Disproof:* This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "However, the command is fixed, and the arguments are not controllable, so how can attacker".

**When an app strips the literal key __proto__ from request bodies, the same pollution succeeds via {"constructor":{"prototype":{"<key>":"<value>"}}} because the prototype is still reachable as obj.constructor.prototype.**

Step 1: send {"__proto__":{"pp1":"x"}} and check for cross-request inheritance to establish a baseline. Step 2: send {"constructor":{"prototype":{"pp2":"x"}}} to the same endpoint. Step 3: on a fresh request, read pp2 and pp1 on a new object. Sonar's hardening notes state the bypass explicitly: disabling __proto__ with --disable-proto=delete does not close the hole, because it is still possible to reach an object's prototype via obj.constructor.prototype, so those property names should still be blocked when validating user-controlled property names. Testing both spellings is therefore the minimum; a filter that only greps for the seven characters of __proto__ is a bypassable filter, and the constructor spelling is the observation that separates "filtered" from "actually safe".

*Disproof:* If the constructor spelling is stripped, coerced to a string, or the merge sink copies own properties only into a null-prototype target, then neither payload reaches a prototype and no inherited key appears on a fresh object: the bypass claim is false for that sink.

## Variations

**A validation control that only checks the top-level keys of a request body is bypassed by prototype pollution, because a recursive merge descends into nested objects and the dangerous key can sit several levels down where the allowlist never looked.**

Mechanism: A validation control that only checks the top-level keys of a request body is bypassed by prototype pollution, because a recursive merge descends into nested objects and the dangerous key can sit several levels down where the allowlist never looked. How to apply it in the field: treat this as the bypass it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable. Boundary of the rule: The rule is false when the check is applied recursively at every depth and the merge refuses to recurse into any key that is not a plain string-keyed object, or when the merge never treats `__proto__`/`constructor`/`prototype` as writable slots; then the nested payload cannot reach the prototype and the shallow-check bypass does not exist.

*Disproof:* The rule is false when the check is applied recursively at every depth and the merge refuses to recurse into any key that is not a plain string-keyed object, or when the merge never treats `__proto__`/`constructor`/`prototype` as writable slots; then the nested payload cannot reach the prototype and the shallow-check bypass does not exist.

## Technology / Framework Considerations

Not yet researched.

## API Considerations

Not yet researched.

## Attack Chains

- `chain.prototype_pollution.auto.01` — prototype_pollution: observe, exercise, confirm (goal: `Establish, exercise and confirm a prototype_pollution condition on an authorised target without relying on anyone else's data.`)

## Real-World Examples

Not yet researched.

## Common False Positives

**Reject a prototype_pollution finding until it is distinguished from the adjacent behaviour this class also covers. "Prototype pollution requires an untrusted JSON body or query object to reach a sink that merges, extends, clones or deep-assigns it into a server-side object; where user input is only read as a scalar and never merged, no payload can..." and "A prototype pollution report is validated only when a probe sent in one request changes an object built by a different, later request; a change reproduced only within the payload's own request does not demonstrate prototype pollution." share a surface and a symptom, so a response that matches the first is not evidence for it while the second remains possible.**

Hypothesis under test: Prototype pollution requires an untrusted JSON body or query object to reach a sink that merges, extends, clones or deep-assigns it into a server-side object; where user input is only read as a scalar and never merged, no payload can...

Adjacent behaviour that produces the same observable result: A prototype pollution report is validated only when a probe sent in one request changes an object built by a different, later request; a change reproduced only within the payload's own request does not demonstrate prototype pollution.

Why this is worth checking before reporting: both are recorded in this class as gated knowledge, so a tester who stops at the first match will report one of them. The two differ in what the server actually did with the input, and that difference is observable in the response rather than in the request.

Required before treating this as a finding: capture the response that demonstrates the first behaviour specifically, and confirm the second is not what was observed.

*Disproof:* This rule is wrong if a controlled test shows the two behaviours can never co-occur on the same surface, or if the corpus entry for "A prototype pollution report is validated only when a probe sent in on" is out of date. In that case this class needs its false-positive guidance rewritten rather than deleted.

**A JSON body containing __proto__ that round-trips through the attacker's own browser or a client-side merge, with no server-side state change, is NOT server-side prototype pollution and must not be filed as this class.**

This looks like prototype pollution because the payload is textbook and the string __proto__ appears in the request, but the observable effect happens entirely client-side, in the attacker's own session. The separating observation is WHO holds the polluted prototype and WHEN: client-side, the injected key is visible only in that browser's DOM/JS context and vanishes on reload; server-side, the key appears in a later request handled by the server and survives a new session. Concretely: fire {"__proto__":{"polluted":"yes"}} at an endpoint, then read the value with a clean second request from a different client with no cookies. If the value appears only in the first browser's document, the finding is a client-side DOM/merge artefact (real, but a different class and much lower impact). The same separation applies to a static-analysis hit on a merge call with no attacker-controlled path: a tool that floods pull requests with low-confidence findings trains developers to ignore it, so the sink alone is never a finding without a reachable path.

*Disproof:* Send the identical payload from a fresh HTTP client that never loaded the app's JavaScript, then request an unrelated endpoint; if the inherited key appears in that server response the pollution is server-side after all and this fp_rule does not apply to it.

**An application that explicitly defines `__proto__` as an own property on one object via Object.defineProperty has not polluted anything: the accessor is shadowed for that object only, and the prototype chain of every other object is unchanged.**

Mechanism: An application that explicitly defines `__proto__` as an own property on one object via Object.defineProperty has not polluted anything: the accessor is shadowed for that object only, and the prototype chain of every other object is unchanged. How to apply it in the field: treat this as the fp_rule it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable. Boundary of the rule: The claim is false when the same call is made on `Object.prototype` itself rather than on an instance, or when the application assigns through the accessor on a shared prototype object; those two cases mutate the chain globally and are genuine pollution despite the identical call syntax.

*Disproof:* The claim is false when the same call is made on `Object.prototype` itself rather than on an instance, or when the application assigns through the accessor on a shared prototype object; those two cases mutate the chain globally and are genuine pollution despite the identical call syntax.

**A payload delivered as a JSON request body and parsed with JSON.parse does not pollute the prototype on its own: the parsed object gets `__proto__` as an ordinary own property, so the absence of inherited state on a fresh object is proof the parser was not the vulnerable step.**

Mechanism: A payload delivered as a JSON request body and parsed with JSON.parse does not pollute the prototype on its own: the parsed object gets `__proto__` as an ordinary own property, so the absence of inherited state on a fresh object is proof the parser was not the vulnerable step. How to apply it in the field: treat this as the fp_rule it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable. Boundary of the rule: The rule is wrong when the parsed object is afterwards merged or assigned into another object by a recursive merge or setter-based copy that walks own keys, because at that point the own `__proto__` key is written through the setter and does mutate the prototype; the parser is innocent but the copy is the sink.

*Disproof:* The rule is wrong when the parsed object is afterwards merged or assigned into another object by a recursive merge or setter-based copy that walks own keys, because at that point the own `__proto__` key is written through the setter and does mutate the prototype; the parser is innocent but the copy is the sink.

## Validation

**Prototype pollution is proved by a property that is visible on an object the test never sent any payload to — a freshly constructed `({})` in the same process returning the injected key — because a successful assignment to the prototype is by definition visible through the whole prototype chain.**

Mechanism: Prototype pollution is proved by a property that is visible on an object the test never sent any payload to — a freshly constructed `({})` in the same process returning the injected key — because a successful assignment to the prototype is by definition visible through the whole prototype chain. How to apply it in the field: treat this as the validation it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable. Boundary of the rule: The claim is false when the visible property is actually an own property of that object (a framework merged the request body into a shared singleton config, a middleware cached the parsed body on the object, or a test harness reused the same object reference), in which case the value is local, not inherited, and must be distinguished by checking the own-property descriptor rather than the value alone.

*Disproof:* The claim is false when the visible property is actually an own property of that object (a framework merged the request body into a shared singleton config, a middleware cached the parsed body on the object, or a test harness reused the same object reference), in which case the value is local, not inherited, and must be distinguished by checking the own-property descriptor rather than the value alone.

**A prototype pollution report is validated only when a probe sent in one request changes an object built by a different, later request; a change reproduced only within the payload's own request does not demonstrate prototype pollution.**

The validation is a differential test with a clean baseline. Record the response of an unrelated read endpoint before any payload; send the pollution payload; re-run the identical read with no payload and no session change; the finding holds only if the second read differs in a way attributable to an inherited property. This mirrors the property that makes a dynamic finding credible in the first place - a finding is reproduced against a real endpoint rather than inferred from a code path - and it is what separates a hand-verified report from the alerts a static tool emits, whose false-positive rate varies by language, rule set, framework support and tuning. Save both raw responses in the report. If you cannot reproduce the cross-request delta on a second run, the finding is a per-request artefact and belongs in the false-positive queue, not the corpus.

*Disproof:* Re-run the read-only baseline three times with no payload in between and confirm the response is byte-identical every time; if the suspected inherited property disappears on the second read, or never appears without the payload in the same request, there is no cross-request state change and the pollution claim is not validated.

**To decide this case, observe: How to apply it in the field: treat this as the fp_rule it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable.**

Derived from prototype_pollution.fp_rule.json_parse_creates_an_own_proto_key_not_a_polluted_prototype, which states the false-positive boundary for this class. The observable above is what separates a real finding from the pattern that only looks like one. A hunter who cannot produce this observation in a request/response pair does not have a finding yet.

*Disproof:* This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (prototype_pollution.fp_rule.json_parse_creates_an_own_proto_key_not_a_polluted_prototype) states the full boundary.

**To decide this case, observe: How to apply it in the field: treat this as the bypass it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable.**

Derived from prototype_pollution.bypass.a_recursive_merge_that_walks_own_keys_defeats_a_shallow_key_allowlist, which states the false-positive boundary for this class. The observable above is what separates a real finding from the pattern that only looks like one. A hunter who cannot produce this observation in a request/response pair does not have a finding yet.

*Disproof:* This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (prototype_pollution.bypass.a_recursive_merge_that_walks_own_keys_defeats_a_shallow_key_allowlist) states the full boundary.

**To decide this case, observe: How to apply it in the field: treat this as the fp_rule it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable.**

Derived from prototype_pollution.fp_rule.defining_an_own_proto_property_is_not_pollution, which states the false-positive boundary for this class. The observable above is what separates a real finding from the pattern that only looks like one. A hunter who cannot produce this observation in a request/response pair does not have a finding yet.

*Disproof:* This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (prototype_pollution.fp_rule.defining_an_own_proto_property_is_not_pollution) states the full boundary.

**To decide this case, observe: How to apply it in the field: treat this as the validation it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable.**

Derived from prototype_pollution.validation.proof_is_inherited_property_visibility_on_an_object_you_never_touched, which states the false-positive boundary for this class. The observable above is what separates a real finding from the pattern that only looks like one. A hunter who cannot produce this observation in a request/response pair does not have a finding yet.

*Disproof:* This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (prototype_pollution.validation.proof_is_inherited_property_visibility_on_an_object_you_never_touched) states the full boundary.

**To decide this case, observe: Hypothesis under test: Prototype pollution requires an untrusted JSON body or query object to reach a sink that merges, extends, clones or deep-assigns it into a server-side object; where user input is only read as a scalar and never merged, no payload can...**

Derived from prototype_pollution.fp_rule.auto.derived, which states the false-positive boundary for this class. The observable above is what separates a real finding from the pattern that only looks like one. A hunter who cannot produce this observation in a request/response pair does not have a finding yet.

*Disproof:* This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (prototype_pollution.fp_rule.auto.derived) states the full boundary.

## Impact

Not yet researched.

## Related Bug Classes

Not yet researched.

## References

- **blog.orange.tw** (writeup)
  - <https://blog.orange.tw/posts/2023-08-2023-webconf-the-evolution-of-web-security/>
- **blog.sonarsource.com** (research)
  - <https://blog.sonarsource.com/blitzjs-prototype-pollution/>
  - <https://blog.sonarsource.com/etherpad-code-execution-vulnerabilities/>
  - <https://blog.sonarsource.com/scripting-outside-the-box-api-client-security-risks-part-1/>
- **developer.mozilla.org** (writeup)
  - <https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/JSON/parse>
  - <https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Object/create>
  - <https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Object/proto>
- **semgrep.dev** (writeup)
  - <https://semgrep.dev/docs/writing-rules/data-flow/taint-mode/>
- **sourcegraph.com** (writeup)
  - <https://sourcegraph.com/blog/code-review-checklist>
  - <https://sourcegraph.com/blog/static-code-analysis-tools>

Every item above is gated on >= 2 distinct publisher hosts (`wks/quality.py`, rule R1). Publisher diversity, not citation count, is what makes these corroborated.
