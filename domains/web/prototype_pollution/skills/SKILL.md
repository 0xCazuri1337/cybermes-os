---
name: prototype_pollution-hunting
description: Use when hunting Prototype Pollution in a web target. Ordered prerequisites, signals, techniques, validation bar and false-positive rules.
---

# Prototype Pollution — hunting skill

<!-- GENERATED from db/wks.db by wks/skillgen.py. DO NOT HAND-EDIT.
     Edit the rows (or ingest better research) and re-run:
     python -m wks.skillgen -->

> surface `web` · CWE 1321 · OWASP A08:2021
> evidence: 27 items, 15 supported, 1 FP rules, 1 chains
> maturity: **researching** — missing: fp_rules

Caller input reaches a property write path that mutates a shared prototype.

**Also called:** prototype pollution, pp, object prototype pollution


## Prerequisites (do not start without these)

- A deserializer that applies assignments addressed by a caller-supplied path string is prototype-pollutable even when the path is validated as a string, because the destination path may itself contain __proto__ or constructor.prototype segments.  _(merged 1 duplicate row(s))_
  - **Disproof:** Send the same payload with the destination path rewritten to a benign key such as user.name; if the destination path is validated against a pattern that excludes __proto__ and constructor, or the assignment is performed with a key that cannot address a prototype, then caller-controlled path addressing does not exist here and the claim is false.
  - Sources: <https://cwe.mitre.org/data/definitions/1321.html> · <https://blog.sonarsource.com/blitzjs-prototype-pollution/> · <https://blog.sonarsource.com/scripting-outside-the-box-api-client-security-risks-part-1/>
- Prototype pollution is a JavaScript vulnerability that enables an attacker to add arbitrary properties to global object prototypes, which may then be inherited by user-defined objects.  _(merged 1 duplicate row(s))_
  - **Disproof:** The claim is false if the application rejects or recursively sanitizes '__proto__', 'constructor', and 'prototype' keys before merging, if untrusted input is never merged into shared objects, or if targets use Object.create(null) with frozen prototypes so that no object inherits from Object.prototype.
  - Sources: <https://cwe.mitre.org/data/definitions/1321.html> · <https://portswigger.net/web-security/prototype-pollution>
- Prototype pollution requires an untrusted JSON body or query object to reach a sink that merges, extends, clones or deep-assigns it into a server-side object; where user input is only read as a scalar and never merged, no payload can pollute Object.prototype.  _(merged 1 duplicate row(s))_
  - **Disproof:** Post {"__proto__":{"polluted":"yes"}} and then, in a SEPARATE request to an unrelated endpoint, read the value back on a fresh object: if ({}).polluted is undefined and no observable behaviour anywhere changes, there is no reachable merge sink and the prerequisite claim is false for that endpoint.
  - Sources: <https://blog.sonarsource.com/blitzjs-prototype-pollution/> · <https://blog.sonarsource.com/etherpad-code-execution-vulnerabilities/> · <https://portswigger.net/web-security/prototype-pollution>

## Recon signals (where to look)

- After a request carrying a __proto__ key, a later request that never repeats the payload shows an inherited property the application never set, which indicates real prototype pollution rather than a rejected input.  _(merged 1 duplicate row(s))_
  - **Disproof:** If the extra property is visible only in the response to the payload request itself, disappears on the next request, and never appears on an object the application builds independently, then the payload was accepted as ordinary data and nothing was written to Object.prototype: the signal is per-request echo, not pollution.
  - Sources: <https://blog.sonarsource.com/blitzjs-prototype-pollution/> · <https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Object/proto>
- Observable signals that a source is pollutable: sending crafted input (query/fragment with __proto__[prop], JSON with an '__proto__' key, or a web message) and observing Object.prototype in the browser console gain a new property; on the server, the same input should not change Object.prototype, so a comparison of object graphs or a forced prototype-key resolution confirms the vector.  _(merged 1 duplicate row(s))_
  - **Disproof:** The claim is false if the application never merges untrusted input into shared objects, if all merges are schema-validated, or if the target uses Object.create(null).
  - Sources: <https://cwe.mitre.org/data/definitions/1321.html> · <https://portswigger.net/web-security/prototype-pollution/client-side>

## Techniques (what to change)

- A vulnerable code pattern where this can happen is, for instance, obj[a][b] = c : if the attacker controls the values of a , b and c , they can set " __proto__ " for a , the property name for b , and the property value for c .  _(merged 1 duplicate row(s))_
  - **Disproof:** Refuted when: the same behaviour is absent when the single named control in the claim is present, and the control is shown to be present rather than assumed. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“A vulnerable code pattern where this can happen is, for instance, obj[a][b] = c ”) does not occur under a test that isolates that control.
  - Sources: <https://blog.sonarsource.com/blitzjs-prototype-pollution/> · <https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/JSON/parse>
- Prototype Pollution occurs when attackers can gain control over properties of a prototype.  _(merged 1 duplicate row(s))_
  - **Disproof:** Refuted when: the same behaviour is absent when the single named control in the claim is present, and the control is shown to be present rather than assumed. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“Prototype Pollution occurs when attackers can gain control over properties of a ”) does not occur under a test that isolates that control.
  - Sources: <https://blog.sonarsource.com/blitzjs-prototype-pollution/> · <https://blog.orange.tw/posts/2023-08-2023-webconf-the-evolution-of-web-security/>
- Prototype pollution sources include the URL query string and fragment (hash) via keys such as __proto__[prop] or __proto__.prop, JSON input parsed by JSON.parse (whose keys are arbitrary strings), and web messages; any of these can write to a prototype when merged recursively.  _(merged 1 duplicate row(s))_ _(unverified)_
  - **Disproof:** The claim is false if the merge never uses controller-supplied keys, if keys are strictly allowlisted, if the merge targets an Object.create(null) object, or if the merge validates that '__proto__' and 'constructor' resolve to the object itself rather than the prototype.
  - Sources: <https://portswigger.net/web-security/prototype-pollution>
- When an app strips the literal key __proto__ from request bodies, the same pollution succeeds via {"constructor":{"prototype":{"<key>":"<value>"}}} because the prototype is still reachable as obj.constructor.prototype.  _(merged 1 duplicate row(s))_
  - **Disproof:** If the constructor spelling is stripped, coerced to a string, or the merge sink copies own properties only into a null-prototype target, then neither payload reaches a prototype and no inherited key appears on a fresh object: the bypass claim is false for that sink.
  - Sources: <https://blog.sonarsource.com/blitzjs-prototype-pollution/> · <https://blog.sonarsource.com/scripting-outside-the-box-api-client-security-risks-part-1/> · <https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/JSON/parse>

## Tests

- To decide this case, observe: Hypothesis under test: Prototype pollution requires an untrusted JSON body or query object to reach a sink that merges, extends, clones or deep-assigns it into a server-side object; where user input is only read as a scalar and never merged, no payload can...  _(merged 1 duplicate row(s))_ _(unverified)_
  - **Disproof:** This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (prototype_pollution.fp_rule.auto.derived) states the full boundary.
  - Sources: <https://blog.sonarsource.com/blitzjs-prototype-pollution/> · <https://blog.sonarsource.com/scripting-outside-the-box-api-client-security-risks-part-1/> · <https://blog.orange.tw/posts/2023-08-2023-webconf-the-evolution-of-web-security/>

## Validation bar (how to prove it)

- A prototype pollution report is validated only when a probe sent in one request changes an object built by a different, later request; a change reproduced only within the payload's own request does not demonstrate prototype pollution.  _(merged 1 duplicate row(s))_ _(unverified)_
  - **Disproof:** Re-run the read-only baseline three times with no payload in between and confirm the response is byte-identical every time; if the suspected inherited property disappears on the second read, or never appears without the payload in the same request, there is no cross-request state change and the pollution claim is not validated.
  - Sources: <https://blog.sonarsource.com/blitzjs-prototype-pollution/> · <https://blog.sonarsource.com/scripting-outside-the-box-api-client-security-risks-part-1/> · <https://sourcegraph.com/blog/static-code-analysis-tools>
- Prototype pollution is proved by a property that is visible on an object the test never sent any payload to — a freshly constructed `({})` in the same process returning the injected key — because a successful assignment to the prototype is by definition visible through the whole prototype chain.  _(merged 1 duplicate row(s))_
  - **Disproof:** The claim is false when the visible property is actually an own property of that object (a framework merged the request body into a shared singleton config, a middleware cached the parsed body on the object, or a test harness reused the same object reference), in which case the value is local, not inherited, and must be distinguished by checking the own-property descriptor rather than the value alone.
  - Sources: <https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Object/create> · <https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Object/proto> · <https://semgrep.dev/docs/writing-rules/data-flow/taint-mode/>

## False-positive rules (when to reject it)

- A JSON body containing __proto__ that round-trips through the attacker's own browser or a client-side merge, with no server-side state change, is NOT server-side prototype pollution and must not be filed as this class.  _(merged 1 duplicate row(s))_ _(unverified)_
  - **Disproof:** Send the identical payload from a fresh HTTP client that never loaded the app's JavaScript, then request an unrelated endpoint; if the inherited key appears in that server response the pollution is server-side after all and this fp_rule does not apply to it.
  - Sources: <https://blog.sonarsource.com/etherpad-code-execution-vulnerabilities/> · <https://sourcegraph.com/blog/static-code-analysis-tools>
- A payload delivered as a JSON request body and parsed with JSON.parse does not pollute the prototype on its own: the parsed object gets `__proto__` as an ordinary own property, so the absence of inherited state on a fresh object is proof the parser was not the vulnerable step.  _(merged 1 duplicate row(s))_ _(unverified)_
  - **Disproof:** The rule is wrong when the parsed object is afterwards merged or assigned into another object by a recursive merge or setter-based copy that walks own keys, because at that point the own `__proto__` key is written through the setter and does mutate the prototype; the parser is innocent but the copy is the sink.
  - Sources: <https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/JSON/parse> · <https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Object/proto> · <https://semgrep.dev/docs/writing-rules/data-flow/taint-mode/>
- An application that explicitly defines `__proto__` as an own property on one object via Object.defineProperty has not polluted anything: the accessor is shadowed for that object only, and the prototype chain of every other object is unchanged.  _(merged 1 duplicate row(s))_
  - **Disproof:** The claim is false when the same call is made on `Object.prototype` itself rather than on an instance, or when the application assigns through the accessor on a shared prototype object; those two cases mutate the chain globally and are genuine pollution despite the identical call syntax.
  - Sources: <https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Object/create> · <https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Object/proto> · <https://semgrep.dev/docs/writing-rules/data-flow/taint-mode/>

## Evidence requirements

- A convincing observation for this class is: Adjacent behaviour that produces the same observable result: A prototype pollution report is validated only when a probe sent in one request changes an object built by a different, later request; a change reproduced only within the payload's own request does not demonstrate prototype pollution.  _(merged 1 duplicate row(s))_
  - **Disproof:** Not evidence when the observable cannot be produced at all -- blind, server-side-only, or identical-in-every-case behaviour leaves nothing to show. The originating rule (prototype_pollution.fp_rule.auto.derived) states the full boundary.
  - Sources: <https://blog.sonarsource.com/blitzjs-prototype-pollution/> · <https://blog.sonarsource.com/scripting-outside-the-box-api-client-security-risks-part-1/> · <https://portswigger.net/web-security/prototype-pollution/server-side>
- A convincing observation for this class is: The whole list of arguments is reflected in the file /proc/self/cmdline so the first element will be at the beginning.  _(merged 1 duplicate row(s))_ _(unverified)_
  - **Disproof:** Not evidence when the observable cannot be produced at all -- blind, server-side-only, or identical-in-every-case behaviour leaves nothing to show. The originating rule (prototype_pollution.auto.t.228bc545) states the full boundary.
  - Sources: <https://blog.sonarsource.com/blitzjs-prototype-pollution/> · <https://sourcegraph.com/blog/code-review-checklist>
- A convincing observation for this class is: This looks like prototype pollution because the payload is textbook and the string __proto__ appears in the request, but the observable effect happens entirely client-side, in the attacker's own session.  _(merged 1 duplicate row(s))_ _(unverified)_
  - **Disproof:** Not evidence when the observable cannot be produced at all -- blind, server-side-only, or identical-in-every-case behaviour leaves nothing to show. The originating rule (prototype_pollution.fp_rule.client_side_roundtrip_is_not_server_pollution) states the full boundary.
  - Sources: <https://blog.sonarsource.com/etherpad-code-execution-vulnerabilities/> · <https://sourcegraph.com/blog/static-code-analysis-tools>
- A convincing observation for this class is: arguments is reflected in the file /proc/self/cmdline so the first element will be at the beginning.  _(merged 1 duplicate row(s))_ _(unverified)_
  - **Disproof:** Not evidence when the observable cannot be produced at all -- blind, server-side-only, or identical-in-every-case behaviour leaves nothing to show. The originating rule (prototype_pollution.auto.t.b79a541e) states the full boundary.
  - Sources: <https://blog.sonarsource.com/blitzjs-prototype-pollution/> · <https://sourcegraph.com/blog/code-review-checklist>
- Prototype pollution can escalate to remote code execution in server-side Node.js applications: polluted properties are consumed by legitimate code gadgets, and research has demonstrated end-to-end RCE in high-profile applications (NPM CLI, Parse Server, Rocket.Chat) and universal gadgets in core Node.js APIs.  _(merged 1 duplicate row(s))_
  - **Disproof:** The claim is false if the polluted property never reaches a sink/gadget and the application does not process it in an unsafe way, or if the target application has no exploitable gadget chain reaching a code-execution primitive.
  - Sources: <https://portswigger.net/web-security/prototype-pollution> · <https://www.usenix.org/conference/usenixsecurity23/presentation/shcherbakov>
- Prototype pollution causes denial of service and can break authentication or authorization checks: overriding pre-defined prototype attributes such as hasOwnProperty, toString, or valueOf can break code that depends on them, and overriding an attribute with an incompatible type can crash the application.  _(merged 1 duplicate row(s))_ _(unverified)_
  - **Disproof:** The claim is false if the application never reads pre-defined prototype attributes in security-sensitive paths, if all objects are created with Object.create(null), or if prototypes are frozen.
  - Sources: <https://cwe.mitre.org/data/definitions/1321.html>
- The evidence that identifies a prototype-pollution vulnerability is the specific merge, deep-assign or setter use on the tainted value, not the input format, because the same JSON body is inert without that sink and a different body format is equally exploitable against it.  _(merged 1 duplicate row(s))_ _(unverified)_
  - **Disproof:** The claim is false when the vulnerable component itself performs the merge internally on raw bytes — a framework's own body-parsing middleware, an ORM deserialising into a typed model — because there the input format is the entire attack surface and no distinct sink code exists to point at.
  - Sources: <https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/JSON/parse> · <https://semgrep.dev/docs/writing-rules/data-flow/taint-mode/>

## Defence bypasses

- A sanitizer that removes only the first occurrence of the literal '__proto__' substring is bypassable: a key such as '__pro__proto__to__' survives a single strip and resolves to '__proto__' when the merge follows the dotted name, polluting the prototype.  _(merged 1 duplicate row(s))_ _(unverified)_
  - **Disproof:** The claim is false if the sanitizer loops until all '__proto__' substrings are removed, or if the merge library ignores keys that contain '__proto__' as a substring.
  - Sources: <https://portswigger.net/web-security/prototype-pollution/client-side>
- A validation control that only checks the top-level keys of a request body is bypassed by prototype pollution, because a recursive merge descends into nested objects and the dangerous key can sit several levels down where the allowlist never looked.  _(merged 1 duplicate row(s))_
  - **Disproof:** The rule is false when the check is applied recursively at every depth and the merge refuses to recurse into any key that is not a plain string-keyed object, or when the merge never treats `__proto__`/`constructor`/`prototype` as writable slots; then the nested payload cannot reach the prototype and the shallow-check bypass does not exist.
  - Sources: <https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Object/proto> · <https://semgrep.dev/docs/writing-rules/data-flow/taint-mode/>
- If an application strips the literal '__proto__' key from input, the '__proto__' accessor can be avoided entirely by using 'constructor.prototype': for any object created by a constructor, myObject.constructor.prototype resolves to the same prototype as myObject.__proto__, so keys 'constructor' and 'prototype' provide an alternative route to pollute Object.prototype (or String.prototype/Array.prototype).  _(merged 1 duplicate row(s))_ _(unverified)_
  - **Disproof:** The claim is false if the merge validates that the constructor key equals the object's own constructor, if the target has no constructor (Object.create(null)), or if prototypes are frozen after initialization.
  - Sources: <https://portswigger.net/web-security/prototype-pollution/client-side>

## Chaining opportunities

- Chain: server-side prototype pollution (source = route 1) is the precondition for remote code execution via library/Node.js universal gadgets; the pollution step alone is usually insufficient without a gadget that reads the attacker-controlled prototype property.  _(merged 1 duplicate row(s))_
  - **Disproof:** The chain fails if the merge is sanitized, if the polluted property never reaches a sink, or if the application uses frozen prototypes / Object.create(null) objects.
  - Sources: <https://portswigger.net/web-security/prototype-pollution> · <https://www.usenix.org/conference/usenixsecurity23/presentation/shcherbakov>
- Prototype pollution alone is only a foothold: RCE requires a second gadget that consumes a polluted key, such as a child-process spawn whose env object inherits a NODE_OPTIONS value that adds --require.  _(merged 1 duplicate row(s))_
  - **Disproof:** If the polluted key is never read by any code path - verified by an unchanged child-process environment and no additional module load in the request logs - then no gadget consumes it and the pollution stops at a DoS-or-nothing level, so the chain to RCE is false.
  - Sources: <https://blog.sonarsource.com/blitzjs-prototype-pollution/> · <https://blog.orange.tw/posts/2023-08-2023-webconf-the-evolution-of-web-security/>


## Hunt procedure

1. Enumerate the surface before probing: collect every endpoint, parameter and object id the class could plausibly sit on.
2. Establish a CONTROLLED BASELINE first — one unauthenticated and one authenticated low-privilege request per candidate — and diff against the probe. A difference with no baseline proves nothing.
3. Change exactly ONE variable per probe. Two changes produce a difference you cannot attribute.
4. Record raw request and response pairs verbatim, including headers, before you interpret anything.

### What counts as proof

- Two responses that differ in a way the CONTROL did not, produced by a single changed variable.
- An invariant the application is supposed to hold, observed broken.
- A second independent confirmation, or an explicit statement that this is single-account evidence only.

> Ordered prerequisites, the validation bar and the false-positive rules below are the authority: this block is the mechanics, those are the standard.
---
Full class document: `domains/web/prototype_pollution/knowledge/DIGEST.md` · retrieve more with `python -m wks.cli search "<query>" --class-id prototype_pollution`

---
Runbook: [`HUNT.md`](HUNT.md) — every promoted technique mapped to an executable procedure with the observables to record.
