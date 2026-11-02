# Prototype Pollution

## Definition

Caller input reaches a property write path that mutates a shared prototype.

- **CWE:** 1321
- **OWASP:** A08:2021
- **Surface:** web
- **Aliases:** ["prototype pollution", "pp", "object prototype pollution"]

Canonical home for `prototype_pollution`. Rendered from `db/wks.db` by `methodology/scripts/build_taxonomy.py` — edit the rows, not this file.

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

## Exploitation

**When an app strips the literal key __proto__ from request bodies, the same pollution succeeds via {"constructor":{"prototype":{"<key>":"<value>"}}} because the prototype is still reachable as obj.constructor.prototype.**

Step 1: send {"__proto__":{"pp1":"x"}} and check for cross-request inheritance to establish a baseline. Step 2: send {"constructor":{"prototype":{"pp2":"x"}}} to the same endpoint. Step 3: on a fresh request, read pp2 and pp1 on a new object. Sonar's hardening notes state the bypass explicitly: disabling __proto__ with --disable-proto=delete does not close the hole, because it is still possible to reach an object's prototype via obj.constructor.prototype, so those property names should still be blocked when validating user-controlled property names. Testing both spellings is therefore the minimum; a filter that only greps for the seven characters of __proto__ is a bypassable filter, and the constructor spelling is the observation that separates "filtered" from "actually safe".

*Disproof:* If the constructor spelling is stripped, coerced to a string, or the merge sink copies own properties only into a null-prototype target, then neither payload reaches a prototype and no inherited key appears on a fresh object: the bypass claim is false for that sink.

## Variations

Not yet researched.

## Technology / Framework Considerations

Not yet researched.

## API Considerations

Not yet researched.

## Attack Chains

Not yet researched.

## Real-World Examples

Not yet researched.

## Common False Positives

**A JSON body containing __proto__ that round-trips through the attacker's own browser or a client-side merge, with no server-side state change, is NOT server-side prototype pollution and must not be filed as this class.**

This looks like prototype pollution because the payload is textbook and the string __proto__ appears in the request, but the observable effect happens entirely client-side, in the attacker's own session. The separating observation is WHO holds the polluted prototype and WHEN: client-side, the injected key is visible only in that browser's DOM/JS context and vanishes on reload; server-side, the key appears in a later request handled by the server and survives a new session. Concretely: fire {"__proto__":{"polluted":"yes"}} at an endpoint, then read the value with a clean second request from a different client with no cookies. If the value appears only in the first browser's document, the finding is a client-side DOM/merge artefact (real, but a different class and much lower impact). The same separation applies to a static-analysis hit on a merge call with no attacker-controlled path: a tool that floods pull requests with low-confidence findings trains developers to ignore it, so the sink alone is never a finding without a reachable path.

*Disproof:* Send the identical payload from a fresh HTTP client that never loaded the app's JavaScript, then request an unrelated endpoint; if the inherited key appears in that server response the pollution is server-side after all and this fp_rule does not apply to it.

## Validation

**A prototype pollution report is validated only when a probe sent in one request changes an object built by a different, later request; a change reproduced only within the payload's own request does not demonstrate prototype pollution.**

The validation is a differential test with a clean baseline. Record the response of an unrelated read endpoint before any payload; send the pollution payload; re-run the identical read with no payload and no session change; the finding holds only if the second read differs in a way attributable to an inherited property. This mirrors the property that makes a dynamic finding credible in the first place - a finding is reproduced against a real endpoint rather than inferred from a code path - and it is what separates a hand-verified report from the alerts a static tool emits, whose false-positive rate varies by language, rule set, framework support and tuning. Save both raw responses in the report. If you cannot reproduce the cross-request delta on a second run, the finding is a per-request artefact and belongs in the false-positive queue, not the corpus.

*Disproof:* Re-run the read-only baseline three times with no payload in between and confirm the response is byte-identical every time; if the suspected inherited property disappears on the second read, or never appears without the payload in the same request, there is no cross-request state change and the pollution claim is not validated.

## Impact

Not yet researched.

## Related Bug Classes

Not yet researched.

## References

- **blog.orange.tw** (blog)
  - <https://blog.orange.tw/posts/2023-08-2023-webconf-the-evolution-of-web-security/>
- **blog.sonarsource.com** (research)
  - <https://blog.sonarsource.com/blitzjs-prototype-pollution/>
  - <https://blog.sonarsource.com/etherpad-code-execution-vulnerabilities/>
  - <https://blog.sonarsource.com/scripting-outside-the-box-api-client-security-risks-part-1/>
- **hackprosec.com** (vendor)
  - <https://www.hackprosec.com/penetration-testing.html>
- **sourcegraph.com** (blog)
  - <https://sourcegraph.com/blog/code-review-checklist>
  - <https://sourcegraph.com/blog/sast-vs-dast>
  - <https://sourcegraph.com/blog/static-code-analysis-tools>

Every item above is gated on >= 2 distinct publisher hosts (`wks/quality.py`, rule R1). Publisher diversity, not citation count, is what makes these corroborated.
