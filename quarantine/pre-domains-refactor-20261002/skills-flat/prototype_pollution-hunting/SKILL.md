---
name: prototype_pollution-hunting
description: Use when hunting Prototype Pollution in a web target. Ordered prerequisites, signals, techniques, validation bar and false-positive rules.
---

# Prototype Pollution — hunting skill

<!-- GENERATED from db/wks.db by wks/skillgen.py. DO NOT HAND-EDIT.
     Edit the rows (or ingest better research) and re-run:
     python -m wks.skillgen -->

> surface `web` · CWE 1321 · OWASP A08:2021
> evidence: 7 items, 7 supported, 1 FP rules, 0 chains
> maturity: **researching** — missing: items, fp_rules, chain

Caller input reaches a property write path that mutates a shared prototype.

**Also called:** prototype pollution, pp, object prototype pollution


## Prerequisites (do not start without these)

- A deserializer that applies assignments addressed by a caller-supplied path string is prototype-pollutable even when the path is validated as a string, because the destination path may itself contain __proto__ or constructor.prototype segments.
  - **Disproof:** Send the same payload with the destination path rewritten to a benign key such as user.name; if the destination path is validated against a pattern that excludes __proto__ and constructor, or the assignment is performed with a key that cannot address a prototype, then caller-controlled path addressing does not exist here and the claim is false.
  - Sources: <https://blog.sonarsource.com/blitzjs-prototype-pollution/> · <https://sourcegraph.com/blog/code-review-checklist>
- Prototype pollution requires an untrusted JSON body or query object to reach a sink that merges, extends, clones or deep-assigns it into a server-side object; where user input is only read as a scalar and never merged, no payload can pollute Object.prototype.
  - **Disproof:** Post {"__proto__":{"polluted":"yes"}} and then, in a SEPARATE request to an unrelated endpoint, read the value back on a fresh object: if ({}).polluted is undefined and no observable behaviour anywhere changes, there is no reachable merge sink and the prerequisite claim is false for that endpoint.
  - Sources: <https://blog.sonarsource.com/blitzjs-prototype-pollution/> · <https://sourcegraph.com/blog/code-review-checklist>

## Recon signals (where to look)

- After a request carrying a __proto__ key, a later request that never repeats the payload shows an inherited property the application never set, which indicates real prototype pollution rather than a rejected input.
  - **Disproof:** If the extra property is visible only in the response to the payload request itself, disappears on the next request, and never appears on an object the application builds independently, then the payload was accepted as ordinary data and nothing was written to Object.prototype: the signal is per-request echo, not pollution.
  - Sources: <https://blog.sonarsource.com/blitzjs-prototype-pollution/> · <https://www.hackprosec.com/penetration-testing.html>

## Techniques (what to change)

- When an app strips the literal key __proto__ from request bodies, the same pollution succeeds via {"constructor":{"prototype":{"<key>":"<value>"}}} because the prototype is still reachable as obj.constructor.prototype.
  - **Disproof:** If the constructor spelling is stripped, coerced to a string, or the merge sink copies own properties only into a null-prototype target, then neither payload reaches a prototype and no inherited key appears on a fresh object: the bypass claim is false for that sink.
  - Sources: <https://blog.sonarsource.com/blitzjs-prototype-pollution/> · <https://blog.sonarsource.com/scripting-outside-the-box-api-client-security-risks-part-1/> · <https://blog.orange.tw/posts/2023-08-2023-webconf-the-evolution-of-web-security/>

## Validation bar (how to prove it)

- A prototype pollution report is validated only when a probe sent in one request changes an object built by a different, later request; a change reproduced only within the payload's own request does not demonstrate prototype pollution.
  - **Disproof:** Re-run the read-only baseline three times with no payload in between and confirm the response is byte-identical every time; if the suspected inherited property disappears on the second read, or never appears without the payload in the same request, there is no cross-request state change and the pollution claim is not validated.
  - Sources: <https://blog.sonarsource.com/scripting-outside-the-box-api-client-security-risks-part-1/> · <https://sourcegraph.com/blog/sast-vs-dast> · <https://sourcegraph.com/blog/static-code-analysis-tools>

## False-positive rules (when to reject it)

- A JSON body containing __proto__ that round-trips through the attacker's own browser or a client-side merge, with no server-side state change, is NOT server-side prototype pollution and must not be filed as this class.
  - **Disproof:** Send the identical payload from a fresh HTTP client that never loaded the app's JavaScript, then request an unrelated endpoint; if the inherited key appears in that server response the pollution is server-side after all and this fp_rule does not apply to it.
  - Sources: <https://blog.sonarsource.com/etherpad-code-execution-vulnerabilities/> · <https://sourcegraph.com/blog/static-code-analysis-tools>

## Chaining opportunities

- Prototype pollution alone is only a foothold: RCE requires a second gadget that consumes a polluted key, such as a child-process spawn whose env object inherits a NODE_OPTIONS value that adds --require.
  - **Disproof:** If the polluted key is never read by any code path - verified by an unchanged child-process environment and no additional module load in the request logs - then no gadget consumes it and the pollution stops at a DoS-or-nothing level, so the chain to RCE is false.
  - Sources: <https://blog.sonarsource.com/blitzjs-prototype-pollution/> · <https://blog.orange.tw/posts/2023-08-2023-webconf-the-evolution-of-web-security/>

---
Full class document: `skills/Web/prototype_pollution/EVIDENCE.md` · retrieve more with `python -m wks.cli search "<query>" --class-id prototype_pollution`
