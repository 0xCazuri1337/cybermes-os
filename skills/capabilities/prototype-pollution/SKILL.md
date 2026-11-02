---
name: prototype-pollution
description: "Canonical Prototype Pollution capability: client-side (DOM XSS) and server-side (Node.js RCE/auth bypass) prototype pollution via unsafe merge/clone/extend. Consolidates exploiting-prototype-pollution-in-javascript. Use when hunting or validating prototype pollution."
sources: consolidated
report_count: 1
---

# Prototype Pollution — Canonical Capability

## 1. Identity and purpose

This is the single primary executable capability for JavaScript prototype pollution (CWE-1321, OWASP A03:2021/A08). It covers client-side pollution leading to DOM XSS and server-side pollution in Node.js leading to RCE, authentication/authorization bypass, and denial of service. It consolidates the legacy sub-skill `exploiting-prototype-pollution-in-javascript` while preserving all source content in `references/` and the original sub-skill directory for rollback.

## 2. Scope

In scope:
- Client-side prototype pollution via URL/query/hash/postMessage/JSON sources.
- Server-side prototype pollution via JSON body and deep-merge/clone/extend functions in Node.js.
- Gadgets: DOM sinks, template engines (EJS/Pug/Handlebars), child_process, auth properties, JSON schema.
- Detection and validation with browser and server-side techniques.

Out of scope (hand off):
- Pure XSS discovery without prototype pollution -> `xss` capability.
- Command injection without prototype pollution -> `command-injection` capability.
- Dependency/supply-chain risk assessment -> `supply_chain` capability.

## 3. Invocation and routing

Use this capability when:
- A merge/clone/extend function accepts user-controlled keys.
- URL parameters or JSON bodies contain `__proto__` or `constructor.prototype`.
- DOM XSS is suspected via prototype-inherited properties.
- Node.js application authorization or template rendering can be influenced by polluted properties.

Routing notes:
- Start with `references/client-side.md` for browser vectors and `references/server-side.md` for Node.js vectors.
- Use `references/gadgets.md` to map source-to-sink chains.
- Use `references/detection-and-tools.md` for automated and manual detection.
- Use `references/api-reference.md` for vulnerable functions and remediation.

## 4. Inputs and outputs

Inputs:
- Target URLs/endpoints, parameters, headers, request templates.
- Optional: Burp Suite project, browser automation, test accounts, source code.

Outputs:
- Confirmed or refuted prototype pollution findings with execution proof.
- Source-to-gadget-to-sink chain documentation.
- False-positive rulings with disproof rationale.

## 5. Preconditions and authorization

- Confirm written authorization and scope before testing.
- Use test accounts; avoid destructive RCE on shared/production systems without explicit approval.
- Respect rate limits and avoid denial-of-service payloads unless authorized.
- Do not access other users' data beyond proof of control.

## 6. Reconnaissance

Recon steps:
1. Identify JavaScript-heavy pages and Node.js API endpoints.
2. Harvest merge/clone/extend calls from source maps, JS bundles, and server code.
3. Detect endpoints accepting JSON objects or deep-merged input.
4. Probe for `__proto__`/`constructor` handling in APIs.
5. Fingerprint frameworks/template engines (EJS, Pug, Handlebars) and libraries (lodash, jQuery).

See `references/server-side.md` and `references/client-side.md`.

## 7. Detection methodology

Core detection flow:
1. Inject canary property via `__proto__` and `constructor.prototype`.
2. Check if property appears on unrelated objects (client) or changes server behavior (status code, spacing, errors).
3. Identify gadgets: properties read from prototype reaching sinks.
4. Prove execution/impact with browser or server-side evidence.
5. Validate with second independent request/account.

References by phase:
- Client-side: `references/client-side.md`.
- Server-side: `references/server-side.md`.
- Gadgets: `references/gadgets.md`.
- Detection/tools: `references/detection-and-tools.md`.

## 8. Technique selection

Select techniques by observed behavior:
- URL/reflection candidate -> client-side pollution tests and DOM Invader.
- JSON API accepting objects -> server-side status-code/spacing/error probes.
- Template engine present -> test template-engine gadgets.
- Auth checks read properties from objects -> pollute auth properties.
- Library known vulnerable -> version-check and targeted payloads.

## 9. Execution steps

1. Establish baseline request/response and object behavior.
2. Replay with one controlled change at a time (`__proto__`, `constructor.prototype`).
3. Record status, headers, body, timing, errors.
4. Identify gadget and construct minimal payload.
5. Prove with browser execution (client) or command output/privilege change (server).
6. Stop and document when not exploitable or out of scope.

## 10. Tool usage

- Burp Suite: DOM Invader, Server-Side Prototype Pollution check, Repeater.
- Scanners: ppfuzz, Nuclei prototype-pollution templates, pp-finder.
- Browser DevTools console for client-side canaries.
- curl/httpx for server-side probes.
- Source review: ESLint security plugins, manual code review.

See `references/detection-and-tools.md`.

## 11. Payloads and test cases

Representative test cases:
- Client: `?__proto__[polluted]=true`, `?constructor[prototype][polluted]=true`.
- Server: `{"__proto__": {"isAdmin": true}}`, `{"constructor": {"prototype": {"isAdmin": true}}}`.
- Status reflection: `{"__proto__": {"status": 510}}`.
- Spacing: `{"__proto__": {"json spaces": 10}}`.
- DoS: `{"__proto__": {"toString": null}}`.
- Template RCE: EJS/Pug/Handlebars payloads in `references/server-side.md`.
- Auth bypass: `{"__proto__": {"isAdmin": true, "role": "admin", "verified": true}}`.

## 12. Evidence

Each finding must include:
- Exact request/response or DOM proof.
- Canary/gadget property used.
- Source-to-sink chain.
- Impact assessment.
- For server-side: command output or authorization change proof.

## 13. Reproduction and validation

- Reproduce with minimal payload in a clean session.
- Validate with second account/origin where applicable.
- Confirm browser actually executes (client) or server behavior changes (server).
- Mark as refuted if no gadget/execution demonstrated.

## 14. False-positive rejection

Reject or downgrade when:
- Property reflects but does not affect behavior or sink.
- No gadget connects pollution to a dangerous sink.
- Server normalizes/rejects `__proto__`/`constructor` keys.
- Object.prototype is frozen or merge uses safe patterns.
- Behavior differences due to caching, localization, or benign defaults.

## 15. Impact

Impact guidance:
- Critical: RCE via template engine or child_process gadget.
- High: authentication/authorization bypass enabling account takeover.
- Medium: client-side DOM XSS requiring user interaction.
- Low: denial of service or non-sensitive property pollution.
- Informational: theoretical pollution without reachable gadget.

## 16. Reporting

Report template:
- Summary: target, pollution type (client/server), gadget, sink, impact.
- Scope/authorization and test window.
- Steps to reproduce: numbered, minimal payload.
- Proof: request/response, browser console, command output.
- Impact and affected data scope.
- Remediation: safe merge patterns, key filtering, Object.freeze, Map usage, library updates.

## 17. Failure modes

- Surface not discovered -> expand recon, check source maps and API versions.
- No test account -> request credentials or scope clarification.
- WAF blocks payloads -> try encoding, content-type confusion, constructor path.
- Rate limiting -> coordinate throttling or hand off.
- Inconclusive -> repeat with fresh sessions and diff responses; mark not confirmed if ambiguous.

## 18. References

All references preserved and must resolve:

| Reference | Load when |
|---|---|
| `references/client-side.md` | Client-side pollution and DOM XSS |
| `references/server-side.md` | Node.js server-side pollution |
| `references/gadgets.md` | Gadget mapping and validation |
| `references/detection-and-tools.md` | Detection and tooling |
| `references/api-reference.md` | Vulnerable functions and remediation |

Original sub-skill remains intact under `exploiting-prototype-pollution-in-javascript/`.

## 19. Testing and mastery

- Validate with the capability tests in `tests/test_prototype_pollution_capability.py`.
- Confirm all referenced files resolve and are non-empty.
- Confirm migration map paths/hashes/status are accurate.
- Practice on authorized labs: PortSwigger prototype pollution labs, vulnerable Node.js apps.
- Mastery criteria: independently discover, prove, and report a prototype pollution finding with full reproduction, impact, and remediation.
EOF


## Knowledge sources

- WKS bug classes: none mapped
- Domain knowledge: none mapped
- WKS remains the structured source of truth; retrieve and validate items through WKS rather than duplicating the full corpus in this skill.
- Research and learning material is mapped in `stage-a/knowledge-source-map.json` and must be validated before promotion.
