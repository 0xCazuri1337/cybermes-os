---
name: xss
description: "Canonical Cross-Site Scripting (XSS) capability: reflected, stored, DOM, blind, mutation (mXSS), framework-specific, filter bypass, and CSP interactions. Consolidates hunt-xss, hunt-dom, xss-hunter, and testing-for-xss-vulnerabilities*. Use when hunting or validating XSS on any target."
sources: github, hackerone_public, portswigger_research, owasp_wstg
report_count: 174
---

# XSS — Canonical Capability

## 1. Identity and purpose

This is the single primary executable capability for Cross-Site Scripting (CWE-79, OWASP A03:2021). It covers all XSS variants and contexts supported by the source material: reflected, stored, DOM-based, blind, mutation (mXSS), framework-specific, filter bypass, and CSP interactions. It also covers DOM clobbering, postMessage hijacking, service-worker abuse, and CSS exfiltration as DOM-side XSS vectors.

Primary objectives:
- Determine whether attacker-controllable input reaches a JavaScript execution context.
- Prove execution in a real browser, not mere reflection.
- Distinguish reflected, stored, DOM, blind, and mutation XSS.
- Handle sanitizer/filter/WAF bypasses and parser differentials.
- Assess CSP gating and bypass opportunities.
- Produce reproducible, impact-rated findings with remediation guidance.

## 2. Scope

In scope:
- Reflected, stored, DOM-based, blind, mutation (mXSS), framework-specific, filter/WAF bypass, and CSP-interaction XSS.
- DOM-side vectors: DOM clobbering, postMessage hijacking, service-worker abuse, CSS exfiltration.
- Validation with Burp Suite or browser automation.
- Evidence standards and false-positive rejection.

Out of scope (hand off):
- Markup that reflects raw HTML but does not execute JavaScript -> `hunt-html-injection` (escalate here once script execution is possible).
- Non-XSS injection classes (SQLi, SSTI, command injection, etc.) -> their own capabilities.
- Pure CORS/CSP policy analysis without XSS execution -> `cors` capability (chain here when execution is possible).

## 3. Invocation and routing

Use this capability when:
- A unique marker is reflected in an HTTP response and you need to determine whether it reaches a script execution context.
- A payload persists and renders in another user's response.
- Source-to-sink analysis shows attacker-controllable data reaching an execution-capable DOM sink.
- You are validating XSS with Burp Suite or a browser.
- You are hunting DOM clobbering, postMessage, service worker, or CSS exfiltration.

Routing notes:
- `hunt-html-injection` is the entry point for non-executable markup; escalate to this capability once script execution becomes possible.
- DOM-only vectors (clobbering, postMessage, service worker, CSS exfil) are handled in `references/dom-clobbering-postmessage-sw-css.md`, not as a separate primary skill.
- Use `references/burp-validation.md` when Burp Suite is available.

## 4. Inputs and outputs

Inputs:
- Target URL/endpoints, parameters, headers, and request templates.
- Optional: Burp Suite project, browser automation, test accounts.
- Optional: CSP policy, framework/version info, WAF behavior.

Outputs:
- Confirmed or refuted XSS findings with browser-execution proof.
- Evidence: request/response pairs, canary values, screenshots/DOM proof, impact assessment.
- False-positive rulings with disproof rationale.
- Remediation guidance.

## 5. Preconditions and authorization

- Confirm written authorization and scope before testing; include domains, accounts, and test windows.
- Use only test accounts and non-production data unless explicitly authorized.
- Respect rate limits and avoid destructive operations on shared resources.
- Do not access other users' data beyond proof of execution.
- Stop at account boundaries; do not escalate without authorization.
- Document out-of-scope endpoints and hand off rather than exploit.

## 6. Reconnaissance

Recon steps:
1. Collect endpoints, parameters, headers, and request templates from proxy logs, JS bundles, source maps, OpenAPI/Swagger, and mobile traffic.
2. Identify reflection points: search parameters, headers, path segments, JSON fields, and stored fields.
3. Identify framework/version and auto-escaping behavior; detect sanitizers and WAFs.
4. Harvest DOM sources/sinks from JavaScript bundles (`location.hash`, `postMessage`, `document.write`, `innerHTML`, etc.).
5. Collect CSP policies and report-only vs enforced mode.
6. Identify high-value contexts: admin panels, stored comments, profile fields, chat, search, and error pages.

See `references/reflected.md`, `references/stored.md`, `references/dom.md`, and `references/dom-clobbering-postmessage-sw-css.md`.

## 7. Detection methodology

Core detection flow:
1. Inject a unique numeric canary (e.g., `91234`) and observe reflection.
2. Determine injection context: HTML body, attribute, JavaScript string, URL, template literal.
3. Try contexts in order: inline script, attribute event, URL/href.
4. Distinguish success from failure: vulnerable means raw, unescaped execution-capable markup; filtered/safe means escaped; blocked means absent or error.
5. For stored XSS, submit via entry point and render in a second user's/role's response.
6. For DOM XSS, trace attacker-controllable source to execution-capable sink.
7. For blind XSS, use dangling markup/unclosed attributes and confirm via out-of-band callback.
8. For mutation (mXSS), account for sanitizer and parser differentials.
9. Check CSP before claiming inline execution.
10. Validate each candidate with a second independent request/account and mark refuted if not proven.

References by phase:
- Reflected: `references/reflected.md`.
- Stored: `references/stored.md`.
- DOM: `references/dom.md`.
- Blind: `references/blind.md`.
- Mutation: `references/mutation-mxss.md`.
- Framework: `references/framework-specific.md`.
- Filter bypass: `references/filter-bypass.md`.
- CSP: `references/csp-interactions.md`.

## 8. Technique selection

Select techniques by observed behavior:
- Unknown reflection -> canary proof + context ladder.
- Stored field -> two-step stored validation.
- DOM sink present -> source-to-sink trace + execution proof.
- Sanitizer present -> mXSS/parser differential techniques.
- Framework target -> framework-specific sinks and auto-escaping bypasses.
- Filter/WAF present -> filter bypass ladder.
- CSP present -> CSP interaction and bypass analysis.
- DOM-side vectors -> clobbering/postMessage/service worker/CSS exfil references.
- High-value targets -> `references/high-payout-patterns.md`.

## 9. Execution steps

1. Establish a baseline request per reflection point and record the response.
2. Replay with one controlled change at a time (canary variants); record status, headers, body, timing.
3. Determine context and select payload based on context and filters.
4. Prove with browser execution, not reflection alone.
5. For stored XSS, confirm second-user render and execution.
6. For DOM XSS, trace source-to-sink and demonstrate execution.
7. For blind XSS, confirm out-of-band callback.
8. For CSP, verify policy on the landing page (nonce/hash/strict-dynamic) and test bypasses.
9. Use Burp Suite when available (`references/burp-validation.md`).
10. Confirm exploitability with a clean reproduction (payload + screenshot/console/DOM proof).
11. Stop and document when a vector is not exploitable or out of scope.

## 10. Tool usage

- Proxy: Burp Suite (Repeater, Intruder, Comparer, Logger++, DOM Invader).
- Browser: Chrome/Firefox DevTools, headless automation, sandboxed PoCs.
- Scanners (triage only): Dalfox, XSStrike, nuclei XSS templates, OWASP ZAP.
- Discovery: ffuf, httpx, KiteRunner, dirsearch, subfinder.
- Utilities: curl, Python requests/httpx, jq, grep, sed.
- Evidence: screenshots, saved requests/responses, canary values, DOM snapshots, OOB interactions.

See `references/burp-validation.md` and `references/evidence-and-fp-rules.md`.

## 11. Payloads and test cases

Representative test cases (adapt to target):
- Unique canary: `alert(91234)` (never `alert(1)` alone on practice pages).
- Inline script: `<script>alert(91234)</script>`.
- Attribute event: `" onmouseover="alert(91234)`, `" onerror="alert(91234)`, `" onload="alert(91234)`.
- URL/href context: `javascript:alert(91234)`.
- Stored: submit payload via entry point, render in second user's response.
- DOM: source-to-sink trace with execution proof.
- Blind: dangling markup/unclosed attributes with OOB callback.
- Mutation: sanitizer/parser differential payloads.
- Framework: framework-specific sinks and auto-escaping bypasses.
- Filter/WAF: encoding, case variation, tag/attribute alternatives.
- CSP: nonce/hash/strict-dynamic analysis and bypass techniques.
- DOM-side: clobbering, postMessage, service worker, CSS exfiltration.

Framework and variant details live in the corresponding references.

## 12. Evidence

Each finding must include:
- Exact request and response (raw HTTP or browser network capture) or DOM proof.
- Canary value used.
- Authentication context and account/role used.
- Browser proof: screenshot/console/DOM showing execution.
- For stored: second-user render proof.
- For DOM: source-to-sink trace.
- For CSP: policy, directive analysis, bypass technique, and payload.
- Impact assessment and affected scope.

## 13. Reproduction and validation

- Reproduce with a real browser while logged into the target (if auth required).
- Validate with a second request/account where applicable.
- Confirm the browser actually executes; reflection alone is not proof.
- For stored, confirm second-user render and execution.
- For DOM, confirm source reaches sink and executes.
- For CSP, confirm execution/exfiltration with policy enforced (not report-only).
- Mark as refuted if the payload does not execute or logs blocked.

## 14. False-positive rejection

Reject or downgrade when:
- Payload reflects but does not execute -> classify as HTML injection or false positive.
- Reflection is in a 302 body (browser never renders it).
- Sanitizer blocks all execution -> document as safe; no finding.
- CSP prevents execution and no bypass exists -> document CSP effectiveness.
- Canary is not unique or decoy `alert(1)` examples are present.
- Response differences are due to caching, localization, or benign metadata.
- Framework auto-escaping or default protections prevent execution.
- Target is out of scope or not reachable in production.

## 15. Impact

Impact guidance:
- Critical: stored XSS in privileged/admin context leading to account takeover or sensitive data exfiltration; chained XSS with high business impact.
- High: reflected/stored XSS on authenticated users enabling session theft or CSRF bypass.
- Medium: DOM XSS requiring user interaction or limited scope; self-XSS with limited impact.
- Low: self-XSS or XSS in low-sensitivity context.
- Informational: reflected markup without execution (hand off to HTML injection).

Always tie impact to business risk and data scope; avoid severity inflation from reflection alone.

## 16. Reporting

Report template:
- Summary: endpoint, vulnerability type, context, impact.
- Scope/authorization: test window, accounts used.
- Steps to reproduce: numbered, minimal; include payload and canary.
- Proof of concept: request/response or hosted PoC + screenshot/console/DOM proof.
- Impact: business and data scope.
- Remediation: context-aware output encoding, safe sinks (textContent), sanitizer hardening, CSP (strict nonces/hashes, no unsafe-inline/eval, strict-dynamic, object-src 'none', base-uri 'self'), framework auto-escaping, input validation.

## 17. Failure modes

- Surface not fully discovered -> expand recon, check mobile/SPA, versions, content types.
- No test account -> request credentials or scope clarification; do not bypass without authorization.
- WAF/gateway blocks payloads -> try encoding, case variation, parser differentials, or content-type confusion.
- Rate limiting stops testing -> coordinate throttling, use allowed test windows, or hand off.
- Reflection without execution -> classify as HTML injection or false positive.
- CSP inconclusive -> verify policy is enforced and test in a clean browser profile.
- Sanitizer blocks all execution -> document as safe; no finding.
- Inconclusive authorization/origin result -> repeat with fresh sessions and diff responses; mark as not confirmed if ambiguous.

## 18. References

All 12 references are preserved and must resolve:

| Reference | Sub-capability | Load when |
|---|---|---|
| `references/reflected.md` | `hunt-xss` | Testing reflected XSS |
| `references/stored.md` | `hunt-xss` | Testing stored XSS |
| `references/dom.md` | `hunt-xss` / `hunt-dom` | DOM XSS suspected |
| `references/blind.md` | `hunt-xss` | Blind XSS / OOB suspected |
| `references/mutation-mxss.md` | `hunt-xss` | Sanitizer bypass / parser differential |
| `references/framework-specific.md` | `hunt-xss` | Framework target identified |
| `references/filter-bypass.md` | `hunt-xss` | Filters/WAF present |
| `references/csp-interactions.md` | `hunt-xss` | CSP present |
| `references/high-payout-patterns.md` | `xss-hunter` | Advanced targets |
| `references/burp-validation.md` | `testing-for-xss-vulnerabilities*` | Burp available |
| `references/dom-clobbering-postmessage-sw-css.md` | `hunt-dom` | DOM-side vectors |
| `references/evidence-and-fp-rules.md` | all | Evidence/FP review |

Original sub-skills remain intact under `hunt-dom/`, `hunt-xss/`, `xss-hunter/`, `testing-for-xss-vulnerabilities/`, and `testing-for-xss-vulnerabilities-with-burpsuite/`.

Recovered legacy material (provenance preserved in references):
- Fragment trap, fragment-decoding checks, and measured CDP/headless validation -> `references/dom.md`.
- OOB-Or-It-Didn't-Happen gate for blind/stored XSS -> `references/blind.md`.
- Gate 0 validation and advanced triage/reporting -> `references/evidence-and-fp-rules.md`.
- Attack chains and SVG `data:` -> `blob:` origin inheritance -> `references/high-payout-patterns.md`.

## 19. Testing and mastery

- Validate with the capability tests in `tests/test_xss_capability.py`.
- Confirm all referenced files resolve and are non-empty.
- Confirm migration map paths/hashes/status are accurate.
- Practice on authorized labs: PortSwigger XSS labs, OWASP crAPI, and framework-specific challenges.
- Mastery criteria: independently discover, browser-prove, and report an XSS finding with full reproduction, impact, and remediation.


## Knowledge sources

- WKS bug classes: xss
- Domain knowledge: xss
- WKS remains the structured source of truth; retrieve and validate items through WKS rather than duplicating the full corpus in this skill.
- Research and learning material is mapped in `stage-a/knowledge-source-map.json` and must be validated before promotion.
