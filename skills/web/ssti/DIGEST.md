<!-- GENERATED from db/wks.db — do not edit -->
# Server-Side Template Injection

> surface: `web` · CWE: CWE-1336 · OWASP: A03:2021
> maturity: **mature** — 22 items, 16 supported, 4 FP rules, 1 chains

Untrusted input is compiled by the template engine rather than treated as data, so the engine's expression language executes.

**Aliases:** ssti, server side template injection, template injection, jinja2 ssti, twig template injection

## Prerequisite

- **Thymeleaf SpEL injection needs request data to reach the expression engine or a dynamically built view name, not merely the data model.**  
  `high_confidence` · score 0.954 · disproved by: Sending arithmetic or expression metacharacters through the parameter and getting the input back as inert data (no evaluation, no error, no type coercion) shows the value never reaches the expression engine.
  sources: <https://snyk.io/blog/thymeleaf-injection/> · <https://www.nccgroup.com/research/technical-advisory-pulse-connect-secure-rce-via-template-injection-cve-2020-8243/>

## Signal

- **An ordinary profile field such as a name parameter is the signal worth chasing, not an exotic input: any value that the server-side template engine renders back is a candidate injection point because the engine will interpret whatever the user put there.**  
  `high_confidence` · score 0.8355 · disproved by: A name parameter whose template metacharacters are stripped or escaped before rendering and come back as literal text, refutes it as an injection point.
  sources: <https://jinja.palletsprojects.com/en/stable/sandbox/> · <https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/pentesting-web/ssti-server-side-template-injection/README.md>

## Technique

- **A template sandbox that pre-checks a dangerous keyword followed by a single space is bypassed by sending a tab in place of that space.**  
  `high_confidence` · score 0.844 · disproved by: If the tab variant is rejected by the same pre-check as the space variant, or is rejected by the downstream type blocklist, the filter is not the weak separator described here.
  sources: <https://snyk.io/blog/thymeleaf-injection/> · <https://www.nccgroup.com/research/technical-advisory-pulse-connect-secure-rce-via-template-injection-cve-2020-8243/>
- **Server-side template injection is proven by sending an arithmetic expression such as {{7*7}}; evaluating to 49 shows the template engine evaluated attacker input.**  
  `high_confidence` · score 0.843 · disproved by: Refuted when the expression is returned verbatim as literal text rather than evaluated, which shows the input is not reaching a template engine.
  sources: <https://portswigger.net/web-security/server-side-template-injection> · <https://raw.githubusercontent.com/Ch4os1/WriteUps-HTB/main/Medium/Unix/Gobox/writeup.md> · <https://raw.githubusercontent.com/Esther7171/HackTheBox-Writeups-Walkthroughs/main/Write-ups/Academy/05.%20Web%20Exploitation/31d.%20Server-side%20Attacks/Server-side%20Attacks.md>
- **If an attacker can influence input into a template before it is processed, then the attacker can invoke arbitrary expressions, i.e. perform injection attacks.**  
  `high_confidence` · score 0.778 · disproved by: Refuted when: the value is bound as a parameter or written through the framework's own encoder, so the interpreter never sees attacker text as syntax. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“If an attacker can influence input into a template before it is processed, then ”) does not occur under a test that isolates that control.
  sources: <https://cwe.mitre.org/data/definitions/1336.html> · <https://portswigger.net/web-security/server-side-template-injection>
- **Template engines can be used on the server or client, so both "sides" could be affected by injection.**  
  `high_confidence` · score 0.778 · disproved by: Refuted when: the value is bound as a parameter or written through the framework's own encoder, so the interpreter never sees attacker text as syntax. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“Template engines can be used on the server or client, so both "sides" could be a”) does not occur under a test that isolates that control.
  sources: <https://cwe.mitre.org/data/definitions/1336.html> · <https://portswigger.net/web-security/server-side-template-injection>
- **The programmer might not use engine's built-in sandboxes or other capabilities to escape or otherwise prevent template injection from untrusted input.**  
  `high_confidence` · score 0.778 · disproved by: Refuted when: the value is bound as a parameter or written through the framework's own encoder, so the interpreter never sees attacker text as syntax. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“The programmer might not use engine's built-in sandboxes or other capabilities t”) does not occur under a test that isolates that control.
  sources: <https://cwe.mitre.org/data/definitions/1336.html> · <https://portswigger.net/web-security/server-side-template-injection>
- **For example, in some template languages, an attacker could inject the expression "{{7*7}}" and determine if the output returns "49" instead.**  
  `high_confidence` · score 0.778 · disproved by: Refuted when: the value is bound as a parameter or written through the framework's own encoder, so the interpreter never sees attacker text as syntax. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“For example, in some template languages, an attacker could inject the expression”) does not occur under a test that isolates that control.
  sources: <https://cwe.mitre.org/data/definitions/1336.html> · <https://portswigger.net/web-security/server-side-template-injection>

## Test

- **The same template payloads used to prove server-side template injection are the right probe for the client-side case, because the client interpreter also expects a template and executes whatever it is handed; a field that renders template syntax as literal text is a clean negative.**  
  `high_confidence` · score 0.863 · disproved by: Template payloads that render as inert literal text in the client interpreter, or a server-side payload whose result differs from the client-side one on identical input, refutes the equivalence.
  sources: <https://snyk.io/blog/thymeleaf-injection/> · <https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/pentesting-web/client-side-template-injection-csti.md>
- **The whole defence for server-side template injection sits at one boundary, the insertion of user input into the template, so that is the only place worth verifying rather than trusting escaping applied somewhere else in the flow.**  
  `high_confidence` · score 0.8355 · disproved by: Template syntax surviving insertion into the template and being evaluated by the engine refutes sanitization and validation happening at that insertion point.
  sources: <https://jinja.palletsprojects.com/en/stable/sandbox/> · <https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/pentesting-web/ssti-server-side-template-injection/README.md>

## Fp Rule

- **A template expression like {{7*7}} echoed back literally in the response is a false SSTI; the report needs the value 49 to appear where the expression was.**  
  `high_confidence` · score 0.945 · disproved by: If the literal echo only appears in a field the application later renders client-side through a JavaScript template engine, the server did not evaluate it and the report belongs to the client-side class, not to server-side template injection.
  sources: <https://httpwg.org/specs/rfc9110.html> · <https://projectdiscovery.io/blog/inside-the-benchmark-pp-architectures-finding-walkthroughs-and-what-each-scanner-actually-caught> · <https://projectdiscovery.io/blog/crafting-dast-nuclei-templates-for-oob-template-engines-injection-a-practical-guide>
- **A sandboxed template environment is not a security proof, since the documentation states the sandbox alone is not a solution for perfect security and that resource-exhaustion and side-effecting objects remain outside what it prevents.**  
  `high_confidence` · score 0.8905 · disproved by: It IS effective for the specific primitive it blocks when attribute and method access are genuinely intercepted, which is why a private-attribute probe is rejected; it is NOT sufficient on its own when the attacker reaches resource exhaustion, a passed-in object with side effects, or an output context the template does not understand, and the report must name which of those was actually shown.
  sources: <https://jinja.palletsprojects.com/en/stable/sandbox/> · <https://twig.symfony.com/doc/api.html>
- **A template injection finding is only proved when the response shows the engine evaluating template syntax, not when it shows the payload reflected literally, because a reflection result is explained by ordinary output encoding and proves nothing about the engine.**  
  `high_confidence` · score 0.8905 · disproved by: It IS template injection when a sentinel expression is computed and the computed result appears in the response rather than the expression text; it is NOT when the response contains the payload unchanged, in which case the correct finding is reflected content or XSS at most, and the SSTI claim must be withdrawn.
  sources: <https://jinja.palletsprojects.com/en/stable/sandbox/> · <https://twig.symfony.com/doc/templates.html>
- **A template engine error message that names the injected payload does not prove the payload was evaluated; a compiler or render error can equally be triggered by malformed template syntax, so error text alone is ambiguous evidence.**  
  `high_confidence` · score 0.8905 · disproved by: It becomes proof when the error is specific to evaluation rather than to parsing, for example a division or type error raised by a syntactically valid expression, which shows the engine executed past parsing; a generic parse error on malformed braces indicates only that the string reached the parser, which is weaker but still real evidence that the template boundary was crossed.
  sources: <https://jinja.palletsprojects.com/en/stable/sandbox/> · <https://twig.symfony.com/doc/templates.html>

## Impact

- **With Jinja as the engine, it is the Jinja directives inside the injected template that turn template injection into code execution and control of the engine itself, so identifying the engine decides what the finding is worth.**  
  `high_confidence` · score 0.808 · disproved by: Jinja syntax injected into a template that renders as literal text with no directive evaluated and no code execution, refutes this mechanism.
  sources: <https://jinja.palletsprojects.com/en/stable/sandbox/> · <https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/pentesting-web/ssti-server-side-template-injection/README.md>

## Bypass

- **Automatic output escaping is an output-context control, not a template-context control, so it prevents an injected value from becoming markup while doing nothing to stop that value from being interpreted as template syntax before rendering.**  
  `high_confidence` · score 0.863 · disproved by: It does protect the response when the only attacker-controlled surface is a template variable whose value is escaped; it does not protect when the attacker controls the template string itself, because the engine parses that string before any escaping is applied, so the escaping layer is downstream of the compromise.
  sources: <https://jinja.palletsprojects.com/en/stable/sandbox/> · <https://twig.symfony.com/doc/templates.html>
