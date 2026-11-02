# History

Append-only. Each entry records WHY the skill changed, not just that it did. Improvement means better hunting behaviour, not more text.

## 2026-10-02 15:57 — 1 diff lines
- items: 12 (supported 12), FP rules 2, chains 1, state mature

```diff
(initial generation, 2026-10-02)
```

## 2026-10-02 16:07 — 8 diff lines
- items: 12 (supported 12), FP rules 2, chains 1, state mature

```diff
--- ssti@current
+++ ssti@new
@@ -64,4 +64,4 @@
   - Sources: <https://blog.qualys.com/vulnerabilities-threat-research/2016/08/31/thwarting-sql-injection-defense-in-depth> · <https://projectdiscovery.io/blog/crafting-dast-nuclei-templates-for-oob-template-engines-injection-a-practical-guide> · <https://projectdiscovery.io/blog/inside-the-benchmark-pp-architectures-finding-walkthroughs-and-what-each-scanner-actually-caught>
 
 ---
-Full class document: `domains/web/ssti/EVIDENCE.md` · retrieve more with `python -m wks.cli search "<query>" --class-id ssti`
+Full class document: `domains/web/ssti/knowledge/DIGEST.md` · retrieve more with `python -m wks.cli search "<query>" --class-id ssti`
```

## 2026-10-02 19:37 — 104 diff lines
- items: 23 (supported 11), FP rules 5, chains 1, state mature

```diff
--- ssti@current
+++ ssti@new
@@ -10,7 +10,7 @@
      python -m wks.skillgen -->
 
 > surface `web` · CWE CWE-1336 · OWASP A03:2021
-> evidence: 12 items, 12 supported, 2 FP rules, 1 chains
+> evidence: 23 items, 11 supported, 5 FP rules, 1 chains
 > maturity: **mature**
 
 Untrusted input is compiled by the template engine rather than treated as data, so the engine's expression language executes.
@@ -26,36 +26,72 @@
 
 ## Techniques (what to change)
 
-- If an attacker can influence input into a template before it is processed, then the attacker can invoke arbitrary expressions, i.e. perform injection attacks.
+- If an attacker can influence input into a template before it is processed, then the attacker can invoke arbitrary expressions, i.e. perform injection attacks. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "If an attacker can influence input into a template before it is processed, then the attack".
   - Sources: <https://cwe.mitre.org/data/definitions/1336.html> · <https://portswigger.net/web-security/server-side-template-injection>
-- Template engines can be used on the server or client, so both "sides" could be affected by injection.
+- Template engines can be used on the server or client, so both "sides" could be affected by injection. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Template engines can be used on the server or client, so both "sides" could be affected by".
   - Sources: <https://cwe.mitre.org/data/definitions/1336.html> · <https://portswigger.net/web-security/server-side-template-injection>
-- The programmer might not use engine's built-in sandboxes or other capabilities to escape or otherwise prevent template injection from untrusted input.
+- The programmer might not use engine's built-in sandboxes or other capabilities to escape or otherwise prevent template injection from untrusted input. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "The programmer might not use engine's built-in sandboxes or other capabilities to escape o".
   - Sources: <https://cwe.mitre.org/data/definitions/1336.html> · <https://portswigger.net/web-security/server-side-template-injection>
-- The programmer might not use engine's built-in sandboxes or other capabilities to escape or otherwise prevent template injection from untrusted input.
+- The programmer might not use engine's built-in sandboxes or other capabilities to escape or otherwise prevent template injection from untrusted input. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "The programmer might not use engine's built-in sandboxes or other capabilities to escape o".
   - Sources: <https://cwe.mitre.org/data/definitions/1336.html> · <https://portswigger.net/web-security/server-side-template-injection>
-- If an attacker can influence input into a template before it is processed, then the attacker can invoke arbitrary expressions, i.e. perform injection attacks.
+- If an attacker can influence input into a template before it is processed, then the attacker can invoke arbitrary expressions, i.e. perform injection attacks. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "If an attacker can influence input into a template before it is processed, then the attack".
   - Sources: <https://cwe.mitre.org/data/definitions/1336.html> · <https://portswigger.net/web-security/server-side-template-injection>
-- For example, in some template languages, an attacker could inject the expression "{{7*7}}" and determine if the output returns "49" instead.
+- For example, in some template languages, an attacker could inject the expression "{{7*7}}" and determine if the output returns "49" instead. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "For example, in some template languages, an attacker could inject the expression "{{7*7}}"".
   - Sources: <https://cwe.mitre.org/data/definitions/1336.html> · <https://portswigger.net/web-security/server-side-template-injection>
-- Template engines can be used on the server or client, so both "sides" could be affected by injection.
+- Template engines can be used on the server or client, so both "sides" could be affected by injection. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Template engines can be used on the server or client, so both "sides" could be affected by".
   - Sources: <https://cwe.mitre.org/data/definitions/1336.html> · <https://portswigger.net/web-security/server-side-template-injection>
-- The programmer might not use engine's built-in sandboxes or other capabilities to escape or otherwise prevent template injection from untrusted input.
+- The programmer might not use engine's built-in sandboxes or other capabilities to escape or otherwise prevent template injection from untrusted input. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "The programmer might not use engine's built-in sandboxes or other capabilities to escape o".
   - Sources: <https://cwe.mitre.org/data/definitions/1336.html> · <https://portswigger.net/web-security/server-side-template-injection>
 - A template sandbox that pre-checks a dangerous keyword followed by a single space is bypassed by sending a tab in place of that space.
   - **Disproof:** If the tab variant is rejected by the same pre-check as the space variant, or is rejected by the downstream type blocklist, the filter is not the weak separator described here.
   - Sources: <https://snyk.io/blog/thymeleaf-injection/> · <https://www.nccgroup.com/research/technical-advisory-pulse-connect-secure-rce-via-template-injection-cve-2020-8243/>
 
+## Tests
+
+- To decide this case, observe: ers, mail scanners, and your own tooling generate ordinary lookups that land on the same listener. The finding survives only when the callback is a record type your template expression would have caused, such as an SRV query from an nslookup call embedded in the expression, or when the resolved payload string appears in the response body so you can attribute the lookup to templ _(unverified)_
+  - **Disproof:** This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (ssti.fprule.generic_oob_dns_callback_is_not_evidence) states the full boundary.
+  - Sources: <https://projectdiscovery.io/blog/crafting-dast-nuclei-templates-for-oob-template-engines-injection-a-practical-guide> · <https://projectdiscovery.io/blog/inside-the-benchmark-pp-architectures-finding-walkthroughs-and-what-each-scanner-actually-caught>
+- To decide this case, observe: treat this as the fp_rule it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable. Boundary of the rule: It IS effective for the specific primitive it blocks when attribute and method access are genuinely intercepted, which is why a private-attribute probe is rejected; it is NOT _(unverified)_
+  - **Disproof:** This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (ssti.fp_rule.a_sandbox_is_not_a_proof_that_the_template_is_safe) states the full boundary.
+  - Sources: <https://jinja.palletsprojects.com/en/stable/sandbox/> · <https://twig.symfony.com/doc/api.html>
+- To decide this case, observe: treat this as the fp_rule it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable. Boundary of the rule: It becomes proof when the error is specific to evaluation rather than to parsing, for example a division or type error raised by a syntactically valid expression, which shows _(unverified)_
+  - **Disproof:** This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (ssti.fp_rule.template_error_messages_alone_do_not_prove_ssti) states the full boundary.
+  - Sources: <https://jinja.palletsprojects.com/en/stable/sandbox/> · <https://twig.symfony.com/doc/templates.html>
+- To decide this case, observe: treat this as the fp_rule it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable. Boundary of the rule: It IS template injection when a sentinel expression is computed and the computed result appears in the response rather than the expression text; it is NOT when the response c
+  - **Disproof:** This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (ssti.fp_rule.arithmetic_evaluation_is_evaluation_not_just_reflection) states the full boundary.
+  - Sources: <https://jinja.palletsprojects.com/en/stable/sandbox/> · <https://twig.symfony.com/doc/templates.html>
+- To decide this case, observe: : treat this as the bypass it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable. Boundary of the rule: It does protect the response when the only attacker-controlled surface is a template variable whose value is escaped; it does not protect when the attacker controls the templ _(unverified)_
+  - **Disproof:** This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (ssti.bypass.autoescape_does_not_defend_the_template_context) states the full boundary.
+  - Sources: <https://jinja.palletsprojects.com/en/stable/sandbox/> · <https://twig.symfony.com/doc/templates.html>
+- To decide this case, observe: sm: The convincing validation pair sends a template expression whose result is a computed value, and the finding stands only when that computed value appears in the response, because a reflected expression could be produced by any endpoint that echoes input. How to apply it in the field: treat this as the validation it is — a hunter must be able to state the concrete observatio
+  - **Disproof:** This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (ssti.validation.prove_evaluation_with_arithmetic_that_the_response_could_not_have_produced) states the full boundary.
+  - Sources: <https://jinja.palletsprojects.com/en/stable/sandbox/> · <https://twig.symfony.com/doc/templates.html>
+
+## Validation bar (how to prove it)
+
+- The convincing validation pair sends a template expression whose result is a computed value, and the finding stands only when that computed value appears in the response, because a reflected expression could be produced by any endpoint that echoes input.
+  - **Disproof:** If the response shows the expression text unchanged or a fixed error mentioning the marker without evaluating it, the proof fails; the pair is convincing only when the returned value is something the server could not have known to echo literally, which is what distinguishes evaluation from reflection.
+  - Sources: <https://jinja.palletsprojects.com/en/stable/sandbox/> · <https://twig.symfony.com/doc/templates.html>
+
 ## False-positive rules (when to reject it)
 
+- A sandboxed template environment is not a security proof, since the documentation states the sandbox alone is not a solution for perfect security and that resource-exhaustion and side-effecting objects remain outside what it prevents.
+  - **Disproof:** It IS effective for the specific primitive it blocks when attribute and method access are genuinely intercepted, which is why a private-attribute probe is rejected; it is NOT sufficient on its own when the attacker reaches resource exhaustion, a passed-in object with side effects, or an output context the template does not understand, and the report must name which of those was actually shown.
+  - Sources: <https://jinja.palletsprojects.com/en/stable/sandbox/> · <https://twig.symfony.com/doc/api.html>
+- A template injection finding is only proved when the response shows the engine evaluating template syntax, not when it shows the payload reflected literally, because a reflection result is explained by ordinary output encoding and proves nothing about the engine.
+  - **Disproof:** It IS template injection when a sentinel expression is computed and the computed result appears in the response rather than the expression text; it is NOT when the response contains the payload unchanged, in which case the correct finding is reflected content or XSS at most, and the SSTI claim must be withdrawn.
+  - Sources: <https://jinja.palletsprojects.com/en/stable/sandbox/> · <https://twig.symfony.com/doc/templates.html>
+- A template engine error message that names the injected payload does not prove the payload was evaluated; a compiler or render error can equally be triggered by malformed template syntax, so error text alone is ambiguous evidence.
+  - **Disproof:** It becomes proof when the error is specific to evaluation rather than to parsing, for example a division or type error raised by a syntactically valid expression, which shows the engine executed past parsing; a generic parse error on malformed braces indicates only that the string reached the parser, which is weaker but still real evidence that the template boundary was crossed.
+  - Sources: <https://jinja.palletsprojects.com/en/stable/sandbox/> · <https://twig.symfony.com/doc/templates.html>
 - A template expression like {{7*7}} echoed back literally in the response is a false SSTI; the report needs the value 49 to appear where the expression was.
   - **Disproof:** If the literal echo only appears in a field the application later renders client-side through a JavaScript template engine, the server did not evaluate it and the report belongs to the client-side class, not to server-side template injection.
   - Sources: <https://httpwg.org/specs/rfc9110.html> · <https://projectdiscovery.io/blog/crafting-dast-nuclei-templates-for-oob-template-engines-injection-a-practical-guide> · <https://projectdiscovery.io/blog/inside-the-benchmark-pp-architectures-finding-walkthroughs-and-what-each-scanner-actually-caught>
@@ -63,5 +99,11 @@
   - **Disproof:** If a plain baseline request with no template payload produces the same callback type and rate against your listener, the listener is the signal and not the target, so the SSTI claim has no surviving evidence.
   - Sources: <https://blog.qualys.com/vulnerabilities-threat-research/2016/08/31/thwarting-sql-injection-defense-in-depth> · <https://projectdiscovery.io/blog/crafting-dast-nuclei-templates-for-oob-template-engines-injection-a-practical-guide> · <https://projectdiscovery.io/blog/inside-the-benchmark-pp-architectures-finding-walkthroughs-and-what-each-scanner-actually-caught>
 
+## Defence bypasses
+
+- Automatic output escaping is an output-context control, not a template-context control, so it prevents an injected value from becoming markup while doing nothing to stop that value from being interpreted as template syntax before rendering.
+  - **Disproof:** It does protect the response when the only attacker-controlled surface is a template variable whose value is escaped; it does not protect when the attacker controls the template string itself, because the engine parses that string before any escaping is applied, so the escaping layer is downstream of the compromise.
+  - Sources: <https://jinja.palletsprojects.com/en/stable/sandbox/> · <https://twig.symfony.com/doc/templates.html>
+
 ---
 Full class document: `domains/web/ssti/knowledge/DIGEST.md` · retrieve more with `python -m wks.cli search "<query>" --class-id ssti`
```

## 2026-10-03 01:46 — 87 diff lines
- items: 30 (supported 19), FP rules 5, chains 1, state mature

```diff
--- ssti@current
+++ ssti@new
@@ -10,7 +10,7 @@
      python -m wks.skillgen -->
 
 > surface `web` · CWE CWE-1336 · OWASP A03:2021
-> evidence: 23 items, 11 supported, 5 FP rules, 1 chains
+> evidence: 30 items, 19 supported, 5 FP rules, 1 chains
 > maturity: **mature**
 
 Untrusted input is compiled by the template engine rather than treated as data, so the engine's expression language executes.
@@ -23,6 +23,12 @@
 - Thymeleaf SpEL injection needs request data to reach the expression engine or a dynamically built view name, not merely the data model.
   - **Disproof:** Sending arithmetic or expression metacharacters through the parameter and getting the input back as inert data (no evaluation, no error, no type coercion) shows the value never reaches the expression engine.
   - Sources: <https://snyk.io/blog/thymeleaf-injection/> · <https://www.nccgroup.com/research/technical-advisory-pulse-connect-secure-rce-via-template-injection-cve-2020-8243/>
+
+## Recon signals (where to look)
+
+- An ordinary profile field such as a name parameter is the signal worth chasing, not an exotic input: any value that the server-side template engine renders back is a candidate injection point because the engine will interpret whatever the user put there.
+  - **Disproof:** A name parameter whose template metacharacters are stripped or escaped before rendering and come back as literal text, refutes it as an injection point.
+  - Sources: <https://jinja.palletsprojects.com/en/stable/sandbox/> · <https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/pentesting-web/ssti-server-side-template-injection/README.md>
 
 ## Techniques (what to change)
 
@@ -53,25 +59,34 @@
 - A template sandbox that pre-checks a dangerous keyword followed by a single space is bypassed by sending a tab in place of that space.
   - **Disproof:** If the tab variant is rejected by the same pre-check as the space variant, or is rejected by the downstream type blocklist, the filter is not the weak separator described here.
   - Sources: <https://snyk.io/blog/thymeleaf-injection/> · <https://www.nccgroup.com/research/technical-advisory-pulse-connect-secure-rce-via-template-injection-cve-2020-8243/>
+- Server-side template injection is proven by sending an arithmetic expression such as {{7*7}}; evaluating to 49 shows the template engine evaluated attacker input.
+  - **Disproof:** Refuted when the expression is returned verbatim as literal text rather than evaluated, which shows the input is not reaching a template engine.
+  - Sources: <https://portswigger.net/web-security/server-side-template-injection> · <https://raw.githubusercontent.com/Ch4os1/WriteUps-HTB/main/Medium/Unix/Gobox/writeup.md> · <https://raw.githubusercontent.com/Esther7171/HackTheBox-Writeups-Walkthroughs/main/Write-ups/Academy/05.%20Web%20Exploitation/31d.%20Server-side%20Attacks/Server-side%20Attacks.md>
 
 ## Tests
 
-- To decide this case, observe: ers, mail scanners, and your own tooling generate ordinary lookups that land on the same listener. The finding survives only when the callback is a record type your template expression would have caused, such as an SRV query from an nslookup call embedded in the expression, or when the resolved payload string appears in the response body so you can attribute the lookup to templ _(unverified)_
+- To decide this case, observe: Discard the SSTI report when the only signal is a bare DNS resolution for your OAST domain, because recursive resolvers, prefetchers, mail scanners, and your own tooling generate ordinary lookups that land on the same listener. _(unverified)_
   - **Disproof:** This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (ssti.fprule.generic_oob_dns_callback_is_not_evidence) states the full boundary.
   - Sources: <https://projectdiscovery.io/blog/crafting-dast-nuclei-templates-for-oob-template-engines-injection-a-practical-guide> · <https://projectdiscovery.io/blog/inside-the-benchmark-pp-architectures-finding-walkthroughs-and-what-each-scanner-actually-caught>
-- To decide this case, observe: treat this as the fp_rule it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable. Boundary of the rule: It IS effective for the specific primitive it blocks when attribute and method access are genuinely intercepted, which is why a private-attribute probe is rejected; it is NOT _(unverified)_
+- To decide this case, observe: How to apply it in the field: treat this as the fp_rule it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable.
   - **Disproof:** This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (ssti.fp_rule.a_sandbox_is_not_a_proof_that_the_template_is_safe) states the full boundary.
   - Sources: <https://jinja.palletsprojects.com/en/stable/sandbox/> · <https://twig.symfony.com/doc/api.html>
-- To decide this case, observe: treat this as the fp_rule it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable. Boundary of the rule: It becomes proof when the error is specific to evaluation rather than to parsing, for example a division or type error raised by a syntactically valid expression, which shows _(unverified)_
+- To decide this case, observe: How to apply it in the field: treat this as the fp_rule it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable.
   - **Disproof:** This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (ssti.fp_rule.template_error_messages_alone_do_not_prove_ssti) states the full boundary.
   - Sources: <https://jinja.palletsprojects.com/en/stable/sandbox/> · <https://twig.symfony.com/doc/templates.html>
-- To decide this case, observe: treat this as the fp_rule it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable. Boundary of the rule: It IS template injection when a sentinel expression is computed and the computed result appears in the response rather than the expression text; it is NOT when the response c
+- To decide this case, observe: How to apply it in the field: treat this as the fp_rule it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable.
   - **Disproof:** This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (ssti.fp_rule.arithmetic_evaluation_is_evaluation_not_just_reflection) states the full boundary.
   - Sources: <https://jinja.palletsprojects.com/en/stable/sandbox/> · <https://twig.symfony.com/doc/templates.html>
-- To decide this case, observe: : treat this as the bypass it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable. Boundary of the rule: It does protect the response when the only attacker-controlled surface is a template variable whose value is escaped; it does not protect when the attacker controls the templ _(unverified)_
+- To decide this case, observe: How to apply it in the field: treat this as the bypass it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable.
   - **Disproof:** This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (ssti.bypass.autoescape_does_not_defend_the_template_context) states the full boundary.
   - Sources: <https://jinja.palletsprojects.com/en/stable/sandbox/> · <https://twig.symfony.com/doc/templates.html>
-- To decide this case, observe: sm: The convincing validation pair sends a template expression whose result is a computed value, and the finding stands only when that computed value appears in the response, because a reflected expression could be produced by any endpoint that echoes input. How to apply it in the field: treat this as the validation it is — a hunter must be able to state the concrete observatio
+- The same template payloads used to prove server-side template injection are the right probe for the client-side case, because the client interpreter also expects a template and executes whatever it is handed; a field that renders template syntax as literal text is a clean negative.
+  - **Disproof:** Template payloads that render as inert literal text in the client interpreter, or a server-side payload whose result differs from the client-side one on identical input, refutes the equivalence.
+  - Sources: <https://snyk.io/blog/thymeleaf-injection/> · <https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/pentesting-web/client-side-template-injection-csti.md>
+- The whole defence for server-side template injection sits at one boundary, the insertion of user input into the template, so that is the only place worth verifying rather than trusting escaping applied somewhere else in the flow.
+  - **Disproof:** Template syntax surviving insertion into the template and being evaluated by the engine refutes sanitization and validation happening at that insertion point.
+  - Sources: <https://jinja.palletsprojects.com/en/stable/sandbox/> · <https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/pentesting-web/ssti-server-side-template-injection/README.md>
+- To decide this case, observe: Mechanism: The convincing validation pair sends a template expression whose result is a computed value, and the finding stands only when that computed value appears in the response, because a reflected expression could be produced by any endpoint that echoes input.
   - **Disproof:** This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (ssti.validation.prove_evaluation_with_arithmetic_that_the_response_could_not_have_produced) states the full boundary.
   - Sources: <https://jinja.palletsprojects.com/en/stable/sandbox/> · <https://twig.symfony.com/doc/templates.html>
 
@@ -99,6 +114,21 @@
   - **Disproof:** If a plain baseline request with no template payload produces the same callback type and rate against your listener, the listener is the signal and not the target, so the SSTI claim has no surviving evidence.
   - Sources: <https://blog.qualys.com/vulnerabilities-threat-research/2016/08/31/thwarting-sql-injection-defense-in-depth> · <https://projectdiscovery.io/blog/crafting-dast-nuclei-templates-for-oob-template-engines-injection-a-practical-guide> · <https://projectdiscovery.io/blog/inside-the-benchmark-pp-architectures-finding-walkthroughs-and-what-each-scanner-actually-caught>
 
+## Evidence requirements
+
+- A convincing observation for this class is: The finding survives only when the callback is a record type your template expression would have caused, such as an SRV query from an nslookup call embedded in the expression, or when the resolved payload string appears in the response body so you can attribute the lookup to template evaluation. _(unverified)_
+  - **Disproof:** Not evidence when the observable cannot be produced at all -- blind, server-side-only, or identical-in-every-case behaviour leaves nothing to show. The originating rule (ssti.fprule.generic_oob_dns_callback_is_not_evidence) states the full boundary.
+  - Sources: <https://projectdiscovery.io/blog/crafting-dast-nuclei-templates-for-oob-template-engines-injection-a-practical-guide> · <https://projectdiscovery.io/blog/inside-the-benchmark-pp-architectures-finding-walkthroughs-and-what-each-scanner-actually-caught>
+
+## Impact framing
+
+- Where the template is evaluated decides the ceiling of the finding: a client-side injection buys arbitrary JavaScript in the victim's browser, not code execution on the remote server, so the two must not be reported with the same severity. _(unverified)_
+  - **Disproof:** A client-side template injection that yields code execution on the remote server, or that produces no JavaScript execution in the victim's browser at all, refutes this impact boundary.
+  - Sources: <https://snyk.io/blog/thymeleaf-injection/> · <https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/pentesting-web/client-side-template-injection-csti.md>
+- With Jinja as the engine, it is the Jinja directives inside the injected template that turn template injection into code execution and control of the engine itself, so identifying the engine decides what the finding is worth.
+  - **Disproof:** Jinja syntax injected into a template that renders as literal text with no directive evaluated and no code execution, refutes this mechanism.
+  - Sources: <https://jinja.palletsprojects.com/en/stable/sandbox/> · <https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/pentesting-web/ssti-server-side-template-injection/README.md>
+
 ## Defence bypasses
 
 - Automatic output escaping is an output-context control, not a template-context control, so it prevents an injected value from becoming markup while doing nothing to stop that value from being interpreted as template syntax before rendering.
```

## 2026-10-03 02:41 — 31 diff lines
- items: 30 (supported 19), FP rules 5, chains 1, state mature

```diff
--- ssti@current
+++ ssti@new
@@ -67,7 +67,7 @@
 
 - To decide this case, observe: Discard the SSTI report when the only signal is a bare DNS resolution for your OAST domain, because recursive resolvers, prefetchers, mail scanners, and your own tooling generate ordinary lookups that land on the same listener. _(unverified)_
   - **Disproof:** This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (ssti.fprule.generic_oob_dns_callback_is_not_evidence) states the full boundary.
-  - Sources: <https://projectdiscovery.io/blog/crafting-dast-nuclei-templates-for-oob-template-engines-injection-a-practical-guide> · <https://projectdiscovery.io/blog/inside-the-benchmark-pp-architectures-finding-walkthroughs-and-what-each-scanner-actually-caught>
+  - Sources: <https://projectdiscovery.io/blog/inside-the-benchmark-pp-architectures-finding-walkthroughs-and-what-each-scanner-actually-caught> · <https://projectdiscovery.io/blog/crafting-dast-nuclei-templates-for-oob-template-engines-injection-a-practical-guide>
 - To decide this case, observe: How to apply it in the field: treat this as the fp_rule it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable.
   - **Disproof:** This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (ssti.fp_rule.a_sandbox_is_not_a_proof_that_the_template_is_safe) states the full boundary.
   - Sources: <https://jinja.palletsprojects.com/en/stable/sandbox/> · <https://twig.symfony.com/doc/api.html>
@@ -109,16 +109,16 @@
   - Sources: <https://jinja.palletsprojects.com/en/stable/sandbox/> · <https://twig.symfony.com/doc/templates.html>
 - A template expression like {{7*7}} echoed back literally in the response is a false SSTI; the report needs the value 49 to appear where the expression was.
   - **Disproof:** If the literal echo only appears in a field the application later renders client-side through a JavaScript template engine, the server did not evaluate it and the report belongs to the client-side class, not to server-side template injection.
-  - Sources: <https://httpwg.org/specs/rfc9110.html> · <https://projectdiscovery.io/blog/crafting-dast-nuclei-templates-for-oob-template-engines-injection-a-practical-guide> · <https://projectdiscovery.io/blog/inside-the-benchmark-pp-architectures-finding-walkthroughs-and-what-each-scanner-actually-caught>
+  - Sources: <https://httpwg.org/specs/rfc9110.html> · <https://projectdiscovery.io/blog/inside-the-benchmark-pp-architectures-finding-walkthroughs-and-what-each-scanner-actually-caught> · <https://projectdiscovery.io/blog/crafting-dast-nuclei-templates-for-oob-template-engines-injection-a-practical-guide>
 - A DNS callback received after an SSTI payload is not proof of server-side template evaluation unless the callback type is one your payload alone could have triggered.
   - **Disproof:** If a plain baseline request with no template payload produces the same callback type and rate against your listener, the listener is the signal and not the target, so the SSTI claim has no surviving evidence.
-  - Sources: <https://blog.qualys.com/vulnerabilities-threat-research/2016/08/31/thwarting-sql-injection-defense-in-depth> · <https://projectdiscovery.io/blog/crafting-dast-nuclei-templates-for-oob-template-engines-injection-a-practical-guide> · <https://projectdiscovery.io/blog/inside-the-benchmark-pp-architectures-finding-walkthroughs-and-what-each-scanner-actually-caught>
+  - Sources: <https://projectdiscovery.io/blog/inside-the-benchmark-pp-architectures-finding-walkthroughs-and-what-each-scanner-actually-caught> · <https://blog.qualys.com/vulnerabilities-threat-research/2016/08/31/thwarting-sql-injection-defense-in-depth> · <https://projectdiscovery.io/blog/crafting-dast-nuclei-templates-for-oob-template-engines-injection-a-practical-guide>
 
 ## Evidence requirements
 
 - A convincing observation for this class is: The finding survives only when the callback is a record type your template expression would have caused, such as an SRV query from an nslookup call embedded in the expression, or when the resolved payload string appears in the response body so you can attribute the lookup to template evaluation. _(unverified)_
   - **Disproof:** Not evidence when the observable cannot be produced at all -- blind, server-side-only, or identical-in-every-case behaviour leaves nothing to show. The originating rule (ssti.fprule.generic_oob_dns_callback_is_not_evidence) states the full boundary.
-  - Sources: <https://projectdiscovery.io/blog/crafting-dast-nuclei-templates-for-oob-template-engines-injection-a-practical-guide> · <https://projectdiscovery.io/blog/inside-the-benchmark-pp-architectures-finding-walkthroughs-and-what-each-scanner-actually-caught>
+  - Sources: <https://projectdiscovery.io/blog/inside-the-benchmark-pp-architectures-finding-walkthroughs-and-what-each-scanner-actually-caught> · <https://projectdiscovery.io/blog/crafting-dast-nuclei-templates-for-oob-template-engines-injection-a-practical-guide>
 
 ## Impact framing
 
```

## 2026-10-04 00:43 — 180 diff lines
- items: 30 (supported 19), FP rules 5, chains 1, state mature

```diff
--- ssti@current
+++ ssti@new
@@ -20,120 +20,117 @@
 
 ## Prerequisites (do not start without these)
 
-- Thymeleaf SpEL injection needs request data to reach the expression engine or a dynamically built view name, not merely the data model.
+- Thymeleaf SpEL injection needs request data to reach the expression engine or a dynamically built view name, not merely the data model.  _(merged 1 duplicate row(s))_
   - **Disproof:** Sending arithmetic or expression metacharacters through the parameter and getting the input back as inert data (no evaluation, no error, no type coercion) shows the value never reaches the expression engine.
   - Sources: <https://snyk.io/blog/thymeleaf-injection/> · <https://www.nccgroup.com/research/technical-advisory-pulse-connect-secure-rce-via-template-injection-cve-2020-8243/>
 
 ## Recon signals (where to look)
 
-- An ordinary profile field such as a name parameter is the signal worth chasing, not an exotic input: any value that the server-side template engine renders back is a candidate injection point because the engine will interpret whatever the user put there.
+- An ordinary profile field such as a name parameter is the signal worth chasing, not an exotic input: any value that the server-side template engine renders back is a candidate injection point because the engine will interpret whatever the user put there.  _(merged 1 duplicate row(s))_
   - **Disproof:** A name parameter whose template metacharacters are stripped or escaped before rendering and come back as literal text, refutes it as an injection point.
   - Sources: <https://jinja.palletsprojects.com/en/stable/sandbox/> · <https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/pentesting-web/ssti-server-side-template-injection/README.md>
 
 ## Techniques (what to change)
 
-- If an attacker can influence input into a template before it is processed, then the attacker can invoke arbitrary expressions, i.e. perform injection attacks. _(unverified)_
+- A template sandbox that pre-checks a dangerous keyword followed by a single space is bypassed by sending a tab in place of that space.  _(merged 1 duplicate row(s))_
+  - **Disproof:** If the tab variant is rejected by the same pre-check as the space variant, or is rejected by the downstream type blocklist, the filter is not the weak separator described here.
+  - Sources: <https://snyk.io/blog/thymeleaf-injection/> · <https://www.nccgroup.com/research/technical-advisory-pulse-connect-secure-rce-via-template-injection-cve-2020-8243/>
+- For example, in some template languages, an attacker could inject the expression "{{7*7}}" and determine if the output returns "49" instead.  _(merged 1 duplicate row(s))_ _(unverified)_
+  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "For example, in some template languages, an attacker could inject the expression "{{7*7}}"".
+  - Sources: <https://cwe.mitre.org/data/definitions/1336.html> · <https://portswigger.net/web-security/server-side-template-injection>
+- If an attacker can influence input into a template before it is processed, then the attacker can invoke arbitrary expressions, i.e. perform injection attacks.  _(merged 2 duplicate row(s))_ _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "If an attacker can influence input into a template before it is processed, then the attack".
   - Sources: <https://cwe.mitre.org/data/definitions/1336.html> · <https://portswigger.net/web-security/server-side-template-injection>
-- Template engines can be used on the server or client, so both "sides" could be affected by injection. _(unverified)_
+- Server-side template injection is proven by sending an arithmetic expression such as {{7*7}}; evaluating to 49 shows the template engine evaluated attacker input.  _(merged 1 duplicate row(s))_
+  - **Disproof:** Refuted when the expression is returned verbatim as literal text rather than evaluated, which shows the input is not reaching a template engine.
+  - Sources: <https://portswigger.net/web-security/server-side-template-injection> · <https://raw.githubusercontent.com/Ch4os1/WriteUps-HTB/main/Medium/Unix/Gobox/writeup.md> · <https://raw.githubusercontent.com/Esther7171/HackTheBox-Writeups-Walkthroughs/main/Write-ups/Academy/05.%20Web%20Exploitation/31d.%20Server-side%20Attacks/Server-side%20Attacks.md>
+- Template engines can be used on the server or client, so both "sides" could be affected by injection.  _(merged 2 duplicate row(s))_ _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Template engines can be used on the server or client, so both "sides" could be affected by".
   - Sources: <https://cwe.mitre.org/data/definitions/1336.html> · <https://portswigger.net/web-security/server-side-template-injection>
-- The programmer might not use engine's built-in sandboxes or other capabilities to escape or otherwise prevent template injection from untrusted input. _(unverified)_
+- The programmer might not use engine's built-in sandboxes or other capabilities to escape or otherwise prevent template injection from untrusted input.  _(merged 3 duplicate row(s))_ _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "The programmer might not use engine's built-in sandboxes or other capabilities to escape o".
   - Sources: <https://cwe.mitre.org/data/definitions/1336.html> · <https://portswigger.net/web-security/server-side-template-injection>
-- The programmer might not use engine's built-in sandboxes or other capabilities to escape or otherwise prevent template injection from untrusted input. _(unverified)_
-  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "The programmer might not use engine's built-in sandboxes or other capabilities to escape o".
-  - Sources: <https://cwe.mitre.org/data/definitions/1336.html> · <https://portswigger.net/web-security/server-side-template-injection>
-- If an attacker can influence input into a template before it is processed, then the attacker can invoke arbitrary expressions, i.e. perform injection attacks. _(unverified)_
-  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "If an attacker can influence input into a template before it is processed, then the attack".
-  - Sources: <https://cwe.mitre.org/data/definitions/1336.html> · <https://portswigger.net/web-security/server-side-template-injection>
-- For example, in some template languages, an attacker could inject the expression "{{7*7}}" and determine if the output returns "49" instead. _(unverified)_
-  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "For example, in some template languages, an attacker could inject the expression "{{7*7}}"".
-  - Sources: <https://cwe.mitre.org/data/definitions/1336.html> · <https://portswigger.net/web-security/server-side-template-injection>
-- Template engines can be used on the server or client, so both "sides" could be affected by injection. _(unverified)_
-  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Template engines can be used on the server or client, so both "sides" could be affected by".
-  - Sources: <https://cwe.mitre.org/data/definitions/1336.html> · <https://portswigger.net/web-security/server-side-template-injection>
-- The programmer might not use engine's built-in sandboxes or other capabilities to escape or otherwise prevent template injection from untrusted input. _(unverified)_
-  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "The programmer might not use engine's built-in sandboxes or other capabilities to escape o".
-  - Sources: <https://cwe.mitre.org/data/definitions/1336.html> · <https://portswigger.net/web-security/server-side-template-injection>
-- A template sandbox that pre-checks a dangerous keyword followed by a single space is bypassed by sending a tab in place of that space.
-  - **Disproof:** If the tab variant is rejected by the same pre-check as the space variant, or is rejected by the downstream type blocklist, the filter is not the weak separator described here.
-  - Sources: <https://snyk.io/blog/thymeleaf-injection/> · <https://www.nccgroup.com/research/technical-advisory-pulse-connect-secure-rce-via-template-injection-cve-2020-8243/>
-- Server-side template injection is proven by sending an arithmetic expression such as {{7*7}}; evaluating to 49 shows the template engine evaluated attacker input.
-  - **Disproof:** Refuted when the expression is returned verbatim as literal text rather than evaluated, which shows the input is not reaching a template engine.
-  - Sources: <https://portswigger.net/web-security/server-side-template-injection> · <https://raw.githubusercontent.com/Ch4os1/WriteUps-HTB/main/Medium/Unix/Gobox/writeup.md> · <https://raw.githubusercontent.com/Esther7171/HackTheBox-Writeups-Walkthroughs/main/Write-ups/Academy/05.%20Web%20Exploitation/31d.%20Server-side%20Attacks/Server-side%20Attacks.md>
 
 ## Tests
 
-- To decide this case, observe: Discard the SSTI report when the only signal is a bare DNS resolution for your OAST domain, because recursive resolvers, prefetchers, mail scanners, and your own tooling generate ordinary lookups that land on the same listener. _(unverified)_
+- The same template payloads used to prove server-side template injection are the right probe for the client-side case, because the client interpreter also expects a template and executes whatever it is handed; a field that renders template syntax as literal text is a clean negative.  _(merged 1 duplicate row(s))_
+  - **Disproof:** Template payloads that render as inert literal text in the client interpreter, or a server-side payload whose result differs from the client-side one on identical input, refutes the equivalence.
+  - Sources: <https://snyk.io/blog/thymeleaf-injection/> · <https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/pentesting-web/client-side-template-injection-csti.md>
+- The whole defence for server-side template injection sits at one boundary, the insertion of user input into the template, so that is the only place worth verifying rather than trusting escaping applied somewhere else in the flow.  _(merged 1 duplicate row(s))_
+  - **Disproof:** Template syntax surviving insertion into the template and being evaluated by the engine refutes sanitization and validation happening at that insertion point.
+  - Sources: <https://jinja.palletsprojects.com/en/stable/sandbox/> · <https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/pentesting-web/ssti-server-side-template-injection/README.md>
+- To decide this case, observe: Discard the SSTI report when the only signal is a bare DNS resolution for your OAST domain, because recursive resolvers, prefetchers, mail scanners, and your own tooling generate ordinary lookups that land on the same listener.  _(merged 1 duplicate row(s))_ _(unverified)_
   - **Disproof:** This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (ssti.fprule.generic_oob_dns_callback_is_not_evidence) states the full boundary.
   - Sources: <https://projectdiscovery.io/blog/inside-the-benchmark-pp-architectures-finding-walkthroughs-and-what-each-scanner-actually-caught> · <https://projectdiscovery.io/blog/crafting-dast-nuclei-templates-for-oob-template-engines-injection-a-practical-guide>
-- To decide this case, observe: How to apply it in the field: treat this as the fp_rule it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable.
-  - **Disproof:** This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (ssti.fp_rule.a_sandbox_is_not_a_proof_that_the_template_is_safe) states the full boundary.
-  - Sources: <https://jinja.palletsprojects.com/en/stable/sandbox/> · <https://twig.symfony.com/doc/api.html>
-- To decide this case, observe: How to apply it in the field: treat this as the fp_rule it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable.
-  - **Disproof:** This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (ssti.fp_rule.template_error_messages_alone_do_not_prove_ssti) states the full boundary.
-  - Sources: <https://jinja.palletsprojects.com/en/stable/sandbox/> · <https://twig.symfony.com/doc/templates.html>
-- To decide this case, observe: How to apply it in the field: treat this as the fp_rule it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable.
-  - **Disproof:** This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (ssti.fp_rule.arithmetic_evaluation_is_evaluation_not_just_reflection) states the full boundary.
-  - Sources: <https://jinja.palletsprojects.com/en/stable/sandbox/> · <https://twig.symfony.com/doc/templates.html>
-- To decide this case, observe: How to apply it in the field: treat this as the bypass it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable.
+- To decide this case, observe: How to apply it in the field: treat this as the bypass it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable.  _(merged 1 duplicate row(s))_
   - **Disproof:** This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (ssti.bypass.autoescape_does_not_defend_the_template_context) states the full boundary.
   - Sources: <https://jinja.palletsprojects.com/en/stable/sandbox/> · <https://twig.symfony.com/doc/templates.html>
-- The same template payloads used to prove server-side template injection are the right probe for the client-side case, because the client interpreter also expects a template and executes whatever it is handed; a field that renders template syntax as literal text is a clean negative.
-  - **Disproof:** Template payloads that render as inert literal text in the client interpreter, or a server-side payload whose result differs from the client-side one on identical input, refutes the equivalence.
-  - Sources: <https://snyk.io/blog/thymeleaf-injection/> · <https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/pentesting-web/client-side-template-injection-csti.md>
-- The whole defence for server-side template injection sits at one boundary, the insertion of user input into the template, so that is the only place worth verifying rather than trusting escaping applied somewhere else in the flow.
-  - **Disproof:** Template syntax surviving insertion into the template and being evaluated by the engine refutes sanitization and validation happening at that insertion point.
-  - Sources: <https://jinja.palletsprojects.com/en/stable/sandbox/> · <https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/pentesting-web/ssti-server-side-template-injection/README.md>
-- To decide this case, observe: Mechanism: The convincing validation pair sends a template expression whose result is a computed value, and the finding stands only when that computed value appears in the response, because a reflected expression could be produced by any endpoint that echoes input.
+- To decide this case, observe: How to apply it in the field: treat this as the fp_rule it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable.  _(merged 3 duplicate row(s))_
+  - **Disproof:** This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (ssti.fp_rule.arithmetic_evaluation_is_evaluation_not_just_reflection) states the full boundary.
+  - Sources: <https://jinja.palletsprojects.com/en/stable/sandbox/> · <https://twig.symfony.com/doc/api.html> · <https://twig.symfony.com/doc/templates.html>
+- To decide this case, observe: Mechanism: The convincing validation pair sends a template expression whose result is a computed value, and the finding stands only when that computed value appears in the response, because a reflected expression could be produced by any endpoint that echoes input.  _(merged 1 duplicate row(s))_
   - **Disproof:** This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (ssti.validation.prove_evaluation_with_arithmetic_that_the_response_could_not_have_produced) states the full boundary.
   - Sources: <https://jinja.palletsprojects.com/en/stable/sandbox/> · <https://twig.symfony.com/doc/templates.html>
 
 ## Validation bar (how to prove it)
 
-- The convincing validation pair sends a template expression whose result is a computed value, and the finding stands only when that computed value appears in the response, because a reflected expression could be produced by any endpoint that echoes input.
+- The convincing validation pair sends a template expression whose result is a computed value, and the finding stands only when that computed value appears in the response, because a reflected expression could be produced by any endpoint that echoes input.  _(merged 1 duplicate row(s))_
   - **Disproof:** If the response shows the expression text unchanged or a fixed error mentioning the marker without evaluating it, the proof fails; the pair is convincing only when the returned value is something the server could not have known to echo literally, which is what distinguishes evaluation from reflection.
   - Sources: <https://jinja.palletsprojects.com/en/stable/sandbox/> · <https://twig.symfony.com/doc/templates.html>
 
 ## False-positive rules (when to reject it)
 
-- A sandboxed template environment is not a security proof, since the documentation states the sandbox alone is not a solution for perfect security and that resource-exhaustion and side-effecting objects remain outside what it prevents.
+- A DNS callback received after an SSTI payload is not proof of server-side template evaluation unless the callback type is one your payload alone could have triggered.  _(merged 1 duplicate row(s))_
+  - **Disproof:** If a plain baseline request with no template payload produces the same callback type and rate against your listener, the listener is the signal and not the target, so the SSTI claim has no surviving evidence.
+  - Sources: <https://projectdiscovery.io/blog/inside-the-benchmark-pp-architectures-finding-walkthroughs-and-what-each-scanner-actually-caught> · <https://blog.qualys.com/vulnerabilities-threat-research/2016/08/31/thwarting-sql-injection-defense-in-depth> · <https://projectdiscovery.io/blog/crafting-dast-nuclei-templates-for-oob-template-engines-injection-a-practical-guide>
+- A sandboxed template environment is not a security proof, since the documentation states the sandbox alone is not a solution for perfect security and that resource-exhaustion and side-effecting objects remain outside what it prevents.  _(merged 1 duplicate row(s))_
   - **Disproof:** It IS effective for the specific primitive it blocks when attribute and method access are genuinely intercepted, which is why a private-attribute probe is rejected; it is NOT sufficient on its own when the attacker reaches resource exhaustion, a passed-in object with side effects, or an output context the template does not understand, and the report must name which of those was actually shown.
   - Sources: <https://jinja.palletsprojects.com/en/stable/sandbox/> · <https://twig.symfony.com/doc/api.html>
-- A template injection finding is only proved when the response shows the engine evaluating template syntax, not when it shows the payload reflected literally, because a reflection result is explained by ordinary output encoding and proves nothing about the engine.
+- A template engine error message that names the injected payload does not prove the payload was evaluated; a compiler or render error can equally be triggered by malformed template syntax, so error text alone is ambiguous evidence.  _(merged 1 duplicate row(s))_
... (truncated)
```

## 2026-10-04 00:50 — 15 diff lines
- items: 30 (supported 19), FP rules 5, chains 1, state mature

```diff
--- ssti@current
+++ ssti@new
@@ -120,10 +120,8 @@
 
 ## Hunt procedure
 
-1. Enumerate the surface before probing: collect every endpoint, parameter and object id the class could plausibly sit on.
-2. Establish a CONTROLLED BASELINE first — one unauthenticated and one authenticated low-privilege request per candidate — and diff against the probe. A difference with no baseline proves nothing.
-3. Change exactly ONE variable per probe. Two changes produce a difference you cannot attribute.
-4. Record raw request and response pairs verbatim, including headers, before you interpret anything.
+1. Fingerprint the engine first with a neutral expression ({{7*7}}, ${7*7}, <%= 7*7 %>) -- a literal 49 tells you which sink you have.
+2. Then probe for command execution and file read separately; arithmetic alone proves template injection, not RCE.
 
 ### What counts as proof
 
```
