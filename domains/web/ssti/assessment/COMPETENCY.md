# Methodology — Server-Side Template Injection

> Derived from 16 verified items. Regenerate with `python -m wks.methodgen --class ssti --apply`. Do not hand-edit: this file is a projection of the evidence, and edits are lost on the next cycle.

**Surface.** Untrusted input is compiled by the template engine rather than treated as data, so the engine's expression language executes.

**References.** CWE-1336 · A03:2021

## 1. Preconditions

_Nothing below is reachable until these hold. Confirm each against the target before spending time on the technique._

**Thymeleaf SpEL injection needs request data to reach the expression engine or a dynamically built view name, not merely the data model.**

Enumerate every endpoint whose response is produced by a template engine and ask whether the view name or template expression is itself constructed from a request parameter, rather than the parameter only being bound into the data model. Where the parameter only enters the model, no expression parsing happens and no sandbox is engaged. Where the app builds template strings or resolves views from input, manual wiring of the engine is usually required, which makes it visible in the response shape. Test by sending an expression metacharacter in the candidate parameter and comparing the response against a control value that never enters the engine.

- *Disproof:* Sending arithmetic or expression metacharacters through the parameter and getting the input back as inert data (no evaluation, no error, no type coercion) shows the value never reaches the expression engine.
- *Evidence:* high_confidence — [nccgroup.com](https://www.nccgroup.com/research/technical-advisory-pulse-connect-secure-rce-via-template-injection-cve-2020-8243/); [snyk.io](https://snyk.io/blog/thymeleaf-injection/)

## 2. Reconnaissance signals

_What to look for while mapping the surface, and where each signal tells you the rest of the procedure is worth running._

**An ordinary profile field such as a name parameter is the signal worth chasing, not an exotic input: any value that the server-side template engine renders back is a candidate injection point because the engine will interpret whatever the user put there.**

An ordinary profile field such as a name parameter is the signal worth chasing, not an exotic input: any value that the server-side template engine renders back is a candidate injection point because the engine will interpret whatever the user put there.

HackTricks reference: SSTI (Server Side Template Injection) (pentesting-web/ssti-server-side-template-injection/README.md)

- *Disproof:* A name parameter whose template metacharacters are stripped or escaped before rendering and come back as literal text, refutes it as an injection point.
- *Evidence:* high_confidence — [jinja.palletsprojects.com](https://jinja.palletsprojects.com/en/stable/sandbox/); [raw.githubusercontent.com](https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/pentesting-web/ssti-server-side-template-injection/README.md)

## 3. Test sequence

_Concrete mutations to try. Each is written to be executable, not to be a description of the vulnerability._

**A template sandbox that pre-checks a dangerous keyword followed by a single space is bypassed by sending a tab in place of that space.**

Read the engine's guard as a string filter, not a parser: if the check is a keyword plus one literal space, send new followed by a tab instead of a space. SpEL treats the tab as ordinary whitespace and parses the expression, while the pre-check does not match. The same shape applies to any engine whose blocklist is defined over a restricted character set, so re-test with tab, newline and multiple-space variants before declaring the filter effective. Confirm by observing a type blocklist rejection with the space variant versus an accepted expression with the tab variant.

- *Disproof:* If the tab variant is rejected by the same pre-check as the space variant, or is rejected by the downstream type blocklist, the filter is not the weak separator described here.
- *Evidence:* high_confidence — [nccgroup.com](https://www.nccgroup.com/research/technical-advisory-pulse-connect-secure-rce-via-template-injection-cve-2020-8243/); [snyk.io](https://snyk.io/blog/thymeleaf-injection/)

**Server-side template injection is proven by sending an arithmetic expression such as {{7*7}}; evaluating to 49 shows the template engine evaluated attacker input.**

In practice on HTB this shows up as: #### Initial Foothold 
- testing login the login form with SQLi as well as some guessing unable to login
- from the title of web page served on port 80 we see that its mentions title `{{.Title}}` from that info we can deduce that the web app is using some sort of template engine to serve the web contents 
- from the header for "Forgot Password" request to `/forgot`, we see that the server is running `Golang` 
![[header info.png]]

Write-up provenance: Ch4os1/WriteUps-HTB :: Medium/Unix/Gobox/writeup.md (738 words, classified web).

- *Disproof:* Refuted when the expression is returned verbatim as literal text rather than evaluated, which shows the input is not reaching a template engine.
- *Evidence:* high_confidence — [portswigger.net](https://portswigger.net/web-security/server-side-template-injection); [raw.githubusercontent.com](https://raw.githubusercontent.com/Ch4os1/WriteUps-HTB/main/Medium/Unix/Gobox/writeup.md)

**If an attacker can influence input into a template before it is processed, then the attacker can invoke arbitrary expressions, i.e. perform injection attacks.**

ert externally-influenced values into free text or messages in order to generate a full web page, document, message, etc. Such engines include Twig, Jinja2, Pug, Java Server Pages, FreeMarker, Velocity, ColdFusion, Smarty, and many others - including PHP itself. Some CMS (Content Management Systems) also use templates. 
 Template engines often have their own custom command or expression language. If an attacker can influence input into a template before it is processed, then the attacker can invoke arbitrary expressions, i.e. perform injection attacks. For example, in some template languages, an attacker could inject the expression "{{7*7}}" and determine if the output returns "49" instead. The syntax varies depending on the language. 
 In some cases, XSS-style attacks can work, which can obscure the root cause if the developer does not closely investigate the root cause of the error. 
 Template engines can be used on the server or client, so b

- *Disproof:* Refuted when: the value is bound as a parameter or written through the framework's own encoder, so the interpreter never sees attacker text as syntax. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“If an attacker can influence input into a template before it is processed, then ”) does not occur under a test that isolates that control.
- *Evidence:* high_confidence — [cwe.mitre.org](https://cwe.mitre.org/data/definitions/1336.html); [portswigger.net](https://portswigger.net/web-security/server-side-template-injection)

**Template engines can be used on the server or client, so both "sides" could be affected by injection.**

oke arbitrary expressions, i.e. perform injection attacks. For example, in some template languages, an attacker could inject the expression "{{7*7}}" and determine if the output returns "49" instead. The syntax varies depending on the language. 
 In some cases, XSS-style attacks can work, which can obscure the root cause if the developer does not closely investigate the root cause of the error. 
 Template engines can be used on the server or client, so both "sides" could be affected by injection. The mechanisms of attack or the affected technologies might be different, but the mistake is fundamentally the same. 
 
 
 
 
 

 

 
 
 
 
 
 
 
 Alternate Terms
 
 
 
 
 
 
 
 
 
 
 Server-Side Template Injection / SSTI
 
 
 This term is used for injection into template engines being used by a server. 
 
 
 
 
 
 Client-Side Template Injection / CSTI
 
 
 This term is used for injection into te

- *Disproof:* Refuted when: the value is bound as a parameter or written through the framework's own encoder, so the interpreter never sees attacker text as syntax. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“Template engines can be used on the server or client, so both "sides" could be a”) does not occur under a test that isolates that control.
- *Evidence:* high_confidence — [cwe.mitre.org](https://cwe.mitre.org/data/definitions/1336.html); [portswigger.net](https://portswigger.net/web-security/server-side-template-injection)

**The programmer might not use engine's built-in sandboxes or other capabilities to escape or otherwise prevent template injection from untrusted input.**

en this
 weakness may be introduced. The Phase identifies a point in the life cycle at which
 introduction
 may occur, while the Note provides a typical scenario related to introduction during the
 given
 phase. 
 
 
 Phase 
 Note 
 
 
 
 
 Architecture and Design 
 The developer might choose a template engine that makes it easier for programmers to write vulnerable code. 
 
 
 
 Implementation 
 The programmer might not use engine's built-in sandboxes or other capabilities to escape or otherwise prevent template injection from untrusted input. 
 
 
 
 
 
 
 
 

 

 
 

 
 
 Applicable Platforms 
 
 
 This listing shows possible areas for which the given
 weakness could appear. These
 may be for specific named Languages, Operating Systems, Architectures, Paradigms,
 Technologies,
 or a class of such platforms. The platform is listed along with how frequently the given
 weakness appears for that instance. 
 
 
 Languages 
 
 
 
 
 Java

- *Disproof:* Refuted when: the value is bound as a parameter or written through the framework's own encoder, so the interpreter never sees attacker text as syntax. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“The programmer might not use engine's built-in sandboxes or other capabilities t”) does not occur under a test that isolates that control.
- *Evidence:* high_confidence — [cwe.mitre.org](https://cwe.mitre.org/data/definitions/1336.html); [portswigger.net](https://portswigger.net/web-security/server-side-template-injection)

**For example, in some template languages, an attacker could inject the expression "{{7*7}}" and determine if the output returns "49" instead.**

g, Java Server Pages, FreeMarker, Velocity, ColdFusion, Smarty, and many others - including PHP itself. Some CMS (Content Management Systems) also use templates. 
 Template engines often have their own custom command or expression language. If an attacker can influence input into a template before it is processed, then the attacker can invoke arbitrary expressions, i.e. perform injection attacks. For example, in some template languages, an attacker could inject the expression "{{7*7}}" and determine if the output returns "49" instead. The syntax varies depending on the language. 
 In some cases, XSS-style attacks can work, which can obscure the root cause if the developer does not closely investigate the root cause of the error. 
 Template engines can be used on the server or client, so both "sides" could be affected by injection. The mechanisms of attack or the affected technologies might be different, but the mistake is fund

- *Disproof:* Refuted when: the value is bound as a parameter or written through the framework's own encoder, so the interpreter never sees attacker text as syntax. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“For example, in some template languages, an attacker could inject the expression”) does not occur under a test that isolates that control.
- *Evidence:* high_confidence — [cwe.mitre.org](https://cwe.mitre.org/data/definitions/1336.html); [portswigger.net](https://portswigger.net/web-security/server-side-template-injection)

## Validation

_No verified validation items yet._ Derived from evidence only, so this section is empty rather than plausible.


## 4. False-positive rejection

_The checks that eliminate the most common non-findings. Run these BEFORE reporting, not after a rejection._

**A template expression like {{7*7}} echoed back literally in the response is a false SSTI; the report needs the value 49 to appear where the expression was.**

Discard the finding when your arithmetic probe comes back verbatim, braces intact, because the target reflected your input into a page or JSON field without ever handing it to a template engine, which makes the signal reflection noise rather than template injection. The finding survives when the evaluated result appears, when a second engine-specific expression evaluates differently from the literal, or when an out-of-band command executes, since that cannot happen without the engine having parsed your input.

- *Disproof:* If the literal echo only appears in a field the application later renders client-side through a JavaScript template engine, the server did not evaluate it and the report belongs to the client-side class, not to server-side template injection.
- *Evidence:* high_confidence — [httpwg.org](https://httpwg.org/specs/rfc9110.html); [projectdiscovery.io](https://projectdiscovery.io/blog/inside-the-benchmark-pp-architectures-finding-walkthroughs-and-what-each-scanner-actually-caught)

**A sandboxed template environment is not a security proof, since the documentation states the sandbox alone is not a solution for perfect security and that resource-exhaustion and side-effecting objects remain outside what it prevents.**

Mechanism: A sandboxed template environment is not a security proof, since the documentation states the sandbox alone is not a solution for perfect security and that resource-exhaustion and side-effecting objects remain outside what it prevents. How to apply it in the field: treat this as the fp_rule it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable. Boundary of the rule: It IS effective for the specific primitive it blocks when attribute and method access are genuinely intercepted, which is why a private-attribute probe is rejected; it is NOT sufficient on its own when the attacker reaches resource exhaustion, a passed-in object with side effects, or an output context the template does not understand, and the report must name which of those was actually shown.

- *Disproof:* It IS effective for the specific primitive it blocks when attribute and method access are genuinely intercepted, which is why a private-attribute probe is rejected; it is NOT sufficient on its own when the attacker reaches resource exhaustion, a passed-in object with side effects, or an output context the template does not understand, and the report must name which of those was actually shown.
- *Evidence:* high_confidence — [jinja.palletsprojects.com](https://jinja.palletsprojects.com/en/stable/sandbox/); [twig.symfony.com](https://twig.symfony.com/doc/api.html)

**A template injection finding is only proved when the response shows the engine evaluating template syntax, not when it shows the payload reflected literally, because a reflection result is explained by ordinary output encoding and proves nothing about the engine.**

Mechanism: A template injection finding is only proved when the response shows the engine evaluating template syntax, not when it shows the payload reflected literally, because a reflection result is explained by ordinary output encoding and proves nothing about the engine. How to apply it in the field: treat this as the fp_rule it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable. Boundary of the rule: It IS template injection when a sentinel expression is computed and the computed result appears in the response rather than the expression text; it is NOT when the response contains the payload unchanged, in which case the correct finding is reflected content or XSS at most, and the SSTI claim must be withdrawn.

- *Disproof:* It IS template injection when a sentinel expression is computed and the computed result appears in the response rather than the expression text; it is NOT when the response contains the payload unchanged, in which case the correct finding is reflected content or XSS at most, and the SSTI claim must be withdrawn.
- *Evidence:* high_confidence — [jinja.palletsprojects.com](https://jinja.palletsprojects.com/en/stable/sandbox/); [twig.symfony.com](https://twig.symfony.com/doc/templates.html)

**A template engine error message that names the injected payload does not prove the payload was evaluated; a compiler or render error can equally be triggered by malformed template syntax, so error text alone is ambiguous evidence.**

Mechanism: A template engine error message that names the injected payload does not prove the payload was evaluated; a compiler or render error can equally be triggered by malformed template syntax, so error text alone is ambiguous evidence. How to apply it in the field: treat this as the fp_rule it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable. Boundary of the rule: It becomes proof when the error is specific to evaluation rather than to parsing, for example a division or type error raised by a syntactically valid expression, which shows the engine executed past parsing; a generic parse error on malformed braces indicates only that the string reached the parser, which is weaker but still real evidence that the template boundary was crossed.

- *Disproof:* It becomes proof when the error is specific to evaluation rather than to parsing, for example a division or type error raised by a syntactically valid expression, which shows the engine executed past parsing; a generic parse error on malformed braces indicates only that the string reached the parser, which is weaker but still real evidence that the template boundary was crossed.
- *Evidence:* high_confidence — [jinja.palletsprojects.com](https://jinja.palletsprojects.com/en/stable/sandbox/); [twig.symfony.com](https://twig.symfony.com/doc/templates.html)

## 5. Known bypasses

_Filters and controls that have defeated the techniques above. Treat these as the reason a naive test fails, not as proof of safety._

**Automatic output escaping is an output-context control, not a template-context control, so it prevents an injected value from becoming markup while doing nothing to stop that value from being interpreted as template syntax before rendering.**

Mechanism: Automatic output escaping is an output-context control, not a template-context control, so it prevents an injected value from becoming markup while doing nothing to stop that value from being interpreted as template syntax before rendering. How to apply it in the field: treat this as the bypass it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable. Boundary of the rule: It does protect the response when the only attacker-controlled surface is a template variable whose value is escaped; it does not protect when the attacker controls the template string itself, because the engine parses that string before any escaping is applied, so the escaping layer is downstream of the compromise.

- *Disproof:* It does protect the response when the only attacker-controlled surface is a template variable whose value is escaped; it does not protect when the attacker controls the template string itself, because the engine parses that string before any escaping is applied, so the escaping layer is downstream of the compromise.
- *Evidence:* high_confidence — [jinja.palletsprojects.com](https://jinja.palletsprojects.com/en/stable/sandbox/); [twig.symfony.com](https://twig.symfony.com/doc/templates.html)

## Chaining

_No verified chain_link items yet._ Derived from evidence only, so this section is empty rather than plausible.


## 6. Impact

_What is actually demonstrable, and what to stop claiming._

**With Jinja as the engine, it is the Jinja directives inside the injected template that turn template injection into code execution and control of the engine itself, so identifying the engine decides what the finding is worth.**

With Jinja as the engine, it is the Jinja directives inside the injected template that turn template injection into code execution and control of the engine itself, so identifying the engine decides what the finding is worth.

HackTricks reference: SSTI (Server Side Template Injection) (pentesting-web/ssti-server-side-template-injection/README.md)

- *Disproof:* Jinja syntax injected into a template that renders as literal text with no directive evaluated and no code execution, refutes this mechanism.
- *Evidence:* high_confidence — [jinja.palletsprojects.com](https://jinja.palletsprojects.com/en/stable/sandbox/); [raw.githubusercontent.com](https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/pentesting-web/ssti-server-side-template-injection/README.md)

## Coverage gap

These stages have no verified evidence and are therefore absent above: Validation, Chaining.
A procedure with a missing validation stage is not safe to act on — it produces findings rather than proofs.

---

*Generated from the evidence base. Where this file and the database disagree, the database is correct.*
