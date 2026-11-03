<!-- GENERATED from db/wks.db — do not edit -->
# Server-Side Template Injection

## Definition

Untrusted input is compiled by the template engine rather than treated as data, so the engine's expression language executes.

- **CWE:** CWE-1336
- **OWASP:** A03:2021
- **Surface:** web
- **Aliases:** ["ssti", "server side template injection", "template injection", "jinja2 ssti", "twig template injection"]

Canonical home for `ssti`. Rendered from `db/wks.db` by `tools/taxonomy/build_taxonomy.py` — edit the rows, not this file.

## Root Cause

Not yet researched.

## Preconditions

**Thymeleaf SpEL injection needs request data to reach the expression engine or a dynamically built view name, not merely the data model.**

Enumerate every endpoint whose response is produced by a template engine and ask whether the view name or template expression is itself constructed from a request parameter, rather than the parameter only being bound into the data model. Where the parameter only enters the model, no expression parsing happens and no sandbox is engaged. Where the app builds template strings or resolves views from input, manual wiring of the engine is usually required, which makes it visible in the response shape. Test by sending an expression metacharacter in the candidate parameter and comparing the response against a control value that never enters the engine.

*Disproof:* Sending arithmetic or expression metacharacters through the parameter and getting the input back as inert data (no evaluation, no error, no type coercion) shows the value never reaches the expression engine.

## Attack Surface

Surface: **web**.

The entry points and enabling conditions for this surface are enumerated under **Preconditions**; the observable signals are under **Detection**.

## Detection

**An ordinary profile field such as a name parameter is the signal worth chasing, not an exotic input: any value that the server-side template engine renders back is a candidate injection point because the engine will interpret whatever the user put there.**

An ordinary profile field such as a name parameter is the signal worth chasing, not an exotic input: any value that the server-side template engine renders back is a candidate injection point because the engine will interpret whatever the user put there.

HackTricks reference: SSTI (Server Side Template Injection) (pentesting-web/ssti-server-side-template-injection/README.md)

*Disproof:* A name parameter whose template metacharacters are stripped or escaped before rendering and come back as literal text, refutes it as an injection point.

**A convincing observation for this class is: The finding survives only when the callback is a record type your template expression would have caused, such as an SRV query from an nslookup call embedded in the expression, or when the resolved payload string appears in the response body so you can attribute the lookup to template evaluation.**

Derived from ssti.fprule.generic_oob_dns_callback_is_not_evidence, which states the boundary for this class. The observation above is what a report must contain to be believed: an artifact the reviewer can re-check, not a claim the hunter asserts. A finding without it is an assertion.

*Disproof:* Not evidence when the observable cannot be produced at all -- blind, server-side-only, or identical-in-every-case behaviour leaves nothing to show. The originating rule (ssti.fprule.generic_oob_dns_callback_is_not_evidence) states the full boundary.

## Exploitation

**If an attacker can influence input into a template before it is processed, then the attacker can invoke arbitrary expressions, i.e. perform injection attacks.**

ert externally-influenced values into free text or messages in order to generate a full web page, document, message, etc. Such engines include Twig, Jinja2, Pug, Java Server Pages, FreeMarker, Velocity, ColdFusion, Smarty, and many others - including PHP itself. Some CMS (Content Management Systems) also use templates. 
 Template engines often have their own custom command or expression language. If an attacker can influence input into a template before it is processed, then the attacker can invoke arbitrary expressions, i.e. perform injection attacks. For example, in some template languages, an attacker could inject the expression "{{7*7}}" and determine if the output returns "49" instead. The syntax varies depending on the language. 
 In some cases, XSS-style attacks can work, which can obscure the root cause if the developer does not closely investigate the root cause of the error. 
 Template engines can be used on the server or client, so b

*Disproof:* Refuted when: the value is bound as a parameter or written through the framework's own encoder, so the interpreter never sees attacker text as syntax. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“If an attacker can influence input into a template before it is processed, then ”) does not occur under a test that isolates that control.

**Template engines can be used on the server or client, so both "sides" could be affected by injection.**

oke arbitrary expressions, i.e. perform injection attacks. For example, in some template languages, an attacker could inject the expression "{{7*7}}" and determine if the output returns "49" instead. The syntax varies depending on the language. 
 In some cases, XSS-style attacks can work, which can obscure the root cause if the developer does not closely investigate the root cause of the error. 
 Template engines can be used on the server or client, so both "sides" could be affected by injection. The mechanisms of attack or the affected technologies might be different, but the mistake is fundamentally the same. 
 
 
 
 
 

 

 
 
 
 
 
 
 
 Alternate Terms
 
 
 
 
 
 
 
 
 
 
 Server-Side Template Injection / SSTI
 
 
 This term is used for injection into template engines being used by a server. 
 
 
 
 
 
 Client-Side Template Injection / CSTI
 
 
 This term is used for injection into te

*Disproof:* Refuted when: the value is bound as a parameter or written through the framework's own encoder, so the interpreter never sees attacker text as syntax. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“Template engines can be used on the server or client, so both "sides" could be a”) does not occur under a test that isolates that control.

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

*Disproof:* Refuted when: the value is bound as a parameter or written through the framework's own encoder, so the interpreter never sees attacker text as syntax. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“The programmer might not use engine's built-in sandboxes or other capabilities t”) does not occur under a test that isolates that control.

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

*Disproof:* Refuted when: the value is bound as a parameter or written through the framework's own encoder, so the interpreter never sees attacker text as syntax. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“The programmer might not use engine's built-in sandboxes or other capabilities t”) does not occur under a test that isolates that control.

**If an attacker can influence input into a template before it is processed, then the attacker can invoke arbitrary expressions, i.e. perform injection attacks.**

ert externally-influenced values into free text or messages in order to generate a full web page, document, message, etc. Such engines include Twig, Jinja2, Pug, Java Server Pages, FreeMarker, Velocity, ColdFusion, Smarty, and many others - including PHP itself. Some CMS (Content Management Systems) also use templates. 
 Template engines often have their own custom command or expression language. If an attacker can influence input into a template before it is processed, then the attacker can invoke arbitrary expressions, i.e. perform injection attacks. For example, in some template languages, an attacker could inject the expression "{{7*7}}" and determine if the output returns "49" instead. The syntax varies depending on the language. 
 In some cases, XSS-style attacks can work, which can obscure the root cause if the developer does not closely investigate the root cause of the error. 
 Template engines can be used on the server or client, so b

*Disproof:* Refuted when: the value is bound as a parameter or written through the framework's own encoder, so the interpreter never sees attacker text as syntax. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“If an attacker can influence input into a template before it is processed, then ”) does not occur under a test that isolates that control.

**For example, in some template languages, an attacker could inject the expression "{{7*7}}" and determine if the output returns "49" instead.**

g, Java Server Pages, FreeMarker, Velocity, ColdFusion, Smarty, and many others - including PHP itself. Some CMS (Content Management Systems) also use templates. 
 Template engines often have their own custom command or expression language. If an attacker can influence input into a template before it is processed, then the attacker can invoke arbitrary expressions, i.e. perform injection attacks. For example, in some template languages, an attacker could inject the expression "{{7*7}}" and determine if the output returns "49" instead. The syntax varies depending on the language. 
 In some cases, XSS-style attacks can work, which can obscure the root cause if the developer does not closely investigate the root cause of the error. 
 Template engines can be used on the server or client, so both "sides" could be affected by injection. The mechanisms of attack or the affected technologies might be different, but the mistake is fund

*Disproof:* Refuted when: the value is bound as a parameter or written through the framework's own encoder, so the interpreter never sees attacker text as syntax. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“For example, in some template languages, an attacker could inject the expression”) does not occur under a test that isolates that control.

**Template engines can be used on the server or client, so both "sides" could be affected by injection.**

oke arbitrary expressions, i.e. perform injection attacks. For example, in some template languages, an attacker could inject the expression "{{7*7}}" and determine if the output returns "49" instead. The syntax varies depending on the language. 
 In some cases, XSS-style attacks can work, which can obscure the root cause if the developer does not closely investigate the root cause of the error. 
 Template engines can be used on the server or client, so both "sides" could be affected by injection. The mechanisms of attack or the affected technologies might be different, but the mistake is fundamentally the same. 
 
 
 
 
 

 

 
 
 
 
 
 
 
 Alternate Terms
 
 
 
 
 
 
 
 
 
 
 Server-Side Template Injection / SSTI
 
 
 This term is used for injection into template engines being used by a server. 
 
 
 
 
 
 Client-Side Template Injection / CSTI
 
 
 This term is used for injection into te

*Disproof:* Refuted when: the value is bound as a parameter or written through the framework's own encoder, so the interpreter never sees attacker text as syntax. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“Template engines can be used on the server or client, so both "sides" could be a”) does not occur under a test that isolates that control.

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

*Disproof:* Refuted when: the value is bound as a parameter or written through the framework's own encoder, so the interpreter never sees attacker text as syntax. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“The programmer might not use engine's built-in sandboxes or other capabilities t”) does not occur under a test that isolates that control.

**A template sandbox that pre-checks a dangerous keyword followed by a single space is bypassed by sending a tab in place of that space.**

Read the engine's guard as a string filter, not a parser: if the check is a keyword plus one literal space, send new followed by a tab instead of a space. SpEL treats the tab as ordinary whitespace and parses the expression, while the pre-check does not match. The same shape applies to any engine whose blocklist is defined over a restricted character set, so re-test with tab, newline and multiple-space variants before declaring the filter effective. Confirm by observing a type blocklist rejection with the space variant versus an accepted expression with the tab variant.

*Disproof:* If the tab variant is rejected by the same pre-check as the space variant, or is rejected by the downstream type blocklist, the filter is not the weak separator described here.

**Server-side template injection is proven by sending an arithmetic expression such as {{7*7}}; evaluating to 49 shows the template engine evaluated attacker input.**

In practice on HTB this shows up as: #### Initial Foothold 
- testing login the login form with SQLi as well as some guessing unable to login
- from the title of web page served on port 80 we see that its mentions title `{{.Title}}` from that info we can deduce that the web app is using some sort of template engine to serve the web contents 
- from the header for "Forgot Password" request to `/forgot`, we see that the server is running `Golang` 
![[header info.png]]

Write-up provenance: Ch4os1/WriteUps-HTB :: Medium/Unix/Gobox/writeup.md (738 words, classified web).

*Disproof:* Refuted when the expression is returned verbatim as literal text rather than evaluated, which shows the input is not reaching a template engine.

## Variations

**Automatic output escaping is an output-context control, not a template-context control, so it prevents an injected value from becoming markup while doing nothing to stop that value from being interpreted as template syntax before rendering.**

Mechanism: Automatic output escaping is an output-context control, not a template-context control, so it prevents an injected value from becoming markup while doing nothing to stop that value from being interpreted as template syntax before rendering. How to apply it in the field: treat this as the bypass it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable. Boundary of the rule: It does protect the response when the only attacker-controlled surface is a template variable whose value is escaped; it does not protect when the attacker controls the template string itself, because the engine parses that string before any escaping is applied, so the escaping layer is downstream of the compromise.

*Disproof:* It does protect the response when the only attacker-controlled surface is a template variable whose value is escaped; it does not protect when the attacker controls the template string itself, because the engine parses that string before any escaping is applied, so the escaping layer is downstream of the compromise.

## Technology / Framework Considerations

Not yet researched.

## API Considerations

Not yet researched.

## Attack Chains

- `chain.ssti.auto.01` — ssti: observe, exercise, confirm (goal: `Establish, exercise and confirm a ssti condition on an authorised target without relying on anyone else's data.`)

## Real-World Examples

Not yet researched.

## Common False Positives

**A sandboxed template environment is not a security proof, since the documentation states the sandbox alone is not a solution for perfect security and that resource-exhaustion and side-effecting objects remain outside what it prevents.**

Mechanism: A sandboxed template environment is not a security proof, since the documentation states the sandbox alone is not a solution for perfect security and that resource-exhaustion and side-effecting objects remain outside what it prevents. How to apply it in the field: treat this as the fp_rule it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable. Boundary of the rule: It IS effective for the specific primitive it blocks when attribute and method access are genuinely intercepted, which is why a private-attribute probe is rejected; it is NOT sufficient on its own when the attacker reaches resource exhaustion, a passed-in object with side effects, or an output context the template does not understand, and the report must name which of those was actually shown.

*Disproof:* It IS effective for the specific primitive it blocks when attribute and method access are genuinely intercepted, which is why a private-attribute probe is rejected; it is NOT sufficient on its own when the attacker reaches resource exhaustion, a passed-in object with side effects, or an output context the template does not understand, and the report must name which of those was actually shown.

**A template injection finding is only proved when the response shows the engine evaluating template syntax, not when it shows the payload reflected literally, because a reflection result is explained by ordinary output encoding and proves nothing about the engine.**

Mechanism: A template injection finding is only proved when the response shows the engine evaluating template syntax, not when it shows the payload reflected literally, because a reflection result is explained by ordinary output encoding and proves nothing about the engine. How to apply it in the field: treat this as the fp_rule it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable. Boundary of the rule: It IS template injection when a sentinel expression is computed and the computed result appears in the response rather than the expression text; it is NOT when the response contains the payload unchanged, in which case the correct finding is reflected content or XSS at most, and the SSTI claim must be withdrawn.

*Disproof:* It IS template injection when a sentinel expression is computed and the computed result appears in the response rather than the expression text; it is NOT when the response contains the payload unchanged, in which case the correct finding is reflected content or XSS at most, and the SSTI claim must be withdrawn.

**A template engine error message that names the injected payload does not prove the payload was evaluated; a compiler or render error can equally be triggered by malformed template syntax, so error text alone is ambiguous evidence.**

Mechanism: A template engine error message that names the injected payload does not prove the payload was evaluated; a compiler or render error can equally be triggered by malformed template syntax, so error text alone is ambiguous evidence. How to apply it in the field: treat this as the fp_rule it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable. Boundary of the rule: It becomes proof when the error is specific to evaluation rather than to parsing, for example a division or type error raised by a syntactically valid expression, which shows the engine executed past parsing; a generic parse error on malformed braces indicates only that the string reached the parser, which is weaker but still real evidence that the template boundary was crossed.

*Disproof:* It becomes proof when the error is specific to evaluation rather than to parsing, for example a division or type error raised by a syntactically valid expression, which shows the engine executed past parsing; a generic parse error on malformed braces indicates only that the string reached the parser, which is weaker but still real evidence that the template boundary was crossed.

**A template expression like {{7*7}} echoed back literally in the response is a false SSTI; the report needs the value 49 to appear where the expression was.**

Discard the finding when your arithmetic probe comes back verbatim, braces intact, because the target reflected your input into a page or JSON field without ever handing it to a template engine, which makes the signal reflection noise rather than template injection. The finding survives when the evaluated result appears, when a second engine-specific expression evaluates differently from the literal, or when an out-of-band command executes, since that cannot happen without the engine having parsed your input.

*Disproof:* If the literal echo only appears in a field the application later renders client-side through a JavaScript template engine, the server did not evaluate it and the report belongs to the client-side class, not to server-side template injection.

**A DNS callback received after an SSTI payload is not proof of server-side template evaluation unless the callback type is one your payload alone could have triggered.**

Discard the SSTI report when the only signal is a bare DNS resolution for your OAST domain, because recursive resolvers, prefetchers, mail scanners, and your own tooling generate ordinary lookups that land on the same listener. The finding survives only when the callback is a record type your template expression would have caused, such as an SRV query from an nslookup call embedded in the expression, or when the resolved payload string appears in the response body so you can attribute the lookup to template evaluation.

*Disproof:* If a plain baseline request with no template payload produces the same callback type and rate against your listener, the listener is the signal and not the target, so the SSTI claim has no surviving evidence.

## Validation

**The convincing validation pair sends a template expression whose result is a computed value, and the finding stands only when that computed value appears in the response, because a reflected expression could be produced by any endpoint that echoes input.**

Mechanism: The convincing validation pair sends a template expression whose result is a computed value, and the finding stands only when that computed value appears in the response, because a reflected expression could be produced by any endpoint that echoes input. How to apply it in the field: treat this as the validation it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable. Boundary of the rule: If the response shows the expression text unchanged or a fixed error mentioning the marker without evaluating it, the proof fails; the pair is convincing only when the returned value is something the server could not have known to echo literally, which is what distinguishes evaluation from reflection.

*Disproof:* If the response shows the expression text unchanged or a fixed error mentioning the marker without evaluating it, the proof fails; the pair is convincing only when the returned value is something the server could not have known to echo literally, which is what distinguishes evaluation from reflection.

**To decide this case, observe: Discard the SSTI report when the only signal is a bare DNS resolution for your OAST domain, because recursive resolvers, prefetchers, mail scanners, and your own tooling generate ordinary lookups that land on the same listener.**

Derived from ssti.fprule.generic_oob_dns_callback_is_not_evidence, which states the false-positive boundary for this class. The observable above is what separates a real finding from the pattern that only looks like one. A hunter who cannot produce this observation in a request/response pair does not have a finding yet.

*Disproof:* This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (ssti.fprule.generic_oob_dns_callback_is_not_evidence) states the full boundary.

**To decide this case, observe: How to apply it in the field: treat this as the fp_rule it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable.**

Derived from ssti.fp_rule.a_sandbox_is_not_a_proof_that_the_template_is_safe, which states the false-positive boundary for this class. The observable above is what separates a real finding from the pattern that only looks like one. A hunter who cannot produce this observation in a request/response pair does not have a finding yet.

*Disproof:* This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (ssti.fp_rule.a_sandbox_is_not_a_proof_that_the_template_is_safe) states the full boundary.

**To decide this case, observe: How to apply it in the field: treat this as the fp_rule it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable.**

Derived from ssti.fp_rule.template_error_messages_alone_do_not_prove_ssti, which states the false-positive boundary for this class. The observable above is what separates a real finding from the pattern that only looks like one. A hunter who cannot produce this observation in a request/response pair does not have a finding yet.

*Disproof:* This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (ssti.fp_rule.template_error_messages_alone_do_not_prove_ssti) states the full boundary.

**To decide this case, observe: How to apply it in the field: treat this as the fp_rule it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable.**

Derived from ssti.fp_rule.arithmetic_evaluation_is_evaluation_not_just_reflection, which states the false-positive boundary for this class. The observable above is what separates a real finding from the pattern that only looks like one. A hunter who cannot produce this observation in a request/response pair does not have a finding yet.

*Disproof:* This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (ssti.fp_rule.arithmetic_evaluation_is_evaluation_not_just_reflection) states the full boundary.

**To decide this case, observe: How to apply it in the field: treat this as the bypass it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable.**

Derived from ssti.bypass.autoescape_does_not_defend_the_template_context, which states the false-positive boundary for this class. The observable above is what separates a real finding from the pattern that only looks like one. A hunter who cannot produce this observation in a request/response pair does not have a finding yet.

*Disproof:* This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (ssti.bypass.autoescape_does_not_defend_the_template_context) states the full boundary.

**The same template payloads used to prove server-side template injection are the right probe for the client-side case, because the client interpreter also expects a template and executes whatever it is handed; a field that renders template syntax as literal text is a clean negative.**

The same template payloads used to prove server-side template injection are the right probe for the client-side case, because the client interpreter also expects a template and executes whatever it is handed; a field that renders template syntax as literal text is a clean negative.

HackTricks reference: Client Side Template Injection (CSTI) (pentesting-web/client-side-template-injection-csti.md)

*Disproof:* Template payloads that render as inert literal text in the client interpreter, or a server-side payload whose result differs from the client-side one on identical input, refutes the equivalence.

**The whole defence for server-side template injection sits at one boundary, the insertion of user input into the template, so that is the only place worth verifying rather than trusting escaping applied somewhere else in the flow.**

The whole defence for server-side template injection sits at one boundary, the insertion of user input into the template, so that is the only place worth verifying rather than trusting escaping applied somewhere else in the flow.

HackTricks reference: SSTI (Server Side Template Injection) (pentesting-web/ssti-server-side-template-injection/README.md)

*Disproof:* Template syntax surviving insertion into the template and being evaluated by the engine refutes sanitization and validation happening at that insertion point.

**To decide this case, observe: Mechanism: The convincing validation pair sends a template expression whose result is a computed value, and the finding stands only when that computed value appears in the response, because a reflected expression could be produced by any endpoint that echoes input.**

Derived from ssti.validation.prove_evaluation_with_arithmetic_that_the_response_could_not_have_produced, which states the false-positive boundary for this class. The observable above is what separates a real finding from the pattern that only looks like one. A hunter who cannot produce this observation in a request/response pair does not have a finding yet.

*Disproof:* This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (ssti.validation.prove_evaluation_with_arithmetic_that_the_response_could_not_have_produced) states the full boundary.

## Impact

**Where the template is evaluated decides the ceiling of the finding: a client-side injection buys arbitrary JavaScript in the victim's browser, not code execution on the remote server, so the two must not be reported with the same severity.**

Where the template is evaluated decides the ceiling of the finding: a client-side injection buys arbitrary JavaScript in the victim's browser, not code execution on the remote server, so the two must not be reported with the same severity.

HackTricks reference: Client Side Template Injection (CSTI) (pentesting-web/client-side-template-injection-csti.md)

*Disproof:* A client-side template injection that yields code execution on the remote server, or that produces no JavaScript execution in the victim's browser at all, refutes this impact boundary.

**With Jinja as the engine, it is the Jinja directives inside the injected template that turn template injection into code execution and control of the engine itself, so identifying the engine decides what the finding is worth.**

With Jinja as the engine, it is the Jinja directives inside the injected template that turn template injection into code execution and control of the engine itself, so identifying the engine decides what the finding is worth.

HackTricks reference: SSTI (Server Side Template Injection) (pentesting-web/ssti-server-side-template-injection/README.md)

*Disproof:* Jinja syntax injected into a template that renders as literal text with no directive evaluated and no code execution, refutes this mechanism.

## Related Bug Classes

Not yet researched.

## References

- **blog.qualys.com** (writeup)
  - <https://blog.qualys.com/vulnerabilities-threat-research/2016/08/31/thwarting-sql-injection-defense-in-depth>
- **cwe.mitre.org** (taxonomy)
  - <https://cwe.mitre.org/data/definitions/1336.html>
- **httpwg.org** (standard)
  - <https://httpwg.org/specs/rfc9110.html>
- **jinja.palletsprojects.com** (research)
  - <https://jinja.palletsprojects.com/en/stable/sandbox/>
- **nccgroup.com** (report)
  - <https://www.nccgroup.com/research/technical-advisory-pulse-connect-secure-rce-via-template-injection-cve-2020-8243/>
- **portswigger.net** (cheatsheet)
  - <https://portswigger.net/web-security/server-side-template-injection>
- **projectdiscovery.io** (writeup)
  - <https://projectdiscovery.io/blog/crafting-dast-nuclei-templates-for-oob-template-engines-injection-a-practical-guide>
  - <https://projectdiscovery.io/blog/inside-the-benchmark-pp-architectures-finding-walkthroughs-and-what-each-scanner-actually-caught>
- **raw.githubusercontent.com** (writeup)
  - <https://raw.githubusercontent.com/Ch4os1/WriteUps-HTB/main/Medium/Unix/Gobox/writeup.md>
  - <https://raw.githubusercontent.com/Esther7171/HackTheBox-Writeups-Walkthroughs/main/Write-ups/Academy/05.%20Web%20Exploitation/31d.%20Server-side%20Attacks/Server-side%20Attacks.md>
  - <https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/pentesting-web/client-side-template-injection-csti.md>
  - <https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/pentesting-web/ssti-server-side-template-injection/README.md>
- **snyk.io** (research)
  - <https://snyk.io/blog/thymeleaf-injection/>
- **twig.symfony.com** (writeup)
  - <https://twig.symfony.com/doc/api.html>
  - <https://twig.symfony.com/doc/templates.html>

Every item above is gated on >= 2 distinct publisher hosts (`wks/quality.py`, rule R1). Publisher diversity, not citation count, is what makes these corroborated.
