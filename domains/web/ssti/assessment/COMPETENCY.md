# Methodology — Server-Side Template Injection

> Derived from 11 verified items. Regenerate with `python -m wks.methodgen --class ssti --apply`. Do not hand-edit: this file is a projection of the evidence, and edits are lost on the next cycle.

**Surface.** Untrusted input is compiled by the template engine rather than treated as data, so the engine's expression language executes.

**References.** CWE-1336 · A03:2021

## 1. Preconditions

_Nothing below is reachable until these hold. Confirm each against the target before spending time on the technique._

**Thymeleaf SpEL injection needs request data to reach the expression engine or a dynamically built view name, not merely the data model.**

Enumerate every endpoint whose response is produced by a template engine and ask whether the view name or template expression is itself constructed from a request parameter, rather than the parameter only being bound into the data model. Where the parameter only enters the model, no expression parsing happens and no sandbox is engaged. Where the app builds template strings or resolves views from input, manual wiring of the engine is usually required, which makes it visible in the response shape. Test by sending an expression metacharacter in the candidate parameter and comparing the response against a control value that never enters the engine.

- *Disproof:* Sending arithmetic or expression metacharacters through the parameter and getting the input back as inert data (no evaluation, no error, no type coercion) shows the value never reaches the expression engine.
- *Evidence:* high_confidence — [nccgroup.com](https://www.nccgroup.com/research/technical-advisory-pulse-connect-secure-rce-via-template-injection-cve-2020-8243/); [snyk.io](https://snyk.io/blog/thymeleaf-injection/)

## Reconnaissance signals

_No verified signal items yet._ Derived from evidence only, so this section is empty rather than plausible.


## 2. Test sequence

_Concrete mutations to try. Each is written to be executable, not to be a description of the vulnerability._

**A template sandbox that pre-checks a dangerous keyword followed by a single space is bypassed by sending a tab in place of that space.**

Read the engine's guard as a string filter, not a parser: if the check is a keyword plus one literal space, send new followed by a tab instead of a space. SpEL treats the tab as ordinary whitespace and parses the expression, while the pre-check does not match. The same shape applies to any engine whose blocklist is defined over a restricted character set, so re-test with tab, newline and multiple-space variants before declaring the filter effective. Confirm by observing a type blocklist rejection with the space variant versus an accepted expression with the tab variant.

- *Disproof:* If the tab variant is rejected by the same pre-check as the space variant, or is rejected by the downstream type blocklist, the filter is not the weak separator described here.
- *Evidence:* high_confidence — [nccgroup.com](https://www.nccgroup.com/research/technical-advisory-pulse-connect-secure-rce-via-template-injection-cve-2020-8243/); [snyk.io](https://snyk.io/blog/thymeleaf-injection/)

## 3. Validation

_How to prove the finding rather than infer it. A technique that cannot be validated must not be reported._

**The convincing validation pair sends a template expression whose result is a computed value, and the finding stands only when that computed value appears in the response, because a reflected expression could be produced by any endpoint that echoes input.**

Mechanism: The convincing validation pair sends a template expression whose result is a computed value, and the finding stands only when that computed value appears in the response, because a reflected expression could be produced by any endpoint that echoes input. How to apply it in the field: treat this as the validation it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable. Boundary of the rule: If the response shows the expression text unchanged or a fixed error mentioning the marker without evaluating it, the proof fails; the pair is convincing only when the returned value is something the server could not have known to echo literally, which is what distinguishes evaluation from reflection.

- *Disproof:* If the response shows the expression text unchanged or a fixed error mentioning the marker without evaluating it, the proof fails; the pair is convincing only when the returned value is something the server could not have known to echo literally, which is what distinguishes evaluation from reflection.
- *Evidence:* high_confidence — [jinja.palletsprojects.com](https://jinja.palletsprojects.com/en/stable/sandbox/); [twig.symfony.com](https://twig.symfony.com/doc/templates.html)

## 4. False-positive rejection

_The checks that eliminate the most common non-findings. Run these BEFORE reporting, not after a rejection._

**A template expression like {{7*7}} echoed back literally in the response is a false SSTI; the report needs the value 49 to appear where the expression was.**

Discard the finding when your arithmetic probe comes back verbatim, braces intact, because the target reflected your input into a page or JSON field without ever handing it to a template engine, which makes the signal reflection noise rather than template injection. The finding survives when the evaluated result appears, when a second engine-specific expression evaluates differently from the literal, or when an out-of-band command executes, since that cannot happen without the engine having parsed your input.

- *Disproof:* If the literal echo only appears in a field the application later renders client-side through a JavaScript template engine, the server did not evaluate it and the report belongs to the client-side class, not to server-side template injection.
- *Evidence:* high_confidence — [httpwg.org](https://httpwg.org/specs/rfc9110.html); [projectdiscovery.io](https://projectdiscovery.io/blog/inside-the-benchmark-pp-architectures-finding-walkthroughs-and-what-each-scanner-actually-caught)

**A DNS callback received after an SSTI payload is not proof of server-side template evaluation unless the callback type is one your payload alone could have triggered.**

Discard the SSTI report when the only signal is a bare DNS resolution for your OAST domain, because recursive resolvers, prefetchers, mail scanners, and your own tooling generate ordinary lookups that land on the same listener. The finding survives only when the callback is a record type your template expression would have caused, such as an SRV query from an nslookup call embedded in the expression, or when the resolved payload string appears in the response body so you can attribute the lookup to template evaluation.

- *Disproof:* If a plain baseline request with no template payload produces the same callback type and rate against your listener, the listener is the signal and not the target, so the SSTI claim has no surviving evidence.
- *Evidence:* high_confidence — [blog.qualys.com](https://blog.qualys.com/vulnerabilities-threat-research/2016/08/31/thwarting-sql-injection-defense-in-depth); [projectdiscovery.io](https://projectdiscovery.io/blog/inside-the-benchmark-pp-architectures-finding-walkthroughs-and-what-each-scanner-actually-caught)

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


## Impact

_No verified impact items yet._ Derived from evidence only, so this section is empty rather than plausible.


## Coverage gap

These stages have no verified evidence and are therefore absent above: Reconnaissance signals, Chaining, Impact.
A procedure with a missing validation stage is not safe to act on — it produces findings rather than proofs.

---

*Generated from the evidence base. Where this file and the database disagree, the database is correct.*
