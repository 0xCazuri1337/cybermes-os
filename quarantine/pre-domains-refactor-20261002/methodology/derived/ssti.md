# Methodology — Server-Side Template Injection

> Derived from 7 verified items. Regenerate with `python -m wks.methodgen --class ssti --apply`. Do not hand-edit: this file is a projection of the evidence, and edits are lost on the next cycle.

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

**If an attacker can influence input into a template before it is processed, then the attacker can invoke arbitrary expressions, i.e. perform injection attacks.**

ert externally-influenced values into free text or messages in order to generate a full web page, document, message, etc. Such engines include Twig, Jinja2, Pug, Java Server Pages, FreeMarker, Velocity, ColdFusion, Smarty, and many others - including PHP itself. Some CMS (Content Management Systems) also use templates. 
 Template engines often have their own custom command or expression language. If an attacker can influence input into a template before it is processed, then the attacker can invoke arbitrary expressions, i.e. perform injection attacks. For example, in some template languages, an attacker could inject the expression "{{7*7}}" and determine if the output returns "49" instead. The syntax varies depending on the language. 
 In some cases, XSS-style attacks can work, which can obscure the root cause if the developer does not closely investigate the root cause of the error. 
 Template engines can be used on the server or client, so b

- *Disproof:* This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "If an attacker can influence input into a template before it is processed, then the attack".
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

- *Disproof:* This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Template engines can be used on the server or client, so both "sides" could be affected by".
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

- *Disproof:* This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "The programmer might not use engine's built-in sandboxes or other capabilities to escape o".
- *Evidence:* high_confidence — [cwe.mitre.org](https://cwe.mitre.org/data/definitions/1336.html); [portswigger.net](https://portswigger.net/web-security/server-side-template-injection)

## Validation

_No verified validation items yet._ Derived from evidence only, so this section is empty rather than plausible.


## 3. False-positive rejection

_The checks that eliminate the most common non-findings. Run these BEFORE reporting, not after a rejection._

**A template expression like {{7*7}} echoed back literally in the response is a false SSTI; the report needs the value 49 to appear where the expression was.**

Discard the finding when your arithmetic probe comes back verbatim, braces intact, because the target reflected your input into a page or JSON field without ever handing it to a template engine, which makes the signal reflection noise rather than template injection. The finding survives when the evaluated result appears, when a second engine-specific expression evaluates differently from the literal, or when an out-of-band command executes, since that cannot happen without the engine having parsed your input.

- *Disproof:* If the literal echo only appears in a field the application later renders client-side through a JavaScript template engine, the server did not evaluate it and the report belongs to the client-side class, not to server-side template injection.
- *Evidence:* high_confidence — [httpwg.org](https://httpwg.org/specs/rfc9110.html); [projectdiscovery.io](https://projectdiscovery.io/blog/inside-the-benchmark-pp-architectures-finding-walkthroughs-and-what-each-scanner-actually-caught)

**A DNS callback received after an SSTI payload is not proof of server-side template evaluation unless the callback type is one your payload alone could have triggered.**

Discard the SSTI report when the only signal is a bare DNS resolution for your OAST domain, because recursive resolvers, prefetchers, mail scanners, and your own tooling generate ordinary lookups that land on the same listener. The finding survives only when the callback is a record type your template expression would have caused, such as an SRV query from an nslookup call embedded in the expression, or when the resolved payload string appears in the response body so you can attribute the lookup to template evaluation.

- *Disproof:* If a plain baseline request with no template payload produces the same callback type and rate against your listener, the listener is the signal and not the target, so the SSTI claim has no surviving evidence.
- *Evidence:* high_confidence — [blog.qualys.com](https://blog.qualys.com/vulnerabilities-threat-research/2016/08/31/thwarting-sql-injection-defense-in-depth); [projectdiscovery.io](https://projectdiscovery.io/blog/inside-the-benchmark-pp-architectures-finding-walkthroughs-and-what-each-scanner-actually-caught)

## Known bypasses

_No verified bypass items yet._ Derived from evidence only, so this section is empty rather than plausible.


## Chaining

_No verified chain_link items yet._ Derived from evidence only, so this section is empty rather than plausible.


## Impact

_No verified impact items yet._ Derived from evidence only, so this section is empty rather than plausible.


## Coverage gap

These stages have no verified evidence and are therefore absent above: Reconnaissance signals, Validation, Known bypasses, Chaining, Impact.
A procedure with a missing validation stage is not safe to act on — it produces findings rather than proofs.

---

*Generated from the evidence base. Where this file and the database disagree, the database is correct.*
