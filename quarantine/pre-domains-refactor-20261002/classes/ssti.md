# Server-Side Template Injection

> surface: `web` · CWE: CWE-1336 · OWASP: A03:2021
> maturity: **researching** — 7 items, 7 supported, 2 FP rules, 0 chains

Untrusted input is compiled by the template engine rather than treated as data, so the engine's expression language executes.

**Aliases:** ssti, server side template injection, template injection, jinja2 ssti, twig template injection

## Prerequisite

- **Thymeleaf SpEL injection needs request data to reach the expression engine or a dynamically built view name, not merely the data model.**  
  `high_confidence` · score 0.929 · disproved by: Sending arithmetic or expression metacharacters through the parameter and getting the input back as inert data (no evaluation, no error, no type coercion) shows the value never reaches the expression engine.
  sources: <https://snyk.io/blog/thymeleaf-injection/> · <https://www.nccgroup.com/research/technical-advisory-pulse-connect-secure-rce-via-template-injection-cve-2020-8243/>

## Technique

- **A template sandbox that pre-checks a dangerous keyword followed by a single space is bypassed by sending a tab in place of that space.**  
  `high_confidence` · score 0.819 · disproved by: If the tab variant is rejected by the same pre-check as the space variant, or is rejected by the downstream type blocklist, the filter is not the weak separator described here.
  sources: <https://snyk.io/blog/thymeleaf-injection/> · <https://www.nccgroup.com/research/technical-advisory-pulse-connect-secure-rce-via-template-injection-cve-2020-8243/>
- **If an attacker can influence input into a template before it is processed, then the attacker can invoke arbitrary expressions, i.e. perform injection attacks.**  
  `high_confidence` · score 0.778 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "If an attacker can influence input into a template before it is processed, then the attack".
  sources: <https://cwe.mitre.org/data/definitions/1336.html> · <https://portswigger.net/web-security/server-side-template-injection>
- **Template engines can be used on the server or client, so both "sides" could be affected by injection.**  
  `high_confidence` · score 0.778 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Template engines can be used on the server or client, so both "sides" could be affected by".
  sources: <https://cwe.mitre.org/data/definitions/1336.html> · <https://portswigger.net/web-security/server-side-template-injection>
- **The programmer might not use engine's built-in sandboxes or other capabilities to escape or otherwise prevent template injection from untrusted input.**  
  `high_confidence` · score 0.778 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "The programmer might not use engine's built-in sandboxes or other capabilities to escape o".
  sources: <https://cwe.mitre.org/data/definitions/1336.html> · <https://portswigger.net/web-security/server-side-template-injection>

## Fp Rule

- **A template expression like {{7*7}} echoed back literally in the response is a false SSTI; the report needs the value 49 to appear where the expression was.**  
  `high_confidence` · score 0.945 · disproved by: If the literal echo only appears in a field the application later renders client-side through a JavaScript template engine, the server did not evaluate it and the report belongs to the client-side class, not to server-side template injection.
  sources: <https://httpwg.org/specs/rfc9110.html> · <https://projectdiscovery.io/blog/crafting-dast-nuclei-templates-for-oob-template-engines-injection-a-practical-guide> · <https://projectdiscovery.io/blog/inside-the-benchmark-pp-architectures-finding-walkthroughs-and-what-each-scanner-actually-caught>
- **A DNS callback received after an SSTI payload is not proof of server-side template evaluation unless the callback type is one your payload alone could have triggered.**  
  `high_confidence` · score 0.89 · disproved by: If a plain baseline request with no template payload produces the same callback type and rate against your listener, the listener is the signal and not the target, so the SSTI claim has no surviving evidence.
  sources: <https://blog.qualys.com/vulnerabilities-threat-research/2016/08/31/thwarting-sql-injection-defense-in-depth> · <https://projectdiscovery.io/blog/crafting-dast-nuclei-templates-for-oob-template-engines-injection-a-practical-guide> · <https://projectdiscovery.io/blog/inside-the-benchmark-pp-architectures-finding-walkthroughs-and-what-each-scanner-actually-caught>

## Known gaps

Not yet satisfied: `items`, `chain`
