# Server-Side Template Injection

## Definition

Untrusted input is compiled by the template engine rather than treated as data, so the engine's expression language executes.

- **CWE:** CWE-1336
- **OWASP:** A03:2021
- **Surface:** web
- **Aliases:** ["ssti", "server side template injection", "template injection", "jinja2 ssti", "twig template injection"]

Canonical home for `ssti`. Rendered from `db/wks.db` by `methodology/scripts/build_taxonomy.py` — edit the rows, not this file.

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

Not yet researched.

## Exploitation

**A template sandbox that pre-checks a dangerous keyword followed by a single space is bypassed by sending a tab in place of that space.**

Read the engine's guard as a string filter, not a parser: if the check is a keyword plus one literal space, send new followed by a tab instead of a space. SpEL treats the tab as ordinary whitespace and parses the expression, while the pre-check does not match. The same shape applies to any engine whose blocklist is defined over a restricted character set, so re-test with tab, newline and multiple-space variants before declaring the filter effective. Confirm by observing a type blocklist rejection with the space variant versus an accepted expression with the tab variant.

*Disproof:* If the tab variant is rejected by the same pre-check as the space variant, or is rejected by the downstream type blocklist, the filter is not the weak separator described here.

## Variations

Not yet researched.

## Technology / Framework Considerations

Not yet researched.

## API Considerations

Not yet researched.

## Attack Chains

Not yet researched.

## Real-World Examples

Not yet researched.

## Common False Positives

**A template expression like {{7*7}} echoed back literally in the response is a false SSTI; the report needs the value 49 to appear where the expression was.**

Discard the finding when your arithmetic probe comes back verbatim, braces intact, because the target reflected your input into a page or JSON field without ever handing it to a template engine, which makes the signal reflection noise rather than template injection. The finding survives when the evaluated result appears, when a second engine-specific expression evaluates differently from the literal, or when an out-of-band command executes, since that cannot happen without the engine having parsed your input.

*Disproof:* If the literal echo only appears in a field the application later renders client-side through a JavaScript template engine, the server did not evaluate it and the report belongs to the client-side class, not to server-side template injection.

**A DNS callback received after an SSTI payload is not proof of server-side template evaluation unless the callback type is one your payload alone could have triggered.**

Discard the SSTI report when the only signal is a bare DNS resolution for your OAST domain, because recursive resolvers, prefetchers, mail scanners, and your own tooling generate ordinary lookups that land on the same listener. The finding survives only when the callback is a record type your template expression would have caused, such as an SRV query from an nslookup call embedded in the expression, or when the resolved payload string appears in the response body so you can attribute the lookup to template evaluation.

*Disproof:* If a plain baseline request with no template payload produces the same callback type and rate against your listener, the listener is the signal and not the target, so the SSTI claim has no surviving evidence.

## Validation

Not yet researched.

## Impact

Not yet researched.

## Related Bug Classes

Not yet researched.

## References

- **blog.qualys.com** (writeup)
  - <https://blog.qualys.com/vulnerabilities-threat-research/2016/08/31/thwarting-sql-injection-defense-in-depth>
- **httpwg.org** (standard)
  - <https://httpwg.org/specs/rfc9110.html>
- **nccgroup.com** (report)
  - <https://www.nccgroup.com/research/technical-advisory-pulse-connect-secure-rce-via-template-injection-cve-2020-8243/>
- **projectdiscovery.io** (writeup)
  - <https://projectdiscovery.io/blog/crafting-dast-nuclei-templates-for-oob-template-engines-injection-a-practical-guide>
  - <https://projectdiscovery.io/blog/inside-the-benchmark-pp-architectures-finding-walkthroughs-and-what-each-scanner-actually-caught>
- **snyk.io** (writeup)
  - <https://snyk.io/blog/thymeleaf-injection/>

Every item above is gated on >= 2 distinct publisher hosts (`wks/quality.py`, rule R1). Publisher diversity, not citation count, is what makes these corroborated.
