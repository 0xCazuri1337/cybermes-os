# LDAP / XPath / NoSQL-Style Injection

## Definition

A filter or path expression is built from attacker input, changing the query structure.

- **CWE:** 90
- **OWASP:** A03:2021
- **Surface:** web
- **Aliases:** ["ldap injection", "xpath injection", "orm injection"]

Canonical home for `ldap`. Rendered from `db/wks.db` by `methodology/scripts/build_taxonomy.py` — edit the rows, not this file.

## Root Cause

Not yet researched.

## Preconditions

Not yet researched.

## Attack Surface

Surface: **web**.

The entry points and enabling conditions for this surface are enumerated under **Preconditions**; the observable signals are under **Detection**.

## Detection

**A widened or non-empty result set for a filter that should have matched nothing, carrying directory attributes the application never renders on a normal miss, is the observable signature of a request-controlled filter structure.**

Signal, not proof. Send a value that cannot match any real object, for example a random high-entropy string, and record the application's normal empty-result path. The variant appends a boolean operator and a clause that makes the filter match broadly. If the response changes from no-results to a populated list, and the payload now carries attributes the app only ever emits for real matches - SID, DNT, DN, objectGUID, userAccountControl - then the filter's structure was request-controlled. The attribute differential is what separates this from a cosmetic application bug: a frontend wildcard in the app's own UI would not cause the backend to return directory attributes it has no reason to expose. TrustedSec's DIT work supplies the vocabulary for reading what came back: in the LDAP world, objects are identified by their distinguished name, or DN, and an RDN refers to the individual components of a distinguished name and identifies an object within its parent, so a DN or objectGUID appearing where the app should have shown nothing is a directory-origin artefact. Which attributes are worth requesting is not arbitrary either - BHIS notes that BloodHound, AdExplorer, ADFind and other LDAP enumerators read the UAC value for discovered objects. Caveat to state in the report: a widened result set proves the filter changed, not yet what an attacker can extract.

*Disproof:* Show that the application's own empty-result path already returns a populated template, or that the attributes in the response are rendered by the frontend from data it fetched on a separate call. Then the widened response is application behaviour rather than directory-side filter evaluation.

## Exploitation

**Where a web-facing application performs an LDAP bind over TLS to a domain controller, the reachable post-injection step is relay of that bind to the DC's LDAPS listener, whose precondition is an absent or strippable client-side message-integrity check.**

Describe the test, do not run it: an application whose auth path binds to AD over LDAPS creates a channel a man-in-the-middle can attempt to terminate. BHIS's relay walkthrough states the routing constraint plainly - LDAP is only available on domain controllers, therefore we must target a domain controller in an LDAP relay attack. The precondition is the message integrity code carried on the NTLM authenticate message: Black Hills' baseline attempt returned 'The client requested signing. Relaying to LDAP will not work!', and they describe the case where, when MIC is not included, the connection from SMB can be relayed to LDAPS. So what you are establishing is whether the application's bind is relayable, which is a property of the client and its patch state rather than of the injection itself - and that is why this belongs in a report as a conditional post-exploitation step, not a claim. The hunt-side corollary is that TrustedSec's LDAP-signing guidance names SMB/LDAP signing plus channel binding enforcement as the control and notes adoption remains low, so an LDAPS bind from an application that presents no channel binding token is exactly the event worth alerting on.

*Disproof:* Show that the application's LDAPS bind presents a channel binding token and that the target DC enforces validation, so a relayed bind is rejected at the TLS layer. Then the bind is not relayable and the post-injection step does not exist.

## Variations

**A domain controller left at the default channel binding policy accepts a bind that carries no channel binding token at all, so relay protection is off unless the policy has been explicitly raised - and only the Always setting actually blocks the bind.**

The bypass is configuration, not technique. TrustedSec lists the three domain controller options for LDAP server channel binding token requirements and marks the shipped default as Never, with When Supported as audit-only and Always as the value that actually rejects. The When Supported setting is the trap: it permits event generation but does not enforce validation, so systems that do not comply continue to communicate with AD, and an assessor reading the policy sees a non-default value and assumes protection is active. The audit-first design is deliberate and is why the guidance says a 30-day period of audit activity should be sufficient, with Event IDs 3074 and 3075 used to find the offenders before enforcement. Detection side of the same bypass: 3075 is specifically the client that performed an LDAP bind over SSL/TLS and did not provide Channel Binding Information, and these events include a source IP address that can be used to track down the offending application - so the bypass is detectable by log review alone. Validating the claim on a target: read the DC policy value, and confirm whether a token-less bind is rejected or merely logged.

*Disproof:* Show the domain controllers have channel binding token requirements set to Always with logging enabled, and that a bind carrying no channel binding token is rejected by the DC rather than merely logged. Then relay protection is active and the bypass does not exist on that target.

## Technology / Framework Considerations

Not yet researched.

## API Considerations

Not yet researched.

## Attack Chains

Not yet researched.

## Real-World Examples

Not yet researched.

## Common False Positives

**A search filter that errors or returns an identical failure for EVERY input, including well-formed values the application has matched before, is an application type-confusion or bind-failure bug and not LDAP injection.**

This is the most expensive LDAP false positive: claiming injection because you sent a malformed filter and got an error back. Error responses are also what a bind failure, a null reference from passing a non-string, or an app-side validation layer produce. The discriminating test is three inputs, always: a known-good value the application has matched before, a random non-matching value, and a value carrying filter metacharacters. If the error is identical across all three, the filter never reached the directory with your bytes in it and the finding is an application bug. Only a differential - good and non-matching both behave normally while metacharacters behave differently - supports injection. Mandiant's write-up supports exactly this discipline: it traces whether user input actually reaches the dangerous sink before classifying anything, and it routes results that do not match ground truth to a dedicated false-positive triage stage that must classify findings definitively rather than by resemblance. Second supporting point for the report: an LDAP bind can fail for reasons unrelated to the filter at all, so a bind error must be separated from a search error before either is called injection. The rule: the error itself is never the evidence; the differential against a known-good control is.

*Disproof:* Show a known-good value and a random non-matching value produce the SAME error, status, and timing as a metacharacter-bearing value, with no differential in any response field. Then there is no filter-structure control and the injection claim is unsupported.

## Validation

**An LDAP injection test is only meaningful after confirming which directory attribute the request-controlled value lands in, because the returned attribute set of a benign query reveals the server-side mapping without any injection being required.**

Validation step that requires no malicious input and often settles the whole question. Issue a benign query with a value you know matches a real object, and read which attributes come back. Those attributes are the ones the server put in the filter or the search scope, and they tell you the mapping. TrustedSec's Titanis cheatsheet shows the mapping plainly: the SPN mapping query is written against servicePrincipalName and returns sAMAccountName, sAMAccountType and servicePrincipalName, so the requested-attribute list is an exact fingerprint of what the filter touched. BHIS supplies the matching field-level fingerprint on the AD side, noting that BloodHound, AdExplorer, ADFind and other LDAP enumerators read the UAC value for discovered objects - meaning userAccountControl is a field genuinely in demand and therefore genuinely worth mapping. The falsification test: if a benign request with a known-good value returns an attribute set that does not change when you submit different values, and no directory identifier appears anywhere in the response, then the request value is not reaching a directory filter at all and there is no injection point here.

*Disproof:* Show that the benign response's attribute set is constant regardless of the submitted value and contains no directory identifier, DN, or SID, while the server demonstrably issues an LDAP search as visible in LDAP diagnostic logging. Then the request value does not enter the filter and no injection test on that field is valid.

## Impact

**Where LDAP signing is not required and channel binding is at its default, a network position between an application and its domain controller can obtain usable bind credential material, making the impact credential theft rather than enumeration.**

State the impact precisely, because it is what justifies the severity. TrustedSec is explicit on the defaults: by default AD does not require LDAP communication to be signed, which makes it vulnerable to hacking, and the channel binding option that would stop the relay sits at its default value. They describe the attacker position directly - placing themselves between the system or application performing an authentication request and AD in an attempt to intercept, modify, and forward the request to obtain a valid authentication ticket - and note these attacks occur under the guise of a normal, legitimate user, which is what makes them hard to spot. Two operational corollaries for the report. First, channel binding is only effective when used with LDAPS, as standard LDAP on port 389 does not operate over SSL/TLS, so a plaintext-port path is unmitigated by design rather than by oversight. Second, the defender's observable is specific and named: monitor Event ID 2889 on domain controllers for signing requests after enabling LDAP diagnostics, and Event IDs 3074 and 3075 for channel binding, with 3075 identifying a client that did not provide Channel Binding Information. Those events include a source IP address that can be used to track down the offending system, which is what turns the impact claim into an actionable detection.

*Disproof:* Show the domain controllers enforce LDAP signing and channel binding at their enforcing settings with auditing in place, so an intercepted bind is rejected at the DC rather than yielding credential material. Then the impact is bounded and the critical severity rating is wrong.

## Related Bug Classes

Not yet researched.

## References

- **blackhillsinfosec.com** (blog)
  - <https://www.blackhillsinfosec.com/abusing-active-directory-certificate-services-part-3>
  - <https://www.blackhillsinfosec.com/bypass-ntlm-message-integrity-check-drop-the-mic>
  - <https://www.blackhillsinfosec.com/one-active-directory-account-can-be-your-best-early-warning>
- **cloud.google.com** (advisory)
  - <https://cloud.google.com/blog/topics/threat-intelligence/defending-against-active-exploitation-of-citrix-netscaler-adc-and-gateway-appliances>
  - <https://cloud.google.com/blog/topics/threat-intelligence/staying-ahead-of-adversarial-ai-through-agentic-source-code-review>
- **trustedsec.com** (blog)
  - <https://trustedsec.com/blog/ekuwu-not-just-another-ad-cs-esc>
  - <https://trustedsec.com/blog/exploring-ntds-dit-part-1-cracking-the-surface-with-dit-explorer>
  - <https://trustedsec.com/blog/kerberos-with-titanis>
  - <https://trustedsec.com/blog/ldap-channel-binding-and-ldap-signing>

Every item above is gated on >= 2 distinct publisher hosts (`wks/quality.py`, rule R1). Publisher diversity, not citation count, is what makes these corroborated.
