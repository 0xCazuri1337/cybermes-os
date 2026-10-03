# LDAP / XPath / NoSQL-Style Injection

> surface: `web` · CWE: 90 · OWASP: A03:2021
> maturity: **mature** — 13 items, 13 supported, 2 FP rules, 1 chains

A filter or path expression is built from attacker input, changing the query structure.

**Aliases:** ldap injection, xpath injection, orm injection

## Signal

- **A widened or non-empty result set for a filter that should have matched nothing, carrying directory attributes the application never renders on a normal miss, is the observable signature of a request-controlled filter structure.**  
  `high_confidence` · score 0.954 · disproved by: Show that the application's own empty-result path already returns a populated template, or that the attributes in the response are rendered by the frontend from data it fetched on a separate call. Then the widened response is application behaviour rather than directory-side filter evaluation.
  sources: <https://trustedsec.com/blog/exploring-ntds-dit-part-1-cracking-the-surface-with-dit-explorer> · <https://www.blackhillsinfosec.com/one-active-directory-account-can-be-your-best-early-warning>

## Technique

- **Where a web-facing application performs an LDAP bind over TLS to a domain controller, the reachable post-injection step is relay of that bind to the DC's LDAPS listener, whose precondition is an absent or strippable client-side message-integrity check.**  
  `high_confidence` · score 0.809 · disproved by: Show that the application's LDAPS bind presents a channel binding token and that the target DC enforces validation, so a relayed bind is rejected at the TLS layer. Then the bind is not relayable and the post-injection step does not exist.
  sources: <https://trustedsec.com/blog/ldap-channel-binding-and-ldap-signing> · <https://www.blackhillsinfosec.com/bypass-ntlm-message-integrity-check-drop-the-mic>
- **(This usually happens when relaying from SMB to LDAP).” SMB to LDAP Connection Failed This behavior is expected.**  
  `high_confidence` · score 0.7895 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "(This usually happens when relaying from SMB to LDAP).” SMB to LDAP Connection Failed This".
  sources: <https://cloud.google.com/blog/topics/threat-intelligence/defending-against-active-exploitation-of-citrix-netscaler-adc-and-gateway-appliances> · <https://www.blackhillsinfosec.com/bypass-ntlm-message-integrity-check-drop-the-mic>
- **A vulnerability was published in 2019 revealing a flaw that allowed an attacker to bypass the NTLM Message Integrity Check (MIC). 4 This issue is known as the “drop the MIC” vulnerability and allows an attacker machine-in-the-middle position to tamper with the NTLM authentication by removing the integrity check.**  
  `high_confidence` · score 0.762 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "A vulnerability was published in 2019 revealing a flaw that allowed an attacker to bypass ".
  sources: <https://cloud.google.com/blog/topics/threat-intelligence/defending-against-active-exploitation-of-citrix-netscaler-adc-and-gateway-appliances> · <https://www.blackhillsinfosec.com/bypass-ntlm-message-integrity-check-drop-the-mic>
- **Exploiting CVE-2019-1040 Once again, let’s imagine we have gained a foothold in the target organization Foobar’s environment.**  
  `high_confidence` · score 0.762 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Exploiting CVE-2019-1040 Once again, let’s imagine we have gained a foothold in the target".
  sources: <https://cloud.google.com/blog/topics/threat-intelligence/defending-against-active-exploitation-of-citrix-netscaler-adc-and-gateway-appliances> · <https://www.blackhillsinfosec.com/bypass-ntlm-message-integrity-check-drop-the-mic>
- **Domain Takeover If we have two domain controllers, and at least one domain controller can be coerced to authenticate to our attacker machine, we can expand upon this attack by relaying credentials from one domain controller to another and creating a computer object with delegation rights to a domain controller.**  
  `high_confidence` · score 0.762 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Domain Takeover If we have two domain controllers, and at least one domain controller can ".
  sources: <https://cloud.google.com/blog/topics/threat-intelligence/defending-against-active-exploitation-of-citrix-netscaler-adc-and-gateway-appliances> · <https://www.blackhillsinfosec.com/bypass-ntlm-message-integrity-check-drop-the-mic>
- **Using the domain credentials obtained from our new computer account snowmachine2$, we can use Coercer to force the victim machine (DC02) to authenticate to the attacker host (10.10.10.200). **Side Note: In some cases, a relay attack may not require domain credentials.**  
  `high_confidence` · score 0.762 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Using the domain credentials obtained from our new computer account snowmachine2$, we can ".
  sources: <https://cloud.google.com/blog/topics/threat-intelligence/defending-against-active-exploitation-of-citrix-netscaler-adc-and-gateway-appliances> · <https://www.blackhillsinfosec.com/bypass-ntlm-message-integrity-check-drop-the-mic>

## Validation

- **An LDAP injection test is only meaningful after confirming which directory attribute the request-controlled value lands in, because the returned attribute set of a benign query reveals the server-side mapping without any injection being required.**  
  `high_confidence` · score 0.809 · disproved by: Show that the benign response's attribute set is constant regardless of the submitted value and contains no directory identifier, DN, or SID, while the server demonstrably issues an LDAP search as visible in LDAP diagnostic logging. Then the request value does not enter the filter and no injection test on that field is valid.
  sources: <https://trustedsec.com/blog/kerberos-with-titanis> · <https://www.blackhillsinfosec.com/one-active-directory-account-can-be-your-best-early-warning>

## Fp Rule

- **A search filter that errors or returns an identical failure for EVERY input, including well-formed values the application has matched before, is an application type-confusion or bind-failure bug and not LDAP injection.**  
  `high_confidence` · score 0.899 · disproved by: Show a known-good value and a random non-matching value produce the SAME error, status, and timing as a metacharacter-bearing value, with no differential in any response field. Then there is no filter-structure control and the injection claim is unsupported.
  sources: <https://cloud.google.com/blog/topics/threat-intelligence/staying-ahead-of-adversarial-ai-through-agentic-source-code-review> · <https://trustedsec.com/blog/ldap-channel-binding-and-ldap-signing>
- **Reject a ldap finding until it is distinguished from the adjacent behaviour this class also covers. "A vulnerability was published in 2019 revealing a flaw that allowed an attacker to bypass the NTLM Message Integrity Check (MIC). 4 This issue is known as the “drop the MIC” vulnerability and allows an attacker machine-in-the-middle..." and "LDAP reachability is not bounded by enumeration: when the domain's CA has HTTP enrollment enabled with request disposition Issue, the same reachability converts into certificate issuance for an authenticated identity, turning read access..." share a surface and a symptom, so a response that matches the first is not evidence for it while the second remains possible.**  
  `high_confidence` · score 0.853 · disproved by: This rule is wrong if a controlled test shows the two behaviours can never co-occur on the same surface, or if the corpus entry for "LDAP reachability is not bounded by enumeration: when the domain's CA " is out of date. In that case this class needs its false-positive guidance rewritten rather than deleted.
  sources: <https://cloud.google.com/blog/topics/threat-intelligence/defending-against-active-exploitation-of-citrix-netscaler-adc-and-gateway-appliances> · <https://trustedsec.com/blog/ekuwu-not-just-another-ad-cs-esc>

## Impact

- **Where LDAP signing is not required and channel binding is at its default, a network position between an application and its domain controller can obtain usable bind credential material, making the impact credential theft rather than enumeration.**  
  `high_confidence` · score 0.8615 · disproved by: Show the domain controllers enforce LDAP signing and channel binding at their enforcing settings with auditing in place, so an intercepted bind is rejected at the DC rather than yielding credential material. Then the impact is bounded and the critical severity rating is wrong.
  sources: <https://cloud.google.com/blog/topics/threat-intelligence/defending-against-active-exploitation-of-citrix-netscaler-adc-and-gateway-appliances> · <https://trustedsec.com/blog/ldap-channel-binding-and-ldap-signing>

## Bypass

- **A domain controller left at the default channel binding policy accepts a bind that carries no channel binding token at all, so relay protection is off unless the policy has been explicitly raised - and only the Always setting actually blocks the bind.**  
  `high_confidence` · score 0.754 · disproved by: Show the domain controllers have channel binding token requirements set to Always with logging enabled, and that a bind carrying no channel binding token is rejected by the DC rather than merely logged. Then relay protection is active and the bypass does not exist on that target.
  sources: <https://trustedsec.com/blog/ldap-channel-binding-and-ldap-signing> · <https://www.blackhillsinfosec.com/bypass-ntlm-message-integrity-check-drop-the-mic>

## Chain Link

- **LDAP reachability is not bounded by enumeration: when the domain's CA has HTTP enrollment enabled with request disposition Issue, the same reachability converts into certificate issuance for an authenticated identity, turning read access into a credential path.**  
  `high_confidence` · score 0.809 · disproved by: Show the CA has HTTP enrollment disabled, or request disposition set to pending or manual approval, so no certificate can be issued unattended. Then LDAP reachability stops at read access and the chain does not close.
  sources: <https://trustedsec.com/blog/ekuwu-not-just-another-ad-cs-esc> · <https://www.blackhillsinfosec.com/abusing-active-directory-certificate-services-part-3>
