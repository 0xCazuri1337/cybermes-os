# LDAP / XPath / NoSQL-Style Injection

> surface: `web` · CWE: 90 · OWASP: A03:2021
> maturity: **mature** — 30 items, 22 supported, 7 FP rules, 1 chains

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
- **A vulnerability was published in 2019 revealing a flaw that allowed an attacker to bypass the NTLM Message Integrity Check (MIC). 4 This issue is known as the “drop the MIC” vulnerability and allows an attacker machine-in-the-middle position to tamper with the NTLM authentication by removing the integrity check.**  
  `under_review` · score 0.762 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "A vulnerability was published in 2019 revealing a flaw that allowed an attacker to bypass ".
  sources: <https://cloud.google.com/blog/topics/threat-intelligence/defending-against-active-exploitation-of-citrix-netscaler-adc-and-gateway-appliances> · <https://www.blackhillsinfosec.com/bypass-ntlm-message-integrity-check-drop-the-mic>
- **Domain Takeover If we have two domain controllers, and at least one domain controller can be coerced to authenticate to our attacker machine, we can expand upon this attack by relaying credentials from one domain controller to another and creating a computer object with delegation rights to a domain controller.**  
  `under_review` · score 0.762 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Domain Takeover If we have two domain controllers, and at least one domain controller can ".
  sources: <https://cloud.google.com/blog/topics/threat-intelligence/defending-against-active-exploitation-of-citrix-netscaler-adc-and-gateway-appliances> · <https://www.blackhillsinfosec.com/bypass-ntlm-message-integrity-check-drop-the-mic>
- **(This usually happens when relaying from SMB to LDAP).” SMB to LDAP Connection Failed This behavior is expected.**  
  `under_review` · score 0.6155 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "(This usually happens when relaying from SMB to LDAP).” SMB to LDAP Connection Failed This".
  sources: <https://www.blackhillsinfosec.com/bypass-ntlm-message-integrity-check-drop-the-mic>
- **Exploiting CVE-2019-1040 Once again, let’s imagine we have gained a foothold in the target organization Foobar’s environment.**  
  `under_review` · score 0.588 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Exploiting CVE-2019-1040 Once again, let’s imagine we have gained a foothold in the target".
  sources: <https://www.blackhillsinfosec.com/bypass-ntlm-message-integrity-check-drop-the-mic>
- **Using the domain credentials obtained from our new computer account snowmachine2$, we can use Coercer to force the victim machine (DC02) to authenticate to the attacker host (10.10.10.200). **Side Note: In some cases, a relay attack may not require domain credentials.**  
  `under_review` · score 0.588 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Using the domain credentials obtained from our new computer account snowmachine2$, we can ".
  sources: <https://www.blackhillsinfosec.com/bypass-ntlm-message-integrity-check-drop-the-mic>

## Test

- **To decide this case, observe: How to apply it in the field: treat this as the fp_rule it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable.**  
  `high_confidence` · score 0.838 · disproved by: This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (ldap.fp_rule.a_listening_on_loopback_is_not_network_exposure_control) states the full boundary.
  sources: <https://www.openldap.org/doc/admin24/security.html> · <https://www.rfc-editor.org/rfc/rfc4511.txt>
- **To decide this case, observe: How to apply it in the field: treat this as the fp_rule it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable.**  
  `high_confidence` · score 0.838 · disproved by: This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (ldap.fp_rule.an_empty_result_on_an_injection_string_means_no_bug_not_a_failed_attack) states the full boundary.
  sources: <https://www.openldap.org/doc/admin24/security.html> · <https://www.rfc-editor.org/rfc/rfc4511.txt>
- **To decide this case, observe: How to apply it in the field: treat this as the bypass it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable.**  
  `high_confidence` · score 0.838 · disproved by: This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (ldap.bypass.blank_password_bind_is_an_auth_bypass_only_if_the_directory_accepts_it) states the full boundary.
  sources: <https://www.openldap.org/doc/admin24/security.html> · <https://www.rfc-editor.org/rfc/rfc4511.txt>
- **To decide this case, observe: How to apply it in the field: treat this as the fp_rule it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable.**  
  `high_confidence` · score 0.838 · disproved by: This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (ldap.fp_rule.a_login_bypass_needs_proved_filter_semantics_not_just_a_wildcard_response) states the full boundary.
  sources: <https://www.openldap.org/doc/admin24/security.html> · <https://www.rfc-editor.org/rfc/rfc4511.txt>
- **To decide this case, observe: How to apply it in the field: treat this as the validation it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable.**  
  `high_confidence` · score 0.838 · disproved by: This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (ldap.validation.prove_filter_injection_with_a_presence_filter_returning_extra_entries) states the full boundary.
  sources: <https://www.openldap.org/doc/admin24/security.html> · <https://www.rfc-editor.org/rfc/rfc4511.txt>
- **When the directory connection uses bind authentication the credential check is performed before the filter is evaluated, so a wildcard payload that returns an authentication error rather than a widened result set is the expected outcome and must be logged as a negative control, not as a blocked attack.**  
  `high_confidence` · score 0.8105 · disproved by: If the connection uses anonymous or unauthenticated bind, or if the application performs the credential check in application code and then opens a separate anonymous LDAP connection to run the filter, the wildcard payload reaches the parser and can widen the result set - in which case the bind-auth reasoning does not hold and the negative control must be discarded. Showing a widened result set on such a connection is what refutes it.
  sources: <https://cheatsheetseries.owasp.org/cheatsheets/LDAP_Injection_Prevention_Cheat_Sheet.html> · <https://www.php.net/manual/en/function.ldap-escape.php>

## Validation

- **Injection is proven only when a wildcard-bearing filter and a byte-identical filter whose metacharacters have been escaped as \XX produce measurably different result sets against the same directory, which isolates filter structure as the only differing variable.**  
  `high_confidence` · score 0.893 · disproved by: If the escaped and unescaped forms return identical result sets, the application escaped the value and there is no injection to report, however many entries the plain wildcard form returned. Equally, if the two forms are not actually byte-identical apart from the escaping - different attribute, different base DN, different HTTP method, or a different session - the comparison is void and any observed difference is unattributable.
  sources: <https://cwe.mitre.org/data/definitions/90.html> · <https://www.rfc-editor.org/rfc/rfc4515.html>
- **An LDAP injection test is only meaningful after confirming which directory attribute the request-controlled value lands in, because the returned attribute set of a benign query reveals the server-side mapping without any injection being required.**  
  `high_confidence` · score 0.874 · disproved by: Show that the benign response's attribute set is constant regardless of the submitted value and contains no directory identifier, DN, or SID, while the server demonstrably issues an LDAP search as visible in LDAP diagnostic logging. Then the request value does not enter the filter and no injection test on that field is valid.
  sources: <https://trustedsec.com/blog/kerberos-with-titanis> · <https://www.blackhillsinfosec.com/one-active-directory-account-can-be-your-best-early-warning>
- **The convincing LDAP injection proof is a request/response pair where a crafted username field returns directory entries that the equivalent legitimate login must not be able to see, confirming the attacker supplied filter structure rather than a literal value.**  
  `high_confidence` · score 0.8655 · disproved by: If the crafted request returns exactly zero entries or a generic authentication error and never widens the matched set, the injection did not take effect; if the endpoint never passes the field into a filter at all but looks it up by a bind, then the finding is not LDAP injection regardless of the metacharacters sent.
  sources: <https://www.openldap.org/doc/admin24/security.html> · <https://www.rfc-editor.org/rfc/rfc4511.txt>

## Fp Rule

- **A search filter that errors or returns an identical failure for EVERY input, including well-formed values the application has matched before, is an application type-confusion or bind-failure bug and not LDAP injection.**  
  `high_confidence` · score 0.899 · disproved by: Show a known-good value and a random non-matching value produce the SAME error, status, and timing as a metacharacter-bearing value, with no differential in any response field. Then there is no filter-structure control and the injection claim is unsupported.
  sources: <https://cloud.google.com/blog/topics/threat-intelligence/staying-ahead-of-adversarial-ai-through-agentic-source-code-review> · <https://trustedsec.com/blog/ldap-channel-binding-and-ldap-signing>
- **A rejected or empty-result response to an LDAP injection payload is the expected outcome of a correctly escaped implementation and must be reported as a negative test rather than as evidence of a partially working attack.**  
  `high_confidence` · score 0.8655 · disproved by: It IS partial success if the response status, timing, or a subtly different error message reveals that the server parsed the metacharacters as filter syntax before rejecting the request; a flat generic rejection with no structural difference gives no signal that the input reached the filter parser at all.
  sources: <https://www.openldap.org/doc/admin24/security.html> · <https://www.rfc-editor.org/rfc/rfc4511.txt>
- **A directory server bound only to a loopback interface is not thereby inaccessible from other hosts, because binding an address controls listening sockets rather than the sources permitted to connect, so an IP firewall is the actual control and its absence is the finding.**  
  `high_confidence` · score 0.838 · disproved by: It IS protected when a host firewall or network ACL genuinely restricts inbound connections to that port, and the finding is void; it is NOT protected merely because slapd listens on loopback, since interface binding and source restriction are separate mechanisms and the guide recommends a firewall for selective restriction.
  sources: <https://www.openldap.org/doc/admin24/security.html> · <https://www.rfc-editor.org/rfc/rfc4511.txt>
- **Sending an LDAP filter metacharacter in a username field only proves injection when the response changes in a way the filter grammar explains, such as an attribute-presence filter returning every entry; a response that merely differs in length or error text is not proof.**  
  `high_confidence` · score 0.838 · disproved by: It IS injection when the crafted value alters which entries match, because the filter grammar contains boolean combinators and a presence test that a string-concatenating implementation would let the attacker supply; it is NOT injection when the library escapes the metacharacters before the query is built, or when the identical change appears for a random nonsense username too, which points at application logic rather than filter control.
  sources: <https://www.openldap.org/doc/admin24/security.html> · <https://www.rfc-editor.org/rfc/rfc4511.txt>
- **Reject a ldap finding until it is distinguished from the adjacent behaviour this class also covers. "A vulnerability was published in 2019 revealing a flaw that allowed an attacker to bypass the NTLM Message Integrity Check (MIC). 4 This issue is known as the “drop the MIC” vulnerability and allows an attacker machine-in-the-middle..." and "LDAP reachability is not bounded by enumeration: when the domain's CA has HTTP enrollment enabled with request disposition Issue, the same reachability converts into certificate issuance for an authenticated identity, turning read access..." share a surface and a symptom, so a response that matches the first is not evidence for it while the second remains possible.**  
  `high_confidence` · score 0.838 · disproved by: This rule is wrong if a controlled test shows the two behaviours can never co-occur on the same surface, or if the corpus entry for "LDAP reachability is not bounded by enumeration: when the domain's CA " is out of date. In that case this class needs its false-positive guidance rewritten rather than deleted.
  sources: <https://trustedsec.com/blog/ekuwu-not-just-another-ad-cs-esc> · <https://www.blackhillsinfosec.com/bypass-ntlm-message-integrity-check-drop-the-mic>
- **A search filter in which an attacker-supplied asterisk arrives at the directory as the literal two-character-plus-hex sequence \2a rather than as a wildcard metacharacter proves the value was escaped per the filter string-representation rule, so a widened result set is not evidence of LDAP injection.**  
  `high_confidence` · score 0.838 · disproved by: It IS injection if the directory evaluated the payload as filter structure rather than as an assertion value - for example the filter parsed as a SubstringFilter with an 'any' component, or the result set differs between '(cn=x)' and '(cn=*\2a*)' in a way that reveals the * was honoured as a wildcard. Showing only that the client's HTTP parameter contained an asterisk proves nothing either way.
  sources: <https://cheatsheetseries.owasp.org/cheatsheets/LDAP_Injection_Prevention_Cheat_Sheet.html> · <https://www.rfc-editor.org/rfc/rfc4515.html>
- **Reporting one shared list of 'LDAP special characters' as the injection surface is a false positive by construction, because the DN metacharacter set and the search-filter metacharacter set do not overlap in the characters they require escaped.**  
  `high_confidence` · score 0.8105 · disproved by: It is a real finding if the application concatenates the value into the DN rather than the filter and the DN metacharacters reach the parser unescaped, since a comma or equals sign in the value then splits or rewrites RDNs. The claim is about the shared-list reasoning being wrong, not that injection is impossible.
  sources: <https://cheatsheetseries.owasp.org/cheatsheets/LDAP_Injection_Prevention_Cheat_Sheet.html> · <https://www.php.net/manual/en/function.ldap-escape.php>

## Evidence

- **A convincing observation for this class is: The falsification test: if a benign request with a known-good value returns an attribute set that does not change when you submit different values, and no directory identifier appears anywhere in the response, then the request value is not reaching a directory filter at all and there is no injection point here.**  
  `high_confidence` · score 0.838 · disproved by: Not evidence when the observable cannot be produced at all -- blind, server-side-only, or identical-in-every-case behaviour leaves nothing to show. The originating rule (ldap.validation.confirm-which-directory-attribute-your-input-maps-to) states the full boundary.
  sources: <https://trustedsec.com/blog/kerberos-with-titanis> · <https://www.blackhillsinfosec.com/one-active-directory-account-can-be-your-best-early-warning>
- **A convincing observation for this class is: Adjacent behaviour that produces the same observable result: LDAP reachability is not bounded by enumeration: when the domain's CA has HTTP enrollment enabled with request disposition Issue, the same reachability converts into certificate issuance for an authenticated identity, turning read access...**  
  `high_confidence` · score 0.8105 · disproved by: Not evidence when the observable cannot be produced at all -- blind, server-side-only, or identical-in-every-case behaviour leaves nothing to show. The originating rule (ldap.fp_rule.auto.derived) states the full boundary.
  sources: <https://trustedsec.com/blog/ekuwu-not-just-another-ad-cs-esc> · <https://www.blackhillsinfosec.com/abusing-active-directory-certificate-services-part-3>

## Impact

- **Where LDAP signing is not required and channel binding is at its default, a network position between an application and its domain controller can obtain usable bind credential material, making the impact credential theft rather than enumeration.**  
  `under_review` · score 0.8615 · disproved by: Show the domain controllers enforce LDAP signing and channel binding at their enforcing settings with auditing in place, so an intercepted bind is rejected at the DC rather than yielding credential material. Then the impact is bounded and the critical severity rating is wrong.
  sources: <https://cloud.google.com/blog/topics/threat-intelligence/defending-against-active-exploitation-of-citrix-netscaler-adc-and-gateway-appliances> · <https://trustedsec.com/blog/ldap-channel-binding-and-ldap-signing>

## Bypass

- **An escaping routine that only replaces the printable metacharacters ( * ) \ will leave non-UTF-8 octets above 0x7F unencoded, so a payload containing a stray high byte is a practical way to test whether the implementation covers the full assertion-value encoding rather than a denylist.**  
  `high_confidence` · score 0.893 · disproved by: It is a false alarm if the application normalises input to valid UTF-8 before escaping, or if the differing response is the application's own input-validation layer rejecting the string before any LDAP call is made. Show that the request never produced a bind or search operation - no LDAP session in the capture or logs - and the high-byte test proved nothing about escaping.
  sources: <https://cwe.mitre.org/data/definitions/90.html> · <https://www.rfc-editor.org/rfc/rfc4515.html>
- **An unauthenticated bind carrying a name but no password resolves to an anonymous authorization association, so it is an authentication bypass exactly when the application treats an anonymous-but-successful bind as an authenticated user.**  
  `under_review` · score 0.838 · disproved by: It is NOT a bypass when the application checks the bind DN it obtained back and rejects the empty or anonymous case, or when the directory is configured to require authentication; it IS a bypass when the application only inspects the bind result code and proceeds, because the connection is then authorised as anonymous.
  sources: <https://www.openldap.org/doc/admin24/security.html> · <https://www.rfc-editor.org/rfc/rfc4511.txt>
- **A domain controller left at the default channel binding policy accepts a bind that carries no channel binding token at all, so relay protection is off unless the policy has been explicitly raised - and only the Always setting actually blocks the bind.**  
  `under_review` · score 0.754 · disproved by: Show the domain controllers have channel binding token requirements set to Always with logging enabled, and that a bind carrying no channel binding token is rejected by the DC rather than merely logged. Then relay protection is active and the bypass does not exist on that target.
  sources: <https://trustedsec.com/blog/ldap-channel-binding-and-ldap-signing> · <https://www.blackhillsinfosec.com/bypass-ntlm-message-integrity-check-drop-the-mic>

## Chain Link

- **LDAP reachability is not bounded by enumeration: when the domain's CA has HTTP enrollment enabled with request disposition Issue, the same reachability converts into certificate issuance for an authenticated identity, turning read access into a credential path.**  
  `high_confidence` · score 0.874 · disproved by: Show the CA has HTTP enrollment disabled, or request disposition set to pending or manual approval, so no certificate can be issued unattended. Then LDAP reachability stops at read access and the chain does not close.
  sources: <https://trustedsec.com/blog/ekuwu-not-just-another-ad-cs-esc> · <https://www.blackhillsinfosec.com/abusing-active-directory-certificate-services-part-3>
