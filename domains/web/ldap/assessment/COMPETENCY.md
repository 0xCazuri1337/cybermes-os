# Methodology — LDAP / XPath / NoSQL-Style Injection

> Derived from 10 verified items. Regenerate with `python -m wks.methodgen --class ldap --apply`. Do not hand-edit: this file is a projection of the evidence, and edits are lost on the next cycle.

**Surface.** A filter or path expression is built from attacker input, changing the query structure.

**References.** CWE-90 · A03:2021

## Preconditions

_No verified prerequisite items yet._ Derived from evidence only, so this section is empty rather than plausible.


## 1. Reconnaissance signals

_What to look for while mapping the surface, and where each signal tells you the rest of the procedure is worth running._

**A widened or non-empty result set for a filter that should have matched nothing, carrying directory attributes the application never renders on a normal miss, is the observable signature of a request-controlled filter structure.**

Signal, not proof. Send a value that cannot match any real object, for example a random high-entropy string, and record the application's normal empty-result path. The variant appends a boolean operator and a clause that makes the filter match broadly. If the response changes from no-results to a populated list, and the payload now carries attributes the app only ever emits for real matches - SID, DNT, DN, objectGUID, userAccountControl - then the filter's structure was request-controlled. The attribute differential is what separates this from a cosmetic application bug: a frontend wildcard in the app's own UI would not cause the backend to return directory attributes it has no reason to expose. TrustedSec's DIT work supplies the vocabulary for reading what came back: in the LDAP world, objects are identified by their distinguished name, or DN, and an RDN refers to the individual components of a distinguished name and identifies an object within its parent, so a DN or objectGUID appearing where the app should have shown nothing is a directory-origin artefact. Which attributes are worth requesting is not arbitrary either - BHIS notes that BloodHound, AdExplorer, ADFind and other LDAP enumerators read the UAC value for discovered objects. Caveat to state in the report: a widened result set proves the filter changed, not yet what an attacker can extract.

- *Disproof:* Show that the application's own empty-result path already returns a populated template, or that the attributes in the response are rendered by the frontend from data it fetched on a separate call. Then the widened response is application behaviour rather than directory-side filter evaluation.
- *Evidence:* high_confidence — [blackhillsinfosec.com](https://www.blackhillsinfosec.com/one-active-directory-account-can-be-your-best-early-warning); [trustedsec.com](https://trustedsec.com/blog/exploring-ntds-dit-part-1-cracking-the-surface-with-dit-explorer)

## 2. Test sequence

_Concrete mutations to try. Each is written to be executable, not to be a description of the vulnerability._

**Where a web-facing application performs an LDAP bind over TLS to a domain controller, the reachable post-injection step is relay of that bind to the DC's LDAPS listener, whose precondition is an absent or strippable client-side message-integrity check.**

Describe the test, do not run it: an application whose auth path binds to AD over LDAPS creates a channel a man-in-the-middle can attempt to terminate. BHIS's relay walkthrough states the routing constraint plainly - LDAP is only available on domain controllers, therefore we must target a domain controller in an LDAP relay attack. The precondition is the message integrity code carried on the NTLM authenticate message: Black Hills' baseline attempt returned 'The client requested signing. Relaying to LDAP will not work!', and they describe the case where, when MIC is not included, the connection from SMB can be relayed to LDAPS. So what you are establishing is whether the application's bind is relayable, which is a property of the client and its patch state rather than of the injection itself - and that is why this belongs in a report as a conditional post-exploitation step, not a claim. The hunt-side corollary is that TrustedSec's LDAP-signing guidance names SMB/LDAP signing plus channel binding enforcement as the control and notes adoption remains low, so an LDAPS bind from an application that presents no channel binding token is exactly the event worth alerting on.

- *Disproof:* Show that the application's LDAPS bind presents a channel binding token and that the target DC enforces validation, so a relayed bind is rejected at the TLS layer. Then the bind is not relayable and the post-injection step does not exist.
- *Evidence:* high_confidence — [blackhillsinfosec.com](https://www.blackhillsinfosec.com/bypass-ntlm-message-integrity-check-drop-the-mic); [trustedsec.com](https://trustedsec.com/blog/ldap-channel-binding-and-ldap-signing)

## 3. Validation

_How to prove the finding rather than infer it. A technique that cannot be validated must not be reported._

**The convincing LDAP injection proof is a request/response pair where a crafted username field returns directory entries that the equivalent legitimate login must not be able to see, confirming the attacker supplied filter structure rather than a literal value.**

Mechanism: The convincing LDAP injection proof is a request/response pair where a crafted username field returns directory entries that the equivalent legitimate login must not be able to see, confirming the attacker supplied filter structure rather than a literal value. How to apply it in the field: treat this as the validation it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable. Boundary of the rule: If the crafted request returns exactly zero entries or a generic authentication error and never widens the matched set, the injection did not take effect; if the endpoint never passes the field into a filter at all but looks it up by a bind, then the finding is not LDAP injection regardless of the metacharacters sent.

- *Disproof:* If the crafted request returns exactly zero entries or a generic authentication error and never widens the matched set, the injection did not take effect; if the endpoint never passes the field into a filter at all but looks it up by a bind, then the finding is not LDAP injection regardless of the metacharacters sent.
- *Evidence:* high_confidence — [openldap.org](https://www.openldap.org/doc/admin24/security.html); [rfc-editor.org](https://www.rfc-editor.org/rfc/rfc4511.txt)

**An LDAP injection test is only meaningful after confirming which directory attribute the request-controlled value lands in, because the returned attribute set of a benign query reveals the server-side mapping without any injection being required.**

Validation step that requires no malicious input and often settles the whole question. Issue a benign query with a value you know matches a real object, and read which attributes come back. Those attributes are the ones the server put in the filter or the search scope, and they tell you the mapping. TrustedSec's Titanis cheatsheet shows the mapping plainly: the SPN mapping query is written against servicePrincipalName and returns sAMAccountName, sAMAccountType and servicePrincipalName, so the requested-attribute list is an exact fingerprint of what the filter touched. BHIS supplies the matching field-level fingerprint on the AD side, noting that BloodHound, AdExplorer, ADFind and other LDAP enumerators read the UAC value for discovered objects - meaning userAccountControl is a field genuinely in demand and therefore genuinely worth mapping. The falsification test: if a benign request with a known-good value returns an attribute set that does not change when you submit different values, and no directory identifier appears anywhere in the response, then the request value is not reaching a directory filter at all and there is no injection point here.

- *Disproof:* Show that the benign response's attribute set is constant regardless of the submitted value and contains no directory identifier, DN, or SID, while the server demonstrably issues an LDAP search as visible in LDAP diagnostic logging. Then the request value does not enter the filter and no injection test on that field is valid.
- *Evidence:* high_confidence — [blackhillsinfosec.com](https://www.blackhillsinfosec.com/one-active-directory-account-can-be-your-best-early-warning); [trustedsec.com](https://trustedsec.com/blog/kerberos-with-titanis)

## 4. False-positive rejection

_The checks that eliminate the most common non-findings. Run these BEFORE reporting, not after a rejection._

**A search filter that errors or returns an identical failure for EVERY input, including well-formed values the application has matched before, is an application type-confusion or bind-failure bug and not LDAP injection.**

This is the most expensive LDAP false positive: claiming injection because you sent a malformed filter and got an error back. Error responses are also what a bind failure, a null reference from passing a non-string, or an app-side validation layer produce. The discriminating test is three inputs, always: a known-good value the application has matched before, a random non-matching value, and a value carrying filter metacharacters. If the error is identical across all three, the filter never reached the directory with your bytes in it and the finding is an application bug. Only a differential - good and non-matching both behave normally while metacharacters behave differently - supports injection. Mandiant's write-up supports exactly this discipline: it traces whether user input actually reaches the dangerous sink before classifying anything, and it routes results that do not match ground truth to a dedicated false-positive triage stage that must classify findings definitively rather than by resemblance. Second supporting point for the report: an LDAP bind can fail for reasons unrelated to the filter at all, so a bind error must be separated from a search error before either is called injection. The rule: the error itself is never the evidence; the differential against a known-good control is.

- *Disproof:* Show a known-good value and a random non-matching value produce the SAME error, status, and timing as a metacharacter-bearing value, with no differential in any response field. Then there is no filter-structure control and the injection claim is unsupported.
- *Evidence:* high_confidence — [cloud.google.com](https://cloud.google.com/blog/topics/threat-intelligence/staying-ahead-of-adversarial-ai-through-agentic-source-code-review); [trustedsec.com](https://trustedsec.com/blog/ldap-channel-binding-and-ldap-signing)

**A rejected or empty-result response to an LDAP injection payload is the expected outcome of a correctly escaped implementation and must be reported as a negative test rather than as evidence of a partially working attack.**

Mechanism: A rejected or empty-result response to an LDAP injection payload is the expected outcome of a correctly escaped implementation and must be reported as a negative test rather than as evidence of a partially working attack. How to apply it in the field: treat this as the fp_rule it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable. Boundary of the rule: It IS partial success if the response status, timing, or a subtly different error message reveals that the server parsed the metacharacters as filter syntax before rejecting the request; a flat generic rejection with no structural difference gives no signal that the input reached the filter parser at all.

- *Disproof:* It IS partial success if the response status, timing, or a subtly different error message reveals that the server parsed the metacharacters as filter syntax before rejecting the request; a flat generic rejection with no structural difference gives no signal that the input reached the filter parser at all.
- *Evidence:* high_confidence — [openldap.org](https://www.openldap.org/doc/admin24/security.html); [rfc-editor.org](https://www.rfc-editor.org/rfc/rfc4511.txt)

**Reject a ldap finding until it is distinguished from the adjacent behaviour this class also covers. "A vulnerability was published in 2019 revealing a flaw that allowed an attacker to bypass the NTLM Message Integrity Check (MIC). 4 This issue is known as the “drop the MIC” vulnerability and allows an attacker machine-in-the-middle..." and "LDAP reachability is not bounded by enumeration: when the domain's CA has HTTP enrollment enabled with request disposition Issue, the same reachability converts into certificate issuance for an authenticated identity, turning read access..." share a surface and a symptom, so a response that matches the first is not evidence for it while the second remains possible.**

Hypothesis under test: A vulnerability was published in 2019 revealing a flaw that allowed an attacker to bypass the NTLM Message Integrity Check (MIC). 4 This issue is known as the “drop the MIC” vulnerability and allows an attacker machine-in-the-middle...

Adjacent behaviour that produces the same observable result: LDAP reachability is not bounded by enumeration: when the domain's CA has HTTP enrollment enabled with request disposition Issue, the same reachability converts into certificate issuance for an authenticated identity, turning read access...

Why this is worth checking before reporting: both are recorded in this class as gated knowledge, so a tester who stops at the first match will report one of them. The two differ in what the server actually did with the input, and that difference is observable in the response rather than in the request.

Required before treating this as a finding: capture the response that demonstrates the first behaviour specifically, and confirm the second is not what was observed.

- *Disproof:* This rule is wrong if a controlled test shows the two behaviours can never co-occur on the same surface, or if the corpus entry for "LDAP reachability is not bounded by enumeration: when the domain's CA " is out of date. In that case this class needs its false-positive guidance rewritten rather than deleted.
- *Evidence:* high_confidence — [cloud.google.com](https://cloud.google.com/blog/topics/threat-intelligence/defending-against-active-exploitation-of-citrix-netscaler-adc-and-gateway-appliances); [trustedsec.com](https://trustedsec.com/blog/ekuwu-not-just-another-ad-cs-esc)

**A directory server bound only to a loopback interface is not thereby inaccessible from other hosts, because binding an address controls listening sockets rather than the sources permitted to connect, so an IP firewall is the actual control and its absence is the finding.**

Mechanism: A directory server bound only to a loopback interface is not thereby inaccessible from other hosts, because binding an address controls listening sockets rather than the sources permitted to connect, so an IP firewall is the actual control and its absence is the finding. How to apply it in the field: treat this as the fp_rule it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable. Boundary of the rule: It IS protected when a host firewall or network ACL genuinely restricts inbound connections to that port, and the finding is void; it is NOT protected merely because slapd listens on loopback, since interface binding and source restriction are separate mechanisms and the guide recommends a firewall for selective restriction.

- *Disproof:* It IS protected when a host firewall or network ACL genuinely restricts inbound connections to that port, and the finding is void; it is NOT protected merely because slapd listens on loopback, since interface binding and source restriction are separate mechanisms and the guide recommends a firewall for selective restriction.
- *Evidence:* high_confidence — [openldap.org](https://www.openldap.org/doc/admin24/security.html); [rfc-editor.org](https://www.rfc-editor.org/rfc/rfc4511.txt)

**Sending an LDAP filter metacharacter in a username field only proves injection when the response changes in a way the filter grammar explains, such as an attribute-presence filter returning every entry; a response that merely differs in length or error text is not proof.**

Mechanism: Sending an LDAP filter metacharacter in a username field only proves injection when the response changes in a way the filter grammar explains, such as an attribute-presence filter returning every entry; a response that merely differs in length or error text is not proof. How to apply it in the field: treat this as the fp_rule it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable. Boundary of the rule: It IS injection when the crafted value alters which entries match, because the filter grammar contains boolean combinators and a presence test that a string-concatenating implementation would let the attacker supply; it is NOT injection when the library escapes the metacharacters before the query is built, or when the identical change appears for a random nonsense username too, which points at application logic rather than filter control.

- *Disproof:* It IS injection when the crafted value alters which entries match, because the filter grammar contains boolean combinators and a presence test that a string-concatenating implementation would let the attacker supply; it is NOT injection when the library escapes the metacharacters before the query is built, or when the identical change appears for a random nonsense username too, which points at application logic rather than filter control.
- *Evidence:* high_confidence — [openldap.org](https://www.openldap.org/doc/admin24/security.html); [rfc-editor.org](https://www.rfc-editor.org/rfc/rfc4511.txt)

## Known bypasses

_No verified bypass items yet._ Derived from evidence only, so this section is empty rather than plausible.


## 5. Chaining

_How this class escalates when combined with others. Each step is anchored to a promoted item._

**LDAP reachability is not bounded by enumeration: when the domain's CA has HTTP enrollment enabled with request disposition Issue, the same reachability converts into certificate issuance for an authenticated identity, turning read access into a credential path.**

This chain is the reason anonymous-bind reachability deserves more than an enumeration rating. LDAP read access yields data; the escalation is that the certificate authority is a second endpoint in the same trust domain. BHIS's ESC8 write-up gives both CA conditions - Web Enrollment: Enabled, Request Disposition: Issue - and the mechanism: if we can coerce a domain account to authenticate to our machine, we can relay the victim's credential material to the CA to obtain a certificate on behalf of that victim. They add that in some cases a relay attack may not even require domain credentials, which is the uncomfortable branch for defenders, since a reachable and weakly protected CA plus a coerced authentication is sufficient on its own. TrustedSec's independent ADCS research closes the loop from the far end: the technique dubbed PassTheCert uses a certificate to authenticate via schannel against LDAP. The chain to write into a report is therefore LDAP reachability to certificate issuance to LDAP authentication as a higher identity - and the corollary for triage is that an anonymous-bind or injection finding should be rated against certificate infrastructure, with the two CA conditions checked on the CA rather than on the LDAP endpoint.

- *Disproof:* Show the CA has HTTP enrollment disabled, or request disposition set to pending or manual approval, so no certificate can be issued unattended. Then LDAP reachability stops at read access and the chain does not close.
- *Evidence:* high_confidence — [blackhillsinfosec.com](https://www.blackhillsinfosec.com/abusing-active-directory-certificate-services-part-3); [trustedsec.com](https://trustedsec.com/blog/ekuwu-not-just-another-ad-cs-esc)

## Impact

_No verified impact items yet._ Derived from evidence only, so this section is empty rather than plausible.


## Coverage gap

These stages have no verified evidence and are therefore absent above: Preconditions, Known bypasses, Impact.
A procedure with a missing validation stage is not safe to act on — it produces findings rather than proofs.

---

*Generated from the evidence base. Where this file and the database disagree, the database is correct.*
