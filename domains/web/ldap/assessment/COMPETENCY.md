# Methodology — LDAP / XPath / NoSQL-Style Injection

> Derived from 19 verified items. Regenerate with `python -m wks.methodgen --class ldap --apply`. Do not hand-edit: this file is a projection of the evidence, and edits are lost on the next cycle.

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

**A vulnerability was published in 2019 revealing a flaw that allowed an attacker to bypass the NTLM Message Integrity Check (MIC). 4 This issue is known as the “drop the MIC” vulnerability and allows an attacker machine-in-the-middle position to tamper with the NTLM authentication by removing the integrity check.**

work! (This usually happens when relaying from SMB to LDAP).” SMB to LDAP Connection Failed This behavior is expected. Typically, SMB traffic cannot be relayed to LDAP(S). NTLM authentication consists of three message types: NTLM_NEGOTIATE , NTLM_CHALLENGE , and NTLM_AUTHENTICATE . A field known as the Message Integrity Code was added to the NTLM_AUTHENTICATE message to prevent message tampering. A vulnerability was published in 2019 revealing a flaw that allowed an attacker to bypass the NTLM Message Integrity Check (MIC). 4 This issue is known as the “drop the MIC” vulnerability and allows an attacker machine-in-the-middle position to tamper with the NTLM authentication by removing the integrity check. When MIC is not included, the connection from SMB can be relayed to LDAPS. Exploiting CVE-2019-1040 Once again, let’s imagine we have gained a foothold in the target organization Foobar’s environment. At this point, we have network level access, and we located the target domain controller DC01.foobar.com (10.10.10.1). To provide a brief initial attack summary: 
 Configure NTLMRelayx to relay NTLM

- *Disproof:* Refuted when: the payload is rejected when the same check runs with the defensive control ENABLED (a strict allowlist, a normalisation pass, or a WAF rule) rather than disabled. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“A vulnerability was published in 2019 revealing a flaw that allowed an attacker ”) does not occur under a test that isolates that control.
- *Evidence:* high_confidence — [blackhillsinfosec.com](https://www.blackhillsinfosec.com/bypass-ntlm-message-integrity-check-drop-the-mic); [cloud.google.com](https://cloud.google.com/blog/topics/threat-intelligence/defending-against-active-exploitation-of-citrix-netscaler-adc-and-gateway-appliances)

## 3. Validation

_How to prove the finding rather than infer it. A technique that cannot be validated must not be reported._

**Injection is proven only when a wildcard-bearing filter and a byte-identical filter whose metacharacters have been escaped as \XX produce measurably different result sets against the same directory, which isolates filter structure as the only differing variable.**

A single payload that returns many entries is weak evidence because an attacker-controlled term may simply be matching broadly on a well-populated attribute. The controlled test pairs two requests whose bytes differ only in the escaping of the metacharacters: '(&(uid=*)(objectClass=person))' style widening versus the escaped form where every asterisk has become \2a. Because RFC 4515 requires the escaped form to be a literal-character assertion, any difference in the returned entries, entry count, or which attributes are rendered can only be attributed to the server interpreting the metacharacters as filter structure. That is the difference between a hypothesis and a proof, and it is the form a report should present.

- *Disproof:* If the escaped and unescaped forms return identical result sets, the application escaped the value and there is no injection to report, however many entries the plain wildcard form returned. Equally, if the two forms are not actually byte-identical apart from the escaping - different attribute, different base DN, different HTTP method, or a different session - the comparison is void and any observed difference is unattributable.
- *Evidence:* high_confidence — [cwe.mitre.org](https://cwe.mitre.org/data/definitions/90.html); [rfc-editor.org](https://www.rfc-editor.org/rfc/rfc4515.html)

**The convincing LDAP injection proof is a request/response pair where a crafted username field returns directory entries that the equivalent legitimate login must not be able to see, confirming the attacker supplied filter structure rather than a literal value.**

Mechanism: The convincing LDAP injection proof is a request/response pair where a crafted username field returns directory entries that the equivalent legitimate login must not be able to see, confirming the attacker supplied filter structure rather than a literal value. How to apply it in the field: treat this as the validation it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable. Boundary of the rule: If the crafted request returns exactly zero entries or a generic authentication error and never widens the matched set, the injection did not take effect; if the endpoint never passes the field into a filter at all but looks it up by a bind, then the finding is not LDAP injection regardless of the metacharacters sent.

- *Disproof:* If the crafted request returns exactly zero entries or a generic authentication error and never widens the matched set, the injection did not take effect; if the endpoint never passes the field into a filter at all but looks it up by a bind, then the finding is not LDAP injection regardless of the metacharacters sent.
- *Evidence:* high_confidence — [openldap.org](https://www.openldap.org/doc/admin24/security.html); [rfc-editor.org](https://www.rfc-editor.org/rfc/rfc4511.txt)

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

**A directory server bound only to a loopback interface is not thereby inaccessible from other hosts, because binding an address controls listening sockets rather than the sources permitted to connect, so an IP firewall is the actual control and its absence is the finding.**

Mechanism: A directory server bound only to a loopback interface is not thereby inaccessible from other hosts, because binding an address controls listening sockets rather than the sources permitted to connect, so an IP firewall is the actual control and its absence is the finding. How to apply it in the field: treat this as the fp_rule it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable. Boundary of the rule: It IS protected when a host firewall or network ACL genuinely restricts inbound connections to that port, and the finding is void; it is NOT protected merely because slapd listens on loopback, since interface binding and source restriction are separate mechanisms and the guide recommends a firewall for selective restriction.

- *Disproof:* It IS protected when a host firewall or network ACL genuinely restricts inbound connections to that port, and the finding is void; it is NOT protected merely because slapd listens on loopback, since interface binding and source restriction are separate mechanisms and the guide recommends a firewall for selective restriction.
- *Evidence:* high_confidence — [openldap.org](https://www.openldap.org/doc/admin24/security.html); [rfc-editor.org](https://www.rfc-editor.org/rfc/rfc4511.txt)

**Sending an LDAP filter metacharacter in a username field only proves injection when the response changes in a way the filter grammar explains, such as an attribute-presence filter returning every entry; a response that merely differs in length or error text is not proof.**

Mechanism: Sending an LDAP filter metacharacter in a username field only proves injection when the response changes in a way the filter grammar explains, such as an attribute-presence filter returning every entry; a response that merely differs in length or error text is not proof. How to apply it in the field: treat this as the fp_rule it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable. Boundary of the rule: It IS injection when the crafted value alters which entries match, because the filter grammar contains boolean combinators and a presence test that a string-concatenating implementation would let the attacker supply; it is NOT injection when the library escapes the metacharacters before the query is built, or when the identical change appears for a random nonsense username too, which points at application logic rather than filter control.

- *Disproof:* It IS injection when the crafted value alters which entries match, because the filter grammar contains boolean combinators and a presence test that a string-concatenating implementation would let the attacker supply; it is NOT injection when the library escapes the metacharacters before the query is built, or when the identical change appears for a random nonsense username too, which points at application logic rather than filter control.
- *Evidence:* high_confidence — [openldap.org](https://www.openldap.org/doc/admin24/security.html); [rfc-editor.org](https://www.rfc-editor.org/rfc/rfc4511.txt)

**A search filter in which an attacker-supplied asterisk arrives at the directory as the literal two-character-plus-hex sequence \2a rather than as a wildcard metacharacter proves the value was escaped per the filter string-representation rule, so a widened result set is not evidence of LDAP injection.**

RFC 4515 defines the wire form of a search filter: an assertion value may only contain UTF-8 characters outside a small exclusion set, and an asterisk must therefore be encoded as the escape sequence \2a. The trap for a hunter is that the browser, the framework, and the LDAP client library each perform a different layer of transformation, so a payload that visibly reads '(cn=*' on the wire may already be inert. In the field this means you cannot conclude anything from the HTTP request body; you have to observe the filter string the directory actually received, either from an LDAP debug log, a packet capture of the LDAP session, or an application trace. If the metacharacter you injected is present as structure in the parsed filter, the filter was concatenated. If it is present as an escape sequence in the assertion value, it is data.

- *Disproof:* It IS injection if the directory evaluated the payload as filter structure rather than as an assertion value - for example the filter parsed as a SubstringFilter with an 'any' component, or the result set differs between '(cn=x)' and '(cn=*\2a*)' in a way that reveals the * was honoured as a wildcard. Showing only that the client's HTTP parameter contained an asterisk proves nothing either way.
- *Evidence:* high_confidence — [cheatsheetseries.owasp.org](https://cheatsheetseries.owasp.org/cheatsheets/LDAP_Injection_Prevention_Cheat_Sheet.html); [rfc-editor.org](https://www.rfc-editor.org/rfc/rfc4515.html)

**Reporting one shared list of 'LDAP special characters' as the injection surface is a false positive by construction, because the DN metacharacter set and the search-filter metacharacter set do not overlap in the characters they require escaped.**

The OWASP cheat sheet enumerates two disjoint sets: for distinguished names the characters requiring exclusion are backslash, hash, plus, comma, semicolon, quote, equals and leading or trailing spaces, while for search filters the set is asterisk, open parenthesis, close parenthesis, backslash and NUL. A single combined list tells a hunter that parentheses are dangerous everywhere and that commas are dangerous everywhere, both of which are wrong - parentheses are structure in a filter and harmless in a DN, and the comma is the RDN separator in a DN and ordinary data in a filter. The field practice that follows is to identify which context your input lands in before choosing payloads, then to build the test string from the set for that context only.

- *Disproof:* It is a real finding if the application concatenates the value into the DN rather than the filter and the DN metacharacters reach the parser unescaped, since a comma or equals sign in the value then splits or rewrites RDNs. The claim is about the shared-list reasoning being wrong, not that injection is impossible.
- *Evidence:* high_confidence — [cheatsheetseries.owasp.org](https://cheatsheetseries.owasp.org/cheatsheets/LDAP_Injection_Prevention_Cheat_Sheet.html); [php.net](https://www.php.net/manual/en/function.ldap-escape.php)

## 5. Known bypasses

_Filters and controls that have defeated the techniques above. Treat these as the reason a naive test fails, not as proof of safety._

**An escaping routine that only replaces the printable metacharacters ( * ) \ will leave non-UTF-8 octets above 0x7F unencoded, so a payload containing a stray high byte is a practical way to test whether the implementation covers the full assertion-value encoding rather than a denylist.**

RFC 4515 places the obligation on the generator of the string representation: octets greater than 0x7F that are not part of a valid UTF-8 sequence must be escaped, and invalid UTF-8 must not be smuggled into the filter at all. A hunter who only tests printable metacharacters is testing the denylist that is easiest to write and the one the OWASP mitigation guidance explicitly warns against. The field technique is to send a term containing a lone continuation byte or a truncated multi-byte sequence alongside the ordinary asterisk payload: if the application returns a malformed or generic error that differs from its response to a clean value, the input reached the parser unencoded and the escaping is incomplete rather than absent.

- *Disproof:* It is a false alarm if the application normalises input to valid UTF-8 before escaping, or if the differing response is the application's own input-validation layer rejecting the string before any LDAP call is made. Show that the request never produced a bind or search operation - no LDAP session in the capture or logs - and the high-byte test proved nothing about escaping.
- *Evidence:* high_confidence — [cwe.mitre.org](https://cwe.mitre.org/data/definitions/90.html); [rfc-editor.org](https://www.rfc-editor.org/rfc/rfc4515.html)

## Chaining

_No verified chain_link items yet._ Derived from evidence only, so this section is empty rather than plausible.


## 6. Impact

_What is actually demonstrable, and what to stop claiming._

**LDAP injection (CWE-90) is an OWASP A03:2021 injection weakness that, when exploitable, undermines confidentiality, integrity, and availability of directory-backed data.**

CWE-90 describes improper neutralization of special elements in an LDAP query. Its impact table lists: Execute Unauthorized Code or Commands; Read Application Data; Modify Application Data, with Scope Confidentiality, Integrity, and Availability (cwe.mitre.org/data/definitions/90.html). The OWASP WSTG confirms that a successful LDAP injection lets a tester access unauthorized content, evade application restrictions, gather unauthorized information, and add or modify objects inside the LDAP tree (owasp.github.io/.../06-LDAP_Injection).

- *Disproof:* LDAP injection is not confined to reading directory content: the same filter manipulation can alter or insert objects and, in some configurations, be abused to cause denial of service through expensive or repeated searches. Treating it as a read-only data-leakage issue underestimates its impact.
- *Evidence:* high_confidence — [cheatsheetseries.owasp.org](https://cheatsheetseries.owasp.org/cheatsheets/Injection_Prevention_Cheat_Sheet.html); [cwe.mitre.org](https://cwe.mitre.org/data/definitions/90.html); [owasp.github.io](https://owasp.github.io/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Injection/06-LDAP_Injection)

## Coverage gap

These stages have no verified evidence and are therefore absent above: Preconditions, Chaining.
A procedure with a missing validation stage is not safe to act on — it produces findings rather than proofs.

---

*Generated from the evidence base. Where this file and the database disagree, the database is correct.*
