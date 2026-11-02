# History

Append-only. Each entry records WHY the skill changed, not just that it did. Improvement means better hunting behaviour, not more text.

## 2026-10-02 15:57 — 1 diff lines
- items: 22 (supported 22), FP rules 2, chains 1, state mature

```diff
(initial generation, 2026-10-02)
```

## 2026-10-02 16:07 — 8 diff lines
- items: 22 (supported 22), FP rules 2, chains 1, state mature

```diff
--- dns_enum@current
+++ dns_enum@new
@@ -100,4 +100,4 @@
   - Sources: <https://www.rfc-editor.org/rfc/rfc1035.html> · <https://academy.hackthebox.com/catalogue/paths> · <https://www.helpnetsecurity.com/2025/02/03/baddns-open-source-tool-check-domain-subdomain-takeover/>
 
 ---
-Full class document: `domains/network/infrastructure/dns_enum/EVIDENCE.md` · retrieve more with `python -m wks.cli search "<query>" --class-id dns_enum`
+Full class document: `domains/network/infrastructure/dns_enum/knowledge/DIGEST.md` · retrieve more with `python -m wks.cli search "<query>" --class-id dns_enum`
```

## 2026-10-02 19:37 — 62 diff lines
- items: 8 (supported 8), FP rules 2, chains 1, state researching
- still missing: items

```diff
--- dns_enum@current
+++ dns_enum@new
@@ -10,8 +10,8 @@
      python -m wks.skillgen -->
 
 > surface `net` · CWE CWE-200 · OWASP —
-> evidence: 22 items, 22 supported, 2 FP rules, 1 chains
-> maturity: **mature**
+> evidence: 8 items, 8 supported, 2 FP rules, 1 chains
+> maturity: **researching** — missing: items
 
 DNS names hosts and services, so a zone disclosure enumerates the network without touching it.
 
@@ -26,48 +26,6 @@
 
 ## Techniques (what to change)
 
-- An XSS vulnerability may allow an attacker to execute arbitrary JavaScript code within the target's browser and result in complete web application compromise if chained together with other vulnerabilities.
-  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "An XSS vulnerability may allow an attacker to execute arbitrary JavaScript code within the".
-  - Sources: <https://academy.hackthebox.com/catalogue/paths> · <https://www.helpnetsecurity.com/2025/02/03/baddns-open-source-tool-check-domain-subdomain-takeover/>
-- SQL injection is a code injection technique used to take advantage of coding vulnerabilities and inject SQL queries via an application to bypass authentication, retrieve data from the back-end database, or achieve code execution on the underlying server.
-  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "SQL injection is a code injection technique used to take advantage of coding vulnerabiliti".
-  - Sources: <https://www.talosintelligence.com/vulnerability_reports/TALOS-2019-0851> · <https://academy.hackthebox.com/catalogue/paths> · <https://www.helpnetsecurity.com/2025/02/03/baddns-open-source-tool-check-domain-subdomain-takeover/>
-- We will cover how to identify, exploit, and prevent each of them through various methods.
-  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "We will cover how to identify, exploit, and prevent each of them through various methods.".
-  - Sources: <https://www.talosintelligence.com/vulnerability_reports/TALOS-2019-0851> · <https://academy.hackthebox.com/catalogue/paths>
-- This module covers the most common attacks and vulnerabilities that can affect web application sessions, such as Session Hijacking, Session Fixation, Cross-Site Request Forgery, Cross-Site Scripting, and Open Redirects.
-  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "This module covers the most common attacks and vulnerabilities that can affect web applica".
-  - Sources: <https://academy.hackthebox.com/catalogue/paths> · <https://www.helpnetsecurity.com/2025/02/03/baddns-open-source-tool-check-domain-subdomain-takeover/>
-- These flaws enable attackers to upload malicious files, execute arbitrary commands on the back-end server, and even take control over the entire server and all web applications hosted on it and potentially gain access to sensitive data or cause a service disruption.
-  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "These flaws enable attackers to upload malicious files, execute arbitrary commands on the ".
-  - Sources: <https://academy.hackthebox.com/catalogue/paths> · <https://www.helpnetsecurity.com/2025/02/03/baddns-open-source-tool-check-domain-subdomain-takeover/>
-- Buffer overflows are common vulnerabilities in software applications that can be exploited to achieve remote code execution (RCE) or perform a Denial-of-Service (DoS) attack.
-  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Buffer overflows are common vulnerabilities in software applications that can be exploited".
-  - Sources: <https://www.talosintelligence.com/vulnerability_reports/TALOS-2019-0851> · <https://academy.hackthebox.com/catalogue/paths>
-- We will discuss how to identify, exploit, and prevent TLS attacks.
-  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "We will discuss how to identify, exploit, and prevent TLS attacks.".
-  - Sources: <https://www.talosintelligence.com/vulnerability_reports/TALOS-2019-0851> · <https://academy.hackthebox.com/catalogue/paths>
-- We will cover how to identify, exploit, and prevent each of these vulnerabilities.
-  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "We will cover how to identify, exploit, and prevent each of these vulnerabilities.".
-  - Sources: <https://www.talosintelligence.com/vulnerability_reports/TALOS-2019-0851> · <https://academy.hackthebox.com/catalogue/paths>
-- If improperly configured or implemented, common web security vulnerabilities such as Information Disclosure, SQL Injection, and Insecure Direct Object Reference (IDOR) may arise.
-  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "If improperly configured or implemented, common web security vulnerabilities such as Infor".
-  - Sources: <https://academy.hackthebox.com/catalogue/paths> · <https://www.helpnetsecurity.com/2025/02/03/baddns-open-source-tool-check-domain-subdomain-takeover/>
-- Kerberos is an authentication protocol that allows users to authenticate and access services on a potentially insecure network.
-  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Kerberos is an authentication protocol that allows users to authenticate and access servic".
-  - Sources: <https://academy.hackthebox.com/catalogue/paths> · <https://www.helpnetsecurity.com/2025/02/03/baddns-open-source-tool-check-domain-subdomain-takeover/>
-- Binary exploitation is a core tenet of penetration testing, but learning it can be daunting.
-  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Binary exploitation is a core tenet of penetration testing, but learning it can be dauntin".
-  - Sources: <https://academy.hackthebox.com/catalogue/paths> · <https://www.helpnetsecurity.com/2025/02/03/baddns-open-source-tool-check-domain-subdomain-takeover/>
-- An XSS vulnerability may allow an attacker to execute arbitrary JavaScript code within the target's browser and result in complete web application compromise if chained together with other vulnerabilities.
-  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "An XSS vulnerability may allow an attacker to execute arbitrary JavaScript code within the".
-  - Sources: <https://www.talosintelligence.com/vulnerability_reports/TALOS-2019-0851> · <https://academy.hackthebox.com/catalogue/paths> · <https://www.helpnetsecurity.com/2025/02/03/baddns-open-source-tool-check-domain-subdomain-takeover/>
-- Command injection vulnerabilities can be leveraged to compromise a hosting server and its entire network.
-  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Command injection vulnerabilities can be leveraged to compromise a hosting server and its ".
-  - Sources: <https://www.talosintelligence.com/vulnerability_reports/TALOS-2019-0851> · <https://academy.hackthebox.com/catalogue/paths>
-- Most often, if we can exploit a vulnerability and gain a foothold on a host, it will be running some version of Windows or Linux.
-  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Most often, if we can exploit a vulnerability and gain a foothold on a host, it will be ru".
-  - Sources: <https://www.talosintelligence.com/vulnerability_reports/TALOS-2019-0851> · <https://academy.hackthebox.com/catalogue/paths>
 - The value of a zone transfer is proportional to what the zone's NS and SOA records already imply, so enumerate those records first to size the transfer, then use the transfer to recover only the names those records never exposed.
   - **Disproof:** The claim is wrong, and the transfer added no enumeration value, if every record it returned was already obtainable from NS, SOA, MX, TXT and service-record queries against the public zone, so no name was concealed by the refusal to transfer; or the transfer returned only the SOA and a single NS RRset matching the authoritative set. In that case the correct finding is a closed zone, not a disclosure, and the enumeration value of the attempt is nil.
   - Sources: <https://www.rfc-editor.org/rfc/rfc1035.html> · <https://academy.hackthebox.com/catalogue/paths>
```

## 2026-10-03 01:46 — 39 diff lines
- items: 10 (supported 10), FP rules 2, chains 1, state researching
- still missing: items

```diff
--- dns_enum@current
+++ dns_enum@new
@@ -10,7 +10,7 @@
      python -m wks.skillgen -->
 
 > surface `net` · CWE CWE-200 · OWASP —
-> evidence: 8 items, 8 supported, 2 FP rules, 1 chains
+> evidence: 10 items, 10 supported, 2 FP rules, 1 chains
 > maturity: **researching** — missing: items
 
 DNS names hosts and services, so a zone disclosure enumerates the network without touching it.
@@ -32,6 +32,9 @@
 - A DNS zone enumerates every host in a namespace without touching it, and an AXFR zone transfer returns the entire zone, so one query against a misconfigured server replaces host discovery.
   - **Disproof:** If an AXFR request from an unauthorized source is refused, or the server only answers transfers to configured secondaries, then the zone cannot be enumerated this way and discovery requires per-host probing.
   - Sources: <https://www.rfc-editor.org/rfc/rfc1035.html> · <https://learn.microsoft.com/en-us/windows-server/networking/dns/dns-top>
+- Zone transfer or a misconfigured DNS service reveals the internal host inventory that no port scan would expose.
+  - **Disproof:** Refuted when the authoritative server refuses AXFR and out-of-zone queries, so the internal inventory is never returned.
+  - Sources: <https://attack.mitre.org/techniques/T1016/001/> · <https://www.rfc-editor.org/rfc/rfc1035.html> · <https://raw.githubusercontent.com/Esther7171/HackTheBox-Writeups-Walkthroughs/main/Write-ups/Academy/02.%20Information%20Gathering/10b.%20DNS%20Enumeration%20Python/DNS%20Enumeration%20Using%20Python.md>
 
 ## Validation bar (how to prove it)
 
@@ -46,10 +49,16 @@
 
 - Reject a dns_enum finding until it is distinguished from the adjacent behaviour this class also covers. "A zone transfer that returns internal hostnames supplies the candidate subdomain list that turns a dangling DNS record into a takeover, because the transfer reveals names that public certificate and archive sources never listed and those..." and "A zone-transfer attempt is only an unexpected probe when the target nameservers are not meant to serve secondaries; where the SOA declares real secondary nameservers, an AXFR request is the designed replication path and its refusal is the..." share a surface and a symptom, so a response that matches the first is not evidence for it while the second remains possible.
   - **Disproof:** This rule is wrong if a controlled test shows the two behaviours can never co-occur on the same surface, or if the corpus entry for "A zone-transfer attempt is only an unexpected probe when the target na" is out of date. In that case this class needs its false-positive guidance rewritten rather than deleted.
-  - Sources: <https://academy.hackthebox.com/catalogue/paths> · <https://learn.microsoft.com/en-us/windows-server/networking/dns/dns-top>
+  - Sources: <https://www.rfc-editor.org/rfc/rfc1035.html> · <https://learn.microsoft.com/en-us/windows-server/networking/dns/dns-top>
 - An AXFR refused by every authoritative nameserver, returning REFUSED or NOTAUTH with an SOA in the authority section, is a closed zone and not a DNS disclosure, provided the same refusal is observed from an address outside the declared secondary set.
   - **Disproof:** The rule is wrong, and the zone is exposed, if any authoritative nameserver returns a full RRsets transfer to an address outside its declared secondary set; if the response is a truncated or partial transfer (SOA plus a subset of records) rather than a clean refusal; if the SOA serial in the refusal differs from the publicly queryable serial, indicating the authority is serving different data than the public view; or if a secondaries-permitted ACL is absent and any source address is served. A partial answer is a leak, not a closure.
   - Sources: <https://www.rfc-editor.org/rfc/rfc1035.html> · <https://academy.hackthebox.com/catalogue/paths>
+
+## Evidence requirements
+
+- A convincing observation for this class is: Adjacent behaviour that produces the same observable result: A zone-transfer attempt is only an unexpected probe when the target nameservers are not meant to serve secondaries; where the SOA declares real secondary nameservers, an AXFR request is the designed replication path and its refusal is the...
+  - **Disproof:** Not evidence when the observable cannot be produced at all -- blind, server-side-only, or identical-in-every-case behaviour leaves nothing to show. The originating rule (dns_enum.fp_rule.auto.derived) states the full boundary.
+  - Sources: <https://www.rfc-editor.org/rfc/rfc1035.html> · <https://learn.microsoft.com/en-us/windows-server/networking/dns/dns-top>
 
 ## Chaining opportunities
 
```

## 2026-10-04 00:43 — 83 diff lines
- items: 10 (supported 10), FP rules 2, chains 1, state researching
- still missing: items

```diff
--- dns_enum@current
+++ dns_enum@new
@@ -20,51 +20,66 @@
 
 ## Prerequisites (do not start without these)
 
-- A zone-transfer attempt is only an unexpected probe when the target nameservers are not meant to serve secondaries; where the SOA declares real secondary nameservers, an AXFR request is the designed replication path and its refusal is the correct behaviour.
+- A zone-transfer attempt is only an unexpected probe when the target nameservers are not meant to serve secondaries; where the SOA declares real secondary nameservers, an AXFR request is the designed replication path and its refusal is the correct behaviour.  _(merged 1 duplicate row(s))_
   - **Disproof:** The claim is wrong, and a refused or silent AXFR is not a clean configuration, if the transfer succeeds from a nameserver that is not in the zone's declared secondary set, or if a secondaries-permitted ACL is missing so any address can pull the whole zone. Success from a non-secondary address is the disproof for the expectation claim; but note that refusal from a genuinely non-secondary server does prove the zone is closed for that host, so the expectation still holds there.
   - Sources: <https://academy.hackthebox.com/catalogue/paths> · <https://www.rfc-editor.org/rfc/rfc1912.html>
 
 ## Techniques (what to change)
 
-- The value of a zone transfer is proportional to what the zone's NS and SOA records already imply, so enumerate those records first to size the transfer, then use the transfer to recover only the names those records never exposed.
+- A DNS zone enumerates every host in a namespace without touching it, and an AXFR zone transfer returns the entire zone, so one query against a misconfigured server replaces host discovery.  _(merged 1 duplicate row(s))_
+  - **Disproof:** If an AXFR request from an unauthorized source is refused, or the server only answers transfers to configured secondaries, then the zone cannot be enumerated this way and discovery requires per-host probing.
+  - Sources: <https://www.rfc-editor.org/rfc/rfc1035.html> · <https://learn.microsoft.com/en-us/windows-server/networking/dns/dns-top>
+- The value of a zone transfer is proportional to what the zone's NS and SOA records already imply, so enumerate those records first to size the transfer, then use the transfer to recover only the names those records never exposed.  _(merged 1 duplicate row(s))_
   - **Disproof:** The claim is wrong, and the transfer added no enumeration value, if every record it returned was already obtainable from NS, SOA, MX, TXT and service-record queries against the public zone, so no name was concealed by the refusal to transfer; or the transfer returned only the SOA and a single NS RRset matching the authoritative set. In that case the correct finding is a closed zone, not a disclosure, and the enumeration value of the attempt is nil.
   - Sources: <https://www.rfc-editor.org/rfc/rfc1035.html> · <https://academy.hackthebox.com/catalogue/paths>
-- A DNS zone enumerates every host in a namespace without touching it, and an AXFR zone transfer returns the entire zone, so one query against a misconfigured server replaces host discovery.
-  - **Disproof:** If an AXFR request from an unauthorized source is refused, or the server only answers transfers to configured secondaries, then the zone cannot be enumerated this way and discovery requires per-host probing.
-  - Sources: <https://www.rfc-editor.org/rfc/rfc1035.html> · <https://learn.microsoft.com/en-us/windows-server/networking/dns/dns-top>
-- Zone transfer or a misconfigured DNS service reveals the internal host inventory that no port scan would expose.
+- Zone transfer or a misconfigured DNS service reveals the internal host inventory that no port scan would expose.  _(merged 1 duplicate row(s))_
   - **Disproof:** Refuted when the authoritative server refuses AXFR and out-of-zone queries, so the internal inventory is never returned.
   - Sources: <https://attack.mitre.org/techniques/T1016/001/> · <https://www.rfc-editor.org/rfc/rfc1035.html> · <https://raw.githubusercontent.com/Esther7171/HackTheBox-Writeups-Walkthroughs/main/Write-ups/Academy/02.%20Information%20Gathering/10b.%20DNS%20Enumeration%20Python/DNS%20Enumeration%20Using%20Python.md>
 
 ## Validation bar (how to prove it)
 
-- A refused DNS zone transfer proves the zone is not AXFR-open, not that no records were retrieved; enumeration evidence requires a returned record set from the transfer, an NSEC walk, or a secondary resolver.
+- A refused DNS zone transfer proves the zone is not AXFR-open, not that no records were retrieved; enumeration evidence requires a returned record set from the transfer, an NSEC walk, or a secondary resolver.  _(merged 1 duplicate row(s))_
   - **Disproof:** The transfer or an equivalent anonymous read returns an actual record set beyond SOA and NS, or an NSEC chain yields NXDOMAIN proofs for names that resolve elsewhere, showing records were retrieved without authentication.
   - Sources: <https://www.talosintelligence.com/vulnerability_reports/TALOS-2019-0851> · <https://www.helpnetsecurity.com/2025/02/03/baddns-open-source-tool-check-domain-subdomain-takeover/>
-- A zone-transfer disclosure is validated only by showing a full multi-record answer whose SOA serial is current and whose names exceed the public NS/SOA/MX set, because an empty or serial-stale answer is a replica, not a disclosure.
+- A zone-transfer disclosure is validated only by showing a full multi-record answer whose SOA serial is current and whose names exceed the public NS/SOA/MX set, because an empty or serial-stale answer is a replica, not a disclosure.  _(merged 1 duplicate row(s))_
   - **Disproof:** The validation fails, and the transfer is not a disclosure, if the returned SOA serial is older than the publicly queryable serial (stale replica); the answer contains the SOA but no additional owner names; every returned record was already obtainable through normal public queries; or the transfer succeeded only from an address inside the declared secondary set, which is the designed replication path rather than an exposure. A current serial plus at least one name absent from the public set is what the finding requires.
   - Sources: <https://www.rfc-editor.org/rfc/rfc1035.html> · <https://academy.hackthebox.com/catalogue/paths> · <https://www.rfc-editor.org/rfc/rfc1912.html>
 
 ## False-positive rules (when to reject it)
 
-- Reject a dns_enum finding until it is distinguished from the adjacent behaviour this class also covers. "A zone transfer that returns internal hostnames supplies the candidate subdomain list that turns a dangling DNS record into a takeover, because the transfer reveals names that public certificate and archive sources never listed and those..." and "A zone-transfer attempt is only an unexpected probe when the target nameservers are not meant to serve secondaries; where the SOA declares real secondary nameservers, an AXFR request is the designed replication path and its refusal is the..." share a surface and a symptom, so a response that matches the first is not evidence for it while the second remains possible.
+- An AXFR refused by every authoritative nameserver, returning REFUSED or NOTAUTH with an SOA in the authority section, is a closed zone and not a DNS disclosure, provided the same refusal is observed from an address outside the declared secondary set.  _(merged 1 duplicate row(s))_
+  - **Disproof:** The rule is wrong, and the zone is exposed, if any authoritative nameserver returns a full RRsets transfer to an address outside its declared secondary set; if the response is a truncated or partial transfer (SOA plus a subset of records) rather than a clean refusal; if the SOA serial in the refusal differs from the publicly queryable serial, indicating the authority is serving different data than the public view; or if a secondaries-permitted ACL is absent and any source address is served. A partial answer is a leak, not a closure.
+  - Sources: <https://www.rfc-editor.org/rfc/rfc1035.html> · <https://academy.hackthebox.com/catalogue/paths>
+- Reject a dns_enum finding until it is distinguished from the adjacent behaviour this class also covers. "A zone transfer that returns internal hostnames supplies the candidate subdomain list that turns a dangling DNS record into a takeover, because the transfer reveals names that public certificate and archive sources never listed and those..." and "A zone-transfer attempt is only an unexpected probe when the target nameservers are not meant to serve secondaries; where the SOA declares real secondary nameservers, an AXFR request is the designed replication path and its refusal is the..." share a surface and a symptom, so a response that matches the first is not evidence for it while the second remains possible.  _(merged 1 duplicate row(s))_
   - **Disproof:** This rule is wrong if a controlled test shows the two behaviours can never co-occur on the same surface, or if the corpus entry for "A zone-transfer attempt is only an unexpected probe when the target na" is out of date. In that case this class needs its false-positive guidance rewritten rather than deleted.
   - Sources: <https://www.rfc-editor.org/rfc/rfc1035.html> · <https://learn.microsoft.com/en-us/windows-server/networking/dns/dns-top>
-- An AXFR refused by every authoritative nameserver, returning REFUSED or NOTAUTH with an SOA in the authority section, is a closed zone and not a DNS disclosure, provided the same refusal is observed from an address outside the declared secondary set.
-  - **Disproof:** The rule is wrong, and the zone is exposed, if any authoritative nameserver returns a full RRsets transfer to an address outside its declared secondary set; if the response is a truncated or partial transfer (SOA plus a subset of records) rather than a clean refusal; if the SOA serial in the refusal differs from the publicly queryable serial, indicating the authority is serving different data than the public view; or if a secondaries-permitted ACL is absent and any source address is served. A partial answer is a leak, not a closure.
-  - Sources: <https://www.rfc-editor.org/rfc/rfc1035.html> · <https://academy.hackthebox.com/catalogue/paths>
 
 ## Evidence requirements
 
-- A convincing observation for this class is: Adjacent behaviour that produces the same observable result: A zone-transfer attempt is only an unexpected probe when the target nameservers are not meant to serve secondaries; where the SOA declares real secondary nameservers, an AXFR request is the designed replication path and its refusal is the...
+- A convincing observation for this class is: Adjacent behaviour that produces the same observable result: A zone-transfer attempt is only an unexpected probe when the target nameservers are not meant to serve secondaries; where the SOA declares real secondary nameservers, an AXFR request is the designed replication path and its refusal is the...  _(merged 1 duplicate row(s))_
   - **Disproof:** Not evidence when the observable cannot be produced at all -- blind, server-side-only, or identical-in-every-case behaviour leaves nothing to show. The originating rule (dns_enum.fp_rule.auto.derived) states the full boundary.
   - Sources: <https://www.rfc-editor.org/rfc/rfc1035.html> · <https://learn.microsoft.com/en-us/windows-server/networking/dns/dns-top>
 
 ## Chaining opportunities
 
-- A zone transfer that returns internal hostnames supplies the candidate subdomain list that turns a dangling DNS record into a takeover, because the transfer reveals names that public certificate and archive sources never listed and those names are the ones still pointing at de-provisioned third-party services.
+- A zone transfer that returns internal hostnames supplies the candidate subdomain list that turns a dangling DNS record into a takeover, because the transfer reveals names that public certificate and archive sources never listed and those names are the ones still pointing at de-provisioned third-party services.  _(merged 1 duplicate row(s))_
   - **Disproof:** The chain is refuted if the zone transfer is refused or returns nothing beyond the public NS and SOA set, leaving no name the certificate sources missed; or if every transferred name resolves to an active, correctly provisioned service, so nothing is claimable; or if the recovered internal names sit outside the registrable domain and therefore outside any session cookie's Domain scope, making a takeover phishing-only rather than session-affecting. The transfer must produce at least one live dangling record for the chain to end anywhere.
   - Sources: <https://www.rfc-editor.org/rfc/rfc1035.html> · <https://academy.hackthebox.com/catalogue/paths> · <https://www.helpnetsecurity.com/2025/02/03/baddns-open-source-tool-check-domain-subdomain-takeover/>
 
+
+## Hunt procedure
+
+1. Enumerate the surface before probing: collect every endpoint, parameter and object id the class could plausibly sit on.
+2. Establish a CONTROLLED BASELINE first — one unauthenticated and one authenticated low-privilege request per candidate — and diff against the probe. A difference with no baseline proves nothing.
+3. Change exactly ONE variable per probe. Two changes produce a difference you cannot attribute.
+4. Record raw request and response pairs verbatim, including headers, before you interpret anything.
+
+### What counts as proof
+
+- Two responses that differ in a way the CONTROL did not, produced by a single changed variable.
+- An invariant the application is supposed to hold, observed broken.
+- A second independent confirmation, or an explicit statement that this is single-account evidence only.
+
+> Ordered prerequisites, the validation bar and the false-positive rules below are the authority: this block is the mechanics, those are the standard.
 ---
 Full class document: `domains/network/infrastructure/dns_enum/knowledge/DIGEST.md` · retrieve more with `python -m wks.cli search "<query>" --class-id dns_enum`
```

## 2026-10-04 00:50 — 14 diff lines
- items: 10 (supported 10), FP rules 2, chains 1, state researching
- still missing: items

```diff
--- dns_enum@current
+++ dns_enum@new
@@ -69,10 +69,7 @@
 
 ## Hunt procedure
 
-1. Enumerate the surface before probing: collect every endpoint, parameter and object id the class could plausibly sit on.
-2. Establish a CONTROLLED BASELINE first — one unauthenticated and one authenticated low-privilege request per candidate — and diff against the probe. A difference with no baseline proves nothing.
-3. Change exactly ONE variable per probe. Two changes produce a difference you cannot attribute.
-4. Record raw request and response pairs verbatim, including headers, before you interpret anything.
+1. Enumerate with subfinder/amass against the registrable domain only, then resolve the names and check which point at live, in-scope services.
 
 ### What counts as proof
 
```

## 2026-10-04 19:46 — 9 diff lines
- items: 10 (supported 10), FP rules 2, chains 1, state researching
- still missing: items

```diff
--- dns_enum@current
+++ dns_enum@new
@@ -80,6 +80,3 @@
 > Ordered prerequisites, the validation bar and the false-positive rules below are the authority: this block is the mechanics, those are the standard.
 ---
 Full class document: `domains/network/infrastructure/dns_enum/knowledge/DIGEST.md` · retrieve more with `python -m wks.cli search "<query>" --class-id dns_enum`
-
----
-Runbook: [`HUNT.md`](HUNT.md) — every promoted technique mapped to an executable procedure with the observables to record.
```

## 2026-10-04 21:39 — 35 diff lines
- items: 12 (supported 12), FP rules 2, chains 1, state mature

```diff
--- dns_enum@current
+++ dns_enum@new
@@ -10,8 +10,8 @@
      python -m wks.skillgen -->
 
 > surface `net` · CWE CWE-200 · OWASP —
-> evidence: 10 items, 10 supported, 2 FP rules, 1 chains
-> maturity: **researching** — missing: items
+> evidence: 12 items, 12 supported, 2 FP rules, 1 chains
+> maturity: **mature**
 
 DNS names hosts and services, so a zone disclosure enumerates the network without touching it.
 
@@ -29,12 +29,21 @@
 - A DNS zone enumerates every host in a namespace without touching it, and an AXFR zone transfer returns the entire zone, so one query against a misconfigured server replaces host discovery.  _(merged 1 duplicate row(s))_
   - **Disproof:** If an AXFR request from an unauthorized source is refused, or the server only answers transfers to configured secondaries, then the zone cannot be enumerated this way and discovery requires per-host probing.
   - Sources: <https://www.rfc-editor.org/rfc/rfc1035.html> · <https://learn.microsoft.com/en-us/windows-server/networking/dns/dns-top>
+- A negative answer from a DNSSEC-signed zone that uses NSEC rather than NSEC3 carries the next existing owner name in its authority section, so an anonymous client can follow that chain and walk the whole zone without an AXFR.  _(merged 1 duplicate row(s))_
+  - **Disproof:** Wrong if the zone publishes NSEC3 rather than NSEC, because the owner and next-owner names are salted hashes and no plaintext successor is returned to follow; equally wrong if minimally covering NSEC records are served, since the span then brackets only the queried label and nothing else is disclosed. Also wrong if the authority section of the negative response is empty, which is the unsigned or opt-out case where one name is never linked to the next. A walk that terminates after a single query, or that returns only names already obtainable from NS, SOA, MX and service-record queries, reveals nothing the public surface did not already publish.
+  - Sources: <https://www.rfc-editor.org/rfc/rfc4034.html> · <https://blog.apnic.net/2023/01/17/subdomain-enumeration-with-dnssec/> · <https://svn.nmap.org/nmap/scripts/dns-nsec-enum.nse>
 - The value of a zone transfer is proportional to what the zone's NS and SOA records already imply, so enumerate those records first to size the transfer, then use the transfer to recover only the names those records never exposed.  _(merged 1 duplicate row(s))_
   - **Disproof:** The claim is wrong, and the transfer added no enumeration value, if every record it returned was already obtainable from NS, SOA, MX, TXT and service-record queries against the public zone, so no name was concealed by the refusal to transfer; or the transfer returned only the SOA and a single NS RRset matching the authoritative set. In that case the correct finding is a closed zone, not a disclosure, and the enumeration value of the attempt is nil.
   - Sources: <https://www.rfc-editor.org/rfc/rfc1035.html> · <https://academy.hackthebox.com/catalogue/paths>
 - Zone transfer or a misconfigured DNS service reveals the internal host inventory that no port scan would expose.  _(merged 1 duplicate row(s))_
   - **Disproof:** Refuted when the authoritative server refuses AXFR and out-of-zone queries, so the internal inventory is never returned.
   - Sources: <https://attack.mitre.org/techniques/T1016/001/> · <https://www.rfc-editor.org/rfc/rfc1035.html> · <https://raw.githubusercontent.com/Esther7171/HackTheBox-Writeups-Walkthroughs/main/Write-ups/Academy/02.%20Information%20Gathering/10b.%20DNS%20Enumeration%20Python/DNS%20Enumeration%20Using%20Python.md>
+
+## Tests
+
+- A wildcard DNS record synthesises an answer for every name under its owner, so a subdomain bruteforce returns a hit for every candidate and the wildcard payload must be probed and subtracted before any discovered hostname is believed.  _(merged 1 duplicate row(s))_
+  - **Disproof:** Not a finding when a randomly generated label under the parent comes back NXDOMAIN from every authoritative nameserver, because nothing is being synthesised and the candidate list needs no subtraction at all; likewise not a finding when the parent answers non-existent names with a distinct per-name address, since address-set subtraction then removes nothing and the surviving names are still fabrications. Reject too when the repeated address is shared hosting rather than a catch-all, where unrelated real names coincidentally share one address, and when the candidate was never resolved against the target's own authoritative server at all but taken from a passive certificate or archive list, which is passive discovery and not this test.
+  - Sources: <https://www.rfc-editor.org/rfc/rfc1034.html> · <https://unit42.paloaltonetworks.com/wildcard-dns-abuse/> · <https://digi.ninja/blog/dns_wildcard_recon.php>
 
 ## Validation bar (how to prove it)
 
```

## 2026-10-31 06:41 — 45 diff lines
- items: 12 (supported 8), FP rules 1, chains 1, state researching
- still missing: fp_rules

```diff
--- dns_enum@current
+++ dns_enum@new
@@ -10,8 +10,8 @@
      python -m wks.skillgen -->
 
 > surface `net` · CWE CWE-200 · OWASP —
-> evidence: 12 items, 12 supported, 2 FP rules, 1 chains
-> maturity: **mature**
+> evidence: 12 items, 8 supported, 1 FP rules, 1 chains
+> maturity: **researching** — missing: fp_rules
 
 DNS names hosts and services, so a zone disclosure enumerates the network without touching it.
 
@@ -26,13 +26,13 @@
 
 ## Techniques (what to change)
 
-- A DNS zone enumerates every host in a namespace without touching it, and an AXFR zone transfer returns the entire zone, so one query against a misconfigured server replaces host discovery.  _(merged 1 duplicate row(s))_
+- A DNS zone enumerates every host in a namespace without touching it, and an AXFR zone transfer returns the entire zone, so one query against a misconfigured server replaces host discovery.  _(merged 1 duplicate row(s))_ _(unverified)_
   - **Disproof:** If an AXFR request from an unauthorized source is refused, or the server only answers transfers to configured secondaries, then the zone cannot be enumerated this way and discovery requires per-host probing.
   - Sources: <https://www.rfc-editor.org/rfc/rfc1035.html> · <https://learn.microsoft.com/en-us/windows-server/networking/dns/dns-top>
 - A negative answer from a DNSSEC-signed zone that uses NSEC rather than NSEC3 carries the next existing owner name in its authority section, so an anonymous client can follow that chain and walk the whole zone without an AXFR.  _(merged 1 duplicate row(s))_
   - **Disproof:** Wrong if the zone publishes NSEC3 rather than NSEC, because the owner and next-owner names are salted hashes and no plaintext successor is returned to follow; equally wrong if minimally covering NSEC records are served, since the span then brackets only the queried label and nothing else is disclosed. Also wrong if the authority section of the negative response is empty, which is the unsigned or opt-out case where one name is never linked to the next. A walk that terminates after a single query, or that returns only names already obtainable from NS, SOA, MX and service-record queries, reveals nothing the public surface did not already publish.
   - Sources: <https://www.rfc-editor.org/rfc/rfc4034.html> · <https://blog.apnic.net/2023/01/17/subdomain-enumeration-with-dnssec/> · <https://svn.nmap.org/nmap/scripts/dns-nsec-enum.nse>
-- The value of a zone transfer is proportional to what the zone's NS and SOA records already imply, so enumerate those records first to size the transfer, then use the transfer to recover only the names those records never exposed.  _(merged 1 duplicate row(s))_
+- The value of a zone transfer is proportional to what the zone's NS and SOA records already imply, so enumerate those records first to size the transfer, then use the transfer to recover only the names those records never exposed.  _(merged 1 duplicate row(s))_ _(unverified)_
   - **Disproof:** The claim is wrong, and the transfer added no enumeration value, if every record it returned was already obtainable from NS, SOA, MX, TXT and service-record queries against the public zone, so no name was concealed by the refusal to transfer; or the transfer returned only the SOA and a single NS RRset matching the authoritative set. In that case the correct finding is a closed zone, not a disclosure, and the enumeration value of the attempt is nil.
   - Sources: <https://www.rfc-editor.org/rfc/rfc1035.html> · <https://academy.hackthebox.com/catalogue/paths>
 - Zone transfer or a misconfigured DNS service reveals the internal host inventory that no port scan would expose.  _(merged 1 duplicate row(s))_
@@ -59,13 +59,13 @@
 - An AXFR refused by every authoritative nameserver, returning REFUSED or NOTAUTH with an SOA in the authority section, is a closed zone and not a DNS disclosure, provided the same refusal is observed from an address outside the declared secondary set.  _(merged 1 duplicate row(s))_
   - **Disproof:** The rule is wrong, and the zone is exposed, if any authoritative nameserver returns a full RRsets transfer to an address outside its declared secondary set; if the response is a truncated or partial transfer (SOA plus a subset of records) rather than a clean refusal; if the SOA serial in the refusal differs from the publicly queryable serial, indicating the authority is serving different data than the public view; or if a secondaries-permitted ACL is absent and any source address is served. A partial answer is a leak, not a closure.
   - Sources: <https://www.rfc-editor.org/rfc/rfc1035.html> · <https://academy.hackthebox.com/catalogue/paths>
-- Reject a dns_enum finding until it is distinguished from the adjacent behaviour this class also covers. "A zone transfer that returns internal hostnames supplies the candidate subdomain list that turns a dangling DNS record into a takeover, because the transfer reveals names that public certificate and archive sources never listed and those..." and "A zone-transfer attempt is only an unexpected probe when the target nameservers are not meant to serve secondaries; where the SOA declares real secondary nameservers, an AXFR request is the designed replication path and its refusal is the..." share a surface and a symptom, so a response that matches the first is not evidence for it while the second remains possible.  _(merged 1 duplicate row(s))_
+- Reject a dns_enum finding until it is distinguished from the adjacent behaviour this class also covers. "A zone transfer that returns internal hostnames supplies the candidate subdomain list that turns a dangling DNS record into a takeover, because the transfer reveals names that public certificate and archive sources never listed and those..." and "A zone-transfer attempt is only an unexpected probe when the target nameservers are not meant to serve secondaries; where the SOA declares real secondary nameservers, an AXFR request is the designed replication path and its refusal is the..." share a surface and a symptom, so a response that matches the first is not evidence for it while the second remains possible.  _(merged 1 duplicate row(s))_ _(unverified)_
   - **Disproof:** This rule is wrong if a controlled test shows the two behaviours can never co-occur on the same surface, or if the corpus entry for "A zone-transfer attempt is only an unexpected probe when the target na" is out of date. In that case this class needs its false-positive guidance rewritten rather than deleted.
   - Sources: <https://www.rfc-editor.org/rfc/rfc1035.html> · <https://learn.microsoft.com/en-us/windows-server/networking/dns/dns-top>
 
 ## Evidence requirements
 
-- A convincing observation for this class is: Adjacent behaviour that produces the same observable result: A zone-transfer attempt is only an unexpected probe when the target nameservers are not meant to serve secondaries; where the SOA declares real secondary nameservers, an AXFR request is the designed replication path and its refusal is the...  _(merged 1 duplicate row(s))_
+- A convincing observation for this class is: Adjacent behaviour that produces the same observable result: A zone-transfer attempt is only an unexpected probe when the target nameservers are not meant to serve secondaries; where the SOA declares real secondary nameservers, an AXFR request is the designed replication path and its refusal is the...  _(merged 1 duplicate row(s))_ _(unverified)_
   - **Disproof:** Not evidence when the observable cannot be produced at all -- blind, server-side-only, or identical-in-every-case behaviour leaves nothing to show. The originating rule (dns_enum.fp_rule.auto.derived) states the full boundary.
   - Sources: <https://www.rfc-editor.org/rfc/rfc1035.html> · <https://learn.microsoft.com/en-us/windows-server/networking/dns/dns-top>
 
```

## 2026-10-31 08:23 — 11 diff lines
- items: 12 (supported 8), FP rules 1, chains 1, state researching
- still missing: fp_rules

```diff
--- dns_enum@current
+++ dns_enum@new
@@ -67,7 +67,7 @@
 
 - A convincing observation for this class is: Adjacent behaviour that produces the same observable result: A zone-transfer attempt is only an unexpected probe when the target nameservers are not meant to serve secondaries; where the SOA declares real secondary nameservers, an AXFR request is the designed replication path and its refusal is the...  _(merged 1 duplicate row(s))_ _(unverified)_
   - **Disproof:** Not evidence when the observable cannot be produced at all -- blind, server-side-only, or identical-in-every-case behaviour leaves nothing to show. The originating rule (dns_enum.fp_rule.auto.derived) states the full boundary.
-  - Sources: <https://www.rfc-editor.org/rfc/rfc1035.html> · <https://learn.microsoft.com/en-us/windows-server/networking/dns/dns-top>
+  - Sources: <https://www.rfc-editor.org/rfc/rfc1035.html> · <https://academy.hackthebox.com/catalogue/paths> · <https://learn.microsoft.com/en-us/windows-server/networking/dns/dns-top>
 
 ## Chaining opportunities
 
```
