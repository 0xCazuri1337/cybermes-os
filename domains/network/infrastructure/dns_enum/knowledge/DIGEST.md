# DNS Enumeration

> surface: `net` · CWE: CWE-200 · OWASP: —
> maturity: **mature** — 22 items, 22 supported, 2 FP rules, 1 chains

DNS names hosts and services, so a zone disclosure enumerates the network without touching it.

**Aliases:** dns enumeration, zone transfer, axfr, dns zone, zone walking, ad integrated dns, srv record, dns records

## Prerequisite

- **A zone-transfer attempt is only an unexpected probe when the target nameservers are not meant to serve secondaries; where the SOA declares real secondary nameservers, an AXFR request is the designed replication path and its refusal is the correct behaviour.**  
  `high_confidence` · score 0.9025 · disproved by: The claim is wrong, and a refused or silent AXFR is not a clean configuration, if the transfer succeeds from a nameserver that is not in the zone's declared secondary set, or if a secondaries-permitted ACL is missing so any address can pull the whole zone. Success from a non-secondary address is the disproof for the expectation claim; but note that refusal from a genuinely non-secondary server does prove the zone is closed for that host, so the expectation still holds there.
  sources: <https://academy.hackthebox.com/catalogue/paths> · <https://www.rfc-editor.org/rfc/rfc1912.html>

## Technique

- **A DNS zone enumerates every host in a namespace without touching it, and an AXFR zone transfer returns the entire zone, so one query against a misconfigured server replaces host discovery.**  
  `high_confidence` · score 0.8775 · disproved by: If an AXFR request from an unauthorized source is refused, or the server only answers transfers to configured secondaries, then the zone cannot be enumerated this way and discovery requires per-host probing.
  sources: <https://www.rfc-editor.org/rfc/rfc1035.html> · <https://learn.microsoft.com/en-us/windows-server/networking/dns/dns-top>
- **The value of a zone transfer is proportional to what the zone's NS and SOA records already imply, so enumerate those records first to size the transfer, then use the transfer to recover only the names those records never exposed.**  
  `high_confidence` · score 0.8415 · disproved by: The claim is wrong, and the transfer added no enumeration value, if every record it returned was already obtainable from NS, SOA, MX, TXT and service-record queries against the public zone, so no name was concealed by the refusal to transfer; or the transfer returned only the SOA and a single NS RRset matching the authoritative set. In that case the correct finding is a closed zone, not a disclosure, and the enumeration value of the attempt is nil.
  sources: <https://www.rfc-editor.org/rfc/rfc1035.html> · <https://academy.hackthebox.com/catalogue/paths>
- **SQL injection is a code injection technique used to take advantage of coding vulnerabilities and inject SQL queries via an application to bypass authentication, retrieve data from the back-end database, or achieve code execution on the underlying server.**  
  `high_confidence` · score 0.818 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "SQL injection is a code injection technique used to take advantage of coding vulnerabiliti".
  sources: <https://www.talosintelligence.com/vulnerability_reports/TALOS-2019-0851> · <https://academy.hackthebox.com/catalogue/paths> · <https://www.helpnetsecurity.com/2025/02/03/baddns-open-source-tool-check-domain-subdomain-takeover/>
- **An XSS vulnerability may allow an attacker to execute arbitrary JavaScript code within the target's browser and result in complete web application compromise if chained together with other vulnerabilities.**  
  `high_confidence` · score 0.818 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "An XSS vulnerability may allow an attacker to execute arbitrary JavaScript code within the".
  sources: <https://www.talosintelligence.com/vulnerability_reports/TALOS-2019-0851> · <https://academy.hackthebox.com/catalogue/paths> · <https://www.helpnetsecurity.com/2025/02/03/baddns-open-source-tool-check-domain-subdomain-takeover/>
- **We will cover how to identify, exploit, and prevent each of them through various methods.**  
  `high_confidence` · score 0.8055 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "We will cover how to identify, exploit, and prevent each of them through various methods.".
  sources: <https://www.talosintelligence.com/vulnerability_reports/TALOS-2019-0851> · <https://academy.hackthebox.com/catalogue/paths>
- **This module covers the most common attacks and vulnerabilities that can affect web application sessions, such as Session Hijacking, Session Fixation, Cross-Site Request Forgery, Cross-Site Scripting, and Open Redirects.**  
  `high_confidence` · score 0.7995 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "This module covers the most common attacks and vulnerabilities that can affect web applica".
  sources: <https://academy.hackthebox.com/catalogue/paths> · <https://www.helpnetsecurity.com/2025/02/03/baddns-open-source-tool-check-domain-subdomain-takeover/>
- **These flaws enable attackers to upload malicious files, execute arbitrary commands on the back-end server, and even take control over the entire server and all web applications hosted on it and potentially gain access to sensitive data or cause a service disruption.**  
  `high_confidence` · score 0.7995 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "These flaws enable attackers to upload malicious files, execute arbitrary commands on the ".
  sources: <https://academy.hackthebox.com/catalogue/paths> · <https://www.helpnetsecurity.com/2025/02/03/baddns-open-source-tool-check-domain-subdomain-takeover/>
- **If improperly configured or implemented, common web security vulnerabilities such as Information Disclosure, SQL Injection, and Insecure Direct Object Reference (IDOR) may arise.**  
  `high_confidence` · score 0.7995 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "If improperly configured or implemented, common web security vulnerabilities such as Infor".
  sources: <https://academy.hackthebox.com/catalogue/paths> · <https://www.helpnetsecurity.com/2025/02/03/baddns-open-source-tool-check-domain-subdomain-takeover/>
- **Buffer overflows are common vulnerabilities in software applications that can be exploited to achieve remote code execution (RCE) or perform a Denial-of-Service (DoS) attack.**  
  `high_confidence` · score 0.778 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Buffer overflows are common vulnerabilities in software applications that can be exploited".
  sources: <https://www.talosintelligence.com/vulnerability_reports/TALOS-2019-0851> · <https://academy.hackthebox.com/catalogue/paths>
- **We will discuss how to identify, exploit, and prevent TLS attacks.**  
  `high_confidence` · score 0.778 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "We will discuss how to identify, exploit, and prevent TLS attacks.".
  sources: <https://www.talosintelligence.com/vulnerability_reports/TALOS-2019-0851> · <https://academy.hackthebox.com/catalogue/paths>
- **We will cover how to identify, exploit, and prevent each of these vulnerabilities.**  
  `high_confidence` · score 0.778 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "We will cover how to identify, exploit, and prevent each of these vulnerabilities.".
  sources: <https://www.talosintelligence.com/vulnerability_reports/TALOS-2019-0851> · <https://academy.hackthebox.com/catalogue/paths>
- **Command injection vulnerabilities can be leveraged to compromise a hosting server and its entire network.**  
  `high_confidence` · score 0.778 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Command injection vulnerabilities can be leveraged to compromise a hosting server and its ".
  sources: <https://www.talosintelligence.com/vulnerability_reports/TALOS-2019-0851> · <https://academy.hackthebox.com/catalogue/paths>
- **Most often, if we can exploit a vulnerability and gain a foothold on a host, it will be running some version of Windows or Linux.**  
  `high_confidence` · score 0.778 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Most often, if we can exploit a vulnerability and gain a foothold on a host, it will be ru".
  sources: <https://www.talosintelligence.com/vulnerability_reports/TALOS-2019-0851> · <https://academy.hackthebox.com/catalogue/paths>
- **An XSS vulnerability may allow an attacker to execute arbitrary JavaScript code within the target's browser and result in complete web application compromise if chained together with other vulnerabilities.**  
  `high_confidence` · score 0.772 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "An XSS vulnerability may allow an attacker to execute arbitrary JavaScript code within the".
  sources: <https://academy.hackthebox.com/catalogue/paths> · <https://www.helpnetsecurity.com/2025/02/03/baddns-open-source-tool-check-domain-subdomain-takeover/>
- **Kerberos is an authentication protocol that allows users to authenticate and access services on a potentially insecure network.**  
  `high_confidence` · score 0.772 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Kerberos is an authentication protocol that allows users to authenticate and access servic".
  sources: <https://academy.hackthebox.com/catalogue/paths> · <https://www.helpnetsecurity.com/2025/02/03/baddns-open-source-tool-check-domain-subdomain-takeover/>
- **Binary exploitation is a core tenet of penetration testing, but learning it can be daunting.**  
  `high_confidence` · score 0.772 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Binary exploitation is a core tenet of penetration testing, but learning it can be dauntin".
  sources: <https://academy.hackthebox.com/catalogue/paths> · <https://www.helpnetsecurity.com/2025/02/03/baddns-open-source-tool-check-domain-subdomain-takeover/>

## Validation

- **A zone-transfer disclosure is validated only by showing a full multi-record answer whose SOA serial is current and whose names exceed the public NS/SOA/MX set, because an empty or serial-stale answer is a replica, not a disclosure.**  
  `high_confidence` · score 0.8935 · disproved by: The validation fails, and the transfer is not a disclosure, if the returned SOA serial is older than the publicly queryable serial (stale replica); the answer contains the SOA but no additional owner names; every returned record was already obtainable through normal public queries; or the transfer succeeded only from an address inside the declared secondary set, which is the designed replication path rather than an exposure. A current serial plus at least one name absent from the public set is what the finding requires.
  sources: <https://www.rfc-editor.org/rfc/rfc1035.html> · <https://academy.hackthebox.com/catalogue/paths> · <https://www.rfc-editor.org/rfc/rfc1912.html>
- **A refused DNS zone transfer proves the zone is not AXFR-open, not that no records were retrieved; enumeration evidence requires a returned record set from the transfer, an NSEC walk, or a secondary resolver.**  
  `high_confidence` · score 0.893 · disproved by: The transfer or an equivalent anonymous read returns an actual record set beyond SOA and NS, or an NSEC chain yields NXDOMAIN proofs for names that resolve elsewhere, showing records were retrieved without authentication.
  sources: <https://www.talosintelligence.com/vulnerability_reports/TALOS-2019-0851> · <https://www.helpnetsecurity.com/2025/02/03/baddns-open-source-tool-check-domain-subdomain-takeover/>

## Fp Rule

- **An AXFR refused by every authoritative nameserver, returning REFUSED or NOTAUTH with an SOA in the authority section, is a closed zone and not a DNS disclosure, provided the same refusal is observed from an address outside the declared secondary set.**  
  `high_confidence` · score 0.869 · disproved by: The rule is wrong, and the zone is exposed, if any authoritative nameserver returns a full RRsets transfer to an address outside its declared secondary set; if the response is a truncated or partial transfer (SOA plus a subset of records) rather than a clean refusal; if the SOA serial in the refusal differs from the publicly queryable serial, indicating the authority is serving different data than the public view; or if a secondaries-permitted ACL is absent and any source address is served. A partial answer is a leak, not a closure.
  sources: <https://www.rfc-editor.org/rfc/rfc1035.html> · <https://academy.hackthebox.com/catalogue/paths>
- **Reject a dns_enum finding until it is distinguished from the adjacent behaviour this class also covers. "A zone transfer that returns internal hostnames supplies the candidate subdomain list that turns a dangling DNS record into a takeover, because the transfer reveals names that public certificate and archive sources never listed and those..." and "A zone-transfer attempt is only an unexpected probe when the target nameservers are not meant to serve secondaries; where the SOA declares real secondary nameservers, an AXFR request is the designed replication path and its refusal is the..." share a surface and a symptom, so a response that matches the first is not evidence for it while the second remains possible.**  
  `high_confidence` · score 0.8665 · disproved by: This rule is wrong if a controlled test shows the two behaviours can never co-occur on the same surface, or if the corpus entry for "A zone-transfer attempt is only an unexpected probe when the target na" is out of date. In that case this class needs its false-positive guidance rewritten rather than deleted.
  sources: <https://academy.hackthebox.com/catalogue/paths> · <https://learn.microsoft.com/en-us/windows-server/networking/dns/dns-top>

## Chain Link

- **A zone transfer that returns internal hostnames supplies the candidate subdomain list that turns a dangling DNS record into a takeover, because the transfer reveals names that public certificate and archive sources never listed and those names are the ones still pointing at de-provisioned third-party services.**  
  `high_confidence` · score 0.9175 · disproved by: The chain is refuted if the zone transfer is refused or returns nothing beyond the public NS and SOA set, leaving no name the certificate sources missed; or if every transferred name resolves to an active, correctly provisioned service, so nothing is claimable; or if the recovered internal names sit outside the registrable domain and therefore outside any session cookie's Domain scope, making a takeover phishing-only rather than session-affecting. The transfer must produce at least one live dangling record for the chain to end anywhere.
  sources: <https://www.rfc-editor.org/rfc/rfc1035.html> · <https://academy.hackthebox.com/catalogue/paths> · <https://www.helpnetsecurity.com/2025/02/03/baddns-open-source-tool-check-domain-subdomain-takeover/>
