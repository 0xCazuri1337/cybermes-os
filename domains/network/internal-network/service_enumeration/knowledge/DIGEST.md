# Service Enumeration and Fingerprinting

> surface: `net` · CWE: CWE-200 · OWASP: —
> maturity: **researching** — 9 items, 6 supported, 1 FP rules, 1 chains

A service's announcement identifies its implementation and often its version, which selects the technique that applies to it.

**Aliases:** service enumeration, banner grabbing, service fingerprinting, version detection, fingerprinting

## Technique

- **Full TCP port scanning with service version detection is the entry step that establishes which attack surface exists before any technique is attempted.**  
  `high_confidence` · score 0.8455 · disproved by: Refuted when the target is unreachable or filters the scan so that no port state is observable, in which case the scan yields no attack surface at all.
  sources: <https://attack.mitre.org/techniques/T1046/> · <https://cwe.mitre.org/data/definitions/200.html> · <https://raw.githubusercontent.com/Esther7171/HackTheBox-Writeups-Walkthroughs/main/Write-ups/Academy/02.%20Information%20Gathering/10.%20Network%20Enumeration%20with%20Nmap/Network%20Enumeration%20with%20Nmap.md>
- **Port and service scanning is used to acquire the list of open services and their banners, and that list is what determines which technique is even applicable to a host.**  
  `high_confidence` · score 0.834 · disproved by: If the scan is run inside an authorized scope and the banners collected match the documented services for every host in that scope, then no unexpected service surface was found and there is nothing to report.
  sources: <https://capec.mitre.org/data/definitions/300.html> · <https://www.rfc-editor.org/rfc/rfc6335.html>
- **Nmap service version detection with -sV probes open ports to identify the running service and its version.**  
  `high_confidence` · score 0.762 · disproved by: Ports are filtered or closed, or version detection returns no match for any service.
  sources: <https://dev.to/alvinseyidov/networking-for-cybersecurity-part-5-scanning-enumeration-fingerprinting-344p> · <https://github.com/jesse12-21/nmap-network-recon/blob/main/README.md>
- **Banner grabbing connects to a service and reads its initial response, revealing service name, version, and OS hints.**  
  `under_review` · score 0.7345 · disproved by: The service sends no banner, or banners are stripped by a reverse proxy or load balancer.
  sources: <https://github.com/jesse12-21/nmap-network-recon/blob/main/README.md> · <https://sammyha.github.io/notes/CPTS/Nmap/Service%20Enumeration/>
- **A full port scan with nmap -p- -sV identifies all 65535 ports and the services running on each, providing complete attack surface visibility.**  
  `supported` · score 0.707 · disproved by: All 65535 ports are filtered by a firewall, or scan time constraints prevent full coverage.
  sources: <https://dev.to/alvinseyidov/networking-for-cybersecurity-part-5-scanning-enumeration-fingerprinting-344p> · <https://sammyha.github.io/notes/CPTS/Nmap/Service%20Enumeration/>

## Validation

- **An RDP session is confirmed malicious only when the account's enumeration-derived RDP access rights and the origin of its credential both support the session; rights alone or a successful session alone are insufficient.**  
  `high_confidence` · score 0.8715 · disproved by: Proof the claim wrong would be a session where the account holds no enumerated RDP right to the destination yet the session succeeded, or one where the credential was legitimately issued to the operator but the session still carried a non-standard channel and created a forward -- in either case rights and credential origin would not have discriminated the finding, and channel plus process evidence would have to be the deciding signal.
  sources: <https://academy.hackthebox.com/course/preview/active-directory-enumeration--attacks> · <https://securelist.com/tr/payload-ransomware-via-group-policy/121335/>

## Fp Rule

- **An open TCP port on an internet-facing host is a baseline observation, not a finding; do not file a port as a vulnerability unless a specific weakness is reachable on that port - an unauthenticated service, a default credential, or a known-vulnerable version - because every listening service is by definition exposed to the network.**  
  `under_review` · score 0.9015 · disproved by: The service listening on the port accepts unauthenticated requests, ships a default or well-known credential, or runs a version with a known exploitable CVE - in which case the open port is the delivery path for a real, demonstrable weakness and belongs in the report as such.
  sources: <https://capec.mitre.org/data/definitions/300.html> · <https://claroty.com/blog/a-comprehensive-guide-to-exposure-management-for-cyber-physical-systems>
- **RDP sessions arriving from a known administrator workstation, a sanctioned jump host, or a training lab endpoint are expected and must not be reported as exposed-service misuse.**  
  `high_confidence` · score 0.8355 · disproved by: Proof the rule wrong would be a session from a sanctioned jump host that is demonstrably not sanctioned operator work -- carrying a non-standard virtual channel, running bulk transfer, or creating a port-forwarding rule on the destination -- which would mean the exemption must be conditioned on channel and process evidence rather than on source host alone.
  sources: <https://academy.hackthebox.com/course/preview/active-directory-enumeration--attacks> · <https://securelist.com/tr/network-anomaly-detection-in-kata/120892/>

## Evidence

- **A convincing observation for this class is: The observable that triggers this false positive is a port scan result listing open TCP ports on an internet-facing host, filed directly as a vulnerability.**  
  `under_review` · score 0.838 · disproved by: Not evidence when the observable cannot be produced at all -- blind, server-side-only, or identical-in-every-case behaviour leaves nothing to show. The originating rule (service_enumeration.fp_rule.open_port_alone_is_not_a_finding) states the full boundary.
  sources: <https://capec.mitre.org/data/definitions/300.html> · <https://claroty.com/blog/a-comprehensive-guide-to-exposure-management-for-cyber-physical-systems>

## Known gaps

Not yet satisfied: `items`, `fp_rules`
