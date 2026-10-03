# Service Enumeration and Fingerprinting

> surface: `net` · CWE: CWE-200 · OWASP: —
> maturity: **mature** — 14 items, 14 supported, 2 FP rules, 1 chains

A service's announcement identifies its implementation and often its version, which selects the technique that applies to it.

**Aliases:** service enumeration, banner grabbing, service fingerprinting, version detection, fingerprinting

## Technique

- **Port and service scanning is used to acquire the list of open services and their banners, and that list is what determines which technique is even applicable to a host.**  
  `high_confidence` · score 0.834 · disproved by: If the scan is run inside an authorized scope and the banners collected match the documented services for every host in that scope, then no unexpected service surface was found and there is nothing to report.
  sources: <https://attack.mitre.org/techniques/T1046/> · <https://www.rfc-editor.org/rfc/rfc6335.html>
- **As a result, it is imperative that organizations implement exposure management, which is the proactive cybersecurity approach of identifying, assessing, and addressing potential vulnerabilities and risks before they can be exploited.**  
  `high_confidence` · score 0.772 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "As a result, it is imperative that organizations implement exposure management, which is t".
  sources: <https://academy.hackthebox.com/course/preview/active-directory-enumeration--attacks> · <https://claroty.com/blog/a-comprehensive-guide-to-exposure-management-for-cyber-physical-systems>
- **Utilizing this method alone has caused often-already overburdened personnel responsible for managing OT vulnerabilities to waste resources prioritizing those that are not exploitable or will not ever be exploited.**  
  `high_confidence` · score 0.772 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Utilizing this method alone has caused often-already overburdened personnel responsible fo".
  sources: <https://academy.hackthebox.com/course/preview/active-directory-enumeration--attacks> · <https://claroty.com/blog/a-comprehensive-guide-to-exposure-management-for-cyber-physical-systems>
- **Comprehensive device discovery will allow them to fully understand the attack surface and any exploitable entry points.**  
  `high_confidence` · score 0.772 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Comprehensive device discovery will allow them to fully understand the attack surface and ".
  sources: <https://academy.hackthebox.com/course/preview/active-directory-enumeration--attacks> · <https://claroty.com/blog/a-comprehensive-guide-to-exposure-management-for-cyber-physical-systems>
- **Threat Validation and Stress Testing:   During the validation stage, organizations should validate the ways a potential attacker could exploit an identified exposure, and how monitoring and control systems may react.**  
  `high_confidence` · score 0.772 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Threat Validation and Stress Testing:   During the validation stage, organizations should ".
  sources: <https://academy.hackthebox.com/course/preview/active-directory-enumeration--attacks> · <https://claroty.com/blog/a-comprehensive-guide-to-exposure-management-for-cyber-physical-systems>
- **If an exploit is not published, organizations may need to investigate via other means including software bills of materials (SBOMs) or vulnerability exploitability eXchange (VEX) files.**  
  `high_confidence` · score 0.772 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "If an exploit is not published, organizations may need to investigate via other means incl".
  sources: <https://academy.hackthebox.com/course/preview/active-directory-enumeration--attacks> · <https://claroty.com/blog/a-comprehensive-guide-to-exposure-management-for-cyber-physical-systems>
- **As a result, it is imperative that organizations implement exposure management, which is the proactive cybersecurity approach of identifying, assessing, and addressing potential vulnerabilities and risks before they can be exploited.**  
  `high_confidence` · score 0.772 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "As a result, it is imperative that organizations implement exposure management, which is t".
  sources: <https://academy.hackthebox.com/course/preview/active-directory-enumeration--attacks> · <https://claroty.com/blog/a-comprehensive-guide-to-exposure-management-for-cyber-physical-systems>
- **Comprehensive device discovery will allow them to fully understand the attack surface and any exploitable entry points.**  
  `high_confidence` · score 0.772 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Comprehensive device discovery will allow them to fully understand the attack surface and ".
  sources: <https://academy.hackthebox.com/course/preview/active-directory-enumeration--attacks> · <https://claroty.com/blog/a-comprehensive-guide-to-exposure-management-for-cyber-physical-systems>
- **Threat Validation and Stress Testing:   During the validation stage, organizations should validate the ways a potential attacker could exploit an identified exposure, and how monitoring and control systems may react.**  
  `high_confidence` · score 0.772 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Threat Validation and Stress Testing:   During the validation stage, organizations should ".
  sources: <https://academy.hackthebox.com/course/preview/active-directory-enumeration--attacks> · <https://claroty.com/blog/a-comprehensive-guide-to-exposure-management-for-cyber-physical-systems>
- **If an exploit is not published, organizations may need to investigate via other means including software bills of materials (SBOMs) or vulnerability exploitability eXchange (VEX) files.**  
  `high_confidence` · score 0.772 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "If an exploit is not published, organizations may need to investigate via other means incl".
  sources: <https://academy.hackthebox.com/course/preview/active-directory-enumeration--attacks> · <https://claroty.com/blog/a-comprehensive-guide-to-exposure-management-for-cyber-physical-systems>
- **Utilizing this method alone has caused often-already overburdened personnel responsible for managing OT vulnerabilities to waste resources prioritizing those that are not exploitable or will not ever be exploited.**  
  `high_confidence` · score 0.772 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Utilizing this method alone has caused often-already overburdened personnel responsible fo".
  sources: <https://academy.hackthebox.com/course/preview/active-directory-enumeration--attacks> · <https://claroty.com/blog/a-comprehensive-guide-to-exposure-management-for-cyber-physical-systems>

## Validation

- **An RDP session is confirmed malicious only when the account's enumeration-derived RDP access rights and the origin of its credential both support the session; rights alone or a successful session alone are insufficient.**  
  `high_confidence` · score 0.8715 · disproved by: Proof the claim wrong would be a session where the account holds no enumerated RDP right to the destination yet the session succeeded, or one where the credential was legitimately issued to the operator but the session still carried a non-standard channel and created a forward -- in either case rights and credential origin would not have discriminated the finding, and channel plus process evidence would have to be the deciding signal.
  sources: <https://academy.hackthebox.com/course/preview/active-directory-enumeration--attacks> · <https://securelist.com/tr/payload-ransomware-via-group-policy/121335/>

## Fp Rule

- **An open TCP port on an internet-facing host is a baseline observation, not a finding; do not file a port as a vulnerability unless a specific weakness is reachable on that port - an unauthenticated service, a default credential, or a known-vulnerable version - because every listening service is by definition exposed to the network.**  
  `high_confidence` · score 0.9015 · disproved by: The service listening on the port accepts unauthenticated requests, ships a default or well-known credential, or runs a version with a known exploitable CVE - in which case the open port is the delivery path for a real, demonstrable weakness and belongs in the report as such.
  sources: <https://capec.mitre.org/data/definitions/300.html> · <https://claroty.com/blog/a-comprehensive-guide-to-exposure-management-for-cyber-physical-systems>
- **RDP sessions arriving from a known administrator workstation, a sanctioned jump host, or a training lab endpoint are expected and must not be reported as exposed-service misuse.**  
  `high_confidence` · score 0.8355 · disproved by: Proof the rule wrong would be a session from a sanctioned jump host that is demonstrably not sanctioned operator work -- carrying a non-standard virtual channel, running bulk transfer, or creating a port-forwarding rule on the destination -- which would mean the exemption must be conditioned on channel and process evidence rather than on source host alone.
  sources: <https://academy.hackthebox.com/course/preview/active-directory-enumeration--attacks> · <https://securelist.com/tr/network-anomaly-detection-in-kata/120892/>
