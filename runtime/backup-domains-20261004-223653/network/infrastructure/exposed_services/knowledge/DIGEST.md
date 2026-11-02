# Exposed Remote Services

> surface: `net` · CWE: CWE-200 · OWASP: —
> maturity: **mature** — 33 items, 29 supported, 2 FP rules, 1 chains

An administrative protocol reachable from where it should not be concedes its authentication surface to that reachability.

**Aliases:** exposed service, exposed services, remote services, internet facing service, management interface exposure

## Prerequisite

- **Internet-facing building management and CPS devices commonly ship with unmanaged third-party remote access tooling and open network ports, which is the precondition that turns an exposed-services finding into a lateral-movement entry point.**  
  `high_confidence` · score 0.844 · disproved by: An inventory showing these CPS environments with no third-party remote access agents and no non-essential open ports would refute the claim for that estate.
  sources: <https://labs.watchtowr.com/here-we-go-again-citrix-netscaler-dtls-preauth-memory-overflow-cve-2026-88772/> · <https://www.claroty.com/blog/claroty-team82-state-of-cps-security-2025-report-building-management-system-exposures>

## Technique

- **AdmirerToo documents CVE-2021-21311 as a route from an authenticated user to elevated privileges, and the authoritative record confirms the same weakness in the affected product.**  
  `high_confidence` · score 0.857 · disproved by: Refuted when the running product is outside the affected version range, or when the specific weakness (CVE-2021-21311) is patched on the target: the documented escalation then does not exist, whatever the advisory still says.
  sources: <https://cwe.mitre.org/data/definitions/918.html> · <https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2021-21311>
- **Monitors documents CVE-2020-9496 as a route from an authenticated user to elevated privileges, and the authoritative record confirms the same weakness in the affected product.**  
  `high_confidence` · score 0.857 · disproved by: Refuted when the running product is outside the affected version range, or when the specific weakness (CVE-2020-9496) is patched on the target: the documented escalation then does not exist, whatever the advisory still says.
  sources: <https://cwe.mitre.org/data/definitions/502.html> · <https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2020-9496>
- **Blunder documents CVE-2019-14287 as a route from an authenticated user to elevated privileges, and the authoritative record confirms the same weakness in the affected product.**  
  `high_confidence` · score 0.8295 · disproved by: Refuted when the running product is outside the affected version range, or when the specific weakness (CVE-2019-14287) is patched on the target: the documented escalation then does not exist, whatever the advisory still says.
  sources: <https://cwe.mitre.org/data/definitions/755.html> · <https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2019-14287>
- **Carpediem documents CVE-2022-0492 as a route from an authenticated user to elevated privileges, and the authoritative record confirms the same weakness in the affected product.**  
  `high_confidence` · score 0.8295 · disproved by: Refuted when the running product is outside the affected version range, or when the specific weakness (CVE-2022-0492) is patched on the target: the documented escalation then does not exist, whatever the advisory still says.
  sources: <https://cwe.mitre.org/data/definitions/287.html> · <https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2022-0492>
- **Control documents CVE-2019-11043 as a route from an authenticated user to elevated privileges, and the authoritative record confirms the same weakness in the affected product.**  
  `high_confidence` · score 0.8295 · disproved by: Refuted when the running product is outside the affected version range, or when the specific weakness (CVE-2019-11043) is patched on the target: the documented escalation then does not exist, whatever the advisory still says.
  sources: <https://cwe.mitre.org/data/definitions/787.html> · <https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2019-11043>
- **Devzat documents CVE-2019-20933 as a route from an authenticated user to elevated privileges, and the authoritative record confirms the same weakness in the affected product.**  
  `high_confidence` · score 0.8295 · disproved by: Refuted when the running product is outside the affected version range, or when the specific weakness (CVE-2019-20933) is patched on the target: the documented escalation then does not exist, whatever the advisory still says.
  sources: <https://cwe.mitre.org/data/definitions/287.html> · <https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2019-20933>
- **Legacy documents CVE-2008-4250 as a route from an authenticated user to elevated privileges, and the authoritative record confirms the same weakness in the affected product.**  
  `high_confidence` · score 0.8295 · disproved by: Refuted when the running product is outside the affected version range, or when the specific weakness (CVE-2008-4250) is patched on the target: the documented escalation then does not exist, whatever the advisory still says.
  sources: <https://cwe.mitre.org/data/definitions/119.html> · <https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2008-4250>
- **Meta documents CVE-2020-29599 as a route from an authenticated user to elevated privileges, and the authoritative record confirms the same weakness in the affected product.**  
  `high_confidence` · score 0.8295 · disproved by: Refuted when the running product is outside the affected version range, or when the specific weakness (CVE-2020-29599) is patched on the target: the documented escalation then does not exist, whatever the advisory still says.
  sources: <https://cwe.mitre.org/data/definitions/91.html> · <https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2020-29599>
- **Passage documents CVE-2019-11447 as a route from an authenticated user to elevated privileges, and the authoritative record confirms the same weakness in the affected product.**  
  `high_confidence` · score 0.8295 · disproved by: Refuted when the running product is outside the affected version range, or when the specific weakness (CVE-2019-11447) is patched on the target: the documented escalation then does not exist, whatever the advisory still says.
  sources: <https://cwe.mitre.org/data/definitions/434.html> · <https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2019-11447>
- **Remote documents CVE-2019-18988 as a route from an authenticated user to elevated privileges, and the authoritative record confirms the same weakness in the affected product.**  
  `high_confidence` · score 0.8295 · disproved by: Refuted when the running product is outside the affected version range, or when the specific weakness (CVE-2019-18988) is patched on the target: the documented escalation then does not exist, whatever the advisory still says.
  sources: <https://cwe.mitre.org/data/definitions/521.html> · <https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2019-18988>
- **Shared documents CVE-2022-0543 as a route from an authenticated user to elevated privileges, and the authoritative record confirms the same weakness in the affected product.**  
  `high_confidence` · score 0.8295 · disproved by: Refuted when the running product is outside the affected version range, or when the specific weakness (CVE-2022-0543) is patched on the target: the documented escalation then does not exist, whatever the advisory still says.
  sources: <https://cwe.mitre.org/data/definitions/862.html> · <https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2022-0543>
- **Time documents CVE-2019-12384 as a route from an authenticated user to elevated privileges, and the authoritative record confirms the same weakness in the affected product.**  
  `high_confidence` · score 0.8295 · disproved by: Refuted when the running product is outside the affected version range, or when the specific weakness (CVE-2019-12384) is patched on the target: the documented escalation then does not exist, whatever the advisory still says.
  sources: <https://cwe.mitre.org/data/definitions/502.html> · <https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2019-12384>
- **A service exposed on an unexpected port is identified by matching its banner and behaviour to a known product, which is what makes the correct next step discoverable.**  
  `high_confidence` · score 0.818 · disproved by: Refuted when the service returns no banner and no identifiable protocol behaviour, leaving nothing to match against a known product.
  sources: <https://attack.mitre.org/tactics/TA0001/> · <https://cwe.mitre.org/data/definitions/200.html> · <https://raw.githubusercontent.com/ajcriado/htb-writeups/main/Academy/CPTS/Content%20Summary/04.%20Footprinting.md>
- **Kerberos is an authentication protocol that allows users to authenticate and access services on a potentially insecure network.**  
  `under_review` · score 0.802 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Kerberos is an authentication protocol that allows users to authenticate and access servic".
  sources: <https://attack.mitre.org/techniques/T1133/> · <https://www.claroty.com/blog/claroty-team82-state-of-cps-security-2025-report-building-management-system-exposures>
- **Ariekei documents CVE-2016-3714 as a route from an authenticated user to elevated privileges, and the authoritative record confirms the same weakness in the affected product.**  
  `high_confidence` · score 0.802 · disproved by: Refuted when the running product is outside the affected version range, or when the specific weakness (CVE-2016-3714) is patched on the target: the documented escalation then does not exist, whatever the advisory still says.
  sources: <https://cwe.mitre.org/data/definitions/20.html> · <https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2016-3714>
- **Feline documents CVE-2020-9484 as a route from an authenticated user to elevated privileges, and the authoritative record confirms the same weakness in the affected product.**  
  `high_confidence` · score 0.802 · disproved by: Refuted when the running product is outside the affected version range, or when the specific weakness (CVE-2020-9484) is patched on the target: the documented escalation then does not exist, whatever the advisory still says.
  sources: <https://cwe.mitre.org/data/definitions/502.html> · <https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2020-9484>
- **Horizontall documents CVE-2019-18818 as a route from an authenticated user to elevated privileges, and the authoritative record confirms the same weakness in the affected product.**  
  `high_confidence` · score 0.802 · disproved by: Refuted when the running product is outside the affected version range, or when the specific weakness (CVE-2019-18818) is patched on the target: the documented escalation then does not exist, whatever the advisory still says.
  sources: <https://cwe.mitre.org/data/definitions/640.html> · <https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2019-18818>
- **Jewel documents CVE-2020-8165 as a route from an authenticated user to elevated privileges, and the authoritative record confirms the same weakness in the affected product.**  
  `high_confidence` · score 0.802 · disproved by: Refuted when the running product is outside the affected version range, or when the specific weakness (CVE-2020-8165) is patched on the target: the documented escalation then does not exist, whatever the advisory still says.
  sources: <https://cwe.mitre.org/data/definitions/502.html> · <https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2020-8165>
- **OpenKeyS documents CVE-2019-19520 as a route from an authenticated user to elevated privileges, and the authoritative record confirms the same weakness in the affected product.**  
  `high_confidence` · score 0.802 · disproved by: Refuted when the running product is outside the affected version range, or when the specific weakness (CVE-2019-19520) is patched on the target: the documented escalation then does not exist, whatever the advisory still says.
  sources: <https://cwe.mitre.org/data/definitions/863.html> · <https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2019-19520>
- **Pit documents CVE-2019-12744 as a route from an authenticated user to elevated privileges, and the authoritative record confirms the same weakness in the affected product.**  
  `high_confidence` · score 0.802 · disproved by: Refuted when the running product is outside the affected version range, or when the specific weakness (CVE-2019-12744) is patched on the target: the documented escalation then does not exist, whatever the advisory still says.
  sources: <https://cwe.mitre.org/data/definitions/434.html> · <https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2019-12744>
- **Ready documents CVE-2018-19571 as a route from an authenticated user to elevated privileges, and the authoritative record confirms the same weakness in the affected product.**  
  `high_confidence` · score 0.802 · disproved by: Refuted when the running product is outside the affected version range, or when the specific weakness (CVE-2018-19571) is patched on the target: the documented escalation then does not exist, whatever the advisory still says.
  sources: <https://cwe.mitre.org/data/definitions/918.html> · <https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2018-19571>
- **RouterSpace documents CVE-2021-3156 as a route from an authenticated user to elevated privileges, and the authoritative record confirms the same weakness in the affected product.**  
  `high_confidence` · score 0.802 · disproved by: Refuted when the running product is outside the affected version range, or when the specific weakness (CVE-2021-3156) is patched on the target: the documented escalation then does not exist, whatever the advisory still says.
  sources: <https://cwe.mitre.org/data/definitions/193.html> · <https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2021-3156>
- **Schooled documents CVE-2020-14321 as a route from an authenticated user to elevated privileges, and the authoritative record confirms the same weakness in the affected product.**  
  `high_confidence` · score 0.802 · disproved by: Refuted when the running product is outside the affected version range, or when the specific weakness (CVE-2020-14321) is patched on the target: the documented escalation then does not exist, whatever the advisory still says.
  sources: <https://cwe.mitre.org/data/definitions/863.html> · <https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2020-14321>
- **Tentacle documents CVE-2020-7247 as a route from an authenticated user to elevated privileges, and the authoritative record confirms the same weakness in the affected product.**  
  `high_confidence` · score 0.802 · disproved by: Refuted when the running product is outside the affected version range, or when the specific weakness (CVE-2020-7247) is patched on the target: the documented escalation then does not exist, whatever the advisory still says.
  sources: <https://cwe.mitre.org/data/definitions/755.html> · <https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2020-7247>
- **Ypuffy documents CVE-2018-14665 as a route from an authenticated user to elevated privileges, and the authoritative record confirms the same weakness in the affected product.**  
  `high_confidence` · score 0.802 · disproved by: Refuted when the running product is outside the affected version range, or when the specific weakness (CVE-2018-14665) is patched on the target: the documented escalation then does not exist, whatever the advisory still says.
  sources: <https://cwe.mitre.org/data/definitions/863.html> · <https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2018-14665>
- **An administrative or remote service reachable from where policy forbids it is an initial-access or persistence surface, because attacker leverage is bounded by reachability rather than by the service's own authentication.**  
  `high_confidence` · score 0.798 · disproved by: If every exposed administrative service is reachable only from an explicitly authorized management segment and enforced at the network layer rather than by application configuration, then the reachability that creates the risk is not present.
  sources: <https://attack.mitre.org/techniques/T1133/> · <https://www.talosintelligence.com/vulnerability_reports/TALOS-2025-2291>
- **Public writeup evidence for exposed_services: unauthenticated mgmt plane RCE.**  
  `high_confidence` · score 0.766 · disproved by: Refuted if the fetched page no longer contains this exact span, or if the described behaviour is corrected or withdrawn by the publisher.
  sources: <https://cwe.mitre.org/data/definitions/284.html> · <https://blog.silentsignal.eu/2026/06/05/unauthenticated-rce-as-qsecofr-via-ibm-i-management-central/>
- **These flaws enable attackers to upload malicious files, execute arbitrary commands on the back-end server, and even take control over the entire server and all web applications hosted on it and potentially gain access to sensitive data or cause a service disruption.**  
  `under_review` · score 0.762 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "These flaws enable attackers to upload malicious files, execute arbitrary commands on the ".
  sources: <https://attack.mitre.org/techniques/T1133/> · <https://www.talosintelligence.com/vulnerability_reports/TALOS-2025-2291>
- **The CrackMapExec tool, known as a "Swiss Army Knife" for testing networks, facilitates enumeration, attacks, and post-exploitation that can be leveraged against most any domain using multiple network protocols.**  
  `under_review` · score 0.678 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "The CrackMapExec tool, known as a "Swiss Army Knife" for testing networks, facilitates enu".
  sources: <https://securelist.com/tr/network-anomaly-detection-in-kata/120892/>
- **Buffer overflows are common vulnerabilities in software applications that can be exploited to achieve remote code execution (RCE) or perform a Denial-of-Service (DoS) attack.**  
  `under_review` · score 0.668 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Buffer overflows are common vulnerabilities in software applications that can be exploited".
  sources: <https://www.talosintelligence.com/vulnerability_reports/TALOS-2025-2291>

## Fp Rule

- **An SSH service answering on an unusual high TCP port on a consumer or edge device is a vendor port-forward feature, not attacker persistence; the discriminator is whether the port serves the vendor's own management tunnel rather than a general-purpose login.**  
  `high_confidence` · score 0.8255 · disproved by: The high-port SSH service hands an interactive shell to an unexpected source, or its host key rotates across scans without a firmware change, showing the daemon is being used as an operator foothold rather than as a vendor management tunnel.
  sources: <https://www.talosintelligence.com/vulnerability_reports/TALOS-2025-2291> · <https://www.helpnetsecurity.com/2026/03/24/detectify-ip-range-scanning/>

## Chain Link

- **An administrative or remote service reachable from where policy forbids it is initial access rather than a standalone exposure, because the reachable authentication surface is what a relay primitive later supplies with credentials it could not otherwise obtain.**  
  `high_confidence` · score 0.9175 · disproved by: Refuted if the administrative service is not reachable from the untrusted segment, or if the service enforces message signing or channel binding on every inbound authentication such that a relayed response is rejected; with either condition the exposure yields no credential and the chain stops at reconnaissance.
  sources: <https://attack.mitre.org/techniques/T1133/> · <https://academy.hackthebox.com/course/preview/active-directory-ldap> · <https://securelist.com/tr/network-anomaly-detection-in-kata/120892/>

## False-positive rules

- **Hypothesis:** An SSH service listening on an unusual high TCP port is an exposed remote service finding.
  - **Invalidated by:** The listener is a vendor port forward terminating on a managed relay that accepts connections only from the vendor's own management subnet, and no account authenticated from the scanning source; the non-standard port is the vendor's published configuration, not an additional exposure.
  - **Rule:** A non-standard port is not a finding by itself. Establish what the listener terminates on, whether logins are restricted to a vendor relay, and whether authentication succeeded from an untrusted source; only the last of those is an exposed remote service.

## Related classes (via chains)

- `smb` SMB/CIFS Abuse (2 chains)
- `lateral_movement` Lateral Movement (2 chains)
