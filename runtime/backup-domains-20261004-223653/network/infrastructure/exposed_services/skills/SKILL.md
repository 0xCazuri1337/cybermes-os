---
name: exposed_services-hunting
description: Use when hunting Exposed Remote Services in a net target. Ordered prerequisites, signals, techniques, validation bar and false-positive rules.
---

# Exposed Remote Services — hunting skill

<!-- GENERATED from db/wks.db by wks/skillgen.py. DO NOT HAND-EDIT.
     Edit the rows (or ingest better research) and re-run:
     python -m wks.skillgen -->

> surface `net` · CWE CWE-200 · OWASP —
> evidence: 33 items, 29 supported, 2 FP rules, 1 chains
> maturity: **mature**

An administrative protocol reachable from where it should not be concedes its authentication surface to that reachability.

**Also called:** exposed service, exposed services, remote services, internet facing service, management interface exposure


## Prerequisites (do not start without these)

- Internet-facing building management and CPS devices commonly ship with unmanaged third-party remote access tooling and open network ports, which is the precondition that turns an exposed-services finding into a lateral-movement entry point.  _(merged 1 duplicate row(s))_
  - **Disproof:** An inventory showing these CPS environments with no third-party remote access agents and no non-essential open ports would refute the claim for that estate.
  - Sources: <https://labs.watchtowr.com/here-we-go-again-citrix-netscaler-dtls-preauth-memory-overflow-cve-2026-88772/> · <https://www.claroty.com/blog/claroty-team82-state-of-cps-security-2025-report-building-management-system-exposures>

## Techniques (what to change)

- A service exposed on an unexpected port is identified by matching its banner and behaviour to a known product, which is what makes the correct next step discoverable.  _(merged 1 duplicate row(s))_
  - **Disproof:** Refuted when the service returns no banner and no identifiable protocol behaviour, leaving nothing to match against a known product.
  - Sources: <https://attack.mitre.org/tactics/TA0001/> · <https://cwe.mitre.org/data/definitions/200.html> · <https://raw.githubusercontent.com/ajcriado/htb-writeups/main/Academy/CPTS/Content%20Summary/04.%20Footprinting.md>
- AdmirerToo documents CVE-2021-21311 as a route from an authenticated user to elevated privileges, and the authoritative record confirms the same weakness in the affected product.  _(merged 1 duplicate row(s))_
  - **Disproof:** Refuted when the running product is outside the affected version range, or when the specific weakness (CVE-2021-21311) is patched on the target: the documented escalation then does not exist, whatever the advisory still says.
  - Sources: <https://cwe.mitre.org/data/definitions/918.html> · <https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2021-21311>
- An administrative or remote service reachable from where policy forbids it is an initial-access or persistence surface, because attacker leverage is bounded by reachability rather than by the service's own authentication.  _(merged 1 duplicate row(s))_
  - **Disproof:** If every exposed administrative service is reachable only from an explicitly authorized management segment and enforced at the network layer rather than by application configuration, then the reachability that creates the risk is not present.
  - Sources: <https://attack.mitre.org/techniques/T1133/> · <https://www.talosintelligence.com/vulnerability_reports/TALOS-2025-2291>
- Ariekei documents CVE-2016-3714 as a route from an authenticated user to elevated privileges, and the authoritative record confirms the same weakness in the affected product.  _(merged 1 duplicate row(s))_
  - **Disproof:** Refuted when the running product is outside the affected version range, or when the specific weakness (CVE-2016-3714) is patched on the target: the documented escalation then does not exist, whatever the advisory still says.
  - Sources: <https://cwe.mitre.org/data/definitions/20.html> · <https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2016-3714>
- Blunder documents CVE-2019-14287 as a route from an authenticated user to elevated privileges, and the authoritative record confirms the same weakness in the affected product.  _(merged 1 duplicate row(s))_
  - **Disproof:** Refuted when the running product is outside the affected version range, or when the specific weakness (CVE-2019-14287) is patched on the target: the documented escalation then does not exist, whatever the advisory still says.
  - Sources: <https://cwe.mitre.org/data/definitions/755.html> · <https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2019-14287>
- Buffer overflows are common vulnerabilities in software applications that can be exploited to achieve remote code execution (RCE) or perform a Denial-of-Service (DoS) attack.  _(merged 1 duplicate row(s))_ _(unverified)_
  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Buffer overflows are common vulnerabilities in software applications that can be exploited".
  - Sources: <https://www.talosintelligence.com/vulnerability_reports/TALOS-2025-2291>
- Carpediem documents CVE-2022-0492 as a route from an authenticated user to elevated privileges, and the authoritative record confirms the same weakness in the affected product.  _(merged 1 duplicate row(s))_
  - **Disproof:** Refuted when the running product is outside the affected version range, or when the specific weakness (CVE-2022-0492) is patched on the target: the documented escalation then does not exist, whatever the advisory still says.
  - Sources: <https://cwe.mitre.org/data/definitions/287.html> · <https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2022-0492>
- Control documents CVE-2019-11043 as a route from an authenticated user to elevated privileges, and the authoritative record confirms the same weakness in the affected product.  _(merged 1 duplicate row(s))_
  - **Disproof:** Refuted when the running product is outside the affected version range, or when the specific weakness (CVE-2019-11043) is patched on the target: the documented escalation then does not exist, whatever the advisory still says.
  - Sources: <https://cwe.mitre.org/data/definitions/787.html> · <https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2019-11043>
- Devzat documents CVE-2019-20933 as a route from an authenticated user to elevated privileges, and the authoritative record confirms the same weakness in the affected product.  _(merged 1 duplicate row(s))_
  - **Disproof:** Refuted when the running product is outside the affected version range, or when the specific weakness (CVE-2019-20933) is patched on the target: the documented escalation then does not exist, whatever the advisory still says.
  - Sources: <https://cwe.mitre.org/data/definitions/287.html> · <https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2019-20933>
- Feline documents CVE-2020-9484 as a route from an authenticated user to elevated privileges, and the authoritative record confirms the same weakness in the affected product.  _(merged 1 duplicate row(s))_
  - **Disproof:** Refuted when the running product is outside the affected version range, or when the specific weakness (CVE-2020-9484) is patched on the target: the documented escalation then does not exist, whatever the advisory still says.
  - Sources: <https://cwe.mitre.org/data/definitions/502.html> · <https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2020-9484>
- Horizontall documents CVE-2019-18818 as a route from an authenticated user to elevated privileges, and the authoritative record confirms the same weakness in the affected product.  _(merged 1 duplicate row(s))_
  - **Disproof:** Refuted when the running product is outside the affected version range, or when the specific weakness (CVE-2019-18818) is patched on the target: the documented escalation then does not exist, whatever the advisory still says.
  - Sources: <https://cwe.mitre.org/data/definitions/640.html> · <https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2019-18818>
- Jewel documents CVE-2020-8165 as a route from an authenticated user to elevated privileges, and the authoritative record confirms the same weakness in the affected product.  _(merged 1 duplicate row(s))_
  - **Disproof:** Refuted when the running product is outside the affected version range, or when the specific weakness (CVE-2020-8165) is patched on the target: the documented escalation then does not exist, whatever the advisory still says.
  - Sources: <https://cwe.mitre.org/data/definitions/502.html> · <https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2020-8165>
- Kerberos is an authentication protocol that allows users to authenticate and access services on a potentially insecure network.  _(merged 1 duplicate row(s))_ _(unverified)_
  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Kerberos is an authentication protocol that allows users to authenticate and access servic".
  - Sources: <https://attack.mitre.org/techniques/T1133/> · <https://www.claroty.com/blog/claroty-team82-state-of-cps-security-2025-report-building-management-system-exposures>
- Legacy documents CVE-2008-4250 as a route from an authenticated user to elevated privileges, and the authoritative record confirms the same weakness in the affected product.  _(merged 1 duplicate row(s))_
  - **Disproof:** Refuted when the running product is outside the affected version range, or when the specific weakness (CVE-2008-4250) is patched on the target: the documented escalation then does not exist, whatever the advisory still says.
  - Sources: <https://cwe.mitre.org/data/definitions/119.html> · <https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2008-4250>
- Meta documents CVE-2020-29599 as a route from an authenticated user to elevated privileges, and the authoritative record confirms the same weakness in the affected product.  _(merged 1 duplicate row(s))_
  - **Disproof:** Refuted when the running product is outside the affected version range, or when the specific weakness (CVE-2020-29599) is patched on the target: the documented escalation then does not exist, whatever the advisory still says.
  - Sources: <https://cwe.mitre.org/data/definitions/91.html> · <https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2020-29599>
- Monitors documents CVE-2020-9496 as a route from an authenticated user to elevated privileges, and the authoritative record confirms the same weakness in the affected product.  _(merged 1 duplicate row(s))_
  - **Disproof:** Refuted when the running product is outside the affected version range, or when the specific weakness (CVE-2020-9496) is patched on the target: the documented escalation then does not exist, whatever the advisory still says.
  - Sources: <https://cwe.mitre.org/data/definitions/502.html> · <https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2020-9496>
- OpenKeyS documents CVE-2019-19520 as a route from an authenticated user to elevated privileges, and the authoritative record confirms the same weakness in the affected product.  _(merged 1 duplicate row(s))_
  - **Disproof:** Refuted when the running product is outside the affected version range, or when the specific weakness (CVE-2019-19520) is patched on the target: the documented escalation then does not exist, whatever the advisory still says.
  - Sources: <https://cwe.mitre.org/data/definitions/863.html> · <https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2019-19520>
- Passage documents CVE-2019-11447 as a route from an authenticated user to elevated privileges, and the authoritative record confirms the same weakness in the affected product.  _(merged 1 duplicate row(s))_
  - **Disproof:** Refuted when the running product is outside the affected version range, or when the specific weakness (CVE-2019-11447) is patched on the target: the documented escalation then does not exist, whatever the advisory still says.
  - Sources: <https://cwe.mitre.org/data/definitions/434.html> · <https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2019-11447>
- Pit documents CVE-2019-12744 as a route from an authenticated user to elevated privileges, and the authoritative record confirms the same weakness in the affected product.  _(merged 1 duplicate row(s))_
  - **Disproof:** Refuted when the running product is outside the affected version range, or when the specific weakness (CVE-2019-12744) is patched on the target: the documented escalation then does not exist, whatever the advisory still says.
  - Sources: <https://cwe.mitre.org/data/definitions/434.html> · <https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2019-12744>
- Public writeup evidence for exposed_services: unauthenticated mgmt plane RCE.  _(merged 1 duplicate row(s))_
  - **Disproof:** Refuted if the fetched page no longer contains this exact span, or if the described behaviour is corrected or withdrawn by the publisher.
  - Sources: <https://cwe.mitre.org/data/definitions/284.html> · <https://blog.silentsignal.eu/2026/06/05/unauthenticated-rce-as-qsecofr-via-ibm-i-management-central/>
- Ready documents CVE-2018-19571 as a route from an authenticated user to elevated privileges, and the authoritative record confirms the same weakness in the affected product.  _(merged 1 duplicate row(s))_
  - **Disproof:** Refuted when the running product is outside the affected version range, or when the specific weakness (CVE-2018-19571) is patched on the target: the documented escalation then does not exist, whatever the advisory still says.
  - Sources: <https://cwe.mitre.org/data/definitions/918.html> · <https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2018-19571>
- Remote documents CVE-2019-18988 as a route from an authenticated user to elevated privileges, and the authoritative record confirms the same weakness in the affected product.  _(merged 1 duplicate row(s))_
  - **Disproof:** Refuted when the running product is outside the affected version range, or when the specific weakness (CVE-2019-18988) is patched on the target: the documented escalation then does not exist, whatever the advisory still says.
  - Sources: <https://cwe.mitre.org/data/definitions/521.html> · <https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2019-18988>
- RouterSpace documents CVE-2021-3156 as a route from an authenticated user to elevated privileges, and the authoritative record confirms the same weakness in the affected product.  _(merged 1 duplicate row(s))_
  - **Disproof:** Refuted when the running product is outside the affected version range, or when the specific weakness (CVE-2021-3156) is patched on the target: the documented escalation then does not exist, whatever the advisory still says.
  - Sources: <https://cwe.mitre.org/data/definitions/193.html> · <https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2021-3156>
- Schooled documents CVE-2020-14321 as a route from an authenticated user to elevated privileges, and the authoritative record confirms the same weakness in the affected product.  _(merged 1 duplicate row(s))_
  - **Disproof:** Refuted when the running product is outside the affected version range, or when the specific weakness (CVE-2020-14321) is patched on the target: the documented escalation then does not exist, whatever the advisory still says.
  - Sources: <https://cwe.mitre.org/data/definitions/863.html> · <https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2020-14321>
- Shared documents CVE-2022-0543 as a route from an authenticated user to elevated privileges, and the authoritative record confirms the same weakness in the affected product.  _(merged 1 duplicate row(s))_
  - **Disproof:** Refuted when the running product is outside the affected version range, or when the specific weakness (CVE-2022-0543) is patched on the target: the documented escalation then does not exist, whatever the advisory still says.
  - Sources: <https://cwe.mitre.org/data/definitions/862.html> · <https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2022-0543>
- Tentacle documents CVE-2020-7247 as a route from an authenticated user to elevated privileges, and the authoritative record confirms the same weakness in the affected product.  _(merged 1 duplicate row(s))_
  - **Disproof:** Refuted when the running product is outside the affected version range, or when the specific weakness (CVE-2020-7247) is patched on the target: the documented escalation then does not exist, whatever the advisory still says.
  - Sources: <https://cwe.mitre.org/data/definitions/755.html> · <https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2020-7247>
- The CrackMapExec tool, known as a "Swiss Army Knife" for testing networks, facilitates enumeration, attacks, and post-exploitation that can be leveraged against most any domain using multiple network protocols.  _(merged 1 duplicate row(s))_ _(unverified)_
  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "The CrackMapExec tool, known as a "Swiss Army Knife" for testing networks, facilitates enu".
  - Sources: <https://securelist.com/tr/network-anomaly-detection-in-kata/120892/>
- These flaws enable attackers to upload malicious files, execute arbitrary commands on the back-end server, and even take control over the entire server and all web applications hosted on it and potentially gain access to sensitive data or cause a service disruption.  _(merged 1 duplicate row(s))_ _(unverified)_
  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "These flaws enable attackers to upload malicious files, execute arbitrary commands on the ".
  - Sources: <https://attack.mitre.org/techniques/T1133/> · <https://www.talosintelligence.com/vulnerability_reports/TALOS-2025-2291>
- Time documents CVE-2019-12384 as a route from an authenticated user to elevated privileges, and the authoritative record confirms the same weakness in the affected product.  _(merged 1 duplicate row(s))_
  - **Disproof:** Refuted when the running product is outside the affected version range, or when the specific weakness (CVE-2019-12384) is patched on the target: the documented escalation then does not exist, whatever the advisory still says.
  - Sources: <https://cwe.mitre.org/data/definitions/502.html> · <https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2019-12384>
- Ypuffy documents CVE-2018-14665 as a route from an authenticated user to elevated privileges, and the authoritative record confirms the same weakness in the affected product.  _(merged 1 duplicate row(s))_
  - **Disproof:** Refuted when the running product is outside the affected version range, or when the specific weakness (CVE-2018-14665) is patched on the target: the documented escalation then does not exist, whatever the advisory still says.
  - Sources: <https://cwe.mitre.org/data/definitions/863.html> · <https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2018-14665>

## False-positive rules (when to reject it)

- An SSH service answering on an unusual high TCP port on a consumer or edge device is a vendor port-forward feature, not attacker persistence; the discriminator is whether the port serves the vendor's own management tunnel rather than a general-purpose login.  _(merged 1 duplicate row(s))_
  - **Disproof:** The high-port SSH service hands an interactive shell to an unexpected source, or its host key rotates across scans without a firmware change, showing the daemon is being used as an operator foothold rather than as a vendor management tunnel.
  - Sources: <https://www.talosintelligence.com/vulnerability_reports/TALOS-2025-2291> · <https://www.helpnetsecurity.com/2026/03/24/detectify-ip-range-scanning/>

## Chaining opportunities

- An administrative or remote service reachable from where policy forbids it is initial access rather than a standalone exposure, because the reachable authentication surface is what a relay primitive later supplies with credentials it could not otherwise obtain.  _(merged 1 duplicate row(s))_
  - **Disproof:** Refuted if the administrative service is not reachable from the untrusted segment, or if the service enforces message signing or channel binding on every inbound authentication such that a relayed response is rejected; with either condition the exposure yields no credential and the chain stops at reconnaissance.
  - Sources: <https://attack.mitre.org/techniques/T1133/> · <https://academy.hackthebox.com/course/preview/active-directory-ldap> · <https://securelist.com/tr/network-anomaly-detection-in-kata/120892/>

## Rejected before you report

- **An SSH service listening on an unusual high TCP port is an exposed remote service finding.**
  - Killed by: The listener is a vendor port forward terminating on a managed relay that accepts connections only from the vendor's own management subnet, and no account authenticated from the scanning source; the non-standard port is the vendor's published configuration, not an additional exposure.
  - Rule: A non-standard port is not a finding by itself. Establish what the listener terminates on, whether logins are restricted to a vendor relay, and whether authentication succeeded from an untrusted source; only the last of those is an exposed remote service.

## Chains to

- `smb` (2 shared chain(s))
- `lateral_movement` (2 shared chain(s))


## Hunt procedure

1. Fingerprint the exposed service, then check its OWN version CVEs against the exact build -- never a CVE class inferred from the product name.

### What counts as proof

- Two responses that differ in a way the CONTROL did not, produced by a single changed variable.
- An invariant the application is supposed to hold, observed broken.
- A second independent confirmation, or an explicit statement that this is single-account evidence only.

> Ordered prerequisites, the validation bar and the false-positive rules below are the authority: this block is the mechanics, those are the standard.
---
Full class document: `domains/network/infrastructure/exposed_services/knowledge/DIGEST.md` · retrieve more with `python -m wks.cli search "<query>" --class-id exposed_services`
