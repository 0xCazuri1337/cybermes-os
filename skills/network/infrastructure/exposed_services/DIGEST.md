<!-- GENERATED from db/wks.db — do not edit -->
# Exposed Remote Services

> surface: `net` · CWE: CWE-200 · OWASP: —
> maturity: **mature** — 12 items, 8 supported, 2 FP rules, 1 chains

An administrative protocol reachable from where it should not be concedes its authentication surface to that reachability.

**Aliases:** exposed service, exposed services, remote services, internet facing service, management interface exposure

## Prerequisite

- **Internet-facing building management and CPS devices commonly ship with unmanaged third-party remote access tooling and open network ports, which is the precondition that turns an exposed-services finding into a lateral-movement entry point.**  
  `high_confidence` · score 0.844 · disproved by: An inventory showing these CPS environments with no third-party remote access agents and no non-essential open ports would refute the claim for that estate.
  sources: <https://labs.watchtowr.com/here-we-go-again-citrix-netscaler-dtls-preauth-memory-overflow-cve-2026-88772/> · <https://www.claroty.com/blog/claroty-team82-state-of-cps-security-2025-report-building-management-system-exposures>

## Technique

- **CVE-2020-9484 is a deserialization flaw in Apache Tomcat's persistent session handling: when an attacker controls a session file and Tomcat uses a FileStore-backed PersistenceManager, a crafted request can deserialize the attacker's object and execute code.**  
  `high_confidence` · score 0.8295 · disproved by: The finding fails when Tomcat is outside the affected branches, uses a different session store, has a filter that rejects the attacker's object, or the attacker cannot control a file at a path known to FileStore.
  sources: <https://cwe.mitre.org/data/definitions/502.html> · <https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2020-9484>
- **CVE-2019-12384 is a polymorphic deserialization flaw in FasterXML jackson-databind before 2.9.9.1; when logback-core is on the classpath, an attacker can use the deserialized object to reach code execution.**  
  `high_confidence` · score 0.8295 · disproved by: The finding fails when jackson-databind is fixed, logback-core is absent, or the application does not deserialize attacker-controlled polymorphic data.
  sources: <https://cwe.mitre.org/data/definitions/502.html> · <https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2019-12384>
- **A service exposed on an unexpected port is identified by matching its banner and behaviour to a known product, which is what makes the correct next step discoverable.**  
  `high_confidence` · score 0.818 · disproved by: Refuted when the service returns no banner and no identifiable protocol behaviour, leaving nothing to match against a known product.
  sources: <https://attack.mitre.org/tactics/TA0001/> · <https://cwe.mitre.org/data/definitions/200.html> · <https://raw.githubusercontent.com/ajcriado/htb-writeups/main/Academy/CPTS/Content%20Summary/04.%20Footprinting.md>
- **CVE-2019-11043 is an out-of-bounds write in PHP-FPM's FastCGI path handling: NVD records that in PHP 7.1.x before 7.1.33, 7.2.x before 7.2.24, and 7.3.x before 7.3.11, certain FPM configurations allow a write past allocated buffers into FCGI protocol data, opening remote code execution.**  
  `high_confidence` · score 0.802 · disproved by: The finding fails when the target runs a fixed PHP release, uses a non-FPM SAPI, or its FPM configuration does not expose the FCGI path described by the CVE; a banner match without the vulnerable path is only a version observation.
  sources: <https://cwe.mitre.org/data/definitions/787.html> · <https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2019-11043>
- **An administrative or remote service reachable from where policy forbids it is an initial-access or persistence surface, because attacker leverage is bounded by reachability rather than by the service's own authentication.**  
  `high_confidence` · score 0.798 · disproved by: If every exposed administrative service is reachable only from an explicitly authorized management segment and enforced at the network layer rather than by application configuration, then the reachability that creates the risk is not present.
  sources: <https://attack.mitre.org/techniques/T1133/> · <https://www.talosintelligence.com/vulnerability_reports/TALOS-2025-2291>

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
