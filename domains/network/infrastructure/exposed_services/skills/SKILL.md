---
name: exposed_services-hunting
description: Use when hunting Exposed Remote Services in a net target. Ordered prerequisites, signals, techniques, validation bar and false-positive rules.
---

# Exposed Remote Services — hunting skill

<!-- GENERATED from db/wks.db by wks/skillgen.py. DO NOT HAND-EDIT.
     Edit the rows (or ingest better research) and re-run:
     python -m wks.skillgen -->

> surface `net` · CWE CWE-200 · OWASP —
> evidence: 12 items, 8 supported, 2 FP rules, 1 chains
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
- An administrative or remote service reachable from where policy forbids it is an initial-access or persistence surface, because attacker leverage is bounded by reachability rather than by the service's own authentication.  _(merged 1 duplicate row(s))_
  - **Disproof:** If every exposed administrative service is reachable only from an explicitly authorized management segment and enforced at the network layer rather than by application configuration, then the reachability that creates the risk is not present.
  - Sources: <https://attack.mitre.org/techniques/T1133/> · <https://www.talosintelligence.com/vulnerability_reports/TALOS-2025-2291>
- CVE-2019-11043 is an out-of-bounds write in PHP-FPM's FastCGI path handling: NVD records that in PHP 7.1.x before 7.1.33, 7.2.x before 7.2.24, and 7.3.x before 7.3.11, certain FPM configurations allow a write past allocated buffers into FCGI protocol data, opening remote code execution.  _(merged 1 duplicate row(s))_
  - **Disproof:** The finding fails when the target runs a fixed PHP release, uses a non-FPM SAPI, or its FPM configuration does not expose the FCGI path described by the CVE; a banner match without the vulnerable path is only a version observation.
  - Sources: <https://cwe.mitre.org/data/definitions/787.html> · <https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2019-11043>
- CVE-2019-12384 is a polymorphic deserialization flaw in FasterXML jackson-databind before 2.9.9.1; when logback-core is on the classpath, an attacker can use the deserialized object to reach code execution.  _(merged 1 duplicate row(s))_
  - **Disproof:** The finding fails when jackson-databind is fixed, logback-core is absent, or the application does not deserialize attacker-controlled polymorphic data.
  - Sources: <https://cwe.mitre.org/data/definitions/502.html> · <https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2019-12384>
- CVE-2020-7247 is an OS command injection in OpenSMTPD 6.6: a crafted SMTP MAIL FROM value containing shell metacharacters can execute arbitrary commands as root in the default configuration.  _(merged 1 duplicate row(s))_ _(unverified)_
  - **Disproof:** The finding fails when the server is not OpenSMTPD 6.6, the configuration rejects the crafted MAIL FROM, or the command does not execute; a bare SMTP banner is only a service observation.
  - Sources: <https://cwe.mitre.org/data/definitions/78.html> · <https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2020-7247>
- CVE-2020-8165 is a deserialization of untrusted data flaw in Rails before 5.2.4.3 and before 6.0.3.1; an attacker can unmarshal user-provided objects in MemCacheStore or RedisCacheStore, potentially achieving remote code execution.  _(merged 1 duplicate row(s))_ _(unverified)_
  - **Disproof:** The finding fails when the Rails version is fixed, the application does not use MemCacheStore or RedisCacheStore, or user input never reaches a cached object that is deserialized.
  - Sources: <https://cwe.mitre.org/data/definitions/502.html> · <https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2020-8165>
- CVE-2020-9484 is a deserialization flaw in Apache Tomcat's persistent session handling: when an attacker controls a session file and Tomcat uses a FileStore-backed PersistenceManager, a crafted request can deserialize the attacker's object and execute code.  _(merged 1 duplicate row(s))_
  - **Disproof:** The finding fails when Tomcat is outside the affected branches, uses a different session store, has a filter that rejects the attacker's object, or the attacker cannot control a file at a path known to FileStore.
  - Sources: <https://cwe.mitre.org/data/definitions/502.html> · <https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2020-9484>
- CVE-2020-9496 is unsafe XML-RPC deserialization in Apache OFBiz 17.12.03; an XML-RPC request can deserialize attacker-controlled data, and NVD also records a cross-site scripting issue in the same component.  _(merged 1 duplicate row(s))_ _(unverified)_
  - **Disproof:** The finding fails when OFBiz is not 17.12.03, the XML-RPC endpoint is disabled or patched, or the request does not reach a deserialization sink.
  - Sources: <https://cwe.mitre.org/data/definitions/502.html> · <https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2020-9496>
- CVE-2021-21311 is a server-side request forgery in Adminer 4.0.0 through 4.7.8; the bundled single-file adminer.php can make the server request an attacker-chosen URL, and the issue is fixed in 4.7.9.  _(merged 1 duplicate row(s))_ _(unverified)_
  - **Disproof:** The finding fails when Adminer is 4.7.9 or later, the vulnerable driver is not bundled, or the request path does not let the attacker choose the outbound URL.
  - Sources: <https://cwe.mitre.org/data/definitions/918.html> · <https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2021-21311>

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

---
Runbook: [`HUNT.md`](HUNT.md) — every promoted technique mapped to an executable procedure with the observables to record.
