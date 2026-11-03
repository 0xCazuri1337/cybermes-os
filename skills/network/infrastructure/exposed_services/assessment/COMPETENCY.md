# Methodology — Exposed Remote Services

> Derived from 8 verified items. Regenerate with `python -m wks.methodgen --class exposed_services --apply`. Do not hand-edit: this file is a projection of the evidence, and edits are lost on the next cycle.

**Surface.** An administrative protocol reachable from where it should not be concedes its authentication surface to that reachability.

**References.** CWE-200

## 1. Preconditions

_Nothing below is reachable until these hold. Confirm each against the target before spending time on the technique._

**Internet-facing building management and CPS devices commonly ship with unmanaged third-party remote access tooling and open network ports, which is the precondition that turns an exposed-services finding into a lateral-movement entry point.**

A hunter should inventory remote-access agents and open ports on non-IT-exposed building systems before anything else, because these are the pivot points into an otherwise segmented network, and should rank an open port as an attack path rather than as a hygiene finding. The precondition framing matters: the exposure itself is ordinary, and the severity comes from what the reachable device trusts once it is spoken to. The claim is falsified by an estate inventory showing no third-party remote access agents and no non-essential open ports on these systems.

- *Disproof:* An inventory showing these CPS environments with no third-party remote access agents and no non-essential open ports would refute the claim for that estate.
- *Evidence:* high_confidence — [claroty.com](https://www.claroty.com/blog/claroty-team82-state-of-cps-security-2025-report-building-management-system-exposures); [labs.watchtowr.com](https://labs.watchtowr.com/here-we-go-again-citrix-netscaler-dtls-preauth-memory-overflow-cve-2026-88772/)

## Reconnaissance signals

_No verified signal items yet._ Derived from evidence only, so this section is empty rather than plausible.


## 2. Test sequence

_Concrete mutations to try. Each is written to be executable, not to be a description of the vulnerability._

**CVE-2020-9484 is a deserialization flaw in Apache Tomcat's persistent session handling: when an attacker controls a session file and Tomcat uses a FileStore-backed PersistenceManager, a crafted request can deserialize the attacker's object and execute code.**

Tomcat's PersistenceManager can persist sessions to a FileStore; if the attacker can write a file and knows its path, a request that selects that session causes the server to deserialize the file's contents. NVD lists the affected Tomcat branches and the FileStore/filter conditions. CWE-502 describes the underlying primitive: deserializing untrusted data without ensuring the result is valid. The test should confirm the Tomcat version, the PersistenceManager/FileStore configuration, and an attacker-writable session file; the presence of Tomcat or a session cookie alone is not enough.

- *Disproof:* The finding fails when Tomcat is outside the affected branches, uses a different session store, has a filter that rejects the attacker's object, or the attacker cannot control a file at a path known to FileStore.
- *Evidence:* high_confidence — [cwe.mitre.org](https://cwe.mitre.org/data/definitions/502.html); [services.nvd.nist.gov](https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2020-9484)

**CVE-2019-12384 is a polymorphic deserialization flaw in FasterXML jackson-databind before 2.9.9.1; when logback-core is on the classpath, an attacker can use the deserialized object to reach code execution.**

Jackson's polymorphic deserialization can instantiate classes named in attacker-controlled data. NVD records that versions before 2.9.9.1 fail to block logback-core and that remote code execution may be possible depending on the classpath. CWE-502 describes the primitive: untrusted data is deserialized without ensuring the result is valid. The test should confirm the jackson-databind version, the presence of logback-core, and a request path that reaches an untyped deserialization sink; a library version alone is a lead.

- *Disproof:* The finding fails when jackson-databind is fixed, logback-core is absent, or the application does not deserialize attacker-controlled polymorphic data.
- *Evidence:* high_confidence — [cwe.mitre.org](https://cwe.mitre.org/data/definitions/502.html); [services.nvd.nist.gov](https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2019-12384)

**A service exposed on an unexpected port is identified by matching its banner and behaviour to a known product, which is what makes the correct next step discoverable.**

In practice on HTB this shows up as: | **Command** | **Description** |
| ---- | ---- |
| `sudo nmap --script ms-sql-info,ms-sql-empty-password,ms-sql-xp-cmdshell,ms-sql-config,ms-sql-ntlm-info,ms-sql-tables,ms-sql-hasdbaccess,ms-sql-dac,ms-sql-dump-hashes --script-args mssql.instance-port=1433,mssql.username=sa,mssql.password=,mssql.instance-name=MSSQLSERVER -sV -p 1433 <IP>` | Nmap port scan |
| `mssqlclient.py <user>@<FQDN/IP> -windows-auth` | Log in to the MSSQL server using Windows authentication. |
| `SQL> select name from sys.databases` | Select databases in mssqlclient |

Write-up provenance: ajcriado/htb-writeups :: Academy/CPTS/Content Summary/04. Footprinting.md (1810 words, classified network).

- *Disproof:* Refuted when the service returns no banner and no identifiable protocol behaviour, leaving nothing to match against a known product.
- *Evidence:* high_confidence — [attack.mitre.org](https://attack.mitre.org/tactics/TA0001/); [cwe.mitre.org](https://cwe.mitre.org/data/definitions/200.html); [raw.githubusercontent.com](https://raw.githubusercontent.com/ajcriado/htb-writeups/main/Academy/CPTS/Content%20Summary/04.%20Footprinting.md)

**CVE-2019-11043 is an out-of-bounds write in PHP-FPM's FastCGI path handling: NVD records that in PHP 7.1.x before 7.1.33, 7.2.x before 7.2.24, and 7.3.x before 7.3.11, certain FPM configurations allow a write past allocated buffers into FCGI protocol data, opening remote code execution.**

The vulnerable surface is an exposed PHP-FPM listener, not the PHP application alone. NVD identifies the affected PHP branches and the FPM setup condition; the write crosses the buffer reserved for FCGI protocol data, which is why the bug can become remote code execution rather than a crash. The CWE-787 definition describes the same primitive: writing past the end or before the beginning of the intended buffer. A test should confirm the exact PHP/FPM version, the reachable FastCGI path, and whether the FPM configuration matches the published condition. A version banner or PHP presence alone is not proof.

- *Disproof:* The finding fails when the target runs a fixed PHP release, uses a non-FPM SAPI, or its FPM configuration does not expose the FCGI path described by the CVE; a banner match without the vulnerable path is only a version observation.
- *Evidence:* high_confidence — [cwe.mitre.org](https://cwe.mitre.org/data/definitions/787.html); [services.nvd.nist.gov](https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2019-11043)

**An administrative or remote service reachable from where policy forbids it is an initial-access or persistence surface, because attacker leverage is bounded by reachability rather than by the service's own authentication.**

Reachability is the whole variable here. A management interface that is authenticated and patched changes character completely depending on who can reach it, because every control downstream of the listener is unreachable to an adversary who cannot complete a TCP handshake to it. The correct test is therefore not 'is this service exposed' but 'is this service reachable from a segment that policy says should not reach it' — an SMTP relay reachable from the DMZ and the same relay reachable from a laptop are different findings with the same banner. Where the service is required for administration, the mitigation pattern ATT&CK recommends for the comparable WinRM case is the general one: lock down critical enclaves with separate infrastructure and restrict access with host firewall rules to specific destinations, rather than trying to harden a listener that should never have been reachable.

- *Disproof:* If every exposed administrative service is reachable only from an explicitly authorized management segment and enforced at the network layer rather than by application configuration, then the reachability that creates the risk is not present.
- *Evidence:* high_confidence — [attack.mitre.org](https://attack.mitre.org/techniques/T1133/); [talosintelligence.com](https://www.talosintelligence.com/vulnerability_reports/TALOS-2025-2291)

## Validation

_No verified validation items yet._ Derived from evidence only, so this section is empty rather than plausible.


## 3. False-positive rejection

_The checks that eliminate the most common non-findings. Run these BEFORE reporting, not after a rejection._

**An SSH service answering on an unusual high TCP port on a consumer or edge device is a vendor port-forward feature, not attacker persistence; the discriminator is whether the port serves the vendor's own management tunnel rather than a general-purpose login.**

The observation that produces this false positive is port 22 absent and SSH present on, for example, TCP 20001, which reads as an operator having moved the shell off the default port to evade detection. Measured across real internet-wide data, SSH appeared on non-standard ports nearly as often as on port 22, so a non-standard port is a population norm rather than an anomaly. A concrete benign instance is a home router whose dropbear SSH service is present and running on port TCP 0.0.0.0:20001 and serves to only allow port forwarding to enable remote cloud connections to the device's configuration service for app-based configuration. That is a vendor cloud-management tunnel: the daemon exists to forward a vendor app session, and it is reachable from the LAN side or the vendor's path by design. The distinguishing test is not the port number but the purpose: does the SSH daemon grant a general interactive shell to an arbitrary source, or does it only relay the vendor management protocol, and is the account/key set constrained to that relay? A high port with a general shell and rotating unknown host keys is a finding; a high port wired to one vendor management endpoint is inventory.

- *Disproof:* The high-port SSH service hands an interactive shell to an unexpected source, or its host key rotates across scans without a firmware change, showing the daemon is being used as an operator foothold rather than as a vendor management tunnel.
- *Evidence:* high_confidence — [helpnetsecurity.com](https://www.helpnetsecurity.com/2026/03/24/detectify-ip-range-scanning/); [talosintelligence.com](https://www.talosintelligence.com/vulnerability_reports/TALOS-2025-2291)

## Known bypasses

_No verified bypass items yet._ Derived from evidence only, so this section is empty rather than plausible.


## 4. Chaining

_How this class escalates when combined with others. Each step is anchored to a promoted item._

**An administrative or remote service reachable from where policy forbids it is initial access rather than a standalone exposure, because the reachable authentication surface is what a relay primitive later supplies with credentials it could not otherwise obtain.**

The exposure and the relay are separate findings that must be reported as one chain or as nothing. The exposure half: an administrative or remote service reachable from a network segment where policy forbids it concedes its authentication surface to that reachability - the control that failed is segmentation, and the consequence is that every authentication mechanism the service offers is now attackable from a position it was never meant to be reached from. The relay half: once such a service answers an outbound or coerced authentication, it hands its own credentials to the party that challenged it, so the exposure converts directly into a credential for the next protocol. The two published halves make this explicit on both sides: Kerberoasting needs only that a low-privileged account and a valid ticket exist to request weakened-encryption service tickets, and it does not matter whether that account actually holds access permissions for those services; separately, forced outbound authentication to an attacker-chosen SMB host returns the server's own NTLM credentials to that host. Compose them and the boundary matters twice - first the attacker needs the service to be reachable at all, and second the relayed credential must land on a service that does not enforce signing or channel binding. Test the chain by confirming reachability from the untrusted segment and then confirming an authentication exchange that returns a credential, not by confirming the port is open.

- *Disproof:* Refuted if the administrative service is not reachable from the untrusted segment, or if the service enforces message signing or channel binding on every inbound authentication such that a relayed response is rejected; with either condition the exposure yields no credential and the chain stops at reconnaissance.
- *Evidence:* high_confidence — [academy.hackthebox.com](https://academy.hackthebox.com/course/preview/active-directory-ldap); [attack.mitre.org](https://attack.mitre.org/techniques/T1133/); [securelist.com](https://securelist.com/tr/network-anomaly-detection-in-kata/120892/)

## Impact

_No verified impact items yet._ Derived from evidence only, so this section is empty rather than plausible.


## Coverage gap

These stages have no verified evidence and are therefore absent above: Reconnaissance signals, Validation, Known bypasses, Impact.
A procedure with a missing validation stage is not safe to act on — it produces findings rather than proofs.

---

*Generated from the evidence base. Where this file and the database disagree, the database is correct.*
