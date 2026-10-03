---
name: exposed_services-hunting
description: Use when hunting Exposed Remote Services in a net target. Ordered prerequisites, signals, techniques, validation bar and false-positive rules.
---

# Exposed Remote Services — hunting skill

<!-- GENERATED from db/wks.db by wks/skillgen.py. DO NOT HAND-EDIT.
     Edit the rows (or ingest better research) and re-run:
     python -m wks.skillgen -->

> surface `net` · CWE CWE-200 · OWASP —
> evidence: 9 items, 5 supported, 2 FP rules, 1 chains
> maturity: **researching** — missing: items

An administrative protocol reachable from where it should not be concedes its authentication surface to that reachability.

**Also called:** exposed service, exposed services, remote services, internet facing service, management interface exposure


## Prerequisites (do not start without these)

- Internet-facing building management and CPS devices commonly ship with unmanaged third-party remote access tooling and open network ports, which is the precondition that turns an exposed-services finding into a lateral-movement entry point.
  - **Disproof:** An inventory showing these CPS environments with no third-party remote access agents and no non-essential open ports would refute the claim for that estate.
  - Sources: <https://labs.watchtowr.com/here-we-go-again-citrix-netscaler-dtls-preauth-memory-overflow-cve-2026-88772/> · <https://www.claroty.com/blog/claroty-team82-state-of-cps-security-2025-report-building-management-system-exposures>

## Techniques (what to change)

- The CrackMapExec tool, known as a "Swiss Army Knife" for testing networks, facilitates enumeration, attacks, and post-exploitation that can be leveraged against most any domain using multiple network protocols. _(unverified)_
  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "The CrackMapExec tool, known as a "Swiss Army Knife" for testing networks, facilitates enu".
  - Sources: <https://securelist.com/tr/network-anomaly-detection-in-kata/120892/>
- These flaws enable attackers to upload malicious files, execute arbitrary commands on the back-end server, and even take control over the entire server and all web applications hosted on it and potentially gain access to sensitive data or cause a service disruption. _(unverified)_
  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "These flaws enable attackers to upload malicious files, execute arbitrary commands on the ".
  - Sources: <https://attack.mitre.org/techniques/T1133/> · <https://www.talosintelligence.com/vulnerability_reports/TALOS-2025-2291>
- Buffer overflows are common vulnerabilities in software applications that can be exploited to achieve remote code execution (RCE) or perform a Denial-of-Service (DoS) attack. _(unverified)_
  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Buffer overflows are common vulnerabilities in software applications that can be exploited".
  - Sources: <https://www.talosintelligence.com/vulnerability_reports/TALOS-2025-2291>
- Kerberos is an authentication protocol that allows users to authenticate and access services on a potentially insecure network. _(unverified)_
  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Kerberos is an authentication protocol that allows users to authenticate and access servic".
  - Sources: <https://attack.mitre.org/techniques/T1133/> · <https://www.claroty.com/blog/claroty-team82-state-of-cps-security-2025-report-building-management-system-exposures>
- A service exposed on an unexpected port is identified by matching its banner and behaviour to a known product, which is what makes the correct next step discoverable.
  - **Disproof:** Refuted when the service returns no banner and no identifiable protocol behaviour, leaving nothing to match against a known product.
  - Sources: <https://attack.mitre.org/tactics/TA0001/> · <https://cwe.mitre.org/data/definitions/200.html> · <https://raw.githubusercontent.com/ajcriado/htb-writeups/main/Academy/CPTS/Content%20Summary/04.%20Footprinting.md>
- An administrative or remote service reachable from where policy forbids it is an initial-access or persistence surface, because attacker leverage is bounded by reachability rather than by the service's own authentication.
  - **Disproof:** If every exposed administrative service is reachable only from an explicitly authorized management segment and enforced at the network layer rather than by application configuration, then the reachability that creates the risk is not present.
  - Sources: <https://attack.mitre.org/techniques/T1133/> · <https://www.talosintelligence.com/vulnerability_reports/TALOS-2025-2291>

## False-positive rules (when to reject it)

- An SSH service answering on an unusual high TCP port on a consumer or edge device is a vendor port-forward feature, not attacker persistence; the discriminator is whether the port serves the vendor's own management tunnel rather than a general-purpose login.
  - **Disproof:** The high-port SSH service hands an interactive shell to an unexpected source, or its host key rotates across scans without a firmware change, showing the daemon is being used as an operator foothold rather than as a vendor management tunnel.
  - Sources: <https://www.talosintelligence.com/vulnerability_reports/TALOS-2025-2291> · <https://www.helpnetsecurity.com/2026/03/24/detectify-ip-range-scanning/>

## Chaining opportunities

- An administrative or remote service reachable from where policy forbids it is initial access rather than a standalone exposure, because the reachable authentication surface is what a relay primitive later supplies with credentials it could not otherwise obtain.
  - **Disproof:** Refuted if the administrative service is not reachable from the untrusted segment, or if the service enforces message signing or channel binding on every inbound authentication such that a relayed response is rejected; with either condition the exposure yields no credential and the chain stops at reconnaissance.
  - Sources: <https://attack.mitre.org/techniques/T1133/> · <https://academy.hackthebox.com/course/preview/active-directory-ldap> · <https://securelist.com/tr/network-anomaly-detection-in-kata/120892/>

## Rejected before you report

- **An SSH service listening on an unusual high TCP port is an exposed remote service finding.**
  - Killed by: The listener is a vendor port forward terminating on a managed relay that accepts connections only from the vendor's own management subnet, and no account authenticated from the scanning source; the non-standard port is the vendor's published configuration, not an additional exposure.
  - Rule: A non-standard port is not a finding by itself. Establish what the listener terminates on, whether logins are restricted to a vendor relay, and whether authentication succeeded from an untrusted source; only the last of those is an exposed remote service.

## Chains to

- `smb` (2 shared chain(s))
- `lateral_movement` (2 shared chain(s))

---
Full class document: `domains/network/infrastructure/exposed_services/knowledge/DIGEST.md` · retrieve more with `python -m wks.cli search "<query>" --class-id exposed_services`
