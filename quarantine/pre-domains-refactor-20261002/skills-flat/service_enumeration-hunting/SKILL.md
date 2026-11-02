---
name: service_enumeration-hunting
description: Use when hunting Service Enumeration and Fingerprinting in a net target. Ordered prerequisites, signals, techniques, validation bar and false-positive rules.
---

# Service Enumeration and Fingerprinting — hunting skill

<!-- GENERATED from db/wks.db by wks/skillgen.py. DO NOT HAND-EDIT.
     Edit the rows (or ingest better research) and re-run:
     python -m wks.skillgen -->

> surface `net` · CWE CWE-200 · OWASP —
> evidence: 4 items, 4 supported, 2 FP rules, 0 chains
> maturity: **researching** — missing: items, chain

A service's announcement identifies its implementation and often its version, which selects the technique that applies to it.

**Also called:** service enumeration, banner grabbing, service fingerprinting, version detection, fingerprinting


## Techniques (what to change)

- Port and service scanning is used to acquire the list of open services and their banners, and that list is what determines which technique is even applicable to a host.
  - **Disproof:** If the scan is run inside an authorized scope and the banners collected match the documented services for every host in that scope, then no unexpected service surface was found and there is nothing to report.
  - Sources: <https://attack.mitre.org/techniques/T1046/> · <https://www.rfc-editor.org/rfc/rfc6335.html>

## Validation bar (how to prove it)

- An RDP session is confirmed malicious only when the account's enumeration-derived RDP access rights and the origin of its credential both support the session; rights alone or a successful session alone are insufficient.
  - **Disproof:** Proof the claim wrong would be a session where the account holds no enumerated RDP right to the destination yet the session succeeded, or one where the credential was legitimately issued to the operator but the session still carried a non-standard channel and created a forward -- in either case rights and credential origin would not have discriminated the finding, and channel plus process evidence would have to be the deciding signal.
  - Sources: <https://academy.hackthebox.com/course/preview/active-directory-enumeration--attacks> · <https://securelist.com/tr/payload-ransomware-via-group-policy/121335/>

## False-positive rules (when to reject it)

- An open TCP port on an internet-facing host is a baseline observation, not a finding; do not file a port as a vulnerability unless a specific weakness is reachable on that port - an unauthenticated service, a default credential, or a known-vulnerable version - because every listening service is by definition exposed to the network.
  - **Disproof:** The service listening on the port accepts unauthenticated requests, ships a default or well-known credential, or runs a version with a known exploitable CVE - in which case the open port is the delivery path for a real, demonstrable weakness and belongs in the report as such.
  - Sources: <https://capec.mitre.org/data/definitions/300.html> · <https://claroty.com/blog/a-comprehensive-guide-to-exposure-management-for-cyber-physical-systems>
- RDP sessions arriving from a known administrator workstation, a sanctioned jump host, or a training lab endpoint are expected and must not be reported as exposed-service misuse.
  - **Disproof:** Proof the rule wrong would be a session from a sanctioned jump host that is demonstrably not sanctioned operator work -- carrying a non-standard virtual channel, running bulk transfer, or creating a port-forwarding rule on the destination -- which would mean the exemption must be conditioned on channel and process evidence rather than on source host alone.
  - Sources: <https://academy.hackthebox.com/course/preview/active-directory-enumeration--attacks> · <https://securelist.com/tr/network-anomaly-detection-in-kata/120892/>

---
Full class document: `skills/Network + AD/service_enumeration/EVIDENCE.md` · retrieve more with `python -m wks.cli search "<query>" --class-id service_enumeration`
