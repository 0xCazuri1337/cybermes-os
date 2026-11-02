---
name: exposed_rmm-hunting
description: Use when hunting Remote Monitoring and Management Abuse in a net target. Ordered prerequisites, signals, techniques, validation bar and false-positive rules.
---

# Remote Monitoring and Management Abuse — hunting skill

<!-- GENERATED from db/wks.db by wks/skillgen.py. DO NOT HAND-EDIT.
     Edit the rows (or ingest better research) and re-run:
     python -m wks.skillgen -->

> surface `net` · CWE CWE-200 · OWASP —
> evidence: 5 items, 5 supported, 4 FP rules, 1 chains
> maturity: **researching** — missing: items

RMM agents are installed to bypass network controls, so their reachability and credential handling determine their risk.

**Also called:** rmm, remote monitoring, teamviewer, anydesk, screenconnect, remote management tool, vnc


## Prerequisites (do not start without these)

- An exposed RMM or remote-management interface is the precondition for the class, because CISA's directive is specifically about getting networked management interfaces off the internet, so exposure of the listener, not the presence of the tool, is what makes the product remotely usable.
  - **Disproof:** If the listener binds only to loopback or a management VLAN and refuses connections from untrusted networks, the interface is not exposed and the RMM agent running on the host is not a finding; the mere presence of the agent, without a reachable listener, disproves this precondition.
  - Sources: <https://www.microsoft.com/en-us/security/blog/2026/09/02/impersonating-it-support-threat-actors-turn-remote-session-into-enterprise-wide-access/> · <https://www.tenable.com/blog/using-the-service-location-protocol-slp-to-find-exposed-management-interfaces>

## Techniques (what to change)

- Remote monitoring and management agents control a host as if local, inheriting the user or software permissions of the session they run in, so an RMM console is a privileged interface whose exposure is governed by its own authentication.
  - **Disproof:** If the RMM management interface is reachable only from an authorized administrative segment and enforces multi-factor authentication, then console compromise requires a pre-existing privileged foothold and the exposure is correspondingly reduced.
  - Sources: <https://attack.mitre.org/techniques/T1219/> · <https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html>

## False-positive rules (when to reject it)

- Finding an RMM or remote-management agent running on a host is not an exposed-RMM finding unless the management listener is reachable from an untrusted network, because software installed by the defender's own deployment is the normal case and the exposure lives at the network edge.
  - **Disproof:** If the management port answers a handshake from an untrusted network, the agent is genuinely exposed and this rule does not apply; conversely a host whose agent is installed, running, and management-tenant-enrolled but whose listener is not reachable is a false positive for this class.
  - Sources: <https://www.microsoft.com/en-us/security/blog/2026/09/29/phishing-abuses-rmm-tools-persistent-access/> · <https://www.tenable.com/blog/using-the-service-location-protocol-slp-to-find-exposed-management-interfaces>
- A legitimately installed RMM agent on a host is not compromise; discard the finding when no unauthorised deployment was shown.
  - **Disproof:** Would be wrong where the installed agent version is one of the known-vulnerable builds and is internet-reachable, since that is an exposure in itself.
  - Sources: <https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-025a> · <https://netlas.io/blog/weaponized_rmm/>
- An internet-exposed ScreenConnect instance is only exploitable below 23.9.8; a patched instance with MFA is not a finding.
  - **Disproof:** Would be wrong where an unpatched build sits behind an MFA-enforced control plane, since the bypass then needs the second factor.
  - Sources: <https://netlas.io/blog/weaponized_rmm/> · <https://www.rapid7.com/blog/post/2024/02/20/etr-high-risk-vulnerabilities-in-connectwise-screenconnect/>

## Rejected before you report

- **An installed remote monitoring and management agent on a workstation is evidence of compromise.**
  - Killed by: The install timestamp falls inside the approved deployment window, the binary matches the vendor-signed package in the software distribution system, and no management listener answered from outside the corporate network; the agent was deployed, not implanted.
  - Rule: An RMM agent's presence is a deployment fact, not a finding. Report it only when install time or signing identity departs from the deployment record, or when a management interface answers from a network that policy forbids.

## Chains to

- `supply_chain` (3 shared chain(s))

---
Full class document: `skills/Network + AD/exposed_rmm/EVIDENCE.md` · retrieve more with `python -m wks.cli search "<query>" --class-id exposed_rmm`
