---
name: ad_ntlm-hunting
description: Use when hunting NTLM Authentication Weaknesses in a ad target. Ordered prerequisites, signals, techniques, validation bar and false-positive rules.
---

# NTLM Authentication Weaknesses — hunting skill

<!-- GENERATED from db/wks.db by wks/skillgen.py. DO NOT HAND-EDIT.
     Edit the rows (or ingest better research) and re-run:
     python -m wks.skillgen -->

> surface `ad` · CWE CWE-294 · OWASP —
> evidence: 3 items, 3 supported, 1 FP rules, 0 chains
> maturity: **researching** — missing: items, supported_items, fp_rules, chain

An NTLM challenge can be relayed to a second service, or a captured hash replayed, because NTLM authenticates the connection rather than the channel to it.

**Also called:** ntlm, ntlmv1, relay, ntlm relay, name piping, named pipe, nbns spoofing, smb relay, responder


## Prerequisites (do not start without these)

- NTLM authentication traffic cannot be treated as an anomaly until a per-host baseline of legitimate NTLM authentication has been established for that host.
  - **Disproof:** If the estate is homogeneous and every domain-joined host is Kerberos-only with NTLM disabled at the DC and on all clients, then any NTLM handshake is by definition outside the baseline and no per-host baseline work is required to call it anomalous.
  - Sources: <https://academy.hackthebox.com/course/preview/active-directory-enumeration--attacks> · <https://securelist.com/tr/network-anomaly-detection-in-kata/120892/>

## Techniques (what to change)

- An NTLM authentication exchange can be relayed rather than cracked: because NTLM authenticates the connection and not the channel to it, a captured challenge-response from one service is replayable against a second service that accepts NTLM.
  - **Disproof:** If the target service rejects the relayed exchange because message signing or channel binding is mandatory, or if no adversary-controlled authentication can be induced on the path, then NTLM relay cannot succeed and any such report is a false positive.
  - Sources: <https://attack.mitre.org/techniques/T1557/001/> · <https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/>

## False-positive rules (when to reject it)

- One outbound SMB session carrying an NTLM Type-3 authenticate message to an external address is the expected result of a UNC link, not evidence that NTLM hashes were stolen; hash theft requires server-side relay artifacts to be present.
  - **Disproof:** The external SMB server emits the Impacket default NTLM challenge and default GUID, or the captured Type-3 response is replayed successfully to a second host or service as an authenticated session, which turns the observation from coercion into confirmed credential theft.
  - Sources: <https://www.proofpoint.com/us/blog/threat-insight/ta577s-unusual-attack-chain-leads-ntlm-data-theft> · <https://www.helpnetsecurity.com/2025/10/21/cisa-warns-of-windows-smb-flaw-under-active-exploitation-cve-2025-33073/>

---
Full class document: `skills/Network + AD/ad_ntlm/EVIDENCE.md` · retrieve more with `python -m wks.cli search "<query>" --class-id ad_ntlm`
