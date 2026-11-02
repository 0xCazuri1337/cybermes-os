# History

Append-only. Each entry records WHY the skill changed, not just that it did. Improvement means better hunting behaviour, not more text.

## 2026-10-02 10:30 — 1 diff lines
- items: 3 (supported 3), FP rules 1, chains 0, state researching
- still missing: methodology, items, supported_items, fp_rules, chain

```diff
(initial generation, 2026-10-02)
```

## 2026-10-02 10:32 — 11 diff lines
- items: 3 (supported 3), FP rules 1, chains 0, state researching
- still missing: items, supported_items, fp_rules, chain

```diff
--- exposed_services@current
+++ exposed_services@new
@@ -11,7 +11,7 @@
 
 > surface `net` · CWE CWE-200 · OWASP —
 > evidence: 3 items, 3 supported, 1 FP rules, 0 chains
-> maturity: **researching** — missing: methodology, items, supported_items, fp_rules, chain
+> maturity: **researching** — missing: items, supported_items, fp_rules, chain
 
 An administrative protocol reachable from where it should not be concedes its authentication surface to that reachability.
 
```

## 2026-10-02 11:07 — 25 diff lines
- items: 3 (supported 3), FP rules 2, chains 0, state researching
- still missing: items, supported_items, chain

```diff
--- exposed_services@current
+++ exposed_services@new
@@ -10,8 +10,8 @@
      python -m wks.skillgen -->
 
 > surface `net` · CWE CWE-200 · OWASP —
-> evidence: 3 items, 3 supported, 1 FP rules, 0 chains
-> maturity: **researching** — missing: items, supported_items, fp_rules, chain
+> evidence: 3 items, 3 supported, 2 FP rules, 0 chains
+> maturity: **researching** — missing: items, supported_items, chain
 
 An administrative protocol reachable from where it should not be concedes its authentication surface to that reachability.
 
@@ -36,5 +36,11 @@
   - **Disproof:** The high-port SSH service hands an interactive shell to an unexpected source, or its host key rotates across scans without a firmware change, showing the daemon is being used as an operator foothold rather than as a vendor management tunnel.
   - Sources: <https://www.talosintelligence.com/vulnerability_reports/TALOS-2025-2291> · <https://www.helpnetsecurity.com/2026/03/24/detectify-ip-range-scanning/>
 
+## Rejected before you report
+
+- **An SSH service listening on an unusual high TCP port is an exposed remote service finding.**
+  - Killed by: The listener is a vendor port forward terminating on a managed relay that accepts connections only from the vendor's own management subnet, and no account authenticated from the scanning source; the non-standard port is the vendor's published configuration, not an additional exposure.
+  - Rule: A non-standard port is not a finding by itself. Establish what the listener terminates on, whether logins are restricted to a vendor relay, and whether authentication succeeded from an untrusted source; only the last of those is an exposed remote service.
+
 ---
 Full class document: `classes/exposed_services.md` · retrieve more with `python -m wks.cli search "<query>" --class-id exposed_services`
```

## 2026-10-02 12:21 — 60 diff lines
- items: 6 (supported 6), FP rules 2, chains 1, state researching
- still missing: items

```diff
--- exposed_services@current
+++ exposed_services@new
@@ -10,8 +10,8 @@
      python -m wks.skillgen -->
 
 > surface `net` · CWE CWE-200 · OWASP —
-> evidence: 3 items, 3 supported, 2 FP rules, 0 chains
-> maturity: **researching** — missing: items, supported_items, chain
+> evidence: 6 items, 6 supported, 2 FP rules, 1 chains
+> maturity: **researching** — missing: items
 
 An administrative protocol reachable from where it should not be concedes its authentication surface to that reachability.
 
@@ -24,11 +24,23 @@
   - **Disproof:** An inventory showing these CPS environments with no third-party remote access agents and no non-essential open ports would refute the claim for that estate.
   - Sources: <https://labs.watchtowr.com/here-we-go-again-citrix-netscaler-dtls-preauth-memory-overflow-cve-2026-88772/> · <https://www.claroty.com/blog/claroty-team82-state-of-cps-security-2025-report-building-management-system-exposures>
 
+## Recon signals (where to look)
+
+- An RDP session whose destination is a domain controller is a higher-severity signal than the same session to a member server, because the destination can perform directory replication.
+  - **Disproof:** Proof the claim wrong would be a deployment in which domain controllers are hardened against interactive RDP entirely -- no RDP listener present, or network-level authentication plus a control that blocks interactive sessions -- so that an RDP session to a DC cannot exist and the severity split is vacuous; or evidence that the flagged DC session was an automated management connection with no interactive channel at all.
+  - Sources: <https://academy.hackthebox.com/course/preview/active-directory-powerview> · <https://securelist.com/tr/network-anomaly-detection-in-kata/120892/>
+
 ## Techniques (what to change)
 
 - An administrative or remote service reachable from where policy forbids it is an initial-access or persistence surface, because attacker leverage is bounded by reachability rather than by the service's own authentication.
   - **Disproof:** If every exposed administrative service is reachable only from an explicitly authorized management segment and enforced at the network layer rather than by application configuration, then the reachability that creates the risk is not present.
   - Sources: <https://attack.mitre.org/techniques/T1133/> · <https://learn.microsoft.com/en-us/windows/win32/termserv/remote-desktop-protocol>
+
+## Validation bar (how to prove it)
+
+- A flagged RDP session to a domain controller discriminates from the benign lookalike only when the operator's rights to that controller are read out of the directory rather than inferred from the session alone.
+  - **Disproof:** Proof the claim wrong would be a case where the account holds no interactive logon right on the domain controller yet the session succeeded anyway, showing the directory rights model did not predict the outcome and that the rights graph is therefore not a sufficient discriminator for this class; or a domain where interactive logon rights are not represented in the enumerated data at all.
+  - Sources: <https://academy.hackthebox.com/course/preview/active-directory-powerview> · <https://securelist.com/tr/network-anomaly-detection-in-kata/120892/>
 
 ## False-positive rules (when to reject it)
 
@@ -36,11 +48,22 @@
   - **Disproof:** The high-port SSH service hands an interactive shell to an unexpected source, or its host key rotates across scans without a firmware change, showing the daemon is being used as an operator foothold rather than as a vendor management tunnel.
   - Sources: <https://www.talosintelligence.com/vulnerability_reports/TALOS-2025-2291> · <https://www.helpnetsecurity.com/2026/03/24/detectify-ip-range-scanning/>
 
+## Chaining opportunities
+
+- An administrative or remote service reachable from where policy forbids it is initial access rather than a standalone exposure, because the reachable authentication surface is what a relay primitive later supplies with credentials it could not otherwise obtain.
+  - **Disproof:** Refuted if the administrative service is not reachable from the untrusted segment, or if the service enforces message signing or channel binding on every inbound authentication such that a relayed response is rejected; with either condition the exposure yields no credential and the chain stops at reconnaissance.
+  - Sources: <https://academy.hackthebox.com/course/preview/active-directory-ldap> · <https://securelist.com/tr/network-anomaly-detection-in-kata/120892/> · <https://securelist.com/tr/payload-ransomware-via-group-policy/121335/>
+
 ## Rejected before you report
 
 - **An SSH service listening on an unusual high TCP port is an exposed remote service finding.**
   - Killed by: The listener is a vendor port forward terminating on a managed relay that accepts connections only from the vendor's own management subnet, and no account authenticated from the scanning source; the non-standard port is the vendor's published configuration, not an additional exposure.
   - Rule: A non-standard port is not a finding by itself. Establish what the listener terminates on, whether logins are restricted to a vendor relay, and whether authentication succeeded from an untrusted source; only the last of those is an exposed remote service.
 
+## Chains to
+
+- `smb` (2 shared chain(s))
+- `lateral_movement` (2 shared chain(s))
+
 ---
 Full class document: `classes/exposed_services.md` · retrieve more with `python -m wks.cli search "<query>" --class-id exposed_services`
```

## 2026-10-02 13:38 — 8 diff lines
- items: 6 (supported 6), FP rules 2, chains 1, state researching
- still missing: items

```diff
--- exposed_services@current
+++ exposed_services@new
@@ -66,4 +66,4 @@
 - `lateral_movement` (2 shared chain(s))
 
 ---
-Full class document: `classes/exposed_services.md` · retrieve more with `python -m wks.cli search "<query>" --class-id exposed_services`
+Full class document: `skills/Network + AD/exposed_services/EVIDENCE.md` · retrieve more with `python -m wks.cli search "<query>" --class-id exposed_services`
```
