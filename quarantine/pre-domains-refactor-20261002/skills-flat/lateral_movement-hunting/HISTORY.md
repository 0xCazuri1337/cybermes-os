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
--- lateral_movement@current
+++ lateral_movement@new
@@ -11,7 +11,7 @@
 
 > surface `net` · CWE CWE-284 · OWASP —
 > evidence: 3 items, 3 supported, 1 FP rules, 0 chains
-> maturity: **researching** — missing: methodology, items, supported_items, fp_rules, chain
+> maturity: **researching** — missing: items, supported_items, fp_rules, chain
 
 Movement is a choice among protocols available between two hosts, so the choice depends on what is reachable and what each protocol authenticates.
 
```

## 2026-10-02 10:46 — 25 diff lines
- items: 3 (supported 3), FP rules 2, chains 0, state researching
- still missing: items, supported_items, chain

```diff
--- lateral_movement@current
+++ lateral_movement@new
@@ -10,8 +10,8 @@
      python -m wks.skillgen -->
 
 > surface `net` · CWE CWE-284 · OWASP —
-> evidence: 3 items, 3 supported, 1 FP rules, 0 chains
-> maturity: **researching** — missing: items, supported_items, fp_rules, chain
+> evidence: 3 items, 3 supported, 2 FP rules, 0 chains
+> maturity: **researching** — missing: items, supported_items, chain
 
 Movement is a choice among protocols available between two hosts, so the choice depends on what is reachable and what each protocol authenticates.
 
@@ -33,5 +33,11 @@
   - **Disproof:** The same session is preceded in the same engagement by credential-dumping or credential-access telemetry for that account, or the authenticating account is not one assigned to the source host's operators, which establishes that the credential was obtained by the test rather than issued to the tester.
   - Sources: <https://redcanary.com/threat-detection-report/techniques/windows-management-instrumentation/> · <https://www.ired.team/offensive-security/credential-access-and-credential-dumping/network-vs-interactive-logons.md> · <https://www.ired.team/offensive-security/lateral-movement/lateral-movement-with-psexec.md>
 
+## Rejected before you report
+
+- **Lateral movement to a privileged host: a domain admin session was present on a machine my foothold account could reach**
+  - Killed by: the session was the account owner operating their own account interactively from their normal station; real operators likewise reuse long-lived legitimate tickets to gain legitimate access rather than minting new authentications
+  - Rule: an existing privileged session on a reachable host is a lookalike; it becomes evidence only when the ticket was extracted or replayed from another host rather than issued interactively to its owner
+
 ---
 Full class document: `classes/lateral_movement.md` · retrieve more with `python -m wks.cli search "<query>" --class-id lateral_movement`
```

## 2026-10-02 10:50 — 34 diff lines
- items: 5 (supported 5), FP rules 3, chains 0, state researching
- still missing: items, chain

```diff
--- lateral_movement@current
+++ lateral_movement@new
@@ -10,13 +10,19 @@
      python -m wks.skillgen -->
 
 > surface `net` · CWE CWE-284 · OWASP —
-> evidence: 3 items, 3 supported, 2 FP rules, 0 chains
-> maturity: **researching** — missing: items, supported_items, chain
+> evidence: 5 items, 5 supported, 3 FP rules, 0 chains
+> maturity: **researching** — missing: items, chain
 
 Movement is a choice among protocols available between two hosts, so the choice depends on what is reachable and what each protocol authenticates.
 
 **Also called:** lateral movement, move laterally, pivot, pivoting, east west movement, internal movement
 
+
+## Prerequisites (do not start without these)
+
+- Lateral movement is only demonstrable when one host is already under control with valid credentials and a reachable second host exists, so observed host-to-host reachability alone is not movement.
+  - **Disproof:** If the source-to-destination authentication in question is attributable to a scheduled task, a management agent, or an interactive logon by the account's own owner with no replayed credential, then the movement hypothesis for that pair is invalidated and the class should not be raised for it.
+  - Sources: <https://academy.hackthebox.com/course/preview/active-directory-powerview> · <https://securelist.com/tr/nighteagle-apt-ghostcontainer-and-tunneling/121323/>
 
 ## Techniques (what to change)
 
@@ -29,6 +35,9 @@
 
 ## False-positive rules (when to reject it)
 
+- Finding a privileged account with an active session on a host you can reach is a lookalike: the session is normally the account owner's own, not evidence of movement.
+  - **Disproof:** If the privileged session's ticket was issued to the account at its normal logon station and logon time with no extraction, theft, or replay from another host, then the session reflects the owner operating their own account and the lateral-movement finding is invalidated.
+  - Sources: <https://academy.hackthebox.com/course/preview/active-directory-enumeration--attacks> · <https://securelist.com/tr/nighteagle-apt-ghostcontainer-and-tunneling/121323/>
 - A remote logon that authenticates with valid domain or local credentials over SMB, WMI, WinRM, or RDP is expected ER and administration activity; do not file remote code execution as a finding unless the credentials were obtained in the same engagement, since the technique and the artefact are identical whether the operator is an attacker or a responder.
   - **Disproof:** The same session is preceded in the same engagement by credential-dumping or credential-access telemetry for that account, or the authenticating account is not one assigned to the source host's operators, which establishes that the credential was obtained by the test rather than issued to the tester.
   - Sources: <https://redcanary.com/threat-detection-report/techniques/windows-management-instrumentation/> · <https://www.ired.team/offensive-security/credential-access-and-credential-dumping/network-vs-interactive-logons.md> · <https://www.ired.team/offensive-security/lateral-movement/lateral-movement-with-psexec.md>
```

## 2026-10-02 11:07 — 29 diff lines
- items: 5 (supported 5), FP rules 4, chains 1, state researching
- still missing: items

```diff
--- lateral_movement@current
+++ lateral_movement@new
@@ -10,8 +10,8 @@
      python -m wks.skillgen -->
 
 > surface `net` · CWE CWE-284 · OWASP —
-> evidence: 5 items, 5 supported, 3 FP rules, 0 chains
-> maturity: **researching** — missing: items, chain
+> evidence: 5 items, 5 supported, 4 FP rules, 1 chains
+> maturity: **researching** — missing: items
 
 Movement is a choice among protocols available between two hosts, so the choice depends on what is reachable and what each protocol authenticates.
 
@@ -47,6 +47,15 @@
 - **Lateral movement to a privileged host: a domain admin session was present on a machine my foothold account could reach**
   - Killed by: the session was the account owner operating their own account interactively from their normal station; real operators likewise reuse long-lived legitimate tickets to gain legitimate access rather than minting new authentications
   - Rule: an existing privileged session on a reachable host is a lookalike; it becomes evidence only when the ticket was extracted or replayed from another host rather than issued interactively to its owner
+- **A remote logon to an administrative share on a peer host is evidence of lateral movement.**
+  - Killed by: The logon used valid domain credentials in the approved remote administration tooling and the identical pattern recurs across many source hosts on a scheduled cycle, so it is the sanctioned access path rather than a pivot; no credential was reused from memory or dump.
+  - Rule: A remote administrative session carrying valid credentials in the sanctioned tool is expected ER activity, not lateral movement. Lateral movement requires either a credential the session could not legitimately hold, or a protocol path outside the approved administration profile.
+
+## Chains to
+
+- `internal_recon` (1 shared chain(s))
+- `info_disclosure` (1 shared chain(s))
+- `ad_enumeration` (1 shared chain(s))
 
 ---
 Full class document: `classes/lateral_movement.md` · retrieve more with `python -m wks.cli search "<query>" --class-id lateral_movement`
```

## 2026-10-02 12:21 — 20 diff lines
- items: 5 (supported 5), FP rules 4, chains 2, state researching
- still missing: items

```diff
--- lateral_movement@current
+++ lateral_movement@new
@@ -10,7 +10,7 @@
      python -m wks.skillgen -->
 
 > surface `net` · CWE CWE-284 · OWASP —
-> evidence: 5 items, 5 supported, 4 FP rules, 1 chains
+> evidence: 5 items, 5 supported, 4 FP rules, 2 chains
 > maturity: **researching** — missing: items
 
 Movement is a choice among protocols available between two hosts, so the choice depends on what is reachable and what each protocol authenticates.
@@ -53,6 +53,8 @@
 
 ## Chains to
 
+- `exposed_services` (2 shared chain(s))
+- `smb` (1 shared chain(s))
 - `internal_recon` (1 shared chain(s))
 - `info_disclosure` (1 shared chain(s))
 - `ad_enumeration` (1 shared chain(s))
```

## 2026-10-02 13:38 — 8 diff lines
- items: 5 (supported 5), FP rules 4, chains 2, state researching
- still missing: items

```diff
--- lateral_movement@current
+++ lateral_movement@new
@@ -60,4 +60,4 @@
 - `ad_enumeration` (1 shared chain(s))
 
 ---
-Full class document: `classes/lateral_movement.md` · retrieve more with `python -m wks.cli search "<query>" --class-id lateral_movement`
+Full class document: `skills/Network + AD/lateral_movement/EVIDENCE.md` · retrieve more with `python -m wks.cli search "<query>" --class-id lateral_movement`
```
