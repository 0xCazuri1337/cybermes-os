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
--- internal_recon@current
+++ internal_recon@new
@@ -11,7 +11,7 @@
 
 > surface `net` · CWE CWE-200 · OWASP —
 > evidence: 3 items, 3 supported, 1 FP rules, 0 chains
-> maturity: **researching** — missing: methodology, items, supported_items, fp_rules, chain
+> maturity: **researching** — missing: items, supported_items, fp_rules, chain
 
 An internal network is not uniform: naming and addressing patterns predict what a host runs, so enumeration is inference as much as probing.
 
```

## 2026-10-02 11:07 — 37 diff lines
- items: 4 (supported 4), FP rules 2, chains 1, state researching
- still missing: items

```diff
--- internal_recon@current
+++ internal_recon@new
@@ -10,8 +10,8 @@
      python -m wks.skillgen -->
 
 > surface `net` · CWE CWE-200 · OWASP —
-> evidence: 3 items, 3 supported, 1 FP rules, 0 chains
-> maturity: **researching** — missing: items, supported_items, fp_rules, chain
+> evidence: 4 items, 4 supported, 2 FP rules, 1 chains
+> maturity: **researching** — missing: items
 
 An internal network is not uniform: naming and addressing patterns predict what a host runs, so enumeration is inference as much as probing.
 
@@ -36,5 +36,23 @@
   - **Disproof:** If Sysmon or EDR process telemetry still captures the full rpcclient argument string when invoked through a socks proxy, the claim would be refuted.
   - Sources: <https://www.elastic.co/security-labs/blog/hunting-for-lateral-movement-using-event-query-language> · <https://www.ired.team/offensive-security/enumeration-and-discovery/enumerating-windows-domains-using-rpcclient-through-socksproxy-bypassing-command-line-logging.md>
 
+## Chaining opportunities
+
+- A directory enumeration filtered to SPN-bearing accounts hands the next link exactly the input kerberoasting consumes, and the recovered service-account password is an authenticated remote-execution channel on hosts the enumeration never touched.
+  - **Disproof:** Refuted if the directory does not expose servicePrincipalName values to the enumerating principal, or if every SPN-bearing account has a password that offline cracking did not recover within the assessment window; without a recovered service-account secret the chain stops at enumeration.
+  - Sources: <https://academy.hackthebox.com/course/preview/active-directory-powerview> · <https://securelist.com/tr/network-anomaly-detection-in-kata/120892/> · <https://securelist.com/tr/nighteagle-apt-ghostcontainer-and-tunneling/121323/>
+
+## Rejected before you report
+
+- **A single native enumeration command observed on a host is evidence of attacker reconnaissance of the internal network.**
+  - Killed by: The identical command is part of the documented administrative routine and appears on managed hosts under their own credentials; no enumerated name is referenced by any subsequent authentication event, so nothing downstream consumed the output.
+  - Rule: One enumeration command is dual use. Before reporting reconnaissance, show the same command in the admin baseline and show a downstream consumer - an authentication event, a connection, or a file access - that references an enumerated name. Absent the consumer you have an unproven telemetry signal.
+
+## Chains to
+
+- `lateral_movement` (1 shared chain(s))
+- `info_disclosure` (1 shared chain(s))
+- `ad_enumeration` (1 shared chain(s))
+
 ---
 Full class document: `classes/internal_recon.md` · retrieve more with `python -m wks.cli search "<query>" --class-id internal_recon`
```

## 2026-10-02 13:38 — 8 diff lines
- items: 4 (supported 4), FP rules 2, chains 1, state researching
- still missing: items

```diff
--- internal_recon@current
+++ internal_recon@new
@@ -55,4 +55,4 @@
 - `ad_enumeration` (1 shared chain(s))
 
 ---
-Full class document: `classes/internal_recon.md` · retrieve more with `python -m wks.cli search "<query>" --class-id internal_recon`
+Full class document: `skills/Network + AD/internal_recon/EVIDENCE.md` · retrieve more with `python -m wks.cli search "<query>" --class-id internal_recon`
```
