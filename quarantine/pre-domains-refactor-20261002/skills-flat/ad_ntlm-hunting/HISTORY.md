# History

Append-only. Each entry records WHY the skill changed, not just that it did. Improvement means better hunting behaviour, not more text.

## 2026-10-02 10:30 — 1 diff lines
- items: 2 (supported 2), FP rules 1, chains 0, state researching
- still missing: methodology, items, supported_items, fp_rules, chain

```diff
(initial generation, 2026-10-02)
```

## 2026-10-02 10:32 — 11 diff lines
- items: 2 (supported 2), FP rules 1, chains 0, state researching
- still missing: items, supported_items, fp_rules, chain

```diff
--- ad_ntlm@current
+++ ad_ntlm@new
@@ -11,7 +11,7 @@
 
 > surface `ad` · CWE CWE-294 · OWASP —
 > evidence: 2 items, 2 supported, 1 FP rules, 0 chains
-> maturity: **researching** — missing: methodology, items, supported_items, fp_rules, chain
+> maturity: **researching** — missing: items, supported_items, fp_rules, chain
 
 An NTLM challenge can be relayed to a second service, or a captured hash replayed, because NTLM authenticates the connection rather than the channel to it.
 
```

## 2026-10-02 10:50 — 23 diff lines
- items: 3 (supported 3), FP rules 1, chains 0, state researching
- still missing: items, supported_items, fp_rules, chain

```diff
--- ad_ntlm@current
+++ ad_ntlm@new
@@ -10,13 +10,19 @@
      python -m wks.skillgen -->
 
 > surface `ad` · CWE CWE-294 · OWASP —
-> evidence: 2 items, 2 supported, 1 FP rules, 0 chains
+> evidence: 3 items, 3 supported, 1 FP rules, 0 chains
 > maturity: **researching** — missing: items, supported_items, fp_rules, chain
 
 An NTLM challenge can be relayed to a second service, or a captured hash replayed, because NTLM authenticates the connection rather than the channel to it.
 
 **Also called:** ntlm, ntlmv1, relay, ntlm relay, name piping, named pipe, nbns spoofing, smb relay, responder
 
+
+## Prerequisites (do not start without these)
+
+- NTLM authentication traffic cannot be treated as an anomaly until a per-host baseline of legitimate NTLM authentication has been established for that host.
+  - **Disproof:** If the estate is homogeneous and every domain-joined host is Kerberos-only with NTLM disabled at the DC and on all clients, then any NTLM handshake is by definition outside the baseline and no per-host baseline work is required to call it anomalous.
+  - Sources: <https://academy.hackthebox.com/course/preview/active-directory-enumeration--attacks> · <https://securelist.com/tr/network-anomaly-detection-in-kata/120892/>
 
 ## Techniques (what to change)
 
```

## 2026-10-02 13:38 — 8 diff lines
- items: 3 (supported 3), FP rules 1, chains 0, state researching
- still missing: items, supported_items, fp_rules, chain

```diff
--- ad_ntlm@current
+++ ad_ntlm@new
@@ -37,4 +37,4 @@
   - Sources: <https://www.proofpoint.com/us/blog/threat-insight/ta577s-unusual-attack-chain-leads-ntlm-data-theft> · <https://www.helpnetsecurity.com/2025/10/21/cisa-warns-of-windows-smb-flaw-under-active-exploitation-cve-2025-33073/>
 
 ---
-Full class document: `classes/ad_ntlm.md` · retrieve more with `python -m wks.cli search "<query>" --class-id ad_ntlm`
+Full class document: `skills/Network + AD/ad_ntlm/EVIDENCE.md` · retrieve more with `python -m wks.cli search "<query>" --class-id ad_ntlm`
```
