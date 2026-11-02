# History

Append-only. Each entry records WHY the skill changed, not just that it did. Improvement means better hunting behaviour, not more text.

## 2026-10-02 10:30 — 1 diff lines
- items: 5 (supported 5), FP rules 3, chains 0, state researching
- still missing: methodology, items, chain

```diff
(initial generation, 2026-10-02)
```

## 2026-10-02 10:32 — 11 diff lines
- items: 5 (supported 5), FP rules 3, chains 0, state researching
- still missing: items, chain

```diff
--- exposed_rmm@current
+++ exposed_rmm@new
@@ -11,7 +11,7 @@
 
 > surface `net` · CWE CWE-200 · OWASP —
 > evidence: 5 items, 5 supported, 3 FP rules, 0 chains
-> maturity: **researching** — missing: methodology, items, chain
+> maturity: **researching** — missing: items, chain
 
 RMM agents are installed to bypass network controls, so their reachability and credential handling determine their risk.
 
```

## 2026-10-02 11:07 — 29 diff lines
- items: 5 (supported 5), FP rules 4, chains 1, state researching
- still missing: items

```diff
--- exposed_rmm@current
+++ exposed_rmm@new
@@ -10,8 +10,8 @@
      python -m wks.skillgen -->
 
 > surface `net` · CWE CWE-200 · OWASP —
-> evidence: 5 items, 5 supported, 3 FP rules, 0 chains
-> maturity: **researching** — missing: items, chain
+> evidence: 5 items, 5 supported, 4 FP rules, 1 chains
+> maturity: **researching** — missing: items
 
 RMM agents are installed to bypass network controls, so their reachability and credential handling determine their risk.
 
@@ -42,5 +42,15 @@
   - **Disproof:** Would be wrong where an unpatched build sits behind an MFA-enforced control plane, since the bypass then needs the second factor.
   - Sources: <https://netlas.io/blog/weaponized_rmm/> · <https://www.rapid7.com/blog/post/2024/02/20/etr-high-risk-vulnerabilities-in-connectwise-screenconnect/>
 
+## Rejected before you report
+
+- **An installed remote monitoring and management agent on a workstation is evidence of compromise.**
+  - Killed by: The install timestamp falls inside the approved deployment window, the binary matches the vendor-signed package in the software distribution system, and no management listener answered from outside the corporate network; the agent was deployed, not implanted.
+  - Rule: An RMM agent's presence is a deployment fact, not a finding. Report it only when install time or signing identity departs from the deployment record, or when a management interface answers from a network that policy forbids.
+
+## Chains to
+
+- `supply_chain` (3 shared chain(s))
+
 ---
 Full class document: `classes/exposed_rmm.md` · retrieve more with `python -m wks.cli search "<query>" --class-id exposed_rmm`
```

## 2026-10-02 13:38 — 8 diff lines
- items: 5 (supported 5), FP rules 4, chains 1, state researching
- still missing: items

```diff
--- exposed_rmm@current
+++ exposed_rmm@new
@@ -53,4 +53,4 @@
 - `supply_chain` (3 shared chain(s))
 
 ---
-Full class document: `classes/exposed_rmm.md` · retrieve more with `python -m wks.cli search "<query>" --class-id exposed_rmm`
+Full class document: `skills/Network + AD/exposed_rmm/EVIDENCE.md` · retrieve more with `python -m wks.cli search "<query>" --class-id exposed_rmm`
```
