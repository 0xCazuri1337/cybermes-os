# History

Append-only. Each entry records WHY the skill changed, not just that it did. Improvement means better hunting behaviour, not more text.

## 2026-10-02 10:30 — 1 diff lines
- items: 8 (supported 7), FP rules 2, chains 0, state researching
- still missing: methodology, items, chain

```diff
(initial generation, 2026-10-02)
```

## 2026-10-02 10:32 — 11 diff lines
- items: 8 (supported 7), FP rules 2, chains 0, state researching
- still missing: items, chain

```diff
--- ad_kerberos@current
+++ ad_kerberos@new
@@ -11,7 +11,7 @@
 
 > surface `ad` · CWE CWE-287 · OWASP —
 > evidence: 8 items, 7 supported, 2 FP rules, 0 chains
-> maturity: **researching** — missing: methodology, items, chain
+> maturity: **researching** — missing: items, chain
 
 Kerberos issues tickets that can be requested offline and cracked, or forged outright when the relevant key material is reachable.
 
```

## 2026-10-02 10:46 — 23 diff lines
- items: 8 (supported 7), FP rules 3, chains 0, state researching
- still missing: items, chain

```diff
--- ad_kerberos@current
+++ ad_kerberos@new
@@ -10,7 +10,7 @@
      python -m wks.skillgen -->
 
 > surface `ad` · CWE CWE-287 · OWASP —
-> evidence: 8 items, 7 supported, 2 FP rules, 0 chains
+> evidence: 8 items, 7 supported, 3 FP rules, 0 chains
 > maturity: **researching** — missing: items, chain
 
 Kerberos issues tickets that can be requested offline and cracked, or forged outright when the relevant key material is reachable.
@@ -51,5 +51,11 @@
   - **Disproof:** Refuted if every service principal name is mapped to an account whose password is a random value of high entropy, or if the domain has disabled RC4 so tickets are AES-encrypted and offline cracking is impractical.
   - Sources: <https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/t1208-kerberoasting.md> · <https://www.zscaler.com/blogs/product-insights/active-directory-kerberoasting-deception-detection>
 
+## Rejected before you report
+
+- **Host is Kerberoasting: one client requested TGS tickets for many SPNs in a short window**
+  - Killed by: the excess was entirely system SPNs, which exist in nearly every corporate environment regardless of adversary activity; the corrected unique non-system SPN count sat below threshold across a full business cycle
+  - Rule: a Kerberoasting threshold that counts system SPNs or raw response packets is invalid; require a per-client count of unique non-system sname values before calling the fan-out an attack
+
 ---
 Full class document: `classes/ad_kerberos.md` · retrieve more with `python -m wks.cli search "<query>" --class-id ad_kerberos`
```

## 2026-10-02 10:50 — 33 diff lines
- items: 10 (supported 9), FP rules 4, chains 0, state researching
- still missing: items, chain

```diff
--- ad_kerberos@current
+++ ad_kerberos@new
@@ -10,13 +10,19 @@
      python -m wks.skillgen -->
 
 > surface `ad` · CWE CWE-287 · OWASP —
-> evidence: 8 items, 7 supported, 3 FP rules, 0 chains
+> evidence: 10 items, 9 supported, 4 FP rules, 0 chains
 > maturity: **researching** — missing: items, chain
 
 Kerberos issues tickets that can be requested offline and cracked, or forged outright when the relevant key material is reachable.
 
 **Also called:** kerberoasting, kerberoast, asrep roasting, as-rep roasting, asreproasting, golden ticket, silver ticket, spn, service principal name, ticket forgery, tgs request, service ticket, krbtgt
 
+
+## Recon signals (where to look)
+
+- A single host receiving TGS-REP responses for numerous unique SPNs inside a short window is an early observable for Kerberoasting but is identical to legitimate service-ticket traffic.
+  - **Disproof:** If the unique SPNs in the window resolve to a single known management or monitoring principal that is documented to service that SPN set on a schedule, then the fan-out is the agent's normal behaviour and the Kerberoasting hypothesis for that host is invalidated.
+  - Sources: <https://academy.hackthebox.com/course/preview/active-directory-enumeration--attacks> · <https://securelist.com/tr/network-anomaly-detection-in-kata/120892/>
 
 ## Techniques (what to change)
 
@@ -35,6 +41,9 @@
 
 ## False-positive rules (when to reject it)
 
+- Counting system SPNs toward a unique-SPN Kerberoasting threshold produces a false positive, because system SPNs exist in nearly every corporate environment and are irrelevant to the attack.
+  - **Disproof:** If a per-client unique-SPN count computed with system SPNs excluded stays below threshold across the estate's normal traffic for a full business cycle, then the threshold was being inflated by system SPNs and the flagged alerts were false positives.
+  - Sources: <https://academy.hackthebox.com/course/preview/active-directory-enumeration--attacks> · <https://securelist.com/tr/network-anomaly-detection-in-kata/120892/>
 - A single Kerberos 4769 service-ticket event is not evidence of Kerberoasting unless it also shows RC4 request, a user account and a burst pattern.
   - **Disproof:** Would be wrong if a domain is hardened so that every 4769 originates from machine accounts using AES, since then the account-name signal alone carries no information.
   - Sources: <https://www.nccgroup.com/research/defending-your-directory-an-expert-guide-to-combating-kerberoasting-in-active-directory/> · <https://www.thehacker.recipes/ad/movement/kerberos/kerberoast>
```

## 2026-10-02 13:38 — 8 diff lines
- items: 10 (supported 9), FP rules 4, chains 0, state researching
- still missing: items, chain

```diff
--- ad_kerberos@current
+++ ad_kerberos@new
@@ -67,4 +67,4 @@
   - Rule: a Kerberoasting threshold that counts system SPNs or raw response packets is invalid; require a per-client count of unique non-system sname values before calling the fan-out an attack
 
 ---
-Full class document: `classes/ad_kerberos.md` · retrieve more with `python -m wks.cli search "<query>" --class-id ad_kerberos`
+Full class document: `skills/Network + AD/ad_kerberos/EVIDENCE.md` · retrieve more with `python -m wks.cli search "<query>" --class-id ad_kerberos`
```
