# History

Append-only. Each entry records WHY the skill changed, not just that it did. Improvement means better hunting behaviour, not more text.

## 2026-10-02 10:30 — 1 diff lines
- items: 4 (supported 4), FP rules 1, chains 0, state researching
- still missing: methodology, items, fp_rules, chain

```diff
(initial generation, 2026-10-02)
```

## 2026-10-02 10:32 — 11 diff lines
- items: 4 (supported 4), FP rules 1, chains 0, state researching
- still missing: items, fp_rules, chain

```diff
--- ad_enumeration@current
+++ ad_enumeration@new
@@ -11,7 +11,7 @@
 
 > surface `ad` · CWE CWE-200 · OWASP —
 > evidence: 4 items, 4 supported, 1 FP rules, 0 chains
-> maturity: **researching** — missing: methodology, items, fp_rules, chain
+> maturity: **researching** — missing: items, fp_rules, chain
 
 Domain membership is queryable without authentication on common paths, so the directory's own structure discloses the map needed to attack it.
 
```

## 2026-10-02 10:50 — 24 diff lines
- items: 5 (supported 5), FP rules 1, chains 0, state researching
- still missing: items, fp_rules, chain

```diff
--- ad_enumeration@current
+++ ad_enumeration@new
@@ -10,7 +10,7 @@
      python -m wks.skillgen -->
 
 > surface `ad` · CWE CWE-200 · OWASP —
-> evidence: 4 items, 4 supported, 1 FP rules, 0 chains
+> evidence: 5 items, 5 supported, 1 FP rules, 0 chains
 > maturity: **researching** — missing: items, fp_rules, chain
 
 Domain membership is queryable without authentication on common paths, so the directory's own structure discloses the map needed to attack it.
@@ -23,6 +23,12 @@
 - Directory enumeration output is only a finding once compared against a baseline of what an unprivileged authenticated account can already read, because modern AD tooling returns surprising privilege paths for ordinary non-admin users.
   - **Disproof:** The same enumeration run against a genuinely unprivileged account reproduces the identical object set and edges, showing the tool's output reflects default read access rather than any escalation.
   - Sources: <https://www.talosintelligence.com/vulnerability_reports/TALOS-2022-1625> · <https://www.helpnetsecurity.com/2024/01/15/adalanche-open-source-active-directory-acl-visualizer-explorer/>
+
+## Recon signals (where to look)
+
+- An anonymous SMB session that returns a full user listing and the domain password policy is an early observable for enumeration, but it is a read-only baseline capability rather than a credential compromise.
+  - **Disproof:** If the anonymous session yields only public directory metadata and no secret, hash, or policy-derived credential, then the enumeration finding reduces to a hardening gap about anonymous access, and any claim of credential compromise from it is invalid.
+  - Sources: <https://academy.hackthebox.com/course/preview/active-directory-enumeration--attacks> · <https://securelist.com/tr/network-anomaly-detection-in-kata/120892/>
 
 ## Techniques (what to change)
 
```

## 2026-10-02 12:21 — 25 diff lines
- items: 5 (supported 5), FP rules 1, chains 1, state researching
- still missing: items, fp_rules

```diff
--- ad_enumeration@current
+++ ad_enumeration@new
@@ -10,8 +10,8 @@
      python -m wks.skillgen -->
 
 > surface `ad` · CWE CWE-200 · OWASP —
-> evidence: 5 items, 5 supported, 1 FP rules, 0 chains
-> maturity: **researching** — missing: items, fp_rules, chain
+> evidence: 5 items, 5 supported, 1 FP rules, 1 chains
+> maturity: **researching** — missing: items, fp_rules
 
 Domain membership is queryable without authentication on common paths, so the directory's own structure discloses the map needed to attack it.
 
@@ -48,5 +48,11 @@
   - **Disproof:** The enumeration module is loaded and its cmdlets invoked from a host with no legitimate administrative role, or the querying account is a service account that has no reason to enumerate the domain, which places the activity outside any administration workflow.
   - Sources: <https://redcanary.com/threat-detection-report/techniques/domain-trust-discovery/> · <https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/active-directory-enumeration-with-ad-module-without-rsat-or-admin-privileges.md>
 
+## Chains to
+
+- `lateral_movement` (1 shared chain(s))
+- `internal_recon` (1 shared chain(s))
+- `info_disclosure` (1 shared chain(s))
+
 ---
 Full class document: `classes/ad_enumeration.md` · retrieve more with `python -m wks.cli search "<query>" --class-id ad_enumeration`
```

## 2026-10-02 13:38 — 8 diff lines
- items: 5 (supported 5), FP rules 1, chains 1, state researching
- still missing: items, fp_rules

```diff
--- ad_enumeration@current
+++ ad_enumeration@new
@@ -55,4 +55,4 @@
 - `info_disclosure` (1 shared chain(s))
 
 ---
-Full class document: `classes/ad_enumeration.md` · retrieve more with `python -m wks.cli search "<query>" --class-id ad_enumeration`
+Full class document: `skills/Network + AD/ad_enumeration/EVIDENCE.md` · retrieve more with `python -m wks.cli search "<query>" --class-id ad_enumeration`
```
