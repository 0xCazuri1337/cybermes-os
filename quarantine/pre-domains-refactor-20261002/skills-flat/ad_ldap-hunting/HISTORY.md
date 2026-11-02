# History

Append-only. Each entry records WHY the skill changed, not just that it did. Improvement means better hunting behaviour, not more text.

## 2026-10-02 10:30 — 1 diff lines
- items: 4 (supported 4), FP rules 2, chains 0, state researching
- still missing: methodology, items, chain

```diff
(initial generation, 2026-10-02)
```

## 2026-10-02 10:32 — 11 diff lines
- items: 4 (supported 4), FP rules 2, chains 0, state researching
- still missing: items, chain

```diff
--- ad_ldap@current
+++ ad_ldap@new
@@ -11,7 +11,7 @@
 
 > surface `ad` · CWE CWE-90 · OWASP —
 > evidence: 4 items, 4 supported, 2 FP rules, 0 chains
-> maturity: **researching** — missing: methodology, items, chain
+> maturity: **researching** — missing: items, chain
 
 Directory queries are attacker-reachable structure: an unescaped filter changes the query, and an unsigned bind lets the response be forged.
 
```

## 2026-10-02 10:50 — 21 diff lines
- items: 5 (supported 5), FP rules 2, chains 0, state researching
- still missing: items, chain

```diff
--- ad_ldap@current
+++ ad_ldap@new
@@ -10,7 +10,7 @@
      python -m wks.skillgen -->
 
 > surface `ad` · CWE CWE-90 · OWASP —
-> evidence: 4 items, 4 supported, 2 FP rules, 0 chains
+> evidence: 5 items, 5 supported, 2 FP rules, 0 chains
 > maturity: **researching** — missing: items, chain
 
 Directory queries are attacker-reachable structure: an unescaped filter changes the query, and an unsigned bind lets the response be forged.
@@ -20,6 +20,9 @@
 
 ## Prerequisites (do not start without these)
 
+- An LDAP-based AD change finding is only testable after object-level directory-service auditing is confirmed on, because without it the pre-change state cannot be recovered.
+  - **Disproof:** If directory service object-level auditing was enabled and continuous at the time of the change, and the 4662-class record names the modifying principal, then the audit-trail prerequisite is not the limiting factor and the LDAP finding can be attributed without reconstruction.
+  - Sources: <https://academy.hackthebox.com/course/preview/active-directory-ldap> · <https://securelist.com/tr/payload-ransomware-via-group-policy/121335/>
 - Any domain-joined workstation, even without RSAT and without admin rights, can run full LDAP-backed Active Directory enumeration once Microsoft.ActiveDirectory.Management.dll is imported, so the prerequisite for AD discovery is network reachability to a DC rather than a privileged toolchain.
   - **Disproof:** A DC that logs and blocks the underlying LDAP bind/query operations from ordinary user workstations, or an environment where the AD Web Services / LDAP ports are unreachable from user segments, would refute the claim.
   - Sources: <https://horizon3.ai/attack-research/defending-with-ad-tripwires-goad-walkthrough/> · <https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/active-directory-enumeration-with-ad-module-without-rsat-or-admin-privileges.md>
```

## 2026-10-02 13:38 — 8 diff lines
- items: 5 (supported 5), FP rules 2, chains 0, state researching
- still missing: items, chain

```diff
--- ad_ldap@current
+++ ad_ldap@new
@@ -43,4 +43,4 @@
   - Sources: <https://www.helpnetsecurity.com/2024/02/08/soaphound-open-source-collect-active-directory-data-adws/> · <https://www.proofpoint.com/us/blog/email-and-cloud-threats/identity-protection-risks-of-domains-and-trusts>
 
 ---
-Full class document: `classes/ad_ldap.md` · retrieve more with `python -m wks.cli search "<query>" --class-id ad_ldap`
+Full class document: `skills/Network + AD/ad_ldap/EVIDENCE.md` · retrieve more with `python -m wks.cli search "<query>" --class-id ad_ldap`
```
