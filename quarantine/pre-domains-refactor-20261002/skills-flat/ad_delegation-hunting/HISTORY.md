# History

Append-only. Each entry records WHY the skill changed, not just that it did. Improvement means better hunting behaviour, not more text.

## 2026-10-02 10:30 — 1 diff lines
- items: 8 (supported 7), FP rules 3, chains 0, state researching
- still missing: methodology, items, chain

```diff
(initial generation, 2026-10-02)
```

## 2026-10-02 10:32 — 11 diff lines
- items: 8 (supported 7), FP rules 3, chains 0, state researching
- still missing: items, chain

```diff
--- ad_delegation@current
+++ ad_delegation@new
@@ -11,7 +11,7 @@
 
 > surface `ad` · CWE CWE-863 · OWASP —
 > evidence: 8 items, 7 supported, 3 FP rules, 0 chains
-> maturity: **researching** — missing: methodology, items, chain
+> maturity: **researching** — missing: items, chain
 
 Delegation lets one identity authenticate as another to a third service, so the ticket a server holds can be replayed as the client it was issued for.
 
```

## 2026-10-02 10:50 — 23 diff lines
- items: 9 (supported 8), FP rules 3, chains 0, state researching
- still missing: items, chain

```diff
--- ad_delegation@current
+++ ad_delegation@new
@@ -10,13 +10,19 @@
      python -m wks.skillgen -->
 
 > surface `ad` · CWE CWE-863 · OWASP —
-> evidence: 8 items, 7 supported, 3 FP rules, 0 chains
+> evidence: 9 items, 8 supported, 3 FP rules, 0 chains
 > maturity: **researching** — missing: items, chain
 
 Delegation lets one identity authenticate as another to a third service, so the ticket a server holds can be replayed as the client it was issued for.
 
 **Also called:** delegation abuse, unconstrained delegation, constrained delegation, resource based constrained delegation, rbcd, s4u2self, s4u2proxy, ms-was
 
+
+## Prerequisites (do not start without these)
+
+- Delegation abuse is only testable after intra-forest delegation and trust configuration is enumerated, because cross-forest trust presence is not a precondition for it.
+  - **Disproof:** If the enumeration returns no accounts with delegation attributes set (no TrustedForDelegation, no msDS-AllowedToDelegateTo, no msDS-AllowedToActOnBehalfOfOtherIdentity) anywhere in the forest, then no delegation abuse is testable regardless of what trust objects exist.
+  - Sources: <https://academy.hackthebox.com/course/preview/active-directory-trust-attacks> · <https://securelist.com/tr/payload-ransomware-via-group-policy/121335/>
 
 ## Techniques (what to change)
 
```

## 2026-10-02 13:38 — 8 diff lines
- items: 9 (supported 8), FP rules 3, chains 0, state researching
- still missing: items, chain

```diff
--- ad_delegation@current
+++ ad_delegation@new
@@ -58,4 +58,4 @@
   - Sources: <https://learn.microsoft.com/en-us/windows-server/security/kerberos/kerberos-constrained-delegation-overview> · <https://www.tenable.com/blog/service-accounts-in-active-directory-these-og-nhis-could-be-your-weakest-link>
 
 ---
-Full class document: `classes/ad_delegation.md` · retrieve more with `python -m wks.cli search "<query>" --class-id ad_delegation`
+Full class document: `skills/Network + AD/ad_delegation/EVIDENCE.md` · retrieve more with `python -m wks.cli search "<query>" --class-id ad_delegation`
```
