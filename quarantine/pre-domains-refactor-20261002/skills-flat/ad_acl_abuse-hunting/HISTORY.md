# History

Append-only. Each entry records WHY the skill changed, not just that it did. Improvement means better hunting behaviour, not more text.

## 2026-10-02 10:30 — 1 diff lines
- items: 3 (supported 3), FP rules 2, chains 0, state researching
- still missing: methodology, items, supported_items, chain

```diff
(initial generation, 2026-10-02)
```

## 2026-10-02 10:32 — 11 diff lines
- items: 3 (supported 3), FP rules 2, chains 0, state researching
- still missing: items, supported_items, chain

```diff
--- ad_acl_abuse@current
+++ ad_acl_abuse@new
@@ -11,7 +11,7 @@
 
 > surface `ad` · CWE CWE-269 · OWASP —
 > evidence: 3 items, 3 supported, 2 FP rules, 0 chains
-> maturity: **researching** — missing: methodology, items, supported_items, chain
+> maturity: **researching** — missing: items, supported_items, chain
 
 A principal holds a permission on an object that permits changing what that object grants, so read access becomes control of the domain.
 
```

## 2026-10-02 10:46 — 23 diff lines
- items: 3 (supported 3), FP rules 3, chains 0, state researching
- still missing: items, supported_items, chain

```diff
--- ad_acl_abuse@current
+++ ad_acl_abuse@new
@@ -10,7 +10,7 @@
      python -m wks.skillgen -->
 
 > surface `ad` · CWE CWE-269 · OWASP —
-> evidence: 3 items, 3 supported, 2 FP rules, 0 chains
+> evidence: 3 items, 3 supported, 3 FP rules, 0 chains
 > maturity: **researching** — missing: items, supported_items, chain
 
 A principal holds a permission on an object that permits changing what that object grants, so read access becomes control of the domain.
@@ -33,5 +33,11 @@
   - **Disproof:** Would be wrong where the same principal is low-privilege and reachable, or where the ACE grants the right to a group the tester already belongs to.
   - Sources: <https://www.thehacker.recipes/ad/movement/dacl/> · <https://specterops.io/blog/2019/02/28/a-case-study-in-wagging-the-dog-computer-takeover/>
 
+## Rejected before you report
+
+- **ACL abuse occurred: BloodHound shows a path from the compromised principal to Domain Admins**
+  - Killed by: no execution evidence existed for any hop; the edges record what the ACL permits, and in the real incident the route taken was left unresolved because the needed telemetry was never collected
+  - Rule: an ACL edge is a capability finding, not an exploitation finding; report incident language only for a hop with independent execution evidence, and otherwise severity-track it as a latent misconfiguration
+
 ---
 Full class document: `classes/ad_acl_abuse.md` · retrieve more with `python -m wks.cli search "<query>" --class-id ad_acl_abuse`
```

## 2026-10-02 10:50 — 23 diff lines
- items: 4 (supported 4), FP rules 4, chains 0, state researching
- still missing: items, chain

```diff
--- ad_acl_abuse@current
+++ ad_acl_abuse@new
@@ -10,8 +10,8 @@
      python -m wks.skillgen -->
 
 > surface `ad` · CWE CWE-269 · OWASP —
-> evidence: 3 items, 3 supported, 3 FP rules, 0 chains
-> maturity: **researching** — missing: items, supported_items, chain
+> evidence: 4 items, 4 supported, 4 FP rules, 0 chains
+> maturity: **researching** — missing: items, chain
 
 A principal holds a permission on an object that permits changing what that object grants, so read access becomes control of the domain.
 
@@ -26,6 +26,9 @@
 
 ## False-positive rules (when to reject it)
 
+- A BloodHound attack path or AdminTo-style edge is a capability finding and not an exploitation finding, because the graph records what is permitted rather than what was performed.
+  - **Disproof:** If the privileged route was never executed - no ticket request matching the edge, no DCSync replication event, no hash-authenticated logon on the downstream host - then the edge remains a latent misconfiguration and the exploitation claim built on it is unsupported.
+  - Sources: <https://academy.hackthebox.com/course/preview/active-directory-bloodhound> · <https://securelist.com/tr/payload-ransomware-via-group-policy/121335/>
 - Replication or delegation ACEs held by Domain Admins, Enterprise Admins, Administrators and Domain Controllers are the Active Directory default, not an ACL-abuse finding.
   - **Disproof:** Would be wrong in a tenant where a group's membership was added silently, because the default right-holder list then hides a real privilege grant.
   - Sources: <https://www.nccgroup.com/research/defending-your-directory-an-expert-guide-to-securing-active-directory-against-dcsync-attacks/> · <https://www.thehacker.recipes/ad/movement/credentials/dumping/dcsync>
```

## 2026-10-02 13:38 — 8 diff lines
- items: 4 (supported 4), FP rules 4, chains 0, state researching
- still missing: items, chain

```diff
--- ad_acl_abuse@current
+++ ad_acl_abuse@new
@@ -43,4 +43,4 @@
   - Rule: an ACL edge is a capability finding, not an exploitation finding; report incident language only for a hop with independent execution evidence, and otherwise severity-track it as a latent misconfiguration
 
 ---
-Full class document: `classes/ad_acl_abuse.md` · retrieve more with `python -m wks.cli search "<query>" --class-id ad_acl_abuse`
+Full class document: `skills/Network + AD/ad_acl_abuse/EVIDENCE.md` · retrieve more with `python -m wks.cli search "<query>" --class-id ad_acl_abuse`
```
