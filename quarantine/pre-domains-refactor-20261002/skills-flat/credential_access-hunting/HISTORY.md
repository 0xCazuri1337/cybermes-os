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
--- credential_access@current
+++ credential_access@new
@@ -11,7 +11,7 @@
 
 > surface `ad` · CWE CWE-522 · OWASP —
 > evidence: 4 items, 4 supported, 2 FP rules, 0 chains
-> maturity: **researching** — missing: methodology, items, chain
+> maturity: **researching** — missing: items, chain
 
 Credential material exists in reachable files and process memory, and recovering it converts one authenticated session into many.
 
```

## 2026-10-02 10:50 — 23 diff lines
- items: 5 (supported 5), FP rules 2, chains 0, state researching
- still missing: items, chain

```diff
--- credential_access@current
+++ credential_access@new
@@ -10,13 +10,19 @@
      python -m wks.skillgen -->
 
 > surface `ad` · CWE CWE-522 · OWASP —
-> evidence: 4 items, 4 supported, 2 FP rules, 0 chains
+> evidence: 5 items, 5 supported, 2 FP rules, 0 chains
 > maturity: **researching** — missing: items, chain
 
 Credential material exists in reachable files and process memory, and recovering it converts one authenticated session into many.
 
 **Also called:** credential access, lsass, ntds.dit, sam, sam hive, credential dumping, mimikatz, dpapi, vault
 
+
+## Recon signals (where to look)
+
+- An inbound NetNTLMv2 hash arriving shortly after files were written to a network share is an early observable for coerced authentication, not proof that the hash was relayed.
+  - **Disproof:** If no authentication event follows the capture that uses the captured hash as NTLM credentials against any target service, and the captured user is shown browsing the share normally, then no credential access occurred and the capture remains an unenacted collection artefact.
+  - Sources: <https://academy.hackthebox.com/course/preview/active-directory-enumeration--attacks> · <https://securelist.com/tr/network-anomaly-detection-in-kata/120892/>
 
 ## Techniques (what to change)
 
```

## 2026-10-02 13:38 — 8 diff lines
- items: 5 (supported 5), FP rules 2, chains 0, state researching
- still missing: items, chain

```diff
--- credential_access@current
+++ credential_access@new
@@ -46,4 +46,4 @@
   - Sources: <https://www.microsoft.com/en-us/security/blog/2022/10/05/detecting-and-preventing-lsass-credential-dumping-attacks/> · <https://www.tenable.com/blog/five-cyber-agencies-sound-alarm-about-active-directory-attacks-beyond-the-basics>
 
 ---
-Full class document: `classes/credential_access.md` · retrieve more with `python -m wks.cli search "<query>" --class-id credential_access`
+Full class document: `skills/Network + AD/credential_access/EVIDENCE.md` · retrieve more with `python -m wks.cli search "<query>" --class-id credential_access`
```
