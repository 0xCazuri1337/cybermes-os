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
--- adcs_abuse@current
+++ adcs_abuse@new
@@ -11,7 +11,7 @@
 
 > surface `ad` · CWE CWE-295 · OWASP —
 > evidence: 3 items, 3 supported, 2 FP rules, 0 chains
-> maturity: **researching** — missing: methodology, items, supported_items, chain
+> maturity: **researching** — missing: items, supported_items, chain
 
 A certificate template that will issue an authenticating certificate to a low-privilege principal converts domain public key into a credential.
 
```

## 2026-10-02 10:50 — 26 diff lines
- items: 4 (supported 4), FP rules 2, chains 0, state researching
- still missing: items, chain

```diff
--- adcs_abuse@current
+++ adcs_abuse@new
@@ -10,8 +10,8 @@
      python -m wks.skillgen -->
 
 > surface `ad` · CWE CWE-295 · OWASP —
-> evidence: 3 items, 3 supported, 2 FP rules, 0 chains
-> maturity: **researching** — missing: items, supported_items, chain
+> evidence: 4 items, 4 supported, 2 FP rules, 0 chains
+> maturity: **researching** — missing: items, chain
 
 A certificate template that will issue an authenticating certificate to a low-privilege principal converts domain public key into a credential.
 
@@ -24,6 +24,12 @@
   - **Disproof:** If no enrolled template combines an authentication EKU with requester-controlled subject names and enrollment open to a low-privilege principal, then no certificate can be obtained that authenticates as another identity.
   - Sources: <https://attack.mitre.org/techniques/T1649/> · <https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-wcce/>
 
+## Validation bar (how to prove it)
+
+- A custom AD CS certificate template is only an abuse finding when its enrollee rights and flags diverge from the shipped standard templates, since custom templates are an intended feature.
+  - **Disproof:** If the template's enrollee rights and flags are identical to, or a strict subset of, the shipped standard templates and the issuing right maps to a documented business owner, then the template is legitimate customisation and the ADCS abuse claim does not hold.
+  - Sources: <https://academy.hackthebox.com/course/preview/adcs-attacks> · <https://securelist.com/tr/payload-ransomware-via-group-policy/121335/>
+
 ## False-positive rules (when to reject it)
 
 - A certificate template with Client Authentication enabled is not ESC1 unless enrollee-supplied subject, no manager approval and zero authorised signatures also hold.
```

## 2026-10-02 13:38 — 8 diff lines
- items: 4 (supported 4), FP rules 2, chains 0, state researching
- still missing: items, chain

```diff
--- adcs_abuse@current
+++ adcs_abuse@new
@@ -40,4 +40,4 @@
   - Sources: <https://www.nccgroup.com/research/defending-your-directory-an-expert-guide-to-fortifying-active-directory-certificate-services-adcs-against-exploitation/> · <https://www.rapid7.com/blog/post/2021/08/03/petitpotam-novel-attack-chain-can-fully-compromise-windows-domains-running-ad-cs/>
 
 ---
-Full class document: `classes/adcs_abuse.md` · retrieve more with `python -m wks.cli search "<query>" --class-id adcs_abuse`
+Full class document: `skills/Network + AD/adcs_abuse/EVIDENCE.md` · retrieve more with `python -m wks.cli search "<query>" --class-id adcs_abuse`
```
