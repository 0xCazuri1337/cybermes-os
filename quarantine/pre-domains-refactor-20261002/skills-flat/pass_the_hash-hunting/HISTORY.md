# History

Append-only. Each entry records WHY the skill changed, not just that it did. Improvement means better hunting behaviour, not more text.

## 2026-10-02 10:30 — 1 diff lines
- items: 6 (supported 4), FP rules 3, chains 0, state researching
- still missing: methodology, items, chain

```diff
(initial generation, 2026-10-02)
```

## 2026-10-02 10:32 — 11 diff lines
- items: 6 (supported 4), FP rules 3, chains 0, state researching
- still missing: items, chain

```diff
--- pass_the_hash@current
+++ pass_the_hash@new
@@ -11,7 +11,7 @@
 
 > surface `ad` · CWE CWE-294 · OWASP —
 > evidence: 6 items, 4 supported, 3 FP rules, 0 chains
-> maturity: **researching** — missing: methodology, items, chain
+> maturity: **researching** — missing: items, chain
 
 A protocol that authenticates the NTLM hash or a service ticket rather than a secret the user holds lets that artefact be replayed verbatim as a credential.
 
```

## 2026-10-02 10:50 — 24 diff lines
- items: 7 (supported 5), FP rules 3, chains 0, state researching
- still missing: items, chain

```diff
--- pass_the_hash@current
+++ pass_the_hash@new
@@ -10,7 +10,7 @@
      python -m wks.skillgen -->
 
 > surface `ad` · CWE CWE-294 · OWASP —
-> evidence: 6 items, 4 supported, 3 FP rules, 0 chains
+> evidence: 7 items, 5 supported, 3 FP rules, 0 chains
 > maturity: **researching** — missing: items, chain
 
 A protocol that authenticates the NTLM hash or a service ticket rather than a secret the user holds lets that artefact be replayed verbatim as a credential.
@@ -23,6 +23,12 @@
 - NTLM and Kerberos protocols accept a key as the credential rather than a secret the user holds, so a captured NTLM hash or service ticket is itself a replayable authentication artifact and needs no password recovery. _(unverified)_
   - **Disproof:** If the hash or ticket is rejected by the target because channel binding, signing, or an authentication level requirement is enforced, then replay does not authenticate and the finding collapses to a failed logon.
   - Sources: <https://attack.mitre.org/techniques/T1550/003/> · <https://cwe.mitre.org/data/definitions/294.html>
+
+## Validation bar (how to prove it)
+
+- A pass-the-hash finding requires a successful authentication made with the obtained hash, and recovering the hash alone - by replication or by capture - is not pass-the-hash.
+  - **Disproof:** If every attempt to authenticate with the recovered NT hash against any target service fails and the target logs no NTLM authentication for that account from the operator's host, then no hash was used and the pass-the-hash claim is false even though credential recovery is real.
+  - Sources: <https://academy.hackthebox.com/course/preview/active-directory-powerview> · <https://securelist.com/tr/nighteagle-apt-ghostcontainer-and-tunneling/121323/>
 
 ## False-positive rules (when to reject it)
 
```

## 2026-10-02 13:38 — 8 diff lines
- items: 7 (supported 5), FP rules 3, chains 0, state researching
- still missing: items, chain

```diff
--- pass_the_hash@current
+++ pass_the_hash@new
@@ -52,4 +52,4 @@
   - Sources: <https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/pass-the-hash-with-machine-accounts.md> · <https://www.zscaler.com/blogs/product-insights/active-directory-kerberoasting-deception-detection>
 
 ---
-Full class document: `classes/pass_the_hash.md` · retrieve more with `python -m wks.cli search "<query>" --class-id pass_the_hash`
+Full class document: `skills/Network + AD/pass_the_hash/EVIDENCE.md` · retrieve more with `python -m wks.cli search "<query>" --class-id pass_the_hash`
```
