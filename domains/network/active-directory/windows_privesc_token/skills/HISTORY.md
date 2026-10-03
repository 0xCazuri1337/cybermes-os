# History

Append-only. Each entry records WHY the skill changed, not just that it did. Improvement means better hunting behaviour, not more text.

## 2026-10-03 02:41 — 1 diff lines
- items: 8 (supported 8), FP rules 0, chains 0, state researching
- still missing: methodology, items, fp_rules, chain

```diff
(initial generation, 2026-10-03)
```

## 2026-10-03 05:00 — 29 diff lines
- items: 10 (supported 10), FP rules 2, chains 1, state researching
- still missing: items

```diff
--- windows_privesc_token@current
+++ windows_privesc_token@new
@@ -10,8 +10,8 @@
      python -m wks.skillgen -->
 
 > surface `ad` · CWE CWE-269 · OWASP A09:2021
-> evidence: 8 items, 8 supported, 0 FP rules, 0 chains
-> maturity: **researching** — missing: methodology, items, fp_rules, chain
+> evidence: 10 items, 10 supported, 2 FP rules, 1 chains
+> maturity: **researching** — missing: items
 
 A low-privilege token is exchanged for a token acting as a more privileged principal, so the escalation happens in the token the process holds rather than in code execution.
 
@@ -46,6 +46,15 @@
   - **Disproof:** No handle to a higher-privilege token can be obtained, or the privilege alone is not sufficient to open one.
   - Sources: <https://cwe.mitre.org/data/definitions/269.html> · <https://man7.org/linux/man-pages/man2/execve.2.html> · <https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/windows-hardening/windows-local-privilege-escalation/privilege-escalation-abusing-tokens.md>
 
+## False-positive rules (when to reject it)
+
+- Reject a windows_privesc_token finding until it is distinguished from the adjacent behaviour this class also covers. "After alternate credentials are supplied, whoami can still show the original local user and groups while outbound SMB, WinRM, LDAP, HTTP, Kerberos or NTLM access happens as the other account, so local identity output is not evidence of who..." and "A failed potato-family run against a service account is often a filtered-token problem rather than a patched host: without SeImpersonatePrivilege or SeAssignPrimaryTokenPrivilege present, the account's default privilege set must be..." share a surface and a symptom, so a response that matches the first is not evidence for it while the second remains possible.
+  - **Disproof:** This rule is wrong if a controlled test shows the two behaviours can never co-occur on the same surface, or if the corpus entry for "A failed potato-family run against a service account is often a filter" is out of date. In that case this class needs its false-positive guidance rewritten rather than deleted.
+  - Sources: <https://cwe.mitre.org/data/definitions/269.html> · <https://man7.org/linux/man-pages/man2/execve.2.html>
+- Reject a windows_privesc_token finding until it is distinguished from the adjacent behaviour this class also covers. "A failed potato-family run against a service account is often a filtered-token problem rather than a patched host: without SeImpersonatePrivilege or SeAssignPrimaryTokenPrivilege present, the account's default privilege set must be..." and "SeImpersonatePrivilege lets a process impersonate any token it can get a handle to, without ever creating one, so every reachable higher-privilege token handle is a potential escalation." share a surface and a symptom, so a response that matches the first is not evidence for it while the second remains possible.
+  - **Disproof:** This rule is wrong if a controlled test shows the two behaviours can never co-occur on the same surface, or if the corpus entry for "SeImpersonatePrivilege lets a process impersonate any token it can get" is out of date. In that case this class needs its false-positive guidance rewritten rather than deleted.
+  - Sources: <https://cwe.mitre.org/data/definitions/269.html> · <https://man7.org/linux/man-pages/man2/execve.2.html>
+
 ## Impact framing
 
 - LSASS is the local component that both caches hashed credentials in memory and issues access tokens, so SYSTEM-level read access there yields credential material and token leverage.
```
