# History

Append-only. Each entry records WHY the skill changed, not just that it did. Improvement means better hunting behaviour, not more text.

## 2026-10-02 15:57 — 1 diff lines
- items: 12 (supported 12), FP rules 2, chains 1, state mature

```diff
(initial generation, 2026-10-02)
```

## 2026-10-02 16:07 — 8 diff lines
- items: 12 (supported 12), FP rules 2, chains 1, state mature

```diff
--- internal_recon@current
+++ internal_recon@new
@@ -79,4 +79,4 @@
 - `ad_enumeration` (1 shared chain(s))
 
 ---
-Full class document: `domains/network/internal-network/internal_recon/EVIDENCE.md` · retrieve more with `python -m wks.cli search "<query>" --class-id internal_recon`
+Full class document: `domains/network/internal-network/internal_recon/knowledge/DIGEST.md` · retrieve more with `python -m wks.cli search "<query>" --class-id internal_recon`
```

## 2026-10-02 19:37 — 57 diff lines
- items: 6 (supported 4), FP rules 1, chains 1, state researching
- still missing: items, fp_rules

```diff
--- internal_recon@current
+++ internal_recon@new
@@ -10,8 +10,8 @@
      python -m wks.skillgen -->
 
 > surface `net` · CWE CWE-200 · OWASP —
-> evidence: 12 items, 12 supported, 2 FP rules, 1 chains
-> maturity: **mature**
+> evidence: 6 items, 4 supported, 1 FP rules, 1 chains
+> maturity: **researching** — missing: items, fp_rules
 
 An internal network is not uniform: naming and addressing patterns predict what a host runs, so enumeration is inference as much as probing.
 
@@ -20,38 +20,20 @@
 
 ## Techniques (what to change)
 
-- If you need to know which tenant an event came from, this is how. */\n| WHERE user.name == \"svc-deploy\" AND event.category == \"authentication\"\n| KEEP _index, @timestamp, event.action, source.ip, host.name\n /* KEEP is not cosmetic.
+- If you need to know which tenant an event came from, this is how. */\n| WHERE user.name == \"svc-deploy\" AND event.category == \"authentication\"\n| KEEP _index, @timestamp, event.action, source.ip, host.name\n /* KEEP is not cosmetic. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "If you need to know which tenant an event came from, this is how. */\n| WHERE user.name ==".
   - Sources: <https://academy.hackthebox.com/course/preview/active-directory-powerview> · <https://www.elastic.co/security-labs/blog/hunting-for-lateral-movement-using-event-query-language>
-- Apache does not class allowlist bypasses like this one as product vulnerabilities, because Log4j does not deserialize data during normal logging.
-  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Apache does not class allowlist bypasses like this one as product vulnerabilities, because".
-  - Sources: <https://academy.hackthebox.com/course/preview/active-directory-powerview> · <https://www.elastic.co/security-labs/blog/hunting-for-lateral-movement-using-event-query-language>
-- We are not claiming complete detection of every custom deserializer.\n\n## How this Java deserialization vulnerability differs from Log4Shell\nLog4j 2 can *emit* log events over the network (for example, `SocketAppender`).
+- We are not claiming complete detection of every custom deserializer.\n\n## How this Java deserialization vulnerability differs from Log4Shell\nLog4j 2 can *emit* log events over the network (for example, `SocketAppender`). _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "We are not claiming complete detection of every custom deserializer.\n\n## How this Java d".
-  - Sources: <https://academy.hackthebox.com/course/preview/active-directory-powerview> · <https://www.elastic.co/security-labs/blog/hunting-for-lateral-movement-using-event-query-language>
-- Chained together, they let an attacker-controlled object graph deserialize with no filter applied.
-  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Chained together, they let an attacker-controlled object graph deserialize with no filter ".
-  - Sources: <https://academy.hackthebox.com/course/preview/active-directory-powerview> · <https://www.elastic.co/security-labs/blog/hunting-for-lateral-movement-using-event-query-language>
-- The receiver can still look healthy and fall back to `SimpleMessage(messageString)`.\n\n`MarshalledObject.get()` deserializes `objBytes` on an inner `ObjectInputStream` that is not a `FilteredObjectInputStream`.
-  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "The receiver can still look healthy and fall back to `SimpleMessage(messageString)`.\n\n`M".
-  - Sources: <https://academy.hackthebox.com/course/preview/active-directory-powerview> · <https://www.elastic.co/security-labs/blog/hunting-for-lateral-movement-using-event-query-language>
-- The exception is 2.8.2: there, `TcpSocketServer` and the (log4j-core) `FilteredObjectInputStream` both ship in core, so a stock deployment using the built-in socket server is exposed without any leftover or custom receiver. #4255 bypasses the CVE-2017-5645 fix inside the same release that introduced it.
-  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "The exception is 2.8.2: there, `TcpSocketServer` and the (log4j-core) `FilteredObjectInput".
-  - Sources: <https://academy.hackthebox.com/course/preview/active-directory-powerview> · <https://www.elastic.co/security-labs/blog/hunting-for-lateral-movement-using-event-query-language>
-- Both coincide at 2.8.2 (FOIS in log4j-core) and at 2.11.0 through 2.26.1 (FOIS in log4j-api); we confirmed command execution on 2.8.2 and on 2.11.0–2.26.1. Versions 2.9.1 and 2.10.0 carry the field, but no FOIS, so the specific allowlist bypass does not apply there.
-  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Both coincide at 2.8.2 (FOIS in log4j-core) and at 2.11.0 through 2.26.1 (FOIS in log4j-ap".
-  - Sources: <https://academy.hackthebox.com/course/preview/active-directory-powerview> · <https://www.elastic.co/security-labs/blog/hunting-for-lateral-movement-using-event-query-language>
-- If it does not, the inner `get()` can still run unfiltered code in whatever *is* on that JVM.\n\n## Setting up detection for Java deserialization attacks\n1.
-  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "If it does not, the inner `get()` can still run unfiltered code in whatever *is* on that J".
   - Sources: <https://academy.hackthebox.com/course/preview/active-directory-powerview> · <https://www.elastic.co/security-labs/blog/hunting-for-lateral-movement-using-event-query-language>
 - Private address space is only unique within an enterprise, so addresses observed on an internal network carry local rather than global meaning and inference about host role is drawn from naming and addressing conventions rather than from any global registry.
   - **Disproof:** If the internal network assigns addresses with no role convention and no name service correlates them, then there is no predictive mapping to exploit and host role must be determined by direct service identification instead.
   - Sources: <https://attack.mitre.org/techniques/T1018/> · <https://www.rfc-editor.org/rfc/rfc1918.html>
 
-## False-positive rules (when to reject it)
+## Tests
 
-- A single instance of a native enumeration command (net user, whoami /all, dsacls, nltest /domain_trusts) from a workstation is a dual-use tool and not a finding on its own; the signal is a CLUSTER of these commands inside a short window from one process tree, because each individual command is a documented day-one administration action.
-  - **Disproof:** The same commands appear multiple times in a tight window from one parent process, or the requesting host is a server or a jump box with no legitimate administrative role, or the commands target a domain admin group rather than the operator's own account - a pattern no administration workflow produces.
+- To decide this case, observe: erate domain controllers and trust status; the adversary reuses the binary rather than shipping a tool. The signal that distinguishes reconnaissance from administration is not the command but the temporal cluster: several of these commands inside a short window from a single process tree, a shape no administration workflow produces because an administrator queries one thing at
+  - **Disproof:** This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (internal_recon.fp_rule.admin_enumeration_command_is_dual_use) states the full boundary.
   - Sources: <https://redcanary.com/threat-detection-report/techniques/domain-trust-discovery/> · <https://www.ired.team/offensive-security/enumeration-and-discovery/t1087-account-discovery.md>
 
 ## Defence bypasses
```

## 2026-10-03 01:46 — 35 diff lines
- items: 5 (supported 2), FP rules 1, chains 1, state researching
- still missing: items, supported_items, fp_rules

```diff
--- internal_recon@current
+++ internal_recon@new
@@ -10,8 +10,8 @@
      python -m wks.skillgen -->
 
 > surface `net` · CWE CWE-200 · OWASP —
-> evidence: 6 items, 4 supported, 1 FP rules, 1 chains
-> maturity: **researching** — missing: items, fp_rules
+> evidence: 5 items, 2 supported, 1 FP rules, 1 chains
+> maturity: **researching** — missing: items, supported_items, fp_rules
 
 An internal network is not uniform: naming and addressing patterns predict what a host runs, so enumeration is inference as much as probing.
 
@@ -22,19 +22,11 @@
 
 - If you need to know which tenant an event came from, this is how. */\n| WHERE user.name == \"svc-deploy\" AND event.category == \"authentication\"\n| KEEP _index, @timestamp, event.action, source.ip, host.name\n /* KEEP is not cosmetic. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "If you need to know which tenant an event came from, this is how. */\n| WHERE user.name ==".
-  - Sources: <https://academy.hackthebox.com/course/preview/active-directory-powerview> · <https://www.elastic.co/security-labs/blog/hunting-for-lateral-movement-using-event-query-language>
 - We are not claiming complete detection of every custom deserializer.\n\n## How this Java deserialization vulnerability differs from Log4Shell\nLog4j 2 can *emit* log events over the network (for example, `SocketAppender`). _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "We are not claiming complete detection of every custom deserializer.\n\n## How this Java d".
-  - Sources: <https://academy.hackthebox.com/course/preview/active-directory-powerview> · <https://www.elastic.co/security-labs/blog/hunting-for-lateral-movement-using-event-query-language>
-- Private address space is only unique within an enterprise, so addresses observed on an internal network carry local rather than global meaning and inference about host role is drawn from naming and addressing conventions rather than from any global registry.
+- Private address space is only unique within an enterprise, so addresses observed on an internal network carry local rather than global meaning and inference about host role is drawn from naming and addressing conventions rather than from any global registry. _(unverified)_
   - **Disproof:** If the internal network assigns addresses with no role convention and no name service correlates them, then there is no predictive mapping to exploit and host role must be determined by direct service identification instead.
-  - Sources: <https://attack.mitre.org/techniques/T1018/> · <https://www.rfc-editor.org/rfc/rfc1918.html>
-
-## Tests
-
-- To decide this case, observe: erate domain controllers and trust status; the adversary reuses the binary rather than shipping a tool. The signal that distinguishes reconnaissance from administration is not the command but the temporal cluster: several of these commands inside a short window from a single process tree, a shape no administration workflow produces because an administrator queries one thing at
-  - **Disproof:** This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (internal_recon.fp_rule.admin_enumeration_command_is_dual_use) states the full boundary.
-  - Sources: <https://redcanary.com/threat-detection-report/techniques/domain-trust-discovery/> · <https://www.ired.team/offensive-security/enumeration-and-discovery/t1087-account-discovery.md>
+  - Sources: <https://www.rfc-editor.org/rfc/rfc1918.html>
 
 ## Defence bypasses
 
```

## 2026-10-03 05:00 — 26 diff lines
- items: 6 (supported 3), FP rules 2, chains 1, state researching
- still missing: items, supported_items

```diff
--- internal_recon@current
+++ internal_recon@new
@@ -10,8 +10,8 @@
      python -m wks.skillgen -->
 
 > surface `net` · CWE CWE-200 · OWASP —
-> evidence: 5 items, 2 supported, 1 FP rules, 1 chains
-> maturity: **researching** — missing: items, supported_items, fp_rules
+> evidence: 6 items, 3 supported, 2 FP rules, 1 chains
+> maturity: **researching** — missing: items, supported_items
 
 An internal network is not uniform: naming and addressing patterns predict what a host runs, so enumeration is inference as much as probing.
 
@@ -27,6 +27,12 @@
 - Private address space is only unique within an enterprise, so addresses observed on an internal network carry local rather than global meaning and inference about host role is drawn from naming and addressing conventions rather than from any global registry. _(unverified)_
   - **Disproof:** If the internal network assigns addresses with no role convention and no name service correlates them, then there is no predictive mapping to exploit and host role must be determined by direct service identification instead.
   - Sources: <https://www.rfc-editor.org/rfc/rfc1918.html>
+
+## False-positive rules (when to reject it)
+
+- Reject a internal_recon finding until it is distinguished from the adjacent behaviour this class also covers. "A directory enumeration filtered to SPN-bearing accounts hands the next link exactly the input kerberoasting consumes, and the recovered service-account password is an authenticated remote-execution channel on hosts the enumeration never..." and "Routing rpcclient enumeration through a Cobalt Strike socks proxy causes the enumeration arguments to never appear in the host's process-creation command line, so command-line based detection of internal domain recon returns nothing." share a surface and a symptom, so a response that matches the first is not evidence for it while the second remains possible.
+  - **Disproof:** This rule is wrong if a controlled test shows the two behaviours can never co-occur on the same surface, or if the corpus entry for "Routing rpcclient enumeration through a Cobalt Strike socks proxy caus" is out of date. In that case this class needs its false-positive guidance rewritten rather than deleted.
+  - Sources: <https://academy.hackthebox.com/course/preview/active-directory-powerview> · <https://securelist.com/tr/network-anomaly-detection-in-kata/120892/>
 
 ## Defence bypasses
 
```
