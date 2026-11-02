# History

Append-only. Each entry records WHY the skill changed, not just that it did. Improvement means better hunting behaviour, not more text.

## 2026-10-03 02:41 — 1 diff lines
- items: 6 (supported 6), FP rules 0, chains 0, state researching
- still missing: methodology, items, fp_rules, chain

```diff
(initial generation, 2026-10-03)
```

## 2026-10-03 05:00 — 29 diff lines
- items: 8 (supported 8), FP rules 2, chains 1, state researching
- still missing: items

```diff
--- windows_privesc_service@current
+++ windows_privesc_service@new
@@ -10,8 +10,8 @@
      python -m wks.skillgen -->
 
 > surface `ad` · CWE CWE-269 · OWASP A04:2021
-> evidence: 6 items, 6 supported, 0 FP rules, 0 chains
-> maturity: **researching** — missing: methodology, items, fp_rules, chain
+> evidence: 8 items, 8 supported, 2 FP rules, 1 chains
+> maturity: **researching** — missing: items
 
 A privileged service is induced to load or impersonate an attacker-chosen identity, so the escalation runs with SYSTEM through a legitimate service entry point.
 
@@ -34,6 +34,15 @@
   - **Disproof:** The services cannot be started by a non-privileged caller, or starting them exposes no new listeners.
   - Sources: <https://cwe.mitre.org/data/definitions/269.html> · <https://man7.org/linux/man-pages/man2/execve.2.html> · <https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/windows-hardening/windows-local-privilege-escalation/service-triggers.md>
 
+## False-positive rules (when to reject it)
+
+- Reject a windows_privesc_service finding until it is distinguished from the adjacent behaviour this class also covers. "The complete named-pipe client impersonation chain requires both SeImpersonatePrivilege and a privileged client such as a SYSTEM service that will connect to an attacker-created pipe, after which the resulting token is duplicated into a..." and "The Terminal Services RPC named pipe \pipe\LSM_API_service is itself a privesc surface: it allows enumerating logged-on sessions and starting a process with a selected user's token." share a surface and a symptom, so a response that matches the first is not evidence for it while the second remains possible.
+  - **Disproof:** This rule is wrong if a controlled test shows the two behaviours can never co-occur on the same surface, or if the corpus entry for "The Terminal Services RPC named pipe \pipe\LSM_API_service is itself a" is out of date. In that case this class needs its false-positive guidance rewritten rather than deleted.
+  - Sources: <https://cwe.mitre.org/data/definitions/269.html> · <https://man7.org/linux/man-pages/man2/execve.2.html>
+- Reject a windows_privesc_service finding until it is distinguished from the adjacent behaviour this class also covers. "Because FILE_CREATE_PIPE_INSTANCE shares its access bit with FILE_APPEND_DATA, a low-privilege user can squat a second server instance under a privileged pipe's name and, since instances are matched FIFO, receive real clients and relay or..." and "The Terminal Services RPC named pipe \pipe\LSM_API_service is itself a privesc surface: it allows enumerating logged-on sessions and starting a process with a selected user's token." share a surface and a symptom, so a response that matches the first is not evidence for it while the second remains possible.
+  - **Disproof:** This rule is wrong if a controlled test shows the two behaviours can never co-occur on the same surface, or if the corpus entry for "The Terminal Services RPC named pipe \pipe\LSM_API_service is itself a" is out of date. In that case this class needs its false-positive guidance rewritten rather than deleted.
+  - Sources: <https://cwe.mitre.org/data/definitions/269.html> · <https://man7.org/linux/man-pages/man2/execve.2.html>
+
 ## Variants
 
 - The Terminal Services RPC named pipe \pipe\LSM_API_service is itself a privesc surface: it allows enumerating logged-on sessions and starting a process with a selected user's token.
```

## 2026-10-04 00:38 — 21 diff lines
- items: 9 (supported 9), FP rules 2, chains 1, state researching
- still missing: items

```diff
--- windows_privesc_service@current
+++ windows_privesc_service@new
@@ -10,7 +10,7 @@
      python -m wks.skillgen -->
 
 > surface `ad` · CWE CWE-269 · OWASP A04:2021
-> evidence: 8 items, 8 supported, 2 FP rules, 1 chains
+> evidence: 9 items, 9 supported, 2 FP rules, 1 chains
 > maturity: **researching** — missing: items
 
 A privileged service is induced to load or impersonate an attacker-chosen identity, so the escalation runs with SYSTEM through a legitimate service entry point.
@@ -18,6 +18,9 @@
 
 ## Techniques (what to change)
 
+- Helpline documents CVE-2017-9362 as a route from an authenticated user to elevated privileges, and the authoritative record confirms the same weakness in the affected product.
+  - **Disproof:** Refuted when the running product is outside the affected version range, or when the specific weakness (CVE-2017-9362) is patched on the target: the documented escalation then does not exist, whatever the advisory still says.
+  - Sources: <https://cwe.mitre.org/data/definitions/611.html> · <https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2017-9362>
 - Service trigger conditions such as a named-pipe connection attempt let an attacker force a privileged service to start, so trigger conditions are themselves a service-start primitive.
   - **Disproof:** The target service has no trigger registered, or the condition cannot be satisfied from the attacker's context.
   - Sources: <https://cwe.mitre.org/data/definitions/269.html> · <https://man7.org/linux/man-pages/man2/execve.2.html> · <https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/windows-hardening/windows-local-privilege-escalation/service-triggers.md>
```

## 2026-10-04 00:43 — 72 diff lines
- items: 9 (supported 9), FP rules 2, chains 1, state researching
- still missing: items

```diff
--- windows_privesc_service@current
+++ windows_privesc_service@new
@@ -18,39 +18,54 @@
 
 ## Techniques (what to change)
 
-- Helpline documents CVE-2017-9362 as a route from an authenticated user to elevated privileges, and the authoritative record confirms the same weakness in the affected product.
+- Any named-pipe server that a privileged client connects to can be turned into that client's privileges by calling ImpersonateNamedPipeClient, making pipe ACLs and client reachability the deciding factors.  _(merged 1 duplicate row(s))_
+  - **Disproof:** The pipe server never impersonates its client, or no privileged client can reach the pipe.
+  - Sources: <https://cwe.mitre.org/data/definitions/269.html> · <https://man7.org/linux/man-pages/man2/execve.2.html> · <https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/windows-hardening/windows-local-privilege-escalation/named-pipe-client-impersonation.md>
+- Because FILE_CREATE_PIPE_INSTANCE shares its access bit with FILE_APPEND_DATA, a low-privilege user can squat a second server instance under a privileged pipe's name and, since instances are matched FIFO, receive real clients and relay or desynchronize their privileged IPC.  _(merged 1 duplicate row(s))_
+  - **Disproof:** The privileged pipe is created without FILE_APPEND_DATA, or instance matching does not place the attacker's instance ahead of legitimate ones.
+  - Sources: <https://cwe.mitre.org/data/definitions/269.html> · <https://man7.org/linux/man-pages/man2/execve.2.html> · <https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/windows-hardening/windows-local-privilege-escalation/named-pipe-client-impersonation.md>
+- Helpline documents CVE-2017-9362 as a route from an authenticated user to elevated privileges, and the authoritative record confirms the same weakness in the affected product.  _(merged 1 duplicate row(s))_
   - **Disproof:** Refuted when the running product is outside the affected version range, or when the specific weakness (CVE-2017-9362) is patched on the target: the documented escalation then does not exist, whatever the advisory still says.
   - Sources: <https://cwe.mitre.org/data/definitions/611.html> · <https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2017-9362>
-- Service trigger conditions such as a named-pipe connection attempt let an attacker force a privileged service to start, so trigger conditions are themselves a service-start primitive.
+- Service trigger conditions such as a named-pipe connection attempt let an attacker force a privileged service to start, so trigger conditions are themselves a service-start primitive.  _(merged 1 duplicate row(s))_
   - **Disproof:** The target service has no trigger registered, or the condition cannot be satisfied from the attacker's context.
   - Sources: <https://cwe.mitre.org/data/definitions/269.html> · <https://man7.org/linux/man-pages/man2/execve.2.html> · <https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/windows-hardening/windows-local-privilege-escalation/service-triggers.md>
-- The complete named-pipe client impersonation chain requires both SeImpersonatePrivilege and a privileged client such as a SYSTEM service that will connect to an attacker-created pipe, after which the resulting token is duplicated into a primary token for the spawned process.
+- Starting dormant built-in services such as RemoteRegistry, WebClient/WebDAV or EFS creates new RPC and named-pipe listeners, so a mere service-start primitive chains into further attack surface.  _(merged 1 duplicate row(s))_
+  - **Disproof:** The services cannot be started by a non-privileged caller, or starting them exposes no new listeners.
+  - Sources: <https://cwe.mitre.org/data/definitions/269.html> · <https://man7.org/linux/man-pages/man2/execve.2.html> · <https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/windows-hardening/windows-local-privilege-escalation/service-triggers.md>
+- The complete named-pipe client impersonation chain requires both SeImpersonatePrivilege and a privileged client such as a SYSTEM service that will connect to an attacker-created pipe, after which the resulting token is duplicated into a primary token for the spawned process.  _(merged 1 duplicate row(s))_
   - **Disproof:** SeImpersonatePrivilege is absent, or no privileged client can be coerced to connect to a rogue pipe instance.
   - Sources: <https://cwe.mitre.org/data/definitions/269.html> · <https://man7.org/linux/man-pages/man2/execve.2.html> · <https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/windows-hardening/windows-local-privilege-escalation/named-pipe-client-impersonation.md>
-- Any named-pipe server that a privileged client connects to can be turned into that client's privileges by calling ImpersonateNamedPipeClient, making pipe ACLs and client reachability the deciding factors.
-  - **Disproof:** The pipe server never impersonates its client, or no privileged client can reach the pipe.
-  - Sources: <https://cwe.mitre.org/data/definitions/269.html> · <https://man7.org/linux/man-pages/man2/execve.2.html> · <https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/windows-hardening/windows-local-privilege-escalation/named-pipe-client-impersonation.md>
-- Because FILE_CREATE_PIPE_INSTANCE shares its access bit with FILE_APPEND_DATA, a low-privilege user can squat a second server instance under a privileged pipe's name and, since instances are matched FIFO, receive real clients and relay or desynchronize their privileged IPC.
-  - **Disproof:** The privileged pipe is created without FILE_APPEND_DATA, or instance matching does not place the attacker's instance ahead of legitimate ones.
-  - Sources: <https://cwe.mitre.org/data/definitions/269.html> · <https://man7.org/linux/man-pages/man2/execve.2.html> · <https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/windows-hardening/windows-local-privilege-escalation/named-pipe-client-impersonation.md>
-- Starting dormant built-in services such as RemoteRegistry, WebClient/WebDAV or EFS creates new RPC and named-pipe listeners, so a mere service-start primitive chains into further attack surface.
-  - **Disproof:** The services cannot be started by a non-privileged caller, or starting them exposes no new listeners.
-  - Sources: <https://cwe.mitre.org/data/definitions/269.html> · <https://man7.org/linux/man-pages/man2/execve.2.html> · <https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/windows-hardening/windows-local-privilege-escalation/service-triggers.md>
 
 ## False-positive rules (when to reject it)
 
-- Reject a windows_privesc_service finding until it is distinguished from the adjacent behaviour this class also covers. "The complete named-pipe client impersonation chain requires both SeImpersonatePrivilege and a privileged client such as a SYSTEM service that will connect to an attacker-created pipe, after which the resulting token is duplicated into a..." and "The Terminal Services RPC named pipe \pipe\LSM_API_service is itself a privesc surface: it allows enumerating logged-on sessions and starting a process with a selected user's token." share a surface and a symptom, so a response that matches the first is not evidence for it while the second remains possible.
+- Reject a windows_privesc_service finding until it is distinguished from the adjacent behaviour this class also covers. "Because FILE_CREATE_PIPE_INSTANCE shares its access bit with FILE_APPEND_DATA, a low-privilege user can squat a second server instance under a privileged pipe's name and, since instances are matched FIFO, receive real clients and relay or..." and "The Terminal Services RPC named pipe \pipe\LSM_API_service is itself a privesc surface: it allows enumerating logged-on sessions and starting a process with a selected user's token." share a surface and a symptom, so a response that matches the first is not evidence for it while the second remains possible.  _(merged 1 duplicate row(s))_
   - **Disproof:** This rule is wrong if a controlled test shows the two behaviours can never co-occur on the same surface, or if the corpus entry for "The Terminal Services RPC named pipe \pipe\LSM_API_service is itself a" is out of date. In that case this class needs its false-positive guidance rewritten rather than deleted.
   - Sources: <https://cwe.mitre.org/data/definitions/269.html> · <https://man7.org/linux/man-pages/man2/execve.2.html>
-- Reject a windows_privesc_service finding until it is distinguished from the adjacent behaviour this class also covers. "Because FILE_CREATE_PIPE_INSTANCE shares its access bit with FILE_APPEND_DATA, a low-privilege user can squat a second server instance under a privileged pipe's name and, since instances are matched FIFO, receive real clients and relay or..." and "The Terminal Services RPC named pipe \pipe\LSM_API_service is itself a privesc surface: it allows enumerating logged-on sessions and starting a process with a selected user's token." share a surface and a symptom, so a response that matches the first is not evidence for it while the second remains possible.
+- Reject a windows_privesc_service finding until it is distinguished from the adjacent behaviour this class also covers. "The complete named-pipe client impersonation chain requires both SeImpersonatePrivilege and a privileged client such as a SYSTEM service that will connect to an attacker-created pipe, after which the resulting token is duplicated into a..." and "The Terminal Services RPC named pipe \pipe\LSM_API_service is itself a privesc surface: it allows enumerating logged-on sessions and starting a process with a selected user's token." share a surface and a symptom, so a response that matches the first is not evidence for it while the second remains possible.  _(merged 1 duplicate row(s))_
   - **Disproof:** This rule is wrong if a controlled test shows the two behaviours can never co-occur on the same surface, or if the corpus entry for "The Terminal Services RPC named pipe \pipe\LSM_API_service is itself a" is out of date. In that case this class needs its false-positive guidance rewritten rather than deleted.
   - Sources: <https://cwe.mitre.org/data/definitions/269.html> · <https://man7.org/linux/man-pages/man2/execve.2.html>
 
 ## Variants
 
-- The Terminal Services RPC named pipe \pipe\LSM_API_service is itself a privesc surface: it allows enumerating logged-on sessions and starting a process with a selected user's token.
+- The Terminal Services RPC named pipe \pipe\LSM_API_service is itself a privesc surface: it allows enumerating logged-on sessions and starting a process with a selected user's token.  _(merged 1 duplicate row(s))_
   - **Disproof:** The named pipe is absent or ACLs prevent a non-privileged caller from reaching the session enumeration and token APIs.
   - Sources: <https://cwe.mitre.org/data/definitions/269.html> · <https://man7.org/linux/man-pages/man2/execve.2.html> · <https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/windows-hardening/stealing-credentials/wts-impersonator.md>
 
+
+## Hunt procedure
+
+1. Enumerate the surface before probing: collect every endpoint, parameter and object id the class could plausibly sit on.
+2. Establish a CONTROLLED BASELINE first — one unauthenticated and one authenticated low-privilege request per candidate — and diff against the probe. A difference with no baseline proves nothing.
+3. Change exactly ONE variable per probe. Two changes produce a difference you cannot attribute.
+4. Record raw request and response pairs verbatim, including headers, before you interpret anything.
+
+### What counts as proof
+
+- Two responses that differ in a way the CONTROL did not, produced by a single changed variable.
+- An invariant the application is supposed to hold, observed broken.
+- A second independent confirmation, or an explicit statement that this is single-account evidence only.
+
+> Ordered prerequisites, the validation bar and the false-positive rules below are the authority: this block is the mechanics, those are the standard.
 ---
 Full class document: `domains/network/active-directory/windows_privesc_service/knowledge/DIGEST.md` · retrieve more with `python -m wks.cli search "<query>" --class-id windows_privesc_service`
```
