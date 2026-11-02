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
--- tunneling_pivoting@current
+++ tunneling_pivoting@new
@@ -11,7 +11,7 @@
 
 > surface `net` · CWE CWE-200 · OWASP —
 > evidence: 4 items, 4 supported, 2 FP rules, 0 chains
-> maturity: **researching** — missing: methodology, items, chain
+> maturity: **researching** — missing: items, chain
 
 A tunnel carries one protocol inside another, so reachability that policy forbids directly can be reintroduced by a host that both sides accept.
 
```

## 2026-10-02 10:50 — 23 diff lines
- items: 5 (supported 5), FP rules 2, chains 0, state researching
- still missing: items, chain

```diff
--- tunneling_pivoting@current
+++ tunneling_pivoting@new
@@ -10,13 +10,19 @@
      python -m wks.skillgen -->
 
 > surface `net` · CWE CWE-200 · OWASP —
-> evidence: 4 items, 4 supported, 2 FP rules, 0 chains
+> evidence: 5 items, 5 supported, 2 FP rules, 0 chains
 > maturity: **researching** — missing: items, chain
 
 A tunnel carries one protocol inside another, so reachability that policy forbids directly can be reintroduced by a host that both sides accept.
 
 **Also called:** tunneling, tunnelling, pivoting, socks, socks proxy, port forwarding, proxy, chisel, reverse tunnel
 
+
+## Recon signals (where to look)
+
+- Continued operator access carried over a legitimate service with no new listening port open is an early observable for tunnelling that no new-port rule will ever fire on.
+  - **Disproof:** If the remote-access exposure is attributable to an approved corporate tunnel service whose domain is on the sanctioned allowlist and whose client was deployed by the platform team, then the session is sanctioned remote access and the tunnelling hypothesis is invalidated.
+  - Sources: <https://academy.hackthebox.com/course/preview/active-directory-powerview> · <https://securelist.com/tr/nighteagle-apt-ghostcontainer-and-tunneling/121323/>
 
 ## Techniques (what to change)
 
```

## 2026-10-02 13:38 — 8 diff lines
- items: 5 (supported 5), FP rules 2, chains 0, state researching
- still missing: items, chain

```diff
--- tunneling_pivoting@current
+++ tunneling_pivoting@new
@@ -46,4 +46,4 @@
   - Sources: <https://www.microsoft.com/en-us/security/blog/2026/08/28/terminalfix-campaign-deploys-reverse-tunnel-through-multistage-intrusion/> · <https://hackertarget.com/ssh-examples-tunnels/>
 
 ---
-Full class document: `classes/tunneling_pivoting.md` · retrieve more with `python -m wks.cli search "<query>" --class-id tunneling_pivoting`
+Full class document: `skills/Network + AD/tunneling_pivoting/EVIDENCE.md` · retrieve more with `python -m wks.cli search "<query>" --class-id tunneling_pivoting`
```
