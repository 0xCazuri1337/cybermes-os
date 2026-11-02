# History

Append-only. Each entry records WHY the skill changed, not just that it did. Improvement means better hunting behaviour, not more text.

## 2026-10-02 10:30 — 1 diff lines
- items: 5 (supported 5), FP rules 2, chains 0, state researching
- still missing: items, chain

```diff
(initial generation, 2026-10-02)
```

## 2026-10-02 13:38 — 36 diff lines
- items: 8 (supported 8), FP rules 2, chains 0, state researching
- still missing: items, chain

```diff
--- deser@current
+++ deser@new
@@ -10,7 +10,7 @@
      python -m wks.skillgen -->
 
 > surface `web` · CWE CWE-502 · OWASP A08:2021
-> evidence: 5 items, 5 supported, 2 FP rules, 0 chains
+> evidence: 8 items, 8 supported, 2 FP rules, 0 chains
 > maturity: **researching** — missing: items, chain
 
 Data is reconstructed into a live object graph whose type system then invokes attacker-reachable behaviour.
@@ -30,6 +30,18 @@
   - **Disproof:** If decoded blobs never contain a class descriptor, or every named-type payload is rejected by subtype validation before instantiation, the traffic is ordinary serialization without an exploitable sink.
   - Sources: <https://bishopfox.com/blog/gwt-unpatched-unauthenticated-java-deserialization-vulnerability> · <https://www.nccgroup.com/research/freddy-an-extension-for-automatically-identifying-deserialisation-issues-in-java-and-net-applications/>
 
+## Techniques (what to change)
+
+- Making an assumption that the code in the deserialized object is valid is dangerous and can enable exploitation.
+  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Making an assumption that the code in the deserialized object is valid is dangerous and ca".
+  - Sources: <https://cwe.mitre.org/data/definitions/502.html> · <https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html>
+- Avoid having unnecessary types or gadgets (a sequence of instances and method invocations that can self-execute during the deserialization process, often found in libraries) available that can be leveraged for malicious ends.
+  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Avoid having unnecessary types or gadgets (a sequence of instances and method invocations ".
+  - Sources: <https://cwe.mitre.org/data/definitions/502.html> · <https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html>
+- Serialization and deserialization refer to the process of taking program-internal object-related data, packaging it in a way that allows the data to be externally stored or transferred ("serialization"), then extracting the serialized data to reconstruct the original object ("deserialization").
+  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Serialization and deserialization refer to the process of taking program-internal object-r".
+  - Sources: <https://cwe.mitre.org/data/definitions/502.html> · <https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html>
+
 ## Validation bar (how to prove it)
 
 - A deserialization endpoint is confirmed only by a differential that shows an attacker-shaped object graph is deserialized and executed before authentication, which is why an unauthenticated remote attacker reaching arbitrary code execution on the vulnerable listener is the observation that closes the chain.
@@ -46,4 +58,4 @@
   - Sources: <https://httpwg.org/specs/rfc9530.html> · <https://projectdiscovery.io/blog/nuclei-templates-november-2025> · <https://projectdiscovery.io/blog/ruby-saml-gitlab-auth-bypass>
 
 ---
-Full class document: `classes/deser.md` · retrieve more with `python -m wks.cli search "<query>" --class-id deser`
+Full class document: `skills/Web/deser/EVIDENCE.md` · retrieve more with `python -m wks.cli search "<query>" --class-id deser`
```
