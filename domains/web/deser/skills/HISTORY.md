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
--- deser@current
+++ deser@new
@@ -70,4 +70,4 @@
   - Sources: <https://httpwg.org/specs/rfc9530.html> · <https://projectdiscovery.io/blog/nuclei-templates-november-2025> · <https://projectdiscovery.io/blog/ruby-saml-gitlab-auth-bypass>
 
 ---
-Full class document: `domains/web/deser/EVIDENCE.md` · retrieve more with `python -m wks.cli search "<query>" --class-id deser`
+Full class document: `domains/web/deser/knowledge/DIGEST.md` · retrieve more with `python -m wks.cli search "<query>" --class-id deser`
```

## 2026-10-02 19:37 — 55 diff lines
- items: 14 (supported 6), FP rules 2, chains 1, state mature

```diff
--- deser@current
+++ deser@new
@@ -10,7 +10,7 @@
      python -m wks.skillgen -->
 
 > surface `web` · CWE CWE-502 · OWASP A08:2021
-> evidence: 12 items, 12 supported, 2 FP rules, 1 chains
+> evidence: 14 items, 6 supported, 2 FP rules, 1 chains
 > maturity: **mature**
 
 Data is reconstructed into a live object graph whose type system then invokes attacker-reachable behaviour.
@@ -32,27 +32,36 @@
 
 ## Techniques (what to change)
 
-- Making an assumption that the code in the deserialized object is valid is dangerous and can enable exploitation.
+- Making an assumption that the code in the deserialized object is valid is dangerous and can enable exploitation. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Making an assumption that the code in the deserialized object is valid is dangerous and ca".
   - Sources: <https://cwe.mitre.org/data/definitions/502.html> · <https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html>
-- Avoid having unnecessary types or gadgets (a sequence of instances and method invocations that can self-execute during the deserialization process, often found in libraries) available that can be leveraged for malicious ends.
+- Avoid having unnecessary types or gadgets (a sequence of instances and method invocations that can self-execute during the deserialization process, often found in libraries) available that can be leveraged for malicious ends. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Avoid having unnecessary types or gadgets (a sequence of instances and method invocations ".
   - Sources: <https://cwe.mitre.org/data/definitions/502.html> · <https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html>
-- Serialization and deserialization refer to the process of taking program-internal object-related data, packaging it in a way that allows the data to be externally stored or transferred ("serialization"), then extracting the serialized data to reconstruct the original object ("deserialization").
+- Serialization and deserialization refer to the process of taking program-internal object-related data, packaging it in a way that allows the data to be externally stored or transferred ("serialization"), then extracting the serialized data to reconstruct the original object ("deserialization"). _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Serialization and deserialization refer to the process of taking program-internal object-r".
   - Sources: <https://cwe.mitre.org/data/definitions/502.html> · <https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html>
-- Serialization and deserialization refer to the process of taking program-internal object-related data, packaging it in a way that allows the data to be externally stored or transferred ("serialization"), then extracting the serialized data to reconstruct the original object ("deserialization").
+- Serialization and deserialization refer to the process of taking program-internal object-related data, packaging it in a way that allows the data to be externally stored or transferred ("serialization"), then extracting the serialized data to reconstruct the original object ("deserialization"). _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Serialization and deserialization refer to the process of taking program-internal object-r".
   - Sources: <https://cwe.mitre.org/data/definitions/502.html> · <https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html>
-- This code does not attempt to verify the source or contents of the file before deserializing it.
+- This code does not attempt to verify the source or contents of the file before deserializing it. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "This code does not attempt to verify the source or contents of the file before deserializi".
   - Sources: <https://cwe.mitre.org/data/definitions/502.html> · <https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html>
-- Since Pickle allows objects to define the process for how they should be unpickled, the attacker can direct the unpickle process to call Popen in the subprocess module and execute /bin/sh.
+- Since Pickle allows objects to define the process for how they should be unpickled, the attacker can direct the unpickle process to call Popen in the subprocess module and execute /bin/sh. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Since Pickle allows objects to define the process for how they should be unpickled, the at".
   - Sources: <https://cwe.mitre.org/data/definitions/502.html> · <https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html>
-- Deserialization issue in commonly-used Java library allows remote execution.
+- Deserialization issue in commonly-used Java library allows remote execution. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Deserialization issue in commonly-used Java library allows remote execution.".
   - Sources: <https://cwe.mitre.org/data/definitions/502.html> · <https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html>
+
+## Tests
+
+- To decide this case, observe: nce a deserializer never saw the attacker-controlled bytes and the gadget chain was never reached. The finding survives only when an edited blob with a changed type field, a changed field value, or an added object was accepted and produced an attacker-chosen effect, which means the check that should have bound the bytes to their origin is missing or bypassable. _(unverified)_
+  - **Disproof:** This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (deser.fprule.integrity_rejected_blob_never_reaches_the_deserializer) states the full boundary.
+  - Sources: <https://projectdiscovery.io/blog/nuclei-templates-november-2025> · <https://projectdiscovery.io/blog/ruby-saml-gitlab-auth-bypass>
+- To decide this case, observe: whole test. Elastic's Log4j 2 research is the model: reproducing the deserialization allowlist bypass was necessary but not sufficient, because reaching command execution took two further things the library does not ship - a process that still deserializes the object stream, and a gadget library already sitting on that JVM. So inventory the target: if the deserializing process
+  - **Disproof:** This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (deser.fp_rule.serialization_endpoint_without_a_gadget_chain_is_not_rce) states the full boundary.
+  - Sources: <https://www.elastic.co/security-labs/threat-command/java-deserialization-vulnerability-log4j-2> · <https://www.sonarsource.com/blog/phpbb3-phar-deserialization-to-remote-code-execution/>
 
 ## Validation bar (how to prove it)
 
```

## 2026-10-03 01:46 — 95 diff lines
- items: 27 (supported 19), FP rules 2, chains 1, state mature

```diff
--- deser@current
+++ deser@new
@@ -10,7 +10,7 @@
      python -m wks.skillgen -->
 
 > surface `web` · CWE CWE-502 · OWASP A08:2021
-> evidence: 14 items, 6 supported, 2 FP rules, 1 chains
+> evidence: 27 items, 19 supported, 2 FP rules, 1 chains
 > maturity: **mature**
 
 Data is reconstructed into a live object graph whose type system then invokes attacker-reachable behaviour.
@@ -23,12 +23,27 @@
 - Jackson deserialization RCE needs default typing explicitly enabled plus a gadget chain assembled from libraries already on the application classpath.
   - **Disproof:** If the endpoint rejects a payload naming a known gadget class with a subtype-validation error while default typing is off, and no request shape can turn typing on, the chain is unreachable.
   - Sources: <https://bishopfox.com/blog/gwt-unpatched-unauthenticated-java-deserialization-vulnerability> · <https://snyk.io/blog/java-json-deserialization-problems-jackson-objectmapper/>
+- Gadget hunting on a model artefact starts with enumerating where its bytes came from, because the library's own URL-to-cache download helper means a cached file is attacker-influenceable input and every file in that cache is in scope.
+  - **Disproof:** Refuted if the cache location is populated only from integrity-verified sources with pinned hashes, so no attacker-controllable bytes can enter the deserialization path through it.
+  - Sources: <https://www.nccgroup.com/research/freddy-an-extension-for-automatically-identifying-deserialisation-issues-in-java-and-net-applications/> · <https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/generic-methodologies-and-resources/python/keras-model-deserialization-rce-and-gadget-hunting.md>
+- Pickle-based model loading is only defensible when the unpickler itself enforces an allowlist, because opcodes execute during deserialization and no import-list scanner covers gadget classes that are not yet published.
+  - **Disproof:** Refuted if unpickling a model artefact that imports something outside the reviewed allowlist raises an error instead of running, or if reconstruction touches plain data structures only and invokes nothing.
+  - Sources: <https://www.nccgroup.com/research/freddy-an-extension-for-automatically-identifying-deserialisation-issues-in-java-and-net-applications/> · <https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/generic-methodologies-and-resources/python/keras-model-deserialization-rce-and-gadget-hunting.md>
+- The chain is bound to the session the payload was staged in, so the trigger request must carry that exact session ID or the deserializer loads a different file and the gadget fails silently.
+  - **Disproof:** Refuted if the chain fires from a request with no matching session cookie, or with a different session ID, which would show the gadget does not depend on session continuity.
+  - Sources: <https://bishopfox.com/blog/gwt-unpatched-unauthenticated-java-deserialization-vulnerability> · <https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/network-services-pentesting/pentesting-web/php-tricks-esp/php-rce-abusing-object-creation-new-usd_get-a-usd_get-b.md>
 
 ## Recon signals (where to look)
 
 - Base64-encoded fully-qualified Java class names appearing in request bodies to a GWT-RPC endpoint indicate the server deserializes attacker-named types.
   - **Disproof:** If decoded blobs never contain a class descriptor, or every named-type payload is rejected by subtype validation before instantiation, the traffic is ordinary serialization without an exploitable sink.
   - Sources: <https://bishopfox.com/blog/gwt-unpatched-unauthenticated-java-deserialization-vulnerability> · <https://www.nccgroup.com/research/freddy-an-extension-for-automatically-identifying-deserialisation-issues-in-java-and-net-applications/>
+- A rejection message naming a specific class during DGC deserialization is direct evidence that JEP290 filtering is installed, and that observation is what downgrades a deserialization finding on the RMI service.
+  - **Disproof:** Refuted if the same class deserialises successfully with no exception on the DGC call, or if the server errors for an unrelated unmarshalling reason with no filter-specific message.
+  - Sources: <https://httpwg.org/specs/rfc9530.html> · <https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/network-services-pentesting/1099-pentesting-java-rmi.md>
+- A JEP290 bypass probe that comes back as IllegalArgumentException from the gadget payload, with the target rated non-vulnerable, is the record that the filter still holds for that gadget class.
+  - **Disproof:** Refuted if the gadget payload instead shows side effects or the object is reconstructed rather than rejected, which would show the filter did not catch that chain.
+  - Sources: <https://httpwg.org/specs/rfc9530.html> · <https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/network-services-pentesting/1099-pentesting-java-rmi.md>
 
 ## Techniques (what to change)
 
@@ -53,15 +68,24 @@
 - Deserialization issue in commonly-used Java library allows remote execution. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Deserialization issue in commonly-used Java library allows remote execution.".
   - Sources: <https://cwe.mitre.org/data/definitions/502.html> · <https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html>
+- The PHP deserialization surface is not confined to __destruct, because the engine invokes the serialization-time magic methods on attacker-chosen class names, so the hunt must first enumerate which of those hooks the reachable classes actually define.
+  - **Disproof:** Refuted if the unserialize call is restricted to an allowlist of classes none of which define the serialization-time magic methods, so no attacker-chosen hook ever runs.
+  - Sources: <https://docs.python.org/3/library/pickle.html> · <https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/pentesting-web/deserialization/README.md>
+- When a deserialization sink only hands the attacker a file-like path, the server-side request can be sourced from the object-construction primitives invoked during reconstruction - a wrapper-backed stream object reaches the network whenever its scheme handler is enabled.
+  - **Disproof:** Refuted if the scheme's stream wrapper is disabled on the target, or if the constructed object never opens the URL so no outbound request is issued from the reconstruction path.
+  - Sources: <https://bishopfox.com/blog/gwt-unpatched-unauthenticated-java-deserialization-vulnerability> · <https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/network-services-pentesting/pentesting-web/php-tricks-esp/php-rce-abusing-object-creation-new-usd_get-a-usd_get-b.md>
+- For .NET the exploitable condition in deserialization is attacker influence over which type gets instantiated, so the test is whether type resolution can be driven to a known dangerous gadget type, and the matching defence is a binder-level allowlist rather than any single serializer being called safe.
+  - **Disproof:** Refuted if type name handling is disabled end to end and no resolver honours an attacker-supplied type name, since then no dangerous gadget type can be selected however risky its properties are.
+  - Sources: <https://docs.python.org/3/library/pickle.html> · <https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/pentesting-web/deserialization/README.md>
 
 ## Tests
 
-- To decide this case, observe: nce a deserializer never saw the attacker-controlled bytes and the gadget chain was never reached. The finding survives only when an edited blob with a changed type field, a changed field value, or an added object was accepted and produced an attacker-chosen effect, which means the check that should have bound the bytes to their origin is missing or bypassable. _(unverified)_
+- To decide this case, observe: Discard the report when your tampered payload was rejected at the integrity or signature layer, since a deserializer never saw the attacker-controlled bytes and the gadget chain was never reached. _(unverified)_
   - **Disproof:** This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (deser.fprule.integrity_rejected_blob_never_reaches_the_deserializer) states the full boundary.
   - Sources: <https://projectdiscovery.io/blog/nuclei-templates-november-2025> · <https://projectdiscovery.io/blog/ruby-saml-gitlab-auth-bypass>
-- To decide this case, observe: whole test. Elastic's Log4j 2 research is the model: reproducing the deserialization allowlist bypass was necessary but not sufficient, because reaching command execution took two further things the library does not ship - a process that still deserializes the object stream, and a gadget library already sitting on that JVM. So inventory the target: if the deserializing process
-  - **Disproof:** This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (deser.fp_rule.serialization_endpoint_without_a_gadget_chain_is_not_rce) states the full boundary.
-  - Sources: <https://www.elastic.co/security-labs/threat-command/java-deserialization-vulnerability-log4j-2> · <https://www.sonarsource.com/blog/phpbb3-phar-deserialization-to-remote-code-execution/>
+- A discovered RMI method that merely calls the remote application's own execute routine proves nothing about deserialization, so the tester first sends a harmless canary to a non-primitive parameter and escalates only after unfiltered deserialization with a gadget chain on the server classpath is confirmed.
+  - **Disproof:** Refuted if the canary produces deserialization-related behaviour identical to a filtered payload, or if a filter rejects the payload class before any gadget resolves.
+  - Sources: <https://httpwg.org/specs/rfc9530.html> · <https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/network-services-pentesting/1099-pentesting-java-rmi.md>
 
 ## Validation bar (how to prove it)
 
@@ -78,5 +102,26 @@
   - **Disproof:** If the type field is resolved against a server-side allowlist so that your substituted class never instantiates, the report is a false positive about a class you cannot reach even though the blob parses, and the acceptance of the blob proves nothing.
   - Sources: <https://httpwg.org/specs/rfc9530.html> · <https://projectdiscovery.io/blog/nuclei-templates-november-2025> · <https://projectdiscovery.io/blog/ruby-saml-gitlab-auth-bypass>
 
+## Evidence requirements
+
+- A deserialization endpoint is only proven exposed when a payload naming a class the application never intends to construct is accepted and instantiated; a request answered with a class-rejection error or a warning naming the disallowed class is a control working, not a finding.
+  - **Disproof:** The claim that an endpoint is exposed is false where the parser enforces an allow-list and rejects the attacker's class, where the endpoint accepts only a self-describing format with no class identity such as JSON bound to a fixed model, or where the deserialization happens only over data the client never supplies. It is equally false where the rejection observed is a parse error on malformed input rather than a class rejection, since that shows nothing about whether classes are filtered - and a clean rejection log is not evidence of exposure under any reading.
+  - Sources: <https://www.php.net/manual/en/function.unserialize.php> · <https://www.rfc-editor.org/rfc/rfc8259.html>
+- Insecure deserialization is proven when a byte string the attacker controls names a class or reduction function in the payload and the server's own parser instantiates or invokes it, so the artifact is the parser's behaviour toward an attacker-named type rather than any parsed value appearing in a response.
+  - **Disproof:** The claim is false when the payload's class name is not on the server's classpath or module path, when the parser is configured with an allow-list - PHP's allowed_classes rejecting anything outside a named set, or an equivalent filter - so the object never becomes an instance of the named type, and when no side effect of that class is observable. It is also false for a format that carries no type identity at all, such as plain JSON parsed into a fixed data model, and false where the endpoint's input is not attacker-controlled in the serialized field at all.
+  - Sources: <https://cwe.mitre.org/data/definitions/470.html> · <https://www.php.net/manual/en/function.unserialize.php>
+- The triage signal that separates an exploitable deserialization sink from an inert one is whether the accepted format carries type identity: a format whose wire representation names a constructible type can be made to instantiate it, while a format limited to four primitive types and two structured types has no field an attacker can use to choose a class.
+  - **Disproof:** The claim that a JSON-only endpoint is not a deserialization sink is false when the application feeds the parsed JSON into a second stage that does reflect - passing it to a dynamic invoker, a template engine, a query builder that maps keys to operators, or a polymorphic binder that honours type-discriminator fields - because the type selection then happens one layer down rather than at the parser. It is also false when the endpoint silently accepts a non-JSON native format on the same parameter despite a JSON-looking content type, which is why the accepted format must be observed on the wire rather than assumed from documentation.
+  - Sources: <https://nodejs.org/api/v8.html> · <https://www.rfc-editor.org/rfc/rfc8259.html>
+- The strongest deserialization artifact is a callback the server makes to a host the attacker chose during reconstruction of the attacker's object, because that request cannot be produced by anything the application legitimately does with the same input.
+  - **Disproof:** The claim is false when no callback arrives at the controlled host despite a payload naming reachable classes, and it cannot be produced at all in an environment with no egress - a fully air-gapped or egress-filtered target - in which case the negative is unverifiable rather than a clean pass. It is also false where the parser rejected the payload outright, where the callback host was unreachable for reasons unrelated to the payload, or where the application itself legitimately makes outbound requests to hosts the tester also controls, which makes the correlation meaningless.
+  - Sources: <https://docs.python.org/3/library/pickle.html> · <https://cwe.mitre.org/data/definitions/470.html>
+
+## Variants
+
+- A model that is safe under the current model-file deserialization can still execute through the legacy Lambda layer, because that path reconstructs marshaled function bytecode as a separate deserialization risk and needs its own check.
+  - **Disproof:** Refuted if a model carrying the Lambda layer is rejected outright, or the marshaled bytecode is never reconstructed, or the target version no longer loads the legacy deserialization path at all.
+  - Sources: <https://www.nccgroup.com/research/freddy-an-extension-for-automatically-identifying-deserialisation-issues-in-java-and-net-applications/> · <https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/generic-methodologies-and-resources/python/keras-model-deserialization-rce-and-gadget-hunting.md>
+
 ---
 Full class document: `domains/web/deser/knowledge/DIGEST.md` · retrieve more with `python -m wks.cli search "<query>" --class-id deser`
```
