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

## 2026-10-04 00:43 — 173 diff lines
- items: 27 (supported 19), FP rules 2, chains 1, state mature

```diff
--- deser@current
+++ deser@new
@@ -20,108 +20,120 @@
 
 ## Prerequisites (do not start without these)
 
-- Jackson deserialization RCE needs default typing explicitly enabled plus a gadget chain assembled from libraries already on the application classpath.
+- Gadget hunting on a model artefact starts with enumerating where its bytes came from, because the library's own URL-to-cache download helper means a cached file is attacker-influenceable input and every file in that cache is in scope.  _(merged 1 duplicate row(s))_
+  - **Disproof:** Refuted if the cache location is populated only from integrity-verified sources with pinned hashes, so no attacker-controllable bytes can enter the deserialization path through it.
+  - Sources: <https://www.nccgroup.com/research/freddy-an-extension-for-automatically-identifying-deserialisation-issues-in-java-and-net-applications/> · <https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/generic-methodologies-and-resources/python/keras-model-deserialization-rce-and-gadget-hunting.md>
+- Jackson deserialization RCE needs default typing explicitly enabled plus a gadget chain assembled from libraries already on the application classpath.  _(merged 1 duplicate row(s))_
   - **Disproof:** If the endpoint rejects a payload naming a known gadget class with a subtype-validation error while default typing is off, and no request shape can turn typing on, the chain is unreachable.
   - Sources: <https://bishopfox.com/blog/gwt-unpatched-unauthenticated-java-deserialization-vulnerability> · <https://snyk.io/blog/java-json-deserialization-problems-jackson-objectmapper/>
-- Gadget hunting on a model artefact starts with enumerating where its bytes came from, because the library's own URL-to-cache download helper means a cached file is attacker-influenceable input and every file in that cache is in scope.
-  - **Disproof:** Refuted if the cache location is populated only from integrity-verified sources with pinned hashes, so no attacker-controllable bytes can enter the deserialization path through it.
-  - Sources: <https://www.nccgroup.com/research/freddy-an-extension-for-automatically-identifying-deserialisation-issues-in-java-and-net-applications/> · <https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/generic-methodologies-and-resources/python/keras-model-deserialization-rce-and-gadget-hunting.md>
-- Pickle-based model loading is only defensible when the unpickler itself enforces an allowlist, because opcodes execute during deserialization and no import-list scanner covers gadget classes that are not yet published.
+- Pickle-based model loading is only defensible when the unpickler itself enforces an allowlist, because opcodes execute during deserialization and no import-list scanner covers gadget classes that are not yet published.  _(merged 1 duplicate row(s))_
   - **Disproof:** Refuted if unpickling a model artefact that imports something outside the reviewed allowlist raises an error instead of running, or if reconstruction touches plain data structures only and invokes nothing.
   - Sources: <https://www.nccgroup.com/research/freddy-an-extension-for-automatically-identifying-deserialisation-issues-in-java-and-net-applications/> · <https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/generic-methodologies-and-resources/python/keras-model-deserialization-rce-and-gadget-hunting.md>
-- The chain is bound to the session the payload was staged in, so the trigger request must carry that exact session ID or the deserializer loads a different file and the gadget fails silently.
+- The chain is bound to the session the payload was staged in, so the trigger request must carry that exact session ID or the deserializer loads a different file and the gadget fails silently.  _(merged 1 duplicate row(s))_
   - **Disproof:** Refuted if the chain fires from a request with no matching session cookie, or with a different session ID, which would show the gadget does not depend on session continuity.
   - Sources: <https://bishopfox.com/blog/gwt-unpatched-unauthenticated-java-deserialization-vulnerability> · <https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/network-services-pentesting/pentesting-web/php-tricks-esp/php-rce-abusing-object-creation-new-usd_get-a-usd_get-b.md>
 
 ## Recon signals (where to look)
 
-- Base64-encoded fully-qualified Java class names appearing in request bodies to a GWT-RPC endpoint indicate the server deserializes attacker-named types.
+- A JEP290 bypass probe that comes back as IllegalArgumentException from the gadget payload, with the target rated non-vulnerable, is the record that the filter still holds for that gadget class.  _(merged 1 duplicate row(s))_
+  - **Disproof:** Refuted if the gadget payload instead shows side effects or the object is reconstructed rather than rejected, which would show the filter did not catch that chain.
+  - Sources: <https://httpwg.org/specs/rfc9530.html> · <https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/network-services-pentesting/1099-pentesting-java-rmi.md>
+- A rejection message naming a specific class during DGC deserialization is direct evidence that JEP290 filtering is installed, and that observation is what downgrades a deserialization finding on the RMI service.  _(merged 1 duplicate row(s))_
+  - **Disproof:** Refuted if the same class deserialises successfully with no exception on the DGC call, or if the server errors for an unrelated unmarshalling reason with no filter-specific message.
+  - Sources: <https://httpwg.org/specs/rfc9530.html> · <https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/network-services-pentesting/1099-pentesting-java-rmi.md>
+- Base64-encoded fully-qualified Java class names appearing in request bodies to a GWT-RPC endpoint indicate the server deserializes attacker-named types.  _(merged 1 duplicate row(s))_
   - **Disproof:** If decoded blobs never contain a class descriptor, or every named-type payload is rejected by subtype validation before instantiation, the traffic is ordinary serialization without an exploitable sink.
   - Sources: <https://bishopfox.com/blog/gwt-unpatched-unauthenticated-java-deserialization-vulnerability> · <https://www.nccgroup.com/research/freddy-an-extension-for-automatically-identifying-deserialisation-issues-in-java-and-net-applications/>
-- A rejection message naming a specific class during DGC deserialization is direct evidence that JEP290 filtering is installed, and that observation is what downgrades a deserialization finding on the RMI service.
-  - **Disproof:** Refuted if the same class deserialises successfully with no exception on the DGC call, or if the server errors for an unrelated unmarshalling reason with no filter-specific message.
-  - Sources: <https://httpwg.org/specs/rfc9530.html> · <https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/network-services-pentesting/1099-pentesting-java-rmi.md>
-- A JEP290 bypass probe that comes back as IllegalArgumentException from the gadget payload, with the target rated non-vulnerable, is the record that the filter still holds for that gadget class.
-  - **Disproof:** Refuted if the gadget payload instead shows side effects or the object is reconstructed rather than rejected, which would show the filter did not catch that chain.
-  - Sources: <https://httpwg.org/specs/rfc9530.html> · <https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/network-services-pentesting/1099-pentesting-java-rmi.md>
 
 ## Techniques (what to change)
 
-- Making an assumption that the code in the deserialized object is valid is dangerous and can enable exploitation. _(unverified)_
+- Avoid having unnecessary types or gadgets (a sequence of instances and method invocations that can self-execute during the deserialization process, often found in libraries) available that can be leveraged for malicious ends.  _(merged 1 duplicate row(s))_ _(unverified)_
+  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Avoid having unnecessary types or gadgets (a sequence of instances and method invocations ".
+  - Sources: <https://cwe.mitre.org/data/definitions/502.html> · <https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html>
+- Deserialization issue in commonly-used Java library allows remote execution.  _(merged 1 duplicate row(s))_ _(unverified)_
+  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Deserialization issue in commonly-used Java library allows remote execution.".
+  - Sources: <https://cwe.mitre.org/data/definitions/502.html> · <https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html>
+- For .NET the exploitable condition in deserialization is attacker influence over which type gets instantiated, so the test is whether type resolution can be driven to a known dangerous gadget type, and the matching defence is a binder-level allowlist rather than any single serializer being called safe.  _(merged 1 duplicate row(s))_
+  - **Disproof:** Refuted if type name handling is disabled end to end and no resolver honours an attacker-supplied type name, since then no dangerous gadget type can be selected however risky its properties are.
+  - Sources: <https://docs.python.org/3/library/pickle.html> · <https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/pentesting-web/deserialization/README.md>
+- Making an assumption that the code in the deserialized object is valid is dangerous and can enable exploitation.  _(merged 1 duplicate row(s))_ _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Making an assumption that the code in the deserialized object is valid is dangerous and ca".
   - Sources: <https://cwe.mitre.org/data/definitions/502.html> · <https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html>
-- Avoid having unnecessary types or gadgets (a sequence of instances and method invocations that can self-execute during the deserialization process, often found in libraries) available that can be leveraged for malicious ends. _(unverified)_
-  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Avoid having unnecessary types or gadgets (a sequence of instances and method invocations ".
-  - Sources: <https://cwe.mitre.org/data/definitions/502.html> · <https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html>
-- Serialization and deserialization refer to the process of taking program-internal object-related data, packaging it in a way that allows the data to be externally stored or transferred ("serialization"), then extracting the serialized data to reconstruct the original object ("deserialization"). _(unverified)_
+- Serialization and deserialization refer to the process of taking program-internal object-related data, packaging it in a way that allows the data to be externally stored or transferred ("serialization"), then extracting the serialized data to reconstruct the original object ("deserialization").  _(merged 2 duplicate row(s))_ _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Serialization and deserialization refer to the process of taking program-internal object-r".
   - Sources: <https://cwe.mitre.org/data/definitions/502.html> · <https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html>
-- Serialization and deserialization refer to the process of taking program-internal object-related data, packaging it in a way that allows the data to be externally stored or transferred ("serialization"), then extracting the serialized data to reconstruct the original object ("deserialization"). _(unverified)_
-  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Serialization and deserialization refer to the process of taking program-internal object-r".
+- Since Pickle allows objects to define the process for how they should be unpickled, the attacker can direct the unpickle process to call Popen in the subprocess module and execute /bin/sh.  _(merged 1 duplicate row(s))_ _(unverified)_
+  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Since Pickle allows objects to define the process for how they should be unpickled, the at".
   - Sources: <https://cwe.mitre.org/data/definitions/502.html> · <https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html>
-- This code does not attempt to verify the source or contents of the file before deserializing it. _(unverified)_
+- The PHP deserialization surface is not confined to __destruct, because the engine invokes the serialization-time magic methods on attacker-chosen class names, so the hunt must first enumerate which of those hooks the reachable classes actually define.  _(merged 1 duplicate row(s))_
+  - **Disproof:** Refuted if the unserialize call is restricted to an allowlist of classes none of which define the serialization-time magic methods, so no attacker-chosen hook ever runs.
+  - Sources: <https://docs.python.org/3/library/pickle.html> · <https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/pentesting-web/deserialization/README.md>
+- This code does not attempt to verify the source or contents of the file before deserializing it.  _(merged 1 duplicate row(s))_ _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "This code does not attempt to verify the source or contents of the file before deserializi".
   - Sources: <https://cwe.mitre.org/data/definitions/502.html> · <https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html>
-- Since Pickle allows objects to define the process for how they should be unpickled, the attacker can direct the unpickle process to call Popen in the subprocess module and execute /bin/sh. _(unverified)_
-  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Since Pickle allows objects to define the process for how they should be unpickled, the at".
-  - Sources: <https://cwe.mitre.org/data/definitions/502.html> · <https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html>
-- Deserialization issue in commonly-used Java library allows remote execution. _(unverified)_
-  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Deserialization issue in commonly-used Java library allows remote execution.".
-  - Sources: <https://cwe.mitre.org/data/definitions/502.html> · <https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html>
-- The PHP deserialization surface is not confined to __destruct, because the engine invokes the serialization-time magic methods on attacker-chosen class names, so the hunt must first enumerate which of those hooks the reachable classes actually define.
-  - **Disproof:** Refuted if the unserialize call is restricted to an allowlist of classes none of which define the serialization-time magic methods, so no attacker-chosen hook ever runs.
-  - Sources: <https://docs.python.org/3/library/pickle.html> · <https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/pentesting-web/deserialization/README.md>
-- When a deserialization sink only hands the attacker a file-like path, the server-side request can be sourced from the object-construction primitives invoked during reconstruction - a wrapper-backed stream object reaches the network whenever its scheme handler is enabled.
+- When a deserialization sink only hands the attacker a file-like path, the server-side request can be sourced from the object-construction primitives invoked during reconstruction - a wrapper-backed stream object reaches the network whenever its scheme handler is enabled.  _(merged 1 duplicate row(s))_
   - **Disproof:** Refuted if the scheme's stream wrapper is disabled on the target, or if the constructed object never opens the URL so no outbound request is issued from the reconstruction path.
   - Sources: <https://bishopfox.com/blog/gwt-unpatched-unauthenticated-java-deserialization-vulnerability> · <https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/network-services-pentesting/pentesting-web/php-tricks-esp/php-rce-abusing-object-creation-new-usd_get-a-usd_get-b.md>
-- For .NET the exploitable condition in deserialization is attacker influence over which type gets instantiated, so the test is whether type resolution can be driven to a known dangerous gadget type, and the matching defence is a binder-level allowlist rather than any single serializer being called safe.
-  - **Disproof:** Refuted if type name handling is disabled end to end and no resolver honours an attacker-supplied type name, since then no dangerous gadget type can be selected however risky its properties are.
-  - Sources: <https://docs.python.org/3/library/pickle.html> · <https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/pentesting-web/deserialization/README.md>
 
 ## Tests
 
-- To decide this case, observe: Discard the report when your tampered payload was rejected at the integrity or signature layer, since a deserializer never saw the attacker-controlled bytes and the gadget chain was never reached. _(unverified)_
+- A discovered RMI method that merely calls the remote application's own execute routine proves nothing about deserialization, so the tester first sends a harmless canary to a non-primitive parameter and escalates only after unfiltered deserialization with a gadget chain on the server classpath is confirmed.  _(merged 1 duplicate row(s))_
+  - **Disproof:** Refuted if the canary produces deserialization-related behaviour identical to a filtered payload, or if a filter rejects the payload class before any gadget resolves.
+  - Sources: <https://httpwg.org/specs/rfc9530.html> · <https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/network-services-pentesting/1099-pentesting-java-rmi.md>
+- To decide this case, observe: Discard the report when your tampered payload was rejected at the integrity or signature layer, since a deserializer never saw the attacker-controlled bytes and the gadget chain was never reached.  _(merged 1 duplicate row(s))_ _(unverified)_
   - **Disproof:** This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (deser.fprule.integrity_rejected_blob_never_reaches_the_deserializer) states the full boundary.
   - Sources: <https://projectdiscovery.io/blog/nuclei-templates-november-2025> · <https://projectdiscovery.io/blog/ruby-saml-gitlab-auth-bypass>
-- A discovered RMI method that merely calls the remote application's own execute routine proves nothing about deserialization, so the tester first sends a harmless canary to a non-primitive parameter and escalates only after unfiltered deserialization with a gadget chain on the server classpath is confirmed.
-  - **Disproof:** Refuted if the canary produces deserialization-related behaviour identical to a filtered payload, or if a filter rejects the payload class before any gadget resolves.
-  - Sources: <https://httpwg.org/specs/rfc9530.html> · <https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/network-services-pentesting/1099-pentesting-java-rmi.md>
 
 ## Validation bar (how to prove it)
 
-- A deserialization endpoint is confirmed only by a differential that shows an attacker-shaped object graph is deserialized and executed before authentication, which is why an unauthenticated remote attacker reaching arbitrary code execution on the vulnerable listener is the observation that closes the chain.
+- A deserialization endpoint is confirmed only by a differential that shows an attacker-shaped object graph is deserialized and executed before authentication, which is why an unauthenticated remote attacker reaching arbitrary code execution on the vulnerable listener is the observation that closes the chain.  _(merged 1 duplicate row(s))_
   - **Disproof:** If the endpoint authenticates before deserializing, or rejects the crafted graph with an integrity error before any object is constructed, or if the runtime has removed the formatter entirely, no side effect is observable and the deserialization segment does not hold.
   - Sources: <https://learn.microsoft.com/en-us/dotnet/standard/serialization/binaryformatter-security-guide> · <https://www.tenable.com/blog/cve-2023-20864-vmware-aria-operations-for-logs-deserialization-vulnerability>
 
 ## False-positive rules (when to reject it)
 
-- An endpoint that accepts a serialised payload is not an insecure-deserialization RCE finding until a gadget chain reachable in the target's own classpath is proven: deserialization without an available gadget is a parse of attacker data, not code execution.
+- A serialized blob whose integrity check you could not defeat is not an insecure-deserialization finding; the finding needs a modified blob accepted without a valid signature.  _(merged 1 duplicate row(s))_
+  - **Disproof:** If the type field is resolved against a server-side allowlist so that your substituted class never instantiates, the report is a false positive about a class you cannot reach even though the blob parses, and the acceptance of the blob proves nothing.
... (truncated)
```

## 2026-10-04 00:50 — 15 diff lines
- items: 27 (supported 19), FP rules 2, chains 1, state mature

```diff
--- deser@current
+++ deser@new
@@ -123,10 +123,8 @@
 
 ## Hunt procedure
 
-1. Enumerate the surface before probing: collect every endpoint, parameter and object id the class could plausibly sit on.
-2. Establish a CONTROLLED BASELINE first — one unauthenticated and one authenticated low-privilege request per candidate — and diff against the probe. A difference with no baseline proves nothing.
-3. Change exactly ONE variable per probe. Two changes produce a difference you cannot attribute.
-4. Record raw request and response pairs verbatim, including headers, before you interpret anything.
+1. Identify the format from the Content-Type and a magic prefix before testing; gadgets differ per library and version.
+2. Probe with a harmless marker object per known library, then escalate only after a callback (interactsh) confirms the sink is reachable.
 
 ### What counts as proof
 
```

## 2026-10-04 13:20 — 37 diff lines
- items: 27 (supported 19), FP rules 2, chains 1, state mature

```diff
--- deser@current
+++ deser@new
@@ -49,28 +49,28 @@
 
 - Avoid having unnecessary types or gadgets (a sequence of instances and method invocations that can self-execute during the deserialization process, often found in libraries) available that can be leveraged for malicious ends.  _(merged 1 duplicate row(s))_ _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Avoid having unnecessary types or gadgets (a sequence of instances and method invocations ".
-  - Sources: <https://cwe.mitre.org/data/definitions/502.html> · <https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html>
+  - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html> · <https://cwe.mitre.org/data/definitions/502.html>
 - Deserialization issue in commonly-used Java library allows remote execution.  _(merged 1 duplicate row(s))_ _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Deserialization issue in commonly-used Java library allows remote execution.".
-  - Sources: <https://cwe.mitre.org/data/definitions/502.html> · <https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html>
+  - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html> · <https://cwe.mitre.org/data/definitions/502.html>
 - For .NET the exploitable condition in deserialization is attacker influence over which type gets instantiated, so the test is whether type resolution can be driven to a known dangerous gadget type, and the matching defence is a binder-level allowlist rather than any single serializer being called safe.  _(merged 1 duplicate row(s))_
   - **Disproof:** Refuted if type name handling is disabled end to end and no resolver honours an attacker-supplied type name, since then no dangerous gadget type can be selected however risky its properties are.
   - Sources: <https://docs.python.org/3/library/pickle.html> · <https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/pentesting-web/deserialization/README.md>
 - Making an assumption that the code in the deserialized object is valid is dangerous and can enable exploitation.  _(merged 1 duplicate row(s))_ _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Making an assumption that the code in the deserialized object is valid is dangerous and ca".
-  - Sources: <https://cwe.mitre.org/data/definitions/502.html> · <https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html>
+  - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html> · <https://cwe.mitre.org/data/definitions/502.html>
 - Serialization and deserialization refer to the process of taking program-internal object-related data, packaging it in a way that allows the data to be externally stored or transferred ("serialization"), then extracting the serialized data to reconstruct the original object ("deserialization").  _(merged 2 duplicate row(s))_ _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Serialization and deserialization refer to the process of taking program-internal object-r".
-  - Sources: <https://cwe.mitre.org/data/definitions/502.html> · <https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html>
+  - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html> · <https://cwe.mitre.org/data/definitions/502.html>
 - Since Pickle allows objects to define the process for how they should be unpickled, the attacker can direct the unpickle process to call Popen in the subprocess module and execute /bin/sh.  _(merged 1 duplicate row(s))_ _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Since Pickle allows objects to define the process for how they should be unpickled, the at".
-  - Sources: <https://cwe.mitre.org/data/definitions/502.html> · <https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html>
+  - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html> · <https://cwe.mitre.org/data/definitions/502.html>
 - The PHP deserialization surface is not confined to __destruct, because the engine invokes the serialization-time magic methods on attacker-chosen class names, so the hunt must first enumerate which of those hooks the reachable classes actually define.  _(merged 1 duplicate row(s))_
   - **Disproof:** Refuted if the unserialize call is restricted to an allowlist of classes none of which define the serialization-time magic methods, so no attacker-chosen hook ever runs.
   - Sources: <https://docs.python.org/3/library/pickle.html> · <https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/pentesting-web/deserialization/README.md>
 - This code does not attempt to verify the source or contents of the file before deserializing it.  _(merged 1 duplicate row(s))_ _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "This code does not attempt to verify the source or contents of the file before deserializi".
-  - Sources: <https://cwe.mitre.org/data/definitions/502.html> · <https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html>
+  - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html> · <https://cwe.mitre.org/data/definitions/502.html>
 - When a deserialization sink only hands the attacker a file-like path, the server-side request can be sourced from the object-construction primitives invoked during reconstruction - a wrapper-backed stream object reaches the network whenever its scheme handler is enabled.  _(merged 1 duplicate row(s))_
   - **Disproof:** Refuted if the scheme's stream wrapper is disabled on the target, or if the constructed object never opens the URL so no outbound request is issued from the reconstruction path.
   - Sources: <https://bishopfox.com/blog/gwt-unpatched-unauthenticated-java-deserialization-vulnerability> · <https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/network-services-pentesting/pentesting-web/php-tricks-esp/php-rce-abusing-object-creation-new-usd_get-a-usd_get-b.md>
```

## 2026-10-04 19:46 — 9 diff lines
- items: 27 (supported 19), FP rules 2, chains 1, state mature

```diff
--- deser@current
+++ deser@new
@@ -135,6 +135,3 @@
 > Ordered prerequisites, the validation bar and the false-positive rules below are the authority: this block is the mechanics, those are the standard.
 ---
 Full class document: `domains/web/deser/knowledge/DIGEST.md` · retrieve more with `python -m wks.cli search "<query>" --class-id deser`
-
----
-Runbook: [`HUNT.md`](HUNT.md) — every promoted technique mapped to an executable procedure with the observables to record.
```

## 2026-10-04 21:29 — 53 diff lines
- items: 27 (supported 26), FP rules 2, chains 1, state mature

```diff
--- deser@current
+++ deser@new
@@ -10,7 +10,7 @@
      python -m wks.skillgen -->
 
 > surface `web` · CWE CWE-502 · OWASP A08:2021
-> evidence: 27 items, 19 supported, 2 FP rules, 1 chains
+> evidence: 27 items, 26 supported, 2 FP rules, 1 chains
 > maturity: **mature**
 
 Data is reconstructed into a live object graph whose type system then invokes attacker-reachable behaviour.
@@ -47,29 +47,29 @@
 
 ## Techniques (what to change)
 
-- Avoid having unnecessary types or gadgets (a sequence of instances and method invocations that can self-execute during the deserialization process, often found in libraries) available that can be leveraged for malicious ends.  _(merged 1 duplicate row(s))_ _(unverified)_
-  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Avoid having unnecessary types or gadgets (a sequence of instances and method invocations ".
+- Avoid having unnecessary types or gadgets (a sequence of instances and method invocations that can self-execute during the deserialization process, often found in libraries) available that can be leveraged for malicious ends.  _(merged 1 duplicate row(s))_
+  - **Disproof:** Refuted when: the value is bound as a parameter or written through the framework's own encoder, so the interpreter never sees attacker text as syntax. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“Avoid having unnecessary types or gadgets (a sequence of instances and method in”) does not occur under a test that isolates that control.
   - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html> · <https://cwe.mitre.org/data/definitions/502.html>
-- Deserialization issue in commonly-used Java library allows remote execution.  _(merged 1 duplicate row(s))_ _(unverified)_
-  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Deserialization issue in commonly-used Java library allows remote execution.".
+- Deserialization issue in commonly-used Java library allows remote execution.  _(merged 1 duplicate row(s))_
+  - **Disproof:** Refuted when: the value is bound as a parameter or written through the framework's own encoder, so the interpreter never sees attacker text as syntax. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“Deserialization issue in commonly-used Java library allows remote execution.”) does not occur under a test that isolates that control.
   - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html> · <https://cwe.mitre.org/data/definitions/502.html>
 - For .NET the exploitable condition in deserialization is attacker influence over which type gets instantiated, so the test is whether type resolution can be driven to a known dangerous gadget type, and the matching defence is a binder-level allowlist rather than any single serializer being called safe.  _(merged 1 duplicate row(s))_
   - **Disproof:** Refuted if type name handling is disabled end to end and no resolver honours an attacker-supplied type name, since then no dangerous gadget type can be selected however risky its properties are.
   - Sources: <https://docs.python.org/3/library/pickle.html> · <https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/pentesting-web/deserialization/README.md>
-- Making an assumption that the code in the deserialized object is valid is dangerous and can enable exploitation.  _(merged 1 duplicate row(s))_ _(unverified)_
-  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Making an assumption that the code in the deserialized object is valid is dangerous and ca".
+- Making an assumption that the code in the deserialized object is valid is dangerous and can enable exploitation.  _(merged 1 duplicate row(s))_
+  - **Disproof:** Refuted when: the same behaviour is absent when the single named control in the claim is present, and the control is shown to be present rather than assumed. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“Making an assumption that the code in the deserialized object is valid is danger”) does not occur under a test that isolates that control.
   - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html> · <https://cwe.mitre.org/data/definitions/502.html>
-- Serialization and deserialization refer to the process of taking program-internal object-related data, packaging it in a way that allows the data to be externally stored or transferred ("serialization"), then extracting the serialized data to reconstruct the original object ("deserialization").  _(merged 2 duplicate row(s))_ _(unverified)_
-  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Serialization and deserialization refer to the process of taking program-internal object-r".
+- Serialization and deserialization refer to the process of taking program-internal object-related data, packaging it in a way that allows the data to be externally stored or transferred ("serialization"), then extracting the serialized data to reconstruct the original object ("deserialization").  _(merged 2 duplicate row(s))_
+  - **Disproof:** Refuted when: the same behaviour is absent when the single named control in the claim is present, and the control is shown to be present rather than assumed. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“Serialization and deserialization refer to the process of taking program-interna”) does not occur under a test that isolates that control.
   - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html> · <https://cwe.mitre.org/data/definitions/502.html>
-- Since Pickle allows objects to define the process for how they should be unpickled, the attacker can direct the unpickle process to call Popen in the subprocess module and execute /bin/sh.  _(merged 1 duplicate row(s))_ _(unverified)_
-  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Since Pickle allows objects to define the process for how they should be unpickled, the at".
+- Since Pickle allows objects to define the process for how they should be unpickled, the attacker can direct the unpickle process to call Popen in the subprocess module and execute /bin/sh.  _(merged 1 duplicate row(s))_
+  - **Disproof:** Refuted when: the value is bound as a parameter or written through the framework's own encoder, so the interpreter never sees attacker text as syntax. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“Since Pickle allows objects to define the process for how they should be unpickl”) does not occur under a test that isolates that control.
   - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html> · <https://cwe.mitre.org/data/definitions/502.html>
 - The PHP deserialization surface is not confined to __destruct, because the engine invokes the serialization-time magic methods on attacker-chosen class names, so the hunt must first enumerate which of those hooks the reachable classes actually define.  _(merged 1 duplicate row(s))_
   - **Disproof:** Refuted if the unserialize call is restricted to an allowlist of classes none of which define the serialization-time magic methods, so no attacker-chosen hook ever runs.
   - Sources: <https://docs.python.org/3/library/pickle.html> · <https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/pentesting-web/deserialization/README.md>
-- This code does not attempt to verify the source or contents of the file before deserializing it.  _(merged 1 duplicate row(s))_ _(unverified)_
-  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "This code does not attempt to verify the source or contents of the file before deserializi".
+- This code does not attempt to verify the source or contents of the file before deserializing it.  _(merged 1 duplicate row(s))_
+  - **Disproof:** Refuted when: the resolved path stays inside the permitted base directory after the platform canonicalises it. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“This code does not attempt to verify the source or contents of the file before d”) does not occur under a test that isolates that control.
   - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html> · <https://cwe.mitre.org/data/definitions/502.html>
 - When a deserialization sink only hands the attacker a file-like path, the server-side request can be sourced from the object-construction primitives invoked during reconstruction - a wrapper-backed stream object reaches the network whenever its scheme handler is enabled.  _(merged 1 duplicate row(s))_
   - **Disproof:** Refuted if the scheme's stream wrapper is disabled on the target, or if the constructed object never opens the URL so no outbound request is issued from the reconstruction path.
```

## 2026-10-28 17:55 — 32 diff lines
- items: 26 (supported 26), FP rules 2, chains 1, state mature

```diff
--- deser@current
+++ deser@new
@@ -10,7 +10,7 @@
      python -m wks.skillgen -->
 
 > surface `web` · CWE CWE-502 · OWASP A08:2021
-> evidence: 27 items, 26 supported, 2 FP rules, 1 chains
+> evidence: 26 items, 26 supported, 2 FP rules, 1 chains
 > maturity: **mature**
 
 Data is reconstructed into a live object graph whose type system then invokes attacker-reachable behaviour.
@@ -59,7 +59,7 @@
 - Making an assumption that the code in the deserialized object is valid is dangerous and can enable exploitation.  _(merged 1 duplicate row(s))_
   - **Disproof:** Refuted when: the same behaviour is absent when the single named control in the claim is present, and the control is shown to be present rather than assumed. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“Making an assumption that the code in the deserialized object is valid is danger”) does not occur under a test that isolates that control.
   - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html> · <https://cwe.mitre.org/data/definitions/502.html>
-- Serialization and deserialization refer to the process of taking program-internal object-related data, packaging it in a way that allows the data to be externally stored or transferred ("serialization"), then extracting the serialized data to reconstruct the original object ("deserialization").  _(merged 2 duplicate row(s))_
+- Serialization and deserialization refer to the process of taking program-internal object-related data, packaging it in a way that allows the data to be externally stored or transferred ("serialization"), then extracting the serialized data to reconstruct the original object ("deserialization").  _(merged 1 duplicate row(s))_
   - **Disproof:** Refuted when: the same behaviour is absent when the single named control in the claim is present, and the control is shown to be present rather than assumed. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“Serialization and deserialization refer to the process of taking program-interna”) does not occur under a test that isolates that control.
   - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html> · <https://cwe.mitre.org/data/definitions/502.html>
 - Since Pickle allows objects to define the process for how they should be unpickled, the attacker can direct the unpickle process to call Popen in the subprocess module and execute /bin/sh.  _(merged 1 duplicate row(s))_
@@ -80,9 +80,9 @@
 - A discovered RMI method that merely calls the remote application's own execute routine proves nothing about deserialization, so the tester first sends a harmless canary to a non-primitive parameter and escalates only after unfiltered deserialization with a gadget chain on the server classpath is confirmed.  _(merged 1 duplicate row(s))_
   - **Disproof:** Refuted if the canary produces deserialization-related behaviour identical to a filtered payload, or if a filter rejects the payload class before any gadget resolves.
   - Sources: <https://httpwg.org/specs/rfc9530.html> · <https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/network-services-pentesting/1099-pentesting-java-rmi.md>
-- To decide this case, observe: Discard the report when your tampered payload was rejected at the integrity or signature layer, since a deserializer never saw the attacker-controlled bytes and the gadget chain was never reached.  _(merged 1 duplicate row(s))_ _(unverified)_
+- To decide this case, observe: Discard the report when your tampered payload was rejected at the integrity or signature layer, since a deserializer never saw the attacker-controlled bytes and the gadget chain was never reached.  _(merged 1 duplicate row(s))_
   - **Disproof:** This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (deser.fprule.integrity_rejected_blob_never_reaches_the_deserializer) states the full boundary.
-  - Sources: <https://projectdiscovery.io/blog/nuclei-templates-november-2025> · <https://projectdiscovery.io/blog/ruby-saml-gitlab-auth-bypass>
+  - Sources: <https://portswigger.net/web-security/deserialization> · <https://projectdiscovery.io/blog/nuclei-templates-november-2025> · <https://projectdiscovery.io/blog/ruby-saml-gitlab-auth-bypass>
 
 ## Validation bar (how to prove it)
 
```

## 2026-10-28 20:33 — 78 diff lines
- items: 33 (supported 31), FP rules 2, chains 1, state mature

```diff
--- deser@current
+++ deser@new
@@ -10,7 +10,7 @@
      python -m wks.skillgen -->
 
 > surface `web` · CWE CWE-502 · OWASP A08:2021
-> evidence: 26 items, 26 supported, 2 FP rules, 1 chains
+> evidence: 33 items, 31 supported, 2 FP rules, 1 chains
 > maturity: **mature**
 
 Data is reconstructed into a live object graph whose type system then invokes attacker-reachable behaviour.
@@ -20,6 +20,9 @@
 
 ## Prerequisites (do not start without these)
 
+- CWE-502 defines insecure deserialization as a product deserializing untrusted data without sufficiently ensuring that the resulting data will be valid; malformed or unexpected data can therefore abuse application logic, deny service, or execute arbitrary code.  _(merged 1 duplicate row(s))_
+  - **Disproof:** A deserializer that only accepts data it generated itself, protected by a MAC or signature verified BEFORE deserialization, is not exploitable: the attacker cannot fabricate valid bytes. Without any integrity control, however, the attacker's bytes are trusted.
+  - Sources: <https://cwe.mitre.org/data/definitions/502.html> · <https://community.owasp.org/vulnerabilities/Deserialization_of_untrusted_data>
 - Gadget hunting on a model artefact starts with enumerating where its bytes came from, because the library's own URL-to-cache download helper means a cached file is attacker-influenceable input and every file in that cache is in scope.  _(merged 1 duplicate row(s))_
   - **Disproof:** Refuted if the cache location is populated only from integrity-verified sources with pinned hashes, so no attacker-controllable bytes can enter the deserialization path through it.
   - Sources: <https://www.nccgroup.com/research/freddy-an-extension-for-automatically-identifying-deserialisation-issues-in-java-and-net-applications/> · <https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/generic-methodologies-and-resources/python/keras-model-deserialization-rce-and-gadget-hunting.md>
@@ -44,6 +47,9 @@
 - Base64-encoded fully-qualified Java class names appearing in request bodies to a GWT-RPC endpoint indicate the server deserializes attacker-named types.  _(merged 1 duplicate row(s))_
   - **Disproof:** If decoded blobs never contain a class descriptor, or every named-type payload is rejected by subtype validation before instantiation, the traffic is ordinary serialization without an exploitable sink.
   - Sources: <https://bishopfox.com/blog/gwt-unpatched-unauthenticated-java-deserialization-vulnerability> · <https://www.nccgroup.com/research/freddy-an-extension-for-automatically-identifying-deserialisation-issues-in-java-and-net-applications/>
+- Serialized data can be identified by language-specific signatures: PHP uses a human-readable string format with type letters and length indicators (e.g., O:4:"User":2:{s:4:"name":s:6:"carlos";s:10:"isLoggedIn":b:1;}), while Java serialization uses binary bytes beginning with ac ed (hex) / rO0 (base64), and a Content-type of application/x-java-serialized-object also indicates Java serialization.  _(merged 1 duplicate row(s))_
+  - **Disproof:** Presence of a signature alone does not prove vulnerability: the application must subsequently deserialize that data from an untrusted source without integrity checks. A well-hardened service that rejects unrecognized types and verifies signatures before parsing will show the signature but not the flaw.
+  - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html> · <https://portswigger.net/web-security/deserialization/exploiting>
 
 ## Techniques (what to change)
 
@@ -56,9 +62,15 @@
 - For .NET the exploitable condition in deserialization is attacker influence over which type gets instantiated, so the test is whether type resolution can be driven to a known dangerous gadget type, and the matching defence is a binder-level allowlist rather than any single serializer being called safe.  _(merged 1 duplicate row(s))_
   - **Disproof:** Refuted if type name handling is disabled end to end and no resolver honours an attacker-supplied type name, since then no dangerous gadget type can be selected however risky its properties are.
   - Sources: <https://docs.python.org/3/library/pickle.html> · <https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/pentesting-web/deserialization/README.md>
+- Magic methods invoked automatically during deserialization (PHP __wakeup()/__destruct(), Java readObject()) and gadget chains let an attacker pass data into dangerous sinks without manually invoking functions; pre-built tools such as ysoserial (Java) and PHPGCC (PHP) ship known chains.  _(merged 1 duplicate row(s))_
+  - **Disproof:** A class with a magic method is not inherently vulnerable: the magic method is only dangerous if it passes attacker-controlled data into a dangerous sink, and if the application does not deserialize untrusted input at all. Similarly, a gadget chain is only exploitable if the required classes and gadgets exist on the server's classpath.
+  - Sources: <https://community.owasp.org/vulnerabilities/Deserialization_of_untrusted_data> · <https://portswigger.net/web-security/deserialization/exploiting>
 - Making an assumption that the code in the deserialized object is valid is dangerous and can enable exploitation.  _(merged 1 duplicate row(s))_
   - **Disproof:** Refuted when: the same behaviour is absent when the single named control in the claim is present, and the control is shown to be present rather than assumed. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“Making an assumption that the code in the deserialized object is valid is danger”) does not occur under a test that isolates that control.
   - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html> · <https://cwe.mitre.org/data/definitions/502.html>
+- PHP's phar:// stream wrapper deserializes a PHAR's serialized manifest metadata implicitly when any filesystem operation is performed on the stream, so a polyglot file masquerading as an image can achieve RCE through an innocuous method such as file_exists().  _(merged 1 duplicate row(s))_ _(unverified)_
+  - **Disproof:** The PHAR technique requires the application to (1) accept a file that the attacker can upload, (2) pass that file into a phar:// stream, and (3) trigger a filesystem operation that reaches the phar wrapper. If uploads are restricted to non-executable types, the file is stored outside the web root, or no filesystem function is called on user input, the attack path is blocked.
+  - Sources: <https://portswigger.net/web-security/deserialization/exploiting>
 - Serialization and deserialization refer to the process of taking program-internal object-related data, packaging it in a way that allows the data to be externally stored or transferred ("serialization"), then extracting the serialized data to reconstruct the original object ("deserialization").  _(merged 1 duplicate row(s))_
   - **Disproof:** Refuted when: the same behaviour is absent when the single named control in the claim is present, and the control is shown to be present rather than assumed. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“Serialization and deserialization refer to the process of taking program-interna”) does not occur under a test that isolates that control.
   - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html> · <https://cwe.mitre.org/data/definitions/502.html>
@@ -89,6 +101,9 @@
 - A deserialization endpoint is confirmed only by a differential that shows an attacker-shaped object graph is deserialized and executed before authentication, which is why an unauthenticated remote attacker reaching arbitrary code execution on the vulnerable listener is the observation that closes the chain.  _(merged 1 duplicate row(s))_
   - **Disproof:** If the endpoint authenticates before deserializing, or rejects the crafted graph with an integrity error before any object is constructed, or if the runtime has removed the formatter entirely, no side effect is observable and the deserialization segment does not hold.
   - Sources: <https://learn.microsoft.com/en-us/dotnet/standard/serialization/binaryformatter-security-guide> · <https://www.tenable.com/blog/cve-2023-20864-vmware-aria-operations-for-logs-deserialization-vulnerability>
+- Safe deserialization practices include verifying integrity before parsing (digital signatures), restricting which classes may be deserialized via ObjectInputStream#resolveClass(), declaring a final readObject() that throws, making sensitive fields transient, and using agents or safe replacement APIs to harden ObjectInputStream.  _(merged 1 duplicate row(s))_
+  - **Disproof:** A post-deserialization signature check is useless because the damage occurs during parsing; client-side cryptography is bypassable if the client is compromised; an allowlist is not sufficient because new gadgets are constantly discovered; and client-side integrity checks assume the attacker cannot read or modify the client. Defense in depth therefore stacks multiple controls rather than relying on a single one.
+  - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html> · <https://cwe.mitre.org/data/definitions/502.html>
 
 ## False-positive rules (when to reject it)
 
@@ -114,11 +129,20 @@
   - **Disproof:** The claim that a JSON-only endpoint is not a deserialization sink is false when the application feeds the parsed JSON into a second stage that does reflect - passing it to a dynamic invoker, a template engine, a query builder that maps keys to operators, or a polymorphic binder that honours type-discriminator fields - because the type selection then happens one layer down rather than at the parser. It is also false when the endpoint silently accepts a non-JSON native format on the same parameter despite a JSON-looking content type, which is why the accepted format must be observed on the wire rather than assumed from documentation.
   - Sources: <https://nodejs.org/api/v8.html> · <https://www.rfc-editor.org/rfc/rfc8259.html>
 
+## Impact framing
+
+- Insecure deserialization allows remote code execution, denial of service, and access-control bypass; the CWE/OWASP description states malformed or unexpected data can be used to abuse application logic, deny service, or execute arbitrary code, and observed examples include Java deserialization RCE and Python pickle command execution.  _(merged 1 duplicate row(s))_
+  - **Disproof:** If the application never deserializes untrusted data - all deserialization inputs are internally generated and integrity-protected - or if it whitelists allowed classes and hardens ObjectInputStream, the impact window narrows. However, many deployments deserialize user-supplied cookies, tokens, or files, so the impact range (logic abuse, DoS, RCE) remains real.
+  - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html> · <https://cwe.mitre.org/data/definitions/502.html> · <https://community.owasp.org/vulnerabilities/Deserialization_of_untrusted_data>
+
 ## Variants
 
 - A model that is safe under the current model-file deserialization can still execute through the legacy Lambda layer, because that path reconstructs marshaled function bytecode as a separate deserialization risk and needs its own check.  _(merged 1 duplicate row(s))_
   - **Disproof:** Refuted if a model carrying the Lambda layer is rejected outright, or the marshaled bytecode is never reconstructed, or the target version no longer loads the legacy deserialization path at all.
   - Sources: <https://www.nccgroup.com/research/freddy-an-extension-for-automatically-identifying-deserialisation-issues-in-java-and-net-applications/> · <https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/generic-methodologies-and-resources/python/keras-model-deserialization-rce-and-gadget-hunting.md>
+- Deserialization can be driven to denial of service by constructing recursive object graphs that never terminate, or by requesting arrays of Integer.MAX_VALUE size, which can exhaust CPU or memory before elements are even read.  _(merged 1 duplicate row(s))_ _(unverified)_
+  - **Disproof:** A JVM or framework hardened with array-length caps, object-cache limits, and refusal to deserialize circular references mitigates memory exhaustion, and a final readObject() that throws prevents any deserialization at all. Yet non-hardened implementations remain exposed because backward compatibility with deployed code constrains these fixes.
+  - Sources: <https://community.owasp.org/vulnerabilities/Deserialization_of_untrusted_data>
 
 
 ## Hunt procedure
```

## 2026-10-31 06:41 — 40 diff lines
- items: 33 (supported 28), FP rules 1, chains 1, state researching
- still missing: fp_rules

```diff
--- deser@current
+++ deser@new
@@ -10,8 +10,8 @@
      python -m wks.skillgen -->
 
 > surface `web` · CWE CWE-502 · OWASP A08:2021
-> evidence: 33 items, 31 supported, 2 FP rules, 1 chains
-> maturity: **mature**
+> evidence: 33 items, 28 supported, 1 FP rules, 1 chains
+> maturity: **researching** — missing: fp_rules
 
 Data is reconstructed into a live object graph whose type system then invokes attacker-reachable behaviour.
 
@@ -44,7 +44,7 @@
 - A rejection message naming a specific class during DGC deserialization is direct evidence that JEP290 filtering is installed, and that observation is what downgrades a deserialization finding on the RMI service.  _(merged 1 duplicate row(s))_
   - **Disproof:** Refuted if the same class deserialises successfully with no exception on the DGC call, or if the server errors for an unrelated unmarshalling reason with no filter-specific message.
   - Sources: <https://httpwg.org/specs/rfc9530.html> · <https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/network-services-pentesting/1099-pentesting-java-rmi.md>
-- Base64-encoded fully-qualified Java class names appearing in request bodies to a GWT-RPC endpoint indicate the server deserializes attacker-named types.  _(merged 1 duplicate row(s))_
+- Base64-encoded fully-qualified Java class names appearing in request bodies to a GWT-RPC endpoint indicate the server deserializes attacker-named types.  _(merged 1 duplicate row(s))_ _(unverified)_
   - **Disproof:** If decoded blobs never contain a class descriptor, or every named-type payload is rejected by subtype validation before instantiation, the traffic is ordinary serialization without an exploitable sink.
   - Sources: <https://bishopfox.com/blog/gwt-unpatched-unauthenticated-java-deserialization-vulnerability> · <https://www.nccgroup.com/research/freddy-an-extension-for-automatically-identifying-deserialisation-issues-in-java-and-net-applications/>
 - Serialized data can be identified by language-specific signatures: PHP uses a human-readable string format with type letters and length indicators (e.g., O:4:"User":2:{s:4:"name":s:6:"carlos";s:10:"isLoggedIn":b:1;}), while Java serialization uses binary bytes beginning with ac ed (hex) / rO0 (base64), and a Content-type of application/x-java-serialized-object also indicates Java serialization.  _(merged 1 duplicate row(s))_
@@ -107,7 +107,7 @@
 
 ## False-positive rules (when to reject it)
 
-- A serialized blob whose integrity check you could not defeat is not an insecure-deserialization finding; the finding needs a modified blob accepted without a valid signature.  _(merged 1 duplicate row(s))_
+- A serialized blob whose integrity check you could not defeat is not an insecure-deserialization finding; the finding needs a modified blob accepted without a valid signature.  _(merged 1 duplicate row(s))_ _(unverified)_
   - **Disproof:** If the type field is resolved against a server-side allowlist so that your substituted class never instantiates, the report is a false positive about a class you cannot reach even though the blob parses, and the acceptance of the blob proves nothing.
   - Sources: <https://httpwg.org/specs/rfc9530.html> · <https://projectdiscovery.io/blog/nuclei-templates-november-2025> · <https://projectdiscovery.io/blog/ruby-saml-gitlab-auth-bypass>
 - An endpoint that accepts a serialised payload is not an insecure-deserialization RCE finding until a gadget chain reachable in the target's own classpath is proven: deserialization without an available gadget is a parse of attacker data, not code execution.  _(merged 1 duplicate row(s))_
@@ -122,7 +122,7 @@
 - Insecure deserialization is proven when a byte string the attacker controls names a class or reduction function in the payload and the server's own parser instantiates or invokes it, so the artifact is the parser's behaviour toward an attacker-named type rather than any parsed value appearing in a response.  _(merged 1 duplicate row(s))_
   - **Disproof:** The claim is false when the payload's class name is not on the server's classpath or module path, when the parser is configured with an allow-list - PHP's allowed_classes rejecting anything outside a named set, or an equivalent filter - so the object never becomes an instance of the named type, and when no side effect of that class is observable. It is also false for a format that carries no type identity at all, such as plain JSON parsed into a fixed data model, and false where the endpoint's input is not attacker-controlled in the serialized field at all.
   - Sources: <https://cwe.mitre.org/data/definitions/470.html> · <https://www.php.net/manual/en/function.unserialize.php>
-- The strongest deserialization artifact is a callback the server makes to a host the attacker chose during reconstruction of the attacker's object, because that request cannot be produced by anything the application legitimately does with the same input.  _(merged 1 duplicate row(s))_
+- The strongest deserialization artifact is a callback the server makes to a host the attacker chose during reconstruction of the attacker's object, because that request cannot be produced by anything the application legitimately does with the same input.  _(merged 1 duplicate row(s))_ _(unverified)_
   - **Disproof:** The claim is false when no callback arrives at the controlled host despite a payload naming reachable classes, and it cannot be produced at all in an environment with no egress - a fully air-gapped or egress-filtered target - in which case the negative is unverifiable rather than a clean pass. It is also false where the parser rejected the payload outright, where the callback host was unreachable for reasons unrelated to the payload, or where the application itself legitimately makes outbound requests to hosts the tester also controls, which makes the correlation meaningless.
   - Sources: <https://docs.python.org/3/library/pickle.html> · <https://cwe.mitre.org/data/definitions/470.html>
 - The triage signal that separates an exploitable deserialization sink from an inert one is whether the accepted format carries type identity: a format whose wire representation names a constructible type can be made to instantiate it, while a format limited to four primitive types and two structured types has no field an attacker can use to choose a class.  _(merged 1 duplicate row(s))_
```

## 2026-11-02 23:13 — 11 diff lines
- items: 33 (supported 28), FP rules 1, chains 1, state researching
- still missing: fp_rules

```diff
--- deser@current
+++ deser@new
@@ -158,7 +158,7 @@
 
 > Ordered prerequisites, the validation bar and the false-positive rules below are the authority: this block is the mechanics, those are the standard.
 ---
-Full class document: `domains/web/deser/knowledge/DIGEST.md` · retrieve more with `python -m wks.cli search "<query>" --class-id deser`
+Full class document: `skills/web/deser/DIGEST.md` · retrieve more with `python -m wks.cli search "<query>" --class-id deser`
 
 ---
 Runbook: [`HUNT.md`](HUNT.md) — every promoted technique mapped to an executable procedure with the observables to record.
```

## 2026-11-02 23:31 — 12 diff lines
- items: 33 (supported 28), FP rules 1, chains 1, state researching
- still missing: fp_rules

```diff
--- deser@current
+++ deser@new
@@ -5,7 +5,8 @@
 
 # Insecure Deserialization — hunting skill
 
-<!-- GENERATED from db/wks.db by wks/skillgen.py. DO NOT HAND-EDIT.
+<!-- GENERATED from db/wks.db — do not edit -->
+<!-- Generated by wks/skillgen.py. DO NOT HAND-EDIT.
      Edit the rows (or ingest better research) and re-run:
      python -m wks.skillgen -->
 
```
