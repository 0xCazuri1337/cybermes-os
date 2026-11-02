# Insecure Deserialization

## Definition

Data is reconstructed into a live object graph whose type system then invokes attacker-reachable behaviour.

- **CWE:** CWE-502
- **OWASP:** A08:2021
- **Surface:** web
- **Aliases:** ["insecure deserialization", "deserialization", "pickle deserialization", "java deserialization gadget", "php object injection"]

Canonical home for `deser`. Rendered from `db/wks.db` by `tools/taxonomy/build_taxonomy.py` — edit the rows, not this file.

## Root Cause

Not yet researched.

## Preconditions

**Jackson deserialization RCE needs default typing explicitly enabled plus a gadget chain assembled from libraries already on the application classpath.**

First establish that polymorphic typing is on: a plain ObjectMapper readValue call into a concrete POJO uses reflection and does not honour an attacker-named type. Then establish that a usable chain exists in whatever libraries the app already loads, because the combination of all classpath classes is what makes a chain constructible. Test in that order, since a negative on default typing makes every payload attempt meaningless. Fingerprint the libraries from error text, response headers or JS bundle dependency lists before choosing a chain.

*Disproof:* If the endpoint rejects a payload naming a known gadget class with a subtype-validation error while default typing is off, and no request shape can turn typing on, the chain is unreachable.

**Gadget hunting on a model artefact starts with enumerating where its bytes came from, because the library's own URL-to-cache download helper means a cached file is attacker-influenceable input and every file in that cache is in scope.**

Gadget hunting on a model artefact starts with enumerating where its bytes came from, because the library's own URL-to-cache download helper means a cached file is attacker-influenceable input and every file in that cache is in scope.

HackTricks reference: Keras Model Deserialization Rce And Gadget Hunting (generic-methodologies-and-resources/python/keras-model-deserialization-rce-and-gadget-hunting.md)

*Disproof:* Refuted if the cache location is populated only from integrity-verified sources with pinned hashes, so no attacker-controllable bytes can enter the deserialization path through it.

**Pickle-based model loading is only defensible when the unpickler itself enforces an allowlist, because opcodes execute during deserialization and no import-list scanner covers gadget classes that are not yet published.**

Pickle-based model loading is only defensible when the unpickler itself enforces an allowlist, because opcodes execute during deserialization and no import-list scanner covers gadget classes that are not yet published.

HackTricks reference: Keras Model Deserialization Rce And Gadget Hunting (generic-methodologies-and-resources/python/keras-model-deserialization-rce-and-gadget-hunting.md)

*Disproof:* Refuted if unpickling a model artefact that imports something outside the reviewed allowlist raises an error instead of running, or if reconstruction touches plain data structures only and invokes nothing.

**The chain is bound to the session the payload was staged in, so the trigger request must carry that exact session ID or the deserializer loads a different file and the gadget fails silently.**

The chain is bound to the session the payload was staged in, so the trigger request must carry that exact session ID or the deserializer loads a different file and the gadget fails silently.

HackTricks reference: Php Rce Abusing Object Creation New Usd Get A Usd Get B (network-services-pentesting/pentesting-web/php-tricks-esp/php-rce-abusing-object-creation-new-usd_get-a-usd_get-b.md)

*Disproof:* Refuted if the chain fires from a request with no matching session cookie, or with a different session ID, which would show the gadget does not depend on session continuity.

## Attack Surface

Surface: **web**.

The entry points and enabling conditions for this surface are enumerated under **Preconditions**; the observable signals are under **Detection**.

## Detection

**Base64-encoded fully-qualified Java class names appearing in request bodies to a GWT-RPC endpoint indicate the server deserializes attacker-named types.**

Watch request bodies for long Base64 blobs that decode to a serialized Java object containing class names and field descriptors; that is the transport, not yet the vulnerability. Corroborate with the server-side policy files: a GWT-RPC serialization policy containing the client-fields decorator marks at least one method that should be reachable for deserialization. Raise the confidence further when a deliberately invalid field name comes back as an IncompatibleRemoteServiceException naming the injected field, which proves the server instantiated the named class before validating.

*Disproof:* If decoded blobs never contain a class descriptor, or every named-type payload is rejected by subtype validation before instantiation, the traffic is ordinary serialization without an exploitable sink.

**A rejection message naming a specific class during DGC deserialization is direct evidence that JEP290 filtering is installed, and that observation is what downgrades a deserialization finding on the RMI service.**

A rejection message naming a specific class during DGC deserialization is direct evidence that JEP290 filtering is installed, and that observation is what downgrades a deserialization finding on the RMI service.

HackTricks reference: 1098/1099/1050 - Pentesting Java RMI - RMI-IIOP (network-services-pentesting/1099-pentesting-java-rmi.md)

*Disproof:* Refuted if the same class deserialises successfully with no exception on the DGC call, or if the server errors for an unrelated unmarshalling reason with no filter-specific message.

**A JEP290 bypass probe that comes back as IllegalArgumentException from the gadget payload, with the target rated non-vulnerable, is the record that the filter still holds for that gadget class.**

A JEP290 bypass probe that comes back as IllegalArgumentException from the gadget payload, with the target rated non-vulnerable, is the record that the filter still holds for that gadget class.

HackTricks reference: 1098/1099/1050 - Pentesting Java RMI - RMI-IIOP (network-services-pentesting/1099-pentesting-java-rmi.md)

*Disproof:* Refuted if the gadget payload instead shows side effects or the object is reconstructed rather than rejected, which would show the filter did not catch that chain.

**A deserialization endpoint is only proven exposed when a payload naming a class the application never intends to construct is accepted and instantiated; a request answered with a class-rejection error or a warning naming the disallowed class is a control working, not a finding.**

Modern runtimes ship the mitigation, so the disproof is what most payloads produce and it needs to be read correctly rather than counted as a near-miss. PHP's unserialize accepts an allow-list of permitted class names, and when the payload names a class outside it the object is materialised as __PHP_Incomplete_Class - a deliberately inert placeholder that exposes no methods - so the gadget never runs and the call chain ends there. The evidentiary move a hunter makes is to demonstrate the boundary in both directions: a payload naming an allowed class is accepted, one naming a class outside the set is refused, and that pair shows the filter is genuinely enforced rather than the parser simply failing on malformed input. A single rejected payload proves nothing either way - it is equally consistent with a working allow-list and with an endpoint that never deserializes that field.

*Disproof:* The claim that an endpoint is exposed is false where the parser enforces an allow-list and rejects the attacker's class, where the endpoint accepts only a self-describing format with no class identity such as JSON bound to a fixed model, or where the deserialization happens only over data the client never supplies. It is equally false where the rejection observed is a parse error on malformed input rather than a class rejection, since that shows nothing about whether classes are filtered - and a clean rejection log is not evidence of exposure under any reading.

**Insecure deserialization is proven when a byte string the attacker controls names a class or reduction function in the payload and the server's own parser instantiates or invokes it, so the artifact is the parser's behaviour toward an attacker-named type rather than any parsed value appearing in a response.**

The mechanism is that a native serializer format carries type identity inside the payload, so unmarshalling is reflection: the wire data decides which class the runtime constructs. CWE-470 names exactly this - external input selects which class to instantiate or which method to invoke - which is why the finding cannot be argued from the schema of the request alone. A hunter produces the artifact by naming a class that exists on the server but is never intended to be constructible from user data, and watching for that class's side effect: a file written, a process spawned, a lookup issued, an outbound callback. The class must be present on the classpath, so a name the server cannot load is a false negative and a name it can load but never reaches from that parameter is a false positive; check reachability, then check effect, in that order.

*Disproof:* The claim is false when the payload's class name is not on the server's classpath or module path, when the parser is configured with an allow-list - PHP's allowed_classes rejecting anything outside a named set, or an equivalent filter - so the object never becomes an instance of the named type, and when no side effect of that class is observable. It is also false for a format that carries no type identity at all, such as plain JSON parsed into a fixed data model, and false where the endpoint's input is not attacker-controlled in the serialized field at all.

**The triage signal that separates an exploitable deserialization sink from an inert one is whether the accepted format carries type identity: a format whose wire representation names a constructible type can be made to instantiate it, while a format limited to four primitive types and two structured types has no field an attacker can use to choose a class.**

This is the check that saves the most wasted probing, because most endpoints that accept 'serialized data' accept something that cannot instantiate anything. JSON defines a closed set of types and no grammar production that names a class, so a parser binding it to a fixed model has nothing to reflect over - passing attacker JSON produces plain maps and lists no matter what strings appear inside them. A native runtime serializer is the opposite: the payload carries the type, and reconstruction dispatches on it. So the hunter reads the Content-Type and the endpoint's parser binding before constructing a single gadget, and treats a 'deserialization' endpoint carrying only JSON as safe from this class unless the application separately passes the parsed structure to something that reflects over it. When a framework supports both, the finding stands on the format the endpoint actually accepts, not the one it could accept.

*Disproof:* The claim that a JSON-only endpoint is not a deserialization sink is false when the application feeds the parsed JSON into a second stage that does reflect - passing it to a dynamic invoker, a template engine, a query builder that maps keys to operators, or a polymorphic binder that honours type-discriminator fields - because the type selection then happens one layer down rather than at the parser. It is also false when the endpoint silently accepts a non-JSON native format on the same parameter despite a JSON-looking content type, which is why the accepted format must be observed on the wire rather than assumed from documentation.

**The strongest deserialization artifact is a callback the server makes to a host the attacker chose during reconstruction of the attacker's object, because that request cannot be produced by anything the application legitimately does with the same input.**

Reconstruction is attacker-observable in a way ordinary parsing is not: the class named in the payload runs initialisation code, and a gadget class will resolve a name from the payload as a function to call. The proof is therefore out of band - a unique token in the payload appears in a DNS lookup, an HTTP request, or an inbound connection at a host the tester controls, which timestamps the event to the single request that carried it. This is the only artifact that survives the objection that a payload merely parsed without harm, because the callback is the harm, and it does not require the tester to guess which class is present: many gadget chains will do. Send one request, watch for the callback, and correlate it by token; a failed callback means the chain is wrong, not that the endpoint is safe.

*Disproof:* The claim is false when no callback arrives at the controlled host despite a payload naming reachable classes, and it cannot be produced at all in an environment with no egress - a fully air-gapped or egress-filtered target - in which case the negative is unverifiable rather than a clean pass. It is also false where the parser rejected the payload outright, where the callback host was unreachable for reasons unrelated to the payload, or where the application itself legitimately makes outbound requests to hosts the tester also controls, which makes the correlation meaningless.

## Exploitation

**Making an assumption that the code in the deserialized object is valid is dangerous and can enable exploitation.**

DoS: Resource Consumption (CPU) 
 
 
 
 
 
 
 Scope: Availability 
 
 
 
 If a function is making an assumption on when to terminate, based on a sentry in a string, it could easily never terminate. 
 
 
 
 
 
 
 
 
 Varies by Context 
 
 
 
 
 
 
 Scope: Other 
 
 
 
 The consequences can vary widely, because it depends on which objects or methods are being deserialized, and how they are used. Making an assumption that the code in the deserialized object is valid is dangerous and can enable exploitation. One example is attackers using gadget chains to perform unauthorized actions, such as generating a shell. 
 
 
 
 
 
 
 
 
 

 

 
 
 
 
 Potential Mitigations 
 
 
 
 
 
 
 Phase(s) 
 Mitigation 
 
 
 
 
 
 
 
 Architecture and Design; Implementation 
 
 
 
 
 
 If available, use the signing/sealing features of the programming language to assure that deserialized data has not been tainted. For e

*Disproof:* This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Making an assumption that the code in the deserialized object is valid is dangerous and ca".

**Avoid having unnecessary types or gadgets (a sequence of instances and method invocations that can self-execute during the deserialization process, often found in libraries) available that can be leveraged for malicious ends.**

ntation 
 
 
 
 
 
 
 Make fields transient to protect them from deserialization. 
 An attempt to serialize and then deserialize a class containing transient fields will result in NULLs where the transient data should be. This is an excellent way to prevent time, environment-based, or sensitive variables from being carried over and used improperly. 
 
 
 
 
 
 
 
 
 
 
 Implementation 
 
 
 
 
 
 Avoid having unnecessary types or gadgets (a sequence of instances and method invocations that can self-execute during the deserialization process, often found in libraries) available that can be leveraged for malicious ends. This limits the potential for unintended or unauthorized types and gadgets to be leveraged by the attacker. Add only acceptable classes to an allowlist. Note: new gadgets are constantly being discovered, so this alone is not a sufficient mitigation. 
 
 
 
 
 
 
 
 
 
 Architecture and Design; Implementation 
 
 
 
 
 
 Employ cryptography of the data or code for protection. However, it's importa

*Disproof:* This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Avoid having unnecessary types or gadgets (a sequence of instances and method invocations ".

**Serialization and deserialization refer to the process of taking program-internal object-related data, packaging it in a way that allows the data to be externally stored or transferred ("serialization"), then extracting the serialized data to reconstruct the original object ("deserialization").**

ed Code Resources 
 
 
 
 
 
 
 
 
 
 
 
 
 
 
 
 
 
 
 Relevant to the view "Architectural Concepts" (View-1008)
 
 
 
 
 
 
 Nature 
 Type 
 ID 
 Name 
 
 
 
 
 
 
 
 
 MemberOf 
 
 
 Category - a CWE entry that contains a set of other entries that share a common characteristic. 
 
 
 
 1019 
 
 
 
 Validate Inputs 
 
 
 
 
 
 
 
 
 
 
 
 
 
 
 
 
 

 

 
 
 
 
 Background Details 
 
 
 
 
 
 
 Serialization and deserialization refer to the process of taking program-internal object-related data, packaging it in a way that allows the data to be externally stored or transferred ("serialization"), then extracting the serialized data to reconstruct the original object ("deserialization").
 
 
 
 
 
 
 

 

 
 
 
 
 Modes
 Of Introduction 
 
 
 The different Modes of Introduction provide information
 about how and when this
 weakness may be introduced. The Phase identifies a point in the life cycle at which
 introduction
 may occur, while the Note provides a typical scenario related to introduction during the
 given
 phase. 
 
 
 Phase 
 Note 
 
 
 
 
 Architecture and Design 
 OMI

*Disproof:* This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Serialization and deserialization refer to the process of taking program-internal object-r".

**Serialization and deserialization refer to the process of taking program-internal object-related data, packaging it in a way that allows the data to be externally stored or transferred ("serialization"), then extracting the serialized data to reconstruct the original object ("deserialization").**

ed Code Resources 
 
 
 
 
 
 
 
 
 
 
 
 
 
 
 
 
 
 
 Relevant to the view "Architectural Concepts" (View-1008)
 
 
 
 
 
 
 Nature 
 Type 
 ID 
 Name 
 
 
 
 
 
 
 
 
 MemberOf 
 
 
 Category - a CWE entry that contains a set of other entries that share a common characteristic. 
 
 
 
 1019 
 
 
 
 Validate Inputs 
 
 
 
 
 
 
 
 
 
 
 
 
 
 
 
 
 

 

 
 
 
 
 Background Details 
 
 
 
 
 
 
 Serialization and deserialization refer to the process of taking program-internal object-related data, packaging it in a way that allows the data to be externally stored or transferred ("serialization"), then extracting the serialized data to reconstruct the original object ("deserialization").
 
 
 
 
 
 
 

 

 
 
 
 
 Modes
 Of Introduction 
 
 
 The different Modes of Introduction provide information
 about how and when this
 weakness may be introduced. The Phase identifies a point in the life cycle at which
 introduction
 may occur, while the Note provides a typical scenario related to introduction during the
 given
 phase. 
 
 
 Phase 
 Note 
 
 
 
 
 Architecture and Design 
 OMI

*Disproof:* This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Serialization and deserialization refer to the process of taking program-internal object-r".

**This code does not attempt to verify the source or contents of the file before deserializing it.**

Example 1 
 
 
 This code snippet deserializes an object from a file and uses it as a UI button: 
 
 
 
 
 
 
 
 
 
 
 (bad code) 
 
 
 Example Language: Java 
 
 
 
 
 
 try { File file = new File("object.obj"); ObjectInputStream in = new ObjectInputStream(new FileInputStream(file)); javax.swing.JButton button = (javax.swing.JButton) in.readObject(); in.close(); } 
 
 
 
 
 
 
 
 
 
 
 
 This code does not attempt to verify the source or contents of the file before deserializing it. An attacker may be able to replace the intended file with a file that contains arbitrary malicious code which will be executed when the button is pressed. 
 
 
 
 
 To mitigate this, explicitly define final readObject() to prevent deserialization. An example of this is: 
 
 
 
 
 
 
 
 
 (good code) 
 
 
 Example Language: Java 
 
 
 
 
 
 private final void readObject(ObjectInputStream in) throw

*Disproof:* This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "This code does not attempt to verify the source or contents of the file before deserializi".

**Since Pickle allows objects to define the process for how they should be unpickled, the attacker can direct the unpickle process to call Popen in the subprocess module and execute /bin/sh.**

fortunately, the code does not verify that the incoming data is legitimate. An attacker can construct a illegitimate, serialized object "AuthToken" that instantiates one of Python's subprocesses to execute arbitrary commands. For instance,the attacker could construct a pickle that leverages Python's subprocess module, which spawns new processes and includes a number of arguments for various uses. Since Pickle allows objects to define the process for how they should be unpickled, the attacker can direct the unpickle process to call Popen in the subprocess module and execute /bin/sh. 
 
 
 
 
 
 
 
 
 
 

 

 
 
 
 Selected Observed
 Examples 
 
 
 Note: this is a curated list of examples for users to understand the variety of ways in which this
 weakness can be introduced. It is not a complete list of all CVEs that are related to this CWE entry. 
 
 
 
 
 Reference 
 Description 
 
 
 
 
 
 
 
 CVE-2024-37052 
 
 
 
 
 insecure deserialization in platform for managing AI/ML

*Disproof:* This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Since Pickle allows objects to define the process for how they should be unpickled, the at".

**Deserialization issue in commonly-used Java library allows remote execution.**

deserialization of untrusted YAML data in dashboard for data query and visualization of Elasticsearch data 
 
 
 
 
 
 
 
 CVE-2024-9314 
 
 
 
 
 PHP object injection in WordPress plugin for AI-based SEO 
 
 
 
 
 
 
 
 CVE-2019-12799 
 
 
 
 
 chain: bypass of untrusted deserialization issue ( CWE-502 ) by using an assumed-trusted class ( CWE-183 ) 
 
 
 
 
 
 
 
 CVE-2015-8103 
 
 
 
 
 Deserialization issue in commonly-used Java library allows remote execution. 
 
 
 
 
 
 
 
 CVE-2015-4852 
 
 
 
 
 Deserialization issue in commonly-used Java library allows remote execution. 
 
 
 
 
 
 
 
 CVE-2013-1465 
 
 
 
 
 Use of PHP unserialize function on untrusted input allows attacker to modify application configuration. 
 
 
 
 
 
 
 
 CVE-2012-3527 
 
 
 
 
 Use of PHP unserialize function on untrusted input in content management system might allow code e

*Disproof:* This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Deserialization issue in commonly-used Java library allows remote execution.".

**The PHP deserialization surface is not confined to __destruct, because the engine invokes the serialization-time magic methods on attacker-chosen class names, so the hunt must first enumerate which of those hooks the reachable classes actually define.**

The PHP deserialization surface is not confined to __destruct, because the engine invokes the serialization-time magic methods on attacker-chosen class names, so the hunt must first enumerate which of those hooks the reachable classes actually define.

HackTricks reference: Deserialization (pentesting-web/deserialization/README.md)

*Disproof:* Refuted if the unserialize call is restricted to an allowlist of classes none of which define the serialization-time magic methods, so no attacker-chosen hook ever runs.

**When a deserialization sink only hands the attacker a file-like path, the server-side request can be sourced from the object-construction primitives invoked during reconstruction - a wrapper-backed stream object reaches the network whenever its scheme handler is enabled.**

When a deserialization sink only hands the attacker a file-like path, the server-side request can be sourced from the object-construction primitives invoked during reconstruction - a wrapper-backed stream object reaches the network whenever its scheme handler is enabled.

HackTricks reference: Php Rce Abusing Object Creation New Usd Get A Usd Get B (network-services-pentesting/pentesting-web/php-tricks-esp/php-rce-abusing-object-creation-new-usd_get-a-usd_get-b.md)

*Disproof:* Refuted if the scheme's stream wrapper is disabled on the target, or if the constructed object never opens the URL so no outbound request is issued from the reconstruction path.

**For .NET the exploitable condition in deserialization is attacker influence over which type gets instantiated, so the test is whether type resolution can be driven to a known dangerous gadget type, and the matching defence is a binder-level allowlist rather than any single serializer being called safe.**

For .NET the exploitable condition in deserialization is attacker influence over which type gets instantiated, so the test is whether type resolution can be driven to a known dangerous gadget type, and the matching defence is a binder-level allowlist rather than any single serializer being called safe.

HackTricks reference: Deserialization (pentesting-web/deserialization/README.md)

*Disproof:* Refuted if type name handling is disabled end to end and no resolver honours an attacker-supplied type name, since then no dangerous gadget type can be selected however risky its properties are.

## Variations

**A model that is safe under the current model-file deserialization can still execute through the legacy Lambda layer, because that path reconstructs marshaled function bytecode as a separate deserialization risk and needs its own check.**

A model that is safe under the current model-file deserialization can still execute through the legacy Lambda layer, because that path reconstructs marshaled function bytecode as a separate deserialization risk and needs its own check.

HackTricks reference: Keras Model Deserialization Rce And Gadget Hunting (generic-methodologies-and-resources/python/keras-model-deserialization-rce-and-gadget-hunting.md)

*Disproof:* Refuted if a model carrying the Lambda layer is rejected outright, or the marshaled bytecode is never reconstructed, or the target version no longer loads the legacy deserialization path at all.

## Technology / Framework Considerations

Not yet researched.

## API Considerations

Not yet researched.

## Attack Chains

- `chain.deser.auto.01` — deser: observe, exercise, confirm (goal: `Establish, exercise and confirm a deser condition on an authorised target without relying on anyone else's data.`)

## Real-World Examples

Not yet researched.

## Common False Positives

**An endpoint that accepts a serialised payload is not an insecure-deserialization RCE finding until a gadget chain reachable in the target's own classpath is proven: deserialization without an available gadget is a parse of attacker data, not code execution.**

Reachability is the whole test. Elastic's Log4j 2 research is the model: reproducing the deserialization allowlist bypass was necessary but not sufficient, because reaching command execution took two further things the library does not ship - a process that still deserializes the object stream, and a gadget library already sitting on that JVM. So inventory the target: if the deserializing process is not reachable from the endpoint, or the classpath contains no usable gadget, the parse produces a value and nothing more. The PHP side has the same shape: Sonar's phpBB research shows the vulnerability lives in the stream wrapper the runtime applies automatically, so a phar payload only matters where that wrapper sits on a reachable code path. Hunting value: this filters every generic serialized-gadget-reachable scanner hit - base64 blobs, RMI payloads, BinaryFormatter payloads, PHAR wrappers and node-serialize payloads arriving at a server with no exploitable class present.

*Disproof:* It IS a finding when a real gadget is present and demonstrably executes - a gadget library on the classpath (commons-collections, spring, ysoserial-style chains), a PHPGGC gadget reachable from a phar stream wrapper, or a typed deserializer that instantiates the attacker-named class. Prove execution with an out-of-band or filesystem marker, not with a successful parse.

**A serialized blob whose integrity check you could not defeat is not an insecure-deserialization finding; the finding needs a modified blob accepted without a valid signature.**

Discard the report when your tampered payload was rejected at the integrity or signature layer, since a deserializer never saw the attacker-controlled bytes and the gadget chain was never reached. The finding survives only when an edited blob with a changed type field, a changed field value, or an added object was accepted and produced an attacker-chosen effect, which means the check that should have bound the bytes to their origin is missing or bypassable.

*Disproof:* If the type field is resolved against a server-side allowlist so that your substituted class never instantiates, the report is a false positive about a class you cannot reach even though the blob parses, and the acceptance of the blob proves nothing.

## Validation

**A deserialization endpoint is confirmed only by a differential that shows an attacker-shaped object graph is deserialized and executed before authentication, which is why an unauthenticated remote attacker reaching arbitrary code execution on the vulnerable listener is the observation that closes the chain.**

Previous primitive hands over: reachability of an endpoint that deserializes caller-supplied bytes. Tenable's analysis of the VMware Aria Operations for Logs flaw states that an unauthenticated, remote attacker capable of accessing the instance could exploit the vulnerability to gain arbitrary code execution with root privileges, and separately notes that an attacker already holding a foothold could use such a flaw as part of post-compromise activity, which is the chaining case. The precondition the next link needs is a gadget or side-effect primitive in the deserialized graph rather than data alone, and Microsoft's position is blunt: the BinaryFormatter type is dangerous and is not recommended for data processing, and BinaryFormatter is insecure and can't be made secure. Observation that proves the segment: an unauthenticated request carrying a serialized object graph produces a process-level side effect (file write, child process) that a control payload without the graph does not.

*Disproof:* If the endpoint authenticates before deserializing, or rejects the crafted graph with an integrity error before any object is constructed, or if the runtime has removed the formatter entirely, no side effect is observable and the deserialization segment does not hold.

**To decide this case, observe: Discard the report when your tampered payload was rejected at the integrity or signature layer, since a deserializer never saw the attacker-controlled bytes and the gadget chain was never reached.**

Derived from deser.fprule.integrity_rejected_blob_never_reaches_the_deserializer, which states the false-positive boundary for this class. The observable above is what separates a real finding from the pattern that only looks like one. A hunter who cannot produce this observation in a request/response pair does not have a finding yet.

*Disproof:* This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (deser.fprule.integrity_rejected_blob_never_reaches_the_deserializer) states the full boundary.

**To decide this case, observe: whole test. Elastic's Log4j 2 research is the model: reproducing the deserialization allowlist bypass was necessary but not sufficient, because reaching command execution took two further things the library does not ship - a process that still deserializes the object stream, and a gadget library already sitting on that JVM. So inventory the target: if the deserializing process**

Derived from deser.fp_rule.serialization_endpoint_without_a_gadget_chain_is_not_rce, which states the false-positive boundary for this class. The observable above is what separates a real finding from the pattern that only looks like one. A hunter who cannot produce this observation in a request/response pair does not have a finding yet.

*Disproof:* This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (deser.fp_rule.serialization_endpoint_without_a_gadget_chain_is_not_rce) states the full boundary.

**A discovered RMI method that merely calls the remote application's own execute routine proves nothing about deserialization, so the tester first sends a harmless canary to a non-primitive parameter and escalates only after unfiltered deserialization with a gadget chain on the server classpath is confirmed.**

A discovered RMI method that merely calls the remote application's own execute routine proves nothing about deserialization, so the tester first sends a harmless canary to a non-primitive parameter and escalates only after unfiltered deserialization with a gadget chain on the server classpath is confirmed.

HackTricks reference: 1098/1099/1050 - Pentesting Java RMI - RMI-IIOP (network-services-pentesting/1099-pentesting-java-rmi.md)

*Disproof:* Refuted if the canary produces deserialization-related behaviour identical to a filtered payload, or if a filter rejects the payload class before any gadget resolves.

## Impact

Not yet researched.

## Related Bug Classes

Not yet researched.

## References

- **bishopfox.com** (research)
  - <https://bishopfox.com/blog/gwt-unpatched-unauthenticated-java-deserialization-vulnerability>
- **cheatsheetseries.owasp.org** (taxonomy)
  - <https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html>
- **cwe.mitre.org** (writeup)
  - <https://cwe.mitre.org/data/definitions/470.html>
  - <https://cwe.mitre.org/data/definitions/502.html>
- **docs.python.org** (research)
  - <https://docs.python.org/3/library/pickle.html>
- **elastic.co** (writeup)
  - <https://www.elastic.co/security-labs/threat-command/java-deserialization-vulnerability-log4j-2>
- **httpwg.org** (docs)
  - <https://httpwg.org/specs/rfc9530.html>
- **learn.microsoft.com** (docs)
  - <https://learn.microsoft.com/en-us/dotnet/standard/serialization/binaryformatter-security-guide>
- **nccgroup.com** (research)
  - <https://www.nccgroup.com/research/freddy-an-extension-for-automatically-identifying-deserialisation-issues-in-java-and-net-applications/>
- **nodejs.org** (writeup)
  - <https://nodejs.org/api/v8.html>
- **php.net** (writeup)
  - <https://www.php.net/manual/en/function.unserialize.php>
- **projectdiscovery.io** (writeup)
  - <https://projectdiscovery.io/blog/nuclei-templates-november-2025>
  - <https://projectdiscovery.io/blog/ruby-saml-gitlab-auth-bypass>
- **raw.githubusercontent.com** (reference)
  - <https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/generic-methodologies-and-resources/python/keras-model-deserialization-rce-and-gadget-hunting.md>
  - <https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/network-services-pentesting/1099-pentesting-java-rmi.md>
  - <https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/network-services-pentesting/pentesting-web/php-tricks-esp/php-rce-abusing-object-creation-new-usd_get-a-usd_get-b.md>
  - <https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/pentesting-web/deserialization/README.md>
- **rfc-editor.org** (writeup)
  - <https://www.rfc-editor.org/rfc/rfc8259.html>
- **snyk.io** (writeup)
  - <https://snyk.io/blog/java-json-deserialization-problems-jackson-objectmapper/>
- **sonarsource.com** (writeup)
  - <https://www.sonarsource.com/blog/phpbb3-phar-deserialization-to-remote-code-execution/>
- **tenable.com** (research)
  - <https://www.tenable.com/blog/cve-2023-20864-vmware-aria-operations-for-logs-deserialization-vulnerability>

Every item above is gated on >= 2 distinct publisher hosts (`wks/quality.py`, rule R1). Publisher diversity, not citation count, is what makes these corroborated.
