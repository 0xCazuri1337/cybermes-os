# Methodology — Insecure Deserialization

> Derived from 19 verified items. Regenerate with `python -m wks.methodgen --class deser --apply`. Do not hand-edit: this file is a projection of the evidence, and edits are lost on the next cycle.

**Surface.** Data is reconstructed into a live object graph whose type system then invokes attacker-reachable behaviour.

**References.** CWE-502 · A08:2021

## 1. Preconditions

_Nothing below is reachable until these hold. Confirm each against the target before spending time on the technique._

**Jackson deserialization RCE needs default typing explicitly enabled plus a gadget chain assembled from libraries already on the application classpath.**

First establish that polymorphic typing is on: a plain ObjectMapper readValue call into a concrete POJO uses reflection and does not honour an attacker-named type. Then establish that a usable chain exists in whatever libraries the app already loads, because the combination of all classpath classes is what makes a chain constructible. Test in that order, since a negative on default typing makes every payload attempt meaningless. Fingerprint the libraries from error text, response headers or JS bundle dependency lists before choosing a chain.

- *Disproof:* If the endpoint rejects a payload naming a known gadget class with a subtype-validation error while default typing is off, and no request shape can turn typing on, the chain is unreachable.
- *Evidence:* high_confidence — [bishopfox.com](https://bishopfox.com/blog/gwt-unpatched-unauthenticated-java-deserialization-vulnerability); [snyk.io](https://snyk.io/blog/java-json-deserialization-problems-jackson-objectmapper/)

**The chain is bound to the session the payload was staged in, so the trigger request must carry that exact session ID or the deserializer loads a different file and the gadget fails silently.**

The chain is bound to the session the payload was staged in, so the trigger request must carry that exact session ID or the deserializer loads a different file and the gadget fails silently.

HackTricks reference: Php Rce Abusing Object Creation New Usd Get A Usd Get B (network-services-pentesting/pentesting-web/php-tricks-esp/php-rce-abusing-object-creation-new-usd_get-a-usd_get-b.md)

- *Disproof:* Refuted if the chain fires from a request with no matching session cookie, or with a different session ID, which would show the gadget does not depend on session continuity.
- *Evidence:* high_confidence — [bishopfox.com](https://bishopfox.com/blog/gwt-unpatched-unauthenticated-java-deserialization-vulnerability); [raw.githubusercontent.com](https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/network-services-pentesting/pentesting-web/php-tricks-esp/php-rce-abusing-object-creation-new-usd_get-a-usd_get-b.md)

**Gadget hunting on a model artefact starts with enumerating where its bytes came from, because the library's own URL-to-cache download helper means a cached file is attacker-influenceable input and every file in that cache is in scope.**

Gadget hunting on a model artefact starts with enumerating where its bytes came from, because the library's own URL-to-cache download helper means a cached file is attacker-influenceable input and every file in that cache is in scope.

HackTricks reference: Keras Model Deserialization Rce And Gadget Hunting (generic-methodologies-and-resources/python/keras-model-deserialization-rce-and-gadget-hunting.md)

- *Disproof:* Refuted if the cache location is populated only from integrity-verified sources with pinned hashes, so no attacker-controllable bytes can enter the deserialization path through it.
- *Evidence:* high_confidence — [nccgroup.com](https://www.nccgroup.com/research/freddy-an-extension-for-automatically-identifying-deserialisation-issues-in-java-and-net-applications/); [raw.githubusercontent.com](https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/generic-methodologies-and-resources/python/keras-model-deserialization-rce-and-gadget-hunting.md)

**Pickle-based model loading is only defensible when the unpickler itself enforces an allowlist, because opcodes execute during deserialization and no import-list scanner covers gadget classes that are not yet published.**

Pickle-based model loading is only defensible when the unpickler itself enforces an allowlist, because opcodes execute during deserialization and no import-list scanner covers gadget classes that are not yet published.

HackTricks reference: Keras Model Deserialization Rce And Gadget Hunting (generic-methodologies-and-resources/python/keras-model-deserialization-rce-and-gadget-hunting.md)

- *Disproof:* Refuted if unpickling a model artefact that imports something outside the reviewed allowlist raises an error instead of running, or if reconstruction touches plain data structures only and invokes nothing.
- *Evidence:* high_confidence — [nccgroup.com](https://www.nccgroup.com/research/freddy-an-extension-for-automatically-identifying-deserialisation-issues-in-java-and-net-applications/); [raw.githubusercontent.com](https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/generic-methodologies-and-resources/python/keras-model-deserialization-rce-and-gadget-hunting.md)

## 2. Reconnaissance signals

_What to look for while mapping the surface, and where each signal tells you the rest of the procedure is worth running._

**Base64-encoded fully-qualified Java class names appearing in request bodies to a GWT-RPC endpoint indicate the server deserializes attacker-named types.**

Watch request bodies for long Base64 blobs that decode to a serialized Java object containing class names and field descriptors; that is the transport, not yet the vulnerability. Corroborate with the server-side policy files: a GWT-RPC serialization policy containing the client-fields decorator marks at least one method that should be reachable for deserialization. Raise the confidence further when a deliberately invalid field name comes back as an IncompatibleRemoteServiceException naming the injected field, which proves the server instantiated the named class before validating.

- *Disproof:* If decoded blobs never contain a class descriptor, or every named-type payload is rejected by subtype validation before instantiation, the traffic is ordinary serialization without an exploitable sink.
- *Evidence:* high_confidence — [bishopfox.com](https://bishopfox.com/blog/gwt-unpatched-unauthenticated-java-deserialization-vulnerability); [nccgroup.com](https://www.nccgroup.com/research/freddy-an-extension-for-automatically-identifying-deserialisation-issues-in-java-and-net-applications/)

**A JEP290 bypass probe that comes back as IllegalArgumentException from the gadget payload, with the target rated non-vulnerable, is the record that the filter still holds for that gadget class.**

A JEP290 bypass probe that comes back as IllegalArgumentException from the gadget payload, with the target rated non-vulnerable, is the record that the filter still holds for that gadget class.

HackTricks reference: 1098/1099/1050 - Pentesting Java RMI - RMI-IIOP (network-services-pentesting/1099-pentesting-java-rmi.md)

- *Disproof:* Refuted if the gadget payload instead shows side effects or the object is reconstructed rather than rejected, which would show the filter did not catch that chain.
- *Evidence:* high_confidence — [httpwg.org](https://httpwg.org/specs/rfc9530.html); [raw.githubusercontent.com](https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/network-services-pentesting/1099-pentesting-java-rmi.md)

**A rejection message naming a specific class during DGC deserialization is direct evidence that JEP290 filtering is installed, and that observation is what downgrades a deserialization finding on the RMI service.**

A rejection message naming a specific class during DGC deserialization is direct evidence that JEP290 filtering is installed, and that observation is what downgrades a deserialization finding on the RMI service.

HackTricks reference: 1098/1099/1050 - Pentesting Java RMI - RMI-IIOP (network-services-pentesting/1099-pentesting-java-rmi.md)

- *Disproof:* Refuted if the same class deserialises successfully with no exception on the DGC call, or if the server errors for an unrelated unmarshalling reason with no filter-specific message.
- *Evidence:* high_confidence — [httpwg.org](https://httpwg.org/specs/rfc9530.html); [raw.githubusercontent.com](https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/network-services-pentesting/1099-pentesting-java-rmi.md)

## 3. Test sequence

_Concrete mutations to try. Each is written to be executable, not to be a description of the vulnerability._

**When a deserialization sink only hands the attacker a file-like path, the server-side request can be sourced from the object-construction primitives invoked during reconstruction - a wrapper-backed stream object reaches the network whenever its scheme handler is enabled.**

When a deserialization sink only hands the attacker a file-like path, the server-side request can be sourced from the object-construction primitives invoked during reconstruction - a wrapper-backed stream object reaches the network whenever its scheme handler is enabled.

HackTricks reference: Php Rce Abusing Object Creation New Usd Get A Usd Get B (network-services-pentesting/pentesting-web/php-tricks-esp/php-rce-abusing-object-creation-new-usd_get-a-usd_get-b.md)

- *Disproof:* Refuted if the scheme's stream wrapper is disabled on the target, or if the constructed object never opens the URL so no outbound request is issued from the reconstruction path.
- *Evidence:* high_confidence — [bishopfox.com](https://bishopfox.com/blog/gwt-unpatched-unauthenticated-java-deserialization-vulnerability); [raw.githubusercontent.com](https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/network-services-pentesting/pentesting-web/php-tricks-esp/php-rce-abusing-object-creation-new-usd_get-a-usd_get-b.md)

**The PHP deserialization surface is not confined to __destruct, because the engine invokes the serialization-time magic methods on attacker-chosen class names, so the hunt must first enumerate which of those hooks the reachable classes actually define.**

The PHP deserialization surface is not confined to __destruct, because the engine invokes the serialization-time magic methods on attacker-chosen class names, so the hunt must first enumerate which of those hooks the reachable classes actually define.

HackTricks reference: Deserialization (pentesting-web/deserialization/README.md)

- *Disproof:* Refuted if the unserialize call is restricted to an allowlist of classes none of which define the serialization-time magic methods, so no attacker-chosen hook ever runs.
- *Evidence:* high_confidence — [docs.python.org](https://docs.python.org/3/library/pickle.html); [raw.githubusercontent.com](https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/pentesting-web/deserialization/README.md)

**For .NET the exploitable condition in deserialization is attacker influence over which type gets instantiated, so the test is whether type resolution can be driven to a known dangerous gadget type, and the matching defence is a binder-level allowlist rather than any single serializer being called safe.**

For .NET the exploitable condition in deserialization is attacker influence over which type gets instantiated, so the test is whether type resolution can be driven to a known dangerous gadget type, and the matching defence is a binder-level allowlist rather than any single serializer being called safe.

HackTricks reference: Deserialization (pentesting-web/deserialization/README.md)

- *Disproof:* Refuted if type name handling is disabled end to end and no resolver honours an attacker-supplied type name, since then no dangerous gadget type can be selected however risky its properties are.
- *Evidence:* high_confidence — [docs.python.org](https://docs.python.org/3/library/pickle.html); [raw.githubusercontent.com](https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/pentesting-web/deserialization/README.md)

## 4. Validation

_How to prove the finding rather than infer it. A technique that cannot be validated must not be reported._

**A deserialization endpoint is confirmed only by a differential that shows an attacker-shaped object graph is deserialized and executed before authentication, which is why an unauthenticated remote attacker reaching arbitrary code execution on the vulnerable listener is the observation that closes the chain.**

Previous primitive hands over: reachability of an endpoint that deserializes caller-supplied bytes. Tenable's analysis of the VMware Aria Operations for Logs flaw states that an unauthenticated, remote attacker capable of accessing the instance could exploit the vulnerability to gain arbitrary code execution with root privileges, and separately notes that an attacker already holding a foothold could use such a flaw as part of post-compromise activity, which is the chaining case. The precondition the next link needs is a gadget or side-effect primitive in the deserialized graph rather than data alone, and Microsoft's position is blunt: the BinaryFormatter type is dangerous and is not recommended for data processing, and BinaryFormatter is insecure and can't be made secure. Observation that proves the segment: an unauthenticated request carrying a serialized object graph produces a process-level side effect (file write, child process) that a control payload without the graph does not.

- *Disproof:* If the endpoint authenticates before deserializing, or rejects the crafted graph with an integrity error before any object is constructed, or if the runtime has removed the formatter entirely, no side effect is observable and the deserialization segment does not hold.
- *Evidence:* high_confidence — [learn.microsoft.com](https://learn.microsoft.com/en-us/dotnet/standard/serialization/binaryformatter-security-guide); [tenable.com](https://www.tenable.com/blog/cve-2023-20864-vmware-aria-operations-for-logs-deserialization-vulnerability)

## 5. False-positive rejection

_The checks that eliminate the most common non-findings. Run these BEFORE reporting, not after a rejection._

**A serialized blob whose integrity check you could not defeat is not an insecure-deserialization finding; the finding needs a modified blob accepted without a valid signature.**

Discard the report when your tampered payload was rejected at the integrity or signature layer, since a deserializer never saw the attacker-controlled bytes and the gadget chain was never reached. The finding survives only when an edited blob with a changed type field, a changed field value, or an added object was accepted and produced an attacker-chosen effect, which means the check that should have bound the bytes to their origin is missing or bypassable.

- *Disproof:* If the type field is resolved against a server-side allowlist so that your substituted class never instantiates, the report is a false positive about a class you cannot reach even though the blob parses, and the acceptance of the blob proves nothing.
- *Evidence:* high_confidence — [httpwg.org](https://httpwg.org/specs/rfc9530.html); [projectdiscovery.io](https://projectdiscovery.io/blog/ruby-saml-gitlab-auth-bypass)

**An endpoint that accepts a serialised payload is not an insecure-deserialization RCE finding until a gadget chain reachable in the target's own classpath is proven: deserialization without an available gadget is a parse of attacker data, not code execution.**

Reachability is the whole test. Elastic's Log4j 2 research is the model: reproducing the deserialization allowlist bypass was necessary but not sufficient, because reaching command execution took two further things the library does not ship - a process that still deserializes the object stream, and a gadget library already sitting on that JVM. So inventory the target: if the deserializing process is not reachable from the endpoint, or the classpath contains no usable gadget, the parse produces a value and nothing more. The PHP side has the same shape: Sonar's phpBB research shows the vulnerability lives in the stream wrapper the runtime applies automatically, so a phar payload only matters where that wrapper sits on a reachable code path. Hunting value: this filters every generic serialized-gadget-reachable scanner hit - base64 blobs, RMI payloads, BinaryFormatter payloads, PHAR wrappers and node-serialize payloads arriving at a server with no exploitable class present.

- *Disproof:* It IS a finding when a real gadget is present and demonstrably executes - a gadget library on the classpath (commons-collections, spring, ysoserial-style chains), a PHPGGC gadget reachable from a phar stream wrapper, or a typed deserializer that instantiates the attacker-named class. Prove execution with an out-of-band or filesystem marker, not with a successful parse.
- *Evidence:* high_confidence — [elastic.co](https://www.elastic.co/security-labs/threat-command/java-deserialization-vulnerability-log4j-2); [sonarsource.com](https://www.sonarsource.com/blog/phpbb3-phar-deserialization-to-remote-code-execution/)

## Known bypasses

_No verified bypass items yet._ Derived from evidence only, so this section is empty rather than plausible.


## Chaining

_No verified chain_link items yet._ Derived from evidence only, so this section is empty rather than plausible.


## Impact

_No verified impact items yet._ Derived from evidence only, so this section is empty rather than plausible.


## Coverage gap

These stages have no verified evidence and are therefore absent above: Known bypasses, Chaining, Impact.
A procedure with a missing validation stage is not safe to act on — it produces findings rather than proofs.

---

*Generated from the evidence base. Where this file and the database disagree, the database is correct.*
