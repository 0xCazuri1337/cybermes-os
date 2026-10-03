# Methodology — Insecure Deserialization

> Derived from 6 verified items. Regenerate with `python -m wks.methodgen --class deser --apply`. Do not hand-edit: this file is a projection of the evidence, and edits are lost on the next cycle.

**Surface.** Data is reconstructed into a live object graph whose type system then invokes attacker-reachable behaviour.

**References.** CWE-502 · A08:2021

## 1. Preconditions

_Nothing below is reachable until these hold. Confirm each against the target before spending time on the technique._

**Jackson deserialization RCE needs default typing explicitly enabled plus a gadget chain assembled from libraries already on the application classpath.**

First establish that polymorphic typing is on: a plain ObjectMapper readValue call into a concrete POJO uses reflection and does not honour an attacker-named type. Then establish that a usable chain exists in whatever libraries the app already loads, because the combination of all classpath classes is what makes a chain constructible. Test in that order, since a negative on default typing makes every payload attempt meaningless. Fingerprint the libraries from error text, response headers or JS bundle dependency lists before choosing a chain.

- *Disproof:* If the endpoint rejects a payload naming a known gadget class with a subtype-validation error while default typing is off, and no request shape can turn typing on, the chain is unreachable.
- *Evidence:* high_confidence — [bishopfox.com](https://bishopfox.com/blog/gwt-unpatched-unauthenticated-java-deserialization-vulnerability); [snyk.io](https://snyk.io/blog/java-json-deserialization-problems-jackson-objectmapper/)

## 2. Reconnaissance signals

_What to look for while mapping the surface, and where each signal tells you the rest of the procedure is worth running._

**Base64-encoded fully-qualified Java class names appearing in request bodies to a GWT-RPC endpoint indicate the server deserializes attacker-named types.**

Watch request bodies for long Base64 blobs that decode to a serialized Java object containing class names and field descriptors; that is the transport, not yet the vulnerability. Corroborate with the server-side policy files: a GWT-RPC serialization policy containing the client-fields decorator marks at least one method that should be reachable for deserialization. Raise the confidence further when a deliberately invalid field name comes back as an IncompatibleRemoteServiceException naming the injected field, which proves the server instantiated the named class before validating.

- *Disproof:* If decoded blobs never contain a class descriptor, or every named-type payload is rejected by subtype validation before instantiation, the traffic is ordinary serialization without an exploitable sink.
- *Evidence:* high_confidence — [bishopfox.com](https://bishopfox.com/blog/gwt-unpatched-unauthenticated-java-deserialization-vulnerability); [nccgroup.com](https://www.nccgroup.com/research/freddy-an-extension-for-automatically-identifying-deserialisation-issues-in-java-and-net-applications/)

## Test sequence

_No verified technique items yet._ Derived from evidence only, so this section is empty rather than plausible.


## 3. Validation

_How to prove the finding rather than infer it. A technique that cannot be validated must not be reported._

**A deserialization endpoint is confirmed only by a differential that shows an attacker-shaped object graph is deserialized and executed before authentication, which is why an unauthenticated remote attacker reaching arbitrary code execution on the vulnerable listener is the observation that closes the chain.**

Previous primitive hands over: reachability of an endpoint that deserializes caller-supplied bytes. Tenable's analysis of the VMware Aria Operations for Logs flaw states that an unauthenticated, remote attacker capable of accessing the instance could exploit the vulnerability to gain arbitrary code execution with root privileges, and separately notes that an attacker already holding a foothold could use such a flaw as part of post-compromise activity, which is the chaining case. The precondition the next link needs is a gadget or side-effect primitive in the deserialized graph rather than data alone, and Microsoft's position is blunt: the BinaryFormatter type is dangerous and is not recommended for data processing, and BinaryFormatter is insecure and can't be made secure. Observation that proves the segment: an unauthenticated request carrying a serialized object graph produces a process-level side effect (file write, child process) that a control payload without the graph does not.

- *Disproof:* If the endpoint authenticates before deserializing, or rejects the crafted graph with an integrity error before any object is constructed, or if the runtime has removed the formatter entirely, no side effect is observable and the deserialization segment does not hold.
- *Evidence:* high_confidence — [learn.microsoft.com](https://learn.microsoft.com/en-us/dotnet/standard/serialization/binaryformatter-security-guide); [tenable.com](https://www.tenable.com/blog/cve-2023-20864-vmware-aria-operations-for-logs-deserialization-vulnerability)

## 4. False-positive rejection

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

These stages have no verified evidence and are therefore absent above: Test sequence, Known bypasses, Chaining, Impact.
A procedure with a missing validation stage is not safe to act on — it produces findings rather than proofs.

---

*Generated from the evidence base. Where this file and the database disagree, the database is correct.*
