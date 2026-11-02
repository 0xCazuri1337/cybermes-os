# Insecure Deserialization

## Definition

Data is reconstructed into a live object graph whose type system then invokes attacker-reachable behaviour.

- **CWE:** CWE-502
- **OWASP:** A08:2021
- **Surface:** web
- **Aliases:** ["insecure deserialization", "deserialization", "pickle deserialization", "java deserialization gadget", "php object injection"]

Canonical home for `deser`. Rendered from `db/wks.db` by `methodology/scripts/build_taxonomy.py` — edit the rows, not this file.

## Root Cause

Not yet researched.

## Preconditions

**Jackson deserialization RCE needs default typing explicitly enabled plus a gadget chain assembled from libraries already on the application classpath.**

First establish that polymorphic typing is on: a plain ObjectMapper readValue call into a concrete POJO uses reflection and does not honour an attacker-named type. Then establish that a usable chain exists in whatever libraries the app already loads, because the combination of all classpath classes is what makes a chain constructible. Test in that order, since a negative on default typing makes every payload attempt meaningless. Fingerprint the libraries from error text, response headers or JS bundle dependency lists before choosing a chain.

*Disproof:* If the endpoint rejects a payload naming a known gadget class with a subtype-validation error while default typing is off, and no request shape can turn typing on, the chain is unreachable.

## Attack Surface

Surface: **web**.

The entry points and enabling conditions for this surface are enumerated under **Preconditions**; the observable signals are under **Detection**.

## Detection

**Base64-encoded fully-qualified Java class names appearing in request bodies to a GWT-RPC endpoint indicate the server deserializes attacker-named types.**

Watch request bodies for long Base64 blobs that decode to a serialized Java object containing class names and field descriptors; that is the transport, not yet the vulnerability. Corroborate with the server-side policy files: a GWT-RPC serialization policy containing the client-fields decorator marks at least one method that should be reachable for deserialization. Raise the confidence further when a deliberately invalid field name comes back as an IncompatibleRemoteServiceException naming the injected field, which proves the server instantiated the named class before validating.

*Disproof:* If decoded blobs never contain a class descriptor, or every named-type payload is rejected by subtype validation before instantiation, the traffic is ordinary serialization without an exploitable sink.

## Exploitation

Not yet researched.

## Variations

Not yet researched.

## Technology / Framework Considerations

Not yet researched.

## API Considerations

Not yet researched.

## Attack Chains

Not yet researched.

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

## Impact

Not yet researched.

## Related Bug Classes

Not yet researched.

## References

- **bishopfox.com** (writeup)
  - <https://bishopfox.com/blog/gwt-unpatched-unauthenticated-java-deserialization-vulnerability>
- **elastic.co** (writeup)
  - <https://www.elastic.co/security-labs/threat-command/java-deserialization-vulnerability-log4j-2>
- **httpwg.org** (docs)
  - <https://httpwg.org/specs/rfc9530.html>
- **learn.microsoft.com** (docs)
  - <https://learn.microsoft.com/en-us/dotnet/standard/serialization/binaryformatter-security-guide>
- **nccgroup.com** (report)
  - <https://www.nccgroup.com/research/freddy-an-extension-for-automatically-identifying-deserialisation-issues-in-java-and-net-applications/>
- **projectdiscovery.io** (writeup)
  - <https://projectdiscovery.io/blog/nuclei-templates-november-2025>
  - <https://projectdiscovery.io/blog/ruby-saml-gitlab-auth-bypass>
- **snyk.io** (writeup)
  - <https://snyk.io/blog/java-json-deserialization-problems-jackson-objectmapper/>
- **sonarsource.com** (writeup)
  - <https://www.sonarsource.com/blog/phpbb3-phar-deserialization-to-remote-code-execution/>
- **tenable.com** (research)
  - <https://www.tenable.com/blog/cve-2023-20864-vmware-aria-operations-for-logs-deserialization-vulnerability>

Every item above is gated on >= 2 distinct publisher hosts (`wks/quality.py`, rule R1). Publisher diversity, not citation count, is what makes these corroborated.
