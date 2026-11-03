# Methodology — Insecure Deserialization

> Derived from 28 verified items. Regenerate with `python -m wks.methodgen --class deser --apply`. Do not hand-edit: this file is a projection of the evidence, and edits are lost on the next cycle.

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

**CWE-502 defines insecure deserialization as a product deserializing untrusted data without sufficiently ensuring that the resulting data will be valid; malformed or unexpected data can therefore abuse application logic, deny service, or execute arbitrary code.**

The weakness applies to C, C++, Java, Python, Ruby, and any language with native object serialization, across any operating platform. OWASP rates it High severity with Medium likelihood of exploit. The core danger is that deserialization reconstructs full objects including private fields from attacker-controlled bytes, and many languages invoke magic methods automatically during deserialization (PortSwigger).

- *Disproof:* A deserializer that only accepts data it generated itself, protected by a MAC or signature verified BEFORE deserialization, is not exploitable: the attacker cannot fabricate valid bytes. Without any integrity control, however, the attacker's bytes are trusted.
- *Evidence:* high_confidence — [community.owasp.org](https://community.owasp.org/vulnerabilities/Deserialization_of_untrusted_data); [cwe.mitre.org](https://cwe.mitre.org/data/definitions/502.html)

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

**A JEP290 bypass probe that comes back as IllegalArgumentException from the gadget payload, with the target rated non-vulnerable, is the record that the filter still holds for that gadget class.**

A JEP290 bypass probe that comes back as IllegalArgumentException from the gadget payload, with the target rated non-vulnerable, is the record that the filter still holds for that gadget class.

HackTricks reference: 1098/1099/1050 - Pentesting Java RMI - RMI-IIOP (network-services-pentesting/1099-pentesting-java-rmi.md)

- *Disproof:* Refuted if the gadget payload instead shows side effects or the object is reconstructed rather than rejected, which would show the filter did not catch that chain.
- *Evidence:* high_confidence — [httpwg.org](https://httpwg.org/specs/rfc9530.html); [raw.githubusercontent.com](https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/network-services-pentesting/1099-pentesting-java-rmi.md)

**Serialized data can be identified by language-specific signatures: PHP uses a human-readable string format with type letters and length indicators (e.g., O:4:"User":2:{s:4:"name":s:6:"carlos";s:10:"isLoggedIn":b:1;}), while Java serialization uses binary bytes beginning with ac ed (hex) / rO0 (base64), and a Content-type of application/x-java-serialized-object also indicates Java serialization.**

In PHP, the native functions are serialize() and unserialize(), and source auditing should start by searching for unserialize() on user input (PortSwigger). In Java, any class implementing java.io.Serializable can be serialized, and source code should be reviewed for readObject() calls on untrusted InputStreams (PortSwigger). The OWASP Deserialization Cheat Sheet lists the Java traffic fingerprints AC ED 00 05 (hex), rO0 (base64), and the HTTP Content-type header application/x-java-serialized-object (OWASP).

- *Disproof:* Presence of a signature alone does not prove vulnerability: the application must subsequently deserialize that data from an untrusted source without integrity checks. A well-hardened service that rejects unrecognized types and verifies signatures before parsing will show the signature but not the flaw.
- *Evidence:* high_confidence — [cheatsheetseries.owasp.org](https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html); [portswigger.net](https://portswigger.net/web-security/deserialization/exploiting)

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

- *Disproof:* Refuted when: the resolved path stays inside the permitted base directory after the platform canonicalises it. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“This code does not attempt to verify the source or contents of the file before d”) does not occur under a test that isolates that control.
- *Evidence:* high_confidence — [cheatsheetseries.owasp.org](https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html); [cwe.mitre.org](https://cwe.mitre.org/data/definitions/502.html)

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

- *Disproof:* Refuted when: the value is bound as a parameter or written through the framework's own encoder, so the interpreter never sees attacker text as syntax. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“Since Pickle allows objects to define the process for how they should be unpickl”) does not occur under a test that isolates that control.
- *Evidence:* high_confidence — [cheatsheetseries.owasp.org](https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html); [cwe.mitre.org](https://cwe.mitre.org/data/definitions/502.html)

**Magic methods invoked automatically during deserialization (PHP __wakeup()/__destruct(), Java readObject()) and gadget chains let an attacker pass data into dangerous sinks without manually invoking functions; pre-built tools such as ysoserial (Java) and PHPGCC (PHP) ship known chains.**

PortSwigger explains that magic methods are invoked automatically when their triggering event occurs, and that some are invoked during deserialization - for example PHP's unserialize() invokes __wakeup(), and Java's ObjectInputStream.readObject() is a magic method invoked during deserialization that can be overridden by Serializable classes to control field deserialization (PortSwigger). A gadget is a snippet of code already present in the application that helps an attacker achieve a goal; chaining multiple gadgets lets the attacker pass input into a dangerous sink gadget, and many vulnerabilities are exploitable only through such chains. ysoserial generates serialized objects from pre-discovered Java chains and even ships universal detection chains such as URLDNS (DNS lookup) and JRMPClient (TCP connection). PHPGCC provides PHP equivalent chains (PortSwigger).

- *Disproof:* A class with a magic method is not inherently vulnerable: the magic method is only dangerous if it passes attacker-controlled data into a dangerous sink, and if the application does not deserialize untrusted input at all. Similarly, a gadget chain is only exploitable if the required classes and gadgets exist on the server's classpath.
- *Evidence:* high_confidence — [community.owasp.org](https://community.owasp.org/vulnerabilities/Deserialization_of_untrusted_data); [portswigger.net](https://portswigger.net/web-security/deserialization/exploiting)

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

- *Disproof:* Refuted when: the same behaviour is absent when the single named control in the claim is present, and the control is shown to be present rather than assumed. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“Making an assumption that the code in the deserialized object is valid is danger”) does not occur under a test that isolates that control.
- *Evidence:* high_confidence — [cheatsheetseries.owasp.org](https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html); [cwe.mitre.org](https://cwe.mitre.org/data/definitions/502.html)

**Avoid having unnecessary types or gadgets (a sequence of instances and method invocations that can self-execute during the deserialization process, often found in libraries) available that can be leveraged for malicious ends.**

ntation 
 
 
 
 
 
 
 Make fields transient to protect them from deserialization. 
 An attempt to serialize and then deserialize a class containing transient fields will result in NULLs where the transient data should be. This is an excellent way to prevent time, environment-based, or sensitive variables from being carried over and used improperly. 
 
 
 
 
 
 
 
 
 
 
 Implementation 
 
 
 
 
 
 Avoid having unnecessary types or gadgets (a sequence of instances and method invocations that can self-execute during the deserialization process, often found in libraries) available that can be leveraged for malicious ends. This limits the potential for unintended or unauthorized types and gadgets to be leveraged by the attacker. Add only acceptable classes to an allowlist. Note: new gadgets are constantly being discovered, so this alone is not a sufficient mitigation. 
 
 
 
 
 
 
 
 
 
 Architecture and Design; Implementation 
 
 
 
 
 
 Employ cryptography of the data or code for protection. However, it's importa

- *Disproof:* Refuted when: the value is bound as a parameter or written through the framework's own encoder, so the interpreter never sees attacker text as syntax. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“Avoid having unnecessary types or gadgets (a sequence of instances and method in”) does not occur under a test that isolates that control.
- *Evidence:* high_confidence — [cheatsheetseries.owasp.org](https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html); [cwe.mitre.org](https://cwe.mitre.org/data/definitions/502.html)

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

- *Disproof:* Refuted when: the same behaviour is absent when the single named control in the claim is present, and the control is shown to be present rather than assumed. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“Serialization and deserialization refer to the process of taking program-interna”) does not occur under a test that isolates that control.
- *Evidence:* high_confidence — [cheatsheetseries.owasp.org](https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html); [cwe.mitre.org](https://cwe.mitre.org/data/definitions/502.html)

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

- *Disproof:* Refuted when: the value is bound as a parameter or written through the framework's own encoder, so the interpreter never sees attacker text as syntax. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“Deserialization issue in commonly-used Java library allows remote execution.”) does not occur under a test that isolates that control.
- *Evidence:* high_confidence — [cheatsheetseries.owasp.org](https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html); [cwe.mitre.org](https://cwe.mitre.org/data/definitions/502.html)

## 4. Validation

_How to prove the finding rather than infer it. A technique that cannot be validated must not be reported._

**A deserialization endpoint is confirmed only by a differential that shows an attacker-shaped object graph is deserialized and executed before authentication, which is why an unauthenticated remote attacker reaching arbitrary code execution on the vulnerable listener is the observation that closes the chain.**

Previous primitive hands over: reachability of an endpoint that deserializes caller-supplied bytes. Tenable's analysis of the VMware Aria Operations for Logs flaw states that an unauthenticated, remote attacker capable of accessing the instance could exploit the vulnerability to gain arbitrary code execution with root privileges, and separately notes that an attacker already holding a foothold could use such a flaw as part of post-compromise activity, which is the chaining case. The precondition the next link needs is a gadget or side-effect primitive in the deserialized graph rather than data alone, and Microsoft's position is blunt: the BinaryFormatter type is dangerous and is not recommended for data processing, and BinaryFormatter is insecure and can't be made secure. Observation that proves the segment: an unauthenticated request carrying a serialized object graph produces a process-level side effect (file write, child process) that a control payload without the graph does not.

- *Disproof:* If the endpoint authenticates before deserializing, or rejects the crafted graph with an integrity error before any object is constructed, or if the runtime has removed the formatter entirely, no side effect is observable and the deserialization segment does not hold.
- *Evidence:* high_confidence — [learn.microsoft.com](https://learn.microsoft.com/en-us/dotnet/standard/serialization/binaryformatter-security-guide); [tenable.com](https://www.tenable.com/blog/cve-2023-20864-vmware-aria-operations-for-logs-deserialization-vulnerability)

**Safe deserialization practices include verifying integrity before parsing (digital signatures), restricting which classes may be deserialized via ObjectInputStream#resolveClass(), declaring a final readObject() that throws, making sensitive fields transient, and using agents or safe replacement APIs to harden ObjectInputStream.**

OWASP Deserialization Cheat Sheet prescribes: use a safe data interchange format such as JSON instead of native unserialize(); in Java, override resolveClass() to restrict deserialization to expected classes (with libraries such as SerialKiller or Apache Commons IO ValidatingObjectInputStream); declare a final readObject() that throws to make domain objects unde Serializable; and apply agents such as rO0 or NotSoSerial to harden ObjectInputStream globally - allowing block-listing but preferring allow-listing (OWASP cheat sheet). CWE-502's potential mitigations mirror these: signing/sealing data, populating a new object rather than deserializing, adding only acceptable classes to an allowlist, and using an application firewall for defense in depth (CWE).

- *Disproof:* A post-deserialization signature check is useless because the damage occurs during parsing; client-side cryptography is bypassable if the client is compromised; an allowlist is not sufficient because new gadgets are constantly discovered; and client-side integrity checks assume the attacker cannot read or modify the client. Defense in depth therefore stacks multiple controls rather than relying on a single one.
- *Evidence:* high_confidence — [cheatsheetseries.owasp.org](https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html); [cwe.mitre.org](https://cwe.mitre.org/data/definitions/502.html)

## 5. False-positive rejection

_The checks that eliminate the most common non-findings. Run these BEFORE reporting, not after a rejection._

**An endpoint that accepts a serialised payload is not an insecure-deserialization RCE finding until a gadget chain reachable in the target's own classpath is proven: deserialization without an available gadget is a parse of attacker data, not code execution.**

Reachability is the whole test. Elastic's Log4j 2 research is the model: reproducing the deserialization allowlist bypass was necessary but not sufficient, because reaching command execution took two further things the library does not ship - a process that still deserializes the object stream, and a gadget library already sitting on that JVM. So inventory the target: if the deserializing process is not reachable from the endpoint, or the classpath contains no usable gadget, the parse produces a value and nothing more. The PHP side has the same shape: Sonar's phpBB research shows the vulnerability lives in the stream wrapper the runtime applies automatically, so a phar payload only matters where that wrapper sits on a reachable code path. Hunting value: this filters every generic serialized-gadget-reachable scanner hit - base64 blobs, RMI payloads, BinaryFormatter payloads, PHAR wrappers and node-serialize payloads arriving at a server with no exploitable class present.

- *Disproof:* It IS a finding when a real gadget is present and demonstrably executes - a gadget library on the classpath (commons-collections, spring, ysoserial-style chains), a PHPGGC gadget reachable from a phar stream wrapper, or a typed deserializer that instantiates the attacker-named class. Prove execution with an out-of-band or filesystem marker, not with a successful parse.
- *Evidence:* high_confidence — [elastic.co](https://www.elastic.co/security-labs/threat-command/java-deserialization-vulnerability-log4j-2); [sonarsource.com](https://www.sonarsource.com/blog/phpbb3-phar-deserialization-to-remote-code-execution/)

## Known bypasses

_No verified bypass items yet._ Derived from evidence only, so this section is empty rather than plausible.


## Chaining

_No verified chain_link items yet._ Derived from evidence only, so this section is empty rather than plausible.


## 6. Impact

_What is actually demonstrable, and what to stop claiming._

**Insecure deserialization allows remote code execution, denial of service, and access-control bypass; the CWE/OWASP description states malformed or unexpected data can be used to abuse application logic, deny service, or execute arbitrary code, and observed examples include Java deserialization RCE and Python pickle command execution.**

OWASP states malformed or unexpected data could be used to abuse application logic, deny service, or execute arbitrary code, and lists Availability, Authorization, and Access-control consequences (OWASP community). CWE-502 demonstrative examples show a Java ObjectInputStream deserializing an untrusted file that may contain arbitrary malicious code executed when the object is used, and a Python cPickle.loads of an untrusted AuthToken that can call Popen to execute /bin/sh (CWE). The OWASP Deserialization Cheat Sheet confirms attacks against deserializers allow denial-of-service, access control, or remote code execution (RCE) attacks (OWASP cheat sheet).

- *Disproof:* If the application never deserializes untrusted data - all deserialization inputs are internally generated and integrity-protected - or if it whitelists allowed classes and hardens ObjectInputStream, the impact window narrows. However, many deployments deserialize user-supplied cookies, tokens, or files, so the impact range (logic abuse, DoS, RCE) remains real.
- *Evidence:* high_confidence — [cheatsheetseries.owasp.org](https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html); [community.owasp.org](https://community.owasp.org/vulnerabilities/Deserialization_of_untrusted_data); [cwe.mitre.org](https://cwe.mitre.org/data/definitions/502.html)

## Coverage gap

These stages have no verified evidence and are therefore absent above: Known bypasses, Chaining.
A procedure with a missing validation stage is not safe to act on — it produces findings rather than proofs.

---

*Generated from the evidence base. Where this file and the database disagree, the database is correct.*
