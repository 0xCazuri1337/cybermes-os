---
name: deser-hunting
description: Use when hunting Insecure Deserialization in a web target. Ordered prerequisites, signals, techniques, validation bar and false-positive rules.
---

# Insecure Deserialization — hunting skill

<!-- GENERATED from db/wks.db by wks/skillgen.py. DO NOT HAND-EDIT.
     Edit the rows (or ingest better research) and re-run:
     python -m wks.skillgen -->

> surface `web` · CWE CWE-502 · OWASP A08:2021
> evidence: 8 items, 8 supported, 2 FP rules, 0 chains
> maturity: **researching** — missing: items, chain

Data is reconstructed into a live object graph whose type system then invokes attacker-reachable behaviour.

**Also called:** insecure deserialization, deserialization, pickle deserialization, java deserialization gadget, php object injection


## Prerequisites (do not start without these)

- Jackson deserialization RCE needs default typing explicitly enabled plus a gadget chain assembled from libraries already on the application classpath.
  - **Disproof:** If the endpoint rejects a payload naming a known gadget class with a subtype-validation error while default typing is off, and no request shape can turn typing on, the chain is unreachable.
  - Sources: <https://bishopfox.com/blog/gwt-unpatched-unauthenticated-java-deserialization-vulnerability> · <https://snyk.io/blog/java-json-deserialization-problems-jackson-objectmapper/>

## Recon signals (where to look)

- Base64-encoded fully-qualified Java class names appearing in request bodies to a GWT-RPC endpoint indicate the server deserializes attacker-named types.
  - **Disproof:** If decoded blobs never contain a class descriptor, or every named-type payload is rejected by subtype validation before instantiation, the traffic is ordinary serialization without an exploitable sink.
  - Sources: <https://bishopfox.com/blog/gwt-unpatched-unauthenticated-java-deserialization-vulnerability> · <https://www.nccgroup.com/research/freddy-an-extension-for-automatically-identifying-deserialisation-issues-in-java-and-net-applications/>

## Techniques (what to change)

- Making an assumption that the code in the deserialized object is valid is dangerous and can enable exploitation.
  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Making an assumption that the code in the deserialized object is valid is dangerous and ca".
  - Sources: <https://cwe.mitre.org/data/definitions/502.html> · <https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html>
- Avoid having unnecessary types or gadgets (a sequence of instances and method invocations that can self-execute during the deserialization process, often found in libraries) available that can be leveraged for malicious ends.
  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Avoid having unnecessary types or gadgets (a sequence of instances and method invocations ".
  - Sources: <https://cwe.mitre.org/data/definitions/502.html> · <https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html>
- Serialization and deserialization refer to the process of taking program-internal object-related data, packaging it in a way that allows the data to be externally stored or transferred ("serialization"), then extracting the serialized data to reconstruct the original object ("deserialization").
  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Serialization and deserialization refer to the process of taking program-internal object-r".
  - Sources: <https://cwe.mitre.org/data/definitions/502.html> · <https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html>

## Validation bar (how to prove it)

- A deserialization endpoint is confirmed only by a differential that shows an attacker-shaped object graph is deserialized and executed before authentication, which is why an unauthenticated remote attacker reaching arbitrary code execution on the vulnerable listener is the observation that closes the chain.
  - **Disproof:** If the endpoint authenticates before deserializing, or rejects the crafted graph with an integrity error before any object is constructed, or if the runtime has removed the formatter entirely, no side effect is observable and the deserialization segment does not hold.
  - Sources: <https://learn.microsoft.com/en-us/dotnet/standard/serialization/binaryformatter-security-guide> · <https://www.tenable.com/blog/cve-2023-20864-vmware-aria-operations-for-logs-deserialization-vulnerability>

## False-positive rules (when to reject it)

- An endpoint that accepts a serialised payload is not an insecure-deserialization RCE finding until a gadget chain reachable in the target's own classpath is proven: deserialization without an available gadget is a parse of attacker data, not code execution.
  - **Disproof:** It IS a finding when a real gadget is present and demonstrably executes - a gadget library on the classpath (commons-collections, spring, ysoserial-style chains), a PHPGGC gadget reachable from a phar stream wrapper, or a typed deserializer that instantiates the attacker-named class. Prove execution with an out-of-band or filesystem marker, not with a successful parse.
  - Sources: <https://www.elastic.co/security-labs/threat-command/java-deserialization-vulnerability-log4j-2> · <https://www.sonarsource.com/blog/phpbb3-phar-deserialization-to-remote-code-execution/>
- A serialized blob whose integrity check you could not defeat is not an insecure-deserialization finding; the finding needs a modified blob accepted without a valid signature.
  - **Disproof:** If the type field is resolved against a server-side allowlist so that your substituted class never instantiates, the report is a false positive about a class you cannot reach even though the blob parses, and the acceptance of the blob proves nothing.
  - Sources: <https://httpwg.org/specs/rfc9530.html> · <https://projectdiscovery.io/blog/nuclei-templates-november-2025> · <https://projectdiscovery.io/blog/ruby-saml-gitlab-auth-bypass>

---
Full class document: `skills/Web/deser/EVIDENCE.md` · retrieve more with `python -m wks.cli search "<query>" --class-id deser`
