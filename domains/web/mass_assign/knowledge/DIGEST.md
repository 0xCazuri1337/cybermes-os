# Mass Assignment / Excessive Data Exposure

> surface: `api` · CWE: CWE-915 · OWASP: API3:2023
> maturity: **mature** — 14 items, 14 supported, 2 FP rules, 1 chains

The server binds client-supplied fields straight onto a model, so a client can set properties the UI never exposes — including privilege fields.

**Aliases:** mass assignment, excessive data exposure, over posting, unintended json properties, graphql over fetch

## Signal

- **A registration or update POST whose body is bound wholesale to the model is exploitable the moment the body carries an extra role or flag field.**  
  `high_confidence` · score 0.929 · disproved by: If the added field is silently dropped on write and never appears in any later authenticated read of the record, the endpoint filters the input and mass assignment is not present.
  sources: <https://bishopfox.com/blog/design-considerations-for-secure-graphql-apis> · <https://snyk.io/blog/avoiding-mass-assignment-node-js/>

## Technique

- **Ruby on Rails allows deserialization of untrusted YAML to execute arbitrary code.**  
  `high_confidence` · score 0.7975 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Ruby on Rails allows deserialization of untrusted YAML to execute arbitrary code.".
  sources: <https://cwe.mitre.org/data/definitions/915.html> · <https://owasp.org/API-Security/editions/2023/en/0xa3-broken-object-property-level-authorization/>
- **Incorrect deserialization in web browser allows escaping the sandbox.**  
  `high_confidence` · score 0.7975 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Incorrect deserialization in web browser allows escaping the sandbox.".
  sources: <https://cwe.mitre.org/data/definitions/915.html> · <https://owasp.org/API-Security/editions/2023/en/0xa3-broken-object-property-level-authorization/>
- **Python script allows remote attackers to execute arbitrary code using pickled objects.**  
  `high_confidence` · score 0.7975 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Python script allows remote attackers to execute arbitrary code using pickled objects.".
  sources: <https://cwe.mitre.org/data/definitions/915.html> · <https://owasp.org/API-Security/editions/2023/en/0xa3-broken-object-property-level-authorization/>
- **Spring framework allows deserialization of objects from untrusted sources to execute arbitrary code.**  
  `high_confidence` · score 0.7975 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Spring framework allows deserialization of objects from untrusted sources to execute arbit".
  sources: <https://cwe.mitre.org/data/definitions/915.html> · <https://owasp.org/API-Security/editions/2023/en/0xa3-broken-object-property-level-authorization/>
- **Media library allows deserialization of objects by untrusted Java applets, leading to arbitrary code execution.**  
  `high_confidence` · score 0.7975 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Media library allows deserialization of objects by untrusted Java applets, leading to arbi".
  sources: <https://cwe.mitre.org/data/definitions/915.html> · <https://owasp.org/API-Security/editions/2023/en/0xa3-broken-object-property-level-authorization/>
- **"Mass assignment" is the name of a feature in Ruby on Rails that allows simultaneous modification of multiple object attributes.**  
  `high_confidence` · score 0.77 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: ""Mass assignment" is the name of a feature in Ruby on Rails that allows simultaneous modif".
  sources: <https://cwe.mitre.org/data/definitions/915.html> · <https://owasp.org/API-Security/editions/2023/en/0xa3-broken-object-property-level-authorization/>
- **Source version control product allows modification of trusted key using mass assignment.**  
  `high_confidence` · score 0.77 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Source version control product allows modification of trusted key using mass assignment.".
  sources: <https://cwe.mitre.org/data/definitions/915.html> · <https://owasp.org/API-Security/editions/2023/en/0xa3-broken-object-property-level-authorization/>
- **Mass assignment allows modification of arbitrary attributes using modified URL.**  
  `high_confidence` · score 0.77 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Mass assignment allows modification of arbitrary attributes using modified URL.".
  sources: <https://cwe.mitre.org/data/definitions/915.html> · <https://owasp.org/API-Security/editions/2023/en/0xa3-broken-object-property-level-authorization/>
- **Application for using LLMs allows modification of a sensitive variable using mass assignment.**  
  `high_confidence` · score 0.77 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Application for using LLMs allows modification of a sensitive variable using mass assignme".
  sources: <https://cwe.mitre.org/data/definitions/915.html> · <https://owasp.org/API-Security/editions/2023/en/0xa3-broken-object-property-level-authorization/>
- **Use of PHP unserialize function on untrusted input allows attacker to modify application configuration.**  
  `high_confidence` · score 0.77 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Use of PHP unserialize function on untrusted input allows attacker to modify application c".
  sources: <https://cwe.mitre.org/data/definitions/915.html> · <https://owasp.org/API-Security/editions/2023/en/0xa3-broken-object-property-level-authorization/>
- **"Mass assignment" is the name of a feature in Ruby on Rails that allows simultaneous modification of multiple object attributes.**  
  `high_confidence` · score 0.77 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: ""Mass assignment" is the name of a feature in Ruby on Rails that allows simultaneous modif".
  sources: <https://cwe.mitre.org/data/definitions/915.html> · <https://owasp.org/API-Security/editions/2023/en/0xa3-broken-object-property-level-authorization/>

## Fp Rule

- **Sending a privileged field and seeing it unchanged is a false mass assignment: the request schema whitelist dropped the field before the handler ran.**  
  `high_confidence` · score 0.929 · disproved by: If the response echoes your submitted privileged value while the database column is untouched, the 200 you saw is your own input reflected, not confirmation of assignment, and the report must be re-run against committed state before it counts.
  sources: <https://httpwg.org/specs/rfc9110.html> · <https://projectdiscovery.io/blog/inside-the-benchmark-pp-architectures-finding-walkthroughs-and-what-each-scanner-actually-caught>
- **Filtering a known list of role field names such as isAdmin, admin or role is not a mass-assignment fix; an allowlist must be enforced server-side.**  
  `high_confidence` · score 0.783 · disproved by: If every alternate field name is rejected by strict schema validation that errors on unknown keys, and only allowlisted fields ever reach the model, the blocklist concern is moot.
  sources: <https://bishopfox.com/blog/design-considerations-for-secure-graphql-apis> · <https://snyk.io/blog/avoiding-mass-assignment-node-js/>
