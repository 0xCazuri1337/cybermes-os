# Mass Assignment / Excessive Data Exposure

> surface: `api` · CWE: CWE-915 · OWASP: API3:2023
> maturity: **mature** — 24 items, 12 supported, 4 FP rules, 1 chains

The server binds client-supplied fields straight onto a model, so a client can set properties the UI never exposes — including privilege fields.

**Aliases:** mass assignment, excessive data exposure, over posting, unintended json properties, graphql over fetch

## Signal

- **A registration or update POST whose body is bound wholesale to the model is exploitable the moment the body carries an extra role or flag field.**  
  `high_confidence` · score 0.929 · disproved by: If the added field is silently dropped on write and never appears in any later authenticated read of the record, the endpoint filters the input and mass assignment is not present.
  sources: <https://bishopfox.com/blog/design-considerations-for-secure-graphql-apis> · <https://snyk.io/blog/avoiding-mass-assignment-node-js/>

## Technique

- **Ruby on Rails allows deserialization of untrusted YAML to execute arbitrary code.**  
  `under_review` · score 0.7975 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Ruby on Rails allows deserialization of untrusted YAML to execute arbitrary code.".
  sources: <https://cwe.mitre.org/data/definitions/915.html> · <https://owasp.org/API-Security/editions/2023/en/0xa3-broken-object-property-level-authorization/>
- **Incorrect deserialization in web browser allows escaping the sandbox.**  
  `under_review` · score 0.7975 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Incorrect deserialization in web browser allows escaping the sandbox.".
  sources: <https://cwe.mitre.org/data/definitions/915.html> · <https://owasp.org/API-Security/editions/2023/en/0xa3-broken-object-property-level-authorization/>
- **Python script allows remote attackers to execute arbitrary code using pickled objects.**  
  `under_review` · score 0.7975 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Python script allows remote attackers to execute arbitrary code using pickled objects.".
  sources: <https://cwe.mitre.org/data/definitions/915.html> · <https://owasp.org/API-Security/editions/2023/en/0xa3-broken-object-property-level-authorization/>
- **Spring framework allows deserialization of objects from untrusted sources to execute arbitrary code.**  
  `under_review` · score 0.7975 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Spring framework allows deserialization of objects from untrusted sources to execute arbit".
  sources: <https://cwe.mitre.org/data/definitions/915.html> · <https://owasp.org/API-Security/editions/2023/en/0xa3-broken-object-property-level-authorization/>
- **Media library allows deserialization of objects by untrusted Java applets, leading to arbitrary code execution.**  
  `under_review` · score 0.7975 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Media library allows deserialization of objects by untrusted Java applets, leading to arbi".
  sources: <https://cwe.mitre.org/data/definitions/915.html> · <https://owasp.org/API-Security/editions/2023/en/0xa3-broken-object-property-level-authorization/>
- **"Mass assignment" is the name of a feature in Ruby on Rails that allows simultaneous modification of multiple object attributes.**  
  `under_review` · score 0.77 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: ""Mass assignment" is the name of a feature in Ruby on Rails that allows simultaneous modif".
  sources: <https://cwe.mitre.org/data/definitions/915.html> · <https://owasp.org/API-Security/editions/2023/en/0xa3-broken-object-property-level-authorization/>
- **Source version control product allows modification of trusted key using mass assignment.**  
  `under_review` · score 0.77 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Source version control product allows modification of trusted key using mass assignment.".
  sources: <https://cwe.mitre.org/data/definitions/915.html> · <https://owasp.org/API-Security/editions/2023/en/0xa3-broken-object-property-level-authorization/>
- **Mass assignment allows modification of arbitrary attributes using modified URL.**  
  `under_review` · score 0.77 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Mass assignment allows modification of arbitrary attributes using modified URL.".
  sources: <https://cwe.mitre.org/data/definitions/915.html> · <https://owasp.org/API-Security/editions/2023/en/0xa3-broken-object-property-level-authorization/>
- **Application for using LLMs allows modification of a sensitive variable using mass assignment.**  
  `under_review` · score 0.77 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Application for using LLMs allows modification of a sensitive variable using mass assignme".
  sources: <https://cwe.mitre.org/data/definitions/915.html> · <https://owasp.org/API-Security/editions/2023/en/0xa3-broken-object-property-level-authorization/>
- **Use of PHP unserialize function on untrusted input allows attacker to modify application configuration.**  
  `under_review` · score 0.77 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Use of PHP unserialize function on untrusted input allows attacker to modify application c".
  sources: <https://cwe.mitre.org/data/definitions/915.html> · <https://owasp.org/API-Security/editions/2023/en/0xa3-broken-object-property-level-authorization/>
- **"Mass assignment" is the name of a feature in Ruby on Rails that allows simultaneous modification of multiple object attributes.**  
  `under_review` · score 0.77 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: ""Mass assignment" is the name of a feature in Ruby on Rails that allows simultaneous modif".
  sources: <https://cwe.mitre.org/data/definitions/915.html> · <https://owasp.org/API-Security/editions/2023/en/0xa3-broken-object-property-level-authorization/>
- **Public writeup evidence for mass_assign: AI agent trust boundary.**  
  `under_review` · score 0.766 · disproved by: Refuted if the fetched page no longer contains this exact span, or if the described behaviour is corrected or withdrawn by the publisher.
  sources: <https://cwe.mitre.org/data/definitions/915.html> · <https://www.varonis.com/blog/rogue-agent-dialogflow-attack>

## Test

- **To decide this case, observe: How to apply it in the field: treat this as the validation it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable.**  
  `high_confidence` · score 0.838 · disproved by: This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (mass_assign.validation.proof_is_a_readback_of_the_persisted_privilege_field_not_a_2xx_response) states the full boundary.
  sources: <https://laravel.com/docs/eloquent> · <https://symfony.com/doc/current/forms.html>
- **To decide this case, observe: How to apply it in the field: treat this as the bypass it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable.**  
  `high_confidence` · score 0.838 · disproved by: This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (mass_assign.bypass.a_fillable_allowlist_still_admits_a_dangerous_key_if_it_is_listed_explicitly) states the full boundary.
  sources: <https://laravel.com/docs/eloquent> · <https://symfony.com/doc/current/forms.html>
- **To decide this case, observe: How to apply it in the field: treat this as the fp_rule it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable.**  
  `high_confidence` · score 0.838 · disproved by: This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (mass_assign.fp_rule.a_silently_discarded_extra_field_is_not_mass_assignment) states the full boundary.
  sources: <https://laravel.com/docs/eloquent> · <https://symfony.com/doc/current/forms.html>
- **To decide this case, observe: How to apply it in the field: treat this as the fp_rule it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable.**  
  `high_confidence` · score 0.838 · disproved by: This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (mass_assign.fp_rule.ignoring_an_unknown_field_is_a_design_choice_until_a_privilege_field_is_actually_written) states the full boundary.
  sources: <https://laravel.com/docs/eloquent> · <https://symfony.com/doc/current/forms.html>

## Validation

- **A convincing mass-assignment proof is a successful response paired with a readback showing the privileged field changed — a follow-up GET, or the object returned by the same request echoing the new value — because a 2xx on its own does not show the attribute reached the database.**  
  `high_confidence` · score 0.8655 · disproved by: The claim is false when the endpoint has no read path available to the tester and the response body never echoes model state; there the evidence must come from an out-of-band channel (a second account observing the change, an email or webhook triggered by the field, or a database log), and without one the finding is unproven rather than disproven.
  sources: <https://laravel.com/docs/eloquent> · <https://symfony.com/doc/current/forms.html>

## Fp Rule

- **Sending a privileged field and seeing it unchanged is a false mass assignment: the request schema whitelist dropped the field before the handler ran.**  
  `high_confidence` · score 0.929 · disproved by: If the response echoes your submitted privileged value while the database column is untouched, the 200 you saw is your own input reflected, not confirmation of assignment, and the report must be re-run against committed state before it counts.
  sources: <https://httpwg.org/specs/rfc9110.html> · <https://projectdiscovery.io/blog/inside-the-benchmark-pp-architectures-finding-walkthroughs-and-what-each-scanner-actually-caught>
- **An API that accepts a body containing fields it does not know is not automatically vulnerable: the finding only exists once a submitted field maps to a server-side attribute the caller must not control, typically an ownership, role, price or verification flag.**  
  `high_confidence` · score 0.8655 · disproved by: The rule is wrong when the ignored field is not simply inert — for example it feeds a logging/audit sink, a cache key, a search index, a downstream webhook payload, or a denormalised duplicate used for authorisation — in which case the same unexpected field is already attacker-controlled and produces an effect even without touching the protected column.
  sources: <https://laravel.com/docs/eloquent> · <https://symfony.com/doc/current/forms.html>
- **A submitted field that the framework silently discards — because it is absent from the model's fillable list — is not a mass-assignment finding; the mass-assignment defect requires the unexpected field to actually change persisted state or a privilege-bearing attribute.**  
  `high_confidence` · score 0.838 · disproved by: The rule is wrong when the discarded-attribute behaviour is a development-only diagnostic that is switched off in production, or when the framework logs and then applies the attribute on a different code path (a fillable check that is bypassed for nested JSON keys, or a direct column write outside the mass-assignment call), in which case the same request that looks discarded in one flow mutates state in another.
  sources: <https://laravel.com/docs/eloquent> · <https://symfony.com/doc/current/forms.html>
- **Filtering a known list of role field names such as isAdmin, admin or role is not a mass-assignment fix; an allowlist must be enforced server-side.**  
  `high_confidence` · score 0.783 · disproved by: If every alternate field name is rejected by strict schema validation that errors on unknown keys, and only allowlisted fields ever reach the model, the blocklist concern is moot.
  sources: <https://bishopfox.com/blog/design-considerations-for-secure-graphql-apis> · <https://snyk.io/blog/avoiding-mass-assignment-node-js/>

## Evidence

- **A model marked unguarded, or a controller that hand-builds the array passed to the ORM's create/update call from the raw request, is a far stronger mass-assignment signal than a generic `role` key in a request body, because it identifies the specific code path with no allowlist at all.**  
  `high_confidence` · score 0.838 · disproved by: The claim is false when the unguarded model is a value object or DTO that never persists a privilege-bearing column, or when every value in the hand-built array is read from a server-side constant and merged with a validated subset of the request; the marker is then present but the sink is not attacker-reachable.
  sources: <https://laravel.com/docs/eloquent> · <https://symfony.com/doc/current/forms.html>

## Bypass

- **A fillable/guarded allowlist is only a defence as strong as its contents: because the allowlist is an explicit enumeration of attribute names, a single over-broad entry (a whole table of columns, a prefix pattern, or a nested JSON path that includes a privileged sub-key) re-opens mass assignment without weakening the mechanism itself.**  
  `high_confidence` · score 0.838 · disproved by: The rule is false when the privileged field is stored in a different model or table from the allowlisted one, or when the ORM writes it through a dedicated setter that the mass-assignment path never reaches, so the over-broad entry still cannot set it.
  sources: <https://laravel.com/docs/eloquent> · <https://symfony.com/doc/current/forms.html>
