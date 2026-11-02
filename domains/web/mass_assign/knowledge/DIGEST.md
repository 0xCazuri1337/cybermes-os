# Mass Assignment / Excessive Data Exposure

> surface: `api` · CWE: CWE-915 · OWASP: API3:2023
> maturity: **mature** — 12 items, 12 supported, 4 FP rules, 1 chains

The server binds client-supplied fields straight onto a model, so a client can set properties the UI never exposes — including privilege fields.

**Aliases:** mass assignment, excessive data exposure, over posting, unintended json properties, graphql over fetch

## Signal

- **A registration or update POST whose body is bound wholesale to the model is exploitable the moment the body carries an extra role or flag field.**  
  `high_confidence` · score 0.929 · disproved by: If the added field is silently dropped on write and never appears in any later authenticated read of the record, the endpoint filters the input and mass assignment is not present.
  sources: <https://bishopfox.com/blog/design-considerations-for-secure-graphql-apis> · <https://snyk.io/blog/avoiding-mass-assignment-node-js/>

## Technique

- **"Mass assignment" is the name of a feature in Ruby on Rails that allows simultaneous modification of multiple object attributes.**  
  `high_confidence` · score 0.77 · disproved by: Refuted when: the same behaviour is absent when the single named control in the claim is present, and the control is shown to be present rather than assumed. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“"Mass assignment" is the name of a feature in Ruby on Rails that allows simultan”) does not occur under a test that isolates that control.
  sources: <https://cwe.mitre.org/data/definitions/915.html> · <https://owasp.org/API-Security/editions/2023/en/0xa3-broken-object-property-level-authorization/>
- **Source version control product allows modification of trusted key using mass assignment.**  
  `high_confidence` · score 0.77 · disproved by: Refuted when: the same behaviour is absent when the single named control in the claim is present, and the control is shown to be present rather than assumed. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“Source version control product allows modification of trusted key using mass ass”) does not occur under a test that isolates that control.
  sources: <https://cwe.mitre.org/data/definitions/915.html> · <https://owasp.org/API-Security/editions/2023/en/0xa3-broken-object-property-level-authorization/>
- **Mass assignment allows modification of arbitrary attributes using modified URL.**  
  `high_confidence` · score 0.77 · disproved by: Refuted when: the resolved Location host is the intended origin, so no request ever leaves the application. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“Mass assignment allows modification of arbitrary attributes using modified URL.”) does not occur under a test that isolates that control.
  sources: <https://cwe.mitre.org/data/definitions/915.html> · <https://owasp.org/API-Security/editions/2023/en/0xa3-broken-object-property-level-authorization/>
- **Application for using LLMs allows modification of a sensitive variable using mass assignment.**  
  `high_confidence` · score 0.77 · disproved by: Refuted when: the same behaviour is absent when the single named control in the claim is present, and the control is shown to be present rather than assumed. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“Application for using LLMs allows modification of a sensitive variable using mas”) does not occur under a test that isolates that control.
  sources: <https://cwe.mitre.org/data/definitions/915.html> · <https://owasp.org/API-Security/editions/2023/en/0xa3-broken-object-property-level-authorization/>

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
