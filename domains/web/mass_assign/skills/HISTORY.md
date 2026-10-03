# History

Append-only. Each entry records WHY the skill changed, not just that it did. Improvement means better hunting behaviour, not more text.

## 2026-10-02 15:57 — 1 diff lines
- items: 14 (supported 14), FP rules 2, chains 1, state mature

```diff
(initial generation, 2026-10-02)
```

## 2026-10-02 16:07 — 8 diff lines
- items: 14 (supported 14), FP rules 2, chains 1, state mature

```diff
--- mass_assign@current
+++ mass_assign@new
@@ -70,4 +70,4 @@
   - Sources: <https://httpwg.org/specs/rfc9110.html> · <https://projectdiscovery.io/blog/inside-the-benchmark-pp-architectures-finding-walkthroughs-and-what-each-scanner-actually-caught>
 
 ---
-Full class document: `domains/web/mass_assign/EVIDENCE.md` · retrieve more with `python -m wks.cli search "<query>" --class-id mass_assign`
+Full class document: `domains/web/mass_assign/knowledge/DIGEST.md` · retrieve more with `python -m wks.cli search "<query>" --class-id mass_assign`
```

## 2026-10-02 19:37 — 110 diff lines
- items: 23 (supported 8), FP rules 4, chains 1, state mature

```diff
--- mass_assign@current
+++ mass_assign@new
@@ -10,7 +10,7 @@
      python -m wks.skillgen -->
 
 > surface `api` · CWE CWE-915 · OWASP API3:2023
-> evidence: 14 items, 14 supported, 2 FP rules, 1 chains
+> evidence: 23 items, 8 supported, 4 FP rules, 1 chains
 > maturity: **mature**
 
 The server binds client-supplied fields straight onto a model, so a client can set properties the UI never exposes — including privilege fields.
@@ -26,48 +26,87 @@
 
 ## Techniques (what to change)
 
-- "Mass assignment" is the name of a feature in Ruby on Rails that allows simultaneous modification of multiple object attributes.
+- "Mass assignment" is the name of a feature in Ruby on Rails that allows simultaneous modification of multiple object attributes. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: ""Mass assignment" is the name of a feature in Ruby on Rails that allows simultaneous modif".
   - Sources: <https://cwe.mitre.org/data/definitions/915.html> · <https://owasp.org/API-Security/editions/2023/en/0xa3-broken-object-property-level-authorization/>
-- Ruby on Rails allows deserialization of untrusted YAML to execute arbitrary code.
+- Ruby on Rails allows deserialization of untrusted YAML to execute arbitrary code. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Ruby on Rails allows deserialization of untrusted YAML to execute arbitrary code.".
   - Sources: <https://cwe.mitre.org/data/definitions/915.html> · <https://owasp.org/API-Security/editions/2023/en/0xa3-broken-object-property-level-authorization/>
-- Incorrect deserialization in web browser allows escaping the sandbox.
+- Incorrect deserialization in web browser allows escaping the sandbox. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Incorrect deserialization in web browser allows escaping the sandbox.".
   - Sources: <https://cwe.mitre.org/data/definitions/915.html> · <https://owasp.org/API-Security/editions/2023/en/0xa3-broken-object-property-level-authorization/>
-- Python script allows remote attackers to execute arbitrary code using pickled objects.
+- Python script allows remote attackers to execute arbitrary code using pickled objects. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Python script allows remote attackers to execute arbitrary code using pickled objects.".
   - Sources: <https://cwe.mitre.org/data/definitions/915.html> · <https://owasp.org/API-Security/editions/2023/en/0xa3-broken-object-property-level-authorization/>
-- Spring framework allows deserialization of objects from untrusted sources to execute arbitrary code.
+- Spring framework allows deserialization of objects from untrusted sources to execute arbitrary code. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Spring framework allows deserialization of objects from untrusted sources to execute arbit".
   - Sources: <https://cwe.mitre.org/data/definitions/915.html> · <https://owasp.org/API-Security/editions/2023/en/0xa3-broken-object-property-level-authorization/>
-- Source version control product allows modification of trusted key using mass assignment.
+- Source version control product allows modification of trusted key using mass assignment. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Source version control product allows modification of trusted key using mass assignment.".
   - Sources: <https://cwe.mitre.org/data/definitions/915.html> · <https://owasp.org/API-Security/editions/2023/en/0xa3-broken-object-property-level-authorization/>
-- Media library allows deserialization of objects by untrusted Java applets, leading to arbitrary code execution.
+- Media library allows deserialization of objects by untrusted Java applets, leading to arbitrary code execution. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Media library allows deserialization of objects by untrusted Java applets, leading to arbi".
   - Sources: <https://cwe.mitre.org/data/definitions/915.html> · <https://owasp.org/API-Security/editions/2023/en/0xa3-broken-object-property-level-authorization/>
-- Mass assignment allows modification of arbitrary attributes using modified URL.
+- Mass assignment allows modification of arbitrary attributes using modified URL. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Mass assignment allows modification of arbitrary attributes using modified URL.".
   - Sources: <https://cwe.mitre.org/data/definitions/915.html> · <https://owasp.org/API-Security/editions/2023/en/0xa3-broken-object-property-level-authorization/>
-- Application for using LLMs allows modification of a sensitive variable using mass assignment.
+- Application for using LLMs allows modification of a sensitive variable using mass assignment. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Application for using LLMs allows modification of a sensitive variable using mass assignme".
   - Sources: <https://cwe.mitre.org/data/definitions/915.html> · <https://owasp.org/API-Security/editions/2023/en/0xa3-broken-object-property-level-authorization/>
-- Use of PHP unserialize function on untrusted input allows attacker to modify application configuration.
+- Use of PHP unserialize function on untrusted input allows attacker to modify application configuration. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Use of PHP unserialize function on untrusted input allows attacker to modify application c".
   - Sources: <https://cwe.mitre.org/data/definitions/915.html> · <https://owasp.org/API-Security/editions/2023/en/0xa3-broken-object-property-level-authorization/>
-- "Mass assignment" is the name of a feature in Ruby on Rails that allows simultaneous modification of multiple object attributes.
+- "Mass assignment" is the name of a feature in Ruby on Rails that allows simultaneous modification of multiple object attributes. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: ""Mass assignment" is the name of a feature in Ruby on Rails that allows simultaneous modif".
   - Sources: <https://cwe.mitre.org/data/definitions/915.html> · <https://owasp.org/API-Security/editions/2023/en/0xa3-broken-object-property-level-authorization/>
 
+## Tests
+
+- To decide this case, observe: eat this as the validation it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable. Boundary of the rule: The claim is false when the endpoint has no read path available to the tester and the response body never echoes model state; there the evidence must come from an out-of-band _(unverified)_
+  - **Disproof:** This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (mass_assign.validation.proof_is_a_readback_of_the_persisted_privilege_field_not_a_2xx_response) states the full boundary.
+  - Sources: <https://laravel.com/docs/eloquent> · <https://symfony.com/doc/current/forms.html>
+- To decide this case, observe: : treat this as the bypass it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable. Boundary of the rule: The rule is false when the privileged field is stored in a different model or table from the allowlisted one, or when the ORM writes it through a dedicated setter that the ma _(unverified)_
+  - **Disproof:** This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (mass_assign.bypass.a_fillable_allowlist_still_admits_a_dangerous_key_if_it_is_listed_explicitly) states the full boundary.
+  - Sources: <https://laravel.com/docs/eloquent> · <https://symfony.com/doc/current/forms.html>
+- To decide this case, observe: treat this as the fp_rule it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable. Boundary of the rule: The rule is wrong when the discarded-attribute behaviour is a development-only diagnostic that is switched off in production, or when the framework logs and then applies the _(unverified)_
+  - **Disproof:** This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (mass_assign.fp_rule.a_silently_discarded_extra_field_is_not_mass_assignment) states the full boundary.
+  - Sources: <https://laravel.com/docs/eloquent> · <https://symfony.com/doc/current/forms.html>
+- To decide this case, observe: treat this as the fp_rule it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable. Boundary of the rule: The rule is wrong when the ignored field is not simply inert — for example it feeds a logging/audit sink, a cache key, a search index, a downstream webhook payload, or a deno _(unverified)_
+  - **Disproof:** This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (mass_assign.fp_rule.ignoring_an_unknown_field_is_a_design_choice_until_a_privilege_field_is_actually_written) states the full boundary.
+  - Sources: <https://laravel.com/docs/eloquent> · <https://symfony.com/doc/current/forms.html>
+
+## Validation bar (how to prove it)
+
+- A convincing mass-assignment proof is a successful response paired with a readback showing the privileged field changed — a follow-up GET, or the object returned by the same request echoing the new value — because a 2xx on its own does not show the attribute reached the database.
+  - **Disproof:** The claim is false when the endpoint has no read path available to the tester and the response body never echoes model state; there the evidence must come from an out-of-band channel (a second account observing the change, an email or webhook triggered by the field, or a database log), and without one the finding is unproven rather than disproven.
+  - Sources: <https://laravel.com/docs/eloquent> · <https://symfony.com/doc/current/forms.html>
+
 ## False-positive rules (when to reject it)
 
+- A submitted field that the framework silently discards — because it is absent from the model's fillable list — is not a mass-assignment finding; the mass-assignment defect requires the unexpected field to actually change persisted state or a privilege-bearing attribute.
+  - **Disproof:** The rule is wrong when the discarded-attribute behaviour is a development-only diagnostic that is switched off in production, or when the framework logs and then applies the attribute on a different code path (a fillable check that is bypassed for nested JSON keys, or a direct column write outside the mass-assignment call), in which case the same request that looks discarded in one flow mutates state in another.
+  - Sources: <https://laravel.com/docs/eloquent> · <https://symfony.com/doc/current/forms.html>
 - Filtering a known list of role field names such as isAdmin, admin or role is not a mass-assignment fix; an allowlist must be enforced server-side.
   - **Disproof:** If every alternate field name is rejected by strict schema validation that errors on unknown keys, and only allowlisted fields ever reach the model, the blocklist concern is moot.
   - Sources: <https://bishopfox.com/blog/design-considerations-for-secure-graphql-apis> · <https://snyk.io/blog/avoiding-mass-assignment-node-js/>
+- An API that accepts a body containing fields it does not know is not automatically vulnerable: the finding only exists once a submitted field maps to a server-side attribute the caller must not control, typically an ownership, role, price or verification flag.
+  - **Disproof:** The rule is wrong when the ignored field is not simply inert — for example it feeds a logging/audit sink, a cache key, a search index, a downstream webhook payload, or a denormalised duplicate used for authorisation — in which case the same unexpected field is already attacker-controlled and produces an effect even without touching the protected column.
+  - Sources: <https://laravel.com/docs/eloquent> · <https://symfony.com/doc/current/forms.html>
 - Sending a privileged field and seeing it unchanged is a false mass assignment: the request schema whitelist dropped the field before the handler ran.
   - **Disproof:** If the response echoes your submitted privileged value while the database column is untouched, the 200 you saw is your own input reflected, not confirmation of assignment, and the report must be re-run against committed state before it counts.
   - Sources: <https://httpwg.org/specs/rfc9110.html> · <https://projectdiscovery.io/blog/inside-the-benchmark-pp-architectures-finding-walkthroughs-and-what-each-scanner-actually-caught>
 
+## Evidence requirements
+
+- A model marked unguarded, or a controller that hand-builds the array passed to the ORM's create/update call from the raw request, is a far stronger mass-assignment signal than a generic `role` key in a request body, because it identifies the specific code path with no allowlist at all.
+  - **Disproof:** The claim is false when the unguarded model is a value object or DTO that never persists a privilege-bearing column, or when every value in the hand-built array is read from a server-side constant and merged with a validated subset of the request; the marker is then present but the sink is not attacker-reachable.
+  - Sources: <https://laravel.com/docs/eloquent> · <https://symfony.com/doc/current/forms.html>
+
+## Defence bypasses
+
+- A fillable/guarded allowlist is only a defence as strong as its contents: because the allowlist is an explicit enumeration of attribute names, a single over-broad entry (a whole table of columns, a prefix pattern, or a nested JSON path that includes a privileged sub-key) re-opens mass assignment without weakening the mechanism itself.
+  - **Disproof:** The rule is false when the privileged field is stored in a different model or table from the allowlisted one, or when the ORM writes it through a dedicated setter that the mass-assignment path never reaches, so the over-broad entry still cannot set it.
+  - Sources: <https://laravel.com/docs/eloquent> · <https://symfony.com/doc/current/forms.html>
+
 ---
 Full class document: `domains/web/mass_assign/knowledge/DIGEST.md` · retrieve more with `python -m wks.cli search "<query>" --class-id mass_assign`
```

## 2026-10-03 01:46 — 32 diff lines
- items: 23 (supported 12), FP rules 4, chains 1, state mature

```diff
--- mass_assign@current
+++ mass_assign@new
@@ -10,7 +10,7 @@
      python -m wks.skillgen -->
 
 > surface `api` · CWE CWE-915 · OWASP API3:2023
-> evidence: 23 items, 8 supported, 4 FP rules, 1 chains
+> evidence: 23 items, 12 supported, 4 FP rules, 1 chains
 > maturity: **mature**
 
 The server binds client-supplied fields straight onto a model, so a client can set properties the UI never exposes — including privilege fields.
@@ -62,16 +62,16 @@
 
 ## Tests
 
-- To decide this case, observe: eat this as the validation it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable. Boundary of the rule: The claim is false when the endpoint has no read path available to the tester and the response body never echoes model state; there the evidence must come from an out-of-band _(unverified)_
+- To decide this case, observe: How to apply it in the field: treat this as the validation it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable.
   - **Disproof:** This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (mass_assign.validation.proof_is_a_readback_of_the_persisted_privilege_field_not_a_2xx_response) states the full boundary.
   - Sources: <https://laravel.com/docs/eloquent> · <https://symfony.com/doc/current/forms.html>
-- To decide this case, observe: : treat this as the bypass it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable. Boundary of the rule: The rule is false when the privileged field is stored in a different model or table from the allowlisted one, or when the ORM writes it through a dedicated setter that the ma _(unverified)_
+- To decide this case, observe: How to apply it in the field: treat this as the bypass it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable.
   - **Disproof:** This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (mass_assign.bypass.a_fillable_allowlist_still_admits_a_dangerous_key_if_it_is_listed_explicitly) states the full boundary.
   - Sources: <https://laravel.com/docs/eloquent> · <https://symfony.com/doc/current/forms.html>
-- To decide this case, observe: treat this as the fp_rule it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable. Boundary of the rule: The rule is wrong when the discarded-attribute behaviour is a development-only diagnostic that is switched off in production, or when the framework logs and then applies the _(unverified)_
+- To decide this case, observe: How to apply it in the field: treat this as the fp_rule it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable.
   - **Disproof:** This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (mass_assign.fp_rule.a_silently_discarded_extra_field_is_not_mass_assignment) states the full boundary.
   - Sources: <https://laravel.com/docs/eloquent> · <https://symfony.com/doc/current/forms.html>
-- To decide this case, observe: treat this as the fp_rule it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable. Boundary of the rule: The rule is wrong when the ignored field is not simply inert — for example it feeds a logging/audit sink, a cache key, a search index, a downstream webhook payload, or a deno _(unverified)_
+- To decide this case, observe: How to apply it in the field: treat this as the fp_rule it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable.
   - **Disproof:** This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (mass_assign.fp_rule.ignoring_an_unknown_field_is_a_design_choice_until_a_privilege_field_is_actually_written) states the full boundary.
   - Sources: <https://laravel.com/docs/eloquent> · <https://symfony.com/doc/current/forms.html>
 
```
