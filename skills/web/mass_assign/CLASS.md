<!-- GENERATED from db/wks.db — do not edit -->
# Mass Assignment / Excessive Data Exposure

## Definition

The server binds client-supplied fields straight onto a model, so a client can set properties the UI never exposes — including privilege fields.

- **CWE:** CWE-915
- **OWASP:** API3:2023
- **Surface:** api
- **Aliases:** ["mass assignment", "excessive data exposure", "over posting", "unintended json properties", "graphql over fetch"]

Canonical home for `mass_assign`. Rendered from `db/wks.db` by `tools/taxonomy/build_taxonomy.py` — edit the rows, not this file.

## Root Cause

Not yet researched.

## Preconditions

Not yet researched.

## Attack Surface

Surface: **api**.

The entry points and enabling conditions for this surface are enumerated under **Preconditions**; the observable signals are under **Detection**.

## Detection

**A registration or update POST whose body is bound wholesale to the model is exploitable the moment the body carries an extra role or flag field.**

Look for endpoints where the entire request body is passed to the model constructor or an ORM create/update call with no field allowlist; that is the precondition. Replay a legitimate request with one additional key whose name is a plausible role or verification flag, and watch both the response and any subsequent authenticated read of the record. Also probe with a truthy non-boolean value, because frameworks frequently coerce any non-empty string into true for boolean-typed attributes. Roles that survive the write are the finding; roles echoed back in the response without persisting are not.

*Disproof:* If the added field is silently dropped on write and never appears in any later authenticated read of the record, the endpoint filters the input and mass assignment is not present.

**A model marked unguarded, or a controller that hand-builds the array passed to the ORM's create/update call from the raw request, is a far stronger mass-assignment signal than a generic `role` key in a request body, because it identifies the specific code path with no allowlist at all.**

Mechanism: A model marked unguarded, or a controller that hand-builds the array passed to the ORM's create/update call from the raw request, is a far stronger mass-assignment signal than a generic `role` key in a request body, because it identifies the specific code path with no allowlist at all. How to apply it in the field: treat this as the evidence it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable. Boundary of the rule: The claim is false when the unguarded model is a value object or DTO that never persists a privilege-bearing column, or when every value in the hand-built array is read from a server-side constant and merged with a validated subset of the request; the marker is then present but the sink is not attacker-reachable.

*Disproof:* The claim is false when the unguarded model is a value object or DTO that never persists a privilege-bearing column, or when every value in the hand-built array is read from a server-side constant and merged with a validated subset of the request; the marker is then present but the sink is not attacker-reachable.

## Exploitation

**"Mass assignment" is the name of a feature in Ruby on Rails that allows simultaneous modification of multiple object attributes.**

ption
 
 
 
 
 
 If the object contains attributes that were only intended for internal use, then their unexpected modification could lead to a vulnerability. 
 This weakness is sometimes known by the language-specific mechanisms that make it possible, such as mass assignment, autobinding, or object injection. 
 
 
 
 
 

 

 
 
 
 
 
 
 
 Alternate Terms
 
 
 
 
 
 
 
 
 
 
 Mass Assignment
 
 
 "Mass assignment" is the name of a feature in Ruby on Rails that allows simultaneous modification of multiple object attributes. 
 
 
 
 
 
 AutoBinding
 
 
 The "Autobinding" term is used in frameworks such as Spring MVC and ASP.NET MVC. 
 
 
 
 
 
 PHP Object Injection
 
 
 Some PHP application researchers use this term for attacking unsafe use of the unserialize() function, but it is also used for CWE-502 . 
 
 
 
 
 
 
 
 
 
 

 

 
 
 
 
 Common Consequences 
 
 
 This table specifies different individual consequences

*Disproof:* Refuted when: the same behaviour is absent when the single named control in the claim is present, and the control is shown to be present rather than assumed. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“"Mass assignment" is the name of a feature in Ruby on Rails that allows simultan”) does not occur under a test that isolates that control.

**Ruby on Rails allows deserialization of untrusted YAML to execute arbitrary code.**

007-5741 
 
 
 
 
 Content management system written in Python interprets untrusted data as pickles, allowing code execution. 
 
 
 
 
 
 
 
 CVE-2011-2520 
 
 
 
 
 Python script allows local users to execute code via pickled data. 
 
 
 
 
 
 
 
 CVE-2005-2875 
 
 
 
 
 Python script allows remote attackers to execute arbitrary code using pickled objects. 
 
 
 
 
 
 
 
 CVE-2013-0277 
 
 
 
 
 Ruby on Rails allows deserialization of untrusted YAML to execute arbitrary code. 
 
 
 
 
 
 
 
 CVE-2011-2894 
 
 
 
 
 Spring framework allows deserialization of objects from untrusted sources to execute arbitrary code. 
 
 
 
 
 
 
 
 CVE-2012-1833 
 
 
 
 
 Grails allows binding of arbitrary parameters to modify arbitrary object properties. 
 
 
 
 
 
 
 
 CVE-2010-3258 
 
 
 
 
 Incorrect deserialization in web browser allows escaping the sandbox. 
 
 
 
 
 
 
 
 CVE-200

*Disproof:* Refuted when: the value is bound as a parameter or written through the framework's own encoder, so the interpreter never sees attacker text as syntax. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“Ruby on Rails allows deserialization of untrusted YAML to execute arbitrary code”) does not occur under a test that isolates that control.

**Incorrect deserialization in web browser allows escaping the sandbox.**

7 
 
 
 
 
 Ruby on Rails allows deserialization of untrusted YAML to execute arbitrary code. 
 
 
 
 
 
 
 
 CVE-2011-2894 
 
 
 
 
 Spring framework allows deserialization of objects from untrusted sources to execute arbitrary code. 
 
 
 
 
 
 
 
 CVE-2012-1833 
 
 
 
 
 Grails allows binding of arbitrary parameters to modify arbitrary object properties. 
 
 
 
 
 
 
 
 CVE-2010-3258 
 
 
 
 
 Incorrect deserialization in web browser allows escaping the sandbox. 
 
 
 
 
 
 
 
 CVE-2008-1013 
 
 
 
 
 Media library allows deserialization of objects by untrusted Java applets, leading to arbitrary code execution. 
 
 
 
 
 
 
 
 
 
 

 

 
 
 
 Weakness Ordinalities 
 
 
 
 
 
 
 Ordinality 
 Description 
 
 
 
 
 
 
 
 
 Primary 
 
 
 
 (where the weakness exists independent of other weaknesses)
 
 
 
 
 
 
 
 
 
 
 

 

 
 
 
 Detection
 Methods

*Disproof:* Refuted when: the same behaviour is absent when the single named control in the claim is present, and the control is shown to be present rather than assumed. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“Incorrect deserialization in web browser allows escaping the sandbox.”) does not occur under a test that isolates that control.

**Python script allows remote attackers to execute arbitrary code using pickled objects.**

se of PHP unserialize function on cookie value allows remote code execution or upload of arbitrary files. 
 
 
 
 
 
 
 
 CVE-2007-5741 
 
 
 
 
 Content management system written in Python interprets untrusted data as pickles, allowing code execution. 
 
 
 
 
 
 
 
 CVE-2011-2520 
 
 
 
 
 Python script allows local users to execute code via pickled data. 
 
 
 
 
 
 
 
 CVE-2005-2875 
 
 
 
 
 Python script allows remote attackers to execute arbitrary code using pickled objects. 
 
 
 
 
 
 
 
 CVE-2013-0277 
 
 
 
 
 Ruby on Rails allows deserialization of untrusted YAML to execute arbitrary code. 
 
 
 
 
 
 
 
 CVE-2011-2894 
 
 
 
 
 Spring framework allows deserialization of objects from untrusted sources to execute arbitrary code. 
 
 
 
 
 
 
 
 CVE-2012-1833 
 
 
 
 
 Grails allows binding of arbitrary parameters to modify arbitrary object properties.

*Disproof:* Refuted when: the value is bound as a parameter or written through the framework's own encoder, so the interpreter never sees attacker text as syntax. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“Python script allows remote attackers to execute arbitrary code using pickled ob”) does not occur under a test that isolates that control.

**Spring framework allows deserialization of objects from untrusted sources to execute arbitrary code.**

on. 
 
 
 
 
 
 
 
 CVE-2011-2520 
 
 
 
 
 Python script allows local users to execute code via pickled data. 
 
 
 
 
 
 
 
 CVE-2005-2875 
 
 
 
 
 Python script allows remote attackers to execute arbitrary code using pickled objects. 
 
 
 
 
 
 
 
 CVE-2013-0277 
 
 
 
 
 Ruby on Rails allows deserialization of untrusted YAML to execute arbitrary code. 
 
 
 
 
 
 
 
 CVE-2011-2894 
 
 
 
 
 Spring framework allows deserialization of objects from untrusted sources to execute arbitrary code. 
 
 
 
 
 
 
 
 CVE-2012-1833 
 
 
 
 
 Grails allows binding of arbitrary parameters to modify arbitrary object properties. 
 
 
 
 
 
 
 
 CVE-2010-3258 
 
 
 
 
 Incorrect deserialization in web browser allows escaping the sandbox. 
 
 
 
 
 
 
 
 CVE-2008-1013 
 
 
 
 
 Media library allows deserialization of objects by untrusted Java applets, leading to arbitrary code execution.

*Disproof:* Refuted when: the value is bound as a parameter or written through the framework's own encoder, so the interpreter never sees attacker text as syntax. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“Spring framework allows deserialization of objects from untrusted sources to exe”) does not occur under a test that isolates that control.

**Source version control product allows modification of trusted key using mass assignment.**

is not a complete list of all CVEs that are related to this CWE entry. 
 
 
 
 
 Reference 
 Description 
 
 
 
 
 
 
 
 CVE-2024-3283 
 
 
 
 
 Application for using LLMs allows modification of a sensitive variable using mass assignment. 
 
 
 
 
 
 
 
 CVE-2012-2054 
 
 
 
 
 Mass assignment allows modification of arbitrary attributes using modified URL. 
 
 
 
 
 
 
 
 CVE-2012-2055 
 
 
 
 
 Source version control product allows modification of trusted key using mass assignment. 
 
 
 
 
 
 
 
 CVE-2008-7310 
 
 
 
 
 Attackers can bypass payment step in e-commerce product. 
 
 
 
 
 
 
 
 CVE-2013-1465 
 
 
 
 
 Use of PHP unserialize function on untrusted input allows attacker to modify application configuration. 
 
 
 
 
 
 
 
 CVE-2012-3527 
 
 
 
 
 Use of PHP unserialize function on untrusted input in content management system might allow code execution.

*Disproof:* Refuted when: the same behaviour is absent when the single named control in the claim is present, and the control is shown to be present rather than assumed. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“Source version control product allows modification of trusted key using mass ass”) does not occur under a test that isolates that control.

**Media library allows deserialization of objects by untrusted Java applets, leading to arbitrary code execution.**

CVE-2011-2894 
 
 
 
 
 Spring framework allows deserialization of objects from untrusted sources to execute arbitrary code. 
 
 
 
 
 
 
 
 CVE-2012-1833 
 
 
 
 
 Grails allows binding of arbitrary parameters to modify arbitrary object properties. 
 
 
 
 
 
 
 
 CVE-2010-3258 
 
 
 
 
 Incorrect deserialization in web browser allows escaping the sandbox. 
 
 
 
 
 
 
 
 CVE-2008-1013 
 
 
 
 
 Media library allows deserialization of objects by untrusted Java applets, leading to arbitrary code execution. 
 
 
 
 
 
 
 
 
 
 

 

 
 
 
 Weakness Ordinalities 
 
 
 
 
 
 
 Ordinality 
 Description 
 
 
 
 
 
 
 
 
 Primary 
 
 
 
 (where the weakness exists independent of other weaknesses)
 
 
 
 
 
 
 
 
 
 
 

 

 
 
 
 Detection
 Methods 
 
 
 
 
 
 Method 
 Details 
 
 
 
 
 
 Automated Static Analysis 
 
 
 
 Automated static analysis, commonly referred to as Static Application Security Testin

*Disproof:* Refuted when: the value is bound as a parameter or written through the framework's own encoder, so the interpreter never sees attacker text as syntax. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“Media library allows deserialization of objects by untrusted Java applets, leadi”) does not occur under a test that isolates that control.

**Mass assignment allows modification of arbitrary attributes using modified URL.**

is a curated list of examples for users to understand the variety of ways in which this
 weakness can be introduced. It is not a complete list of all CVEs that are related to this CWE entry. 
 
 
 
 
 Reference 
 Description 
 
 
 
 
 
 
 
 CVE-2024-3283 
 
 
 
 
 Application for using LLMs allows modification of a sensitive variable using mass assignment. 
 
 
 
 
 
 
 
 CVE-2012-2054 
 
 
 
 
 Mass assignment allows modification of arbitrary attributes using modified URL. 
 
 
 
 
 
 
 
 CVE-2012-2055 
 
 
 
 
 Source version control product allows modification of trusted key using mass assignment. 
 
 
 
 
 
 
 
 CVE-2008-7310 
 
 
 
 
 Attackers can bypass payment step in e-commerce product. 
 
 
 
 
 
 
 
 CVE-2013-1465 
 
 
 
 
 Use of PHP unserialize function on untrusted input allows attacker to modify application configuration. 
 
 
 
 
 
 
 
 CVE-2012-3527

*Disproof:* Refuted when: the resolved Location host is the intended origin, so no request ever leaves the application. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“Mass assignment allows modification of arbitrary attributes using modified URL.”) does not occur under a test that isolates that control.

**Application for using LLMs allows modification of a sensitive variable using mass assignment.**

uteToSet] = value; 
 return object; 
 } 
 
 
 
 
 
 
 
 
 
 
 
 
 
 
 
 
 
 
 

 

 
 
 
 Selected Observed
 Examples 
 
 
 Note: this is a curated list of examples for users to understand the variety of ways in which this
 weakness can be introduced. It is not a complete list of all CVEs that are related to this CWE entry. 
 
 
 
 
 Reference 
 Description 
 
 
 
 
 
 
 
 CVE-2024-3283 
 
 
 
 
 Application for using LLMs allows modification of a sensitive variable using mass assignment. 
 
 
 
 
 
 
 
 CVE-2012-2054 
 
 
 
 
 Mass assignment allows modification of arbitrary attributes using modified URL. 
 
 
 
 
 
 
 
 CVE-2012-2055 
 
 
 
 
 Source version control product allows modification of trusted key using mass assignment. 
 
 
 
 
 
 
 
 CVE-2008-7310 
 
 
 
 
 Attackers can bypass payment step in e-commerce product. 
 
 
 
 
 
 
 
 CVE-2013-1465 
 
 
 
 
 Use of PHP un

*Disproof:* Refuted when: the same behaviour is absent when the single named control in the claim is present, and the control is shown to be present rather than assumed. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“Application for using LLMs allows modification of a sensitive variable using mas”) does not occur under a test that isolates that control.

**Use of PHP unserialize function on untrusted input allows attacker to modify application configuration.**

s assignment. 
 
 
 
 
 
 
 
 CVE-2012-2054 
 
 
 
 
 Mass assignment allows modification of arbitrary attributes using modified URL. 
 
 
 
 
 
 
 
 CVE-2012-2055 
 
 
 
 
 Source version control product allows modification of trusted key using mass assignment. 
 
 
 
 
 
 
 
 CVE-2008-7310 
 
 
 
 
 Attackers can bypass payment step in e-commerce product. 
 
 
 
 
 
 
 
 CVE-2013-1465 
 
 
 
 
 Use of PHP unserialize function on untrusted input allows attacker to modify application configuration. 
 
 
 
 
 
 
 
 CVE-2012-3527 
 
 
 
 
 Use of PHP unserialize function on untrusted input in content management system might allow code execution. 
 
 
 
 
 
 
 
 CVE-2012-0911 
 
 
 
 
 Use of PHP unserialize function on untrusted input in content management system allows code execution using a crafted cookie value. 
 
 
 
 
 
 
 
 CVE-2012-0911 
 
 
 
 
 Content management system written in PH

*Disproof:* Refuted when: the same behaviour is absent when the single named control in the claim is present, and the control is shown to be present rather than assumed. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“Use of PHP unserialize function on untrusted input allows attacker to modify app”) does not occur under a test that isolates that control.

**"Mass assignment" is the name of a feature in Ruby on Rails that allows simultaneous modification of multiple object attributes.**

ption
 
 
 
 
 
 If the object contains attributes that were only intended for internal use, then their unexpected modification could lead to a vulnerability. 
 This weakness is sometimes known by the language-specific mechanisms that make it possible, such as mass assignment, autobinding, or object injection. 
 
 
 
 
 

 

 
 
 
 
 
 
 
 Alternate Terms
 
 
 
 
 
 
 
 
 
 
 Mass Assignment
 
 
 "Mass assignment" is the name of a feature in Ruby on Rails that allows simultaneous modification of multiple object attributes. 
 
 
 
 
 
 AutoBinding
 
 
 The "Autobinding" term is used in frameworks such as Spring MVC and ASP.NET MVC. 
 
 
 
 
 
 PHP Object Injection
 
 
 Some PHP application researchers use this term for attacking unsafe use of the unserialize() function, but it is also used for CWE-502 . 
 
 
 
 
 
 
 
 
 
 

 

 
 
 
 
 Common Consequences 
 
 
 This table specifies different individual consequences

*Disproof:* Refuted when: the same behaviour is absent when the single named control in the claim is present, and the control is shown to be present rather than assumed. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“"Mass assignment" is the name of a feature in Ruby on Rails that allows simultan”) does not occur under a test that isolates that control.

**Public writeup evidence for mass_assign: AI agent trust boundary.**

HARVESTED FROM bugbountydaily RSS -> https://www.varonis.com/blog/rogue-agent-dialogflow-attack
Reason it matters: AI agent trust boundary.

The vulnerability allowed attackers to exploit the Code Blocks feature to inject persistent malicious code into the Dialogflow agents’ pipeline, silently exfiltrating conversations and conducting large-scale phishing campaigns.

*Disproof:* Refuted if the fetched page no longer contains this exact span, or if the described behaviour is corrected or withdrawn by the publisher.

## Variations

**A fillable/guarded allowlist is only a defence as strong as its contents: because the allowlist is an explicit enumeration of attribute names, a single over-broad entry (a whole table of columns, a prefix pattern, or a nested JSON path that includes a privileged sub-key) re-opens mass assignment without weakening the mechanism itself.**

Mechanism: A fillable/guarded allowlist is only a defence as strong as its contents: because the allowlist is an explicit enumeration of attribute names, a single over-broad entry (a whole table of columns, a prefix pattern, or a nested JSON path that includes a privileged sub-key) re-opens mass assignment without weakening the mechanism itself. How to apply it in the field: treat this as the bypass it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable. Boundary of the rule: The rule is false when the privileged field is stored in a different model or table from the allowlisted one, or when the ORM writes it through a dedicated setter that the mass-assignment path never reaches, so the over-broad entry still cannot set it.

*Disproof:* The rule is false when the privileged field is stored in a different model or table from the allowlisted one, or when the ORM writes it through a dedicated setter that the mass-assignment path never reaches, so the over-broad entry still cannot set it.

## Technology / Framework Considerations

Not yet researched.

## API Considerations

Not yet researched.

## Attack Chains

- `chain.mass_assign.auto.01` — mass_assign: observe, exercise, confirm (goal: `Establish, exercise and confirm a mass_assign condition on an authorised target without relying on anyone else's data.`)

## Real-World Examples

Not yet researched.

## Common False Positives

**A submitted field that the framework silently discards — because it is absent from the model's fillable list — is not a mass-assignment finding; the mass-assignment defect requires the unexpected field to actually change persisted state or a privilege-bearing attribute.**

Mechanism: A submitted field that the framework silently discards — because it is absent from the model's fillable list — is not a mass-assignment finding; the mass-assignment defect requires the unexpected field to actually change persisted state or a privilege-bearing attribute. How to apply it in the field: treat this as the fp_rule it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable. Boundary of the rule: The rule is wrong when the discarded-attribute behaviour is a development-only diagnostic that is switched off in production, or when the framework logs and then applies the attribute on a different code path (a fillable check that is bypassed for nested JSON keys, or a direct column write outside the mass-assignment call), in which case the same request that looks discarded in one flow mutates state in another.

*Disproof:* The rule is wrong when the discarded-attribute behaviour is a development-only diagnostic that is switched off in production, or when the framework logs and then applies the attribute on a different code path (a fillable check that is bypassed for nested JSON keys, or a direct column write outside the mass-assignment call), in which case the same request that looks discarded in one flow mutates state in another.

**Filtering a known list of role field names such as isAdmin, admin or role is not a mass-assignment fix; an allowlist must be enforced server-side.**

A handler that drops a handful of well-known privileged keys is trivially defeated by renaming the attribute, since the guessable-name list is public. Test by sending the same privilege intent under several plausible alternate names and confirming that none of them persists. The durable check is whether an explicit allowlist of permitted fields is applied before the model is constructed, not whether a denylist of role words exists somewhere in the code. If the framework performs strict schema validation with unknown keys rejected, that is the real control and the finding does not hold.

*Disproof:* If every alternate field name is rejected by strict schema validation that errors on unknown keys, and only allowlisted fields ever reach the model, the blocklist concern is moot.

**An API that accepts a body containing fields it does not know is not automatically vulnerable: the finding only exists once a submitted field maps to a server-side attribute the caller must not control, typically an ownership, role, price or verification flag.**

Mechanism: An API that accepts a body containing fields it does not know is not automatically vulnerable: the finding only exists once a submitted field maps to a server-side attribute the caller must not control, typically an ownership, role, price or verification flag. How to apply it in the field: treat this as the fp_rule it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable. Boundary of the rule: The rule is wrong when the ignored field is not simply inert — for example it feeds a logging/audit sink, a cache key, a search index, a downstream webhook payload, or a denormalised duplicate used for authorisation — in which case the same unexpected field is already attacker-controlled and produces an effect even without touching the protected column.

*Disproof:* The rule is wrong when the ignored field is not simply inert — for example it feeds a logging/audit sink, a cache key, a search index, a downstream webhook payload, or a denormalised duplicate used for authorisation — in which case the same unexpected field is already attacker-controlled and produces an effect even without touching the protected column.

**Sending a privileged field and seeing it unchanged is a false mass assignment: the request schema whitelist dropped the field before the handler ran.**

Discard the finding when a single request carrying the privileged field and one benign field shows the benign field applied and the privileged field silently ignored, because a typed request schema validated the body before the handler and never handed it the extra key. The finding survives when the privileged field actually changed in server state, verified by reading it back from a second session rather than from the response that echoed your request back to you.

*Disproof:* If the response echoes your submitted privileged value while the database column is untouched, the 200 you saw is your own input reflected, not confirmation of assignment, and the report must be re-run against committed state before it counts.

## Validation

**A convincing mass-assignment proof is a successful response paired with a readback showing the privileged field changed — a follow-up GET, or the object returned by the same request echoing the new value — because a 2xx on its own does not show the attribute reached the database.**

Mechanism: A convincing mass-assignment proof is a successful response paired with a readback showing the privileged field changed — a follow-up GET, or the object returned by the same request echoing the new value — because a 2xx on its own does not show the attribute reached the database. How to apply it in the field: treat this as the validation it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable. Boundary of the rule: The claim is false when the endpoint has no read path available to the tester and the response body never echoes model state; there the evidence must come from an out-of-band channel (a second account observing the change, an email or webhook triggered by the field, or a database log), and without one the finding is unproven rather than disproven.

*Disproof:* The claim is false when the endpoint has no read path available to the tester and the response body never echoes model state; there the evidence must come from an out-of-band channel (a second account observing the change, an email or webhook triggered by the field, or a database log), and without one the finding is unproven rather than disproven.

**To decide this case, observe: How to apply it in the field: treat this as the validation it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable.**

Derived from mass_assign.validation.proof_is_a_readback_of_the_persisted_privilege_field_not_a_2xx_response, which states the false-positive boundary for this class. The observable above is what separates a real finding from the pattern that only looks like one. A hunter who cannot produce this observation in a request/response pair does not have a finding yet.

*Disproof:* This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (mass_assign.validation.proof_is_a_readback_of_the_persisted_privilege_field_not_a_2xx_response) states the full boundary.

**To decide this case, observe: How to apply it in the field: treat this as the bypass it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable.**

Derived from mass_assign.bypass.a_fillable_allowlist_still_admits_a_dangerous_key_if_it_is_listed_explicitly, which states the false-positive boundary for this class. The observable above is what separates a real finding from the pattern that only looks like one. A hunter who cannot produce this observation in a request/response pair does not have a finding yet.

*Disproof:* This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (mass_assign.bypass.a_fillable_allowlist_still_admits_a_dangerous_key_if_it_is_listed_explicitly) states the full boundary.

**To decide this case, observe: How to apply it in the field: treat this as the fp_rule it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable.**

Derived from mass_assign.fp_rule.a_silently_discarded_extra_field_is_not_mass_assignment, which states the false-positive boundary for this class. The observable above is what separates a real finding from the pattern that only looks like one. A hunter who cannot produce this observation in a request/response pair does not have a finding yet.

*Disproof:* This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (mass_assign.fp_rule.a_silently_discarded_extra_field_is_not_mass_assignment) states the full boundary.

**To decide this case, observe: How to apply it in the field: treat this as the fp_rule it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable.**

Derived from mass_assign.fp_rule.ignoring_an_unknown_field_is_a_design_choice_until_a_privilege_field_is_actually_written, which states the false-positive boundary for this class. The observable above is what separates a real finding from the pattern that only looks like one. A hunter who cannot produce this observation in a request/response pair does not have a finding yet.

*Disproof:* This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (mass_assign.fp_rule.ignoring_an_unknown_field_is_a_design_choice_until_a_privilege_field_is_actually_written) states the full boundary.

## Impact

Not yet researched.

## Related Bug Classes

Not yet researched.

## References

- **bishopfox.com** (writeup)
  - <https://bishopfox.com/blog/design-considerations-for-secure-graphql-apis>
- **cwe.mitre.org** (taxonomy)
  - <https://cwe.mitre.org/data/definitions/915.html>
- **httpwg.org** (standard)
  - <https://httpwg.org/specs/rfc9110.html>
- **laravel.com** (writeup)
  - <https://laravel.com/docs/eloquent>
- **owasp.org** (taxonomy)
  - <https://owasp.org/API-Security/editions/2023/en/0xa3-broken-object-property-level-authorization/>
- **projectdiscovery.io** (research)
  - <https://projectdiscovery.io/blog/inside-the-benchmark-pp-architectures-finding-walkthroughs-and-what-each-scanner-actually-caught>
- **snyk.io** (writeup)
  - <https://snyk.io/blog/avoiding-mass-assignment-node-js/>
- **symfony.com** (writeup)
  - <https://symfony.com/doc/current/forms.html>
- **varonis.com** (writeup)
  - <https://www.varonis.com/blog/rogue-agent-dialogflow-attack>

Every item above is gated on >= 2 distinct publisher hosts (`wks/quality.py`, rule R1). Publisher diversity, not citation count, is what makes these corroborated.
