# Subdomain Takeover

## Definition

A DNS record still points at a de-provisioned service that anyone can now claim.

- **CWE:** 404
- **OWASP:** A10:2021
- **Surface:** infra
- **Aliases:** ["subdomain takeover", "dangling dns", "dangling cname"]

Canonical home for `subdomain_takeover`. Rendered from `db/wks.db` by `tools/taxonomy/build_taxonomy.py` — edit the rows, not this file.

## Root Cause

Not yet researched.

## Preconditions

**A subdomain becomes attacker-controllable when a cancelled third-party service leaves its CNAME behind in the DNS zone, so the dangling record rather than the provider account is what has to be removed.**

A subdomain becomes attacker-controllable when a cancelled third-party service leaves its CNAME behind in the DNS zone, so the dangling record rather than the provider account is what has to be removed.

HackTricks reference: subdomain takeover (https://kathan19.gitbook.io/howtohunt/subdomain-takeover/subdomain_takeover.md)

*Disproof:* The CNAME is deleted from the zone file, or the hostname no longer resolves to the abandoned third-party service.

**A subdomain becomes attacker-controllable when a cancelled third-party service leaves its CNAME behind in the DNS zone, so the dangling record rather than the provider account is what has to be removed.**

A subdomain becomes attacker-controllable when a cancelled third-party service leaves its CNAME behind in the DNS zone, so the dangling record rather than the provider account is what has to be removed.

HackTricks reference: subdomain takeover (https://kathan19.gitbook.io/howtohunt/subdomain-takeover/subdomain_takeover.md)

*Disproof:* The CNAME is deleted from the zone file, or the hostname no longer resolves to the abandoned third-party service.

## Attack Surface

Surface: **infra**.

The entry points and enabling conditions for this surface are enumerated under **Preconditions**; the observable signals are under **Detection**.

## Detection

**A dangling CNAME candidate is signalled by the hostname answering with a 404 not found error from the third-party destination it is attached to.**

A dangling CNAME candidate is signalled by the hostname answering with a 404 not found error from the third-party destination it is attached to.

HackTricks reference: sub or top level domain takeover (https://kathan19.gitbook.io/howtohunt/subdomain-takeover/sub_or_top_level_domain_takeover.md)

*Disproof:* The hostname returns a live response from the provider or a different error entirely, so the 404 is not the third-party service's dangling-target response.

**A dangling CNAME candidate is signalled by the hostname answering with a 404 not found error from the third-party destination it is attached to.**

A dangling CNAME candidate is signalled by the hostname answering with a 404 not found error from the third-party destination it is attached to.

HackTricks reference: sub or top level domain takeover (https://kathan19.gitbook.io/howtohunt/subdomain-takeover/sub_or_top_level_domain_takeover.md)

*Disproof:* The hostname returns a live response from the provider or a different error entirely, so the 404 is not the third-party service's dangling-target response.

**A convincing observation for this class is: The observable that triggers this false positive is a hostname appearing in passive subdomain enumeration output and filed as a subdomain takeover.**

Derived from subdomain_takeover.fp_rule.passive_list_is_a_lead_not_a_claimable_subdomain, which states the boundary for this class. The observation above is what a report must contain to be believed: an artifact the reviewer can re-check, not a claim the hunter asserts. A finding without it is an assertion.

*Disproof:* Not evidence when the observable cannot be produced at all -- blind, server-side-only, or identical-in-every-case behaviour leaves nothing to show. The originating rule (subdomain_takeover.fp_rule.passive_list_is_a_lead_not_a_claimable_subdomain) states the full boundary.

**A convincing observation for this class is: Adjacent behaviour that produces the same observable result: A dangling NS delegation is categorically worse than a dangling CNAME because the transitive trust built into DNS makes every domain that directly or indirectly depends on that record vulnerable, not only the subdomain that owns it.**

Derived from subdomain_takeover.fp_rule.auto.derived, which states the boundary for this class. The observation above is what a report must contain to be believed: an artifact the reviewer can re-check, not a claim the hunter asserts. A finding without it is an assertion.

*Disproof:* Not evidence when the observable cannot be produced at all -- blind, server-side-only, or identical-in-every-case behaviour leaves nothing to show. The originating rule (subdomain_takeover.fp_rule.auto.derived) states the full boundary.

**The distinguishing observation is the provider's own unclaimed-resource response when the target endpoint is requested directly, because that is what ties the victim hostname to a specific claimable resource type rather than to a merely deprecated or unreachable service.**

Mechanism: The distinguishing observation is the provider's own unclaimed-resource response when the target endpoint is requested directly, because that is what ties the victim hostname to a specific claimable resource type rather than to a merely deprecated or unreachable service. How to apply it in the field: treat this as the evidence it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable. Boundary of the rule: The claim is false when the provider returns an indistinguishable generic error for both unclaimed and nonexistent resources, in which case the fingerprint cannot be established from the response alone and the finding needs a signup attempt or a provider-side confirmation instead of a response-body match.

*Disproof:* The claim is false when the provider returns an indistinguishable generic error for both unclaimed and nonexistent resources, in which case the fingerprint cannot be established from the response alone and the finding needs a signup attempt or a provider-side confirmation instead of a response-body match.

## Exploitation

**This often happens because the subdomain's DNS record hasn't been properly de-provisioned or points to a service that is no longer in use.**

,"add_second_content_block":false,"add_testimonial":false,"add_browser_bar_styling":false,"add_floating_image":false,"review":{"stars":0}}},{"id":"mlqkxpzl","type":"half_width_content","data":{"image_alignment":"Right","heading":"Subdomain takeover, a brief explanation","text":" Subdomain takeover occurs when an attacker gains control of a subdomain belonging to a legitimate domain of the target. This often happens because the subdomain's DNS record hasn't been properly de-provisioned or points to a service that is no longer in use. Hostile subdomain takeover is a term coined by Detectify Security Researchers ( read the original writeup ). It refers to when an attacker takes control of a service no longer in use but that the target still has a DNS record pointing a subdomain to. As the DNS record points to a vacant service, this is also referred to as dangling DNS entries . The severity of a subdomain takeover is very contex

*Disproof:* Refuted when: the same behaviour is absent when the single named control in the claim is present, and the control is shown to be present rather than assumed. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“This often happens because the subdomain's DNS record hasn't been properly de-pr”) does not occur under a test that isolates that control.

**The takeover is usually only considered severe if it compromises other systems or gives direct access to user data (such as cookies).**

le subdomain takeover is a term coined by Detectify Security Researchers ( read the original writeup ). It refers to when an attacker takes control of a service no longer in use but that the target still has a DNS record pointing a subdomain to. As the DNS record points to a vacant service, this is also referred to as dangling DNS entries . The severity of a subdomain takeover is very contextual. The takeover is usually only considered severe if it compromises other systems or gives direct access to user data (such as cookies). Spinning up a fake page on the compromised subdomain for phishing purposes is bad enough. Consider an attacker getting control of one out of many Name Server (NS) delegations for the root (apex) zone. Then the severity can get worse than the most critical form of SQL injection. This can, over time, give the attacker access to all traffic destined for the vulnerable domain, including all its subdo

*Disproof:* Refuted when: the same behaviour is absent when the single named control in the claim is present, and the control is shown to be present rather than assumed. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“The takeover is usually only considered severe if it compromises other systems o”) does not occur under a test that isolates that control.

**This can, over time, give the attacker access to all traffic destined for the vulnerable domain, including all its subdomains.**

is usually only considered severe if it compromises other systems or gives direct access to user data (such as cookies). Spinning up a fake page on the compromised subdomain for phishing purposes is bad enough. Consider an attacker getting control of one out of many Name Server (NS) delegations for the root (apex) zone. Then the severity can get worse than the most critical form of SQL injection. This can, over time, give the attacker access to all traffic destined for the vulnerable domain, including all its subdomains. ","image":"https://d35ayjp87i0qx4.cloudfront.net/subdomain-takeover-(1).png","add_button":false,"add_second_content_block":false,"add_testimonial":false,"add_browser_bar_styling":false,"add_floating_image":false,"review":{"stars":0}}},{"id":"mlqkye99","type":"ethical_hackers_cta","data":{"heading":"Take action where it matters","subheading":"Detectify Crowdsource","description":"From subdomain ta

*Disproof:* Refuted when: the same behaviour is absent when the single named control in the claim is present, and the control is shown to be present rather than assumed. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“This can, over time, give the attacker access to all traffic destined for the vu”) does not occur under a test that isolates that control.

**Subdomain takeover, a brief explanation Subdomain takeover occurs when an attacker gains control of a subdomain belonging to a legitimate domain of the target.**

s it easy to find dangling DNS records and potential subdomain takeovers . Findings without proper triage and remediation is yet of little value. Collaborate on the platform with members of your security team and developers. Or make use of our powerful integrations to fit your workflows. From Jira and Slack to Datadog and Splunk. Connect using Workato, a flexible iPaaS, or with our versatile API. Subdomain takeover, a brief explanation Subdomain takeover occurs when an attacker gains control of a subdomain belonging to a legitimate domain of the target. This often happens because the subdomain's DNS record hasn't been properly de-provisioned or points to a service that is no longer in use. Hostile subdomain takeover is a term coined by Detectify Security Researchers ( read the original writeup ). It refers to when an attacker takes control of a service no longer in use but that the target still has a DNS record pointing a subdomain to. As the DN

*Disproof:* Refuted when: the same behaviour is absent when the single named control in the claim is present, and the control is shown to be present rather than assumed. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“Subdomain takeover, a brief explanation Subdomain takeover occurs when an attack”) does not occur under a test that isolates that control.

**Subdomain takeover, a brief explanation Subdomain takeover occurs when an attacker gains control of a subdomain belonging to a legitimate domain of the target.**

s it easy to find dangling DNS records and potential subdomain takeovers . Findings without proper triage and remediation is yet of little value. Collaborate on the platform with members of your security team and developers. Or make use of our powerful integrations to fit your workflows. From Jira and Slack to Datadog and Splunk. Connect using Workato, a flexible iPaaS, or with our versatile API. Subdomain takeover, a brief explanation Subdomain takeover occurs when an attacker gains control of a subdomain belonging to a legitimate domain of the target. This often happens because the subdomain's DNS record hasn't been properly de-provisioned or points to a service that is no longer in use. Hostile subdomain takeover is a term coined by Detectify Security Researchers ( read the original writeup ). It refers to when an attacker takes control of a service no longer in use but that the target still has a DNS record pointing a subdomain to. As the DN

*Disproof:* Refuted when: the same behaviour is absent when the single named control in the claim is present, and the control is shown to be present rather than assumed. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“Subdomain takeover, a brief explanation Subdomain takeover occurs when an attack”) does not occur under a test that isolates that control.

**The takeover is usually only considered severe if it compromises other systems or gives direct access to user data (such as cookies).**

le subdomain takeover is a term coined by Detectify Security Researchers ( read the original writeup ). It refers to when an attacker takes control of a service no longer in use but that the target still has a DNS record pointing a subdomain to. As the DNS record points to a vacant service, this is also referred to as dangling DNS entries . The severity of a subdomain takeover is very contextual. The takeover is usually only considered severe if it compromises other systems or gives direct access to user data (such as cookies). Spinning up a fake page on the compromised subdomain for phishing purposes is bad enough. Consider an attacker getting control of one out of many Name Server (NS) delegations for the root (apex) zone. Then the severity can get worse than the most critical form of SQL injection. This can, over time, give the attacker access to all traffic destined for the vulnerable domain, including all its subdo

*Disproof:* Refuted when: the same behaviour is absent when the single named control in the claim is present, and the control is shown to be present rather than assumed. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“The takeover is usually only considered severe if it compromises other systems o”) does not occur under a test that isolates that control.

**This often happens because the subdomain's DNS record hasn't been properly de-provisioned or points to a service that is no longer in use.**

,"add_second_content_block":false,"add_testimonial":false,"add_browser_bar_styling":false,"add_floating_image":false,"review":{"stars":0}}},{"id":"mlqkxpzl","type":"half_width_content","data":{"image_alignment":"Right","heading":"Subdomain takeover, a brief explanation","text":" Subdomain takeover occurs when an attacker gains control of a subdomain belonging to a legitimate domain of the target. This often happens because the subdomain's DNS record hasn't been properly de-provisioned or points to a service that is no longer in use. Hostile subdomain takeover is a term coined by Detectify Security Researchers ( read the original writeup ). It refers to when an attacker takes control of a service no longer in use but that the target still has a DNS record pointing a subdomain to. As the DNS record points to a vacant service, this is also referred to as dangling DNS entries . The severity of a subdomain takeover is very contex

*Disproof:* Refuted when: the same behaviour is absent when the single named control in the claim is present, and the control is shown to be present rather than assumed. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“This often happens because the subdomain's DNS record hasn't been properly de-pr”) does not occur under a test that isolates that control.

**This can, over time, give the attacker access to all traffic destined for the vulnerable domain, including all its subdomains.**

is usually only considered severe if it compromises other systems or gives direct access to user data (such as cookies). Spinning up a fake page on the compromised subdomain for phishing purposes is bad enough. Consider an attacker getting control of one out of many Name Server (NS) delegations for the root (apex) zone. Then the severity can get worse than the most critical form of SQL injection. This can, over time, give the attacker access to all traffic destined for the vulnerable domain, including all its subdomains. ","image":"https://d35ayjp87i0qx4.cloudfront.net/subdomain-takeover-(1).png","add_button":false,"add_second_content_block":false,"add_testimonial":false,"add_browser_bar_styling":false,"add_floating_image":false,"review":{"stars":0}}},{"id":"mlqkye99","type":"ethical_hackers_cta","data":{"heading":"Take action where it matters","subheading":"Detectify Crowdsource","description":"From subdomain ta

*Disproof:* Refuted when: the same behaviour is absent when the single named control in the claim is present, and the control is shown to be present rather than assumed. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“This can, over time, give the attacker access to all traffic destined for the vu”) does not occur under a test that isolates that control.

**When an MX record points at a mail-server hostname that has expired and become registrable, an outsider can claim that hostname and silently receive mail for the affected domain or subdomain.**

The hunter gets a concrete passive check: resolve every MX target across the domain and subdomain estate, then test which of those targets are themselves available for registration. The exposure lives below the apex domain, where most subdomain-hunting effort stops, and a registration attempt is a far cheaper test than the credential-phishing outcome it enables. The claim is falsified by an estate in which every MX target resolves to an actively controlled, registered host with no expiry available in the registration record.

*Disproof:* A DNS estate in which every MX target hostname resolves to an actively controlled, registered host with no expiry in the registration record would refute the claim.

**A subdomain takeover is established when a hostname's CNAME still points at a third-party PaaS domain that no longer serves, letting the tester register that third-party hostname and take control of the subdomain.**

A subdomain takeover is established when a hostname's CNAME still points at a third-party PaaS domain that no longer serves, letting the tester register that third-party hostname and take control of the subdomain.

HackTricks reference: easy methods (https://kathan19.gitbook.io/howtohunt/subdomain-takeover/easy_methods.md)

*Disproof:* The CNAME target still serves content or returns a provider-owned response other than a dangling 404, meaning the subscription is active and the hostname is unclaimable.

**A subdomain takeover is established when a hostname's CNAME still points at a third-party PaaS domain that no longer serves, letting the tester register that third-party hostname and take control of the subdomain.**

A subdomain takeover is established when a hostname's CNAME still points at a third-party PaaS domain that no longer serves, letting the tester register that third-party hostname and take control of the subdomain.

HackTricks reference: easy methods (https://kathan19.gitbook.io/howtohunt/subdomain-takeover/easy_methods.md)

*Disproof:* The CNAME target still serves content or returns a provider-owned response other than a dangling 404, meaning the subscription is active and the hostname is unclaimable.

## Variations

**On a partial CNAME setup the proxying provider only fronts the subdomains explicitly delegated to it, so the tester must not assume the whole zone is under that provider's control — a subdomain outside the delegated set has different takeover prerequisites and different record expectations.**

Mechanism: On a partial CNAME setup the proxying provider only fronts the subdomains explicitly delegated to it, so the tester must not assume the whole zone is under that provider's control — a subdomain outside the delegated set has different takeover prerequisites and different record expectations. How to apply it in the field: treat this as the bypass it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable. Boundary of the rule: The rule is false when the zone uses the primary (full) setup with all records managed by the proxying provider, in which case every subdomain is on the same footing and the partial-setup distinction carries no security consequence for the specific name being tested.

*Disproof:* The rule is false when the zone uses the primary (full) setup with all records managed by the proxying provider, in which case every subdomain is on the same footing and the partial-setup distinction carries no security consequence for the specific name being tested.

**A dangling record that enables takeover can be a CNAME or an A record pointing at a released IP address, so DNS enumeration has to inspect both record types instead of CNAMEs alone.**

A dangling record that enables takeover can be a CNAME or an A record pointing at a released IP address, so DNS enumeration has to inspect both record types instead of CNAMEs alone.

OWASP notes that A records pointing to released IP addresses can be vulnerable if the IP is reassigned and the attacker obtains it; Microsoft describes the CNAME case where a DNS record points to a deprovisioned Azure resource.

*Disproof:* No A or CNAME record in the zone resolves to an unclaimed third-party service, leaving no dangling target to register.

**A dangling record that enables takeover can be a CNAME or an A record pointing at third-party services, so DNS enumeration has to inspect both record types instead of CNAMEs alone.**

A dangling record that enables takeover can be a CNAME or an A record pointing at third-party services, so DNS enumeration has to inspect both record types instead of CNAMEs alone.

HackTricks reference: sub or top level domain takeover (https://kathan19.gitbook.io/howtohunt/subdomain-takeover/sub_or_top_level_domain_takeover.md)

*Disproof:* No A or CNAME record in the zone resolves to an unclaimed third-party service, leaving no dangling target to register.

## Technology / Framework Considerations

Not yet researched.

## API Considerations

Not yet researched.

## Attack Chains

- `chain.subdomain_takeover.auto.01` — subdomain_takeover: observe, exercise, confirm (goal: `Establish, exercise and confirm a subdomain_takeover condition on an authorised target without relying on anyone else's data.`)

## Real-World Examples

Not yet researched.

## Common False Positives

**A CNAME pointing at a third-party service hostname is not a takeover finding until the tester has proven that service instance can actually be registered or claimed; a dangling-looking record to a provider that namespaces per customer with a random or account-bound token does not hand the name to whoever requests it.**

Mechanism: A CNAME pointing at a third-party service hostname is not a takeover finding until the tester has proven that service instance can actually be registered or claimed; a dangling-looking record to a provider that namespaces per customer with a random or account-bound token does not hand the name to whoever requests it. How to apply it in the field: treat this as the fp_rule it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable. Boundary of the rule: The rule is wrong when the specific provider and resource type are confirmed claimable — an unclaimed bucket or app name that resolves to the provider's generic hosting endpoint — because the takeover then depends only on registering that resource, not on any token; the fingerprint must be re-checked against the provider's current signup rules rather than assumed.

*Disproof:* The rule is wrong when the specific provider and resource type are confirmed claimable — an unclaimed bucket or app name that resolves to the provider's generic hosting endpoint — because the takeover then depends only on registering that resource, not on any token; the fingerprint must be re-checked against the provider's current signup rules rather than assumed.

**Reject a subdomain_takeover finding until it is distinguished from the adjacent behaviour this class also covers. "A DNS record left pointing at a de-provisioned third-party service lets an attacker serve content on a host inside the target's own domain, which converts into session theft whenever the session cookie's Domain attribute covers that..." and "A dangling NS delegation is categorically worse than a dangling CNAME because the transitive trust built into DNS makes every domain that directly or indirectly depends on that record vulnerable, not only the subdomain that owns it." share a surface and a symptom, so a response that matches the first is not evidence for it while the second remains possible.**

Hypothesis under test: A DNS record left pointing at a de-provisioned third-party service lets an attacker serve content on a host inside the target's own domain, which converts into session theft whenever the session cookie's Domain attribute covers that...

Adjacent behaviour that produces the same observable result: A dangling NS delegation is categorically worse than a dangling CNAME because the transitive trust built into DNS makes every domain that directly or indirectly depends on that record vulnerable, not only the subdomain that owns it.

Why this is worth checking before reporting: both are recorded in this class as gated knowledge, so a tester who stops at the first match will report one of them. The two differ in what the server actually did with the input, and that difference is observable in the response rather than in the request.

Required before treating this as a finding: capture the response that demonstrates the first behaviour specifically, and confirm the second is not what was observed.

*Disproof:* This rule is wrong if a controlled test shows the two behaviours can never co-occur on the same surface, or if the corpus entry for "A dangling NS delegation is categorically worse than a dangling CNAME " is out of date. In that case this class needs its false-positive guidance rewritten rather than deleted.

**Resolving the victim hostname to a generic provider IP is not by itself a takeover: CNAME flattening intentionally resolves the chain to a final IP address instead of returning the CNAME record, so an IP-only view of the resolution hides the very record that would identify the claimable target.**

Mechanism: Resolving the victim hostname to a generic provider IP is not by itself a takeover: CNAME flattening intentionally resolves the chain to a final IP address instead of returning the CNAME record, so an IP-only view of the resolution hides the very record that would identify the claimable target. How to apply it in the field: treat this as the fp_rule it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable. Boundary of the rule: The rule is wrong when the flattening provider's own IP is what serves the unclaimed-resource page for the victim's hostname — in that case the flattened resolution did remove the record-level evidence while the takeover remains real, and the finding must rest on the content-served observation rather than the DNS record.

*Disproof:* The rule is wrong when the flattening provider's own IP is what serves the unclaimed-resource page for the victim's hostname — in that case the flattened resolution did remove the record-level evidence while the takeover remains real, and the finding must rest on the content-served observation rather than the DNS record.

**A hostname returned by passive subdomain enumeration is a lead, not a subdomain takeover; do not file it unless the dangling DNS record resolves to a provider whose own resource is confirmed unclaimed, because a passive record frequently points at a shared, still-registered SaaS tenant that resolves and serves normally.**

The observable that triggers this false positive is a hostname appearing in passive subdomain enumeration output and filed as a subdomain takeover. Passive enumeration collects records from third-party datasets, and a CNAME in such a dataset frequently points at a shared SaaS tenant that is still registered and serving normally - the record is real but the resource behind it belongs to someone. Takeover requires a provider-side unclaimed resource, and that is the only observation that proves a third party could actually register it. This rule therefore filters the passive-list membership and holds the report to the provider's unclaimed-resource response plus a resource identifier the assessor can register, which is the difference between a lead and a demonstrated claimable subdomain.

*Disproof:* The CNAME target's provider returns an explicit unclaimed or no-such-site error for the resource, and the resource identifier in the DNS record can be registered by the assessor - which is the actual proof that a third party could take it over.
**Hypothesis:** Link-branding subdomains CNAME to the provider's bare apex domain, therefore they are dangling takeovers
- Invalidated by: The body was byte-identical to the provider's own apex 404, the documented takeover fingerprint was absent from the response, the vendor integration is marked not vulnerable, and the account is still active with live DKIM keys and an SPF include. Only these three branding CNAMEs are unconfigured leftovers
- **Rejection rule:** A CNAME to a provider's BARE apex is not an account-specific fingerprint. Confirm the response differs from the provider's own apex root and that the documented takeover string is present in the body; then confirm the vendor account is still live. Apex CNAMEs with none of those are leftovers

**Hypothesis:** A subdomain resolves to a hosting provider whose anti-takeover verification record is present, therefore the takeover is blocked
- Invalidated by: The provider's anti-takeover verification TXT record is present in the zone, so ownership is already proven and a third party cannot claim the name
- **Rejection rule:** A dangling CNAME on a provider that uses an ownership-verification TXT record is protected while that record is present. Check the zone for it before reporting; its presence is the disproof, not a mitigating factor

**Hypothesis:** A subdomain CNAMEs to a SaaS provider whose own domain-ownership lock means a third party must publish a verification TXT record in the zone, therefore the hostname is not claimable and the dangling record is DNS hygiene only
- Invalidated by: Claiming the hostname requires proving ownership by publishing a TXT record in the victim's DNS zone, which requires control of that zone. The provider additionally implements an ownership lock, so the hostname is bound to a previously-provisioned account and other accounts cannot adopt it
- **Rejection rule:** A dangling CNAME is not a takeover until the provider is shown to be CLAIMABLE by a third party. If signup requires a TXT record in the victim's zone, or the vendor is not on the known-vulnerable list, or the provider locks ownership after first use, the finding is DNS hygiene. State the claimability test explicitly and cite the provider doc that settles it

**Hypothesis:** A subdomain CNAMEs to a shared provider domain and the provider serves an empty page, therefore the record is dangling and claimable
- Invalidated by: The random hostname returned the identical response, so the provider serves that body for ANY hostname - it is a wildcard catch-all, not an unconfigured hostname. Nothing is reserved and nothing is dangling
- **Rejection rule:** Before calling any provider response a dangling record, send a RANDOM Host header to the same edge IP. If the response is identical, the provider is a wildcard catch-all and your hostname is indistinguishable from a name that was never configured - that is not a takeover

## Validation

**A subdomain takeover is proved by serving attacker-controlled content on the victim's own hostname, which requires two observations: a claimable resource identified on the provider, and that resource's content appearing when the victim hostname is requested.**

Mechanism: A subdomain takeover is proved by serving attacker-controlled content on the victim's own hostname, which requires two observations: a claimable resource identified on the provider, and that resource's content appearing when the victim hostname is requested. How to apply it in the field: treat this as the validation it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable. Boundary of the rule: The claim is false where the provider shows a generic "site not found" or parking/interstitial page for unclaimed resources — that response is provider-controlled, not attacker content, so it demonstrates the dangling record but not the ability to serve content, and the item must be reported at the lower severity or held until content control is shown.

*Disproof:* The claim is false where the provider shows a generic "site not found" or parking/interstitial page for unclaimed resources — that response is provider-controlled, not attacker content, so it demonstrates the dangling record but not the ability to serve content, and the item must be reported at the lower severity or held until content control is shown.

**To decide this case, observe: How to apply it in the field: treat this as the fp_rule it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable.**

Derived from subdomain_takeover.fp_rule.a_dangling_record_is_only_a_risk_when_the_target_service_can_actually_be_claimed, which states the false-positive boundary for this class. The observable above is what separates a real finding from the pattern that only looks like one. A hunter who cannot produce this observation in a request/response pair does not have a finding yet.

*Disproof:* This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (subdomain_takeover.fp_rule.a_dangling_record_is_only_a_risk_when_the_target_service_can_actually_be_claimed) states the full boundary.

**To decide this case, observe: How to apply it in the field: treat this as the validation it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable.**

Derived from subdomain_takeover.validation.proof_is_a_success_response_from_the_victim_hostname_plus_a_claimed_resource, which states the false-positive boundary for this class. The observable above is what separates a real finding from the pattern that only looks like one. A hunter who cannot produce this observation in a request/response pair does not have a finding yet.

*Disproof:* This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (subdomain_takeover.validation.proof_is_a_success_response_from_the_victim_hostname_plus_a_claimed_resource) states the full boundary.

**To decide this case, observe: How to apply it in the field: treat this as the bypass it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable.**

Derived from subdomain_takeover.bypass.a_partial_cname_setup_means_one_provider_proxies_only_some_subdomains, which states the false-positive boundary for this class. The observable above is what separates a real finding from the pattern that only looks like one. A hunter who cannot produce this observation in a request/response pair does not have a finding yet.

*Disproof:* This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (subdomain_takeover.bypass.a_partial_cname_setup_means_one_provider_proxies_only_some_subdomains) states the full boundary.

**To decide this case, observe: How to apply it in the field: treat this as the fp_rule it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable.**

Derived from subdomain_takeover.fp_rule.cname_flattening_makes_the_resolved_ip_normal_not_takeover_evidence, which states the false-positive boundary for this class. The observable above is what separates a real finding from the pattern that only looks like one. A hunter who cannot produce this observation in a request/response pair does not have a finding yet.

*Disproof:* This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (subdomain_takeover.fp_rule.cname_flattening_makes_the_resolved_ip_normal_not_takeover_evidence) states the full boundary.

## Impact

**A dangling NS delegation is categorically worse than a dangling CNAME because the transitive trust built into DNS makes every domain that directly or indirectly depends on that record vulnerable, not only the subdomain that owns it.**

The impact ceiling of a dangling record is set by record type, and the published research separates the cases explicitly. A CNAME record specifies the canonical name of an alias domain, so hijacking it affects the alias alone. An NS record instead delegates an authoritative name server, and when the delegation is dangling the damage inherits from DNS design rather than from application logic: the transitive trust that is built into DNS could make all domains that directly or indirectly depend on the dangling NS record vulnerable, because a domain usually has multiple NS records. The Detectify framing agrees on the ceiling, noting that an attacker taking control of one of many name server delegations for the root apex zone can push severity beyond the most critical injection bug. The practical consequence for triage is that a dangling NS cannot be dispositioned by asking which host it exposes, only by asking how many zones delegate through it.

*Disproof:* Refuted when the delegated name server still resolves to infrastructure the organisation controls and has not been released, or when the affected zone delegates exclusively through records that remain bound, leaving no dangling path to the apex.

**A taken-over subdomain is dangerous beyond content control because the attacker's service can inherit the domain owner's wildcard SSL, making phishing on the subdomain TLS-trusted and unknown to the owner.**

A taken-over subdomain is dangerous beyond content control because the attacker's service can inherit the domain owner's wildcard SSL, making phishing on the subdomain TLS-trusted and unknown to the owner.

HackTricks reference: sub or top level domain takeover (https://kathan19.gitbook.io/howtohunt/subdomain-takeover/sub_or_top_level_domain_takeover.md)

*Disproof:* The service provider issues no certificate covering the hostname to its new registrant, so the attacker's service cannot present the owner's wildcard certificate.

**A taken-over subdomain is dangerous beyond content control because the attacker's service can inherit the domain owner's wildcard SSL, making phishing on the subdomain TLS-trusted and unknown to the owner.**

A taken-over subdomain is dangerous beyond content control because the attacker's service can inherit the domain owner's wildcard SSL, making phishing on the subdomain TLS-trusted and unknown to the owner.

HackTricks reference: sub or top level domain takeover (https://kathan19.gitbook.io/howtohunt/subdomain-takeover/sub_or_top_level_domain_takeover.md)

*Disproof:* The service provider issues no certificate covering the hostname to its new registrant, so the attacker's service cannot present the owner's wildcard certificate.

## Related Bug Classes

Not yet researched.

## References

- **blog.qualys.com** (research)
  - <https://blog.qualys.com/product-tech/2024/01/11/totalcloud-insights-crafting-effective-indicators-of-compromise-iocs-for-sub-domain-takeover-risk-detection>
- **cheatsheetseries.owasp.org** (cheatsheet)
  - <https://cheatsheetseries.owasp.org/cheatsheets/Subdomain_Takeover_Prevention_Cheat_Sheet.html>
- **detectify.com** (research)
  - <https://detectify.com/solutions/prevent-subdomain-takeover>
  - <https://www.detectify.com/solutions/prevent-subdomain-takeover>
- **developers.cloudflare.com** (writeup)
  - <https://developers.cloudflare.com/dns/cname-flattening/>
  - <https://developers.cloudflare.com/dns/zone-setups/>
- **docs.projectdiscovery.io** (docs)
  - <https://docs.projectdiscovery.io/opensource/subfinder/>
- **firebase.google.com** (writeup)
  - <https://firebase.google.com/docs/hosting/full-config>
- **httpwg.org** (standard)
  - <https://httpwg.org/specs/rfc6265.html>
- **kathan19.gitbook.io** (reference)
  - <https://kathan19.gitbook.io/howtohunt/subdomain-takeover/easy_methods.md>
  - <https://kathan19.gitbook.io/howtohunt/subdomain-takeover/sub_or_top_level_domain_takeover.md>
  - <https://kathan19.gitbook.io/howtohunt/subdomain-takeover/subdomain_takeover.md>
- **labs.watchtowr.com** (research)
  - <https://labs.watchtowr.com/the-perils-of-expired-domains-were-reading-your-email/>
- **learn.microsoft.com** (docs)
  - <https://learn.microsoft.com/en-us/azure/security/fundamentals/subdomain-takeover>
- **netlify.com** (docs)
  - <https://www.netlify.com/docs/domains/custom-domains/>
- **raw.githubusercontent.com** (research)
  - <https://raw.githubusercontent.com/EdOverflow/can-i-take-over-xyz/master/README.md>
- **unit42.paloaltonetworks.com** (research)
  - <https://unit42.paloaltonetworks.com/dangling-domains/>

Every item above is gated on >= 2 distinct publisher hosts (`wks/quality.py`, rule R1). Publisher diversity, not citation count, is what makes these corroborated.
