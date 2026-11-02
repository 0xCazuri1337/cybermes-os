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
--- subdomain_takeover@current
+++ subdomain_takeover@new
@@ -73,4 +73,4 @@
   - Sources: <https://httpwg.org/specs/rfc6265.html> · <https://blog.qualys.com/product-tech/2024/01/11/totalcloud-insights-crafting-effective-indicators-of-compromise-iocs-for-sub-domain-takeover-risk-detection>
 
 ---
-Full class document: `domains/web/subdomain_takeover/EVIDENCE.md` · retrieve more with `python -m wks.cli search "<query>" --class-id subdomain_takeover`
+Full class document: `domains/web/subdomain_takeover/knowledge/DIGEST.md` · retrieve more with `python -m wks.cli search "<query>" --class-id subdomain_takeover`
```

## 2026-10-02 19:37 — 107 diff lines
- items: 23 (supported 15), FP rules 4, chains 1, state mature

```diff
--- subdomain_takeover@current
+++ subdomain_takeover@new
@@ -10,7 +10,7 @@
      python -m wks.skillgen -->
 
 > surface `infra` · CWE 404 · OWASP A10:2021
-> evidence: 14 items, 14 supported, 2 FP rules, 1 chains
+> evidence: 23 items, 15 supported, 4 FP rules, 1 chains
 > maturity: **mature**
 
 A DNS record still points at a de-provisioned service that anyone can now claim.
@@ -20,48 +20,87 @@
 
 ## Techniques (what to change)
 
-- This often happens because the subdomain's DNS record hasn't been properly de-provisioned or points to a service that is no longer in use.
+- This often happens because the subdomain's DNS record hasn't been properly de-provisioned or points to a service that is no longer in use. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "This often happens because the subdomain's DNS record hasn't been properly de-provisioned ".
   - Sources: <https://httpwg.org/specs/rfc6265.html> · <https://www.detectify.com/solutions/prevent-subdomain-takeover>
-- The takeover is usually only considered severe if it compromises other systems or gives direct access to user data (such as cookies).
+- The takeover is usually only considered severe if it compromises other systems or gives direct access to user data (such as cookies). _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "The takeover is usually only considered severe if it compromises other systems or gives di".
   - Sources: <https://httpwg.org/specs/rfc6265.html> · <https://www.detectify.com/solutions/prevent-subdomain-takeover>
-- This can, over time, give the attacker access to all traffic destined for the vulnerable domain, including all its subdomains.
+- This can, over time, give the attacker access to all traffic destined for the vulnerable domain, including all its subdomains. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "This can, over time, give the attacker access to all traffic destined for the vulnerable d".
   - Sources: <https://httpwg.org/specs/rfc6265.html> · <https://www.detectify.com/solutions/prevent-subdomain-takeover>
-- Subdomain takeover, a brief explanation Subdomain takeover occurs when an attacker gains control of a subdomain belonging to a legitimate domain of the target.
+- Subdomain takeover, a brief explanation Subdomain takeover occurs when an attacker gains control of a subdomain belonging to a legitimate domain of the target. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Subdomain takeover, a brief explanation Subdomain takeover occurs when an attacker gains c".
   - Sources: <https://httpwg.org/specs/rfc6265.html> · <https://www.detectify.com/solutions/prevent-subdomain-takeover>
-- Subdomain takeover, a brief explanation Subdomain takeover occurs when an attacker gains control of a subdomain belonging to a legitimate domain of the target.
+- Subdomain takeover, a brief explanation Subdomain takeover occurs when an attacker gains control of a subdomain belonging to a legitimate domain of the target. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Subdomain takeover, a brief explanation Subdomain takeover occurs when an attacker gains c".
   - Sources: <https://httpwg.org/specs/rfc6265.html> · <https://www.detectify.com/solutions/prevent-subdomain-takeover>
-- The takeover is usually only considered severe if it compromises other systems or gives direct access to user data (such as cookies).
+- The takeover is usually only considered severe if it compromises other systems or gives direct access to user data (such as cookies). _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "The takeover is usually only considered severe if it compromises other systems or gives di".
   - Sources: <https://httpwg.org/specs/rfc6265.html> · <https://www.detectify.com/solutions/prevent-subdomain-takeover>
-- This often happens because the subdomain's DNS record hasn't been properly de-provisioned or points to a service that is no longer in use.
+- This often happens because the subdomain's DNS record hasn't been properly de-provisioned or points to a service that is no longer in use. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "This often happens because the subdomain's DNS record hasn't been properly de-provisioned ".
   - Sources: <https://httpwg.org/specs/rfc6265.html> · <https://www.detectify.com/solutions/prevent-subdomain-takeover>
-- This can, over time, give the attacker access to all traffic destined for the vulnerable domain, including all its subdomains.
+- This can, over time, give the attacker access to all traffic destined for the vulnerable domain, including all its subdomains. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "This can, over time, give the attacker access to all traffic destined for the vulnerable d".
   - Sources: <https://httpwg.org/specs/rfc6265.html> · <https://www.detectify.com/solutions/prevent-subdomain-takeover>
 - When an MX record points at a mail-server hostname that has expired and become registrable, an outsider can claim that hostname and silently receive mail for the affected domain or subdomain.
   - **Disproof:** A DNS estate in which every MX target hostname resolves to an actively controlled, registered host with no expiry in the registration record would refute the claim.
   - Sources: <https://labs.watchtowr.com/the-perils-of-expired-domains-were-reading-your-email/> · <https://www.detectify.com/solutions/prevent-subdomain-takeover>
 
+## Tests
+
+- To decide this case, observe: treat this as the fp_rule it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable. Boundary of the rule: The rule is wrong when the specific provider and resource type are confirmed claimable — an unclaimed bucket or app name that resolves to the provider's generic hosting endpo
+  - **Disproof:** This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (subdomain_takeover.fp_rule.a_dangling_record_is_only_a_risk_when_the_target_service_can_actually_be_claimed) states the full boundary.
+  - Sources: <https://developers.cloudflare.com/dns/cname-flattening/> · <https://firebase.google.com/docs/hosting/full-config>
+- To decide this case, observe: eat this as the validation it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable. Boundary of the rule: The claim is false where the provider shows a generic "site not found" or parking/interstitial page for unclaimed resources — that response is provider-controlled, not attack
+  - **Disproof:** This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (subdomain_takeover.validation.proof_is_a_success_response_from_the_victim_hostname_plus_a_claimed_resource) states the full boundary.
+  - Sources: <https://developers.cloudflare.com/dns/zone-setups/> · <https://firebase.google.com/docs/hosting/full-config>
+- To decide this case, observe: : treat this as the bypass it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable. Boundary of the rule: The rule is false when the zone uses the primary (full) setup with all records managed by the proxying provider, in which case every subdomain is on the same footing and the
+  - **Disproof:** This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (subdomain_takeover.bypass.a_partial_cname_setup_means_one_provider_proxies_only_some_subdomains) states the full boundary.
+  - Sources: <https://developers.cloudflare.com/dns/cname-flattening/> · <https://firebase.google.com/docs/hosting/full-config>
+- To decide this case, observe: treat this as the fp_rule it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable. Boundary of the rule: The rule is wrong when the flattening provider's own IP is what serves the unclaimed-resource page for the victim's hostname — in that case the flattened resolution did remov
+  - **Disproof:** This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (subdomain_takeover.fp_rule.cname_flattening_makes_the_resolved_ip_normal_not_takeover_evidence) states the full boundary.
+  - Sources: <https://developers.cloudflare.com/dns/cname-flattening/> · <https://firebase.google.com/docs/hosting/full-config>
+
+## Validation bar (how to prove it)
+
+- A subdomain takeover is proved by serving attacker-controlled content on the victim's own hostname, which requires two observations: a claimable resource identified on the provider, and that resource's content appearing when the victim hostname is requested.
+  - **Disproof:** The claim is false where the provider shows a generic "site not found" or parking/interstitial page for unclaimed resources — that response is provider-controlled, not attacker content, so it demonstrates the dangling record but not the ability to serve content, and the item must be reported at the lower severity or held until content control is shown.
+  - Sources: <https://developers.cloudflare.com/dns/zone-setups/> · <https://firebase.google.com/docs/hosting/full-config>
+
 ## False-positive rules (when to reject it)
 
+- A CNAME pointing at a third-party service hostname is not a takeover finding until the tester has proven that service instance can actually be registered or claimed; a dangling-looking record to a provider that namespaces per customer with a random or account-bound token does not hand the name to whoever requests it.
+  - **Disproof:** The rule is wrong when the specific provider and resource type are confirmed claimable — an unclaimed bucket or app name that resolves to the provider's generic hosting endpoint — because the takeover then depends only on registering that resource, not on any token; the fingerprint must be re-checked against the provider's current signup rules rather than assumed.
+  - Sources: <https://developers.cloudflare.com/dns/cname-flattening/> · <https://firebase.google.com/docs/hosting/full-config>
 - Reject a subdomain_takeover finding until it is distinguished from the adjacent behaviour this class also covers. "A DNS record left pointing at a de-provisioned third-party service lets an attacker serve content on a host inside the target's own domain, which converts into session theft whenever the session cookie's Domain attribute covers that..." and "A dangling NS delegation is categorically worse than a dangling CNAME because the transitive trust built into DNS makes every domain that directly or indirectly depends on that record vulnerable, not only the subdomain that owns it." share a surface and a symptom, so a response that matches the first is not evidence for it while the second remains possible.
   - **Disproof:** This rule is wrong if a controlled test shows the two behaviours can never co-occur on the same surface, or if the corpus entry for "A dangling NS delegation is categorically worse than a dangling CNAME " is out of date. In that case this class needs its false-positive guidance rewritten rather than deleted.
   - Sources: <https://detectify.com/solutions/prevent-subdomain-takeover> · <https://blog.qualys.com/product-tech/2024/01/11/totalcloud-insights-crafting-effective-indicators-of-compromise-iocs-for-sub-domain-takeover-risk-detection>
+- Resolving the victim hostname to a generic provider IP is not by itself a takeover: CNAME flattening intentionally resolves the chain to a final IP address instead of returning the CNAME record, so an IP-only view of the resolution hides the very record that would identify the claimable target.
+  - **Disproof:** The rule is wrong when the flattening provider's own IP is what serves the unclaimed-resource page for the victim's hostname — in that case the flattened resolution did remove the record-level evidence while the takeover remains real, and the finding must rest on the content-served observation rather than the DNS record.
+  - Sources: <https://developers.cloudflare.com/dns/cname-flattening/> · <https://firebase.google.com/docs/hosting/full-config>
 - A hostname returned by passive subdomain enumeration is a lead, not a subdomain takeover; do not file it unless the dangling DNS record resolves to a provider whose own resource is confirmed unclaimed, because a passive record frequently points at a shared, still-registered SaaS tenant that resolves and serves normally.
   - **Disproof:** The CNAME target's provider returns an explicit unclaimed or no-such-site error for the resource, and the resource identifier in the DNS record can be registered by the assessor - which is the actual proof that a third party could take it over.
   - Sources: <https://docs.projectdiscovery.io/opensource/subfinder/> · <https://www.netlify.com/docs/domains/custom-domains/>
+
+## Evidence requirements
+
+- The distinguishing observation is the provider's own unclaimed-resource response when the target endpoint is requested directly, because that is what ties the victim hostname to a specific claimable resource type rather than to a merely deprecated or unreachable service.
+  - **Disproof:** The claim is false when the provider returns an indistinguishable generic error for both unclaimed and nonexistent resources, in which case the fingerprint cannot be established from the response alone and the finding needs a signup attempt or a provider-side confirmation instead of a response-body match.
+  - Sources: <https://developers.cloudflare.com/dns/cname-flattening/> · <https://firebase.google.com/docs/hosting/full-config>
 
 ## Impact framing
 
 - A dangling NS delegation is categorically worse than a dangling CNAME because the transitive trust built into DNS makes every domain that directly or indirectly depends on that record vulnerable, not only the subdomain that owns it.
   - **Disproof:** Refuted when the delegated name server still resolves to infrastructure the organisation controls and has not been released, or when the affected zone delegates exclusively through records that remain bound, leaving no dangling path to the apex.
   - Sources: <https://detectify.com/solutions/prevent-subdomain-takeover> · <https://unit42.paloaltonetworks.com/dangling-domains/>
+
+## Defence bypasses
+
+- On a partial CNAME setup the proxying provider only fronts the subdomains explicitly delegated to it, so the tester must not assume the whole zone is under that provider's control — a subdomain outside the delegated set has different takeover prerequisites and different record expectations.
+  - **Disproof:** The rule is false when the zone uses the primary (full) setup with all records managed by the proxying provider, in which case every subdomain is on the same footing and the partial-setup distinction carries no security consequence for the specific name being tested.
+  - Sources: <https://developers.cloudflare.com/dns/cname-flattening/> · <https://developers.cloudflare.com/dns/zone-setups/> · <https://firebase.google.com/docs/hosting/full-config>
 
 ## Chaining opportunities
 
```

## 2026-10-03 01:46 — 126 diff lines
- items: 35 (supported 19), FP rules 4, chains 1, state mature

```diff
--- subdomain_takeover@current
+++ subdomain_takeover@new
@@ -10,13 +10,31 @@
      python -m wks.skillgen -->
 
 > surface `infra` · CWE 404 · OWASP A10:2021
-> evidence: 23 items, 15 supported, 4 FP rules, 1 chains
+> evidence: 35 items, 19 supported, 4 FP rules, 1 chains
 > maturity: **mature**
 
 A DNS record still points at a de-provisioned service that anyone can now claim.
 
 **Also called:** subdomain takeover, dangling dns, dangling cname
 
+
+## Prerequisites (do not start without these)
+
+- A subdomain becomes attacker-controllable when a cancelled third-party service leaves its CNAME behind in the DNS zone, so the dangling record rather than the provider account is what has to be removed. _(unverified)_
+  - **Disproof:** The CNAME is deleted from the zone file, or the hostname no longer resolves to the abandoned third-party service.
+  - Sources: <https://httpwg.org/specs/rfc6265.html> · <https://kathan19.gitbook.io/howtohunt/subdomain-takeover/subdomain_takeover.md>
+- A subdomain becomes attacker-controllable when a cancelled third-party service leaves its CNAME behind in the DNS zone, so the dangling record rather than the provider account is what has to be removed.
+  - **Disproof:** The CNAME is deleted from the zone file, or the hostname no longer resolves to the abandoned third-party service.
+  - Sources: <https://httpwg.org/specs/rfc6265.html> · <https://blog.qualys.com/product-tech/2024/01/11/totalcloud-insights-crafting-effective-indicators-of-compromise-iocs-for-sub-domain-takeover-risk-detection> · <https://kathan19.gitbook.io/howtohunt/subdomain-takeover/subdomain_takeover.md>
+
+## Recon signals (where to look)
+
+- A dangling CNAME candidate is signalled by the hostname answering with a 404 not found error from the third-party destination it is attached to. _(unverified)_
+  - **Disproof:** The hostname returns a live response from the provider or a different error entirely, so the 404 is not the third-party service's dangling-target response.
+  - Sources: <https://httpwg.org/specs/rfc6265.html> · <https://kathan19.gitbook.io/howtohunt/subdomain-takeover/sub_or_top_level_domain_takeover.md>
+- A dangling CNAME candidate is signalled by the hostname answering with a 404 not found error from the third-party destination it is attached to.
+  - **Disproof:** The hostname returns a live response from the provider or a different error entirely, so the 404 is not the third-party service's dangling-target response.
+  - Sources: <https://httpwg.org/specs/rfc6265.html> · <https://blog.qualys.com/product-tech/2024/01/11/totalcloud-insights-crafting-effective-indicators-of-compromise-iocs-for-sub-domain-takeover-risk-detection> · <https://kathan19.gitbook.io/howtohunt/subdomain-takeover/sub_or_top_level_domain_takeover.md>
 
 ## Techniques (what to change)
 
@@ -47,45 +65,57 @@
 - When an MX record points at a mail-server hostname that has expired and become registrable, an outsider can claim that hostname and silently receive mail for the affected domain or subdomain.
   - **Disproof:** A DNS estate in which every MX target hostname resolves to an actively controlled, registered host with no expiry in the registration record would refute the claim.
   - Sources: <https://labs.watchtowr.com/the-perils-of-expired-domains-were-reading-your-email/> · <https://www.detectify.com/solutions/prevent-subdomain-takeover>
+- A subdomain takeover is established when a hostname's CNAME still points at a third-party PaaS domain that no longer serves, letting the tester register that third-party hostname and take control of the subdomain. _(unverified)_
+  - **Disproof:** The CNAME target still serves content or returns a provider-owned response other than a dangling 404, meaning the subscription is active and the hostname is unclaimable.
+  - Sources: <https://httpwg.org/specs/rfc6265.html> · <https://kathan19.gitbook.io/howtohunt/subdomain-takeover/easy_methods.md>
+- A subdomain takeover is established when a hostname's CNAME still points at a third-party PaaS domain that no longer serves, letting the tester register that third-party hostname and take control of the subdomain.
+  - **Disproof:** The CNAME target still serves content or returns a provider-owned response other than a dangling 404, meaning the subscription is active and the hostname is unclaimable.
+  - Sources: <https://httpwg.org/specs/rfc6265.html> · <https://blog.qualys.com/product-tech/2024/01/11/totalcloud-insights-crafting-effective-indicators-of-compromise-iocs-for-sub-domain-takeover-risk-detection> · <https://kathan19.gitbook.io/howtohunt/subdomain-takeover/easy_methods.md>
 
 ## Tests
 
-- To decide this case, observe: treat this as the fp_rule it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable. Boundary of the rule: The rule is wrong when the specific provider and resource type are confirmed claimable — an unclaimed bucket or app name that resolves to the provider's generic hosting endpo
+- To decide this case, observe: How to apply it in the field: treat this as the fp_rule it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable. _(unverified)_
   - **Disproof:** This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (subdomain_takeover.fp_rule.a_dangling_record_is_only_a_risk_when_the_target_service_can_actually_be_claimed) states the full boundary.
-  - Sources: <https://developers.cloudflare.com/dns/cname-flattening/> · <https://firebase.google.com/docs/hosting/full-config>
-- To decide this case, observe: eat this as the validation it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable. Boundary of the rule: The claim is false where the provider shows a generic "site not found" or parking/interstitial page for unclaimed resources — that response is provider-controlled, not attack
+  - Sources: <https://developers.cloudflare.com/dns/cname-flattening/>
+- To decide this case, observe: How to apply it in the field: treat this as the validation it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable. _(unverified)_
   - **Disproof:** This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (subdomain_takeover.validation.proof_is_a_success_response_from_the_victim_hostname_plus_a_claimed_resource) states the full boundary.
-  - Sources: <https://developers.cloudflare.com/dns/zone-setups/> · <https://firebase.google.com/docs/hosting/full-config>
-- To decide this case, observe: : treat this as the bypass it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable. Boundary of the rule: The rule is false when the zone uses the primary (full) setup with all records managed by the proxying provider, in which case every subdomain is on the same footing and the
+  - Sources: <https://developers.cloudflare.com/dns/zone-setups/>
+- To decide this case, observe: How to apply it in the field: treat this as the bypass it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable.
   - **Disproof:** This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (subdomain_takeover.bypass.a_partial_cname_setup_means_one_provider_proxies_only_some_subdomains) states the full boundary.
   - Sources: <https://developers.cloudflare.com/dns/cname-flattening/> · <https://firebase.google.com/docs/hosting/full-config>
-- To decide this case, observe: treat this as the fp_rule it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable. Boundary of the rule: The rule is wrong when the flattening provider's own IP is what serves the unclaimed-resource page for the victim's hostname — in that case the flattened resolution did remov
+- To decide this case, observe: How to apply it in the field: treat this as the fp_rule it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable. _(unverified)_
   - **Disproof:** This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (subdomain_takeover.fp_rule.cname_flattening_makes_the_resolved_ip_normal_not_takeover_evidence) states the full boundary.
-  - Sources: <https://developers.cloudflare.com/dns/cname-flattening/> · <https://firebase.google.com/docs/hosting/full-config>
+  - Sources: <https://developers.cloudflare.com/dns/cname-flattening/>
 
 ## Validation bar (how to prove it)
 
 - A subdomain takeover is proved by serving attacker-controlled content on the victim's own hostname, which requires two observations: a claimable resource identified on the provider, and that resource's content appearing when the victim hostname is requested.
   - **Disproof:** The claim is false where the provider shows a generic "site not found" or parking/interstitial page for unclaimed resources — that response is provider-controlled, not attacker content, so it demonstrates the dangling record but not the ability to serve content, and the item must be reported at the lower severity or held until content control is shown.
-  - Sources: <https://developers.cloudflare.com/dns/zone-setups/> · <https://firebase.google.com/docs/hosting/full-config>
+  - Sources: <https://www.detectify.com/solutions/prevent-subdomain-takeover> · <https://developers.cloudflare.com/dns/zone-setups/>
 
 ## False-positive rules (when to reject it)
 
 - A CNAME pointing at a third-party service hostname is not a takeover finding until the tester has proven that service instance can actually be registered or claimed; a dangling-looking record to a provider that namespaces per customer with a random or account-bound token does not hand the name to whoever requests it.
   - **Disproof:** The rule is wrong when the specific provider and resource type are confirmed claimable — an unclaimed bucket or app name that resolves to the provider's generic hosting endpoint — because the takeover then depends only on registering that resource, not on any token; the fingerprint must be re-checked against the provider's current signup rules rather than assumed.
-  - Sources: <https://developers.cloudflare.com/dns/cname-flattening/> · <https://firebase.google.com/docs/hosting/full-config>
+  - Sources: <https://unit42.paloaltonetworks.com/dangling-domains/> · <https://developers.cloudflare.com/dns/cname-flattening/>
 - Reject a subdomain_takeover finding until it is distinguished from the adjacent behaviour this class also covers. "A DNS record left pointing at a de-provisioned third-party service lets an attacker serve content on a host inside the target's own domain, which converts into session theft whenever the session cookie's Domain attribute covers that..." and "A dangling NS delegation is categorically worse than a dangling CNAME because the transitive trust built into DNS makes every domain that directly or indirectly depends on that record vulnerable, not only the subdomain that owns it." share a surface and a symptom, so a response that matches the first is not evidence for it while the second remains possible.
   - **Disproof:** This rule is wrong if a controlled test shows the two behaviours can never co-occur on the same surface, or if the corpus entry for "A dangling NS delegation is categorically worse than a dangling CNAME " is out of date. In that case this class needs its false-positive guidance rewritten rather than deleted.
-  - Sources: <https://detectify.com/solutions/prevent-subdomain-takeover> · <https://blog.qualys.com/product-tech/2024/01/11/totalcloud-insights-crafting-effective-indicators-of-compromise-iocs-for-sub-domain-takeover-risk-detection>
+  - Sources: <https://blog.qualys.com/product-tech/2024/01/11/totalcloud-insights-crafting-effective-indicators-of-compromise-iocs-for-sub-domain-takeover-risk-detection> · <https://detectify.com/solutions/prevent-subdomain-takeover>
 - Resolving the victim hostname to a generic provider IP is not by itself a takeover: CNAME flattening intentionally resolves the chain to a final IP address instead of returning the CNAME record, so an IP-only view of the resolution hides the very record that would identify the claimable target.
   - **Disproof:** The rule is wrong when the flattening provider's own IP is what serves the unclaimed-resource page for the victim's hostname — in that case the flattened resolution did remove the record-level evidence while the takeover remains real, and the finding must rest on the content-served observation rather than the DNS record.
-  - Sources: <https://developers.cloudflare.com/dns/cname-flattening/> · <https://firebase.google.com/docs/hosting/full-config>
+  - Sources: <https://httpwg.org/specs/rfc6265.html> · <https://developers.cloudflare.com/dns/cname-flattening/>
 - A hostname returned by passive subdomain enumeration is a lead, not a subdomain takeover; do not file it unless the dangling DNS record resolves to a provider whose own resource is confirmed unclaimed, because a passive record frequently points at a shared, still-registered SaaS tenant that resolves and serves normally.
   - **Disproof:** The CNAME target's provider returns an explicit unclaimed or no-such-site error for the resource, and the resource identifier in the DNS record can be registered by the assessor - which is the actual proof that a third party could take it over.
   - Sources: <https://docs.projectdiscovery.io/opensource/subfinder/> · <https://www.netlify.com/docs/domains/custom-domains/>
 
 ## Evidence requirements
 
+- A convincing observation for this class is: The observable that triggers this false positive is a hostname appearing in passive subdomain enumeration output and filed as a subdomain takeover.
+  - **Disproof:** Not evidence when the observable cannot be produced at all -- blind, server-side-only, or identical-in-every-case behaviour leaves nothing to show. The originating rule (subdomain_takeover.fp_rule.passive_list_is_a_lead_not_a_claimable_subdomain) states the full boundary.
+  - Sources: <https://docs.projectdiscovery.io/opensource/subfinder/> · <https://www.netlify.com/docs/domains/custom-domains/>
+- A convincing observation for this class is: Adjacent behaviour that produces the same observable result: A dangling NS delegation is categorically worse than a dangling CNAME because the transitive trust built into DNS makes every domain that directly or indirectly depends on that record vulnerable, not only the subdomain that owns it.
+  - **Disproof:** Not evidence when the observable cannot be produced at all -- blind, server-side-only, or identical-in-every-case behaviour leaves nothing to show. The originating rule (subdomain_takeover.fp_rule.auto.derived) states the full boundary.
+  - Sources: <https://blog.qualys.com/product-tech/2024/01/11/totalcloud-insights-crafting-effective-indicators-of-compromise-iocs-for-sub-domain-takeover-risk-detection> · <https://detectify.com/solutions/prevent-subdomain-takeover>
 - The distinguishing observation is the provider's own unclaimed-resource response when the target endpoint is requested directly, because that is what ties the victim hostname to a specific claimable resource type rather than to a merely deprecated or unreachable service.
   - **Disproof:** The claim is false when the provider returns an indistinguishable generic error for both unclaimed and nonexistent resources, in which case the fingerprint cannot be established from the response alone and the finding needs a signup attempt or a provider-side confirmation instead of a response-body match.
   - Sources: <https://developers.cloudflare.com/dns/cname-flattening/> · <https://firebase.google.com/docs/hosting/full-config>
@@ -95,6 +125,21 @@
 - A dangling NS delegation is categorically worse than a dangling CNAME because the transitive trust built into DNS makes every domain that directly or indirectly depends on that record vulnerable, not only the subdomain that owns it.
   - **Disproof:** Refuted when the delegated name server still resolves to infrastructure the organisation controls and has not been released, or when the affected zone delegates exclusively through records that remain bound, leaving no dangling path to the apex.
   - Sources: <https://detectify.com/solutions/prevent-subdomain-takeover> · <https://unit42.paloaltonetworks.com/dangling-domains/>
+- A taken-over subdomain is dangerous beyond content control because the attacker's service can inherit the domain owner's wildcard SSL, making phishing on the subdomain TLS-trusted and unknown to the owner. _(unverified)_
+  - **Disproof:** The service provider issues no certificate covering the hostname to its new registrant, so the attacker's service cannot present the owner's wildcard certificate.
+  - Sources: <https://httpwg.org/specs/rfc6265.html> · <https://kathan19.gitbook.io/howtohunt/subdomain-takeover/sub_or_top_level_domain_takeover.md>
+- A taken-over subdomain is dangerous beyond content control because the attacker's service can inherit the domain owner's wildcard SSL, making phishing on the subdomain TLS-trusted and unknown to the owner.
+  - **Disproof:** The service provider issues no certificate covering the hostname to its new registrant, so the attacker's service cannot present the owner's wildcard certificate.
+  - Sources: <https://httpwg.org/specs/rfc6265.html> · <https://blog.qualys.com/product-tech/2024/01/11/totalcloud-insights-crafting-effective-indicators-of-compromise-iocs-for-sub-domain-takeover-risk-detection> · <https://kathan19.gitbook.io/howtohunt/subdomain-takeover/sub_or_top_level_domain_takeover.md>
+
+## Variants
+
+- A dangling record that enables takeover can be a CNAME or an A record pointing at third-party services, so DNS enumeration has to inspect both record types instead of CNAMEs alone. _(unverified)_
+  - **Disproof:** No A or CNAME record in the zone resolves to an unclaimed third-party service, leaving no dangling target to register.
+  - Sources: <https://httpwg.org/specs/rfc6265.html> · <https://kathan19.gitbook.io/howtohunt/subdomain-takeover/sub_or_top_level_domain_takeover.md>
... (truncated)
```

## 2026-10-03 05:00 — 32 diff lines
- items: 35 (supported 19), FP rules 8, chains 1, state mature

```diff
--- subdomain_takeover@current
+++ subdomain_takeover@new
@@ -10,7 +10,7 @@
      python -m wks.skillgen -->
 
 > surface `infra` · CWE 404 · OWASP A10:2021
-> evidence: 35 items, 19 supported, 4 FP rules, 1 chains
+> evidence: 35 items, 19 supported, 8 FP rules, 1 chains
 > maturity: **mature**
 
 A DNS record still points at a de-provisioned service that anyone can now claim.
@@ -156,5 +156,20 @@
   - **Disproof:** If the session cookie is issued without a Domain attribute, or its scope excludes the claimable subdomain, the attacker-controlled host receives no ambient credential and no session is stolen through this path.
   - Sources: <https://httpwg.org/specs/rfc6265.html> · <https://blog.qualys.com/product-tech/2024/01/11/totalcloud-insights-crafting-effective-indicators-of-compromise-iocs-for-sub-domain-takeover-risk-detection>
 
+## Rejected before you report
+
+- **A subdomain CNAMEs to a SaaS provider whose own domain-ownership lock means a third party must publish a verification TXT record in the zone, therefore the hostname is not claimable and the dangling record is DNS hygiene only**
+  - Killed by: Claiming the hostname requires proving ownership by publishing a TXT record in the victim's DNS zone, which requires control of that zone. The provider additionally implements an ownership lock, so the hostname is bound to a previously-provisioned account and other accounts cannot adopt it
+  - Rule: A dangling CNAME is not a takeover until the provider is shown to be CLAIMABLE by a third party. If signup requires a TXT record in the victim's zone, or the vendor is not on the known-vulnerable list, or the provider locks ownership after first use, the finding is DNS hygiene. State the claimability test explicitly and cite the provider doc that settles it
+- **A subdomain CNAMEs to a shared provider domain and the provider serves an empty page, therefore the record is dangling and claimable**
+  - Killed by: The random hostname returned the identical response, so the provider serves that body for ANY hostname - it is a wildcard catch-all, not an unconfigured hostname. Nothing is reserved and nothing is dangling
+  - Rule: Before calling any provider response a dangling record, send a RANDOM Host header to the same edge IP. If the response is identical, the provider is a wildcard catch-all and your hostname is indistinguishable from a name that was never configured - that is not a takeover
+- **Link-branding subdomains CNAME to the provider's bare apex domain, therefore they are dangling takeovers**
+  - Killed by: The body was byte-identical to the provider's own apex 404, the documented takeover fingerprint was absent from the response, the vendor integration is marked not vulnerable, and the account is still active with live DKIM keys and an SPF include. Only these three branding CNAMEs are unconfigured leftovers
+  - Rule: A CNAME to a provider's BARE apex is not an account-specific fingerprint. Confirm the response differs from the provider's own apex root and that the documented takeover string is present in the body; then confirm the vendor account is still live. Apex CNAMEs with none of those are leftovers
+- **A subdomain resolves to a hosting provider whose anti-takeover verification record is present, therefore the takeover is blocked**
+  - Killed by: The provider's anti-takeover verification TXT record is present in the zone, so ownership is already proven and a third party cannot claim the name
+  - Rule: A dangling CNAME on a provider that uses an ownership-verification TXT record is protected while that record is present. Check the zone for it before reporting; its presence is the disproof, not a mitigating factor
+
 ---
 Full class document: `domains/web/subdomain_takeover/knowledge/DIGEST.md` · retrieve more with `python -m wks.cli search "<query>" --class-id subdomain_takeover`
```

## 2026-10-04 00:43 — 202 diff lines
- items: 35 (supported 19), FP rules 8, chains 1, state mature

```diff
--- subdomain_takeover@current
+++ subdomain_takeover@new
@@ -20,139 +20,109 @@
 
 ## Prerequisites (do not start without these)
 
-- A subdomain becomes attacker-controllable when a cancelled third-party service leaves its CNAME behind in the DNS zone, so the dangling record rather than the provider account is what has to be removed. _(unverified)_
-  - **Disproof:** The CNAME is deleted from the zone file, or the hostname no longer resolves to the abandoned third-party service.
-  - Sources: <https://httpwg.org/specs/rfc6265.html> · <https://kathan19.gitbook.io/howtohunt/subdomain-takeover/subdomain_takeover.md>
-- A subdomain becomes attacker-controllable when a cancelled third-party service leaves its CNAME behind in the DNS zone, so the dangling record rather than the provider account is what has to be removed.
+- A subdomain becomes attacker-controllable when a cancelled third-party service leaves its CNAME behind in the DNS zone, so the dangling record rather than the provider account is what has to be removed.  _(merged 2 duplicate row(s))_ _(unverified)_
   - **Disproof:** The CNAME is deleted from the zone file, or the hostname no longer resolves to the abandoned third-party service.
   - Sources: <https://httpwg.org/specs/rfc6265.html> · <https://blog.qualys.com/product-tech/2024/01/11/totalcloud-insights-crafting-effective-indicators-of-compromise-iocs-for-sub-domain-takeover-risk-detection> · <https://kathan19.gitbook.io/howtohunt/subdomain-takeover/subdomain_takeover.md>
 
 ## Recon signals (where to look)
 
-- A dangling CNAME candidate is signalled by the hostname answering with a 404 not found error from the third-party destination it is attached to. _(unverified)_
-  - **Disproof:** The hostname returns a live response from the provider or a different error entirely, so the 404 is not the third-party service's dangling-target response.
-  - Sources: <https://httpwg.org/specs/rfc6265.html> · <https://kathan19.gitbook.io/howtohunt/subdomain-takeover/sub_or_top_level_domain_takeover.md>
-- A dangling CNAME candidate is signalled by the hostname answering with a 404 not found error from the third-party destination it is attached to.
+- A dangling CNAME candidate is signalled by the hostname answering with a 404 not found error from the third-party destination it is attached to.  _(merged 2 duplicate row(s))_ _(unverified)_
   - **Disproof:** The hostname returns a live response from the provider or a different error entirely, so the 404 is not the third-party service's dangling-target response.
   - Sources: <https://httpwg.org/specs/rfc6265.html> · <https://blog.qualys.com/product-tech/2024/01/11/totalcloud-insights-crafting-effective-indicators-of-compromise-iocs-for-sub-domain-takeover-risk-detection> · <https://kathan19.gitbook.io/howtohunt/subdomain-takeover/sub_or_top_level_domain_takeover.md>
 
 ## Techniques (what to change)
 
-- This often happens because the subdomain's DNS record hasn't been properly de-provisioned or points to a service that is no longer in use. _(unverified)_
+- A subdomain takeover is established when a hostname's CNAME still points at a third-party PaaS domain that no longer serves, letting the tester register that third-party hostname and take control of the subdomain.  _(merged 2 duplicate row(s))_ _(unverified)_
+  - **Disproof:** The CNAME target still serves content or returns a provider-owned response other than a dangling 404, meaning the subscription is active and the hostname is unclaimable.
+  - Sources: <https://httpwg.org/specs/rfc6265.html> · <https://blog.qualys.com/product-tech/2024/01/11/totalcloud-insights-crafting-effective-indicators-of-compromise-iocs-for-sub-domain-takeover-risk-detection> · <https://kathan19.gitbook.io/howtohunt/subdomain-takeover/easy_methods.md>
+- Subdomain takeover, a brief explanation Subdomain takeover occurs when an attacker gains control of a subdomain belonging to a legitimate domain of the target.  _(merged 2 duplicate row(s))_ _(unverified)_
+  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Subdomain takeover, a brief explanation Subdomain takeover occurs when an attacker gains c".
+  - Sources: <https://httpwg.org/specs/rfc6265.html> · <https://www.detectify.com/solutions/prevent-subdomain-takeover>
+- The takeover is usually only considered severe if it compromises other systems or gives direct access to user data (such as cookies).  _(merged 2 duplicate row(s))_ _(unverified)_
+  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "The takeover is usually only considered severe if it compromises other systems or gives di".
+  - Sources: <https://httpwg.org/specs/rfc6265.html> · <https://www.detectify.com/solutions/prevent-subdomain-takeover>
+- This can, over time, give the attacker access to all traffic destined for the vulnerable domain, including all its subdomains.  _(merged 2 duplicate row(s))_ _(unverified)_
+  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "This can, over time, give the attacker access to all traffic destined for the vulnerable d".
+  - Sources: <https://httpwg.org/specs/rfc6265.html> · <https://www.detectify.com/solutions/prevent-subdomain-takeover>
+- This often happens because the subdomain's DNS record hasn't been properly de-provisioned or points to a service that is no longer in use.  _(merged 2 duplicate row(s))_ _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "This often happens because the subdomain's DNS record hasn't been properly de-provisioned ".
   - Sources: <https://httpwg.org/specs/rfc6265.html> · <https://www.detectify.com/solutions/prevent-subdomain-takeover>
-- The takeover is usually only considered severe if it compromises other systems or gives direct access to user data (such as cookies). _(unverified)_
-  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "The takeover is usually only considered severe if it compromises other systems or gives di".
-  - Sources: <https://httpwg.org/specs/rfc6265.html> · <https://www.detectify.com/solutions/prevent-subdomain-takeover>
-- This can, over time, give the attacker access to all traffic destined for the vulnerable domain, including all its subdomains. _(unverified)_
-  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "This can, over time, give the attacker access to all traffic destined for the vulnerable d".
-  - Sources: <https://httpwg.org/specs/rfc6265.html> · <https://www.detectify.com/solutions/prevent-subdomain-takeover>
-- Subdomain takeover, a brief explanation Subdomain takeover occurs when an attacker gains control of a subdomain belonging to a legitimate domain of the target. _(unverified)_
-  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Subdomain takeover, a brief explanation Subdomain takeover occurs when an attacker gains c".
-  - Sources: <https://httpwg.org/specs/rfc6265.html> · <https://www.detectify.com/solutions/prevent-subdomain-takeover>
-- Subdomain takeover, a brief explanation Subdomain takeover occurs when an attacker gains control of a subdomain belonging to a legitimate domain of the target. _(unverified)_
-  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Subdomain takeover, a brief explanation Subdomain takeover occurs when an attacker gains c".
-  - Sources: <https://httpwg.org/specs/rfc6265.html> · <https://www.detectify.com/solutions/prevent-subdomain-takeover>
-- The takeover is usually only considered severe if it compromises other systems or gives direct access to user data (such as cookies). _(unverified)_
-  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "The takeover is usually only considered severe if it compromises other systems or gives di".
-  - Sources: <https://httpwg.org/specs/rfc6265.html> · <https://www.detectify.com/solutions/prevent-subdomain-takeover>
-- This often happens because the subdomain's DNS record hasn't been properly de-provisioned or points to a service that is no longer in use. _(unverified)_
-  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "This often happens because the subdomain's DNS record hasn't been properly de-provisioned ".
-  - Sources: <https://httpwg.org/specs/rfc6265.html> · <https://www.detectify.com/solutions/prevent-subdomain-takeover>
-- This can, over time, give the attacker access to all traffic destined for the vulnerable domain, including all its subdomains. _(unverified)_
-  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "This can, over time, give the attacker access to all traffic destined for the vulnerable d".
-  - Sources: <https://httpwg.org/specs/rfc6265.html> · <https://www.detectify.com/solutions/prevent-subdomain-takeover>
-- When an MX record points at a mail-server hostname that has expired and become registrable, an outsider can claim that hostname and silently receive mail for the affected domain or subdomain.
+- When an MX record points at a mail-server hostname that has expired and become registrable, an outsider can claim that hostname and silently receive mail for the affected domain or subdomain.  _(merged 1 duplicate row(s))_
   - **Disproof:** A DNS estate in which every MX target hostname resolves to an actively controlled, registered host with no expiry in the registration record would refute the claim.
   - Sources: <https://labs.watchtowr.com/the-perils-of-expired-domains-were-reading-your-email/> · <https://www.detectify.com/solutions/prevent-subdomain-takeover>
-- A subdomain takeover is established when a hostname's CNAME still points at a third-party PaaS domain that no longer serves, letting the tester register that third-party hostname and take control of the subdomain. _(unverified)_
-  - **Disproof:** The CNAME target still serves content or returns a provider-owned response other than a dangling 404, meaning the subscription is active and the hostname is unclaimable.
-  - Sources: <https://httpwg.org/specs/rfc6265.html> · <https://kathan19.gitbook.io/howtohunt/subdomain-takeover/easy_methods.md>
-- A subdomain takeover is established when a hostname's CNAME still points at a third-party PaaS domain that no longer serves, letting the tester register that third-party hostname and take control of the subdomain.
-  - **Disproof:** The CNAME target still serves content or returns a provider-owned response other than a dangling 404, meaning the subscription is active and the hostname is unclaimable.
-  - Sources: <https://httpwg.org/specs/rfc6265.html> · <https://blog.qualys.com/product-tech/2024/01/11/totalcloud-insights-crafting-effective-indicators-of-compromise-iocs-for-sub-domain-takeover-risk-detection> · <https://kathan19.gitbook.io/howtohunt/subdomain-takeover/easy_methods.md>
 
 ## Tests
 
-- To decide this case, observe: How to apply it in the field: treat this as the fp_rule it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable. _(unverified)_
+- To decide this case, observe: How to apply it in the field: treat this as the bypass it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable.  _(merged 1 duplicate row(s))_
+  - **Disproof:** This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (subdomain_takeover.bypass.a_partial_cname_setup_means_one_provider_proxies_only_some_subdomains) states the full boundary.
+  - Sources: <https://developers.cloudflare.com/dns/cname-flattening/> · <https://firebase.google.com/docs/hosting/full-config>
+- To decide this case, observe: How to apply it in the field: treat this as the fp_rule it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable.  _(merged 2 duplicate row(s))_ _(unverified)_
   - **Disproof:** This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (subdomain_takeover.fp_rule.a_dangling_record_is_only_a_risk_when_the_target_service_can_actually_be_claimed) states the full boundary.
   - Sources: <https://developers.cloudflare.com/dns/cname-flattening/>
-- To decide this case, observe: How to apply it in the field: treat this as the validation it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable. _(unverified)_
+- To decide this case, observe: How to apply it in the field: treat this as the validation it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable.  _(merged 1 duplicate row(s))_ _(unverified)_
   - **Disproof:** This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (subdomain_takeover.validation.proof_is_a_success_response_from_the_victim_hostname_plus_a_claimed_resource) states the full boundary.
   - Sources: <https://developers.cloudflare.com/dns/zone-setups/>
-- To decide this case, observe: How to apply it in the field: treat this as the bypass it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable.
-  - **Disproof:** This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (subdomain_takeover.bypass.a_partial_cname_setup_means_one_provider_proxies_only_some_subdomains) states the full boundary.
-  - Sources: <https://developers.cloudflare.com/dns/cname-flattening/> · <https://firebase.google.com/docs/hosting/full-config>
-- To decide this case, observe: How to apply it in the field: treat this as the fp_rule it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable. _(unverified)_
-  - **Disproof:** This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (subdomain_takeover.fp_rule.cname_flattening_makes_the_resolved_ip_normal_not_takeover_evidence) states the full boundary.
-  - Sources: <https://developers.cloudflare.com/dns/cname-flattening/>
 
 ## Validation bar (how to prove it)
 
-- A subdomain takeover is proved by serving attacker-controlled content on the victim's own hostname, which requires two observations: a claimable resource identified on the provider, and that resource's content appearing when the victim hostname is requested.
+- A subdomain takeover is proved by serving attacker-controlled content on the victim's own hostname, which requires two observations: a claimable resource identified on the provider, and that resource's content appearing when the victim hostname is requested.  _(merged 1 duplicate row(s))_
   - **Disproof:** The claim is false where the provider shows a generic "site not found" or parking/interstitial page for unclaimed resources — that response is provider-controlled, not attacker content, so it demonstrates the dangling record but not the ability to serve content, and the item must be reported at the lower severity or held until content control is shown.
   - Sources: <https://www.detectify.com/solutions/prevent-subdomain-takeover> · <https://developers.cloudflare.com/dns/zone-setups/>
 
 ## False-positive rules (when to reject it)
 
-- A CNAME pointing at a third-party service hostname is not a takeover finding until the tester has proven that service instance can actually be registered or claimed; a dangling-looking record to a provider that namespaces per customer with a random or account-bound token does not hand the name to whoever requests it.
+- A CNAME pointing at a third-party service hostname is not a takeover finding until the tester has proven that service instance can actually be registered or claimed; a dangling-looking record to a provider that namespaces per customer with a random or account-bound token does not hand the name to whoever requests it.  _(merged 1 duplicate row(s))_
   - **Disproof:** The rule is wrong when the specific provider and resource type are confirmed claimable — an unclaimed bucket or app name that resolves to the provider's generic hosting endpoint — because the takeover then depends only on registering that resource, not on any token; the fingerprint must be re-checked against the provider's current signup rules rather than assumed.
   - Sources: <https://unit42.paloaltonetworks.com/dangling-domains/> · <https://developers.cloudflare.com/dns/cname-flattening/>
-- Reject a subdomain_takeover finding until it is distinguished from the adjacent behaviour this class also covers. "A DNS record left pointing at a de-provisioned third-party service lets an attacker serve content on a host inside the target's own domain, which converts into session theft whenever the session cookie's Domain attribute covers that..." and "A dangling NS delegation is categorically worse than a dangling CNAME because the transitive trust built into DNS makes every domain that directly or indirectly depends on that record vulnerable, not only the subdomain that owns it." share a surface and a symptom, so a response that matches the first is not evidence for it while the second remains possible.
+- A hostname returned by passive subdomain enumeration is a lead, not a subdomain takeover; do not file it unless the dangling DNS record resolves to a provider whose own resource is confirmed unclaimed, because a passive record frequently points at a shared, still-registered SaaS tenant that resolves and serves normally.  _(merged 1 duplicate row(s))_
+  - **Disproof:** The CNAME target's provider returns an explicit unclaimed or no-such-site error for the resource, and the resource identifier in the DNS record can be registered by the assessor - which is the actual proof that a third party could take it over.
+  - Sources: <https://docs.projectdiscovery.io/opensource/subfinder/> · <https://www.netlify.com/docs/domains/custom-domains/>
+- Reject a subdomain_takeover finding until it is distinguished from the adjacent behaviour this class also covers. "A DNS record left pointing at a de-provisioned third-party service lets an attacker serve content on a host inside the target's own domain, which converts into session theft whenever the session cookie's Domain attribute covers that..." and "A dangling NS delegation is categorically worse than a dangling CNAME because the transitive trust built into DNS makes every domain that directly or indirectly depends on that record vulnerable, not only the subdomain that owns it." share a surface and a symptom, so a response that matches the first is not evidence for it while the second remains possible.  _(merged 1 duplicate row(s))_
   - **Disproof:** This rule is wrong if a controlled test shows the two behaviours can never co-occur on the same surface, or if the corpus entry for "A dangling NS delegation is categorically worse than a dangling CNAME " is out of date. In that case this class needs its false-positive guidance rewritten rather than deleted.
   - Sources: <https://blog.qualys.com/product-tech/2024/01/11/totalcloud-insights-crafting-effective-indicators-of-compromise-iocs-for-sub-domain-takeover-risk-detection> · <https://detectify.com/solutions/prevent-subdomain-takeover>
-- Resolving the victim hostname to a generic provider IP is not by itself a takeover: CNAME flattening intentionally resolves the chain to a final IP address instead of returning the CNAME record, so an IP-only view of the resolution hides the very record that would identify the claimable target.
+- Resolving the victim hostname to a generic provider IP is not by itself a takeover: CNAME flattening intentionally resolves the chain to a final IP address instead of returning the CNAME record, so an IP-only view of the resolution hides the very record that would identify the claimable target.  _(merged 1 duplicate row(s))_
   - **Disproof:** The rule is wrong when the flattening provider's own IP is what serves the unclaimed-resource page for the victim's hostname — in that case the flattened resolution did remove the record-level evidence while the takeover remains real, and the finding must rest on the content-served observation rather than the DNS record.
   - Sources: <https://httpwg.org/specs/rfc6265.html> · <https://developers.cloudflare.com/dns/cname-flattening/>
-- A hostname returned by passive subdomain enumeration is a lead, not a subdomain takeover; do not file it unless the dangling DNS record resolves to a provider whose own resource is confirmed unclaimed, because a passive record frequently points at a shared, still-registered SaaS tenant that resolves and serves normally.
-  - **Disproof:** The CNAME target's provider returns an explicit unclaimed or no-such-site error for the resource, and the resource identifier in the DNS record can be registered by the assessor - which is the actual proof that a third party could take it over.
... (truncated)
```

## 2026-10-04 00:50 — 15 diff lines
- items: 35 (supported 19), FP rules 8, chains 1, state mature

```diff
--- subdomain_takeover@current
+++ subdomain_takeover@new
@@ -144,10 +144,8 @@
 
 ## Hunt procedure
 
-1. Enumerate the surface before probing: collect every endpoint, parameter and object id the class could plausibly sit on.
-2. Establish a CONTROLLED BASELINE first — one unauthenticated and one authenticated low-privilege request per candidate — and diff against the probe. A difference with no baseline proves nothing.
-3. Change exactly ONE variable per probe. Two changes produce a difference you cannot attribute.
-4. Record raw request and response pairs verbatim, including headers, before you interpret anything.
+1. Identify the dangling record, then confirm the unclaimed resource actually serves content on that exact host -- a CNAME alone is not takeover.
+2. Check the provider's own fingerprint (dangling DNS vs a generic 404) before claiming it.
 
 ### What counts as proof
 
```

## 2026-10-04 13:20 — 28 diff lines
- items: 35 (supported 22), FP rules 8, chains 1, state mature

```diff
--- subdomain_takeover@current
+++ subdomain_takeover@new
@@ -10,7 +10,7 @@
      python -m wks.skillgen -->
 
 > surface `infra` · CWE 404 · OWASP A10:2021
-> evidence: 35 items, 19 supported, 8 FP rules, 1 chains
+> evidence: 35 items, 22 supported, 8 FP rules, 1 chains
 > maturity: **mature**
 
 A DNS record still points at a de-provisioned service that anyone can now claim.
@@ -56,12 +56,12 @@
 - To decide this case, observe: How to apply it in the field: treat this as the bypass it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable.  _(merged 1 duplicate row(s))_
   - **Disproof:** This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (subdomain_takeover.bypass.a_partial_cname_setup_means_one_provider_proxies_only_some_subdomains) states the full boundary.
   - Sources: <https://developers.cloudflare.com/dns/cname-flattening/> · <https://firebase.google.com/docs/hosting/full-config>
-- To decide this case, observe: How to apply it in the field: treat this as the fp_rule it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable.  _(merged 2 duplicate row(s))_ _(unverified)_
+- To decide this case, observe: How to apply it in the field: treat this as the fp_rule it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable.  _(merged 2 duplicate row(s))_
   - **Disproof:** This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (subdomain_takeover.fp_rule.a_dangling_record_is_only_a_risk_when_the_target_service_can_actually_be_claimed) states the full boundary.
-  - Sources: <https://developers.cloudflare.com/dns/cname-flattening/>
-- To decide this case, observe: How to apply it in the field: treat this as the validation it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable.  _(merged 1 duplicate row(s))_ _(unverified)_
+  - Sources: <https://developers.cloudflare.com/dns/cname-flattening/> · <https://firebase.google.com/docs/hosting/full-config>
+- To decide this case, observe: How to apply it in the field: treat this as the validation it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable.  _(merged 1 duplicate row(s))_
   - **Disproof:** This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (subdomain_takeover.validation.proof_is_a_success_response_from_the_victim_hostname_plus_a_claimed_resource) states the full boundary.
-  - Sources: <https://developers.cloudflare.com/dns/zone-setups/>
+  - Sources: <https://developers.cloudflare.com/dns/zone-setups/> · <https://firebase.google.com/docs/hosting/full-config>
 
 ## Validation bar (how to prove it)
 
```

## 2026-10-04 19:46 — 9 diff lines
- items: 35 (supported 22), FP rules 8, chains 1, state mature

```diff
--- subdomain_takeover@current
+++ subdomain_takeover@new
@@ -156,6 +156,3 @@
 > Ordered prerequisites, the validation bar and the false-positive rules below are the authority: this block is the mechanics, those are the standard.
 ---
 Full class document: `domains/web/subdomain_takeover/knowledge/DIGEST.md` · retrieve more with `python -m wks.cli search "<query>" --class-id subdomain_takeover`
-
----
-Runbook: [`HUNT.md`](HUNT.md) — every promoted technique mapped to an executable procedure with the observables to record.
```

## 2026-10-04 21:29 — 37 diff lines
- items: 35 (supported 30), FP rules 8, chains 1, state mature

```diff
--- subdomain_takeover@current
+++ subdomain_takeover@new
@@ -10,7 +10,7 @@
      python -m wks.skillgen -->
 
 > surface `infra` · CWE 404 · OWASP A10:2021
-> evidence: 35 items, 22 supported, 8 FP rules, 1 chains
+> evidence: 35 items, 30 supported, 8 FP rules, 1 chains
 > maturity: **mature**
 
 A DNS record still points at a de-provisioned service that anyone can now claim.
@@ -35,17 +35,17 @@
 - A subdomain takeover is established when a hostname's CNAME still points at a third-party PaaS domain that no longer serves, letting the tester register that third-party hostname and take control of the subdomain.  _(merged 2 duplicate row(s))_ _(unverified)_
   - **Disproof:** The CNAME target still serves content or returns a provider-owned response other than a dangling 404, meaning the subscription is active and the hostname is unclaimable.
   - Sources: <https://httpwg.org/specs/rfc6265.html> · <https://blog.qualys.com/product-tech/2024/01/11/totalcloud-insights-crafting-effective-indicators-of-compromise-iocs-for-sub-domain-takeover-risk-detection> · <https://kathan19.gitbook.io/howtohunt/subdomain-takeover/easy_methods.md>
-- Subdomain takeover, a brief explanation Subdomain takeover occurs when an attacker gains control of a subdomain belonging to a legitimate domain of the target.  _(merged 2 duplicate row(s))_ _(unverified)_
-  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Subdomain takeover, a brief explanation Subdomain takeover occurs when an attacker gains c".
+- Subdomain takeover, a brief explanation Subdomain takeover occurs when an attacker gains control of a subdomain belonging to a legitimate domain of the target.  _(merged 2 duplicate row(s))_
+  - **Disproof:** Refuted when: the same behaviour is absent when the single named control in the claim is present, and the control is shown to be present rather than assumed. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“Subdomain takeover, a brief explanation Subdomain takeover occurs when an attack”) does not occur under a test that isolates that control.
   - Sources: <https://httpwg.org/specs/rfc6265.html> · <https://www.detectify.com/solutions/prevent-subdomain-takeover>
-- The takeover is usually only considered severe if it compromises other systems or gives direct access to user data (such as cookies).  _(merged 2 duplicate row(s))_ _(unverified)_
-  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "The takeover is usually only considered severe if it compromises other systems or gives di".
+- The takeover is usually only considered severe if it compromises other systems or gives direct access to user data (such as cookies).  _(merged 2 duplicate row(s))_
+  - **Disproof:** Refuted when: the same behaviour is absent when the single named control in the claim is present, and the control is shown to be present rather than assumed. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“The takeover is usually only considered severe if it compromises other systems o”) does not occur under a test that isolates that control.
   - Sources: <https://httpwg.org/specs/rfc6265.html> · <https://www.detectify.com/solutions/prevent-subdomain-takeover>
-- This can, over time, give the attacker access to all traffic destined for the vulnerable domain, including all its subdomains.  _(merged 2 duplicate row(s))_ _(unverified)_
-  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "This can, over time, give the attacker access to all traffic destined for the vulnerable d".
+- This can, over time, give the attacker access to all traffic destined for the vulnerable domain, including all its subdomains.  _(merged 2 duplicate row(s))_
+  - **Disproof:** Refuted when: the same behaviour is absent when the single named control in the claim is present, and the control is shown to be present rather than assumed. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“This can, over time, give the attacker access to all traffic destined for the vu”) does not occur under a test that isolates that control.
   - Sources: <https://httpwg.org/specs/rfc6265.html> · <https://www.detectify.com/solutions/prevent-subdomain-takeover>
-- This often happens because the subdomain's DNS record hasn't been properly de-provisioned or points to a service that is no longer in use.  _(merged 2 duplicate row(s))_ _(unverified)_
-  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "This often happens because the subdomain's DNS record hasn't been properly de-provisioned ".
+- This often happens because the subdomain's DNS record hasn't been properly de-provisioned or points to a service that is no longer in use.  _(merged 2 duplicate row(s))_
+  - **Disproof:** Refuted when: the same behaviour is absent when the single named control in the claim is present, and the control is shown to be present rather than assumed. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“This often happens because the subdomain's DNS record hasn't been properly de-pr”) does not occur under a test that isolates that control.
   - Sources: <https://httpwg.org/specs/rfc6265.html> · <https://www.detectify.com/solutions/prevent-subdomain-takeover>
 - When an MX record points at a mail-server hostname that has expired and become registrable, an outsider can claim that hostname and silently receive mail for the affected domain or subdomain.  _(merged 1 duplicate row(s))_
   - **Disproof:** A DNS estate in which every MX target hostname resolves to an actively controlled, registered host with no expiry in the registration record would refute the claim.
```

## 2026-10-07 00:46 — 1 DoD-session rule (pre-gate, no skillgen run)
- items: unchanged; 1 FP-kill rule filed in `research/pending/fp/fp-dod-session-2026-10-03.json` (source: `/mnt/e/bugbounty/DOD/sessions/2026-10-03-kh/findings/triage-verdict-part3.md`)

```diff
--- subdomain_takeover@current
+++ subdomain_takeover@pending
+- subdomain_takeover.fprule.login_pf_class_is_keycloak: `<html class="login-pf">` is Okta/Keycloak login-portal CSS, not an Azure unclaimed-page signal. Keyword match is not a verdict: need a dangling DoD-controlled DNS record, canary-path byte-identical check, and an impossible-hostname DNSFAIL control.
```

## 2026-10-28 10:06 — 91 diff lines
- items: 26 (supported 19), FP rules 7, chains 1, state mature

```diff
--- subdomain_takeover@current
+++ subdomain_takeover@new
@@ -10,7 +10,7 @@
      python -m wks.skillgen -->
 
 > surface `infra` · CWE 404 · OWASP A10:2021
-> evidence: 35 items, 30 supported, 8 FP rules, 1 chains
+> evidence: 26 items, 19 supported, 7 FP rules, 1 chains
 > maturity: **mature**
 
 A DNS record still points at a de-provisioned service that anyone can now claim.
@@ -20,33 +20,33 @@
 
 ## Prerequisites (do not start without these)
 
-- A subdomain becomes attacker-controllable when a cancelled third-party service leaves its CNAME behind in the DNS zone, so the dangling record rather than the provider account is what has to be removed.  _(merged 2 duplicate row(s))_ _(unverified)_
+- A subdomain becomes attacker-controllable when a cancelled third-party service leaves its CNAME behind in the DNS zone, so the dangling record rather than the provider account is what has to be removed.  _(merged 1 duplicate row(s))_
   - **Disproof:** The CNAME is deleted from the zone file, or the hostname no longer resolves to the abandoned third-party service.
-  - Sources: <https://httpwg.org/specs/rfc6265.html> · <https://blog.qualys.com/product-tech/2024/01/11/totalcloud-insights-crafting-effective-indicators-of-compromise-iocs-for-sub-domain-takeover-risk-detection> · <https://kathan19.gitbook.io/howtohunt/subdomain-takeover/subdomain_takeover.md>
+  - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/Subdomain_Takeover_Prevention_Cheat_Sheet.html> · <https://learn.microsoft.com/en-us/azure/security/fundamentals/subdomain-takeover> · <https://kathan19.gitbook.io/howtohunt/subdomain-takeover/subdomain_takeover.md>
 
 ## Recon signals (where to look)
 
-- A dangling CNAME candidate is signalled by the hostname answering with a 404 not found error from the third-party destination it is attached to.  _(merged 2 duplicate row(s))_ _(unverified)_
+- A dangling CNAME candidate is signalled by the hostname answering with a 404 not found error from the third-party destination it is attached to.  _(merged 1 duplicate row(s))_ _(unverified)_
   - **Disproof:** The hostname returns a live response from the provider or a different error entirely, so the 404 is not the third-party service's dangling-target response.
-  - Sources: <https://httpwg.org/specs/rfc6265.html> · <https://blog.qualys.com/product-tech/2024/01/11/totalcloud-insights-crafting-effective-indicators-of-compromise-iocs-for-sub-domain-takeover-risk-detection> · <https://kathan19.gitbook.io/howtohunt/subdomain-takeover/sub_or_top_level_domain_takeover.md>
+  - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/Subdomain_Takeover_Prevention_Cheat_Sheet.html> · <https://kathan19.gitbook.io/howtohunt/subdomain-takeover/sub_or_top_level_domain_takeover.md>
 
 ## Techniques (what to change)
 
-- A subdomain takeover is established when a hostname's CNAME still points at a third-party PaaS domain that no longer serves, letting the tester register that third-party hostname and take control of the subdomain.  _(merged 2 duplicate row(s))_ _(unverified)_
+- A subdomain takeover is established when a hostname's CNAME still points at a third-party PaaS domain that no longer serves, letting the tester register that third-party hostname and take control of the subdomain.  _(merged 1 duplicate row(s))_
   - **Disproof:** The CNAME target still serves content or returns a provider-owned response other than a dangling 404, meaning the subscription is active and the hostname is unclaimable.
-  - Sources: <https://httpwg.org/specs/rfc6265.html> · <https://blog.qualys.com/product-tech/2024/01/11/totalcloud-insights-crafting-effective-indicators-of-compromise-iocs-for-sub-domain-takeover-risk-detection> · <https://kathan19.gitbook.io/howtohunt/subdomain-takeover/easy_methods.md>
-- Subdomain takeover, a brief explanation Subdomain takeover occurs when an attacker gains control of a subdomain belonging to a legitimate domain of the target.  _(merged 2 duplicate row(s))_
+  - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/Subdomain_Takeover_Prevention_Cheat_Sheet.html> · <https://learn.microsoft.com/en-us/azure/security/fundamentals/subdomain-takeover> · <https://kathan19.gitbook.io/howtohunt/subdomain-takeover/easy_methods.md>
+- Subdomain takeover, a brief explanation Subdomain takeover occurs when an attacker gains control of a subdomain belonging to a legitimate domain of the target.  _(merged 1 duplicate row(s))_
   - **Disproof:** Refuted when: the same behaviour is absent when the single named control in the claim is present, and the control is shown to be present rather than assumed. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“Subdomain takeover, a brief explanation Subdomain takeover occurs when an attack”) does not occur under a test that isolates that control.
-  - Sources: <https://httpwg.org/specs/rfc6265.html> · <https://www.detectify.com/solutions/prevent-subdomain-takeover>
-- The takeover is usually only considered severe if it compromises other systems or gives direct access to user data (such as cookies).  _(merged 2 duplicate row(s))_
+  - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/Subdomain_Takeover_Prevention_Cheat_Sheet.html> · <https://learn.microsoft.com/en-us/azure/security/fundamentals/subdomain-takeover> · <https://www.detectify.com/solutions/prevent-subdomain-takeover>
+- The takeover is usually only considered severe if it compromises other systems or gives direct access to user data (such as cookies).  _(merged 1 duplicate row(s))_ _(unverified)_
   - **Disproof:** Refuted when: the same behaviour is absent when the single named control in the claim is present, and the control is shown to be present rather than assumed. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“The takeover is usually only considered severe if it compromises other systems o”) does not occur under a test that isolates that control.
-  - Sources: <https://httpwg.org/specs/rfc6265.html> · <https://www.detectify.com/solutions/prevent-subdomain-takeover>
-- This can, over time, give the attacker access to all traffic destined for the vulnerable domain, including all its subdomains.  _(merged 2 duplicate row(s))_
+  - Sources: <https://www.detectify.com/solutions/prevent-subdomain-takeover>
+- This can, over time, give the attacker access to all traffic destined for the vulnerable domain, including all its subdomains.  _(merged 1 duplicate row(s))_ _(unverified)_
   - **Disproof:** Refuted when: the same behaviour is absent when the single named control in the claim is present, and the control is shown to be present rather than assumed. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“This can, over time, give the attacker access to all traffic destined for the vu”) does not occur under a test that isolates that control.
-  - Sources: <https://httpwg.org/specs/rfc6265.html> · <https://www.detectify.com/solutions/prevent-subdomain-takeover>
-- This often happens because the subdomain's DNS record hasn't been properly de-provisioned or points to a service that is no longer in use.  _(merged 2 duplicate row(s))_
+  - Sources: <https://www.detectify.com/solutions/prevent-subdomain-takeover>
+- This often happens because the subdomain's DNS record hasn't been properly de-provisioned or points to a service that is no longer in use.  _(merged 1 duplicate row(s))_ _(unverified)_
   - **Disproof:** Refuted when: the same behaviour is absent when the single named control in the claim is present, and the control is shown to be present rather than assumed. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“This often happens because the subdomain's DNS record hasn't been properly de-pr”) does not occur under a test that isolates that control.
-  - Sources: <https://httpwg.org/specs/rfc6265.html> · <https://www.detectify.com/solutions/prevent-subdomain-takeover>
+  - Sources: <https://www.detectify.com/solutions/prevent-subdomain-takeover>
 - When an MX record points at a mail-server hostname that has expired and become registrable, an outsider can claim that hostname and silently receive mail for the affected domain or subdomain.  _(merged 1 duplicate row(s))_
   - **Disproof:** A DNS estate in which every MX target hostname resolves to an actively controlled, registered host with no expiry in the registration record would refute the claim.
   - Sources: <https://labs.watchtowr.com/the-perils-of-expired-domains-were-reading-your-email/> · <https://www.detectify.com/solutions/prevent-subdomain-takeover>
@@ -80,9 +80,9 @@
 - Reject a subdomain_takeover finding until it is distinguished from the adjacent behaviour this class also covers. "A DNS record left pointing at a de-provisioned third-party service lets an attacker serve content on a host inside the target's own domain, which converts into session theft whenever the session cookie's Domain attribute covers that..." and "A dangling NS delegation is categorically worse than a dangling CNAME because the transitive trust built into DNS makes every domain that directly or indirectly depends on that record vulnerable, not only the subdomain that owns it." share a surface and a symptom, so a response that matches the first is not evidence for it while the second remains possible.  _(merged 1 duplicate row(s))_
   - **Disproof:** This rule is wrong if a controlled test shows the two behaviours can never co-occur on the same surface, or if the corpus entry for "A dangling NS delegation is categorically worse than a dangling CNAME " is out of date. In that case this class needs its false-positive guidance rewritten rather than deleted.
   - Sources: <https://blog.qualys.com/product-tech/2024/01/11/totalcloud-insights-crafting-effective-indicators-of-compromise-iocs-for-sub-domain-takeover-risk-detection> · <https://detectify.com/solutions/prevent-subdomain-takeover>
-- Resolving the victim hostname to a generic provider IP is not by itself a takeover: CNAME flattening intentionally resolves the chain to a final IP address instead of returning the CNAME record, so an IP-only view of the resolution hides the very record that would identify the claimable target.  _(merged 1 duplicate row(s))_
+- Resolving the victim hostname to a generic provider IP is not by itself a takeover: CNAME flattening intentionally resolves the chain to a final IP address instead of returning the CNAME record, so an IP-only view of the resolution hides the very record that would identify the claimable target.  _(merged 1 duplicate row(s))_ _(unverified)_
   - **Disproof:** The rule is wrong when the flattening provider's own IP is what serves the unclaimed-resource page for the victim's hostname — in that case the flattened resolution did remove the record-level evidence while the takeover remains real, and the finding must rest on the content-served observation rather than the DNS record.
-  - Sources: <https://httpwg.org/specs/rfc6265.html> · <https://developers.cloudflare.com/dns/cname-flattening/>
+  - Sources: <https://developers.cloudflare.com/dns/cname-flattening/>
 
 ## Evidence requirements
 
@@ -101,15 +101,15 @@
 - A dangling NS delegation is categorically worse than a dangling CNAME because the transitive trust built into DNS makes every domain that directly or indirectly depends on that record vulnerable, not only the subdomain that owns it.  _(merged 1 duplicate row(s))_
   - **Disproof:** Refuted when the delegated name server still resolves to infrastructure the organisation controls and has not been released, or when the affected zone delegates exclusively through records that remain bound, leaving no dangling path to the apex.
   - Sources: <https://detectify.com/solutions/prevent-subdomain-takeover> · <https://unit42.paloaltonetworks.com/dangling-domains/>
-- A taken-over subdomain is dangerous beyond content control because the attacker's service can inherit the domain owner's wildcard SSL, making phishing on the subdomain TLS-trusted and unknown to the owner.  _(merged 2 duplicate row(s))_ _(unverified)_
+- A taken-over subdomain is dangerous beyond content control because the attacker's service can inherit the domain owner's wildcard SSL, making phishing on the subdomain TLS-trusted and unknown to the owner.  _(merged 1 duplicate row(s))_ _(unverified)_
   - **Disproof:** The service provider issues no certificate covering the hostname to its new registrant, so the attacker's service cannot present the owner's wildcard certificate.
-  - Sources: <https://httpwg.org/specs/rfc6265.html> · <https://blog.qualys.com/product-tech/2024/01/11/totalcloud-insights-crafting-effective-indicators-of-compromise-iocs-for-sub-domain-takeover-risk-detection> · <https://kathan19.gitbook.io/howtohunt/subdomain-takeover/sub_or_top_level_domain_takeover.md>
+  - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/Subdomain_Takeover_Prevention_Cheat_Sheet.html> · <https://kathan19.gitbook.io/howtohunt/subdomain-takeover/sub_or_top_level_domain_takeover.md>
 
 ## Variants
 
-- A dangling record that enables takeover can be a CNAME or an A record pointing at third-party services, so DNS enumeration has to inspect both record types instead of CNAMEs alone.  _(merged 2 duplicate row(s))_ _(unverified)_
+- A dangling record that enables takeover can be a CNAME or an A record pointing at third-party services, so DNS enumeration has to inspect both record types instead of CNAMEs alone.  _(merged 1 duplicate row(s))_ _(unverified)_
   - **Disproof:** No A or CNAME record in the zone resolves to an unclaimed third-party service, leaving no dangling target to register.
-  - Sources: <https://httpwg.org/specs/rfc6265.html> · <https://blog.qualys.com/product-tech/2024/01/11/totalcloud-insights-crafting-effective-indicators-of-compromise-iocs-for-sub-domain-takeover-risk-detection> · <https://kathan19.gitbook.io/howtohunt/subdomain-takeover/sub_or_top_level_domain_takeover.md>
+  - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/Subdomain_Takeover_Prevention_Cheat_Sheet.html> · <https://kathan19.gitbook.io/howtohunt/subdomain-takeover/sub_or_top_level_domain_takeover.md>
 
 ## Defence bypasses
 
```

## 2026-10-28 14:45 — 57 diff lines
- items: 19 (supported 15), FP rules 7, chains 1, state mature

```diff
--- subdomain_takeover@current
+++ subdomain_takeover@new
@@ -10,7 +10,7 @@
      python -m wks.skillgen -->
 
 > surface `infra` · CWE 404 · OWASP A10:2021
-> evidence: 26 items, 19 supported, 7 FP rules, 1 chains
+> evidence: 19 items, 15 supported, 7 FP rules, 1 chains
 > maturity: **mature**
 
 A DNS record still points at a de-provisioned service that anyone can now claim.
@@ -35,33 +35,12 @@
 - A subdomain takeover is established when a hostname's CNAME still points at a third-party PaaS domain that no longer serves, letting the tester register that third-party hostname and take control of the subdomain.  _(merged 1 duplicate row(s))_
   - **Disproof:** The CNAME target still serves content or returns a provider-owned response other than a dangling 404, meaning the subscription is active and the hostname is unclaimable.
   - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/Subdomain_Takeover_Prevention_Cheat_Sheet.html> · <https://learn.microsoft.com/en-us/azure/security/fundamentals/subdomain-takeover> · <https://kathan19.gitbook.io/howtohunt/subdomain-takeover/easy_methods.md>
-- Subdomain takeover, a brief explanation Subdomain takeover occurs when an attacker gains control of a subdomain belonging to a legitimate domain of the target.  _(merged 1 duplicate row(s))_
-  - **Disproof:** Refuted when: the same behaviour is absent when the single named control in the claim is present, and the control is shown to be present rather than assumed. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“Subdomain takeover, a brief explanation Subdomain takeover occurs when an attack”) does not occur under a test that isolates that control.
-  - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/Subdomain_Takeover_Prevention_Cheat_Sheet.html> · <https://learn.microsoft.com/en-us/azure/security/fundamentals/subdomain-takeover> · <https://www.detectify.com/solutions/prevent-subdomain-takeover>
 - The takeover is usually only considered severe if it compromises other systems or gives direct access to user data (such as cookies).  _(merged 1 duplicate row(s))_ _(unverified)_
   - **Disproof:** Refuted when: the same behaviour is absent when the single named control in the claim is present, and the control is shown to be present rather than assumed. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“The takeover is usually only considered severe if it compromises other systems o”) does not occur under a test that isolates that control.
-  - Sources: <https://www.detectify.com/solutions/prevent-subdomain-takeover>
-- This can, over time, give the attacker access to all traffic destined for the vulnerable domain, including all its subdomains.  _(merged 1 duplicate row(s))_ _(unverified)_
-  - **Disproof:** Refuted when: the same behaviour is absent when the single named control in the claim is present, and the control is shown to be present rather than assumed. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“This can, over time, give the attacker access to all traffic destined for the vu”) does not occur under a test that isolates that control.
-  - Sources: <https://www.detectify.com/solutions/prevent-subdomain-takeover>
-- This often happens because the subdomain's DNS record hasn't been properly de-provisioned or points to a service that is no longer in use.  _(merged 1 duplicate row(s))_ _(unverified)_
-  - **Disproof:** Refuted when: the same behaviour is absent when the single named control in the claim is present, and the control is shown to be present rather than assumed. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“This often happens because the subdomain's DNS record hasn't been properly de-pr”) does not occur under a test that isolates that control.
   - Sources: <https://www.detectify.com/solutions/prevent-subdomain-takeover>
 - When an MX record points at a mail-server hostname that has expired and become registrable, an outsider can claim that hostname and silently receive mail for the affected domain or subdomain.  _(merged 1 duplicate row(s))_
   - **Disproof:** A DNS estate in which every MX target hostname resolves to an actively controlled, registered host with no expiry in the registration record would refute the claim.
   - Sources: <https://labs.watchtowr.com/the-perils-of-expired-domains-were-reading-your-email/> · <https://www.detectify.com/solutions/prevent-subdomain-takeover>
-
-## Tests
-
-- To decide this case, observe: How to apply it in the field: treat this as the bypass it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable.  _(merged 1 duplicate row(s))_
-  - **Disproof:** This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (subdomain_takeover.bypass.a_partial_cname_setup_means_one_provider_proxies_only_some_subdomains) states the full boundary.
-  - Sources: <https://developers.cloudflare.com/dns/cname-flattening/> · <https://firebase.google.com/docs/hosting/full-config>
-- To decide this case, observe: How to apply it in the field: treat this as the fp_rule it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable.  _(merged 2 duplicate row(s))_
-  - **Disproof:** This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (subdomain_takeover.fp_rule.a_dangling_record_is_only_a_risk_when_the_target_service_can_actually_be_claimed) states the full boundary.
-  - Sources: <https://developers.cloudflare.com/dns/cname-flattening/> · <https://firebase.google.com/docs/hosting/full-config>
-- To decide this case, observe: How to apply it in the field: treat this as the validation it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable.  _(merged 1 duplicate row(s))_
-  - **Disproof:** This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (subdomain_takeover.validation.proof_is_a_success_response_from_the_victim_hostname_plus_a_claimed_resource) states the full boundary.
-  - Sources: <https://developers.cloudflare.com/dns/zone-setups/> · <https://firebase.google.com/docs/hosting/full-config>
 
 ## Validation bar (how to prove it)
 
@@ -107,9 +86,9 @@
 
 ## Variants
 
-- A dangling record that enables takeover can be a CNAME or an A record pointing at third-party services, so DNS enumeration has to inspect both record types instead of CNAMEs alone.  _(merged 1 duplicate row(s))_ _(unverified)_
+- A dangling record that enables takeover can be a CNAME or an A record pointing at a released IP address, so DNS enumeration has to inspect both record types instead of CNAMEs alone.  _(merged 1 duplicate row(s))_
   - **Disproof:** No A or CNAME record in the zone resolves to an unclaimed third-party service, leaving no dangling target to register.
-  - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/Subdomain_Takeover_Prevention_Cheat_Sheet.html> · <https://kathan19.gitbook.io/howtohunt/subdomain-takeover/sub_or_top_level_domain_takeover.md>
+  - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/Subdomain_Takeover_Prevention_Cheat_Sheet.html> · <https://learn.microsoft.com/en-us/azure/security/fundamentals/subdomain-takeover>
 
 ## Defence bypasses
 
```

## 2026-10-28 17:55 — 42 diff lines
- items: 17 (supported 16), FP rules 7, chains 1, state mature

```diff
--- subdomain_takeover@current
+++ subdomain_takeover@new
@@ -10,7 +10,7 @@
      python -m wks.skillgen -->
 
 > surface `infra` · CWE 404 · OWASP A10:2021
-> evidence: 19 items, 15 supported, 7 FP rules, 1 chains
+> evidence: 17 items, 16 supported, 7 FP rules, 1 chains
 > maturity: **mature**
 
 A DNS record still points at a de-provisioned service that anyone can now claim.
@@ -26,18 +26,15 @@
 
 ## Recon signals (where to look)
 
-- A dangling CNAME candidate is signalled by the hostname answering with a 404 not found error from the third-party destination it is attached to.  _(merged 1 duplicate row(s))_ _(unverified)_
+- A dangling CNAME candidate is signalled by the hostname answering with a 404 not found error from the third-party destination it is attached to.  _(merged 1 duplicate row(s))_
   - **Disproof:** The hostname returns a live response from the provider or a different error entirely, so the 404 is not the third-party service's dangling-target response.
-  - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/Subdomain_Takeover_Prevention_Cheat_Sheet.html> · <https://kathan19.gitbook.io/howtohunt/subdomain-takeover/sub_or_top_level_domain_takeover.md>
+  - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/Subdomain_Takeover_Prevention_Cheat_Sheet.html> · <https://raw.githubusercontent.com/EdOverflow/can-i-take-over-xyz/master/README.md>
 
 ## Techniques (what to change)
 
 - A subdomain takeover is established when a hostname's CNAME still points at a third-party PaaS domain that no longer serves, letting the tester register that third-party hostname and take control of the subdomain.  _(merged 1 duplicate row(s))_
   - **Disproof:** The CNAME target still serves content or returns a provider-owned response other than a dangling 404, meaning the subscription is active and the hostname is unclaimable.
   - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/Subdomain_Takeover_Prevention_Cheat_Sheet.html> · <https://learn.microsoft.com/en-us/azure/security/fundamentals/subdomain-takeover> · <https://kathan19.gitbook.io/howtohunt/subdomain-takeover/easy_methods.md>
-- The takeover is usually only considered severe if it compromises other systems or gives direct access to user data (such as cookies).  _(merged 1 duplicate row(s))_ _(unverified)_
-  - **Disproof:** Refuted when: the same behaviour is absent when the single named control in the claim is present, and the control is shown to be present rather than assumed. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“The takeover is usually only considered severe if it compromises other systems o”) does not occur under a test that isolates that control.
-  - Sources: <https://www.detectify.com/solutions/prevent-subdomain-takeover>
 - When an MX record points at a mail-server hostname that has expired and become registrable, an outsider can claim that hostname and silently receive mail for the affected domain or subdomain.  _(merged 1 duplicate row(s))_
   - **Disproof:** A DNS estate in which every MX target hostname resolves to an actively controlled, registered host with no expiry in the registration record would refute the claim.
   - Sources: <https://labs.watchtowr.com/the-perils-of-expired-domains-were-reading-your-email/> · <https://www.detectify.com/solutions/prevent-subdomain-takeover>
@@ -80,9 +77,6 @@
 - A dangling NS delegation is categorically worse than a dangling CNAME because the transitive trust built into DNS makes every domain that directly or indirectly depends on that record vulnerable, not only the subdomain that owns it.  _(merged 1 duplicate row(s))_
   - **Disproof:** Refuted when the delegated name server still resolves to infrastructure the organisation controls and has not been released, or when the affected zone delegates exclusively through records that remain bound, leaving no dangling path to the apex.
   - Sources: <https://detectify.com/solutions/prevent-subdomain-takeover> · <https://unit42.paloaltonetworks.com/dangling-domains/>
-- A taken-over subdomain is dangerous beyond content control because the attacker's service can inherit the domain owner's wildcard SSL, making phishing on the subdomain TLS-trusted and unknown to the owner.  _(merged 1 duplicate row(s))_ _(unverified)_
-  - **Disproof:** The service provider issues no certificate covering the hostname to its new registrant, so the attacker's service cannot present the owner's wildcard certificate.
-  - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/Subdomain_Takeover_Prevention_Cheat_Sheet.html> · <https://kathan19.gitbook.io/howtohunt/subdomain-takeover/sub_or_top_level_domain_takeover.md>
 
 ## Variants
 
```

## 2026-10-31 06:41 — 46 diff lines
- items: 17 (supported 11), FP rules 5, chains 1, state mature

```diff
--- subdomain_takeover@current
+++ subdomain_takeover@new
@@ -10,7 +10,7 @@
      python -m wks.skillgen -->
 
 > surface `infra` · CWE 404 · OWASP A10:2021
-> evidence: 17 items, 16 supported, 7 FP rules, 1 chains
+> evidence: 17 items, 11 supported, 5 FP rules, 1 chains
 > maturity: **mature**
 
 A DNS record still points at a de-provisioned service that anyone can now claim.
@@ -50,10 +50,10 @@
 - A CNAME pointing at a third-party service hostname is not a takeover finding until the tester has proven that service instance can actually be registered or claimed; a dangling-looking record to a provider that namespaces per customer with a random or account-bound token does not hand the name to whoever requests it.  _(merged 1 duplicate row(s))_
   - **Disproof:** The rule is wrong when the specific provider and resource type are confirmed claimable — an unclaimed bucket or app name that resolves to the provider's generic hosting endpoint — because the takeover then depends only on registering that resource, not on any token; the fingerprint must be re-checked against the provider's current signup rules rather than assumed.
   - Sources: <https://unit42.paloaltonetworks.com/dangling-domains/> · <https://developers.cloudflare.com/dns/cname-flattening/>
-- A hostname returned by passive subdomain enumeration is a lead, not a subdomain takeover; do not file it unless the dangling DNS record resolves to a provider whose own resource is confirmed unclaimed, because a passive record frequently points at a shared, still-registered SaaS tenant that resolves and serves normally.  _(merged 1 duplicate row(s))_
+- A hostname returned by passive subdomain enumeration is a lead, not a subdomain takeover; do not file it unless the dangling DNS record resolves to a provider whose own resource is confirmed unclaimed, because a passive record frequently points at a shared, still-registered SaaS tenant that resolves and serves normally.  _(merged 1 duplicate row(s))_ _(unverified)_
   - **Disproof:** The CNAME target's provider returns an explicit unclaimed or no-such-site error for the resource, and the resource identifier in the DNS record can be registered by the assessor - which is the actual proof that a third party could take it over.
   - Sources: <https://docs.projectdiscovery.io/opensource/subfinder/> · <https://www.netlify.com/docs/domains/custom-domains/>
-- Reject a subdomain_takeover finding until it is distinguished from the adjacent behaviour this class also covers. "A DNS record left pointing at a de-provisioned third-party service lets an attacker serve content on a host inside the target's own domain, which converts into session theft whenever the session cookie's Domain attribute covers that..." and "A dangling NS delegation is categorically worse than a dangling CNAME because the transitive trust built into DNS makes every domain that directly or indirectly depends on that record vulnerable, not only the subdomain that owns it." share a surface and a symptom, so a response that matches the first is not evidence for it while the second remains possible.  _(merged 1 duplicate row(s))_
+- Reject a subdomain_takeover finding until it is distinguished from the adjacent behaviour this class also covers. "A DNS record left pointing at a de-provisioned third-party service lets an attacker serve content on a host inside the target's own domain, which converts into session theft whenever the session cookie's Domain attribute covers that..." and "A dangling NS delegation is categorically worse than a dangling CNAME because the transitive trust built into DNS makes every domain that directly or indirectly depends on that record vulnerable, not only the subdomain that owns it." share a surface and a symptom, so a response that matches the first is not evidence for it while the second remains possible.  _(merged 1 duplicate row(s))_ _(unverified)_
   - **Disproof:** This rule is wrong if a controlled test shows the two behaviours can never co-occur on the same surface, or if the corpus entry for "A dangling NS delegation is categorically worse than a dangling CNAME " is out of date. In that case this class needs its false-positive guidance rewritten rather than deleted.
   - Sources: <https://blog.qualys.com/product-tech/2024/01/11/totalcloud-insights-crafting-effective-indicators-of-compromise-iocs-for-sub-domain-takeover-risk-detection> · <https://detectify.com/solutions/prevent-subdomain-takeover>
 - Resolving the victim hostname to a generic provider IP is not by itself a takeover: CNAME flattening intentionally resolves the chain to a final IP address instead of returning the CNAME record, so an IP-only view of the resolution hides the very record that would identify the claimable target.  _(merged 1 duplicate row(s))_ _(unverified)_
@@ -62,10 +62,10 @@
 
 ## Evidence requirements
 
-- A convincing observation for this class is: Adjacent behaviour that produces the same observable result: A dangling NS delegation is categorically worse than a dangling CNAME because the transitive trust built into DNS makes every domain that directly or indirectly depends on that record vulnerable, not only the subdomain that owns it.  _(merged 1 duplicate row(s))_
+- A convincing observation for this class is: Adjacent behaviour that produces the same observable result: A dangling NS delegation is categorically worse than a dangling CNAME because the transitive trust built into DNS makes every domain that directly or indirectly depends on that record vulnerable, not only the subdomain that owns it.  _(merged 1 duplicate row(s))_ _(unverified)_
   - **Disproof:** Not evidence when the observable cannot be produced at all -- blind, server-side-only, or identical-in-every-case behaviour leaves nothing to show. The originating rule (subdomain_takeover.fp_rule.auto.derived) states the full boundary.
   - Sources: <https://blog.qualys.com/product-tech/2024/01/11/totalcloud-insights-crafting-effective-indicators-of-compromise-iocs-for-sub-domain-takeover-risk-detection> · <https://detectify.com/solutions/prevent-subdomain-takeover>
-- A convincing observation for this class is: The observable that triggers this false positive is a hostname appearing in passive subdomain enumeration output and filed as a subdomain takeover.  _(merged 1 duplicate row(s))_
+- A convincing observation for this class is: The observable that triggers this false positive is a hostname appearing in passive subdomain enumeration output and filed as a subdomain takeover.  _(merged 1 duplicate row(s))_ _(unverified)_
   - **Disproof:** Not evidence when the observable cannot be produced at all -- blind, server-side-only, or identical-in-every-case behaviour leaves nothing to show. The originating rule (subdomain_takeover.fp_rule.passive_list_is_a_lead_not_a_claimable_subdomain) states the full boundary.
   - Sources: <https://docs.projectdiscovery.io/opensource/subfinder/> · <https://www.netlify.com/docs/domains/custom-domains/>
 - The distinguishing observation is the provider's own unclaimed-resource response when the target endpoint is requested directly, because that is what ties the victim hostname to a specific claimable resource type rather than to a merely deprecated or unreachable service.  _(merged 1 duplicate row(s))_
@@ -80,7 +80,7 @@
 
 ## Variants
 
-- A dangling record that enables takeover can be a CNAME or an A record pointing at a released IP address, so DNS enumeration has to inspect both record types instead of CNAMEs alone.  _(merged 1 duplicate row(s))_
+- A dangling record that enables takeover can be a CNAME or an A record pointing at a released IP address, so DNS enumeration has to inspect both record types instead of CNAMEs alone.  _(merged 1 duplicate row(s))_ _(unverified)_
   - **Disproof:** No A or CNAME record in the zone resolves to an unclaimed third-party service, leaving no dangling target to register.
   - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/Subdomain_Takeover_Prevention_Cheat_Sheet.html> · <https://learn.microsoft.com/en-us/azure/security/fundamentals/subdomain-takeover>
 
```
