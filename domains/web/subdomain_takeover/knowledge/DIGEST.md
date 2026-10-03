# Subdomain Takeover

> surface: `infra` · CWE: 404 · OWASP: A10:2021
> maturity: **mature** — 14 items, 14 supported, 2 FP rules, 1 chains

A DNS record still points at a de-provisioned service that anyone can now claim.

**Aliases:** subdomain takeover, dangling dns, dangling cname

## Technique

- **When an MX record points at a mail-server hostname that has expired and become registrable, an outsider can claim that hostname and silently receive mail for the affected domain or subdomain.**  
  `high_confidence` · score 0.844 · disproved by: A DNS estate in which every MX target hostname resolves to an actively controlled, registered host with no expiry in the registration record would refute the claim.
  sources: <https://labs.watchtowr.com/the-perils-of-expired-domains-were-reading-your-email/> · <https://www.detectify.com/solutions/prevent-subdomain-takeover>
- **This often happens because the subdomain's DNS record hasn't been properly de-provisioned or points to a service that is no longer in use.**  
  `high_confidence` · score 0.778 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "This often happens because the subdomain's DNS record hasn't been properly de-provisioned ".
  sources: <https://httpwg.org/specs/rfc6265.html> · <https://www.detectify.com/solutions/prevent-subdomain-takeover>
- **The takeover is usually only considered severe if it compromises other systems or gives direct access to user data (such as cookies).**  
  `high_confidence` · score 0.778 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "The takeover is usually only considered severe if it compromises other systems or gives di".
  sources: <https://httpwg.org/specs/rfc6265.html> · <https://www.detectify.com/solutions/prevent-subdomain-takeover>
- **This can, over time, give the attacker access to all traffic destined for the vulnerable domain, including all its subdomains.**  
  `high_confidence` · score 0.778 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "This can, over time, give the attacker access to all traffic destined for the vulnerable d".
  sources: <https://httpwg.org/specs/rfc6265.html> · <https://www.detectify.com/solutions/prevent-subdomain-takeover>
- **Subdomain takeover, a brief explanation Subdomain takeover occurs when an attacker gains control of a subdomain belonging to a legitimate domain of the target.**  
  `high_confidence` · score 0.778 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Subdomain takeover, a brief explanation Subdomain takeover occurs when an attacker gains c".
  sources: <https://httpwg.org/specs/rfc6265.html> · <https://www.detectify.com/solutions/prevent-subdomain-takeover>
- **Subdomain takeover, a brief explanation Subdomain takeover occurs when an attacker gains control of a subdomain belonging to a legitimate domain of the target.**  
  `high_confidence` · score 0.778 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Subdomain takeover, a brief explanation Subdomain takeover occurs when an attacker gains c".
  sources: <https://httpwg.org/specs/rfc6265.html> · <https://www.detectify.com/solutions/prevent-subdomain-takeover>
- **The takeover is usually only considered severe if it compromises other systems or gives direct access to user data (such as cookies).**  
  `high_confidence` · score 0.778 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "The takeover is usually only considered severe if it compromises other systems or gives di".
  sources: <https://httpwg.org/specs/rfc6265.html> · <https://www.detectify.com/solutions/prevent-subdomain-takeover>
- **This often happens because the subdomain's DNS record hasn't been properly de-provisioned or points to a service that is no longer in use.**  
  `high_confidence` · score 0.778 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "This often happens because the subdomain's DNS record hasn't been properly de-provisioned ".
  sources: <https://httpwg.org/specs/rfc6265.html> · <https://www.detectify.com/solutions/prevent-subdomain-takeover>
- **This can, over time, give the attacker access to all traffic destined for the vulnerable domain, including all its subdomains.**  
  `high_confidence` · score 0.778 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "This can, over time, give the attacker access to all traffic destined for the vulnerable d".
  sources: <https://httpwg.org/specs/rfc6265.html> · <https://www.detectify.com/solutions/prevent-subdomain-takeover>

## Fp Rule

- **Reject a subdomain_takeover finding until it is distinguished from the adjacent behaviour this class also covers. "A DNS record left pointing at a de-provisioned third-party service lets an attacker serve content on a host inside the target's own domain, which converts into session theft whenever the session cookie's Domain attribute covers that..." and "A dangling NS delegation is categorically worse than a dangling CNAME because the transitive trust built into DNS makes every domain that directly or indirectly depends on that record vulnerable, not only the subdomain that owns it." share a surface and a symptom, so a response that matches the first is not evidence for it while the second remains possible.**  
  `high_confidence` · score 0.863 · disproved by: This rule is wrong if a controlled test shows the two behaviours can never co-occur on the same surface, or if the corpus entry for "A dangling NS delegation is categorically worse than a dangling CNAME " is out of date. In that case this class needs its false-positive guidance rewritten rather than deleted.
  sources: <https://detectify.com/solutions/prevent-subdomain-takeover> · <https://blog.qualys.com/product-tech/2024/01/11/totalcloud-insights-crafting-effective-indicators-of-compromise-iocs-for-sub-domain-takeover-risk-detection>
- **A hostname returned by passive subdomain enumeration is a lead, not a subdomain takeover; do not file it unless the dangling DNS record resolves to a provider whose own resource is confirmed unclaimed, because a passive record frequently points at a shared, still-registered SaaS tenant that resolves and serves normally.**  
  `high_confidence` · score 0.8475 · disproved by: The CNAME target's provider returns an explicit unclaimed or no-such-site error for the resource, and the resource identifier in the DNS record can be registered by the assessor - which is the actual proof that a third party could take it over.
  sources: <https://docs.projectdiscovery.io/opensource/subfinder/> · <https://www.netlify.com/docs/domains/custom-domains/>

## Impact

- **A dangling NS delegation is categorically worse than a dangling CNAME because the transitive trust built into DNS makes every domain that directly or indirectly depends on that record vulnerable, not only the subdomain that owns it.**  
  `high_confidence` · score 0.808 · disproved by: Refuted when the delegated name server still resolves to infrastructure the organisation controls and has not been released, or when the affected zone delegates exclusively through records that remain bound, leaving no dangling path to the apex.
  sources: <https://detectify.com/solutions/prevent-subdomain-takeover> · <https://unit42.paloaltonetworks.com/dangling-domains/>

## Chain Link

- **A subdomain_takeover on a sibling host chains into session theft when the session cookie's Domain attribute covers the taken-over subdomain.**  
  `high_confidence` · score 0.929 · disproved by: If the session cookie is issued without a Domain attribute, or its scope excludes the claimable subdomain, the attacker-controlled host receives no ambient credential and no session is stolen through this path.
  sources: <https://httpwg.org/specs/rfc6265.html> · <https://blog.qualys.com/product-tech/2024/01/11/totalcloud-insights-crafting-effective-indicators-of-compromise-iocs-for-sub-domain-takeover-risk-detection>
- **A DNS record left pointing at a de-provisioned third-party service lets an attacker serve content on a host inside the target's own domain, which converts into session theft whenever the session cookie's Domain attribute covers that sibling host.**  
  `high_confidence` · score 0.8715 · disproved by: Refuted when the affected host sits outside every session cookie's Domain attribute, or when the application binds its session to a host-only cookie; the DNS half alone is then cosmetic phishing and not session theft.
  sources: <https://detectify.com/solutions/prevent-subdomain-takeover> · <https://unit42.paloaltonetworks.com/dangling-domains/>
