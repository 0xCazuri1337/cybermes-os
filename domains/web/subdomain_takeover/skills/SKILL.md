---
name: subdomain_takeover-hunting
description: Use when hunting Subdomain Takeover in a infra target. Ordered prerequisites, signals, techniques, validation bar and false-positive rules.
---

# Subdomain Takeover — hunting skill

<!-- GENERATED from db/wks.db by wks/skillgen.py. DO NOT HAND-EDIT.
     Edit the rows (or ingest better research) and re-run:
     python -m wks.skillgen -->

> surface `infra` · CWE 404 · OWASP A10:2021
> evidence: 17 items, 11 supported, 5 FP rules, 1 chains
> maturity: **mature**

A DNS record still points at a de-provisioned service that anyone can now claim.

**Also called:** subdomain takeover, dangling dns, dangling cname


## Prerequisites (do not start without these)

- A subdomain becomes attacker-controllable when a cancelled third-party service leaves its CNAME behind in the DNS zone, so the dangling record rather than the provider account is what has to be removed.  _(merged 1 duplicate row(s))_
  - **Disproof:** The CNAME is deleted from the zone file, or the hostname no longer resolves to the abandoned third-party service.
  - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/Subdomain_Takeover_Prevention_Cheat_Sheet.html> · <https://learn.microsoft.com/en-us/azure/security/fundamentals/subdomain-takeover> · <https://kathan19.gitbook.io/howtohunt/subdomain-takeover/subdomain_takeover.md>

## Recon signals (where to look)

- A dangling CNAME candidate is signalled by the hostname answering with a 404 not found error from the third-party destination it is attached to.  _(merged 1 duplicate row(s))_
  - **Disproof:** The hostname returns a live response from the provider or a different error entirely, so the 404 is not the third-party service's dangling-target response.
  - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/Subdomain_Takeover_Prevention_Cheat_Sheet.html> · <https://raw.githubusercontent.com/EdOverflow/can-i-take-over-xyz/master/README.md>

## Techniques (what to change)

- A subdomain takeover is established when a hostname's CNAME still points at a third-party PaaS domain that no longer serves, letting the tester register that third-party hostname and take control of the subdomain.  _(merged 1 duplicate row(s))_
  - **Disproof:** The CNAME target still serves content or returns a provider-owned response other than a dangling 404, meaning the subscription is active and the hostname is unclaimable.
  - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/Subdomain_Takeover_Prevention_Cheat_Sheet.html> · <https://learn.microsoft.com/en-us/azure/security/fundamentals/subdomain-takeover> · <https://kathan19.gitbook.io/howtohunt/subdomain-takeover/easy_methods.md>
- When an MX record points at a mail-server hostname that has expired and become registrable, an outsider can claim that hostname and silently receive mail for the affected domain or subdomain.  _(merged 1 duplicate row(s))_
  - **Disproof:** A DNS estate in which every MX target hostname resolves to an actively controlled, registered host with no expiry in the registration record would refute the claim.
  - Sources: <https://labs.watchtowr.com/the-perils-of-expired-domains-were-reading-your-email/> · <https://www.detectify.com/solutions/prevent-subdomain-takeover>

## Validation bar (how to prove it)

- A subdomain takeover is proved by serving attacker-controlled content on the victim's own hostname, which requires two observations: a claimable resource identified on the provider, and that resource's content appearing when the victim hostname is requested.  _(merged 1 duplicate row(s))_
  - **Disproof:** The claim is false where the provider shows a generic "site not found" or parking/interstitial page for unclaimed resources — that response is provider-controlled, not attacker content, so it demonstrates the dangling record but not the ability to serve content, and the item must be reported at the lower severity or held until content control is shown.
  - Sources: <https://www.detectify.com/solutions/prevent-subdomain-takeover> · <https://developers.cloudflare.com/dns/zone-setups/>

## False-positive rules (when to reject it)

- A CNAME pointing at a third-party service hostname is not a takeover finding until the tester has proven that service instance can actually be registered or claimed; a dangling-looking record to a provider that namespaces per customer with a random or account-bound token does not hand the name to whoever requests it.  _(merged 1 duplicate row(s))_
  - **Disproof:** The rule is wrong when the specific provider and resource type are confirmed claimable — an unclaimed bucket or app name that resolves to the provider's generic hosting endpoint — because the takeover then depends only on registering that resource, not on any token; the fingerprint must be re-checked against the provider's current signup rules rather than assumed.
  - Sources: <https://unit42.paloaltonetworks.com/dangling-domains/> · <https://developers.cloudflare.com/dns/cname-flattening/>
- A hostname returned by passive subdomain enumeration is a lead, not a subdomain takeover; do not file it unless the dangling DNS record resolves to a provider whose own resource is confirmed unclaimed, because a passive record frequently points at a shared, still-registered SaaS tenant that resolves and serves normally.  _(merged 1 duplicate row(s))_ _(unverified)_
  - **Disproof:** The CNAME target's provider returns an explicit unclaimed or no-such-site error for the resource, and the resource identifier in the DNS record can be registered by the assessor - which is the actual proof that a third party could take it over.
  - Sources: <https://docs.projectdiscovery.io/opensource/subfinder/> · <https://www.netlify.com/docs/domains/custom-domains/>
- Reject a subdomain_takeover finding until it is distinguished from the adjacent behaviour this class also covers. "A DNS record left pointing at a de-provisioned third-party service lets an attacker serve content on a host inside the target's own domain, which converts into session theft whenever the session cookie's Domain attribute covers that..." and "A dangling NS delegation is categorically worse than a dangling CNAME because the transitive trust built into DNS makes every domain that directly or indirectly depends on that record vulnerable, not only the subdomain that owns it." share a surface and a symptom, so a response that matches the first is not evidence for it while the second remains possible.  _(merged 1 duplicate row(s))_ _(unverified)_
  - **Disproof:** This rule is wrong if a controlled test shows the two behaviours can never co-occur on the same surface, or if the corpus entry for "A dangling NS delegation is categorically worse than a dangling CNAME " is out of date. In that case this class needs its false-positive guidance rewritten rather than deleted.
  - Sources: <https://blog.qualys.com/product-tech/2024/01/11/totalcloud-insights-crafting-effective-indicators-of-compromise-iocs-for-sub-domain-takeover-risk-detection> · <https://detectify.com/solutions/prevent-subdomain-takeover>
- Resolving the victim hostname to a generic provider IP is not by itself a takeover: CNAME flattening intentionally resolves the chain to a final IP address instead of returning the CNAME record, so an IP-only view of the resolution hides the very record that would identify the claimable target.  _(merged 1 duplicate row(s))_ _(unverified)_
  - **Disproof:** The rule is wrong when the flattening provider's own IP is what serves the unclaimed-resource page for the victim's hostname — in that case the flattened resolution did remove the record-level evidence while the takeover remains real, and the finding must rest on the content-served observation rather than the DNS record.
  - Sources: <https://developers.cloudflare.com/dns/cname-flattening/>

## Evidence requirements

- A convincing observation for this class is: Adjacent behaviour that produces the same observable result: A dangling NS delegation is categorically worse than a dangling CNAME because the transitive trust built into DNS makes every domain that directly or indirectly depends on that record vulnerable, not only the subdomain that owns it.  _(merged 1 duplicate row(s))_ _(unverified)_
  - **Disproof:** Not evidence when the observable cannot be produced at all -- blind, server-side-only, or identical-in-every-case behaviour leaves nothing to show. The originating rule (subdomain_takeover.fp_rule.auto.derived) states the full boundary.
  - Sources: <https://blog.qualys.com/product-tech/2024/01/11/totalcloud-insights-crafting-effective-indicators-of-compromise-iocs-for-sub-domain-takeover-risk-detection> · <https://detectify.com/solutions/prevent-subdomain-takeover>
- A convincing observation for this class is: The observable that triggers this false positive is a hostname appearing in passive subdomain enumeration output and filed as a subdomain takeover.  _(merged 1 duplicate row(s))_ _(unverified)_
  - **Disproof:** Not evidence when the observable cannot be produced at all -- blind, server-side-only, or identical-in-every-case behaviour leaves nothing to show. The originating rule (subdomain_takeover.fp_rule.passive_list_is_a_lead_not_a_claimable_subdomain) states the full boundary.
  - Sources: <https://docs.projectdiscovery.io/opensource/subfinder/> · <https://www.netlify.com/docs/domains/custom-domains/>
- The distinguishing observation is the provider's own unclaimed-resource response when the target endpoint is requested directly, because that is what ties the victim hostname to a specific claimable resource type rather than to a merely deprecated or unreachable service.  _(merged 1 duplicate row(s))_
  - **Disproof:** The claim is false when the provider returns an indistinguishable generic error for both unclaimed and nonexistent resources, in which case the fingerprint cannot be established from the response alone and the finding needs a signup attempt or a provider-side confirmation instead of a response-body match.
  - Sources: <https://developers.cloudflare.com/dns/cname-flattening/> · <https://firebase.google.com/docs/hosting/full-config>

## Impact framing

- A dangling NS delegation is categorically worse than a dangling CNAME because the transitive trust built into DNS makes every domain that directly or indirectly depends on that record vulnerable, not only the subdomain that owns it.  _(merged 1 duplicate row(s))_
  - **Disproof:** Refuted when the delegated name server still resolves to infrastructure the organisation controls and has not been released, or when the affected zone delegates exclusively through records that remain bound, leaving no dangling path to the apex.
  - Sources: <https://detectify.com/solutions/prevent-subdomain-takeover> · <https://unit42.paloaltonetworks.com/dangling-domains/>

## Variants

- A dangling record that enables takeover can be a CNAME or an A record pointing at a released IP address, so DNS enumeration has to inspect both record types instead of CNAMEs alone.  _(merged 1 duplicate row(s))_ _(unverified)_
  - **Disproof:** No A or CNAME record in the zone resolves to an unclaimed third-party service, leaving no dangling target to register.
  - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/Subdomain_Takeover_Prevention_Cheat_Sheet.html> · <https://learn.microsoft.com/en-us/azure/security/fundamentals/subdomain-takeover>

## Defence bypasses

- On a partial CNAME setup the proxying provider only fronts the subdomains explicitly delegated to it, so the tester must not assume the whole zone is under that provider's control — a subdomain outside the delegated set has different takeover prerequisites and different record expectations.  _(merged 1 duplicate row(s))_
  - **Disproof:** The rule is false when the zone uses the primary (full) setup with all records managed by the proxying provider, in which case every subdomain is on the same footing and the partial-setup distinction carries no security consequence for the specific name being tested.
  - Sources: <https://developers.cloudflare.com/dns/cname-flattening/> · <https://developers.cloudflare.com/dns/zone-setups/> · <https://firebase.google.com/docs/hosting/full-config>

## Chaining opportunities

- A DNS record left pointing at a de-provisioned third-party service lets an attacker serve content on a host inside the target's own domain, which converts into session theft whenever the session cookie's Domain attribute covers that sibling host.  _(merged 1 duplicate row(s))_
  - **Disproof:** Refuted when the affected host sits outside every session cookie's Domain attribute, or when the application binds its session to a host-only cookie; the DNS half alone is then cosmetic phishing and not session theft.
  - Sources: <https://detectify.com/solutions/prevent-subdomain-takeover> · <https://unit42.paloaltonetworks.com/dangling-domains/>
- A subdomain_takeover on a sibling host chains into session theft when the session cookie's Domain attribute covers the taken-over subdomain.  _(merged 1 duplicate row(s))_
  - **Disproof:** If the session cookie is issued without a Domain attribute, or its scope excludes the claimable subdomain, the attacker-controlled host receives no ambient credential and no session is stolen through this path.
  - Sources: <https://httpwg.org/specs/rfc6265.html> · <https://blog.qualys.com/product-tech/2024/01/11/totalcloud-insights-crafting-effective-indicators-of-compromise-iocs-for-sub-domain-takeover-risk-detection>

## Rejected before you report

- **A subdomain CNAMEs to a SaaS provider whose own domain-ownership lock means a third party must publish a verification TXT record in the zone, therefore the hostname is not claimable and the dangling record is DNS hygiene only**
  - Killed by: Claiming the hostname requires proving ownership by publishing a TXT record in the victim's DNS zone, which requires control of that zone. The provider additionally implements an ownership lock, so the hostname is bound to a previously-provisioned account and other accounts cannot adopt it
  - Rule: A dangling CNAME is not a takeover until the provider is shown to be CLAIMABLE by a third party. If signup requires a TXT record in the victim's zone, or the vendor is not on the known-vulnerable list, or the provider locks ownership after first use, the finding is DNS hygiene. State the claimability test explicitly and cite the provider doc that settles it
- **A subdomain CNAMEs to a shared provider domain and the provider serves an empty page, therefore the record is dangling and claimable**
  - Killed by: The random hostname returned the identical response, so the provider serves that body for ANY hostname - it is a wildcard catch-all, not an unconfigured hostname. Nothing is reserved and nothing is dangling
  - Rule: Before calling any provider response a dangling record, send a RANDOM Host header to the same edge IP. If the response is identical, the provider is a wildcard catch-all and your hostname is indistinguishable from a name that was never configured - that is not a takeover
- **Link-branding subdomains CNAME to the provider's bare apex domain, therefore they are dangling takeovers**
  - Killed by: The body was byte-identical to the provider's own apex 404, the documented takeover fingerprint was absent from the response, the vendor integration is marked not vulnerable, and the account is still active with live DKIM keys and an SPF include. Only these three branding CNAMEs are unconfigured leftovers
  - Rule: A CNAME to a provider's BARE apex is not an account-specific fingerprint. Confirm the response differs from the provider's own apex root and that the documented takeover string is present in the body; then confirm the vendor account is still live. Apex CNAMEs with none of those are leftovers
- **A subdomain resolves to a hosting provider whose anti-takeover verification record is present, therefore the takeover is blocked**
  - Killed by: The provider's anti-takeover verification TXT record is present in the zone, so ownership is already proven and a third party cannot claim the name
  - Rule: A dangling CNAME on a provider that uses an ownership-verification TXT record is protected while that record is present. Check the zone for it before reporting; its presence is the disproof, not a mitigating factor


## Hunt procedure

1. Identify the dangling record, then confirm the unclaimed resource actually serves content on that exact host -- a CNAME alone is not takeover.
2. Check the provider's own fingerprint (dangling DNS vs a generic 404) before claiming it.

### What counts as proof

- Two responses that differ in a way the CONTROL did not, produced by a single changed variable.
- An invariant the application is supposed to hold, observed broken.
- A second independent confirmation, or an explicit statement that this is single-account evidence only.

> Ordered prerequisites, the validation bar and the false-positive rules below are the authority: this block is the mechanics, those are the standard.
---
Full class document: `domains/web/subdomain_takeover/knowledge/DIGEST.md` · retrieve more with `python -m wks.cli search "<query>" --class-id subdomain_takeover`

---
Runbook: [`HUNT.md`](HUNT.md) — every promoted technique mapped to an executable procedure with the observables to record.
