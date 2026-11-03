<!-- GENERATED from db/wks.db — do not edit -->
# Subdomain Takeover

> surface: `infra` · CWE: 404 · OWASP: A10:2021
> maturity: **mature** — 17 items, 11 supported, 5 FP rules, 1 chains

A DNS record still points at a de-provisioned service that anyone can now claim.

**Aliases:** subdomain takeover, dangling dns, dangling cname

## Prerequisite

- **A subdomain becomes attacker-controllable when a cancelled third-party service leaves its CNAME behind in the DNS zone, so the dangling record rather than the provider account is what has to be removed.**  
  `high_confidence` · score 0.8 · disproved by: The CNAME is deleted from the zone file, or the hostname no longer resolves to the abandoned third-party service.
  sources: <https://cheatsheetseries.owasp.org/cheatsheets/Subdomain_Takeover_Prevention_Cheat_Sheet.html> · <https://learn.microsoft.com/en-us/azure/security/fundamentals/subdomain-takeover> · <https://kathan19.gitbook.io/howtohunt/subdomain-takeover/subdomain_takeover.md>

## Signal

- **A dangling CNAME candidate is signalled by the hostname answering with a 404 not found error from the third-party destination it is attached to.**  
  `high_confidence` · score 0.808 · disproved by: The hostname returns a live response from the provider or a different error entirely, so the 404 is not the third-party service's dangling-target response.
  sources: <https://cheatsheetseries.owasp.org/cheatsheets/Subdomain_Takeover_Prevention_Cheat_Sheet.html> · <https://raw.githubusercontent.com/EdOverflow/can-i-take-over-xyz/master/README.md>

## Technique

- **When an MX record points at a mail-server hostname that has expired and become registrable, an outsider can claim that hostname and silently receive mail for the affected domain or subdomain.**  
  `high_confidence` · score 0.844 · disproved by: A DNS estate in which every MX target hostname resolves to an actively controlled, registered host with no expiry in the registration record would refute the claim.
  sources: <https://labs.watchtowr.com/the-perils-of-expired-domains-were-reading-your-email/> · <https://www.detectify.com/solutions/prevent-subdomain-takeover>
- **A subdomain takeover is established when a hostname's CNAME still points at a third-party PaaS domain that no longer serves, letting the tester register that third-party hostname and take control of the subdomain.**  
  `high_confidence` · score 0.8 · disproved by: The CNAME target still serves content or returns a provider-owned response other than a dangling 404, meaning the subscription is active and the hostname is unclaimable.
  sources: <https://cheatsheetseries.owasp.org/cheatsheets/Subdomain_Takeover_Prevention_Cheat_Sheet.html> · <https://learn.microsoft.com/en-us/azure/security/fundamentals/subdomain-takeover> · <https://kathan19.gitbook.io/howtohunt/subdomain-takeover/easy_methods.md>

## Validation

- **A subdomain takeover is proved by serving attacker-controlled content on the victim's own hostname, which requires two observations: a claimable resource identified on the provider, and that resource's content appearing when the victim hostname is requested.**  
  `high_confidence` · score 0.863 · disproved by: The claim is false where the provider shows a generic "site not found" or parking/interstitial page for unclaimed resources — that response is provider-controlled, not attacker content, so it demonstrates the dangling record but not the ability to serve content, and the item must be reported at the lower severity or held until content control is shown.
  sources: <https://www.detectify.com/solutions/prevent-subdomain-takeover> · <https://developers.cloudflare.com/dns/zone-setups/>

## Fp Rule

- **A CNAME pointing at a third-party service hostname is not a takeover finding until the tester has proven that service instance can actually be registered or claimed; a dangling-looking record to a provider that namespaces per customer with a random or account-bound token does not hand the name to whoever requests it.**  
  `high_confidence` · score 0.8905 · disproved by: The rule is wrong when the specific provider and resource type are confirmed claimable — an unclaimed bucket or app name that resolves to the provider's generic hosting endpoint — because the takeover then depends only on registering that resource, not on any token; the fingerprint must be re-checked against the provider's current signup rules rather than assumed.
  sources: <https://unit42.paloaltonetworks.com/dangling-domains/> · <https://developers.cloudflare.com/dns/cname-flattening/>

## Evidence

- **The distinguishing observation is the provider's own unclaimed-resource response when the target endpoint is requested directly, because that is what ties the victim hostname to a specific claimable resource type rather than to a merely deprecated or unreachable service.**  
  `high_confidence` · score 0.8655 · disproved by: The claim is false when the provider returns an indistinguishable generic error for both unclaimed and nonexistent resources, in which case the fingerprint cannot be established from the response alone and the finding needs a signup attempt or a provider-side confirmation instead of a response-body match.
  sources: <https://developers.cloudflare.com/dns/cname-flattening/> · <https://firebase.google.com/docs/hosting/full-config>

## Impact

- **A dangling NS delegation is categorically worse than a dangling CNAME because the transitive trust built into DNS makes every domain that directly or indirectly depends on that record vulnerable, not only the subdomain that owns it.**  
  `high_confidence` · score 0.808 · disproved by: Refuted when the delegated name server still resolves to infrastructure the organisation controls and has not been released, or when the affected zone delegates exclusively through records that remain bound, leaving no dangling path to the apex.
  sources: <https://detectify.com/solutions/prevent-subdomain-takeover> · <https://unit42.paloaltonetworks.com/dangling-domains/>

## Bypass

- **On a partial CNAME setup the proxying provider only fronts the subdomains explicitly delegated to it, so the tester must not assume the whole zone is under that provider's control — a subdomain outside the delegated set has different takeover prerequisites and different record expectations.**  
  `high_confidence` · score 0.854 · disproved by: The rule is false when the zone uses the primary (full) setup with all records managed by the proxying provider, in which case every subdomain is on the same footing and the partial-setup distinction carries no security consequence for the specific name being tested.
  sources: <https://developers.cloudflare.com/dns/cname-flattening/> · <https://developers.cloudflare.com/dns/zone-setups/> · <https://firebase.google.com/docs/hosting/full-config>

## Chain Link

- **A subdomain_takeover on a sibling host chains into session theft when the session cookie's Domain attribute covers the taken-over subdomain.**  
  `high_confidence` · score 0.929 · disproved by: If the session cookie is issued without a Domain attribute, or its scope excludes the claimable subdomain, the attacker-controlled host receives no ambient credential and no session is stolen through this path.
  sources: <https://httpwg.org/specs/rfc6265.html> · <https://blog.qualys.com/product-tech/2024/01/11/totalcloud-insights-crafting-effective-indicators-of-compromise-iocs-for-sub-domain-takeover-risk-detection>
- **A DNS record left pointing at a de-provisioned third-party service lets an attacker serve content on a host inside the target's own domain, which converts into session theft whenever the session cookie's Domain attribute covers that sibling host.**  
  `high_confidence` · score 0.8715 · disproved by: Refuted when the affected host sits outside every session cookie's Domain attribute, or when the application binds its session to a host-only cookie; the DNS half alone is then cosmetic phishing and not session theft.
  sources: <https://detectify.com/solutions/prevent-subdomain-takeover> · <https://unit42.paloaltonetworks.com/dangling-domains/>

## False-positive rules

- **Hypothesis:** A subdomain CNAMEs to a SaaS provider whose own domain-ownership lock means a third party must publish a verification TXT record in the zone, therefore the hostname is not claimable and the dangling record is DNS hygiene only
  - **Invalidated by:** Claiming the hostname requires proving ownership by publishing a TXT record in the victim's DNS zone, which requires control of that zone. The provider additionally implements an ownership lock, so the hostname is bound to a previously-provisioned account and other accounts cannot adopt it
  - **Rule:** A dangling CNAME is not a takeover until the provider is shown to be CLAIMABLE by a third party. If signup requires a TXT record in the victim's zone, or the vendor is not on the known-vulnerable list, or the provider locks ownership after first use, the finding is DNS hygiene. State the claimability test explicitly and cite the provider doc that settles it

- **Hypothesis:** A subdomain CNAMEs to a shared provider domain and the provider serves an empty page, therefore the record is dangling and claimable
  - **Invalidated by:** The random hostname returned the identical response, so the provider serves that body for ANY hostname - it is a wildcard catch-all, not an unconfigured hostname. Nothing is reserved and nothing is dangling
  - **Rule:** Before calling any provider response a dangling record, send a RANDOM Host header to the same edge IP. If the response is identical, the provider is a wildcard catch-all and your hostname is indistinguishable from a name that was never configured - that is not a takeover

- **Hypothesis:** Link-branding subdomains CNAME to the provider's bare apex domain, therefore they are dangling takeovers
  - **Invalidated by:** The body was byte-identical to the provider's own apex 404, the documented takeover fingerprint was absent from the response, the vendor integration is marked not vulnerable, and the account is still active with live DKIM keys and an SPF include. Only these three branding CNAMEs are unconfigured leftovers
  - **Rule:** A CNAME to a provider's BARE apex is not an account-specific fingerprint. Confirm the response differs from the provider's own apex root and that the documented takeover string is present in the body; then confirm the vendor account is still live. Apex CNAMEs with none of those are leftovers

- **Hypothesis:** A subdomain resolves to a hosting provider whose anti-takeover verification record is present, therefore the takeover is blocked
  - **Invalidated by:** The provider's anti-takeover verification TXT record is present in the zone, so ownership is already proven and a third party cannot claim the name
  - **Rule:** A dangling CNAME on a provider that uses an ownership-verification TXT record is protected while that record is present. Check the zone for it before reporting; its presence is the disproof, not a mitigating factor
