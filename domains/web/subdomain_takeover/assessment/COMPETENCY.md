# Methodology — Subdomain Takeover

> Derived from 11 verified items. Regenerate with `python -m wks.methodgen --class subdomain_takeover --apply`. Do not hand-edit: this file is a projection of the evidence, and edits are lost on the next cycle.

**Surface.** A DNS record still points at a de-provisioned service that anyone can now claim.

**References.** CWE-404 · A10:2021

## 1. Preconditions

_Nothing below is reachable until these hold. Confirm each against the target before spending time on the technique._

**A subdomain becomes attacker-controllable when a cancelled third-party service leaves its CNAME behind in the DNS zone, so the dangling record rather than the provider account is what has to be removed.**

A subdomain becomes attacker-controllable when a cancelled third-party service leaves its CNAME behind in the DNS zone, so the dangling record rather than the provider account is what has to be removed.

HackTricks reference: subdomain takeover (https://kathan19.gitbook.io/howtohunt/subdomain-takeover/subdomain_takeover.md)

- *Disproof:* The CNAME is deleted from the zone file, or the hostname no longer resolves to the abandoned third-party service.
- *Evidence:* high_confidence — [cheatsheetseries.owasp.org](https://cheatsheetseries.owasp.org/cheatsheets/Subdomain_Takeover_Prevention_Cheat_Sheet.html); [kathan19.gitbook.io](https://kathan19.gitbook.io/howtohunt/subdomain-takeover/subdomain_takeover.md); [learn.microsoft.com](https://learn.microsoft.com/en-us/azure/security/fundamentals/subdomain-takeover)

## 2. Reconnaissance signals

_What to look for while mapping the surface, and where each signal tells you the rest of the procedure is worth running._

**A dangling CNAME candidate is signalled by the hostname answering with a 404 not found error from the third-party destination it is attached to.**

A dangling CNAME candidate is signalled by the hostname answering with a 404 not found error from the third-party destination it is attached to.

HackTricks reference: sub or top level domain takeover (https://kathan19.gitbook.io/howtohunt/subdomain-takeover/sub_or_top_level_domain_takeover.md)

- *Disproof:* The hostname returns a live response from the provider or a different error entirely, so the 404 is not the third-party service's dangling-target response.
- *Evidence:* high_confidence — [cheatsheetseries.owasp.org](https://cheatsheetseries.owasp.org/cheatsheets/Subdomain_Takeover_Prevention_Cheat_Sheet.html); [raw.githubusercontent.com](https://raw.githubusercontent.com/EdOverflow/can-i-take-over-xyz/master/README.md)

## 3. Test sequence

_Concrete mutations to try. Each is written to be executable, not to be a description of the vulnerability._

**When an MX record points at a mail-server hostname that has expired and become registrable, an outsider can claim that hostname and silently receive mail for the affected domain or subdomain.**

The hunter gets a concrete passive check: resolve every MX target across the domain and subdomain estate, then test which of those targets are themselves available for registration. The exposure lives below the apex domain, where most subdomain-hunting effort stops, and a registration attempt is a far cheaper test than the credential-phishing outcome it enables. The claim is falsified by an estate in which every MX target resolves to an actively controlled, registered host with no expiry available in the registration record.

- *Disproof:* A DNS estate in which every MX target hostname resolves to an actively controlled, registered host with no expiry in the registration record would refute the claim.
- *Evidence:* high_confidence — [detectify.com](https://www.detectify.com/solutions/prevent-subdomain-takeover); [labs.watchtowr.com](https://labs.watchtowr.com/the-perils-of-expired-domains-were-reading-your-email/)

**A subdomain takeover is established when a hostname's CNAME still points at a third-party PaaS domain that no longer serves, letting the tester register that third-party hostname and take control of the subdomain.**

A subdomain takeover is established when a hostname's CNAME still points at a third-party PaaS domain that no longer serves, letting the tester register that third-party hostname and take control of the subdomain.

HackTricks reference: easy methods (https://kathan19.gitbook.io/howtohunt/subdomain-takeover/easy_methods.md)

- *Disproof:* The CNAME target still serves content or returns a provider-owned response other than a dangling 404, meaning the subscription is active and the hostname is unclaimable.
- *Evidence:* high_confidence — [cheatsheetseries.owasp.org](https://cheatsheetseries.owasp.org/cheatsheets/Subdomain_Takeover_Prevention_Cheat_Sheet.html); [kathan19.gitbook.io](https://kathan19.gitbook.io/howtohunt/subdomain-takeover/easy_methods.md); [learn.microsoft.com](https://learn.microsoft.com/en-us/azure/security/fundamentals/subdomain-takeover)

## 4. Validation

_How to prove the finding rather than infer it. A technique that cannot be validated must not be reported._

**A subdomain takeover is proved by serving attacker-controlled content on the victim's own hostname, which requires two observations: a claimable resource identified on the provider, and that resource's content appearing when the victim hostname is requested.**

Mechanism: A subdomain takeover is proved by serving attacker-controlled content on the victim's own hostname, which requires two observations: a claimable resource identified on the provider, and that resource's content appearing when the victim hostname is requested. How to apply it in the field: treat this as the validation it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable. Boundary of the rule: The claim is false where the provider shows a generic "site not found" or parking/interstitial page for unclaimed resources — that response is provider-controlled, not attacker content, so it demonstrates the dangling record but not the ability to serve content, and the item must be reported at the lower severity or held until content control is shown.

- *Disproof:* The claim is false where the provider shows a generic "site not found" or parking/interstitial page for unclaimed resources — that response is provider-controlled, not attacker content, so it demonstrates the dangling record but not the ability to serve content, and the item must be reported at the lower severity or held until content control is shown.
- *Evidence:* high_confidence — [detectify.com](https://www.detectify.com/solutions/prevent-subdomain-takeover); [developers.cloudflare.com](https://developers.cloudflare.com/dns/zone-setups/)

## 5. False-positive rejection

_The checks that eliminate the most common non-findings. Run these BEFORE reporting, not after a rejection._

**A CNAME pointing at a third-party service hostname is not a takeover finding until the tester has proven that service instance can actually be registered or claimed; a dangling-looking record to a provider that namespaces per customer with a random or account-bound token does not hand the name to whoever requests it.**

Mechanism: A CNAME pointing at a third-party service hostname is not a takeover finding until the tester has proven that service instance can actually be registered or claimed; a dangling-looking record to a provider that namespaces per customer with a random or account-bound token does not hand the name to whoever requests it. How to apply it in the field: treat this as the fp_rule it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable. Boundary of the rule: The rule is wrong when the specific provider and resource type are confirmed claimable — an unclaimed bucket or app name that resolves to the provider's generic hosting endpoint — because the takeover then depends only on registering that resource, not on any token; the fingerprint must be re-checked against the provider's current signup rules rather than assumed.

- *Disproof:* The rule is wrong when the specific provider and resource type are confirmed claimable — an unclaimed bucket or app name that resolves to the provider's generic hosting endpoint — because the takeover then depends only on registering that resource, not on any token; the fingerprint must be re-checked against the provider's current signup rules rather than assumed.
- *Evidence:* high_confidence — [developers.cloudflare.com](https://developers.cloudflare.com/dns/cname-flattening/); [unit42.paloaltonetworks.com](https://unit42.paloaltonetworks.com/dangling-domains/)

## 6. Known bypasses

_Filters and controls that have defeated the techniques above. Treat these as the reason a naive test fails, not as proof of safety._

**On a partial CNAME setup the proxying provider only fronts the subdomains explicitly delegated to it, so the tester must not assume the whole zone is under that provider's control — a subdomain outside the delegated set has different takeover prerequisites and different record expectations.**

Mechanism: On a partial CNAME setup the proxying provider only fronts the subdomains explicitly delegated to it, so the tester must not assume the whole zone is under that provider's control — a subdomain outside the delegated set has different takeover prerequisites and different record expectations. How to apply it in the field: treat this as the bypass it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable. Boundary of the rule: The rule is false when the zone uses the primary (full) setup with all records managed by the proxying provider, in which case every subdomain is on the same footing and the partial-setup distinction carries no security consequence for the specific name being tested.

- *Disproof:* The rule is false when the zone uses the primary (full) setup with all records managed by the proxying provider, in which case every subdomain is on the same footing and the partial-setup distinction carries no security consequence for the specific name being tested.
- *Evidence:* high_confidence — [developers.cloudflare.com](https://developers.cloudflare.com/dns/cname-flattening/); [firebase.google.com](https://firebase.google.com/docs/hosting/full-config)

## 7. Chaining

_How this class escalates when combined with others. Each step is anchored to a promoted item._

**A subdomain_takeover on a sibling host chains into session theft when the session cookie's Domain attribute covers the taken-over subdomain.**

Step: confirm the takeover by resolving the dangling CNAME to a third-party service whose bucket or site is claimable in an attacker account, then compare the session cookie's Domain attribute against the taken-over host. That subdomain_takeover chains into session compromise because the Domain attribute specifies those hosts to which the cookie will be sent, so a cookie scoped to the parent domain is attached to requests for the attacker-controlled subdomain and a script there reads it. The precondition is that the cookie was issued with a Domain attribute at all; when the server omits it, the cookie returns only to the origin server and the chain breaks.

- *Disproof:* If the session cookie is issued without a Domain attribute, or its scope excludes the claimable subdomain, the attacker-controlled host receives no ambient credential and no session is stolen through this path.
- *Evidence:* high_confidence — [blog.qualys.com](https://blog.qualys.com/product-tech/2024/01/11/totalcloud-insights-crafting-effective-indicators-of-compromise-iocs-for-sub-domain-takeover-risk-detection); [httpwg.org](https://httpwg.org/specs/rfc6265.html)

**A DNS record left pointing at a de-provisioned third-party service lets an attacker serve content on a host inside the target's own domain, which converts into session theft whenever the session cookie's Domain attribute covers that sibling host.**

Two published facts compose into the chain. First, a dangling record is exploitable because the record still exists after the service behind it is gone, and attackers abuse the trust of the still-registered owner name rather than of the expired domain. Second, the impact of a takeover is contextual and only becomes severe when it compromises other systems or yields direct access to user data such as cookies. Taken together: the DNS half produces an attacker-controlled origin that passes same-site visual inspection, and the cookie Domain attribute half supplies the actual credential. The end state is an authenticated session replayed by the attacker against the real application, which is why a dangling record in a low-signal inventory can outrank a misconfigured host in risk.

- *Disproof:* Refuted when the affected host sits outside every session cookie's Domain attribute, or when the application binds its session to a host-only cookie; the DNS half alone is then cosmetic phishing and not session theft.
- *Evidence:* high_confidence — [detectify.com](https://detectify.com/solutions/prevent-subdomain-takeover); [unit42.paloaltonetworks.com](https://unit42.paloaltonetworks.com/dangling-domains/)

## 8. Impact

_What is actually demonstrable, and what to stop claiming._

**A dangling NS delegation is categorically worse than a dangling CNAME because the transitive trust built into DNS makes every domain that directly or indirectly depends on that record vulnerable, not only the subdomain that owns it.**

The impact ceiling of a dangling record is set by record type, and the published research separates the cases explicitly. A CNAME record specifies the canonical name of an alias domain, so hijacking it affects the alias alone. An NS record instead delegates an authoritative name server, and when the delegation is dangling the damage inherits from DNS design rather than from application logic: the transitive trust that is built into DNS could make all domains that directly or indirectly depend on the dangling NS record vulnerable, because a domain usually has multiple NS records. The Detectify framing agrees on the ceiling, noting that an attacker taking control of one of many name server delegations for the root apex zone can push severity beyond the most critical injection bug. The practical consequence for triage is that a dangling NS cannot be dispositioned by asking which host it exposes, only by asking how many zones delegate through it.

- *Disproof:* Refuted when the delegated name server still resolves to infrastructure the organisation controls and has not been released, or when the affected zone delegates exclusively through records that remain bound, leaving no dangling path to the apex.
- *Evidence:* high_confidence — [detectify.com](https://detectify.com/solutions/prevent-subdomain-takeover); [unit42.paloaltonetworks.com](https://unit42.paloaltonetworks.com/dangling-domains/)

---

*Generated from the evidence base. Where this file and the database disagree, the database is correct.*
