# Methodology — Subdomain Takeover

> Derived from 5 verified items. Regenerate with `python -m wks.methodgen --class subdomain_takeover --apply`. Do not hand-edit: this file is a projection of the evidence, and edits are lost on the next cycle.

**Surface.** A DNS record still points at a de-provisioned service that anyone can now claim.

**References.** CWE-404 · A10:2021

## Preconditions

_No verified prerequisite items yet._ Derived from evidence only, so this section is empty rather than plausible.


## Reconnaissance signals

_No verified signal items yet._ Derived from evidence only, so this section is empty rather than plausible.


## 1. Test sequence

_Concrete mutations to try. Each is written to be executable, not to be a description of the vulnerability._

**When an MX record points at a mail-server hostname that has expired and become registrable, an outsider can claim that hostname and silently receive mail for the affected domain or subdomain.**

The hunter gets a concrete passive check: resolve every MX target across the domain and subdomain estate, then test which of those targets are themselves available for registration. The exposure lives below the apex domain, where most subdomain-hunting effort stops, and a registration attempt is a far cheaper test than the credential-phishing outcome it enables. The claim is falsified by an estate in which every MX target resolves to an actively controlled, registered host with no expiry available in the registration record.

- *Disproof:* A DNS estate in which every MX target hostname resolves to an actively controlled, registered host with no expiry in the registration record would refute the claim.
- *Evidence:* high_confidence — [detectify.com](https://www.detectify.com/solutions/prevent-subdomain-takeover); [labs.watchtowr.com](https://labs.watchtowr.com/the-perils-of-expired-domains-were-reading-your-email/)

## Validation

_No verified validation items yet._ Derived from evidence only, so this section is empty rather than plausible.


## 2. False-positive rejection

_The checks that eliminate the most common non-findings. Run these BEFORE reporting, not after a rejection._

**A hostname returned by passive subdomain enumeration is a lead, not a subdomain takeover; do not file it unless the dangling DNS record resolves to a provider whose own resource is confirmed unclaimed, because a passive record frequently points at a shared, still-registered SaaS tenant that resolves and serves normally.**

The observable that triggers this false positive is a hostname appearing in passive subdomain enumeration output and filed as a subdomain takeover. Passive enumeration collects records from third-party datasets, and a CNAME in such a dataset frequently points at a shared SaaS tenant that is still registered and serving normally - the record is real but the resource behind it belongs to someone. Takeover requires a provider-side unclaimed resource, and that is the only observation that proves a third party could actually register it. This rule therefore filters the passive-list membership and holds the report to the provider's unclaimed-resource response plus a resource identifier the assessor can register, which is the difference between a lead and a demonstrated claimable subdomain.

- *Disproof:* The CNAME target's provider returns an explicit unclaimed or no-such-site error for the resource, and the resource identifier in the DNS record can be registered by the assessor - which is the actual proof that a third party could take it over.
- *Evidence:* high_confidence — [docs.projectdiscovery.io](https://docs.projectdiscovery.io/opensource/subfinder/); [netlify.com](https://www.netlify.com/docs/domains/custom-domains/)

## Known bypasses

_No verified bypass items yet._ Derived from evidence only, so this section is empty rather than plausible.


## 3. Chaining

_How this class escalates when combined with others. Each step is anchored to a promoted item._

**A subdomain_takeover on a sibling host chains into session theft when the session cookie's Domain attribute covers the taken-over subdomain.**

Step: confirm the takeover by resolving the dangling CNAME to a third-party service whose bucket or site is claimable in an attacker account, then compare the session cookie's Domain attribute against the taken-over host. That subdomain_takeover chains into session compromise because the Domain attribute specifies those hosts to which the cookie will be sent, so a cookie scoped to the parent domain is attached to requests for the attacker-controlled subdomain and a script there reads it. The precondition is that the cookie was issued with a Domain attribute at all; when the server omits it, the cookie returns only to the origin server and the chain breaks.

- *Disproof:* If the session cookie is issued without a Domain attribute, or its scope excludes the claimable subdomain, the attacker-controlled host receives no ambient credential and no session is stolen through this path.
- *Evidence:* high_confidence — [blog.qualys.com](https://blog.qualys.com/product-tech/2024/01/11/totalcloud-insights-crafting-effective-indicators-of-compromise-iocs-for-sub-domain-takeover-risk-detection); [httpwg.org](https://httpwg.org/specs/rfc6265.html)

**A DNS record left pointing at a de-provisioned third-party service lets an attacker serve content on a host inside the target's own domain, which converts into session theft whenever the session cookie's Domain attribute covers that sibling host.**

Two published facts compose into the chain. First, a dangling record is exploitable because the record still exists after the service behind it is gone, and attackers abuse the trust of the still-registered owner name rather than of the expired domain. Second, the impact of a takeover is contextual and only becomes severe when it compromises other systems or yields direct access to user data such as cookies. Taken together: the DNS half produces an attacker-controlled origin that passes same-site visual inspection, and the cookie Domain attribute half supplies the actual credential. The end state is an authenticated session replayed by the attacker against the real application, which is why a dangling record in a low-signal inventory can outrank a misconfigured host in risk.

- *Disproof:* Refuted when the affected host sits outside every session cookie's Domain attribute, or when the application binds its session to a host-only cookie; the DNS half alone is then cosmetic phishing and not session theft.
- *Evidence:* high_confidence — [detectify.com](https://detectify.com/solutions/prevent-subdomain-takeover); [unit42.paloaltonetworks.com](https://unit42.paloaltonetworks.com/dangling-domains/)

## 4. Impact

_What is actually demonstrable, and what to stop claiming._

**A dangling NS delegation is categorically worse than a dangling CNAME because the transitive trust built into DNS makes every domain that directly or indirectly depends on that record vulnerable, not only the subdomain that owns it.**

The impact ceiling of a dangling record is set by record type, and the published research separates the cases explicitly. A CNAME record specifies the canonical name of an alias domain, so hijacking it affects the alias alone. An NS record instead delegates an authoritative name server, and when the delegation is dangling the damage inherits from DNS design rather than from application logic: the transitive trust that is built into DNS could make all domains that directly or indirectly depend on the dangling NS record vulnerable, because a domain usually has multiple NS records. The Detectify framing agrees on the ceiling, noting that an attacker taking control of one of many name server delegations for the root apex zone can push severity beyond the most critical injection bug. The practical consequence for triage is that a dangling NS cannot be dispositioned by asking which host it exposes, only by asking how many zones delegate through it.

- *Disproof:* Refuted when the delegated name server still resolves to infrastructure the organisation controls and has not been released, or when the affected zone delegates exclusively through records that remain bound, leaving no dangling path to the apex.
- *Evidence:* high_confidence — [detectify.com](https://detectify.com/solutions/prevent-subdomain-takeover); [unit42.paloaltonetworks.com](https://unit42.paloaltonetworks.com/dangling-domains/)

## Coverage gap

These stages have no verified evidence and are therefore absent above: Preconditions, Reconnaissance signals, Validation, Known bypasses.
A procedure with a missing validation stage is not safe to act on — it produces findings rather than proofs.

---

*Generated from the evidence base. Where this file and the database disagree, the database is correct.*
