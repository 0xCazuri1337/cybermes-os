# Subdomain Takeover

## Definition

A DNS record still points at a de-provisioned service that anyone can now claim.

- **CWE:** 404
- **OWASP:** A10:2021
- **Surface:** infra
- **Aliases:** ["subdomain takeover", "dangling dns", "dangling cname"]

Canonical home for `subdomain_takeover`. Rendered from `db/wks.db` by `methodology/scripts/build_taxonomy.py` — edit the rows, not this file.

## Root Cause

Not yet researched.

## Preconditions

Not yet researched.

## Attack Surface

Surface: **infra**.

The entry points and enabling conditions for this surface are enumerated under **Preconditions**; the observable signals are under **Detection**.

## Detection

Not yet researched.

## Exploitation

**When an MX record points at a mail-server hostname that has expired and become registrable, an outsider can claim that hostname and silently receive mail for the affected domain or subdomain.**

The hunter gets a concrete passive check: resolve every MX target across the domain and subdomain estate, then test which of those targets are themselves available for registration. The exposure lives below the apex domain, where most subdomain-hunting effort stops, and a registration attempt is a far cheaper test than the credential-phishing outcome it enables. The claim is falsified by an estate in which every MX target resolves to an actively controlled, registered host with no expiry available in the registration record.

*Disproof:* A DNS estate in which every MX target hostname resolves to an actively controlled, registered host with no expiry in the registration record would refute the claim.

## Variations

Not yet researched.

## Technology / Framework Considerations

Not yet researched.

## API Considerations

Not yet researched.

## Attack Chains

Not yet researched.

## Real-World Examples

Not yet researched.

## Common False Positives

**A hostname returned by passive subdomain enumeration is a lead, not a subdomain takeover; do not file it unless the dangling DNS record resolves to a provider whose own resource is confirmed unclaimed, because a passive record frequently points at a shared, still-registered SaaS tenant that resolves and serves normally.**

The observable that triggers this false positive is a hostname appearing in passive subdomain enumeration output and filed as a subdomain takeover. Passive enumeration collects records from third-party datasets, and a CNAME in such a dataset frequently points at a shared SaaS tenant that is still registered and serving normally - the record is real but the resource behind it belongs to someone. Takeover requires a provider-side unclaimed resource, and that is the only observation that proves a third party could actually register it. This rule therefore filters the passive-list membership and holds the report to the provider's unclaimed-resource response plus a resource identifier the assessor can register, which is the difference between a lead and a demonstrated claimable subdomain.

*Disproof:* The CNAME target's provider returns an explicit unclaimed or no-such-site error for the resource, and the resource identifier in the DNS record can be registered by the assessor - which is the actual proof that a third party could take it over.

## Validation

Not yet researched.

## Impact

**A dangling NS delegation is categorically worse than a dangling CNAME because the transitive trust built into DNS makes every domain that directly or indirectly depends on that record vulnerable, not only the subdomain that owns it.**

The impact ceiling of a dangling record is set by record type, and the published research separates the cases explicitly. A CNAME record specifies the canonical name of an alias domain, so hijacking it affects the alias alone. An NS record instead delegates an authoritative name server, and when the delegation is dangling the damage inherits from DNS design rather than from application logic: the transitive trust that is built into DNS could make all domains that directly or indirectly depend on the dangling NS record vulnerable, because a domain usually has multiple NS records. The Detectify framing agrees on the ceiling, noting that an attacker taking control of one of many name server delegations for the root apex zone can push severity beyond the most critical injection bug. The practical consequence for triage is that a dangling NS cannot be dispositioned by asking which host it exposes, only by asking how many zones delegate through it.

*Disproof:* Refuted when the delegated name server still resolves to infrastructure the organisation controls and has not been released, or when the affected zone delegates exclusively through records that remain bound, leaving no dangling path to the apex.

## Related Bug Classes

Not yet researched.

## References

- **blog.qualys.com** (writeup)
  - <https://blog.qualys.com/product-tech/2024/01/11/totalcloud-insights-crafting-effective-indicators-of-compromise-iocs-for-sub-domain-takeover-risk-detection>
- **detectify.com** (research)
  - <https://detectify.com/solutions/prevent-subdomain-takeover>
  - <https://www.detectify.com/solutions/prevent-subdomain-takeover>
- **docs.projectdiscovery.io** (docs)
  - <https://docs.projectdiscovery.io/opensource/subfinder/>
- **httpwg.org** (standard)
  - <https://httpwg.org/specs/rfc6265.html>
- **labs.watchtowr.com** (research)
  - <https://labs.watchtowr.com/the-perils-of-expired-domains-were-reading-your-email/>
- **netlify.com** (docs)
  - <https://www.netlify.com/docs/domains/custom-domains/>
- **unit42.paloaltonetworks.com** (research)
  - <https://unit42.paloaltonetworks.com/dangling-domains/>

Every item above is gated on >= 2 distinct publisher hosts (`wks/quality.py`, rule R1). Publisher diversity, not citation count, is what makes these corroborated.
