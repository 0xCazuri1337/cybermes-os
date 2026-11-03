# ssrf-to-cloud-metadata-credential-theft

## Objective

Goal: **cloud_credential_theft**.

An attacker-controlled URL is fetched by the server, and a scheme or host-validation gap allows a link-local metadata address to be reached, returning short-lived instance credentials in the response body.

## Preconditions

1. an endpoint that fetches a user-supplied URL and reflects something about the result
2. a reachable fetch endpoint and knowledge of how the URL is parsed
3. a way to vary the address representation without changing the request's semantics
4. network egress from the attacker's host to the cloud provider's API endpoint

## Initial Weakness

**Step 1.** Find a parameter that causes the server to retrieve an attacker-supplied URL, such as an image import, PDF renderer, webhook tester, document converter or link preview.

- Why: This is the only step that crosses the trust boundary into the server's own network position; without a server-side fetch there is nothing to chain into.

## Chain Steps

**1. `ssrf` — Find a parameter that causes the server to retrieve an attacker-supplied URL, such as an image import, PDF renderer, webhook tester, document converter or link preview.**

- Why: This is the only step that crosses the trust boundary into the server's own network position; without a server-side fetch there is nothing to chain into.
- Requires: an endpoint that fetches a user-supplied URL and reflects something about the result

**2. `ssrf` — Determine whether the fetch's scheme and host validation rejects link-local and loopback destinations, distinguishing an application-level block from a block enforced only by the network egress path.**

- Why: The difference decides whether the next step is a bypass or a direct reach. An application block means a bypass technique is required; no application block means the destination is simply reachable.
- Requires: a reachable fetch endpoint and knowledge of how the URL is parsed

**3. `ssrf` — Reach the instance metadata service and request its credential document, using an alternative representation such as a decimal or octal encoding of the address, a redirect from an allowed host, or an IPv6 form, if a literal block is present.**

- Why: Each representation targets a specific place the validation can be inconsistent: a literal string comparison in the parser, the resolver, or the network layer. Trying them is the difference between a blocked and a successful reach.
- Requires: a way to vary the address representation without changing the request's semantics

**4. `api_trust` — Use the returned credentials against the cloud provider's own API from the attacker's own host, testing read access to object storage and then the ability to list or write buckets.**

- Why: Impact is only established by using the credential. Credentials scoped to the instance's own role frequently still grant broad data access, and proving that converts an information disclosure into a cloud compromise finding.
- Requires: network egress from the attacker's host to the cloud provider's API endpoint

## Required Conditions

- an endpoint that fetches a user-supplied URL and reflects something about the result
- a reachable fetch endpoint and knowledge of how the URL is parsed
- a way to vary the address representation without changing the request's semantics
- network egress from the attacker's host to the cloud provider's API endpoint

## Impact

The attacker obtains instance credentials, and in most cloud configurations those credentials grant access to the cloud account's storage, metadata and internal services, escalating a single-request information leak to broad cloud compromise.

## Detection Strategy

Not yet researched.

## Validation

Not yet researched.

## Real-World Examples

Not yet researched.

## Related Bug Classes

- `api_trust` — canonical: [`skills/web/api_trust/CLASS.md`]
- `ssrf` — canonical: [`skills/web/ssrf/CLASS.md`]

## References

Not yet researched.
