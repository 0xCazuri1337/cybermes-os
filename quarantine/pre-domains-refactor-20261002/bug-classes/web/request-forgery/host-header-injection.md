# Host Header Injection

## Definition

The server builds a security-relevant URL or decision from a caller-controlled Host header.

- **CWE:** 644
- **OWASP:** A05:2021
- **Surface:** web
- **Aliases:** ["host header", "password reset poisoning", "absolute url poisoning"]

Canonical home for `host_header`. Rendered from `db/wks.db` by `methodology/scripts/build_taxonomy.py` — edit the rows, not this file.

## Root Cause

Not yet researched.

## Preconditions

**Host-header injection requires the application to derive an absolute URL, link, or cache key from the request Host field, which may differ from the connection's host or port.**

RFC 9110 states a request may be misdirected such that the received Host header field differs from the connection's host or port, which is exactly the condition a host-header attack exploits. Before hunting, find an application path that echoes the Host value into a response: a password-reset link, an absolute redirect, an emailed canonical URL, or a cache key. If no path reflects Host, the class has no foothold on that target.

*Disproof:* If the application never reflects the Host value into any response body, header or outbound link, a forged Host produces no observable difference and the prerequisite fails.

## Attack Surface

Surface: **web**.

The entry points and enabling conditions for this surface are enumerated under **Preconditions**; the observable signals are under **Detection**.

## Detection

Not yet researched.

## Exploitation

**When a front-end injects X-Forwarded-Host to preserve the original host through a load balancer, an attacker can inject the payload through that header and bypass validation applied to Host, because the framework resolves the override header instead of the validated one.**

The mechanism is a precedence disagreement, not a broken allowlist. Websites are often accessed via some kind of intermediary system, such as a load balancer or a reverse proxy, and in that kind of architecture the Host header that the back-end server receives may contain the domain name for one of these intermediary systems. To solve that problem the front-end may inject the X-Forwarded-Host header, containing the original value of the Host header from the client's initial request, and for this reason, when an X-Forwarded-Host header is present, many frameworks will refer to this instead. That last clause is the hunting trap: you may observe this behavior even when there is no front-end that uses this header. Procedure: hold Host at the legitimate value, add X-Forwarded-Host with the attacker value, and diff the response against a clean baseline. Any change in a generated absolute URL, a redirect Location, or an allow/deny decision is the finding. The same holds for X-Host, X-Forwarded-Server, X-HTTP-Host-Override and Forwarded, so probe the whole override family rather than the single well-known name.

*Disproof:* The claim is wrong, and the override header is inert, if the response is byte-identical to the clean baseline with the override present, meaning the framework ignored it; the only change is in a header or body region no browser or downstream consumer uses to make a security decision; or the deployment genuinely terminates at a proxy that strips every override header before the framework sees it, which must be shown by observing that the attacker value never reaches any application-controlled output. Validate by diffing, not by the presence of the header in the request.

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

**A Host header whose value length exactly equals the server's configured maximum produces a one-byte NULL overwrite in the server's own parser, which is a length-check defect and not host-header routing or cache steering.**

The observation is a crash, a reset, or corrupted state on a device when the Host header is sent at exactly the configured maximum length, which is commonly written up as host-header handling weakness and escalated as routing manipulation or password-reset poisoning. Two different failures are being conflated. Host-header routing abuse depends on a backend that trusts the field to choose an upstream, generate absolute URLs, or select a cache key, and the header value is attacker-chosen data in that case: the user agent is a client-supplied header, so a control that checks the name but not the address can be bypassed by forging it. A length-check defect is different. In a documented embedded case, the length of the Host header value is checked to ensure that it is at most the configured maximum and that length is then used as the index into a heap buffer, so a value of exactly the configured size results in a one byte buffer overwrite with a NULL byte. No backend routing decision exists to steer, and no cache key changes. The distinguishing test is the shape of the effect: if varying the Host value across many syntactically valid hostnames produces no differential response in links, redirects, or cache hits, and only the boundary length crashes the process, the finding belongs to input validation, not to host-header injection.

*Disproof:* Changing only the Host header to another valid hostname changes the response body, an absolute URL, or the cache entry served, which shows the field is being consumed for routing or keying rather than only for length validation.

**A Host or X-Forwarded-Host value reflected unencoded into the response markup, with no shared cache in front of the page, is not a finding on its own: no attacker can force a victim's browser to send an incorrect host in a useful manner.**

Reflected client-side issues driven by the Host header are the classic host-header false positive, and the reason is structural. When probing for Host header attacks you will often come across seemingly vulnerable behavior that isn't directly exploitable, such as the Host header being reflected in the response markup without HTML-encoding or used directly in script imports; there is no way for an attacker to force a victim's browser to issue an incorrect host in a useful manner. The reflection is therefore not a payload delivery mechanism. The same holds for an attacker who poisons their own request: they poison their own session, which they already control. Reject unless one of two upgrades is demonstrated: a shared cache in front of the page, which turns the useless reflected vulnerability into a dangerous stored one by persuading the cache to serve a poisoned response to other users; or a server-side sink, where the reflected value reaches an authorisation check, a redirect construction, or an absolute-URL builder, in which case the finding belongs to host header URL poisoning, not to reflected XSS.

*Disproof:* The rule is wrong, and there is a real finding, if: a shared cache serves the poisoned response to a second, different session (then it is cache poisoning, and cache_deception.technique.unkeyed_reflection_below_a_dynamic_segment_becomes_a_shared_key is the right class); or the reflected value is consumed server-side, changing an authz decision, a Location header, or a generated absolute URL even in a single-request replay; or the reflection reaches an HTTP response header that the browser treats as navigable (Location, Link, Refresh). Same-request reflection into HTML markup alone never qualifies.

## Validation

Not yet researched.

## Impact

**When an intermediary routes on the Host header field, an attacker-chosen Host value steers the request to a different backend and yields cross-tenant credential impact.**

Step: send the same request twice with two different Host header values pointing at distinct backends and compare the response body, any absolute URL the server generates from that Host, and which tenant's data comes back. The attacker gains whatever the wrongly selected backend serves, including credentials issued for a host the attacker chose, because a load balancer in front of an identity or session API that makes routing decisions based on the Host header will deliver the request to the attacker's intended backend on the attacker's terms. Note that a user agent normally supplies the Host field itself, so the primitive only exists where a proxy forwards or trusts the client value.

*Disproof:* If both Host values return responses from the same backend and any generated absolute URL ignores the supplied Host, the routing trust boundary does not exist and there is no host_header impact to report.

## Related Bug Classes

Not yet researched.

## References

- **academy.hackthebox.com** (docs)
  - <https://academy.hackthebox.com/course/preview/abusing-http-misconfigurations>
- **googleprojectzero.blogspot.com** (research)
  - <https://googleprojectzero.blogspot.com/2020/10/enter-the-vault-auth-issues-hashicorp-vault.html>
- **helpnetsecurity.com** (research)
  - <https://www.helpnetsecurity.com/2026/08/31/ai-crawlers-scan-exposed-credentials/>
- **httpwg.org** (standard)
  - <https://httpwg.org/specs/rfc9110.html>
- **portswigger.net** (docs)
  - <https://portswigger.net/web-security/host-header/exploiting>
- **snyk.io** (writeup)
  - <https://snyk.io/blog/how-to-avoid-web-cache-poisoning-attacks/>
- **talosintelligence.com** (vendor_advisory)
  - <https://www.talosintelligence.com/vulnerability_reports/TALOS-2023-1746>

Every item above is gated on >= 2 distinct publisher hosts (`wks/quality.py`, rule R1). Publisher diversity, not citation count, is what makes these corroborated.
