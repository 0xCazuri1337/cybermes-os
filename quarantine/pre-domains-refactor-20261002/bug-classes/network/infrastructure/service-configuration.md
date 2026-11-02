# Service-Specific Configuration Assessment

## Definition

A service's own configuration — signing, binding, authentication method — determines whether its protocol weaknesses are reachable.

- **CWE:** CWE-16
- **OWASP:** None
- **Surface:** net
- **Aliases:** ["service configuration", "configuration assessment", "service hardening", "protocol configuration", "misconfigured service"]

Canonical home for `service_enumeration_detail`. Rendered from `db/wks.db` by `methodology/scripts/build_taxonomy.py` — edit the rows, not this file.

## Root Cause

Not yet researched.

## Preconditions

Not yet researched.

## Attack Surface

Surface: **net**.

The entry points and enabling conditions for this surface are enumerated under **Preconditions**; the observable signals are under **Detection**.

## Detection

Not yet researched.

## Exploitation

**Whether a service's protocol weaknesses are reachable is decided by that service's own configuration — signing requirements, binding, authentication method and lockout policy — so service identification must be followed by configuration assessment before any weakness is asserted.**

This is the step that separates an enumeration report from a finding. The same open port with the same banner is a different risk depending on whether the protocol requires signing, whether the authentication method is replayable, and whether failed attempts are locked out — and the configuration values that decide it are precisely the ones an attacker must get right for their technique to work. The two exemplar controls are authentication policy (multi-factor defeats replayable credential attacks; account lockout is the common protection against brute force but must be balanced so it cannot itself be used to deny service by locking other users out) and the protocol configuration of the service itself. So the assessment procedure is: identify the service, read its authentication and signing configuration, then evaluate the specific weakness against that configuration. A weakness reported without the configuration step is a hypothesis, and its disproof lives in the configuration.

*Disproof:* If the service enforces signing and strong authentication with lockout applied, then the protocol weaknesses that enumeration would suggest are not reachable and the class yields no finding for that service.

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

**A TCP banner that reveals the service name and version is information disclosure and is not an authorization bypass, an authentication weakness, or a remote-code-execution finding; file it under information disclosure only, and only when the version actually maps to a known-vulnerable build.**

The observable that triggers this false positive is a TCP banner that reveals the service name and version, escalated from information disclosure into an access-control or authentication finding. The banner is read without authenticating, so nothing was bypassed and no trust boundary was crossed; CAPEC rates port-scanning-derived information of this kind as low severity, and exposure management treats an open port as risk only once a vulnerability is located on it. Two conditions lift the banner out of this rule: the disclosed version maps to a published CVE with a demonstrated exploit path, or the banner itself discloses a credential or an internal hostname that was not already inside the assessment scope. Absent those, the banner is reconnaissance output and belongs in neither an authorization nor an authentication finding.

*Disproof:* The disclosed version maps to a published CVE with a working exploit path, or the banner itself carries a credential or internal hostname that was not already known to the assessment scope - in which case the disclosure is materially different from a routine version string.

## Validation

Not yet researched.

## Impact

Not yet researched.

## Related Bug Classes

Not yet researched.

## References

- **attack.mitre.org** (taxonomy)
  - <https://attack.mitre.org/techniques/T1046/>
- **capec.mitre.org** (standard)
  - <https://capec.mitre.org/data/definitions/300.html>
- **cheatsheetseries.owasp.org** (cheatsheet)
  - <https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html>
- **claroty.com** (writeup)
  - <https://claroty.com/blog/a-comprehensive-guide-to-exposure-management-for-cyber-physical-systems>

Every item above is gated on >= 2 distinct publisher hosts (`wks/quality.py`, rule R1). Publisher diversity, not citation count, is what makes these corroborated.
