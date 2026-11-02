# Methodology — Service-Specific Configuration Assessment

> Derived from 5 verified items. Regenerate with `python -m wks.methodgen --class service_enumeration_detail --apply`. Do not hand-edit: this file is a projection of the evidence, and edits are lost on the next cycle.

**Surface.** A service's own configuration — signing, binding, authentication method — determines whether its protocol weaknesses are reachable.

**References.** CWE-16

## Preconditions

_No verified prerequisite items yet._ Derived from evidence only, so this section is empty rather than plausible.


## Reconnaissance signals

_No verified signal items yet._ Derived from evidence only, so this section is empty rather than plausible.


## 1. Test sequence

_Concrete mutations to try. Each is written to be executable, not to be a description of the vulnerability._

**Whether a service's protocol weaknesses are reachable is decided by that service's own configuration — signing requirements, binding, authentication method and lockout policy — so service identification must be followed by configuration assessment before any weakness is asserted.**

This is the step that separates an enumeration report from a finding. The same open port with the same banner is a different risk depending on whether the protocol requires signing, whether the authentication method is replayable, and whether failed attempts are locked out — and the configuration values that decide it are precisely the ones an attacker must get right for their technique to work. The two exemplar controls are authentication policy (multi-factor defeats replayable credential attacks; account lockout is the common protection against brute force but must be balanced so it cannot itself be used to deny service by locking other users out) and the protocol configuration of the service itself. So the assessment procedure is: identify the service, read its authentication and signing configuration, then evaluate the specific weakness against that configuration. A weakness reported without the configuration step is a hypothesis, and its disproof lives in the configuration.

- *Disproof:* If the service enforces signing and strong authentication with lockout applied, then the protocol weaknesses that enumeration would suggest are not reachable and the class yields no finding for that service.
- *Evidence:* high_confidence — [attack.mitre.org](https://attack.mitre.org/techniques/T1046/); [cheatsheetseries.owasp.org](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html)

## Validation

_No verified validation items yet._ Derived from evidence only, so this section is empty rather than plausible.


## 2. False-positive rejection

_The checks that eliminate the most common non-findings. Run these BEFORE reporting, not after a rejection._

**A TCP banner that reveals the service name and version is information disclosure and is not an authorization bypass, an authentication weakness, or a remote-code-execution finding; file it under information disclosure only, and only when the version actually maps to a known-vulnerable build.**

The observable that triggers this false positive is a TCP banner that reveals the service name and version, escalated from information disclosure into an access-control or authentication finding. The banner is read without authenticating, so nothing was bypassed and no trust boundary was crossed; CAPEC rates port-scanning-derived information of this kind as low severity, and exposure management treats an open port as risk only once a vulnerability is located on it. Two conditions lift the banner out of this rule: the disclosed version maps to a published CVE with a demonstrated exploit path, or the banner itself discloses a credential or an internal hostname that was not already inside the assessment scope. Absent those, the banner is reconnaissance output and belongs in neither an authorization nor an authentication finding.

- *Disproof:* The disclosed version maps to a published CVE with a working exploit path, or the banner itself carries a credential or internal hostname that was not already known to the assessment scope - in which case the disclosure is materially different from a routine version string.
- *Evidence:* high_confidence — [capec.mitre.org](https://capec.mitre.org/data/definitions/300.html); [claroty.com](https://claroty.com/blog/a-comprehensive-guide-to-exposure-management-for-cyber-physical-systems)

**Reject a service_enumeration_detail finding until it is distinguished from the adjacent behaviour this class also covers. "Whether a service's protocol weaknesses are reachable is decided by that service's own configuration — signing requirements, binding, authentication method and lockout policy — so service identification must be followed by configuration..." and "As a result, it is imperative that organizations implement exposure management, which is the proactive cybersecurity approach of identifying, assessing, and addressing potential vulnerabilities and risks before they can be exploited." share a surface and a symptom, so a response that matches the first is not evidence for it while the second remains possible.**

Hypothesis under test: Whether a service's protocol weaknesses are reachable is decided by that service's own configuration — signing requirements, binding, authentication method and lockout policy — so service identification must be followed by configuration...

Adjacent behaviour that produces the same observable result: As a result, it is imperative that organizations implement exposure management, which is the proactive cybersecurity approach of identifying, assessing, and addressing potential vulnerabilities and risks before they can be exploited.

Why this is worth checking before reporting: both are recorded in this class as gated knowledge, so a tester who stops at the first match will report one of them. The two differ in what the server actually did with the input, and that difference is observable in the response rather than in the request.

Required before treating this as a finding: capture the response that demonstrates the first behaviour specifically, and confirm the second is not what was observed.

- *Disproof:* This rule is wrong if a controlled test shows the two behaviours can never co-occur on the same surface, or if the corpus entry for "As a result, it is imperative that organizations implement exposure ma" is out of date. In that case this class needs its false-positive guidance rewritten rather than deleted.
- *Evidence:* high_confidence — [attack.mitre.org](https://attack.mitre.org/techniques/T1046/); [cheatsheetseries.owasp.org](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html)

## Known bypasses

_No verified bypass items yet._ Derived from evidence only, so this section is empty rather than plausible.


## Chaining

_No verified chain_link items yet._ Derived from evidence only, so this section is empty rather than plausible.


## Impact

_No verified impact items yet._ Derived from evidence only, so this section is empty rather than plausible.


## Coverage gap

These stages have no verified evidence and are therefore absent above: Preconditions, Reconnaissance signals, Validation, Known bypasses, Chaining, Impact.
A procedure with a missing validation stage is not safe to act on — it produces findings rather than proofs.

---

*Generated from the evidence base. Where this file and the database disagree, the database is correct.*
