# HUNT runbook — service_enumeration_detail

**2 promoted technique/test/variant items**, each mapped to an executable procedure derived from the shape of the claim. Generated from `db/wks.db`; do not hand-edit (regenerate with `python tools/playbook.py service_enumeration_detail network`).

Sources of steps: 0 item-authored, 2 template-derived (a template step is the SHAPE's procedure, not a claim-specific one — treat those as the starting point and adapt).

## Index

- [service_enumeration_detail.technique.service_configuration_determines_reachability](#service-enumeration-detail-technique-service-configuration-determines-reachability) — Filter-bypass ladder
- [service_enumeration_detail.auto.t.5d50fcbc](#service-enumeration-detail-auto-t-5d50fcbc) — State-changing verification

<a id="service-enumeration-detail-technique-service-configuration-determines-reachability"></a>

## service_enumeration_detail.technique.service_configuration_determines_reachability

**Claim.** Whether a service's protocol weaknesses are reachable is decided by that service's own configuration — signing requirements, binding, authentication method and lockout policy — so service identification must be followed by configuration assessment before any weakness is asserted.

**Procedure — Filter-bypass ladder** (shapes: filter_bypass, filesystem_sink; steps from template)

1. First establish what the filter rejects: send the plain attack value and record the rejection (status, message, silence).
2. Then vary ONE encoding dimension at a time: separators, case, trailing dots, alternate separators, redundant segments, container-level normalisation.
3. The first variation that passes identifies the filter's matching weakness precisely — which is the finding.
4. Confirm the bypass reaches the sink by observing an EFFECT, not by observing a different response status.

**Record:** plain value rejection, bypass variant that passed, observed effect at the sink

**Vary these — each changes what you do and what you see**

- **Do two layers disagree about the same bytes?** — single: **do** one parser sees the request; **observe** a consistent rejection or acceptance.
- **What PROVES it, beyond a status code?** — state: **do** read the state back; **observe** the change visible to a second identity.

**If the first attempt is flat**

No effect raw? Walk the encoding ladder: raw -> percent-encoded -> double-encoded -> look-alike separators, one rung at a time, never all at once.
Flat direct? Go through the real front door (proxy/CDN). Intermediaries normalise, and their normalisation is the behaviour you are hunting.
Still flat? You have proven the sink is not reachable on this path, which is a RESULT. Record it and move to the next candidate rather than escalating payloads blindly.

**Also applies — alternate procedures for this item**

- *Filesystem sink confirmation* — Prove the sink reads a file at all BEFORE testing traversal: fetch a file you KNOW exists on the target and confirm real content comes back.

<a id="service-enumeration-detail-auto-t-5d50fcbc"></a>

## service_enumeration_detail.auto.t.5d50fcbc

**Claim.** Failure to utilize TLS or other strong transport for the login page allows an attacker to modify the login form action, causing the user's credentials to be posted to an arbitrary location.

**Procedure — State-changing verification** (shapes: state_change; steps from template)

1. Capture the pre-state with a read-only request and record it.
2. Perform the single state change.
3. Read the state again THROUGH THE SAME ACCOUNT and, if a second test identity exists, through that identity too.
4. A change visible only to the actor proves write access, not a vulnerability. Cross-account visibility is what makes it one.

**Record:** pre-state, post-state (same identity), post-state (second identity) if available

**Vary these — each changes what you do and what you see**

- **Do two layers disagree about the same bytes?** — single: **do** one parser sees the request; **observe** a consistent rejection or acceptance.
- **AS whom are you testing?** — low_priv: **do** send as your lowest-privilege account; **observe** whether the response differs from anonymous.

**If the first attempt is flat**

No effect raw? Walk the encoding ladder: raw -> percent-encoded -> double-encoded -> look-alike separators, one rung at a time, never all at once.
Flat direct? Go through the real front door (proxy/CDN). Intermediaries normalise, and their normalisation is the behaviour you are hunting.
Still flat? You have proven the sink is not reachable on this path, which is a RESULT. Record it and move to the next candidate rather than escalating payloads blindly.
