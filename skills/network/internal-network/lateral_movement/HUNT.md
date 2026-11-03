# HUNT runbook — lateral_movement

**4 promoted technique/test/variant items**, each mapped to an executable procedure derived from the shape of the claim. Generated from `db/wks.db`; do not hand-edit (regenerate with `python tools/playbook.py lateral_movement network`).

Sources of steps: 0 item-authored, 4 template-derived (a template step is the SHAPE's procedure, not a claim-specific one — treat those as the starting point and adapt).

## Index

- [lateral_movement.technique.relay_fingerprint_then_admin_share_lsa_secret_access](#lateral-movement-technique-relay-fingerprint-then-admin-share-lsa-secret-access) — Filesystem sink confirmation
- [lateral_movement.technique.remote_service_choice_is_protocol_selection](#lateral-movement-technique-remote-service-choice-is-protocol-selection) — Claim verification (no mechanical template matched)
- [lateral_movement.auto.05](#lateral-movement-auto-05) — Filter-bypass ladder
- [lateral_movement.auto.t.5dd47cac](#lateral-movement-auto-t-5dd47cac) — Filter-bypass ladder

<a id="lateral-movement-technique-relay-fingerprint-then-admin-share-lsa-secret-access"></a>

## lateral_movement.technique.relay_fingerprint_then_admin_share_lsa_secret_access

**Claim.** Once a relay is confirmed by the attacker server's default Impacket NTLM challenge, the lateral-movement step is a session against the target's C$ or ADMIN$ share, dumping LSA secrets from Remote Registry including the computer account password.

**Procedure — Filesystem sink confirmation** (shapes: filesystem_sink; steps from template)

1. Prove the sink reads a file at all BEFORE testing traversal: fetch a file you KNOW exists on the target and confirm real content comes back.
2. If you cannot get a known-good read, there is no traversal finding to report — the sink is not proven.
3. Then apply the traversal value and confirm the returned content is from OUTSIDE the intended directory. Content, not status code.
4. Reject any result where only the status line differs: proxies, error handlers and WAFs produce status differentials with no file ever read.

**Record:** known-good read, outside-directory content sample, negative control (baseline vs traversal)

**Vary these — each changes what you do and what you see**

- **Do two layers disagree about the same bytes?** — container: **do** nest the value one layer deeper (archive, template, include); **observe** a second interpretation after the first check.
- **AS whom are you testing?** — low_priv: **do** send as your lowest-privilege account; **observe** whether the response differs from anonymous.
- **What PROVES it, beyond a status code?** — differential: **do** compare against a control that differs in one variable; **observe** the difference the control did not produce.

**If the first attempt is flat**

No effect raw? Walk the encoding ladder: raw -> percent-encoded -> double-encoded -> look-alike separators, one rung at a time, never all at once.
Flat direct? Go through the real front door (proxy/CDN). Intermediaries normalise, and their normalisation is the behaviour you are hunting.
Still flat? You have proven the sink is not reachable on this path, which is a RESULT. Record it and move to the next candidate rather than escalating payloads blindly.

<a id="lateral-movement-technique-remote-service-choice-is-protocol-selection"></a>

## lateral_movement.technique.remote_service_choice_is_protocol_selection

**Claim.** Lateral movement is a selection among the remote access protocols actually reachable between two hosts, so the movement choice is determined by reachability and each protocol's authentication model rather than by attacker preference.

**Procedure — Claim verification (no mechanical template matched)** (shapes: fallback; steps from template)

1. Restate the claim as an assertion about observable behaviour.
2. Identify the ONE request that would be true if the claim holds and false if it does not.
3. Run it with a control that differs in exactly one variable.
4. If you cannot name the control, you cannot prove the claim — park it as unverified rather than reporting it.

**Record:** the discriminating request, control, observed result

**Vary these — each changes what you do and what you see**

- **Do two layers disagree about the same bytes?** — single: **do** one parser sees the request; **observe** a consistent rejection or acceptance.

**If the first attempt is flat**

No effect raw? Walk the encoding ladder: raw -> percent-encoded -> double-encoded -> look-alike separators, one rung at a time, never all at once.
Flat direct? Go through the real front door (proxy/CDN). Intermediaries normalise, and their normalisation is the behaviour you are hunting.
Still flat? You have proven the sink is not reachable on this path, which is a RESULT. Record it and move to the next candidate rather than escalating payloads blindly.

<a id="lateral-movement-auto-05"></a>

## lateral_movement.auto.05

**Claim.** These flaws enable attackers to upload malicious files, execute arbitrary commands on the back-end server, and even take control over the entire server and all web applications hosted on it and potentially gain access to sensitive data or cause a service disruption.

**Procedure — Filter-bypass ladder** (shapes: filter_bypass, filesystem_sink; steps from template)

1. First establish what the filter rejects: send the plain attack value and record the rejection (status, message, silence).
2. Then vary ONE encoding dimension at a time: separators, case, trailing dots, alternate separators, redundant segments, container-level normalisation.
3. The first variation that passes identifies the filter's matching weakness precisely — which is the finding.
4. Confirm the bypass reaches the sink by observing an EFFECT, not by observing a different response status.

**Record:** plain value rejection, bypass variant that passed, observed effect at the sink

**Vary these — each changes what you do and what you see**

- **Do two layers disagree about the same bytes?** — single: **do** one parser sees the request; **observe** a consistent rejection or acceptance.
- **What PROVES it, beyond a status code?** — differential: **do** compare against a control that differs in one variable; **observe** the difference the control did not produce.

**If the first attempt is flat**

No effect raw? Walk the encoding ladder: raw -> percent-encoded -> double-encoded -> look-alike separators, one rung at a time, never all at once.
Flat direct? Go through the real front door (proxy/CDN). Intermediaries normalise, and their normalisation is the behaviour you are hunting.
Still flat? You have proven the sink is not reachable on this path, which is a RESULT. Record it and move to the next candidate rather than escalating payloads blindly.

**Also applies — alternate procedures for this item**

- *Filesystem sink confirmation* — Prove the sink reads a file at all BEFORE testing traversal: fetch a file you KNOW exists on the target and confirm real content comes back.

<a id="lateral-movement-auto-t-5dd47cac"></a>

## lateral_movement.auto.t.5dd47cac

**Claim.** These flaws enable attackers to upload malicious files, execute arbitrary commands on the back-end server, and even take control over the entire server and all web applications hosted on it and potentially gain access to sensitive data or cause a service disruption.

**Procedure — Filter-bypass ladder** (shapes: filter_bypass, filesystem_sink; steps from template)

1. First establish what the filter rejects: send the plain attack value and record the rejection (status, message, silence).
2. Then vary ONE encoding dimension at a time: separators, case, trailing dots, alternate separators, redundant segments, container-level normalisation.
3. The first variation that passes identifies the filter's matching weakness precisely — which is the finding.
4. Confirm the bypass reaches the sink by observing an EFFECT, not by observing a different response status.

**Record:** plain value rejection, bypass variant that passed, observed effect at the sink

**Vary these — each changes what you do and what you see**

- **Do two layers disagree about the same bytes?** — single: **do** one parser sees the request; **observe** a consistent rejection or acceptance.
- **What PROVES it, beyond a status code?** — differential: **do** compare against a control that differs in one variable; **observe** the difference the control did not produce.

**If the first attempt is flat**

No effect raw? Walk the encoding ladder: raw -> percent-encoded -> double-encoded -> look-alike separators, one rung at a time, never all at once.
Flat direct? Go through the real front door (proxy/CDN). Intermediaries normalise, and their normalisation is the behaviour you are hunting.
Still flat? You have proven the sink is not reachable on this path, which is a RESULT. Record it and move to the next candidate rather than escalating payloads blindly.

**Also applies — alternate procedures for this item**

- *Filesystem sink confirmation* — Prove the sink reads a file at all BEFORE testing traversal: fetch a file you KNOW exists on the target and confirm real content comes back.
