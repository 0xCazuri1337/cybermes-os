# Hunt card — lateral_movement

2 promoted technique/test items, each mapped to an executable procedure derived from its shape.

## lateral_movement.technique.relay_fingerprint_then_admin_share_lsa_secret_access

**Claim.** Once a relay is confirmed by the attacker server's default Impacket NTLM challenge, the lateral-movement step is a session against the target's C$ or ADMIN$ share, dumping LSA secrets from Remote Registry including the computer account password.

**Procedure — Filesystem sink confirmation** (shapes: filesystem_sink, state_change)

1. Prove the sink reads a file at all BEFORE testing traversal: fetch a file you KNOW exists on the target and confirm real content comes back.
2. If you cannot get a known-good read, there is no traversal finding to report — the sink is not proven.
3. Then apply the traversal value and confirm the returned content is from OUTSIDE the intended directory. Content, not status code.
4. Reject any result where only the status line differs: proxies, error handlers and WAFs produce status differentials with no file ever read.

**Record:** known-good read, outside-directory content sample, negative control (baseline vs traversal)

## lateral_movement.technique.remote_service_choice_is_protocol_selection

**Claim.** Lateral movement is a selection among the remote access protocols actually reachable between two hosts, so the movement choice is determined by reachability and each protocol's authentication model rather than by attacker preference.

**Procedure — Claim verification (no mechanical template matched)** (shapes: fallback)

1. Restate the claim as an assertion about observable behaviour.
2. Identify the ONE request that would be true if the claim holds and false if it does not.
3. Run it with a control that differs in exactly one variable.
4. If you cannot name the control, you cannot prove the claim — park it as unverified rather than reporting it.

**Record:** the discriminating request, control, observed result
