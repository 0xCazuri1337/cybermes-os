# Hunt card — tunneling_pivoting

3 promoted technique/test items, each mapped to an executable procedure derived from its shape.

## tunneling_pivoting.test.an_ssh_or_socks_tunnel_inside_the_estate_is_not

**Claim.** To decide this case, observe: Discard when the tunnel was observed entirely between hosts inside the scoped network: the intrusion report shows the actor's SSH tunnel was built to present RDP access from a public IP address they owned, which is what distinguishes ingress from internal administration.

**Procedure — Single-parameter differential probe** (shapes: http_param_probe)

1. Record the BASELINE: request the endpoint with a benign, known-good value for the parameter. Save the full response (status, length, body hash).
2. Change exactly ONE variable: set the parameter to the attack value. Send it again with identical method, headers and cookies.
3. DIFF the two responses on all three axes: status code, body length, and body content hash.
4. Attribute every difference. A difference the control did not produce is the finding; a difference the control also produces is the application's normal behaviour.
5. Then re-run the attack value THREE times to separate a real condition from per-request noise (timing, nonce, ordering).

**Record:** baseline response hash, attack response hash, status delta, body-length delta, reproductions

## tunneling_pivoting.technique.encapsulation_reintroduces_forbidden_reachability

**Claim.** A tunnel carries one protocol inside another, so a reachability that policy forbids directly can be reintroduced through a host both sides accept — the boundary that matters is the tunnel endpoint, not the inner protocol.

**Procedure — Single-parameter differential probe** (shapes: http_param_probe, filesystem_sink, state_change)

1. Record the BASELINE: request the endpoint with a benign, known-good value for the parameter. Save the full response (status, length, body hash).
2. Change exactly ONE variable: set the parameter to the attack value. Send it again with identical method, headers and cookies.
3. DIFF the two responses on all three axes: status code, body length, and body content hash.
4. Attribute every difference. A difference the control did not produce is the finding; a difference the control also produces is the application's normal behaviour.
5. Then re-run the attack value THREE times to separate a real condition from per-request noise (timing, nonce, ordering).

**Record:** baseline response hash, attack response hash, status delta, body-length delta, reproductions

## tunneling_pivoting.technique.a_pivot_is_established_by_tunnelling_traffic_for_a_second

**Claim.** A pivot is established by tunnelling traffic for a second network segment through the already-compromised host, which carries no credentials of its own.

**Procedure — State-changing verification** (shapes: state_change, race_condition)

1. Capture the pre-state with a read-only request and record it.
2. Perform the single state change.
3. Read the state again THROUGH THE SAME ACCOUNT and, if a second test identity exists, through that identity too.
4. A change visible only to the actor proves write access, not a vulnerability. Cross-account visibility is what makes it one.

**Record:** pre-state, post-state (same identity), post-state (second identity) if available
