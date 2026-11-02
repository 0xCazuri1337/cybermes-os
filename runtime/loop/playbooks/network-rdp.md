# Hunt card — rdp

10 promoted technique/test items, each mapped to an executable procedure derived from its shape.

## rdp.technique.tcp-tunnel-carried-inside-an-rdp-session

**Claim.** Arbitrary TCP reachability can be obtained by tunnelling that TCP stream inside an already-authenticated RDP session's dynamic virtual channels, so the forwarded traffic leaves the network disguised as an RDP stream.

**Procedure — Single-parameter differential probe** (shapes: http_param_probe, state_change)

1. Record the BASELINE: request the endpoint with a benign, known-good value for the parameter. Save the full response (status, length, body hash).
2. Change exactly ONE variable: set the parameter to the attack value. Send it again with identical method, headers and cookies.
3. DIFF the two responses on all three axes: status code, body length, and body content hash.
4. Attribute every difference. A difference the control did not produce is the finding; a difference the control also produces is the application's normal behaviour.
5. Then re-run the attack value THREE times to separate a real condition from per-request noise (timing, nonce, ordering).

**Record:** baseline response hash, attack response hash, status delta, body-length delta, reproductions

## rdp.validation.domain-controller-destination-cross-checked-against-the-rights-graph

**Claim.** A flagged RDP session to a domain controller discriminates from the benign lookalike only when the operator's rights to that controller are read out of the directory rather than inferred from the session alone.

**Procedure — Filesystem sink confirmation** (shapes: filesystem_sink, state_change)

1. Prove the sink reads a file at all BEFORE testing traversal: fetch a file you KNOW exists on the target and confirm real content comes back.
2. If you cannot get a known-good read, there is no traversal finding to report — the sink is not proven.
3. Then apply the traversal value and confirm the returned content is from OUTSIDE the intended directory. Content, not status code.
4. Reject any result where only the status line differs: proxies, error handlers and WAFs produce status differentials with no file ever read.

**Record:** known-good read, outside-directory content sample, negative control (baseline vs traversal)

## rdp.technique.virtual-channel-inventory-from-rdpcorets-operational-log

**Claim.** Every RDP virtual channel opened and closed during a session is logged by the host as event ID 132 (opened) and 148 (closed) in Microsoft-Windows-RemoteDesktopServices-RdpCoreTS/Operational.evtx, naming each channel.

**Procedure — Filesystem sink confirmation** (shapes: filesystem_sink, state_change)

1. Prove the sink reads a file at all BEFORE testing traversal: fetch a file you KNOW exists on the target and confirm real content comes back.
2. If you cannot get a known-good read, there is no traversal finding to report — the sink is not proven.
3. Then apply the traversal value and confirm the returned content is from OUTSIDE the intended directory. Content, not status code.
4. Reject any result where only the status line differs: proxies, error handlers and WAFs produce status differentials with no file ever read.

**Record:** known-good read, outside-directory content sample, negative control (baseline vs traversal)

## rdp.signal.rdp-session-to-a-domain-controller

**Claim.** An RDP session whose destination is a domain controller is a higher-severity signal than the same session to a member server, because the destination can perform directory replication.

**Procedure — Filesystem sink confirmation** (shapes: filesystem_sink, state_change)

1. Prove the sink reads a file at all BEFORE testing traversal: fetch a file you KNOW exists on the target and confirm real content comes back.
2. If you cannot get a known-good read, there is no traversal finding to report — the sink is not proven.
3. Then apply the traversal value and confirm the returned content is from OUTSIDE the intended directory. Content, not status code.
4. Reject any result where only the status line differs: proxies, error handlers and WAFs produce status differentials with no file ever read.

**Record:** known-good read, outside-directory content sample, negative control (baseline vs traversal)

## rdp.technique.virtual_channel_count_makes_extension_surface_unbounded

**Claim.** RDP is a multiple-channel protocol supporting up to 64,000 separate virtual channels, so third-party channel plugins turn one authenticated session into an extensible command surface that a perimeter review of TCP/3389 does not cover.

**Procedure — Single-parameter differential probe** (shapes: http_param_probe, filesystem_sink, state_change)

1. Record the BASELINE: request the endpoint with a benign, known-good value for the parameter. Save the full response (status, length, body hash).
2. Change exactly ONE variable: set the parameter to the attack value. Send it again with identical method, headers and cookies.
3. DIFF the two responses on all three axes: status code, body length, and body content hash.
4. Attribute every difference. A difference the control did not produce is the finding; a difference the control also produces is the application's normal behaviour.
5. Then re-run the attack value THREE times to separate a real condition from per-request noise (timing, nonce, ordering).

**Record:** baseline response hash, attack response hash, status delta, body-length delta, reproductions

## rdp.signal.unauthorized-rdp-port-or-external-rdp-peer

**Claim.** An RDP or SSH session that uses a port not on the authorized list for that host, or that peers with an external IP address, is a signal that the session was not established through the approved access path.

**Procedure — Single-parameter differential probe** (shapes: http_param_probe, filesystem_sink, state_change)

1. Record the BASELINE: request the endpoint with a benign, known-good value for the parameter. Save the full response (status, length, body hash).
2. Change exactly ONE variable: set the parameter to the attack value. Send it again with identical method, headers and cookies.
3. DIFF the two responses on all three axes: status code, body length, and body content hash.
4. Attribute every difference. A difference the control did not produce is the finding; a difference the control also produces is the application's normal behaviour.
5. Then re-run the attack value THREE times to separate a real condition from per-request noise (timing, nonce, ordering).

**Record:** baseline response hash, attack response hash, status delta, body-length delta, reproductions

## rdp.technique.an_exposed_rdp_service_is_confirmed_by_a_successful_authen

**Claim.** An exposed RDP service is confirmed by a successful authentication attempt with discovered or sprayed credentials, which yields an interactive desktop session.

**Procedure — State-changing verification** (shapes: state_change)

1. Capture the pre-state with a read-only request and record it.
2. Perform the single state change.
3. Read the state again THROUGH THE SAME ACCOUNT and, if a second test identity exists, through that identity too.
4. A change visible only to the actor proves write access, not a vulnerability. Cross-account visibility is what makes it one.

**Record:** pre-state, post-state (same identity), post-state (second identity) if available

## rdp.technique.clipboard_and_drive_redirection_carries_data_off_host

**Claim.** Clipboard mapping and drive, port and printer redirection in an RDP session give the interactive user a bidirectional data path off the server, so an RDP foothold exfiltrates by copy rather than by tooling.

**Procedure — Filesystem sink confirmation** (shapes: filesystem_sink, state_change)

1. Prove the sink reads a file at all BEFORE testing traversal: fetch a file you KNOW exists on the target and confirm real content comes back.
2. If you cannot get a known-good read, there is no traversal finding to report — the sink is not proven.
3. Then apply the traversal value and confirm the returned content is from OUTSIDE the intended directory. Content, not status code.
4. Reject any result where only the status line differs: proxies, error handlers and WAFs produce status differentials with no file ever read.

**Record:** known-good read, outside-directory content sample, negative control (baseline vs traversal)

## rdp.technique.attacker-named-virtual-channel-reveals-the-tunnel

**Claim.** When a TCP tunnel is carried over an RDP session, the RdpCoreTS 132 and 148 events carry the tool's channel name or an arbitrary attacker-chosen alphanumeric string instead of a standard RemoteFX channel name.

**Procedure — State-changing verification** (shapes: state_change)

1. Capture the pre-state with a read-only request and record it.
2. Perform the single state change.
3. Read the state again THROUGH THE SAME ACCOUNT and, if a second test identity exists, through that identity too.
4. A change visible only to the actor proves write access, not a vulnerability. Cross-account visibility is what makes it one.

**Record:** pre-state, post-state (same identity), post-state (second identity) if available

## rdp.technique.port-forwarding-and-socket-forward-behind-an-rdp-session

**Claim.** Once an RDP session is established the operator can stand up stock Windows port-forwarding and socket-forwarding functionality on the target, so an internal-only service becomes reachable through a host the operator already holds an interactive session on.

**Procedure — State-changing verification** (shapes: state_change, race_condition)

1. Capture the pre-state with a read-only request and record it.
2. Perform the single state change.
3. Read the state again THROUGH THE SAME ACCOUNT and, if a second test identity exists, through that identity too.
4. A change visible only to the actor proves write access, not a vulnerability. Cross-account visibility is what makes it one.

**Record:** pre-state, post-state (same identity), post-state (second identity) if available
