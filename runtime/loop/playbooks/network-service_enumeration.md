# Hunt card — service_enumeration

3 promoted technique/test items, each mapped to an executable procedure derived from its shape.

## service_enumeration.validation.rdp-session-correlated-with-enumerated-rdp-rights-and-credential-origin

**Claim.** An RDP session is confirmed malicious only when the account's enumeration-derived RDP access rights and the origin of its credential both support the session; rights alone or a successful session alone are insufficient.

**Procedure — Filesystem sink confirmation** (shapes: filesystem_sink, state_change)

1. Prove the sink reads a file at all BEFORE testing traversal: fetch a file you KNOW exists on the target and confirm real content comes back.
2. If you cannot get a known-good read, there is no traversal finding to report — the sink is not proven.
3. Then apply the traversal value and confirm the returned content is from OUTSIDE the intended directory. Content, not status code.
4. Reject any result where only the status line differs: proxies, error handlers and WAFs produce status differentials with no file ever read.

**Record:** known-good read, outside-directory content sample, negative control (baseline vs traversal)

## service_enumeration.technique.full_tcp_port_scanning_with_service_version_detection_is_t

**Claim.** Full TCP port scanning with service version detection is the entry step that establishes which attack surface exists before any technique is attempted.

**Procedure — State-changing verification** (shapes: state_change)

1. Capture the pre-state with a read-only request and record it.
2. Perform the single state change.
3. Read the state again THROUGH THE SAME ACCOUNT and, if a second test identity exists, through that identity too.
4. A change visible only to the actor proves write access, not a vulnerability. Cross-account visibility is what makes it one.

**Record:** pre-state, post-state (same identity), post-state (second identity) if available

## service_enumeration.technique.banner_selects_the_applicable_technique

**Claim.** Port and service scanning is used to acquire the list of open services and their banners, and that list is what determines which technique is even applicable to a host.

**Procedure — Filesystem sink confirmation** (shapes: filesystem_sink)

1. Prove the sink reads a file at all BEFORE testing traversal: fetch a file you KNOW exists on the target and confirm real content comes back.
2. If you cannot get a known-good read, there is no traversal finding to report — the sink is not proven.
3. Then apply the traversal value and confirm the returned content is from OUTSIDE the intended directory. Content, not status code.
4. Reject any result where only the status line differs: proxies, error handlers and WAFs produce status differentials with no file ever read.

**Record:** known-good read, outside-directory content sample, negative control (baseline vs traversal)
