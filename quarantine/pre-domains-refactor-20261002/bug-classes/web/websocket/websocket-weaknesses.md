# WebSocket Weaknesses

## Definition

The persistent channel inherits origin, authorisation and message-validation weaknesses of its upgrade request.

- **CWE:** 1004
- **OWASP:** A04:2021
- **Surface:** web
- **Aliases:** ["websockets", "ws", "cross site websocket hijacking"]

Canonical home for `websocket`. Rendered from `db/wks.db` by `methodology/scripts/build_taxonomy.py` — edit the rows, not this file.

## Root Cause

Not yet researched.

## Preconditions

Not yet researched.

## Attack Surface

Surface: **web**.

The entry points and enabling conditions for this surface are enumerated under **Preconditions**; the observable signals are under **Detection**.

## Detection

Not yet researched.

## Exploitation

**Because the browser handshake cannot carry an Authorization header, a WebSocket endpoint is only authenticated if the credential arrives through the Sec-WebSocket-Protocol value or an explicit post-connect authentication frame; test each channel by omitting it and observing whether the connection still receives application data.**

Run three separate probes. Probe one: connect with no credential in the subprotocol and send nothing, noting whether the server emits any application payload or admits the socket. Probe two: pass a self-signed or wrong-signature token as Sec-WebSocket-Protocol and see whether it is accepted. Probe three: connect and send the auth frame used by Okta's socketio-jwt pattern, which validates a JWT after the socket opens, and observe both whether an invalid token is rejected and whether the server enforces a timeout on how long it waits for that frame. The documented shape is that the socket exists briefly before it is proven.

*Disproof:* The channel test fails if a connection with no credential still receives application data, or if an invalid or unsigned token is accepted. It also fails to implicate this endpoint if the deployment terminates authentication in a reverse proxy that injects an identity header rather than in the socket handler, in which case the trust boundary to test is the proxy, not the frame.

## Variations

**Passing the session credential in the WebSocket URL query string bypasses every header-stripping and referrer-policy control, because URLs are recorded verbatim in proxy, server and browser history even where the same token would never be logged as a header.**

Connect to wss://host/ws?token=<captured access token>, then enumerate the places that copy the request line: the reverse proxy access log, the application log, browser history, and any monitoring or crash reporter that records URLs. Grep each for the token value. A single hit is the bypass, because a credential in a log is a credential a log reader can replay. Contrast it with the header case on the same target: a token sent in a header appears in no URL field, so the difference between the two placements is the finding, not the mere presence of a token.

*Disproof:* The bypass is not demonstrated if the token never appears in any log, proxy record, history entry or telemetry field you can reach, or if the server rejects query-string credentials outright at the upgrade. It also does not apply where the credential is single-use, short-lived and audience-bound, because its theft then yields nothing beyond the attacker's own session.

## Technology / Framework Considerations

Not yet researched.

## API Considerations

Not yet researched.

## Attack Chains

Not yet researched.

## Real-World Examples

Not yet researched.

## Common False Positives

**A WebSocket endpoint that only accepts a connection, echoes the caller's own frames back, and serves no other user's data is not cross-site WebSocket hijacking unless the handshake ALSO lacks Origin validation and the connection carries ambient credentials: hijack is the combination of cross-site connectability and session-authorised state.**

Two conditions, both required. Condition one is the handshake: ZAP's rule fires when the server accepts the Upgrade with a modified Origin, so an open handshake is only half the finding. Condition two is the state: Datadog's analysis of a real WebSocket authentication bypass shows why, because WebSocket connections are not restricted by the browser's same-origin policy, so cross-site reachability alone hands an attacker the socket and the damage comes entirely from what that socket can then read or mutate on the victim's behalf. On an echo endpoint both halves are empty: nothing is validated and nothing is exposed. Confirm by driving the channel with a second identity and asking whether any frame belonging to someone else ever arrives. Hunting value: this removes the echo, debug-console, presence and telemetry endpoints, which respond 101 to any Origin and are the bulk of cross-origin handshake alerts.

*Disproof:* It IS CSWSH if Origin is unvalidated AND the connection carries a session cookie or bearer token that lets the attacker read or mutate state belonging to the victim: another user's message, a private channel, an account action. Prove impact with a second identity, not with the attacker's own frame.

**A WebSocket endpoint that completes the upgrade for an arbitrary Origin is not Cross-Site WebSocket Hijacking until the server acts on an attacker-reachable frame or event; establishing the connection alone proves only that the handshake does not check Origin.**

Separate the two halves. First, send the upgrade request with a foreign Origin and record whether it returns 101, which establishes the missing check and nothing more. Second, drive the full attack shape from a page on the attacker origin: open the socket, wait for the server to push, and attempt at least one state-changing send that the victim's session would authorize. The finding is proven when that action changes server state, because the browser attached the victim's cookie as ambient authority and the deputy acted on it. Okta's guidance that a token-issuing endpoint must be vigilant about confirming the caller's origin and keeping the allowlist strict shows what the defence looks like, and the same discipline applies to a socket whose frames mutate state.

*Disproof:* The report is a false positive if the 101 is granted but every pushed frame and every send is refused without a credential the attacker lacks, or if the socket only ever emits public data. It is also a false positive if the state change required a second, attacker-independent authorization step that the attacker's frame could not satisfy.

## Validation

**A WebSocket that only pushes object identifiers has no data exposure to demonstrate, so a CSWSH or unauthenticated-socket report on such a channel is not substantiated until a test shows the frame itself carrying a field the reader could not otherwise obtain.**

Capture several frames from the socket while authenticated, then repeat from an unauthenticated or cross-origin context. Decode each frame and list the fields present. If the payload is only an id, the exposure is limited to revealing that something changed and the honest write-up is the identifier plus whatever an authenticated fetch of that id would still require. Okta's documented mitigation for exactly this problem is to change the endpoint so it only sends IDs so that no sensitive data is propagated, meaning a channel already shaped that way is behaving as designed. Escalate only once a frame contains a name, email, balance or any other field the reader was not entitled to.

*Disproof:* The report is substantiated and this item disproved the moment a captured frame contains a real field: a full record, a permission-bearing value, or an internal identifier that resolves to data with no further authorization check. Also disprove it if the socket genuinely required authentication before any frame was emitted, since then there is no unauthenticated read to demonstrate.

## Impact

Not yet researched.

## Related Bug Classes

Not yet researched.

## References

- **auth0.com** (blog)
  - <https://auth0.com/blog/confused-deputy-the-old-bug-that-ai-agents-keep-reintroducing/>
  - <https://auth0.com/blog/cross-site-request-forgery-csrf/>
  - <https://auth0.com/docs/secure/tokens/token-best-practices>
- **developer.okta.com** (blog)
  - <https://developer.okta.com/blog/2018/09/25/spring-webflux-websockets-react>
  - <https://developer.okta.com/blog/2020/10/28/secure-web-apps-websockets-nodejs>
  - <https://developer.okta.com/blog/2022/07/08/spa-web-security-csrf-xss>
  - <https://developer.okta.com/docs/concepts/session/>
- **securitylabs.datadoghq.com** (writeup)
  - <https://securitylabs.datadoghq.com/articles/claude-mcp-cve-2025-52882/>
- **tailscale.com** (docs)
  - <https://tailscale.com/docs/features/tailscale-serve>
- **zaproxy.org** (docs)
  - <https://www.zaproxy.org/docs/alerts/100025/>

Every item above is gated on >= 2 distinct publisher hosts (`wks/quality.py`, rule R1). Publisher diversity, not citation count, is what makes these corroborated.
