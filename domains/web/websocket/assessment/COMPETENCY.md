# Methodology — WebSocket Weaknesses

> Derived from 14 verified items. Regenerate with `python -m wks.methodgen --class websocket --apply`. Do not hand-edit: this file is a projection of the evidence, and edits are lost on the next cycle.

**Surface.** The persistent channel inherits origin, authorisation and message-validation weaknesses of its upgrade request.

**References.** CWE-1004 · A04:2021

## Preconditions

_No verified prerequisite items yet._ Derived from evidence only, so this section is empty rather than plausible.


## Reconnaissance signals

_No verified signal items yet._ Derived from evidence only, so this section is empty rather than plausible.


## 1. Test sequence

_Concrete mutations to try. Each is written to be executable, not to be a description of the vulnerability._

**Because the browser handshake cannot carry an Authorization header, a WebSocket endpoint is only authenticated if the credential arrives through the Sec-WebSocket-Protocol value or an explicit post-connect authentication frame; test each channel by omitting it and observing whether the connection still receives application data.**

Run three separate probes. Probe one: connect with no credential in the subprotocol and send nothing, noting whether the server emits any application payload or admits the socket. Probe two: pass a self-signed or wrong-signature token as Sec-WebSocket-Protocol and see whether it is accepted. Probe three: connect and send the auth frame used by Okta's socketio-jwt pattern, which validates a JWT after the socket opens, and observe both whether an invalid token is rejected and whether the server enforces a timeout on how long it waits for that frame. The documented shape is that the socket exists briefly before it is proven.

- *Disproof:* The channel test fails if a connection with no credential still receives application data, or if an invalid or unsigned token is accepted. It also fails to implicate this endpoint if the deployment terminates authentication in a reverse proxy that injects an identity header rather than in the socket handler, in which case the trust boundary to test is the proxy, not the frame.
- *Evidence:* high_confidence — [auth0.com](https://auth0.com/blog/cross-site-request-forgery-csrf/); [developer.okta.com](https://developer.okta.com/blog/2020/10/28/secure-web-apps-websockets-nodejs)

## 2. Validation

_How to prove the finding rather than infer it. A technique that cannot be validated must not be reported._

**A WebSocket that only pushes object identifiers has no data exposure to demonstrate, so a CSWSH or unauthenticated-socket report on such a channel is not substantiated until a test shows the frame itself carrying a field the reader could not otherwise obtain.**

Capture several frames from the socket while authenticated, then repeat from an unauthenticated or cross-origin context. Decode each frame and list the fields present. If the payload is only an id, the exposure is limited to revealing that something changed and the honest write-up is the identifier plus whatever an authenticated fetch of that id would still require. Okta's documented mitigation for exactly this problem is to change the endpoint so it only sends IDs so that no sensitive data is propagated, meaning a channel already shaped that way is behaving as designed. Escalate only once a frame contains a name, email, balance or any other field the reader was not entitled to.

- *Disproof:* The report is substantiated and this item disproved the moment a captured frame contains a real field: a full record, a permission-bearing value, or an internal identifier that resolves to data with no further authorization check. Also disprove it if the socket genuinely required authentication before any frame was emitted, since then there is no unauthenticated read to demonstrate.
- *Evidence:* high_confidence — [developer.okta.com](https://developer.okta.com/blog/2018/09/25/spring-webflux-websockets-react); [tailscale.com](https://tailscale.com/docs/features/tailscale-serve)

**The convincing evidence for cross-site WebSocket reach is a raw upgrade request carrying an attacker-controlled Origin that still completes with HTTP 101 and then exchanges frames with the victim's authenticated session, which proves the handshake has no origin gate.**

Mechanism: The convincing evidence for cross-site WebSocket reach is a raw upgrade request carrying an attacker-controlled Origin that still completes with HTTP 101 and then exchanges frames with the victim's authenticated session, which proves the handshake has no origin gate. How to apply it in the field: treat this as the validation it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable. Boundary of the rule: If the same request with a foreign Origin receives 403 or 401 the handshake is gated and the finding fails; a 101 alone is not enough if the follow-on frames are unauthenticated, since an anonymous channel proves missing origin control but not victim-session impact.

- *Disproof:* If the same request with a foreign Origin receives 403 or 401 the handshake is gated and the finding fails; a 101 alone is not enough if the follow-on frames are unauthenticated, since an anonymous channel proves missing origin control but not victim-session impact.
- *Evidence:* high_confidence — [rfc-editor.org](https://www.rfc-editor.org/rfc/rfc6455.txt); [tomcat.apache.org](https://tomcat.apache.org/tomcat-9.0-doc/web-socket-howto.html)

## 3. False-positive rejection

_The checks that eliminate the most common non-findings. Run these BEFORE reporting, not after a rejection._

**Receiving messages injected into a WebSocket channel by a malicious page is not XSS unless the handler reflects or evaluates the payload in an HTML context, so an attacker-controlled frame that is merely parsed as JSON is a data-integrity finding, not a script-execution one.**

Mechanism: Receiving messages injected into a WebSocket channel by a malicious page is not XSS unless the handler reflects or evaluates the payload in an HTML context, so an attacker-controlled frame that is merely parsed as JSON is a data-integrity finding, not a script-execution one. How to apply it in the field: treat this as the fp_rule it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable. Boundary of the rule: It IS XSS when the frame content is concatenated into a response body, written into innerHTML, or evaluated by the client; it is not when the payload stays inside JSON.parse or a typed schema field and no HTML sink receives it, in which case the correct class is injection into a data consumer rather than script execution.

- *Disproof:* It IS XSS when the frame content is concatenated into a response body, written into innerHTML, or evaluated by the client; it is not when the payload stays inside JSON.parse or a typed schema field and no HTML sink receives it, in which case the correct class is injection into a data consumer rather than script execution.
- *Evidence:* high_confidence — [rfc-editor.org](https://www.rfc-editor.org/rfc/rfc6455.txt); [tomcat.apache.org](https://tomcat.apache.org/tomcat-9.0-doc/web-socket-howto.html)

**A WebSocket handshake is a normal HTTP upgrade request that still carries cookies, so SameSite only reduces cross-site reach for browsers that attach the cookie on this request; a server that never validates the Origin header at handshake time is exposed regardless of the SameSite attribute on its session cookie.**

Mechanism: A WebSocket handshake is a normal HTTP upgrade request that still carries cookies, so SameSite only reduces cross-site reach for browsers that attach the cookie on this request; a server that never validates the Origin header at handshake time is exposed regardless of the SameSite attribute on its session cookie. How to apply it in the field: treat this as the fp_rule it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable. Boundary of the rule: It is NOT exposed if the handshake is only reachable from a non-browser client that the attacker cannot author, or if the server enforces an origin allow-list at upgrade time; and the SameSite argument itself is falsified when the cookie is SameSite=None or when the vulnerable channel is used by a non-browser client whose cookie jar is not governed by SameSite at all.

- *Disproof:* It is NOT exposed if the handshake is only reachable from a non-browser client that the attacker cannot author, or if the server enforces an origin allow-list at upgrade time; and the SameSite argument itself is falsified when the cookie is SameSite=None or when the vulnerable channel is used by a non-browser client whose cookie jar is not governed by SameSite at all.
- *Evidence:* high_confidence — [rfc-editor.org](https://www.rfc-editor.org/rfc/rfc6455.txt); [w3.org](https://www.w3.org/TR/websockets/)

**A page or config string containing wss:// is not by itself evidence that the WebSocket channel is protected, because confidentiality and integrity come from actually running the handshake over TLS end to end rather than from the scheme label appearing in source.**

Mechanism: A page or config string containing wss:// is not by itself evidence that the WebSocket channel is protected, because confidentiality and integrity come from actually running the handshake over TLS end to end rather than from the scheme label appearing in source. How to apply it in the field: treat this as the fp_rule it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable. Boundary of the rule: It IS protected when the handshake reaches wss:// and the transport negotiates TLS with a certificate the client validates; it is not protected when a wss:// literal is present but a proxy terminates or downgrades the upgrade, or when the code builds the URL from an attacker-controlled scheme value so the same code path can be handed a ws:// target.

- *Disproof:* It IS protected when the handshake reaches wss:// and the transport negotiates TLS with a certificate the client validates; it is not protected when a wss:// literal is present but a proxy terminates or downgrades the upgrade, or when the code builds the URL from an attacker-controlled scheme value so the same code path can be handed a ws:// target.
- *Evidence:* high_confidence — [rfc-editor.org](https://www.rfc-editor.org/rfc/rfc6455.txt); [w3.org](https://www.w3.org/TR/websockets/)

**A WebSocket endpoint that only accepts a connection, echoes the caller's own frames back, and serves no other user's data is not cross-site WebSocket hijacking unless the handshake ALSO lacks Origin validation and the connection carries ambient credentials: hijack is the combination of cross-site connectability and session-authorised state.**

Two conditions, both required. Condition one is the handshake: ZAP's rule fires when the server accepts the Upgrade with a modified Origin, so an open handshake is only half the finding. Condition two is the state: Datadog's analysis of a real WebSocket authentication bypass shows why, because WebSocket connections are not restricted by the browser's same-origin policy, so cross-site reachability alone hands an attacker the socket and the damage comes entirely from what that socket can then read or mutate on the victim's behalf. On an echo endpoint both halves are empty: nothing is validated and nothing is exposed. Confirm by driving the channel with a second identity and asking whether any frame belonging to someone else ever arrives. Hunting value: this removes the echo, debug-console, presence and telemetry endpoints, which respond 101 to any Origin and are the bulk of cross-origin handshake alerts.

- *Disproof:* It IS CSWSH if Origin is unvalidated AND the connection carries a session cookie or bearer token that lets the attacker read or mutate state belonging to the victim: another user's message, a private channel, an account action. Prove impact with a second identity, not with the attacker's own frame.
- *Evidence:* high_confidence — [securitylabs.datadoghq.com](https://securitylabs.datadoghq.com/articles/claude-mcp-cve-2025-52882/); [zaproxy.org](https://www.zaproxy.org/docs/alerts/100025/)

**A WebSocket endpoint that completes the upgrade for an arbitrary Origin is not Cross-Site WebSocket Hijacking until the server acts on an attacker-reachable frame or event; establishing the connection alone proves only that the handshake does not check Origin.**

Separate the two halves. First, send the upgrade request with a foreign Origin and record whether it returns 101, which establishes the missing check and nothing more. Second, drive the full attack shape from a page on the attacker origin: open the socket, wait for the server to push, and attempt at least one state-changing send that the victim's session would authorize. The finding is proven when that action changes server state, because the browser attached the victim's cookie as ambient authority and the deputy acted on it. Okta's guidance that a token-issuing endpoint must be vigilant about confirming the caller's origin and keeping the allowlist strict shows what the defence looks like, and the same discipline applies to a socket whose frames mutate state.

- *Disproof:* The report is a false positive if the 101 is granted but every pushed frame and every send is refused without a credential the attacker lacks, or if the socket only ever emits public data. It is also a false positive if the state change required a second, attacker-independent authorization step that the attacker's frame could not satisfy.
- *Evidence:* high_confidence — [auth0.com](https://auth0.com/blog/confused-deputy-the-old-bug-that-ai-agents-keep-reintroducing/); [developer.okta.com](https://developer.okta.com/blog/2022/07/08/spa-web-security-csrf-xss)

## 4. Known bypasses

_Filters and controls that have defeated the techniques above. Treat these as the reason a naive test fails, not as proof of safety._

**Passing the session credential in the WebSocket URL query string bypasses every header-stripping and referrer-policy control, because URLs are recorded verbatim in proxy, server and browser history even where the same token would never be logged as a header.**

Connect to wss://host/ws?token=<captured access token>, then enumerate the places that copy the request line: the reverse proxy access log, the application log, browser history, and any monitoring or crash reporter that records URLs. Grep each for the token value. A single hit is the bypass, because a credential in a log is a credential a log reader can replay. Contrast it with the header case on the same target: a token sent in a header appears in no URL field, so the difference between the two placements is the finding, not the mere presence of a token.

- *Disproof:* The bypass is not demonstrated if the token never appears in any log, proxy record, history entry or telemetry field you can reach, or if the server rejects query-string credentials outright at the upgrade. It also does not apply where the credential is single-use, short-lived and audience-bound, because its theft then yields nothing beyond the attacker's own session.
- *Evidence:* high_confidence — [auth0.com](https://auth0.com/docs/secure/tokens/token-best-practices); [tailscale.com](https://tailscale.com/docs/features/tailscale-serve)

**A reverse proxy that routes HTTP endpoints through authentication can leave a WebSocket upgrade path outside that same authentication layer, so the bypass is demonstrated by finding an upgrade path the proxy forwards while the sibling HTTP route returns 401.**

Mechanism: A reverse proxy that routes HTTP endpoints through authentication can leave a WebSocket upgrade path outside that same authentication layer, so the bypass is demonstrated by finding an upgrade path the proxy forwards while the sibling HTTP route returns 401. How to apply it in the field: treat this as the bypass it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable. Boundary of the rule: It is not a bypass when the proxy applies the same authentication rule to the upgrade request as to normal routes, or when the application independently authenticates and authorises every message after the handshake rather than trusting the connection to be pre-authorised.

- *Disproof:* It is not a bypass when the proxy applies the same authentication rule to the upgrade request as to normal routes, or when the application independently authenticates and authorises every message after the handshake rather than trusting the connection to be pre-authorised.
- *Evidence:* high_confidence — [nginx.org](https://nginx.org/en/docs/http/ngx_http_proxy_module.html); [rfc-editor.org](https://www.rfc-editor.org/rfc/rfc6455.txt)

## Chaining

_No verified chain_link items yet._ Derived from evidence only, so this section is empty rather than plausible.


## Impact

_No verified impact items yet._ Derived from evidence only, so this section is empty rather than plausible.


## Coverage gap

These stages have no verified evidence and are therefore absent above: Preconditions, Reconnaissance signals, Chaining, Impact.
A procedure with a missing validation stage is not safe to act on — it produces findings rather than proofs.

---

*Generated from the evidence base. Where this file and the database disagree, the database is correct.*
