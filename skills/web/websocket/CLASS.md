<!-- GENERATED from db/wks.db — do not edit -->
# WebSocket Weaknesses

## Definition

The persistent channel inherits origin, authorisation and message-validation weaknesses of its upgrade request.

- **CWE:** 1004
- **OWASP:** A04:2021
- **Surface:** web
- **Aliases:** ["websockets", "ws", "cross site websocket hijacking"]

Canonical home for `websocket`. Rendered from `db/wks.db` by `tools/taxonomy/build_taxonomy.py` — edit the rows, not this file.

## Root Cause

Not yet researched.

## Preconditions

Not yet researched.

## Attack Surface

Surface: **web**.

The entry points and enabling conditions for this surface are enumerated under **Preconditions**; the observable signals are under **Detection**.

## Detection

**A WebSocket endpoint that returns no Access-Control-Allow-Origin header is not thereby safe, because the upgrade handshake is not subject to CORS: the cross-origin request is delivered and accepted regardless, so the absence of CORS headers is the expected baseline rather than evidence of a control.**

This is the most common false negative in WebSocket testing, and the vendor documentation states it plainly: CORS only applies to HTTP long-polling, WebSocket connections are not subject to CORS restrictions, and if you want to restrict who can actually reach your site you must use the application's own allowRequest option instead. So a hunter who checks for CORS headers, finds none, and concludes the endpoint is unreachable from a foreign page has inverted the logic - nothing was needed to make the request arrive, since the browser does not consult CORS on this path. The correct artefact is therefore the open connection itself, and the correct hunt is to look for whatever origin restriction the server actually implements, if any, and to test by connecting from a real foreign origin rather than from a script running on the same site.

*Disproof:* The claim that the handshake bypasses CORS does not establish a vulnerability, and must not be reported as one by itself: an endpoint that validates Origin inside its own handshake handler, or that requires a non-cookie credential, is protected by a control CORS would never have supplied. The claim is also inapplicable to a transport that is not a browser WebSocket upgrade - a native client, a server-to-server connection, or a managed gateway that terminates the socket and re-origin-checks upstream - and to polling transports, where CORS does apply and its absence may genuinely block the cross-origin read.

**The consequence of the hijack is proven when a frame the server pushes to the connection opened from the foreign origin contains data that page is not entitled to read - the victim's account state, another user's message, or an internal identifier - because that data left the server over a channel the attacker opened.**

A hijacked socket is often dismissed as low impact because the attacker page can only send what its own script sends; the record that establishes real severity is the reverse direction, the unsolicited server-to-client push. Once readyState reports OPEN, anything the server broadcasts arrives as message events with a data payload, so an attacker sitting on the foreign page receives the same pushes the victim would have received. The reportable artifact is that frame's content captured in the attacker's page, timestamped and tied to the connection, and the key question for the reviewer is whether the data would have been readable had the page been opened normally by the victim - if yes, this is the victim's data and the finding is disclosure, not merely a policy violation. Where the server pushes nothing until the attacker subscribes, that subscription frame is itself part of the evidence.

*Disproof:* The claim is false when the connection delivers only data the attacker's own session is entitled to - its own messages, its own account state - since identical bytes on both sides mean nothing crossed a boundary. It is also false where no server frame arrives at all and the channel permits only client-to-server writes, where the pushed data is a public or already-unauthenticated feed, and where the frame was fetched by an ordinary authenticated HTTP request from the same page rather than arriving over the socket. A frame observed without a corresponding accepted foreign-origin handshake is unattributable and cannot support the claim.

**Cross-site WebSocket hijacking is proven when a handshake sent from a page on a foreign origin is answered 101 Switching Protocols and the connection then delivers a server frame, because the artifact is an established bidirectional channel the attacker page opened, not a rejected upgrade.**

The decision happens entirely in the handshake, so the handshake transcript is the reportable artifact: capture the HTTP request the foreign page produced - including its Origin header - and the 101 response the server returned to it. A 101 is the whole finding, because from that point the socket is open and the server believes the connection belongs to whoever opened it. CWE-940 names the defect exactly: the product establishes a communication channel for an incoming request without properly verifying it is coming from the expected origin, and the consequence is that the attacker may gain privileges and reach functionality meant for the legitimate page's user. The report should also note whether any Origin check exists at all versus one that exists and is wrong, since the remediation differs; a socket that authenticates only by cookie with no origin comparison is the canonical case.

*Disproof:* The claim is false when the handshake is refused - a 403, a 401, or any status other than 101 - or when the connection is accepted but immediately closed before any frame is delivered, since no channel was established. It is also false where the WebSocket is authenticated by something the foreign page cannot supply, such as a bearer token in the URL query or a per-connection signature the attacker does not hold; a cookie-authenticated socket whose origin check passes because the attacker's page is same-origin is not cross-site and proves nothing. A 101 obtained from a raw client outside a browser is likewise not evidence, since it never demonstrated cross-origin reachability.

**A server that accepts the upgrade without an Origin header at all, or with one that is unvalidated, proves nothing about its intent but does prove the endpoint cannot be relying on the browser's origin model, because nothing in the accepted handshake ever established who asked.**

The point of the Origin header on an upgrade is that it is the only browser-supplied statement of who is asking, since the WebSocket API cannot attach custom headers or read the response as a CORS-checked fetch. When a 101 comes back for a request carrying no Origin, or one that the server accepts without comparing to anything, the transcript contains no evidence of a cross-origin decision at all, which means any origin restriction must be enforced elsewhere - by the credential itself or by an upstream proxy. A hunter records this as the primary artifact and it shapes the whole finding: an accepted handshake with Origin absent is a policy gap that a reviewer can re-check by replaying the same upgrade without the header, and it is strictly worse than an endpoint that at least compares Origin, because the latter fails closed on a missing header by design.

*Disproof:* The claim is false where the origin restriction is enforced by a different mechanism entirely - a per-connection token bound to the session, mutual TLS on the upgrade, or a gateway that terminates and re-checks - since the handshake need not carry Origin for the channel to be safe. It is also false for deployments where every legitimate client is non-browser and cannot send Origin, where requiring it would break the protocol without adding a control. An upgrade rejected specifically for a missing Origin is the opposite of the claim and is a working control.

## Exploitation

**Take into account that cookies will work just fine if the web app and the API are served from the same domain, so you might not need token based authentication.**

use scope=openid in token-based authentication to avoid having a huge token. You can control any standard OpenID Connect (OIDC) claims that you want to get in the token by adding them as scope values. For example, scope=openid name email family_name address phone_number . To learn more, see Standard Claims on openid.net . 
 You can mix token-based authentication with cookie-based authentication. Take into account that cookies will work just fine if the web app and the API are served from the same domain, so you might not need token based authentication. If you need to, we also return a JWT on the web app flow. Each of our SDKs will do it differently. If you want to call your APIs from JavaScript(instead of using the existing cookie), then you have to set the access tokens using Web Workers or JavaScript closures to handle token transmissions and storage. To learn more, read the Browser in-memory scenarios section of our Token Storage page. 
 ​ R

*Disproof:* Refuted when: the same behaviour is absent when the single named control in the claim is present, and the control is shown to be present rather than assumed. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“Take into account that cookies will work just fine if the web app and the API ar”) does not occur under a test that isolates that control.

**If you try to do a redirect with context.redirect , the authentication flow will return an error.**

To execute special logic, you can look at the context.protocol property in your rule. If the value is oauth2-refresh-token , then the rule is running during the exchange. 
 When trying to get a refresh token, the audience parameter is not available on the Rules context object. If you receive an error when attempting to add the audience parameter, verify that you do not have it set on the token. 
 If you try to do a redirect with context.redirect , the authentication flow will return an error. 
 If you have added custom claims to your tokens using a rule, the custom claims will appear in new tokens issued when using a refresh token for as long as your rule is in place. Although new tokens do not automatically inherit custom claims, rules run during the refresh token flow, so the same code will be executed. This allows you to add or change custom claims in newly-issued tokens without fo

*Disproof:* This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "If you try to do a redirect with context.redirect , the authentication flow will return an".

**Browser WebSocket behavior : Unlike traditional HTTP requests, WebSocket connections are not restricted by the browser's same-origin policy.**

encryption (SSE), for transport. The Claude Code extension also used a WebSocket, bound to localhost , for communication between the MCP server and the IDE. 
 The vulnerability stemmed from several architectural decisions in pre-patch versions: 
 
 Unauthenticated WebSocket server : The extension started a WebSocket server without implementing any form of client authentication or authorization. 
 Browser WebSocket behavior : Unlike traditional HTTP requests, WebSocket connections are not restricted by the browser's same-origin policy. 
 Binding to localhost : The server was bound to localhost , but this binding provided no protection against browser-initiated connections from malicious websites. 
 Dynamic port assignment : The use of dynamic ports provided minimal security through obscurity because port ranges could be systematically attacked with brute force. 
 
 The MCP server architecture was designed to enable seamless int

*Disproof:* Refuted when: the same behaviour is absent when the single named control in the claim is present, and the control is shown to be present rather than assumed. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“Browser WebSocket behavior : Unlike traditional HTTP requests, WebSocket connect”) does not occur under a test that isolates that control.

**Take into account that cookies will work just fine if the web app and the API are served from the same domain, so you might not need token based authentication.**

use scope=openid in token-based authentication to avoid having a huge token. You can control any standard OpenID Connect (OIDC) claims that you want to get in the token by adding them as scope values. For example, scope=openid name email family_name address phone_number . To learn more, see Standard Claims on openid.net . 
 You can mix token-based authentication with cookie-based authentication. Take into account that cookies will work just fine if the web app and the API are served from the same domain, so you might not need token based authentication. If you need to, we also return a JWT on the web app flow. Each of our SDKs will do it differently. If you want to call your APIs from JavaScript(instead of using the existing cookie), then you have to set the access tokens using Web Workers or JavaScript closures to handle token transmissions and storage. To learn more, read the Browser in-memory scenarios section of our Token Storage page. 
 ​ R

*Disproof:* Refuted when: the same behaviour is absent when the single named control in the claim is present, and the control is shown to be present rather than assumed. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“Take into account that cookies will work just fine if the web app and the API ar”) does not occur under a test that isolates that control.

**If you try to do a redirect with context.redirect , the authentication flow will return an error.**

To execute special logic, you can look at the context.protocol property in your rule. If the value is oauth2-refresh-token , then the rule is running during the exchange. 
 When trying to get a refresh token, the audience parameter is not available on the Rules context object. If you receive an error when attempting to add the audience parameter, verify that you do not have it set on the token. 
 If you try to do a redirect with context.redirect , the authentication flow will return an error. 
 If you have added custom claims to your tokens using a rule, the custom claims will appear in new tokens issued when using a refresh token for as long as your rule is in place. Although new tokens do not automatically inherit custom claims, rules run during the refresh token flow, so the same code will be executed. This allows you to add or change custom claims in newly-issued tokens without fo

*Disproof:* This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "If you try to do a redirect with context.redirect , the authentication flow will return an".

**For educational purposes, it's worth demonstrating an exploit proof of concept (PoC), if only to highlight the severity of this issue and the ease with which it could be exploited.**

t : The use of dynamic ports provided minimal security through obscurity because port ranges could be systematically attacked with brute force. 
 
 The MCP server architecture was designed to enable seamless integration between different Claude Code components. However, the architecture inadvertently created a significant attack surface that was eliminated in the patched version. 
 Exploitation 
 For educational purposes, it's worth demonstrating an exploit proof of concept (PoC), if only to highlight the severity of this issue and the ease with which it could be exploited. However, we will not publish the code. 
 How the exploit works 
 The exploitation process takes advantage of fundamental characteristics of the WebSocket protocol and browser behavior: 
 
 Initial access : An attacker lures a victim to a malicious website or compromises a legitimate site with malicious JavaScript code. 
 Port discovery : The malicious script systematically attempts WebSocket conn

*Disproof:* This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "For educational purposes, it's worth demonstrating an exploit proof of concept (PoC), if o".

**A WebSocket handshake that authenticates the connection through an ambient session cookie, but never compares the Origin request header against an allow-list, lets any malicious page open a real-time channel on behalf of an authenticated victim.**

Mechanism: the handshake is an ordinary HTTP upgrade request that still carries cookies, so the browser attaches the victim's session automatically. Because the connection is then established without an origin gate, the malicious page receives the same channel the victim's page would have. How to apply it: record the handshake transcript (request with victim-origin, Origin header, response 101) and replay the same upgrade from a foreign origin to confirm the server never compares Origin. Boundary: this is not exploitable when the credential is a bearer token in the URL query or a per-connection signature the attacker cannot forge, and it is not a CSRF-style vuln when the server enforces an origin allow-list at upgrade time.

*Disproof:* Refuted when a foreign-origin upgrade is answered 403 or 401, or when the handshake requires a per-connection secret the attacker's page cannot supply; also refuted when the endpoint independently re-authorizes every message after the handshake.

**A client that can read and modify outbound WebSocket frames - such as price, quantity, user id, or amount - can cause the server to execute privileged actions on attacker-controlled payload values that it would never accept from an HTTP request.**

Mechanism: the handshake may authenticate the connection, but the application may treat the connection as an extension of the HTTP session and trust the fields inside frames. If the field serializer permits replay or alteration, a low-privilege socket can upgrade the amount on a charge, or reassign an action to another user. How to apply it: open a socket, subscribe to a privileged topic, then send a frame with a tampered value and observe the server's response. Boundary: not exploitable when frames are MAC-protected or encrypted per-message so a reader cannot modify them in-flight, or when the receiving side verifies a signature on every payload before acting.

*Disproof:* Refuted when frames are MAC-protected or encrypted per-message so a reader cannot modify them in-flight, or when the receiving side verifies a signature on every payload before acting.

**Because the browser handshake cannot carry an Authorization header, a WebSocket endpoint is only authenticated if the credential arrives through the Sec-WebSocket-Protocol value or an explicit post-connect authentication frame; test each channel by omitting it and observing whether the connection still receives application data.**

Run three separate probes. Probe one: connect with no credential in the subprotocol and send nothing, noting whether the server emits any application payload or admits the socket. Probe two: pass a self-signed or wrong-signature token as Sec-WebSocket-Protocol and see whether it is accepted. Probe three: connect and send the auth frame used by Okta's socketio-jwt pattern, which validates a JWT after the socket opens, and observe both whether an invalid token is rejected and whether the server enforces a timeout on how long it waits for that frame. The documented shape is that the socket exists briefly before it is proven.

*Disproof:* The channel test fails if a connection with no credential still receives application data, or if an invalid or unsigned token is accepted. It also fails to implicate this endpoint if the deployment terminates authentication in a reverse proxy that injects an identity header rather than in the socket handler, in which case the trust boundary to test is the proxy, not the frame.

**A live socket.io endpoint can be version-fingerprinted from its handshake, so a hunter must compare the observed version against released advisories rather than assuming a framework version is safe.**

Mechanism: the socket.io handshake and transport negotiation reveal a version string. Fingerprinting the version lets a hunter check that release's known advisories (including ReDoS in websocket-extensions and DoS in the ws module) before assuming safety. How to apply it: send a polling handshake and record the version, then cross-reference the released advisory list for that release. Boundary: not reliable when a CDN or reverse proxy normalizes the version string, and the fingerprint is only as current as the advisory database used.

*Disproof:* Falsified if the handshake does not expose a version that can be matched, or if the deployed version corresponds to a patched release whose advisory has been updated to exclude the observed flaw.

## Variations

**When handshake or transport authentication is present but individual WebSocket frames carry no second authorization check, a connected client can submit privileged frames such as deleteUser or getSecretConfig that the server would reject if sent over HTTP.**

Mechanism: a low-privilege socket that passed the handshake can keep the channel open and send write frames the data model reserves for higher roles. The handshake auth is a one-time gate; without per-message auth the server trusts the connection as a proxy for the requester's identity. How to apply it: open a socket as a low-privilege account, then attempt privileged mutations and observe success. Boundary: not a bypass when every message is independently re-authorized against the session, and not exploitable when frames are signed or encrypted per-message so an observer cannot forge them.

*Disproof:* Refuted when every message is independently re-authorized against the session, or when the server rejects frames that request privileged actions without proof of entitlement.

**A reverse proxy that routes HTTP endpoints through authentication can leave a WebSocket upgrade path outside that same authentication layer, so the bypass is demonstrated by finding an upgrade path the proxy forwards while the sibling HTTP route returns 401.**

Mechanism: A reverse proxy that routes HTTP endpoints through authentication can leave a WebSocket upgrade path outside that same authentication layer, so the bypass is demonstrated by finding an upgrade path the proxy forwards while the sibling HTTP route returns 401. How to apply it in the field: treat this as the bypass it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable. Boundary of the rule: It is not a bypass when the proxy applies the same authentication rule to the upgrade request as to normal routes, or when the application independently authenticates and authorises every message after the handshake rather than trusting the connection to be pre-authorised.

*Disproof:* It is not a bypass when the proxy applies the same authentication rule to the upgrade request as to normal routes, or when the application independently authenticates and authorises every message after the handshake rather than trusting the connection to be pre-authorised.

**Passing the session credential in the WebSocket URL query string bypasses every header-stripping and referrer-policy control, because URLs are recorded verbatim in proxy, server and browser history even where the same token would never be logged as a header.**

Connect to wss://host/ws?token=<captured access token>, then enumerate the places that copy the request line: the reverse proxy access log, the application log, browser history, and any monitoring or crash reporter that records URLs. Grep each for the token value. A single hit is the bypass, because a credential in a log is a credential a log reader can replay. Contrast it with the header case on the same target: a token sent in a header appears in no URL field, so the difference between the two placements is the finding, not the mere presence of a token.

*Disproof:* The bypass is not demonstrated if the token never appears in any log, proxy record, history entry or telemetry field you can reach, or if the server rejects query-string credentials outright at the upgrade. It also does not apply where the credential is single-use, short-lived and audience-bound, because its theft then yields nothing beyond the attacker's own session.

**A reverse proxy that authenticates sibling HTTP routes can leave the WebSocket upgrade path unauthenticated, so an attacker reaches the authenticated WS endpoint by upgrading the request while the same endpoint returns 401 for normal HTTP.**

Mechanism: the proxy terminates TLS and forwards the upgrade to the backend. If the auth layer is attached only to the HTTP router, the Upgrade request never passes through it. The finding is demonstrated by sending a normal authenticated HTTP request (401) and a matching Upgrade request (101 or 200) from the same session. How to apply it: probe one endpoint with both methods and diff the status. Boundary: not a bypass when the proxy applies the identical authentication rule to upgrade requests as to normal routes, or when every message after the handshake is independently re-authorized regardless of the connection's pre-auth state.

*Disproof:* Refuted when the proxy applies the identical authentication rule to upgrade requests as to normal routes, or when every message after the handshake is independently re-authorized regardless of the connection's pre-auth state.

**A socket.io server that only validates the initial handshake but does not enforce per-namespace and per-room permission checks lets a low-privilege socket join a privileged namespace or another user's room.**

Mechanism: socket.io routes messages by namespace and room. If the authenticating middleware only runs at connection time, a socket that connects as a guest can still call server-side callbacks for a privileged namespace or subscribe to a room belonging to another user. How to apply it: enumerate namespaces, attempt to join each room, and send a privileged event as a low-privilege socket. Boundary: not exploitable when authorization is checked on every callback, when rooms are scoped to the session or project, and when namespace access is itself role-gated.

*Disproof:* Refuted when join and leave handlers enforce per-namespace/per-room permission checks, and when privileged namespaces require a role that the handshake does not grant.

## Technology / Framework Considerations

Not yet researched.

## API Considerations

Not yet researched.

## Attack Chains

- `chain.websocket.auto.01` — websocket: observe, exercise, confirm (goal: `Establish, exercise and confirm a websocket condition on an authorised target without relying on anyone else's data.`)

## Real-World Examples

Not yet researched.

## Common False Positives

**Receiving messages injected into a WebSocket channel by a malicious page is not XSS unless the handler reflects or evaluates the payload in an HTML context, so an attacker-controlled frame that is merely parsed as JSON is a data-integrity finding, not a script-execution one.**

Mechanism: Receiving messages injected into a WebSocket channel by a malicious page is not XSS unless the handler reflects or evaluates the payload in an HTML context, so an attacker-controlled frame that is merely parsed as JSON is a data-integrity finding, not a script-execution one. How to apply it in the field: treat this as the fp_rule it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable. Boundary of the rule: It IS XSS when the frame content is concatenated into a response body, written into innerHTML, or evaluated by the client; it is not when the payload stays inside JSON.parse or a typed schema field and no HTML sink receives it, in which case the correct class is injection into a data consumer rather than script execution.

*Disproof:* It IS XSS when the frame content is concatenated into a response body, written into innerHTML, or evaluated by the client; it is not when the payload stays inside JSON.parse or a typed schema field and no HTML sink receives it, in which case the correct class is injection into a data consumer rather than script execution.

**A WebSocket endpoint that only accepts a connection, echoes the caller's own frames back, and serves no other user's data is not cross-site WebSocket hijacking unless the handshake ALSO lacks Origin validation and the connection carries ambient credentials: hijack is the combination of cross-site connectability and session-authorised state.**

Two conditions, both required. Condition one is the handshake: ZAP's rule fires when the server accepts the Upgrade with a modified Origin, so an open handshake is only half the finding. Condition two is the state: Datadog's analysis of a real WebSocket authentication bypass shows why, because WebSocket connections are not restricted by the browser's same-origin policy, so cross-site reachability alone hands an attacker the socket and the damage comes entirely from what that socket can then read or mutate on the victim's behalf. On an echo endpoint both halves are empty: nothing is validated and nothing is exposed. Confirm by driving the channel with a second identity and asking whether any frame belonging to someone else ever arrives. Hunting value: this removes the echo, debug-console, presence and telemetry endpoints, which respond 101 to any Origin and are the bulk of cross-origin handshake alerts.

*Disproof:* It IS CSWSH if Origin is unvalidated AND the connection carries a session cookie or bearer token that lets the attacker read or mutate state belonging to the victim: another user's message, a private channel, an account action. Prove impact with a second identity, not with the attacker's own frame.

**A WebSocket endpoint that completes the upgrade for an arbitrary Origin is not Cross-Site WebSocket Hijacking until the server acts on an attacker-reachable frame or event; establishing the connection alone proves only that the handshake does not check Origin.**

Separate the two halves. First, send the upgrade request with a foreign Origin and record whether it returns 101, which establishes the missing check and nothing more. Second, drive the full attack shape from a page on the attacker origin: open the socket, wait for the server to push, and attempt at least one state-changing send that the victim's session would authorize. The finding is proven when that action changes server state, because the browser attached the victim's cookie as ambient authority and the deputy acted on it. Okta's guidance that a token-issuing endpoint must be vigilant about confirming the caller's origin and keeping the allowlist strict shows what the defence looks like, and the same discipline applies to a socket whose frames mutate state.

*Disproof:* The report is a false positive if the 101 is granted but every pushed frame and every send is refused without a credential the attacker lacks, or if the socket only ever emits public data. It is also a false positive if the state change required a second, attacker-independent authorization step that the attacker's frame could not satisfy.

**A WebSocket handshake is a normal HTTP upgrade request that still carries cookies, so SameSite only reduces cross-site reach for browsers that attach the cookie on this request; a server that never validates the Origin header at handshake time is exposed regardless of the SameSite attribute on its session cookie.**

Mechanism: A WebSocket handshake is a normal HTTP upgrade request that still carries cookies, so SameSite only reduces cross-site reach for browsers that attach the cookie on this request; a server that never validates the Origin header at handshake time is exposed regardless of the SameSite attribute on its session cookie. How to apply it in the field: treat this as the fp_rule it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable. Boundary of the rule: It is NOT exposed if the handshake is only reachable from a non-browser client that the attacker cannot author, or if the server enforces an origin allow-list at upgrade time; and the SameSite argument itself is falsified when the cookie is SameSite=None or when the vulnerable channel is used by a non-browser client whose cookie jar is not governed by SameSite at all.

*Disproof:* It is NOT exposed if the handshake is only reachable from a non-browser client that the attacker cannot author, or if the server enforces an origin allow-list at upgrade time; and the SameSite argument itself is falsified when the cookie is SameSite=None or when the vulnerable channel is used by a non-browser client whose cookie jar is not governed by SameSite at all.

**A page or config string containing wss:// is not by itself evidence that the WebSocket channel is protected, because confidentiality and integrity come from actually running the handshake over TLS end to end rather than from the scheme label appearing in source.**

Mechanism: A page or config string containing wss:// is not by itself evidence that the WebSocket channel is protected, because confidentiality and integrity come from actually running the handshake over TLS end to end rather than from the scheme label appearing in source. How to apply it in the field: treat this as the fp_rule it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable. Boundary of the rule: It IS protected when the handshake reaches wss:// and the transport negotiates TLS with a certificate the client validates; it is not protected when a wss:// literal is present but a proxy terminates or downgrades the upgrade, or when the code builds the URL from an attacker-controlled scheme value so the same code path can be handed a ws:// target.

*Disproof:* It IS protected when the handshake reaches wss:// and the transport negotiates TLS with a certificate the client validates; it is not protected when a wss:// literal is present but a proxy terminates or downgrades the upgrade, or when the code builds the URL from an attacker-controlled scheme value so the same code path can be handed a ws:// target.

## Validation

**A WebSocket that only pushes object identifiers has no data exposure to demonstrate, so a CSWSH or unauthenticated-socket report on such a channel is not substantiated until a test shows the frame itself carrying a field the reader could not otherwise obtain.**

Capture several frames from the socket while authenticated, then repeat from an unauthenticated or cross-origin context. Decode each frame and list the fields present. If the payload is only an id, the exposure is limited to revealing that something changed and the honest write-up is the identifier plus whatever an authenticated fetch of that id would still require. Okta's documented mitigation for exactly this problem is to change the endpoint so it only sends IDs so that no sensitive data is propagated, meaning a channel already shaped that way is behaving as designed. Escalate only once a frame contains a name, email, balance or any other field the reader was not entitled to.

*Disproof:* The report is substantiated and this item disproved the moment a captured frame contains a real field: a full record, a permission-bearing value, or an internal identifier that resolves to data with no further authorization check. Also disprove it if the socket genuinely required authentication before any frame was emitted, since then there is no unauthenticated read to demonstrate.

**The convincing evidence for cross-site WebSocket reach is a raw upgrade request carrying an attacker-controlled Origin that still completes with HTTP 101 and then exchanges frames with the victim's authenticated session, which proves the handshake has no origin gate.**

Mechanism: The convincing evidence for cross-site WebSocket reach is a raw upgrade request carrying an attacker-controlled Origin that still completes with HTTP 101 and then exchanges frames with the victim's authenticated session, which proves the handshake has no origin gate. How to apply it in the field: treat this as the validation it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable. Boundary of the rule: If the same request with a foreign Origin receives 403 or 401 the handshake is gated and the finding fails; a 101 alone is not enough if the follow-on frames are unauthenticated, since an anonymous channel proves missing origin control but not victim-session impact.

*Disproof:* If the same request with a foreign Origin receives 403 or 401 the handshake is gated and the finding fails; a 101 alone is not enough if the follow-on frames are unauthenticated, since an anonymous channel proves missing origin control but not victim-session impact.

**To decide this case, observe: How to apply it in the field: treat this as the fp_rule it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable.**

Derived from websocket.fp_rule.wss_scheme_alone_is_not_evidence_of_a_secure_channel, which states the false-positive boundary for this class. The observable above is what separates a real finding from the pattern that only looks like one. A hunter who cannot produce this observation in a request/response pair does not have a finding yet.

*Disproof:* This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (websocket.fp_rule.wss_scheme_alone_is_not_evidence_of_a_secure_channel) states the full boundary.

**To decide this case, observe: How to apply it in the field: treat this as the bypass it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable.**

Derived from websocket.bypass.proxy_reachable_websocket_endpoints_need_the_same_auth_as_http_routes, which states the false-positive boundary for this class. The observable above is what separates a real finding from the pattern that only looks like one. A hunter who cannot produce this observation in a request/response pair does not have a finding yet.

*Disproof:* This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (websocket.bypass.proxy_reachable_websocket_endpoints_need_the_same_auth_as_http_routes) states the full boundary.

**To decide this case, observe: How to apply it in the field: treat this as the fp_rule it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable.**

Derived from websocket.fp_rule.same_site_cookie_policy_does_not_apply_to_a_websocket_handshake, which states the false-positive boundary for this class. The observable above is what separates a real finding from the pattern that only looks like one. A hunter who cannot produce this observation in a request/response pair does not have a finding yet.

*Disproof:* This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (websocket.fp_rule.same_site_cookie_policy_does_not_apply_to_a_websocket_handshake) states the full boundary.

**To decide this case, observe: How to apply it in the field: treat this as the fp_rule it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable.**

Derived from websocket.fp_rule.a_101_switching_protocols_on_an_unauthenticated_channel_is_not_cross_site_scripting, which states the false-positive boundary for this class. The observable above is what separates a real finding from the pattern that only looks like one. A hunter who cannot produce this observation in a request/response pair does not have a finding yet.

*Disproof:* This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (websocket.fp_rule.a_101_switching_protocols_on_an_unauthenticated_channel_is_not_cross_site_scripting) states the full boundary.

**To decide this case, observe: How to apply it in the field: treat this as the validation it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable.**

Derived from websocket.validation.prove_cross_site_reach_with_a_foreign_origin_upgrade, which states the false-positive boundary for this class. The observable above is what separates a real finding from the pattern that only looks like one. A hunter who cannot produce this observation in a request/response pair does not have a finding yet.

*Disproof:* This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (websocket.validation.prove_cross_site_reach_with_a_foreign_origin_upgrade) states the full boundary.

## Impact

Not yet researched.

## Related Bug Classes

Not yet researched.

## References

- **auth0.com** (blog)
  - <https://auth0.com/blog/confused-deputy-the-old-bug-that-ai-agents-keep-reintroducing/>
  - <https://auth0.com/blog/cross-site-request-forgery-csrf/>
- **cwe.mitre.org** (writeup)
  - <https://cwe.mitre.org/data/definitions/940.html>
- **developer.mozilla.org** (writeup)
  - <https://developer.mozilla.org/en-US/docs/Web/API/MessageEvent>
  - <https://developer.mozilla.org/en-US/docs/Web/API/WebSocket>
  - <https://developer.mozilla.org/en-US/docs/Web/API/WebSocket/readyState>
- **developer.okta.com** (blog)
  - <https://developer.okta.com/blog/2018/09/25/spring-webflux-websockets-react>
  - <https://developer.okta.com/blog/2020/10/28/secure-web-apps-websockets-nodejs>
  - <https://developer.okta.com/blog/2022/07/08/spa-web-security-csrf-xss>
  - <https://developer.okta.com/docs/concepts/session/>
- **nginx.org** (docs)
  - <https://nginx.org/en/docs/http/ngx_http_proxy_module.html>
- **nvd.nist.gov** (reference)
  - <https://nvd.nist.gov/vuln/search/results?form_type=CMP&results_type=overview&query_text=CVE-2020-7662>
- **portswigger.net** (practitioner_guide)
  - <https://portswigger.net/web-security/cross-site-websocket-hijacking>
- **rfc-editor.org** (writeup)
  - <https://www.rfc-editor.org/rfc/rfc6455.txt>
  - <https://www.rfc-editor.org/rfc/rfc8441.html>
- **securitylabs.datadoghq.com** (writeup)
  - <https://securitylabs.datadoghq.com/articles/claude-mcp-cve-2025-52882/>
- **socket.io** (docs)
  - <https://socket.io/docs/v4/handling-cors/>
- **tailscale.com** (docs)
  - <https://tailscale.com/docs/features/tailscale-serve>
- **tomcat.apache.org** (writeup)
  - <https://tomcat.apache.org/tomcat-9.0-doc/web-socket-howto.html>
- **w3.org** (writeup)
  - <https://www.w3.org/TR/websockets/>
- **zaproxy.org** (docs)
  - <https://www.zaproxy.org/docs/alerts/100025/>

Every item above is gated on >= 2 distinct publisher hosts (`wks/quality.py`, rule R1). Publisher diversity, not citation count, is what makes these corroborated.
