# WebSocket Weaknesses

> surface: `web` · CWE: 1004 · OWASP: A04:2021
> maturity: **mature** — 26 items, 19 supported, 5 FP rules, 1 chains

The persistent channel inherits origin, authorisation and message-validation weaknesses of its upgrade request.

**Aliases:** websockets, ws, cross site websocket hijacking

## Technique

- **Because the browser handshake cannot carry an Authorization header, a WebSocket endpoint is only authenticated if the credential arrives through the Sec-WebSocket-Protocol value or an explicit post-connect authentication frame; test each channel by omitting it and observing whether the connection still receives application data.**  
  `high_confidence` · score 0.864 · disproved by: The channel test fails if a connection with no credential still receives application data, or if an invalid or unsigned token is accepted. It also fails to implicate this endpoint if the deployment terminates authentication in a reverse proxy that injects an identity header rather than in the socket handler, in which case the trust boundary to test is the proxy, not the frame.
  sources: <https://auth0.com/blog/cross-site-request-forgery-csrf/> · <https://developer.okta.com/blog/2020/10/28/secure-web-apps-websockets-nodejs>
- **Browser WebSocket behavior : Unlike traditional HTTP requests, WebSocket connections are not restricted by the browser's same-origin policy.**  
  `under_review` · score 0.7745 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Browser WebSocket behavior : Unlike traditional HTTP requests, WebSocket connections are n".
  sources: <https://securitylabs.datadoghq.com/articles/claude-mcp-cve-2025-52882/> · <https://www.rfc-editor.org/rfc/rfc6455.txt>
- **Take into account that cookies will work just fine if the web app and the API are served from the same domain, so you might not need token based authentication.**  
  `under_review` · score 0.747 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Take into account that cookies will work just fine if the web app and the API are served f".
  sources: <https://securitylabs.datadoghq.com/articles/claude-mcp-cve-2025-52882/> · <https://www.rfc-editor.org/rfc/rfc6455.txt>
- **Take into account that cookies will work just fine if the web app and the API are served from the same domain, so you might not need token based authentication.**  
  `under_review` · score 0.747 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Take into account that cookies will work just fine if the web app and the API are served f".
  sources: <https://securitylabs.datadoghq.com/articles/claude-mcp-cve-2025-52882/> · <https://www.rfc-editor.org/rfc/rfc6455.txt>
- **If you try to do a redirect with context.redirect , the authentication flow will return an error.**  
  `under_review` · score 0.708 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "If you try to do a redirect with context.redirect , the authentication flow will return an".
  sources: <https://securitylabs.datadoghq.com/articles/claude-mcp-cve-2025-52882/>
- **If you try to do a redirect with context.redirect , the authentication flow will return an error.**  
  `under_review` · score 0.708 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "If you try to do a redirect with context.redirect , the authentication flow will return an".
  sources: <https://securitylabs.datadoghq.com/articles/claude-mcp-cve-2025-52882/>
- **For educational purposes, it's worth demonstrating an exploit proof of concept (PoC), if only to highlight the severity of this issue and the ease with which it could be exploited.**  
  `under_review` · score 0.653 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "For educational purposes, it's worth demonstrating an exploit proof of concept (PoC), if o".
  sources: <https://securitylabs.datadoghq.com/articles/claude-mcp-cve-2025-52882/>

## Test

- **To decide this case, observe: How to apply it in the field: treat this as the bypass it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable.**  
  `high_confidence` · score 0.8655 · disproved by: This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (websocket.bypass.proxy_reachable_websocket_endpoints_need_the_same_auth_as_http_routes) states the full boundary.
  sources: <https://nginx.org/en/docs/http/ngx_http_proxy_module.html> · <https://www.rfc-editor.org/rfc/rfc6455.txt>
- **To decide this case, observe: How to apply it in the field: treat this as the fp_rule it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable.**  
  `high_confidence` · score 0.838 · disproved by: This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (websocket.fp_rule.wss_scheme_alone_is_not_evidence_of_a_secure_channel) states the full boundary.
  sources: <https://www.rfc-editor.org/rfc/rfc6455.txt> · <https://www.w3.org/TR/websockets/>
- **To decide this case, observe: How to apply it in the field: treat this as the fp_rule it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable.**  
  `high_confidence` · score 0.838 · disproved by: This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (websocket.fp_rule.same_site_cookie_policy_does_not_apply_to_a_websocket_handshake) states the full boundary.
  sources: <https://www.rfc-editor.org/rfc/rfc6455.txt> · <https://www.w3.org/TR/websockets/>
- **To decide this case, observe: How to apply it in the field: treat this as the fp_rule it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable.**  
  `high_confidence` · score 0.838 · disproved by: This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (websocket.fp_rule.a_101_switching_protocols_on_an_unauthenticated_channel_is_not_cross_site_scripting) states the full boundary.
  sources: <https://tomcat.apache.org/tomcat-9.0-doc/web-socket-howto.html> · <https://www.rfc-editor.org/rfc/rfc6455.txt>
- **To decide this case, observe: How to apply it in the field: treat this as the validation it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable.**  
  `high_confidence` · score 0.838 · disproved by: This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (websocket.validation.prove_cross_site_reach_with_a_foreign_origin_upgrade) states the full boundary.
  sources: <https://tomcat.apache.org/tomcat-9.0-doc/web-socket-howto.html> · <https://www.rfc-editor.org/rfc/rfc6455.txt>

## Validation

- **A WebSocket that only pushes object identifiers has no data exposure to demonstrate, so a CSWSH or unauthenticated-socket report on such a channel is not substantiated until a test shows the frame itself carrying a field the reader could not otherwise obtain.**  
  `high_confidence` · score 0.839 · disproved by: The report is substantiated and this item disproved the moment a captured frame contains a real field: a full record, a permission-bearing value, or an internal identifier that resolves to data with no further authorization check. Also disprove it if the socket genuinely required authentication before any frame was emitted, since then there is no unauthenticated read to demonstrate.
  sources: <https://tailscale.com/docs/features/tailscale-serve> · <https://developer.okta.com/blog/2018/09/25/spring-webflux-websockets-react>
- **The convincing evidence for cross-site WebSocket reach is a raw upgrade request carrying an attacker-controlled Origin that still completes with HTTP 101 and then exchanges frames with the victim's authenticated session, which proves the handshake has no origin gate.**  
  `high_confidence` · score 0.838 · disproved by: If the same request with a foreign Origin receives 403 or 401 the handshake is gated and the finding fails; a 101 alone is not enough if the follow-on frames are unauthenticated, since an anonymous channel proves missing origin control but not victim-session impact.
  sources: <https://tomcat.apache.org/tomcat-9.0-doc/web-socket-howto.html> · <https://www.rfc-editor.org/rfc/rfc6455.txt>

## Fp Rule

- **Receiving messages injected into a WebSocket channel by a malicious page is not XSS unless the handler reflects or evaluates the payload in an HTML context, so an attacker-controlled frame that is merely parsed as JSON is a data-integrity finding, not a script-execution one.**  
  `high_confidence` · score 0.8655 · disproved by: It IS XSS when the frame content is concatenated into a response body, written into innerHTML, or evaluated by the client; it is not when the payload stays inside JSON.parse or a typed schema field and no HTML sink receives it, in which case the correct class is injection into a data consumer rather than script execution.
  sources: <https://tomcat.apache.org/tomcat-9.0-doc/web-socket-howto.html> · <https://www.rfc-editor.org/rfc/rfc6455.txt>
- **A WebSocket handshake is a normal HTTP upgrade request that still carries cookies, so SameSite only reduces cross-site reach for browsers that attach the cookie on this request; a server that never validates the Origin header at handshake time is exposed regardless of the SameSite attribute on its session cookie.**  
  `high_confidence` · score 0.8655 · disproved by: It is NOT exposed if the handshake is only reachable from a non-browser client that the attacker cannot author, or if the server enforces an origin allow-list at upgrade time; and the SameSite argument itself is falsified when the cookie is SameSite=None or when the vulnerable channel is used by a non-browser client whose cookie jar is not governed by SameSite at all.
  sources: <https://www.rfc-editor.org/rfc/rfc6455.txt> · <https://www.w3.org/TR/websockets/>
- **A page or config string containing wss:// is not by itself evidence that the WebSocket channel is protected, because confidentiality and integrity come from actually running the handshake over TLS end to end rather than from the scheme label appearing in source.**  
  `high_confidence` · score 0.838 · disproved by: It IS protected when the handshake reaches wss:// and the transport negotiates TLS with a certificate the client validates; it is not protected when a wss:// literal is present but a proxy terminates or downgrades the upgrade, or when the code builds the URL from an attacker-controlled scheme value so the same code path can be handed a ws:// target.
  sources: <https://www.rfc-editor.org/rfc/rfc6455.txt> · <https://www.w3.org/TR/websockets/>
- **A WebSocket endpoint that only accepts a connection, echoes the caller's own frames back, and serves no other user's data is not cross-site WebSocket hijacking unless the handshake ALSO lacks Origin validation and the connection carries ambient credentials: hijack is the combination of cross-site connectability and session-authorised state.**  
  `high_confidence` · score 0.8355 · disproved by: It IS CSWSH if Origin is unvalidated AND the connection carries a session cookie or bearer token that lets the attacker read or mutate state belonging to the victim: another user's message, a private channel, an account action. Prove impact with a second identity, not with the attacker's own frame.
  sources: <https://www.zaproxy.org/docs/alerts/100025/> · <https://securitylabs.datadoghq.com/articles/claude-mcp-cve-2025-52882/>
- **A WebSocket endpoint that completes the upgrade for an arbitrary Origin is not Cross-Site WebSocket Hijacking until the server acts on an attacker-reachable frame or event; establishing the connection alone proves only that the handshake does not check Origin.**  
  `high_confidence` · score 0.809 · disproved by: The report is a false positive if the 101 is granted but every pushed frame and every send is refused without a credential the attacker lacks, or if the socket only ever emits public data. It is also a false positive if the state change required a second, attacker-independent authorization step that the attacker's frame could not satisfy.
  sources: <https://auth0.com/blog/confused-deputy-the-old-bug-that-ai-agents-keep-reintroducing/> · <https://developer.okta.com/blog/2022/07/08/spa-web-security-csrf-xss>

## Evidence

- **Cross-site WebSocket hijacking is proven when a handshake sent from a page on a foreign origin is answered 101 Switching Protocols and the connection then delivers a server frame, because the artifact is an established bidirectional channel the attacker page opened, not a rejected upgrade.**  
  `high_confidence` · score 0.909 · disproved by: The claim is false when the handshake is refused - a 403, a 401, or any status other than 101 - or when the connection is accepted but immediately closed before any frame is delivered, since no channel was established. It is also false where the WebSocket is authenticated by something the foreign page cannot supply, such as a bearer token in the URL query or a per-connection signature the attacker does not hold; a cookie-authenticated socket whose origin check passes because the attacker's page is same-origin is not cross-site and proves nothing. A 101 obtained from a raw client outside a browser is likewise not evidence, since it never demonstrated cross-origin reachability.
  sources: <https://cwe.mitre.org/data/definitions/940.html> · <https://developer.mozilla.org/en-US/docs/Web/API/WebSocket/readyState> · <https://www.rfc-editor.org/rfc/rfc8441.html>
- **A server that accepts the upgrade without an Origin header at all, or with one that is unvalidated, proves nothing about its intent but does prove the endpoint cannot be relying on the browser's origin model, because nothing in the accepted handshake ever established who asked.**  
  `high_confidence` · score 0.909 · disproved by: The claim is false where the origin restriction is enforced by a different mechanism entirely - a per-connection token bound to the session, mutual TLS on the upgrade, or a gateway that terminates and re-checks - since the handshake need not carry Origin for the channel to be safe. It is also false for deployments where every legitimate client is non-browser and cannot send Origin, where requiring it would break the protocol without adding a control. An upgrade rejected specifically for a missing Origin is the opposite of the claim and is a working control.
  sources: <https://developer.mozilla.org/en-US/docs/Web/API/WebSocket> · <https://socket.io/docs/v4/handling-cors/> · <https://www.rfc-editor.org/rfc/rfc8441.html>
- **A WebSocket endpoint that returns no Access-Control-Allow-Origin header is not thereby safe, because the upgrade handshake is not subject to CORS: the cross-origin request is delivered and accepted regardless, so the absence of CORS headers is the expected baseline rather than evidence of a control.**  
  `high_confidence` · score 0.893 · disproved by: The claim that the handshake bypasses CORS does not establish a vulnerability, and must not be reported as one by itself: an endpoint that validates Origin inside its own handshake handler, or that requires a non-cookie credential, is protected by a control CORS would never have supplied. The claim is also inapplicable to a transport that is not a browser WebSocket upgrade - a native client, a server-to-server connection, or a managed gateway that terminates the socket and re-origin-checks upstream - and to polling transports, where CORS does apply and its absence may genuinely block the cross-origin read.
  sources: <https://cwe.mitre.org/data/definitions/940.html> · <https://socket.io/docs/v4/handling-cors/>
- **The consequence of the hijack is proven when a frame the server pushes to the connection opened from the foreign origin contains data that page is not entitled to read - the victim's account state, another user's message, or an internal identifier - because that data left the server over a channel the attacker opened.**  
  `high_confidence` · score 0.8265 · disproved by: The claim is false when the connection delivers only data the attacker's own session is entitled to - its own messages, its own account state - since identical bytes on both sides mean nothing crossed a boundary. It is also false where no server frame arrives at all and the channel permits only client-to-server writes, where the pushed data is a public or already-unauthenticated feed, and where the frame was fetched by an ordinary authenticated HTTP request from the same page rather than arriving over the socket. A frame observed without a corresponding accepted foreign-origin handshake is unattributable and cannot support the claim.
  sources: <https://cwe.mitre.org/data/definitions/940.html> · <https://developer.mozilla.org/en-US/docs/Web/API/MessageEvent> · <https://developer.mozilla.org/en-US/docs/Web/API/WebSocket/readyState>

## Bypass

- **Passing the session credential in the WebSocket URL query string bypasses every header-stripping and referrer-policy control, because URLs are recorded verbatim in proxy, server and browser history even where the same token would never be logged as a header.**  
  `high_confidence` · score 0.9265 · disproved by: The bypass is not demonstrated if the token never appears in any log, proxy record, history entry or telemetry field you can reach, or if the server rejects query-string credentials outright at the upgrade. It also does not apply where the credential is single-use, short-lived and audience-bound, because its theft then yields nothing beyond the attacker's own session.
  sources: <https://tailscale.com/docs/features/tailscale-serve> · <https://securitylabs.datadoghq.com/articles/claude-mcp-cve-2025-52882/>
- **A reverse proxy that routes HTTP endpoints through authentication can leave a WebSocket upgrade path outside that same authentication layer, so the bypass is demonstrated by finding an upgrade path the proxy forwards while the sibling HTTP route returns 401.**  
  `high_confidence` · score 0.8655 · disproved by: It is not a bypass when the proxy applies the same authentication rule to the upgrade request as to normal routes, or when the application independently authenticates and authorises every message after the handshake rather than trusting the connection to be pre-authorised.
  sources: <https://securitylabs.datadoghq.com/articles/claude-mcp-cve-2025-52882/> · <https://www.rfc-editor.org/rfc/rfc6455.txt>

## Chain Link

- **A replayed session cookie becomes a live push channel the moment a socket upgrade accepts that cookie, so session-theft impact must be restated as continuous unauthorized data reception rather than only what the stolen session could fetch on demand.**  
  `under_review` · score 0.8825 · disproved by: The chain does not hold if the socket upgrade independently requires a fresh proof the stolen cookie does not supply, if the server binds the session to a device or connection attribute the attacker did not capture, or if the pushed stream carries no data the attacker was not already entitled to. Absent a standing channel, the impact stays at the level session theft alone justifies.
  sources: <https://developer.okta.com/docs/concepts/session/> · <https://auth0.com/blog/confused-deputy-the-old-bug-that-ai-agents-keep-reintroducing/> · <https://auth0.com/blog/cross-site-request-forgery-csrf/>
