# History

Append-only. Each entry records WHY the skill changed, not just that it did. Improvement means better hunting behaviour, not more text.

## 2026-10-02 15:57 — 1 diff lines
- items: 12 (supported 12), FP rules 2, chains 1, state mature

```diff
(initial generation, 2026-10-02)
```

## 2026-10-02 16:07 — 8 diff lines
- items: 12 (supported 12), FP rules 2, chains 1, state mature

```diff
--- websocket@current
+++ websocket@new
@@ -70,4 +70,4 @@
   - Sources: <https://developer.okta.com/docs/concepts/session/> · <https://auth0.com/blog/confused-deputy-the-old-bug-that-ai-agents-keep-reintroducing/> · <https://auth0.com/blog/cross-site-request-forgery-csrf/>
 
 ---
-Full class document: `domains/web/websocket/EVIDENCE.md` · retrieve more with `python -m wks.cli search "<query>" --class-id websocket`
+Full class document: `domains/web/websocket/knowledge/DIGEST.md` · retrieve more with `python -m wks.cli search "<query>" --class-id websocket`
```

## 2026-10-02 19:37 — 104 diff lines
- items: 22 (supported 14), FP rules 5, chains 1, state mature

```diff
--- websocket@current
+++ websocket@new
@@ -10,7 +10,7 @@
      python -m wks.skillgen -->
 
 > surface `web` · CWE 1004 · OWASP A04:2021
-> evidence: 12 items, 12 supported, 2 FP rules, 1 chains
+> evidence: 22 items, 14 supported, 5 FP rules, 1 chains
 > maturity: **mature**
 
 The persistent channel inherits origin, authorisation and message-validation weaknesses of its upgrade request.
@@ -20,52 +20,85 @@
 
 ## Techniques (what to change)
 
-- Take into account that cookies will work just fine if the web app and the API are served from the same domain, so you might not need token based authentication.
+- Take into account that cookies will work just fine if the web app and the API are served from the same domain, so you might not need token based authentication. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Take into account that cookies will work just fine if the web app and the API are served f".
   - Sources: <https://auth0.com/docs/secure/tokens/token-best-practices> · <https://securitylabs.datadoghq.com/articles/claude-mcp-cve-2025-52882/>
-- If you try to do a redirect with context.redirect , the authentication flow will return an error.
+- If you try to do a redirect with context.redirect , the authentication flow will return an error. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "If you try to do a redirect with context.redirect , the authentication flow will return an".
   - Sources: <https://auth0.com/docs/secure/tokens/token-best-practices> · <https://securitylabs.datadoghq.com/articles/claude-mcp-cve-2025-52882/>
-- Browser WebSocket behavior : Unlike traditional HTTP requests, WebSocket connections are not restricted by the browser's same-origin policy.
+- Browser WebSocket behavior : Unlike traditional HTTP requests, WebSocket connections are not restricted by the browser's same-origin policy. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Browser WebSocket behavior : Unlike traditional HTTP requests, WebSocket connections are n".
   - Sources: <https://auth0.com/docs/secure/tokens/token-best-practices> · <https://securitylabs.datadoghq.com/articles/claude-mcp-cve-2025-52882/>
-- Take into account that cookies will work just fine if the web app and the API are served from the same domain, so you might not need token based authentication.
+- Take into account that cookies will work just fine if the web app and the API are served from the same domain, so you might not need token based authentication. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Take into account that cookies will work just fine if the web app and the API are served f".
   - Sources: <https://auth0.com/docs/secure/tokens/token-best-practices> · <https://securitylabs.datadoghq.com/articles/claude-mcp-cve-2025-52882/>
-- If you try to do a redirect with context.redirect , the authentication flow will return an error.
+- If you try to do a redirect with context.redirect , the authentication flow will return an error. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "If you try to do a redirect with context.redirect , the authentication flow will return an".
   - Sources: <https://auth0.com/docs/secure/tokens/token-best-practices> · <https://securitylabs.datadoghq.com/articles/claude-mcp-cve-2025-52882/>
-- For educational purposes, it's worth demonstrating an exploit proof of concept (PoC), if only to highlight the severity of this issue and the ease with which it could be exploited.
+- For educational purposes, it's worth demonstrating an exploit proof of concept (PoC), if only to highlight the severity of this issue and the ease with which it could be exploited. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "For educational purposes, it's worth demonstrating an exploit proof of concept (PoC), if o".
   - Sources: <https://auth0.com/docs/secure/tokens/token-best-practices> · <https://securitylabs.datadoghq.com/articles/claude-mcp-cve-2025-52882/>
 - Because the browser handshake cannot carry an Authorization header, a WebSocket endpoint is only authenticated if the credential arrives through the Sec-WebSocket-Protocol value or an explicit post-connect authentication frame; test each channel by omitting it and observing whether the connection still receives application data.
   - **Disproof:** The channel test fails if a connection with no credential still receives application data, or if an invalid or unsigned token is accepted. It also fails to implicate this endpoint if the deployment terminates authentication in a reverse proxy that injects an identity header rather than in the socket handler, in which case the trust boundary to test is the proxy, not the frame.
   - Sources: <https://auth0.com/blog/cross-site-request-forgery-csrf/> · <https://developer.okta.com/blog/2020/10/28/secure-web-apps-websockets-nodejs>
 
+## Tests
+
+- To decide this case, observe: treat this as the fp_rule it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable. Boundary of the rule: It IS protected when the handshake reaches wss:// and the transport negotiates TLS with a certificate the client validates; it is not protected when a wss:// literal is prese
+  - **Disproof:** This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (websocket.fp_rule.wss_scheme_alone_is_not_evidence_of_a_secure_channel) states the full boundary.
+  - Sources: <https://www.rfc-editor.org/rfc/rfc6455.txt> · <https://www.w3.org/TR/websockets/>
+- To decide this case, observe: : treat this as the bypass it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable. Boundary of the rule: It is not a bypass when the proxy applies the same authentication rule to the upgrade request as to normal routes, or when the application independently authenticates and aut _(unverified)_
+  - **Disproof:** This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (websocket.bypass.proxy_reachable_websocket_endpoints_need_the_same_auth_as_http_routes) states the full boundary.
+  - Sources: <https://nginx.org/en/docs/http/ngx_http_proxy_module.html> · <https://www.rfc-editor.org/rfc/rfc6455.txt>
+- To decide this case, observe: treat this as the fp_rule it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable. Boundary of the rule: It is NOT exposed if the handshake is only reachable from a non-browser client that the attacker cannot author, or if the server enforces an origin allow-list at upgrade time
+  - **Disproof:** This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (websocket.fp_rule.same_site_cookie_policy_does_not_apply_to_a_websocket_handshake) states the full boundary.
+  - Sources: <https://www.rfc-editor.org/rfc/rfc6455.txt> · <https://www.w3.org/TR/websockets/>
+- To decide this case, observe: treat this as the fp_rule it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable. Boundary of the rule: It IS XSS when the frame content is concatenated into a response body, written into innerHTML, or evaluated by the client; it is not when the payload stays inside JSON.parse
+  - **Disproof:** This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (websocket.fp_rule.a_101_switching_protocols_on_an_unauthenticated_channel_is_not_cross_site_scripting) states the full boundary.
+  - Sources: <https://tomcat.apache.org/tomcat-9.0-doc/web-socket-howto.html> · <https://www.rfc-editor.org/rfc/rfc6455.txt>
+- To decide this case, observe: eat this as the validation it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable. Boundary of the rule: If the same request with a foreign Origin receives 403 or 401 the handshake is gated and the finding fails; a 101 alone is not enough if the follow-on frames are unauthentica
+  - **Disproof:** This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (websocket.validation.prove_cross_site_reach_with_a_foreign_origin_upgrade) states the full boundary.
+  - Sources: <https://tomcat.apache.org/tomcat-9.0-doc/web-socket-howto.html> · <https://www.rfc-editor.org/rfc/rfc6455.txt>
+
 ## Validation bar (how to prove it)
 
 - A WebSocket that only pushes object identifiers has no data exposure to demonstrate, so a CSWSH or unauthenticated-socket report on such a channel is not substantiated until a test shows the frame itself carrying a field the reader could not otherwise obtain.
   - **Disproof:** The report is substantiated and this item disproved the moment a captured frame contains a real field: a full record, a permission-bearing value, or an internal identifier that resolves to data with no further authorization check. Also disprove it if the socket genuinely required authentication before any frame was emitted, since then there is no unauthenticated read to demonstrate.
   - Sources: <https://tailscale.com/docs/features/tailscale-serve> · <https://developer.okta.com/blog/2018/09/25/spring-webflux-websockets-react>
+- The convincing evidence for cross-site WebSocket reach is a raw upgrade request carrying an attacker-controlled Origin that still completes with HTTP 101 and then exchanges frames with the victim's authenticated session, which proves the handshake has no origin gate.
+  - **Disproof:** If the same request with a foreign Origin receives 403 or 401 the handshake is gated and the finding fails; a 101 alone is not enough if the follow-on frames are unauthenticated, since an anonymous channel proves missing origin control but not victim-session impact.
+  - Sources: <https://tomcat.apache.org/tomcat-9.0-doc/web-socket-howto.html> · <https://www.rfc-editor.org/rfc/rfc6455.txt>
 
 ## False-positive rules (when to reject it)
 
+- Receiving messages injected into a WebSocket channel by a malicious page is not XSS unless the handler reflects or evaluates the payload in an HTML context, so an attacker-controlled frame that is merely parsed as JSON is a data-integrity finding, not a script-execution one.
+  - **Disproof:** It IS XSS when the frame content is concatenated into a response body, written into innerHTML, or evaluated by the client; it is not when the payload stays inside JSON.parse or a typed schema field and no HTML sink receives it, in which case the correct class is injection into a data consumer rather than script execution.
+  - Sources: <https://tomcat.apache.org/tomcat-9.0-doc/web-socket-howto.html> · <https://www.rfc-editor.org/rfc/rfc6455.txt>
 - A WebSocket endpoint that only accepts a connection, echoes the caller's own frames back, and serves no other user's data is not cross-site WebSocket hijacking unless the handshake ALSO lacks Origin validation and the connection carries ambient credentials: hijack is the combination of cross-site connectability and session-authorised state.
   - **Disproof:** It IS CSWSH if Origin is unvalidated AND the connection carries a session cookie or bearer token that lets the attacker read or mutate state belonging to the victim: another user's message, a private channel, an account action. Prove impact with a second identity, not with the attacker's own frame.
   - Sources: <https://www.zaproxy.org/docs/alerts/100025/> · <https://securitylabs.datadoghq.com/articles/claude-mcp-cve-2025-52882/>
 - A WebSocket endpoint that completes the upgrade for an arbitrary Origin is not Cross-Site WebSocket Hijacking until the server acts on an attacker-reachable frame or event; establishing the connection alone proves only that the handshake does not check Origin.
   - **Disproof:** The report is a false positive if the 101 is granted but every pushed frame and every send is refused without a credential the attacker lacks, or if the socket only ever emits public data. It is also a false positive if the state change required a second, attacker-independent authorization step that the attacker's frame could not satisfy.
   - Sources: <https://auth0.com/blog/confused-deputy-the-old-bug-that-ai-agents-keep-reintroducing/> · <https://developer.okta.com/blog/2022/07/08/spa-web-security-csrf-xss>
+- A WebSocket handshake is a normal HTTP upgrade request that still carries cookies, so SameSite only reduces cross-site reach for browsers that attach the cookie on this request; a server that never validates the Origin header at handshake time is exposed regardless of the SameSite attribute on its session cookie.
+  - **Disproof:** It is NOT exposed if the handshake is only reachable from a non-browser client that the attacker cannot author, or if the server enforces an origin allow-list at upgrade time; and the SameSite argument itself is falsified when the cookie is SameSite=None or when the vulnerable channel is used by a non-browser client whose cookie jar is not governed by SameSite at all.
+  - Sources: <https://www.rfc-editor.org/rfc/rfc6455.txt> · <https://www.w3.org/TR/websockets/>
+- A page or config string containing wss:// is not by itself evidence that the WebSocket channel is protected, because confidentiality and integrity come from actually running the handshake over TLS end to end rather than from the scheme label appearing in source.
+  - **Disproof:** It IS protected when the handshake reaches wss:// and the transport negotiates TLS with a certificate the client validates; it is not protected when a wss:// literal is present but a proxy terminates or downgrades the upgrade, or when the code builds the URL from an attacker-controlled scheme value so the same code path can be handed a ws:// target.
+  - Sources: <https://www.rfc-editor.org/rfc/rfc6455.txt> · <https://www.w3.org/TR/websockets/>
 
 ## Defence bypasses
 
+- A reverse proxy that routes HTTP endpoints through authentication can leave a WebSocket upgrade path outside that same authentication layer, so the bypass is demonstrated by finding an upgrade path the proxy forwards while the sibling HTTP route returns 401.
+  - **Disproof:** It is not a bypass when the proxy applies the same authentication rule to the upgrade request as to normal routes, or when the application independently authenticates and authorises every message after the handshake rather than trusting the connection to be pre-authorised.
+  - Sources: <https://nginx.org/en/docs/http/ngx_http_proxy_module.html> · <https://www.rfc-editor.org/rfc/rfc6455.txt>
 - Passing the session credential in the WebSocket URL query string bypasses every header-stripping and referrer-policy control, because URLs are recorded verbatim in proxy, server and browser history even where the same token would never be logged as a header.
   - **Disproof:** The bypass is not demonstrated if the token never appears in any log, proxy record, history entry or telemetry field you can reach, or if the server rejects query-string credentials outright at the upgrade. It also does not apply where the credential is single-use, short-lived and audience-bound, because its theft then yields nothing beyond the attacker's own session.
   - Sources: <https://auth0.com/docs/secure/tokens/token-best-practices> · <https://tailscale.com/docs/features/tailscale-serve>
 
 ## Chaining opportunities
 
-- A replayed session cookie becomes a live push channel the moment a socket upgrade accepts that cookie, so session-theft impact must be restated as continuous unauthorized data reception rather than only what the stolen session could fetch on demand.
+- A replayed session cookie becomes a live push channel the moment a socket upgrade accepts that cookie, so session-theft impact must be restated as continuous unauthorized data reception rather than only what the stolen session could fetch on demand. _(unverified)_
   - **Disproof:** The chain does not hold if the socket upgrade independently requires a fresh proof the stolen cookie does not supply, if the server binds the session to a device or connection attribute the attacker did not capture, or if the pushed stream carries no data the attacker was not already entitled to. Absent a standing channel, the impact stays at the level session theft alone justifies.
   - Sources: <https://developer.okta.com/docs/concepts/session/> · <https://auth0.com/blog/confused-deputy-the-old-bug-that-ai-agents-keep-reintroducing/> · <https://auth0.com/blog/cross-site-request-forgery-csrf/>
 
```

## 2026-10-03 01:46 — 97 diff lines
- items: 26 (supported 18), FP rules 5, chains 1, state mature

```diff
--- websocket@current
+++ websocket@new
@@ -10,7 +10,7 @@
      python -m wks.skillgen -->
 
 > surface `web` · CWE 1004 · OWASP A04:2021
-> evidence: 22 items, 14 supported, 5 FP rules, 1 chains
+> evidence: 26 items, 18 supported, 5 FP rules, 1 chains
 > maturity: **mature**
 
 The persistent channel inherits origin, authorisation and message-validation weaknesses of its upgrade request.
@@ -22,41 +22,41 @@
 
 - Take into account that cookies will work just fine if the web app and the API are served from the same domain, so you might not need token based authentication. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Take into account that cookies will work just fine if the web app and the API are served f".
-  - Sources: <https://auth0.com/docs/secure/tokens/token-best-practices> · <https://securitylabs.datadoghq.com/articles/claude-mcp-cve-2025-52882/>
+  - Sources: <https://securitylabs.datadoghq.com/articles/claude-mcp-cve-2025-52882/> · <https://www.rfc-editor.org/rfc/rfc6455.txt>
 - If you try to do a redirect with context.redirect , the authentication flow will return an error. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "If you try to do a redirect with context.redirect , the authentication flow will return an".
-  - Sources: <https://auth0.com/docs/secure/tokens/token-best-practices> · <https://securitylabs.datadoghq.com/articles/claude-mcp-cve-2025-52882/>
+  - Sources: <https://securitylabs.datadoghq.com/articles/claude-mcp-cve-2025-52882/>
 - Browser WebSocket behavior : Unlike traditional HTTP requests, WebSocket connections are not restricted by the browser's same-origin policy. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Browser WebSocket behavior : Unlike traditional HTTP requests, WebSocket connections are n".
-  - Sources: <https://auth0.com/docs/secure/tokens/token-best-practices> · <https://securitylabs.datadoghq.com/articles/claude-mcp-cve-2025-52882/>
+  - Sources: <https://securitylabs.datadoghq.com/articles/claude-mcp-cve-2025-52882/> · <https://www.rfc-editor.org/rfc/rfc6455.txt>
 - Take into account that cookies will work just fine if the web app and the API are served from the same domain, so you might not need token based authentication. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Take into account that cookies will work just fine if the web app and the API are served f".
-  - Sources: <https://auth0.com/docs/secure/tokens/token-best-practices> · <https://securitylabs.datadoghq.com/articles/claude-mcp-cve-2025-52882/>
+  - Sources: <https://securitylabs.datadoghq.com/articles/claude-mcp-cve-2025-52882/> · <https://www.rfc-editor.org/rfc/rfc6455.txt>
 - If you try to do a redirect with context.redirect , the authentication flow will return an error. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "If you try to do a redirect with context.redirect , the authentication flow will return an".
-  - Sources: <https://auth0.com/docs/secure/tokens/token-best-practices> · <https://securitylabs.datadoghq.com/articles/claude-mcp-cve-2025-52882/>
+  - Sources: <https://securitylabs.datadoghq.com/articles/claude-mcp-cve-2025-52882/>
 - For educational purposes, it's worth demonstrating an exploit proof of concept (PoC), if only to highlight the severity of this issue and the ease with which it could be exploited. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "For educational purposes, it's worth demonstrating an exploit proof of concept (PoC), if o".
-  - Sources: <https://auth0.com/docs/secure/tokens/token-best-practices> · <https://securitylabs.datadoghq.com/articles/claude-mcp-cve-2025-52882/>
+  - Sources: <https://securitylabs.datadoghq.com/articles/claude-mcp-cve-2025-52882/>
 - Because the browser handshake cannot carry an Authorization header, a WebSocket endpoint is only authenticated if the credential arrives through the Sec-WebSocket-Protocol value or an explicit post-connect authentication frame; test each channel by omitting it and observing whether the connection still receives application data.
   - **Disproof:** The channel test fails if a connection with no credential still receives application data, or if an invalid or unsigned token is accepted. It also fails to implicate this endpoint if the deployment terminates authentication in a reverse proxy that injects an identity header rather than in the socket handler, in which case the trust boundary to test is the proxy, not the frame.
   - Sources: <https://auth0.com/blog/cross-site-request-forgery-csrf/> · <https://developer.okta.com/blog/2020/10/28/secure-web-apps-websockets-nodejs>
 
 ## Tests
 
-- To decide this case, observe: treat this as the fp_rule it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable. Boundary of the rule: It IS protected when the handshake reaches wss:// and the transport negotiates TLS with a certificate the client validates; it is not protected when a wss:// literal is prese
+- To decide this case, observe: How to apply it in the field: treat this as the fp_rule it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable.
   - **Disproof:** This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (websocket.fp_rule.wss_scheme_alone_is_not_evidence_of_a_secure_channel) states the full boundary.
   - Sources: <https://www.rfc-editor.org/rfc/rfc6455.txt> · <https://www.w3.org/TR/websockets/>
-- To decide this case, observe: : treat this as the bypass it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable. Boundary of the rule: It is not a bypass when the proxy applies the same authentication rule to the upgrade request as to normal routes, or when the application independently authenticates and aut _(unverified)_
+- To decide this case, observe: How to apply it in the field: treat this as the bypass it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable. _(unverified)_
   - **Disproof:** This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (websocket.bypass.proxy_reachable_websocket_endpoints_need_the_same_auth_as_http_routes) states the full boundary.
-  - Sources: <https://nginx.org/en/docs/http/ngx_http_proxy_module.html> · <https://www.rfc-editor.org/rfc/rfc6455.txt>
-- To decide this case, observe: treat this as the fp_rule it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable. Boundary of the rule: It is NOT exposed if the handshake is only reachable from a non-browser client that the attacker cannot author, or if the server enforces an origin allow-list at upgrade time
+  - Sources: <https://www.rfc-editor.org/rfc/rfc6455.txt>
+- To decide this case, observe: How to apply it in the field: treat this as the fp_rule it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable.
   - **Disproof:** This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (websocket.fp_rule.same_site_cookie_policy_does_not_apply_to_a_websocket_handshake) states the full boundary.
   - Sources: <https://www.rfc-editor.org/rfc/rfc6455.txt> · <https://www.w3.org/TR/websockets/>
-- To decide this case, observe: treat this as the fp_rule it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable. Boundary of the rule: It IS XSS when the frame content is concatenated into a response body, written into innerHTML, or evaluated by the client; it is not when the payload stays inside JSON.parse
+- To decide this case, observe: How to apply it in the field: treat this as the fp_rule it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable.
   - **Disproof:** This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (websocket.fp_rule.a_101_switching_protocols_on_an_unauthenticated_channel_is_not_cross_site_scripting) states the full boundary.
   - Sources: <https://tomcat.apache.org/tomcat-9.0-doc/web-socket-howto.html> · <https://www.rfc-editor.org/rfc/rfc6455.txt>
-- To decide this case, observe: eat this as the validation it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable. Boundary of the rule: If the same request with a foreign Origin receives 403 or 401 the handshake is gated and the finding fails; a 101 alone is not enough if the follow-on frames are unauthentica
+- To decide this case, observe: How to apply it in the field: treat this as the validation it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable.
   - **Disproof:** This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (websocket.validation.prove_cross_site_reach_with_a_foreign_origin_upgrade) states the full boundary.
   - Sources: <https://tomcat.apache.org/tomcat-9.0-doc/web-socket-howto.html> · <https://www.rfc-editor.org/rfc/rfc6455.txt>
 
@@ -87,14 +87,29 @@
   - **Disproof:** It IS protected when the handshake reaches wss:// and the transport negotiates TLS with a certificate the client validates; it is not protected when a wss:// literal is present but a proxy terminates or downgrades the upgrade, or when the code builds the URL from an attacker-controlled scheme value so the same code path can be handed a ws:// target.
   - Sources: <https://www.rfc-editor.org/rfc/rfc6455.txt> · <https://www.w3.org/TR/websockets/>
 
+## Evidence requirements
+
+- A WebSocket endpoint that returns no Access-Control-Allow-Origin header is not thereby safe, because the upgrade handshake is not subject to CORS: the cross-origin request is delivered and accepted regardless, so the absence of CORS headers is the expected baseline rather than evidence of a control.
+  - **Disproof:** The claim that the handshake bypasses CORS does not establish a vulnerability, and must not be reported as one by itself: an endpoint that validates Origin inside its own handshake handler, or that requires a non-cookie credential, is protected by a control CORS would never have supplied. The claim is also inapplicable to a transport that is not a browser WebSocket upgrade - a native client, a server-to-server connection, or a managed gateway that terminates the socket and re-origin-checks upstream - and to polling transports, where CORS does apply and its absence may genuinely block the cross-origin read.
+  - Sources: <https://cwe.mitre.org/data/definitions/940.html> · <https://socket.io/docs/v4/handling-cors/>
+- The consequence of the hijack is proven when a frame the server pushes to the connection opened from the foreign origin contains data that page is not entitled to read - the victim's account state, another user's message, or an internal identifier - because that data left the server over a channel the attacker opened.
+  - **Disproof:** The claim is false when the connection delivers only data the attacker's own session is entitled to - its own messages, its own account state - since identical bytes on both sides mean nothing crossed a boundary. It is also false where no server frame arrives at all and the channel permits only client-to-server writes, where the pushed data is a public or already-unauthenticated feed, and where the frame was fetched by an ordinary authenticated HTTP request from the same page rather than arriving over the socket. A frame observed without a corresponding accepted foreign-origin handshake is unattributable and cannot support the claim.
+  - Sources: <https://cwe.mitre.org/data/definitions/940.html> · <https://developer.mozilla.org/en-US/docs/Web/API/MessageEvent> · <https://developer.mozilla.org/en-US/docs/Web/API/WebSocket/readyState>
+- Cross-site WebSocket hijacking is proven when a handshake sent from a page on a foreign origin is answered 101 Switching Protocols and the connection then delivers a server frame, because the artifact is an established bidirectional channel the attacker page opened, not a rejected upgrade.
+  - **Disproof:** The claim is false when the handshake is refused - a 403, a 401, or any status other than 101 - or when the connection is accepted but immediately closed before any frame is delivered, since no channel was established. It is also false where the WebSocket is authenticated by something the foreign page cannot supply, such as a bearer token in the URL query or a per-connection signature the attacker does not hold; a cookie-authenticated socket whose origin check passes because the attacker's page is same-origin is not cross-site and proves nothing. A 101 obtained from a raw client outside a browser is likewise not evidence, since it never demonstrated cross-origin reachability.
+  - Sources: <https://cwe.mitre.org/data/definitions/940.html> · <https://developer.mozilla.org/en-US/docs/Web/API/WebSocket/readyState> · <https://www.rfc-editor.org/rfc/rfc8441.html>
+- A server that accepts the upgrade without an Origin header at all, or with one that is unvalidated, proves nothing about its intent but does prove the endpoint cannot be relying on the browser's origin model, because nothing in the accepted handshake ever established who asked.
+  - **Disproof:** The claim is false where the origin restriction is enforced by a different mechanism entirely - a per-connection token bound to the session, mutual TLS on the upgrade, or a gateway that terminates and re-checks - since the handshake need not carry Origin for the channel to be safe. It is also false for deployments where every legitimate client is non-browser and cannot send Origin, where requiring it would break the protocol without adding a control. An upgrade rejected specifically for a missing Origin is the opposite of the claim and is a working control.
+  - Sources: <https://developer.mozilla.org/en-US/docs/Web/API/WebSocket> · <https://socket.io/docs/v4/handling-cors/> · <https://www.rfc-editor.org/rfc/rfc8441.html>
+
 ## Defence bypasses
 
 - A reverse proxy that routes HTTP endpoints through authentication can leave a WebSocket upgrade path outside that same authentication layer, so the bypass is demonstrated by finding an upgrade path the proxy forwards while the sibling HTTP route returns 401.
   - **Disproof:** It is not a bypass when the proxy applies the same authentication rule to the upgrade request as to normal routes, or when the application independently authenticates and authorises every message after the handshake rather than trusting the connection to be pre-authorised.
-  - Sources: <https://nginx.org/en/docs/http/ngx_http_proxy_module.html> · <https://www.rfc-editor.org/rfc/rfc6455.txt>
+  - Sources: <https://securitylabs.datadoghq.com/articles/claude-mcp-cve-2025-52882/> · <https://www.rfc-editor.org/rfc/rfc6455.txt>
 - Passing the session credential in the WebSocket URL query string bypasses every header-stripping and referrer-policy control, because URLs are recorded verbatim in proxy, server and browser history even where the same token would never be logged as a header.
   - **Disproof:** The bypass is not demonstrated if the token never appears in any log, proxy record, history entry or telemetry field you can reach, or if the server rejects query-string credentials outright at the upgrade. It also does not apply where the credential is single-use, short-lived and audience-bound, because its theft then yields nothing beyond the attacker's own session.
-  - Sources: <https://auth0.com/docs/secure/tokens/token-best-practices> · <https://tailscale.com/docs/features/tailscale-serve>
+  - Sources: <https://tailscale.com/docs/features/tailscale-serve> · <https://securitylabs.datadoghq.com/articles/claude-mcp-cve-2025-52882/>
 
 ## Chaining opportunities
 
```

## 2026-10-04 00:43 — 163 diff lines
- items: 26 (supported 18), FP rules 5, chains 1, state mature

```diff
--- websocket@current
+++ websocket@new
@@ -20,102 +20,105 @@
 
 ## Techniques (what to change)
 
-- Take into account that cookies will work just fine if the web app and the API are served from the same domain, so you might not need token based authentication. _(unverified)_
+- Because the browser handshake cannot carry an Authorization header, a WebSocket endpoint is only authenticated if the credential arrives through the Sec-WebSocket-Protocol value or an explicit post-connect authentication frame; test each channel by omitting it and observing whether the connection still receives application data.  _(merged 1 duplicate row(s))_
+  - **Disproof:** The channel test fails if a connection with no credential still receives application data, or if an invalid or unsigned token is accepted. It also fails to implicate this endpoint if the deployment terminates authentication in a reverse proxy that injects an identity header rather than in the socket handler, in which case the trust boundary to test is the proxy, not the frame.
+  - Sources: <https://auth0.com/blog/cross-site-request-forgery-csrf/> · <https://developer.okta.com/blog/2020/10/28/secure-web-apps-websockets-nodejs>
+- Browser WebSocket behavior : Unlike traditional HTTP requests, WebSocket connections are not restricted by the browser's same-origin policy.  _(merged 1 duplicate row(s))_ _(unverified)_
+  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Browser WebSocket behavior : Unlike traditional HTTP requests, WebSocket connections are n".
+  - Sources: <https://securitylabs.datadoghq.com/articles/claude-mcp-cve-2025-52882/> · <https://www.rfc-editor.org/rfc/rfc6455.txt>
+- For educational purposes, it's worth demonstrating an exploit proof of concept (PoC), if only to highlight the severity of this issue and the ease with which it could be exploited.  _(merged 1 duplicate row(s))_ _(unverified)_
+  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "For educational purposes, it's worth demonstrating an exploit proof of concept (PoC), if o".
+  - Sources: <https://securitylabs.datadoghq.com/articles/claude-mcp-cve-2025-52882/>
+- If you try to do a redirect with context.redirect , the authentication flow will return an error.  _(merged 2 duplicate row(s))_ _(unverified)_
+  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "If you try to do a redirect with context.redirect , the authentication flow will return an".
+  - Sources: <https://securitylabs.datadoghq.com/articles/claude-mcp-cve-2025-52882/>
+- Take into account that cookies will work just fine if the web app and the API are served from the same domain, so you might not need token based authentication.  _(merged 2 duplicate row(s))_ _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Take into account that cookies will work just fine if the web app and the API are served f".
   - Sources: <https://securitylabs.datadoghq.com/articles/claude-mcp-cve-2025-52882/> · <https://www.rfc-editor.org/rfc/rfc6455.txt>
-- If you try to do a redirect with context.redirect , the authentication flow will return an error. _(unverified)_
-  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "If you try to do a redirect with context.redirect , the authentication flow will return an".
-  - Sources: <https://securitylabs.datadoghq.com/articles/claude-mcp-cve-2025-52882/>
-- Browser WebSocket behavior : Unlike traditional HTTP requests, WebSocket connections are not restricted by the browser's same-origin policy. _(unverified)_
-  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Browser WebSocket behavior : Unlike traditional HTTP requests, WebSocket connections are n".
-  - Sources: <https://securitylabs.datadoghq.com/articles/claude-mcp-cve-2025-52882/> · <https://www.rfc-editor.org/rfc/rfc6455.txt>
-- Take into account that cookies will work just fine if the web app and the API are served from the same domain, so you might not need token based authentication. _(unverified)_
-  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Take into account that cookies will work just fine if the web app and the API are served f".
-  - Sources: <https://securitylabs.datadoghq.com/articles/claude-mcp-cve-2025-52882/> · <https://www.rfc-editor.org/rfc/rfc6455.txt>
-- If you try to do a redirect with context.redirect , the authentication flow will return an error. _(unverified)_
-  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "If you try to do a redirect with context.redirect , the authentication flow will return an".
-  - Sources: <https://securitylabs.datadoghq.com/articles/claude-mcp-cve-2025-52882/>
-- For educational purposes, it's worth demonstrating an exploit proof of concept (PoC), if only to highlight the severity of this issue and the ease with which it could be exploited. _(unverified)_
-  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "For educational purposes, it's worth demonstrating an exploit proof of concept (PoC), if o".
-  - Sources: <https://securitylabs.datadoghq.com/articles/claude-mcp-cve-2025-52882/>
-- Because the browser handshake cannot carry an Authorization header, a WebSocket endpoint is only authenticated if the credential arrives through the Sec-WebSocket-Protocol value or an explicit post-connect authentication frame; test each channel by omitting it and observing whether the connection still receives application data.
-  - **Disproof:** The channel test fails if a connection with no credential still receives application data, or if an invalid or unsigned token is accepted. It also fails to implicate this endpoint if the deployment terminates authentication in a reverse proxy that injects an identity header rather than in the socket handler, in which case the trust boundary to test is the proxy, not the frame.
-  - Sources: <https://auth0.com/blog/cross-site-request-forgery-csrf/> · <https://developer.okta.com/blog/2020/10/28/secure-web-apps-websockets-nodejs>
 
 ## Tests
 
-- To decide this case, observe: How to apply it in the field: treat this as the fp_rule it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable.
-  - **Disproof:** This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (websocket.fp_rule.wss_scheme_alone_is_not_evidence_of_a_secure_channel) states the full boundary.
-  - Sources: <https://www.rfc-editor.org/rfc/rfc6455.txt> · <https://www.w3.org/TR/websockets/>
-- To decide this case, observe: How to apply it in the field: treat this as the bypass it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable. _(unverified)_
+- To decide this case, observe: How to apply it in the field: treat this as the bypass it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable.  _(merged 1 duplicate row(s))_ _(unverified)_
   - **Disproof:** This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (websocket.bypass.proxy_reachable_websocket_endpoints_need_the_same_auth_as_http_routes) states the full boundary.
   - Sources: <https://www.rfc-editor.org/rfc/rfc6455.txt>
-- To decide this case, observe: How to apply it in the field: treat this as the fp_rule it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable.
-  - **Disproof:** This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (websocket.fp_rule.same_site_cookie_policy_does_not_apply_to_a_websocket_handshake) states the full boundary.
-  - Sources: <https://www.rfc-editor.org/rfc/rfc6455.txt> · <https://www.w3.org/TR/websockets/>
-- To decide this case, observe: How to apply it in the field: treat this as the fp_rule it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable.
+- To decide this case, observe: How to apply it in the field: treat this as the fp_rule it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable.  _(merged 3 duplicate row(s))_
   - **Disproof:** This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (websocket.fp_rule.a_101_switching_protocols_on_an_unauthenticated_channel_is_not_cross_site_scripting) states the full boundary.
-  - Sources: <https://tomcat.apache.org/tomcat-9.0-doc/web-socket-howto.html> · <https://www.rfc-editor.org/rfc/rfc6455.txt>
-- To decide this case, observe: How to apply it in the field: treat this as the validation it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable.
+  - Sources: <https://www.rfc-editor.org/rfc/rfc6455.txt> · <https://www.w3.org/TR/websockets/> · <https://tomcat.apache.org/tomcat-9.0-doc/web-socket-howto.html>
+- To decide this case, observe: How to apply it in the field: treat this as the validation it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable.  _(merged 1 duplicate row(s))_
   - **Disproof:** This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (websocket.validation.prove_cross_site_reach_with_a_foreign_origin_upgrade) states the full boundary.
   - Sources: <https://tomcat.apache.org/tomcat-9.0-doc/web-socket-howto.html> · <https://www.rfc-editor.org/rfc/rfc6455.txt>
 
 ## Validation bar (how to prove it)
 
-- A WebSocket that only pushes object identifiers has no data exposure to demonstrate, so a CSWSH or unauthenticated-socket report on such a channel is not substantiated until a test shows the frame itself carrying a field the reader could not otherwise obtain.
+- A WebSocket that only pushes object identifiers has no data exposure to demonstrate, so a CSWSH or unauthenticated-socket report on such a channel is not substantiated until a test shows the frame itself carrying a field the reader could not otherwise obtain.  _(merged 1 duplicate row(s))_
   - **Disproof:** The report is substantiated and this item disproved the moment a captured frame contains a real field: a full record, a permission-bearing value, or an internal identifier that resolves to data with no further authorization check. Also disprove it if the socket genuinely required authentication before any frame was emitted, since then there is no unauthenticated read to demonstrate.
   - Sources: <https://tailscale.com/docs/features/tailscale-serve> · <https://developer.okta.com/blog/2018/09/25/spring-webflux-websockets-react>
-- The convincing evidence for cross-site WebSocket reach is a raw upgrade request carrying an attacker-controlled Origin that still completes with HTTP 101 and then exchanges frames with the victim's authenticated session, which proves the handshake has no origin gate.
+- The convincing evidence for cross-site WebSocket reach is a raw upgrade request carrying an attacker-controlled Origin that still completes with HTTP 101 and then exchanges frames with the victim's authenticated session, which proves the handshake has no origin gate.  _(merged 1 duplicate row(s))_
   - **Disproof:** If the same request with a foreign Origin receives 403 or 401 the handshake is gated and the finding fails; a 101 alone is not enough if the follow-on frames are unauthenticated, since an anonymous channel proves missing origin control but not victim-session impact.
   - Sources: <https://tomcat.apache.org/tomcat-9.0-doc/web-socket-howto.html> · <https://www.rfc-editor.org/rfc/rfc6455.txt>
 
 ## False-positive rules (when to reject it)
 
-- Receiving messages injected into a WebSocket channel by a malicious page is not XSS unless the handler reflects or evaluates the payload in an HTML context, so an attacker-controlled frame that is merely parsed as JSON is a data-integrity finding, not a script-execution one.
+- A WebSocket endpoint that completes the upgrade for an arbitrary Origin is not Cross-Site WebSocket Hijacking until the server acts on an attacker-reachable frame or event; establishing the connection alone proves only that the handshake does not check Origin.  _(merged 1 duplicate row(s))_
+  - **Disproof:** The report is a false positive if the 101 is granted but every pushed frame and every send is refused without a credential the attacker lacks, or if the socket only ever emits public data. It is also a false positive if the state change required a second, attacker-independent authorization step that the attacker's frame could not satisfy.
+  - Sources: <https://auth0.com/blog/confused-deputy-the-old-bug-that-ai-agents-keep-reintroducing/> · <https://developer.okta.com/blog/2022/07/08/spa-web-security-csrf-xss>
+- A WebSocket endpoint that only accepts a connection, echoes the caller's own frames back, and serves no other user's data is not cross-site WebSocket hijacking unless the handshake ALSO lacks Origin validation and the connection carries ambient credentials: hijack is the combination of cross-site connectability and session-authorised state.  _(merged 1 duplicate row(s))_
+  - **Disproof:** It IS CSWSH if Origin is unvalidated AND the connection carries a session cookie or bearer token that lets the attacker read or mutate state belonging to the victim: another user's message, a private channel, an account action. Prove impact with a second identity, not with the attacker's own frame.
+  - Sources: <https://www.zaproxy.org/docs/alerts/100025/> · <https://securitylabs.datadoghq.com/articles/claude-mcp-cve-2025-52882/>
+- A WebSocket handshake is a normal HTTP upgrade request that still carries cookies, so SameSite only reduces cross-site reach for browsers that attach the cookie on this request; a server that never validates the Origin header at handshake time is exposed regardless of the SameSite attribute on its session cookie.  _(merged 1 duplicate row(s))_
+  - **Disproof:** It is NOT exposed if the handshake is only reachable from a non-browser client that the attacker cannot author, or if the server enforces an origin allow-list at upgrade time; and the SameSite argument itself is falsified when the cookie is SameSite=None or when the vulnerable channel is used by a non-browser client whose cookie jar is not governed by SameSite at all.
+  - Sources: <https://www.rfc-editor.org/rfc/rfc6455.txt> · <https://www.w3.org/TR/websockets/>
+- A page or config string containing wss:// is not by itself evidence that the WebSocket channel is protected, because confidentiality and integrity come from actually running the handshake over TLS end to end rather than from the scheme label appearing in source.  _(merged 1 duplicate row(s))_
+  - **Disproof:** It IS protected when the handshake reaches wss:// and the transport negotiates TLS with a certificate the client validates; it is not protected when a wss:// literal is present but a proxy terminates or downgrades the upgrade, or when the code builds the URL from an attacker-controlled scheme value so the same code path can be handed a ws:// target.
+  - Sources: <https://www.rfc-editor.org/rfc/rfc6455.txt> · <https://www.w3.org/TR/websockets/>
+- Receiving messages injected into a WebSocket channel by a malicious page is not XSS unless the handler reflects or evaluates the payload in an HTML context, so an attacker-controlled frame that is merely parsed as JSON is a data-integrity finding, not a script-execution one.  _(merged 1 duplicate row(s))_
   - **Disproof:** It IS XSS when the frame content is concatenated into a response body, written into innerHTML, or evaluated by the client; it is not when the payload stays inside JSON.parse or a typed schema field and no HTML sink receives it, in which case the correct class is injection into a data consumer rather than script execution.
   - Sources: <https://tomcat.apache.org/tomcat-9.0-doc/web-socket-howto.html> · <https://www.rfc-editor.org/rfc/rfc6455.txt>
-- A WebSocket endpoint that only accepts a connection, echoes the caller's own frames back, and serves no other user's data is not cross-site WebSocket hijacking unless the handshake ALSO lacks Origin validation and the connection carries ambient credentials: hijack is the combination of cross-site connectability and session-authorised state.
-  - **Disproof:** It IS CSWSH if Origin is unvalidated AND the connection carries a session cookie or bearer token that lets the attacker read or mutate state belonging to the victim: another user's message, a private channel, an account action. Prove impact with a second identity, not with the attacker's own frame.
-  - Sources: <https://www.zaproxy.org/docs/alerts/100025/> · <https://securitylabs.datadoghq.com/articles/claude-mcp-cve-2025-52882/>
-- A WebSocket endpoint that completes the upgrade for an arbitrary Origin is not Cross-Site WebSocket Hijacking until the server acts on an attacker-reachable frame or event; establishing the connection alone proves only that the handshake does not check Origin.
-  - **Disproof:** The report is a false positive if the 101 is granted but every pushed frame and every send is refused without a credential the attacker lacks, or if the socket only ever emits public data. It is also a false positive if the state change required a second, attacker-independent authorization step that the attacker's frame could not satisfy.
-  - Sources: <https://auth0.com/blog/confused-deputy-the-old-bug-that-ai-agents-keep-reintroducing/> · <https://developer.okta.com/blog/2022/07/08/spa-web-security-csrf-xss>
-- A WebSocket handshake is a normal HTTP upgrade request that still carries cookies, so SameSite only reduces cross-site reach for browsers that attach the cookie on this request; a server that never validates the Origin header at handshake time is exposed regardless of the SameSite attribute on its session cookie.
-  - **Disproof:** It is NOT exposed if the handshake is only reachable from a non-browser client that the attacker cannot author, or if the server enforces an origin allow-list at upgrade time; and the SameSite argument itself is falsified when the cookie is SameSite=None or when the vulnerable channel is used by a non-browser client whose cookie jar is not governed by SameSite at all.
-  - Sources: <https://www.rfc-editor.org/rfc/rfc6455.txt> · <https://www.w3.org/TR/websockets/>
-- A page or config string containing wss:// is not by itself evidence that the WebSocket channel is protected, because confidentiality and integrity come from actually running the handshake over TLS end to end rather than from the scheme label appearing in source.
-  - **Disproof:** It IS protected when the handshake reaches wss:// and the transport negotiates TLS with a certificate the client validates; it is not protected when a wss:// literal is present but a proxy terminates or downgrades the upgrade, or when the code builds the URL from an attacker-controlled scheme value so the same code path can be handed a ws:// target.
-  - Sources: <https://www.rfc-editor.org/rfc/rfc6455.txt> · <https://www.w3.org/TR/websockets/>
 
 ## Evidence requirements
 
-- A WebSocket endpoint that returns no Access-Control-Allow-Origin header is not thereby safe, because the upgrade handshake is not subject to CORS: the cross-origin request is delivered and accepted regardless, so the absence of CORS headers is the expected baseline rather than evidence of a control.
+- A WebSocket endpoint that returns no Access-Control-Allow-Origin header is not thereby safe, because the upgrade handshake is not subject to CORS: the cross-origin request is delivered and accepted regardless, so the absence of CORS headers is the expected baseline rather than evidence of a control.  _(merged 1 duplicate row(s))_
   - **Disproof:** The claim that the handshake bypasses CORS does not establish a vulnerability, and must not be reported as one by itself: an endpoint that validates Origin inside its own handshake handler, or that requires a non-cookie credential, is protected by a control CORS would never have supplied. The claim is also inapplicable to a transport that is not a browser WebSocket upgrade - a native client, a server-to-server connection, or a managed gateway that terminates the socket and re-origin-checks upstream - and to polling transports, where CORS does apply and its absence may genuinely block the cross-origin read.
   - Sources: <https://cwe.mitre.org/data/definitions/940.html> · <https://socket.io/docs/v4/handling-cors/>
-- The consequence of the hijack is proven when a frame the server pushes to the connection opened from the foreign origin contains data that page is not entitled to read - the victim's account state, another user's message, or an internal identifier - because that data left the server over a channel the attacker opened.
+- A server that accepts the upgrade without an Origin header at all, or with one that is unvalidated, proves nothing about its intent but does prove the endpoint cannot be relying on the browser's origin model, because nothing in the accepted handshake ever established who asked.  _(merged 1 duplicate row(s))_
+  - **Disproof:** The claim is false where the origin restriction is enforced by a different mechanism entirely - a per-connection token bound to the session, mutual TLS on the upgrade, or a gateway that terminates and re-checks - since the handshake need not carry Origin for the channel to be safe. It is also false for deployments where every legitimate client is non-browser and cannot send Origin, where requiring it would break the protocol without adding a control. An upgrade rejected specifically for a missing Origin is the opposite of the claim and is a working control.
+  - Sources: <https://developer.mozilla.org/en-US/docs/Web/API/WebSocket> · <https://socket.io/docs/v4/handling-cors/> · <https://www.rfc-editor.org/rfc/rfc8441.html>
+- Cross-site WebSocket hijacking is proven when a handshake sent from a page on a foreign origin is answered 101 Switching Protocols and the connection then delivers a server frame, because the artifact is an established bidirectional channel the attacker page opened, not a rejected upgrade.  _(merged 1 duplicate row(s))_
+  - **Disproof:** The claim is false when the handshake is refused - a 403, a 401, or any status other than 101 - or when the connection is accepted but immediately closed before any frame is delivered, since no channel was established. It is also false where the WebSocket is authenticated by something the foreign page cannot supply, such as a bearer token in the URL query or a per-connection signature the attacker does not hold; a cookie-authenticated socket whose origin check passes because the attacker's page is same-origin is not cross-site and proves nothing. A 101 obtained from a raw client outside a browser is likewise not evidence, since it never demonstrated cross-origin reachability.
+  - Sources: <https://cwe.mitre.org/data/definitions/940.html> · <https://developer.mozilla.org/en-US/docs/Web/API/WebSocket/readyState> · <https://www.rfc-editor.org/rfc/rfc8441.html>
+- The consequence of the hijack is proven when a frame the server pushes to the connection opened from the foreign origin contains data that page is not entitled to read - the victim's account state, another user's message, or an internal identifier - because that data left the server over a channel the attacker opened.  _(merged 1 duplicate row(s))_
   - **Disproof:** The claim is false when the connection delivers only data the attacker's own session is entitled to - its own messages, its own account state - since identical bytes on both sides mean nothing crossed a boundary. It is also false where no server frame arrives at all and the channel permits only client-to-server writes, where the pushed data is a public or already-unauthenticated feed, and where the frame was fetched by an ordinary authenticated HTTP request from the same page rather than arriving over the socket. A frame observed without a corresponding accepted foreign-origin handshake is unattributable and cannot support the claim.
... (truncated)
```

## 2026-10-04 00:50 — 14 diff lines
- items: 26 (supported 18), FP rules 5, chains 1, state mature

```diff
--- websocket@current
+++ websocket@new
@@ -108,10 +108,7 @@
 
 ## Hunt procedure
 
-1. Enumerate the surface before probing: collect every endpoint, parameter and object id the class could plausibly sit on.
-2. Establish a CONTROLLED BASELINE first — one unauthenticated and one authenticated low-privilege request per candidate — and diff against the probe. A difference with no baseline proves nothing.
-3. Change exactly ONE variable per probe. Two changes produce a difference you cannot attribute.
-4. Record raw request and response pairs verbatim, including headers, before you interpret anything.
+1. Check the Origin check on the upgrade handshake and on every message handler, then look for missing authentication on the frame handler itself.
 
 ### What counts as proof
 
```

## 2026-10-04 13:20 — 23 diff lines
- items: 26 (supported 19), FP rules 5, chains 1, state mature

```diff
--- websocket@current
+++ websocket@new
@@ -10,7 +10,7 @@
      python -m wks.skillgen -->
 
 > surface `web` · CWE 1004 · OWASP A04:2021
-> evidence: 26 items, 18 supported, 5 FP rules, 1 chains
+> evidence: 26 items, 19 supported, 5 FP rules, 1 chains
 > maturity: **mature**
 
 The persistent channel inherits origin, authorisation and message-validation weaknesses of its upgrade request.
@@ -38,9 +38,9 @@
 
 ## Tests
 
-- To decide this case, observe: How to apply it in the field: treat this as the bypass it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable.  _(merged 1 duplicate row(s))_ _(unverified)_
+- To decide this case, observe: How to apply it in the field: treat this as the bypass it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable.  _(merged 1 duplicate row(s))_
   - **Disproof:** This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (websocket.bypass.proxy_reachable_websocket_endpoints_need_the_same_auth_as_http_routes) states the full boundary.
-  - Sources: <https://www.rfc-editor.org/rfc/rfc6455.txt>
+  - Sources: <https://nginx.org/en/docs/http/ngx_http_proxy_module.html> · <https://www.rfc-editor.org/rfc/rfc6455.txt>
 - To decide this case, observe: How to apply it in the field: treat this as the fp_rule it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable.  _(merged 3 duplicate row(s))_
   - **Disproof:** This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (websocket.fp_rule.a_101_switching_protocols_on_an_unauthenticated_channel_is_not_cross_site_scripting) states the full boundary.
   - Sources: <https://www.rfc-editor.org/rfc/rfc6455.txt> · <https://www.w3.org/TR/websockets/> · <https://tomcat.apache.org/tomcat-9.0-doc/web-socket-howto.html>
```

## 2026-10-04 19:46 — 9 diff lines
- items: 26 (supported 19), FP rules 5, chains 1, state mature

```diff
--- websocket@current
+++ websocket@new
@@ -119,6 +119,3 @@
 > Ordered prerequisites, the validation bar and the false-positive rules below are the authority: this block is the mechanics, those are the standard.
 ---
 Full class document: `domains/web/websocket/knowledge/DIGEST.md` · retrieve more with `python -m wks.cli search "<query>" --class-id websocket`
-
----
-Runbook: [`HUNT.md`](HUNT.md) — every promoted technique mapped to an executable procedure with the observables to record.
```

## 2026-10-04 21:29 — 33 diff lines
- items: 26 (supported 22), FP rules 5, chains 1, state mature

```diff
--- websocket@current
+++ websocket@new
@@ -10,7 +10,7 @@
      python -m wks.skillgen -->
 
 > surface `web` · CWE 1004 · OWASP A04:2021
-> evidence: 26 items, 19 supported, 5 FP rules, 1 chains
+> evidence: 26 items, 22 supported, 5 FP rules, 1 chains
 > maturity: **mature**
 
 The persistent channel inherits origin, authorisation and message-validation weaknesses of its upgrade request.
@@ -23,8 +23,8 @@
 - Because the browser handshake cannot carry an Authorization header, a WebSocket endpoint is only authenticated if the credential arrives through the Sec-WebSocket-Protocol value or an explicit post-connect authentication frame; test each channel by omitting it and observing whether the connection still receives application data.  _(merged 1 duplicate row(s))_
   - **Disproof:** The channel test fails if a connection with no credential still receives application data, or if an invalid or unsigned token is accepted. It also fails to implicate this endpoint if the deployment terminates authentication in a reverse proxy that injects an identity header rather than in the socket handler, in which case the trust boundary to test is the proxy, not the frame.
   - Sources: <https://auth0.com/blog/cross-site-request-forgery-csrf/> · <https://developer.okta.com/blog/2020/10/28/secure-web-apps-websockets-nodejs>
-- Browser WebSocket behavior : Unlike traditional HTTP requests, WebSocket connections are not restricted by the browser's same-origin policy.  _(merged 1 duplicate row(s))_ _(unverified)_
-  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Browser WebSocket behavior : Unlike traditional HTTP requests, WebSocket connections are n".
+- Browser WebSocket behavior : Unlike traditional HTTP requests, WebSocket connections are not restricted by the browser's same-origin policy.  _(merged 1 duplicate row(s))_
+  - **Disproof:** Refuted when: the same behaviour is absent when the single named control in the claim is present, and the control is shown to be present rather than assumed. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“Browser WebSocket behavior : Unlike traditional HTTP requests, WebSocket connect”) does not occur under a test that isolates that control.
   - Sources: <https://securitylabs.datadoghq.com/articles/claude-mcp-cve-2025-52882/> · <https://www.rfc-editor.org/rfc/rfc6455.txt>
 - For educational purposes, it's worth demonstrating an exploit proof of concept (PoC), if only to highlight the severity of this issue and the ease with which it could be exploited.  _(merged 1 duplicate row(s))_ _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "For educational purposes, it's worth demonstrating an exploit proof of concept (PoC), if o".
@@ -32,8 +32,8 @@
 - If you try to do a redirect with context.redirect , the authentication flow will return an error.  _(merged 2 duplicate row(s))_ _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "If you try to do a redirect with context.redirect , the authentication flow will return an".
   - Sources: <https://securitylabs.datadoghq.com/articles/claude-mcp-cve-2025-52882/>
-- Take into account that cookies will work just fine if the web app and the API are served from the same domain, so you might not need token based authentication.  _(merged 2 duplicate row(s))_ _(unverified)_
-  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Take into account that cookies will work just fine if the web app and the API are served f".
+- Take into account that cookies will work just fine if the web app and the API are served from the same domain, so you might not need token based authentication.  _(merged 2 duplicate row(s))_
+  - **Disproof:** Refuted when: the same behaviour is absent when the single named control in the claim is present, and the control is shown to be present rather than assumed. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“Take into account that cookies will work just fine if the web app and the API ar”) does not occur under a test that isolates that control.
   - Sources: <https://securitylabs.datadoghq.com/articles/claude-mcp-cve-2025-52882/> · <https://www.rfc-editor.org/rfc/rfc6455.txt>
 
 ## Tests
```

## 2026-10-28 14:45 — 37 diff lines
- items: 20 (supported 17), FP rules 5, chains 1, state mature

```diff
--- websocket@current
+++ websocket@new
@@ -10,7 +10,7 @@
      python -m wks.skillgen -->
 
 > surface `web` · CWE 1004 · OWASP A04:2021
-> evidence: 26 items, 22 supported, 5 FP rules, 1 chains
+> evidence: 20 items, 17 supported, 5 FP rules, 1 chains
 > maturity: **mature**
 
 The persistent channel inherits origin, authorisation and message-validation weaknesses of its upgrade request.
@@ -29,24 +29,12 @@
 - For educational purposes, it's worth demonstrating an exploit proof of concept (PoC), if only to highlight the severity of this issue and the ease with which it could be exploited.  _(merged 1 duplicate row(s))_ _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "For educational purposes, it's worth demonstrating an exploit proof of concept (PoC), if o".
   - Sources: <https://securitylabs.datadoghq.com/articles/claude-mcp-cve-2025-52882/>
-- If you try to do a redirect with context.redirect , the authentication flow will return an error.  _(merged 2 duplicate row(s))_ _(unverified)_
+- If you try to do a redirect with context.redirect , the authentication flow will return an error.  _(merged 1 duplicate row(s))_ _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "If you try to do a redirect with context.redirect , the authentication flow will return an".
   - Sources: <https://securitylabs.datadoghq.com/articles/claude-mcp-cve-2025-52882/>
 - Take into account that cookies will work just fine if the web app and the API are served from the same domain, so you might not need token based authentication.  _(merged 2 duplicate row(s))_
   - **Disproof:** Refuted when: the same behaviour is absent when the single named control in the claim is present, and the control is shown to be present rather than assumed. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“Take into account that cookies will work just fine if the web app and the API ar”) does not occur under a test that isolates that control.
   - Sources: <https://securitylabs.datadoghq.com/articles/claude-mcp-cve-2025-52882/> · <https://www.rfc-editor.org/rfc/rfc6455.txt>
-
-## Tests
-
-- To decide this case, observe: How to apply it in the field: treat this as the bypass it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable.  _(merged 1 duplicate row(s))_
-  - **Disproof:** This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (websocket.bypass.proxy_reachable_websocket_endpoints_need_the_same_auth_as_http_routes) states the full boundary.
-  - Sources: <https://nginx.org/en/docs/http/ngx_http_proxy_module.html> · <https://www.rfc-editor.org/rfc/rfc6455.txt>
-- To decide this case, observe: How to apply it in the field: treat this as the fp_rule it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable.  _(merged 3 duplicate row(s))_
-  - **Disproof:** This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (websocket.fp_rule.a_101_switching_protocols_on_an_unauthenticated_channel_is_not_cross_site_scripting) states the full boundary.
-  - Sources: <https://www.rfc-editor.org/rfc/rfc6455.txt> · <https://www.w3.org/TR/websockets/> · <https://tomcat.apache.org/tomcat-9.0-doc/web-socket-howto.html>
-- To decide this case, observe: How to apply it in the field: treat this as the validation it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable.  _(merged 1 duplicate row(s))_
-  - **Disproof:** This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (websocket.validation.prove_cross_site_reach_with_a_foreign_origin_upgrade) states the full boundary.
-  - Sources: <https://tomcat.apache.org/tomcat-9.0-doc/web-socket-howto.html> · <https://www.rfc-editor.org/rfc/rfc6455.txt>
 
 ## Validation bar (how to prove it)
 
```

## 2026-10-28 17:55 — 26 diff lines
- items: 17 (supported 16), FP rules 5, chains 1, state mature

```diff
--- websocket@current
+++ websocket@new
@@ -10,7 +10,7 @@
      python -m wks.skillgen -->
 
 > surface `web` · CWE 1004 · OWASP A04:2021
-> evidence: 20 items, 17 supported, 5 FP rules, 1 chains
+> evidence: 17 items, 16 supported, 5 FP rules, 1 chains
 > maturity: **mature**
 
 The persistent channel inherits origin, authorisation and message-validation weaknesses of its upgrade request.
@@ -26,13 +26,7 @@
 - Browser WebSocket behavior : Unlike traditional HTTP requests, WebSocket connections are not restricted by the browser's same-origin policy.  _(merged 1 duplicate row(s))_
   - **Disproof:** Refuted when: the same behaviour is absent when the single named control in the claim is present, and the control is shown to be present rather than assumed. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“Browser WebSocket behavior : Unlike traditional HTTP requests, WebSocket connect”) does not occur under a test that isolates that control.
   - Sources: <https://securitylabs.datadoghq.com/articles/claude-mcp-cve-2025-52882/> · <https://www.rfc-editor.org/rfc/rfc6455.txt>
-- For educational purposes, it's worth demonstrating an exploit proof of concept (PoC), if only to highlight the severity of this issue and the ease with which it could be exploited.  _(merged 1 duplicate row(s))_ _(unverified)_
-  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "For educational purposes, it's worth demonstrating an exploit proof of concept (PoC), if o".
-  - Sources: <https://securitylabs.datadoghq.com/articles/claude-mcp-cve-2025-52882/>
-- If you try to do a redirect with context.redirect , the authentication flow will return an error.  _(merged 1 duplicate row(s))_ _(unverified)_
-  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "If you try to do a redirect with context.redirect , the authentication flow will return an".
-  - Sources: <https://securitylabs.datadoghq.com/articles/claude-mcp-cve-2025-52882/>
-- Take into account that cookies will work just fine if the web app and the API are served from the same domain, so you might not need token based authentication.  _(merged 2 duplicate row(s))_
+- Take into account that cookies will work just fine if the web app and the API are served from the same domain, so you might not need token based authentication.  _(merged 1 duplicate row(s))_
   - **Disproof:** Refuted when: the same behaviour is absent when the single named control in the claim is present, and the control is shown to be present rather than assumed. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“Take into account that cookies will work just fine if the web app and the API ar”) does not occur under a test that isolates that control.
   - Sources: <https://securitylabs.datadoghq.com/articles/claude-mcp-cve-2025-52882/> · <https://www.rfc-editor.org/rfc/rfc6455.txt>
 
```

## 2026-10-28 21:43 — 71 diff lines
- items: 24 (supported 23), FP rules 5, chains 1, state mature

```diff
--- websocket@current
+++ websocket@new
@@ -10,7 +10,7 @@
      python -m wks.skillgen -->
 
 > surface `web` · CWE 1004 · OWASP A04:2021
-> evidence: 17 items, 16 supported, 5 FP rules, 1 chains
+> evidence: 24 items, 23 supported, 5 FP rules, 1 chains
 > maturity: **mature**
 
 The persistent channel inherits origin, authorisation and message-validation weaknesses of its upgrade request.
@@ -20,6 +20,15 @@
 
 ## Techniques (what to change)
 
+- A WebSocket handshake that authenticates the connection through an ambient session cookie, but never compares the Origin request header against an allow-list, lets any malicious page open a real-time channel on behalf of an authenticated victim.  _(merged 1 duplicate row(s))_
+  - **Disproof:** Refuted when a foreign-origin upgrade is answered 403 or 401, or when the handshake requires a per-connection secret the attacker's page cannot supply; also refuted when the endpoint independently re-authorizes every message after the handshake.
+  - Sources: <https://portswigger.net/web-security/cross-site-websocket-hijacking> · <https://www.rfc-editor.org/rfc/rfc6455.txt> · <https://www.w3.org/TR/websockets/>
+- A client that can read and modify outbound WebSocket frames - such as price, quantity, user id, or amount - can cause the server to execute privileged actions on attacker-controlled payload values that it would never accept from an HTTP request.  _(merged 1 duplicate row(s))_
+  - **Disproof:** Refuted when frames are MAC-protected or encrypted per-message so a reader cannot modify them in-flight, or when the receiving side verifies a signature on every payload before acting.
+  - Sources: <https://cwe.mitre.org/data/definitions/940.html> · <https://www.rfc-editor.org/rfc/rfc6455.txt>
+- A live socket.io endpoint can be version-fingerprinted from its handshake, so a hunter must compare the observed version against released advisories rather than assuming a framework version is safe.  _(merged 1 duplicate row(s))_
+  - **Disproof:** Falsified if the handshake does not expose a version that can be matched, or if the deployed version corresponds to a patched release whose advisory has been updated to exclude the observed flaw.
+  - Sources: <https://nvd.nist.gov/vuln/search/results?form_type=CMP&results_type=overview&query_text=CVE-2020-7662> · <https://portswigger.net/web-security/cross-site-websocket-hijacking>
 - Because the browser handshake cannot carry an Authorization header, a WebSocket endpoint is only authenticated if the credential arrives through the Sec-WebSocket-Protocol value or an explicit post-connect authentication frame; test each channel by omitting it and observing whether the connection still receives application data.  _(merged 1 duplicate row(s))_
   - **Disproof:** The channel test fails if a connection with no credential still receives application data, or if an invalid or unsigned token is accepted. It also fails to implicate this endpoint if the deployment terminates authentication in a reverse proxy that injects an identity header rather than in the socket handler, in which case the trust boundary to test is the proxy, not the frame.
   - Sources: <https://auth0.com/blog/cross-site-request-forgery-csrf/> · <https://developer.okta.com/blog/2020/10/28/secure-web-apps-websockets-nodejs>
@@ -61,10 +70,10 @@
 
 - A WebSocket endpoint that returns no Access-Control-Allow-Origin header is not thereby safe, because the upgrade handshake is not subject to CORS: the cross-origin request is delivered and accepted regardless, so the absence of CORS headers is the expected baseline rather than evidence of a control.  _(merged 1 duplicate row(s))_
   - **Disproof:** The claim that the handshake bypasses CORS does not establish a vulnerability, and must not be reported as one by itself: an endpoint that validates Origin inside its own handshake handler, or that requires a non-cookie credential, is protected by a control CORS would never have supplied. The claim is also inapplicable to a transport that is not a browser WebSocket upgrade - a native client, a server-to-server connection, or a managed gateway that terminates the socket and re-origin-checks upstream - and to polling transports, where CORS does apply and its absence may genuinely block the cross-origin read.
-  - Sources: <https://cwe.mitre.org/data/definitions/940.html> · <https://socket.io/docs/v4/handling-cors/>
+  - Sources: <https://socket.io/docs/v4/handling-cors/> · <https://cwe.mitre.org/data/definitions/940.html>
 - A server that accepts the upgrade without an Origin header at all, or with one that is unvalidated, proves nothing about its intent but does prove the endpoint cannot be relying on the browser's origin model, because nothing in the accepted handshake ever established who asked.  _(merged 1 duplicate row(s))_
   - **Disproof:** The claim is false where the origin restriction is enforced by a different mechanism entirely - a per-connection token bound to the session, mutual TLS on the upgrade, or a gateway that terminates and re-checks - since the handshake need not carry Origin for the channel to be safe. It is also false for deployments where every legitimate client is non-browser and cannot send Origin, where requiring it would break the protocol without adding a control. An upgrade rejected specifically for a missing Origin is the opposite of the claim and is a working control.
-  - Sources: <https://developer.mozilla.org/en-US/docs/Web/API/WebSocket> · <https://socket.io/docs/v4/handling-cors/> · <https://www.rfc-editor.org/rfc/rfc8441.html>
+  - Sources: <https://socket.io/docs/v4/handling-cors/> · <https://developer.mozilla.org/en-US/docs/Web/API/WebSocket> · <https://www.rfc-editor.org/rfc/rfc8441.html>
 - Cross-site WebSocket hijacking is proven when a handshake sent from a page on a foreign origin is answered 101 Switching Protocols and the connection then delivers a server frame, because the artifact is an established bidirectional channel the attacker page opened, not a rejected upgrade.  _(merged 1 duplicate row(s))_
   - **Disproof:** The claim is false when the handshake is refused - a 403, a 401, or any status other than 101 - or when the connection is accepted but immediately closed before any frame is delivered, since no channel was established. It is also false where the WebSocket is authenticated by something the foreign page cannot supply, such as a bearer token in the URL query or a per-connection signature the attacker does not hold; a cookie-authenticated socket whose origin check passes because the attacker's page is same-origin is not cross-site and proves nothing. A 101 obtained from a raw client outside a browser is likewise not evidence, since it never demonstrated cross-origin reachability.
   - Sources: <https://cwe.mitre.org/data/definitions/940.html> · <https://developer.mozilla.org/en-US/docs/Web/API/WebSocket/readyState> · <https://www.rfc-editor.org/rfc/rfc8441.html>
@@ -74,18 +83,30 @@
 
 ## Defence bypasses
 
+- A reverse proxy that authenticates sibling HTTP routes can leave the WebSocket upgrade path unauthenticated, so an attacker reaches the authenticated WS endpoint by upgrading the request while the same endpoint returns 401 for normal HTTP.  _(merged 1 duplicate row(s))_
+  - **Disproof:** Refuted when the proxy applies the identical authentication rule to upgrade requests as to normal routes, or when every message after the handshake is independently re-authorized regardless of the connection's pre-auth state.
+  - Sources: <https://nginx.org/en/docs/http/ngx_http_proxy_module.html> · <https://www.rfc-editor.org/rfc/rfc6455.txt>
 - A reverse proxy that routes HTTP endpoints through authentication can leave a WebSocket upgrade path outside that same authentication layer, so the bypass is demonstrated by finding an upgrade path the proxy forwards while the sibling HTTP route returns 401.  _(merged 1 duplicate row(s))_
   - **Disproof:** It is not a bypass when the proxy applies the same authentication rule to the upgrade request as to normal routes, or when the application independently authenticates and authorises every message after the handshake rather than trusting the connection to be pre-authorised.
   - Sources: <https://securitylabs.datadoghq.com/articles/claude-mcp-cve-2025-52882/> · <https://www.rfc-editor.org/rfc/rfc6455.txt>
+- A socket.io server that only validates the initial handshake but does not enforce per-namespace and per-room permission checks lets a low-privilege socket join a privileged namespace or another user's room.  _(merged 1 duplicate row(s))_
+  - **Disproof:** Refuted when join and leave handlers enforce per-namespace/per-room permission checks, and when privileged namespaces require a role that the handshake does not grant.
+  - Sources: <https://socket.io/docs/v4/handling-cors/> · <https://cwe.mitre.org/data/definitions/940.html>
 - Passing the session credential in the WebSocket URL query string bypasses every header-stripping and referrer-policy control, because URLs are recorded verbatim in proxy, server and browser history even where the same token would never be logged as a header.  _(merged 1 duplicate row(s))_
   - **Disproof:** The bypass is not demonstrated if the token never appears in any log, proxy record, history entry or telemetry field you can reach, or if the server rejects query-string credentials outright at the upgrade. It also does not apply where the credential is single-use, short-lived and audience-bound, because its theft then yields nothing beyond the attacker's own session.
   - Sources: <https://tailscale.com/docs/features/tailscale-serve> · <https://securitylabs.datadoghq.com/articles/claude-mcp-cve-2025-52882/>
+- When handshake or transport authentication is present but individual WebSocket frames carry no second authorization check, a connected client can submit privileged frames such as deleteUser or getSecretConfig that the server would reject if sent over HTTP.  _(merged 1 duplicate row(s))_
+  - **Disproof:** Refuted when every message is independently re-authorized against the session, or when the server rejects frames that request privileged actions without proof of entitlement.
+  - Sources: <https://socket.io/docs/v4/handling-cors/> · <https://cwe.mitre.org/data/definitions/940.html>
 
 ## Chaining opportunities
 
 - A replayed session cookie becomes a live push channel the moment a socket upgrade accepts that cookie, so session-theft impact must be restated as continuous unauthorized data reception rather than only what the stolen session could fetch on demand.  _(merged 1 duplicate row(s))_ _(unverified)_
   - **Disproof:** The chain does not hold if the socket upgrade independently requires a fresh proof the stolen cookie does not supply, if the server binds the session to a device or connection attribute the attacker did not capture, or if the pushed stream carries no data the attacker was not already entitled to. Absent a standing channel, the impact stays at the level session theft alone justifies.
   - Sources: <https://developer.okta.com/docs/concepts/session/> · <https://auth0.com/blog/confused-deputy-the-old-bug-that-ai-agents-keep-reintroducing/> · <https://auth0.com/blog/cross-site-request-forgery-csrf/>
+- CSWSH alone yields a privileged real-time channel; combined with missing per-message authentication or in-flight frame injection, that channel escalates to cross-tenant data exfiltration or account takeover.  _(merged 1 duplicate row(s))_
+  - **Disproof:** The chain is unproven if the hijacked channel carries no data the attacker is not already entitled to read, if per-message auth stops every privileged frame, or if the server rejects attacker-controlled payload values before acting.
+  - Sources: <https://cwe.mitre.org/data/definitions/940.html> · <https://portswigger.net/web-security/cross-site-websocket-hijacking>
 
 
 ## Hunt procedure
```

## 2026-10-31 06:41 — 81 diff lines
- items: 24 (supported 12), FP rules 3, chains 1, state mature

```diff
--- websocket@current
+++ websocket@new
@@ -10,7 +10,7 @@
      python -m wks.skillgen -->
 
 > surface `web` · CWE 1004 · OWASP A04:2021
-> evidence: 24 items, 23 supported, 5 FP rules, 1 chains
+> evidence: 24 items, 12 supported, 3 FP rules, 1 chains
 > maturity: **mature**
 
 The persistent channel inherits origin, authorisation and message-validation weaknesses of its upgrade request.
@@ -23,19 +23,19 @@
 - A WebSocket handshake that authenticates the connection through an ambient session cookie, but never compares the Origin request header against an allow-list, lets any malicious page open a real-time channel on behalf of an authenticated victim.  _(merged 1 duplicate row(s))_
   - **Disproof:** Refuted when a foreign-origin upgrade is answered 403 or 401, or when the handshake requires a per-connection secret the attacker's page cannot supply; also refuted when the endpoint independently re-authorizes every message after the handshake.
   - Sources: <https://portswigger.net/web-security/cross-site-websocket-hijacking> · <https://www.rfc-editor.org/rfc/rfc6455.txt> · <https://www.w3.org/TR/websockets/>
-- A client that can read and modify outbound WebSocket frames - such as price, quantity, user id, or amount - can cause the server to execute privileged actions on attacker-controlled payload values that it would never accept from an HTTP request.  _(merged 1 duplicate row(s))_
+- A client that can read and modify outbound WebSocket frames - such as price, quantity, user id, or amount - can cause the server to execute privileged actions on attacker-controlled payload values that it would never accept from an HTTP request.  _(merged 1 duplicate row(s))_ _(unverified)_
   - **Disproof:** Refuted when frames are MAC-protected or encrypted per-message so a reader cannot modify them in-flight, or when the receiving side verifies a signature on every payload before acting.
   - Sources: <https://cwe.mitre.org/data/definitions/940.html> · <https://www.rfc-editor.org/rfc/rfc6455.txt>
 - A live socket.io endpoint can be version-fingerprinted from its handshake, so a hunter must compare the observed version against released advisories rather than assuming a framework version is safe.  _(merged 1 duplicate row(s))_
   - **Disproof:** Falsified if the handshake does not expose a version that can be matched, or if the deployed version corresponds to a patched release whose advisory has been updated to exclude the observed flaw.
   - Sources: <https://nvd.nist.gov/vuln/search/results?form_type=CMP&results_type=overview&query_text=CVE-2020-7662> · <https://portswigger.net/web-security/cross-site-websocket-hijacking>
-- Because the browser handshake cannot carry an Authorization header, a WebSocket endpoint is only authenticated if the credential arrives through the Sec-WebSocket-Protocol value or an explicit post-connect authentication frame; test each channel by omitting it and observing whether the connection still receives application data.  _(merged 1 duplicate row(s))_
+- Because the browser handshake cannot carry an Authorization header, a WebSocket endpoint is only authenticated if the credential arrives through the Sec-WebSocket-Protocol value or an explicit post-connect authentication frame; test each channel by omitting it and observing whether the connection still receives application data.  _(merged 1 duplicate row(s))_ _(unverified)_
   - **Disproof:** The channel test fails if a connection with no credential still receives application data, or if an invalid or unsigned token is accepted. It also fails to implicate this endpoint if the deployment terminates authentication in a reverse proxy that injects an identity header rather than in the socket handler, in which case the trust boundary to test is the proxy, not the frame.
   - Sources: <https://auth0.com/blog/cross-site-request-forgery-csrf/> · <https://developer.okta.com/blog/2020/10/28/secure-web-apps-websockets-nodejs>
-- Browser WebSocket behavior : Unlike traditional HTTP requests, WebSocket connections are not restricted by the browser's same-origin policy.  _(merged 1 duplicate row(s))_
+- Browser WebSocket behavior : Unlike traditional HTTP requests, WebSocket connections are not restricted by the browser's same-origin policy.  _(merged 1 duplicate row(s))_ _(unverified)_
   - **Disproof:** Refuted when: the same behaviour is absent when the single named control in the claim is present, and the control is shown to be present rather than assumed. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“Browser WebSocket behavior : Unlike traditional HTTP requests, WebSocket connect”) does not occur under a test that isolates that control.
   - Sources: <https://securitylabs.datadoghq.com/articles/claude-mcp-cve-2025-52882/> · <https://www.rfc-editor.org/rfc/rfc6455.txt>
-- Take into account that cookies will work just fine if the web app and the API are served from the same domain, so you might not need token based authentication.  _(merged 1 duplicate row(s))_
+- Take into account that cookies will work just fine if the web app and the API are served from the same domain, so you might not need token based authentication.  _(merged 1 duplicate row(s))_ _(unverified)_
   - **Disproof:** Refuted when: the same behaviour is absent when the single named control in the claim is present, and the control is shown to be present rather than assumed. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“Take into account that cookies will work just fine if the web app and the API ar”) does not occur under a test that isolates that control.
   - Sources: <https://securitylabs.datadoghq.com/articles/claude-mcp-cve-2025-52882/> · <https://www.rfc-editor.org/rfc/rfc6455.txt>
 
@@ -50,13 +50,13 @@
 
 ## False-positive rules (when to reject it)
 
-- A WebSocket endpoint that completes the upgrade for an arbitrary Origin is not Cross-Site WebSocket Hijacking until the server acts on an attacker-reachable frame or event; establishing the connection alone proves only that the handshake does not check Origin.  _(merged 1 duplicate row(s))_
+- A WebSocket endpoint that completes the upgrade for an arbitrary Origin is not Cross-Site WebSocket Hijacking until the server acts on an attacker-reachable frame or event; establishing the connection alone proves only that the handshake does not check Origin.  _(merged 1 duplicate row(s))_ _(unverified)_
   - **Disproof:** The report is a false positive if the 101 is granted but every pushed frame and every send is refused without a credential the attacker lacks, or if the socket only ever emits public data. It is also a false positive if the state change required a second, attacker-independent authorization step that the attacker's frame could not satisfy.
   - Sources: <https://auth0.com/blog/confused-deputy-the-old-bug-that-ai-agents-keep-reintroducing/> · <https://developer.okta.com/blog/2022/07/08/spa-web-security-csrf-xss>
 - A WebSocket endpoint that only accepts a connection, echoes the caller's own frames back, and serves no other user's data is not cross-site WebSocket hijacking unless the handshake ALSO lacks Origin validation and the connection carries ambient credentials: hijack is the combination of cross-site connectability and session-authorised state.  _(merged 1 duplicate row(s))_
   - **Disproof:** It IS CSWSH if Origin is unvalidated AND the connection carries a session cookie or bearer token that lets the attacker read or mutate state belonging to the victim: another user's message, a private channel, an account action. Prove impact with a second identity, not with the attacker's own frame.
   - Sources: <https://www.zaproxy.org/docs/alerts/100025/> · <https://securitylabs.datadoghq.com/articles/claude-mcp-cve-2025-52882/>
-- A WebSocket handshake is a normal HTTP upgrade request that still carries cookies, so SameSite only reduces cross-site reach for browsers that attach the cookie on this request; a server that never validates the Origin header at handshake time is exposed regardless of the SameSite attribute on its session cookie.  _(merged 1 duplicate row(s))_
+- A WebSocket handshake is a normal HTTP upgrade request that still carries cookies, so SameSite only reduces cross-site reach for browsers that attach the cookie on this request; a server that never validates the Origin header at handshake time is exposed regardless of the SameSite attribute on its session cookie.  _(merged 1 duplicate row(s))_ _(unverified)_
   - **Disproof:** It is NOT exposed if the handshake is only reachable from a non-browser client that the attacker cannot author, or if the server enforces an origin allow-list at upgrade time; and the SameSite argument itself is falsified when the cookie is SameSite=None or when the vulnerable channel is used by a non-browser client whose cookie jar is not governed by SameSite at all.
   - Sources: <https://www.rfc-editor.org/rfc/rfc6455.txt> · <https://www.w3.org/TR/websockets/>
 - A page or config string containing wss:// is not by itself evidence that the WebSocket channel is protected, because confidentiality and integrity come from actually running the handshake over TLS end to end rather than from the scheme label appearing in source.  _(merged 1 duplicate row(s))_
@@ -68,7 +68,7 @@
 
 ## Evidence requirements
 
-- A WebSocket endpoint that returns no Access-Control-Allow-Origin header is not thereby safe, because the upgrade handshake is not subject to CORS: the cross-origin request is delivered and accepted regardless, so the absence of CORS headers is the expected baseline rather than evidence of a control.  _(merged 1 duplicate row(s))_
+- A WebSocket endpoint that returns no Access-Control-Allow-Origin header is not thereby safe, because the upgrade handshake is not subject to CORS: the cross-origin request is delivered and accepted regardless, so the absence of CORS headers is the expected baseline rather than evidence of a control.  _(merged 1 duplicate row(s))_ _(unverified)_
   - **Disproof:** The claim that the handshake bypasses CORS does not establish a vulnerability, and must not be reported as one by itself: an endpoint that validates Origin inside its own handshake handler, or that requires a non-cookie credential, is protected by a control CORS would never have supplied. The claim is also inapplicable to a transport that is not a browser WebSocket upgrade - a native client, a server-to-server connection, or a managed gateway that terminates the socket and re-origin-checks upstream - and to polling transports, where CORS does apply and its absence may genuinely block the cross-origin read.
   - Sources: <https://socket.io/docs/v4/handling-cors/> · <https://cwe.mitre.org/data/definitions/940.html>
 - A server that accepts the upgrade without an Origin header at all, or with one that is unvalidated, proves nothing about its intent but does prove the endpoint cannot be relying on the browser's origin model, because nothing in the accepted handshake ever established who asked.  _(merged 1 duplicate row(s))_
@@ -86,16 +86,16 @@
 - A reverse proxy that authenticates sibling HTTP routes can leave the WebSocket upgrade path unauthenticated, so an attacker reaches the authenticated WS endpoint by upgrading the request while the same endpoint returns 401 for normal HTTP.  _(merged 1 duplicate row(s))_
   - **Disproof:** Refuted when the proxy applies the identical authentication rule to upgrade requests as to normal routes, or when every message after the handshake is independently re-authorized regardless of the connection's pre-auth state.
   - Sources: <https://nginx.org/en/docs/http/ngx_http_proxy_module.html> · <https://www.rfc-editor.org/rfc/rfc6455.txt>
-- A reverse proxy that routes HTTP endpoints through authentication can leave a WebSocket upgrade path outside that same authentication layer, so the bypass is demonstrated by finding an upgrade path the proxy forwards while the sibling HTTP route returns 401.  _(merged 1 duplicate row(s))_
+- A reverse proxy that routes HTTP endpoints through authentication can leave a WebSocket upgrade path outside that same authentication layer, so the bypass is demonstrated by finding an upgrade path the proxy forwards while the sibling HTTP route returns 401.  _(merged 1 duplicate row(s))_ _(unverified)_
   - **Disproof:** It is not a bypass when the proxy applies the same authentication rule to the upgrade request as to normal routes, or when the application independently authenticates and authorises every message after the handshake rather than trusting the connection to be pre-authorised.
   - Sources: <https://securitylabs.datadoghq.com/articles/claude-mcp-cve-2025-52882/> · <https://www.rfc-editor.org/rfc/rfc6455.txt>
-- A socket.io server that only validates the initial handshake but does not enforce per-namespace and per-room permission checks lets a low-privilege socket join a privileged namespace or another user's room.  _(merged 1 duplicate row(s))_
+- A socket.io server that only validates the initial handshake but does not enforce per-namespace and per-room permission checks lets a low-privilege socket join a privileged namespace or another user's room.  _(merged 1 duplicate row(s))_ _(unverified)_
   - **Disproof:** Refuted when join and leave handlers enforce per-namespace/per-room permission checks, and when privileged namespaces require a role that the handshake does not grant.
   - Sources: <https://socket.io/docs/v4/handling-cors/> · <https://cwe.mitre.org/data/definitions/940.html>
-- Passing the session credential in the WebSocket URL query string bypasses every header-stripping and referrer-policy control, because URLs are recorded verbatim in proxy, server and browser history even where the same token would never be logged as a header.  _(merged 1 duplicate row(s))_
+- Passing the session credential in the WebSocket URL query string bypasses every header-stripping and referrer-policy control, because URLs are recorded verbatim in proxy, server and browser history even where the same token would never be logged as a header.  _(merged 1 duplicate row(s))_ _(unverified)_
   - **Disproof:** The bypass is not demonstrated if the token never appears in any log, proxy record, history entry or telemetry field you can reach, or if the server rejects query-string credentials outright at the upgrade. It also does not apply where the credential is single-use, short-lived and audience-bound, because its theft then yields nothing beyond the attacker's own session.
   - Sources: <https://tailscale.com/docs/features/tailscale-serve> · <https://securitylabs.datadoghq.com/articles/claude-mcp-cve-2025-52882/>
-- When handshake or transport authentication is present but individual WebSocket frames carry no second authorization check, a connected client can submit privileged frames such as deleteUser or getSecretConfig that the server would reject if sent over HTTP.  _(merged 1 duplicate row(s))_
+- When handshake or transport authentication is present but individual WebSocket frames carry no second authorization check, a connected client can submit privileged frames such as deleteUser or getSecretConfig that the server would reject if sent over HTTP.  _(merged 1 duplicate row(s))_ _(unverified)_
   - **Disproof:** Refuted when every message is independently re-authorized against the session, or when the server rejects frames that request privileged actions without proof of entitlement.
   - Sources: <https://socket.io/docs/v4/handling-cors/> · <https://cwe.mitre.org/data/definitions/940.html>
 
```
