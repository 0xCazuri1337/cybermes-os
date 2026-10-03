# WebSocket Weaknesses

> surface: `web` · CWE: 1004 · OWASP: A04:2021
> maturity: **mature** — 12 items, 12 supported, 2 FP rules, 1 chains

The persistent channel inherits origin, authorisation and message-validation weaknesses of its upgrade request.

**Aliases:** websockets, ws, cross site websocket hijacking

## Technique

- **Because the browser handshake cannot carry an Authorization header, a WebSocket endpoint is only authenticated if the credential arrives through the Sec-WebSocket-Protocol value or an explicit post-connect authentication frame; test each channel by omitting it and observing whether the connection still receives application data.**  
  `high_confidence` · score 0.864 · disproved by: The channel test fails if a connection with no credential still receives application data, or if an invalid or unsigned token is accepted. It also fails to implicate this endpoint if the deployment terminates authentication in a reverse proxy that injects an identity header rather than in the socket handler, in which case the trust boundary to test is the proxy, not the frame.
  sources: <https://auth0.com/blog/cross-site-request-forgery-csrf/> · <https://developer.okta.com/blog/2020/10/28/secure-web-apps-websockets-nodejs>
- **If you try to do a redirect with context.redirect , the authentication flow will return an error.**  
  `high_confidence` · score 0.827 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "If you try to do a redirect with context.redirect , the authentication flow will return an".
  sources: <https://auth0.com/docs/secure/tokens/token-best-practices> · <https://securitylabs.datadoghq.com/articles/claude-mcp-cve-2025-52882/>
- **If you try to do a redirect with context.redirect , the authentication flow will return an error.**  
  `high_confidence` · score 0.827 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "If you try to do a redirect with context.redirect , the authentication flow will return an".
  sources: <https://auth0.com/docs/secure/tokens/token-best-practices> · <https://securitylabs.datadoghq.com/articles/claude-mcp-cve-2025-52882/>
- **Browser WebSocket behavior : Unlike traditional HTTP requests, WebSocket connections are not restricted by the browser's same-origin policy.**  
  `high_confidence` · score 0.7995 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Browser WebSocket behavior : Unlike traditional HTTP requests, WebSocket connections are n".
  sources: <https://auth0.com/docs/secure/tokens/token-best-practices> · <https://securitylabs.datadoghq.com/articles/claude-mcp-cve-2025-52882/>
- **Take into account that cookies will work just fine if the web app and the API are served from the same domain, so you might not need token based authentication.**  
  `high_confidence` · score 0.772 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Take into account that cookies will work just fine if the web app and the API are served f".
  sources: <https://auth0.com/docs/secure/tokens/token-best-practices> · <https://securitylabs.datadoghq.com/articles/claude-mcp-cve-2025-52882/>
- **Take into account that cookies will work just fine if the web app and the API are served from the same domain, so you might not need token based authentication.**  
  `high_confidence` · score 0.772 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Take into account that cookies will work just fine if the web app and the API are served f".
  sources: <https://auth0.com/docs/secure/tokens/token-best-practices> · <https://securitylabs.datadoghq.com/articles/claude-mcp-cve-2025-52882/>
- **For educational purposes, it's worth demonstrating an exploit proof of concept (PoC), if only to highlight the severity of this issue and the ease with which it could be exploited.**  
  `high_confidence` · score 0.772 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "For educational purposes, it's worth demonstrating an exploit proof of concept (PoC), if o".
  sources: <https://auth0.com/docs/secure/tokens/token-best-practices> · <https://securitylabs.datadoghq.com/articles/claude-mcp-cve-2025-52882/>

## Validation

- **A WebSocket that only pushes object identifiers has no data exposure to demonstrate, so a CSWSH or unauthenticated-socket report on such a channel is not substantiated until a test shows the frame itself carrying a field the reader could not otherwise obtain.**  
  `high_confidence` · score 0.839 · disproved by: The report is substantiated and this item disproved the moment a captured frame contains a real field: a full record, a permission-bearing value, or an internal identifier that resolves to data with no further authorization check. Also disprove it if the socket genuinely required authentication before any frame was emitted, since then there is no unauthenticated read to demonstrate.
  sources: <https://tailscale.com/docs/features/tailscale-serve> · <https://developer.okta.com/blog/2018/09/25/spring-webflux-websockets-react>

## Fp Rule

- **A WebSocket endpoint that only accepts a connection, echoes the caller's own frames back, and serves no other user's data is not cross-site WebSocket hijacking unless the handshake ALSO lacks Origin validation and the connection carries ambient credentials: hijack is the combination of cross-site connectability and session-authorised state.**  
  `high_confidence` · score 0.8355 · disproved by: It IS CSWSH if Origin is unvalidated AND the connection carries a session cookie or bearer token that lets the attacker read or mutate state belonging to the victim: another user's message, a private channel, an account action. Prove impact with a second identity, not with the attacker's own frame.
  sources: <https://www.zaproxy.org/docs/alerts/100025/> · <https://securitylabs.datadoghq.com/articles/claude-mcp-cve-2025-52882/>
- **A WebSocket endpoint that completes the upgrade for an arbitrary Origin is not Cross-Site WebSocket Hijacking until the server acts on an attacker-reachable frame or event; establishing the connection alone proves only that the handshake does not check Origin.**  
  `high_confidence` · score 0.809 · disproved by: The report is a false positive if the 101 is granted but every pushed frame and every send is refused without a credential the attacker lacks, or if the socket only ever emits public data. It is also a false positive if the state change required a second, attacker-independent authorization step that the attacker's frame could not satisfy.
  sources: <https://auth0.com/blog/confused-deputy-the-old-bug-that-ai-agents-keep-reintroducing/> · <https://developer.okta.com/blog/2022/07/08/spa-web-security-csrf-xss>

## Bypass

- **Passing the session credential in the WebSocket URL query string bypasses every header-stripping and referrer-policy control, because URLs are recorded verbatim in proxy, server and browser history even where the same token would never be logged as a header.**  
  `high_confidence` · score 0.9025 · disproved by: The bypass is not demonstrated if the token never appears in any log, proxy record, history entry or telemetry field you can reach, or if the server rejects query-string credentials outright at the upgrade. It also does not apply where the credential is single-use, short-lived and audience-bound, because its theft then yields nothing beyond the attacker's own session.
  sources: <https://auth0.com/docs/secure/tokens/token-best-practices> · <https://tailscale.com/docs/features/tailscale-serve>

## Chain Link

- **A replayed session cookie becomes a live push channel the moment a socket upgrade accepts that cookie, so session-theft impact must be restated as continuous unauthorized data reception rather than only what the stolen session could fetch on demand.**  
  `high_confidence` · score 0.8825 · disproved by: The chain does not hold if the socket upgrade independently requires a fresh proof the stolen cookie does not supply, if the server binds the session to a device or connection attribute the attacker did not capture, or if the pushed stream carries no data the attacker was not already entitled to. Absent a standing channel, the impact stays at the level session theft alone justifies.
  sources: <https://developer.okta.com/docs/concepts/session/> · <https://auth0.com/blog/confused-deputy-the-old-bug-that-ai-agents-keep-reintroducing/> · <https://auth0.com/blog/cross-site-request-forgery-csrf/>
