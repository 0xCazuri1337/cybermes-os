---
name: websocket-hunting
description: Use when hunting WebSocket Weaknesses in a web target. Ordered prerequisites, signals, techniques, validation bar and false-positive rules.
---

# WebSocket Weaknesses — hunting skill

<!-- GENERATED from db/wks.db by wks/skillgen.py. DO NOT HAND-EDIT.
     Edit the rows (or ingest better research) and re-run:
     python -m wks.skillgen -->

> surface `web` · CWE 1004 · OWASP A04:2021
> evidence: 6 items, 6 supported, 2 FP rules, 0 chains
> maturity: **researching** — missing: items, chain

The persistent channel inherits origin, authorisation and message-validation weaknesses of its upgrade request.

**Also called:** websockets, ws, cross site websocket hijacking


## Techniques (what to change)

- Because the browser handshake cannot carry an Authorization header, a WebSocket endpoint is only authenticated if the credential arrives through the Sec-WebSocket-Protocol value or an explicit post-connect authentication frame; test each channel by omitting it and observing whether the connection still receives application data.
  - **Disproof:** The channel test fails if a connection with no credential still receives application data, or if an invalid or unsigned token is accepted. It also fails to implicate this endpoint if the deployment terminates authentication in a reverse proxy that injects an identity header rather than in the socket handler, in which case the trust boundary to test is the proxy, not the frame.
  - Sources: <https://auth0.com/blog/cross-site-request-forgery-csrf/> · <https://developer.okta.com/blog/2020/10/28/secure-web-apps-websockets-nodejs>

## Validation bar (how to prove it)

- A WebSocket that only pushes object identifiers has no data exposure to demonstrate, so a CSWSH or unauthenticated-socket report on such a channel is not substantiated until a test shows the frame itself carrying a field the reader could not otherwise obtain.
  - **Disproof:** The report is substantiated and this item disproved the moment a captured frame contains a real field: a full record, a permission-bearing value, or an internal identifier that resolves to data with no further authorization check. Also disprove it if the socket genuinely required authentication before any frame was emitted, since then there is no unauthenticated read to demonstrate.
  - Sources: <https://tailscale.com/docs/features/tailscale-serve> · <https://developer.okta.com/blog/2018/09/25/spring-webflux-websockets-react>

## False-positive rules (when to reject it)

- A WebSocket endpoint that only accepts a connection, echoes the caller's own frames back, and serves no other user's data is not cross-site WebSocket hijacking unless the handshake ALSO lacks Origin validation and the connection carries ambient credentials: hijack is the combination of cross-site connectability and session-authorised state.
  - **Disproof:** It IS CSWSH if Origin is unvalidated AND the connection carries a session cookie or bearer token that lets the attacker read or mutate state belonging to the victim: another user's message, a private channel, an account action. Prove impact with a second identity, not with the attacker's own frame.
  - Sources: <https://www.zaproxy.org/docs/alerts/100025/> · <https://securitylabs.datadoghq.com/articles/claude-mcp-cve-2025-52882/>
- A WebSocket endpoint that completes the upgrade for an arbitrary Origin is not Cross-Site WebSocket Hijacking until the server acts on an attacker-reachable frame or event; establishing the connection alone proves only that the handshake does not check Origin.
  - **Disproof:** The report is a false positive if the 101 is granted but every pushed frame and every send is refused without a credential the attacker lacks, or if the socket only ever emits public data. It is also a false positive if the state change required a second, attacker-independent authorization step that the attacker's frame could not satisfy.
  - Sources: <https://auth0.com/blog/confused-deputy-the-old-bug-that-ai-agents-keep-reintroducing/> · <https://developer.okta.com/blog/2022/07/08/spa-web-security-csrf-xss>

## Defence bypasses

- Passing the session credential in the WebSocket URL query string bypasses every header-stripping and referrer-policy control, because URLs are recorded verbatim in proxy, server and browser history even where the same token would never be logged as a header.
  - **Disproof:** The bypass is not demonstrated if the token never appears in any log, proxy record, history entry or telemetry field you can reach, or if the server rejects query-string credentials outright at the upgrade. It also does not apply where the credential is single-use, short-lived and audience-bound, because its theft then yields nothing beyond the attacker's own session.
  - Sources: <https://auth0.com/docs/secure/tokens/token-best-practices> · <https://tailscale.com/docs/features/tailscale-serve>

## Chaining opportunities

- A replayed session cookie becomes a live push channel the moment a socket upgrade accepts that cookie, so session-theft impact must be restated as continuous unauthorized data reception rather than only what the stolen session could fetch on demand.
  - **Disproof:** The chain does not hold if the socket upgrade independently requires a fresh proof the stolen cookie does not supply, if the server binds the session to a device or connection attribute the attacker did not capture, or if the pushed stream carries no data the attacker was not already entitled to. Absent a standing channel, the impact stays at the level session theft alone justifies.
  - Sources: <https://developer.okta.com/docs/concepts/session/> · <https://auth0.com/blog/confused-deputy-the-old-bug-that-ai-agents-keep-reintroducing/> · <https://auth0.com/blog/cross-site-request-forgery-csrf/>

---
Full class document: `skills/Web/websocket/EVIDENCE.md` · retrieve more with `python -m wks.cli search "<query>" --class-id websocket`
