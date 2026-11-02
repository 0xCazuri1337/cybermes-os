# Methodology — WebSocket Weaknesses

> Derived from 12 verified items. Regenerate with `python -m wks.methodgen --class websocket --apply`. Do not hand-edit: this file is a projection of the evidence, and edits are lost on the next cycle.

**Surface.** The persistent channel inherits origin, authorisation and message-validation weaknesses of its upgrade request.

**References.** CWE-1004 · A04:2021

## Preconditions

_No verified prerequisite items yet._ Derived from evidence only, so this section is empty rather than plausible.


## Reconnaissance signals

_No verified signal items yet._ Derived from evidence only, so this section is empty rather than plausible.


## 1. Test sequence

_Concrete mutations to try. Each is written to be executable, not to be a description of the vulnerability._

**A WebSocket handshake that authenticates the connection through an ambient session cookie, but never compares the Origin request header against an allow-list, lets any malicious page open a real-time channel on behalf of an authenticated victim.**

Mechanism: the handshake is an ordinary HTTP upgrade request that still carries cookies, so the browser attaches the victim's session automatically. Because the connection is then established without an origin gate, the malicious page receives the same channel the victim's page would have. How to apply it: record the handshake transcript (request with victim-origin, Origin header, response 101) and replay the same upgrade from a foreign origin to confirm the server never compares Origin. Boundary: this is not exploitable when the credential is a bearer token in the URL query or a per-connection signature the attacker cannot forge, and it is not a CSRF-style vuln when the server enforces an origin allow-list at upgrade time.

- *Disproof:* Refuted when a foreign-origin upgrade is answered 403 or 401, or when the handshake requires a per-connection secret the attacker's page cannot supply; also refuted when the endpoint independently re-authorizes every message after the handshake.
- *Evidence:* high_confidence — [portswigger.net](https://portswigger.net/web-security/cross-site-websocket-hijacking); [rfc-editor.org](https://www.rfc-editor.org/rfc/rfc6455.txt); [w3.org](https://www.w3.org/TR/websockets/)

**A live socket.io endpoint can be version-fingerprinted from its handshake, so a hunter must compare the observed version against released advisories rather than assuming a framework version is safe.**

Mechanism: the socket.io handshake and transport negotiation reveal a version string. Fingerprinting the version lets a hunter check that release's known advisories (including ReDoS in websocket-extensions and DoS in the ws module) before assuming safety. How to apply it: send a polling handshake and record the version, then cross-reference the released advisory list for that release. Boundary: not reliable when a CDN or reverse proxy normalizes the version string, and the fingerprint is only as current as the advisory database used.

- *Disproof:* Falsified if the handshake does not expose a version that can be matched, or if the deployed version corresponds to a patched release whose advisory has been updated to exclude the observed flaw.
- *Evidence:* high_confidence — [nvd.nist.gov](https://nvd.nist.gov/vuln/search/results?form_type=CMP&results_type=overview&query_text=CVE-2020-7662); [portswigger.net](https://portswigger.net/web-security/cross-site-websocket-hijacking)

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

**A page or config string containing wss:// is not by itself evidence that the WebSocket channel is protected, because confidentiality and integrity come from actually running the handshake over TLS end to end rather than from the scheme label appearing in source.**

Mechanism: A page or config string containing wss:// is not by itself evidence that the WebSocket channel is protected, because confidentiality and integrity come from actually running the handshake over TLS end to end rather than from the scheme label appearing in source. How to apply it in the field: treat this as the fp_rule it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable. Boundary of the rule: It IS protected when the handshake reaches wss:// and the transport negotiates TLS with a certificate the client validates; it is not protected when a wss:// literal is present but a proxy terminates or downgrades the upgrade, or when the code builds the URL from an attacker-controlled scheme value so the same code path can be handed a ws:// target.

- *Disproof:* It IS protected when the handshake reaches wss:// and the transport negotiates TLS with a certificate the client validates; it is not protected when a wss:// literal is present but a proxy terminates or downgrades the upgrade, or when the code builds the URL from an attacker-controlled scheme value so the same code path can be handed a ws:// target.
- *Evidence:* high_confidence — [rfc-editor.org](https://www.rfc-editor.org/rfc/rfc6455.txt); [w3.org](https://www.w3.org/TR/websockets/)

**A WebSocket endpoint that only accepts a connection, echoes the caller's own frames back, and serves no other user's data is not cross-site WebSocket hijacking unless the handshake ALSO lacks Origin validation and the connection carries ambient credentials: hijack is the combination of cross-site connectability and session-authorised state.**

Two conditions, both required. Condition one is the handshake: ZAP's rule fires when the server accepts the Upgrade with a modified Origin, so an open handshake is only half the finding. Condition two is the state: Datadog's analysis of a real WebSocket authentication bypass shows why, because WebSocket connections are not restricted by the browser's same-origin policy, so cross-site reachability alone hands an attacker the socket and the damage comes entirely from what that socket can then read or mutate on the victim's behalf. On an echo endpoint both halves are empty: nothing is validated and nothing is exposed. Confirm by driving the channel with a second identity and asking whether any frame belonging to someone else ever arrives. Hunting value: this removes the echo, debug-console, presence and telemetry endpoints, which respond 101 to any Origin and are the bulk of cross-origin handshake alerts.

- *Disproof:* It IS CSWSH if Origin is unvalidated AND the connection carries a session cookie or bearer token that lets the attacker read or mutate state belonging to the victim: another user's message, a private channel, an account action. Prove impact with a second identity, not with the attacker's own frame.
- *Evidence:* high_confidence — [securitylabs.datadoghq.com](https://securitylabs.datadoghq.com/articles/claude-mcp-cve-2025-52882/); [zaproxy.org](https://www.zaproxy.org/docs/alerts/100025/)

## 4. Known bypasses

_Filters and controls that have defeated the techniques above. Treat these as the reason a naive test fails, not as proof of safety._

**A reverse proxy that authenticates sibling HTTP routes can leave the WebSocket upgrade path unauthenticated, so an attacker reaches the authenticated WS endpoint by upgrading the request while the same endpoint returns 401 for normal HTTP.**

Mechanism: the proxy terminates TLS and forwards the upgrade to the backend. If the auth layer is attached only to the HTTP router, the Upgrade request never passes through it. The finding is demonstrated by sending a normal authenticated HTTP request (401) and a matching Upgrade request (101 or 200) from the same session. How to apply it: probe one endpoint with both methods and diff the status. Boundary: not a bypass when the proxy applies the identical authentication rule to upgrade requests as to normal routes, or when every message after the handshake is independently re-authorized regardless of the connection's pre-auth state.

- *Disproof:* Refuted when the proxy applies the identical authentication rule to upgrade requests as to normal routes, or when every message after the handshake is independently re-authorized regardless of the connection's pre-auth state.
- *Evidence:* high_confidence — [nginx.org](https://nginx.org/en/docs/http/ngx_http_proxy_module.html); [rfc-editor.org](https://www.rfc-editor.org/rfc/rfc6455.txt)

## 5. Chaining

_How this class escalates when combined with others. Each step is anchored to a promoted item._

**CSWSH alone yields a privileged real-time channel; combined with missing per-message authentication or in-flight frame injection, that channel escalates to cross-tenant data exfiltration or account takeover.**

Mechanism: Phase 1 is CSWSH - the attacker page opens a cookie-authenticated socket and receives the victim's real-time stream. Phase 2 adds a missing control: without per-message auth, the attacker can also push privileged frames, not just receive. Phase 3 adds in-flight tampering so the attacker rewrites values (price, quantity, amount, user id) inside legitimate frames. How to apply it: capture the victim stream, send a privileged frame, then tamper with a numeric field and confirm the server acts on it. Boundary: the chain only holds when each phase's control is actually missing; prove each link with its own request.

- *Disproof:* The chain is unproven if the hijacked channel carries no data the attacker is not already entitled to read, if per-message auth stops every privileged frame, or if the server rejects attacker-controlled payload values before acting.
- *Evidence:* high_confidence — [cwe.mitre.org](https://cwe.mitre.org/data/definitions/940.html); [portswigger.net](https://portswigger.net/web-security/cross-site-websocket-hijacking)

## Impact

_No verified impact items yet._ Derived from evidence only, so this section is empty rather than plausible.


## Coverage gap

These stages have no verified evidence and are therefore absent above: Preconditions, Reconnaissance signals, Impact.
A procedure with a missing validation stage is not safe to act on — it produces findings rather than proofs.

---

*Generated from the evidence base. Where this file and the database disagree, the database is correct.*
