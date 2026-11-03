# Host override header poisoning to password reset token theft

> goal: `account_takeover`
> generated from `db/wks.db` — edit the rows, not this file

A reset link built from an attacker-supplied override-header host delivers the victim's reset token to the attacker, who redeems it for full account takeover.

## Impact

The impact is total account compromise reached without any authentication, credential guessing, or user interaction beyond requesting their own password reset, and a shared cache in front of the response lets one poisoned response harvest several victims rather than one.

## Sequence

### 1. Establish that an override header value supplied by the client is resolved in place of Host, which is the mechanism in host_header.technique.x_forwarded_host_overrides_a_validated_host_header.

**Why it works:** A front-end may inject X-Forwarded-Host to preserve the original host through a load balancer, and many frameworks refer to that header when it is present, even where none was injected by a proxy.

**Requires:** An intercepting proxy able to hold Host fixed while varying the override header

### 2. Confirm the application builds the password-reset absolute link from that resolved host value rather than from a server-side configured base URL.

**Why it works:** If a web application uses the host header to construct absolute links, an attacker may be able to manipulate the host header to force the construction of malicious links.

**Requires:** Control of one test account to request a reset and inspect the emitted message

### 3. Request a reset for the victim with the attacker-controlled override header and capture the reset token from the attacker-received link.

**Why it works:** The reset email is generated server-side during the victim's unauthenticated request, so the emitted link carries the attacker's authority without any prior access.

**Requires:** A victim mailbox or an attacker-hosted endpoint that logs inbound tokens

### 4. Redeem the captured token against the legitimate application to reset the victim's password, then verify the session as the victim.

**Why it works:** The token is the application's own authorisation artefact; once the attacker holds it the reset completes on the real origin with no further precondition.

**Requires:** A live, unredeemed reset token
