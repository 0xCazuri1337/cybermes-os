# Methodology — SSRF (Server-Side Request Forgery)

> Generated 2026-10-01T18:41:23Z. Competency id: `ssrf`.
> Aligned with `CONTROL/CONTROL.md` §4 (separation of claims) and
> `CONTROL/rules.md` R2 (scanner output is an observation, not proof).

## What this establishes

Whether the server can be induced to make a request to a destination the attacker chooses.

## Procedure

 1. **Find server-side fetch points** — URL previews, webhooks, imports, PDF renderers, image proxies, and any 'fetch this URL'
affordance.
 2. **Test the basic case** — A URL you control, confirming the server really made the request.
 3. **Determine protocol handling** — file://, gopher://, dict:// and redirects to them. Many filters check the scheme but
follow the redirect.
 4. **Test redirect following** — A 302 from your host to an internal address bypasses an allowlist that only validated
the first hop.
 5. **Test DNS rebinding** — Where a name resolves to an internal address on the second lookup.
 6. **Test header smuggling via the fetch** — Whether the server forwards attacker-chosen headers to the internal service.
 7. **Establish reachability of the internal target** — The response often proves it.
 8. **Assess impact honestly** — Metadata access, internal service reach, and blind timing are different severities.
State which you demonstrated.

## What would disprove the hypothesis

A finding here is wrong if any of the following holds. Check them before
reporting, and record which one applied.

- The destination is validated after resolution, not before.
- Redirects are not followed to a different scheme or address space.
- The request never reaches a controllable destination and no timing signal exists.

## Gates before this becomes a finding

- server-side request proven, not inferred
- internal reachability demonstrated with minimal impact

## Authority

`CONTROL/CONTROL.md` outranks this page. If this procedure suggests an action
outside the recorded scope, the scope wins — see `CONTROL/state.md`.

Tools are sensors. A tool that reports a finding here has satisfied none of
the gates above by itself.
