# Methodology — CSRF

> Generated 2026-10-01T18:41:23Z. Competency id: `csrf`.
> Aligned with `CONTROL/CONTROL.md` §4 (separation of claims) and
> `CONTROL/rules.md` R2 (scanner output is an observation, not proof).

## What this establishes

Whether the server accepts state-changing requests that it did not intend to receive from a third-party context.

## Procedure

 1. **Determine the cookie attributes** — SameSite (and whether it is Lax, Strict or None), Secure, and whether the app relies on
a custom header.
 2. **Identify state-changing endpoints** — Including ones not exposed in the UI — the hidden ones are where CSRF lives.
 3. **Check the token requirement** — Per-session, per-request, signed, and rotated. A static token shared across users is not
a CSRF defence.
 4. **Check the Origin/Referer enforcement** — And whether it applies to every state-changing method, not only POST.
 5. **Check JSON endpoints specifically** — A Content-Type of application/json forces a preflight in modern browsers, which is a
real defence — verify the server actually requires it.
 6. **Test the logout CSRF variant** — Often unguarded and low-noise to demonstrate.
 7. **Assess the real impact** — CSRF severity comes entirely from the action — a forced logout is not a forced password
change.

## What would disprove the hypothesis

A finding here is wrong if any of the following holds. Check them before
reporting, and record which one applied.

- SameSite is enforced on the session cookie for every state-changing request.
- A per-request token bound to the session is required and validated.
- The endpoint rejects non-preflighted content types.

## Gates before this becomes a finding

- action is genuinely state-changing
- browser-forced nature demonstrated, not simulated with curl alone

## Authority

`CONTROL/CONTROL.md` outranks this page. If this procedure suggests an action
outside the recorded scope, the scope wins — see `CONTROL/state.md`.

Tools are sensors. A tool that reports a finding here has satisfied none of
the gates above by itself.
