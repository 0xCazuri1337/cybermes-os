# Methodology — Authorization / Access Control

> Generated 2026-10-01T18:41:23Z. Competency id: `authorization`.
> Aligned with `CONTROL/CONTROL.md` §4 (separation of claims) and
> `CONTROL/rules.md` R2 (scanner output is an observation, not proof).

## What this establishes

Whether the server enforces, on each request, who may act on which object. Client-side checks and hidden UI are not enforcement.

## Procedure

 1. **Identify the object** — Every id the request carries: path, query, body, header. Note which ones name a resource
and which name a user.
 2. **Identify the owner** — Whose resource it is. Establish with a legitimate request from the owning account, not
by guessing.
 3. **Identify the attacker** — A second, lower-privileged account. A single account cannot demonstrate cross-user
access.
 4. **Capture the authorized request** — Exact request, headers, cookies, and body from the owner. This is the control.
 5. **Vary only the object identifier** — Change nothing else. Two changed variables cannot attribute a result.
 6. **Replay under the attacker session** — Same request, attacker's credentials, the other's object id.
 7. **Compare** — Status, body, side effects, and any object identifier returned. A 200 with the same
shape is the finding; a 403 is the negative control.
 8. **Check the enforcement point** — Is the decision server-side per request, or inferred from what the UI offered? A check
that lives in the client is not enforcement.
 9. **Test vertical access** — Lower privilege attempting an administrative action. Distinct failure mode from
horizontal.
10. **Test presence-disclosure separately** — Whether the resource *exists* is a different finding from whether it is readable. Do not
merge them.
11. **Verify impact safely** — Read-only where possible. Establish what is exposed, do not exercise it destructively.
12. **Collect reproducible evidence** — Both requests, both responses, both identities.

## What would disprove the hypothesis

A finding here is wrong if any of the following holds. Check them before
reporting, and record which one applied.

- The response differs only in fields the object does not own.
- The server rejects cross-user access with a consistent, enforced decision.
- The identifier is not resolvable to another principal's object at all.

## Gates before this becomes a finding

- reproducible across repeats
- attributable to the identifier alone
- impact demonstrated, not inferred

## Authority

`CONTROL/CONTROL.md` outranks this page. If this procedure suggests an action
outside the recorded scope, the scope wins — see `CONTROL/state.md`.

Tools are sensors. A tool that reports a finding here has satisfied none of
the gates above by itself.
