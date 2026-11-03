# Methodology — Reconnaissance

> Generated 2026-10-01T18:41:23Z. Competency id: `recon`.
> Aligned with `CONTROL/CONTROL.md` §4 (separation of claims) and
> `CONTROL/rules.md` R2 (scanner output is an observation, not proof).

## What this establishes

Establishing the actual attack surface before deciding what to test. Everything downstream depends on this being right.

## Procedure

 1. **Scope first** — Confirm what is in scope before enumerating. Enumerating out-of-scope assets is itself a
violation.
 2. **Enumerate subdomains** — Passive sources first, then resolve. Record only live hosts.
 3. **Resolve and probe** — Distinguish a resolved name from a live host. A wildcard DNS record is the classic false
positive.
 4. **Enumerate ports and services** — Note the services, versions, and anything unexpected.
 5. **Crawl and collect URLs** — Include parameters. Parameterised URLs are where testing starts.
 6. **Extract JavaScript** — JS is where endpoints, keys, routes and internal hostnames live.
 7. **Identify technologies** — Frameworks, versions, and the security posture that follows from them.
 8. **Identify authentication flows** — Login, registration, reset, and SSO endpoints.
 9. **Map the object model** — What things exist, how they reference each other, and who owns them. This is what makes
IDOR testing possible.
10. **Prioritise** — Rank by exposure × impact × novelty. Test the interesting thing first.

## What would disprove the hypothesis

A finding here is wrong if any of the following holds. Check them before
reporting, and record which one applied.

- The host does not resolve or does not serve HTTP.
- The subdomain is a wildcard record pointing at a parked host.

## Gates before this becomes a finding

- scope confirmed before enumeration
- live hosts distinguished from resolved names

## Authority

`CONTROL/CONTROL.md` outranks this page. If this procedure suggests an action
outside the recorded scope, the scope wins — see `CONTROL/state.md`.

Tools are sensors. A tool that reports a finding here has satisfied none of
the gates above by itself.
