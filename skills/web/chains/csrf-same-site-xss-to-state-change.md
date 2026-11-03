# Same-site sibling script execution to forged state change on the real origin

> goal: `Use script execution on a sibling domain of the target site to defeat SameSite and the CSRF token, then commit a state-changing action on the real origin that the server treats as legitimate.`
> generated from `db/wks.db` — edit the rows, not this file

SameSite is site-scoped and CSRF tokens are readable by same-site script, so a single injection on one host in the registrable domain defeats both controls for the primary application.

## Impact

Any state change the logged-in user can perform, issued from the real origin so it passes origin, referer and token validation, with the finding attributed to the wrong host.

## Sequence

### 1. Achieve JavaScript execution on any sibling host within the target's registrable domain.

**Why it works:** A cross-origin request can still be same-site, and any vulnerability enabling arbitrary JavaScript execution can be abused to bypass site-based defenses on other domains belonging to the same site, so the session cookie is still attached to the forged request.

**Backed by:** `csrf.bypass.samesite_restriction_defeated_by_same_site_xss`

**This step fails if:** The site has no sibling subdomains, or every subdomain is separately trusted and none carries reflected or stored script execution, and no client-side redirect reflects attacker input into a navigation on the target site.

### 2. From that same-site context, read the CSRF token out of the real origin's DOM and submit the state-changing request with it.

**Why it works:** OWASP states XSS can defeat all CSRF mitigation techniques, and the token requirement only holds while the attacker cannot read the value, so a token read from the same-site context satisfies condition three that would otherwise hold the attack.

**Backed by:** `csrf.prerequisite.three_conditions_constitute_exploitability`

**This step fails if:** Any one of the three conditions is absent at the endpoint: there is no attacker-interesting state change, the session is bound to something the browser will not auto-send cross-site (a custom header the SOP blocks), or the request requires a parameter value the attacker cannot read or guess (a current password, a server-stored one-time code, a fresh synchronizer token bound to the victim session).
