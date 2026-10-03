# open_redirect: observe, exercise, confirm

> goal: `Establish, exercise and confirm a open_redirect condition on an authorised target without relying on anyone else's data.`
> generated from `db/wks.db` — edit the rows, not this file

A three-step single-class chain for open_redirect. Each step is grounded in a gated knowledge item from this class rather than asserted, so the chain records what the corpus actually supports.

## Impact

Proves a open_redirect condition is present and reproducible, which is the minimum for a reportable finding.

## Sequence

### 1. Establish the precondition and record the baseline: A tenant's OAuth authorize endpoint redirecting to an arbitrary external origin is the third-party application's registered redirect_uri, not an open redirect in the tenant's own web application.

**Why it works:** Without a recorded baseline you cannot show what changed, and the later steps have nothing to compare against. Source context: The observation is a request to a first-party-looking Microsoft or Google authorize URL that returns a 302 to an attacker domain, which scans as a textbook open redirect on a trusted host. A distinct...

**Requires:** an authorised target with a reachable surface for open_redirect, and permission to record responses

**Backed by:** `open_redirect.fp_rule.registered_oauth_redirect_uri_is_not_a_webapp_open_redirect`

**This step fails if:** The arbitrary external destination is reachable with a client id the tenant never registered, or with a registered client id whose redirect_uri is fixed to the application's own origin, which shows the redirection value is attacker-supplied in the request rather than tenant-configured.

### 2. Exercise it against the target and capture the raw request and response: An open redirect on the OAuth authorize endpoint chains into authorization-code theft when redirect_uri is accepted from user input instead of an allowlist.

**Why it works:** In this class the corpus records no numeric evidence score for this item, so treat it as a lead to exercise rather than a proven behaviour, which is why it is worth exercising directly. An exercise without a captured raw request and response is an opinion.

**Requires:** two accounts or two privilege levels you control, and a repeating request you can diff

**Backed by:** `open_redirect.chain_link.oauth_authorize_code_interception`

**This step fails if:** If the authorize endpoint rejects or ignores an unregistered redirect_uri and the Location field stays on an allowlisted origin, the chain does not form and the finding is a normal post-login navigation.

### 3. Confirm the result reproduces and crosses the boundary you claim, using only accounts you own: A 301/302 whose Location is a relative path, a protocol-relative same-origin path, or an absolute URL whose authority equals the request Host is not an open redirect: the browser cannot be moved off the origin, so there is no phishing pivot and no token or...

**Why it works:** Here the corpus records no numeric evidence score for this item, so treat it as a lead to exercise rather than a proven behaviour, and confirmation is what separates a reportable finding from a theoretical one. Using only your own accounts keeps the test inside authorised scope while still proving the boundary is missing.

**Requires:** the captured evidence from the previous step, and a second run proving it is not a one-off

**Backed by:** `open_redirect.fp_rule.redirect_to_relative_path_on_same_origin_is_not_open`

**This step fails if:** The redirect IS open if the authority differs after full parsing - userinfo tricks that put an attacker host in the userinfo field, backslash or tab/CR injection that browsers normalise into an authority, punycode/IDN homographs, an open redirector the app itself chains to, or a relative path the front-end router resolves against an attacker-controlled protocol/host. Resolve the Location through a real browser parser before accepting it as same-origin.
