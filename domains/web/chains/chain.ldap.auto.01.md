# ldap: observe, exercise, confirm

> goal: `Establish, exercise and confirm a ldap condition on an authorised target without relying on anyone else's data.`
> generated from `db/wks.db` — edit the rows, not this file

A three-step single-class chain for ldap. Each step is grounded in a gated knowledge item from this class rather than asserted, so the chain records what the corpus actually supports.

## Impact

Proves a ldap condition is present and reproducible, which is the minimum for a reportable finding.

## Sequence

### 1. Establish the precondition and record the baseline: A widened or non-empty result set for a filter that should have matched nothing, carrying directory attributes the application never renders on a normal miss, is the observable signature of a request-controlled filter structure.

**Why it works:** Without a recorded baseline you cannot show what changed, and the later steps have nothing to compare against. Source context: Signal, not proof. Send a value that cannot match any real object, for example a random high-entropy string, and record the application's normal empty-result path. The variant appends a boolean...

**Requires:** an authorised target with a reachable surface for ldap, and permission to record responses

**Backed by:** `ldap.signal.result-set-widens-and-directory-attributes-appear`

**This step fails if:** Show that the application's own empty-result path already returns a populated template, or that the attributes in the response are rendered by the frontend from data it fetched on a separate call. Then the widened response is application behaviour rather than directory-side filter evaluation.

### 2. Exercise it against the target and capture the raw request and response: Where LDAP signing is not required and channel binding is at its default, a network position between an application and its domain controller can obtain usable bind credential material, making the impact credential theft rather than enumeration.

**Why it works:** In this class the corpus records no numeric evidence score for this item, so treat it as a lead to exercise rather than a proven behaviour, which is why it is worth exercising directly. An exercise without a captured raw request and response is an opinion.

**Requires:** two accounts or two privilege levels you control, and a repeating request you can diff

**Backed by:** `ldap.impact.unenforced-signing-exposes-bind-credential-material`

**This step fails if:** Show the domain controllers enforce LDAP signing and channel binding at their enforcing settings with auditing in place, so an intercepted bind is rejected at the DC rather than yielding credential material. Then the impact is bounded and the critical severity rating is wrong.

### 3. Confirm the result reproduces and crosses the boundary you claim, using only accounts you own: A search filter that errors or returns an identical failure for EVERY input, including well-formed values the application has matched before, is an application type-confusion or bind-failure bug and not LDAP injection.

**Why it works:** Here the corpus records no numeric evidence score for this item, so treat it as a lead to exercise rather than a proven behaviour, and confirmation is what separates a reportable finding from a theoretical one. Using only your own accounts keeps the test inside authorised scope while still proving the boundary is missing.

**Requires:** the captured evidence from the previous step, and a second run proving it is not a one-off

**Backed by:** `ldap.fp.filter-error-on-every-input-is-app-type-confusion`

**This step fails if:** Show a known-good value and a random non-matching value produce the SAME error, status, and timing as a metacharacter-bearing value, with no differential in any response field. Then there is no filter-structure control and the injection claim is unsupported.
