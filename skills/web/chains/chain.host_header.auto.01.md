# host_header: observe, exercise, confirm

> goal: `Establish, exercise and confirm a host_header condition on an authorised target without relying on anyone else's data.`
> generated from `db/wks.db` — edit the rows, not this file

A three-step single-class chain for host_header. Each step is grounded in a gated knowledge item from this class rather than asserted, so the chain records what the corpus actually supports.

## Impact

Proves a host_header condition is present and reproducible, which is the minimum for a reportable finding.

## Sequence

### 1. Establish the precondition and record the baseline: A Host header whose value length exactly equals the server's configured maximum produces a one-byte NULL overwrite in the server's own parser, which is a length-check defect and not host-header routing or cache steering.

**Why it works:** Without a recorded baseline you cannot show what changed, and the later steps have nothing to compare against. Source context: The observation is a crash, a reset, or corrupted state on a device when the Host header is sent at exactly the configured maximum length, which is commonly written up as host-header handling...

**Requires:** an authorised target with a reachable surface for host_header, and permission to record responses

**Backed by:** `host_header.fp_rule.host_value_length_equal_to_configured_max_is_a_length_check_bug`

**This step fails if:** Changing only the Host header to another valid hostname changes the response body, an absolute URL, or the cache entry served, which shows the field is being consumed for routing or keying rather than only for length validation.

### 2. Exercise it against the target and capture the raw request and response: When a front-end injects X-Forwarded-Host to preserve the original host through a load balancer, an attacker can inject the payload through that header and bypass validation applied to Host, because the framework resolves the override header instead of the...

**Why it works:** In this class the corpus records no numeric evidence score for this item, so treat it as a lead to exercise rather than a proven behaviour, which is why it is worth exercising directly. An exercise without a captured raw request and response is an opinion.

**Requires:** two accounts or two privilege levels you control, and a repeating request you can diff

**Backed by:** `host_header.technique.x_forwarded_host_overrides_a_validated_host_header`

**This step fails if:** The claim is wrong, and the override header is inert, if the response is byte-identical to the clean baseline with the override present, meaning the framework ignored it; the only change is in a header or body region no browser or downstream consumer uses to make a security decision; or the deployment genuinely terminates at a proxy that strips every override header before the framework sees it, which must be shown by observing that the attacker value never reaches any application-controlled output. Validate by diffing, not by the presence of the header in the request.

### 3. Confirm the result reproduces and crosses the boundary you claim, using only accounts you own: A Host or X-Forwarded-Host value reflected unencoded into the response markup, with no shared cache in front of the page, is not a finding on its own: no attacker can force a victim's browser to send an incorrect host in a useful manner.

**Why it works:** Here the corpus records no numeric evidence score for this item, so treat it as a lead to exercise rather than a proven behaviour, and confirmation is what separates a reportable finding from a theoretical one. Using only your own accounts keeps the test inside authorised scope while still proving the boundary is missing.

**Requires:** the captured evidence from the previous step, and a second run proving it is not a one-off

**Backed by:** `host_header.fp_rule.reflected_host_without_a_cache_is_not_a_client_exploitable_finding`

**This step fails if:** The rule is wrong, and there is a real finding, if: a shared cache serves the poisoned response to a second, different session (then it is cache poisoning, and cache_deception.technique.unkeyed_reflection_below_a_dynamic_segment_becomes_a_shared_key is the right class); or the reflected value is consumed server-side, changing an authz decision, a Location header, or a generated absolute URL even in a single-request replay; or the reflection reaches an HTTP response header that the browser treats as navigable (Location, Link, Refresh). Same-request reflection into HTML markup alone never qualifies.
