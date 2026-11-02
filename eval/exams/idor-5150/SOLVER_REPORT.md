# IDOR Assessment — InternalOps/1.7

**Target:** http://127.0.0.1:8771 (Python `BaseHTTP/0.6 Python/3.14.7`)
**Scope:** authorised assessment of a locally-generated, deliberately-vulnerable test app
**Date:** 2026-10-02

---

## 1. Attack surface map

| Method | Path | Auth | Behaviour |
|---|---|---|---|
| GET | `/` | none | HTML landing page. Renders `signed in as <user>` (or `anonymous`) and one link: `/api/v2/policy/` |
| POST | `/login` | none | Body `user=<name>` (urlencoded), **no password**. Sets cookie `sid=<16 hex>` (`Path=/; HttpOnly; SameSite=None`). Unknown user → `401 {"error":"invalid credentials"}` |
| GET | `/api/v2/policy/` | session required | Collection route. Returns only the caller's own records |
| GET | `/api/v2/policy/<ref>` | session required | **Item route. No ownership check.** |

Identifier format: `A-<4 digits>`. Known records `A-1001` … `A-1004`.

**Negative results from endpoint discovery** — all returned `404 {"error":"not found"}` (i.e. the router does not implement them; this is *not* an authorization signal): `/api/v2/policy` (no trailing slash), `/api/v2/`, `/api/`, `/api/v1/policy/`, `/api/v2/users`, `/api/v2/user/alice`, `/api/v2/admin`, `/api/v2/admin/`, `/api/v2/me`, `/api/v2/session`, `/api/v2/whoami`, `/api/v2/config`, `/api/v2/health`, `/api/v2/backup`, `/api/v2/export`, `/api/v2/audit`, `/api/v2/logs`, `/api/v2/search`, `/admin`, `/console`, `/debug`, `/robots.txt`, `/sitemap.xml`, and `/api/v2/policy/A-1001/{owner,amount}`.

### Trust boundary model

The application has one clear confidentiality boundary: a policy record belongs to exactly one `owner`, and only that owner (plus presumably an admin role) may read it.

The application **enforces this boundary at the collection route and omits it at the item route.** That asymmetry is the whole finding:

- `GET /api/v2/policy/` — filters by session identity.
- `GET /api/v2/policy/<ref>` — filters by *authentication only* (`302 → /login` when there is no valid session), then returns the record regardless of who owns it.

The route decides access, not the client. Nothing in the HTML or JSON hints the item route should be restricted, so a user following a leaked or guessed link has no signal that they crossed a boundary.

---

## 2. Findings

### FINDING 1 — Insecure Direct Object Reference on the item route: any authenticated user can read any other user's policy record (Broken Object Level Authorization)

**Severity: High.** Broken access control on a single endpoint. Full confidentiality loss of every policy record in the system for any authenticated (non-admin) account.

**Root cause:** the item route authenticates the caller but never compares the record's `owner` against the caller's session identity. The ownership check exists — but only on the collection route.

#### Evidence

**Step 1 — establish the baseline. bob's collection shows only bob's own record:**

```http
POST /login HTTP/1.1
Host: 127.0.0.1:8771
Content-Type: application/x-www-form-urlencoded

user=bob
```
```http
HTTP/1.1 200 OK
Content-Type: application/json
set-cookie: sid=fc128ebbe486682d; Path=/; HttpOnly; SameSite=None

{"ok": true}
```
```http
GET /api/v2/policy/ HTTP/1.1
Host: 127.0.0.1:8771
Cookie: sid=fc128ebbe486682d
```
```http
HTTP/1.1 200 OK
Content-Type: application/json

{"records": [{"ref": "A-1002", "amount": 910, "status": "settled"}]}
```

bob is shown **one** record, and it is bob's own. The application has, by its own behaviour, told bob that he has exactly one policy record. The application also discloses the owner identity on the item route (`"owner": "bob"`), which confirms the ownership model exists and is populated.

**Step 2 — bob reads a record the application never showed him, owned by alice:**

```http
GET /api/v2/policy/A-1001 HTTP/1.1
Host: 127.0.0.1:8771
Cookie: sid=fc128ebbe486682d
```
```http
HTTP/1.1 200 OK
Content-Type: application/json

{"ref": "A-1001", "owner": "alice", "amount": 4200}
```

`200 OK`. bob received `A-1001`, whose body names `"owner": "alice"` — a different principal — together with the sensitive field `amount: 4200`.

**Step 3 — the full cross-identity access matrix (the decisive test).** Every record, requested by every identity:

```
GET A-1001 -> alice 200 {"ref":"A-1001","owner":"alice","amount":4200}
              bob   200 {"ref":"A-1001","owner":"alice","amount":4200}
              carol 200 {"ref":"A-1001","owner":"alice","amount":4200}
              root  200 {"ref":"A-1001","owner":"alice","amount":4200}

GET A-1002 -> alice 200 {"ref":"A-1002","owner":"bob","amount":910}
              bob   200 {"ref":"A-1002","owner":"bob","amount":910}
              carol 200 {"ref":"A-1002","owner":"bob","amount":910}
              root  200 {"ref":"A-1002","owner":"bob","amount":910}

GET A-1003 -> alice 200 {"ref":"A-1003","owner":"carol","amount":7777}
              bob   200 {"ref":"A-1003","owner":"carol","amount":7777}
              carol 200 {"ref":"A-1003","owner":"carol","amount":7777}
              root  200 {"ref":"A-1003","owner":"carol","amount":7777}

GET A-1004 -> alice 200 {"ref":"A-1004","owner":"alice","amount":150}
              bob   200 {"ref":"A-1004","owner":"alice","amount":150}
              carol 200 {"ref":"A-1004","owner":"alice","amount":150}
              root  200 {"ref":"A-1004","owner":"alice","amount":150}
```

The response is byte-identical regardless of caller. The matrix is **uniformly permissive across all 4 identities × 4 records = 16 combinations**, whereas the collection route over the same 4 identities returns 0, 1, 1, and 2 records respectively. The authorization decision is not weakened or partially bypassed — on the item route it is simply absent.

**Step 4 — data exfiltration, not just a metadata leak.** Two arbitrary cross-user reads carrying amounts the caller has no legitimate claim to:

```http
GET /api/v2/policy/A-1003 HTTP/1.1
Cookie: sid=fc128ebbe486682d        <- bob
```
```http
HTTP/1.1 200 OK
{"ref": "A-1003", "owner": "carol", "amount": 7777}
```

```http
GET /api/v2/policy/A-1004 HTTP/1.1
Cookie: sid=c45b1da17c2532e2        <- carol
```
```http
HTTP/1.1 200 OK
{"ref": "A-1004", "owner": "alice", "amount": 150}
```

`7777` is a value that appears **nowhere** in bob's or carol's own collection listings — it is only obtainable by reaching across the boundary.

**Step 5 — completeness of the bypass.** An enumeration sweep of `A-900`..`A-1011` as bob returned all four records in the system and nothing else:

```
bob -> A-1001 {"ref": "A-1001", "owner": "alice", "amount": 4200}
bob -> A-1002 {"ref": "A-1002", "owner": "bob",   "amount": 910}
bob -> A-1003 {"ref": "A-1003", "owner": "carol", "amount": 7777}
bob -> A-1004 {"ref": "A-1004", "owner": "alice", "amount": 150}
total readable-by-bob refs found: 4
```

bob's legitimate reach is 1 of 4 records (25%). Through the item route alone he reaches 4 of 4 (100%). Every non-existent ref returns a distinct `404 {"error":"no such record"}`, which doubles as a record-existence oracle for enumeration.

#### Why this is a real vulnerability and not expected behaviour

Four independent arguments, each of which alone would be sufficient:

1. **The application's own collection route defines the boundary and refuses it.** `GET /api/v2/policy/` as bob returns `{A-1002}` only. The system has authoritatively expressed the rule "bob may see A-1002". The item route returning `A-1001` to the same cookie in the same session directly contradicts that. The two routes disagree about the same data, so at most one of them can be correct — and the collection route is the one being conservative, since the app volunteers `owner` on every record.

2. **The response names a different principal than the caller.** The payload self-identifies `"owner": "alice"` while authenticated as bob. Even if "everyone can read everything" were intended policy, the app would have no reason to populate and emit an `owner` field. The field exists to express ownership; it is disclosed to someone the ownership model excludes.

3. **Identity A versus identity B is decisive here, and the difference is total.** bob legitimately sees 1 record; via the item route he sees all 4. That is not a difference in scope granularity or an intentional admin-style broad read available to a privileged role — it is available to `bob`, an ordinary user, with no privilege, no admin token, and no second factor.

4. **`root` is not the discriminator, which removes the main benign explanation.** The obvious defence is "root is the admin, so root seeing everything is fine." That defence fails: bob, carol, and alice — all regular users — get exactly the same unrestricted access as root. There is no role that can be granted broad read access, because *no* identity is denied it. A genuine admin-scoped read would show `root`-only access; here access is universal.

The identifier space is also trivially enumerable: sequential `A-1001`-style refs with a distinguishing `404` for misses mean no guesswork is required, so this is exploitable in a handful of requests by any registered low-privilege user.

**Remediation:** the item route must apply the same owner predicate as the collection route, comparing the record's `owner` against the session identity (plus an explicit, separately-implemented admin override if one is genuinely required), and must return `404` rather than `403` for other users' records so existence is not disclosed. Authorization must be enforced server-side at the data-access layer rather than inferred from route shape, so that the collection and item paths cannot diverge again.

---

## 3. Hypotheses tested and rejected

| # | Hypothesis | Test performed | Observed result | Conclusion |
|---|---|---|---|---|
| 1 | The app has no authentication and everything is public | `GET /api/v2/policy/A-1001` with no cookie; with `sid=deadbeefdeadbeef`; with `sid=` | `302 Found`, `location: /login`, empty body, in all three cases | **Rejected.** Session enforcement is real on the item route. The 302 is why the collection route also returned 404 to anonymous — anonymous was redirected, not authorized. The finding is specifically *authenticated-but-cross-user*, not unauthenticated access. |
| 2 | The collection route is also unscoped, making this a global-exposure bug rather than a route asymmetry | Logged in as all four identities, `GET /api/v2/policy/` | alice→2 own, bob→1 own, carol→1 own, root→0. Each record appears under exactly one owner and no record appears in another's list | **Rejected.** The collection route filters correctly. This is what makes the item-route gap a genuine broken access control rather than a permissive-by-design app. |
| 3 | `root` is the admin account and broad read access is intended for it, so cross-identity reads are by design | Compared item-route responses for `root` against `alice`, `bob`, `carol` | All four identities receive byte-identical 200 responses for all four records. Non-admin users are *not* denied what root is granted | **Rejected.** If this were an intentional admin capability, the non-admin identities would be excluded. The access is universal, so no authorization policy is being implemented. |
| 4 | The item route is client-side-gated and access is only prevented by the UI not linking to other records | Read the served HTML at `/` in an authenticated session; checked whether any owner check exists client-side | `/` contains only `<h1>InternalOps/1.7</h1>`, `signed in as <user>`, and a single collection link. No per-record links, no client logic, no owner filtering anywhere | **Rejected.** There is no client-side control to bypass — the record link was never the gate. Authorization belongs on the server and is missing there. |
| 5 | Only the `status`/`amount` summary is exposed cross-user; the sensitive detail is separately protected | Read full item bodies cross-identity | Full body returned including `owner` and `amount`; `amount: 7777` for `A-1003` was obtained by bob and appears in no listing bob is entitled to | **Rejected.** The item route is the more permissive path, not a hardened one. |
| 6 | State-changing verbs on the item route permit cross-user tampering | `POST`, `PUT`, `DELETE`, `OPTIONS` on `/api/v2/policy/A-1002` and `/api/v2/policy/A-1003` as alice, bob, and root | `POST` → `404 {"error":"not found"}`; `PUT`/`DELETE`/`OPTIONS` → `501` with a stock Python `BaseHTTP` HTML error page | **Rejected as untestable-by-design.** These methods are not implemented by the server at all — the 501 originates from the stdlib HTTP server, not from application code. **No write-side IDOR exists or can exist here.** Reported as read-only disclosure; impact is confined to confidentiality. |
| 7 | Session identifiers are weak, fixed, or replayable, compounding the IDOR | Compared `sid` values across repeated logins per identity; re-used a captured `sid` after a fresh login for the same identity | Every login issued a distinct 16-hex `sid`; a captured `sid` remained valid for its own identity only, and never gained cross-identity reach | **Rejected.** Session IDs are per-login unique and not the vector. The cookies are also `HttpOnly`. Note `SameSite=None` without `Secure`, but that is a hardening gap on a plaintext loopback target, not a demonstrated exploit path. |
| 8 | Authentication itself is trivially bypassable, making the IDOR moot | `POST /login` with `user=nosuchuser`; confirmed no password field exists | `401 {"error":"invalid credentials"}` for unknown users; **no password is required for any valid user** — `user=alice` alone returns `200 {"ok": true}` and a session | **Partially confirmed, out of scope as a finding.** Username-only auth with no secret means *any* account can be claimed by an unauthenticated party — the application-wide impact is arguably worse than the IDOR. However the brief explicitly specified this login mechanism, so it is recorded as a design observation rather than counted as a discovered vulnerability. |
| 9 | Path traversal or encoding tricks reach records beyond the `A-####` namespace | `GET /api/v2/policy/A-1001/`, `/api/v2/policy/1001` (no prefix), `/api/v2/policy/search`, `/api/v2/policy/A-1001/owner`, `/api/v2/policy/A-9999` | `A-1001/` → `404 not found`; `1001` → `404 no such record`; `search` → `404 no such record`; `A-1001/owner` → `404 not found`; `A-9999` → `404 no such record` | **Rejected.** No traversal, prefix-stripping, or sub-resource path reached any record outside the intended namespace. The IDOR requires no bypass trick at all — the plain canonical URL suffices. |

---

## 4. Could not be tested

- **Any write path.** `PUT`, `DELETE`, and `OPTIONS` return `501` from the Python stdlib server; `POST` to the item route returns the router's `404`. There is no implemented state-changing endpoint, so modification, deletion, privilege escalation via write, and CSRF impact are all untestable. If write verbs exist behind a different path or verb, they were not found by endpoint discovery.
- **Authorization on the login endpoint itself** (throttling, lockout, enumeration rate limits) — out of scope for a single-shot test and not probed.
- **Cookie `Secure` flag absence and `SameSite=None` without `Secure`** — noted from the raw `Set-Cookie` header but not exploited. The target is plaintext HTTP on loopback, so there is no TLS interception path available to demonstrate impact.
- **Whether `root` has any privilege *not* visible in these two endpoints** — `root`'s collection list is empty (`{"records": []}`) and its item access is identical to everyone else's. An admin-only surface may exist on undiscovered routes; the discovery sweep returned only `not found` for all candidates, so no second privileged surface was located.
- **Timing side channels** on record existence — `404 no such record` vs `200` is a definitive existence oracle, so no timing analysis was needed.