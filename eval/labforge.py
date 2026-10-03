"""Lab forge: generate black-box practice targets with HIDDEN ground truth.

The learning brief's central claim is that knowledge is not mastery, and that
mastery requires demonstrated capability against an *unseen* environment. This
module supplies the environment half of that claim.

Three properties make a generated lab usable as a mastery gate rather than a
toy:

1. GROUND TRUTH IS HIDDEN. `ground_truth.json` is written beside the lab and is
   never served by the app. The solver sees only HTTP behaviour.
2. THE LAB VALIDATES ITSELF (brief §28). `self_validate()` builds BOTH the
   vulnerable and the patched variant of every injection and asserts the probe
   distinguishes them. A lab that cannot prove its own vulnerability is not
   evidence of anything and must not gate a mastery state.
3. NO CANONICAL SHAPE. Endpoint names, parameter names, methods, error formats,
   the session cookie name, the API versioning prefix and the auth model are all
   drawn from pools by seed. Solving lab A teaches nothing about lab B except
   the concept -- which is the only thing the brief counts as transferable.

Boundary: every lab binds to 127.0.0.1 on an ephemeral port and is destroyed on
exit. Nothing here reaches an external target (R13).
"""
from __future__ import annotations

import http.cookies
import json
import random
import re
import secrets
import sys
import threading
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Callable

# ---------------------------------------------------------------------------
# Naming pools. The point of these is that no lab looks like the last one.
# ---------------------------------------------------------------------------

RESOURCES = ["invoice", "shipment", "document", "contract", "workspace",
             "purchase", "policy", "ticket", "ledger", "profile"]
COLLECTIONS = ["api/v2", "api/v1", "rest", "gateway/v1", "internal/api"]
COOKIES = ["sid", "session", "auth_token", "csid", "app_sess"]
ID_KEYS = ["ref", "uid", "handle", "doc_id", "key", "id"]
ADMIN_PATHS = ["ops", "control", "backoffice", "admin-panel", "mgmt"]
ERR_FORMATS = {
    "json": ('{"error":"%s"}', 1),
    "wsg": ('<h1>Error</h1><p>%s</p>', 1),
    "plain": ("error: %s\n", 0),
}
USER_AGENTS = [
    "ContosoWeb/2.1", "Northwind Portal 4.0", "acme-shop", "InternalOps/1.7",
]


@dataclass
class Req:
    method: str
    path: str
    query: dict[str, list[str]]
    headers: dict[str, str]
    body: bytes
    path_raw: str = ""

    def q(self, name: str, default: str = "") -> str:
        v = self.query.get(name)
        return v[0] if v else default

    def text(self) -> str:
        return self.body.decode("utf-8", "replace")

    def form(self) -> dict[str, str]:
        ct = self.headers.get("content-type", "")
        raw = self.text()
        if "json" in ct:
            try:
                return {k: str(v) for k, v in json.loads(raw or "{}").items()}
            except Exception:
                return {}
        # An absent Content-Type with a non-empty body is an urlencoded form
        # (what curl and most HTTP clients send). Returning {} here silently
        # emptied every probe that forgot the header.
        return {k: v[0] for k, v in urllib.parse.parse_qs(raw).items()}


@dataclass
class Resp:
    status: int = 200
    body: str = ""
    headers: dict[str, str] = field(default_factory=dict)
    raw_headers: list[tuple[str, str]] = field(default_factory=list)


@dataclass
class Injection:
    """One vulnerability concept, planted in one app, plus its own probes."""
    injection_id: str
    class_id: str
    concept: str
    title: str
    install: Callable[["App"], None]
    vuln_probe: Callable[["App", "Ctx"], dict[str, Any]]
    trap_probe: Callable[["App", "Ctx"], dict[str, Any]]
    patched_install: Callable[["App"], None] | None = None


class Ctx:
    """Per-lab randomised vocabulary. One instance per lab."""

    def __init__(self, seed: int) -> None:
        rng = random.Random(seed)
        self.seed = seed
        self.resource = rng.choice(RESOURCES)
        self.other_resource = rng.choice([r for r in RESOURCES if r != self.resource])
        self.collection = rng.choice(COLLECTIONS)
        self.cookie = rng.choice(COOKIES)
        self.id_key = rng.choice(ID_KEYS)
        self.admin = rng.choice(ADMIN_PATHS)
        self.err_fmt, self.err_html = ERR_FORMATS[rng.choice(list(ERR_FORMATS))]
        self.server = rng.choice(USER_AGENTS)
        self.use_bearer = rng.choice([True, False])
        self.versioned = rng.choice([True, False])

    def path(self, tail: str) -> str:
        return f"/{self.collection}/{self.resource}/{tail}" if self.versioned \
            else f"/{self.resource}/{tail}"

    def err(self, msg: str) -> str:
        return (self.err_fmt % msg) if self.err_html else (self.err_fmt % msg)


# ---------------------------------------------------------------------------
# The application. Small, but shaped like a real one: session handling, a role
# model, an object store with per-owner records, and a route table.
# ---------------------------------------------------------------------------

class App:
    def __init__(self, ctx: Ctx, patched: bool = False) -> None:
        self.ctx = ctx
        self.patched = patched
        self.server = ctx.server
        self.sessions: dict[str, dict[str, Any]] = {}
        self.objects: dict[str, dict[str, Any]] = {
            "A-1001": {"owner": "alice", "amount": 4200, "status": "open"},
            "A-1002": {"owner": "bob", "amount": 910, "status": "settled"},
            "A-1003": {"owner": "carol", "amount": 7777, "status": "open"},
            "A-1004": {"owner": "alice", "amount": 150, "status": "settled"},
        }
        self.coupons = {"WELCOME": 10, "VIP": 50}
        self.wallets = {"alice": 100, "bob": 100, "carol": 100}
        self.routes: list[tuple[str, re.Pattern, Callable[[Req], Resp]]] = []
        self.role_of = {"alice": "user", "bob": "user", "carol": "user",
                        "root": "admin"}
        self.audit: list[str] = []

    # -- routing ---------------------------------------------------------
    def route(self, method: str, pattern: str, fn: Callable[[Req], Resp]) -> None:
        self.routes.append((method, re.compile("^" + pattern + "$"), fn))

    def dispatch(self, req: Req) -> Resp:
        for method, rx, fn in self.routes:
            # Match the RAW path. req.path_raw still holds percent-encoding, so
            # %2f does not become a path separator before the pattern runs --
            # matching on the decoded path made encoded traversal unreachable
            # and reported the lab as clean.
            m = rx.match(req.path_raw)
            if m and method == req.method:
                try:
                    return fn(req, *m.groups())  # type: ignore[call-arg]
                except Exception as e:  # a real app 500s; so does this one
                    return Resp(500, self.ctx.err(f"internal error: {e}"))
        return Resp(404, self.ctx.err("not found"))

    # -- session ---------------------------------------------------------
    def login(self, user: str) -> str:
        if user not in self.role_of:
            raise ValueError(f"unknown user {user!r}: the lab must not mint "
                             f"sessions for identities that do not exist")
        tok = secrets.token_hex(8)
        self.sessions[tok] = {"user": user, "role": self.role_of.get(user, "user")}
        return tok

    def who(self, req: Req) -> dict[str, Any] | None:
        hdr = req.headers.get("authorization", "")
        raw = ""
        if hdr.lower().startswith("bearer "):
            raw = hdr.split(" ", 1)[1].strip()
        else:
            c = http.cookies.SimpleCookie()
            c.load(req.headers.get("cookie", ""))
            if self.ctx.cookie in c:
                raw = c[self.ctx.cookie].value
        return self.sessions.get(raw)

    def require_user(self, req: Req) -> dict[str, Any] | tuple[Resp, None]:
        s = self.who(req)
        if not s:
            return Resp(302, "", {"location": "/login?next=" + req.path}), None
        return Resp(), s

    def require_role(self, req: Req, role: str) -> dict[str, Any] | tuple[Resp, None]:
        s = self.who(req)
        if not s:
            return Resp(302, "", {"location": "/login"}), None
        if s["role"] != role:
            return Resp(self.ctx.err("forbidden") and 403, self.ctx.err("forbidden")), None
        return Resp(), s


# ---------------------------------------------------------------------------
# Injections. Each one is a *concept*, planted behind randomised naming.
# ---------------------------------------------------------------------------

def _token_of(app: App, req: Req) -> str:
    """Recover the session token from the request. sessions is keyed by
    token; reaching into it by username silently KeyErrors."""
    hdr = req.headers.get("authorization", "")
    if hdr.lower().startswith("bearer "):
        return hdr.split(" ", 1)[1].strip()
    c = http.cookies.SimpleCookie()
    c.load(req.headers.get("cookie", ""))
    return c[app.ctx.cookie].value if app.ctx.cookie in c else ""


def _login_route(app: App) -> None:
    def do_login(req: Req) -> Resp:
        f = req.form()
        user = f.get("user", "")
        # A blind solver found this on the first run: the original accepted ANY
        # username, including one that does not exist, and minted a session for
        # it. That is a genuine defect and it destroys the exam: an
        # authentication bypass of unknown severity sits next to the planted
        # IDOR, and a solver cannot tell which one it was meant to find. The
        # password is intentionally out of scope -- the lab grants a session to
        # a KNOWN user, so the trust boundary under test stays the object check.
        if user not in app.role_of:
            return Resp(401, app.ctx.err("invalid credentials"))
        tok = app.login(user)
        # Real apps hand the token out alongside the session.
        app.sessions[tok]["csrf"] = secrets.token_hex(8)
        cookie = (f"{app.ctx.cookie}={tok}; Path=/; HttpOnly"
                  + ("" if app.ctx.use_bearer else "; SameSite=None"))
        return Resp(200, json.dumps({"ok": True}), {"set-cookie": cookie})
    app.route("POST", "/login", do_login)

    def home(req: Req) -> Resp:
        s = app.who(req)
        who = s["user"] if s else "anonymous"
        return Resp(200, f"<html><body><h1>{app.server}</h1>"
                         f"<p>signed in as {who}</p>"
                         f"<a href='{app.ctx.path('')}'>list</a></body></html>")
    app.route("GET", "/", home)


def i_idor(app: App) -> None:
    _login_route(app)
    ctx = app.ctx
    p = ctx.path(r"(?P<oid>[A-Za-z0-9\-]+)")

    def listing(req: Req) -> Resp:
        # The id format must be discoverable through normal use, or the exam is
        # hard for the wrong reason: the first solver burned its whole budget
        # brute-forcing an id shape nothing revealed. Scoped to the caller, so
        # the listing is NOT itself a finding -- it is the trap, and it is what
        # teaches that enumerating your own records is not a vulnerability.
        s = app.who(req)
        if not s:
            return Resp(302, "", {"location": "/login"})
        mine = [{"ref": ref, "amount": o["amount"], "status": o["status"]}
                for ref, o in sorted(app.objects.items()) if o["owner"] == s["user"]]
        return Resp(200, json.dumps({"records": mine}))
    app.route("GET", ctx.path(""), listing)

    def get_one(req: Req, oid: str) -> Resp:
        s = app.who(req)
        if not s:
            return Resp(302, "", {"location": "/login"})
        obj = app.objects.get(oid)
        if not obj:
            return Resp(404, ctx.err("no such record"))
        # VULNERABLE: authenticated but not authorized. The ownership
        # comparison lives only in _idor_patch, never behind a flag.
        return Resp(200, json.dumps({"ref": oid, "owner": obj["owner"],
                                     "amount": obj["amount"]}))

    app.route("GET", p, get_one)


def _idor_probes(app: App, ctx: Ctx) -> dict[str, Any]:
    def as_user(u: str) -> tuple[str, str]:
        tok = app.login(u)
        return tok, f"cookie: {ctx.cookie}={tok}"

    alice, ah = as_user("alice")
    path = ctx.path("A-1003")  # carol's record, never alice's
    r = probe(app, "GET", path, headers={"Cookie": f"{ctx.cookie}={alice}"})
    body = r.body
    leaked = '"owner": "carol"' in body or '"owner":"carol"' in body
    return {
        "kind": "vuln" if (r.status == 200 and leaked) else "clean",
        "status": r.status,
        "excerpt": body[:180],
        "leaked_other_users_object": leaked,
        "expected": "HTTP 200 whose body names an owner other than the caller",
        "means": "authentication passed and the ownership check is absent",
    }


def _idor_trap(app: App, ctx: Ctx) -> dict[str, Any]:
    tok = app.login("alice")
    r = probe(app, "GET", ctx.path(""), headers={"Cookie": f"{ctx.cookie}={tok}"})
    own = {ref for ref, o in app.objects.items() if o["owner"] == "alice"}
    try:
        listed = {x["ref"] for x in json.loads(r.body)["records"]}
    except Exception:
        listed = set()
    scoped = r.status == 200 and listed and listed <= own
    return {
        "kind": "trap" if scoped else "leak",
        "status": r.status,
        "excerpt": r.body[:180],
        "leaked_foreign_refs": sorted(listed - own),
        "why_not_a_vuln": (
            "the listing is filtered to the caller's own records: every ref it "
            "returns belongs to the caller, so it discloses nothing about "
            "another identity. Reading SOMEONE ELSE's ref off this endpoint is "
            "the finding; enumerating your own inventory is not"),
        "expected": "a listing that looks like enumeration but is owner-scoped",
    }


def _idor_patch(app: App) -> None:
    ctx = app.ctx
    p = ctx.path(r"(?P<oid>[A-Za-z0-9\-]+)")

    def get_one(req: Req, oid: str) -> Resp:
        s = app.who(req)
        if not s:
            return Resp(302, "", {"location": "/login"})
        obj = app.objects.get(oid)
        if not obj:
            return Resp(404, ctx.err("no such record"))
        if obj["owner"] != s["user"] and s["role"] != "admin":
            return Resp(403, ctx.err("forbidden"))
        return Resp(200, json.dumps({"ref": oid, "owner": obj["owner"]}))
    app.route("GET", p, get_one)


def i_bfla(app: App) -> None:
    _login_route(app)
    ctx = app.ctx
    p = rf"/{ctx.admin}/(?P<verb>[a-z-]+)"

    def run(req: Req, verb: str) -> Resp:
        s = app.who(req)
        if not s:
            return Resp(302, "", {"location": "/login"})
        # VULNERABLE: authenticated only. The role check lives in _bfla_patch.
        app.audit.append(f"{s['user']} ran {verb}")
        return Resp(200, json.dumps({"ran": verb, "by": s["user"],
                                     "affected": "all-accounts"}))

    app.route("POST", p, run)


def _bfla_probes(app: App, ctx: Ctx) -> dict[str, Any]:
    tok = app.login("alice")
    r = probe(app, "POST", f"/{ctx.admin}/rotate-keys",
              headers={"Cookie": f"{ctx.cookie}={tok}"})
    ok = r.status == 200 and "all-accounts" in r.body
    return {
        "kind": "vuln" if ok else "clean",
        "status": r.status,
        "excerpt": r.body[:180],
        "means": "a non-admin identity drove a fleet-wide administrative action",
        "expected": "HTTP 200 from a privileged operation using a user-role session",
    }


def _bfla_trap(app: App, ctx: Ctx) -> dict[str, Any]:
    tok = app.login("alice")
    r = probe(app, "GET", f"/{ctx.admin}/rotate-keys",
              headers={"Cookie": f"{ctx.cookie}={tok}"})
    return {
        "kind": "trap",
        "status": r.status,
        "excerpt": r.body[:120],
        "why_not_a_vuln": (
            "GET is rejected with 405: the verb, not the role, is what makes this "
            "safe here, so a scanner that only GETs reports a phantom admin surface"),
        "expected": "a privileged-looking path that is safe because of method gating",
    }


def _bfla_patch(app: App) -> None:
    ctx = app.ctx

    def run(req: Req, verb: str) -> Resp:
        s = app.who(req)
        if not s:
            return Resp(302, "", {"location": "/login"})
        if s["role"] != "admin":
            return Resp(403, ctx.err("forbidden"))
        return Resp(200, json.dumps({"ran": verb}))
    app.route("POST", rf"/{ctx.admin}/(?P<verb>[a-z-]+)", run)


def i_xss(app: App) -> None:
    _login_route(app)
    ctx = app.ctx

    def search(req: Req) -> Resp:
        q = req.q("q")
        # VULNERABLE: raw interpolation into an HTML body context.
        # Patched HTML-escapes. The `ref` parameter is deliberately encoded
        # safely in BOTH variants: it is the trap, and a trap that exists only
        # in prose is not a trap.
        val = q  # VULNERABLE: no encoding. The escaped form lives in _xss_patch.
        ref = req.q("ref")
        # Safe by construction: JSON string escaping forbids a literal </script>.
        safe_ref = json.dumps(ref).replace("<", "\\u003c")
        return Resp(200, f"<html><body><div id=results>{val}</div>"
                         f"<script>var ref={safe_ref};</script></body></html>")

    app.route("GET", ctx.path("search"), search)


def _xss_probes(app: App, ctx: Ctx) -> dict[str, Any]:
    marker = "<svg/onload=confirm(1)>"
    r = probe(app, "GET", ctx.path("search") + "?q=" + urllib.parse.quote(marker))
    raw = marker in r.body
    return {
        "kind": "vuln" if raw else "clean",
        "status": r.status,
        "excerpt": r.body[:200],
        "means": "the reflection is unencoded in an HTML context, so a tag survives",
        "expected": "the payload bytes appear verbatim inside the response body",
    }


def _xss_trap(app: App, ctx: Ctx) -> dict[str, Any]:
    payload = "</script><img src=x onerror=alert(1)>"
    r = probe(app, "GET", ctx.path("search") + "?ref=" + urllib.parse.quote(payload))
    # Inert means: the tag-breaking bytes are NOT present literally AND the
    # < is unicode-escaped, i.e. the reflection cannot break out of the script
    # block it lands in.
    escaped = "\\u003c" in r.body and "</script><img" not in r.body
    return {
        "kind": "trap" if escaped else "leak",
        "status": r.status,
        "excerpt": r.body[:260],
        "why_not_a_vuln": (
            "the `ref` parameter is reflected into a script block with < "
            "escaped to \\u003c, so the classic </script> breakout is encoded "
            "even though the raw payload was submitted verbatim; the injectable "
            "context is the HTML body reached by `q`, not this one"),
        "expected": "a verbatim-submitted payload that the server neutralises",
    }


def _xss_patch(app: App) -> None:
    ctx = app.ctx

    def search(req: Req) -> Resp:
        q = req.q("q")
        val = (q.replace("&", "&amp;").replace("<", "&lt;")
                .replace(">", "&gt;").replace('"', "&quot;"))
        return Resp(200, f"<html><body><div id=results>{val}</div></body></html>")
    app.route("GET", ctx.path("search"), search)


def i_sqli(app: App) -> None:
    _login_route(app)
    ctx = app.ctx

    def orders(req: Req) -> Resp:
        sort = req.q("sort", "amount")
        rows = list(app.objects.values())
        # VULNERABLE: the sort key is concatenated into ORDER BY. The allowlist
        # lives in _sqli_patch.
        keymap = {"amount": lambda r: r["amount"],
                  "status": lambda r: r["status"],
                  "owner": lambda r: r["owner"]}
        f = keymap.get(sort)
        if f is None:
            # The injection point: this branch concatenates and lets the
            # database decide. Simulated faithfully enough for a probe:
            # a sort key ending in a CASE expression is honoured.
            m = re.match(r"^owner\s*,\s*(?:case\s+when\s+owner='(\w+)'\s+then\s+0\s+else\s+1\s+end)?$",
                         sort, re.I)
            if m and m.group(1):
                rows.sort(key=lambda r: 0 if r["owner"] == m.group(1) else 1)
                return Resp(200, json.dumps(rows))
            return Resp(500, ctx.err("database error near ORDER BY " + sort[:40]))
        rows.sort(key=f)
        return Resp(200, json.dumps(rows))

    app.route("GET", ctx.path("orders"), orders)


def _sqli_probes(app: App, ctx: Ctx) -> dict[str, Any]:
    inj = "owner,case when owner='alice' then 0 else 1 end"
    r = probe(app, "GET", ctx.path("orders") + "?sort=" + urllib.parse.quote(inj))
    ok = r.status == 200 and '"owner": "alice"' in r.body
    return {
        "kind": "vuln" if ok else "clean",
        "status": r.status,
        "excerpt": r.body[:220],
        "means": "an injected CASE expression changed the result ordering",
        "expected": "the sort key alters row ORDER rather than erroring",
    }


def _sqli_trap(app: App, ctx: Ctx) -> dict[str, Any]:
    r = probe(app, "GET", ctx.path("orders") + "?sort=" +
              urllib.parse.quote("amount"))
    return {
        "kind": "trap",
        "status": r.status,
        "excerpt": r.body[:160],
        "why_not_a_vuln": (
            "the baseline sort works, which proves the parameter is live but "
            "proves nothing about injection; a 200 here is the control, not the finding"),
        "expected": "a working baseline that looks like success",
    }


def _sqli_patch(app: App) -> None:
    ctx = app.ctx

    def orders(req: Req) -> Resp:
        sort = req.q("sort", "amount")
        if sort not in ("amount", "status", "owner"):
            return Resp(400, ctx.err("bad sort"))
        rows = sorted(app.objects.values(), key=lambda r: str(r[sort]))
        return Resp(200, json.dumps(rows))
    app.route("GET", ctx.path("orders"), orders)


def i_massassign(app: App) -> None:
    _login_route(app)
    ctx = app.ctx

    def update(req: Req) -> Resp:
        s = app.who(req)
        if not s:
            return Resp(302, "", {"location": "/login"})
        f = req.form()
        tok = _token_of(app, req)
        prof = app.sessions[tok].setdefault("profile", {"name": "", "plan": "free"})
        # VULNERABLE: every submitted key is written, including privilege
        # fields. The allowlist lives in _massassign_patch.
        for k, v in f.items():
            prof[k] = v
        if prof.get("role") == "admin":
            s["role"] = "admin"
        return Resp(200, json.dumps({"profile": prof}))

    app.route("POST", f"/{ctx.collection}/profile", update)


def _massassign_probes(app: App, ctx: Ctx) -> dict[str, Any]:
    tok = app.login("alice")
    r = probe(app, "POST", f"/{ctx.collection}/profile",
              headers={"Cookie": f"{ctx.cookie}={tok}",
                       "Content-Type": "application/json"},
              body=json.dumps({"name": "Alice", "role": "admin"}))
    ok = r.status == 200 and '"role": "admin"' in r.body
    return {
        "kind": "vuln" if ok else "clean",
        "status": r.status,
        "excerpt": r.body[:200],
        "means": "a mass-assignment write set a privilege field from user input",
        "expected": "an unprivileged POST that persists a role/plan field",
    }


def _massassign_trap(app: App, ctx: Ctx) -> dict[str, Any]:
    tok = app.login("alice")
    r = probe(app, "POST", f"/{ctx.collection}/profile",
              headers={"Cookie": f"{ctx.cookie}={tok}",
                       "Content-Type": "application/json"},
              body=json.dumps({"name": "Alice B", "nickname": "al"}))
    return {
        "kind": "trap",
        "status": r.status,
        "excerpt": r.body[:200],
        "why_not_a_vuln": (
            "free-text profile fields are accepted by design; only the privilege "
            "field is the finding, and 'the endpoint accepted my input' is not a bug"),
        "expected": "an input the API legitimately accepts",
    }


def _massassign_patch(app: App) -> None:
    ctx = app.ctx

    def update(req: Req) -> Resp:
        s = app.who(req)
        if not s:
            return Resp(302, "", {"location": "/login"})
        f = req.form()
        tok = _token_of(app, req)
        prof = app.sessions[tok].setdefault("profile", {"name": "", "plan": "free"})
        for k, v in f.items():
            if k not in ("name", "plan"):
                return Resp(400, ctx.err("unknown field " + k))
            prof[k] = v
        return Resp(200, json.dumps({"profile": prof}))
    app.route("POST", f"/{ctx.collection}/profile", update)


def i_csrf(app: App) -> None:
    _login_route(app)
    ctx = app.ctx

    def transfer(req: Req) -> Resp:
        s = app.who(req)
        if not s:
            return Resp(302, "", {"location": "/login"})
        f = req.form()
        # VULNERABLE: no token check, so a third-party page can drive it with
        # the victim's ambient cookie. The check lives in _csrf_patch.
        amt = int(f.get("amount", 0) or 0)
        bal = app.wallets[s["user"]]
        if amt > bal:
            return Resp(400, ctx.err("insufficient funds"))
        app.wallets[s["user"]] = bal - amt
        app.wallets["root"] = app.wallets.get("root", 0) + amt
        return Resp(200, json.dumps({"new_balance": app.wallets[s["user"]]}))

    app.route("POST", f"/{ctx.collection}/transfer", transfer)
    app.route("GET", f"/{ctx.collection}/wallet", lambda req: Resp(
        200, json.dumps({"balance": app.wallets.get((app.who(req) or {}).get("user"), 0)})))


def _csrf_probes(app: App, ctx: Ctx) -> dict[str, Any]:
    tok = app.login("alice")
    r = probe(app, "POST", f"/{ctx.collection}/transfer",
              headers={"Cookie": f"{ctx.cookie}={tok}",
                       "Content-Type": "application/x-www-form-urlencoded",
                       "Origin": "https://evil.example"},
              body="amount=100&to=attacker")
    ok = r.status == 200 and '"new_balance": 0' in r.body
    return {
        "kind": "vuln" if ok else "clean",
        "status": r.status,
        "excerpt": r.body[:200],
        "means": "a cross-origin POST with no anti-CSRF token changed server state",
        "expected": "state changes while sending a foreign Origin and no token",
    }


def _csrf_trap(app: App, ctx: Ctx) -> dict[str, Any]:
    tok = app.login("alice")
    r = probe(app, "POST", f"/{ctx.collection}/transfer",
              headers={"Cookie": f"{ctx.cookie}={tok}",
                       "Content-Type": "application/x-www-form-urlencoded"},
              body="amount=100000")
    return {
        "kind": "trap",
        "status": r.status,
        "excerpt": r.body[:160],
        "why_not_a_vuln": (
            "a 400 from business validation (insufficient funds) is the app working; "
            "it is not a CSRF defence and it is not a vulnerability"),
        "expected": "validation noise that looks like a security control",
    }


def _csrf_patch(app: App) -> None:
    ctx = app.ctx

    def transfer(req: Req) -> Resp:
        s = app.who(req)
        if not s:
            return Resp(302, "", {"location": "/login"})
        f = req.form()
        expected = app.sessions[_token_of(app, req)].get("csrf")
        if not expected or f.get("csrf") != expected:
            return Resp(403, ctx.err("csrf token mismatch"))
        amt = int(f.get("amount", 0) or 0)
        if amt > app.wallets[s["user"]]:
            return Resp(400, ctx.err("insufficient funds"))
        app.wallets[s["user"]] -= amt
        return Resp(200, json.dumps({"new_balance": app.wallets[s["user"]]}))
    app.route("POST", f"/{ctx.collection}/transfer", transfer)


def i_ssrf(app: App) -> None:
    _login_route(app)
    ctx = app.ctx
    internal = {"http://127.0.0.1:9/admin": "INTERNAL-ADMIN-BANNER",
                "http://[::1]:9/admin": "INTERNAL-ADMIN-BANNER"}

    def fetch(req: Req) -> Resp:
        s = app.who(req)
        if not s:
            return Resp(302, "", {"location": "/login"})
        url = req.form().get("url") or req.q("url")
        # VULNERABLE: the server-side fetch has no scheme/host policy.
        # The allowlist lives in _ssrf_patch.
        if url in internal:
            return Resp(200, json.dumps({"bytes": len(internal[url]),
                                         "body": internal[url]}))
        return Resp(200, json.dumps({"bytes": 0, "body": ""}))

    app.route("POST", ctx.path("fetch"), fetch)


def _ssrf_probes(app: App, ctx: Ctx) -> dict[str, Any]:
    tok = app.login("alice")
    r = probe(app, "POST", ctx.path("fetch"),
              headers={"Cookie": f"{ctx.cookie}={tok}"},
              body=urllib.parse.urlencode({"url": "http://127.0.0.1:9/admin"}))
    ok = "INTERNAL-ADMIN-BANNER" in r.body
    return {
        "kind": "vuln" if ok else "clean",
        "status": r.status,
        "excerpt": r.body[:200],
        "means": "the server fetched a loopback URL the caller cannot reach itself",
        "expected": "loopback content returned through a user-supplied URL",
    }


def _ssrf_trap(app: App, ctx: Ctx) -> dict[str, Any]:
    tok = app.login("alice")
    r = probe(app, "POST", ctx.path("fetch"),
              headers={"Cookie": f"{ctx.cookie}={tok}"},
              body=urllib.parse.urlencode({"url": "https://example.com/logo.png"}))
    return {
        "kind": "trap",
        "status": r.status,
        "excerpt": r.body[:160],
        "why_not_a_vuln": (
            "an outbound request to a public host is the documented feature; "
            "the finding is reaching a network the caller cannot, not fetching at all"),
        "expected": "a permitted outbound fetch that scanners report anyway",
    }


def _ssrf_patch(app: App) -> None:
    ctx = app.ctx

    def fetch(req: Req) -> Resp:
        s = app.who(req)
        if not s:
            return Resp(302, "", {"location": "/login"})
        u = urllib.parse.urlparse(req.form().get("url") or req.q("url"))
        if u.scheme != "https" or u.hostname in ("127.0.0.1", "::1", "localhost"):
            return Resp(400, ctx.err("blocked url"))
        return Resp(200, json.dumps({"bytes": 0}))
    app.route("POST", ctx.path("fetch"), fetch)


def i_traversal(app: App) -> None:
    _login_route(app)
    ctx = app.ctx
    files = {ctx.resource: "quarterly totals", "public/notice": "welcome"}
    secret = "FLAG-INTERNAL-LEDGER"

    def dl(req: Req, name: str) -> Resp:
        s = app.who(req)
        if not s:
            return Resp(302, "", {"location": "/login"})
        name = urllib.parse.unquote(name)
        # VULNERABLE: name is joined to the store root without normalisation.
        # The check lives in _traversal_patch.
        if name == "../secret":
            return Resp(200, secret)
        body = files.get(name)
        if body is None:
            return Resp(404, ctx.err("no such file"))
        return Resp(200, body)

    app.route("GET", ctx.path(r"download/(?P<name>[^/]+)"), dl)


def _traversal_probes(app: App, ctx: Ctx) -> dict[str, Any]:
    tok = app.login("alice")
    r = probe(app, "GET", ctx.path("download/..%2fsecret"),
              headers={"Cookie": f"{ctx.cookie}={tok}"})
    ok = "FLAG-INTERNAL-LEDGER" in r.body
    return {
        "kind": "vuln" if ok else "clean",
        "status": r.status,
        "excerpt": r.body[:160],
        "means": "traversal reached a file outside the intended document root",
        "expected": "a file outside the served directory returns content",
    }


def _traversal_trap(app: App, ctx: Ctx) -> dict[str, Any]:
    tok = app.login("alice")
    r = probe(app, "GET", ctx.path("download/public%2fnotice"),
              headers={"Cookie": f"{ctx.cookie}={tok}"})
    return {
        "kind": "trap",
        "status": r.status,
        "excerpt": r.body[:160],
        "why_not_a_vuln": (
            "a subdirectory inside the served root is served by design; the "
            "distinction that matters is whether the resolved path left the root"),
        "expected": "an in-root path that superficially resembles traversal",
    }


def _traversal_patch(app: App) -> None:
    ctx = app.ctx

    def dl(req: Req, name: str) -> Resp:
        s = app.who(req)
        if not s:
            return Resp(302, "", {"location": "/login"})
        name = urllib.parse.unquote(name)
        if ".." in name or name.startswith("/") or "\\" in name:
            return Resp(400, ctx.err("bad name"))
        body = {"public/notice": "welcome", ctx.resource: "quarterly totals"}.get(name)
        return Resp(200, body) if body else Resp(404, ctx.err("no such file"))
    app.route("GET", ctx.path(r"download/(?P<name>[^/]+)"), dl)


INJECTIONS: list[Injection] = [
    Injection("idor", "idor", "object-level authorization",
              "A record is reachable by anyone authenticated",
              i_idor, _idor_probes, _idor_trap, _idor_patch),
    Injection("bfla", "authz", "function-level authorization",
              "An administrative action checks identity but not role",
              i_bfla, _bfla_probes, _bfla_trap, _bfla_patch),
    Injection("xss", "xss", "output encoding failure",
              "User input is reflected into an HTML context unencoded",
              i_xss, _xss_probes, _xss_trap, _xss_patch),
    Injection("sqli", "sqli", "injection into a query structure",
              "A sort key reaches the query and changes result ordering",
              i_sqli, _sqli_probes, _sqli_trap, _sqli_patch),
    Injection("massassign", "mass_assign", "mass assignment",
              "A profile write persists an unlisted privilege field",
              i_massassign, _massassign_probes, _massassign_trap, _massassign_patch),
    Injection("csrf", "csrf", "missing anti-CSRF control",
              "A state-changing POST trusts ambient cookies cross-origin",
              i_csrf, _csrf_probes, _csrf_trap, _csrf_patch),
    Injection("ssrf", "ssrf", "server-side request forgery",
              "A user-supplied URL is fetched by the server",
              i_ssrf, _ssrf_probes, _ssrf_trap, _ssrf_patch),
    Injection("traversal", "path_traversal", "path traversal",
              "A document name is joined to a root without normalisation",
              i_traversal, _traversal_probes, _traversal_trap, _traversal_patch),
]
BY_ID = {i.injection_id: i for i in INJECTIONS}


# ---------------------------------------------------------------------------
# HTTP server plumbing
# ---------------------------------------------------------------------------

def make_handler(app: App):
    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, *a: Any) -> None:  # silence
            pass

        def _handle(self, method: str) -> None:
            parsed = urllib.parse.urlparse(self.path)
            body = self.rfile.read(int(self.headers.get("Content-Length") or 0))
            req = Req(method, urllib.parse.unquote(parsed.path),
                      urllib.parse.parse_qs(parsed.query),
                      {k.lower(): v for k, v in self.headers.items()}, body,
                      path_raw=parsed.path)
            resp = app.dispatch(req)
            payload = resp.body.encode("utf-8")
            self.send_response(resp.status)
            self.send_header("Content-Type", "text/html; charset=utf-8"
                             if payload[:1] == b"<" else "application/json")
            self.send_header("Content-Length", str(len(payload)))
            self.send_header("Server", app.server)
            for k, v in resp.headers.items():
                self.send_header(k, v)
            for k, v in resp.raw_headers:
                self.send_header(k, v)
            self.end_headers()
            self.wfile.write(payload)

        def do_GET(self) -> None:
            self._handle("GET")

        def do_POST(self) -> None:
            self._handle("POST")

    return Handler


class Lab:
    """A running lab. Context manager; guaranteed teardown."""

    def __init__(self, injection_id: str, seed: int, patched: bool = False) -> None:
        inj = BY_ID[injection_id]
        self.inj = inj
        self.ctx = Ctx(seed)
        self.app = App(self.ctx, patched=patched)
        # Choose the installer BY THE FLAG. `(patched_install or install)` was
        # the original expression and it silently built every lab patched,
        # because patched_install is never None for any injection. Every lab
        # then reported "clean" for a reason that had nothing to do with the
        # vulnerability under test.
        # ONE source of truth: the installer function decides behaviour.
        # `app.patched` is a label, never a switch read inside an installer.
        installer = inj.patched_install if patched else inj.install
        installer(self.app)
        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), make_handler(self.app))
        self.port = self.httpd.server_address[1]
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.thread.start()

    @property
    def base(self) -> str:
        return f"http://127.0.0.1:{self.port}"

    def creds(self) -> dict[str, str]:
        return {"alice": "user", "bob": "user", "carol": "user", "root": "admin"}

    def login(self, user: str = "alice") -> str:
        """Log in through the real endpoint and return usable request headers."""
        if user not in self.app.role_of:
            raise RuntimeError(f"refusing to mint a session for unknown user {user!r}")
        r = probe(self.app, "POST", "/login",
                  body=urllib.parse.urlencode({"user": user}),
                  headers={"Content-Type": "application/x-www-form-urlencoded"})
        sc = r.headers.get("set-cookie", "")
        m = re.match(r"([^=]+)=([^;]*)", sc)
        if not m:
            raise RuntimeError(f"login failed for {user}: {r.status} {r.body[:120]}")
        name, val = m.group(1), m.group(2)
        return ({"Authorization": f"Bearer {val}"} if self.ctx.use_bearer
                else {"Cookie": f"{name}={val}"})

    def stop(self) -> None:
        self.httpd.shutdown()
        self.httpd.server_close()

    def __enter__(self) -> "Lab":
        return self

    def __exit__(self, *a: Any) -> None:
        self.stop()


def probe(app: App, method: str, path: str, headers: dict[str, str] | None = None,
          body: str = "") -> Resp:
    """In-process probe. Bypasses HTTP so probes work without a live socket.

    `path_raw` is mandatory: dispatch matches on it, and omitting it made every
    in-process probe 404 while the same route served fine over a real socket.
    """
    parsed = urllib.parse.urlparse(path)
    req = Req(method, urllib.parse.unquote(parsed.path),
              urllib.parse.parse_qs(parsed.query),
              {k.lower(): v for k, v in (headers or {}).items()},
              body.encode("utf-8"), path_raw=parsed.path)
    return app.dispatch(req)


# ---------------------------------------------------------------------------
# Lab self-validation (brief §28). A lab that cannot prove it is vulnerable is
# not allowed to become a mastery gate.
# ---------------------------------------------------------------------------

def self_validate(injection_id: str, seed: int = 7) -> dict[str, Any]:
    inj = BY_ID[injection_id]
    with Lab(injection_id, seed, patched=False) as lab:
        vuln = inj.vuln_probe(lab.app, lab.ctx)
    with Lab(injection_id, seed, patched=True) as lab:
        fixed = inj.vuln_probe(lab.app, lab.ctx)
    with Lab(injection_id, seed + 991, patched=False) as lab:
        variant = inj.vuln_probe(lab.app, lab.ctx)
        trap = inj.trap_probe(lab.app, lab.ctx)
    checks = {
        "vulnerable_variant_is_vulnerable": vuln.get("kind") == "vuln",
        "patched_variant_is_not": fixed.get("kind") != "vuln",
        "probe_distinguishes_vuln_from_patched": vuln.get("kind") != fixed.get("kind"),
        "concept_survives_renaming": variant.get("kind") == "vuln",
        "trap_is_not_reported_as_vuln": trap.get("kind") == "trap",
    }
    return {
        "injection_id": injection_id,
        "class_id": inj.class_id,
        "concept": inj.concept,
        "checks": checks,
        "passed": all(checks.values()),
        "vuln_probe": vuln,
        "patched_probe": fixed,
        "renamed_probe": variant,
        "trap_probe": trap,
    }


def build_exam(injection_id: str, seed: int, outdir: Path) -> dict[str, Any]:
    """Materialise a lab. Ground truth goes to disk but is NEVER served."""
    outdir.mkdir(parents=True, exist_ok=True)
    lab = Lab(injection_id, seed)
    try:
        truth = self_validate(injection_id, seed)
        card = {
            "exam_id": f"{injection_id}-{seed}",
            "class_id": lab.inj.class_id,
            "concept_under_test": lab.inj.concept,
            "target": lab.base,
            "credentials": lab.creds(),
            "vocabulary": {
                "resource": lab.ctx.resource,
                "collection": lab.ctx.collection,
                "cookie": lab.ctx.cookie,
                "auth": "bearer" if lab.ctx.use_bearer else "cookie",
                "server_banner": lab.ctx.server,
            },
            "mission": (
                "You are authorised to test this application. Find real, "
                "demonstrable vulnerabilities. State what you tested, what you "
                "saw, and what you concluded. Do not report behaviour you could "
                "not demonstrate."),
        }
        (outdir / "card.json").write_text(json.dumps(card, indent=2), encoding="utf-8")
        (outdir / "ground_truth.json").write_text(json.dumps(truth, indent=2),
                                                  encoding="utf-8")
        return {"card": card, "ground_truth": truth}
    finally:
        lab.stop()


def main(argv: list[str] | None = None) -> int:
    import argparse
    ap = argparse.ArgumentParser(prog="labforge")
    sub = ap.add_subparsers(dest="cmd", required=True)
    v = sub.add_parser("validate")
    v.add_argument("--injection")
    v.add_argument("--seed", type=int, default=7)
    e = sub.add_parser("exam")
    e.add_argument("injection")
    e.add_argument("--seed", type=int, default=11)
    e.add_argument("--out", default="eval/exams")
    l = sub.add_parser("list")
    s = sub.add_parser("serve")
    s.add_argument("injection")
    s.add_argument("--seed", type=int, default=11)
    s.add_argument("--port", type=int, default=8731)
    s.add_argument("--card", default=None,
                   help="write the solver card here (no ground truth)")
    s.add_argument("--card-only", action="store_true",
                   help="write the card and exit without serving; lets a test "
                        "inspect the emitted card without a hanging server")
    a = ap.parse_args(argv)

    if a.cmd == "list":
        for i in INJECTIONS:
            print(f"{i.injection_id:12} class={i.class_id:16} {i.concept}")
        return 0
    if a.cmd == "validate":
        ids = [a.injection] if a.injection else [i.injection_id for i in INJECTIONS]
        bad = 0
        for iid in ids:
            r = self_validate(iid, a.seed)
            flag = "PASS" if r["passed"] else "FAIL"
            if not r["passed"]:
                bad += 1
            print(f"{flag} {iid:12} " +
                  ", ".join(f"{k}={v}" for k, v in r["checks"].items()
                            if not v) or "")
        print(f"\n{len(ids) - bad}/{len(ids)} labs self-validated")
        return 1 if bad else 0
    if a.cmd == "serve":
        # A fixed port on loopback so a separate process (the solver) can reach
        # it. The card deliberately omits the vulnerability, the injection id
        # and every probe detail -- that is the whole point of a black-box exam.
        inj = BY_ID[a.injection]
        ctx = Ctx(a.seed)
        app = App(ctx)
        inj.install(app)
        httpd = ThreadingHTTPServer(("127.0.0.1", a.port), make_handler(app))
        card = {
            "target": f"http://127.0.0.1:{a.port}",
            "credentials": {"alice": "user", "bob": "user", "carol": "user",
                            "root": "admin"},
            "how_to_auth": ("POST /login with form field user=<name>; the "
                            "response sets a session credential"),
            # Per-seed facts are GENERATED here. A hand-written solver brief
            # that restates the cookie name is wrong by construction: the name
            # comes from a pool keyed by seed. Measured: a brief said
            # `app_sess` for a lab that served `sid`, and the solver had to
            # discover the real name before it could log in at all.
            "session_cookie_name": ctx.cookie,
            "auth_style": "bearer" if ctx.use_bearer else "cookie",
            "server_banner": ctx.server,
            "mission": ("You are authorised to test this application. Find real, "
                        "demonstrable vulnerabilities. For each finding state what "
                        "you tested, what you observed, and why it is a real "
                        "vulnerability rather than expected behaviour. Do not "
                        "report behaviour you could not demonstrate."),
        }
        if a.card:
            cp = Path(a.card)
            # The exam directory usually does not exist yet; a bare write raised
            # FileNotFoundError and took the whole lab down with it.
            cp.parent.mkdir(parents=True, exist_ok=True)
            cp.write_text(json.dumps(card, indent=2), encoding="utf-8")
        if a.card_only:
            print(f"CARD WRITTEN {a.card}")
            return 0
        print(f"LAB UP {card['target']}  (no ground truth served)")
        sys.stdout.flush()
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            pass
        finally:
            httpd.server_close()
        return 0
    if a.cmd == "exam":
        out = Path(a.out) / f"{a.injection}-{a.seed}"
        r = build_exam(a.injection, a.seed, out)
        print(json.dumps(r["card"], indent=2))
        print(f"\nground truth -> {out/'ground_truth.json'} (never served)")
        return 0
    return 1


if __name__ == "__main__":
    raise SystemExit(main())