"""Authorization context (master prompt §4-§7).

The existing `scope_grant` answers one question — is this host named? — and
answers it well. §4 asks for something wider and the difference matters:

    AuthorizationContext {
        program, target, in_scope_assets, out_of_scope_assets,
        allowed_actions, forbidden_actions, rate_limits,
        authentication_context, special_rules,
        reporting_requirements, testing_window
    }

Three properties this module owns, each of which was a hole in the old shape:

1. **ACTIONS, not just targets.** A grant saying "offensive_allowed" cannot
   express "no destructive payloads" or "no social engineering". An action that
   is not named in `allowed_actions` is refused even against a granted host —
   because §3 puts program rules above autonomy and §57 ranks program rules
   second, above safety and evidence.

2. **AMBIGUITY IS A STATE, NOT A GUESS.** §5 forbids inferring authorization
   from DNS, ownership, shared infrastructure, certificates or redirects. So
   `parse()` returns `AMBIGUOUS` with the specific missing field when it cannot
   resolve the boundary, and every active action checks `ctx.decision()`. An
   ambiguous context authorises RECOGNITION and refuses everything else — the
   same split `research_only` already made, but now for missing information
   rather than for an absent permission.

3. **A FORBIDDEN TECHNIQUE HAS A SUBSTITUTE PATH (§7).** Refusing is the floor,
   not the answer. `resolve_prohibited` maps the objective onto a permitted
   technique when one exists, so a hunt blocked on "no SQLMap" continues with
   hand-built requests. The mapping is data, inspectable, and it refuses rather
   than guessing when it has no entry.

Scope observations (§6) are recorded and NEVER tested. `classify_asset` is the
single decision point, and it is deny-on-unknown by construction: an asset that
is neither in the in-scope list nor the out-of-scope list is `undetermined`, and
undetermined is not in-scope.
"""
from __future__ import annotations

import json
import re
import sqlite3
from dataclasses import dataclass, field, asdict
from typing import Any, Iterable

from . import store

# ---------------------------------------------------------------------------
# The action vocabulary. Closed, because an open vocabulary means a technique
# nobody anticipated is silently allowed by omission.
# ---------------------------------------------------------------------------

ACTIONS = (
    "recon",            # passive asset discovery, no packets to the target
    "probe",            # direct HTTP requests to named hosts
    "authenticate",     # use credentials the user supplied for this target
    "scan",             # port/service scanning
    "enumerate",        # directory/user/service enumeration
    "fuzz",             # parameter and input fuzzing
    "inject",           # SQLi/NoSMTP/command injection attempts
    "exploit",          # driving a weakness to its consequence
    "escalate",         # privilege escalation
    "lateral",          # moving to another host
    "exfiltrate",       # taking data out
    "destroy",          # destructive: delete, encrypt, wipe, DoS
    "social",           # phishing / human manipulation
    "report",           # writing the report out
)

# Actions that are NEVER permitted, whatever a grant says. §7: a program
# prohibition outranks a general permission, so this list is enforced above the
# database rather than being one more row someone has to remember.
NEVER_PERMITTED = ("destroy", "social")

# Actions that require the grant to be explicitly OFFENSIVE. A `research_only`
# grant permits the recognition half and nothing else.
OFFENSIVE_ACTIONS = ("scan", "enumerate", "fuzz", "inject", "exploit",
                     "escalate", "lateral", "exfiltrate")

# ---------------------------------------------------------------------------
# §7 forbidden technique -> permitted equivalent.
# Objective FRAGMENTS -> (permitted technique, why it is permitted).
# Only techniques that reach the same evidence without the prohibited step
# belong here. A mapping to "do it more quietly" would be a rule evasion.
# ---------------------------------------------------------------------------

PROHIBITED_SUBSTITUTES: dict[str, tuple[str, str]] = {
    "sqlmap": ("manual parameterised request construction with a single "
               "delimiter pair, verified by response differential",
               "SQLMap is often auto-banned by WAF fingerprinting; a "
               "hand-built request is both permitted and quieter"),
    "nikto": ("targeted request set derived from the class methodology, each "
              "request carrying an expected-artifact clause",
              "automated scanners trip IDS signatures without producing the "
              "evidence a report needs"),
    "nmap": ("protocol-level service identification from banner and behaviour "
             "on already-authorised hosts",
             "port scanning is frequently out of scope even when the host is "
             "in scope; banner/behaviour reach the same facts"),
    "hydra": ("credential-stuffing detection against a self-registration flow "
              "the program owns, at a documented rate",
              "password-spraying tools are near-universally prohibited"),
    "metasploit": ("a minimal single-purpose proof script whose every request "
                   "is recorded as evidence",
                   "frameworks fire auxiliary modules outside the tested "
                   "scope; an explicit script cannot"),
    "masscan": ("DNS and certificate-transparency enumeration for asset "
                "discovery",
                "raw-SYN scanning is prohibited almost everywhere; the asset "
                "list is what a hunt actually needs first"),
    "dos": ("a resource-exhaustion hypothesis stated as a non-destructive "
            "measurement (concurrency budget observed, latency curve fitted)",
            "denial-of-service is universally prohibited and the measurement "
            "reaches the same finding safely"),
    "phishing": ("an authorization-boundary review of what a low-privilege "
                 "account can reach",
                 "human manipulation is out of scope by policy almost "
                 "everywhere; the privilege question is the actual finding"),
}

_PROHIBITED_PATTERNS = tuple(re.escape(k) for k in PROHIBITED_SUBSTITUTES)


def detect_prohibited(objective: str) -> list[str]:
    """Which prohibited techniques does this objective name?"""
    t = (objective or "").lower()
    return [k for k in PROHIBITED_SUBSTITUTES if k in t]


# ---------------------------------------------------------------------------
# Rate limits (§45). Part of the authorization boundary, not a nicety.
# ---------------------------------------------------------------------------

DEFAULT_RATE_LIMIT: dict[str, Any] = {
    "requests_per_second": 1.0,
    "concurrency": 2,
    "burst": 2,
    "per_host_per_minute": 30,
}


@dataclass
class RateBudget:
    """Requests allowed, requests spent. Deliberately tiny arithmetic.

    The budget is consumed by every outbound action the hunt takes — recon
    probes, browser navigations, tool invocations — so §45's "retries must not
    accidentally become uncontrolled traffic" is a property of the type rather
    than of a call site's discipline.
    """
    requests_per_second: float = 1.0
    concurrency: int = 2
    burst: int = 2
    per_host_per_minute: int = 30
    _host_spend: dict[str, int] = field(default_factory=dict, repr=False)
    _last: float = field(default=0.0, repr=False)

    def _now(self) -> float:
        import time
        return time.monotonic()

    def spend(self, host: str = "-") -> dict[str, Any]:
        """Consume one request. Returns whether it may proceed and why not."""
        import time
        n = self._host_spend.get(host, 0) + 1
        if n > self.per_host_per_minute:
            return {"allowed": False,
                    "reason": f"per-host budget exhausted ({n}/"
                               f"{self.per_host_per_minute} to {host})",
                    "host": host, "spent": n}
        if n > self.burst:
            gap = 1.0 / max(self.requests_per_second, 0.001)
            wait = (n - self.burst) * gap
            elapsed = self._now() - self._last
            if elapsed < wait:
                return {"allowed": False, "reason": "paced", "sleep_s":
                        round(wait - elapsed, 3), "host": host}
        self._host_spend[host] = n
        self._last = self._now()
        return {"allowed": True, "host": host, "spent": n}

    def reset_window(self) -> None:
        self._host_spend.clear()

    def snapshot(self) -> dict[str, Any]:
        return {"requests_per_second": self.requests_per_second,
                "concurrency": self.concurrency, "burst": self.burst,
                "per_host_per_minute": self.per_host_per_minute,
                "spent_by_host": dict(self._host_spend)}


# ---------------------------------------------------------------------------
# The context
# ---------------------------------------------------------------------------

REQUIRED_FIELDS = ("program", "target", "in_scope_assets",
                   "reporting_requirements", "authorization_ref")

# The kinds that permit OFFENSIVE actions (scan/enumerate/fuzz/inject/exploit/
# escalate/lateral/exfiltrate). A kind outside this set permits recognition
# only. `authz.decision` refuses every offensive action for an unknown kind.
OFFENSIVE_KINDS = ("bugbounty", "internal_authorized", "lab", "customer")


@dataclass
class AuthorizationContext:
    program: str = ""
    target: str = ""
    in_scope_assets: list[str] = field(default_factory=list)
    out_of_scope_assets: list[str] = field(default_factory=list)
    allowed_actions: list[str] = field(default_factory=list)
    forbidden_actions: list[str] = field(default_factory=list)
    rate_limits: dict[str, Any] = field(default_factory=dict)
    authentication_context: dict[str, Any] = field(default_factory=dict)
    special_rules: list[str] = field(default_factory=list)
    reporting_requirements: dict[str, Any] = field(default_factory=dict)
    testing_window: dict[str, Any] = field(default_factory=dict)
    authorization_ref: str = ""
    kind: str = "unknown"

    # ---------------------------------------------------------------- helpers
    def __post_init__(self) -> None:
        # MEASURED DEFECT: `budget` used to be a @property that CONSTRUCTED a
        # fresh `RateBudget` on every access. `decision(..., rate=True)` calls
        # `self.budget.spend(host)`, so `_host_spend` and `_last` were reset
        # before every single request — `per_host_per_minute` never accumulated
        # and the pacing gap was always measured against a zero timestamp.
        # The limit existed on paper and enforced nothing (R35: "a budget no
        # call site consults is not a budget" — this one WAS consulted, and
        # still did nothing).
        #
        # The budget is now ONE object per context, built once and shared by
        # every decision. It is deliberately NOT a dataclass field: `to_json`
        # serialises the context for the checkpoint, and a live budget carries
        # mutable spend state that has no business in a persisted record.
        self._budget = self._build_budget()

    def _build_budget(self) -> RateBudget:
        rl = self.rate_limits or DEFAULT_RATE_LIMIT
        return RateBudget(
            requests_per_second=float(rl.get("requests_per_second",
                                             DEFAULT_RATE_LIMIT["requests_per_second"])),
            concurrency=int(rl.get("concurrency", DEFAULT_RATE_LIMIT["concurrency"])),
            burst=int(rl.get("burst", DEFAULT_RATE_LIMIT["burst"])),
            per_host_per_minute=int(rl.get("per_host_per_minute",
                                           DEFAULT_RATE_LIMIT["per_host_per_minute"])))

    @property
    def budget(self) -> RateBudget:
        """The ONE budget for this context. Spend accumulates across calls."""
        return self._budget

    def is_ambiguous(self) -> bool:
        return bool(self.missing_fields())

    def missing_fields(self) -> list[str]:
        """§5: what is genuinely undetermined. Named, never guessed around."""
        miss = [f for f in REQUIRED_FIELDS if not getattr(self, f)]
        if not self.in_scope_assets:
            miss.append("in_scope_assets (empty means nothing is in scope)")
        return miss

    def asset_verdict(self, asset: str) -> str:
        """`in_scope` | `out_of_scope` | `undetermined`. Never inferred."""
        a = _norm(asset)
        if not a:
            return "undetermined"
        for s in self.in_scope_assets:
            if _norm(s) == a:
                return "in_scope"
        for s in self.out_of_scope_assets:
            n = _norm(s)
            if n == a or (n.startswith("*.") and a.endswith(n[1:])):
                return "out_of_scope"
        # §5 explicitly: do not infer from a suffix, a certificate, a redirect
        # or a shared IP. Absent from the list is `undetermined`, and
        # undetermined is NOT in scope.
        return "undetermined"

    # ------------------------------------------------------------ the decision
    def decision(self, action: str, *, asset: str | None = None,
                 rate: bool = False) -> dict[str, Any]:
        """The single gate. Returns a verdict dict; never raises.

        Order is §57's global priority order, evaluated literally:
        authorization -> program rules -> safety -> evidence integrity.
        """
        action = (action or "").strip().lower()
        deny = _deny   # bound locally so the method reads as one decision path

        # 1. Authorization
        if self.is_ambiguous():
            return deny(
                "AMBIGUOUS_AUTHORIZATION",
                f"authorization is materially incomplete: missing "
                f"{', '.join(self.missing_fields())}. Ask the user; do not "
                f"infer it (§5)",
                action=action,
                recognition_only=True)

        if not self.target:
            return deny("NO_TARGET", "no target named", action=action,
                        recognition_only=True)

        # 2. Program rules
        if action in NEVER_PERMITTED:
            return deny(
                "PROHIBITED_TECHNIQUE",
                f"{action!r} is never permitted by this engine regardless of "
                f"grant (§7). Find the permitted equivalent.",
                action=action)

        if action in self.forbidden_actions:
            return deny("PROGRAM_RULE",
                        f"program forbids {action!r}", action=action)

        # 3. Safety — the asset boundary
        host = asset if asset is not None else self.target
        verdict = self.asset_verdict(host)
        if verdict == "out_of_scope":
            return deny(
                "OUT_OF_SCOPE",
                f"{host!r} is recorded as out of scope: discoverable, never "
                f"tested (§6)",
                action=action, asset=host, record_only=True)
        if verdict == "undetermined":
            return deny(
                "UNDETERMINED_ASSET",
                f"{host!r} is in neither scope list; authorization is not "
                f"inferred from DNS, certificates, redirects or shared "
                f"infrastructure (§5)",
                action=action, asset=host, recognition_only=True)

        # 4. The action allow-list
        if action not in ACTIONS:
            return deny("UNKNOWN_ACTION",
                        f"{action!r} is not in the action vocabulary",
                        action=action)
        if action not in self.allowed_actions:
            return deny(
                "ACTION_NOT_ALLOWED",
                f"program allows {sorted(self.allowed_actions) or 'nothing'} "
                f"for {self.program!r}; {action!r} is not among them",
                action=action, asset=host)

        # 5. Offensive actions need explicit offensive permission
        if action in OFFENSIVE_ACTIONS and not self.offensive_allowed():
            return deny(
                "NOT_OFFENSIVE",
                f"{action!r} is offensive; the grant for {host!r} permits "
                f"recognition only",
                action=action, asset=host)

        # 6. Rate limits are part of the boundary (§45), not a later concern
        if rate:
            spend = self.budget.spend(_norm(host))
            if not spend["allowed"]:
                # MEASURED: this passed `detail=spend` as a keyword while
                # `_deny(reason, detail, **kw)` already binds `detail`
                # positionally — a TypeError ("multiple values for argument
                # 'detail'") that turned a rate-limit refusal into a crash.
                # It was unreachable while `budget` rebuilt itself per access
                # and therefore never exceeded its limit. The two were fixed
                # together: the budget now accumulates, so this path runs.
                return deny("RATE_LIMIT", spend["reason"], action=action,
                            asset=host, spend=spend)

        return {"allowed": True, "action": action, "asset": host,
                "basis": f"program={self.program} ref={self.authorization_ref}"}

    def offensive_allowed(self) -> bool:
        return bool(self.kind in OFFENSIVE_KINDS) and "recon" in self.allowed_actions

    # ------------------------------------------------------------- persistence
    def to_json(self) -> dict[str, Any]:
        d = asdict(self)
        d.pop("_host_spend", None)
        d.pop("_last", None)
        return d

    @classmethod
    def from_json(cls, raw: dict[str, Any]) -> "AuthorizationContext":
        fields = {f for f in cls.__dataclass_fields__ if not f.startswith("_")}
        return cls(**{k: v for k, v in (raw or {}).items() if k in fields})

    # ---------------------------------------------------------- §7 resolution
    def resolve_prohibited(self, objective: str) -> dict[str, Any]:
        """Refuse the technique, name the permitted equivalent, keep hunting."""
        hits = detect_prohibited(objective)
        if not hits:
            return {"prohibited": [], "resolved": True,
                    "note": "no prohibited technique named"}
        out = []
        for tech in hits:
            technique, why = PROHIBITED_SUBSTITUTES[tech]
            out.append({"prohibited": tech, "permitted": technique,
                        "why_permitted": why,
                        "gate": self.decision("probe").get("allowed", False)})
        return {
            "prohibited": hits,
            "resolved": True,
            "substitutes": out,
            "note": ("objective rewritten to the permitted equivalent; the "
                     "prohibited technique is not attempted"),
        }

    def register(self, con: sqlite3.Connection, *, scope_key: str = ""
                 ) -> str:
        """Persist as a scope_grant so the orchestrator's existing gate sees it.

        One owner of authorization state: this module is richer, but the row it
        writes is the one `store.check_scope` already reads, so there is no
        second answer to "is this target authorized".
        """
        key = scope_key or f"ctx.{self.program or 'unnamed'}." + (
            _norm(self.target).replace(".", "-") or "no-target")
        store.grant_scope(
            con, key, self.target or "-", self.kind or "research_only",
            self.authorization_ref or "UNSPECIFIED",
            offensive_allowed=self.offensive_allowed())
        con.execute(
            "INSERT OR REPLACE INTO checkpoint(scope, label, state_json, created_at)"
            " VALUES ('authorization', ?, ?, ?)",
            (key, json.dumps(self.to_json(), default=str), store.now()))
        con.commit()
        return key

    def validate_and_record(self, con: sqlite3.Connection, *,
                            hunt_id: str) -> dict[str, Any]:
        """Validate this authorization and RECORD the receipt.

        THE RECEIPT IS WHAT MAKES A FINDING COUNT AS PRODUCTION IMPACT.

        MEASURED 2026-11-02: `finding.provenance` was DERIVED from the
        context of creation and then asserted. `classify_from_context`
        returned PRODUCTION_HUNT for any hunt with an id and a routable
        target, so the system decided on its own that its output was
        production hunting impact -- and nothing in the system recorded
        that the hunt was authorized at all.

        This method is the one place a hunt's authorization becomes a
        PERSISTED FACT. It:

          1. refuses outright when the context is materially incomplete
             (an ambiguous authorization authorises nothing);
          2. asks the single gate whether a probe is permitted against the
             named target;
          3. writes a `hunt_authorization` row recording the program,
             target, kind, authorization reference and whether the
             authorization was VALIDATED.

        The row is the receipt `orch.provenance.authorization_backs`
        consults. A hunt that never reached this method has no receipt,
        and its findings carry UNKNOWN -- which contributes zero impact.

        Returns the verdict. It never raises for a refusal: a refusal is
        a verdict, and the caller records it as one.
        """
        if not hunt_id:
            return {"validated": False, "hunt_id": None,
                    "reason": "no hunt id: an authorization receipt must "
                              "name the hunt it authorises"}
        missing = self.missing_fields()
        if missing:
            return {"validated": False, "hunt_id": hunt_id,
                    "reason": ("authorization is materially incomplete: "
                               f"missing {', '.join(missing)}"),
                    "missing": missing}
        probe = self.decision("probe")
        validated = bool(probe.get("allowed"))
        reason = (probe.get("basis") if validated
                  else (probe.get("detail") or probe.get("reason")
                        or "probe refused"))
        auth_id = f"auth.{hunt_id}"
        con.execute(
            "INSERT OR REPLACE INTO hunt_authorization(auth_id, hunt_id,"
            " program, target, kind, authorization_ref, offensive_allowed,"
            " validated, validated_at, created_at, context_json, note)"
            " VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
            (auth_id, hunt_id, self.program or "UNSPECIFIED",
             self.target or "-", self.kind or "research_only",
             self.authorization_ref or "UNSPECIFIED",
             1 if self.offensive_allowed() else 0,
             1 if validated else 0,
             store.now() if validated else None,
             store.now(),
             json.dumps(self.to_json(), default=str),
             reason))
        con.commit()
        return {"validated": validated, "hunt_id": hunt_id,
                "auth_id": auth_id, "reason": reason,
                "program": self.program, "target": self.target,
                "kind": self.kind,
                "authorization_ref": self.authorization_ref,
                "offensive_allowed": bool(self.offensive_allowed()),
                "note": ("the receipt is persisted; a finding produced by "
                         "this hunt may carry PRODUCTION_HUNT only because "
                         "this row exists and is validated")}

    def load(con: sqlite3.Connection, key: str) -> "AuthorizationContext | None":
        row = con.execute(
            "SELECT state_json FROM checkpoint WHERE scope='authorization' "
            "AND label=?", (key,)).fetchone()
        return cls.from_json(json.loads(row["state_json"])) if row else None


# ---------------------------------------------------------------------------
# §6 scope observation — discovered, recorded, never tested
# ---------------------------------------------------------------------------

class ScopeLedger:
    """The out-of-scope register.

    §6 is a three-step rule (DISCOVER -> RECORD -> DO NOT TEST) and the third
    step is the only one that can fail silently, so the ledger is the only
    place an asset's scope verdict can be obtained during a hunt.
    """

    def __init__(self, con: sqlite3.Connection, ctx: AuthorizationContext):
        self.con = con
        self.ctx = ctx
        self._ensure()

    def _ensure(self) -> None:
        self.con.execute("""
            CREATE TABLE IF NOT EXISTS scope_observation (
              asset        TEXT PRIMARY KEY,
              verdict      TEXT NOT NULL,   -- in_scope|out_of_scope|undetermined
              discovered_by TEXT,
              evidence     TEXT,
              tested       INTEGER NOT NULL DEFAULT 0,
              recorded_at  TEXT NOT NULL
            )""")
        self.con.commit()

    def record(self, asset: str, *, discovered_by: str = "",
               evidence: str = "") -> dict[str, Any]:
        verdict = self.ctx.asset_verdict(asset)
        row = self.con.execute(
            "SELECT verdict, tested FROM scope_observation WHERE asset=?",
            (_norm(asset),)).fetchone()
        if row:
            # Provenance is additive: a later, better-scoped discovery may
            # upgrade `undetermined`, but an asset already marked out of scope
            # can never be quietly promoted by a second observer.
            new = row["verdict"] if row["verdict"] != "undetermined" else verdict
            self.con.execute(
                "UPDATE scope_observation SET verdict=?, discovered_by=?,"
                " evidence=?, recorded_at=? WHERE asset=?",
                (new, discovered_by or "unknown", evidence, store.now(),
                 _norm(asset)))
        else:
            self.con.execute(
                "INSERT INTO scope_observation(asset, verdict, discovered_by,"
                " evidence, tested, recorded_at) VALUES (?,?,?,?,0,?)",
                (_norm(asset), verdict, discovered_by or "unknown", evidence,
                 store.now()))
        self.con.commit()
        return {"asset": asset, "verdict": verdict,
                "tested": False,
                "note": ("recorded; NOT actively tested (§6)"
                         if verdict != "in_scope" else "in scope")}

    def permit_testing(self, asset: str) -> dict[str, Any]:
        """The gate. Returns a verdict; `tested` is written only on success."""
        row = self.con.execute(
            "SELECT verdict, tested FROM scope_observation WHERE asset=?",
            (_norm(asset),)).fetchone()
        if not row:
            return {"allowed": False, "reason": "asset never recorded (§6)",
                    "asset": asset}
        if row["verdict"] != "in_scope":
            return {"allowed": False,
                    "reason": f"asset verdict is {row['verdict']}: discovered "
                              f"and recorded, never actively tested (§6)",
                    "asset": asset, "tested": False}
        return {"allowed": True, "asset": asset, "tested": True}

    def mark_tested(self, asset: str) -> None:
        self.con.execute(
            "UPDATE scope_observation SET tested=1 WHERE asset=?",
            (_norm(asset),))
        self.con.commit()

    def register_all(self, assets: Iterable[str], *, discovered_by: str = ""
                     ) -> list[dict[str, Any]]:
        return [self.record(a, discovered_by=discovered_by) for a in assets]

    def report(self) -> dict[str, Any]:
        rows = self.con.execute(
            "SELECT verdict, count(*) n, sum(tested) tested FROM"
            " scope_observation GROUP BY verdict").fetchall()
        return {r["verdict"]: {"count": r["n"], "tested": r["tested"] or 0}
                for r in rows}

    def assert_untested(self) -> list[str]:
        """Which out-of-scope assets were tested? A non-empty list is a defect.

        This is a self-check the hunt runs before reporting: it is the only way
        §6's third step becomes observable rather than aspirational.
        """
        return [r["asset"] for r in self.con.execute(
            "SELECT asset FROM scope_observation WHERE verdict='out_of_scope'"
            " AND tested=1")]


# ---------------------------------------------------------------------------

def _deny(reason: str, detail: str, **kw) -> dict[str, Any]:
    out = {"allowed": False, "reason": reason, "detail": detail}
    out.update(kw)
    out.setdefault("recognition_only", False)
    out.setdefault("record_only", False)
    return out


def _norm(asset: str) -> str:
    a = (asset or "").strip().lower()
    a = re.sub(r"^https?://", "", a)
    a = a.split("/", 1)[0]
    return a.strip(".")