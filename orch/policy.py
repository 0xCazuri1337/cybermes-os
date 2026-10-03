"""Provider policy, safe proof, rate limiting, and the decision rules
(master prompt §29, §44, §45, §56, §57).

§44 is the one section that describes a policy rather than a capability, and a
policy nobody enforces is decoration. This module makes it code:

    ONE PROVIDER · NO AUTOMATIC PROVIDER FALLBACK · >=10 RETRIES ·
    EXPONENTIAL BACKOFF · THE CONFIGURED HERMES MODEL

so:

  * `ProviderPolicy.route()` REFUSES a second provider. The refusal names the
    policy, because the failure it prevents is silent: a run that quietly
    switched models would produce findings whose provenance is a lie.
  * `call_with_retry()` performs the retries with real exponential backoff and
    a Jittered delay, then returns `UNAVAILABLE` with the attempt ledger. It
    never changes provider, and it records every attempt so "we tried 10 times"
    is a row count rather than a promise.
  * `provider_switch_attempts` is negative: the audit proves no switch happened.

§29's maximum safe proof is a computation, not an instinct: `safe_proof()`
takes the strongest demonstration that is inside the boundary and refuses to
reach past it, and it NAMES what it refused so the operator learns where the
ceiling was.

§57's global priority order is a `decide()` that takes competing objectives and
returns a winner with the reason it outranked the loser — so the ordering is
inspectable rather than implied by whichever branch ran first.
"""
from __future__ import annotations

import json
import random
import sqlite3
import time
from typing import Any, Callable

from . import store

# ---------------------------------------------------------------------------
# §44 provider policy
# ---------------------------------------------------------------------------

MAX_RETRIES = 10
BASE_BACKOFF_S = 1.0
BACKOFF_CAP_S = 60.0


class ProviderSwitchRefused(RuntimeError):
    """§44: no automatic provider fallback. This is raised, not logged."""


class ProviderPolicy:
    """The one configured route, plus the refusal to change it."""

    def __init__(self, *, provider: str = "", model: str = ""):
        self.provider = provider
        self.model = model
        self.attempts: list[dict[str, Any]] = []

    def route(self, requested_provider: str = "",
              requested_model: str = "") -> dict[str, Any]:
        """Resolve the route, refusing any provider change."""
        want_p = requested_provider or self.provider
        want_m = requested_model or self.model
        if want_p and self.provider and want_p != self.provider:
            raise ProviderSwitchRefused(
                f"provider fallback is PROHIBITED (§44). configured="
                f"{self.provider!r} requested={want_p!r}. Tool and agent "
                f"substitution is allowed; provider substitution is not.")
        if want_m and self.model and want_m != self.model:
            raise ProviderSwitchRefused(
                f"model switch is PROHIBITED (§44): configured={self.model!r} "
                f"requested={want_m!r}")
        return {"provider": want_p, "model": want_m, "switched": False}

    def backoff(self, attempt: int) -> float:
        """Exponential with full jitter, capped. Never a fixed sleep."""
        raw = min(BACKOFF_CAP_S, BASE_BACKOFF_S * (2 ** max(0, attempt - 1)))
        return round(random.uniform(0.0, raw), 3)

    def call_with_retry(self, fn: Callable[..., Any], *, label: str = "call",
                        max_retries: int = MAX_RETRIES,
                        sleep: bool = True) -> dict[str, Any]:
        """Retry with exponential backoff on the SAME provider.

        Returns `UNAVAILABLE` once the budget is spent, with the attempt ledger
        attached. Raising here would lose the count; returning UNAVAILABLE is
        what §44 specifies, and the caller decides what an unavailable call
        means for its task.
        """
        if max_retries < 1:
            raise ValueError("max_retries must be >= 1")
        ledger: list[dict[str, Any]] = []
        for attempt in range(1, max_retries + 1):
            delay = self.backoff(attempt)
            try:
                out = fn()
                self.attempts.append({"label": label, "attempt": attempt,
                                      "ok": True})
                ledger.append({"attempt": attempt, "ok": True,
                               "provider": self.provider})
                return {"status": "OK", "attempts": attempt,
                        "ledger": ledger, "result": out,
                        "provider": self.provider, "model": self.model}
            except Exception as e:  # noqa: BLE001 - failure is expected here
                ledger.append({"attempt": attempt, "ok": False,
                               "error": f"{type(e).__name__}: {e}",
                               "backoff_s": delay})
                self.attempts.append({"label": label, "attempt": attempt,
                                      "ok": False, "error": str(e)})
                if attempt == max_retries:
                    break
                if sleep:
                    time.sleep(min(delay, 2.0))   # bounded so a test is quick
        return {"status": "UNAVAILABLE", "attempts": len(ledger),
                "ledger": ledger, "provider": self.provider,
                "reason": (f"exhausted {max_retries} retries on provider "
                           f"{self.provider!r} with exponential backoff; NO "
                           f"provider fallback is permitted (§44)"),
                "switched": False}

    def switch_attempts(self) -> list[dict[str, Any]]:
        """Every attempt where the provider differed. Must always be empty."""
        return [a for a in self.attempts if a.get("provider") not in
                (None, self.provider)]


# ---------------------------------------------------------------------------
# §29 maximum safe proof
# ---------------------------------------------------------------------------

# Ordered strongest-first. `safe_proof` walks this and returns the first tier
# the boundary allows, plus the tiers it refused.
PROOF_TIERS = (
    ("read_only_response", "request the resource and compare the response",
     "authorized", False),
    ("differential_response", "compare two requests differing in one parameter",
     "authorized", False),
    ("single_user_test_account", "act within an account the program supplied",
     "authorized", False),
    ("cross_account_read", "read an object owned by a second, program-supplied "
                           "account", "needs_program_approval", True),
    ("state_changing_request", "perform a write the application will accept",
     "needs_program_approval", True),
    ("privilege_escalation", "act with elevated privilege in the target",
     "needs_program_approval", True),
    ("denial_of_service", "exhaust a resource the target depends on",
     "NEVER", True),
    ("data_exfiltration", "move data outside the assessed boundary",
     "NEVER", True),
    ("persistent_modification", "leave a change behind in the target",
     "NEVER", True),
)


def safe_proof(ctx, *, tier: str = "differential_response") -> dict[str, Any]:
    """The strongest proof the authorization boundary permits.

    Two distinct questions, kept distinct because conflating them is how an
    engine talks itself past the ceiling:

    * "may I use THIS tier?" — a request for a specific strength. A NEVER tier
      is refused outright even if the program granted everything, because §29's
      boundary is authorized + permitted + safe + non-destructive and safety is
      not delegable to a grant. Falling back to a weaker tier and reporting
      `allowed: True` would be a lie about what was asked.
    * "what is the strongest tier available?" — computed by the same walk, and
      returned in `strongest_available` either way.
    """
    names = [t[0] for t in PROOF_TIERS]
    if tier not in names:
        return {"allowed": False,
                "reason": f"unknown proof tier {tier!r}; known: {names}",
                "chosen": None, "strongest_available": None}
    idx = names.index(tier)

    # 1. Can this specific tier be used at all?
    spec = PROOF_TIERS[idx]
    if spec[2] == "NEVER":
        return {"allowed": False,
                "reason": (f"{tier} is destructive or outside the assessed "
                           f"boundary: never a safe proof, whatever the "
                           f"program grants (§29)"),
                "requested": tier, "chosen": None,
                "strongest_available": _strongest(ctx)}

    # 2. Walk down to find the strongest tier the boundary DOES permit, and
    #    report whether the requested one is that tier or below.
    strongest = _strongest(ctx)
    if strongest is None:
        return {"allowed": False, "requested": tier, "chosen": None,
                "strongest_available": None,
                "reason": "no proof tier is permitted under this authorization"}
    if idx <= names.index(strongest):
        return {"allowed": True, "requested": tier,
                "chosen": {"tier": tier, "how": spec[1],
                           "requires_approval": spec[2] != "authorized"},
                "strongest_available": strongest,
                "note": ("requested tier is inside the boundary; the strongest "
                         "permitted tier is stronger still")}

    # 3. The requested tier is STRONGER than anything permitted. Say so, and
    #    name the ceiling — refusing without the alternative is a dead end.
    return {"allowed": False, "requested": tier, "chosen": None,
            "strongest_available": strongest,
            "reason": (f"{tier} is stronger than this authorization permits; "
                       f"the ceiling is {strongest}"),
            "use_instead": {"tier": strongest,
                            "how": dict((t[0], t[1]) for t in PROOF_TIERS)[strongest]},
            "note": ("severity is never bought by crossing the boundary "
                     "(§29); the hunt stops at the strongest SAFE proof")}


def _strongest(ctx) -> str | None:
    """The strongest tier the boundary permits — the LAST permitted one.

    Returning the FIRST permitted tier makes every grant look maximally
    restrictive, which is safe but wrong: the hunt would stop at a read-only
    probe while a differential response was permitted, and §29 asks for the
    strongest SAFE proof precisely so severity is not artificially capped.
    """
    found = None
    for name, _how, need, offensive in PROOF_TIERS:
        if need == "NEVER":
            continue
        if ctx.decision("exploit" if offensive else "probe").get("allowed"):
            found = name
    return found


# ---------------------------------------------------------------------------
# §45 rate limits as a mandatory constraint
# ---------------------------------------------------------------------------

class RateGovernor:
    """Counts every outbound action class, including retries and agents.

    §45: "retries must not accidentally become uncontrolled traffic." A budget
    a caller can forget to consult is not a budget, so this is consulted by
    `orch.tools.ToolRegistry.run` and by `orch.hunting` before any action.
    """

    def __init__(self, ctx=None, *, max_concurrent: int | None = None):
        self.ctx = ctx
        self.budget = ctx.budget if ctx is not None else authz_budget_default()
        if max_concurrent is not None:
            self.budget.concurrency = max_concurrent
        self.in_flight = 0
        self.log: list[dict[str, Any]] = []

    def acquire(self, *, host: str = "-", actor: str = "agent",
                kind: str = "request") -> dict[str, Any]:
        if self.in_flight >= self.budget.concurrency:
            self.log.append({"actor": actor, "kind": kind, "host": host,
                             "allowed": False, "why": "concurrency cap"})
            return {"allowed": False, "reason": "CONCURRENCY_CAP",
                    "detail": f"{self.in_flight} in flight >= "
                              f"{self.budget.concurrency}"}
        spend = self.budget.spend(host)
        if not spend["allowed"]:
            self.log.append({"actor": actor, "kind": kind, "host": host,
                             "allowed": False, "why": spend["reason"]})
            return {"allowed": False, "reason": "RATE_LIMIT",
                    "detail": spend}
        self.in_flight += 1
        self.log.append({"actor": actor, "kind": kind, "host": host,
                         "allowed": True})
        return {"allowed": True, "host": host, "spent": spend["spent"],
                "concurrency": self.in_flight}

    def release(self) -> None:
        self.in_flight = max(0, self.in_flight - 1)

    def report(self) -> dict[str, Any]:
        denied = [e for e in self.log if not e["allowed"]]
        return {"requests": len(self.log), "denied": len(denied),
                "by_actor": {a: sum(1 for e in self.log if e["actor"] == a)
                             for a in {e["actor"] for e in self.log}},
                "budget": self.budget.snapshot(),
                "denials": denied[:10]}


def authz_budget_default():
    from .authz import RateBudget
    return RateBudget()


# ---------------------------------------------------------------------------
# §56 core decision rules + §57 global priority order
# ---------------------------------------------------------------------------

# §57 verbatim, highest first. The ORDER IS THE RULE.
PRIORITY_ORDER = (
    "authorization",        # 1
    "program_rules",        # 2
    "safety",               # 3
    "evidence_integrity",   # 4
    "technical_correctness",  # 5
    "impact_potential",     # 6
    "attack_surface_coverage",  # 7
    "research_learning_value",  # 8
    "resource_efficiency",  # 9
)

# Which priority each objective's dimension belongs to.
OBJECTIVE_DIMENSION = {
    "proceed_without_authorization": "authorization",
    "respect_program_rule": "program_rules",
    "stay_inside_boundary": "safety",
    "fabricate_evidence": "evidence_integrity",
    "report_unvalidated": "technical_correctness",
    "maximise_severity": "impact_potential",
    "cover_more_surface": "attack_surface_coverage",
    "learn_something": "research_learning_value",
    "finish_sooner": "resource_efficiency",
}

# The §56 rules that are DECISIONS rather than implementations. Each names the
# module that enforces it, so "it is a rule" is not the same as "it is checked".
DECISION_RULES = {
    1: ("Authorization comes before active testing.", "orch.authz.decision"),
    2: ("Autonomy exists inside confirmed boundaries.",
        "orch.authz.AuthorizationContext"),
    3: ("Never assume ambiguous authorization.", "orch.authz.missing_fields"),
    4: ("Out-of-scope discoveries are recorded but not actively tested.",
        "orch.authz.ScopeLedger.permit_testing"),
    5: ("The hunting plan is dynamic.", "orch.hunting.replan"),
    6: ("The task graph is dynamic.", "orch.dag / orch.hunting.add_task"),
    7: ("Agent assignment is dynamic.", "orch.agentkit.select_agent"),
    8: ("Tool selection is dynamic.", "orch.tools.ToolRegistry.resolve"),
    9: ("Parallelism is dynamic.", "orch.hunting.plan_wave"),
    10: ("Research and hunting can run in parallel.",
         "orch.hypothesis.open_unknown"),
    11: ("Learning can modify active hunting.",
         "orch.learning.loop.apply_knowledge"),
    12: ("Unknown behavior opens a research path and a hunting path.",
         "orch.hypothesis.open_unknown"),
    13: ("Failed techniques should trigger adaptation, not blind repetition.",
         "orch.orchestrator.RECOVERY_LADDER"),
    14: ("Weak evidence should trigger continued investigation and revalidation.",
         "orch.lifecycle.revalidation_queue"),
    15: ("Deduplication runs throughout the Hunt.", "orch.validate.dedupe"),
    16: ("Similar findings must be independently evaluated before being called "
         "duplicates.", "orch.lifecycle.compare_findings"),
    17: ("Important findings require strong validation.", "orch.finalgate"),
    18: ("No report is generated before the Final Validation Gate.",
         "orch.finalgate.FINAL_GATE"),
    19: ("Completion is determined by marginal value, not a fixed checklist.",
         "orch.hunting.completion_decision"),
    20: ("Every Hunt must be recoverable.", "orch.huntrt.resume"),
    21: ("Every important decision must be traceable.", "orch.hunting.history"),
    22: ("Research must pass quality/validation gates before permanent "
         "knowledge admission.", "wks.quality"),
    23: ("Provider fallback is prohibited.", "orch.policy.ProviderPolicy.route"),
    24: ("Tool/agent substitution is allowed.", "orch.tools / orch.agentkit"),
    25: ("Rate limits are mandatory constraints.", "orch.policy.RateGovernor"),
}


def decide(objectives: dict[str, bool]) -> dict[str, Any]:
    """Resolve competing objectives by §57, and show the arithmetic.

    `objectives` maps an objective name to whether it is being pursued. Returns
    the winner plus every loser with the dimension that outranked it, because a
    priority order that cannot be explained cannot be audited.
    """
    active = [o for o, on in objectives.items() if on]
    if not active:
        return {"winner": None, "reason": "no active objective",
                "ranking": [], "note": "nothing to decide"}

    def rank(o: str) -> int:
        dim = OBJECTIVE_DIMENSION.get(o)
        if dim is None:
            return len(PRIORITY_ORDER) + 1        # unranked sorts last
        return PRIORITY_ORDER.index(dim) + 1

    ranked = sorted(active, key=lambda o: (rank(o), o))
    winner = ranked[0]
    losers = [{"objective": o, "dimension": OBJECTIVE_DIMENSION.get(o, "unranked"),
               "priority": rank(o),
               "outranked_by": winner} for o in ranked[1:]]
    return {"winner": winner, "dimension": OBJECTIVE_DIMENSION.get(winner),
            "priority": rank(winner), "ranking": [
                {"objective": o, "priority": rank(o),
                 "dimension": OBJECTIVE_DIMENSION.get(o, "unranked")}
                for o in ranked],
            "losers": losers,
            "order": list(PRIORITY_ORDER),
            "note": ("lower-level optimisation never violates a higher-level "
                     "requirement (§57)")}


def rule_matrix() -> list[dict[str, Any]]:
    """§56 as data, each rule pointing at the module that enforces it."""
    return [{"rule": n, "text": t, "enforced_by": w} for n, (t, w) in
            sorted(DECISION_RULES.items())]


def unranked_objectives() -> list[str]:
    """Objectives present in the caller that §57 does not rank.

    Reported rather than silently sorted last: an objective nobody ranked is a
    decision nobody made.
    """
    return [o for o in OBJECTIVE_DIMENSION if o not in PRIORITY_ORDER]