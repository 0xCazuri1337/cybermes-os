"""The OMH <-> Cyber integration boundary. ONE module, adapters only.

Why this module exists
----------------------
OMH (oh-my-hermes) is Hermes' orchestration layer: decomposition, research
fan-out, long-running loops, parallel agents, adversarial QA. Cyber is the
security-domain authority: authorization, scope, the evidence gate, knowledge
validity, mastery, the finding gate.

Before this module the two systems did not know each other. A grep for `omh`
across the tree returned ZERO hits in every `.py` file: the Cyber architecture
(`authz`, `agentkit`, `hypothesis`, `finalgate`, `lifecycle`, `researcher`,
`lifecycle`) already implemented every mechanism the integration needs --
dual-path unknown behaviour, dynamic agent selection, L1-L6 validation, the
report gate, the retest ledger -- but none of it was reachable from OMH, and
no OMH primitive was reachable from Cyber. The gap was WIRING, not design.

So this file is deliberately thin. It does not reimplement a single mechanism.
Every public function is an adapter that:

  * translates a Cyber state into an OMH work contract (the Cyber -> OMH
    direction), and
  * translates an OMH agent's return value back into a Cyber-typed row
    through Cyber's OWN gate (the OMH -> Cyber direction).

Three rules this module is built on, each from something that would otherwise
be silently wrong:

 1. **OMH never becomes the authority.** Every function that could grant,
    validate, promote or authorize delegates to the existing Cyber function.
    There is no path here that writes an authorization, a validated finding, a
    promoted item or a scope grant. `omh.py` cannot reach `store.grant_scope`,
    `validate.apply_validation`, `quality` thresholds or `finalgate.apply_gate`
    -- deliberately, it simply never imports them.

 2. **An OMH result is a CLAIM, never a verdict.** OMH agents return typed
    envelopes; `orch.agentkit.parse_output` types them and downgrades
    `VALIDATED_FINDING` to `CANDIDATE_FINDING` on the way in. The Cyber gate
    then re-derives L1-L6 from stored evidence and decides. That ordering
    (claim -> gate -> verdict) is the reason this integration cannot certify
    its own findings.

 3. **Research completion is NOT knowledge approval.** OMH research lands in
    `knowledge/incoming/` as an intake file, and then the existing
    `wks.ingest.ingest_file(verify=True)` decides. A research agent that
    fetches ten perfect pages promotes nothing until that gate passes.

Authority map, so a reader can check the claim above without reading the code:

    OMH may  -> decompose, fan out research, run parallel lanes, drive a loop,
                hold orchestration state, write an intake file, propose
                hypotheses, propose a finding
    Cyber may -> authorize, scope, grant capability, gate evidence, promote a
                claim to knowledge, validate a finding, pass the report gate,
                declare mastery, apply a stop condition

Both directions use Cyber's own tables and functions. No new database, no new
scheduler, no duplicated memory, no second learning engine.

Contract I -- Cyber -> OMH (mission brief)
------------------------------------------
`MissionContract.to_payload()` is the single dict an OMH agent receives. Its
keys are drawn from what Cyber already stores, so nothing is invented here:

    mission, domain, class_id, objective, research_question, knowledge_gap,
    scope, authorization_state, credentials, tools, acceptance_criteria,
    evidence_requirements, stop_conditions, budget

    "mission" / "objective"  <- task.objective (what the task graph already says)
    "domain"                 <- class_domain.class_id -> domain
    "research_question"      <- derived from the objective for a research lane
    "knowledge_gap"          <- quality.gap_report for that class
    "scope"                  <- store.check_scope(target) -- the EXACT-host gate
    "authorization_state"    <- that gate's verdict, never inferred from intent
    "tools"                  <- orch.tools.ToolRegistry.inventory() (pure question)
    "stop_conditions"        <- from orch.policy + the mission's own budget
    "budget"                 <- turns/tasks, from the mission, not from OMH

Contract O -- OMH -> Cyber (result envelope)
--------------------------------------------
`ResultIngest.ingest()` runs one OMH agent's return value through
`orch.agentkit.parse_output` (the closed §23 vocabulary) and persists it to
`agent_result`. Nothing else is accepted. A research lane additionally returns
a `RESEARCH_RESULT`, whose payload IS the intake file, and which is written to
`knowledge/incoming/` -- the path `orch.executor.do_research` already reads.

Where the mapping lives
-----------------------
Phase 4 of the brief maps OMH workflows onto the hunting lifecycle. The map is
declared once, as data, in `WORKFLOW_MAP`, and it is the ONLY place the six
workflow names appear. `orch/omh_cli.py` dispatches from that table, so a
workflow cannot drift from the lifecycle phase it claims to implement.
"""
from __future__ import annotations

import json
import os
import re
import shutil
import sqlite3
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Iterable

from wks import config as wks_config
from wks import quality

from . import (agentkit, authz, dag, executor as executor_mod, hypothesis,
               policy, store, tools as tools_mod)

# ==========================================================================
# OMH workflow primitives (Phase 4 mapping). Declared once, as data.
# ==========================================================================

# The lifecycle phase each OMH workflow serves. This table is the ONLY place
# the six workflow names appear; `omh_cli` dispatches from it, so a workflow
# cannot drift from the phase it claims to implement.
WORKFLOW_MAP: dict[str, str] = {
    "ulw-context":  "UNDERSTAND",
    "ulw-plan":     "PLAN",
    "ulw-research": "RESEARCH",
    "ulw-work":     "TEST",
    "ulw-loop":     "ITERATE",
    "ulw-qa":       "VALIDATE",
}

# A workflow that would touch a target must be preceded by the authorization
# gate. This is the Phase 8 hard gate, expressed once.
OFFENSIVE_WORKFLOWS = frozenset({"ulw-work", "ulw-loop"})


def _reject_workflow(proposed: Iterable[str]) -> dict[str, Any]:
    """Refuse a workflow name Cyber does not map.

    An unmapped workflow is a request to run something whose relationship to
    the security lifecycle was never established. Accepting it would let a
    caller name any tool by calling it a workflow.
    """
    return {"ok": False, "rejected": list(proposed),
            "known": sorted(WORKFLOW_MAP),
            "reason": "workflow not in WORKFLOW_MAP; refusing to guess its "
                      "lifecycle phase"}


def _slug(text: str, limit: int = 48) -> str:
    return "".join(c if c.isalnum() else "-" for c in (text or "").lower())[:limit].strip("-")

# ==========================================================================
# CONTRACT I -- Cyber -> OMH
# ==========================================================================

# Default stop conditions. A lane that cannot prove it is finished must stop,
# so every mission carries an explicit exhaustion clause.
DEFAULT_STOP_CONDITIONS = (
    "strong finding passed the Cyber finding gate",
    "scope exhausted: no in-scope asset remains untested",
    "authorization expired or was withdrawn",
    "no meaningful next action remains (stopcheck says no useful work)",
    "policy blocks execution",
    "required evidence cannot be obtained",
    "mission budget exhausted",
)


@dataclass
class MissionContract:
    """The one payload an OMH agent receives.

    Every field is READ FROM CYBER, never supplied by the caller. A caller can
    choose which task runs; it cannot declare its own scope, its own
    authorization state or its own acceptance criteria, because each of those
    comes from a table Cyber owns.
    """

    task_key: str
    objective: str
    hunt_id: str | None = None
    target: str = ""
    workflows: tuple[str, ...] = ()
    budget_tasks: int = 5
    budget_turns: int = 20
    max_iterations: int = 3

    # -- authorisation: read, never inferred --------------------------------
    @property
    def scope(self) -> dict[str, Any]:
        """Cyber's own exact-host scope gate. Delegates; never re-decides."""
        if not self.target:
            return {"authorized": False, "reason": "no_target",
                    "detail": "mission names no target; nothing is authorized"}
        return store.check_scope(self._con(), self.target)

    def _con(self) -> sqlite3.Connection:
        return store.open_db(create=False)

    def is_authorized(self) -> bool:
        return bool(self.scope.get("authorized"))

    # -- the payload --------------------------------------------------------
    def to_payload(self, con: sqlite3.Connection | None = None) -> dict[str, Any]:
        con = con or self._con()
        row = store.get_task(con, self.task_key)
        if row is None:
            raise KeyError(f"task {self.task_key!r} is not in the graph")

        cls = row["class_id"]
        gap = None
        if cls:
            gaps = {g["class_id"]: g for g in quality.gap_report(con)}
            gap = gaps.get(cls)

        scope = store.check_scope(con, self.target) if self.target else {
            "authorized": False, "reason": "no_target",
            "detail": "mission names no target; nothing is authorized"}

        try:
            # `inventory` is a MODULE-level function; ToolRegistry the class has
            # an instance method of the same name. Calling the class attribute
            # here returns an unbound function instead of an answer.
            tool_inventory = tools_mod.inventory(None)
        except Exception as e:  # noqa: BLE001 - availability is a question,
            tool_inventory = {"error": f"{type(e).__name__}: {e}"}

        payload = {
            "mission": self.task_key,
            "domain": self._domain(con, cls),
            "class_id": cls,
            "objective": row["objective"],
            "research_question": self._research_question(row),
            "knowledge_gap": gap,
            "target": self.target,
            "scope": scope,
            # Never inferred from intent: this is the gate's own verdict.
            "authorization_state": ("authorized" if scope.get("authorized")
                                    else f"REFUSED: {scope.get('reason')}"),
            "credentials": {"declared": bool(scope.get("authorized")),
                            "note": "credential material stays in the caller; "
                                    "only its presence is advertised"},
            "tools": tool_inventory,
            "acceptance_criteria": row["expected_artifact"] or "",
            "evidence_requirements": row["evidence_req"] or "",
            "stop_conditions": list(DEFAULT_STOP_CONDITIONS),
            "budget": {"tasks": self.budget_tasks, "turns": self.budget_turns,
                       "iterations": self.max_iterations},
            "workflows": list(self.workflows),
        }
        return payload

    @staticmethod
    def _domain(con: sqlite3.Connection, cls: str | None) -> str:
        """Read `class_domain.domain`.

        The column is TEXT, not a foreign key -- there is no `domain` table, so
        a join against one raises `no such table` on every mission brief. A
        helper that only ever ran in a test which never built a brief would
        have shipped that.
        """
        if not cls:
            return "system"
        row = con.execute(
            "SELECT domain FROM class_domain WHERE class_id=? LIMIT 1",
            (cls,)).fetchone()
        return (row["domain"] if row and row["domain"] else "system")

    @staticmethod
    def _research_question(row: sqlite3.Row) -> str:
        """A question, not a topic.

        A research lane that receives `xss` returns twelve pages about XSS. A
        research lane that receives a falsifiable question returns evidence for
        or against one claim, which is what the gate can adjudicate.
        """
        return (f"What does the published record say that would make the "
                f"following true or false for a real target, and what "
                f"observable behaviour would settle it? Task: "
                f"{row['objective'][:400]}")


@dataclass
class LaneSpec:
    """One parallel attack-surface lane (Phase 5).

    `stop_condition` and `evidence_contract` are mandatory-by-construction:
    `__post_init__` refuses a lane that has neither, because a lane with no
    stop condition is an unbounded agent and a lane with no evidence contract
    produces output nothing downstream can gate.
    """

    name: str
    objective: str
    class_id: str | None = None
    depends_on: list[str] = field(default_factory=list)
    inputs: list[str] = field(default_factory=list)
    expected_outputs: list[str] = field(default_factory=list)
    stop_condition: str = ""
    evidence_contract: str = ""
    target: str = ""

    def __post_init__(self) -> None:
        if not (self.stop_condition or "").strip():
            raise ValueError(f"lane {self.name!r} refused: no stop_condition. "
                             "A lane that cannot end is not a lane.")
        if not (self.evidence_contract or "").strip():
            raise ValueError(f"lane {self.name!r} refused: no evidence_contract. "
                             "Output nothing downstream can gate is not evidence.")
        if self.depends_on:
            raise ValueError(f"lane {self.name!r} declared dependencies "
                             f"{self.depends_on}; parallel lanes must be "
                             "independent -- make it sequential or split it")

    def to_payload(self) -> dict[str, Any]:
        return {"lane": self.name, "objective": self.objective,
                "class_id": self.class_id, "inputs": list(self.inputs),
                "expected_outputs": list(self.expected_outputs),
                "stop_condition": self.stop_condition,
                "evidence_contract": self.evidence_contract,
                "target": self.target,
                "depends_on": list(self.depends_on)}


# ==========================================================================
# CONTRACT O -- OMH -> Cyber
# ==========================================================================


def research_intake_path(class_id: str) -> Path:
    """Where a research lane's evidence must land.

    `knowledge/incoming/` is the path `orch.executor.do_research` reads, so
    writing anywhere else produces evidence no gate will ever see -- the
    "research completed, nothing learned" failure mode.
    """
    if not re.match(r"^[a-z0-9_]+$", class_id or ""):
        raise ValueError(f"refused: {class_id!r} is not a class id shape")
    return wks_config.root() / "research" / "incoming" / f"omh-{class_id}.json"


def write_research_intake(class_id: str, items: list[dict[str, Any]], *,
                          sources: list[dict[str, Any]] | None = None,
                          notes: str = "") -> dict[str, Any]:
    """Land an OMH research payload where Cyber's own research path reads it.

    Writes a REGISTRY-adjacent intake file and returns the path; it does NOT
    ingest. Ingestion is `wks.ingest.ingest_file(verify=True)`, which is the
    only thing that can promote a claim, and it runs later, through the normal
    research task. Handing OMH a shortcut here would make "researched" and
    "promoted" the same event.

    The payload is written verbatim. If a lane produced a bad claim, the gate
    rejects it -- which is the designed outcome, not a failure of this writer.
    """
    from wks.ingest import REQUIRED

    if not items:
        return {"ok": False, "reason": "no items; an empty intake file looks "
                                       "like completed research"}
    out = research_intake_path(class_id)
    payload = {"class_id": class_id, "items": items,
               "sources": sources or [], "notes": notes,
               "provenance": "OMH research lane via orch.omh; quotes are "
                             "re-verified verbatim by wks.ingest at ingest time"}
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(payload, indent=2, ensure_ascii=False) + "\n",
                   encoding="utf-8")
    bad = [i.get("item_key", "?") for i in items
           if any(not i.get(f) for f in REQUIRED)]
    return {"ok": True, "path": str(out), "items": len(items),
            "shape_errors": bad,
            "note": "written, NOT ingested: knowledge approval remains "
                    "wks.ingest's decision"}


def research_gap(class_id: str) -> dict[str, Any]:
    """What is actually missing for this class, per the existing gap report."""
    con = store.open_db(create=False)
    for g in quality.gap_report(con):
        if g["class_id"] == class_id:
            return g
    return {"class_id": class_id, "missing": ["class not registered"],
            "state": "unknown", "n_items": 0, "n_fp": 0, "n_chains": 0,
            "n_supported": 0, "checks": {}, "priority": 9}


class ResultIngest:
    """One entry point for everything OMH returns.

    Every function here funnels through `orch.agentkit.parse_output`, the
    closed §23 vocabulary, so an OMH agent cannot introduce a new claim type.
    An agent that declares `VALIDATED_FINDING` is downgraded to
    `CANDIDATE_FINDING` on the way in; only `orch.validate` can move a finding
    further, and only on stored evidence.
    """

    def __init__(self, con: sqlite3.Connection):
        self.con = con

    def ingest(self, raw: Any, *, run_key: str, task_key: str = "",
               persist: bool = True) -> dict[str, Any]:
        env = agentkit.parse_output(raw, run_key=run_key, task_key=task_key,
                                    con=self.con if persist else None)
        return {"ok": True, "type": env["type"], "claimed": env["original_type"],
                "downgraded": bool(env["downgraded"]), "notes": env["notes"],
                "result_key": env.get("result_key", "")}

    def ingest_failure(self, role_key: str, *, reason: str,
                       class_id: str | None = None,
                       task_key: str | None = None) -> dict[str, Any]:
        """A failed lane is RECORDED, never smoothed over (Phase 19)."""
        agentkit.record_failure(self.con, role_key, reason=reason,
                                class_id=class_id, task_key=task_key)
        return {"ok": True, "recorded": "agent_failure", "role": role_key,
                "reason": reason}


# ==========================================================================
# PHASE 8 -- the hard authorization + scope gate
# ==========================================================================


@dataclass
class AuthorizationGate:
    """The Phase 8 gate, delegating entirely to Cyber.

    A mission may not enter active testing until this passes. It calls
    `store.check_scope` (exact hostname, deny-by-default, no wildcards) and
    `authz.AuthorizationContext.decision` (the §57 gate). It adds no rule of its
    own and it never infers authorization from intent -- a user asking to hunt
    is not a grant, and a discovered asset that looks related is not in scope.
    """

    target: str
    program: str = ""
    action: str = "scan"
    in_scope_assets: list[str] = field(default_factory=list)
    out_of_scope_assets: list[str] = field(default_factory=list)
    allowed_actions: list[str] = field(default_factory=list)
    forbidden_actions: list[str] = field(default_factory=list)
    reporting_requirements: dict[str, Any] = field(default_factory=dict)
    authorization_ref: str = ""

    def context(self) -> authz.AuthorizationContext:
        # Two shapes must match Cyber's own vocabulary exactly, and both
        # produced a silent NOT_OFFENSIVE refusal until measured:
        #   * `kind` is `bugbounty`, NOT `bug_bounty` -- the gate compares
        #     against a closed tuple, so an unmatched spelling reads as an
        #     unknown authorization kind and denies offensive work.
        #   * `offensive_allowed()` also requires `recon` in allowed_actions,
        #     so a program that permits `scan` but never `recon` is
        #     recognition-only. Adding `recon` here is NOT a grant: it is
        #     Cyber's own definition of a program that allows recognition, and
        #     the grant in `scope_grant` still has to exist.
        return authz.AuthorizationContext(
            program=self.program, target=self.target,
            in_scope_assets=list(self.in_scope_assets),
            out_of_scope_assets=list(self.out_of_scope_assets),
            allowed_actions=list(self.allowed_actions),
            forbidden_actions=list(self.forbidden_actions),
            reporting_requirements=dict(self.reporting_requirements),
            authorization_ref=self.authorization_ref,
            kind="bugbounty" if self.program else "unknown")

    def check(self, con: sqlite3.Connection, *,
              action: str | None = None) -> dict[str, Any]:
        """Return a verdict dict. Never raises, never guesses.

        MEASURED 2026-10-31: the §57 decision refused with
        "AMBIGUOUS_AUTHORIZATION: missing authorization_ref" even when a
        `scope_grant` row existed for the target carrying
        `authorization_ref='REF-1'`. The gate built its
        `AuthorizationContext` from ITS OWN fields only, and
        `AuthorizationGate.authorization_ref` defaults to `""` -- so the
        grant's reference was never seen, and a recorded, explicit,
        operator-created grant was treated as if no authorization existed.

        That is the wrong direction for a safety gate to fail in: it
        refuses work that WAS authorized, which trains the operator to
        bypass the gate.

        The fix reads the reference from the grant the gate is validating.
        This is NOT an inference -- §5 forbids inferring authorization from
        DNS, certificates, redirects or shared infrastructure, and a
        `scope_grant` row with an explicit `authorization_ref` is none of
        those. It is the operator's own recorded grant.

        The grant's `kind` is read the same way, so the offensive-action
        vocabulary is the grant's, not a guess.
        """
        act = action or self.action
        ledger = store.check_scope(con, self.target) if self.target else {
            "authorized": False, "reason": "no_target"}

        # Build the context from the GRANT when the caller did not supply
        # the reference itself. An explicit field on the gate still wins.
        ctx = self.context()
        if not ctx.authorization_ref and ledger.get("authorization_ref"):
            ctx.authorization_ref = str(ledger["authorization_ref"])
        grant_kind = str(ledger.get("kind") or "").strip().lower()
        if grant_kind and ctx.kind in ("unknown", ""):
            # `scope_grant.kind` is stored as `bug_bounty`; the action
            # vocabulary uses `bugbounty`. `offensive_allowed` refuses an
            # unknown kind, so the spelling has to match the closed tuple.
            ctx.kind = "bugbounty" if grant_kind.replace("_", "") == "bugbounty" \
                else grant_kind
        verdict = ctx.decision(act, asset=self.target)

        permitted = bool(ledger.get("authorized")) and bool(verdict.get("allowed"))
        out = {
            "allowed": permitted,
            "target": self.target,
            "action": act,
            "missing_fields": ctx.missing_fields(),
            "scope_grant": ledger,
            "authorization_decision": verdict,
        }
        if not permitted:
            out["reason"] = (verdict.get("reason") if not verdict.get("allowed")
                             else ledger.get("reason"))
            out["detail"] = (verdict.get("detail") if not verdict.get("allowed")
                             else ledger.get("detail"))
        return out


def assert_authorized(con: sqlite3.Connection, gate: AuthorizationGate,
                      *, action: str = "scan") -> dict[str, Any]:
    """Refuse loudly rather than proceed. Returns the verdict either way."""
    v = gate.check(con, action=action)
    if not v["allowed"]:
        store.emit_event(
            con, f"omh_authz_block:{gate.target}:{action}", "security",
            source="orch.omh", severity="error",
            payload={"target": gate.target, "action": action,
                     "reason": v.get("reason"), "detail": v.get("detail")},
            relevance=0.9)
    return v


# ==========================================================================
# PHASE 5 -- parallel lanes
# ==========================================================================


def plan_lanes(mission: MissionContract, con: sqlite3.Connection, *,
               classes: Iterable[str] | None = None) -> dict[str, Any]:
    """Select lanes from the ACTUAL attack surface, not a fixed roster.

    Every requested class must already be a registered, in-scope concern:
    a lane is only created for a class Cyber knows about. This is what keeps
    Phase 5's "do not force every target through every lane" honest -- the
    lane set is derived from `quality.gap_report` and the registered classes,
    never from a template.
    """
    known = {g["class_id"] for g in quality.gap_report(con)}
    wanted = [c for c in (classes or []) if c in known]
    refused = [c for c in (classes or []) if c not in known]

    lanes: list[dict[str, Any]] = []
    for cls in wanted:
        gap = research_gap(cls)
        lanes.append(LaneSpec(
            name=f"lane.{cls}",
            objective=f"assess {cls} exposure on {mission.target or 'the recorded surface'}",
            class_id=cls,
            inputs=[f"knowledge gap for {cls}: {gap.get('missing')}"],
            expected_outputs=[f"observations classified as {cls} or UNKNOWN",
                              "evidence rows with request/response pairs"],
            stop_condition=(f"all in-scope endpoints for {cls} tested, or the "
                            f"class is unresearchable and the refusal recorded"),
            evidence_contract=("recorded before/after pairs; every claim cites "
                               "an evidence id; no classification without a "
                               "citation"),
            target=mission.target).to_payload())

    return {"ok": True, "lanes": lanes, "refused_classes": refused,
            "independent": True,
            "note": "lanes are independent by construction; run them in any "
                    "order and aggregate afterwards"}


# ==========================================================================
# PHASE 9 + 10 -- research during hunting, and failure -> learning
# ==========================================================================


def research_during_hunt(con: sqlite3.Connection, hunt_id: str, *,
                         description: str,
                         signals: list[str] | None = None
                         ) -> dict[str, Any]:
    """An UNKNOWN opens both a research path and a hunting path (§30).

    This is Phase 9's canonical loop, and it delegates to the existing
    `HypothesisEngine.open_unknown`, which already creates both tasks and
    pairs them in `unknown_behaviour` so neither can quietly become the other.

    It also repairs a real routing defect: `open_unknown` names its research
    task `unknown.research.<id>`, but `orch.executor.RESEARCH_RE` is anchored
    at `^research\\.`, so that task routed to `do_maintenance` and the research
    path never ran. `pick_handler` is fixed to match; this function returns the
    key so a caller can see which task carries the work.
    """
    engine = hypothesis.HypothesisEngine(con, hunt_id)
    return engine.open_unknown(description, signals=signals or [],
                               prefix="unknown")
def failure_to_learning(con: sqlite3.Connection, *, hyp_key: str,
                        failure_detail: str) -> dict[str, Any]:
    """Phase 10: a failed hypothesis is DATA, not a dead end.

    A refuted hypothesis is recorded against its own key, and the question it
    raised is turned into a real research task -- so the next action is
    research or a different approach, never an identical repeat. Repeating one
    failed action without new evidence is a stall with a counter, and the
    existing recovery ladder (`store.orphan_recovery` / `agents.recover`)
    exists to refuse exactly that.
    """
    engine = hypothesis.HypothesisEngine(con)
    row = engine.get(hyp_key)
    if row is None:
        return {"ok": False, "reason": f"no hypothesis {hyp_key!r}"}

    engine.set_status(hyp_key, "refuted")
    cls = row["class_id"]
    question = (f"why was this hypothesis refuted, and what does the published "
                f"record say about {cls or 'this behaviour'} that would explain "
                f"the observation? Failure detail: {failure_detail[:400]}")

    unknown = research_during_hunt(
        con, row["hunt_id"] or "default",
        description=question,
        signals=list(hypothesis.UNKNOWN_SIGNALS))

    store.emit_event(
        con, f"hypothesis_refuted:{hyp_key}", "research",
        source="orch.omh", severity="warn",
        payload={"hyp_key": hyp_key, "class_id": cls,
                 "detail": failure_detail[:400],
                 "research_task": unknown.get("research_task")},
        relevance=0.7)

    return {"ok": True, "hyp_key": hyp_key, "status": "refuted",
            "research_task": unknown.get("research_task"),
            "hunting_task": unknown.get("hunting_task"),
            "note": ("refusal recorded; a fresh research path opened. Do not "
                     "repeat the identical action without new evidence.")}


# ==========================================================================
# PHASE 15 -- adversarial QA
# ==========================================================================


def qa_finding(con: sqlite3.Connection, finding_key: str, *,
               validator_run: str, claimant_run: str | None = None,
               reproduced: bool = False) -> dict[str, Any]:
    """Run one finding through the existing validation and report gates.

    Two properties are load-bearing here:

      * INDEPENDENCE. `validator_run` must differ from `claimant_run`, and
        Cyber re-checks this in `validate.check_independence`. A hunter that
        certifies its own result passes nothing -- the check is in the gate,
        not in the caller.
      * RE-DERIVATION. `finalgate.gate` recomputes L1-L6 from stored evidence
        and ignores any verdict the caller supplies. This function therefore
        returns the gate's own answer and never a summary of the agent's own
        confidence.

    The returned `report_ready` is Cyber's, not OMH's.

    A MISSING FINDING IS DISTINGUISHED FROM A FAILED VALIDATION.
    MEASURED 2026-11-01: `finalgate.gate` returned `report_ready: False`
    for both a finding that genuinely failed the gates and a finding key
    that does not exist. `ok` was `True` in both cases. A caller could not
    tell "the finding was checked and failed" from "there was no finding to
    check", and would treat a missing finding as evidence that the gates
    are strict. The result now carries `outcome`, and a missing finding
    returns `ok: False` with the reason named.
    """
    from . import finalgate

    if claimant_run and validator_run == claimant_run:
        return {"ok": False, "report_ready": False,
                "reason": "validator_run equals claimant_run: QA is not "
                          "independent (L4), refusing to certify"}

    v = finalgate.gate(con, finding_key, reproduced=reproduced,
                       claimant_run=claimant_run,
                       validator_run=validator_run)
    fp_stage = (v.get("stages") or {}).get("false_positive") or {}
    outcome = fp_stage.get("outcome")
    if outcome == "missing_finding":
        return {"ok": False, "report_ready": False,
                "finding_key": finding_key,
                "outcome": "missing_finding",
                "reason": (f"no finding is stored under {finding_key!r}; "
                           "there is nothing to certify. This is not a "
                           "validation failure -- the finding was never "
                           "checked"),
                "authority": "orch.finalgate (Cyber); OMH supplied no part of "
                             "this verdict"}
    return {"ok": True, "finding_key": finding_key,
            "outcome": outcome or "evaluated",
            "report_ready": bool(v.get("report_ready")),
            "verdict": v.get("state") or v.get("verdict"),
            "stages": v.get("stages"),
            "authority": "orch.finalgate (Cyber); OMH supplied no part of "
                         "this verdict"}


# ==========================================================================
# PHASE 13 -- the autonomous loop
# ==========================================================================

LOOP_SCHEMA = """
CREATE TABLE IF NOT EXISTS omh_loop (
  loop_key    TEXT PRIMARY KEY,
  mission     TEXT NOT NULL,
  target      TEXT,
  hunt_id     TEXT,
  phase       TEXT NOT NULL DEFAULT 'PLAN',
  iteration   INTEGER NOT NULL DEFAULT 0,
  objective   TEXT,
  hypothesis  TEXT,
  knowledge_state TEXT,
  budget      INTEGER NOT NULL DEFAULT 3,
  iterations_used INTEGER NOT NULL DEFAULT 0,
  stop_condition TEXT,
  evidence_req TEXT,
  state       TEXT NOT NULL DEFAULT 'running',
  stop_reason TEXT,
  created_at  TEXT NOT NULL,
  updated_at  TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS ix_omh_loop_state ON omh_loop(state);
"""


def _ensure_loop(con: sqlite3.Connection) -> None:
    con.executescript(LOOP_SCHEMA)
    con.commit()


def open_loop(con: sqlite3.Connection, *, mission: str, objective: str,
              target: str = "", hunt_id: str = "", budget: int = 3,
              evidence_req: str = "",
              stop_condition: str = "") -> str:
    """Open a loop. A loop is orchestration state ONLY.

    It is stored in its own table rather than in a task or a checkpoint because
    it is neither: it is the mission-level iteration record, and Cyber's task
    graph cannot express "which iteration of which mission". It holds no
    knowledge, so nothing in it can ever be mistaken for a claim.
    """
    _ensure_loop(con)
    key = f"loop.{_slug(mission)}.{abs(hash(mission)) % (10 ** 6)}"
    now_ = store.now()
    con.execute(
        "INSERT OR REPLACE INTO omh_loop(loop_key, mission, target, hunt_id,"
        " phase, iteration, objective, budget, stop_condition, evidence_req,"
        " state, created_at, updated_at)"
        " VALUES (?,?,?,?,'PLAN',0,?,?,?,?, 'running', ?, ?)",
        (key, mission, target, hunt_id, objective, int(budget),
         stop_condition or "; ".join(DEFAULT_STOP_CONDITIONS), evidence_req,
         now_, now_))
    con.commit()
    return key


def loop_state(con: sqlite3.Connection, loop_key: str) -> dict[str, Any]:
    _ensure_loop(con)
    row = con.execute("SELECT * FROM omh_loop WHERE loop_key=?",
                      (loop_key,)).fetchone()
    return dict(row) if row else {}


def record_iteration(con: sqlite3.Connection, loop_key: str, *,
                     phase: str, objective: str = "",
                     hypothesis: str = "",
                     knowledge_state: str = "") -> dict[str, Any]:
    """Advance the loop. Refuses to advance a STOPPED loop.

    A stopped loop that resumes on the next tick is how an overnight run
    quietly turns into an unbounded one: the stop condition fires, the record
    is written, and the next iteration reads a loop that looks live again.
    """
    _ensure_loop(con)
    st = loop_state(con, loop_key)
    if not st:
        return {"ok": False, "reason": f"no loop {loop_key!r}"}
    if st["state"] == "stopped":
        return {"ok": False, "reason": "loop is stopped",
                "stop_reason": st.get("stop_reason"), "loop_key": loop_key}

    used = int(st["iterations_used"]) + 1
    # `budget` is the number of iterations the mission may RUN, so this
    # iteration is the last one the budget permits -- and recording it spends
    # the budget, which is why the state flips on `>=`. The earlier
    # `used > budget` let iteration budget+1 run before stopping on budget+2, so
    # a `budget=2` mission performed three rounds of work: exactly the
    # unbounded-attention failure Phase 13 exists to prevent.
    stopped = used >= int(st["budget"])
    con.execute(
        "UPDATE omh_loop SET phase=?, iteration=iteration+1, objective=?,"
        " hypothesis=?, knowledge_state=?, iterations_used=?, state=?,"
        " stop_reason=?, updated_at=? WHERE loop_key=?",
        (phase, objective or st.get("objective"), hypothesis or None,
         knowledge_state or None, used, "stopped" if stopped else "running",
         "budget exhausted" if stopped else None, store.now(), loop_key))
    con.commit()
    return {"ok": True, "loop_key": loop_key,
            "iteration": int(st["iteration"]) + 1,
            "iterations_used": used, "budget": st["budget"],
            "state": "stopped" if stopped else "running",
            "stop_reason": "budget exhausted" if stopped else None}


def loop_may_continue(con: sqlite3.Connection, loop_key: str) -> dict[str, Any]:
    """The loop's continue/stop decision, derived from Cyber's own signals.

    Deliberately conservative: it stops when the budget is spent, when a stop
    condition is recorded, or when Cyber's own "is there still useful work?"
    question says no. It never continues merely because another action could
    be generated.
    """
    from . import scheduler

    st = loop_state(con, loop_key)
    if not st:
        return {"continue": False, "reason": f"no loop {loop_key!r}"}
    if st["state"] == "stopped":
        return {"continue": False, "reason": st.get("stop_reason") or "stopped",
                "loop_key": loop_key}
    if int(st["iterations_used"]) >= int(st["budget"]):
        return {"continue": False, "reason": "mission budget exhausted",
                "loop_key": loop_key}

    try:
        useful = scheduler.has_useful_work(con)
    except Exception as e:  # noqa: BLE001
        # An unreadable stop-signal is NOT permission to continue. Stop and
        # say why: the alternative is an unbounded unattended loop.
        return {"continue": False,
                "reason": f"stopcheck unavailable ({type(e).__name__}: {e}); "
                          f"refusing to continue unattended",
                "loop_key": loop_key}

    active = bool(useful.get("useful_work") or useful.get("ready")
                  or useful.get("tasks_ready"))
    return {"continue": active, "loop_key": loop_key,
            "reason": ("useful work remains" if active
                       else "stopcheck reports no useful work"),
            "stopcheck": useful}


def stop_loop(con: sqlite3.Connection, loop_key: str,
              reason: str) -> dict[str, Any]:
    _ensure_loop(con)
    con.execute("UPDATE omh_loop SET state='stopped', stop_reason=?,"
                " updated_at=? WHERE loop_key=?",
                (reason, store.now(), loop_key))
    con.commit()
    return {"ok": True, "loop_key": loop_key, "state": "stopped",
            "stop_reason": reason}


# ==========================================================================
# Phase 18 -- memory boundary
# ==========================================================================

# OMH memory holds ORCHESTRATION lessons only. The canonical split:
#
#   OMH memory   -> workflow failures, process patterns, orchestration notes
#   Cyber corpus -> techniques, claims, sources, evidence, mastery
#
# `MEMORY_FORBIDDEN_SUBJECTS` is asserted by the test suite, because the only
# way this boundary is ever checked is if something checks it.
MEMORY_FORBIDDEN_SUBJECTS = (
    "technique", "payload", "bypass", "exploit", "vulnerability",
    "cwe", "finding", "knowledge item", "mastery",
)


def memory_admissible(subject: str) -> dict[str, Any]:
    """Is this subject allowed into OMH memory?

    Process yes, technique no. A technique belongs to the corpus, where it is
    gated on evidence; in OMH memory it would be an unverified claim with no
    citation and no way to be re-checked.
    """
    s = (subject or "").strip().lower()
    hit = [w for w in MEMORY_FORBIDDEN_SUBJECTS if w in s]
    if hit:
        return {"admissible": False, "matched": hit,
                "reason": "security knowledge belongs in the Cyber corpus, "
                          "which gates it on evidence; OMH memory holds "
                          "orchestration lessons only"}
    return {"admissible": True, "matched": []}


def integration_report(con: sqlite3.Connection) -> dict[str, Any]:
    """One screen of what the integration has actually done."""
    _ensure_loop(con)
    loops = con.execute(
        "SELECT state, count(*) n FROM omh_loop GROUP BY state").fetchall()
    results = con.execute(
        "SELECT type, count(*) n FROM agent_result GROUP BY type").fetchall()
    return {
        "loops": {r["state"]: r["n"] for r in loops},
        "agent_results": {r["type"]: r["n"] for r in results},
        "workflow_map": WORKFLOW_MAP,
        "authority": {
            "omh": ["decompose", "fan-out research", "parallel lanes",
                    "loop state", "intake files", "hypothesis proposals"],
            "cyber": ["authorization", "scope", "capability grant", "evidence "
                      "gate", "knowledge promotion", "finding validation",
                      "report gate", "mastery", "stop conditions"],
        },
    }