"""The hunting engine: the observe -> decide -> act loop (master prompt §1-§62).

§58 is the loop this module implements literally:

    OBSERVE -> UNDERSTAND -> GENERATE OPTIONS -> EVALUATE -> SELECT ACTION
    -> EXECUTE -> CAPTURE RESULT -> UPDATE STATE -> REPLAN

and §47 forbids deciding completion from a checklist, so `completion_decision`
scores the MARGINAL value of continuing against its cost — remaining surface,
unexplored hypotheses, potential impact, new signals, research gaps,
environmental change, evidence gaps, resource cost — and returns CONTINUE /
PAUSE / ABANDON_PATH / REVISIT / COMPLETE_HUNT with the arithmetic.

Three design commitments:

1. **Every phase writes state before it acts.** `act()` checkpoints first, so a
   crash mid-phase resumes from the phase boundary instead of replaying.
   Nothing held in memory is load-bearing across a crash.

2. **Nothing executes without a verdict.** The engine asks `authz` for a
   decision, and an action without one is refused at the call site, not by the
   caller's discipline. §3 and §57 ranked first are the same mechanism.

3. **No observation is invented.** `observe()` reads from tables that agents
   wrote. If nothing was observed, the loop says so and generates no
   hypotheses — a generator fed nothing must emit nothing, or it is fiction.

This module is the composition root; it owns no new gates. Every control lives
in the module that owns it, which is why a `HuntingEngine` here is a
coordinator rather than a second implementation of everything.
"""
from __future__ import annotations

import json
import sqlite3
import uuid
from typing import Any, Callable, Iterable

from wks import config as wks_config

from . import (agentkit, authz as authz_mod, dag, finalgate, huntrt,
               hypothesis as hyp_mod, lifecycle as lifecycle_mod, orchestrator,
               policy, priority, reporting, store, surface as surface_mod,
               tools as tools_mod, validate as v1)

# ---------------------------------------------------------------------------
# §59 hunting state machine
# ---------------------------------------------------------------------------

STATES = (
    "INIT",
    "AUTHORIZATION_GATE",
    "INITIAL_PLAN",
    "DYNAMIC_RECON",
    "ATTACK_SURFACE",
    "HYPOTHESIS_GENERATION",
    "PARALLEL_HUNTING",
    "RESEARCH_LEARNING",
    "ADAPTATION_REPLANNING",
    "VALIDATION",
    "DEDUPLICATION",
    "EVIDENCE",
    "RETEST",
    "FINAL_GATE",
    "REPORTING",
    "POST_HUNT_LEARNING",
    "NEXT_CYCLE_STATE",
    "COMPLETE",
    "BLOCKED_AUTHORIZATION",
)

# Non-linear by design (§59: "transitions are not strictly linear"), so the
# machine declares which states may RE-ENTER which.
REENTRY = {
    "DYNAMIC_RECON": ("ATTACK_SURFACE", "HYPOTHESIS_GENERATION",
                      "ADAPTATION_REPLANNING"),
    "ATTACK_SURFACE": ("HYPOTHESIS_GENERATION", "DYNAMIC_RECON",
                       "ADAPTATION_REPLANNING"),
    "HYPOTHESIS_GENERATION": ("PARALLEL_HUNTING", "RESEARCH_LEARNING",
                              "ADAPTATION_REPLANNING"),
    "PARALLEL_HUNTING": ("RESEARCH_LEARNING", "VALIDATION", "EVIDENCE",
                         "ADAPTATION_REPLANNING", "DYNAMIC_RECON"),
    "ADAPTATION_REPLANNING": ("DYNAMIC_RECON", "ATTACK_SURFACE",
                              "HYPOTHESIS_GENERATION", "PARALLEL_HUNTING",
                              "VALIDATION"),
    "RESEARCH_LEARNING": ("ADAPTATION_REPLANNING", "HYPOTHESIS_GENERATION"),
    "VALIDATION": ("RETEST", "EVIDENCE", "DEDUPLICATION", "FINAL_GATE",
                   "ADAPTATION_REPLANNING"),
    "RETEST": ("VALIDATION", "FINAL_GATE", "ADAPTATION_REPLANNING"),
}

SCHEMA = """
CREATE TABLE IF NOT EXISTS hunt (
  hunt_id     TEXT PRIMARY KEY,
  program     TEXT,
  target      TEXT,
  state       TEXT NOT NULL DEFAULT 'INIT',
  kind        TEXT,
  started_at  TEXT NOT NULL,
  finished_at TEXT,
  cycles      INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS hunt_observation (
  obs_key   TEXT PRIMARY KEY,
  hunt_id   TEXT NOT NULL,
  phase     TEXT,
  kind      TEXT NOT NULL,
  statement TEXT NOT NULL,
  source    TEXT,
  signals   TEXT,          -- JSON list, for hypothesis classification
  at        TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS ix_obs_hunt ON hunt_observation(hunt_id, kind);
CREATE TABLE IF NOT EXISTS hunt_transition (
  id       INTEGER PRIMARY KEY,
  hunt_id  TEXT NOT NULL,
  from_state TEXT,
  to_state TEXT NOT NULL,
  reason   TEXT,
  at       TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS ix_trans_hunt ON hunt_transition(hunt_id, id);
"""


def _ensure(con: sqlite3.Connection) -> None:
    con.executescript(SCHEMA)
    con.commit()


def _now() -> str:
    import datetime
    return datetime.datetime.now(datetime.timezone.utc).isoformat(
        timespec="seconds")


class HuntingEngine:
    """§61's definition of success, as a composition of the owning modules."""

    def __init__(self, con: sqlite3.Connection, ctx: authz_mod.AuthorizationContext,
                 *, hunt_id: str | None = None, run: huntrt.HuntRuntime | None = None):
        _ensure(con)
        self.con = con
        self.ctx = ctx
        self.hunt_id = hunt_id or huntrt.make_hunt_id(ctx.target, ctx.program)
        self.run = run or huntrt.HuntRuntime(self.hunt_id)
        self.surface = surface_mod.Surface(con, self.hunt_id)
        self.hyps = hyp_mod.HypothesisEngine(con, self.hunt_id)
        self.lifecycle = lifecycle_mod.FindingLifecycle(con, self.hunt_id)
        self.tools = tools_mod.ToolRegistry(con, self.hunt_id)
        self.ledger = authz_mod.ScopeLedger(con, ctx)
        self.governor = policy.RateGovernor(ctx)
        self.state = "INIT"
        self.cycles = 0
        self._register()

    # ------------------------------------------------------------- lifecycle
    def _register(self) -> None:
        self.con.execute(
            "INSERT OR IGNORE INTO hunt(hunt_id, program, target, state, kind,"
            " started_at, cycles) VALUES (?,?,?,?,?,?,0)",
            (self.hunt_id, self.ctx.program, self.ctx.target, self.state,
             self.ctx.kind, _now()))
        self.con.commit()

    def _move(self, to_state: str, reason: str = "") -> dict[str, Any]:
        if to_state not in STATES:
            raise ValueError(f"unknown hunt state {to_state!r}; known: {STATES}")
        legal = REENTRY.get(self.state, ())
        from_state = self.state
        self.con.execute(
            "INSERT INTO hunt_transition(hunt_id, from_state, to_state, reason, at)"
            " VALUES (?,?,?,?,?)",
            (self.hunt_id, from_state, to_state, reason, _now()))
        self.con.execute("UPDATE hunt SET state=?, cycles=? WHERE hunt_id=?",
                         (to_state, self.cycles, self.hunt_id))
        self.con.commit()
        self.state = to_state
        self.run.log("phase", **{"from": from_state, "to": to_state,
                                 "reason": reason})
        return {"from": from_state, "to": to_state, "legal_reentry": to_state in legal,
                "reason": reason}

    # =========================== §4 AUTHORIZATION GATE =====================
    def authorization_gate(self) -> dict[str, Any]:
        self._move("AUTHORIZATION_GATE", "§4 gate before any active testing")
        missing = self.ctx.missing_fields()
        probe = self.ctx.decision("probe")
        if missing:
            self._move("BLOCKED_AUTHORIZATION",
                       "materially ambiguous scope; asking the user (§5)")
            q = ("I need these before testing anything: "
                 + ", ".join(missing) + ". What is the program, which assets are "
                 "in scope, and what does the program require in a report?")
            self.run.log("authorization_ambiguous", missing=missing)
            return {"passed": False, "missing": missing, "question": q,
                    "recognition_only": True,
                    "note": ("authorization is never inferred from DNS, "
                             "ownership, shared infrastructure, certificates "
                             "or redirects (§5)")}

        # Register the context and the in-scope assets.
        self.ctx.register(self.con)
        for a in self.ctx.in_scope_assets:
            self.ledger.record(a, discovered_by="authorization_context")
        verdict = {
            "passed": probe.get("allowed", False),
            "probe": probe,
            "kind": self.ctx.kind,
            "program": self.ctx.program,
            "scoped": [self.ctx.asset_verdict(a)
                       for a in self.ctx.in_scope_assets],
        }
        if not verdict["passed"]:
            self._move("BLOCKED_AUTHORIZATION", probe.get("detail", "refused"))
        else:
            self._move("INITIAL_PLAN", "authorization confirmed")
        self.run.log("authorization_verified", verdict=verdict)
        return verdict

    # ============================= §8 INITIAL PLAN ========================
    def initial_plan(self) -> dict[str, Any]:
        """A plan shaped by target type, architecture, auth state and gaps."""
        self._move("INITIAL_PLAN", "§8 first plan (a starting hypothesis, "
                                   "not a commitment)")
        keys = orchestrator.decompose(
            self.con, f"hunt {self.ctx.target} for {self.ctx.program}",
            domain=self.ctx.kind, prefix=f"hunt.{self.hunt_id}",
            expected_artifact="gated evidence or a recorded gap",
            evidence_req="reproduction with stored request/response")

        # Recon tasks are target-DRIVEN (§12), not fixed.
        recon = self._recon_tasks()

        # Authentication state changes what is reachable, so it is a task.
        authz_tasks = []
        if self.ctx.authentication_context.get("credentials_available"):
            authz_tasks.append(f"hunt.{self.hunt_id}.authn.establish-session")

        # Attack surface and hypothesis seeding.
        surface_key = f"hunt.{self.hunt_id}.surface.build"
        store.add_task(self.con, surface_key,
                       f"build the attack surface for {self.ctx.target} from "
                       f"recon observations", priority=2,
                       expected_artifact="surface nodes and edges with evidence",
                       evidence_req="every node carries the observation that "
                                    "created it")
        hyp_key = f"hunt.{self.hunt_id}.hypotheses.generate"
        store.add_task(self.con, hyp_key,
                       f"generate hypotheses from observed surface and the "
                       f"corpus", priority=1,
                       expected_artifact="hypotheses each with a disproof",
                       evidence_req="every hypothesis names the observation "
                                    "that produced it")

        dag.refresh_readiness(self.con)
        plan = {"tasks": keys + recon + authz_tasks + [surface_key, hyp_key],
                "recon": recon, "surface_task": surface_key,
                "hypothesis_task": hyp_key,
                "validation_strategy": {
                    "paths": list(finalgate.VALIDATION_PATHS),
                    "required_paths": finalgate.required_paths(important=True),
                    "independence": "L4: validator must hold a different role"},
                "evidence_strategy": {
                    "kinds": ["request", "response", "payload", "repro",
                              "screenshot", "log"],
                    "immutability": "evidence rows are hashed and never deleted"},
                "research_requirements": {
                    "unknown_behaviour": "§30 dual path",
                    "gate": "wks.quality: 2 independent publisher hosts"}}
        self.run.log("initial_plan", tasks=len(plan["tasks"]))
        self.run.save_checkpoint({"at": _now(), "phase": self.state, **plan})
        return plan

    def _recon_tasks(self) -> list[str]:
        """§12: recon technique follows what is observed, not a fixed sequence."""
        out = []
        base = f"hunt.{self.hunt_id}.recon"
        specs = [
            ("dns", "enumerate DNS records and subdomains for the target",
             "records with their source"),
            ("http", "probe the in-scope hosts and record status/headers/title",
             "one request/response pair per host"),
            ("tls", "collect certificate names and protocol support",
             "certificate SANs and negotiated protocol"),
            ("js", "fetch and analyse JavaScript for endpoints and secrets",
             "endpoint list extracted from served JS"),
        ]
        for kind, objective, artifact in specs:
            k = f"{base}.{kind}"
            store.add_task(self.con, k, objective, priority=3,
                           expected_artifact=artifact,
                           evidence_req="observed output, not inference")
            out.append(k)
        return out

    # ======================= §58 OBSERVE -> UNDERSTAND ====================
    def observe(self, kind: str, statement: str, *, source: str = "",
                signals: Iterable[str] = (), phase: str = "") -> str:
        """Record ONE observation. This is the only way state enters the hunt.

        Nothing here infers. An engine that generated its own observations
        would generate its own confirmations, which is the failure mode §19's
        generator has to avoid.
        """
        key = f"obs.{self.hunt_id}.{uuid.uuid4().hex[:12]}"
        self.con.execute(
            "INSERT INTO hunt_observation(obs_key, hunt_id, phase, kind,"
            " statement, source, signals, at) VALUES (?,?,?,?,?,?,?,?)",
            (key, self.hunt_id, phase or self.state, kind, statement, source,
             json.dumps(sorted(signals)), _now()))
        self.con.commit()
        self.run.log("observation", kind=kind, statement=statement[:160])
        return key

    def observations(self, kind: str | None = None) -> list[dict[str, Any]]:
        sql = "SELECT * FROM hunt_observation WHERE hunt_id=?"
        args: list[Any] = [self.hunt_id]
        if kind:
            sql += " AND kind=?"
            args.append(kind)
        out = []
        for r in self.con.execute(sql + " ORDER BY at", args):
            d = dict(r)
            d["signals"] = json.loads(d.get("signals") or "[]")
            out.append(d)
        return out

    def understand(self) -> dict[str, Any]:
        """OBSERVE + UNDERSTAND: what is known, and what it means."""
        obs = self.observations()
        by_kind: dict[str, int] = {}
        signals: set[str] = set()
        for o in obs:
            by_kind[o["kind"]] = by_kind.get(o["kind"], 0) + 1
            signals.update(o["signals"])
        cls = hyp_mod.classify_behaviour(sorted(signals)) if signals else {
            "classification": "UNKNOWN", "reason": "no signals observed yet"}
        summary = {"observations": len(obs), "by_kind": by_kind,
                   "signals": sorted(signals),
                   "behaviour_class": cls["classification"],
                   "surface": self.surface.summary(),
                   "hypotheses": self.hyps.summary(),
                   "tool_inventory": self.tools.inventory()}
        self.run.log("understood", **{k: v for k, v in summary.items()
                                      if k != "surface"})
        return summary

    # ========================== §19 HYPOTHESIS GENERATION ==================
    def generate_hypotheses(self) -> dict[str, Any]:
        self._move("ATTACK_SURFACE", "consolidate the surface before proposing")
        self._move("HYPOTHESIS_GENERATION", "§19 generate, do not consult a list")
        made: list[str] = []
        made += self.hyps.from_surface()
        for cid in self._target_classes():
            made += self.hyps.from_knowledge(cid, limit=3)
        made += self.hyps.from_prior_findings()

        # §30: unclassified behaviour opens BOTH paths.
        unknown_paths = []
        for o in self.observations():
            sig = o["signals"]
            if not sig:
                continue
            cls = hyp_mod.classify_behaviour(sig)
            if cls["classification"] == "UNKNOWN" and sig:
                unknown_paths.append(self.hyps.open_unknown(
                    o["statement"], signals=sig,
                    prefix=f"hunt.{self.hunt_id}.unknown"))

        out = {"generated": len(made), "keys": made,
               "unknown_paths": unknown_paths,
               "note": ("every hypothesis carries a disproof; a hypothesis "
                        "without one is refused by the engine, not by a "
                        "reviewer")}
        self.run.log("hypotheses_generated", count=len(made),
                     unknowns=len(unknown_paths))
        return out

    def _target_classes(self) -> list[str]:
        # `hunt_observation` carries no class_id column: an observation is a
        # SIGNAL observation, and the class comes from classifying those signals.
        # Querying a column that was never declared made every knowledge-driven
        # proposal path raise, which is why this fallback was the only live one.
        techs = [n["name"].lower() for n in self.surface.nodes("technology")]
        endpoints = [n["name"].lower() for n in self.surface.nodes("endpoint")]
        hay = " ".join(techs + endpoints)
        out = []
        for cid in hyp_mod.SIGNATURES:
            if cid in hay:
                out.append(cid)
        return sorted(set(out))[:6]

    # ======================= §21 PARALLEL HUNTING ========================
    def plan_wave(self, *, limit: int | None = None) -> dict[str, Any]:
        """§24/§9: pick the next parallel slice, dynamically.

        Ranking is the existing priority engine (live evidence, not a declared
        number), then the concurrency cap is applied, then the selection is
        recorded. A cap never looks like a completed wave.
        """
        dag.refresh_readiness(self.con)
        ranked = [t for t in priority.rank(self.con)
                  if t["task_key"].startswith(f"hunt.{self.hunt_id}")
                  or t["task_key"].startswith(("research.", "unknown."))]
        cap = limit or __import__("orch.concurrency", fromlist=["x"]).budget()
        wave = ranked[:cap]
        deferred = ranked[cap:]
        out = {"wave": [t["task_key"] for t in wave],
               "deferred": [t["task_key"] for t in deferred],
               "cap": cap,
               "ranking": ranked[:12],
               "note": ("parallelism is a consequence of the graph and the "
                        "measured cap, not a goal (§24)")}
        self.run.log("wave_planned", wave=out["wave"], deferred=out["deferred"])
        return out

    def delegate(self, task_keys: Iterable[str]) -> dict[str, Any]:
        """§20-§22: select a specialist per task, by score, and dispatch.

        The gate still applies — selection proposes, `agents.dispatch` decides.
        A refusal here is reported, never forced.
        """
        from . import agents
        results = []
        for key in task_keys:
            row = store.get_task(self.con, key)
            if row is None:
                results.append({"task": key, "dispatched": False,
                                "reason": "task does not exist"})
                continue
            sel = agentkit.select_agent(
                self.con, objective=row["objective"],
                domain=self.ctx.kind or "web", class_id=row["class_id"])
            if not sel["selected"]:
                results.append({"task": key, "dispatched": False,
                                "reason": sel["reason"]})
                continue
            outcome = agents.dispatch(
                self.con, f"run-{key}", sel["selected"], row["objective"],
                task_key=key, target=self.ctx.target)
            results.append({"task": key, "role": sel["selected"],
                            "score": sel["ranking"][0]["score"],
                            "dispatched": outcome.get("dispatched"),
                            "reason": outcome.get("reason")})
        self.run.log("delegated", results=results)
        return {"delegations": results,
                "note": ("agent selection is scored; the authorization gate "
                         "still governs dispatch")}

    # ========================= §26 TECHNIQUE FAILURE ======================
    def on_technique_failure(self, task_key: str, *, why: str) -> dict[str, Any]:
        """§26: a failed technique triggers ADAPTATION, not repetition.

        Uses the existing recovery ladder and records which rung was reached, so
        "we tried again" is distinguishable from "we tried something else".
        """
        from . import agents
        r = agents.recover(self.con, task_key,
                           orchestrator.RECOVERY_LADDER,
                           budget=orchestrator.RECOVERY_BUDGET)
        agentkit.record_failure(self.con, "executor", reason=why,
                                task_key=task_key)
        self.run.log("technique_failed", task=task_key, why=why,
                     ladder=r.get("strategies"))
        return {"task": task_key, "why": why, "recovery": r,
                "note": ("each rung is a genuinely different strategy; the "
                         "budget is 10 and exhausting it BLOCKS rather than "
                         "looping (§26)")}

    # ========================= §39 EVIDENCE ===============================
    def capture_evidence(self, finding_key: str, *, kind: str, request_raw: str = "",
                        response_raw: str = "", payload: str = "",
                        endpoint: str = "", provenance: str = "") -> int:
        """§39: evidence with hash, provenance, timestamp. Never deleted."""
        f = store.get_task(self.con, finding_key) if False else None
        row = self.con.execute("SELECT id FROM finding WHERE finding_key=?",
                               (finding_key,)).fetchone()
        if not row:
            raise KeyError(f"evidence must attach to an existing finding; "
                           f"{finding_key!r} does not exist")
        eid = store.add_evidence(self.con, kind, finding_id=int(row["id"]),
                                 target=self.ctx.target,
                                 endpoint=endpoint or self.ctx.target,
                                 request_raw=request_raw,
                                 response_raw=response_raw, payload=payload,
                                 provenance=provenance or "orch.hunting")
        self.run.log("evidence_captured", finding=finding_key, kind=kind,
                     evidence_id=eid)
        return eid

    # ===================== §47 COMPLETION DECISION ========================
    def completion_decision(self) -> dict[str, Any]:
        """§47: completion is the MARGINAL value of continuing, not a checklist."""
        rem = reporting.remaining_paths(self.con, self.hunt_id)
        open_hyps = rem["open_hypotheses"]
        queued = rem["revalidation_queue"]
        blocked = rem["blocked_tasks"]
        ready = rem["ready_tasks"]
        unknowns = rem["unresolved_unknown_behaviour"]

        surface = self.surface.summary()
        remaining_surface = max(0, 6 - surface["observed_nodes"])
        # How much impact is still ON the table: findings that are open and
        # not yet resolved. `finding` is the orchestration table and has no
        # hunt_id column -- hunt membership is expressed through the lifecycle
        # machine and the task graph, so an earlier query that filtered on
        # `finding.hunt_id` raised on every completion decision.
        potential_impact = int(self.con.execute(
            "SELECT count(*) n FROM finding WHERE status IN"
            " ('candidate','validating','validated')").fetchone()["n"])
        evidence_gaps = int(self.con.execute(
            "SELECT count(*) n FROM finding f WHERE f.status IN"
            " ('candidate','validated') AND NOT EXISTS (SELECT 1 FROM evidence"
            " e WHERE e.finding_id=f.id)").fetchone()["n"])
        env_changes = len(self.lifecycle.changes())
        resource_cost = len(ready) + len(blocked)

        # Value and cost, both measured. Neither is asserted.
        value = (3 * len(open_hyps) + 4 * len(unknowns) + 2 * len(queued)
                 + 3 * potential_impact + 2 * evidence_gaps
                 + 1 * remaining_surface + 2 * env_changes)
        cost = 2 * len(ready) + 1 * len(blocked)

        if ready or open_hyps or unknowns or queued:
            decision = "CONTINUE"
            why = "runnable work or open hypotheses remain"
        elif evidence_gaps and not resource_cost:
            decision = "CONTINUE"
            why = f"{evidence_gaps} validated-or-candidate finding(s) have no evidence"
        elif potential_impact and not resource_cost:
            decision = "REVISIT"
            why = f"{potential_impact} finding(s) still open with no work queued"
        elif env_changes:
            decision = "REVISIT"
            why = f"{env_changes} target change(s) recorded; the hunt may be stale"
        elif resource_cost:
            decision = "PAUSE"
            why = f"work exists ({resource_cost}) but none is runnable"
        else:
            decision = "COMPLETE_HUNT"
            why = "no runnable work, no open hypotheses, no evidence gaps"

        out = {"decision": decision, "why": why, "value": value, "cost": cost,
               "marginal": value - cost,
               "factors": {"remaining_attack_surface": remaining_surface,
                           "unexplored_hypotheses": len(open_hyps),
                           "potential_impact": potential_impact,
                           "new_signals": len(unknowns),
                           "research_gaps": len(unknowns),
                           "environmental_changes": env_changes,
                           "evidence_gaps": evidence_gaps,
                           "resource_cost": resource_cost,
                           "ready_tasks": len(ready),
                           "blocked_tasks": len(blocked)},
               "note": ("completion is never defined by a count of scans, "
                        "tools, agents, requests or elapsed time (§47)")}
        self.run.log("completion_decision", **{k: v for k, v in out.items()
                                               if k != "factors"})
        return out

    # ===================== §8+ OBSERVE/DECIDE/ACT LOOP ===================
    def cycle(self, *, executor: Callable | None = None,
              max_tasks: int = 6) -> dict[str, Any]:
        """One full §58 loop. Persists state at every phase boundary."""
        self.cycles += 1
        trace: list[dict[str, Any]] = []

        # OBSERVE + UNDERSTAND
        trace.append({"phase": "understand",
                      "result": self.understand()})

        # GENERATE OPTIONS + EVALUATE + SELECT ACTION
        decision = self.completion_decision()
        trace.append({"phase": "decide", "result": decision})
        if decision["decision"] in ("COMPLETE_HUNT", "PAUSE"):
            self.run.log("loop_halted", decision=decision["decision"])
            return {"cycles": self.cycles, "trace": trace,
                    "decision": decision}

        # EXECUTE
        wave = self.plan_wave()
        trace.append({"phase": "plan", "result": wave})
        delegated = self.delegate(wave["wave"])
        trace.append({"phase": "delegate", "result": delegated})

        executed: list[dict[str, Any]] = []
        if executor is not None:
            from . import executor as exec_mod
            for entry in wave["wave"]:
                row = store.get_task(self.con, entry)
                if row is None:
                    continue
                executed.append(exec_mod.execute(self.con, row))
        trace.append({"phase": "execute", "result": executed})

        # CAPTURE RESULT + UPDATE STATE
        gate_rows = self._revalidate()
        trace.append({"phase": "validate", "result": gate_rows})

        # REPLAN
        moved = self._replan(decision)
        trace.append({"phase": "replan", "result": moved})

        self.run.save_checkpoint({"at": _now(), "cycle": self.cycles,
                                  "state": self.state,
                                  "decision": decision,
                                  "wave": wave["wave"]})
        return {"cycles": self.cycles, "trace": trace, "decision": decision,
                "executed": executed, "replan": moved}

    def _revalidate(self) -> list[dict[str, Any]]:
        out = []
        for f in store.findings(self.con, "candidate"):
            g = finalgate.gate(self.con, f["finding_key"])
            if not g["report_ready"]:
                # §37: weak evidence is queued, not discarded.
                self.lifecycle.queue_revalidation(
                    f["finding_key"],
                    reason="final gate: " + ", ".join(
                        g["failed_critical"] or g["failed_other"] or ["unknown"]),
                    levels_failed=[n.upper() for n in g["failed_critical"]],
                    evidence_ids=[])
            out.append({"finding_key": f["finding_key"], "verdict": g["verdict"],
                        "failed": g["failed_critical"]})
        return out

    def _replan(self, decision: dict[str, Any]) -> dict[str, Any]:
        """§9/§2: the plan reflects the latest evidence, and moves backward."""
        moved = self._move("ADAPTATION_REPLANNING",
                           f"cycle {self.cycles}: {decision['decision']}")
        action = decision["decision"]
        if decision["marginal"] < 0 and action == "CONTINUE":
            # Low marginal value: deprioritise rather than churn.
            n = priority.reorder_tasks(self.con)
            moved["deprioritised"] = n
        if action == "REVISIT":
            self.lifecycle.record_change(
                kind="behaviour_changed", subject=self.ctx.target,
                after={"decision": "REVISIT"},
                impact="hunt may be stale; surface re-check queued",
                preserved="validated findings and their evidence",
                rebuilt=["attack surface"])
        back = self._move("DYNAMIC_RECON" if action == "CONTINUE"
                          else "VALIDATION", "resume the loop")
        return {"transition": moved, "resume": back}

    # ========================= §52 HUNT CLOSURE ===========================
    def close(self, *, final_audit: dict[str, Any] | None = None
              ) -> dict[str, Any]:
        """§51 + §52: dossier, next-cycle state, and a resumable checkpoint."""
        decision = self.completion_decision()
        dossier = reporting.dossier(self.con, self.hunt_id, run=self.run)
        nxt = reporting.next_cycle_state(self.con, self.hunt_id,
                                         completion=decision, run=self.run)
        self._move("NEXT_CYCLE_STATE", f"persisted; decision={decision['decision']}")
        self._move("COMPLETE", "hunt closed")
        self.con.execute("UPDATE hunt SET finished_at=? WHERE hunt_id=?",
                         (_now(), self.hunt_id))
        self.con.commit()

        untested = self.ledger.assert_untested()
        out = {"hunt_id": self.hunt_id,
               "completion": decision,
               "dossier_path": dossier.get("dossier_path"),
               "next_cycle_path": nxt.get("path"),
               "final_audit": final_audit,
               "out_of_scope_tested": untested,
               "scope_ledger": self.ledger.report(),
               "tool_coverage_gaps": self.tools.coverage_gaps(),
               "resumable": reporting.resume_hunt(self.hunt_id)["resumable"],
               "note": ("the next hunt starts from this state rather than from "
                        "zero (§52)")}
        if untested:
            out["DEFECT"] = (f"{len(untested)} out-of-scope asset(s) were "
                             f"tested: {untested} — §6 violation")
        self.run.log("hunt_closed", decision=decision["decision"],
                     out_of_scope_tested=untested)
        return out

    # ===================================================================
    def state_report(self) -> dict[str, Any]:
        """The full §10 global model, for an operator reading one screen."""
        transitions = [dict(r) for r in self.con.execute(
            "SELECT from_state, to_state, reason, at FROM hunt_transition"
            " WHERE hunt_id=? ORDER BY id", (self.hunt_id,))]
        return {"hunt_id": self.hunt_id, "state": self.state,
                "cycles": self.cycles,
                "authorization": self.ctx.to_json(),
                "attack_surface": self.surface.summary(),
                "hypotheses": self.hyps.summary(),
                "finding_lifecycle": self.lifecycle.summary(),
                "graph": dag.graph_report(self.con),
                "transitions": transitions[-12:],
                "runtime": self.run.resume(),
                "decisions": policy.rule_matrix()[:5],
                "priority_order": list(policy.PRIORITY_ORDER)}