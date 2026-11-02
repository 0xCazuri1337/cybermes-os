"""Hypothesis engine (§19) and the dual path for unknown behaviour (§30).

§19 is the section the rest of the engine hangs off: "the system must be able to
generate hypotheses it was not explicitly handed." A checklist engine cannot
do that; a generator over OBSERVED surface + CORPUS knowledge + PRIOR FINDINGS
can. So this module is a generator, not a template list:

    Observed behaviour + Attack surface + Known knowledge + Previous findings
    + Research + Agent observations + Environmental state  ->  hypotheses

Each generated hypothesis carries the observations that produced it and a
DISPROOF — the observation that would refute it (§35/I3: a test that cannot fail
proves nothing). A hypothesis with no disproof is a guess with a title.

§30's dual path is the other half: behaviour matching no known class opens a
research path AND a hunting path at the same time, and neither is allowed to
quietly become the other. `classify_behaviour` returns UNKNOWN and both branches
are created; research cannot mark the behaviour known without evidence, and
hunting cannot classify it without a citation.

Nothing here executes an action. It proposes; the caller decides.
"""
from __future__ import annotations

import json
import re
import sqlite3
from typing import Any, Iterable

from . import store, surface as surface_mod

# ---------------------------------------------------------------------------
# Hypothesis schema
# ---------------------------------------------------------------------------

SCHEMA = """
CREATE TABLE IF NOT EXISTS hypothesis (
  hyp_key     TEXT PRIMARY KEY,
  hunt_id     TEXT,
  statement   TEXT NOT NULL,        -- falsifiable: "if X then Y"
  class_id    TEXT,                 -- NULL when behaviour is UNKNOWN (§30)
  disproof    TEXT,                 -- the observation that would refute it
  origin      TEXT NOT NULL,        -- surface|knowledge|finding|research|agent
  basis       TEXT,                 -- JSON: the observations that produced it
  status      TEXT NOT NULL DEFAULT 'open',
      -- open|testing|validated|invalidated|refuted|unknown_researching
  confidence  REAL NOT NULL DEFAULT 0.0,
  created_at  TEXT NOT NULL,
  updated_at  TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS ix_hyp_status ON hypothesis(status, confidence);
CREATE INDEX IF NOT EXISTS ix_hyp_class ON hypothesis(class_id);

-- §30 unknown behaviour: both paths, explicitly paired.
CREATE TABLE IF NOT EXISTS unknown_behaviour (
  ub_key     TEXT PRIMARY KEY,
  hunt_id    TEXT,
  description TEXT NOT NULL,
  research_task  TEXT,              -- task_key of the research path
  hunting_task   TEXT,              -- task_key of the hunting path
  classification TEXT NOT NULL DEFAULT 'UNCLASSIFIED',
  resolved_by    TEXT,
  created_at  TEXT NOT NULL
);
"""

STATUSES = ("open", "testing", "validated", "invalidated", "refuted",
            "unknown_researching")


def _ensure(con: sqlite3.Connection) -> None:
    con.executescript(SCHEMA)
    con.commit()


# ---------------------------------------------------------------------------
# Class signatures. Not a checklist — a MATCHER over observable behaviour, used
# to decide whether a behaviour is known or unknown. §30 depends entirely on
# this being honest: a signature that matches everything makes every behaviour
# "known" and the research path never opens.
# ---------------------------------------------------------------------------

# (class_id, required observable signals, any-of supporting signals)
#
# MEASURED (2026-10-03, bootcamp C3): five keys here named classes that DO NOT
# EXIST in `bug_class`, so `classify_behaviour` could return an id with no page,
# chain, skill or methodology behind it — a hunt would look correctly
# classified while pointing at nothing. eval/test_hunt_classification.py T3
# now fails on any unregistered key, so this cannot silently regress.
#
# Each was remapped to the registered class that actually owns the behaviour,
# confirmed against `bug_class.summary` rather than guessed:
#   auth             -> authn  (establishing identity; authz/oauth kept separate)
#   csrf_bypass      -> csrf   (SameSite-only defence is a CSRF variant, not a class)
#   nosqli           -> nosql  (the corpus class is `nosql`)
#   request_smuggling-> smuggling
#   business_logic   -> bizlogic (the corpus class is `bizlogic`)
SIGNATURES: dict[str, dict[str, Any]] = {
    "idor": {"all": ["object_reference"], "any": ["other_user_object",
                                                  "ownership_check_absent",
                                                  "sequential_id"]},
    "authz": {"all": ["privileged_action"], "any": ["role_check",
                                                    "permission_check_absent"]},
    "authn": {"all": ["auth_flow"], "any": ["session_fixation", "weak_token",
                                            "credential_reuse", "jwt_none"]},
    "csrf": {"all": ["state_changing_request"],
             "any": ["no_csrf_token", "cookie_auth_only", "referer_only",
                     "same_site_absent"]},
    "xss": {"all": ["user_input_reflected"],
            "any": ["unescaped_html", "script_context", "dom_sink"]},
    "sqli": {"all": ["sql_error_or_behaviour"],
             "any": ["boolean_differential", "union_marker", "time_based"]},
    "nosql": {"all": ["query_parameter"], "any": ["operator_injection",
                                                  "javascript_object"]},
    "ssti": {"all": ["template_rendered"], "any": ["expression_evaluated",
                                                 "arithmetic_probe"]},
    "deser": {"all": ["serialized_payload_accepted"],
              "any": ["gadget_marker", "type_confusion", "magic_bytes"]},
    "ssrf": {"all": ["url_parameter_fetched_by_server"],
             "any": ["internal_address_reachable", "redirect_followed",
                     "metadata_endpoint"]},
    "path_traversal": {"all": ["file_path_parameter"],
                       "any": ["dotdot_accepted", "absolute_path_accepted"]},
    "bizlogic": {"all": ["workflow_step"], "any": ["step_skippable",
                                                   "negative_quantity",
                                                   "coupon_reuse"]},
    "race": {"all": ["concurrent_operation"],
             "any": ["no_lock", "check_then_act"]},
    "mass_assign": {"all": ["json_body_accepted"],
                    "any": ["privileged_field_accepted", "mass_assignment"]},
    "graphql": {"all": ["graphql_endpoint"], "any": ["introspection_enabled",
                                                    "batching_enabled"]},
    "cors": {"all": ["cors_header_present"],
             "any": ["origin_reflected", "credentials_with_wildcard"]},
    "smuggling": {"all": ["content_length_conflict"],
                  "any": ["cl_te_disagreement", "desync_observed"]},
    "xxe": {"all": ["xml_parser_reached"],
            "any": ["external_entity_resolved", "file_read"]},
    "open_redirect": {"all": ["redirect_parameter"],
                      "any": ["external_host_allowed", "javascript_scheme"]},
}

# Signals that make behaviour UNKNOWN rather than "probably something else".
UNKNOWN_SIGNALS = ("unexpected_status", "inconsistent_behaviour",
                   "unexplained_timing", "novel_response_shape",
                   "unmapped_error", "behaviour_change_after_input")


def classify_behaviour(signals: Iterable[str]) -> dict[str, Any]:
    """Map observable signals onto a class, or declare the behaviour unknown.

    Returns `{"classification": <class_id>|"UNKNOWN", "matched": [...],
    "unmatched": [...]}` and never resolves a tie by iteration order — an
    ambiguous match is reported as ambiguous, because a confidently wrong
    classification sends the hunt at the wrong class for the rest of its life.
    """
    sig = {s.strip().lower() for s in signals if s}
    if not sig:
        return {"classification": "UNKNOWN", "reason": "no signals supplied",
                "matched": [], "unmatched": []}

    if sig & set(UNKNOWN_SIGNALS):
        return {"classification": "UNKNOWN",
                "reason": "behaviour carries signals matching no known class",
                "trigger_signals": sorted(sig & set(UNKNOWN_SIGNALS)),
                "matched": [], "unmatched": sorted(sig)}

    scored: list[tuple[int, str]] = []
    for cid, spec in SIGNATURES.items():
        need_all = {s.lower() for s in spec["all"]}
        need_any = {s.lower() for s in spec["any"]}
        if not need_all <= sig:
            continue
        hits = need_any & sig
        if not hits:
            continue
        scored.append((len(hits), cid))

    if not scored:
        return {"classification": "UNKNOWN",
                "reason": "no signature matches the observed signals",
                "matched": [], "unmatched": sorted(sig)}

    scored.sort(reverse=True)
    if len(scored) > 1 and scored[0][0] == scored[1][0]:
        return {"classification": "UNKNOWN",
                "reason": (f"ambiguous between {[c for _, c in scored[:2]]} "
                           f"with equal support; not resolved by order"),
                "matched": [c for _, c in scored], "unmatched": sorted(sig)}

    # SIGNATURES stores its signals as LISTS, so set arithmetic against them
    # raised TypeError -- on the success path, which is the path every unknown
    # behaviour takes. §30's dual path depends on this returning, not raising.
    spec = SIGNATURES[scored[0][1]]
    declared = {str(s).lower() for s in spec["all"]} | {
        str(s).lower() for s in spec["any"]}
    return {"classification": scored[0][1],
            "support": scored[0][0],
            "matched": [scored[0][1]],
            "unmatched": sorted(sig - declared)}


# ---------------------------------------------------------------------------
# The engine
# ---------------------------------------------------------------------------

class HypothesisEngine:
    """Generates hypotheses from surface + corpus + prior findings."""

    def __init__(self, con: sqlite3.Connection, hunt_id: str = "default"):
        self.con = con
        self.hunt_id = hunt_id
        _ensure(con)
        self.surface = surface_mod.Surface(con, hunt_id)

    # ------------------------------------------------------------- authoring
    def propose(self, statement: str, *, class_id: str | None,
                disproof: str, origin: str, basis: dict[str, Any] | None = None,
                confidence: float = 0.0) -> str:
        """Record a hypothesis. A hypothesis without a disproof is REFUSED.

        The refusal is the point: §35/I3 says a test that cannot fail proves
        nothing, and a hypothesis with no falsifier is a claim. Returning a
        key here would put it in the graph and eventually in a report.
        """
        if not (disproof or "").strip():
            raise ValueError(
                "hypothesis refused: no disproof supplied. Name the observation "
                "that would refute it, or it is a claim, not a hypothesis.")
        if len(statement.strip()) < 20:
            raise ValueError("hypothesis refused: statement too short to be "
                             "falsifiable")
        k = f"hyp.{self.hunt_id}.{abs(hash(statement)) % (10 ** 10)}"
        self.con.execute(
            "INSERT OR REPLACE INTO hypothesis(hyp_key, hunt_id, statement,"
            " class_id, disproof, origin, basis, status, confidence,"
            " created_at, updated_at) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
            (k, self.hunt_id, statement.strip(), class_id, disproof.strip(),
             origin, json.dumps(basis or {}, default=str), "open",
             float(confidence), store.now(), store.now()))
        self.con.commit()
        return k

    def set_status(self, hyp_key: str, status: str, *, confidence: float | None = None
                   ) -> None:
        if status not in STATUSES:
            raise ValueError(f"unknown hypothesis status {status!r}; "
                             f"known: {STATUSES}")
        self.con.execute(
            "UPDATE hypothesis SET status=?, confidence=COALESCE(?, confidence),"
            " updated_at=? WHERE hyp_key=?",
            (status, confidence, store.now(), hyp_key))
        self.con.commit()

    def get(self, hyp_key: str) -> sqlite3.Row | None:
        return self.con.execute("SELECT * FROM hypothesis WHERE hyp_key=?",
                                (hyp_key,)).fetchone()

    def open_hypotheses(self, limit: int = 50) -> list[dict[str, Any]]:
        rows = self.con.execute(
            "SELECT * FROM hypothesis WHERE hunt_id=? AND status IN"
            " ('open','testing','unknown_researching')"
            " ORDER BY confidence DESC, created_at LIMIT ?",
            (self.hunt_id, limit)).fetchall()
        out = []
        for r in rows:
            d = dict(r)
            d["basis"] = _loads(d.get("basis"))
            out.append(d)
        return out

    # ------------------------------------------------- §19 surface-driven gen
    def from_surface(self) -> list[str]:
        """Generate hypotheses the caller did not supply.

        Every rule below is (observation, consequence) — the surface provides
        the observation, the consequence is a testable claim about the target,
        and the disproof is a measurement. This is the difference between a
        generator and a checklist: an unauthenticated admin route produces a
        HORIZONTAL hypothesis only if the surface shows an object reference,
        and an UNAUTH hypothesis only if it shows no auth requirement.
        """
        facts = self.surface.reachability_facts()
        made: list[str] = []

        # Unauthenticated endpoints touching privileged-looking paths.
        for ep in facts["unauthenticated_endpoints"]:
            if not re.search(r"admin|manage|internal|debug|actuator|console|"
                             r"config|swagger|graphql|health|status|metrics|"
                             r"backup|export|upload", ep, re.I):
                continue
            made.append(self.propose(
                f"the unauthenticated endpoint {ep} may expose a privileged "
                f"action, so a low-privilege or anonymous caller can reach "
                f"functionality the application intends to restrict",
                class_id="authz",
                disproof=(f"refuted if a request to {ep} without any session "
                          f"receives 401/403, or returns only public data in "
                          f"both the anonymous and an unprivileged session"),
                origin="surface",
                basis={"endpoint": ep, "facts": facts},
                confidence=0.55))

        # Object references on any reachable endpoint -> IDOR.
        # The endpoint LIST is read from the surface, never from a count.
        # `facts["endpoints"] and [...]` short-circuits to the INTEGER 0 when
        # the surface has no endpoints, and iterating an int raises — so the
        # one case that most needs a careful answer (an empty surface) was the
        # one case that crashed.
        for node in self.surface.nodes("endpoint"):
            ep = node["name"]
            attrs = _loads(node["attributes"])
            if not attrs.get("params"):
                continue
            param_names = " ".join(str(x) for x in attrs.get("params", []))
            if re.search(r"\b(id|uid|uuid|key|ref|handle|doc|invoice|order|"
                         r"account|user|file|no)\b", param_names, re.I):
                made.append(self.propose(
                    f"the parameterised endpoint {ep} may accept an object "
                    f"reference that is not bound to the caller's identity, so "
                    f"one principal can read another's object",
                    class_id="idor",
                    disproof=(f"refuted if swapping {ep}'s object reference to "
                              f"an object owned by a second principal returns "
                              f"404/403 for both, or byte-identical data"),
                    origin="surface",
                    basis={"endpoint": ep, "params": attrs.get("params")},
                    confidence=0.5))

        # A declared boundary with no crossing recorded is worth a look, but
        # only as an UNCLEARED-BOUNDARY hypothesis with its own disproof.
        if facts["no_boundary_declared"] and facts["hosts"]:
            made.append(self.propose(
                f"no trust boundary is declared for the observed surface, so a "
                f"privilege boundary between {facts['hosts'][0]} and any "
                f"downstream service is assumed rather than verified",
                class_id="authz",
                disproof=("refuted if the application enforces a server-side "
                          "authorization check that holds when the caller's "
                          "identity is stripped from the request"),
                origin="surface", basis={"facts": facts}, confidence=0.3))

        return made

    # ------------------------------------------- §19 knowledge-driven gen
    def from_knowledge(self, class_id: str, limit: int = 5) -> list[str]:
        """Derive hypotheses from the GATED corpus, not from a checklist.

        Each item already passed the evidence gate, so its claim is a citable
        premise; the hypothesis is the application of that premise to the
        target, and its disproof is that premise's own disproof clause. A
        claim with no disproof clause cannot produce a hypothesis here, which
        is correct — it would be an unfalsifiable one.
        """
        from wks import retrieval
        made: list[str] = []
        try:
            hits = retrieval.retrieve(self.con, class_id, limit=limit)
        except Exception as e:  # noqa: BLE001 - retrieval may be mid-rebuild
            return [self.propose(
                f"class {class_id} may be under-researched: retrieval failed "
                f"({type(e).__name__}: {e}), so no evidence-backed hypothesis "
                f"can be proposed from the corpus",
                class_id=class_id,
                disproof=("refuted if retrieval for this class returns at "
                          "least one item whose validation_state is "
                          "supported or high_confidence"),
                origin="knowledge", basis={"error": str(e)}, confidence=0.1)]
        for h in hits:
            claim = (h.get("claim") or h.get("title") or "").strip()
            disproof = (h.get("disproof") or "").strip()
            if not claim or not disproof:
                continue
            made.append(self.propose(
                f"the target may exhibit {class_id} behaviour described by the "
                f"corpus claim: {claim[:200]}",
                class_id=class_id,
                disproof=disproof,
                origin="knowledge",
                basis={"item_key": h.get("item_key"),
                       "sources": h.get("sources", [])[:3]},
                confidence=0.45))
        return made

    # ---------------------------------------- §19 prior-finding-driven gen
    def from_prior_findings(self) -> list[str]:
        """A validated weakness in this hunt is a node in the attack graph.

        §27: "use newly discovered weaknesses as nodes in an Attack Graph." A
        finding that reached `validated` implies the next question — what does
        this reach that was not obviously reachable — so each one spawns a
        reachability hypothesis rather than being filed and forgotten.
        """
        made: list[str] = []
        rows = self.con.execute(
            "SELECT finding_key, title, class_id, endpoint, asset FROM finding"
            " WHERE status IN ('validated','candidate') AND target IS NOT NULL"
        ).fetchall()
        for r in rows:
            if not r["endpoint"]:
                continue
            made.append(self.propose(
                f"the validated weakness {r['finding_key']} on {r['endpoint']} "
                f"may be usable as a pivot to reach a further asset or "
                f"privilege level not directly exposed by the entry point",
                class_id=r["class_id"] or "authz",
                disproof=(f"refuted if a reproduction of {r['finding_key']} "
                          f"confines its effect to the originally reported "
                          f"asset {r['asset'] or r['endpoint']} and grants no "
                          f"new reachability"),
                origin="finding",
                basis={"finding_key": r["finding_key"],
                       "class_id": r["class_id"]},
                confidence=0.4))
        return made

    # ------------------------------------------ §30 the dual path
    def open_unknown(self, description: str, *, signals: list[str] | None = None,
                     prefix: str = "unknown") -> dict[str, Any]:
        """Unknown behaviour opens a RESEARCH path AND a HUNTING path.

        Neither may quietly become the other. The research task exists to find
        a citation; the hunting task exists to characterise the behaviour
        without classifying it. `ub_key` pairs them so a later resolution has to
        say WHICH evidence resolved it.
        """
        cls = classify_behaviour(signals or [s for s in description.lower().split()
                                            if s])
        research_key = f"{prefix}.research.{abs(hash(description)) % (10 ** 8)}"
        hunting_key = f"{prefix}.hunt.{abs(hash(description)) % (10 ** 8)}"

        store.add_task(
            self.con, research_key,
            f"research the unclassified behaviour: {description}",
            priority=2,
            expected_artifact=("a cited classification with >=2 independent "
                               "publisher hosts, or a recorded refusal"),
            evidence_req=("quote verified verbatim on the live source; no "
                          "classification without a citation"),
            status="ready")
        store.add_task(
            self.con, hunting_key,
            f"characterise the unclassified behaviour without classifying it: "
            f"{description}",
            priority=2,
            expected_artifact=("observed request/response pairs, the trigger "
                               "condition, and the trust boundary it sits "
                               "behind"),
            evidence_req="recorded before/after pairs; classification deferred",
            status="ready")

        key = f"ub.{research_key}"
        self.con.execute(
            "INSERT OR REPLACE INTO unknown_behaviour(ub_key, hunt_id,"
            " description, research_task, hunting_task, classification,"
            " resolved_by, created_at) VALUES (?,?,?,?,?,?,?,?)",
            (key, self.hunt_id, description, research_key, hunting_key,
             cls["classification"], None, store.now()))
        self.con.commit()
        return {"ub_key": key, "classification": cls["classification"],
                "research_task": research_key, "hunting_task": hunting_key,
                "why": cls.get("reason", ""),
                "note": "both paths opened (§30): research finds the citation, "
                        "hunting characterises the behaviour"}

    def resolve_unknown(self, ub_key: str, classification: str, *,
                        resolved_by: str) -> None:
        """Close an unknown ONLY with evidence naming what resolved it."""
        if not (resolved_by or "").strip():
            raise ValueError("refused: an unknown behaviour cannot be resolved "
                             "without naming the evidence that resolved it")
        self.con.execute(
            "UPDATE unknown_behaviour SET classification=?, resolved_by=?"
            " WHERE ub_key=?",
            (classification, resolved_by, ub_key))
        self.con.commit()

    def open_unknowns(self) -> list[dict[str, Any]]:
        return [dict(r) for r in self.con.execute(
            "SELECT * FROM unknown_behaviour WHERE hunt_id=? AND resolved_by"
            " IS NULL", (self.hunt_id,)).fetchall()]

    def summary(self) -> dict[str, Any]:
        by_status = {r["status"]: r["n"] for r in self.con.execute(
            "SELECT status, count(*) n FROM hypothesis WHERE hunt_id=?"
            " GROUP BY status", (self.hunt_id,))}
        by_origin = {r["origin"]: r["n"] for r in self.con.execute(
            "SELECT origin, count(*) n FROM hypothesis WHERE hunt_id=?"
            " GROUP BY origin", (self.hunt_id,))}
        return {"hunt_id": self.hunt_id, "by_status": by_status,
                "by_origin": by_origin,
                "open_unknowns": len(self.open_unknowns()),
                "total": sum(by_status.values())}


def _loads(raw: str | None) -> dict[str, Any]:
    try:
        v = json.loads(raw or "{}")
        return v if isinstance(v, dict) else {}
    except (ValueError, TypeError):
        return {}