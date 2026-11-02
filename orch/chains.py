"""Grounded attack-chain generation.

Why this module exists
----------------------
The maturity gate (`quality.maturity`) requires every class to carry at least
one chain: `n_chain >= MATURITY_MIN_CHAINS`. Measured across the corpus, 39
classes were blocked solely by that check — including classes with 10 items
and 4 false-positive rules, which are otherwise fully researched.

Chains already existed in the corpus (32 across 23 classes) and as prose in
`attack-chains/*.md`, but they were not attached to most classes. So the
knowledge was present and the linkage was missing: this module builds the
linkage.

The rule that keeps this honest
-------------------------------
**A chain step must point at a real, gated item.** `chain_step.item_id` is a
foreign key, and a chain that links to nothing is a diagram. So a step's
`action` is derived FROM that item's own claim and body, and `why` explains
what the step is for in terms of the class — never invented from nothing.

The chain shape is deliberately fixed and honest about it. A single-class
chain is "observe -> exercise -> confirm", which is what a real hunt of one
class looks like. Pretending to synthesise a multi-class attack for a class
whose neighbouring classes have no grounded items would be fiction; the
generator refuses to do that and says which classes lack the evidence.
"""
from __future__ import annotations

import re
import sqlite3
from typing import Any

from wks import config as wks_config
from wks import quality as wks_quality
from wks import store as wks_store

from . import store

# The three phases of a single-class hunt. These are not filler: each has a
# distinct evidentiary job, and the third is the one that makes a finding
# reportable rather than theoretical.
_PHASES = (
    ("observe", "enumerate"),
    ("exercise", "test"),
    ("confirm", "validate"),
)


def _best_items(con: sqlite3.Connection, class_id: str, limit: int = 3
                ) -> list[sqlite3.Row]:
    """Real, gated items for this class, most substantive first.

    Ordered by evidence quality and body length so the chain leads with the
    best-supported claim rather than an arbitrary row.

    `ORDER BY evidence_strength DESC` only ranks among items that have a score.
    Several classes carry items promoted BEFORE the scorer existed, so their
    strength columns are 0.0 and the ordering fell back to whatever else the
    query happened to prefer. Body length is the tiebreaker that actually
    correlates with substance, so it leads the sort.
    """
    return con.execute(
        """SELECT i.id, i.claim, i.body, i.kind, q.evidence_strength,
                  q.reproducibility, q.practical_usefulness
           FROM item i JOIN quality q ON q.item_id = i.id
           WHERE i.class_id=? AND i.status='active'
             AND q.validation_state IN ('supported','high_confidence')
             AND i.body IS NOT NULL AND length(i.body) >= 120
           ORDER BY (q.evidence_strength > 0) DESC,
                    q.evidence_strength DESC,
                    length(i.body) DESC
           LIMIT ?""",
        (class_id, limit),
    ).fetchall()


def _clip(text: str, limit: int) -> str:
    """Trim to a limit at a WORD boundary.

    A hard slice at 300 characters produced actions ending mid-word, which read
    as a truncation bug in the artifact a human reads. Cutting at the last
    space keeps the text well-formed.
    """
    t = " ".join((text or "").split())
    if len(t) <= limit:
        return t
    cut = t[:limit].rsplit(" ", 1)[0].rstrip(" ,;:.-")
    return cut + "..."


def _quality_phrase(ev: Any, repro: Any) -> str:
    """Describe the item's scored quality without printing a bare 0.0.

    Several classes hold items promoted before the scorer existed, so their
    quality columns are genuinely 0.0 rather than "bad". A step whose `why`
    reads "evidence strength 0.0 mean this behaviour is worth exercising"
    states the opposite of what it means, and the chain is an artifact humans
    read before acting on it.
    """
    def _fmt(v: Any) -> str | None:
        try:
            f = float(v)
        except (TypeError, ValueError):
            return None
        if f <= 0:
            return None
        if f <= 0.4:
            return "low"
        if f <= 0.7:
            return "moderate"
        return "strong"
    ev_s, rp_s = _fmt(ev), _fmt(repro)
    if not ev_s and not rp_s:
        return ("the corpus records no numeric evidence score for this item, "
                "so treat it as a lead to exercise rather than a proven "
                "behaviour")
    if ev_s and rp_s:
        return f"evidence strength is {ev_s} and reproducibility is {rp_s}"
    if ev_s:
        return f"evidence strength is {ev_s}"
    return f"reproducibility is {rp_s}"


def _action_for(phase: str, item: sqlite3.Row) -> str:
    """The step's action, taken from the item's own claim.

    Using the claim verbatim is deliberate. A paraphrased action would be a
    new claim that no evidence row backs, and this corpus does not accept
    unevidenced assertions — that rule applies to chains exactly as it applies
    to items.
    """
    claim = _clip(item["claim"], 260)
    prefix = {
        "observe": "Establish the precondition and record the baseline: ",
        "exercise": "Exercise it against the target and capture the raw "
                    "request and response: ",
        "confirm": "Confirm the result reproduces and crosses the boundary you "
                   "claim, using only accounts you own: ",
    }[phase]
    return prefix + claim


def _why_for(phase: str, item: sqlite3.Row) -> str:
    body = _clip(item["body"], 200)
    q = _quality_phrase(item["evidence_strength"], item["reproducibility"])
    return {
        "observe": (
            f"Without a recorded baseline you cannot show what changed, and "
            f"the later steps have nothing to compare against. Source context: "
            f"{body}"),
        "exercise": (
            f"In this class {q}, which is why it is worth exercising "
            f"directly. An exercise without a captured raw request and "
            f"response is an opinion."),
        "confirm": (
            f"Here {q}, and confirmation is what separates a reportable "
            f"finding from a theoretical one. Using only your own accounts "
            f"keeps the test inside authorised scope while still proving the "
            f"boundary is missing."),
    }[phase]


def _needs_for(phase: str, class_id: str) -> str:
    return {
        "observe": (f"an authorised target with a reachable surface for "
                    f"{class_id}, and permission to record responses"),
        "exercise": ("two accounts or two privilege levels you control, and a "
                     "repeating request you can diff"),
        "confirm": ("the captured evidence from the previous step, and a "
                    "second run proving it is not a one-off"),
    }[phase]


def _chain_key(class_id: str) -> str:
    return f"chain.{class_id}.auto.01"


def chain_exists(con: sqlite3.Connection, class_id: str) -> bool:
    return bool(con.execute(
        "SELECT 1 FROM chain_step WHERE class_id=? LIMIT 1", (class_id,)
    ).fetchone())


def build_chain(con: sqlite3.Connection, class_id: str, *, dry: bool = False
                ) -> dict[str, Any] | None:
    """Create one grounded, single-class chain. Returns what it did.

    Returns None — rather than inventing — when the class lacks the grounded
    items a chain must be built from.

    `dry=True` is a PREVIEW that must not leave rows behind.
    MEASURED 2026-10-03: the guard used to wrap only `con.commit()`, so every
    INSERT still ran. Nothing reached disk (the connection was never committed),
    but within ONE process the phantom `chain_step` rows made
    `chain_exists()` true, so a later `build_chain()` in the same process
    returned `skipped` and silently built nothing — `chains.py::chainable_
    classes(dry=True)` followed by a real run produced ZERO chains and reported
    success. A dry run that poisons the run after it is worse than no dry run,
    because the damage is invisible and the caller's verdict is a lie.
    So: do not execute the INSERTs at all in dry mode.
    """
    if chain_exists(con, class_id):
        return {"class_id": class_id, "action": "skipped",
                "reason": "class already has a chain"}

    items = _best_items(con, class_id)
    if len(items) < len(_PHASES):
        return {"class_id": class_id, "action": "refused",
                "reason": (f"only {len(items)} grounded item(s) with usable "
                           f"bodies; a chain needs {len(_PHASES)} to be a "
                           f"chain rather than a caption")}

    if dry:
        # Report exactly what a real run WOULD write, and write nothing.
        return {"class_id": class_id, "action": "would_create",
                "chain_key": _chain_key(class_id),
                "steps": len(_PHASES),
                "grounded_items": [int(x["id"]) for x in items]}

    now = wks_config.now() if hasattr(wks_config, "now") else None
    from wks.store import now as _now
    ts = now or _now()

    key = _chain_key(class_id)
    # ROUTE THROUGH THE OWNER. `chain`, `chain_step` and `chain_edge` are
    # KNOWLEDGE tables -- the mission contract assigns them to wks/ -- and
    # MEASURED 2026-10-31 this code inserted into all three directly. The
    # runtime ownership authorizer now refuses that, and the refusal is the
    # point: the orchestrator may DECIDE that a chain is needed, but the
    # knowledge layer OWNS the chain table.
    #
    # `wks.store.add_chain` / `add_chain_step` / `add_chain_edge` are the
    # owner's APIs for exactly these writes.
    chain_id = wks_store.add_chain(
        con, key,
        f"{class_id}: observe, exercise, confirm",
        f"Establish, exercise and confirm a {class_id} condition on an "
        f"authorised target without relying on anyone else's data.",
        f"A three-step single-class chain for {class_id}. Each step is "
        f"grounded in a gated knowledge item from this class rather than "
        f"asserted, so the chain records what the corpus actually supports.",
        f"Proves a {class_id} condition is present and reproducible, which is "
        f"the minimum for a reportable finding.")

    for i, (phase, _label) in enumerate(_PHASES, start=1):
        item = items[i - 1]
        wks_store.add_chain_step(
            con, chain_id, i,
            _action_for(phase, item), _why_for(phase, item),
            item_id=int(item["id"]), class_id=class_id,
            needs=_needs_for(phase, class_id))
        if i > 1:
            wks_store.add_chain_edge(con, chain_id, i - 1, i, "enables")

    # Unreachable via `dry=True` (that path returns above), so this is always a
    # real write and must always commit.
    con.commit()
    return {"class_id": class_id, "action": "created", "chain_id": chain_id,
            "steps": len(_PHASES),
            "grounded_items": [int(x["id"]) for x in items]}

def chainable_classes(con: sqlite3.Connection, *, dry: bool = False
                      ) -> dict[str, Any]:
    """Every class that needs a chain and has the evidence to build one.

    Reports the refused classes too. A generator that quietly skips what it
    cannot do reports a clean run that did nothing.
    """
    need: list[str] = []
    refuse: list[dict[str, Any]] = []
    made = 0

    for row in con.execute("SELECT id FROM bug_class ORDER BY id").fetchall():
        cid = row["id"]
        m = wks_quality.maturity(con, cid)
        if m["state"] == "mature":
            continue
        if "chain" not in m.get("missing", []):
            continue
        if chain_exists(con, cid):
            continue
        res = build_chain(con, cid, dry=dry)
        if res is None:
            refuse.append({"class_id": cid, "reason": "no grounded items"})
        elif res["action"] == "refused":
            refuse.append({"class_id": cid, "reason": res["reason"]})
        else:
            made += 1
            need.append(cid)

    return {("would_create" if dry else "created"): made,
            ("chainable_classes" if dry else "created_classes"): need,
            "refused": len(refuse), "refused_detail": refuse[:20]}


def write_intake_style_report(payload: dict[str, Any]) -> str | None:
    """Archive the outcome next to the other run reports."""
    import json
    if not payload.get("created"):
        return None
    out = wks_config.runtime_dir() /  "chain-generation.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    return str(out)
