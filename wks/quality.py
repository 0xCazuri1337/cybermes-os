"""The quality gate (brief §15).

One rule governs this module: **a citation is not proof.**

The previous system promoted 1,380 items to `validated` while 1,378 of them had
no usable source at all and carried invented cross-references (`Ref1`, `Ref2`).
That failure is prevented structurally here, by making the hard gates
*necessary* conditions rather than advisory scores:

  1. >= MIN_SOURCES sources, and
  2. >= MIN_PUBLISHER_HOSTS DISTINCT HOSTS among them  (two pages on one host
     is one publisher, not corroboration), and
  3. no invented cross-references, and
  4. a claim specific enough to be falsifiable.

A weighted score alone would have passed those stubs: they are short but fluent,
and a fluent stub scores well on `practical_usefulness` unless usefulness is
defined as *demonstrated* rather than *asserted*.
"""
from __future__ import annotations

import json
import re
import sqlite3
from datetime import datetime, timezone
from typing import Any

from . import config, disproof as disproof_module, relevance, store

# Invented citations: the exact shape found in the quarantined corpus.
_FABRICATED_REF = re.compile(
    r"^\s*(ref\d*|source\d*|src\d*|cite\d*|n/?a|none|tbd|todo|x{2,}|asdf|"
    r"placeholder|example\.com|source|reference)\s*$",
    re.IGNORECASE,
)

# Vague claims that assert nothing testable.
_VAGUE = re.compile(
    r"^\s*(this (is|may|can) be (a )?(vulnerable|exploitable|an issue|bad)|"
    r"it is (vulnerable|exploitable|insecure)|might be (vulnerable|an issue)|"
    r"potentially (vulnerable|exploitable))\b",
    re.IGNORECASE,
)

# Reasons that block promotion but can be resolved by better evidence. Kept as
# a set so new gate reasons cannot silently become advisory: a reason added to
# `assess` without a decision here would default to blocking, which is the safe
# direction, but the set keeps the intent explicit and reviewable.
_BLOCKING_TAGS = {
    "NO_SOURCES",
    "INSUFFICIENT_SOURCES",
    "INSUFFICIENT_PUBLISHER_HOSTS",
    "DISCOVERY_ONLY_SOURCE",
    # The claim is about a different class, or is course prose. MEASURED: 221
    # of 1111 active items (20.0%) matched this, including 82.6% of
    # `exposed_rmm` holding OWASP password-policy advice. Every one of them
    # passed every provenance gate, because provenance says nothing about
    # subject. Blocking (not rejecting) is right: better evidence for the
    # RIGHT class promotes it there.
    "OFF_CLASS_TOPIC",
    "MODULE_FILLER",
    # MEASURED: 586 of 1334 items (43.9%) carried a disproof that names no
    # falsifying test and quotes the claim as its own evidence. See
    # wks/disproof.py. Blocking, not rejecting: the claim may be sound.
    "BOILERPLATE_DISPROOF",
    "CIRCULAR_DISPROOF",
}

# Never promotable at any score: the item's evidence or its claim is broken,
# not merely thin.
_REJECT_TAGS = {
    "FABRICATED_REFS",
    "UNFALSIFIABLE_CLAIM",
}


def _year(value: str | None) -> int | None:
    if not value:
        return None
    m = re.search(r"(\d{4})", value)
    return int(m.group(1)) if m else None


def has_fabricated_refs(texts: list[str]) -> list[str]:
    """Invented cross-references. A gate must never be satisfiable by fiction."""
    return [t for t in texts if t and _FABRICATED_REF.match(str(t).strip())]


def assess(
    con: sqlite3.Connection, item_id: int, *, today: datetime | None = None
) -> dict[str, Any]:
    """Score one item across the ten dimensions and decide its state."""
    today = today or datetime.now(timezone.utc)
    item = con.execute("SELECT * FROM item WHERE id=?", (item_id,)).fetchone()
    if item is None:
        raise LookupError(f"no item {item_id}")

    ev = store.item_evidence(con, item_id)
    claim = (item["claim"] or "").strip()
    body = (item["body"] or "").strip()
    disproof = (item["disproof"] or "").strip()

    # Builder pages (Notion / GitBook / static hosts) are documents someone
    # typed, not reviewed authorities. They are filtered out of the publisher
    # count so two pages a single author uploaded can never look like
    # corroboration. They remain in `ev` for the quote check: citing one as a
    # lead is fine; COUNTING one is not.
    hosts = {e["host"] for e in ev}
    builder_hosts = {h for h in hosts if config.is_builder_host(h)}
    if builder_hosts:
        hosts = {h for h in hosts if not config.is_builder_host(h)}
    # Count distinct PUBLISHERS, not distinct hostnames: www.microsoft.com and
    # learn.microsoft.com are the same company and must not corroborate each
    # other. Hostnames are still reported below for diagnosis.
    orgs = {config.publisher_org(h) for h in hosts if config.publisher_org(h)}
    publishers = {(e["publisher"] or e["host"]) for e in ev
                  if not config.is_builder_host(e["host"])}
    authorities = [int(e["authority"] or 3) for e in ev]
    types = {e["source_type"] for e in ev}
    best_auth = min(authorities) if authorities else 5
    years = [y for y in (_year(e["retrieved_at"]) for e in ev) if y]
    this_year = today.year
    age = (this_year - max(years)) if years else None

    # ---- dimensions (each 0..1) -----------------------------------------
    # 1. source credibility: best available authority tier.
    source_credibility = {1: 1.0, 2: 0.7, 3: 0.45, 4: 0.2, 5: 0.05}.get(best_auth, 0.2)

    # 2. technical specificity: is there a concrete object/condition to test?
    spec = 0.0
    if len(claim) >= config.MIN_CLAIM_CHARS:
        spec += 0.35
    if body and len(body) >= config.MIN_BODY_CHARS_SUPPORTED:
        spec += 0.35
    if disproof:
        spec += 0.30   # states what would falsify it — the anti-checklist rule
    technical_specificity = min(spec, 1.0)

    # 3. evidence strength: quoted spans beat bare links.
    quoted = [e for e in ev if e["quote"]]
    if not ev:
        evidence_strength = 0.0
    else:
        evidence_strength = min(
            0.35 + 0.15 * len(ev) + (0.25 if quoted else 0.0), 1.0
        )

    # 4. reproducibility: does the item describe a testable procedure?
    signals = sum(
        1 for w in (
            "request", "response", "header", "parameter", "payload", "endpoint",
            "probe", "compare", "differential", "verify", "replay", "baseline",
        ) if w in (claim + " " + body).lower()
    )
    reproducibility = min(signals / 4.0, 1.0)

    # 5. corroboration: INDEPENDENT publishers, not URL count.
    corroboration = min(len(publishers) / 2.0, 1.0)

    # 6. practical usefulness: DEMONSTRATED value, not asserted value.
    #    An item nobody has hunted with cannot show usefulness; hunt-learned
    #    items (real_world_demo>0) or explicitly rated items score higher.
    practical_usefulness = min(int(item["hunting_value"] or 3) / 5.0, 1.0)

    # 7. recency: full credit <2y, decaying to 0.15 at 8y.
    if age is None:
        recency = 0.15
    elif age <= 2:
        recency = 1.0
    else:
        recency = max(0.15, 1.0 - 0.12 * (age - 2))

    # 8. internal consistency: a disproof clause and a self-consistent claim.
    consistency = 0.5 + (0.5 if disproof else 0.0)
    if _VAGUE.match(claim):
        consistency -= 0.3

    # 9. real-world demonstration: an item with provenance from a real report
    #    or writeup describing exploitation, not just a taxonomy page.
    rwd = 1.0 if types & {"report", "writeup", "research"} else (
        0.4 if types & {"docs", "cheatsheet", "vendor"} else 0.0
    )
    if types and types <= {"taxonomy", "advisory"}:
        rwd = 0.2

    # 10. limitations documented.
    limitations_documented = 1.0 if disproof or "not" in body.lower() or "when " in body.lower() else 0.25

    dims = {
        "source_credibility": source_credibility,
        "technical_specificity": technical_specificity,
        "evidence_strength": evidence_strength,
        "reproducibility": reproducibility,
        "corroboration": corroboration,
        "practical_usefulness": practical_usefulness,
        "recency": recency,
        "internal_consistency": max(consistency, 0.0),
        "real_world_demo": rwd,
        "limitations_documented": limitations_documented,
    }
    score = sum(dims[k] * w for k, w in config.QUALITY_WEIGHTS.items())

    # ---- HARD GATES -----------------------------------------------------
    reasons: list[str] = []
    if not ev:
        reasons.append("NO_SOURCES")
    else:
        if len(ev) < config.MIN_SOURCES:
            reasons.append(f"INSUFFICIENT_SOURCES({len(ev)}<{config.MIN_SOURCES})")
        if builder_hosts:
            reasons.append(
                f"BUILDER_PAGE_NOT_PUBLISHER({','.join(sorted(builder_hosts))})")
        if len(orgs) < config.MIN_PUBLISHER_HOSTS:
            reasons.append(
                f"INSUFFICIENT_PUBLISHER_HOSTS({len(orgs)}<{config.MIN_PUBLISHER_HOSTS}"
                f":{','.join(sorted(hosts))})"
            )
        if types and types <= set(config.DISCOVERY_ONLY):
            reasons.append("DISCOVERY_ONLY_SOURCE")
    if fabricated := has_fabricated_refs(
        [e["quote"] for e in ev] + [e["locator"] for e in ev]
    ):
        reasons.append(f"FABRICATED_REFS({len(fabricated)})")
    if len(claim) < config.MIN_CLAIM_CHARS:
        reasons.append("VAGUE_CLAIM")
    if _VAGUE.match(claim):
        reasons.append("UNFALSIFIABLE_CLAIM")

    # ---- DISPROOF QUALITY: does the disproof actually refute something? ----
    # MEASURED: 586 of 1334 active items (43.9%) carried this template, which
    # looks rigorous and refutes nothing --
    #   "This is refuted if an authoritative source shows the described
    #    behaviour does not occur ... : "<the claim, quoted back>"
    # It names no falsifying test and cites the claim as its own evidence, yet
    # R4 scores 0.30 of `technical_specificity` for HAVING a disproof, so these
    # items were paid for a disproof they did not earn. A disproof that cannot
    # fail is the same defect as a missing one.
    #
    # Blocking, not rejecting: the CLAIM is often perfectly good (an SSRF or
    # SQLi mechanism sentence is real knowledge). Only the disproof is hollow,
    # and it is replaceable -- so the item is held for repair, never deleted.
    dp = disproof_module.reason_for(disproof, claim)
    if dp:
        reasons.append(dp.split(":")[0].strip())

    # ---- SUBJECT GATE: is the claim about the class it is filed under? ----
    # Every other gate above is about PROVENANCE (is the quote real, does it
    # corroborate) and none is about SUBJECT. An OWASP password-cheatsheet
    # quote is real, verbatim, and corroborated by two publisher orgs, so it
    # sailed through every one of them while being filed under `exposed_rmm`.
    # That is how 155 items became knowledge that teaches the wrong thing, and
    # how classes read `mature` on filler.
    #
    # Only the two POSITIVE-evidence verdicts block (see wks.relevance). An
    # unplaceable claim annotates rather than blocks, because holding on the
    # ABSENCE of a vocabulary match was measured ~70% wrong.
    rel = relevance.assess(item["class_id"], claim)
    if rel is not None and rel.holds:
        reasons.append(rel.tag)

    # ---- state ----------------------------------------------------------
    # Reasons are recorded as `TAG` or `TAG(detail)`; compare on the TAG alone.
    # Matching the raw string is a trap: `FABRICATED_REFS(4)` != `FABRICATED_REFS`
    # and the check silently fails, which is exactly how a fabricated-source
    # item reached `supported` during development.
    tags = {r.split("(")[0].strip() for r in reasons}

    # Fabricated refs and unfalsifiable claims are unpromotable, NOT merely
    # unpromoted: they are evidence of a broken acquisition step, so they are
    # rejected outright. Everything else blocks promotion but may still be
    # resolved by better evidence later.
    if tags & _REJECT_TAGS:
        state = "rejected"
    elif tags & _BLOCKING_TAGS:
        state = "under_review"
    elif score >= config.STATE_THRESHOLDS["high_confidence"]:
        state = "high_confidence"
    elif score >= config.STATE_THRESHOLDS["supported"]:
        state = "supported"
    elif score >= config.STATE_THRESHOLDS["under_review"]:
        state = "under_review"
    else:
        state = "discovered"

    return {"item_id": item_id, "score": score, "state": state,
            "dims": dims, "reasons": reasons, "tags": sorted(tags),
            "hosts": sorted(hosts), "publishers": sorted(publishers)}


def assess_all(con: sqlite3.Connection) -> dict[str, int]:
    """Re-gate every item. Idempotent; safe to run after any ingestion."""
    counts: dict[str, int] = {}
    for row in con.execute("SELECT id FROM item WHERE status='active'").fetchall():
        r = assess(con, int(row["id"]))
        store.set_state(con, r["item_id"], r["state"], r["score"], r["reasons"])
        counts[r["state"]] = counts.get(r["state"], 0) + 1
    con.commit()
    return counts


def maturity(con: sqlite3.Connection, class_id: str) -> dict[str, Any]:
    """§29 definition of done, measured. Not asserted — computed."""
    row = store.get_class(con, class_id)
    if row is None:
        # Full key set, zeros throughout. The early return used to carry only
        # class_id/state/missing, so any caller doing the natural
        # `maturity(...)["n_fp"]` -- as the gap report and the selftest both do
        # -- raised KeyError instead of reading a zero. An unknown class is a
        # normal condition (a name typo, a class added to a brief that does not
        # exist), so it must not be the one input that crashes a consumer.
        return {
            "class_id": class_id, "state": "unknown", "missing": ["class"],
            "n_items": 0, "n_supported": 0, "n_fp": 0, "n_chains": 0,
            "checks": {k: False for k in
                       ("taxonomy_placed", "methodology", "items",
                        "supported_items", "fp_rules", "chain", "skill")},
        }

    n_items = con.execute(
        """SELECT count(*) n FROM item i JOIN quality q ON q.item_id=i.id
           WHERE i.class_id=? AND i.status='active'""", (class_id,)
    ).fetchone()["n"]
    n_high = con.execute(
        """SELECT count(*) n FROM item i JOIN quality q ON q.item_id=i.id
           WHERE i.class_id=? AND i.status='active'
             AND q.validation_state IN ('supported','high_confidence')""",
        (class_id,),
    ).fetchone()["n"]
    # FP knowledge exists in TWO shapes: the authored fp_case narrative (looked
        # vulnerable because / test performed / invalidated by) and the gate-passed
        # `fp_rule` ITEM that the research pipeline produces. Counting only fp_case
        # made the gap report demand fp_rules from classes that already had two
        # verified ones -- it sent a whole wave to re-derive FP rules that were
        # already promoted, and the metric never moved. Count both.
    n_fp_case = con.execute(
        "SELECT count(*) n FROM fp_case WHERE class_id=?", (class_id,)
    ).fetchone()["n"]
    n_fp_item = con.execute(
        """SELECT count(*) n FROM item i JOIN quality q ON q.item_id=i.id
           WHERE i.class_id=? AND i.status='active' AND i.kind='fp_rule'
             AND q.validation_state IN ('supported','high_confidence')""",
        (class_id,),
    ).fetchone()["n"]
    n_fp = n_fp_case + n_fp_item
    n_chain = con.execute(
        """SELECT count(DISTINCT chain_id) n FROM chain_step
           WHERE class_id=?""", (class_id,)
    ).fetchone()["n"]
    has_method = bool(row["methodology"])
    has_skill = bool(row["skill_path"])

    checks = {
        "taxonomy_placed": True,
        "methodology": has_method,
        "items": n_items >= config.MATURITY_MIN_ITEMS,
        "supported_items": n_high >= config.MATURITY_MIN_HIGH_CONF,
        "fp_rules": n_fp >= config.MATURITY_MIN_FP_RULES,
        "chain": n_chain >= config.MATURITY_MIN_CHAINS,
        "skill": has_skill,
    }
    missing = [k for k, v in checks.items() if not v]
    state = "mature" if not missing else ("researching" if n_items else "planned")
    return {
        "class_id": class_id, "state": state, "missing": missing,
        "n_items": n_items, "n_supported": n_high, "n_fp": n_fp,
        "n_chains": n_chain, "checks": checks,
    }


def gap_report(con: sqlite3.Connection) -> list[dict[str, Any]]:
    """Weakest classes first — the overnight loop's work queue (§30)."""
    out = []
    for row in con.execute("SELECT id FROM bug_class ORDER BY id").fetchall():
        m = maturity(con, row["id"])
        # Priority is a cost model: unstarted classes cost the most, then
        # missing methodology/skill/FP/chain, then how thin the supported
        # evidence is. Higher = do sooner. (§30 overnight ordering.)
        priority = (
            (50 if m["n_items"] == 0 else 0)
            + (20 if not m["checks"]["methodology"] else 0)
            + (15 if not m["checks"]["skill"] else 0)
            + (10 * max(0, config.MATURITY_MIN_ITEMS - m["n_items"]))
            + (5 * max(0, config.MATURITY_MIN_HIGH_CONF - m["n_supported"]))
            + (5 if m["n_fp"] == 0 else 0)
            + (5 if m["n_chains"] == 0 else 0)
        )
        m["priority"] = priority
        out.append(m)
    return sorted(out, key=lambda m: (-m["priority"], m["class_id"]))
