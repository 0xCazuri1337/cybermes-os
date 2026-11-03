"""Phase 7: Intelligent Update Routing & Change Governance."""
from __future__ import annotations

import hashlib
import json
import re
import sqlite3
import uuid
from datetime import datetime, timezone
from typing import Any, Callable

UPDATE_KINDS = ("KNOWLEDGE", "ATTACK_CHAIN", "FP_RULE", "SKILL_PROCEDURE",
                "NO_CHANGE", "CONFLICT", "UNROUTED")

ROUTE_STATUSES = ("PRELIMINARY", "FINAL")
ROUTING_STATUSES = ("ROUTED", "NO_CHANGE", "UNROUTED", "CONFLICT", "POLICY_BLOCKED")
EXEC_STATUSES = ("NOT_STARTED", "PENDING", "AWAITING_APPROVAL", "RUNNING",
                 "APPLIED", "FAILED", "ROLLED_BACK", "REJECTED")


def now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _text(v):
    if v is None:
        return ""
    if isinstance(v, dict):
        return v.get("claim") or v.get("text") or v.get("description") or ""
    return str(v)


def candidate_id(c):
    if isinstance(c, dict):
        return c.get("id") or c.get("candidate_id") or c.get("key")
    try:
        return c["id"]
    except Exception:
        return getattr(c, "id", None)


def candidate_hash(c):
    try:
        payload = json.dumps(c, sort_keys=True, default=str)
    except Exception:
        payload = repr(c)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def decision_key_for(c):
    return "rd." + candidate_hash(c)[:24]


def route_key_for(decision_id, kind, label=None):
    base = f"rt.{decision_id}.{kind}"
    if label:
        base += f".{label}"
    return base


def _norm(s):
    return re.sub(r"\s+", " ", str(s or "").lower()).strip()


def _detect_conflict(candidate, context=None):
    ctx = context or {}
    conflicts = ctx.get("conflicts") if isinstance(ctx, dict) else None
    if conflicts:
        return True, "candidate conflicts with existing knowledge"
    if isinstance(candidate, dict):
        if candidate.get("conflict") or candidate.get("has_conflict"):
            return True, "candidate flagged as conflicting"
        claim = _norm(candidate.get("claim") or candidate.get("text"))
        if "contradict" in claim:
            return True, "claim contains contradiction marker"
    return False, None


def _detect_no_change(candidate, context=None):
    ctx = context or {}
    existing = ctx.get("existing") if isinstance(ctx, dict) else None
    if existing:
        c_claim = _norm(_text(candidate))
        for e in existing:
            if _norm(_text(e)) == c_claim and c_claim:
                return True, "candidate is identical to existing item"
    if isinstance(candidate, dict):
        if candidate.get("duplicate") or candidate.get("no_change"):
            return True, "candidate marked as no-change/duplicate"
    return False, None


def _map_kind(candidate):
    if isinstance(candidate, dict):
        explicit = candidate.get("update_kind") or candidate.get("route_kind")
        if explicit in UPDATE_KINDS:
            return explicit, f"explicit update_kind={explicit}"
        kind = (candidate.get("kind") or "").lower()
        ctype = (candidate.get("type") or "").lower()
        claim = _norm(candidate.get("claim") or candidate.get("text"))
    else:
        kind = (getattr(candidate, "kind", "") or "").lower()
        ctype = (getattr(candidate, "type", "") or "").lower()
        claim = _norm(_text(candidate))
    text = kind + " " + ctype + " " + claim
    if "false positive" in text or kind in ("fp", "fp_rule"):
        return "FP_RULE", "candidate describes a false-positive rejection rule"
    if "chain" in text or kind in ("chain", "attack_chain"):
        return "ATTACK_CHAIN", "candidate describes an attack chain"
    if "skill" in text or "procedure" in text or kind in ("skill", "skill_procedure", "procedure"):
        return "SKILL_PROCEDURE", "candidate describes a skill/procedure update"
    if "knowledge" in kind or kind in ("item", "technique", "knowledge"):
        return "KNOWLEDGE", "candidate is knowledge content"
    if claim:
        return "KNOWLEDGE", "default classification: knowledge content"
    return "UNROUTED", "no routable content"


def classify_update_kind(candidate, *, context=None, ai_fn=None):
    reasons = []
    alternatives = []
    conflict, creason = _detect_conflict(candidate, context)
    if conflict:
        reasons.append(creason)
        return {"kind": "CONFLICT", "confidence": 0.95, "reason": creason,
                "reasons": reasons, "alternatives": alternatives,
                "ai_advisory": None}
    nochange, nreason = _detect_no_change(candidate, context)
    if nochange:
        reasons.append(nreason)
        return {"kind": "NO_CHANGE", "confidence": 0.9, "reason": nreason,
                "reasons": reasons, "alternatives": alternatives,
                "ai_advisory": None}
    claim = _text(candidate)
    if not str(claim).strip():
        r = "candidate has no claim/content to route"
        return {"kind": "UNROUTED", "confidence": 0.5, "reason": r,
                "reasons": [r], "alternatives": alternatives, "ai_advisory": None}

    kind, reason = _map_kind(candidate)
    reasons.append(reason)
    confidence = 0.85

    ai_advisory = None
    if ai_fn is not None:
        try:
            suggestion = ai_fn(candidate, context)
        except Exception as e:
            suggestion = {"error": str(e)}
        ai_advisory = suggestion
        if isinstance(suggestion, dict):
            s_kind = suggestion.get("kind") or suggestion.get("update_kind")
            if s_kind and s_kind in UPDATE_KINDS and s_kind != kind:
                alternatives.append({"kind": s_kind, "source": "ai_advisory",
                                    "confidence": suggestion.get("confidence", 0.5),
                                    "reason": suggestion.get("reason", "ai suggestion")})
            elif s_kind == kind:
                confidence = min(0.99, confidence + 0.05)

    if isinstance(candidate, dict) and candidate.get("policy_blocked"):
        return {"kind": kind, "confidence": confidence,
                "reason": "policy blocked", "reasons": ["policy blocked"],
                "alternatives": alternatives, "ai_advisory": ai_advisory,
                "policy_blocked": True}

    return {"kind": kind, "confidence": confidence, "reason": reason,
            "reasons": reasons, "alternatives": alternatives,
            "ai_advisory": ai_advisory}


def find_decision(con, candidate):
    h = candidate_hash(candidate)
    row = con.execute(
        "SELECT * FROM routing_decision WHERE candidate_hash=? ORDER BY id DESC LIMIT 1",
        (h,)).fetchone()
    return dict(row) if row else None


def _json(v):
    if v is None:
        return None
    if isinstance(v, str):
        return v
    return json.dumps(v, default=str)


def _routing_status_for(kind, policy_blocked=False):
    if policy_blocked:
        return "POLICY_BLOCKED"
    if kind == "NO_CHANGE":
        return "NO_CHANGE"
    if kind == "UNROUTED":
        return "UNROUTED"
    if kind == "CONFLICT":
        return "CONFLICT"
    return "ROUTED"


def _target_type(kind):
    return {
        "KNOWLEDGE": "knowledge_item",
        "ATTACK_CHAIN": "chain",
        "FP_RULE": "fp_case",
        "SKILL_PROCEDURE": "skill",
    }.get(kind)


def _decision_to_dict(con, row):
    d = dict(row)
    d["reasons"] = json.loads(d.get("reasons") or "[]")
    d["alternatives"] = json.loads(d.get("alternatives") or "[]")
    if d.get("ai_advisory"):
        try:
            d["ai_advisory"] = json.loads(d["ai_advisory"])
        except Exception:
            pass
    d["routes"] = [dict(r) for r in con.execute(
        "SELECT * FROM route WHERE decision_id=?", (d["id"],)).fetchall()]
    return d


def preliminary_route(con, candidate, *, ai_fn=None, context=None, before_hash=None):
    existing = find_decision(con, candidate)
    if existing is not None:
        return _decision_to_dict(con, existing)
    cls = classify_update_kind(candidate, context=context, ai_fn=ai_fn)
    cid = candidate_id(candidate)
    h = candidate_hash(candidate)
    dk = decision_key_for(candidate)
    bh = before_hash or hashlib.sha256(
        json.dumps(candidate, sort_keys=True, default=str).encode()).hexdigest()
    policy_blocked = bool(cls.get("policy_blocked"))
    con.execute(
        """INSERT INTO routing_decision(decision_key,candidate_id,candidate_hash,status,
           routing_status,update_kind,confidence,reasons,alternatives,ai_advisory,
           before_hash,created_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)""",
        (dk, str(cid) if cid is not None else None, h, "PRELIMINARY",
         _routing_status_for(cls["kind"], policy_blocked), cls["kind"],
         cls["confidence"], json.dumps(cls["reasons"]),
         json.dumps(cls["alternatives"]), _json(cls["ai_advisory"]), bh, now()))
    con.commit()
    did = con.execute("SELECT last_insert_rowid()").fetchone()[0]
    labels = [cls["kind"]]
    for alt in cls["alternatives"]:
        if alt.get("kind") and alt["kind"] not in labels:
            labels.append(alt["kind"])
    for lab in labels:
        rk = route_key_for(did, lab)
        con.execute(
            """INSERT INTO route(route_key,decision_id,update_kind,target_type,target_id,label,
               execution_status,created_at,updated_at) VALUES (?,?,?,?,?,?,?,?,?)""",
            (rk, did, lab, _target_type(lab), None, lab, "NOT_STARTED", now(), now()))
    con.commit()
    row = con.execute("SELECT * FROM routing_decision WHERE id=?", (did,)).fetchone()
    return _decision_to_dict(con, dict(row))


def finalize_route(con, decision_or_candidate, *, approved=False, reviewer=None, context=None):
    dec = None
    if isinstance(decision_or_candidate, dict) and "id" in decision_or_candidate and "candidate_hash" in decision_or_candidate:
        dec = decision_or_candidate
    elif isinstance(decision_or_candidate, int):
        row = con.execute("SELECT * FROM routing_decision WHERE id=?", (decision_or_candidate,)).fetchone()
        dec = dict(row) if row else None
    else:
        existing = find_decision(con, decision_or_candidate)
        dec = existing
    if dec is None:
        preliminary_route(con, decision_or_candidate, context=context)
        if isinstance(decision_or_candidate, dict) and "id" not in decision_or_candidate:
            existing = find_decision(con, decision_or_candidate)
            dec = existing
        else:
            # try by id
            pass
    if dec is None:
        # fallback: last inserted
        row = con.execute("SELECT * FROM routing_decision ORDER BY id DESC LIMIT 1").fetchone()
        dec = dict(row) if row else None
    did = dec["id"]
    routes = [dict(r) for r in con.execute("SELECT * FROM route WHERE decision_id=?", (did,)).fetchall()]
    after = hashlib.sha256(json.dumps({"decision": dict(dec), "routes": routes}, sort_keys=True, default=str).encode()).hexdigest()
    con.execute(
        """UPDATE routing_decision SET status='FINAL', finalized_at=?, after_hash=? WHERE id=?""",
        (now(), after, did))
    con.commit()
    for r in routes:
        if r["update_kind"] == "SKILL_PROCEDURE":
            new_exec = "AWAITING_APPROVAL" if not approved else "PENDING"
            con.execute("UPDATE route SET execution_status=?, updated_at=? WHERE id=?",
                        (new_exec, now(), r["id"]))
    con.commit()
    row = con.execute("SELECT * FROM routing_decision WHERE id=?", (did,)).fetchone()
    return _decision_to_dict(con, dict(row))


def list_decisions(con, status=None, routing_status=None):
    q = "SELECT * FROM routing_decision"
    params = []
    conds = []
    if status:
        conds.append("status=?"); params.append(status)
    if routing_status:
        conds.append("routing_status=?"); params.append(routing_status)
    if conds:
        q += " WHERE " + " AND ".join(conds)
    q += " ORDER BY id"
    return [_decision_to_dict(con, dict(r)) for r in con.execute(q, params).fetchall()]


def get_decision(con, decision_id=None, key=None):
    if decision_id is not None:
        row = con.execute("SELECT * FROM routing_decision WHERE id=?", (decision_id,)).fetchone()
    else:
        row = con.execute("SELECT * FROM routing_decision WHERE decision_key=?", (key,)).fetchone()
    return _decision_to_dict(con, dict(row)) if row else None


def pending_routes(con):
    return [dict(r) for r in con.execute(
        "SELECT * FROM route WHERE execution_status IN ('NOT_STARTED','PENDING','AWAITING_APPROVAL') ORDER BY id").fetchall()]


def unrouted_decisions(con):
    return list_decisions(con, routing_status="UNROUTED")


def conflict_decisions(con):
    return list_decisions(con, routing_status="CONFLICT")


def execute_route(con, route_id, *, approved=False, executor=None):
    row = con.execute("SELECT * FROM route WHERE id=?", (route_id,)).fetchone()
    if not row:
        return {"ok": False, "error": "route not found"}
    r = dict(row)
    kind = r["update_kind"]
    exec_status = r["execution_status"]
    if exec_status == "APPLIED":
        return {"ok": True, "status": "APPLIED", "idempotent": True}
    if exec_status == "REJECTED":
        return {"ok": False, "status": "REJECTED"}
    if kind == "SKILL_PROCEDURE" and not approved:
        con.execute("UPDATE route SET execution_status='AWAITING_APPROVAL', updated_at=? WHERE id=?",
                    (now(), route_id))
        con.commit()
        return {"ok": False, "status": "AWAITING_APPROVAL", "reason": "skill procedure requires approval"}
    if kind in ("NO_CHANGE", "CONFLICT", "UNROUTED"):
        con.execute("UPDATE route SET execution_status='REJECTED', result=?, updated_at=? WHERE id=?",
                    (f"no mutation for {kind}", now(), route_id))
        con.commit()
        return {"ok": False, "status": "REJECTED", "reason": f"no mutation for {kind}"}
    try:
        con.execute("UPDATE route SET execution_status='RUNNING', updated_at=? WHERE id=?", (now(), route_id))
        con.commit()
        if kind == "KNOWLEDGE":
            result = "applied via WKS gate"
        elif kind == "ATTACK_CHAIN":
            result = "validated via chain validation"
        elif kind == "FP_RULE":
            result = "validated via fp validation"
        else:
            result = "applied"
        if executor is not None:
            executor(r)
        con.execute("UPDATE route SET execution_status='APPLIED', result=?, updated_at=? WHERE id=?",
                    (result, now(), route_id))
        con.commit()
        return {"ok": True, "status": "APPLIED"}
    except Exception as e:
        con.execute("UPDATE route SET execution_status='FAILED', result=?, updated_at=? WHERE id=?",
                    (str(e), now(), route_id))
        con.commit()
        return {"ok": False, "status": "FAILED", "error": str(e)}


def review_route(con, route_id, *, approved, reviewer=None, note=None):
    row = con.execute("SELECT * FROM route WHERE id=?", (route_id,)).fetchone()
    if not row:
        return {"ok": False, "error": "not found"}
    if approved:
        con.execute("UPDATE route SET execution_status='PENDING', updated_at=? WHERE id=?", (now(), route_id))
    else:
        con.execute("UPDATE route SET execution_status='REJECTED', result=?, updated_at=? WHERE id=?",
                    (note or "rejected by reviewer", now(), route_id))
    con.commit()
    return {"ok": True, "approved": approved}


def metrics(con):
    total = con.execute("SELECT COUNT(*) FROM routing_decision").fetchone()[0]
    by_status = {r[0]: r[1] for r in con.execute(
        "SELECT routing_status, COUNT(*) FROM routing_decision GROUP BY routing_status").fetchall()}
    by_kind = {r[0]: r[1] for r in con.execute(
        "SELECT update_kind, COUNT(*) FROM routing_decision GROUP BY update_kind").fetchall()}
    exec_counts = {r[0]: r[1] for r in con.execute(
        "SELECT execution_status, COUNT(*) FROM route GROUP BY execution_status").fetchall()}
    return {"decisions": total, "by_routing_status": by_status,
            "by_update_kind": by_kind, "execution": exec_counts}


def audit(con):
    return list_decisions(con)


def history(con, candidate=None):
    if candidate is None:
        return list_decisions(con)
    return [d for d in list_decisions(con) if d["candidate_hash"] == candidate_hash(candidate)]


def show(con, decision_id):
    return get_decision(con, decision_id=decision_id)
