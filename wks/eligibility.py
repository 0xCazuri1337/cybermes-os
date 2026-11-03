"""Centralized eligibility policy for knowledge projection and retrieval.

Knowledge states in this corpus are only: high_confidence, supported,
under_review, rejected (the mission's 8-state list is not implemented;
see CONTROL/state.md). Eligibility turns a raw validation state into a
*use decision*: which items may back an authoritative answer, which are
reachable only as labelled investigation material, and which are
historical.

Modes
-----
AUTHORITATIVE (default)
    Only ``supported`` / ``high_confidence`` items with valid provenance
    (at least one linked source) and no open conflict on their class.
    Trust priors never bypass this: an ``under_review`` item with a high
    prior is still excluded.

INVESTIGATION
    Labelled: every state is accessible, but each result carries its
    validation state so a hunter can see what is unverified.

HISTORICAL
    Outdated-labelled: historical material is reachable and explicitly
    marked as outdated/legacy. Rejected material stays excluded.
"""
from __future__ import annotations

from enum import Enum
from typing import Any, Iterable

from . import store


class EligibilityMode(str, Enum):
    AUTHORITATIVE = "AUTHORITATIVE"
    INVESTIGATION = "INVESTIGATION"
    HISTORICAL = "HISTORICAL"


# Convenience aliases used by callers and tests.
Mode = EligibilityMode
AUTHORITATIVE = EligibilityMode.AUTHORITATIVE
INVESTIGATION = EligibilityMode.INVESTIGATION
HISTORICAL = EligibilityMode.HISTORICAL
ELIGIBILITY_MODES = (EligibilityMode.AUTHORITATIVE, EligibilityMode.INVESTIGATION,
                     EligibilityMode.HISTORICAL)


def normalize_mode(mode: Any) -> EligibilityMode:
    if isinstance(mode, EligibilityMode):
        return mode
    if mode is None:
        return EligibilityMode.AUTHORITATIVE
    text = str(mode).strip().upper()
    # Accept common aliases.
    aliases = {
        "AUTHORITATIVE": EligibilityMode.AUTHORITATIVE,
        "AUTHORITATIVE_ONLY": EligibilityMode.AUTHORITATIVE,
        "STRICT": EligibilityMode.AUTHORITATIVE,
        "INVESTIGATION": EligibilityMode.INVESTIGATION,
        "INVESTIGATIVE": EligibilityMode.INVESTIGATION,
        "ALL": EligibilityMode.INVESTIGATION,
        "LABELLED": EligibilityMode.INVESTIGATION,
        "HISTORICAL": EligibilityMode.HISTORICAL,
        "HISTORY": EligibilityMode.HISTORICAL,
        "OUTDATED": EligibilityMode.HISTORICAL,
    }
    if text in aliases:
        return aliases[text]
    try:
        return EligibilityMode(text)
    except ValueError:
        return EligibilityMode.AUTHORITATIVE


def _state_of(item: Any) -> str:
    if isinstance(item, dict):
        return str(item.get("state") or item.get("validation_state") or "").strip()
    try:
        return str(item["validation_state"] if "validation_state" in item.keys() else
                   item["state"]).strip()
    except Exception:
        return str(getattr(item, "state", "") or getattr(item, "validation_state", "")).strip()


def _class_of(item: Any) -> str | None:
    if isinstance(item, dict):
        return item.get("class_id")
    try:
        return item["class_id"]
    except Exception:
        return getattr(item, "class_id", None)


def _id_of(item: Any) -> int | None:
    if isinstance(item, dict):
        v = item.get("id") or item.get("item_id")
        return int(v) if v is not None else None
    try:
        v = item["id"] if "id" in item.keys() else item["item_id"]
        return int(v) if v is not None else None
    except Exception:
        v = getattr(item, "id", None) or getattr(item, "item_id", None)
        return int(v) if v is not None else None


def has_open_conflict(con: Any, item: Any = None, class_id: str | None = None) -> bool:
    """Whether ``item``/``class_id`` has an open conflict."""
    if class_id is None:
        class_id = _class_of(item)
    iid = _id_of(item) if item is not None else None
    if con is None:
        # Fall back to data carried on the item.
        if isinstance(item, dict):
            if item.get("open_conflicts"):
                return True
            if item.get("conflicts"):
                return len(item.get("conflicts") or []) > 0
        return False
    # item-level conflicts (conflict.item_a / item_b)
    if iid is not None:
        n = con.execute(
            "SELECT count(*) n FROM conflict WHERE status='open' "
            "AND (item_a=? OR item_b=?)", (iid, iid),
        ).fetchone()
        if int(n["n"] if hasattr(n, "keys") else n[0]) > 0:
            return True
    if class_id is not None:
        n = con.execute(
            "SELECT count(*) n FROM conflict WHERE status='open' AND class_id=?",
            (class_id,),
        ).fetchone()
        if int(n["n"] if hasattr(n, "keys") else n[0]) > 0:
            return True
    return False


def valid_provenance(con: Any, item: Any = None) -> bool:
    """An item has valid provenance if it links at least one source."""
    iid = _id_of(item)
    if con is not None and iid is not None:
        try:
            ev = store.item_evidence(con, iid)
            return bool(ev)
        except Exception:
            pass
    if isinstance(item, dict):
        srcs = item.get("sources")
        if srcs:
            return True
        if item.get("has_provenance") is True:
            return True
        if item.get("source_count", 0):
            return True
    return False


def is_eligible(item: Any, mode: Any = EligibilityMode.AUTHORITATIVE, *,
                con: Any = None, class_id: str | None = None,
                open_conflicts: bool | None = None) -> bool:
    mode = normalize_mode(mode)
    state = _state_of(item)
    if class_id is None:
        class_id = _class_of(item)

    if mode is EligibilityMode.INVESTIGATION:
        return True

    if mode is EligibilityMode.HISTORICAL:
        # Outdated material is reachable; rejected material is not.
        return state != "rejected"

    # AUTHORITATIVE
    if state not in ("supported", "high_confidence"):
        return False
    if open_conflicts is None:
        open_conflicts = has_open_conflict(con, item, class_id)
    if open_conflicts:
        return False
    if not valid_provenance(con, item):
        return False
    return True


# Aliases / alternate spellings used by callers and tests.
eligible = is_eligible
eligibility = is_eligible


def filter_items(items: Iterable[Any], mode: Any = EligibilityMode.AUTHORITATIVE,
                 *, con: Any = None, **kw: Any) -> list[Any]:
    return [it for it in items if is_eligible(it, mode, con=con, **kw)]


filter_eligible = filter_items
eligible_items = filter_items


def label(item: Any, mode: Any = EligibilityMode.AUTHORITATIVE) -> str:
    mode = normalize_mode(mode)
    state = _state_of(item)
    if mode is EligibilityMode.AUTHORITATIVE:
        return state
    if mode is EligibilityMode.INVESTIGATION:
        return f"labelled:{state}"
    if mode is EligibilityMode.HISTORICAL:
        if state == "outdated":
            return "outdated-labelled"
        return f"historical:{state}"
    return state


eligibility_label = label
label_for_mode = label


def evaluate(item: Any, mode: Any = EligibilityMode.AUTHORITATIVE, *,
             con: Any = None, class_id: str | None = None) -> dict[str, Any]:
    mode = normalize_mode(mode)
    reasons = []
    state = _state_of(item)
    if class_id is None:
        class_id = _class_of(item)
    oc = has_open_conflict(con, item, class_id)
    vp = valid_provenance(con, item)
    if mode is EligibilityMode.AUTHORITATIVE:
        if state not in ("supported", "high_confidence"):
            reasons.append(f"state {state!r} not authoritative")
        if oc:
            reasons.append("open conflict")
        if not vp:
            reasons.append("invalid provenance")
    elif mode is EligibilityMode.HISTORICAL:
        if state == "rejected":
            reasons.append("rejected")
    ok = is_eligible(item, mode, con=con, class_id=class_id, open_conflicts=oc)
    return {"eligible": ok, "mode": mode.value, "state": state,
            "open_conflict": oc, "valid_provenance": vp, "reasons": reasons,
            "label": label(item, mode)}


def trust_prior_cannot_bypass(item: Any, prior: float = 1.0) -> bool:
    """Trust prior is a ranking multiplier, never an eligibility override."""
    return is_eligible(item, EligibilityMode.AUTHORITATIVE)
