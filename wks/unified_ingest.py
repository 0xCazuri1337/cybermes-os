"""Unified knowledge ingestion contract (Phase 3).

Single entry point for both research and learning pipelines. Validates the
candidate, optionally verifies quotes, sanitizes through pipeline.ingest_claim,
and returns the verdict plus origin.
"""
from __future__ import annotations

import sqlite3
from typing import Any

from . import pipeline, store
from . import verify_quotes as _VQ


_REQUIRED = ("item_key", "class_id", "claim", "kind", "sources")


def _candidate_value(candidate: Any, key: str, default=None):
    if isinstance(candidate, dict):
        return candidate.get(key, default)
    return getattr(candidate, key, default)


def ingest_candidate(
    con: sqlite3.Connection,
    candidate: Any,
    origin: str = "RESEARCH",
    verify: bool = True,
    verify_quotes: bool | None = None,
    **kwargs: Any,
) -> dict[str, Any]:
    if verify_quotes is not None:
        verify = bool(verify_quotes)
    # Allow origin/verify to be carried inside the candidate too.
    cand_origin = _candidate_value(candidate, "origin", None)
    if cand_origin is not None:
        origin = cand_origin
    if "verify" in (candidate if isinstance(candidate, dict) else {}):
        verify = bool(candidate.get("verify", verify))
    if "verify_quotes" in kwargs:
        verify = bool(kwargs.pop("verify_quotes"))

    # Validate required fields.
    for field in _REQUIRED:
        val = _candidate_value(candidate, field, None)
        if val is None or (isinstance(val, str) and not val.strip()) or (isinstance(val, (list, tuple)) and field == "sources" and len(val) == 0):
            raise ValueError(f"missing required field: {field}")
    # sources must be a list
    sources = list(_candidate_value(candidate, "sources"))
    if not isinstance(sources, list) or not sources:
        raise ValueError("missing required field: sources")

    item_key = _candidate_value(candidate, "item_key")
    class_id = _candidate_value(candidate, "class_id")
    claim = _candidate_value(candidate, "claim")
    kind = _candidate_value(candidate, "kind")

    # Optional quote verification.
    if verify:
        for s in sources:
            quote = s.get("quote") if isinstance(s, dict) else None
            url = s.get("url") if isinstance(s, dict) else None
            if quote and url:
                try:
                    page = pipeline.fetch(url, limit=1_500_000, quote=quote)
                except Exception:
                    page = {"access_state": "FETCH_FAILED", "text": ""}
                state = page.get("access_state", "UNVERIFIED")
                if state != "ACTIVE" or not _VQ.find_quote(page.get("text", ""), quote):
                    return {
                        "state": "rejected",
                        "score": 0.0,
                        "reasons": ["FABRICATED_QUOTE"],
                        "origin": origin,
                        "injection_findings": [],
                    }

    # Build ingest_claim kwargs from candidate (sanitization happens inside).
    ingest_kwargs = dict(
        item_key=item_key,
        class_id=class_id,
        claim=claim,
        kind=kind,
        sources=sources,
        body=_candidate_value(candidate, "body", None),
        disproof=_candidate_value(candidate, "disproof", None),
        surface=_candidate_value(candidate, "surface", None),
        severity_hint=_candidate_value(candidate, "severity_hint", None),
        hunting_value=_candidate_value(candidate, "hunting_value", 3),
        origin=origin,
    )

    verdict = pipeline.ingest_claim(con, **ingest_kwargs)
    verdict = dict(verdict)
    verdict["origin"] = origin
    return verdict
