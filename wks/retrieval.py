"""Hybrid retrieval (brief §14).

Global lexical index (FTS5/BM25) + per-class logical namespaces + cross-class
relationship traversal + metadata filtering (state, recency, surface, kind).

Why no embeddings: none are available on this host, and more importantly a
single blind vector bucket is the wrong shape for hunting knowledge. Retrieval
here must be *inspectable* — a hunter needs to see which sources back a claim and
which claims are still unverified. BM25 plus explicit filters answers that;
cosine similarity over a mixed corpus of stubs and evidence does not.

Conflict surfacing (§14): when two high-confidence items in the same class
disagree on the same topic, retrieval returns the conflict rather than
silently picking one.
"""
from __future__ import annotations

import json
import re
import sqlite3
from typing import Any

from . import store


def _bm25(con: sqlite3.Connection, query: str, limit: int) -> list[sqlite3.Row]:
    """Lexical match with OR semantics, ranked by BM25.

    FTS5 defaults to AND across terms, which is wrong for this use case: a
    hunter types "how do I test boolean blind sqli for a numeric id" and gets
    NOTHING back because one term is absent from the claim — even though the
    claim is the best possible answer. OR with BM25 ranking degrades
    gracefully: more terms matched => better rank, and the caller sees the
    provenance and state of each hit before trusting it.

    Terms are quoted so a user typing `OR`, `*` or `"` cannot alter the query
    or raise; each is sanitised to word characters.
    """
    terms = [
        t for t in re.findall(r"[A-Za-z0-9_]{2,}", query or "")
    ]
    if not terms:
        return []
    match = " OR ".join(f'"{t}"' for t in terms)
    try:
        return con.execute(
            """SELECT i.*, bm25(item_fts) AS rank,
                      q.validation_state, q.score AS qscore,
                      q.gate_reasons
               FROM item_fts f
               JOIN item i  ON i.id = f.rowid
               JOIN quality q ON q.item_id = i.id
               WHERE item_fts MATCH ?
                 AND i.status='active'
               ORDER BY rank LIMIT ?""",
            (match, limit),
        ).fetchall()
    except sqlite3.OperationalError:
        return []


# Trust prior per validation state (§14: low-quality retrieved material must
# not silently override stronger knowledge). This is a multiplier applied to the
# relevance signal, not a filter, so an unverified item is still *reachable* when
# a hunter asks for it — it just cannot outrank evidenced knowledge.
_STATE_PRIOR = {
    "high_confidence": 1.00,
    "supported": 0.92,
    "under_review": 0.55,
    "discovered": 0.35,
    "unresolved": 0.30,
    "disputed": 0.25,
    "outdated": 0.20,
    "rejected": 0.05,
}


def _rank(hit: sqlite3.Row, rel: float) -> float:
    """Blend lexical relevance with evidence quality.

    Pure BM25 is actively wrong for this corpus: it rewards short, dense text,
    so a 60-character stub ("SQL injection is a code injection technique...")
    outranks a 400-character evidenced claim on the same subject. That is the
    retrieval-side twin of the promotion failure. Blending keeps relevance
    primary while letting evidence decide between comparable matches.
    """
    prior = _STATE_PRIOR.get(hit["validation_state"], 0.3)
    q = float(hit["qscore"] or 0.0)
    # rel is a positive BM25 distance (smaller = better); map to 0..1.
    return prior * (0.65 + 0.20 * rel + 0.15 * q)


def retrieve(
    con: sqlite3.Connection,
    query: str,
    *,
    class_id: str | None = None,
    surface: str | None = None,
    kind: str | None = None,
    states: list[str] | None = None,
    min_score: float = 0.0,
    limit: int = 8,
    expand: bool = True,
) -> list[dict[str, Any]]:
    """Retrieve by blended relevance, then filter, then expand relationships."""
    rows = _bm25(con, query, (limit * 6) if expand else limit)
    # SQLite's bm25() returns NEGATIVE scores where MORE NEGATIVE IS BETTER.
    # Taking abs() — or assuming positive-is-better — silently inverts the
    # ranking, which is how an unrelated class ended up above the right one
    # while the raw BM25 order was correct. Normalise the signed value instead.
    raw = [float(r["rank"]) for r in rows] or [0.0]
    worst, best = max(raw), min(raw)          # worst is the largest (closest to 0)
    span = (worst - best) or 1.0
    scored = sorted(
        [(_rank(r, (worst - float(r["rank"])) / span), r) for r in rows],
        key=lambda p: -p[0],
    )

    out: list[dict[str, Any]] = []
    for blend, r in scored:
        if class_id and r["class_id"] != class_id:
            continue
        if surface and (r["surface"] or "") != surface:
            continue
        if kind and r["kind"] != kind:
            continue
        if states and r["validation_state"] not in states:
            continue
        if min_score and float(r["qscore"] or 0) < min_score:
            continue
        ev = store.item_evidence(con, int(r["id"]))
        out.append({
            "item_key": r["item_key"],
            "class_id": r["class_id"],
            "claim": r["claim"],
            "kind": r["kind"],
            "surface": r["surface"],
            "severity_hint": r["severity_hint"],
            "hunting_value": r["hunting_value"],
            "body": r["body"],
            "disproof": r["disproof"],
            "state": r["validation_state"],
            "score": round(float(r["qscore"] or 0), 4),
            "relevance": round(blend, 4),
            "rank": round(float(r["rank"]), 4),
            "sources": [
                {"publisher": e["publisher"], "url": e["url"],
                 "host": e["host"], "authority": e["authority"],
                 "quote": e["quote"]}
                for e in ev
            ],
            "chains": _chains_for(con, int(r["id"])),
            "conflicts": _conflicts_for(con, int(r["id"])),
        })
        if len(out) >= limit:
            break
    return out


def _chains_for(con: sqlite3.Connection, item_id: int) -> list[dict[str, Any]]:
    rows = con.execute(
        """SELECT c.chain_key, c.name, c.goal, cs.ord, cs.action, cs.why
           FROM chain_step cs JOIN chain c ON c.id=cs.chain_id
           WHERE cs.item_id=? ORDER BY c.chain_key, cs.ord""",
        (item_id,),
    ).fetchall()
    by: dict[str, dict[str, Any]] = {}
    for r in rows:
        c = by.setdefault(r["chain_key"], {"chain_key": r["chain_key"],
                                           "name": r["name"], "goal": r["goal"],
                                           "steps": []})
        c["steps"].append({"ord": r["ord"], "action": r["action"], "why": r["why"]})
    return list(by.values())


def _conflicts_for(con: sqlite3.Connection, item_id: int) -> list[dict[str, Any]]:
    return [
        {"id": r["id"], "topic": r["topic"], "other_claim": r["claim_b"],
         "status": r["status"]}
        for r in con.execute(
            """SELECT c.* FROM conflict c
               WHERE (c.item_a=? OR c.item_b=?) AND c.status='open'""",
            (item_id, item_id),
        ).fetchall()
    ]


def related_classes(con: sqlite3.Connection, class_id: str, limit: int = 6) -> list[dict[str, Any]]:
    """Classes co-occurring in chains — the cross-class relationship view."""
    rows = con.execute(
        """SELECT cs2.class_id AS cid, b.name, b.surface, count(*) AS n
           FROM chain_step cs1
           JOIN chain_step cs2 ON cs2.chain_id=cs1.chain_id AND cs2.class_id<>cs1.class_id
           JOIN bug_class b ON b.id=cs2.class_id
           WHERE cs1.class_id=?
           GROUP BY cs2.class_id ORDER BY n DESC LIMIT ?""",
        (class_id, limit),
    ).fetchall()
    return [{"class_id": r["cid"], "name": r["name"],
             "surface": r["surface"], "chains": r["n"]} for r in rows]


def class_digest(con: sqlite3.Connection, class_id: str) -> dict[str, Any]:
    """Everything known about one class, in one call. Progressive disclosure."""
    cls = store.get_class(con, class_id)
    if cls is None:
        raise LookupError(class_id)
    by_kind: dict[str, list[dict[str, Any]]] = {}
    for r in con.execute(
        """SELECT i.*, q.validation_state, q.score FROM item i
           JOIN quality q ON q.item_id=i.id
           WHERE i.class_id=? AND i.status='active'
           ORDER BY q.score DESC, i.hunting_value DESC, i.item_key""",
        (class_id,),
    ).fetchall():
        by_kind.setdefault(r["kind"], []).append({
            "item_key": r["item_key"], "claim": r["claim"],
            "disproof": r["disproof"], "state": r["validation_state"],
            "score": round(float(r["score"] or 0), 4),
            "sources": [e["url"] for e in store.item_evidence(con, int(r["id"]))],
        })
    fps = [
        {"hypothesis": r["hypothesis"], "invalidated_by": r["invalidated_by"],
         "rejection_rule": r["rejection_rule"]}
        for r in con.execute(
            "SELECT * FROM fp_case WHERE class_id=?", (class_id,)
        ).fetchall()
    ]
    from .quality import maturity
    return {
        "class_id": class_id, "name": cls["name"], "surface": cls["surface"],
        "cwe": cls["cwe"], "owasp": cls["owasp"],
        "aliases": json.loads(cls["aliases"] or "[]"),
        "summary": cls["summary"],
        "maturity": maturity(con, class_id),
        "by_kind": by_kind,
        "false_positives": fps,
        "related_classes": related_classes(con, class_id),
    }


def open_conflicts(con: sqlite3.Connection) -> list[dict[str, Any]]:
    return [
        {"id": r["id"], "class_id": r["class_id"], "topic": r["topic"],
         "claim_a": r["claim_a"], "claim_b": r["claim_b"]}
        for r in con.execute("SELECT * FROM conflict WHERE status='open'").fetchall()
    ]


def rebuild_index(con: sqlite3.Connection) -> None:
    """FTS is derived state; regenerate from canonical tables (§13 ownership).

    With an external-content table, `INSERT INTO item_fts(item_fts) VALUES('rebuild')`
    re-reads the content table, so the triggers must be disabled for the
    duration or every row is indexed twice (which then doubles the hits). The
    'delete' command form is the documented way to do this safely.
    """
    con.execute("INSERT INTO item_fts(item_fts, rank) VALUES('delete', 1)")
    con.execute("INSERT INTO item_fts(item_fts) VALUES('rebuild')")
    con.commit()
