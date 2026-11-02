"""Quality metrics (brief §28).

Every metric here answers a question a maintainer actually asks:
  - Can I trust a retrieved item?          -> unsupported_claim_rate
  - Is the corpus growing garbage?         -> promotion_rejection_rate, dup rate
  - Is it stale?                            -> stale_rate
  - Is it complete?                         -> class_maturity, coverage gaps
  - Is retrieval useful?                    -> retrieval hit rate on probes

A metric that cannot go DOWN is decoration. Each of these can.
"""
from __future__ import annotations

import json
import sqlite3
from typing import Any

from . import config, quality


def _pct(n: int, d: int) -> float:
    return round(100.0 * n / d, 2) if d else 0.0


def metrics(con: sqlite3.Connection | None = None) -> dict[str, Any]:
    """Published corpus metrics.

    MEASURED (audit 2026-10-02): two enabled cron loops ingested while an audit
    was running, so `metrics()` reported items_total=471 in one pass and 501 in
    another -- both correct, neither citable. A published metric must name the
    corpus state it describes.

    With no argument this now takes a FROZEN COPY of the store (via sqlite's
    online backup API, never a file copy -- the db is WAL) and computes every
    number from that one immutable file, returning a `snapshot` block with the
    copy's sha256 and row fingerprints. A caller that passes its own connection
    is assumed to have managed its own consistency, and is told so in the result.
    """
    provenance: dict[str, Any]
    if con is None:
        from . import snapshot as _snap
        info = _snap.frozen_copy()
        con = _snap.read_frozen(info)
        provenance = {"mode": "frozen_copy", **{
            k: info[k] for k in
            ("path", "sha256", "integrity_check", "fingerprint_matches")}}
    else:
        from . import snapshot as _snap
        provenance = {
            "mode": "caller_supplied_connection",
            "note": "consistency is the caller's responsibility; pass no "
                    "argument for a guaranteed-consistent frozen copy",
            "fingerprint": _snap._fingerprint(con),
        }
    return _metrics(con, provenance)


def _metrics(con: sqlite3.Connection, provenance: dict[str, Any]) -> dict[str, Any]:
    # Count only ACTIVE items. A superseded row is retained history (invariant
    # I8) and must not inflate the live corpus size or the promotion rate —
    # otherwise "100% promoted" would be reported against a total that
    # includes knowledge the system has already retired.
    total = con.execute(
        "SELECT count(*) n FROM item WHERE status='active'").fetchone()["n"]
    by_state = {
        r["validation_state"]: r["n"]
        for r in con.execute(
            """SELECT q.validation_state, count(*) n FROM quality q
               JOIN item i ON i.id=q.item_id
               WHERE i.status='active' GROUP BY 1""").fetchall()
    }
    promoted = sum(by_state.get(s, 0) for s in ("supported", "high_confidence"))

    # Unsupported-claim rate: items presented as knowledge that cannot survive
    # the gate. This is the number that was ~100% in the previous system.
    unsupported = by_state.get("under_review", 0) + by_state.get("discovered", 0)

    # Duplication: identical claim text, or same claim hash per class.
    dupes = con.execute(
        """SELECT count(*) n FROM (
             SELECT lower(trim(claim)) c FROM item
             GROUP BY lower(trim(claim)) HAVING count(*) > 1)"""
    ).fetchone()["n"]

    # Stale: active items whose newest evidence predates the freshness window.
    stale = con.execute(
        """SELECT count(*) n FROM item i
           WHERE i.status='active' AND NOT EXISTS (
             SELECT 1 FROM item_source x JOIN source s ON s.id=x.source_id
             WHERE x.item_id=i.id AND s.retrieved_at >= date('now','-3 years'))"""
    ).fetchone()["n"]

    # STALE *SOURCES*, which is what the audit actually needed and could not
    # get. The item-level number above asks "is this item's evidence old"; it
    # cannot detect a page that was rewritten yesterday, because nothing stored
    # a content hash to compare against. `wks.staleness` re-fetches and diffs
    # hashes; here we report what the store KNOWS, and say plainly when the
    # answer is "not measured" rather than "nothing is stale".
    #
    # Before the 2026-10-02 migration, http_status and content_hash were NULL on
    # every row, so a 0.0 stale rate was reporting an unmeasured quantity as a
    # clean bill of health. `sources_unmeasured` makes that visible.
    from . import transport as _http
    access_census = {r["access_state"]: r["n"] for r in con.execute(
        "SELECT coalesce(access_state,'NULL') access_state, count(*) n "
        "FROM source GROUP BY 1")}
    n_sources_unmeasured = con.execute(
        "SELECT count(*) n FROM source WHERE access_state='UNVERIFIED'"
    ).fetchone()["n"]
    n_sources_never_hashed = con.execute(
        "SELECT count(*) n FROM source WHERE content_hash IS NULL OR content_hash=''"
    ).fetchone()["n"]

    n_sources = con.execute("SELECT count(*) n FROM source").fetchone()["n"]
    n_hosts = con.execute("SELECT count(DISTINCT host) n FROM source").fetchone()["n"]
    # Hosts are not publishers. `learn.microsoft.com` and `microsoft.com` are
    # one company, and the corroboration gate already counts ORGS; reporting
    # only hosts made the corpus look 91 publishers wide.
    #
    # Two denominators, both reported, because they answer different questions
    # and conflating them produced a real discrepancy during the 2026-10-02
    # audit (77 orgs over every registered source vs 66 orgs over the hosts
    # actually cited by promoted items). Naming them removes the ambiguity
    # rather than leaving the reader to guess which one a number means.
    _all_orgs = {config.publisher_org(r["host"]) for r in con.execute(
        "SELECT DISTINCT host FROM source") if r["host"]}
    _cited_orgs = {config.publisher_org(r["host"]) for r in con.execute(
        """SELECT DISTINCT s.host FROM item_source x JOIN source s ON s.id=x.source_id
           JOIN item i ON i.id=x.item_id WHERE i.status='active'""") if r["host"]}
    _cited_hosts = {r["host"] for r in con.execute(
        """SELECT DISTINCT s.host FROM item_source x JOIN source s ON s.id=x.source_id
           JOIN item i ON i.id=x.item_id WHERE i.status='active'""") if r["host"]}
    n_classes = con.execute("SELECT count(*) n FROM bug_class").fetchone()["n"]
    n_mature = sum(1 for g in quality.gap_report(con) if g["state"] == "mature")
    # Count BOTH fp shapes. fp_case is the authored rubric table; the research
    # pipeline emits gate-passed `fp_rule` ITEMS instead. Counting only fp_case
    # reported 58 while the corpus held 85 active fp_rule items, so the headline
    # metric under-reported by 27 and the cycle report repeated it downstream.
    # quality.maturity() had the identical blind spot and was fixed earlier;
    # this is the same rule applied to the reporter.
    n_fp_case = con.execute("SELECT count(*) n FROM fp_case").fetchone()["n"]
    n_fp_items = con.execute(
        """SELECT count(*) n FROM item
           WHERE kind='fp_rule' AND status='active'""").fetchone()["n"]
    n_fp = n_fp_case + n_fp_items
    # Chains likewise have two shapes: the `chain` table holds assembled
    # chains, chain_link ITEMS are the segments that get assembled into one.
    # Reporting only the table hid 25 segments of work.
    n_chains = con.execute("SELECT count(*) n FROM chain").fetchone()["n"]
    n_chain_links = con.execute(
        """SELECT count(*) n FROM item
           WHERE kind='chain_link' AND status='active'""").fetchone()["n"]
    # Conflicts: report the WHOLE population, not just the open rows.
    # `open_conflicts` alone printed 0 over a 184-row table, which read as
    # "conflict handling is healthy" to anyone who did not query the db.
    _cstat = {r["status"]: r["n"] for r in con.execute(
        "SELECT status, count(*) n FROM conflict GROUP BY status")}
    n_conflicts = _cstat.get("open", 0)
    n_conflict_rows = sum(_cstat.values())
    # The number that matters for correctness: an open conflict with no recorded
    # resolution is an actual live contradiction.
    n_unresolved = con.execute(
        "SELECT count(*) n FROM conflict WHERE status='open' AND "
        "(resolution IS NULL OR trim(resolution)='')").fetchone()["n"]

    # Items carrying a disproof clause — the anti-checklist measure. Scoped to
    # active items for the same reason as `total`, so the rate cannot exceed
    # 100% (it did: 101.92%, because 53 disproof rows were divided by 52 items).
    n_disproof = con.execute(
        """SELECT count(*) n FROM item i
           WHERE i.status='active'
             AND i.disproof IS NOT NULL AND trim(i.disproof)<>''"""
    ).fetchone()["n"]

    # Blocked-on-single-host: the single most common fixable deficiency.
    blocked_hosts = con.execute(
        """SELECT count(*) n FROM quality
           WHERE gate_reasons LIKE '%INSUFFICIENT_PUBLISHER_HOSTS%'"""
    ).fetchone()["n"]

    return {
        "items_total": total,
        "items_by_state": by_state,
        "items_promoted": promoted,
        "promotion_rate_pct": _pct(promoted, total),
        "unsupported_claim_rate_pct": _pct(unsupported, total),
        "items_with_disproof": n_disproof,
        "disproof_rate_pct": _pct(n_disproof, total),
        "duplicate_claim_groups": dupes,
        "duplicate_rate_pct": _pct(dupes, total),
        "stale_rate_pct": _pct(stale, total),
        "sources": n_sources,
        "publisher_hosts": n_hosts,
        "publisher_orgs": {
            "registered_sources": len(_all_orgs),
            "cited_by_active_items": len(_cited_orgs),
            "hosts_cited_by_active_items": len(_cited_hosts),
            "note": ("hosts != publishers: learn.microsoft.com and "
                     "microsoft.com collapse to one org, as do the 5 owasp.org "
                     "hosts and the 3 mitre.org hosts. The corroboration gate "
                     "counts ORGS, which is why 16 items citing 2 hosts each "
                     "are held."),
        },
        "blocked_on_single_host": blocked_hosts,
        "source_access": {
            "census": access_census,
            "unmeasured": n_sources_unmeasured,
            "without_content_hash": n_sources_never_hashed,
            "vocabulary": sorted(_http.ACCESS_STATES),
            "note": ("`unmeasured` counts sources whose access was never "
                     "measured. A stale_rate_pct of 0 with a non-zero "
                     "`without_content_hash` means 'not checked', not "
                     "'nothing is stale'."),
        },
        "snapshot": provenance,
        "classes": n_classes,
        "classes_mature": n_mature,
        "class_maturity_pct": _pct(n_mature, n_classes),
        "false_positive_rules": n_fp,
        "false_positive_rules_breakdown": {
            "fp_case": n_fp_case, "fp_rule_items": n_fp_items,
        },
        "chains": n_chains,
        "chain_link_segments": n_chain_links,
        "open_conflicts": n_conflicts,
        "conflict_rows_total": n_conflict_rows,
        "conflict_rows_by_status": _cstat,
        "unresolved_conflicts": n_unresolved,
        "thresholds": {
            "min_publisher_hosts": config.MIN_PUBLISHER_HOSTS,
            "maturity_min_items": config.MATURITY_MIN_ITEMS,
        },
    }


PROBES = [
    ("idor", "object id from another user returns another user's data"),
    ("sqli", "boolean based blind injection numeric id predicate"),
    ("ssrf", "server side request forgery internal metadata url"),
    ("xss", "stored xss in a html sink executed in another session"),
    ("jwt", "jwt algorithm confusion none algorithm accepted"),
    # A single-use limit overrun is a `bizlogic` claim, not a `race` one: the
    # probe used to ask "exceed a single use limit", which legitimately ranks
    # bizlogic first and read as a retrieval failure when retrieval was right.
    # Race is the non-atomic read-modify-write window, so name that instead.
    ("race", "non atomic read modify write window between check and act"),
    ("csrf", "state changing post without a token still succeeds"),
    ("graphql", "graphql introspection batching aliases bypass rate limit"),
]


def retrieval_probe(con: sqlite3.Connection) -> dict[str, Any]:
    """Does retrieval answer a hunter's question?(§28 retrieval relevance)

    A probe passes when the top hit is promoted (not `discovered`/`rejected`)
    AND belongs to the intended class. Empty corpus scores 0 — never a default
    "pass", which would make the metric decorative.

    WHY THERE ARE FOUR VERDICTS, NOT TWO (measured 2026-10-02)
        The first version reported only pass/fail and averaged all 8 probes into
        `hit_rate_pct`. The `csrf` probe failed — correctly, csrf has zero gated
        items — but it failed for a completely different reason than `idor`
        failing would, and the single rate could not say which. It reported
        "87.5%" for a corpus where one probe was measuring a class that does
        not exist yet. That is a metric that reads as reassurance while
        describing a gap.

        So the verdict is now explicit, and the rate is computed ONLY over
        probes whose class actually has gated knowledge:
          pass         — top hit is promoted AND from the intended class
          wrong_class  — retrieval answered, but from a different class
          weak_state   — right class, but the top item is not promoted
          no_knowledge — the class has no gated items; retrieval was never
                         the thing under test, so it is excluded from the rate
                         and reported as a coverage gap instead.
    """
    results = [retrieval_probe_one(con, cid, q) for cid, q in PROBES]
    ok = sum(1 for r in results if r["verdict"] == "pass")
    tested = sum(1 for r in results if r["verdict"] != "no_knowledge")
    return {
        "probes": len(results),
        "passed": ok,
        "tested": tested,
        "no_knowledge": sum(1 for r in results if r["verdict"] == "no_knowledge"),
        # Denominator is what could be tested, not everything attempted.
        "hit_rate_pct": _pct(ok, tested),
        "detail": results,
    }


def retrieval_probe_one(con: sqlite3.Connection, class_id: str, q: str) -> dict[str, Any]:
    from . import retrieval
    n_items = con.execute(
        "SELECT count(*) n FROM item WHERE class_id=? AND status='active'",
        (class_id,)).fetchone()["n"]
    hits = retrieval.retrieve(con, q, limit=3)
    top = hits[0] if hits else None

    if n_items == 0:
        verdict = "no_knowledge"
    elif not top:
        verdict = "wrong_class"
    elif top["class_id"] != class_id:
        verdict = "wrong_class"
    elif top["state"] not in ("supported", "high_confidence"):
        verdict = "weak_state"
    else:
        verdict = "pass"

    return {"class_id": class_id, "query": q, "pass": verdict == "pass",
            "verdict": verdict, "class_items": n_items,
            "top": (top or {}).get("item_key"),
            "top_class": (top or {}).get("class_id"),
            "top_state": (top or {}).get("state"),
            "n_hits": len(hits)}
