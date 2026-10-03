"""Per-class coverage, dimension by dimension.

The audit asked "which classes are missing depth or publisher diversity" and
the answer needed an ad-hoc script, because `wks.cli gaps` reports a flat
`missing` list and the reporter never said how much of each dimension was
present. A gap you cannot size is a gap you cannot prioritise.

Five dimensions, each with its own denominator:

    items          active items                       >= MATURITY_MIN_ITEMS
    supported       promoted items                     >= MATURITY_MIN_HIGH_CONF
    fp_rules        fp_case rows + promoted fp_rule items  >= MATURITY_MIN_FP_RULES
    chains          distinct chains carrying a step    >= MATURITY_MIN_CHAINS
    diversity       distinct PUBLISHER ORGS among the  >= MIN_PUBLISHER_HOSTS
                    class's cited sources             (hosts are not publishers)

plus `blocked`, which is the count of items held specifically for
INSUFFICIENT_PUBLISHER_HOSTS -- the dimension that was invisible before, and
the one the 16-item repair addressed.

`unreachable` is the honest verdict for a class whose NORMATIVE SEEDS cannot
satisfy the diversity gate: adding research will never promote its items. That
is a seed defect, not a research deficit, and the two need different fixes.
"""
from __future__ import annotations

import json
import sqlite3
from typing import Any

from . import config
from .sourcebook import worklist

DIMENSIONS = ("items", "supported", "fp_rules", "chains", "diversity")


def _class_hosts(con: sqlite3.Connection, class_id: str) -> set[str]:
    return {
        (r["host"] or "").lower() for r in con.execute(
            """SELECT DISTINCT s.host FROM item_source x
               JOIN source s ON s.id=x.source_id
               JOIN item i ON i.id=x.item_id WHERE i.class_id=?""", (class_id,))
    }


def _blocked(con: sqlite3.Connection, class_id: str) -> int:
    return con.execute(
        """SELECT count(*) n FROM quality q JOIN item i ON i.id=q.item_id
           WHERE i.class_id=? AND q.gate_reasons LIKE '%INSUFFICIENT_PUBLISHER_HOSTS%'""",
        (class_id,)).fetchone()["n"]


def _seed_reachable(class_id: str) -> dict[str, Any]:
    """Can this class EVER satisfy the publisher gate from its seeds alone?"""
    try:
        w = worklist(class_id, None)
    except Exception as e:
        return {"reachable": None, "reason": f"no seed routing: {e}"}
    return {
        "reachable": bool(w.get("corroboration_reachable")),
        "seed_orgs": w.get("seed_publisher_orgs", []),
        "warning": w.get("gate_warning") or None,
    }


def class_coverage(con: sqlite3.Connection, class_id: str) -> dict[str, Any]:
    from . import quality as Q
    m = Q.maturity(con, class_id)
    hosts = _class_hosts(con, class_id)
    orgs = sorted({config.publisher_org(h) for h in hosts if h})
    n_fp_case = con.execute(
        "SELECT count(*) n FROM fp_case WHERE class_id=?", (class_id,)).fetchone()["n"]
    n_fp_item = con.execute(
        """SELECT count(*) n FROM item i JOIN quality q ON q.item_id=i.id
           WHERE i.class_id=? AND i.status='active' AND i.kind='fp_rule'
             AND q.validation_state IN ('supported','high_confidence')""",
        (class_id,)).fetchone()["n"]
    n_chain = con.execute(
        """SELECT count(DISTINCT chain_id) n FROM chain_step WHERE class_id=?""",
        (class_id,)).fetchone()["n"]

    have = {
        "items": m["n_items"],
        "supported": m["n_supported"],
        "fp_rules": n_fp_case + n_fp_item,
        "chains": n_chain,
        "diversity": len(orgs),
    }
    need = {
        "items": config.MATURITY_MIN_ITEMS,
        "supported": config.MATURITY_MIN_HIGH_CONF,
        "fp_rules": config.MATURITY_MIN_FP_RULES,
        "chains": config.MATURITY_MIN_CHAINS,
        "diversity": config.MIN_PUBLISHER_HOSTS,
    }
    short = {d: (have[d], need[d]) for d in DIMENSIONS if have[d] < need[d]}
    seed = _seed_reachable(class_id)

    return {
        "class_id": class_id,
        "state": m["state"],
        "have": have, "need": need,
        "short": short,
        "missing": m["missing"],
        "blocked_single_publisher": _blocked(con, class_id),
        "hosts": sorted(hosts), "publisher_orgs": orgs,
        "seed_corroboration_reachable": seed["reachable"],
        "seed_publisher_orgs": seed.get("seed_orgs"),
        # A class whose seeds cannot corroborate is NOT a research task. Saying
        # so is the difference between sending a wave at a wall and fixing seeds.
        "actionable": bool(short) and seed["reachable"] is not False,
    }


def corpus_coverage(con: sqlite3.Connection) -> dict[str, Any]:
    rows = [class_coverage(con, r["id"]) for r in con.execute(
        "SELECT id FROM bug_class ORDER BY id")]
    by_dim = {d: sum(1 for r in rows if d in r["short"]) for d in DIMENSIONS}
    return {
        "classes": len(rows),
        "mature": sum(1 for r in rows if r["state"] == "mature"),
        "short_by_dimension": by_dim,
        "blocked_single_publisher_items": sum(
            r["blocked_single_publisher"] for r in rows),
        "classes_seed_unreachable": [
            {"class_id": r["class_id"], "seed_orgs": r["seed_publisher_orgs"]}
            for r in rows if r["seed_corroboration_reachable"] is False],
        "rows": rows,
    }


def main(argv: list[str] | None = None) -> int:
    import argparse
    ap = argparse.ArgumentParser(prog="wks.coverage")
    ap.add_argument("--class", dest="class_id")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--limit", type=int, default=0)
    a = ap.parse_args(argv)
    from . import store
    con = store.open_db(create=False)
    if a.class_id:
        out = class_coverage(con, a.class_id)
    else:
        out = corpus_coverage(con)
        if a.limit:
            rows = sorted(out.pop("rows"), key=lambda r: (
                not r["actionable"], -len(r["short"]), r["class_id"]))
            out["worst_first"] = rows[:a.limit]
    con.close()
    if a.json:
        print(json.dumps(out, indent=1, default=str))
        return 0
    if a.class_id:
        print(f"{a.class_id}: state={out['state']} orgs={out['publisher_orgs']}")
        print(f"  have={out['have']}")
        print(f"  need={out['need']}")
        print(f"  short={out['short']}")
        print(f"  seed reachable={out['seed_corroboration_reachable']}")
        return 0
    print(f"classes={out['classes']}  mature={out['mature']}")
    print(f"short by dimension: {out['short_by_dimension']}")
    print(f"items blocked on a single publisher: "
          f"{out['blocked_single_publisher_items']}")
    print(f"classes whose SEEDS can never corroborate: "
          f"{len(out['classes_seed_unreachable'])}")
    for r in out["classes_seed_unreachable"]:
        print(f"  {r['class_id']:28} seed orgs={r['seed_orgs']}")
    for r in out.get("worst_first", []):
        print(f"  {r['class_id']:26} short={sorted(r['short'])} "
              f"blocked={r['blocked_single_publisher']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())