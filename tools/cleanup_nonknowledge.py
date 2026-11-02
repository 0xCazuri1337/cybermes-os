#!/usr/bin/env python3
"""Retire non-knowledge rows and collapse byte-identical claims.

The corpus is not a scraped page archive. Three kinds of row are not knowledge
even when their citations are real:

  * MODULE_FILLER -- course prose ("This module covers ...", "We will ...")
    copied from a table of contents. It teaches nothing a hunter can test.
  * TEMPLATE_CLAIM -- generated CVE sentences that assert the same route
    regardless of what the cited record says. The gate already holds them;
    keeping them in the active corpus still counts them as coverage.
  * exact duplicate claims -- one sentence filed in several classes, often by
    a scraper. It double-counts the corpus and makes a class look mature when
    it has one fact wearing several labels.

These rows are NOT deleted. `status` becomes `superseded`, the row and all of
its source links remain, and duplicates get `dedup_of`/`canonical_id` pointing
at the surviving row. A JSON report records every action so the editorial
decision is auditable. Run without `--apply` first.

    python3 tools/cleanup_nonknowledge.py            # report only
    python3 tools/cleanup_nonknowledge.py --apply    # write statuses
"""
from __future__ import annotations

import argparse
import collections
import json
import re
import sqlite3
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from wks import relevance, store  # noqa: E402

DEFAULT_OUT = ROOT / "learning" / "gaps" / "nonknowledge-cleanup.json"
_STATE_RANK = {"high_confidence": 4, "supported": 3, "under_review": 2,
               "discovered": 1}
_REL_RANK = {relevance.ON_TOPIC: 5, relevance.SIBLING: 4,
             relevance.AMBIGUOUS: 3, relevance.ORPHAN: 2,
             relevance.MISFILED: 1, relevance.MODULE_FILLER: 0}


def _norm_claim(s: str) -> str:
    return re.sub(r"\s+", " ", (s or "").strip().lower())


def _reasons(raw: str | None) -> list[str]:
    try:
        return list(json.loads(raw or "[]"))
    except json.JSONDecodeError:
        return []


def _reason_tag(raw: str | None, tag: str) -> bool:
    return any(r.startswith(tag) for r in _reasons(raw))


def _source_counts(con: sqlite3.Connection, item_id: int) -> tuple[int, int]:
    row = con.execute(
        "select count(*) n, count(distinct host) h from item_source "
        "join source on source.id=item_source.source_id where item_id=?",
        (item_id,)).fetchone()
    return int(row["n"] or 0), int(row["h"] or 0)


def load_review_manifest(path: str | Path | None) -> dict[str, str]:
    """Load a curator-reviewed retirement list: item_key -> short reason.

    The automatic rules are deliberately narrow. This manifest is the escape
    hatch for rows a human has read and classified as non-knowledge (course
    narration, article meta-commentary, scraped page-builder output). Keeping
    the reason in the report makes the editorial decision auditable.
    """
    if not path:
        return {}
    raw = json.loads(Path(path).read_text(encoding="utf-8"))
    entries = raw.get("items", raw) if isinstance(raw, dict) else raw
    out: dict[str, str] = {}
    for entry in entries:
        if isinstance(entry, str):
            out[entry] = "reviewed_nonknowledge"
            continue
        key = entry.get("item_key")
        if not key:
            continue
        out[key] = str(entry.get("reason") or "reviewed_nonknowledge")
    return out


def build_plan(con: sqlite3.Connection, retire_template: bool = False,
               review_manifest: dict[str, str] | None = None) -> list[dict]:
    rows = con.execute(
        """select i.id, i.item_key, i.class_id, i.kind, i.claim, i.body,
                  i.created_at, q.validation_state, q.gate_reasons
           from item i join quality q on q.item_id=i.id
           where i.status='active' and i.dedup_of is null
           order by i.id""").fetchall()
    plan: list[dict] = []
    reviewed = review_manifest or {}

    # A row with dedup_of set is a duplicate pointer, not live knowledge. Older
    # waves sometimes left such rows active, which inflated both coverage and
    # maturity. Supersede them here so the invariant "active => not a duplicate"
    # is repaired by the same auditable tool that records dedup pointers.
    for r in con.execute(
        """select i.id, i.item_key, i.class_id, i.kind, i.claim, i.body,
                  i.created_at, q.validation_state, q.gate_reasons,
                  i.dedup_of, i.canonical_id
           from item i join quality q on q.item_id=i.id
           where i.status='active' and i.dedup_of is not null
           order by i.id""").fetchall():
        plan.append({
            "action": "retire",
            "reason": "duplicate:dedup_pointer",
            "item_id": r["id"], "item_key": r["item_key"],
            "class_id": r["class_id"], "claim": r["claim"],
            "validation_state": r["validation_state"],
            "gate_reasons": _reasons(r["gate_reasons"]),
            "dedup_of": r["dedup_of"], "canonical_id": r["canonical_id"],
        })

    # A page builder's JSON payload is not a claim and not a body. MEASURED:
    # three Detectify rows stored `"add_second_content_block":false,...` as the
    # body and then cited the sentence fragment embedded in it. The fragment
    # may be true, but the row is an acquisition artifact, not knowledge.
    scraped_markers = ("add_second_content_block", "add_testimonial",
                       "add_browser_bar_styling", "image_alignment",
                       '"review":{"stars"',
                       "Hostile subdomain takeover is a term coined by Detectify")

    # 1. Non-knowledge rows. The gate's own measured tags decide, not a new
    #    semantic guess. A filler or template row is retired even when one of
    #    its citations is genuine: the citation supports the page, not the
    #    sentence shape built from it.
    for r in rows:
        if r["item_key"] in reviewed:
            plan.append({
                "action": "retire",
                "reason": f"nonknowledge:reviewed:{reviewed[r['item_key']]}",
                "item_id": r["id"], "item_key": r["item_key"],
                "class_id": r["class_id"], "claim": r["claim"],
                "validation_state": r["validation_state"],
                "gate_reasons": _reasons(r["gate_reasons"]),
            })
            continue
        tag = None
        body = r["body"] or ""
        if any(marker in body for marker in scraped_markers):
            tag = "scraped_fragment"
        elif _reason_tag(r["gate_reasons"], "MODULE_FILLER"):
            tag = "module_filler"
        elif _reason_tag(r["gate_reasons"], "LEAD_ONLY"):
            tag = "lead_only"
        elif _reason_tag(r["gate_reasons"], "TEMPLATE_CLAIM"):
            tag = "template_claim"
        if tag == "template_claim" and not retire_template:
            # The gate deliberately holds template claims for a factual
            # rewrite; retiring them by default would erase the review queue.
            # Report them, but keep them active unless the curator opts in.
            plan.append({
                "action": "hold",
                "reason": "nonknowledge:template_claim",
                "item_id": r["id"], "item_key": r["item_key"],
                "class_id": r["class_id"], "claim": r["claim"],
                "validation_state": r["validation_state"],
                "gate_reasons": _reasons(r["gate_reasons"]),
            })
            continue
        if tag:
            plan.append({
                "action": "retire",
                "reason": f"nonknowledge:{tag}",
                "item_id": r["id"], "item_key": r["item_key"],
                "class_id": r["class_id"], "claim": r["claim"],
                "validation_state": r["validation_state"],
                "gate_reasons": _reasons(r["gate_reasons"]),
            })

    bad_ids = {p["item_id"] for p in plan if p["action"] == "retire"}

    # 2. Exact claim duplicates among the remaining rows. Pick the canonical
    #    row by relevance first, then promotion state, then independent-source
    #    breadth. This keeps an on-topic held row over a misfiled promoted one.
    groups: dict[str, list[sqlite3.Row]] = collections.defaultdict(list)
    for r in rows:
        if r["id"] not in bad_ids:
            groups[_norm_claim(r["claim"])].append(r)

    for _, items in groups.items():
        if len(items) < 2:
            continue
        scored = []
        for r in items:
            verdict = relevance.assess(r["class_id"], r["claim"])
            rel_state = verdict.state if verdict else "UNPROBEABLE"
            nsrc, nhost = _source_counts(con, r["id"])
            scored.append((( _REL_RANK.get(rel_state, 2),
                            _STATE_RANK.get(r["validation_state"], 0),
                            nhost, nsrc, -r["id"]), r, rel_state))
        scored.sort(key=lambda x: x[0], reverse=True)
        canonical = scored[0][1]
        for _, r, rel_state in scored[1:]:
            plan.append({
                "action": "dedup",
                "reason": "exact_duplicate_claim",
                "item_id": r["id"], "item_key": r["item_key"],
                "class_id": r["class_id"], "claim": r["claim"],
                "validation_state": r["validation_state"],
                "gate_reasons": _reasons(r["gate_reasons"]),
                "canonical_id": canonical["id"],
                "canonical_key": canonical["item_key"],
                "canonical_class": canonical["class_id"],
                "canonical_state": canonical["validation_state"],
                "relevance_state": rel_state,
            })
    return plan


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="cleanup_nonknowledge.py")
    ap.add_argument("--apply", action="store_true",
                    help="write statuses (default: report only)")
    ap.add_argument("--out", default=str(DEFAULT_OUT))
    ap.add_argument("--retire-template", action="store_true",
                    help="also retire TEMPLATE_CLAIM rows (default: hold them)")
    ap.add_argument("--review-manifest",
                    help="JSON list of item_key/reason rows a curator has "
                         "classified as non-knowledge")
    args = ap.parse_args(argv)

    con = store.open_db()
    review_manifest = load_review_manifest(args.review_manifest)
    plan = build_plan(con, retire_template=args.retire_template,
                      review_manifest=review_manifest)
    by_action = collections.Counter(p["action"] for p in plan)
    by_reason = collections.Counter(p["reason"] for p in plan)
    by_state = collections.Counter(p["validation_state"] for p in plan)
    by_class = collections.Counter(p["class_id"] for p in plan)

    print(f"planned rows: {len(plan)}")
    print("  actions:", dict(by_action))
    print("  reasons:", dict(by_reason))
    print("  prior states:", dict(by_state))
    print("  top classes:")
    for cid, n in by_class.most_common(15):
        print(f"    {n:3} {cid}")
    for p in plan[:12]:
        print(f"  {p['action']:7} {p['item_key'][:58]:58} {p['reason']}")
        if p["action"] == "dedup":
            print(f"          -> {p['canonical_key']} ({p['canonical_state']})")
    if len(plan) > 12:
        print(f"  ... {len(plan) - 12} more")

    planned_mutations = sum(1 for p in plan
                            if p["action"] in ("retire", "dedup"))
    report = {
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "db": str(store.config.db_path()),
        "applied": bool(args.apply),
        "summary": {
            "rows": len(plan),
            "actions": dict(by_action),
            "reasons": dict(by_reason),
            "prior_states": dict(by_state),
            "classes": dict(by_class),
            "planned_mutations": planned_mutations,
            "held_rows": by_action.get("hold", 0),
            "reviewed_manifest": len(review_manifest),
            "reviewed_found": sum(
                1 for p in plan
                if p["reason"].startswith("nonknowledge:reviewed:")),
        },
        "rows": plan,
    }
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(report, indent=1), encoding="utf-8")
    print(f"wrote {out}")

    if not args.apply:
        print("report only; re-run with --apply to write")
        return 0

    now = store.now()
    applied = 0
    with con:
        for p in plan:
            if p["action"] != "retire" and p["action"] != "dedup":
                continue
            if p["action"] == "retire":
                con.execute(
                    "update item set status='superseded', updated_at=? where id=?",
                    (now, p["item_id"]))
            else:
                con.execute(
                    "update item set status='superseded', dedup_of=?, "
                    "canonical_id=?, updated_at=? where id=?",
                    (p["canonical_id"], p["canonical_id"], now, p["item_id"]))
            applied += 1
    print(f"applied {applied} of {len(plan)} planned rows "
          f"({by_action.get('hold', 0)} held)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
