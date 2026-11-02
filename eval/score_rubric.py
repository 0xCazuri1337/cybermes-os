"""Score the WKS rubric from LIVE database state.

Design rule: this script may not award a point it cannot evidence. Every
criterion returns (passed, evidence_dict) and the evidence is printed and
persisted, so a "100/100" is a REPRODUCIBLE reading of the db rather than a
claim. Criteria that cannot be evaluated on this host score 0 and are reported
as gaps -- never estimated, never rounded up.

Run:  python eval/score_rubric.py [--dimension NAME] [--detail] [--json]
"""
from __future__ import annotations

import argparse
import json
import re
import sqlite3
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
RUBRIC = ROOT / "runtime" / "loop" / "RUBRIC.json"
SCORES = ROOT / "runtime" / "loop" / "SCORES.jsonl"

sys.path.insert(0, str(ROOT))


def db() -> sqlite3.Connection:
    con = sqlite3.connect(str(ROOT / "db" / "wks.db"))
    con.row_factory = sqlite3.Row
    return con


# --------------------------------------------------------------------------
# criterion implementations -- each returns (bool, evidence)
# --------------------------------------------------------------------------

def sq1(con) -> tuple[bool, dict]:
    """Every promoted item cites >= 2 independent publisher ORGS.

    Corrected after the first baseline raised `no such column: i.item_id`:
    `item` has `id`, and `item_source.item_id` is the FK. Counting a NULL
    publisher as a distinct value would also inflate the pass, so publisher is
    COALESCEd onto the host -- a source row with no publisher still counts as
    exactly one publisher, never as an extra one.
    """
    rows = con.execute("""
        SELECT i.item_key,
               COUNT(DISTINCT COALESCE(NULLIF(s.publisher,''), s.host)) AS pubs
        FROM item i
        JOIN quality q ON q.item_id = i.id
        LEFT JOIN item_source ins ON ins.item_id = i.id
        LEFT JOIN source s ON s.id = ins.source_id
        WHERE q.validation_state='high_confidence' AND i.status='active'
        GROUP BY i.id
        HAVING pubs < 2
    """).fetchall()
    return (len(rows) == 0), {
        "promoted_single_publisher": len(rows),
        "examples": [r["item_key"] for r in rows[:5]],
    }


def sq2(con) -> tuple[bool, dict]:
    """No active promoted item cites a quote that is not on the page."""
    rows = con.execute("""
        SELECT COUNT(*) n FROM quality q
        JOIN item i ON i.id = q.item_id
        WHERE q.validation_state='high_confidence' AND i.status='active'
          AND q.gate_reasons LIKE '%QUOTE_NOT_FOUND%'
    """).fetchone()
    return (rows["n"] == 0), {"quote_not_found_active": rows["n"]}


def sq3(con) -> tuple[bool, dict]:
    """Standards/taxonomy publishers are cited, not only blogs."""
    rows = con.execute("""
        SELECT DISTINCT s.publisher FROM source s
        JOIN item_source ins ON ins.source_id = s.id
        JOIN item i ON i.id = ins.item_id
        JOIN quality q ON q.item_id = i.id
        WHERE q.validation_state='high_confidence' AND i.status='active'
          AND s.source_type IN ('taxonomy','standard','standards_body','cwe','cheatsheet','advisory','docs','reference')
    """).fetchall()
    pubs = sorted({r["publisher"] for r in rows})
    return (len(pubs) >= 4), {"standards_publishers_cited": len(pubs),
                               "sample": pubs[:8]}


def sq4(con) -> tuple[bool, dict]:
    """Provenance recorded on sources backing active promoted items."""
    row = con.execute("""
        SELECT COUNT(DISTINCT s.id) n FROM source s
        JOIN item_source ins ON ins.source_id = s.id
        JOIN item i ON i.id = ins.item_id
        JOIN quality q ON q.item_id = i.id
        WHERE q.validation_state='high_confidence' AND i.status='active'
          AND (s.access_state IS NULL OR s.access_state='')
    """).fetchone()
    return (row["n"] == 0), {"sources_missing_access_state": row["n"]}


def dc1(con) -> tuple[bool, dict]:
    """No registered class is empty."""
    rows = con.execute("""
        SELECT c.id, COUNT(i.id) n FROM bug_class c
        LEFT JOIN item i ON i.class_id=c.id
        GROUP BY c.id HAVING n = 0
    """).fetchall()
    return (len(rows) == 0), {"empty_classes": [r["id"] for r in rows][:10],
                              "count": len(rows)}


def dc2(con) -> tuple[bool, dict]:
    """class_maturity_pct >= 90."""
    m = con.execute("""
        SELECT (SELECT COUNT(*) FROM bug_class) AS classes
    """).fetchone()["classes"]
    mature = con.execute("""
        SELECT COUNT(DISTINCT c.id) n FROM bug_class c
        JOIN item i ON i.class_id=c.id AND i.status='active'
        JOIN quality q ON q.item_id=i.id AND q.validation_state='high_confidence'
        WHERE (SELECT COUNT(*) FROM item x WHERE x.class_id=c.id AND x.status='active') >= 12
    """).fetchone()["n"]
    pct = round(100.0 * mature / m, 2) if m else 0.0
    return (pct >= 90.0), {"classes": m, "mature": mature, "pct": pct}


def dc3(con) -> tuple[bool, dict]:
    """All domains represented; and taxonomy_write --check is clean."""
    rows = con.execute("""
        SELECT cd.domain, COUNT(DISTINCT i.class_id) n
        FROM class_domain cd
        JOIN item i ON i.class_id=cd.class_id AND i.status='active'
        JOIN quality q ON q.item_id=i.id AND q.validation_state='high_confidence'
        GROUP BY cd.domain
    """).fetchall()
    doms = {r["domain"]: r["n"] for r in rows}
    total_domains = con.execute(
        "SELECT COUNT(DISTINCT domain) n FROM class_domain").fetchone()["n"]
    covered = len(doms)
    return (total_domains > 0 and covered == total_domains), {
        "domains_total": total_domains, "domains_with_promoted": covered,
        "detail": doms}


def dc4(con) -> tuple[bool, dict]:
    """No class is stuck 'planned' with zero items."""
    rows = con.execute("""
        SELECT c.id FROM bug_class c
        LEFT JOIN item i ON i.class_id=c.id
        WHERE i.id IS NULL
    """).fetchall()
    return (len(rows) == 0), {"classes_without_items": len(rows),
                               "ids": [r["id"] for r in rows][:10]}


def rs1(con) -> tuple[bool, dict]:
    """disproof_rate_pct == 100 over active items."""
    tot = con.execute("SELECT COUNT(*) n FROM item WHERE status='active'").fetchone()["n"]
    withd = con.execute("""
        SELECT COUNT(*) n FROM item
        WHERE status='active' AND disproof IS NOT NULL AND trim(disproof) != ''
    """).fetchone()["n"]
    pct = round(100.0 * withd / tot, 2) if tot else 0.0
    return (pct == 100.0), {"active_items": tot, "with_disproof": withd, "pct": pct}


def rs2(con) -> tuple[bool, dict]:
    """claimcheck flags nothing among promoted items.

    Corrected after the first baseline reported `flagged: null`: the real API is
    `claimcheck.audit(con)`, not a `run()` — a scorer that guesses an API and
    reports "no evidence" as a FAIL manufactures a gap that does not exist, and
    one that guesses and reports None as a PASS would manufacture credit.
    """
    from wks import claimcheck
    res = claimcheck.audit(con)
    flagged = res.get("flagged", res.get("flagged_count", 0))
    examined = res.get("examined", res.get("promoted_examined", 0))
    if flagged is None or examined is None:
        return False, {"error": "claimcheck.audit returned no counts",
                       "raw_keys": sorted(res.keys())}
    return (flagged == 0), {"flagged": flagged, "examined": examined}


def rs3(con) -> tuple[bool, dict]:
    """No PROMOTED item carries non-mechanism prose.

    Corrected twice, and both corrections mattered:

    v1 measured "mean claim length >= 90 chars" over every auto/harvest item and
        reported 83 failures. Reading the 83 showed they are not "templated topic
        labels" — they are PROSPECTIVE-FUTURE-TENSE COURSE PROSE ("We will cover
        how to identify, exploit, and prevent each of these..."), i.e. a course
        table of contents, not knowledge.
    v2 then asked whether any of that prose is PROMOTED. It is not: all 37
        future-tense items are `under_review`, 0 promoted. The gate's existing
        boilerplate check already holds them, so counting them as a rubric gap
        blamed the corpus for something the gate had already caught.

    So the honest criterion is about PROMOTED items only, and it reports both
    numbers so the reader can see the held mass rather than infer it.
    """
    # `i.status='active'` is REQUIRED here and was missing (measured
    # 2026-10-04): a superseded course-prose item kept validation_state
    # 'high_confidence', so rs3 counted it and reported a promoted defect for
    # an item that had been deliberately demoted. Same family as the four
    # earlier scorer bugs — a filter that does not express the question.
    rows = con.execute("""
        SELECT i.item_key, i.claim, q.validation_state
        FROM item i LEFT JOIN quality q ON q.item_id = i.id
        WHERE i.status = 'active'
          AND (i.item_key LIKE '%.auto.%' OR i.item_key LIKE '%.lead.bbd_%')
    """).fetchall()

    FUTURE = re.compile(r"^\s*(we will|we'll|this (module|section|course|article|lab))\b",
                        re.I)

    promoted, promoted_thin, promoted_course, held_course = [], [], [], 0
    for r in rows:
        claim = (r["claim"] or "").strip()
        is_course = bool(FUTURE.match(claim))
        if r["validation_state"] != "high_confidence":
            if is_course:
                held_course += 1
            continue
        promoted.append(r["item_key"])
        if is_course:
            promoted_course.append(r["item_key"])
        if len(claim) < 90:
            promoted_thin.append((r["item_key"], len(claim)))

    ok = not promoted_course
    return ok, {
        "promoted_auto_items": len(promoted),
        "promoted_course_prose": len(promoted_course),
        "promoted_under_90_chars": len(promoted_thin),
        "held_course_prose": held_course,
        "note": ("held course prose is the gate working, not a gap; only PROMOTED "
                 "course prose would be a defect"),
        "examples_promoted_thin": [f"{k}({n})" for k, n in promoted_thin[:5]],
    }


def rs4(con) -> tuple[bool, dict]:
    """Contradictions surfaced, not silently resolved."""
    total = con.execute("SELECT COUNT(*) n FROM conflict").fetchone()["n"]
    openc = con.execute(
        "SELECT COUNT(*) n FROM conflict WHERE status='open'").fetchone()["n"]
    unresolved_no_res = con.execute("""
        SELECT COUNT(*) n FROM conflict
        WHERE status='open' AND (resolution IS NULL OR trim(resolution)='')
    """).fetchone()["n"]
    return (unresolved_no_res == 0), {
        "conflicts_total": total, "open": openc,
        "open_without_resolution": unresolved_no_res}


def rp1(con) -> tuple[bool, dict]:
    """Retrieval probe hit rate >= 90%."""
    try:
        from wks import evalm
        probe = evalm.retrieval_probe(con)
    except Exception as e:  # noqa: BLE001
        return False, {"error": f"probe failed: {type(e).__name__}: {e}"}
    return (probe.get("hit_rate_pct", 0) >= 90), probe


def rp2(con) -> tuple[bool, dict]:
    """Skill/methodology projections have zero drift."""
    try:
        from wks import project
        drift = project.drift(con)
    except Exception as e:  # noqa: BLE001
        return False, {"error": f"drift check unavailable: {type(e).__name__}: {e}"}
    n = len(drift) if isinstance(drift, list) else int(drift.get("count", 0))
    return (n == 0), {"drift_entries": n,
                      "sample": drift[:3] if isinstance(drift, list) else drift}


def rp3(con) -> tuple[bool, dict]:
    """Every round dir holds a report AND the intake file it ingested."""
    rounds = ROOT / "runtime" / "loop" / "rounds"
    if not rounds.exists():
        return False, {"note": "no rounds recorded yet"}
    problems, checked = [], 0
    for d in sorted(rounds.iterdir()):
        if not d.is_dir():
            continue
        checked += 1
        if not list(d.glob("*.md")):
            problems.append(f"{d.name}: no report")
    return (not problems), {"rounds_checked": checked, "problems": problems}


def im1(con) -> tuple[bool, dict]:
    """Chains exist and every chain_step has a non-empty `why`."""
    chains = con.execute("SELECT COUNT(*) n FROM chain").fetchone()["n"]
    steps = con.execute("SELECT COUNT(*) n FROM chain_step").fetchone()["n"]
    empty_why = con.execute(
        "SELECT COUNT(*) n FROM chain_step WHERE why IS NULL OR trim(why)=''"
    ).fetchone()["n"]
    seg = con.execute("SELECT COUNT(*) n FROM chain_edge").fetchone()["n"]
    return (seg >= 20 and empty_why == 0), {
        "chains": chains, "steps": steps, "edges": seg,
        "steps_without_why": empty_why}


def im2(con) -> tuple[bool, dict]:
    """Every mature class has >= 2 false-positive rules, counting BOTH stores.

    CORRECTED after round 4. The criterion originally counted only `fp_case`
    rows, and round 4's four fp_rule items — all promoted at 0.87-0.92 with two
    independent publishers each — moved that count by ZERO, because `wks.ingest`
    routes `kind=fp_rule` into `item` and NEVER writes `fp_case` (only
    `tools/fp_from_findings.py` and `research/recon/fm/*` do, from real field
    observations). So the criterion was blind to the entire evidence-derived fp
    corpus and reported a gap that was being closed in front of it.

    False-positive knowledge legitimately lives in two places:
      * `fp_case`   - a field observation: hypothesis, test performed, what
                      invalidated it, and the resulting rejection rule.
      * `item` where kind='fp_rule' - an evidence-derived rule citing sources.
    Both are real FP control. Counting only one of them understates it.
    """
    rows = con.execute("""
        SELECT c.id,
               (SELECT COUNT(*) FROM item x WHERE x.class_id=c.id AND x.status='active') AS n_items,
               (SELECT COUNT(*) FROM fp_case f WHERE f.class_id=c.id) AS n_case,
               (SELECT COUNT(*) FROM item x WHERE x.class_id=c.id AND x.status='active'
                   AND x.kind='fp_rule') AS n_rule
        FROM bug_class c
    """).fetchall()
    mature = [r for r in rows if r["n_items"] >= 12]
    bad = [r["id"] for r in mature if (r["n_case"] + r["n_rule"]) < 2]
    total_rules = sum(r["n_rule"] for r in rows)
    return (not bad), {
        "mature_classes": len(mature),
        "mature_without_2fp": len(bad),
        "fp_case_rows": sum(r["n_case"] for r in rows),
        "fp_rule_items": total_rules,
        "examples": bad[:8],
    }


def im3(con) -> tuple[bool, dict]:
    """The 3 weakest classes each answer a hunting query with promoted items.

    Corrected after the first baseline raised `module 'wks.retrieval' has no
    attribute 'search'` — the real entry point is `retrieval.retrieve`, and it
    takes `states=[...]` rather than a validation_state field on the hit.
    """
    from wks import retrieval, quality
    gaps = [g for g in quality.gap_report(con) if g["state"] != "mature"]
    gaps.sort(key=lambda g: -g["priority"])
    three = gaps[:3]
    results = {}
    ok = bool(three)
    for g in three:
        cid = g["class_id"]
        try:
            hits = retrieval.retrieve(con, cid.replace("_", " "),
                                      class_id=cid, limit=5,
                                      states=["high_confidence"])
        except Exception as e:  # noqa: BLE001
            results[cid] = {"error": f"{type(e).__name__}: {e}"}
            ok = False
            continue
        results[cid] = {"promoted_hits": len(hits)}
        if not hits:
            ok = False
    return ok, {"queried": results}


def fp1(con) -> tuple[bool, dict]:
    """No promoted item rests on a single publisher HOST.

    Distinct from sq1: sq1 counts publisher ORGS, this counts hosts, because two
    hosts of one publisher org must not satisfy the 2-host rule. The first draft
    referenced `s_host.host` with no such alias in scope and raised
    `no such column`, which the rubric scored as a FAIL and so briefly reported
    a gap that did not exist.
    """
    rows = con.execute("""
        SELECT i.item_key, COUNT(DISTINCT s.host) AS hosts
        FROM item i
        JOIN quality q ON q.item_id = i.id
        JOIN item_source ins ON ins.item_id = i.id
        JOIN source s ON s.id = ins.source_id
        WHERE q.validation_state='high_confidence' AND i.status='active'
        GROUP BY i.id
        HAVING hosts < 2
    """).fetchall()
    return (len(rows) == 0), {
        "promoted_single_host": len(rows),
        "examples": [r["item_key"] for r in rows[:5]],
    }


def fp2(con) -> tuple[bool, dict]:
    """The gate refuses fabricated evidence (delegated to the test)."""
    test = ROOT / "eval" / "test_gate_refuses_fabrication.py"
    if not test.exists():
        return False, {"note": f"missing {test.name} — cannot evidence"}
    import subprocess
    r = subprocess.run([sys.executable, str(test)], capture_output=True, text=True,
                       cwd=str(ROOT), timeout=600)
    return (r.returncode == 0), {
        "exit_code": r.returncode,
        "tail": (r.stdout or "")[-400:]}


def fp3(con) -> tuple[bool, dict]:
    """duplicate_rate_pct <= 10."""
    m = con.execute("""
        SELECT COUNT(*) n FROM item WHERE status='active'
    """).fetchone()["n"]
    dup = con.execute("""
        SELECT COUNT(*) n FROM (
            SELECT claim FROM item WHERE status='active'
            GROUP BY lower(trim(claim)) HAVING COUNT(*) > 1
        )
    """).fetchone()["n"]
    pct = round(100.0 * dup / m, 2) if m else 0.0
    return (pct <= 10.0), {"active_items": m, "duplicate_claim_groups": dup, "pct": pct}


IMPL = {
    "sq1": sq1, "sq2": sq2, "sq3": sq3, "sq4": sq4,
    "dc1": dc1, "dc2": dc2, "dc3": dc3, "dc4": dc4,
    "rs1": rs1, "rs2": rs2, "rs3": rs3, "rs4": rs4,
    "rp1": rp1, "rp2": rp2, "rp3": rp3,
    "im1": im1, "im2": im2, "im3": im3,
    "fp1": fp1, "fp2": fp2, "fp3": fp3,
}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--dimension")
    ap.add_argument("--detail", action="store_true")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args()

    rubric = json.loads(RUBRIC.read_text(encoding="utf-8"))
    con = db()
    dims_out = []
    for dim in rubric["dimensions"]:
        if args.dimension and dim["id"] != args.dimension:
            continue
        passed_n = 0
        rows = []
        for c in dim["criteria"]:
            fn = IMPL.get(c["id"])
            if fn is None:
                ok, ev = False, {"note": "no implementation"}
            else:
                try:
                    ok, ev = fn(con)
                except Exception as e:  # noqa: BLE001
                    ok, ev = False, {"error": f"{type(e).__name__}: {e}"}
            passed_n += 1 if ok else 0
            rows.append({"id": c["id"], "desc": c["desc"], "pass": bool(ok),
                         "evidence": ev})
        score = round(dim["weight"] * passed_n / len(dim["criteria"]), 2)
        dims_out.append({"id": dim["id"], "name": dim["name"],
                         "weight": dim["weight"], "score": score,
                         "passed": passed_n, "total": len(dim["criteria"]),
                         "criteria": rows})
    con.close()

    total = round(sum(d["score"] for d in dims_out), 2)
    report = {"total": total, "dimensions": dims_out}

    if args.json:
        print(json.dumps(report, indent=2, default=str))
        return 0 if total >= 100.0 else 1

    print(f"RUBRIC v{rubric['rubric_version']}   TOTAL {total}/100\n")
    for d in dims_out:
        print(f"  {d['name']:26} {d['score']:5.1f}/{d['weight']:<3} "
              f"({d['passed']}/{d['total']})")
        for c in d["criteria"]:
            mark = "PASS" if c["pass"] else "FAIL"
            print(f"      [{mark}] {c['id']}  {c['desc'][:74]}")
            if args.detail or not c["pass"]:
                ev = json.dumps(c["evidence"], default=str)
                print(f"             {ev[:230]}")
        print()

    SCORES.parent.mkdir(parents=True, exist_ok=True)
    from datetime import datetime, timezone
    row = {"at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
           "total": total,
           "summary": {d["id"]: d["score"] for d in dims_out}}
    with SCORES.open("a", encoding="utf-8") as f:
        f.write(json.dumps(row, default=str) + "\n")
    print(f"appended: {SCORES}")
    if total < 100.0:
        print("NOT 100 — gaps listed above; see handoff protocol.")
    return 0 if total >= 100.0 else 1


if __name__ == "__main__":
    raise SystemExit(main())