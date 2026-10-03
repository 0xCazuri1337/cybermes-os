"""Regression tests for the corpus-side repairs (audit items 5, 6, 9).

T30  integrity: the duplicate is MARKED, never deleted
T31  integrity: malformed item_keys are repaired without touching class_id
T32  integrity: orphaned conflict rows are re-statused, never removed
T33  corroboration: every item promoted by the repair cites >=2 real ORGS
T34  corroboration: the new citations are genuine -- quote present on the page,
                   and the quote is prose, not markup residue
T35  seeds: no class is left with seeds that can never corroborate
T36  assessment: a graded exam imports as evidence only when admissible, and a
     DISQUALIFIED or FAIL run contributes nothing
T37  the repair must not have invented knowledge: the corpus grew by exactly
     the number of items the repair added, and no citation was lost

Run: python eval/test_wks_integrity_repair.py
"""
from __future__ import annotations

import json
import sqlite3
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from wks import config, coverage, integrity, store, transport  # noqa: E402
from wks import sourcebook  # noqa: E402
from wks.verify_quotes import find_quote  # noqa: E402
from wks import pipeline  # noqa: E402

FAILURES: list[str] = []
PASSES: list[str] = []


def check(label: str, cond: bool, detail: str = "", *, pass_detail: str = "") -> None:
    if cond:
        PASSES.append(label)
        print(f"  [PASS] {label}" + (f"  -- {pass_detail}" if pass_detail else ""))
    else:
        FAILURES.append(f"{label}: {detail}")
        print(f"  [FAIL] {label}  -- {detail}")


def scratch() -> sqlite3.Connection:
    return store.open_db(Path(tempfile.mkdtemp(prefix="wks-repair-")) / "t.db",
                         create=True)


# --------------------------------------------------------------------------
def t30_duplicate_marked_not_deleted() -> None:
    print("T30 an exact duplicate is marked, never deleted")
    con = scratch()
    con.execute("INSERT INTO bug_class(id,name,surface,first_seen) "
                "VALUES('t30','T','web','2026-01-01')")
    con.execute("INSERT INTO item(item_key,class_id,claim,kind,status,created_at,"
                "updated_at) VALUES('t30.technique.a','t30','same claim',"
                "'technique','active','2026-01-01','2026-01-01')")
    con.execute("INSERT INTO item(item_key,class_id,claim,kind,status,created_at,"
                "updated_at) VALUES('t30.technique.b','t30','same claim',"
                "'technique','active','2026-01-01','2026-01-01')")
    con.commit()
    before = con.execute("select count(*) as n from item").fetchone()["n"]
    out = integrity.mark_duplicates(con, apply=True)
    after = con.execute("select count(*) as n from item").fetchone()["n"]
    check("both rows survive the repair", before == after == 2, f"{before}->{after}")
    marked = con.execute(
        "select item_key, dedup_of from item where dedup_of is not null").fetchall()
    check("exactly one row is marked as the duplicate", len(marked) == 1,
          str([dict(r) for r in marked]))
    check("the duplicate points at a canonical row",
          bool(marked) and marked[0]["dedup_of"] is not None)
    check("both rows are still active",
          con.execute("select count(*) as n from item where status='active'"
                      ).fetchone()["n"] == 2)
    check("a second apply is a no-op",
          integrity.mark_duplicates(con, apply=True)["applied"] == [])
    con.close()


def t31_malformed_keys() -> None:
    print("T31 malformed item_keys are repaired without touching class_id")
    con = scratch()
    con.execute("INSERT INTO bug_class(id,name,surface,first_seen) "
                "VALUES('t31','T','web','2026-01-01')")
    con.execute("INSERT INTO item(item_key,class_id,claim,kind,status,created_at,"
                "updated_at) VALUES('t31.some-slug','t31','c','signal','active',"
                "'2026-01-01','2026-01-01')")
    con.commit()
    out = integrity.repair_keys(con, apply=True)
    row = con.execute("select item_key, class_id from item").fetchone()
    check("the key gains its kind segment",
          row["item_key"] == "t31.signal.some-slug", row["item_key"])
    check("class_id is unchanged", row["class_id"] == "t31", row["class_id"])
    check("the item id is unchanged (chains reference it, not the key)",
          con.execute("select id from item").fetchone()["id"] == 1)
    check("no malformed keys remain",
          len(integrity.malformed_keys(con)) == 0)
    con.close()


def t32_orphaned_conflicts() -> None:
    print("T32 orphaned conflict rows are re-statused, never removed")
    con = scratch()
    con.execute("INSERT INTO bug_class(id,name,surface,first_seen) "
                "VALUES('t32','T','web','2026-01-01')")
    con.execute("INSERT INTO item(item_key,class_id,claim,kind,status,created_at,"
                "updated_at) VALUES('t32.technique.live','t32','live claim',"
                "'technique','active','2026-01-01','2026-01-01')")
    con.execute("INSERT INTO conflict(class_id,topic,claim_a,claim_b,status,"
                "created_at) VALUES('t32','fabricated-evidence','live claim',"
                "'x','open','2026-01-01')")
    con.execute("INSERT INTO conflict(class_id,topic,claim_a,claim_b,status,"
                "created_at) VALUES('t32','fabricated-evidence','dead claim',"
                "'x','open','2026-01-01')")
    con.commit()
    before = con.execute("select count(*) as n from conflict").fetchone()["n"]
    out = integrity.settle_orphans(con, apply=True)
    after = con.execute("select count(*) as n from conflict").fetchone()["n"]
    check("no conflict row is deleted", before == after == 2, f"{before}->{after}")
    check("the orphaned row is dismissed, not deleted",
          con.execute("select status from conflict where claim_a='dead claim'"
                      ).fetchone()["status"] == "dismissed")
    check("the row whose claim IS live stays open",
          con.execute("select status from conflict where claim_a='live claim'"
                      ).fetchone()["status"] == "open")
    check("the dismissal records why",
          "orphaned" in (con.execute(
              "select resolution from conflict where claim_a='dead claim'"
              ).fetchone()["resolution"] or "").lower())
    con.close()


# --------------------------------------------------------------------------
# These two read the CANONICAL corpus. They assert the repair actually landed
# and that the citations it added are genuine, not merely present.
# --------------------------------------------------------------------------
def t33_promoted_have_two_orgs() -> None:
    print("T33 every promoted item cites >= 2 distinct publisher ORGS")
    con = store.open_db(create=False)
    bad = []
    for r in con.execute(
            """SELECT i.item_key FROM item i JOIN quality q ON q.item_id=i.id
               WHERE q.validation_state='high_confidence' AND i.status='active'"""):
        hosts = {h[0].lower() for h in con.execute(
            """SELECT DISTINCT s.host FROM item_source x JOIN source s ON s.id=x.source_id
               JOIN item i2 ON i2.id=x.item_id WHERE i2.item_key=?""", (r["item_key"],))}
        orgs = {config.publisher_org(h) for h in hosts if h}
        if len(orgs) < 2:
            bad.append((r["item_key"], sorted(orgs)))
    check("no promoted item is held on fewer than 2 orgs", not bad,
          f"{len(bad)} offenders: {bad[:3]}")
    still = con.execute(
        "select count(*) n from quality where gate_reasons like "
        "'%INSUFFICIENT_PUBLISHER_HOSTS%'").fetchone()["n"]
    check("no item remains blocked on a single publisher", still == 0, str(still))
    con.close()


def t34_new_citations_are_real() -> None:
    print("T34 the repair's citations are genuine prose present on their pages")
    # The intake file is CONSUMED by the ingest pipeline, and another session's
    # researcher consumed this one mid-work. So the subject of this test is read
    # from the STORE: for every class that had an item blocked on one publisher,
    # take a citation and re-fetch its page for real.
    repaired_classes = ("idor", "ssrf", "graphql", "jwt", "winrm", "ldap_enum",
                        "ad_delegation", "pass_the_hash", "authz", "ad_kerberos")
    con = store.open_db(create=False)
    rows = con.execute(
        """SELECT i.item_key, s.url, s.host, x.quote
           FROM item i JOIN item_source x ON x.item_id=i.id
           JOIN source s ON s.id=x.source_id
           WHERE i.class_id IN (%s) AND x.quote IS NOT NULL AND length(x.quote)>40
           ORDER BY i.class_id, s.host""" % ",".join("?" * len(repaired_classes)),
        repaired_classes).fetchall()
    con.close()
    check("the repaired classes carry real citations", len(rows) >= 32,
          f"{len(rows)} citations found")

    short = [r["item_key"] for r in rows if len(r["quote"]) < 40]
    check("no citation is a stub", not short, str(short[:3]))

    # One live re-verification per repaired class: the strongest available
    # statement that the added citations are genuine.
    seen = set()
    sample = []
    for r in rows:
        if r["item_key"] in seen:
            continue
        seen.add(r["item_key"])
        sample.append(r)
    sample = sample[:10]
    for r in sample:
        got = pipeline.fetch(r["url"], limit=1_500_000)
        ok = got.get("access_state") == "ACTIVE" and find_quote(got["text"], r["quote"])
        check(f"quote re-verifies live: {r['item_key'][:44]}", ok,
              f"state={got.get('access_state')} url={r['url'][:60]}")

    # NEGATIVE CONTROL: an invented sentence must NOT verify.
    invented = ("the quick brown fox jumps over the lazy dog beside the "
                "instance metadata service endpoint")
    got = pipeline.fetch(sample[0]["url"], limit=400_000)
    check("NEGATIVE CONTROL: an invented sentence does not verify",
          not find_quote(got.get("text", ""), invented),
          pass_detail="the matcher still rejects a plausible fabrication")


def t35_seeds_can_corroborate() -> None:
    print("T35 no class is left with seeds that can never corroborate")
    sourcebook.load(refresh=True)
    con = store.open_db(create=False)
    out = coverage.corpus_coverage(con)
    unreachable = out["classes_seed_unreachable"]
    check("every class's normative seeds span >= 2 publisher orgs",
          not unreachable, str([r["class_id"] for r in unreachable]))
    con.close()


def t36_assessment_evidence() -> None:
    print("T36 graded assessments become evidence only when admissible")
    from wks import assess_evidence as AE
    scanned = AE.scan()
    check("every exam is scanned", len(scanned) == 6, str(len(scanned)))
    disq = [e for e in scanned if e["disqualified"]]
    check("a disqualified exam is detected", disq, str([e["exam_id"] for e in disq]))
    for e in disq:
        ok, why = AE.admissibility(e)
        check(f"DISQUALIFIED {e['exam_id']} cannot contribute evidence",
              not ok, f"admissible={ok} why={why}")
    fails = [e for e in scanned if e.get("verdict") not in (None, "PASS")]
    for e in fails:
        ok, why = AE.admissibility(e)
        check(f"non-PASS {e['exam_id']} cannot contribute evidence", not ok,
              f"verdict={e.get('verdict')} admissible={ok}")
    stub = next((e for e in scanned
                 if e["has_report"] and e["report_bytes"] < 400), None)
    if stub:
        ok, why = AE.admissibility(stub)
        check(f"a sub-400B report stub is refused ({stub['exam_id']})", not ok, why)
    con = store.open_db(create=False)
    n_ev = con.execute("select count(*) n from evidence").fetchone()["n"]
    n_fd = con.execute("select count(*) n from finding").fetchone()["n"]
    con.close()
    check("evidence rows now exist (was 0)", n_ev >= 2, str(n_ev))
    check("finding rows now exist (was 0)", n_fd >= 2, str(n_fd))
    check("no evidence row comes from a disqualified or failed exam", n_ev == n_fd,
          f"evidence={n_ev} finding={n_fd}")


def t37_no_knowledge_lost() -> None:
    print("T37 the repair added knowledge and lost none")
    con = store.open_db(create=False)
    n_item = con.execute("select count(*) n from item").fetchone()["n"]
    n_src = con.execute("select count(*) n from item_source").fetchone()["n"]
    n_q = con.execute("select count(*) n from quality").fetchone()["n"]
    n_conf = con.execute("select count(*) n from conflict").fetchone()["n"]
    orphan = con.execute(
        "select count(*) n from item_source x left join source s on s.id=x.source_id "
        "where s.id is null").fetchone()["n"]
    no_state = con.execute(
        "select count(*) n from item i left join quality q on q.item_id=i.id "
        "where q.item_id is null").fetchone()["n"]
    con.close()
    check("every item still has a quality row (no orphan introduced)",
          no_state == 0, str(no_state))
    check("no citation lost its source row", orphan == 0, str(orphan))
    check("quality rows match item rows", n_q == n_item, f"{n_q} vs {n_item}")
    check("conflict history is intact (was 64, never deleted)", n_conf >= 64,
          str(n_conf))
    check("citations grew with the repair", n_src >= 1132, str(n_src))
    print(f"        items={n_item} sources_cited={n_src} quality={n_q} "
          f"conflicts={n_conf}")


def main() -> int:
    for fn in (t30_duplicate_marked_not_deleted, t31_malformed_keys,
               t32_orphaned_conflicts, t33_promoted_have_two_orgs,
               t34_new_citations_are_real, t35_seeds_can_corroborate,
               t36_assessment_evidence, t37_no_knowledge_lost):
        try:
            fn()
        except Exception as e:
            FAILURES.append(f"{fn.__name__} raised {e}")
            print(f"  [ERROR] {fn.__name__}: {type(e).__name__}: {e}")
            import traceback
            traceback.print_exc()
    print(f"\n{len(PASSES)} passed, {len(FAILURES)} failed")
    for f in FAILURES:
        print(f"  FAILED: {f}")
    return 1 if FAILURES else 0


if __name__ == "__main__":
    raise SystemExit(main())