#!/usr/bin/env python3
"""The write-up pipeline must reach the CORPUS, not stop at the report.

MEASURED 2026-11-01: the learning workflow's output was a DEAD END. The
write-up pipeline captured lessons into the canonical `lesson` table in
state `captured`, and nothing ever moved them on. Every reader that
matters -- `before_recon`, `before_summary`, `_prior_for_signal` --
filters on `state='verified'`. So a lesson distilled from a published
write-up could never influence a hunt. The live database showed exactly
that: 48 lessons, all `captured`, 0 verified, 0 `writeup_lesson` rows.

Worse, the capture stage was unreachable. The `/update` "all" path ran
`write_lessons_markdown()` -- which only RENDERS the table into
`memory/report-lessons.md` -- and never called `extract_lessons()`, which
CAPTURES lessons into that table. So `/update` regenerated the report
from whatever was already in the table and added nothing to it.

This test proves the whole chain:

    processed write-up -> captured lesson -> VERIFIED lesson
                       -> writeup_lesson routing row
                       -> the lesson is returned as intelligence

and proves the gate still holds: a write-up with no source URL, or no
class, does NOT reach `verified`.

It uses the PRODUCTION entry points (`orch.store.open_db`,
`writeups.pipeline`) against a temporary database. No external target.
"""

from __future__ import annotations

import pathlib
import shutil
import sqlite3
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

PASS = 0
FAIL = 0


def check(cond: bool, label: str, detail: str = "") -> bool:
    global PASS, FAIL
    if cond:
        PASS += 1
        print(f"  [PASS] {label}")
    else:
        FAIL += 1
        print(f"  [FAIL] {label}  ({detail})")
    return bool(cond)


def _redirect_db(root: pathlib.Path) -> dict:
    from orch import store as orch_store
    from wks import config as wks_config

    db = root / "db" / "wks.db"
    saved = {"orch": orch_store.db_path, "wks": wks_config.db_path}
    orch_store.db_path = lambda: db            # type: ignore[assignment]
    wks_config.db_path = lambda: db            # type: ignore[assignment]
    return saved


def _restore_db(saved: dict) -> None:
    from orch import store as orch_store
    from wks import config as wks_config

    orch_store.db_path = saved["orch"]         # type: ignore[assignment]
    wks_config.db_path = saved["wks"]         # type: ignore[assignment]


SOURCED = """---
title: Boolean Blind SQLi in the Search Endpoint
class_id: sqli
url: https://example.com/advisories/blind-sqli-search
content_hash: deadbeefcafe
source_path: writeups/raw/example/blind-sqli-search.md
---

The endpoint returned a different number of rows for a true predicate
than for the corresponding false predicate. The difference was stable
across repeated requests, which proves the boolean condition is
evaluated by the database rather than by the application. This confirmed
a blind SQL injection vulnerability.
"""

UNSOURCED = """---
title: An Unsourced Claim About SQL Injection
class_id: sqli
---

Somebody claimed the endpoint was injectable but published no URL, so
there is nothing a reader can go and check.
"""


def main() -> int:
    tmp = pathlib.Path(tempfile.mkdtemp(prefix="cyber_wup_"))
    (tmp / "db").mkdir(parents=True, exist_ok=True)
    saved = _redirect_db(tmp)
    try:
        from orch import store as orch_store
        from learning_engine import engine as le
        from writeups import pipeline as P

        con = orch_store.open_db(create=True)
        le.ensure_schema(con)

        # -----------------------------------------------------------------
        print("\nA. A SOURCED WRITE-UP REACHES THE VERIFIED STATE")
        sourced = tmp / "sourced.md"
        sourced.write_text(SOURCED, encoding="utf-8")
        r = P.extract_lessons(sourced, con=con)

        check(r.get("recorded", 0) >= 1,
              "the write-up produced at least one lesson", str(r)[:200])
        check(r.get("verifiable") is True,
              "a write-up with a class and a source URL is VERIFIABLE",
              str(r.get("verify_reason")))
        check(r.get("verified", 0) >= 1,
              "the lesson was PROMOTED to verified", str(r)[:200])

        row = con.execute(
            "SELECT topic, state, class_id, score, evidence FROM lesson"
            " WHERE state='verified'").fetchone()
        check(row is not None,
              "a VERIFIED lesson row exists in the canonical table", "")
        if row is not None:
            check(row["class_id"] == "sqli",
                  "the verified lesson carries the write-up's class",
                  str(row["class_id"]))
            check(float(row["score"] or 0) >= 0.6,
                  "the verified lesson scores above the unverified floor",
                  str(row["score"]))
            check("example.com" in (row["evidence"] or ""),
                  "the verified lesson records the SOURCE URL as its evidence",
                  str(row["evidence"])[:200])

        # -----------------------------------------------------------------
        print("\nB. THE ROUTING IS DURABLE")
        n_wl = con.execute("SELECT count(*) FROM writeup_lesson").fetchone()[0]
        check(n_wl >= 1,
              "the writeup_lesson routing row was written", f"n={n_wl}")
        wl = con.execute(
            "SELECT source_path, class_id, lesson_key FROM writeup_lesson"
        ).fetchone()
        if wl is not None:
            check(bool(wl["lesson_key"]),
                  "the routing row names the lesson it produced", "")
            check(wl["class_id"] == "sqli",
                  "the routing row carries the class", str(wl["class_id"]))

        # -----------------------------------------------------------------
        print("\nC. THE GATE HOLDS — NO SOURCE, NO VERIFICATION")
        unsourced = tmp / "unsourced.md"
        unsourced.write_text(UNSOURCED, encoding="utf-8")
        r2 = P.extract_lessons(unsourced, con=con)
        check(r2.get("verifiable") is False,
              "a write-up with NO source URL is NOT verifiable",
              str(r2.get("verify_reason")))
        check(r2.get("verified", 0) == 0,
              "an unsourced write-up promotes NOTHING", str(r2)[:200])
        check(bool(r2.get("verify_reason")),
              "the refusal says WHY", str(r2.get("verify_reason")))

        # The unsourced lesson must exist in `captured` state -- held, not
        # discarded -- so a later run with a source can promote it.
        held = con.execute(
            "SELECT state FROM lesson WHERE topic LIKE 'sqli: An Unsourced%'"
        ).fetchone()
        check(held is not None,
              "the unsourced lesson was still CAPTURED (held, not discarded)",
              "")
        if held is not None:
            check(held["state"] == "captured",
                  "the unsourced lesson is NOT verified", held["state"])

        # -----------------------------------------------------------------
        print("\nD. THE VERIFIED LESSON IS RETURNED AS INTELLIGENCE")
        # This is the point of the whole chain: a reader that feeds a hunt
        # must SEE a write-up-derived lesson.
        prior = le.before_recon(con, "example.com")
        classes = prior.get("classes_with_verified_lessons") or []
        check("sqli" in classes,
              "the verified write-up lesson appears in the hunt's prior classes",
              str(classes))
        lessons = prior.get("lessons") or []
        check(any(x.get("class_id") == "sqli" for x in lessons),
              "the lesson BODY is returned to the hunt", str(lessons)[:200])

        # -----------------------------------------------------------------
        print("\nE. THE LESSON REACHES THE SKILL THE AGENT LOADS")
        # `update_hook` is the only path that calls
        # `wks.project.refresh_class`, and it had no production caller. But
        # the projection renders from `wks.retrieval.class_digest`, which
        # reads the `item` table -- NOT `lesson`. So the lesson has to
        # become a knowledge ITEM before the refresh means anything.
        from wks import ownership as own
        with own.owner_write(con, own.WKS):
            con.execute(
                "INSERT OR IGNORE INTO bug_class(id,name,surface,first_seen)"
                " VALUES ('sqli','SQL Injection','web','2026-11-01')")
            con.commit()
        lrow = con.execute(
            "SELECT lesson_key FROM lesson WHERE state='verified'").fetchone()
        if lrow is not None:
            upd = le.update_hook(con, lesson_key=lrow["lesson_key"])
            check(upd.get("ok") is True,
                  "update_hook projects the verified lesson",
                  str(upd)[:300])
            check(not upd.get("errors"),
                  "the projection reported NO errors", str(upd.get("errors")))
            item = con.execute(
                "SELECT id, item_key, class_id, kind, claim FROM item"
                " WHERE item_key=?",
                (f"lesson.{lrow['lesson_key']}",)).fetchone()
            check(item is not None,
                  "the lesson became a KNOWLEDGE ITEM in the corpus",
                  str(upd)[:200])
            if item is not None:
                check(item["class_id"] == "sqli",
                      "the item carries the class", item["class_id"])
                check(item["kind"] == "technique",
                      "the item is a technique", item["kind"])
                check(bool(item["claim"]),
                      "the item carries the lesson's claim", item["claim"])
            # Promotion is quality.py's job alone -- the learning engine
            # does not get to mark its own lesson as high quality.
            q = con.execute(
                "SELECT validation_state FROM quality WHERE item_id=?",
                (item["id"],)).fetchone() if item is not None else None
            check(q is not None and q["validation_state"] == "discovered",
                  "the item is left in `discovered` for the quality gate",
                  str(dict(q)) if q else "no quality row")
            # The SOURCE must be linked, or the item can never be promoted.
            n_src = con.execute(
                "SELECT count(*) FROM item_source WHERE item_id=?",
                (item["id"],)).fetchone()[0] if item is not None else 0
            check(n_src >= 1,
                  "the item is CITED to the write-up it came from",
                  f"n={n_src}")
            # Idempotent: re-running must not duplicate the item.
            n_before = con.execute("SELECT count(*) FROM item").fetchone()[0]
            le.update_hook(con, lesson_key=lrow["lesson_key"])
            n_after = con.execute("SELECT count(*) FROM item").fetchone()[0]
            check(n_after == n_before,
                  "re-running the projection does NOT duplicate the item",
                  f"{n_before} -> {n_after}")

        # -----------------------------------------------------------------
        print("\nF. THE CAPTURE STAGE IS REACHABLE FROM THE PIPELINE")
        # The defect was that `all_stages` never called `extract_lessons`.
        # Assert the wiring directly, by source inspection of the function
        # body -- this is a WIRING check, so it must not pretend to be a
        # behavioural one.
        import ast
        import inspect
        src = inspect.getsource(P.all_stages)
        tree = ast.parse(src)
        fn = next(n for n in ast.walk(tree)
                  if isinstance(n, ast.FunctionDef)
                  and n.name == "all_stages")
        calls = []
        for node in ast.walk(fn):
            if (isinstance(node, ast.Call)
                    and isinstance(node.func, ast.Name)):
                calls.append(node.func.id)
        check("extract_all_lessons" in calls,
              "all_stages CALLS the capture stage", str(calls))
        check("write_lessons_markdown" in calls,
              "all_stages CALLS the render stage", str(calls))
        if ("extract_all_lessons" in calls
                and "write_lessons_markdown" in calls):
            # The order of the two CALLS, not the order they are mentioned
            # in the docstring.
            call_lines = {}
            for node in ast.walk(fn):
                if (isinstance(node, ast.Call)
                        and isinstance(node.func, ast.Name)
                        and node.func.id in ("extract_all_lessons",
                                             "write_lessons_markdown")):
                    call_lines.setdefault(node.func.id, node.lineno)
            check(call_lines["extract_all_lessons"]
                  < call_lines["write_lessons_markdown"],
                  "the capture stage runs BEFORE the render stage",
                  str(call_lines))

        con.close()
    finally:
        _restore_db(saved)
        shutil.rmtree(tmp, ignore_errors=True)

    print("\n" + "=" * 60)
    if FAIL:
        print(f"FAILURES ({FAIL}):")
        print("THE WRITE-UP PIPELINE DOES NOT REACH THE CORPUS.")
        return 1
    print(f"{PASS}/{PASS + FAIL} CHECKS PASS")
    print("A sourced write-up's lesson reaches the verified state, is")
    print("routed durably, and is returned to a hunt as intelligence.")
    print("An unsourced write-up is held unverified, and the capture stage")
    print("is reachable from the pipeline that runs it.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
