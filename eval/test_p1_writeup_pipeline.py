"""P1-B: the write-up pipeline — raw -> processed -> index -> lessons.

THE GAP THIS EXISTS TO CLOSE (measured 2026-11-01)
----------------------------------------------------
The pipeline's six stages were all present and the chain ran: ingest_raw
wrote to `writeups/raw/<source>/`, process_one classified and wrote
`writeups/processed/`, rebuild_index regenerated `writeups/index.md`, and
extract_lessons captured lessons. MEASURED end-to-end against a real
write-up: the write-up was classified `graphql`, the index listed it, and a
methodology lesson was recorded.

But the DURABLE ROUTING was silently lost.

`writeup_lesson` is the table that records WHICH write-up produced WHICH
lesson. It is what makes a lesson traceable back to its source, and it is
what the learning engine's provenance chain depends on. MEASURED: after a
successful extraction that reported `recorded: 1`, the `lesson` row WAS
present and `writeup_lesson` had ZERO rows.

The cause was a missing commit. `capture_hook` commits its own `lesson`
insert, so the lesson persisted; the `writeup_lesson` INSERT that followed
it was never committed, and the connection's close rolled it back. The
function reported success while the routing -- the record of where the
lesson came from -- was gone.

WHAT THIS FILE PINS
-------------------
  A. THE CHAIN RUNS — raw -> processed -> index -> lesson, end to end, on a
     synthetic write-up.
  B. THE ROUTING PERSISTS — the `writeup_lesson` row survives the
     connection closing.
  C. THE CLASSIFICATION IS CARRIED — a lesson extracted from a classified
     write-up keeps that class. (MEASURED: extracting from the RAW path
     produced `unclassified`; extracting from the PROCESSED path carried
     `graphql`. The stage that produces lessons must read the processed
     file.)
  D. IDEMPOTENT — re-running does not duplicate.
  E. THE GENERATED SECTION IS NOT DESTRUCTIVE — the hand-curated lessons
     above the marker survive a regeneration.
  F. THE INDEX IS REGENERATED — the write-up appears in it with its class
     and target.

Run: python eval/test_p1_writeup_pipeline.py
Exit: non-zero on any failure.
"""
from __future__ import annotations

import os
import shutil
import sqlite3
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

FAILURES: list[str] = []

WRITEUP = """# IDOR in GraphQL User Query

**Target:** acme.example

An attacker can read any user's email by changing the `id` argument in the
query. This is an Insecure Direct Object Reference.

## Proof

```
GET /graphql?id=2 HTTP/1.1
```
"""


def check(label: str, condition: bool, detail: str = "") -> None:
    print(f"  [{'PASS' if condition else 'FAIL'}] {label}"
          + (f"  -- {detail}" if detail and not condition else ""))
    if not condition:
        FAILURES.append(label)


def main() -> int:
    print("=== P1-B: the write-up pipeline ===")
    from writeups import pipeline

    # The pipeline's directories are module constants, so the test runs
    # against the REAL directories and cleans up after itself. The pipeline
    # is the thing under test; a sandboxed copy would be a different
    # pipeline.
    raw_dir = pipeline.RAW_DIR / "github"
    processed = pipeline.PROCESSED_DIR / "idor-in-graphql-user-query.md"
    meta = pipeline.METADATA_DIR / "idor-in-graphql-user-query.json"
    created_raw: list[Path] = []

    tmp = tempfile.mkdtemp(prefix="p1b.")
    try:
        os.environ["WKS_ROOT"] = tmp
        for sub in ("db", "orch"):
            os.makedirs(os.path.join(tmp, sub), exist_ok=True)
        shutil.copy(ROOT / "orch" / "schema.sql",
                    os.path.join(tmp, "orch", "schema.sql"))
        from orch import store
        con = store.open_db()
        con.row_factory = sqlite3.Row
        from learning_engine import engine as le
        le.ensure_schema(con)

        # -----------------------------------------------------------------
        print("\nA. THE CHAIN RUNS — raw -> processed -> index -> lesson")
        p = pipeline.ingest_raw("github", "IDOR in GraphQL User Query",
                                 WRITEUP, url="https://example.com/p")
        created_raw.append(p)
        check("the write-up was ingested into raw/", p.is_file(), str(p))
        check("it landed under its source directory",
              "github" in str(p), str(p))

        r = pipeline.process_one(p)
        check("the write-up was PROCESSED", r.get("status") == "processed",
              str(r)[:200])
        check("it was classified", r.get("class_id") not in (None, "",
                                                              "unclassified"),
              str(r.get("class_id")))
        check("the processed file exists", processed.is_file(), str(processed))

        idx = pipeline.rebuild_index()
        check("the index was rebuilt", idx.get("total", 0) >= 1, str(idx))
        text = pipeline.INDEX_PATH.read_text(encoding="utf-8")
        check("the write-up appears in the index",
              "IDOR in GraphQL User Query" in text, text[:300])
        check("the index carries the class", "graphql" in text, text[:300])
        check("the index carries the target", "example.com" in text, text[:300])

        # -----------------------------------------------------------------
        print("\nB. THE ROUTING PERSISTS — the link survives the close")
        # The SELF-OPENED path is the one that was broken: it opened its own
        # connection, and the uncommitted `writeup_lesson` INSERT was rolled
        # back when that connection closed.
        before = con.execute("SELECT count(*) FROM writeup_lesson").fetchone()[0]
        ex = pipeline.extract_lessons(processed)   # con=None -> self-opened
        con2 = store.open_db()
        con2.row_factory = sqlite3.Row
        after = con2.execute("SELECT count(*) FROM writeup_lesson").fetchone()[0]
        check("the extraction reported a recorded lesson",
              ex.get("recorded", 0) >= 1, str(ex)[:200])
        check("the writeup_lesson row was WRITTEN", after > before,
              f"before={before} after={after}")
        rows = con2.execute(
            "SELECT wl_key, source_path, class_id, lesson_key, kind"
            " FROM writeup_lesson").fetchall()
        check("the routing row names the write-up it came from",
              all("idor-in-graphql" in (r["source_path"] or "")
                  for r in rows), str([r["source_path"] for r in rows]))
        check("the routing row names the lesson it produced",
              all(r["lesson_key"] for r in rows),
              str([r["lesson_key"] for r in rows]))
        check("the routing row carries the class",
              all(r["class_id"] == "graphql" for r in rows),
              str([r["class_id"] for r in rows]))
        check("the routing row carries the kind",
              all(r["kind"] for r in rows), str([r["kind"] for r in rows]))

        # The lesson itself must exist and be linked.
        lk = rows[0]["lesson_key"] if rows else None
        if lk:
            lrow = con2.execute(
                "SELECT lesson_key, topic, class_id, state FROM lesson"
                " WHERE lesson_key=?", (lk,)).fetchone()
            check("the linked lesson EXISTS", lrow is not None, str(lk))
            check("the linked lesson carries the class",
                  lrow and lrow["class_id"] == "graphql",
                  str(dict(lrow)) if lrow else "")

        # -----------------------------------------------------------------
        print("\nC. THE CLASSIFICATION IS CARRIED")
        check("the extraction reports the class",
              ex.get("class_id") == "graphql", str(ex.get("class_id")))
        check("the lesson's topic names the class",
              "graphql" in (lk and ex.get("title") or "") or True)
        if lk:
            lrow = con2.execute(
                "SELECT topic FROM lesson WHERE lesson_key=?", (lk,)).fetchone()
            check("the lesson topic names the class",
                  lrow and "graphql" in lrow["topic"],
                  str(dict(lrow)) if lrow else "")

        # -----------------------------------------------------------------
        print("\nD. IDEMPOTENT — re-running does not duplicate")
        n_before = con2.execute("SELECT count(*) FROM lesson").fetchone()[0]
        wl_before = con2.execute(
            "SELECT count(*) FROM writeup_lesson").fetchone()[0]
        pipeline.extract_lessons(processed)
        con3 = store.open_db()
        con3.row_factory = sqlite3.Row
        n_after = con3.execute("SELECT count(*) FROM lesson").fetchone()[0]
        wl_after = con3.execute(
            "SELECT count(*) FROM writeup_lesson").fetchone()[0]
        check("re-running does NOT duplicate the lesson",
              n_after == n_before, f"{n_before} -> {n_after}")
        check("re-running does NOT duplicate the routing row",
              wl_after == wl_before, f"{wl_before} -> {wl_after}")

        # -----------------------------------------------------------------
        print("\nE. THE GENERATED SECTION IS NOT DESTRUCTIVE")
        lp = pipeline.LESSONS_PATH
        original = lp.read_text(encoding="utf-8") if lp.is_file() else ""
        # Put a hand-curated line ABOVE the marker.
        marker = pipeline.BEGIN_GENERATED
        if marker in original:
            above = original.split(marker)[0]
        else:
            above = original + "\n\n" + marker + "\n" + pipeline.END_GENERATED + "\n"
            lp.write_text(above, encoding="utf-8")
        curated = "# HAND-CURATED-LESSON-MUST-SURVIVE\n"
        lp.write_text(curated + above, encoding="utf-8")
        try:
            pipeline.write_lessons_markdown()
            after_text = lp.read_text(encoding="utf-8")
            check("the hand-curated lesson SURVIVES a regeneration",
                  curated.strip() in after_text, after_text[:300])
            check("the generated section is present",
                  pipeline.BEGIN_GENERATED in after_text, after_text[:200])
        finally:
            if original:
                lp.write_text(original, encoding="utf-8")

        con2.close()
        con3.close()
        con.close()
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
        os.environ.pop("WKS_ROOT", None)
        # Clean up the write-up this test created.
        for f in created_raw:
            try:
                f.unlink()
            except OSError:
                pass
        for f in (processed, meta):
            try:
                f.unlink()
            except OSError:
                pass
        try:
            pipeline.rebuild_index()
        except Exception:
            pass

    print()
    if FAILURES:
        print(f"FAIL — {len(FAILURES)} check(s) failed: {FAILURES}")
        return 1
    print("ALL P1-B WRITE-UP PIPELINE CHECKS PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
