"""Regression test for the write-up processing pipeline.

MEASURED 2026-10-31: `.opencode/commands/update.md` specifies a four-stage
write-up pipeline (fetch into `writeups/raw/`, process into
`writeups/processed/` with triple-layer dedup, rebuild `writeups/index.md`
as a table, distil lessons into `memory/report-lessons.md`), but no Python
module implemented it. `writeups/raw/`, `writeups/processed/`,
`writeups/metadata/` and `writeups/feeds/` were all empty.

These checks cover the parts that are EASY to get wrong and that a
"does it import" test would never catch:

  * the triple-layer dedup actually fires, and the LAYER is reported
  * the pipeline is IDEMPOTENT -- running it twice changes nothing
  * classification uses the system taxonomy, and an unmatchable write-up
    is NOT forced into a class
  * a lesson is captured through the learning engine's idempotent hook
  * the index is a TABLE with the columns the spec names
  * nothing writes outside the sandbox

The pipeline writes to absolute paths derived from the package location, so
the test COPIES the package into a sandbox and points the copy at a
sandboxed database. The canonical corpus is never touched.
"""
from __future__ import annotations

import os
import shutil
import sqlite3
import sys
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))

PASSES: list[str] = []
FAILURES: list[str] = []


def check(label: str, ok: bool, detail: str = "") -> None:
    if ok:
        PASSES.append(label)
        print(f"  [PASS] {label}")
    else:
        FAILURES.append(f"{label} -- {detail}")
        print(f"  [FAIL] {label}  {detail}")


def sandbox_pipeline():
    """Copy the writeups package into a sandbox and import it from there.

    The pipeline derives ROOT from its own file location, so a copy is the
    only way to redirect its output. The sandbox gets its own `db/` and
    `memory/` so no canonical artifact is reachable.
    """
    sb = Path(tempfile.mkdtemp(prefix="writeup_pipeline_test_"))
    shutil.copytree(REPO / "writeups", sb / "writeups")
    (sb / "db").mkdir(parents=True, exist_ok=True)
    (sb / "memory").mkdir(parents=True, exist_ok=True)
    for name in ("learning_engine", "wks", "orch"):
        shutil.copytree(REPO / name, sb / name,
                        ignore=shutil.ignore_patterns("__pycache__"))
    sys.path.insert(0, str(sb))
    for mod in list(sys.modules):
        if mod.split(".")[0] in ("writeups", "wks", "orch", "learning_engine"):
            del sys.modules[mod]
    import writeups.pipeline as pipeline
    return sb, pipeline


BODY = """# SQL Injection in the Search Parameter

The application concatenates the `q` parameter directly into a SQL query
without parameterisation. When the parameter is set to a single quote the
database returns a syntax error, and a UNION SELECT extracts the version.

## Lessons

- Always use parameterised queries; string concatenation of user input into
  SQL is the root cause of this entire class of finding, and no amount of
  input filtering makes concatenation safe.
- Test for SQL injection by comparing the baseline response against a
  response carrying a single quote, and then by attempting a UNION SELECT
  with a known column count.

The impact is a full read of the application database including user
credentials and session tokens.
"""

BODY2 = """# Another Search Injection

The application concatenates the `q` parameter directly into a SQL query
without parameterisation, in a second write-up about the same product.

## Lessons

- Always use parameterised queries; string concatenation of user input into
  SQL is the root cause of this entire class of finding, and no amount of
  input filtering makes concatenation safe.
"""


def t01_ingest_writes_to_raw() -> None:
    print("T01 ingest_raw writes into writeups/raw/<source>/")
    sb, P = sandbox_pipeline()
    try:
        p = P.ingest_raw("hackerone", "SQL Injection in Acme",
                         BODY, url="https://hackerone.com/reports/1")
        check("the file is created", p.is_file(), str(p))
        check("it is under raw/<source>/",
              p.parent.name == "hackerone" and p.parent.parent.name == "raw",
              str(p))
        check("the filename carries the topic and a timestamp",
              p.stem.startswith("sql-injection-in-acme_"), p.stem)
        check("it is inside the sandbox, not the canonical tree",
              str(p).startswith(str(sb)), str(p))
        text = p.read_text(encoding="utf-8")
        check("the frontmatter records the title", "title: SQL Injection" in text)
        check("the frontmatter records the url",
              "url: https://hackerone.com/reports/1" in text)
    finally:
        shutil.rmtree(sb, ignore_errors=True)


def t02_classification_uses_the_taxonomy() -> None:
    print("T02 classification maps to the system taxonomy")
    sb, P = sandbox_pipeline()
    try:
        r = P.classify("SQL Injection in Acme API", "a sqli in the q parameter")
        check("a SQLi write-up classifies as sqli", r["class_id"] == "sqli",
              str(r))
        check("the confidence is reported", 0 < r["confidence"] <= 1.0, str(r))
        r2 = P.classify("JWT audience confusion", "the token audience is unchecked")
        check("a JWT write-up classifies as jwt", r2["class_id"] == "jwt", str(r2))
        r3 = P.classify("Some entirely unrelated article",
                        "This text is about gardening and has no security content.")
        check("an unmatchable write-up is NOT forced into a class",
              r3["class_id"] == "unclassified", str(r3))
        check("an unmatchable write-up has zero confidence",
              r3["confidence"] == 0.0, str(r3))
    finally:
        shutil.rmtree(sb, ignore_errors=True)


def t03_process_writes_and_indexes() -> None:
    print("T03 process_one writes the processed file and the dedup index")
    sb, P = sandbox_pipeline()
    try:
        src = P.ingest_raw("hackerone", "SQL Injection in Acme", BODY,
                           url="https://hackerone.com/reports/1")
        r = P.process_one(src)
        check("the write-up is processed", r["status"] == "processed", str(r))
        out = Path(r["path"])
        check("the processed file exists", out.is_file(), str(out))
        check("it is under processed/", out.parent.name == "processed", str(out))
        meta = P.METADATA_DIR / (out.stem + ".json")
        check("a dedup index sidecar is written", meta.is_file(), str(meta))
        idx = P.load_index()
        check("the index has all three layers",
              any(k.startswith("url:") for k in idx)
              and any(k.startswith("title:") for k in idx)
              and any(k.startswith("hash:") for k in idx),
              str(sorted(idx)))
    finally:
        shutil.rmtree(sb, ignore_errors=True)


def t04_triple_layer_dedup() -> None:
    print("T04 the triple-layer dedup fires, and reports WHICH layer matched")
    sb, P = sandbox_pipeline()
    try:
        src = P.ingest_raw("hackerone", "SQL Injection in Acme", BODY,
                           url="https://hackerone.com/reports/1")
        P.process_one(src)

        # LAYER 1: the same URL.
        same_url = P.ingest_raw("medium", "Totally Different Title",
                                "Completely different body text here.",
                                url="https://hackerone.com/reports/1")
        r1 = P.process_one(same_url)
        check("the same URL is a duplicate", r1["status"] == "skipped", str(r1))
        check("the url layer is named", r1.get("layer") == "url", str(r1))

        # LAYER 2: the same normalised title, different URL and body.
        same_title = P.ingest_raw("medium", "sql injection in acme!",
                                  "A different body that shares the title.",
                                  url="https://medium.com/@x/other")
        r2 = P.process_one(same_title)
        check("the same normalised title is a duplicate",
              r2["status"] == "skipped", str(r2))
        check("the title layer is named", r2.get("layer") == "title", str(r2))

        # LAYER 3: the same content, different title and URL.
        same_content = P.ingest_raw("medium", "Something Else Entirely",
                                    BODY, url="https://medium.com/@x/third")
        r3 = P.process_one(same_content)
        check("the same content hash is a duplicate",
              r3["status"] == "skipped", str(r3))
        check("the hash layer is named", r3.get("layer") == "hash", str(r3))

        # A genuinely new write-up still gets through.
        new_one = P.ingest_raw("medium", "A Different Vulnerability Class",
                               "This write-up is about a completely different"
                               " issue, involving OAuth token validation and"
                               " the redirect_uri parameter not being checked.",
                               url="https://medium.com/@x/fourth")
        r4 = P.process_one(new_one)
        check("a genuinely new write-up is processed",
              r4["status"] == "processed", str(r4))
    finally:
        shutil.rmtree(sb, ignore_errors=True)


def t05_rerun_is_idempotent() -> None:
    print("T05 re-running the pipeline changes nothing")
    sb, P = sandbox_pipeline()
    try:
        src = P.ingest_raw("hackerone", "SQL Injection in Acme", BODY,
                           url="https://hackerone.com/reports/1")
        P.process_one(src)
        processed_before = sorted(p.name for p in P.PROCESSED_DIR.glob("*.md"))
        index_before = P.load_index()
        n_before = len(P.load_index())

        again = P.process_all()
        check("the second run processes nothing",
              again["processed"] == 0, str(again["processed"]))
        check("the second run skips the write-up",
              again["skipped"] == 1, str(again["skipped"]))
        processed_after = sorted(p.name for p in P.PROCESSED_DIR.glob("*.md"))
        check("no extra processed file was written",
              processed_before == processed_after,
              f"{processed_before} vs {processed_after}")
        check("the dedup index did not grow", len(P.load_index()) == n_before,
              f"{n_before} vs {len(P.load_index())}")
    finally:
        shutil.rmtree(sb, ignore_errors=True)


def t06_index_is_a_table() -> None:
    print("T06 rebuild_index writes the table the spec names")
    sb, P = sandbox_pipeline()
    try:
        src = P.ingest_raw("hackerone", "SQL Injection in Acme", BODY,
                           url="https://hackerone.com/reports/1")
        P.process_one(src)
        r = P.rebuild_index()
        check("the index reports a total", r["total"] == 1, str(r))
        text = P.INDEX_PATH.read_text(encoding="utf-8")
        check("the header row names the spec's columns",
              "| Title | Vuln Type | Target | Source |" in text, text[:200])
        check("the row carries the vuln type", "sqli" in text, text[:400])
        check("the row carries the target host",
              "hackerone.com" in text, text[:400])
        check("the index lives in the sandbox",
              str(P.INDEX_PATH).startswith(str(sb)), str(P.INDEX_PATH))
    finally:
        shutil.rmtree(sb, ignore_errors=True)


def t07_lessons_are_captured_idempotently() -> None:
    print("T07 lessons are captured through the learning engine's hook")
    sb, P = sandbox_pipeline()
    try:
        # A sandboxed canonical database.
        db_path = sb / "db" / "wks.db"
        con = sqlite3.connect(db_path)
        con.row_factory = sqlite3.Row
        con.execute("PRAGMA foreign_keys=ON")

        src = P.ingest_raw("hackerone", "SQL Injection in Acme", BODY,
                           url="https://hackerone.com/reports/1")
        pr = P.process_one(src)

        r1 = P.extract_lessons(pr["path"], con=con)
        check("at least one lesson is extracted", len(r1["lessons"]) >= 1, str(r1))
        n1 = con.execute("SELECT count(*) n FROM lesson").fetchone()["n"]
        check("a lesson row exists", n1 >= 1, str(n1))
        nw1 = con.execute("SELECT count(*) n FROM writeup_lesson").fetchone()["n"]
        check("the routing is recorded in writeup_lesson", nw1 >= 1, str(nw1))

        # Capture again: the hook is idempotent, so no second row.
        r2 = P.extract_lessons(pr["path"], con=con)
        n2 = con.execute("SELECT count(*) n FROM lesson").fetchone()["n"]
        check("capturing again creates NO second lesson row",
              n2 == n1, f"{n1} vs {n2}")
        con.close()
    finally:
        shutil.rmtree(sb, ignore_errors=True)


def t08_report_lessons_markdown() -> None:
    print("T08 the lessons markdown is generated from the canonical rows")
    sb, P = sandbox_pipeline()
    try:
        db_path = sb / "db" / "wks.db"
        con = sqlite3.connect(db_path)
        con.row_factory = sqlite3.Row
        con.execute("PRAGMA foreign_keys=ON")
        src = P.ingest_raw("hackerone", "SQL Injection in Acme", BODY,
                           url="https://hackerone.com/reports/1")
        pr = P.process_one(src)
        P.extract_lessons(pr["path"], con=con)
        con.close()

        r = P.write_lessons_markdown()
        check("the file is written", P.LESSONS_PATH.is_file(), str(P.LESSONS_PATH))
        text = P.LESSONS_PATH.read_text(encoding="utf-8")
        check("it lives in the sandbox", str(P.LESSONS_PATH).startswith(str(sb)),
              str(P.LESSONS_PATH))
        check("the count is reported", isinstance(r["lessons"], int), str(r))
    finally:
        shutil.rmtree(sb, ignore_errors=True)


def t09_curated_lessons_survive_the_generator() -> None:
    print("T09 the generator NEVER destroys hand-curated lessons")
    sb, P = sandbox_pipeline()
    try:
        # A lessons file with curated content ABOVE the markers.
        P.LESSONS_PATH.parent.mkdir(parents=True, exist_ok=True)
        curated = ("# Report lessons — distilled training data\n\n"
                   "## 2026-10-30 — a real hunt\n"
                   "- A hand-curated lesson that exists nowhere else.\n"
                   "- Another one.\n\n"
                   f"{P.BEGIN_GENERATED}\nold generated content\n"
                   f"{P.END_GENERATED}\n")
        P.LESSONS_PATH.write_text(curated, encoding="utf-8")

        # The canonical table has no verified lessons, so the generated
        # section becomes empty -- and the curated section must survive.
        db_path = sb / "db" / "wks.db"
        con = sqlite3.connect(db_path)
        con.row_factory = sqlite3.Row
        P.write_lessons_markdown()
        con.close()

        after = P.LESSONS_PATH.read_text(encoding="utf-8")
        check("the curated lesson survives",
              "A hand-curated lesson that exists nowhere else." in after,
              after[:300])
        check("the second curated lesson survives",
              "Another one." in after, after[:300])
        check("the curated section is still ABOVE the markers",
              after.index("A hand-curated lesson")
              < after.index(P.BEGIN_GENERATED), after[:300])
        check("the generated section was replaced, not appended",
              "old generated content" not in after, after[:300])
        check("the markers survive",
              P.BEGIN_GENERATED in after and P.END_GENERATED in after)

        # A file with NO markers must not lose its content either.
        P.LESSONS_PATH.write_text(
            "# Report lessons\n\n- only this one\n", encoding="utf-8")
        P.write_lessons_markdown()
        after2 = P.LESSONS_PATH.read_text(encoding="utf-8")
        check("a file with no markers keeps its content",
              "only this one" in after2, after2[:300])
        check("the markers are added",
              P.BEGIN_GENERATED in after2 and P.END_GENERATED in after2,
              after2[:300])
    finally:
        shutil.rmtree(sb, ignore_errors=True)


def main() -> int:
    for fn in (t01_ingest_writes_to_raw,
               t02_classification_uses_the_taxonomy,
               t03_process_writes_and_indexes,
               t04_triple_layer_dedup,
               t05_rerun_is_idempotent,
               t06_index_is_a_table,
               t07_lessons_are_captured_idempotently,
               t08_report_lessons_markdown,
               t09_curated_lessons_survive_the_generator):
        try:
            fn()
        except Exception as e:
            import traceback
            traceback.print_exc()
            FAILURES.append(f"{fn.__name__} raised {type(e).__name__}: {e}")
    print(f"\n{len(PASSES)} passed, {len(FAILURES)} failed")
    for f in FAILURES:
        print(f"  FAILED: {f}")
    print("WRITEUP PIPELINE: ALL CHECKS PASS" if not FAILURES
          else "WRITEUP PIPELINE: FAILURES ABOVE")
    return 1 if FAILURES else 0


if __name__ == "__main__":
    raise SystemExit(main())
