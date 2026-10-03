"""T24 -- the conflict writer must be IDEMPOTENT.

MEASURED (wave 10): `wks/ingest.py` inserted a conflict row unconditionally on
every QUOTE_NOT_FOUND rejection. Re-ingesting an unchanged file therefore
recorded the SAME dispute again each time: one sandbox run ingesting
w5-fp-web.json twice ended with 45 open rows for 10 distinct disputes, and a
single `deser` claim was stored 9 times. `open_conflicts` then counts ingest
invocations, not disputes.

Validated BOTH ways, because a test that only ever passes protects nothing:
  T24a  two ingests of the same failing file -> ONE open row (idempotent)
  T24b  a genuinely DIFFERENT rejection still gets its own row (dedupe is not
        a blanket swallow -- a checker that cannot fail is not a checker)
  T24c  --dry writes nothing
  T24d  the rejection is still REPORTED on every run (storage is deduped, the
        signal to the caller is not)

Runs entirely inside a sandbox db; the canonical db is never touched.
"""
from __future__ import annotations

import json
import os
import shutil
import sqlite3
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PASS, FAIL = "PASS", "FAIL"
results = []


def check(name: str, ok: bool, detail: str = "") -> None:
    results.append((name, ok))
    print("  [%s] %s%s" % (PASS if ok else FAIL, name, ("  -- " + detail) if detail else ""))


def sandbox() -> tuple[Path, dict]:
    sb = Path(tempfile.mkdtemp(prefix="wks-t24-"))
    (sb / "research" / "incoming").mkdir(parents=True)
    env = dict(os.environ, WKS_ROOT=str(sb), PYTHONPATH=str(ROOT))
    # FRESH schema. An earlier version copied the canonical db, which carried the
    # 43 pre-existing open rows left by the wave-10 bug into every fixture -- the
    # test then failed on inherited state while proving nothing about the writer.
    init = subprocess.run([sys.executable, "-m", "wks.cli", "init"],
                          cwd=str(ROOT), env=env, capture_output=True,
                          text=True, timeout=600)
    if not (sb / "db" / "wks.db").exists():
        raise SystemExit("sandbox init failed: %s %s" % (init.stdout, init.stderr))
    add = subprocess.run([sys.executable, "-m", "wks.cli", "add-class",
                          "t24cl", "T24 Sandbox Class", "web"],
                         cwd=str(ROOT), env=env, capture_output=True,
                         text=True, timeout=600)
    print("  [setup] init+add-class rc=%s" % add.returncode)
    if add.returncode != 0:
        print("  [setup] %s %s" % (add.stdout[-400:], add.stderr[-400:]))
    return sb, env


def run_ingest(sb: Path, env: dict, path: Path, dry: bool = False) -> str:
    args = [sys.executable, "-m", "wks.ingest", str(path)]
    if dry:
        args.append("--dry")
    p = subprocess.run(args, cwd=str(ROOT), env=env, capture_output=True,
                       text=True, timeout=1800)
    return (p.stdout or "") + (p.stderr or "")


def open_rows(sb: Path) -> list[tuple]:
    con = sqlite3.connect(str(sb / "db" / "wks.db"))
    rows = con.execute("SELECT id, class_id, claim_a, claim_b FROM conflict "
                       "WHERE status='open' AND topic='fabricated-evidence'").fetchall()
    con.close()
    return rows


def failing_file(sb: Path, claim: str, fname: str) -> Path:
    # One item whose quote cannot be on the cited page -> FABRICATED.
    #
    # The cited page MUST fetch. example.org failed here, which yields
    # FETCH_FAILED -> UNVERIFIED, and an unverified item never reaches the
    # conflict branch -- so the first version of this fixture passed the
    # idempotence checks by never exercising the writer at all. example.com
    # returns 200 with 427 chars and is enough: the quote is absent either way.
    p = sb / "research" / "incoming" / fname
    item = {
        "item_key": "t24cl.fp_rule.never_matches_the_page",
        "class_id": "t24cl",
        "kind": "fp_rule",
        "claim": claim,
        "body": "x" * 220,
        "disproof": "Refuted if the quoted span is present on the cited page.",
        "surface": "web",
        "severity_hint": "low",
        "hunting_value": 1,
        "sources": [
            {"url": "https://example.com/", "source_type": "docs",
             "host": "example.com",
             "quote": "a span deliberately absent from any live page zzzq"},
            {"url": "https://example.com/#two", "source_type": "docs",
             "host": "example.com",
             "quote": "another absent span qqqw"},
        ],
    }
    p.write_text(json.dumps({"items": [item]}, indent=1), encoding="utf-8")
    return p


def register_class(sb: Path) -> None:
    env = dict(os.environ, WKS_ROOT=str(sb), PYTHONPATH=str(ROOT))
    subprocess.run([sys.executable, "-m", "wks.cli", "add-class", "t24cl",
                    "T24 Sandbox Class", "web"],
                   cwd=str(ROOT), env=env, capture_output=True, text=True,
                   timeout=300)


print("T24 conflict-insert idempotence (re-ingesting an unchanged file must not "
      "multiply disputes)")

# --- T24a: same file twice -> one row ---------------------------------------
sb, env = sandbox()
try:
    register_class(sb)
    f = failing_file(sb, "A claim whose quote is absent from the cited page.",
                     "t24a.json")
    run_ingest(sb, env, f)
    after1 = open_rows(sb)
    run_ingest(sb, env, f)
    after2 = open_rows(sb)
    check("T24a second identical ingest adds NO row", len(after2) == len(after1),
          "after1=%d after2=%d" % (len(after1), len(after2)))
    check("T24a the first rejection did record a dispute", len(after1) == 1,
          "rows=%d" % len(after1))
    check("T24a distinct fingerprints == row count (no redundancy)",
          len({(r[1], r[2], r[3]) for r in after2}) == len(after2),
          "rows=%d distinct=%d" % (len(after2),
                                   len({(r[1], r[2], r[3]) for r in after2})))
finally:
    shutil.rmtree(sb, ignore_errors=True)

# --- T24b: a DIFFERENT rejection still gets its own row ----------------------
sb, env = sandbox()
try:
    register_class(sb)
    f1 = failing_file(sb, "First distinct absent-quote claim alpha.",
                      "t24b1.json")
    run_ingest(sb, env, f1)
    n1 = len(open_rows(sb))
    f2 = failing_file(sb, "Second distinct absent-quote claim beta.",
                      "t24b2.json")
    run_ingest(sb, env, f2)
    rows = open_rows(sb)
    check("T24b a different rejection is NOT swallowed by the dedupe",
          len(rows) == n1 + 1, "before=%d after=%d" % (n1, len(rows)))
    check("T24b both claims are represented",
          len({r[2] for r in rows}) == 2,
          "claims=%s" % sorted({r[2][:28] for r in rows}))
finally:
    shutil.rmtree(sb, ignore_errors=True)

# --- T24c: --dry writes nothing ---------------------------------------------
sb, env = sandbox()
try:
    register_class(sb)
    f = failing_file(sb, "Dry run must not leave a dispute behind.",
                     "t24c.json")
    run_ingest(sb, env, f, dry=True)
    check("T24c --dry writes no conflict row", len(open_rows(sb)) == 0,
          "rows=%d" % len(open_rows(sb)))
finally:
    shutil.rmtree(sb, ignore_errors=True)

# --- negative control: the dedupe must not suppress the rejection REPORT -----
print("T24 negative control (the reject is still reported to the caller)")
sb, env = sandbox()
try:
    register_class(sb)
    f = failing_file(sb, "Reported as rejected even though deduped.",
                     "t24d.json")
    out1 = run_ingest(sb, env, f)
    out2 = run_ingest(sb, env, f)
    r1 = "rejected=1" in out1
    r2 = "rejected=1" in out2
    check("T24d repeat run still REPORTS the rejection", r1 and r2,
          "first=%s second=%s" % (r1, r2))
    check("T24d reporting twice while storing one row is the intended behaviour",
          len(open_rows(sb)) == 1, "rows=%d" % len(open_rows(sb)))
finally:
    shutil.rmtree(sb, ignore_errors=True)

bad = [n for n, ok in results if not ok]
print("\n%d/%d checks pass" % (len(results) - len(bad), len(results)))
if bad:
    print("FAILED: %s" % bad)
    raise SystemExit(1)
print("T24 OK")