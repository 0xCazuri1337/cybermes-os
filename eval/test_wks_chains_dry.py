#!/usr/bin/env python
"""T27: `chains.build_chain(dry=True)` must not leave rows behind.

MEASURED 2026-10-03, and it is a defect the green suite could not see:

    chains.chainable_classes(con, dry=True)   -> reported "created: 5"
    chains.chainable_classes(con, dry=False)  -> created: 0, and every class
                                                  came back "skipped"

Nothing reached DISK (the connection was never committed), so a fresh
connection still showed 71 chains -- which is exactly why this went unnoticed.
But inside ONE process the dry run's INSERTs were live on the connection, so
`chain_exists()` saw phantom `chain_step` rows and the real run skipped every
class while reporting success. **A dry run that poisons the run after it is
worse than no dry run**, because the damage is invisible and the caller's
verdict is a lie.

This test asserts the fix in BOTH directions:
  * the dry run writes NOTHING (chain / chain_step / chain_edge all unmoved),
  * a dry run does not poison a real run in the same process,
  * a real run after a dry run DOES create the chain (the pass case, so the fix
    cannot "pass" by simply disabling the dry path).
"""
from __future__ import annotations

import os
import sqlite3
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

FAILURES: list[str] = []


def check(cond: bool, label: str) -> None:
    print(f"  [{'PASS' if cond else 'FAIL'}] {label}")
    if not cond:
        FAILURES.append(label)


def _counts(con) -> tuple[int, int, int]:
    return tuple(
        con.execute(f"SELECT COUNT(*) FROM {t}").fetchone()[0]
        for t in ("chain", "chain_step", "chain_edge")
    )


def main() -> int:
    # A throwaway WKS_ROOT so we never write to the live corpus.
    sandbox = tempfile.mkdtemp(prefix="wks-t27-")
    os.environ["WKS_ROOT"] = sandbox
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

    from orch import chains
    from wks import config as wks_config

    # Build a minimal but REAL corpus: one class with >= 3 grounded items,
    # because `build_chain` refuses a class with fewer than 3 usable items.
    root = Path(sandbox)
    (root / "db").mkdir(parents=True, exist_ok=True)
    con = sqlite3.connect(str(root / "db" / "wks.db"))
    con.row_factory = sqlite3.Row
    con.executescript(
        """
        CREATE TABLE bug_class (id TEXT PRIMARY KEY, name TEXT, surface TEXT,
                                cwe TEXT, owasp TEXT, aliases TEXT,
                                summary TEXT, status TEXT, methodology TEXT,
                                skill_path TEXT, first_seen TEXT,
                                last_reviewed TEXT);
        CREATE TABLE item (id INTEGER PRIMARY KEY, item_key TEXT, class_id TEXT,
                           claim TEXT, kind TEXT, surface TEXT,
                           severity_hint TEXT, hunting_value INTEGER,
                           body TEXT, disproof TEXT, status TEXT,
                           created_at TEXT, updated_at TEXT, dedup_of INTEGER,
                           canonical_id INTEGER);
        CREATE TABLE chain (id INTEGER PRIMARY KEY, chain_key TEXT, name TEXT,
                            goal TEXT, summary TEXT, impact TEXT,
                            created_at TEXT, updated_at TEXT);
        CREATE TABLE chain_step (id INTEGER PRIMARY KEY, chain_id INTEGER,
                                 ord INTEGER, item_id INTEGER, class_id TEXT,
                                 action TEXT, why TEXT, needs TEXT);
        CREATE TABLE chain_edge (id INTEGER PRIMARY KEY, chain_id INTEGER,
                                 from_step INTEGER, to_step INTEGER,
                                 relation TEXT);
        CREATE TABLE quality (item_id INTEGER PRIMARY KEY,
                              validation_state TEXT, evidence_strength REAL,
                              reproducibility REAL, practical_usefulness REAL);
        """
    )
    con.execute(
        "INSERT INTO bug_class(id,name,surface,status) VALUES"
        " ('t27','T27 Probe','web','planned')"
    )
    for i in range(3):
        cur = con.execute(
            "INSERT INTO item(item_key,class_id,claim,kind,body,disproof,"
            "status,created_at,updated_at) VALUES (?,?,?,?,?,?,?,?,?)",
            (f"t27.item.{i}", "t27", f"claim {i}", "technique",
             f"body {i} " * 40, "would be refuted if the behaviour did not occur",
             "active", "2026-01-01T00:00:00+00:00", "2026-01-01T00:00:00+00:00"),
        )
        # `_best_items` only considers GATED items, so the fixture must carry
        # a quality row -- an item with no score is invisible to the builder,
        # which would make this fixture test the refusal path instead.
        con.execute(
            "INSERT INTO quality(item_id, validation_state, evidence_strength,"
            " reproducibility, practical_usefulness) VALUES (?,?,?,?,?)",
            (int(cur.lastrowid), "high_confidence", 0.8, 0.7, 0.6),
        )
    con.commit()

    print("T27 chains.dry must not write")
    before = _counts(con)

    dry = chains.build_chain(con, "t27", dry=True)
    check(dry is not None, "dry run returns a plan")
    check(dry.get("action") == "would_create",
          f"dry run reports 'would_create' not 'created' (got {dry.get('action')!r})")
    check(not chains.chain_exists(con, "t27"),
          "after a dry run, chain_exists() is still FALSE (no phantom rows)")

    after_dry = _counts(con)
    check(after_dry == before,
          f"dry run wrote nothing: chain/step/edge {before} -> {after_dry}")

    # The failure mode that motivated the test: a real run in the SAME process
    # after a dry run must still build the chain.
    real = chains.build_chain(con, "t27", dry=False)
    check(real is not None and real.get("action") == "created",
          f"a real run after a dry run still creates the chain "
          f"(got {real if real is None else real.get('action')!r})")

    after_real = _counts(con)
    check(after_real[0] == before[0] + 1, f"one new chain row ({after_real})")
    check(after_real[1] > before[1], f"chain_step rows written ({after_real})")
    check(chains.chain_exists(con, "t27"),
          "chain_exists() is TRUE only after a real run")

    # Control: the refusal path must still refuse, so the fix cannot "pass" by
    # short-circuiting the whole function.
    con.execute(
        "INSERT INTO bug_class(id,name,surface,status) VALUES"
        " ('t27thin','T27 Thin','web','planned')"
    )
    con.execute(
        "INSERT INTO item(item_key,class_id,claim,kind,body,disproof,status,"
        "created_at,updated_at) VALUES (?,?,?,?,?,?,?,?,?)",
        ("t27thin.item.0", "t27thin", "c", "technique", "b" * 400,
         "d", "active", "2026-01-01T00:00:00+00:00", "2026-01-01T00:00:00+00:00"),
    )
    con.commit()
    thin = chains.build_chain(con, "t27thin", dry=True)
    check(thin is not None and thin.get("action") == "refused",
          f"a class with <3 grounded items is still REFUSED in dry mode "
          f"(got {thin if thin is None else thin.get('action')!r})")

    con.close()
    print(f"\n{'ALL PASS' if not FAILURES else str(len(FAILURES)) + ' FAILED'}")
    for f in FAILURES:
        print(f"  - {f}")
    return 1 if FAILURES else 0


if __name__ == "__main__":
    raise SystemExit(main())
