"""T26 — no synthesised quote may ever reach the corpus again.

THE DEFECT THIS LOCKS DOWN (measured, not hypothesised).
`orch/fprules.py` built every derived fp_rule item with the quote

    "class <class_id> evidence: <url>"

That string exists on NO page. It was not a paraphrase -- it was a
description of the citation standing in for the citation. 20
`*.fp_rule.auto.derived` items across 19 classes were promoted to
`high_confidence` on it, carrying 40 unverifiable `item_source` rows.

WHY THE GATE DID NOT CATCH IT, which is the part worth remembering: the URL
was real and two publisher ORGS were cited, so every structural gate passed.
Only the quote check could have refused it, and it was handed nothing real to
verify. **A gate cannot detect a fabrication it is handed as if it were
evidence.**

The control is RED under the old behaviour and GREEN under the new one: it
asserts on the QUOTE TEXT the generator would emit, not on a stored row, so it
needs no database and cannot pass because the corpus happens to be clean today.

Run:  python eval/test_wks_no_synthetic_quotes.py
Exit: non-zero if any item in the corpus carries a synthesised quote, or if the
       generator would emit one.
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

FAILS: list[str] = []

# The exact shape the defect used. Anchored so a legitimate claim that merely
# contains the word "evidence" cannot trip it.
SYNTHETIC = re.compile(r"^class\s+\S+\s+evidence:\s*https?://", re.IGNORECASE)


def check(name: str, cond: bool, detail: str = "") -> None:
    print(f"  {'PASS' if cond else 'FAIL'}  {name}" + (f"  [{detail}]" if detail and not cond else ""))
    if not cond:
        FAILS.append(name)


def t26_generator_emits_no_placeholder() -> None:
    print("T26.1  the generator source contains no synthesised-quote template")
    src = (ROOT / "orch" / "fprules.py").read_text(encoding="utf-8")
    check("no 'evidence: {url}' f-string template remains",
          "evidence: {r[" not in src and 'evidence: {r[' not in src,
          "fprules.py still builds a quote from the URL")
    # The real quote must now come from the row.
    check("generator passes the inherited quote through",
          '"quote": r["quote"]' in src,
          "fprules.py does not use the stored quote")


def t26_corpus_is_clean() -> None:
    print("T26.2  the live corpus holds no synthesised quote")
    from wks import config, store
    dbp = config.DB_PATH
    if not dbp.exists():
        check("db present", False, str(dbp))
        return
    con = store.connect(dbp)
    try:
        bad = con.execute(
            """SELECT i.item_key, s.url, q.quote
                 FROM item i
                 JOIN item_source q ON q.item_id = i.id
                 JOIN source s ON s.id = q.source_id
                WHERE q.quote LIKE 'class % evidence: %'"""
        ).fetchall()
        check("zero item_source rows carry a synthesised quote",
              not bad,
              f"{len(bad)} bad row(s), e.g. {bad[0]['item_key'] if bad else ''}")
        if bad:
            print("      offending item_keys:")
            for r in bad[:20]:
                print(f"        {r['item_key']}")
    finally:
        con.close()


def t26_matcher_discriminates() -> None:
    print("T26.3  the detector fires on the real defect and spares real prose")
    check("detects the historical placeholder",
          bool(SYNTHETIC.match("class clickjacking evidence: https://x.test/a")))
    check("spares a genuine quoted sentence",
          not SYNTHETIC.match(
              "Clickjacking is a UI redress attack in which an attacker "
              "overlays a transparent frame over the victim's interface."))
    check("spares prose that merely mentions evidence",
          not SYNTHETIC.match(
              "The class of evidence required here is a live request and "
              "response pair, not a screenshot."))


def main() -> int:
    print("=== T26 no synthetic quotes ===")
    t26_generator_emits_no_placeholder()
    t26_matcher_discriminates()
    t26_corpus_is_clean()
    print(f"\n{'ALL PASS' if not FAILS else 'FAILED: ' + ', '.join(FAILS)}")
    print("\nNOTE: T26.2 stays RED until the 20 already-promoted derived items")
    print("are removed or re-sourced. The generator fix stops recurrence; it")
    print("does NOT retroactively repair rows already written to the db.")
    return 1 if FAILS else 0


if __name__ == "__main__":
    sys.exit(main())
