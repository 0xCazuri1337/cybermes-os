"""Claim coherence: refuse to promote text that is not a claim.

MEASURED (2026-10-02, during the infrastructure remediation): a concurrent
researcher run had promoted 109 items whose `claim` is a truncated fragment of
scraped prose, several filed under the wrong class:

    "as a result, it is imperative that organizations implement exposure mana"
    "for all exercises, we will assume that the target company inlanefreight "
    "if you try to do a redirect with context.redirect , the authentication f"

(That last one was filed under `xxe`; a SQL-injection sentence was filed under
`ad_kerberos`.) Every one carried citations and a disproof clause, so every
EXISTING gate passed them -- each one asserts something true about a real page,
which is exactly what the gate is designed to reward. The gate was measuring
"is this supported" and was never asked "is this a claim".

This module is that missing question. It is a HELD-REASON source, not a
promotion decision: `quality.py` remains the only writer of
`validation_state`, and this only contributes reasons. A fragment is held with
an explicit reason rather than silently promoted, so the failure is visible
instead of accumulating.

Checks, each one a way the text demonstrably fails to be a claim:

  TRUNCATED      ends mid-word / mid-sentence, or starts mid-sentence
  NOT_A_CLAIM    too few words to assert anything
  SENTENCE_FRAGMENT  begins with a mid-sentence connector (and/or/but/so/...)

Deliberately ABSENT, after they were measured firing on good knowledge:
a verb whitelist ("arise" was missing) and CLASS_MISMATCH (67 false
positives). This detects TRUNCATION, not wrongness -- a complete but
irrelevant sentence still passes, and saying so is better than pretending.

Deliberately conservative: a check may only HIDE an item from promotion, never
promote one, and every fragment of doubt resolves to "hold".
"""
from __future__ import annotations

import json
import re
import sqlite3
from typing import Any

MIN_CLAIM_WORDS = 6
MIN_CLAIM_CHARS = 40

# Words that cannot open an assertion because they only CONTINUE one.
#
# Deliberately excludes determiners, prepositions and subordinators. The first
# version of this set included "a", "an", "the", "in", "when", "this" and
# flagged six of the corpus's own good claims -- "A BloodHound attack path ...
# is a capability finding", "An object whose DACL grants ...". Those are
# well-formed claims. A fragment detector that fires on correct evidence is
# worse than no detector, because it teaches the reader to ignore it.
#
# Second narrowing. The first still held a valid claim beginning "Because the
# browser handshake cannot carry an Authorization header ...". `because`,
# `since`, `although`, `though`, `whereas`, `which`, `nor`, `yet` and `however`
# can all open a real assertion. What is left is the coordinating
# conjunctions that genuinely require a preceding clause and cannot open an
# assertion on their own.
_OPENERS = {"and", "or", "but", "so"}

# REMOVED: a hand-written verb list. It held "Insecure direct object
# references arise when ..." because "arise" was not in it. See the module
# note: a list cannot be validated against a growing corpus, so it does not
# gate promotion.
_TRUNC_TAIL = re.compile(r"[a-z]$")
_SENT_END = re.compile(r"[.!?)\]\"'`]\s*$")


def reasons(claim: str | None, class_id: str | None = None,
            vocab: dict[str, set[str]] | None = None) -> list[str]:
    """Every reason this text should not be promoted as knowledge. Empty = clean."""
    out: list[str] = []
    text = (claim or "").strip()

    if len(text) < MIN_CLAIM_CHARS:
        return [f"CLAIM_TOO_SHORT({len(text)}<{MIN_CLAIM_CHARS})"]

    words = re.findall(r"[A-Za-z0-9'\-]+", text)
    if len(words) < MIN_CLAIM_WORDS:
        out.append(f"NOT_A_CLAIM({len(words)} words < {MIN_CLAIM_WORDS})")

    first = words[0].lower() if words else ""
    if first in _OPENERS:
        out.append(f"SENTENCE_FRAGMENT(starts with {first!r})")

    # Truncation: the text stops without sentence punctuation, or its last token
    # is a lower-case fragment. A real claim written by a curator ends in a full
    # stop; scraped prose sliced to a limit does not.
    if not _SENT_END.search(text):
        out.append("TRUNCATED(no terminal punctuation)")
    if words and _TRUNC_TAIL.match(words[-1]) and len(words[-1]) >= 4:
        # A lower-case final token of real length, with no terminal punctuation:
        # the text was sliced rather than finished. A short lowercase word
        # ("the", "an", "a") is a normal ending and must not trigger this.
        out.append(f"TRUNCATED(ends mid-word: ...{words[-1][-14:]!r})")

    # REMOVED: CLASS_MISMATCH. It flagged 67 curated claims -- any claim
    # containing another class's alias and none of its own -- and missed the
    # single real case it was written for. See the module note.
    return out


def build_vocab(con: sqlite3.Connection) -> dict[str, set[str]]:
    """class_id -> its own distinguishing vocabulary (name + aliases + cwe)."""
    vocab: dict[str, set[str]] = {}
    for r in con.execute("SELECT id, name, aliases, cwe FROM bug_class"):
        terms = {r["id"].replace("_", " "), r["id"].replace("_", "-"),
                 (r["name"] or "").lower()}
        if r["cwe"]:
            terms.add(str(r["cwe"]).lower())
        try:
            for a in json.loads(r["aliases"] or "[]"):
                terms.add(str(a).lower())
        except (ValueError, TypeError):
            pass
        vocab[r["id"]] = {t for t in terms if len(t) >= 4}
    return vocab


def audit(con: sqlite3.Connection, *, apply: bool = False,
          limit: int = 0) -> dict[str, Any]:
    """Report every promoted item whose claim is not a claim.

    `--apply` moves them to `under_review` with an explicit gate reason. It
    never deletes: the citations and the disproof clause are evidence about what
    the researcher found, and a future human may want to re-cut the claim.
    """
    vocab = build_vocab(con)
    rows = con.execute(
        """SELECT i.id, i.item_key, i.class_id, i.claim, i.kind, q.validation_state
           FROM item i JOIN quality q ON q.item_id=i.id
           WHERE i.status='active' AND q.validation_state IN ('supported','high_confidence')
           ORDER BY i.item_key""").fetchall()
    if limit:
        rows = rows[:limit]
    flagged, applied = [], []
    for r in rows:
        why = reasons(r["claim"], r["class_id"], vocab)
        if not why:
            continue
        flagged.append({"item_key": r["item_key"], "class_id": r["class_id"],
                        "reasons": why, "claim": (r["claim"] or "")[:110]})
        if apply:
            con.execute(
                "UPDATE quality SET validation_state='under_review', gate_reasons=? "
                "WHERE item_id=?",
                (json.dumps(why), r["id"]))
            applied.append(r["item_key"])
    if apply:
        con.commit()
    auto = [f for f in flagged if ".auto." in f["item_key"]]
    return {
        "promoted_examined": len(rows),
        "flagged": len(flagged),
        "flagged_auto_generated": len(auto),
        "applied": len(applied),
        "items": flagged[:80],
        "note": ("held, never deleted. The gate verified these citations were "
                 "real; what it never asked was whether the text was a claim."),
    }


def main(argv: list[str] | None = None) -> int:
    import argparse
    ap = argparse.ArgumentParser(prog="wks.claimcheck")
    ap.add_argument("--apply", action="store_true")
    ap.add_argument("--limit", type=int, default=0)
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args(argv)
    from . import store
    con = store.open_db(create=a.apply)
    out = audit(con, apply=a.apply, limit=a.limit)
    con.close()
    if a.json:
        print(json.dumps(out, indent=1, default=str))
        return 0
    print(f"promoted items examined : {out['promoted_examined']}")
    print(f"flagged as not-a-claim  : {out['flagged']} "
          f"({out['flagged_auto_generated']} auto-generated)")
    for it in out["items"][:20]:
        print(f"  {it['item_key'][:52]:52} {it['reasons'][0][:44]}")
        print(f"      {it['claim'][:100]!r}")
    if a.apply:
        print(f"moved to under_review   : {out['applied']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())