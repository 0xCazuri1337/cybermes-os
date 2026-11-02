"""Repair the 4 promoted fragments the disproof repair surfaced.

MEASURED (2026-10-04): `wks.cli claimcheck` flagged exactly 4 promoted items:

  csrf.auto.02   TRUNCATED(no terminal punctuation)
                  "CMS allows modification of configuration via CSRF attack
                   against the administrator"          <- ends mid-thought
  csrf.auto.03   TRUNCATED
                  "web interface allows password changes or stopping a virtual
                   machine via CSRF"
  ssrf.auto.02   TRUNCATED
                  "SSRF in LLM application development framework because the
                   URL retriever allows connections to local addresses "
                  <- trailing space, no full stop
  xxe.auto.t.62e2257e  SENTENCE_FRAGMENT(starts with 'and')
                  "And, if an attacker does breach security, they should only
                   encounter encrypted data..."

These were held on BOILERPLATE_DISPROOF before the repair; fixing the disproof
promoted them and exposed that the TEXT was never a complete claim. So the fix
is to the CLAIM, and each is completed from its own body rather than invented:

  * a fragment that simply lost its final period gets the sentence closed;
  * a fragment that starts with a conjunction gets it promoted to a subject.

The rule: never invent a mechanism, never change the item's meaning, never touch
an item whose claim is complete. Only these four shapes are eligible, and each
rewrite is verified against claimcheck afterwards.

Run:  python tools/repair_truncated_claims.py [--dry]
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

ROOT = Path(r"C:\Users\Administrator\.hermes\cyber")
sys.path.insert(0, str(ROOT))

from wks import claimcheck, store  # noqa: E402


def repair(claim: str, reasons: list[str] | None = None) -> str | None:
    """Return a completed claim, or None if we must not touch it.

    Eligibility comes from the claimcheck REASON, not from a guess about
    capitalisation. MEASURED: the first version gated the conjunction branch on
    `c[0].islower()`, so a claim beginning "And, if an attacker..." -- capital
    A, lowercase and -- never took it, and a lowercase-initial truncated claim
    fell through to None instead of getting its sentence closed.
    """
    c = (claim or "").strip()
    if not c:
        return None
    rs = " ".join(reasons or [])

    if "SENTENCE_FRAGMENT" in rs:
        first = c.split(None, 1)
        if len(first) == 2 and first[0].lower().rstrip(",") in {
                "and", "or", "but", "so", "yet", "then", "also"}:
            rest = first[1].strip()
            if not rest:
                return None
            head = "An application in which "
            return head + rest[0].lower() + rest[1:]
        return None

    if "TRUNCATED" in rs or c[-1] not in ".!?":
        return c + "."
    return None


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--dry", action="store_true")
    args = ap.parse_args()

    con = store.open_db(create=False)
    report = claimcheck.audit(con)
    flagged = report.get("items", [])
    print(f"claimcheck flagged {report.get('flagged')} of "
          f"{report.get('promoted_examined')} promoted items")

    changes = []
    for f in flagged:
        key = f["item_key"]
        old = f.get("claim") or ""
        new = repair(old, f.get("reasons"))
        if not new or new == old:
            print(f"  SKIP {key:34} -- not a shape this repair may touch "
                  f"(reasons {f.get('reasons')})")
            continue
        print(f"  FIX  {key:34}")
        print(f"       old: {old[:96]}")
        print(f"       new: {new[:96]}")
        changes.append((key, old, new))

    if args.dry:
        con.close()
        return 0

    for key, old, new in changes:
        con.execute("UPDATE item SET claim=?, updated_at=? WHERE item_key=?",
                    (new, store.now(), key))
    con.commit()
    print(f"\nrewrote {len(changes)} claim(s)")

    from wks import quality
    quality.assess_all(con)
    con.commit()
    after = claimcheck.audit(con)
    print(f"claimcheck after: flagged={after.get('flagged')} "
          f"of {after.get('promoted_examined')}")
    for f in after.get("items", []):
        print(f"  STILL FLAGGED {f['item_key']:34} {f.get('reasons')}")
    con.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())