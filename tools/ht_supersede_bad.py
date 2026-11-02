"""Supersede the 3 promoted items whose PARTNER citation does not re-verify.

Measured, and the reasoning matters: live re-verification of the 75 promoted
HackTricks items found 147/150 quotes verify. All 3 failures are the SAME
recycled OWASP partner quote, which carries heading furniture and therefore
cannot be re-verified against the live page.

These are NOT fabrications. Their HackTricks quote is verbatim, and the partner
quote was itself copied from an older corpus item the gate had already promoted.
But an unverifiable citation is not evidence, so the item cannot stand as
`high_confidence`. Invariant I8 says supersede, never delete.

It also records WHY, so the row is not silently lost and a later wave can
re-source the partner. Writes to quality.gate_reasons rather than inventing a
new state.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from wks import retrieval, store  # noqa: E402

TARGETS = [
    "xss.technique.ht_chrome_cache_to_xss_include",
    "xss.signal.ht_the_original_seccon_challenge_writ",
    "xss.signal.ht_chrome_has_changed_bfcache_eligibi",
]
REASON = ("UNVERIFIABLE_PARTNER: recycled partner quote carries heading "
          "furniture and does not re-verify against the live page; the "
          "HackTricks quote is verbatim but the second publisher is unusable. "
          "Needs a re-sourced partner.")


def main():
    con = store.connect()
    superseded, missing = 0, []
    for key in TARGETS:
        r = con.execute("SELECT id, status FROM item WHERE item_key=?",
                        (key,)).fetchone()
        if not r:
            missing.append(key)
            continue
        con.execute("UPDATE item SET status='superseded', updated_at=? WHERE id=?",
                    (store.now(), r["id"]))
        con.execute("UPDATE quality SET validation_state='under_review', "
                    "gate_reasons=? WHERE item_id=?",
                    (REASON, r["id"]))
        superseded += 1
    con.commit()
    retrieval.rebuild_index(con)

    print("superseded : %d" % superseded)
    for k in missing:
        print("  NOT FOUND : %s" % k)

    # ASSERT against the db, do not trust the count
    left = list(con.execute(
        "SELECT item_key FROM item WHERE item_key LIKE 'xss.%ht_chrome%'"
        "    OR item_key LIKE 'xss.signal.ht_the_original_seccon%'"
        "    OR item_key LIKE 'xss.signal.ht_chrome_has_changed%'"))
    bad = [dict(r) for r in left if r["item_key"] not in TARGETS]
    active = con.execute(
        "SELECT COUNT(*) FROM item WHERE status='active' AND item_key IN (%s)"
        % ",".join("?" * len(TARGETS)), TARGETS).fetchone()[0]
    print("still active of the 3 targets : %d (must be 0)" % active)
    assert active == 0, "supersede did not take effect"
    print("ASSERT OK")


if __name__ == "__main__":
    main()