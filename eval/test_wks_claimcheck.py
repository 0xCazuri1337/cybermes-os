"""Claim-coherence checker, validated in BOTH directions.

A verdict is worth nothing until the checker has been shown to pass genuine
material AND fail fabricated material. Six real claims from this corpus are the
positive controls; six measured fragments are the negative controls.

Run: python eval/test_wks_claimcheck.py
"""
from __future__ import annotations

import sqlite3
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from wks import claimcheck as CC, store  # noqa: E402

FAILURES: list[str] = []
PASSES: list[str] = []


def check(label: str, cond: bool, detail: str = "", *, pass_detail: str = "") -> None:
    if cond:
        PASSES.append(label)
        print(f"  [PASS] {label}" + (f"  -- {pass_detail}" if pass_detail else ""))
    else:
        FAILURES.append(f"{label}: {detail}")
        print(f"  [FAIL] {label}  -- {detail}")


# ---- POSITIVE controls: real, curated claims from this corpus -------------
GOOD = [
    "A BloodHound attack path or AdminTo-style edge is a capability finding and "
    "not an exploitation finding until a principal is controlled.",
    "An object whose DACL grants a low-privilege principal WRITE_DAC, "
    "WRITE_OWNER or a generic write right is writable, and a writable object is "
    "a takeover primitive rather than a vulnerability on its own.",
    "When a write-capable principal can set msDS-AllowedToDelegateTo on a host "
    "or service account, the attacker can request a service ticket for any "
    "principal to the listed SPN and present it to that resource.",
    "The first request of a cross-site request forgery attack must prove that a "
    "state-changing endpoint accepts a session cookie with no token.",
    "An unconstrained-delegation host that a domain controller authenticates to "
    "exposes the controller's service ticket to interception.",
    "Insecure direct object references arise when an application uses "
    "user-supplied input to access objects directly instead of enforcing "
    "authorization per object.",
    # Two regressions this suite actually caught. Both are valid claims that a
    # broader SENTENCE_FRAGMENT held: one for starting with "A", one for
    # starting with "Because".
    "Because the browser handshake cannot carry an Authorization header, a "
    "WebSocket endpoint is only authenticable through a subprotocol or a "
    "connection cookie.",
    "A cross-site request forgery against a JSON API is only reportable when "
    "the state-changing endpoint sets no SameSite cookie attribute.",
]


def t_positive_controls() -> None:
    print("T38 POSITIVE: real curated claims must PASS the checker")
    con = store.open_db(create=False)
    vocab = CC.build_vocab(con)
    con.close()
    for claim in GOOD:
        why = CC.reasons(claim, "idor", vocab)
        check(f"clean claim passes: {claim[:46]!r}", not why, str(why))
    # determiners and subordinators must never trip the fragment check
    for opener in ("A ", "An ", "The ", "When ", "If ", "This ", "For ",
                   "Because ", "Since ", "Although ", "However ", "Whereas "):
        c = opener + "value is set by the server and reused on the next request " \
                     "without any integrity check being applied."
        why = CC.reasons(c, "idor", vocab)
        check(f"opener {opener.strip()!r} is allowed", not why, str(why))


# ---- NEGATIVE controls: the measured fragments ---------------------------
BAD = [
    ("as a result, it is imperative that organizations implement exposure mana",
     "TRUNCATED"),
    ("for all exercises, we will assume that the target company inlanefreight ",
     "TRUNCATED"),
    ("if you try to do a redirect with context.redirect , the authentication f",
     "TRUNCATED"),
    ("missing authentication lets anyone proxy requests unauthenticated, and a",
     "TRUNCATED"),
    ("a", "TOO_SHORT"),
    ("", "TOO_SHORT"),
]


def t_negative_controls() -> None:
    print("T38 NEGATIVE: the measured fragments must FAIL the checker")
    con = store.open_db(create=False)
    vocab = CC.build_vocab(con)
    con.close()
    for text, expect in BAD:
        why = CC.reasons(text, "idor", vocab)
        check(f"fragment is held: {text[:40]!r}", bool(why), "accepted a fragment")
        check(f"  reason mentions {expect}",
              any(expect.split("(")[0] in w for w in why), str(why))


def t_unreliable_checks_absent() -> None:
    """The two checks that fired on good knowledge must STAY OUT.

    Both were measured: CLASS_MISMATCH produced 67 false positives on curated
    claims, and the verb whitelist held a valid claim for using "arise". They
    are removed, and this asserts they stay removed -- re-adding either without
    a both-directions validation is how a gate becomes decoration.
    """
    print("T38 unreliable checks stay ABSENT (measured 67 false positives)")
    con = store.open_db(create=False)
    vocab = CC.build_vocab(con)
    con.close()
    # A claim using "arise" must pass: it did not before.
    arise = ("Insecure direct object references arise when an application uses "
             "user-supplied input to access objects directly.")
    why = CC.reasons(arise, "idor", vocab)
    check("a claim using 'arise' is NOT held for a missing verb",
          not any("no verb" in w for w in why), str(why))
    # A CSRF claim mentioning 'session' must pass: CLASS_MISMATCH killed it.
    csrf = ("The first request of a cross-site request forgery attack must "
            "prove that a state-changing endpoint accepts a session cookie "
            "with no token.")
    why2 = CC.reasons(csrf, "csrf", vocab)
    check("a CSRF claim mentioning 'session' is NOT held for class mismatch",
          not why2, str(why2))
    src = (Path(ROOT) / "wks" / "claimcheck.py").read_text(encoding="utf-8")
    check("CLASS_MISMATCH is not in the source", "CLASS_MISMATCH(" not in src)
    check("the verb whitelist is not in the source", "_VERBS" not in src)


def _catches_fragment() -> bool:
    """Does the checker STILL hold a known fragment right now?

    This is a capability probe, not a corpus census. Asserting only "no
    truncated items remain" would pass just as happily against a checker that
    had stopped working entirely -- the exact state this suite exists to
    prevent. So it drives a real, measured fragment through the live checker and
    requires a hold reason back.
    """
    con = store.open_db(create=False)
    vocab = CC.build_vocab(con)
    con.close()
    why = CC.reasons(
        "the response body differs from the not-found case and the caller "
        "learned",                      # no terminal punctuation: a fragment
        "idor", vocab)
    return any("TRUNCATED" in w for w in why)


def t_live_corpus() -> None:
    print("T38 live corpus: the checker must not flag curated knowledge")
    con = store.open_db(create=False)
    out = CC.audit(con, apply=False)
    con.close()
    curated = [f for f in out["items"] if ".auto." not in f["item_key"]]
    check("few curated claims are flagged (false-positive budget)",
          len(curated) <= 2,
          f"{len(curated)} curated flagged: {[c['item_key'] for c in curated][:5]}")

    # A fragment must be CAUGHT. That capability is proven by the negative
    # controls above (t_negative_controls), which drive real fragments through
    # the checker and require TRUNCATED/TOO_SHORT back.
    #
    # What this section asserts about the LIVE corpus is the invariant that
    # actually matters: NO ACTIVE item is currently truncated. It used to
    # require that flagged/held `.auto.` fragments EXIST -- which fails the
    # moment the corpus is repaired, i.e. the test went red as a direct result
    # of fixing the defect it was written to catch. A repair must be able to
    # turn a gate green. This assertion still goes red if any active claim
    # regresses to a fragment.
    con2 = store.open_db(create=False)
    held_truncated = {
        r["item_key"] for r in con2.execute(
            """SELECT i.item_key FROM quality q JOIN item i ON i.id=q.item_id
               WHERE q.validation_state='under_review'
                 AND q.gate_reasons LIKE '%TRUNCATED%'""")}
    con2.close()
    flagged_auto = {f["item_key"] for f in out["items"] if ".auto." in f["item_key"]}
    active_truncated = {f["item_key"] for f in out["items"]}
    check("no ACTIVE claim is a truncated fragment",
          not active_truncated,
          f"{len(active_truncated)} truncated: {list(active_truncated)[:5]}")
    check("the checker CAN catch a fragment (capability, not corpus state)",
          _catches_fragment(),
          "checker no longer holds a known fragment")
    check("no curated claim is held for TRUNCATED (false-positive budget)",
          not [k for k in held_truncated if ".auto." not in k],
          f"{[k for k in held_truncated if '.auto.' not in k][:5]}")
    print(f"        examined={out['promoted_examined']} "
          f"flagged_now={out['flagged']} (auto={out['flagged_auto_generated']}) "
          f"already_held={len(held_truncated)}")


def main() -> int:
    for fn in (t_positive_controls, t_negative_controls,
               t_unreliable_checks_absent, t_live_corpus):
        try:
            fn()
        except Exception as e:
            FAILURES.append(f"{fn.__name__} raised {e}")
            print(f"  [ERROR] {fn.__name__}: {type(e).__name__}: {e}")
    print(f"\n{len(PASSES)} passed, {len(FAILURES)} failed")
    for f in FAILURES:
        print(f"  FAILED: {f}")
    return 1 if FAILURES else 0


if __name__ == "__main__":
    raise SystemExit(main())