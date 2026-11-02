"""C3 — the class-selection path must select the RIGHT classes from a target,
and must refuse when it cannot.

Why this test exists
--------------------
The session GOAL requires choosing the correct vulnerability classes from target
observations alone, before any request is sent. MEASURED baseline (2026-10-03):

  * `orch.hypothesis.classify_behaviour` is CORRECT for the 20 classes it
    declares: 8/8 probe cases classified right, including two it correctly
    REFUSED (a novel behaviour, and a csrf/csrf_bypass tie) rather than guessing.
  * But it can name only 15 of the 70 registered corpus classes. Five of its
    keys (`auth`, `business_logic`, `csrf_bypass`, `nosqli`,
    `request_smuggling`) are NOT registered classes at all, so it can return a
    class id for which no page, chain, skill or methodology exists.
  * 55 corpus classes are unselectable by observation, and nothing in
    `metrics`, `gaps` or the masterprompt score reports any of that.

So the gate this test enforces is deliberately two-sided:

  T1  every declared signature's signal set selects that class   (the PASS path)
  T2  a deliberately WRONG signal set does NOT select the class  (the FAIL path,
      so the check cannot be satisfied by disabling matching)
  T3  every key in SIGNATURES names a REGISTERED corpus class    (kills the
      phantom-key class of defect)
  T4  every corpus class is either selectable OR on an explicit,
      reviewed allowlist with a stated reason                   (kills the
      invisible-coverage class of defect)
  T5  an ambiguous tie is reported UNKNOWN and never resolved by
      iteration order                                         (§30)

Read-only. Exit 0 only when every assertion holds.
Run:  python eval/test_hunt_classification.py
"""
from __future__ import annotations

import os
import sqlite3
import sys

WKS = os.environ.get("WKS_ROOT", ".")
sys.path.insert(0, WKS)
os.chdir(WKS)

from orch import hypothesis as hyp  # noqa: E402

FAILS: list[str] = []
PASSES = 0


def check(cond: bool, label: str, detail: str = "") -> None:
    global PASSES
    if cond:
        PASSES += 1
        print(f"  [PASS] {label}")
    else:
        print(f"  [FAIL] {label}" + (f"\n         {detail}" if detail else ""))
        FAILS.append(label)


con = sqlite3.connect(f"{WKS}/db/wks.db")
registered = {r[0] for r in con.execute("SELECT id FROM bug_class")}

print("T1  every declared signature selects its own class")
for cid, spec in sorted(hyp.SIGNATURES.items()):
    signals = list(spec["all"]) + [spec["any"][0]]
    r = hyp.classify_behaviour(signals)
    check(r["classification"] == cid,
          f"{cid:20} -> {r['classification']}",
          f"signal set {signals} selected {r['classification']} "
          f"({r.get('reason', '')})")

print()
print("T2  a WRONG signal set does not select the class")
# One signal from a DIFFERENT class must never select the target class.
for cid, spec in sorted(hyp.SIGNATURES.items()):
    foreign = hyp.SIGNATURES["deser"]["all"][0]  # a signal unique to deser
    if foreign in spec["all"] or foreign in spec["any"]:
        continue
    r = hyp.classify_behaviour(list(spec["all"]) + [foreign])
    check(r["classification"] != cid,
          f"{cid:20} refuses a foreign signal",
          f"a foreign signal still selected {cid}")

print()
print("T3  every SIGNATURES key names a REGISTERED class")
for cid in sorted(hyp.SIGNATURES):
    if cid in registered:
        PASSES += 1
        print(f"  [PASS] {cid:20} is a registered corpus class")
    else:
        print(f"  [FAIL] {cid:20} is NOT a registered corpus class "
              f"-- classify_behaviour can return a class with no page, "
              f"chain, skill or methodology")
        FAILS.append(f"phantom signature key: {cid}")

print()
print("T4  unselectable classes are explicit and reviewed, not invisible")
unselectable = sorted(registered - set(hyp.SIGNATURES))
allow_path = os.path.join(WKS, "orch", "classification_allowlist.py")
allow: dict[str, str] = {}
if os.path.exists(allow_path):
    sys.path.insert(0, os.path.join(WKS, "orch"))
    from classification_allowlist import ALLOWLIST  # type: ignore
    allow = dict(ALLOWLIST)
unaccounted = [c for c in unselectable if c not in allow]
if not unaccounted:
    print(f"  [PASS] every unselectable class ({len(unselectable)}) has a "
          f"stated reason on the allowlist")
else:
    print(f"  [FAIL] {len(unaccounted)} unselectable classes have NO stated "
          f"reason -- the coverage gap is invisible in every existing metric:")
    print("         " + ", ".join(unaccounted[:20]))
    FAILS.append("unaccounted unselectable classes")
stale_allow = [c for c in allow if c not in registered]
check(not stale_allow, "allowlist names no retired class",
      f"stale entries: {stale_allow}")

print()
print("T5  an ambiguous tie is UNKNOWN, never resolved by iteration order")
# MEASURED: the original tie here was csrf vs csrf_bypass. Merging the phantom
# `csrf_bypass` key into `csrf` (T3) legitimately removed that tie, and no two
# signatures now share an `all` signal, so a natural tie can no longer be built
# from the live table. Asserting the old tie would assert a bug FIX as a defect.
#
# So the PROPERTY is tested with a synthetic tie injected into SIGNATURES and
# removed again in a `finally` -- the refusal must hold for ANY tie, not only for
# one that happens to exist in today's data. The second assertion is the control:
# with one candidate removed the same signals resolve cleanly, so this check
# cannot pass by simply refusing everything.
_A, _B, _SHARED = "__w13_tie_a__", "__w13_tie_b__", "__w13_tie_shared__"
_SIG = hyp.SIGNATURES
_before = len(_SIG)
_SIG[_A] = {"all": [_SHARED], "any": ["__w13_only_a__"]}
_SIG[_B] = {"all": [_SHARED], "any": ["__w13_only_b__"]}
try:
    tie = hyp.classify_behaviour([_SHARED, "__w13_only_a__", "__w13_only_b__"])
    check(tie["classification"] == "UNKNOWN", "equal-support tie refused",
          f"resolved to {tie['classification']} instead of refusing")
    check(set(tie.get("matched", [])) >= {_A, _B},
          "the tie names BOTH candidates", f"matched={tie.get('matched')}")
    del _SIG[_B]
    clear = hyp.classify_behaviour([_SHARED, "__w13_only_a__"])
    check(clear["classification"] == _A,
          "unambiguous set resolves (tie check is not over-refusing)",
          f"got {clear['classification']}")
finally:
    _SIG.pop(_A, None)
    _SIG.pop(_B, None)
check(len(_SIG) == _before, "SIGNATURES restored after the probe",
      f"{len(_SIG)} keys remain, expected {_before}")

novel = hyp.classify_behaviour(["novel_response_shape"])
check(novel["classification"] == "UNKNOWN",
      "a novel behaviour is UNKNOWN",
      f"guessed {novel['classification']}")

print()
print("=" * 78)
if FAILS:
    print(f"C3 CLASSIFICATION: FAIL — {len(FAILS)} of {PASSES + len(FAILS)} "
          f"assertions failed")
    for f in FAILS:
        print("  -", f)
    sys.exit(1)
print(f"C3 CLASSIFICATION: PASS — {PASSES} assertions. "
      f"{len(registered)} classes registered, "
      f"{len(set(hyp.SIGNATURES) & registered)} selectable by observation, "
      f"{len(unselectable)} on an explicit allowlist.")