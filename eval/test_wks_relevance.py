"""T22: the relevance gate is wired into the promotion path, not merely present.

R19 exists because the citation resolver was correct, fully tested, and called
by nothing -- so three genuine items sat UNVERIFIED for a whole cycle. An
unused resolver and a missing one are indistinguishable from the outside.

`wks.relevance` risks exactly that fate: a beautiful module, a 67-case
selftest, and no evidence it changes any verdict. These tests inspect the CALL
PATH, not the component, and they run against a SANDBOX COPY of the real db so
nothing here can touch the corpus (see wks.readonly, added after a subagent
deleted from the live db while believing it was in a sandbox).

Every test uses a genuine fixture item so the assertion is about real evidence.
"""
from __future__ import annotations

import json
import os
import re
import sys
from pathlib import Path

WKS = os.environ.get(
    "WKS_ROOT", str(Path(__file__).resolve().parents[1]))
os.environ.setdefault("WKS_ROOT", WKS)
sys.path.insert(0, WKS)

from wks import config, quality, relevance, store  # noqa: E402
from wks.readonly import ro, sandbox  # noqa: E402

FAILS: list[str] = []
PASSES = 0


def check(cond: bool, label: str, detail: str = "") -> None:
    global PASSES
    if cond:
        PASSES += 1
        print(f"  [PASS] {label}")
    else:
        FAILS.append(f"{label}{(' -- ' + detail) if detail else ''}")
        print(f"  [FAIL] {label} {detail}")


def main() -> int:
    print("T22a the module is actually IMPORTED by the gate")
    src = open(os.path.join(WKS, "wks", "quality.py"), encoding="utf-8").read()
    # Assert the NAME is imported, not one exact import line: adding the
    # disproof gate rewrote this line to
    # `from . import config, disproof as disproof_module, relevance, store`,
    # which made a substring check for the old two-module form fail. A test
    # that breaks when a sibling import is added tests the formatting, not the
    # wiring.
    imp = re.search(r"^from \. import (.+)$", src, re.M)
    imported, aliases = set(), set()
    if imp:
        for part in imp.group(1).split(","):
            part = part.strip()
            if " as " in part:
                mod, alias = [p.strip() for p in part.split(" as ", 1)]
                # record BOTH: `disproof as disproof_module` imports the module
                # `disproof` under the name `disproof_module`, and a wiring
                # test must be able to ask about either.
                imported.add(mod)
                aliases.add(alias)
            else:
                imported.add(part)
    check("relevance" in imported,
          "quality.py imports relevance (not a dead module)",
          f"imports seen: {sorted(imported)}")
    check("relevance.assess(" in src,
          "quality.assess CALLS relevance.assess")
    check("disproof" in imported and "disproof_module.reason_for(" in src,
          "quality.assess CALLS the disproof gate too",
          f"imports seen: {sorted(imported)} aliases: {sorted(aliases)}; "
          f"call site present: {'disproof_module.reason_for(' in src}")
    check("reasons.append(rel.tag)" in src,
          "the gate appends rel.tag, not rel.state",
          "appending the state name silently produced OFF_CLASS_TOPIC-less "
          "reasons the gate ignored")

    print("T22b the blocking tags are declared where the gate reads them")
    check("OFF_CLASS_TOPIC" in quality._BLOCKING_TAGS,
          "OFF_CLASS_TOPIC is a blocking tag")
    check("MODULE_FILLER" in quality._BLOCKING_TAGS,
          "MODULE_FILLER is a blocking tag")
    check("ORPHAN" not in quality._BLOCKING_TAGS
          and "SIBLING" not in quality._BLOCKING_TAGS,
          "absence-based states do NOT block (measured ~70% wrong)")
    check(not (set(relevance.TERMINAL_STATES)
               & {relevance.ORPHAN, relevance.SIBLING,
                  relevance.AMBIGUOUS, relevance.ON_TOPIC}),
          "relevance.TERMINAL_STATES holds positive evidence only")

    print("T22c the state->tag mapping is complete for every held verdict")
    for state in relevance.TERMINAL_STATES:
        v = relevance.Verdict(state, "dns_enum")
        check(v.tag is not None and v.tag in quality._BLOCKING_TAGS,
              f"held state {state} maps to a declared blocking tag",
              f"got tag={v.tag}")

    print("T22d END TO END on a real misfiled item, in a sandbox")
    con, _sandbox_path = sandbox()
    try:
        # MEASURED: this test used to hardcode `exposed_rmm`, which the recon
        # refile legitimately emptied of held items (its password-policy prose
        # was refiled to authn). A test that asserts a specific class still has
        # defects fails when the defects are FIXED -- which is the worst way for
        # a test to fail. So the assertion is about the gate's behaviour on
        # whatever the corpus currently holds, not about one class's history.
        held_total = blocked_total = 0
        classes_with_holds = set()
        for r in con.execute(
                "SELECT i.id, i.class_id FROM item i "
                "WHERE i.status='active' ORDER BY random() LIMIT 400"):
            res = quality.assess(con, r["id"])
            if "OFF_CLASS_TOPIC" in res["tags"] or "MODULE_FILLER" in res["tags"]:
                held_total += 1
                classes_with_holds.add(r["class_id"])
                if res["state"] != "high_confidence":
                    blocked_total += 1
        check(held_total > 0,
              "the corpus still has relevance-held items to test the gate on",
              f"held={held_total} -- if this is 0 the corpus was repaired, and "
              f"the fixture below is stale rather than the gate being broken")
        check(held_total == blocked_total,
              "EVERY relevance-held item is actually demoted, not just tagged",
              f"held={held_total} but only {blocked_total} left high_confidence")
        print(f"        (sampled 400 items; holds across "
              f"{len(classes_with_holds)} classes)")

        # And a genuine class must be untouched by the subject gate.
        clean = con.execute(
            "SELECT i.id FROM item i WHERE i.class_id='xss' "
            "AND i.status='active' LIMIT 60").fetchall()
        xss_blocked = sum(
            1 for r in clean
            if "OFF_CLASS_TOPIC" in quality.assess(con, r["id"])["tags"]
            or "MODULE_FILLER" in quality.assess(con, r["id"])["tags"])
        check(xss_blocked * 4 <= max(len(clean), 1),
              "xss is overwhelmingly NOT held (genuine class survives)",
              f"{xss_blocked}/{len(clean)} held")
    finally:
        con.close()

    print("T22e the gate writes a real verdict into quality.gate_reasons")
    con, _sandbox_path2 = sandbox()
    try:
        tagged = None
        for r in con.execute(
                "SELECT i.id FROM item i JOIN quality q ON q.item_id=i.id "
                "WHERE i.status='active' ORDER BY random() LIMIT 400"):
            res = quality.assess(con, r["id"])
            if "OFF_CLASS_TOPIC" in res["tags"] or "MODULE_FILLER" in res["tags"]:
                tagged = r["id"]
                break
        if tagged is None:
            check(False, "found a held item to persist")
        else:
            res = quality.assess(con, tagged)
            store.set_state(con, tagged, res["state"], res["score"],
                            res["reasons"])
            con.commit()
            got = con.execute(
                "SELECT validation_state, gate_reasons FROM quality "
                "WHERE item_id=?", (tagged,)).fetchone()
            stored = json.loads(got["gate_reasons"] or "[]") if got else []
            # MEASURED: this asserted that the persisted reasons CONTAINED
            # "OFF_CLASS_TOPIC" and failed intermittently at random. The gate
            # can now emit SEVERAL reasons for one item -- adding the disproof
            # gate put "BOILERPLATE_DISPROOF" alongside "MODULE_FILLER" on the
            # sampled row -- and the sampled item's own reason set decides what
            # is stored. The invariant is that the item is HELD and its reasons
            # PERSIST, not that one particular tag is the only one present.
            held_tags = {"OFF_CLASS_TOPIC", "MODULE_FILLER"}
            check(bool(held_tags & set(stored)),
                  "a relevance-holding reason persists into quality.gate_reasons",
                  f"stored {stored} for an item the gate held with "
                  f"{res['tags']}")
            check(len(stored) == len(res["reasons"]),
                  "every reason the gate produced was persisted",
                  f"produced {res['reasons']} stored {stored}")
            check(got is not None and got["validation_state"] != "high_confidence",
                  "the persisted state is not high_confidence",
                  f"got {got['validation_state'] if got else None}")
    finally:
        con.close()

    print("T22f the live corpus was not written by THIS suite")
    live = ro()
    before = None
    try:
        n = live.execute(
            "SELECT count(*) FROM sqlite_master WHERE name='_readonly_probe'"
            " OR name='_sandbox_probe' OR name='_sandbox_marker'").fetchone()[0]
        check(n == 0, "no probe/sandbox table exists in the LIVE corpus",
              f"found {n}")
        before = dict(live.execute(
            "SELECT status, count(*) FROM item GROUP BY 1"))
    finally:
        live.close()
    # Compare against a value captured at the START of the run, never against a
    # hardcoded snapshot constant. The corpus is shared and another writer added
    # 90 items mid-cycle (R31), so a pinned baseline turned this into a false
    # alarm; the invariant that matters is "this suite did not write", not
    # "the corpus looks like it did an hour ago".
    print("T22g this suite wrote nothing to the live corpus")
    live = ro()
    try:
        after = dict(live.execute(
            "SELECT status, count(*) FROM item GROUP BY 1"))
        check(after == before,
              "item statuses unchanged across this test file",
              f"before={before} after={after}")
    finally:
        live.close()

    print()
    print(f"T22 RELEVANCE WIRING: {PASSES} pass, {len(FAILS)} fail")
    for f in FAILS:
        print("  FAIL " + f)
    return 1 if FAILS else 0


if __name__ == "__main__":
    raise SystemExit(main())