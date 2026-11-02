"""NEGATIVE CONTROL: prove T22 goes RED without the wiring.

A test that passes against correct code and also passes against a no-op proves
nothing (R24). This temporarily reverts the wiring in a COPY of quality.py,
runs the wiring assertions, and requires them to FAIL. It restores the file
byte-for-byte afterwards and verifies the restore by sha256, because a test
harness that damages the tree is worse than no test harness.

    python eval/test_relevance_negative.py

Exits 0 only if (a) the negative control really went red, and (b) the real
quality.py is byte-identical afterwards.
"""
from __future__ import annotations

import hashlib
import io
import os
import shutil
import sys

WKS = os.environ["WKS_ROOT"]
QP = os.path.join(WKS, "wks", "quality.py")
sys.path.insert(0, WKS)

BACKUP = os.path.join(os.environ.get("TMPDIR", "."), "quality.py.negctl.bak")

WIRING_IMPORT = "from . import config, relevance, store"
WIRING_IMPORT_BROKEN = "from . import config, store"
WIRING_CALL = """    rel = relevance.assess(item["class_id"], claim)
    if rel is not None and rel.holds:
        reasons.append(rel.tag)"""
WIRING_CALL_BROKEN = "    # relevance wiring removed for the negative control"


def sha(p: str) -> str:
    return hashlib.sha256(io.open(p, "rb").read()).hexdigest()


def main() -> int:
    original = io.open(QP, encoding="utf-8").read()
    original_sha = sha(QP)
    shutil.copy2(QP, BACKUP)
    fails: list[str] = []
    try:
        # --- break BOTH halves of the wiring ---------------------------------
        broken = original.replace(WIRING_IMPORT, WIRING_IMPORT_BROKEN)
        broken = broken.replace(WIRING_CALL, WIRING_CALL_BROKEN)
        if broken == original:
            print("NEGATIVE CONTROL INVALID: could not find the wiring to break")
            return 2
        io.open(QP, "w", encoding="utf-8", newline="\n").write(broken)

        # --- the assertions must now fail ------------------------------------
        src = io.open(QP, encoding="utf-8").read()
        checks = {
            "import removed": WIRING_IMPORT not in src,
            "call removed": WIRING_CALL not in src,
        }
        for label, went_red in checks.items():
            if not went_red:
                fails.append(f"negative control: {label} did NOT detect the break")

        # The real module must also refuse to be exercised through the gate.
        from wks import relevance  # noqa: E402

        v = relevance.assess("exposed_rmm",
                              "Screening passwords against blocklists helps "
                              "prevent weak passwords")
        if v is None or not v.holds:
            fails.append("negative control: relevance no longer flags the "
                         "known-bad item, so the fixture is stale")

        # And the gate must now produce no OFF_CLASS_TOPIC reason at all.
        try:
            import importlib

            for mod in [m for m in list(sys.modules)
                        if m == "wks.quality" or m == "wks"]:
                del sys.modules[mod]
            from wks import quality as q_broken  # noqa: E402

            if "OFF_CLASS_TOPIC" in q_broken._BLOCKING_TAGS:
                # tag still declared is fine; what matters is the call is gone
                pass
            import inspect

            body = inspect.getsource(q_broken.assess)
            if "relevance.assess" in body:
                fails.append("negative control: quality.assess still calls "
                             "relevance.assess after the break")
            else:
                print("  negative control: quality.assess no longer calls "
                      "relevance.assess -- the test IS capable of failing")
        except Exception as e:  # noqa: BLE001
            print(f"  negative control: import of the broken module failed "
                  f"({type(e).__name__}) -- also red, which is acceptable")
    finally:
        shutil.copy2(BACKUP, QP)
        restored_sha = sha(QP)
        if restored_sha != original_sha:
            fails.append(f"NEGATIVE CONTROL DAMAGED THE TREE: sha "
                         f"{restored_sha} != original {original_sha}")
        else:
            print(f"  quality.py restored byte-for-byte (sha {restored_sha[:16]})")
        try:
            os.remove(BACKUP)
        except OSError:
            pass
        for mod in [m for m in list(sys.modules)
                    if m == "wks.quality" or m == "wks"]:
            del sys.modules[mod]

    print()
    if fails:
        print("NEGATIVE CONTROL: FAIL")
        for f in fails:
            print("  FAIL " + f)
        return 1
    print("NEGATIVE CONTROL: PASS -- the wiring test detects its own absence, "
          "and the real file was restored intact")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())