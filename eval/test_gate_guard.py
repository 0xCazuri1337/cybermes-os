"""Gate-guard tests.

The guard exists because `config.py` and `quality.py` were once modified by a
process outside the session that owned them. The change happened to strengthen
the gate, so nothing failed — it succeeded by luck. These tests prove it can
FAIL, because a guard that cannot fail is the same decoration the guard was
written to remove.

Every test runs against a disposable copy of the repository. The real gate
files are never touched.
"""
from __future__ import annotations

import os
import shutil
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

FAILURES: list[str] = []
PASSES = 0


def check(name: str, cond: bool, detail: str = "") -> None:
    global PASSES
    if cond:
        PASSES += 1
        print(f"  [PASS] {name}")
    else:
        FAILURES.append(f"{name}: {detail}")
        print(f"  [FAIL] {name}  {detail}")


def sandbox() -> Path:
    tmp = Path(tempfile.mkdtemp(prefix="orch-gate-"))
    dest = tmp / "cyber"
    # The guard only needs the gate code, the schema, the live DB, and
    # CONTROL. Copying the generated corpus and the old DB snapshots made this
    # test spend minutes in filesystem metadata before its first assertion.
    for name in ("wks", "orch", "db", "CONTROL"):
        src = ROOT / name
        if src.is_dir():
            shutil.copytree(src, dest / name, ignore=shutil.ignore_patterns(
                "__pycache__", "*.db.bak*", "wks-pre-*.db*",
                "*.db-wal", "*.db-shm"))
        elif src.is_file():
            shutil.copy2(src, dest / name)
    shutil.copy2(ROOT / "CONTROL.md", dest / "CONTROL.md")
    return tmp, dest


def fresh_modules(dest: Path):
    os.environ["WKS_ROOT"] = str(dest)
    for m in [m for m in list(sys.modules) if m.startswith(("wks", "orch"))]:
        del sys.modules[m]
    sys.path.insert(0, str(dest))
    from orch import gate_guard, store
    return gate_guard, store


def main() -> int:
    tmp, dest = sandbox()
    gate_guard, store = fresh_modules(dest)
    con = store.open_db()

    print("G1 re-baselining without a reason is refused")
    try:
        gate_guard.baseline(con, reason="   ")
        check("empty reason refused", False, "no error raised")
    except ValueError as e:
        check("empty reason refused", "explicit reason" in str(e), str(e))

    print("\nG2 a clean baseline verifies OK")
    r = gate_guard.baseline(con, reason="test baseline")
    check("all gate files fingerprinted",
          len(r["baselined"]) == len(gate_guard.GATE_FILES),
          f"{len(r['baselined'])} of {len(gate_guard.GATE_FILES)}")
    gate_guard.remember_settings(con)
    v = gate_guard.verify(con)
    check("verify passes on an untouched tree", v["ok"], str(v))
    check("all 8 critical settings are read",
          len(v["settings"]) == 8, str(v["settings"]))
    check("the 2-host rule is among them",
          v["settings"].get("MIN_PUBLISHER_HOSTS") == 2,
          str(v["settings"]))

    print("\nG3 weakening a threshold is DETECTED and NAMED")
    cfg = dest / "wks" / "config.py"
    original = cfg.read_text(encoding="utf-8")
    cfg.write_text(original.replace("MIN_PUBLISHER_HOSTS = 2",
                                    "MIN_PUBLISHER_HOSTS = 1"),
                    encoding="utf-8")
    v2 = gate_guard.verify(con)
    check("verify fails", not v2["ok"], "tampering went undetected")
    check("config.py is named",
          any(c["file"] == "wks/config.py" for c in v2["changed_files"]),
          str(v2["changed_files"]))
    named = [c for c in v2["settings_changed"]
             if c["setting"] == "MIN_PUBLISHER_HOSTS"]
    check("the exact setting is named", bool(named), str(v2["settings_changed"]))
    check("with both the old and new value",
          bool(named) and named[0]["was"] == 2 and named[0]["now"] == 1,
          str(named))
    cfg.write_text(original, encoding="utf-8")

    print("\nG4 a comment-only edit is reported as modified, not as a safety change")
    cfg.write_text(original + "\n# an explanatory comment\n", encoding="utf-8")
    v3 = gate_guard.verify(con)
    check("the file is reported modified", bool(v3["changed_files"]),
          "comment edit went unnoticed")
    check("but NO threshold is reported changed",
          not v3["settings_changed"], str(v3["settings_changed"]))
    cfg.write_text(original, encoding="utf-8")

    print("\nG5 a missing gate file fails verification")
    q = dest / "wks" / "quality.py"
    saved = q.read_text(encoding="utf-8")
    q.unlink()
    v4 = gate_guard.verify(con)
    check("a missing gate file fails", not v4["ok"], "deletion went unnoticed")
    check("the missing file is named",
          "wks/quality.py" in v4["missing_files"], str(v4["missing_files"]))
    q.write_text(saved, encoding="utf-8")

    print("\nG6 the self-audit FAILS on a tampered gate")
    # Do NOT call remember_settings here: that would overwrite the stored
    # "before" snapshot and the diff would have nothing to compare against —
    # which is exactly how a guard silently stops guarding. The settings
    # baseline set in G2 must survive to be compared against the tamper.
    cfg.write_text(original.replace("MATURITY_MIN_FP_RULES = 2",
                                    "MATURITY_MIN_FP_RULES = 0"),
                    encoding="utf-8")
    gate_guard, store = fresh_modules(dest)
    con2 = store.open_db()
    from orch import selfaudit
    audit = selfaudit.audit(con2)
    gcheck = [c for c in audit["checks"]
              if c["name"] == "the quality gate is unmodified"]
    check("the audit has a gate-integrity check", bool(gcheck), "check absent")
    check("it FAILS on tampering", bool(gcheck) and not gcheck[0]["passed"],
          str(gcheck[0]["detail"])[:120] if gcheck else "")
    check("the audit verdict is degraded", audit["health"] == "degraded",
          f"health={audit['health']}")
    check("the failure names the setting",
          bool(gcheck) and "MATURITY_MIN_FP_RULES" in gcheck[0]["detail"],
          str(gcheck[0]["detail"])[:160] if gcheck else "")
    cfg.write_text(original, encoding="utf-8")

    con2.close()
    con.close()
    shutil.rmtree(tmp, ignore_errors=True)

    print()
    if FAILURES:
        print(f"GATE GUARD: {PASSES} passed, {len(FAILURES)} FAILED")
        for f in FAILURES:
            print(f"  - {f}")
        return 1
    print(f"GATE GUARD: ALL {PASSES} CHECKS PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())