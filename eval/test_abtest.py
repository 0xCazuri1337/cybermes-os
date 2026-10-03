"""A/B framework tests (spec §46).

The load-bearing property is NEGATIVE: the framework must refuse to declare a
winner when the evidence does not support one. A benchmark framework that
always produces an answer is worse than none, because it converts noise into
architecture decisions.

Every refusal path is tested by making it fail on purpose.
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
    tmp = Path(tempfile.mkdtemp(prefix="orch-ab-"))
    dest = tmp / "cyber"
    shutil.copytree(ROOT, dest, ignore=shutil.ignore_patterns(
        "quarantine", "*.tar.gz", "__pycache__", "state"))
    return dest


def main() -> int:
    root = sandbox()
    os.environ["WKS_ROOT"] = str(root)
    sys.path.insert(0, str(root))
    for m in [m for m in list(sys.modules) if m.startswith(("wks", "orch"))]:
        del sys.modules[m]
    from orch import abtest, store

    con = store.open_db()

    print("A1 an experiment needs at least two arms")
    try:
        abtest.plan(con, "exp.single", "q", "m", ["only_one"])
        check("single arm refused", False, "no error raised")
    except ValueError as e:
        check("single arm refused", "2 arms" in str(e), str(e))

    print("\nA2 an experiment must declare a metric")
    try:
        abtest.plan(con, "exp.nometric", "q", "", ["a", "b"])
        check("empty metric refused", False, "no error raised")
    except ValueError:
        check("empty metric refused", True)

    print("\nA3 a real difference produces a real winner")
    r = abtest.run_benchmark(con, "exp.basic", "which is faster?",
                             "latency_ms",
                             {"fast": lambda: 10.0, "slow": lambda: 50.0})
    # 'latency' is lower-is-better, so the lower arm must win. If the direction
    # were inferred wrongly this would pick 'slow' and the test would catch it.
    check("lower-is-better metric picks the lower arm", r["winner"] == "fast",
          f"winner={r['winner']} values={r['values']}")
    check("verdict names both numbers", "10.0" in r["verdict"]
          and "50.0" in r["verdict"], r["verdict"])

    print("\nA4 a higher-is-better metric picks the higher arm")
    r2 = abtest.run_benchmark(con, "exp.rate", "which is better?",
                              "hit_rate_pct",
                              {"low": lambda: 0.4, "high": lambda: 0.9})
    check("higher-is-better metric picks the higher arm",
          r2["winner"] == "high", f"winner={r2['winner']} values={r2['values']}")

    print("\nA5 an unmeasured arm REFUSES a verdict")
    abtest.plan(con, "exp.partial", "q", "score", ["measured", "missing"])
    store.record_arm(con, "exp.partial", "measured", "score", 1.0, "only arm")
    con.commit()
    r3 = abtest.decide(con, "exp.partial")
    check("no winner when an arm was never measured", r3["winner"] is None,
          str(r3))
    check("refusal explains the arm was never measured",
          "never" in (r3["verdict"] or "").lower(), str(r3["verdict"]))
    check("the unmeasured arm is named", "missing" in (r3["verdict"] or ""),
          str(r3["verdict"]))

    print("\nA6 a difference below the threshold adopts nothing")
    r4 = abtest.run_benchmark(con, "exp.tiny", "negligible difference?",
                              "score",
                              {"a": lambda: 1.000, "b": lambda: 1.001})
    # both arms measured, but the delta is 0.001
    row = con.execute("SELECT status, winner FROM ab_experiment"
                      " WHERE exp_key='exp.tiny'").fetchone()
    # with default min_delta=0 a winner is allowed; with a threshold it is not
    r5 = abtest.decide(con, "exp.tiny", min_delta=0.01)
    check("a threshold refuses a negligible difference", r5["winner"] is None,
          f"winner={r5['winner']}")
    check("threshold refusal is recorded", "below min_delta" in
          (r5["verdict"] or ""), str(r5["verdict"]))
    stored = con.execute("SELECT verdict FROM ab_experiment WHERE"
                         " exp_key='exp.tiny'").fetchone()["verdict"]
    check("threshold refusal is persisted to the experiment row",
          "below min_delta" in (stored or ""), str(stored))

    print("\nA7 a crashing arm is recorded, not fatal")
    def boom():
        raise RuntimeError("arm exploded")

    r6 = abtest.run_benchmark(con, "exp.crash", "one arm fails", "score",
                              {"good": lambda: 5.0, "bad": boom})
    res = abtest.results(con, "exp.crash")
    check("the failed arm is recorded as None", res["values"]["bad"] is None,
          str(res["values"]))
    check("the failure reason is kept",
          "arm exploded" in (res["details"]["bad"] or ""),
          str(res["details"]))
    check("the surviving arm still won", r6["winner"] == "good",
          f"winner={r6['winner']} verdict={r6['verdict']}")
    check("the verdict says it was uncontested, not compared",
          "uncontested" in (r6["verdict"] or ""), str(r6["verdict"]))
    check("the crashed arm is named in the verdict",
          "bad" in (r6["verdict"] or ""), str(r6["verdict"]))

    print("\nA8 redefining a metric on a live key is refused")
    abtest.plan(con, "exp.stable", "q", "metric_a", ["a", "b"])
    store.record_arm(con, "exp.stable", "a", "metric_a", 1.0, "x")
    store.record_arm(con, "exp.stable", "b", "metric_a", 2.0, "x")
    con.commit()
    try:
        abtest.plan(con, "exp.stable", "q", "metric_B", ["a", "b"])
        check("metric change refused", False, "no error raised")
    except ValueError as e:
        check("metric change refused", "mix two different" in str(e), str(e))

    print("\nA9 re-running a decided experiment clears stale results")
    abtest.decide(con, "exp.stable")
    before = con.execute("SELECT count(*) n FROM ab_result WHERE"
                         " exp_key='exp.stable'").fetchone()["n"]
    check("results present before re-run", before == 2, str(before))
    abtest.run_benchmark(con, "exp.stable", "q", "metric_a",
                         {"a": lambda: 9.0, "b": lambda: 1.0})
    after = abtest.results(con, "exp.stable")
    check("stale values replaced, not merged", after["values"]["a"] == 9.0
          and after["values"]["b"] == 1.0, str(after["values"]))
    # 'score' is higher-is-better, so 9.0 beats 1.0
    check("the new verdict reflects the new data",
          after["winner"] == "a", str(after["winner"]))

    con.close()
    shutil.rmtree(root.parent, ignore_errors=True)

    print()
    if FAILURES:
        print(f"ABTEST: {PASSES} passed, {len(FAILURES)} FAILED")
        for f in FAILURES:
            print(f"  - {f}")
        return 1
    print(f"ABTEST: ALL {PASSES} CHECKS PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())