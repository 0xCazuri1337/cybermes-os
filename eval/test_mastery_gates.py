"""The mastery floor must reject placeholders WITHOUT rejecting honest work.

R17's lesson, applied to the new MIN_GATE_BYTES floors: a checker that only
fails is as useless as one that only passes. If the floors are too high, a
terse but genuine mechanism note gets refused and the operator learns to pad
artifacts -- which is worse than the defect it fixed.

So this suite runs BOTH directions:

  NEGATIVE  a placeholder cannot close a gate (TODO, TBD, empty, 300-byte TODO)
  POSITIVE  a real, terse mechanism note -- of honest length -- MUST close one

The positive cases are written to be as SHORT as an honest answer plausibly
could be. If any of these are refused, the floor is wrong.

    python eval/test_mastery_gates.py
"""
from __future__ import annotations

import os
import shutil
import subprocess
import sys
import tempfile

WKS = os.environ["WKS_ROOT"]
FAILS: list[str] = []
N = 0


def check(cond: bool, label: str, detail: str = "") -> None:
    global N
    N += 1
    if cond:
        print(f"  [PASS] {label}")
    else:
        FAILS.append(f"{label} {detail}")
        print(f"  [FAIL] {label} {detail}")


def sandbox() -> str:
    dst = tempfile.mkdtemp(prefix="mastery_")
    shutil.copytree(os.path.join(WKS, "wks"), os.path.join(dst, "wks"),
                    ignore=shutil.ignore_patterns("__pycache__"))
    os.makedirs(os.path.join(dst, "db"), exist_ok=True)
    shutil.copy2(os.path.join(WKS, "db", "wks.db"),
                 os.path.join(dst, "db", "wks.db"))
    os.makedirs(os.path.join(dst, "mastery"), exist_ok=True)
    return dst


def record(root: str, gate: str, content: str | None, name: str) -> bool:
    """Try to close `gate` on this content. True == accepted."""
    p = os.path.join(root, name)
    if content is None:
        open(p, "wb").close()
    else:
        open(p, "w", encoding="utf-8").write(content)
    r = subprocess.run(
        [sys.executable, "-m", "wks.mastery", "record", "probe", gate,
         "--evidence", p],
        cwd=root, capture_output=True, text=True,
        env=dict(os.environ, WKS_ROOT=root, PYTHONPATH=root))
    return r.returncode == 0


def main() -> int:
    root = sandbox()
    try:
        print("NEGATIVE: placeholders must NOT close a gate")
        for gate in ("explain", "recognize", "hypothesize", "test",
                     "interpret", "validate", "reject_fp", "generalize",
                     "chain", "failure_analysis", "black_box", "transfer"):
            accepted = record(root, gate, "TODO", f"{gate}_todo.md")
            check(not accepted,
                  f"{gate}: a 4-byte TODO is refused",
                  "ACCEPTED -- the gate cannot fail")
        for gate in ("hypothesize", "explain"):
            check(not record(root, gate, None, f"{gate}_empty.md"),
                  f"{gate}: a ZERO-BYTE file is refused")
        # long-but-worthless must also fail
        padded = "TODO\n" + ("x" * 400)
        check(not record(root, "explain", padded, "explain_padded.md"),
              "explain: a 400-byte padded TODO is refused")
        check(not record(root, "chain", "TBD", "chain_tbd.md"),
              "chain: 'TBD' is refused")

        print("POSITIVE: honest, terse artefacts MUST close their gate")
        real = {
            "explain": (
                "A DOM XSS sink: the attacker controls `location.hash`, which "
                "the page writes into `el.innerHTML` without escaping. The "
                "browser therefore parses the payload as markup and runs its "
                "script handlers in the page's origin. The invariant that "
                "fails is context-aware output encoding at the write, not any "
                "property of the input."),
            "recognize": (
                "Signals worth investigating: the value is reflected in a "
                "response body; a script context appears in the sink; the "
                "input arrives from a controllable source such as the "
                "fragment, query or a stored field; CSP is absent or does not "
                "cover the sink."),
            "test": (
                "1. Confirm reflection of a unique marker -- low information "
                "gain, it only proves reachability. 2. Test a benign tag in "
                "each candidate context (HTML body, attribute, JS string, URL) "
                "-- high gain, it localises the sink. 3. Probe the encoder by "
                "varying one character class at a time -- high gain, it finds "
                "the normalisation gap. 4. Stop when one context executes."),
            "interpret": (
                "200 with the marker echoed -> the input is reflected but not "
                "yet proven executable; next, identify the context. 200 with "
                "the payload reflected ESCAPED -> an encoder is present, so "
                "look for a context it does not cover. 403 or a WAF page -> "
                "inconclusive, change technique rather than payload. Empty "
                "body -> the sink is not on this path."),
            "reject_fp": (
                "Rejected: self-XSS where the payload is in the URL the tester "
                "themselves loaded. Disproof test: the same payload placed in "
                "a stored field for a second user executes -- absent that, it "
                "is not a finding. Rejected: a 400 from the WAF reported as a "
                "block; disproof is that the same request succeeds with a "
                "different UA."),
            "generalize": (
                "Common: reflected parameter into an HTML body. Uncommon: a "
                "stored value rendered inside an event-handler attribute. "
                "Defensive: a sanitizer that strips `<` but not the handler "
                "name, so `<`-only payloads fail while `onerror=` on an "
                "existing tag succeeds."),
            "chain": (
                "Prerequisite: a stored XSS that fires in an authenticated "
                "session. Transition: the victim's browser issues an "
                "same-origin authenticated request. Escalation: the response "
                "body is exfiltrated to an attacker host. Blocker: a CSP that "
                "forbids script and blocks the outbound destination."),
            "failure_analysis": (
                "Expected the reflected value to execute in the attribute "
                "context. Actual: it was rendered as HTML text. Wrong "
                "assumption: that the attribute was unquoted. Next test: quote "
                "the injected value so the parser cannot terminate the "
                "attribute, then re-check which context the sink uses."),
            "hypothesize": (
                "If the value is reflected unescaped, then a benign tag should "
                "render as an element rather than as text. If an encoder is "
                "present, a single `<` should appear as `&lt;`. If a CSP "
                "exists without unsafe-inline, execution should fail even when "
                "the sink is reached."),
            "interpret2": "unused",
        }
        for gate, text in real.items():
            if gate not in ("explain", "recognize", "test", "interpret",
                            "reject_fp", "generalize", "chain",
                            "failure_analysis", "hypothesize"):
                continue
            acc = record(root, gate, text, f"{gate}_real.md")
            size = len(text.encode())
            check(acc, f"{gate}: an honest {size}-byte note is ACCEPTED",
                  "REFUSED -- the floor is too high and would force padding")
    finally:
        shutil.rmtree(root, ignore_errors=True)

    print()
    print(f"MASTERY GATE SUITE: {N - len(FAILS)}/{N} pass")
    for f in FAILS:
        print("  FAIL " + f)
    return 1 if FAILS else 0


if __name__ == "__main__":
    raise SystemExit(main())