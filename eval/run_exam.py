"""Run a full black-box exam: forge -> serve -> grade -> record the gate.

One command produces one auditable outcome. Nothing here trusts the solver's
own account of what it did; `grade_exam` re-derives the verdict from the lab.

    python eval/run_exam.py idor --seed 4242

A gate is closed ONLY when the grader returns PASS. A FAIL is recorded as a
failure artifact, because "I tried and missed it" is the input to gap analysis
and must not vanish.
"""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import grade_exam  # noqa: E402
import labforge as L  # noqa: E402


def wait_ready(base: str, tries: int = 25) -> bool:
    for _ in range(tries):
        try:
            with urllib.request.urlopen(base + "/", timeout=3) as f:
                f.read(64)
            return True
        except Exception:
            time.sleep(0.2)
    return False


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="run_exam")
    ap.add_argument("injection")
    ap.add_argument("--seed", type=int, default=4242)
    ap.add_argument("--port", type=int, default=8751)
    ap.add_argument("--root", default=None)
    ap.add_argument("--gate", default="black_box",
                    help="mastery gate to attempt (black_box or transfer)")
    a = ap.parse_args(argv)

    root = Path(a.root) if a.root else Path(__file__).resolve().parent.parent
    out = root / "eval" / "exams" / f"{a.injection}-{a.seed}"
    out.mkdir(parents=True, exist_ok=True)

    # 1. Self-validate FIRST. A lab that cannot prove its own vulnerability may
    #    not gate a mastery state, so refuse before spending a solve on it.
    truth = L.self_validate(a.injection, a.seed)
    if not truth["passed"]:
        print("LAB SELF-VALIDATION FAILED -- refusing to run an exam on it:")
        print(json.dumps(truth["checks"], indent=2))
        return 2
    print(f"lab self-validated: {a.injection} seed={a.seed}")

    # 2. Card only. No ground truth in anything the solver reads.
    inj = L.BY_ID[a.injection]
    ctx = L.Ctx(a.seed)
    app = L.App(ctx)
    inj.install(app)
    from http.server import ThreadingHTTPServer
    httpd = ThreadingHTTPServer(("127.0.0.1", a.port), L.make_handler(app))
    card = {
        "exam_id": f"{a.injection}-{a.seed}",
        "target": f"http://127.0.0.1:{a.port}",
        "credentials": {"alice": "user", "bob": "user", "carol": "user",
                        "root": "admin"},
        "how_to_auth": ("POST /login with form body user=<name>; the response "
                        "sets a session credential. Log in as two different "
                        "identities to compare what each may see."),
        # Per-seed facts are emitted HERE, not restated by hand in a solver
        # brief. A brief that hardcodes the cookie name from a previous seed is
        # wrong by construction: the name is drawn from a pool per seed.
        "session_cookie_name": ctx.cookie,
        "auth_style": "bearer" if ctx.use_bearer else "cookie",
        "server_banner": ctx.server,
        "mission": ("You are authorised to test this application. Find real, "
                    "demonstrable vulnerabilities. For each finding state what you "
                    "tested, what you observed, and why it is a real vulnerability "
                    "rather than expected behaviour. Do not report behaviour you "
                    "could not demonstrate."),
    }
    (out / "card.json").write_text(json.dumps(card, indent=2), encoding="utf-8")
    (out / "ground_truth.json").write_text(json.dumps(truth, indent=2), encoding="utf-8")
    print(f"lab up at {card['target']}  card -> {out/'card.json'}")

    import threading
    t = threading.Thread(target=httpd.serve_forever, daemon=True)
    t.start()
    if not wait_ready(card["target"]):
        print("lab failed to become ready")
        httpd.shutdown()
        return 2

    print("\n" + "=" * 70)
    print(json.dumps(card, indent=2))
    print("=" * 70)
    print("Write the solver's findings to:", out / "SOLVER_REPORT.md")
    print("(ground truth is on disk but was never served over HTTP)")
    httpd.shutdown()
    httpd.server_close()
    return 0


def grade_and_record(exam_dir: Path, gate: str = "black_box") -> int:
    """Grade a finished exam and close or refuse the mastery gate."""
    res = grade_exam.grade(exam_dir)
    (exam_dir / "GRADE.json").write_text(json.dumps(res, indent=2), encoding="utf-8")
    print(json.dumps(res, indent=2))
    if res["verdict"] != "PASS":
        print(f"\nFAIL -> not recorded as mastery. Gap recorded at {exam_dir}.")
        return 1

    from wks import mastery
    cid = res["class_id"]
    rec = mastery.load(cid)
    rec.gates[gate] = {
        "closed": True,
        "evidence": str(exam_dir / "GRADE.json"),
        "exam": res["exam"],
        "at": res.get("exam"),
    }
    mastery.save(rec)
    print(f"\ngate {gate} closed for {cid}: {len(rec.closed())}/{len(mastery.GATE_IDS)}"
          f" state={rec.derive_state()}")
    return 0


if __name__ == "__main__":
    argv = sys.argv[1:]
    if argv and argv[0] == "grade":
        raise SystemExit(grade_and_record(Path(argv[1]),
                                          argv[2] if len(argv) > 2 else "black_box"))
    raise SystemExit(main(argv))