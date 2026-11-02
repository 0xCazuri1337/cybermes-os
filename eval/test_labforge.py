"""Lab-forge regression suite.

The rule this file exists to enforce: a checker that cannot FAIL is worse than
no checker, because its green output is indistinguishable from knowledge. Every
"does the lab work" assertion here is paired with a control that MUST fail.

    python eval/test_labforge.py
"""
from __future__ import annotations

import json
import sys
import urllib.error
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import labforge as L  # noqa: E402

RESULTS: list[tuple[str, bool, str]] = []


def check(name: str, cond: bool, detail: str = "") -> None:
    RESULTS.append((name, bool(cond), detail))


# --- T1: every lab self-validates across several seeds ------------------------
def t1_labs_validate() -> None:
    for seed in (7, 23, 101):
        for inj in L.INJECTIONS:
            r = L.self_validate(inj.injection_id, seed)
            failed = [k for k, v in r["checks"].items() if not v]
            check(f"T1 {inj.injection_id}@{seed}", r["passed"],
                  f"failed: {failed}" if failed else "")


# --- T2: NEGATIVE CONTROL. A lab with no vulnerability must NOT validate ------
def t2_control_secure_app_fails() -> None:
    """Build the app with ONLY the patched installers, then assert the forge
    reports it as NOT vulnerable. If this passes vacuously the whole suite is
    worthless, so it also asserts the probe really did observe a difference."""
    observed_difference = 0
    for inj in L.INJECTIONS:
        with L.Lab(inj.injection_id, 7, patched=True) as lab:
            probe_result = inj.vuln_probe(lab.app, lab.ctx)
        check(f"T2 {inj.injection_id} secure app is clean",
              probe_result.get("kind") != "vuln",
              f"kind={probe_result.get('kind')}")
        with L.Lab(inj.injection_id, 7, patched=False) as lab:
            vuln_result = inj.vuln_probe(lab.app, lab.ctx)
        if vuln_result.get("kind") != probe_result.get("kind"):
            observed_difference += 1
    check("T2 probe discriminates on every injection",
          observed_difference == len(L.INJECTIONS),
          f"{observed_difference}/{len(L.INJECTIONS)} distinguishable")


# --- T3: NEGATIVE CONTROL. The checker must reject a tampered lab -------------
def t3_control_tampered_app_fails() -> None:
    """Force every installer's guard to hold, then assert self_validate says
    FAIL. Proves the verdict is derived, not asserted."""
    original = {}
    for inj in L.INJECTIONS:
        original[inj.injection_id] = inj.patched_install
        inj.patched_install = inj.install  # patched_install == vulnerable one
    try:
        rejected = 0
        for inj in L.INJECTIONS:
            r = L.self_validate(inj.injection_id, 7)
            # With no patched variant the probe cannot distinguish, so at least
            # `patched_variant_is_not` / `distinguishes` must fail.
            if not r["passed"]:
                rejected += 1
        check("T3 tampered (unpatchable) labs are rejected",
              rejected == len(L.INJECTIONS), f"{rejected}/{len(L.INJECTIONS)} rejected")
    finally:
        for inj in L.INJECTIONS:
            inj.patched_install = original[inj.injection_id]


# --- T4: ground truth is NEVER reachable over HTTP ---------------------------
def t4_ground_truth_not_served() -> None:
    needles = ["ground_truth", "INTERNAL-ADMIN-BANNER", "FLAG-INTERNAL-LEDGER",
               "why_not_a_vuln", "patched_install", "expected"]
    with L.Lab("idor", 5) as lab:
        base = lab.base
        paths = ["/", "/ground_truth.json", "/eval", "/../ground_truth.json",
                 "/../../eval/labforge.py"]
        for p in paths:
            try:
                with urllib.request.urlopen(base + p, timeout=5) as f:
                    body = f.read().decode("utf-8", "replace")
                    status = f.status
            except urllib.error.HTTPError as e:
                body, status = e.read().decode("utf-8", "replace"), e.code
            except Exception as e:
                body, status = str(e), 0
            leaked = [n for n in needles if n in body and n != "expected"]
            check(f"T4 {p} not leaked (status {status})", not leaked,
                  f"leaked={leaked}")


# --- T5: a live socket reproduces the in-process verdict ----------------------
def t5_socket_matches_inprocess() -> None:
    """The self-validation runs in-process. If the HTTP server served something
    different, every mastery gate would be scored against a fiction."""
    with L.Lab("idor", 31) as lab:
        headers = lab.login("alice")
        oid = "A-1003"
        path = lab.ctx.path(oid)
        req = urllib.request.Request(lab.base + path, headers=headers)
        with urllib.request.urlopen(req, timeout=5) as f:
            body, status = f.read().decode(), f.status
        truth = L._idor_probes(lab.app, lab.ctx)
        check("T5 socket leaks the foreign record", "carol" in body and status == 200,
              f"status={status} body={body[:120]}")
        check("T5 socket agrees with in-process probe",
              (status == 200) == (truth.get("kind") == "vuln"),
              f"socket={status} inproc={truth.get('kind')}")


# --- T6: labs are bound to loopback only -------------------------------------
def t6_loopback_only() -> None:
    with L.Lab("sqli", 3) as lab:
        check("T6 binds 127.0.0.1", lab.base.startswith("http://127.0.0.1:"),
              lab.base)


# --- T7: traps must be real, i.e. the trap probe must observe an inert result -
def t7_traps_are_inert() -> None:
    for inj in L.INJECTIONS:
        with L.Lab(inj.injection_id, 7 + 55, patched=False) as lab:
            t = inj.trap_probe(lab.app, lab.ctx)
        check(f"T7 {inj.injection_id} trap inert", t.get("kind") == "trap",
              f"kind={t.get('kind')} excerpt={str(t.get('excerpt'))[:100]}")
        check(f"T7 {inj.injection_id} trap explains itself",
              len(t.get("why_not_a_vuln", "")) > 40, "")


# --- T8: no authentication bypass smuggled into the lab ----------------------
def t8_no_arbitrary_login() -> None:
    """A lab that accepts any username carries a second, unintended finding
    next to the planted one, and the solver cannot tell which it was meant to
    find. Found by a blind solver on the first idor exam."""
    import urllib.parse as up
    for inj in L.INJECTIONS:
        with L.Lab(inj.injection_id, 7, patched=False) as lab:
            r = L.probe(lab.app, "POST", "/login", body=up.urlencode({"user": "nosuchuser"}))
            check(f"T8 {inj.injection_id} rejects unknown user", r.status == 401,
                  f"status={r.status} body={r.body[:80]}")
            known = L.probe(lab.app, "POST", "/login", body=up.urlencode({"user": "alice"}))
            check(f"T8 {inj.injection_id} accepts known user", known.status == 200,
                  f"status={known.status}")
        try:
            with L.Lab(inj.injection_id, 7) as lab:
                lab.login("ghost")
            check(f"T8 {inj.injection_id} Lab.login refuses unknown user", False,
                  "minted a session for a non-existent identity")
        except RuntimeError:
            check(f"T8 {inj.injection_id} Lab.login refuses unknown user", True)


# --- T9: the id format must be discoverable without brute force --------------
def t9_ids_are_discoverable() -> None:
    """Found when the first blind solver burned its entire budget guessing the
    object-id shape. A real engagement gets ids from normal UI flow; an exam
    that hides them is hard for the wrong reason."""
    with L.Lab("idor", 4242) as lab:
        hdrs = lab.login("alice")
        path = lab.ctx.path("")
        r = L.probe(lab.app, "GET", path, headers=hdrs)
        import json as _json
        try:
            body = _json.loads(r.body)
            refs = [x["ref"] for x in body["records"]]
        except Exception:
            refs = []
        check("T9 listing returns the caller's records", bool(refs),
              f"status={r.status} body={r.body[:120]}")
        # and the advertised id must actually resolve to that user's record
        if refs:
            obj = L.probe(lab.app, "GET", path + refs[0], headers=hdrs)
            check("T9 an advertised ref resolves for its owner", obj.status == 200,
                  f"status={obj.status}")


# --- T10: a solver's POST must work over every normal client style -----------
def t10_post_works_for_clients() -> None:
    """A blind solver reported "POST returns an empty body" and suspected the
    server. Verified: it was their raw-socket half-close, not the lab. Lock the
    behaviour anyway -- an exam that some clients cannot log into is an exam
    that measures socket handling instead of the vulnerability."""
    import http.client as hc
    import socket as sk
    with L.Lab("idor", 61) as lab:
        port = lab.port
        # (a) http.client, keep-alive
        c = hc.HTTPConnection("127.0.0.1", port, timeout=10)
        c.request("POST", "/login", body=b"user=alice",
                  headers={"Content-Type": "application/x-www-form-urlencoded"})
        r = c.getresponse()
        b1 = r.read()
        check("T10 http.client POST returns a body", r.status == 200 and b'"ok"' in b1,
              f"status={r.status} body={b1[:60]}")
        # (b) raw socket, then half-close without waiting (the reported symptom)
        body = b"user=alice"
        so = sk.create_connection(("127.0.0.1", port), timeout=10)
        so.sendall((b"POST /login HTTP/1.1\r\nHost: x\r\n"
                    b"Content-Type: application/x-www-form-urlencoded\r\n"
                    b"Content-Length: %d\r\nConnection: close\r\n\r\n" % len(body)
                    ) + body)
        data = b""
        while True:
            chunk = so.recv(4096)
            if not chunk:
                break
            data += chunk
        so.close()
        check("T10 raw-socket POST returns a body", b'"ok"' in data,
              f"got {data[:80]!r}")
        # (c) the in-process probe path must agree
        p = L.probe(lab.app, "POST", "/login", body="user=alice")
        check("T10 in-process POST agrees", p.status == 200 and '"ok"' in p.body,
              f"status={p.status}")
        c.close()


# --- T11: the emitted exam card must state the lab's ACTUAL per-seed facts ---
def t11_card_matches_the_lab() -> None:
    """A solver brief that restates the cookie name by hand is wrong by
    construction: the name is drawn from a pool per seed. Measured: a brief said
    `app_sess` for a lab that served `sid`, so the solver could not log in from
    the information it was given.

    This runs the real CLI so it tests the ACTUAL emitted card, not a copy of
    the same expression."""
    import subprocess
    import sys as _sys
    import tempfile
    for seed in (5150, 4242, 9091, 77):
        with tempfile.TemporaryDirectory() as td:
            card_path = str(Path(td) / "card.json")
            proc = subprocess.run(
                [_sys.executable, str(Path(__file__).with_name("labforge.py")),
                 "serve", "idor", "--seed", str(seed), "--port", "8799",
                 "--card", card_path, "--card-only"],
                capture_output=True, text=True, timeout=25)
            check(f"T11 seed {seed} serve emits a card", proc.returncode == 0,
                  proc.stderr[-200:])
            if not Path(card_path).exists():
                continue
            card = json.loads(Path(card_path).read_text(encoding="utf-8"))
            with L.Lab("idor", seed) as lab:
                check(f"T11 seed {seed} card cookie matches lab",
                      card.get("session_cookie_name") == lab.ctx.cookie,
                      f"card={card.get('session_cookie_name')} lab={lab.ctx.cookie}")
                check(f"T11 seed {seed} card auth_style matches lab",
                      card.get("auth_style") == ("bearer" if lab.ctx.use_bearer else "cookie"),
                      f"card={card.get('auth_style')}")
                check(f"T11 seed {seed} card banner matches lab",
                      card.get("server_banner") == lab.ctx.server,
                      f"card={card.get('server_banner')} lab={lab.ctx.server}")


def run() -> int:
    for fn in (t1_labs_validate, t2_control_secure_app_fails,
               t3_control_tampered_app_fails, t4_ground_truth_not_served,
               t5_socket_matches_inprocess, t6_loopback_only,
               t7_traps_are_inert, t8_no_arbitrary_login,
               t9_ids_are_discoverable,
               t10_post_works_for_clients,
               t11_card_matches_the_lab):
        try:
            fn()
        except Exception as e:  # a crashed test is a failed test, not a skip
            check(f"{fn.__name__} crashed", False, repr(e))
    passed = sum(1 for _, ok, _ in RESULTS if ok)
    failed = [(n, d) for n, ok, d in RESULTS if not ok]
    for n, ok, d in RESULTS:
        if not ok:
            print(f"  FAIL {n}  {d}")
    print(f"\n{passed}/{len(RESULTS)} lab-forge checks passed")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(run())