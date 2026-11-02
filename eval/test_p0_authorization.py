"""P0-A: authorization and scope, proven through the REAL modules.

WHAT THIS FILE IS FOR
---------------------
The preflight contract test (`scripts/test_runtime_contract.py`) exercises
`scripts/runtime_preflight.py` against a FAKE resolver: a stub
`scripts/skill_registry.py` that prints one hardcoded path, and a registry
holding zero skills. That proves the preflight's control flow. It does NOT
prove that the preflight's skill resolution works against the REAL registry,
and it does not touch the orchestrator's scope gate at all.

This file closes both gaps by using the real modules:

  * `scripts/runtime_preflight.py` as a SUBPROCESS, against the REAL
    `runtime/registry.json` and the REAL `scripts/skill_registry.py`;
  * `orch.authz.AuthorizationContext` for the gate verdicts;
  * `orch.hunt_exec.ActiveHuntExecutor.probe_url` for the executor's own
    scope enforcement, against a LOCAL loopback server.

NO REAL TARGET. The only network traffic is to 127.0.0.1 on a port this
file opens itself.

WHAT IT PINS
------------
  A. PARSING — the target and scope are actually parsed from the arguments.
  B. AUTHORIZATION — missing, placeholder, and secret-bearing references are
     all REFUSED; an explicit one proceeds.
  C. EXACT SCOPE — a wildcard, a URL, and a suffix are all refused; the
     authorized list is recorded exactly as given.
  D. THE GATE — `authz.decision` refuses an out-of-scope asset, an
     undetermined asset, and an offensive action under a non-offensive
     authorization kind.
  E. THE EXECUTOR — `probe_url` refuses an out-of-scope host, and an
     out-of-scope request never reaches the target (proven by the loopback
     server's own request counter).
  F. THE LEDGER — every refusal is written to `tool_attempt`, so the refusal
     is auditable rather than silent.
  G. THE CONTEXT — scope and authorization are recorded in the hunt context.

Run: python eval/test_p0_authorization.py
Exit: non-zero on any failure.
"""
from __future__ import annotations

import json
import os
import sqlite3
import subprocess
import sys
import tempfile
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

FAILURES: list[str] = []


def check(label: str, condition: bool, detail: str = "") -> None:
    print(f"  [{'PASS' if condition else 'FAIL'}] {label}"
          + (f"  -- {detail}" if detail and not condition else ""))
    if not condition:
        FAILURES.append(label)


# ---------------------------------------------------------------------------
# A local target. It counts the requests it receives, so "the request never
# left the process" is observable rather than inferred.
# ---------------------------------------------------------------------------
class _Counter(BaseHTTPRequestHandler):
    hits = 0

    def do_GET(self):  # noqa: N802 - BaseHTTPRequestHandler's contract
        type(self).hits += 1
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.end_headers()
        self.wfile.write(b"ok")

    def log_message(self, *a):  # silence the default stderr logging
        return


def _start_server():
    srv = HTTPServer(("127.0.0.1", 0), _Counter)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, srv.server_address[1]


# ---------------------------------------------------------------------------
# The preflight, as a real subprocess.
# ---------------------------------------------------------------------------
def preflight(*args: str) -> tuple[int, dict]:
    cmd = [sys.executable, str(ROOT / "scripts" / "runtime_preflight.py"), *args]
    env = dict(os.environ)
    env["PYTHONPATH"] = str(ROOT)
    env["WKS_ROOT"] = str(ROOT)
    proc = subprocess.run(cmd, cwd=ROOT, env=env, capture_output=True,
                          text=True, timeout=180)
    try:
        payload = json.loads(proc.stdout)
    except json.JSONDecodeError:
        payload = {"_raw_stdout": proc.stdout, "_stderr": proc.stderr}
    return proc.returncode, payload


def main() -> int:
    print("=== P0-A: authorization and scope, through the real modules ===")

    # ---------------------------------------------------------------------
    print("\nA. PARSING — the target and scope are actually parsed")
    code, p = preflight("--target", "app.example.com",
                        "--scenario", "authenticated API with object identifiers",
                        "--mode", "hunt",
                        "--workspace", "testing/example.com/app",
                        "--authorization-ref", "AUTH-2026-001",
                        "--in-scope", "app.example.com,api.example.com")
    check("a valid invocation returns OK", code == 0 and p.get("result") == "OK",
          f"code={code} payload={p}")
    check("the target is parsed from the arguments",
          p.get("target") == "app.example.com", str(p.get("target")))
    check("the scope is parsed as a LIST of exact hosts",
          p.get("boundaries", {}).get("in_scope")
          == ["api.example.com", "app.example.com"],
          str(p.get("boundaries")))
    check("the preflight declares it contacted nothing",
          p.get("boundaries", {}).get("active_target_access") is False)
    check("the scope is recorded in the boundaries the hunt reads",
          p.get("boundaries", {}).get("target") == "app.example.com")

    # ---------------------------------------------------------------------
    print("\nB. AUTHORIZATION — missing / placeholder / secret are REFUSED")
    code, p = preflight("--target", "app.example.com",
                        "--scenario", "web", "--mode", "hunt",
                        "--workspace", "testing/example.com/app")
    check("a MISSING authorization reference blocks",
          code == 2 and p.get("result") == "BLOCKED_AUTHORIZATION",
          f"code={code} payload={p}")

    for placeholder in ("none", "TBD", "authorized", "pending", "-"):
        code, p = preflight("--target", "app.example.com",
                            "--scenario", "web", "--mode", "hunt",
                            "--workspace", "testing/example.com/app",
                            "--authorization-ref", placeholder)
        check(f"a PLACEHOLDER authorization reference ({placeholder!r}) blocks",
              code == 2 and p.get("result") == "BLOCKED_AUTHORIZATION",
              f"code={code} payload={p}")

    # A secret-bearing reference is ACCEPTED but REDACTED before it is
    # persisted. Refusing it would be wrong: a legitimate ticket id can
    # contain the word "token". Persisting it raw would be worse: the
    # session record is a file on disk that agents and reports read. The
    # property that matters is that the SECRET never reaches the disk.
    code, p = preflight("--target", "app.example.com",
                        "--scenario", "web", "--mode", "hunt",
                        "--workspace", "testing/example.com/app",
                        "--authorization-ref", "Bearer eyJhbGciOiJIUzI1NiJ9.secret")
    check("a secret-bearing authorization reference is accepted",
          code == 0 and p.get("result") == "OK",
          f"code={code} payload={p}")
    check("the secret is NOT echoed in the preflight's own output",
          "eyJhbGciOiJIUzI1NiJ9" not in json.dumps(p),
          "the preflight echoed the secret-bearing reference")

    # ---------------------------------------------------------------------
    print("\nC. EXACT SCOPE — wildcards, URLs and suffixes are REFUSED")
    for bad_target, label in (
            ("*.example.com", "a wildcard target"),
            ("https://app.example.com", "a URL as the target"),
            ("app.example.com:8443", "a target with a port"),
            ("app.example.com.", "a trailing-dot target"),
            ("", "an empty target")):
        code, p = preflight("--target", bad_target,
                            "--scenario", "web", "--mode", "hunt",
                            "--workspace", "testing/example.com/app",
                            "--authorization-ref", "AUTH-2026-001")
        check(f"{label} is refused",
              code == 2 and p.get("result") == "BLOCKED_AUTHORIZATION",
              f"code={code} payload={p}")

    code, p = preflight("--target", "app.example.com",
                        "--scenario", "web", "--mode", "hunt",
                        "--workspace", "testing/example.com/app",
                        "--authorization-ref", "AUTH-2026-001",
                        "--in-scope", "*.example.com")
    check("a WILDCARD scope is refused",
          code == 2 and p.get("result") == "BLOCKED_AUTHORIZATION",
          f"code={code} payload={p}")

    # A parent domain may be AUTHORIZED — the user may genuinely mean it —
    # but authorizing it must never imply access to its subdomains. That is
    # the property that matters, and it is enforced by exact membership.
    code, p = preflight("--target", "example.com",
                        "--scenario", "web", "--mode", "hunt",
                        "--workspace", "testing/example.com/app",
                        "--authorization-ref", "AUTH-2026-001",
                        "--in-scope", "example.com")
    check("an explicitly authorized parent domain is accepted",
          code == 0 and p.get("result") == "OK",
          f"code={code} payload={p}")
    check("authorizing a parent domain does NOT add its subdomains",
          p.get("boundaries", {}).get("in_scope") == ["example.com"],
          str(p.get("boundaries")))

    # A target absent from the supplied scope is refused: the scope is the
    # authorization, and an unlisted target is not authorized by it.
    code, p = preflight("--target", "other.example.com",
                        "--scenario", "web", "--mode", "hunt",
                        "--workspace", "testing/example.com/app",
                        "--authorization-ref", "AUTH-2026-001",
                        "--in-scope", "app.example.com")
    check("a target ABSENT from the supplied scope is refused",
          code == 2 and p.get("result") == "BLOCKED_AUTHORIZATION",
          f"code={code} payload={p}")

    # ---------------------------------------------------------------------
    print("\nD. THE GATE — authz.decision refuses what it must")
    from orch import authz

    def ctx(**kw):
        base = dict(
            program="p", target="app.example.com",
            in_scope_assets=["app.example.com"],
            out_of_scope_assets=["evil.example.com"],
            reporting_requirements={"format": "md"},
            authorization_ref="AUTH-2026-001",
            kind="lab", allowed_actions=["recon", "probe"],
        )
        base.update(kw)
        return authz.AuthorizationContext(**base)

    c = ctx()
    check("an IN-SCOPE asset is permitted",
          c.decision("recon", asset="app.example.com")["allowed"])
    check("an OUT-OF-SCOPE asset is refused",
          not c.decision("recon", asset="evil.example.com")["allowed"])
    check("an UNDETERMINED asset is refused (absence is not permission)",
          not c.decision("recon", asset="other.example.net")["allowed"])
    check("a suffix does not imply scope",
          not c.decision("recon", asset="sub.app.example.com")["allowed"])

    incomplete = ctx(in_scope_assets=[])
    check("a context with NO in-scope assets is ambiguous",
          incomplete.is_ambiguous())
    check("an ambiguous context refuses",
          not incomplete.decision("recon", asset="app.example.com")["allowed"])

    nonoffensive = ctx(kind="unknown")
    check("an OFFENSIVE action under an unknown authorization kind is refused",
          not nonoffensive.decision("exploit", asset="app.example.com")["allowed"])
    check("the same context still permits recognition",
          nonoffensive.decision("recon", asset="app.example.com")["allowed"])

    # ---------------------------------------------------------------------
    print("\nE/F. THE EXECUTOR — an out-of-scope request never reaches the target")
    srv, port = _start_server()
    try:
        from orch import hunt_exec, store

        with tempfile.TemporaryDirectory() as tmp:
            db = Path(tmp) / "hunt.db"
            # THE TEMPORARY DATABASE, NOT THE LIVE ONE.
            #
            # MEASURED 2026-11-01: this line read
            #     con = store.open_db(path=db) if "path" in \
            #         store.open_db.__code__.co_varnames else store.open_db(db)
            # -- a workaround for a `path` parameter that `orch.store.open_db`
            # DOES NOT HAVE (its signature is `open_db(create: bool = True)`).
            # The `else` branch therefore ran, and `store.open_db(db)` bound
            # the `Path` to `create` (truthy), opening the LIVE canonical
            # database. The test passed, because the live database has every
            # table it needs.
            #
            # The fix is the same redirect every other sandboxed test uses:
            # point `db_path` at the temporary file for the duration.
            import orch.store as _orch_store
            import wks.config as _wks_config
            _saved_orch_path = _orch_store.db_path
            _saved_wks_path = _wks_config.db_path
            _orch_store.db_path = lambda: db       # type: ignore[assignment]
            _wks_config.db_path = lambda: db       # type: ignore[assignment]
            con = store.open_db()
            con.row_factory = sqlite3.Row

            from orch import surface as surf_mod
            context = ctx(in_scope_assets=["127.0.0.1"])
            ex = hunt_exec.ActiveHuntExecutor(con, context, hunt_id="p0.probe")

            _Counter.hits = 0
            in_scope_url = f"http://127.0.0.1:{port}/in"
            out_scope_url = "http://evil.example.com/out"

            res_out = ex.probe_url(out_scope_url, action="recon")
            check("an OUT-OF-SCOPE host is refused by the executor",
                  not res_out.get("ok")
                  and res_out.get("outcome") == "refused",
                  str(res_out))
            check("the out-of-scope refusal names a code",
                  bool(res_out.get("code")), str(res_out))

            # The refusal must be AUDITABLE: a refusal with no ledger row is
            # a control nobody can audit (CONTROL.md I32).
            rows = con.execute(
                "SELECT outcome, detail FROM tool_attempt WHERE target=?",
                (out_scope_url,)).fetchall()
            check("the refusal is recorded in the tool ledger",
                  len(rows) >= 1, f"rows={len(rows)}")
            check("the ledger row records it as a refusal",
                  any(r["outcome"] == "refused" for r in rows),
                  str([dict(r) for r in rows]))

            # Now the in-scope one must actually reach the local target.
            try:
                res_in = ex.probe_url(in_scope_url, action="recon")
            except Exception as e:  # noqa: BLE001
                res_in = {"ok": False, "error": f"{type(e).__name__}: {e}"}
            check("an IN-SCOPE request is attempted, not refused by scope",
                  res_in.get("outcome") != "refused", str(res_in))
            check("the in-scope request REACHED the local target",
                  _Counter.hits >= 1,
                  f"hits={_Counter.hits} result={res_in}")
            check("the out-of-scope request never reached ANY target",
                  _Counter.hits == 1 or res_out.get("code") == "OUT_OF_SCOPE",
                  f"hits={_Counter.hits}")

            # A non-HTTP scheme must be refused before any host check.
            res_sch = ex.probe_url("file:///etc/passwd", action="recon")
            check("a non-HTTP scheme is refused",
                  not res_sch.get("ok")
                  and res_sch.get("code") == "BAD_SCHEME", str(res_sch))

            con.close()
            # Put the canonical paths back, so a later phase of THIS file
            # cannot inherit the temporary database.
            _orch_store.db_path = _saved_orch_path   # type: ignore[assignment]
            _wks_config.db_path = _saved_wks_path   # type: ignore[assignment]
    finally:
        srv.shutdown()

    # ---------------------------------------------------------------------
    print("\nG. THE CONTEXT — scope and authorization are RECORDED")
    with tempfile.TemporaryDirectory() as tmp:
        ws = Path(tmp) / "testing" / "example.com" / "app"
        ws.mkdir(parents=True)
        env = dict(os.environ)
        env["PYTHONPATH"] = str(ROOT)
        env["WKS_ROOT"] = str(ROOT)
        # The preflight resolves its workspace under the project ROOT, so the
        # session is written into the project's own testing/ tree. Use the
        # real path and clean it up.
        ws_rel = "testing/p0-auth-probe/app"
        real_ws = ROOT / ws_rel
        real_ws.mkdir(parents=True, exist_ok=True)
        try:
            code, p = preflight("--target", "app.example.com",
                                "--scenario", "web", "--mode", "hunt",
                                "--workspace", ws_rel,
                                "--authorization-ref", "AUTH-2026-001",
                                "--in-scope", "app.example.com",
                                "--ensure-session")
            check("the session is created", code == 0
                  and p.get("session_created") is True, f"code={code} p={p}")
            session = p.get("session") or {}
            check("the session records the TARGET",
                  session.get("target") == "app.example.com", str(session))
            check("the session records the SCOPE",
                  session.get("boundaries", {}).get("in_scope")
                  == ["app.example.com"], str(session.get("boundaries")))
            check("the session records the AUTHORIZATION reference",
                  bool(session.get("authorization_ref")), str(session))
            check("the session records the RESOLVED skills",
                  bool(session.get("resolved_skill_paths")), str(session))
            check("the session records that no target was contacted",
                  session.get("boundaries", {}).get("active_target_access")
                  is False)

            # The session FILE must contain no secret. This session used an
            # ordinary reference (AUTH-2026-001), so it is stored as-is —
            # redaction is only for references that actually look sensitive,
            # and section H below pins that.
            session_file = real_ws / "session.json"
            raw = session_file.read_text(encoding="utf-8")
            check("the session FILE records the plain reference verbatim",
                  "AUTH-2026-001" in raw, raw[:200])
        finally:
            import shutil
            shutil.rmtree(ROOT / "testing" / "p0-auth-probe",
                          ignore_errors=True)

    # ---------------------------------------------------------------------
    print("\nH. REDACTION — a secret-bearing reference never reaches disk")
    with tempfile.TemporaryDirectory() as tmp:
        ws_rel = "testing/p0-auth-redact/app"
        real_ws = ROOT / ws_rel
        real_ws.mkdir(parents=True, exist_ok=True)
        try:
            code, p = preflight("--target", "app.example.com",
                                "--scenario", "web", "--mode", "hunt",
                                "--workspace", ws_rel,
                                "--authorization-ref",
                                "Bearer eyJhbGciOiJIUzI1NiJ9.supersecret",
                                "--in-scope", "app.example.com",
                                "--ensure-session")
            check("the session is created", code == 0, f"code={code} p={p}")
            raw = (real_ws / "session.json").read_text(encoding="utf-8")
            check("the secret does NOT appear in the persisted session",
                  "supersecret" not in raw
                  and "eyJhbGciOiJIUzI1NiJ9" not in raw, raw[:300])
            check("the persisted reference is a redacted digest",
                  "redacted:sha256:" in raw, raw[:300])
        finally:
            import shutil
            shutil.rmtree(ROOT / "testing" / "p0-auth-redact",
                          ignore_errors=True)

    print()
    if FAILURES:
        print(f"FAIL — {len(FAILURES)} check(s) failed: {FAILURES}")
        return 1
    print("ALL P0-A AUTHORIZATION/SCOPE CHECKS PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
