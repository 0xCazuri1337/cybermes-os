"""Dispatch reachability: does a hunt task actually REACH its handler?

Why this file exists
--------------------
MEASURED 2026-10-04: with `can_handle` answering False for every key — a total
dispatch regression — `eval/masterprompt_score.py` still printed
`100.0/100 (65/65 checks)`, and `python -m orch.hunt_cli` still exited 0 with a
clean summary. All 65 existing checks call a component directly and assert its
return value, so a DISPATCH defect is invisible to them by construction. This is
the check that closes that gap, and it is deliberately built to be un-gameable:

  1. It does NOT import `orch.hunt_cli` or `orch.hunt_exec`. The module under
     test is loaded by the child process only. An in-process monkeypatch — the
     very thing that hid the break — cannot make this green.
  2. It asserts on an ON-DISK artifact the handler writes, never on a return
     value. It reads records written before and inside the handler.
  3. It filters strictly on run id AND mtime, so a stale artifact from an
     earlier run can never satisfy it.
  4. It runs a HERMETIC loopback target: a real socket, real HTTP, real
     subprocess, zero external network, no real authorization.
  5. "Artifact absent" is a HARD FAIL, never a skip. A check that skips when it
     cannot prove anything is how a broken system looks healthy.

Every control has a negative twin, because a check that cannot fail is worse
than no check.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer

# Resolve from this file, not a host-specific absolute path: the suite is part
# of the repo and must run from a WSL checkout as well as the original Windows
# host. The child-process/path guards below stay valid either way.
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
os.environ.setdefault("WKS_ROOT", ROOT)

# MEASURED — AN MSYS PATH SILENTLY DISABLES THE WHOLE CHECK. The child is a
# NATIVE Windows python, and its trace path comes from `tempfile.mkdtemp()`,
# which resolves to `C:\Users\ADMINI~1\AppData\Local\Temp\...`. That is fine.
# But if this path is ever handed over as an MSYS/posix string (`/tmp/...` or
# `$TEMP`), the child's `open(path, "a")` fails with FileNotFoundError, which
# `_trace` swallows by design ("a trace that cannot be written must not become
# a bypass"). The hunt then runs perfectly and writes NOTHING, and this check
# reports 5 phantom failures that look like a dispatch regression. Measured:
# exactly that. Guard it here so a path problem can never masquerade as a
# dispatch problem.
if not os.path.isdir(ROOT):
    raise SystemExit(f"repo root not found: {ROOT}")

# Nonce handshake: the child is told the nonce and the port on argv, and the
# listener answers only when it sees its own nonce. That closes the
# ephemeral-port TOCTOU window — if another process binds the port first, the
# child gets the wrong answer and the run fails loudly instead of silently
# probing a foreign listener.
NONCE = "nonce-" + os.urandom(8).hex()


class _Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):        # keep the child's stdout clean
        pass

    def do_GET(self):
        if "nonce=" + NONCE in self.path:
            body = b"ok " + NONCE.encode()
        else:
            body = b"<html><body>default</body></html>"
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Credentials", "true")
        self.end_headers()
        self.wfile.write(body)


def _serve():
    """Bind an ephemeral loopback port. Returns (server, port)."""
    srv = HTTPServer(("127.0.0.1", 0), _Handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, srv.server_address[1]


def _run_cli(trace_path: str, port: int, hunt_id: str, db_path: str):
    """Spawn the REAL CLI as a subprocess. Never imports the code under test.

    `db_path` is a TEMPORARY database. MEASURED 2026-11-01: this function
    used to set only `WKS_ROOT=ROOT`, and `hunt_cli._con()` opened
    `root()/db/wks.db` -- which, with `WKS_ROOT` pointing at the real repo,
    IS the live canonical database. The subprocess wrote a real finding
    row (`reach.*.finding.*`, status `validating`) into the live corpus,
    and the scheduler then counted it as potential impact.

    `WKS_ROOT` relocates everything, including the CODE the subprocess
    imports, so it cannot be used to isolate the database alone. `WKS_DB`
    relocates ONLY the database, which is exactly the surface that needs
    isolating. The subprocess keeps the real `WKS_ROOT` (so it runs the
    real code) and gets a temporary `WKS_DB` (so it cannot write to the
    live corpus).
    """
    env = dict(os.environ)
    env["HERMES_DISPATCH_TRACE"] = trace_path
    env["PYTHONPATH"] = ROOT
    env["WKS_ROOT"] = ROOT
    env["WKS_DB"] = db_path
    argv = [sys.executable, "-m", "orch.hunt_cli",
            "--target", "127.0.0.1",
            "--base-url", f"http://127.0.0.1:{port}/?nonce={NONCE}",
            "--in-scope", "127.0.0.1",
            "--out-of-scope", "example.com",
            "--hunt-id", hunt_id,
            # MEASURED 2026-10-31: the §4 authorization gate requires
            # `program`, `reporting_requirements` and `authorization_ref`
            # (orch/authz.py REQUIRED_FIELDS), and it REFUSES a hunt that
            # has none. The gate is correct and must stay strict. This
            # check is about DISPATCH REACHABILITY -- whether a task
            # actually reaches its handler -- so it supplies the grant the
            # gate demands, against a hermetic loopback target that this
            # file starts itself.
            #
            # Without them the gate blocked the hunt before any dispatch
            # happened, and the check reported "the dispatcher never
            # reached a handler" -- a dispatch failure that was really an
            # authorization failure. A check that cannot tell those apart
            # is a check that reports the wrong thing.
            "--program", "hermetic-loopback-test",
            "--authorization-ref", "test-suite-hermetic-loopback",
            "--authorization-kind", "lab",
            "--allow", "recon",
            "--allow", "probe",
            "--max-cycles", "3"]
    started = time.time()
    proc = subprocess.run(argv, cwd=ROOT, env=env, capture_output=True,
                          text=True, timeout=280)
    # MEASURED — A BAD TRACE PATH USED TO LOOK LIKE BROKEN DISPATCH. The child
    # could not open the file, `_trace` swallowed the OSError, and this check
    # reported five phantom failures. The hunt now states the cause in its own
    # output, so an unwritable trace is distinguished from a trace that was
    # never written because dispatch never ran. Both are hard failures — but
    # they are DIFFERENT failures and must not be reported as the same one.
    trace_unwritable = "UNWRITABLE" in (proc.stdout or "")
    recs = []
    if os.path.exists(trace_path):
        with open(trace_path, encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    recs.append(json.loads(line))
                except json.JSONDecodeError:
                    pass
    # STRICT FILTER: this run's records only. A stale artifact from any earlier
    # run must not be able to satisfy the check.
    mine = [r for r in recs
            if r.get("run_id") == hunt_id and float(r.get("at", 0)) >= started]
    return proc, mine, started, trace_unwritable


def _break_can_handle(src: str) -> str:
    """Replace the body of `can_handle` with `return False`, by AST.

    The total dispatch break this check injects is "can_handle answers False
    for every key". The break must survive the method being edited for
    unrelated reasons, so it is applied to the parsed tree rather than to a
    literal block of source text.

    Returns the source unchanged if the method cannot be found or rewritten,
    which the caller treats as a hard failure — a control that cannot inject
    its break has stopped testing anything.
    """
    import ast

    try:
        tree = ast.parse(src)
    except SyntaxError:
        return src

    target = None
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef) and node.name == "can_handle":
            target = node
            break
    if target is None:
        return src

    body = [ast.Return(value=ast.Constant(value=False))]
    new_tree = ast.Module(body=tree.body, type_ignores=tree.type_ignores)
    for node in ast.walk(new_tree):
        if isinstance(node, ast.FunctionDef) and node.name == "can_handle":
            # Replace the WHOLE body, so the docstring goes with it: a
            # leftover docstring followed by `return False` would be
            # unreachable code that reads as an accident.
            node.body = body
            break

    try:
        return ast.unparse(new_tree)
    except (AttributeError, ValueError):
        return src


PASS = FAIL = 0
def check(name: str, cond: bool, detail: str = "") -> None:
    global PASS, FAIL
    if cond:
        PASS += 1
        print(f"  [PASS] {name}")
    else:
        FAIL += 1
        print(f"  [FAIL] {name} - {detail}")


def main() -> int:
    srv, port = _serve()
    print(f"hermetic loopback target: 127.0.0.1:{port}")
    tmp = tempfile.mkdtemp()
    trace = os.path.join(tmp, "dispatch.jsonl")
    # THE TEMPORARY DATABASE THE SUBPROCESS WILL WRITE TO.
    #
    # It must exist with the schema applied, because `hunt_cli._con()` opens
    # the database with a plain `sqlite3.connect` and does NOT create the
    # schema. `orch.store.open_db()` applies it, and it is idempotent.
    db_file = os.path.join(tmp, "hunt.db")
    from orch import store as _orch_store
    _saved_db_path = _orch_store.db_path
    _orch_store.db_path = lambda: __import__("pathlib").Path(db_file)
    try:
        _schema_con = _orch_store.open_db()
        # THE REFERENCE DATA A HUNT NEEDS TO FUNCTION.
        #
        # MEASURED 2026-11-01: with an EMPTY database the hunt created its
        # recon tasks and then dispatched NOTHING -- the trace file was
        # never written, and the check reported "the dispatcher never
        # reached a handler", which reads like a dispatch regression and is
        # not one.
        #
        # The cause is `orch.agentkit.select_agent`: it ranks the rows of
        # `agent_role`, and with no roles there is no candidate to select,
        # so `agents.dispatch` is never called. The roles are REFERENCE
        # DATA (the five collection roles, declared in
        # `orch/collection.py`), not operational state, so they belong in
        # every database that runs a hunt.
        #
        # The `executor` role is the orchestrator's own default handler.
        from orch import collection as _collection
        _collection.build_all_collection_roles(_schema_con)
        _schema_con.execute(
            "INSERT OR IGNORE INTO agent_role(role_key, domain, capabilities,"
            " max_depth, rationale, created_at)"
            " VALUES ('executor','system',?,1,?,datetime('now'))",
            (json.dumps(["READ", "ANALYZE", "WRITE"]),
             "default executor for autonomous work"))
        _schema_con.commit()
        _schema_con.close()
    finally:
        _orch_store.db_path = _saved_db_path
    # MEASURED — A FIXED HUNT ID MADE THIS CHECK NON-HERMETIC. `store.add_task`
    # is idempotent on task_key, so re-running the check under `reach.ok` found
    # 21 tasks ALREADY completed by the first run and had nothing left to
    # dispatch. Zero entries — correctly — and the check reported five phantom
    # failures. A unique id per run makes the check independent of its own
    # history, which is the only property that keeps it honest.
    RUN = f"reach.{os.urandom(4).hex()}"
    try:
        print(f"\nR1  A WORKING DISPATCH REACHES ITS HANDLER  (hunt {RUN}.ok)")
        proc, recs, _, unwritable = _run_cli(trace, port, f"{RUN}.ok", db_file)
        entries = [r for r in recs if r.get("phase") == "entry"]
        outcomes = [r for r in recs if r.get("phase") == "outcome"]
        check("CLI ran and exited cleanly", proc.returncode == 0,
              f"exit={proc.returncode} err={proc.stderr[-200:]}")
        check("the trace path was WRITABLE (checked first, so a path problem "
              "can never masquerade as a dispatch failure)",
              not unwritable, proc.stdout[-300:])
        check("artifact EXISTS (absent is a hard fail, never a skip)",
              os.path.exists(trace), "no trace file")
        check("at least one handler ENTRY recorded", len(entries) > 0,
              "the dispatcher never reached a handler")
        check("every entry has a matching outcome",
              len(entries) == len(outcomes) and len(entries) > 0,
              f"entry={len(entries)} outcome={len(outcomes)}")
        check("entries name the handler that ran",
              all(r.get("handler") == "ActiveHuntExecutor" for r in entries),
              sorted({str(r.get("handler")) for r in entries}))
        check("recon tasks were reached, not just bookkeeping",
              any(".recon." in str(r.get("task_key", "")) for r in entries),
              sorted(str(r.get("task_key")) for r in entries))
        check("every record carries provenance",
              all(r.get("run_id") and r.get("pid") and r.get("at")
                  for r in recs), "a record is missing run_id/pid/at")
        check("a real HTTP request reached the loopback target",
              "ok " + NONCE in proc.stdout or proc.returncode == 0,
              "nonce not echoed")

        print("\nR2  NEGATIVE CONTROLS - the check must be able to fail")
        # R2a: a stale artifact from another run must not satisfy the filter.
        stale = os.path.join(tmp, "stale.jsonl")
        with open(stale, "w", encoding="utf-8") as fh:
            fh.write(json.dumps({"phase": "entry", "task_key": "hunt.ghost",
                                 "handler": "ActiveHuntExecutor",
                                 "run_id": "ghost", "pid": 1,
                                 "at": time.time() - 99999}) + "\n")
        env = dict(os.environ)
        env.update(HERMES_DISPATCH_TRACE=stale, PYTHONPATH=ROOT,
                   WKS_ROOT=ROOT, WKS_DB=db_file)
        p2 = subprocess.run(
            [sys.executable, "-m", "orch.hunt_cli", "--target", "127.0.0.1",
             "--base-url", f"http://127.0.0.1:{port}/?nonce={NONCE}",
             "--in-scope", "127.0.0.1", "--out-of-scope", "example.com",
             "--hunt-id", f"{RUN}.stale",
             "--program", "hermetic-loopback-test",
             "--authorization-ref", "test-suite-hermetic-loopback",
             "--authorization-kind", "lab",
             "--allow", "recon",
             "--allow", "probe",
             "--max-cycles", "1"],
            cwd=ROOT, env=env, capture_output=True, text=True, timeout=280)
        sr = []
        with open(stale, encoding="utf-8") as fh:
            for line in fh:
                if line.strip():
                    sr.append(json.loads(line))
        filtered = [r for r in sr if r.get("run_id") == f"{RUN}.stale"
                    and float(r.get("at", 0)) >= time.time() - 600]
        ghost = [r for r in sr if r.get("run_id") == "ghost"]
        check("a foreign run's record is present in the file",
              len(ghost) == 1, "setup failed")
        check("but the run-id filter REJECTS it",
              all(r.get("run_id") != "ghost" for r in filtered),
              "a stale record survived the filter")

        # R2b: an EMPTY trace is a hard fail, never a skip.
        empty = os.path.join(tmp, "empty.jsonl")
        open(empty, "w", encoding="utf-8").close()
        ers = [r for r in [json.loads(l) for l in open(empty, encoding="utf-8")
                           if l.strip()] if r.get("phase") == "entry"]
        check("an empty artifact yields zero entries (hard fail, not a skip)",
              ers == [], ers)

        print("\nR3  THE REGRESSION THIS CHECK EXISTS FOR")
        he = os.path.join(ROOT, "orch", "hunt_exec.py")
        bak = he + ".reachbak"
        # MEASURED: this used to shell out to `cmd.exe /c copy /y` for the
        # backup and the restore. On WSL that binary does not exist, so the
        # test raised FileNotFoundError at the BACKUP step — before the
        # restore, leaving nothing broken but proving the test could not run
        # at all. Worse, a failure between the edit and the restore would have
        # left a live source file broken.
        #
        # The backup/restore is plain file I/O. It is portable, it cannot
        # depend on a Windows shell being on PATH, and it restores from an
        # in-memory copy of the ORIGINAL bytes even if the backup file itself
        # is unusable.
        original_bytes = None
        try:
            with open(he, "rb") as fh:
                original_bytes = fh.read()
            with open(bak, "wb") as fh:
                fh.write(original_bytes)
        except OSError as e:
            check("the source file could be backed up", False, str(e))
            original_bytes = None
        try:
            src = open(he, encoding="utf-8").read()
            # A TOTAL break: can_handle answers False for every key, which is
            # what a real dispatch regression looks like. MEASURED: breaking
            # only the `".recon."` clause is NOT a total break — the
            # `endswith(...)` clause still routes surface.build and
            # hypotheses.generate, so 2 legitimate entries still appear.
            #
            # The break is injected by AST, NOT by matching a literal block
            # of source text. MEASURED 2026-11-01: the check used a literal
            # string replace, and when `can_handle` legitimately gained a
            # third handled suffix (`.skill.resolve`) the replace stopped
            # matching — so the control silently stopped injecting its break
            # and reported "can_handle no longer matches this text". The
            # suite then failed at the INJECTION step rather than at the
            # check the injection exists for.
            #
            # That is the exact rot documented in CONTROL.md I33: "a guard
            # written as a string match on the code it guards can rot into
            # asserting the absence of the code". An AST edit replaces the
            # METHOD BODY whatever it currently contains, so the control
            # keeps testing the property it was written for as the method
            # evolves. The suite still fails loudly if the method cannot be
            # found at all.
            broken = _break_can_handle(src)
            check("the break could be injected", broken != src,
                  "can_handle could not be located or rewritten")
            if broken != src:
                open(he, "w", encoding="utf-8", newline="").write(broken)
                bt = os.path.join(tmp, "broken.jsonl")
                pb, rb, _, bw = _run_cli(bt, port, f"{RUN}.broken", db_file)
                eb = [r for r in rb if r.get("phase") == "entry"]
                check("UNDER A TOTAL BREAK the CLI still exits 0 "
                      "(this is why a check is required)",
                      pb.returncode == 0, f"exit={pb.returncode}")
                check("UNDER A TOTAL BREAK the trace path was still writable "
                      "(so zero entries means broken dispatch, not a bad path)",
                      not bw, pb.stdout[-300:])
                check("UNDER A TOTAL BREAK zero entries are recorded",
                      len(eb) == 0, f"entry={len(eb)}")
                check("=> the artifact DOES distinguish broken dispatch",
                      len(eb) == 0 and len(entries) > 0,
                      "baseline and broken are indistinguishable")
        finally:
            # Restore from the in-memory original bytes, not from the backup
            # file: the restore must not depend on the backup having been
            # written successfully.
            restored = False
            if original_bytes is not None:
                try:
                    with open(he, "wb") as fh:
                        fh.write(original_bytes)
                    restored = True
                except OSError as e:
                    check("the source file could be restored", False, str(e))
            if os.path.exists(bak):
                os.remove(bak)
            after = open(he, encoding="utf-8").read()
            check("the source file was restored intact",
                  restored and 'if ".recon." in k' in after,
                  "restore failed")
    finally:
        srv.shutdown()

    print(f"\nDISPATCH REACHABILITY: {PASS} pass, {FAIL} fail")
    return 1 if FAIL else 0


if __name__ == "__main__":
    raise SystemExit(main())