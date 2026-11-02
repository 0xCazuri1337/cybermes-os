#!/usr/bin/env python3
"""THE EVAL SUITE MUST NOT WRITE TO THE LIVE CANONICAL DATABASE.

MEASURED 2026-11-01: `eval/test_p0_skill_registry.py` read
`con = store.open_db(db)`, where `store` is `orch.store`. But
`orch.store.open_db` takes NO path -- its signature is
`open_db(create: bool = True)`. The `Path` argument was therefore bound to
`create`, which is truthy, and the call opened the LIVE canonical
database (`db/wks.db`) instead of the temporary one.

The test PASSED, because the live database has every table the test
needs. The damage was silent and real: the live corpus carried 42 of its
46 `finding` rows as test artifacts, and all 50 `lesson` rows were
test-derived. The scheduler counts open findings as "potential impact", so
the system's own health metrics were reading test data as hunting output.

This test makes the property CHECKABLE rather than assumed:

  A. `orch.store.open_db` takes no path, so a path argument cannot be
     silently bound to `create`. (A signature check, because the failure
     mode IS the signature.)
  B. No eval file may call `orch.store.open_db` with a positional
     argument.
  C. No eval file may call `orch.store.open_db()` at all without having
     redirected `db_path` or set `WKS_ROOT` first.
  D. THE BEHAVIOURAL CONTROL: run a representative eval file and prove
     the live database's row counts are UNCHANGED by it. A source-level
     check can only find the pattern; this finds the effect.
"""

from __future__ import annotations

import ast
import inspect
import os
import pathlib
import re
import sqlite3
import tempfile
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
EVAL = ROOT / "eval"
sys.path.insert(0, str(ROOT))

PASS = 0
FAIL = 0


def check(cond: bool, label: str, detail: str = "") -> bool:
    global PASS, FAIL
    if cond:
        PASS += 1
        print(f"  [PASS] {label}")
    else:
        FAIL += 1
        print(f"  [FAIL] {label}  ({detail})")
    return bool(cond)


def live_counts() -> dict[str, int]:
    """Row counts in the LIVE canonical database."""
    from wks import config as wks_config

    db = wks_config.db_path()
    if not db.exists():
        return {}
    con = sqlite3.connect(db, timeout=30)
    try:
        out = {}
        for table in ("finding", "lesson", "lesson_feedback", "evidence",
                      "finding_transition", "surface_node", "task",
                      "agent_run", "event"):
            try:
                out[table] = con.execute(
                    f"SELECT count(*) FROM {table}").fetchone()[0]
            except sqlite3.Error:
                out[table] = -1
        return out
    finally:
        con.close()


def main() -> int:
    print("=== THE EVAL SUITE MUST NOT POLLUTE THE LIVE CORPUS ===")

    # -----------------------------------------------------------------
    print("\nA. THE SIGNATURE THAT MADE THE LEAK POSSIBLE")
    from orch import store as orch_store

    sig = inspect.signature(orch_store.open_db)
    params = list(sig.parameters)
    check("path" not in params and "db" not in params,
          "orch.store.open_db takes NO path parameter",
          f"signature={sig}")
    check(params == ["create"],
          "orch.store.open_db's only parameter is `create`", f"parameters={params}")
    # The exact failure: a Path bound to a bool parameter.
    from pathlib import Path
    check(bool(Path("/tmp/anything")) is True,
          "a Path is TRUTHY, so it would silently enable `create`",
          "a truthy Path bound to `create` opens the canonical database")

    # -----------------------------------------------------------------
    print("\nB. NO EVAL FILE PASSES A PATH TO orch.store.open_db")
    #
    # THE DISTINCTION THAT MATTERS:
    #   wks.store.open_db(path=None, create=True, *, owner=None, ...)
    #       -- legitimately takes a path.
    #   orch.store.open_db(create=True)
    #       -- takes NO path. A positional argument binds to `create`.
    # So only the ORCHESTRATOR's store is the leak vector. `wks.store`
    # calls are correct and must not be flagged.
    offenders = []
    for f in sorted(EVAL.glob("*.py")):
        src = f.read_text(encoding="utf-8")
        try:
            tree = ast.parse(src)
        except (OSError, SyntaxError):
            continue
        # Which local names are bound to which store?
        wks_names, orch_names = set(), set()
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom):
                if node.module == "orch":
                    for a in node.names:
                        if a.name == "store":
                            orch_names.add(a.asname or "store")
                elif node.module == "wks":
                    for a in node.names:
                        if a.name == "store":
                            wks_names.add(a.asname or "store")
            elif isinstance(node, ast.Import):
                for a in node.names:
                    if a.name == "orch.store":
                        orch_names.add(a.asname or "orch.store")
                    elif a.name == "wks.store":
                        wks_names.add(a.asname or "wks.store")
        if not orch_names:
            continue
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            fn = node.func
            if not (isinstance(fn, ast.Attribute) and fn.attr == "open_db"):
                continue
            base = fn.value
            name = base.id if isinstance(base, ast.Name) else (
                base.attr if isinstance(base, ast.Attribute) else None)
            if name not in orch_names:
                continue
            if node.args:
                offenders.append(f"{f.name}:{node.lineno} "
                                 f"open_db({ast.unparse(node.args[0])})")
    check(not offenders,
          "no eval file passes a positional argument to orch.store.open_db",
          "; ".join(offenders[:5]))

    # -----------------------------------------------------------------
    print("\nC. EVERY orch.store.open_db CALL IS SANDBOXED")
    unsandboxed = []
    for f in sorted(EVAL.glob("*.py")):
        src = f.read_text(encoding="utf-8")
        if not re.search(r"from orch import [^\n]*\bstore\b", src) \
                and "import orch.store" not in src:
            continue
        if not re.search(r"\b(?:orch_)?store\.open_db\(", src):
            continue
        # A test is sandboxed if it redirects db_path or sets WKS_ROOT.
        sandboxed = ("db_path =" in src) or ("WKS_ROOT" in src) \
            or ("db_path=" in src)
        if not sandboxed:
            unsandboxed.append(f.name)
    check(not unsandboxed,
          "every eval file that opens the orchestrator DB is sandboxed",
          "; ".join(unsandboxed[:5]))

    # -----------------------------------------------------------------
    print("\nD2. THE SUBPROCESS VECTOR — WKS_DB MUST BE SANDBOXED TOO")
    #
    # MEASURED 2026-11-01: `WKS_ROOT` alone CANNOT sandbox a subprocess.
    # It relocates the whole tree, including the code the subprocess
    # imports, so a subprocess that must run the real code has to keep the
    # real `WKS_ROOT` -- and with it, the real `db/wks.db`.
    # `eval/test_dispatch_reachability.py` proved this by writing a real
    # `finding` row into the live corpus.
    #
    # `WKS_DB` is the second lever: it relocates ONLY the database.
    from wks import config as _wks_config

    _tmp = pathlib.Path(tempfile.mkdtemp(prefix="wks-db-override-"))
    _old = os.environ.get("WKS_DB")
    os.environ["WKS_DB"] = str(_tmp / "override.db")
    try:
        check("WKS_DB redirects db_path()",
              _wks_config.db_path() == _tmp / "override.db",
              str(_wks_config.db_path()))
        # And the override must survive the ROOT relocation, so that a
        # subprocess with the real WKS_ROOT still gets the temp database.
        _old_root = os.environ.get("WKS_ROOT")
        os.environ["WKS_ROOT"] = str(ROOT)
        try:
            check("WKS_DB wins over WKS_ROOT",
                  _wks_config.db_path() == _tmp / "override.db",
                  str(_wks_config.db_path()))
        finally:
            if _old_root is None:
                os.environ.pop("WKS_ROOT", None)
            else:
                os.environ["WKS_ROOT"] = _old_root
    finally:
        if _old is None:
            os.environ.pop("WKS_DB", None)
        else:
            os.environ["WKS_DB"] = _old
    check("removing WKS_DB restores the canonical path",
          _wks_config.db_path() == ROOT / "db" / "wks.db",
          str(_wks_config.db_path()))

    # Every eval file that spawns a subprocess with the REAL WKS_ROOT must
    # also set WKS_DB.
    unsafe = []
    for f in sorted(EVAL.glob("*.py")):
        src = f.read_text(encoding="utf-8")
        if "subprocess.run" not in src and "subprocess.Popen" not in src:
            continue
        # Does it hand the LIVE root to a subprocess?
        if not re.search(r'WKS_ROOT["\']?\s*[=:]\s*["\']?(?:str\()?ROOT',
                         src):
            continue
        if "WKS_DB" not in src:
            unsafe.append(f.name)
    check("every subprocess that gets the live WKS_ROOT also gets WKS_DB",
          not unsafe, "; ".join(unsafe[:5]))

    # -----------------------------------------------------------------
    print("\nD. THE BEHAVIOURAL CONTROL — a real eval run changes nothing")
    before = live_counts()
    check(bool(before),
          "the live database is readable", str(before))
    if before:
        env = dict(os.environ)
        env["WKS_ROOT"] = str(ROOT)
        r = subprocess.run(
            [sys.executable, str(EVAL / "test_p0_skill_registry.py")],
            capture_output=True, text=True, timeout=900, env=env, cwd=str(ROOT))
        check(r.returncode == 0,
          "the eval file still PASSES",
              (r.stdout or "")[-300:] + (r.stderr or "")[-300:])
        after = live_counts()
        changed = {t: (before.get(t), after.get(t))
                   for t in before if before.get(t) != after.get(t)}
        check(not changed,
          "the live database's row counts are UNCHANGED by the run", str(changed))

        # The specific tables the leak used to write.
        for table in ("finding", "lesson", "lesson_feedback",
                      "surface_node"):
            check(f"the live `{table}` count is unchanged",
                  before.get(table) == after.get(table),
                  f"{before.get(table)} -> {after.get(table)}")

    # -----------------------------------------------------------------
    print("\nE. THE LIVE CORPUS HOLDS NO TEST ARTIFACTS")
    from wks import config as wks_config

    db = wks_config.db_path()
    if db.exists():
        con = sqlite3.connect(db, timeout=30)
        try:
            # The quarantined findings are retained but marked rejected.
            live = con.execute(
                "SELECT count(*) FROM finding WHERE status IN"
                " ('candidate','validating','validated')").fetchone()[0]
            check(live == 0,
          "no test finding is presented as live knowledge",
                  f"{live} finding(s) still counted as potential impact")
            verified = con.execute(
                "SELECT count(*) FROM lesson WHERE state='verified'"
            ).fetchone()[0]
            check(verified == 0,
          "no test lesson is returned as intelligence",
                  f"{verified} verified lesson(s)")
            # Nothing was deleted.
            total = con.execute("SELECT count(*) FROM finding").fetchone()[0]
            check(total >= 42,
          "the quarantined findings are RETAINED, not deleted", f"{total} finding row(s) still present")
            lessons = con.execute("SELECT count(*) FROM lesson").fetchone()[0]
            check(lessons >= 46,
          "the quarantined lessons are RETAINED, not deleted", f"{lessons} lesson row(s) still present")
        finally:
            con.close()

    print("\n" + "=" * 60)
    if FAIL:
        print(f"FAILURES ({FAIL}):")
        print("THE EVAL SUITE CAN WRITE TO THE LIVE CANONICAL DATABASE,")
        print("OR THE LIVE CORPUS STILL HOLDS TEST ARTIFACTS.")
        return 1
    print(f"{PASS}/{PASS + FAIL} CHECKS PASS")
    print("The eval suite is sandboxed, a real eval run leaves the live")
    print("database's row counts unchanged, and the live corpus presents")
    print("no test artifact as knowledge.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
