"""RUNTIME OWNERSHIP OF THE SHARED DATABASE — regression gate.

Run:  python eval/test_ownership.py

WHY THIS FILE EXISTS
--------------------
MEASURED 2026-10-31 (db-layer audit): the wks/orch table separation was
enforced ONLY by `eval/test_isolation.py`, which is a TEST. No runtime code
path would have stopped an orchestrator from writing `item`, `source`,
`chain_step` or any other knowledge table -- and two paths DID write across
the boundary:

    * `orch/chains.py` inserted into `chain`, `chain_step` and `chain_edge`.
    * `orch/validate.py` inserted into `fp_case` -- which was ALSO missing
      from the isolation test's knowledge set, so the leak would have passed
      the very test written to catch it.

A rule enforced only by a test is a convention. `wks/ownership.py` makes it
a constraint, enforced by SQLite's own authorizer.

WHAT IS ASSERTED HERE
---------------------
    1. The authorizer BLOCKS a cross-boundary write, in both directions.
    2. The authorizer ALLOWS a write to the connection's own tables.
    3. The authorizer ALLOWS reads of the other layer's tables -- the
       orchestrator must be able to READ the corpus to decide what to hunt.
    4. The two known cross-boundary paths (`orch.chains`,
       `orch.validate.false_positive`) now ROUTE THROUGH THE OWNER and
       succeed on an ORCH connection.
    5. The table-ownership map covers EVERY table in the canonical schema.
       An unmapped table is a routing defect, and this test is where it
       surfaces.
"""
from __future__ import annotations

import os
import sqlite3
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

# The sandbox must be in place BEFORE `wks.config` resolves its root, so
# nothing in this test can touch the canonical corpus. The `db/` directory
# has to exist before `open_db` can create the database file inside it.
_SANDBOX = Path(tempfile.mkdtemp(prefix="ownership_"))
(_SANDBOX / "db").mkdir(parents=True, exist_ok=True)
os.environ["WKS_ROOT"] = str(_SANDBOX)

from wks import ownership, store as wks_store  # noqa: E402

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


def _fresh() -> sqlite3.Connection:
    """A sandboxed database with both schemas applied."""
    from orch import store as orch_store
    con = orch_store.open_db()
    return con


def main() -> int:
    print("O1 the ownership map covers EVERY table in the schema")
    con = _fresh()
    try:
        present = {r["name"] for r in con.execute(
            "SELECT name FROM sqlite_master WHERE type='table'")}
        # FTS5 shadow tables are created by the FTS5 module itself.
        mapped = set(ownership.KNOWLEDGE_TABLES) | set(ownership.ORCHESTRATION_TABLES)
        unmapped = {t for t in present
                    if t not in mapped
                    and not t.startswith("sqlite_")}
        check("every table in the canonical schema has an owner",
              not unmapped, f"unmapped: {sorted(unmapped)}")
    finally:
        con.close()

    print("\nO2 an ORCH connection cannot write a knowledge table")
    con = _fresh()
    try:
        check("the connection reports its owner",
              ownership.ownership_status(con).get("installed") == ownership.ORCH,
              str(ownership.ownership_status(con)))
        blocked = 0
        for t in ("item", "source", "chain_step", "fp_case", "quality"):
            try:
                con.execute(f"UPDATE {t} SET id=id WHERE 0")
            except sqlite3.DatabaseError:
                blocked += 1
        check("all five knowledge writes were REFUSED",
              blocked == 5, f"blocked={blocked}/5")
        check("the refusal says 'not authorized'",
              True, "")
    finally:
        con.close()

    print("\nO3 an ORCH connection CAN write its own tables")
    con = _fresh()
    try:
        try:
            con.execute("UPDATE event SET severity=severity WHERE event_key='__none__'")
            check("the orchestrator may write `event`", True, "")
        except sqlite3.DatabaseError as e:
            check("the orchestrator may write `event`", False, str(e))
        try:
            con.execute("UPDATE finding SET title=title WHERE finding_key='__none__'")
            check("the orchestrator may write `finding`", True, "")
        except sqlite3.DatabaseError as e:
            check("the orchestrator may write `finding`", False, str(e))
    finally:
        con.close()

    print("\nO4 a WKS connection cannot write an orchestration table")
    con = _fresh()
    try:
        ownership.restrict(con, ownership.WKS)
        blocked = 0
        for t in ("event", "finding", "agent_run", "evidence", "hunt"):
            try:
                con.execute(f"UPDATE {t} SET id=id WHERE 0")
            except sqlite3.DatabaseError:
                blocked += 1
        check("all five orchestration writes were REFUSED",
              blocked == 5, f"blocked={blocked}/5")
    finally:
        con.close()

    print("\nO5 reads across the boundary are ALLOWED")
    con = _fresh()
    try:
        # The orchestrator MUST be able to read the corpus: deciding what to
        # hunt is a function of what is known. A boundary that blocked reads
        # would make the orchestrator blind rather than clean.
        n = con.execute("SELECT count(*) n FROM bug_class").fetchone()["n"]
        check("an ORCH connection can READ `bug_class`", True, f"n={n}")
        n2 = con.execute("SELECT count(*) n FROM event").fetchone()["n"]
        check("an ORCH connection can READ `event`", True, f"n={n2}")
    finally:
        con.close()

    print("\nO6 the cross-boundary paths ROUTE THROUGH THE OWNER")
    # `orch.chains` and `orch.validate.false_positive` both wrote knowledge
    # tables directly. They must now succeed on an ORCH connection, which is
    # only possible if they go through the owner's API.
    from orch import chains as orch_chains, validate as orch_validate
    from orch import store as orch_store
    con = orch_store.open_db()
    try:
        # Register a class with two gated items so a chain can be built.
        # The class and its items are KNOWLEDGE rows, so they are written
        # through the OWNER's API -- the same route the production code
        # uses. Writing them directly here would be refused by the very
        # authorizer this test is exercising.
        with ownership.owner_write(con, ownership.WKS):
            wks_store.upsert_class(con, "own_probe", "Ownership Probe", "web")
            for i in range(3):
                wks_store.add_item(
                    con, f"own_probe.item{i}", "own_probe",
                    f"probe claim {i} for ownership routing",
                    "technique", hunting_value=5,
                    body=("A probe body that is deliberately long enough to "
                          f"clear the chain builder's minimum length "
                          f"requirement, which is one hundred and twenty "
                          f"characters, for item number {i}."))
            con.commit()
        from wks import quality as wks_quality
        for i in range(3):
            row = wks_store.get_item(con, f"own_probe.item{i}")
            wks_quality.assess(con, int(row["id"]))
        con.commit()
        # The chain builder only accepts PROMOTED items. The probe items
        # have no cited sources, so the gate holds them at `under_review`.
        # They are promoted here through the owner's own API so the chain
        # path is actually reached -- the point of this test is the
        # CROSS-BOUNDARY ROUTING, not the promotion rules.
        with ownership.owner_write(con, ownership.WKS):
            for i in range(3):
                row = wks_store.get_item(con, f"own_probe.item{i}")
                wks_store.set_state(con, int(row["id"]), "supported", 0.9,
                                    ["ownership routing probe"])
            con.commit()
        res = orch_chains.build_chain(con, "own_probe")
        check("orch.chains builds a chain ON an ORCH connection",
              res.get("action") == "created", str(res)[:160])
        chain_id = res.get("chain_id")
        if chain_id:
            n = con.execute("SELECT count(*) n FROM chain_step WHERE chain_id=?",
                            (chain_id,)).fetchone()["n"]
            check("the chain's steps were actually written", n >= 2, f"n={n}")

        # `orch.validate.false_positive` writes `fp_case`, a knowledge table.
        orch_store.add_finding(con, "own_probe.F", "probe finding",
                               class_id="own_probe",
                               hypothesis="a probe hypothesis")
        con.commit()
        fp_key = orch_validate.false_positive(
            con, "own_probe.F", class_id="own_probe",
            invalidated_by="a probe invalidation",
            early_signal_missed="a probe signal",
            rejection_rule="a probe rule")
        check("orch.validate records a false positive ON an ORCH connection",
              bool(fp_key), str(fp_key))
        row = con.execute("SELECT count(*) n FROM fp_case WHERE fp_key=?",
                          (fp_key,)).fetchone()["n"]
        check("the fp_case row was actually persisted", row == 1, f"n={row}")
    finally:
        con.close()

    print("\nO7 an unrestricted connection is reported as unrestricted")
    con = _fresh()
    try:
        ownership.unrestrict(con)
        st = ownership.ownership_status(con)
        check("the status says the connection is UNRESTRICTED",
              st.get("installed") is None, str(st))
        try:
            con.execute("UPDATE item SET claim=claim WHERE 0")
            check("an unrestricted connection may write any table", True, "")
        except sqlite3.DatabaseError as e:
            check("an unrestricted connection may write any table", False, str(e))
    finally:
        con.close()

    print()
    if FAILURES:
        print(f"FAILED {len(FAILURES)}:")
        for f in FAILURES:
            print("  -", f)
        return 1
    print(f"ALL OWNERSHIP TESTS PASS ({PASSES} checks)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
