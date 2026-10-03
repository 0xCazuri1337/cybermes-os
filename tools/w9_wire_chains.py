"""Wire chain assembly into wks.ingest.

MEASURED defect (2026-10-02, wave 9): a child submitted 4 items carrying a
`chain` block, `wks.ingest` reported all 4 `promoted`, and the `chain` table
gained ZERO rows. `chains` stayed at 8 in metrics while the child reported four
new chains. The chain structure was written into the item body and silently
dropped — the item read as a success, so the loss was invisible.

Root cause: `wks.ingest` never looked at `it["chain"]`. `wks/authoring.py`
already has `add_chain()` with the right validation (>=2 steps, every step needs
an action AND a why — "an unjustified chain is worse than no chain"), and
`wks/store.py` has the writers. Nothing connected them.

Fix: after an item is ACCEPTED, assemble any `chain` block it carries, through
the same validated `authoring.add_chain`. A malformed chain is reported, never
silently dropped, and never blocks the item itself (the item's evidence stands on
its own; the chain is a derived view).

Steps are bound to real items: a step naming an `item_key` that exists in the db
is linked by item_id, so `build_taxonomy.py` can render the chain with its
evidence.
"""
import io

P = r"C:/Users/Administrator/.hermes/cyber/wks/ingest.py"
src = io.open(P, encoding="utf-8").read()

# 1. assemble chains for accepted items, before the index rebuild
OLD = """    if not dry:
        retrieval.rebuild_index(con)
    con.close()"""
NEW = '''    # ---- chain assembly -------------------------------------------------
    # MEASURED: a `chain` block on an accepted item used to be dropped on the
    # floor. The item reported `promoted` and no chain row appeared, so four
    # researched chains read as four successes while `metrics` never moved.
    # Assemble through `authoring.add_chain`, which already refuses a chain with
    # fewer than 2 steps or a step with no justification.
    chains_written, chain_errors = [], []
    if not dry:
        for it in items:
            spec = it.get("chain")
            if not isinstance(spec, dict):
                continue
            key = it["item_key"]
            if (accepted if any(r["item_key"] == key for r in accepted)
                    else blocked):
                pass
            accepted_keys = {r["item_key"] for r in accepted}
            if key not in accepted_keys:
                # An unverified item must not anchor a chain.
                chain_errors.append({"item_key": key,
                                     "reason": "host item was not promoted"})
                continue
            # Bind each step to a REAL item so the chain renders with evidence.
            steps = []
            for s in (spec.get("steps") or []):
                s = dict(s)
                ref = s.pop("item_key", None)
                if ref:
                    row = con.execute(
                        "SELECT id, class_id FROM item WHERE item_key=?",
                        (ref,)).fetchone()
                    if row is not None:
                        s["item_id"] = int(row["id"])
                        s["class_id"] = s.get("class_id") or row["class_id"]
                steps.append(s)
            spec = dict(spec, steps=steps)
            if not spec.get("chain_key"):
                spec["chain_key"] = spec.get("name", "").lower().replace(" ", "-")
            good, msg = authoring.add_chain(con, spec)
            (chains_written if good else chain_errors).append(
                msg if good else {"item_key": key, "reason": msg})
        con.commit()

    if not dry:
        retrieval.rebuild_index(con)
    con.close()'''
if "chain assembly" in src:
    print("already wired; no change")
elif OLD not in src:
    raise SystemExit("rebuild_index anchor not found - refusing to guess")
else:
    src = src.replace(OLD, NEW, 1)

# 2. import authoring
OLDI = "from wks import config, quality, retrieval, store, verify_quotes  # noqa: E402"
if "authoring" not in src.split("REQUIRED")[0]:
    if OLDI not in src:
        raise SystemExit("import line not found - refusing to guess")
    src = src.replace(
        OLDI,
        "from wks import (authoring, config, quality, retrieval, store,  # noqa: E402\n"
        "                  verify_quotes)", 1)

# 3. surface the results in the return value and the CLI totals
OLDR = '''        "promoted": accepted, "held": blocked,
    }'''
NEWR = '''        "promoted": accepted, "held": blocked,
        "chains_written": chains_written, "chain_errors": chain_errors,
    }'''
if OLDR not in src:
    raise SystemExit("return dict anchor not found - refusing to guess")
src = src.replace(OLDR, NEWR, 1)

OLDP = '''        totals["shape_errors"] += len(r["shape_errors"])'''
NEWP = '''        totals["shape_errors"] += len(r["shape_errors"])
        totals["chains"] = totals.get("chains", 0) + len(r.get("chains_written", []))
        totals["chain_errors"] = totals.get("chain_errors", 0) + len(
            r.get("chain_errors", []))'''
if OLDP not in src:
    raise SystemExit("totals anchor not found - refusing to guess")
src = src.replace(OLDP, NEWP, 1)

OLDO = '''    print(f"\\nTOTAL submitted={totals['submitted']} promoted={totals['promoted']} "'''
NEWO = '''    for e in totals.get("_chain_error_detail", []):
        print(f"  CHAIN_ERROR {e.get('item_key')}: {e.get('reason')}")
    print(f"\\nTOTAL submitted={totals['submitted']} promoted={totals['promoted']} "'''
src = src.replace(OLDO, NEWO, 1)

# collect the detail for printing
src = src.replace(
    '''        totals["chain_errors"] = totals.get("chain_errors", 0) + len(
            r.get("chain_errors", []))''',
    '''        totals["chain_errors"] = totals.get("chain_errors", 0) + len(
            r.get("chain_errors", []))
        totals.setdefault("_chain_error_detail", []).extend(
            r.get("chain_errors", []))''', 1)

# 4. include chain count in the TOTAL line
src = src.replace(
    '''f"held={totals['held']} rejected={totals['rejected']} "
          f"shape_errors={totals['shape_errors']}")''',
    '''f"held={totals['held']} rejected={totals['rejected']} "
          f"shape_errors={totals['shape_errors']} "
          f"chains={totals.get('chains', 0)} "
          f"chain_errors={totals.get('chain_errors', 0)}")''', 1)

io.open(P, "w", encoding="utf-8").write(src)
print("patched", P)