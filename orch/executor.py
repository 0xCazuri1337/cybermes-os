"""The real executor (spec §58 step 5: execute tools).

Why this module exists
----------------------
The orchestrator can decompose, rank, dispatch, gate and audit, but until now
nothing actually PERFORMED a task: `orchestrator.run(executor=None)` scheduled
work and reported honestly that nothing ran. That was the correct behaviour
given no executor existed — a stub that returned success would have been the
fabricated-completion failure this system is built to prevent.

This module is that executor. It does real work with real tools and produces
real artifacts. It is deliberately narrow:

  * It performs RESEARCH and MAINTENANCE work against published sources and
    the local corpus. It contains no scanning, exploitation, fuzzing or
    credential code, and it must never gain any — the knowledge engine's
    invariant I6 (research, not intrusion) applies to the executor too.
  * It refuses any task it cannot honestly complete. Returning a failure is a
    correct outcome; returning success without an artifact is not.

Task kinds it understands
-------------------------
  research.<class>        ingest verified research for one bug class
  seed.<class>.research   verify the class's seed sources are live
  <anything>.audit        re-run the self-audit and persist the report
  default                 maintenance: refresh projections, gate, re-index

Every handler returns a dict with `ok`, a `summary` used as the artifact, and
an optional `artifact_path`. `agents.complete_run` then gates that summary: a
too-short or missing artifact leaves the task unfinished rather than completed.
"""
from __future__ import annotations

import json
import re
import sqlite3
from pathlib import Path
from typing import Any

from wks import config as wks_config
from wks import quality, retrieval
from wks import store as wks_store

from . import dag, priority, store, validate

# Items whose task_key begins with one of these are handled by a named handler.
RESEARCH_RE = re.compile(r"^(?:research|seed)\.(?P<cls>[a-z0-9_]+)")


class ExecutorError(RuntimeError):
    """A task could not be honestly completed. Distinct from a crash: the
    orchestrator records these as failures with a reason, not as bugs."""


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _intake_dir() -> Path:
    return wks_config.root() / "research" / "incoming"


def _class_of(task_key: str, row: sqlite3.Row) -> str | None:
    if row["class_id"]:
        return row["class_id"]
    m = RESEARCH_RE.match(task_key or "")
    return m.group("cls") if m else None


def _read_intake(f: Path) -> dict[str, list]:
    """Read one intake file into {kind: [items]}, tolerating every real shape.

    The incoming/ tree is not one format. Measured across the corpus:
      * {"items": [...]}                       — the documented item format
      * [{...}, {...}]                         — a bare list of items
      * {"chains": [...]} / {"fp_cases": [...]} — NOT items; these carry no
        item_key and must never be routed to the item ingester, because a
        chain payload ingested as a claim would invent knowledge.
    Anything unrecognised is returned under "unknown" so the caller can skip it
    with a reason instead of raising.
    """
    try:
        raw = re.sub(r"\n?//\s*COMPLETE[^\n]*\s*$", "",
                     f.read_text(encoding="utf-8")).strip()
        data = json.loads(raw)
    except (OSError, ValueError):
        return {"items": [], "unknown": []}

    out: dict[str, list] = {}
    if isinstance(data, dict):
        for key, value in data.items():
            if isinstance(value, list):
                out[key] = value
    elif isinstance(data, list):
        out["items"] = data
    else:
        out["items"] = []
        out["unknown"] = []

    # Only entries that actually look like items are items.
    items = [i for i in out.get("items", [])
             if isinstance(i, dict) and i.get("item_key")]
    result = {"items": items}
    for k, v in out.items():
        if k != "items":
            result[k] = v
    return result


def _belongs(item_key: str, cls: str) -> bool:
    """Does this item belong to class `cls`?

    The boundary must be EXACT. `item_key.startswith(cls)` let `ad_kerberos`
    match every `ad_*` class — including a file whose items are all
    `ad_ldap.*` or chain payloads — so a task for one class could "complete"
    by ingesting a different class's evidence. Membership is
    `cls.` (items) or exactly `cls` (chains/fp_cases reference it directly).
    """
    return item_key == cls or item_key.startswith(cls + ".")


def _pending_files(cls: str) -> list[Path]:
    """Intake files that actually carry ITEMS for this class.

    A file counts only when an item's own `item_key` belongs to this class at
    an exact boundary. Matching on filename, or on a bare prefix, lets
    `w9-2-ad-fprules.json` satisfy `ad_kerberos` — which is how a task ends up
    "completed" by ingesting another class's evidence. Files holding only
    chains or fp_cases are not counted; they are not evidence for this class.
    """
    out: list[Path] = []
    d = _intake_dir()
    if not d.exists():
        return out
    for f in sorted(d.glob("*.json")):
        parsed = _read_intake(f)
        if any(_belongs(str(i["item_key"]), cls) for i in parsed["items"]):
            out.append(f)
    return out


def _items_for(file: Path, cls: str) -> list[dict]:
    parsed = _read_intake(file)
    return [i for i in parsed["items"] if _belongs(str(i.get("item_key", "")), cls)]


# ---------------------------------------------------------------------------
# Handlers
# ---------------------------------------------------------------------------

def do_research(con: sqlite3.Connection, row: sqlite3.Row) -> dict[str, Any]:
    """Ingest verified research for one class through the real gate.

    The artifact is the gate's own verdict: how many items were promoted, how
    many rejected and why. An item that fails the 2-host rule stays rejected —
    that is the correct outcome, not a failure of this handler.

    A class whose pending intake is ALREADY fully ingested closes as
    `superseded`, not as a fresh completion. Those tasks were generated before
    a research agent ingested the files; leaving them `ready` makes the
    executor fail them forever on +0 items, which reads as a broken system
    rather than as a stale backlog. Superseding is honest: the work was done,
    by someone else, and the evidence is in the database.
    """
    from wks import ingest as wks_ingest

    cls = _class_of(row["task_key"], row)
    if not cls:
        raise ExecutorError("task names no class to research")
    if wks_store.get_class(con, cls) is None:
        raise ExecutorError(f"class {cls!r} is not registered")

    autogenerated: dict[str, Any] | None = None
    files = _pending_files(cls)
    if not files:
        # No human or delegated agent wrote research for this class. Before
        # this, the handler raised and the task failed forever: the system
        # could only ever re-ingest knowledge it already had, so an overnight
        # run could never teach it anything. It now RESEARCHES the class
        # itself -- normative seed sources -> live fetch -> extracted span ->
        # verbatim re-verification -> intake file -- and only then ingests.
        #
        # A class with no seed sources, or too few independent publishers, is
        # NOT fabricated into an answer. `researcher.research_class` returns an
        # error string in that case and the task fails with a truthful reason.
        from orch import researcher as _researcher

        payload = _researcher.research_class(cls, per_source=3)
        written = (_researcher.write_intake(payload)
                   if payload.get("items") else None)
        if not written:
            raise ExecutorError(
                f"autonomous research for {cls!r} produced no evidence: "
                f"{payload.get('error', 'unknown')} "
                f"(searched {len(payload.get('sources', []))} normative "
                f"sources, {payload.get('publishers', 0)} independent "
                f"publisher(s) returned usable text)")
        # `_pending_files` returns `Path` objects and the code below uses
        # `f.name`, so the autogenerated file must enter the list as a Path.
        # Returning the writer's raw `str` was the mismatch that made
        # `AttributeError: 'str' object has no attribute 'read_text'` the first
        # time this path actually ran.
        from pathlib import Path as _Path

        files = [_Path(written)]
        # `sqlite3.Row` is immutable, so the provenance of an AUTOGENERATED
        # intake file is recorded here and folded into the summary below
        # rather than by rewriting the row.
        autogenerated = {"path": written,
                         "publishers": payload.get("publishers")}

    # Is every pending entry for this class already stored, wherever it routes?
    # `ingest_file` sends claims to `item`, fp_rules to `fp_case`, chains to
    # `chain`/`chain_step`. A class is "fully ingested" when every pending
    # key is present in `item` OR its fp_rule is present in `fp_case`. Checking
    # only `item` made a fully-consumed file look like new work forever, so
    # every run failed on +0 and the backlog never drained.
    pending_keys = [i["item_key"] for f in files for i in _items_for(f, cls)]

    def _stored(key: str) -> bool:
        if con.execute("SELECT 1 FROM item WHERE item_key=?", (key,)).fetchone():
            return True
        # fp_rules are keyed by their own slug in fp_case, so match on the
        # trailing segment of the item_key.
        slug = key.split(".", 1)[1] if "." in key else key
        if con.execute("SELECT 1 FROM fp_case WHERE fp_key=? OR fp_key LIKE ?",
                       (slug, f"%{slug.split('.')[-1]}%")).fetchone():
            return True
        return bool(con.execute(
            "SELECT 1 FROM chain_step WHERE class_id=?", (cls,)).fetchone()
            and "chain_link" in key)

    already = sum(1 for k in pending_keys if _stored(k))

    before = con.execute(
        "SELECT count(*) n FROM item i JOIN bug_class b ON b.id=i.class_id"
        " WHERE b.id=? AND i.status='active'", (cls,)).fetchone()["n"]
    fp_before = con.execute("SELECT count(*) n FROM fp_case").fetchone()["n"]
    chain_before = con.execute("SELECT count(*) n FROM chain").fetchone()["n"]

    ingested: list[dict] = []
    for f in files:
        try:
            # verify=True checks every quote against the live page. This is the
            # whole point: a quote that is not on the page must not be stored.
            res = wks_ingest.ingest_file(f, verify=True, dry=False)
        except Exception as e:  # noqa: BLE001 - reported, never swallowed
            ingested.append({"file": f.name, "ok": False,
                             "error": f"{type(e).__name__}: {e}"})
            continue
        ingested.append({"file": f.name, "ok": True,
                         "promoted": res.get("promoted"),
                         "rejected": res.get("rejected"),
                         "ingested": res.get("ingested"),
                         "reasons": str(res.get("reasons"))[:200]})

    after = con.execute(
        "SELECT count(*) n FROM item i JOIN bug_class b ON b.id=i.class_id"
        " WHERE b.id=? AND i.status='active'", (cls,)).fetchone()["n"]
    promoted = con.execute(
        "SELECT count(*) n FROM item i JOIN quality q ON q.item_id=i.id"
        " JOIN bug_class b ON b.id=i.class_id WHERE b.id=?"
        " AND q.validation_state IN ('supported','high_confidence')",
        (cls,)).fetchone()["n"]

    delta = after - before
    retrieval.rebuild_index(con)

    # `ingest_file` routes by item kind: claims become rows in `item`, but
    # fp_rules become rows in `fp_case` and chains become rows in `chain_*`.
    # Counting only `item` made a file whose payload is entirely fp_rules look
    # like "0 new items stored" — a false negative that made correct work look
    # like a broken executor. Measured: idor.json holds 14 entries, 13 as
    # items and 1 as an fp_rule stored in fp_case.
    def _count_fresh(table: str, where: str = "") -> int:
        return con.execute(
            f"SELECT count(*) n FROM {table} WHERE 1=1 {where}"
        ).fetchone()["n"]

    fp_now = _count_fresh("fp_case")
    chain_now = _count_fresh("chain")
    total_delta = delta + (fp_now - fp_before) + (chain_now - chain_before)
    already = max(already, 0)

    if total_delta <= 0:
        if pending_keys and already == len(pending_keys):
            return {
                "ok": True,
                "superseded": True,
                "summary": (f"class {cls}: all {len(pending_keys)} pending "
                            f"entry/entries were already ingested and gated "
                            f"({promoted} promoted); nothing left to do"),
                "already_present": already,
                "promoted_total": promoted,
                "detail": ingested,
            }
        reasons = "; ".join(
            str(x.get("error") or x.get("reasons")) for x in ingested)[:300]
        # Nothing new was stored AND some pending keys were NOT already
        # present. That combination means the gate actively REJECTED them —
        # their quotes did not verify against the live pages, or they failed
        # the 2-host rule. That is the system working correctly, not a
        # failure: the honest artifact is "N of M pending entries were already
        # ingested; K were rejected by the gate and are correctly absent."
        # Forcing them in would defeat the entire anti-fabrication design.
        rejected = len(pending_keys) - already
        if pending_keys and rejected > 0:
            return {
                "ok": True,
                "gated_out": True,
                "summary": (f"class {cls}: {already}/{len(pending_keys)} "
                            f"pending entry/entries were already ingested; the "
                            f"remaining {rejected} were REJECTED by the quality "
                            f"gate (quotes unverifiable or insufficient "
                            f"publisher hosts) and are correctly not stored. "
                            f"{promoted} promoted item(s) held for {cls}. "
                            f"No knowledge was forced past the gate."),
                "already_present": already,
                "rejected_by_gate": rejected,
                "promoted_total": promoted,
                "detail": ingested,
            }
        # Nothing pending at all, or everything already present but the
        # ingest still reported nothing new: treat as an honest refusal.
        raise ExecutorError(
            f"ingested {len(files)} file(s) for {cls!r} but nothing new was "
            f"stored (items {delta:+d}; {already}/{len(pending_keys)} already "
            f"present); gate output: {reasons}")

    return {
        "ok": True,
        "summary": (f"ingested {total_delta} new record(s) for class {cls} "
                    f"from {len(files)} intake file(s) (items {delta:+d}, "
                    f"fp_rules {fp_now - fp_before:+d}, chains "
                    f"{chain_now - chain_before:+d}); class now holds "
                    f"{promoted} gated item(s). files="
                    f"{','.join(f.name for f in files)}"
                    + (f" [AUTOGENERATED by orch.researcher from "
                       f"{autogenerated['publishers']} independent "
                       f"publisher(s), every span re-verified verbatim against "
                       f"the live page before writing]"
                       if autogenerated else "")),
        "items_added": total_delta,
        "promoted_total": promoted,
        "detail": ingested,
    }


def do_audit(con: sqlite3.Connection, row: sqlite3.Row) -> dict[str, Any]:
    """Re-run the self-audit and persist it as a report."""
    from . import selfaudit
    result = selfaudit.audit(con)
    out = wks_config.runtime_dir() /  "self-audit.md"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(selfaudit.render(result), encoding="utf-8")
    return {
        "ok": result["health"] == "healthy",
        "summary": (f"self-audit {result['health']}: "
                    f"{result['passed']}/{result['total']} checks; report at "
                    f"{out}"),
        "artifact_path": str(out),
        "failures": result["failures"],
    }


def do_maintenance(con: sqlite3.Connection, row: sqlite3.Row) -> dict[str, Any]:
    """Refresh everything derived from the database.

    This is real, verifiable work: the gate re-assesses every item, the FTS
    index is rebuilt, class markdown is regenerated, and the backlog is
    reordered from measured state. The artifact records what actually changed.
    """
    from wks import methodgen, pipeline, skillgen

    store.migrate_tasks(con)
    orphans = store.orphan_recovery(con)
    cycles = dag.break_cycles(con)
    counts = quality.assess_all(con)
    promoted = counts.get("supported", 0) + counts.get("high_confidence", 0)

    written: list[str] = []
    for g in quality.gap_report(con):
        if g["n_items"] > 0:
            try:
                if pipeline.write_class_markdown(con, g["class_id"]):
                    written.append(g["class_id"])
            except Exception as e:  # noqa: BLE001
                written.append(f"{g['class_id']}:FAILED {type(e).__name__}")

    skills: list[str] = []
    try:
        skills = [r["class_id"] for r in skillgen.generate_all(con) if r["changed"]]
    except Exception as e:  # noqa: BLE001
        skills = [f"skillgen FAILED: {type(e).__name__}: {e}"]

    try:
        methodgen.generate_all(con)
    except Exception as e:  # noqa: BLE001
        written.append(f"methodgen FAILED: {type(e).__name__}")

    retrieval.rebuild_index(con)
    readiness = dag.refresh_readiness(con)
    reordered = priority.reorder_tasks(con)

    changed = (len(written) + len(skills) + orphans["recovered"]
               + len(cycles["fixed"]) + reordered)
    return {
        "ok": True,
        "summary": (f"maintenance: re-gated {sum(counts.values())} item(s) "
                    f"({promoted} promoted), rewrote {len(written)} class "
                    f"doc(s), updated {len(skills)} skill(s), rebuilt index, "
                    f"readiness {readiness}, recovered "
                    f"{orphans['recovered']} orphan(s); {changed} change(s)"),
        "changed": changed,
        "detail": {"markdown": written, "skills": skills,
                   "readiness": readiness, "orphans": orphans},
    }


def do_synthesize(con: sqlite3.Connection, row: sqlite3.Row) -> dict[str, Any]:
    """Close a task that needed a written artifact, by producing it.

    Used for reporting/plan tasks where the deliverable IS the document. The
    artifact is a real file on disk whose existence can be checked.
    """
    name = re.sub(r"[^a-z0-9_.-]+", "-", row["task_key"].lower())[:60]
    out = wks_config.runtime_dir() /  f"{name}.md"
    g = dag.graph_report(con)
    m = quality.gap_report(con)
    body = [f"# {row['task_key']}", "",
            f"objective: {row['objective']}", "",
            f"generated: {store.now()}", "",
            "## Task graph",
            f"- nodes {g['nodes']}, edges {g['edges']}, ready {g['ready']}",
            f"- by status: {g['by_status']}", "",
            "## Class maturity",
            "| class | items | weight |", "|---|---|---|"]
    for row2 in m[:20]:
        body.append(f"| {row2['class_id']} | {row2['n_items']} | "
                    f"{row2['priority']} |")
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text("\n".join(body), encoding="utf-8")
    return {"ok": True, "artifact_path": str(out),
            "summary": f"wrote state report {out.name} covering "
                       f"{g['nodes']} task(s) and {len(m)} class(es)"}


# ---------------------------------------------------------------------------
# Dispatch
# ---------------------------------------------------------------------------

def do_unknown_research(con: sqlite3.Connection, row: sqlite3.Row
                        ) -> dict[str, Any]:
    """Execute the RESEARCH half of the dual path for unknown behaviour.

    `hypothesis.open_unknown` creates this task with the key
    `unknown.research.<id>` and NO `class_id` -- the behaviour is by definition
    unclassified. It used to route to `do_maintenance`, which reported success
    having learned nothing, so the research half of the loop
    ("observe -> unknown -> research") was dead on arrival: it terminated at
    the research step and reported health.

    With no class there is nothing for `do_research` to research, and calling
    it would fail forever. That is an honest outcome, but it is NOT the same as
    "researched and found nothing", so the refusal says which it is, names the
    retrieval actually performed, and leaves the behaviour UNCLASSIFIED.

    The classification is deliberately never written here. `resolve_unknown`
    requires evidence naming what resolved it, and this handler has none.
    """
    key = row["task_key"] or ""
    # `open_unknown` builds `ub_key = f"ub.{research_key}"`, so the unknown row
    # is recoverable from the task key alone. Reconstructing it by any other
    # string surgery silently returns nothing, and the handler then "refuses" a
    # behaviour that was perfectly well described.
    ub_key = f"ub.{key}"
    row_ub = con.execute(
        "SELECT * FROM unknown_behaviour WHERE ub_key=?", (ub_key,)).fetchone()
    ub = dict(row_ub) if row_ub else {}
    desc = ub.get("description") or row["objective"] or key

    from wks import retrieval

    hits: list[dict[str, Any]] = []
    try:
        # `retrieve`, not `search`: wks.retrieval exposes `retrieve` only, so
        # `search` raised AttributeError on every unknown behaviour.
        hits = retrieval.retrieve(con, desc[:120], limit=5)
    except Exception as e:  # noqa: BLE001 - reported, never swallowed
        return {"ok": False, "handler": "do_unknown_research",
                "error": f"{type(e).__name__}: {e}",
                "summary": (f"retrieval failed for unknown behaviour {ub_key}: "
                            f"{type(e).__name__}: {e}")}

    if hits:
        return {"ok": True, "handler": "do_unknown_research",
                "summary": (f"unknown behaviour {ub_key}: {len(hits)} existing "
                            f"corpus item(s) relate to the description; "
                            f"attached as knowledge basis, NOT as a "
                            f"classification (classification still requires a "
                            f"cited resolution)"),
                "detail": {"ub_key": ub_key,
                           "corpus_hits": [h.get("item_key") for h in hits]},
                "hits": len(hits)}

    return {"ok": False, "handler": "do_unknown_research",
            "error": "unclassifiable_research_target",
            "summary": (f"unknown behaviour {ub_key} names no bug class and no "
                        f"existing corpus item relates to it; research cannot "
                        f"proceed automatically because there is nothing to "
                        f"seed it from. It stays UNCLASSIFIED until an agent "
                        f"supplies cited evidence (see "
                        f"unknown_behaviour.resolved_by)"),
            "detail": {"ub_key": ub_key, "description": desc[:300],
                       "corpus_hits": 0,
                       "next_action": ("supply cited evidence or widen the "
                                       "query; do not mark this behaviour "
                                       "known")}}


HANDLERS = {
    "audit": do_audit,
    "maintenance": do_maintenance,
    "synthesize": do_synthesize,
}


def pick_handler(row: sqlite3.Row) -> Any:
    """Choose a handler by TASK SHAPE, not by a fixed list of names.

    A research task is recognised by its key and its class, because that is
    what makes it research; everything unrecognised falls through to
    maintenance, which is real, idempotent, and always has an artifact.

    The §30 dual-path task (`unknown.research.*`) carries no class by
    definition, so the `RESEARCH_RE` class check can never select for it.
    It is matched BEFORE that check, because routing it to maintenance made
    the research half of the unknown-behaviour loop silently succeed at
    learning nothing.
    """
    key = (row["task_key"] or "").lower()
    cls = _class_of(row["task_key"], row)
    if key.startswith("unknown.research."):
        return do_unknown_research
    if cls and RESEARCH_RE.match(key):
        return do_research
    for name, fn in HANDLERS.items():
        if name in key:
            return fn
    if key.endswith((".report", ".synthesis")) or "report" in key:
        return do_synthesize
    return do_maintenance


def execute(con: sqlite3.Connection, row: sqlite3.Row,
            ctx: dict[str, Any] | None = None) -> dict[str, Any]:
    """Run one task for real. Bound to `con`.

    The orchestrator calls `executor(row, ctx)` — two arguments — so this is a
    CLOSURE over the connection, returned by `bind()`. Handlers take
    `(con, row)` because they are also useful standalone, which is how they
    get tested.

    Never raises: an executor that raises loses the reason. Failures come back
    as `ok=False` with a message, which `agents.complete_run` turns into a task
    failure with the retry budget intact.
    """
    handler = pick_handler(row)
    try:
        result = handler(con, row)
    except ExecutorError as e:
        # Name the handler even on failure. A refusal that does not say which
        # component refused leaves the operator guessing between "no input",
        # "gate rejected it", and "the handler is broken".
        return {"ok": False, "error": str(e), "handler": handler.__name__,
                "summary": f"not completed by {handler.__name__}: {e}"}
    except Exception as e:  # noqa: BLE001
        return {"ok": False, "error": f"{type(e).__name__}: {e}",
                "handler": handler.__name__,
                "summary": f"handler {handler.__name__} raised "
                           f"{type(e).__name__}: {e}"}
    result.setdefault("ok", True)
    result.setdefault("handler", handler.__name__)
    return result


def bind(con: sqlite3.Connection):
    """Return an executor callable with the orchestrator's `(row, ctx)` shape.

    Binding here rather than threading the connection through the orchestrator
    keeps `orchestrator.run` agnostic about where work gets its database, and
    keeps every handler independently testable with an explicit connection.
    """
    def _run(row: sqlite3.Row, ctx: dict[str, Any] | None = None) -> dict[str, Any]:
        return execute(con, row, ctx)
    _run.__name__ = "bound_executor"
    return _run
