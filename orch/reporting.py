"""Reporting, the hunt dossier, and next-cycle state
(master prompt §49, §50, §51, §52).

§49: "do not force a universal report format" — the format follows the program.
So `render()` asks the authorization context what the program requires and
falls back to a documented structure only when the program says nothing. The
fallback is named as a fallback, because a report that silently adopts the
wrong format is a report the program will bounce.

§51 requires the dossier to be MORE than the report: hunt history, validation
history, retest history, duplicate decisions, attack surface, scope
observations, important failed paths, research performed, knowledge changes,
remaining unexplored paths. `dossier()` builds it from stored state — it does
not ask the caller to narrate.

§52 requires the next hunt to begin from accumulated state rather than from
zero. `next_cycle_state()` writes exactly that, and `resume_hunt()` reads it
back, so the claim is a round trip rather than a promise.
"""
from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timezone
from typing import Any

from . import authz as authz_mod
from . import finalgate, huntrt, lifecycle as lifecycle_mod
from . import store

# §49 format registry. `renderer` names the function that produces the section
# set; nothing here assumes HackerOne is the platform.
PROGRAM_FORMATS: dict[str, dict[str, Any]] = {
    "hackerone": {"sections": ["Summary", "Steps to reproduce", "Impact",
                               "Evidence", "Severity", "Duplicate status"],
                  "severity_scale": "critical/high/medium/low/info"},
    "bugcrowd": {"sections": ["Summary", "Steps to reproduce", "Impact",
                               "Severity justification"],
                 "severity_scale": "P1-P5"},
    "intigriti": {"sections": ["Summary", "Proof of concept", "Impact",
                                "Remediation"],
                  "severity_scale": "critical/high/medium/low/info"},
    "vdp": {"sections": ["Summary", "Description", "Impact", "Remediation"],
            "severity_scale": "unspecified"},
    "internal": {"sections": ["Summary", "Technical detail", "Evidence",
                              "Impact", "Remediation"],
                 "severity_scale": "CVSS"},
    "lab": {"sections": ["Summary", "Steps to reproduce", "Expected vs actual",
                         "Lesson"],
            "severity_scale": "n/a"},
}

DEFAULT_SECTIONS = ("Summary", "Scope and authorization", "Technical detail",
                    "Steps to reproduce", "Impact", "Evidence", "Root cause",
                    "Affected component", "Attack path", "Severity rationale",
                    "Program compliance", "Duplicate status")


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


# ---------------------------------------------------------------------------
# §49 format selection + rendering
# ---------------------------------------------------------------------------

def program_format(ctx: authz_mod.AuthorizationContext | None) -> dict[str, Any]:
    """Pick the format the PROGRAM requires, and say when it is a default."""
    reporting = (ctx.reporting_requirements if ctx else {}) or {}
    named = str(reporting.get("format") or reporting.get("platform") or "").lower()
    for key, spec in PROGRAM_FORMATS.items():
        if key in named:
            return {"format": key, "source": "program_requirement",
                    "sections": tuple(spec["sections"]),
                    "severity_scale": spec["severity_scale"]}
    if reporting.get("sections"):
        return {"format": "custom",
                "source": "program_requirement",
                "sections": tuple(reporting["sections"]),
                "severity_scale": str(reporting.get("severity_scale", "unspecified"))}
    return {"format": "default", "source": "DEFAULT (program said nothing)",
            "sections": DEFAULT_SECTIONS, "severity_scale": "unspecified",
            "warning": ("no program reporting requirement was recorded, so "
                        "this structure is a documented default, not the "
                        "program's required format (§49)")}


def render(con: sqlite3.Connection, finding_key: str, *,
           ctx: authz_mod.AuthorizationContext | None = None,
           run: huntrt.HuntRuntime | None = None,
           reproduced: bool = False,
           claimant_run: str | None = None,
           validator_run: str | None = None) -> dict[str, Any]:
    """Render one finding's report, in the program's format if known.

    Refuses to write anything for a finding that has not cleared the final
    gate — §18's "reports must contain only validated claims" plus §48's "if a
    critical validation condition fails: NO REPORT".

    The reproduction and independence facts are PARAMETERS because the gate
    re-derives its verdict from them. `render` re-runs `finalgate.gate`, so a
    caller that had already established reproduction had to pass it again or
    the second gate would fail L3 on the same finding and refuse the report the
    first gate had just approved — a gate whose verdict depends on who asked.
    """
    f = con.execute("SELECT * FROM finding WHERE finding_key=?",
                    (finding_key,)).fetchone()
    if not f:
        return {"written": False, "reason": "finding does not exist"}

    gate = finalgate.gate(con, finding_key, reproduced=reproduced,
                          claimant_run=claimant_run,
                          validator_run=validator_run)
    fmt = program_format(ctx)
    lifecycle = lifecycle_mod.FindingLifecycle(con)
    state = lifecycle.state(finding_key)

    if not gate["report_ready"]:
        return {"written": False,
                "reason": "final validation gate not cleared",
                "verdict": gate["verdict"],
                "failed_critical": gate["failed_critical"],
                "return_to": gate["return_to"],
                "format": fmt["format"],
                "note": ("NO REPORT is the correct outcome here (§48); the "
                         "finding returns to "
                         f"{gate['return_to']} for more work")}

    ev = [dict(r) for r in con.execute(
        "SELECT kind, target, asset, endpoint, sha256, captured_at FROM evidence"
        " WHERE finding_id=?", (f["id"],))]
    paths = finalgate.validation_paths(con, finding_key)
    weakness = con.execute(
        "SELECT * FROM weakness_link WHERE finding_key=? LIMIT 1",
        (finding_key,)).fetchone()

    lines = [f"# {f['title']}", "",
             f"- finding_key: `{finding_key}`",
             f"- program format: **{fmt['format']}** ({fmt['source']})",
             f"- severity: {f['severity']} ({fmt['severity_scale']})",
             f"- validation: {gate['score']} "
             f"({len(paths['present'])} independent path(s): "
             f"{', '.join(paths['present'])})",
             f"- lifecycle: {state} -> REPORT_READY", ""]
    if fmt.get("warning"):
        lines += [f"> {fmt['warning']}", ""]

    sections = {
        "Summary": (f["title"] or "").strip() + ".\n\nHypothesis: " +
                    (f["hypothesis"] or "not stated"),
        "Scope and authorization": _scope_section(con, f, ctx),
        "Technical detail": _technical_section(f, weakness),
        "Steps to reproduce": _repro_section(con, finding_key),
        "Impact": (f"Stated impact: {(f['hypothesis'] or '')[:400]}\n\n"
                   f"Boundary crossed: {weakness['boundary'] if weakness else 'none recorded'}\n"
                   f"Privilege crossed: {weakness['privilege'] if weakness else 'none recorded'}"),
        "Evidence": _evidence_section(ev),
        "Root cause": (weakness["weakness"] if weakness
                       else "root cause not separately recorded"),
        "Affected component": f"target={f['target']} asset={f['asset']} "
                              f"endpoint={f['endpoint']}",
        "Attack path": _attack_path_section(weakness, con, finding_key),
        "Severity rationale": f"severity={f['severity']} on a "
                              f"{fmt['severity_scale']} scale; "
                              f"impact check: "
                              f"{gate['stages']['impact']['detail']}",
        "Program compliance": _compliance_section(con, ctx, f),
        "Duplicate status": _dup_section(con, finding_key),
    }

    for name in fmt["sections"]:
        if name in sections:
            lines += [f"## {name}", "", sections[name], ""]
    # Anything the format omits but §50 requires is APPENDED and marked, rather
    # than dropped. A program format is a minimum, not a licence to omit the
    # scope and duplicate sections.
    extra = [n for n in DEFAULT_SECTIONS if n not in fmt["sections"]]
    if extra:
        lines += ["", "---", "",
                  "## Sections required by the reporting standard but not named "
                  "by the program format", ""]
        for name in extra:
            lines += [f"### {name}", "", sections.get(name, "not recorded"), ""]

    text = "\n".join(lines)
    where = (run.write("reports", f"{finding_key}.md", text) if run
             else _default_report_path(finding_key))
    if run is None:
        from wks import config as wc
        p = wc.root() / "reports" / f"{finding_key}.md"
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text, encoding="utf-8")
        where = str(p)

    lifecycle.transition(finding_key, "DELIVERED", reason="report rendered",
                         changed_by="orch.reporting")
    store.set_finding_status(con, finding_key, "reported", report_path=where)
    quality = finalgate.report_quality(where,
                                       program_requirements=ctx.reporting_requirements
                                       if ctx else None)
    return {"written": True, "path": where, "format": fmt,
            "gate": gate["verdict"], "quality": quality,
            "sections": list(fmt["sections"])}


def _default_report_path(finding_key: str) -> str:
    from wks import config as wc
    return str(wc.root() / "reports" / f"{finding_key}.md")


def _scope_section(con, f, ctx) -> str:
    rows = con.execute(
        "SELECT asset, verdict, tested FROM scope_observation WHERE asset IN"
        " (?, ?)", ((f["target"] or "").lower(), (f["asset"] or "").lower())
    ).fetchall()
    lines = []
    if ctx:
        lines += [f"- program: {ctx.program}",
                  f"- authorization ref: {ctx.authorization_ref}",
                  f"- kind: {ctx.kind}",
                  f"- in scope: {', '.join(ctx.in_scope_assets) or 'none'}",
                  f"- out of scope: {', '.join(ctx.out_of_scope_assets) or 'none'}",
                  f"- allowed actions: {', '.join(ctx.allowed_actions) or 'none'}"]
    for r in rows:
        lines.append(f"- {r['asset']}: {r['verdict']} (tested={r['tested']})")
    if not rows and not ctx:
        lines.append("- NO authorization record; this report would not have "
                     "been produced")
    return "\n".join(lines)


def _technical_section(f, weakness) -> str:
    bits = [f"- class: {f['class_id'] or 'not classified'}",
            f"- hypothesis: {f['hypothesis'] or 'not stated'}"]
    if weakness:
        bits += [f"- entry point: {weakness['entry_node']}",
                 f"- weakness: {weakness['weakness']}",
                 f"- rationale: {weakness['rationale'] or 'not recorded'}"]
    return "\n".join(bits)


def _repro_section(con, finding_key) -> str:
    rows = con.execute(
        "SELECT kind, endpoint, payload, sha256 FROM evidence WHERE finding_id="
        "(SELECT id FROM finding WHERE finding_key=?) ORDER BY id",
        (finding_key,)).fetchall()
    if not rows:
        return ("no reproduction evidence recorded — this section is present "
                "because the format requires it, and its absence is itself the "
                "finding about the evidence")
    return "\n".join(f"- [{r['kind']}] {r['endpoint'] or ''} "
                     f"sha256={r['sha256'][:16]} "
                     f"payload={(r['payload'] or '')[:120]}" for r in rows)


def _evidence_section(ev) -> str:
    if not ev:
        return "no evidence rows"
    return "\n".join(f"- {e['kind']}: target={e['target']} endpoint={e['endpoint']} "
                     f"sha256={(e['sha256'] or '')[:16]} at {e['captured_at']}"
                     for e in ev)


def _attack_path_section(weakness, con, finding_key) -> str:
    if not weakness:
        return "no weakness link recorded"
    parts = [f"entry={weakness['entry_node']}",
             f"weakness={weakness['weakness']}",
             f"boundary={weakness['boundary'] or 'none'}",
             f"privilege={weakness['privilege'] or 'none'}",
             f"sensitive={weakness['sensitive'] or 'none'}",
             f"impact={weakness['impact'] or 'none'}"]
    chains = con.execute(
        "SELECT verdict, rung, reason FROM dedup_decision WHERE finding_key=?",
        (finding_key,)).fetchall()
    for c in chains:
        parts.append(f"dedup: {c['verdict']} via {c['rung']}")
    return "\n".join(parts)


def _compliance_section(con, ctx, f) -> str:
    n = con.execute(
        "SELECT count(*) n FROM tool_attempt WHERE outcome IN ('refused',"
        "'substituted') AND target=?", (f["target"],)).fetchone()["n"]
    bits = [f"- refused or substituted tool attempts on this target: {n}"]
    if ctx:
        bits += [f"- rate limits: {json.dumps(ctx.rate_limits) or 'program default'}",
                 f"- special rules: {'; '.join(ctx.special_rules) or 'none'}",
                 f"- prohibited techniques attempted: none permitted"]
    gaps = con.execute(
        "SELECT DISTINCT substitute, tool FROM tool_attempt WHERE outcome='"
        "substituted' AND target=?", (f["target"],)).fetchall()
    for g in gaps:
        bits.append(f"- tool substitution: {g['tool']} -> {g['substitute']}")
    return "\n".join(bits)


def _dup_section(con, finding_key) -> str:
    rows = con.execute(
        "SELECT vs_key, verdict, rung, reason FROM dedup_decision WHERE"
        " finding_key=?", (finding_key,)).fetchall()
    if not rows:
        return "the §38 ladder recorded no comparison"
    return "\n".join(f"- vs {r['vs_key']}: {r['verdict']} via {r['rung']} "
                     f"({r['reason']})" for r in rows)


# ---------------------------------------------------------------------------
# §51 final hunt dossier — more than the report
# ---------------------------------------------------------------------------

def dossier(con: sqlite3.Connection, hunt_id: str, *,
            run: huntrt.HuntRuntime | None = None) -> dict[str, Any]:
    """Build the dossier from stored state. Nothing here is narrated."""
    hr = run or huntrt.HuntRuntime(hunt_id)
    lc = lifecycle_mod.FindingLifecycle(con, hunt_id)

    findings = [dict(r) for r in con.execute(
        "SELECT finding_key, title, status, severity, class_id, endpoint,"
        " validation_json, report_path FROM finding ORDER BY id")]
    board = lc.board()
    # `evidence` carries finding_id, not finding_key. Joining is the only way
    # to attribute a row without duplicating the key onto every write.
    evidence = [dict(r) for r in con.execute(
        "SELECT COALESCE(f.finding_key, e.finding_id) AS finding_key,"
        " e.kind, e.sha256, e.provenance, e.captured_at"
        " FROM evidence e LEFT JOIN finding f ON f.id = e.finding_id"
        " ORDER BY e.id")]
    retests = [dict(r) for r in con.execute(
        "SELECT finding_key, trigger, verdict, detail, at FROM retest_record"
        " ORDER BY at")]
    dedups = [dict(r) for r in con.execute(
        "SELECT finding_key, vs_key, verdict, rung, reason, at FROM"
        " dedup_decision ORDER BY at")]
    surface_nodes = [dict(r) for r in con.execute(
        "SELECT kind, name, observed FROM surface_node WHERE hunt_id=?"
        " ORDER BY kind, name", (hunt_id,))]
    surface_edges = [dict(r) for r in con.execute(
        "SELECT src, dst, rel FROM surface_edge WHERE hunt_id=?", (hunt_id,))]
    scope = [dict(r) for r in con.execute(
        "SELECT asset, verdict, tested, discovered_by, evidence FROM"
        " scope_observation ORDER BY asset")]
    changes = lc.changes()
    attempts = [dict(r) for r in con.execute(
        "SELECT tool, outcome, detail, substitute, at FROM tool_attempt WHERE"
        " hunt_id=? ORDER BY attempt_id", (hunt_id,))]
    hyps = [dict(r) for r in con.execute(
        "SELECT hyp_key, statement, class_id, status, origin, confidence FROM"
        " hypothesis WHERE hunt_id=? ORDER BY created_at", (hunt_id,))]
    unknowns = [dict(r) for r in con.execute(
        "SELECT ub_key, description, classification, resolved_by FROM"
        " unknown_behaviour WHERE hunt_id=?", (hunt_id,))]
    research = [dict(r) for r in con.execute(
            "SELECT task_key, objective, status, result FROM task"
            " WHERE task_key LIKE 'research.%' OR class_id IS NOT NULL")]
    events = [dict(r) for r in con.execute(
        "SELECT event_key, kind, source, severity, state, relevance FROM event"
        " ORDER BY id DESC LIMIT 100")]

    failed_paths = [a for a in attempts
                    if a["outcome"] in ("failed", "unavailable", "refused")]
    knowledge_changes = [e for e in events
                         if e["kind"] in ("cve", "technique", "gap")]

    report = {
        "hunt_id": hunt_id,
        "generated_at": _now(),
        "findings": findings,
        "finding_lifecycle": {k: v for k, v in board.items() if v},
        "evidence_chain": evidence,
        "validation_history": [
            {"finding_key": f["finding_key"], "vector": f["validation_json"]}
            for f in findings if f["validation_json"]],
        "retest_history": retests,
        "duplicate_decisions": dedups,
        "attack_surface": {"nodes": surface_nodes, "edges": surface_edges},
        "scope_observations": scope,
        "hunt_history": hr.history(),
        "important_failed_paths": failed_paths,
        "research_performed": research,
        "knowledge_changes": knowledge_changes,
        "hypotheses": hyps,
        "unknown_behaviours": unknowns,
        "tool_attempts": attempts,
        "remaining_unexplored_paths": remaining_paths(con, hunt_id),
    }
    if run is not None:
        path = run.write("reports", "DOSSIER.json",
                         json.dumps(report, default=str, indent=2))
        report["dossier_path"] = path
    return report


def remaining_paths(con: sqlite3.Connection, hunt_id: str) -> dict[str, Any]:
    """§51's "remaining unexplored paths" and §52's open questions."""
    open_hyps = con.execute(
        "SELECT hyp_key, statement, confidence FROM hypothesis WHERE hunt_id=?"
        " AND status IN ('open','testing','unknown_researching')",
        (hunt_id,)).fetchall()
    queued = con.execute(
        "SELECT finding_key, reason FROM revalidation_queue WHERE state='queued'"
    ).fetchall()
    blocked = con.execute(
        "SELECT task_key, objective, result FROM task WHERE status='blocked'"
    ).fetchall()
    ready = con.execute(
        "SELECT task_key FROM task WHERE status='ready'").fetchall()
    unknown = con.execute(
        "SELECT ub_key, description FROM unknown_behaviour WHERE hunt_id=?"
        " AND resolved_by IS NULL", (hunt_id,)).fetchall()
    return {"open_hypotheses": [dict(r) for r in open_hyps],
            "revalidation_queue": [dict(r) for r in queued],
            "blocked_tasks": [dict(r) for r in blocked],
            "ready_tasks": [dict(r) for r in ready],
            "unresolved_unknown_behaviour": [dict(r) for r in unknown]}


# ---------------------------------------------------------------------------
# §52 next-cycle state
# ---------------------------------------------------------------------------

def next_cycle_state(con: sqlite3.Connection, hunt_id: str, *,
                     completion: dict[str, Any] | None = None,
                     run: huntrt.HuntRuntime | None = None) -> dict[str, Any]:
    """Persist what the NEXT hunt needs to know. Readable, not resumable-only."""
    hr = run or huntrt.HuntRuntime(hunt_id)
    rem = remaining_paths(con, hunt_id)
    blocked = [t for t in rem["blocked_tasks"]]
    ready = [t["task_key"] for t in rem["ready_tasks"]]
    state = {
        "hunt_id": hunt_id,
        "generated_at": _now(),
        "what_remains_unexplored": rem["open_hypotheses"] + rem["blocked_tasks"],
        "what_was_exhausted": [t["task_key"] for t in con.execute(
            "SELECT task_key FROM task WHERE status IN"
            " ('completed','superseded')")],
        "what_changed": [dict(r) for r in con.execute(
            "SELECT kind, subject, before, after FROM target_change WHERE"
            " hunt_id=?", (hunt_id,))],
        "what_was_learned": [dict(r) for r in con.execute(
            "SELECT hyp_key, statement, class_id, status FROM hypothesis WHERE"
            " hunt_id=?", (hunt_id,))],
        "what_failed": [dict(r) for r in con.execute(
            "SELECT tool, outcome, detail FROM tool_attempt WHERE hunt_id=? AND"
            " outcome!='ok'", (hunt_id,))],
        "what_should_be_revisited": [t["task_key"] for t in blocked],
        "open_hypotheses": [h["hyp_key"] for h in rem["open_hypotheses"]],
        "assets_discovered": [dict(r) for r in con.execute(
            "SELECT name, kind, observed FROM surface_node WHERE hunt_id=?",
            (hunt_id,))],
        "knowledge_available": {
                    # class_id lives on `item`; `quality` carries the state. Counting a
                    # class_id column on quality raised "no such column" on every hunt
                    # closure, which is why next-cycle state was never written — the
                    # artefact §52 depends on was silently unreachable.
                    "classes_with_promoted_items": con.execute(
                        "SELECT count(DISTINCT i.class_id) n FROM quality q"
                        " JOIN item i ON i.id = q.item_id WHERE"
                        " q.validation_state IN ('supported','high_confidence')"
                    ).fetchone()["n"],
            "classes_known_weak": [dict(r) for r in con.execute(
                "SELECT class_id, count(*) n FROM item WHERE status='active'"
                " GROUP BY class_id HAVING n < 3")],
        },
        "next_cycle_priority": (
            completion.get("decision") if completion else None),
        "resume_from": "runtime/hunts/%s/history/checkpoint-hunt.json" % hunt_id,
    }
    if run is not None:
        path = run.write("history", "next-cycle.json",
                         json.dumps(state, default=str, indent=2))
        state["path"] = path
        run.save_checkpoint({"at": _now(), "state": state,
                             "ready": ready}, name="hunt")
    return state


def resume_hunt(hunt_id: str) -> dict[str, Any]:
    """§52's payoff: the next hunt starts from accumulated state."""
    hr = huntrt.HuntRuntime(hunt_id)
    p = hr.dir("history") / "next-cycle.json"
    if not p.exists():
        return {"hunt_id": hunt_id, "resumable": False,
                "reason": "no next-cycle state; this hunt has not closed"}
    state = json.loads(p.read_text(encoding="utf-8"))
    return {"hunt_id": hunt_id, "resumable": True, "state": state,
            "open_hypotheses": state.get("open_hypotheses", []),
            "should_revisit": state.get("what_should_be_revisited", []),
            "priority": state.get("next_cycle_priority"),
            "assets": len(state.get("assets_discovered", []))}