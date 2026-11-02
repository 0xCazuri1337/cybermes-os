"""Command line interface. One entry point, no framework.

    python -m wks.cli init                    create schema
    python -m wks.cli selftest                run the gate regressions
    python -m wks.cli add-class ID NAME SURF  register a bug class
    python -m wks.cli ingest FILE.json        load researched items
    python -m wks.cli gate                    re-assess every item
    python -m wks.cli search "query"          retrieve (trust-ranked)
    python -m wks.cli show CLASS              class digest
    python -m wks.cli gaps                    weakest classes first
    python -m wks.cli tasks                   backlog / next task
    python -m wks.cli cycle                   one autonomous improvement cycle
    python -m wks.cli report                  last run summary
    python -m wks.cli metrics                 quality metrics
    python -m wks.cli probe                   retrieval relevance probes
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from . import config, pipeline, quality, retrieval, store


def _con(args):
    return store.open_db(create=getattr(args, "init", False) or not config.db_path().exists())


def cmd_init(args) -> int:
    con = store.open_db(create=True)
    retrieval.rebuild_index(con)
    print(f"WKS initialised at {config.db_path()}")
    con.close()
    return 0


def cmd_selftest(args) -> int:
    here = Path(__file__).resolve().parent.parent / "eval" / "test_wks.py"
    sys.path.insert(0, str(here.parent))
    import importlib.util
    spec = importlib.util.spec_from_file_location("wks_selftest", here)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod.run()


def cmd_add_class(args) -> int:
    con = store.open_db(create=True)
    store.upsert_class(con, args.id, args.name, args.surface,
                       cwe=args.cwe, owasp=args.owasp, summary=args.summary)
    con.commit()
    print(f"class {args.id} registered ({args.surface})")
    con.close()
    return 0


def cmd_ingest(args) -> int:
    """Load researched items through the VERIFIED ingest boundary.

    MEASURED DEFECT (P0): this command used to call
    `pipeline.ingest_claim` directly, which stores whatever quote string it
    is handed and re-gates it. That is the UNVERIFIED path: no page was
    fetched and no quote was checked, so a fabricated quote was stored and
    then scored by the gate exactly like a real one. `wks.ingest.ingest_file`
    is the verified boundary — it fetches each cited page, matches the quote
    against the live bytes, and REJECTS an item whose quote is not present.

    `scripts/ingest-loop.sh` (the operational batch path) invoked this
    command, so the bypass was not a theoretical alternative entry point: it
    was the one the loop actually used.

    There is now ONE ingest boundary. This command delegates to it.
    """
    from wks import ingest as _ingest

    result = _ingest.ingest_file(Path(args.file),
                                 verify=not getattr(args, "no_verify", False),
                                 dry=getattr(args, "dry", False))
    for e in result.get("shape_errors", []):
        print(f"  SHAPE  {e['item_key']}: missing {e['missing']}")
    for e in result.get("rejected_fabricated", []):
        print(f"  REJECT {e['item_key']}: {e['reason']}")
    for r in result.get("promoted", []):
        flag = "!!" if r.get("tags") else "  "
        print(f"{flag} {r['item_key']:38} {r['state']:15} "
              f"{r['score']:.2f}  {','.join(r.get('tags', [])[:2])}")
    for r in result.get("held", []):
        flag = "!!" if r.get("tags") else "  "
        print(f"{flag} {r['item_key']:38} {r['state']:15} "
              f"{r['score']:.2f}  {','.join(r.get('tags', [])[:2])}")
    print(f"submitted={result['submitted']} "
          f"promoted={len(result['promoted'])} "
          f"held={len(result['held'])} "
          f"rejected={len(result['rejected_fabricated'])} "
          f"shape_errors={len(result['shape_errors'])}")
    return 0


def cmd_gate(args) -> int:
    con = store.open_db()
    counts = quality.assess_all(con)
    retrieval.rebuild_index(con)
    for k, v in sorted(counts.items(), key=lambda p: -p[1]):
        print(f"  {k:16} {v}")
    con.close()
    return 0


def cmd_search(args) -> int:
    con = store.open_db()
    hits = retrieval.retrieve(con, " ".join(args.query),
                             class_id=args.class_id, limit=args.limit,
                             states=args.state or None)
    if not hits:
        print("no hits")
    for h in hits:
        print(f"\n[{h['state']}] rel={h['relevance']:.3f} score={h['score']:.2f} "
              f"({h['class_id']}/{h['kind']})")
        print(f"  {h['claim']}")
        if h["disproof"]:
            print(f"  disproved by: {h['disproof']}")
        for s in h["sources"]:
            q = (s["quote"] or "")[:80]
            print(f"  - {s['host']} q={q}")
        for c in h["chains"]:
            print(f"  chain: {c['name']} ({c['goal']})")
        for c in h["conflicts"]:
            print(f"  CONFLICT[{c['topic']}]: {c['other_claim'][:70]}")
    con.close()
    return 0


def cmd_show(args) -> int:
    con = store.open_db()
    print(json.dumps(retrieval.class_digest(con, args.class_id),
                     indent=2, default=str))
    con.close()
    return 0


def cmd_gaps(args) -> int:
    con = store.open_db()
    print(f"{'class':24} {'state':12} {'pri':>4} {'items':>5} {'sup':>4} "
          f"{'fp':>3} {'chn':>3}  missing")
    for g in quality.gap_report(con):
        print(f"{g['class_id']:24} {g['state']:12} {g['priority']:>4} "
              f"{g['n_items']:>5} {g['n_supported']:>4} {g['n_fp']:>3} "
              f"{g['n_chains']:>3}  {','.join(g['missing'][:4])}")
    con.close()
    return 0


def cmd_tasks(args) -> int:
    con = store.open_db()
    if args.generate:
        for t in pipeline.next_tasks(con):
            print(f"  + {t['task_key']} (p{t['priority']})")
    nxt = store.next_task(con)
    if nxt:
        print(f"\nNEXT: {nxt['task_key']} [p{nxt['priority']}] {nxt['objective']}")
        print(f"  artifact: {nxt['expected_artifact']}")
        print(f"  evidence: {nxt['evidence_req']}")
    else:
        print("no runnable task")
    pending = con.execute(
        "SELECT status, count(*) n FROM task GROUP BY status").fetchall()
    print("\nbacklog: " + ", ".join(f"{r['status']}={r['n']}" for r in pending))
    con.close()
    return 0


def cmd_metrics(args) -> int:
    """Published metrics. Takes a FROZEN COPY by default.

    MEASURED (audit 2026-10-02): passing the live connection here produced a
    number that depended on WHEN it was run -- items_total read 471 in one pass
    and 501 in another during a single audit, because two cron loops were
    ingesting. `evalm.metrics()` can guarantee consistency only when the caller
    does not supply its own connection, so this no longer supplies one.
    `--live` opts into the old behaviour and says so in the output.
    """
    from . import evalm
    if getattr(args, "live", False):
        con = store.open_db(create=False)
        out = evalm.metrics(con)
        con.close()
    else:
        out = evalm.metrics()   # frozen copy; no writer can invalidate it
    print(json.dumps(out, indent=2, default=str))
    return 0


def cmd_cycle(args) -> int:
    from . import cycle
    con = store.open_db(create=True)
    r = cycle.run_cycle(con, max_items=args.max_items)
    print(r["summary"])
    con.close()
    return 0


def cmd_skills_sync(args) -> int:
    """Refresh (or check) every artifact derived from the corpus.

    Thin wrapper over wks.project so the CLI, the cycle and ingest all reach
    the SAME writers. A second implementation here would be a third owner for
    the same file, which is the duplicate-owner defect the domains refactor
    exists to prevent.
    """
    from . import project
    argv: list[str] = []
    if args.check:
        argv.append("--check")
    if args.apply:
        argv.append("--apply")
    if args.json:
        argv.append("--json")
    for c in (args.classes or []):
        argv += ["--class", c]
    return project.main(argv)


def cmd_probe(args) -> int:
    from . import evalm
    con = store.open_db()
    print(json.dumps(evalm.retrieval_probe(con), indent=2, default=str))
    con.close()
    return 0


def cmd_report(args) -> int:
    con = store.open_db()
    row = con.execute(
        "SELECT * FROM run ORDER BY id DESC LIMIT 1").fetchone()
    if not row:
        print("no runs recorded")
        return 1
    print(f"# run {row['run_key']}  ({row['status']})")
    print(f"started {row['started_at']}  finished {row['finished_at']}")
    print()
    print(row["summary_md"] or "")
    con.close()
    return 0


def cmd_verify_seeds(args) -> int:
    from . import network_taxonomy as nettax, pipeline, taxonomy
    # `domain=all` is the default because a dead seed in EITHER domain is a
    # defect of the same system, and a checker that only ever looks at the half
    # that happens to be populated reports clean while half the tree rots.
    dom = getattr(args, "domain", "all")
    seeds = dict(taxonomy.SEEDS)
    if dom in ("all", "network"):
        seeds.update(nettax.NET_SEEDS)
    if dom == "web":
        seeds = dict(taxonomy.SEEDS)
    rep = pipeline.verify_seed(seeds)
    out = config.runtime_dir() /  "seed-verification.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(rep, indent=2), encoding="utf-8")
    print(f"classes={len(rep['classes'])} "
          f"corroboration-capable={rep['ok']} dead_urls={rep['n_dead']}")
    for cid, e in rep["classes"].items():
        flag = "" if e["corroboration_possible"] else "  <-- CAN NEVER CORROBORATE"
        print(f"  {cid:16} urls={e['n_urls']} hosts={e['n_hosts']}{flag}")
        for u in e["dead"]:
            print(f"      DEAD {u}")
    print(f"\nwritten: {out}")
    return 0 if rep["ok"] else 1


def cmd_seed(args) -> int:
    from . import seed as seeder
    con = store.open_db(create=True)
    r = seeder.seed(con, domain=getattr(args, "domain", "all"))
    print(f"registered {r['registered']} classes in domain={r['domain']} "
          f"({len(r['created'])} new)")
    for s in r["skipped"]:
        print(f"  SKIP {s['class_id']} [{s.get('domain','?')}]: {s['reason']}")
    con.close()
    return 0


def cmd_route(args) -> int:
    """Resolve a natural-language objective to its domain(s) (§6, §7).

    The brief requires that "Learn XSS" and "Master Kerberos attack paths"
    reach different domains without the user naming either, and that an
    objective spanning both activates both. This is that decision, as a
    command, so it is inspectable rather than implicit.
    """
    from . import domains
    r = domains.route(" ".join(args.objective))
    print(r.explain())
    if r.specializations:
        print(f"  suggested next: python -m wks.cli route --expand "
              f"{' '.join(args.objective)}")
    return 0


def cmd_route_expand(args) -> int:
    """What the router implies is in scope: the classes it selects, per domain."""
    from . import domains, network_taxonomy as nettax, taxonomy
    r = domains.route(" ".join(args.objective))
    print(r.explain())
    for dom in r.domains:
        print(f"\n=== {dom.upper()} classes in scope ===")
        if dom == domains.WEB:
            for cid, s in taxonomy.CLASSES.items():
                print(f"  {cid:<24} {s.name}")
        elif dom == domains.NETWORK:
            for spec, ids in nettax.BY_SPECIALIZATION.items():
                if r.specializations and spec not in r.specializations:
                    continue
                print(f"  -- {spec} --")
                for cid in ids:
                    print(f"     {cid:<21} {nettax.NET_CLASSES[cid].name}")
    return 0


def cmd_domain_health(args) -> int:
    """Per-domain state: what is registered, what has evidence, what is empty.

    The brief (§25) requires the system to distinguish KNOWLEDGE CONFIDENCE from
    PRACTICAL CAPABILITY, and to say plainly what it has only read. A domain
    with 25 classes and 0 items is a map with no knowledge, and reporting it
    without that distinction is the decoration the brief forbids.
    """
    from . import domains
    con = store.open_db(create=False)
    out: dict[str, dict] = {}
    for dom in (domains.WEB, domains.NETWORK):
        ids = _ids_for(dom)
        classes = [r["id"] for r in con.execute(
            "SELECT id FROM bug_class WHERE id IN ({})".format(
                ",".join("?" * len(ids))), ids)] if ids else []
        items = con.execute(
            "SELECT COUNT(*) FROM item WHERE class_id IN ({})".format(
                ",".join("?" * len(ids))), ids).fetchone()[0] if ids else 0
        out[dom] = {"declared": len(ids), "registered": len(classes),
                    "items_with_evidence": items}
    con.close()
    print("DOMAIN HEALTH — registered vs. evidenced")
    print("A domain with classes but no items is a MAP, not knowledge.\n")
    for dom, v in out.items():
        print(f"  {dom:<10} declared={v['declared']:<4} registered={v['registered']:<4} "
              f"items={v['items_with_evidence']}")
        if v["registered"] and not v["items_with_evidence"]:
            print(f"    -> {v['registered']} classes, ZERO gated items. "
                  f"Taxonomy without evidence. (brief §25)")
    return 0


def _ids_for(dom: str) -> list[str]:
    from . import network_taxonomy as nettax, taxonomy
    if dom == "web":
        return list(taxonomy.CLASSES)
    return list(nettax.NET_CLASSES)


def cmd_sourcebook(args) -> int:
    """The merged source registry: per-class worklist from `db/sources.json`.

    Distinct from `cmd_sources`, which reads the LEAD registry module only.
    This answers the question a child actually asks — "which pages do I read
    for this class, and which are already cited" — from one file.
    """
    from . import sourcebook
    if getattr(args, "rebuild", False):
        import subprocess
        r = subprocess.run(
            [sys.executable, str(config.root() / "tools" / "build_sources.py")],
            cwd=str(config.root()))
        if r.returncode != 0:
            print("rebuild FAILED — registry left untouched")
            return r.returncode
    # Built by APPENDING, never by a ternary around a `+` chain. In
    # `[a] if a else [] + [b] + [c]` the conditional binds looser than `+`, so
    # the whole tail becomes the else-branch and the flags vanish — which is
    # exactly how `--json` silently produced plain text here.
    argv: list[str] = []
    if args.class_id:
        argv.append(args.class_id)
    if args.classes:
        argv.append("--classes")
    if args.json:
        argv.append("--json")
    try:
        return sourcebook.main(argv)
    except sourcebook.SourceRegistryMissing as e:
        print(str(e))
        return 1


def cmd_sources(args) -> int:
    """Register / list the research-source registry (R20).

    Never writes an item, evidence link or validation_state.
    """
    from . import research_sources, seed as seeder
    probs = research_sources.problems()
    if args.register:
        con = store.open_db(create=True)
        r = seeder.register_research_sources(con)
        n_items = con.execute("SELECT COUNT(*) FROM item").fetchone()[0]
        n_src = con.execute("SELECT COUNT(*) FROM source").fetchone()[0]
        con.close()
        print(f"registry={r['registry_total']} created={r['created']} "
              f"updated={r['updated']} distinct_hosts={r['hosts']}")
        print(f"source table now {n_src} rows | item table still {n_items} "
              f"(unchanged: registering a source creates no knowledge)")
    if not args.register or args.list:
        print(f"\n{'TIER':<5}{'ACCESS':<8}{'TYPE':<11}{'HOST':<34}TITLE")
        print("-" * 118)
        for t in sorted(research_sources.TIERS):
            for s in research_sources.RESEARCH_SOURCES:
                if s.tier != t:
                    continue
                print(f"{s.tier:<5}{s.access:<8}{s.source_type:<11}"
                      f"{s.host:<34}{s.title[:36]}")
    if probs:
        print("\nVOCABULARY PROBLEMS (would silently degrade authority):")
        for p in probs:
            print("  ! " + p)
        return 1
    return 0


def cmd_overnight(args) -> int:
    from . import overnight
    return overnight.main(["--cycles", str(args.cycles), "--sleep", str(args.sleep),
                           "--max-tasks", str(args.max_tasks)])


def cmd_audit_legacy(args) -> int:
    import subprocess
    root = args.path or str(config.root() / "quarantine" / "knowledge_reconcile")
    argv = [str(Path(__file__).resolve().parent.parent / "eval" / "audit_legacy.py"), root]
    return subprocess.call([sys.executable, *argv])


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="wks", description="Web & API Knowledge System")
    sub = p.add_subparsers(dest="cmd", required=True)

    sub.add_parser("init").set_defaults(fn=cmd_init)
    sub.add_parser("selftest").set_defaults(fn=cmd_selftest)
    sub.add_parser("gate").set_defaults(fn=cmd_gate)
    sub.add_parser("gaps").set_defaults(fn=cmd_gaps)
    sub.add_parser("report").set_defaults(fn=cmd_report)

    a = sub.add_parser("add-class")
    a.add_argument("id"); a.add_argument("name"); a.add_argument("surface")
    a.add_argument("--cwe"); a.add_argument("--owasp"); a.add_argument("--summary")
    a.set_defaults(fn=cmd_add_class)

    a = sub.add_parser("ingest")
    a.add_argument("file")
    # The verification escape hatch is explicit and named. The UNVERIFIED
    # path used to be the DEFAULT for this command; it is now opt-in.
    a.add_argument("--no-verify", action="store_true",
                   help="skip live quote verification (NOT recommended)")
    a.add_argument("--dry", action="store_true",
                   help="evaluate against a scratch copy; write nothing")
    a.set_defaults(fn=cmd_ingest)

    a = sub.add_parser("search")
    a.add_argument("query", nargs="+")
    a.add_argument("--class-id"); a.add_argument("--limit", type=int, default=6)
    a.add_argument("--state", action="append")
    a.set_defaults(fn=cmd_search)

    a = sub.add_parser("show")
    a.add_argument("class_id"); a.set_defaults(fn=cmd_show)

    a = sub.add_parser("tasks")
    a.add_argument("--generate", action="store_true")
    a.set_defaults(fn=cmd_tasks)

    a = sub.add_parser("metrics")
    a.add_argument("--live", action="store_true",
                   help="read the live store instead of a frozen copy (faster, "
                        "but the numbers are only true for that instant)")
    a.set_defaults(fn=cmd_metrics)
    sub.add_parser("probe").set_defaults(fn=cmd_probe)

    a = sub.add_parser("cycle")
    a.add_argument("--max-items", type=int, default=5)
    a.set_defaults(fn=cmd_cycle)

    a = sub.add_parser("verify-seeds")
    a.add_argument("--domain", choices=["all", "web", "network"], default="all")
    a.set_defaults(fn=cmd_verify_seeds)
    a = sub.add_parser("seed")
    a.add_argument("--domain", choices=["all", "web", "network"], default="all")
    a.set_defaults(fn=cmd_seed)

    a = sub.add_parser("route", help="objective -> domain(s), per the brief")
    a.add_argument("objective", nargs="+")
    a.add_argument("--expand", action="store_true",
                   help="also list the classes the route puts in scope")
    # Dispatch on the flag AFTER parsing, not here: `--expand` is only known
    # once argparse has run, so choosing the handler at registration time via a
    # getattr on the namespace would always pick the default and silently
    # ignore the flag. A wrapper reads args.expand at call time.
    def _route_dispatch(args) -> int:
        return cmd_route_expand(args) if args.expand else cmd_route(args)

    a.set_defaults(fn=_route_dispatch)
    sub.add_parser("domain-health",
                   help="per-domain registered vs. evidenced (brief §25)"
                   ).set_defaults(fn=cmd_domain_health)

    a = sub.add_parser("sources",
                       help="research-source registry (R20): register or list")
    a.add_argument("--register", action="store_true",
                   help="upsert registry entries into the source table")
    a.add_argument("--list", action="store_true",
                   help="print the registry with tier/access/type")
    a.set_defaults(fn=cmd_sources)

    a = sub.add_parser("overnight")
    a.add_argument("--cycles", type=int, default=4)
    a.add_argument("--sleep", type=int, default=0)
    a.add_argument("--max-tasks", type=int, default=1)
    a.set_defaults(fn=cmd_overnight)

    # The single-file source registry the learning loop retrieves from.
    # `wks.cli sources` reads the LEAD registry module; this reads the MERGED
    # file that also carries the normative class seeds, so one command answers
    # "where do I read for this class" instead of four.
    a = sub.add_parser("sourcebook",
                       help="merged source registry: per-class worklist")
    a.add_argument("class_id", nargs="?", help="class to brief")
    a.add_argument("--classes", action="store_true", help="list every class")
    a.add_argument("--json", action="store_true", help="emit JSON, not text")
    a.add_argument("--rebuild", action="store_true",
                   help="regenerate db/sources.json from the 4 registries first")
    a.set_defaults(fn=cmd_sourcebook)

    a = sub.add_parser("audit-legacy")
    a.add_argument("path", nargs="?")
    a.set_defaults(fn=cmd_audit_legacy)

    # The drift check for what the AGENT LOADS. `domains/` is in
    # skills.external_dirs, so a stale SKILL.md is not a stale document -- it is
    # the model being handed yesterday's evidence. Exits 1 on any finding.
    a = sub.add_parser("skills-sync",
                       help="refresh/check skills+digests+assessments "
                            "(the files Hermes loads from domains/)")
    a.add_argument("--check", action="store_true")
    a.add_argument("--apply", action="store_true")
    a.add_argument("--class", dest="classes", action="append", default=None)
    a.add_argument("--json", action="store_true")
    a.set_defaults(fn=cmd_skills_sync)

    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return args.fn(args)


if __name__ == "__main__":
    raise SystemExit(main())
