"""Ingest agent-produced research files under gate enforcement.

    python -m wks.ingest research/pending/idor.json

This is the boundary between delegated research and the canonical corpus. It
exists because a subagent's report is a self-report: nothing a research agent
claims about its own sources is trusted here. Every item passes through:

  1. schema shape check
  2. quote verification against the LIVE page   <- the anti-fabrication gate
  3. host-diversity + fabricated-ref assessment (wks/quality.py)
  4. only then does the item enter the db

An item whose quote cannot be found on the page it cites is rejected, not
downgraded. Two of the four first-wave research files contained exactly that, and
a system that had accepted them would have been worse than one with no knowledge
at all.
"""
from __future__ import annotations

import argparse
import json
import re
import sqlite3
import sys
from pathlib import Path
from urllib.parse import urlparse

sys.path.insert(0, str(Path(__file__).resolve().parent))

from wks import (authoring, config, quality, retrieval, store,  # noqa: E402
                  verify_quotes)

REQUIRED = ("item_key", "kind", "claim", "body", "disproof", "sources")
VALID_KINDS = {"prerequisite", "signal", "technique", "test", "validation",
               "fp_rule", "evidence", "impact", "variant", "bypass", "chain_link"}


def host_of(url: str) -> str:
    return (urlparse(url).hostname or "").lower().removeprefix("www.")


def _scratch_db() -> "tuple[Path, object]":
    """Snapshot the canonical db into a throwaway file for a --dry run.

    A dry run must answer "what WOULD promote", so it has to run the real gate.
    The old stub verdict ("(dry-run)") never matched the promoted set, so every
    item was reported as held and the dry run looked like a total failure even
    when the corpus was clean.

    The snapshot uses SQLite's online backup API, NOT shutil.copy2: in WAL mode
    committed rows live in the -wal sidecar, so a plain file copy yields a db
    with an EMPTY schema-adjacent corpus -- it reported "unknown class" for
    classes that demonstrably existed. backup() folds the WAL in.
    """
    import tempfile

    src_path = Path(config.db_path())
    tmpdir = Path(tempfile.mkdtemp(prefix="wks_dry_"))
    dst = tmpdir / "dry.db"
    if src_path.exists():
        src = sqlite3.connect(str(src_path))
        try:
            out = sqlite3.connect(str(dst))
            try:
                src.backup(out)
            finally:
                out.close()
        finally:
            src.close()
    return dst, tmpdir


def ingest_file(path: Path | str, *, verify: bool = True, dry: bool = False) -> dict:
    # Accept a str as well as a Path: the CLI and any caller passing a glob
    # result get strings, and `Path.read_text` on a str fails deep inside.
    path = Path(path)
    tmpdir = None
    if dry:
        db_copy, tmpdir = _scratch_db()
        con = store.open_db(db_copy, create=True)
    else:
        con = store.open_db(create=True)
    raw = path.read_text(encoding="utf-8")
    # Research files carry a trailing `// COMPLETE <n>` marker so an agent's
    # completion is greppable. It is a comment, not JSON, and json.loads rejects
    # it — so strip it here rather than making every producer remember.
    raw = re.sub(r"\n?//\s*COMPLETE[^\n]*\s*$", "", raw).strip()
    data = json.loads(raw)
    items = data["items"] if isinstance(data, dict) else data

    # Shape validation first: reject nonsense before spending network on it.
    shaped, shape_errors = [], []
    for it in items:
        missing = [k for k in REQUIRED if not it.get(k)]
        if missing:
            shape_errors.append({"item_key": it.get("item_key"), "missing": missing})
            continue
        if it["kind"] not in VALID_KINDS:
            shape_errors.append({"item_key": it["item_key"],
                                 "missing": [f"invalid kind {it['kind']!r}"]})
            continue
        cid = it["item_key"].split(".")[0]
        if store.get_class(con, cid) is None:
            shape_errors.append({"item_key": it["item_key"],
                                 "missing": [f"unknown class {cid!r}"]})
            continue
        shaped.append(it)

    # Quote verification against live pages (network). Called once, captured,
    # then parsed — running it twice would double every page fetch.
    verdicts: dict[str, str] = {}
    if verify:
        import contextlib
        import io
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            verify_quotes.main(["--file", str(path), "--json"])
        try:
            qres = json.loads(buf.getvalue())
            verdicts = {r["item_key"]: r["overall"] for r in qres}
        except Exception:
            verdicts = {}
    else:
        verdicts = {}

    accepted, blocked, rejected = [], [], []
    for it in shaped:
        key = it["item_key"]
        cid = key.split(".")[0]
        v = verdicts.get(key, "UNVERIFIED")
        if v == "FABRICATED":
            rejected.append({"item_key": key, "reason": "QUOTE_NOT_FOUND_ON_CITED_PAGE",
                             "sources": [s.get("url") for s in it["sources"]]})
            if not dry:
                # MEASURED (wave 10): this used to be an unconditional INSERT,
                # so re-ingesting an unchanged file recorded the SAME dispute
                # again on every run. One sandbox test ingesting w5-fp-web.json
                # twice left 45 open rows for 10 distinct disputes, and the
                # deser claim was stored 9 times. open_conflicts then measures
                # how many times a file was ingested, not how many disputes
                # exist -- a metric that grows on a clean re-run is a broken
                # control, and it drowns the real disputes in the noise.
                #
                # Fixed by fingerprinting the dispute (class, claim, and the
                # cited urls) and reusing the existing open row, so a repeat
                # rejection is idempotent. The fingerprint is recorded in
                # `resolution` because the conflict table has no column for it,
                # which also gives tools/resolve_disputes.py a stable key.
                urls = [s.get("url") for s in it["sources"]]
                fingerprint = json.dumps(
                    {"class_id": cid, "claim": it["claim"], "urls": sorted(
                        u for u in urls if u)},
                    sort_keys=True, separators=(",", ":"))
                detail = f"cited quote not present on page: {urls}"
                row = con.execute(
                    "SELECT id, resolution FROM conflict WHERE status='open'"
                    " AND class_id=? AND claim_a=? AND claim_b=?",
                    (cid, it["claim"], detail)).fetchone()
                if row is None:
                    con.execute(
                        "INSERT INTO conflict"
                        " (class_id,topic,claim_a,claim_b,status,created_at)"
                        " VALUES (?,?,?,?,'open',datetime('now'))",
                        (cid, "fabricated-evidence", it["claim"], detail))
                else:
                    # already recorded: count the recurrence instead of
                    # duplicating the row
                    con.execute(
                        "UPDATE conflict SET resolution=?"
                        " WHERE id=?",
                        ("repeat-rejection fingerprint=%s" % fingerprint, row["id"]))
            continue

        from wks import pipeline
        sources = []
        for s in it["sources"]:
            url = s.get("url", "")
            sources.append({
                "url": url,
                "source_type": s.get("source_type", "writeup"),
                "host": s.get("host") or host_of(url),
                "quote": s.get("quote"),
                "locator": s.get("locator"),
                "title": s.get("title"),
            })
        if dry:
            # Real gate run against the scratch copy: honest promoted/held split.
            verdict = pipeline.ingest_claim(
                con, item_key=key, class_id=cid, claim=it["claim"],
                kind=it["kind"], sources=sources, body=it.get("body"),
                disproof=it.get("disproof"),
                surface=it.get("surface"),
                severity_hint=it.get("severity_hint"),
                hunting_value=int(it.get("hunting_value", 4)),
            )
            verdict["state"] = "(dry) " + verdict["state"]
        else:
            verdict = pipeline.ingest_claim(
                con, item_key=key, class_id=cid, claim=it["claim"],
                kind=it["kind"], sources=sources, body=it.get("body"),
                disproof=it.get("disproof"),
                surface=it.get("surface"),
                severity_hint=it.get("severity_hint"),
                hunting_value=int(it.get("hunting_value", 4)),
            )
        rec = {"item_key": key, "state": verdict["state"],
               "score": round(verdict["score"], 3), "tags": verdict.get("tags", []),
               "quote_check": v}
        # Classify on the REAL state, not the "(dry) "-prefixed display label,
        # or a dry run would report every item as held again.
        real_state = verdict["state"].removeprefix("(dry) ")
        (accepted if real_state in ("supported", "high_confidence")
         else blocked).append(rec)

    # ---- chain assembly -------------------------------------------------
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
    con.close()
    if tmpdir is not None:
        import shutil
        shutil.rmtree(tmpdir, ignore_errors=True)
    return {
        "file": str(path), "submitted": len(items),
        "shape_errors": shape_errors,
        "rejected_fabricated": rejected,
        "promoted": accepted, "held": blocked,
        "chains_written": chains_written, "chain_errors": chain_errors,
    }


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="wks.ingest")
    ap.add_argument("files", nargs="+")
    ap.add_argument("--no-verify", action="store_true",
                    help="skip live quote verification (NOT recommended)")
    ap.add_argument("--dry", action="store_true")
    args = ap.parse_args(argv)

    totals = {"submitted": 0, "promoted": 0, "held": 0,
              "rejected": 0, "shape_errors": 0}
    for f in args.files:
        r = ingest_file(Path(f), verify=not args.no_verify, dry=args.dry)
        print(f"\n=== {r['file']} ===")
        print(f"submitted={r['submitted']} promoted={len(r['promoted'])} "
              f"held={len(r['held'])} rejected={len(r['rejected_fabricated'])} "
              f"shape_errors={len(r['shape_errors'])}")
        for e in r["shape_errors"]:
            print(f"  SHAPE  {e['item_key']}: missing {e['missing']}")
        for e in r["rejected_fabricated"]:
            print(f"  REJECT {e['item_key']}: {e['reason']}")
        for e in r["promoted"]:
            print(f"  + {e['item_key']:46} {e['state']:15} {e['score']:.2f}")
        for e in r["held"]:
            print(f"  ~ {e['item_key']:46} {e['state']:15} "
                  f"{','.join(e['tags'][:2])}")
        totals["submitted"] += r["submitted"]
        totals["promoted"] += len(r["promoted"])
        totals["held"] += len(r["held"])
        totals["rejected"] += len(r["rejected_fabricated"])
        totals["shape_errors"] += len(r["shape_errors"])
        totals["chains"] = totals.get("chains", 0) + len(r.get("chains_written", []))
        totals["chain_errors"] = totals.get("chain_errors", 0) + len(
            r.get("chain_errors", []))
        totals.setdefault("_chain_error_detail", []).extend(
            r.get("chain_errors", []))

    for e in totals.get("_chain_error_detail", []):
        print(f"  CHAIN_ERROR {e.get('item_key')}: {e.get('reason')}")
    print(f"\nTOTAL submitted={totals['submitted']} promoted={totals['promoted']} "
          f"held={totals['held']} rejected={totals['rejected']} "
          f"shape_errors={totals['shape_errors']} "
          f"chains={totals.get('chains', 0)} "
          f"chain_errors={totals.get('chain_errors', 0)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
