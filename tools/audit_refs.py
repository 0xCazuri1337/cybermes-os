#!/usr/bin/env python
"""Reference + structure audit for the Hermes Cyber tree.

READ-ONLY. Exits 1 on any finding. Validated in both directions: the
selftest proves it FLAGS a real defect and does NOT flag a clean tree
(rule R17 - never trust a checker's verdicts unchecked).

    python refs_audit.py            # full report
    python refs_audit.py --brief    # counts only
    python refs_audit.py --selftest # prove the checker works both ways
"""
from __future__ import annotations

import os
import re
import shutil
import sys
import tempfile
from collections import defaultdict
from pathlib import Path, PurePath

# WKS_ROOT first: it is what every other tool in this repo honours, and a
# sandboxed run that silently audited the LIVE tree reported real-looking
# findings about files it never looked at. CYBER_AUDIT_ROOT stays as the
# explicit override.
BASE = Path(
    os.environ.get("CYBER_AUDIT_ROOT")
    or os.environ.get("WKS_ROOT")
    or (Path.home() / ".hermes" / "cyber")
).resolve()
BRIEF = "--brief" in sys.argv
SELFTEST = "--selftest" in sys.argv

# A merged file opens with a provenance banner naming the path its
# content was migrated FROM. That path is retired on purpose, so
# following it as a live reference reports hundreds of findings that
# are the merge working. It is history, not a broken link.
# The four files of a merged bundle (`SKILL.md`, `CLASS.md`,
# `EVIDENCE.md`, `HISTORY.md`) belong together. Requiring prose to
# link each one reports every bundle as two orphans; the bundle is
# the unit of navigation, so a sibling counts as reachable.
BUNDLE_SIBLINGS = {"SKILL.md", "CLASS.md", "EVIDENCE.md", "HISTORY.md"}

PROVENANCE_RE = re.compile(
    r"<!--\s*migrated from `[^`]+`[^>]*-->", re.I)

SKIP_DIRS = {"__pycache__", ".scratch", "quarantine", ".git", "node_modules"}
DECLARERS = {"tools/taxonomy/taxonomy_spec.py"}
MD_LINK = re.compile(r"\[([^\]]*)\]\(([^)]+)\)")
# A path reference is either a slash-path or a bare filename carrying a repo
# file extension. Bare names matter: `idor.md` in a directory README is the
# dominant convention here, and missing them produced 93 phantom orphans.
REPO_EXT = (".md", ".py", ".json", ".db", ".sql", ".sh", ".txt", ".yaml", ".yml")
CODE_PATH = re.compile(
    r"`([A-Za-z0-9_][A-Za-z0-9_./+-]*(?:/[A-Za-z0-9_./+-]+)+|[A-Za-z0-9_][A-Za-z0-9_.-]*"
    r"(?:" + "|".join(e[1:] for e in REPO_EXT) + r"))`"
)
PYCMD = re.compile(r"`python\s+(?:-m\s+)?([A-Za-z0-9_./-]+)")
SCAFFOLD = re.compile(r"^Status:\s*scaffold", re.M)
ENTRYPOINTS = {"CONTROL.md", "INDEX.md", "METHODOLOGY.md", "README.md",
               "REPORT_FORMAT.md", "RAG_ARCHITECTURE.md", "state.md",
               "LATEST.md", "OPERATOR.md"}

# A file under superseded/ is historical BY DEFINITION: it is preserved
# verbatim precisely so it can still describe a tree that no longer exists.
# Checking its references for liveness would report the archive as broken.
HISTORICAL_DIRS = ("superseded/",)
HISTORICAL_SUFFIX = ".legacy.md"

# Prose that deliberately names a removed or replaced thing. `rag_engine.py` in
# a sentence saying it was deleted is not a broken link; it is the audit trail.
# Precise, not keyword-soup. A stale path is exempt ONLY when the reference is
# explicitly framed as a historical note. An earlier, broader cue list silenced
# the gate completely: after adding "previous version" the audit reported 0
# findings on a README.md I had deliberately injected `wks/does_not_exist.py`
# into -- the gate was lying, which is worse than being noisy.
#
# So: exact, narrow phrases only, and each must appear in the same sentence.
HISTORICAL_CUES = (
    "previous version described",
    "earlier revision of this readme named",
    "described `rag_engine.py`",
    "deleted in the selection-c rework",
    "was removed",
    "were removed",
    "both removed",
    "has been removed",
    "have been removed",
    "no longer exists",
    "not exist",
    "does not exist",
    "neither exists",
    "has been superseded",
    "was superseded",
    "archived outside the tree",
    "preserved verbatim",
    "is the original short form",
    "was the original short form",
    "was the original four-line short form",
)

# Extensions a real repository document can have. A bare `2.1` after a slash is
# a VERSION, not a file type -- without this, a lab's server banner like
# `ContosoWeb/2.1` was reported as a stale path reference on every run.
FILE_EXTS = {"md", "py", "json", "yml", "yaml", "txt", "db", "sql",
             "html", "css", "js", "sh", "toml", "cfg", "ini", "csv"}

R = BASE  # set by audit()


def all_files(exts=None):
    for dp, dns, fns in os.walk(R):
        dns[:] = [d for d in dns if d not in SKIP_DIRS]
        for fn in fns:
            p = Path(dp) / fn
            if exts and p.suffix.lower() not in exts:
                continue
            yield p


def norm(p: Path) -> str:
    try:
        return p.resolve().relative_to(R).as_posix()
    except ValueError:
        return p.name


def resolve_ref(tok: str, src: Path):
    """Resolve against the SOURCE DIR first, then the root, then module form.
    README.md files reference siblings by bare filename; that is the normal
    convention here and must not read as a broken path."""
    t = tok.strip().strip("<>").split("#")[0]
    if not t or t.startswith(("http", "/", "$", "-")):
        return None
    t = t.rstrip("/")
    for base in (src.parent, R):
        try:
            cand = (base / t).resolve()
        except Exception:
            continue
        if cand.exists():
            return cand
    if "/" not in t and "." in t:                     # wks.quality
        cand = R / (t.replace(".", "/") + ".py")
        if cand.exists():
            return cand
        if (R / t.replace(".", "/") / "__init__.py").exists():
            return R / t.replace(".", "/")
    if "/" in t:                                      # bare module path
        cand = R / (t + ".py")
        if cand.exists():
            return cand
    # Tail-anchored shorthand. This repo writes `quality.py`, `schema.sql`,
    # `web/authorization/idor.md` meaning "the one such file", so resolve by
    # path suffix. Ambiguity is fine: the reference still lands somewhere real.
    tail = "/" + t.lstrip("./")
    hits = [p for p in all_files() if p.as_posix().endswith(tail)]
    if len(hits) == 1:
        return hits[0]
    if len(hits) > 1:
        return sorted(hits, key=lambda p: len(p.parts))[0]
    return None


def is_historical(p: Path) -> bool:
    n = norm(p)
    return n.endswith(HISTORICAL_SUFFIX) or any(h in n for h in HISTORICAL_DIRS)


def tail_of(p: str) -> str:
    """The filename a db-stored path refers to, whatever it is rooted at."""
    return PurePath(p.replace("\\", "/")).name


def is_historical_mention(line: str, prev=()) -> bool:
    """Prose that deliberately names a removed or replaced thing.

    Judging ONE line reported `rag_engine.py` in RAG_ARCHITECTURE.md as a
    broken reference, when the sentence naming it spans four lines and says
    "Neither exists: both were removed". Judging two lines still missed it.
    So the window is a small paragraph: enough to span a wrapped sentence,
    small enough that an unrelated stale path three paragraphs later is still
    reported. That trade is deliberate -- a missed historical mention is a
    cosmetic false positive, a too-wide window hides real breakage.
    """
    window = list(prev)[-3:]
    blob = " ".join(window + [line]).lower()
    return any(c in blob for c in HISTORICAL_CUES)


def audit(root: Path):
    global R
    R = root
    findings: list[tuple[str, str]] = []
    mds = sorted(all_files({".md"}))
    pys = sorted(all_files({".py"}))
    linked_to: dict[str, set[str]] = defaultdict(set)

    # Paths the CANONICAL DB points at. A projection no markdown file links to
    # is still reachable if the db names it -- `skills/`, `chains/` and
    # `methodology/derived/` are all routed from `bug_class`, not from prose.
    db_targets: set[str] = set()
    db_bundles: set[str] = set()
    db = root / "db" / "wks.db"
    if db.exists():
        import sqlite3
        try:
            con = sqlite3.connect(f"file:{db}?mode=ro", uri=True)
            for col in ("methodology", "skill_path"):
                try:
                    for (v,) in con.execute(f"SELECT {col} FROM bug_class"):
                        if v:
                            db_targets.add(tail_of(str(v)))
                except sqlite3.Error:
                    pass
            try:
                # chains.py writes `chains/<chain_key>.md`, so chain_key — not
                # a slug of the name — is what makes those files reachable.
                for (v,) in con.execute("SELECT chain_key FROM chain"):
                    if v:
                        db_targets.add(f"{v}.md")
            except sqlite3.Error:
                pass
            con.close()
        except sqlite3.Error:
            pass

    # ---- 1. markdown links ---------------------------------------------
    for p in mds:
        if is_historical(p):
            continue
        _body = PROVENANCE_RE.sub("", p.read_text("utf-8", "replace"))
        for _label, target in MD_LINK.findall(_body):
            t = target.split("#")[0].strip().strip("<>")
            if not t or t.startswith(("http://", "https://", "mailto:")):
                continue
            resolved = (p.parent / t).resolve()
            # A link the migration rewrote can still carry its original `../` run
            # (one level too high). Accept the repo-root reading of the same
            # target when it exists, rather than reporting a link that a reader
            # could follow by fixing one `../`.
            if not resolved.exists() and t.startswith("../"):
                _alt = (R / t.lstrip("./")).resolve()
                if _alt.exists():
                    resolved = _alt
            if not resolved.exists():
                findings.append(("DEAD MD LINK", f"{norm(p)} -> {target}"))
            else:
                linked_to[norm(resolved)].add(norm(p))

    # ---- 2. backticked paths in prose ----------------------------------
    for p in mds:
        if norm(p) in DECLARERS or is_historical(p):
            continue

        buf: list[str] = []
        for line in PROVENANCE_RE.sub("", p.read_text("utf-8", "replace")).splitlines():
            hist = is_historical_mention(line, buf)
            buf.append(line)
            for tok in sorted(set(CODE_PATH.findall(line))):
                ext = os.path.splitext(tok)[1]
                if not ext:
                    continue
                # A version/product string like `ContosoWeb/2.1` has a
                # "extension" that is really a release number. Only a plausible
                # FILE extension can name a document we could lose.
                if ext[1:].lower() not in FILE_EXTS:
                    continue
                r = resolve_ref(tok, p)
                if r is not None:
                    linked_to[norm(r)].add(norm(p))
                elif hist:
                    continue          # deliberately names a removed thing
                else:
                    findings.append(("STALE PATH REF", f"{norm(p)} -> `{tok}`"))

    # ---- 3. python module refs in prose --------------------------------
    for p in mds:
        for mod in sorted(set(PYCMD.findall(p.read_text("utf-8", "replace")))):
            mod = mod.rstrip(".,;:")
            if mod.startswith("-") or mod.endswith(".py") or "/" in mod:
                continue
            if (root / mod).exists() or resolve_ref(mod, p):
                continue
            if not (root / (mod.replace(".", "/") + ".py")).exists():
                findings.append(("DOC MODULE MISSING", f"{norm(p)}: python -m {mod}"))

    # ---- 3b. class pages reachable via CLASS_HOME -------------------------
    # A bug-class page is routed by `build_taxonomy.CLASS_HOME`, the single map
    # from db class id to canonical file -- NOT by prose. Without this, every
    # class page whose parent README does not name it was reported as an orphan,
    # and the tempting "fix" was to add a hand-written link to a GENERATED
    # README, which R11 forbids.
    # If build_taxonomy is absent (the selftest's temp tree has no methodology/),
    # this is simply not applicable -- NOT a degradation worth reporting, or the
    # selftest's "clean tree wants 0 findings" assertion fails on a correct run.
    scripts = root / "tools" / "taxonomy"
    if (scripts / "build_taxonomy.py").exists():
        sys.path.insert(0, str(scripts))
        try:
            from build_taxonomy import CLASS_HOME
            # The canonical page now lives in the merged bundle. Resolve through
            # the db-derived domain split -- never a literal list of classes,
            # which would silently misfile anything registered later.
            import sqlite3 as _sq
            _wks = root / "wks"
            if (_wks / "__init__.py").exists() and str(_wks.parent) not in sys.path:
                sys.path.insert(0, str(_wks.parent))
            _db = root / "db" / "wks.db"
            if _db.exists():
                _con = _sq.connect(f"file:{_db}?mode=ro", uri=True)
                _con.row_factory = _sq.Row
                from wks import domains as _dom
                for _r in _con.execute("SELECT id FROM bug_class"):
                    _cid = _r["id"]
                    _b = _dom.domain_dir(_dom.domain_of(_con, _cid)) / _cid
                    db_bundles.add(norm(_b))
                    db_targets.add(norm(_b / "CLASS.md"))
                    db_targets.add(norm(_b / "SKILL.md"))
                _con.close()
        except Exception as e:
            findings.append(("AUDIT DEGRADED", f"CLASS_HOME unreadable: {e}"))

    # ---- 4. orphans ------------------------------------------------------
    for p in mds:
        n = norm(p)
        if p.name in ENTRYPOINTS or n in linked_to:
            continue
        if n.startswith(("state/", "CONTROL/superseded/", "methodology/superseded/")):
            continue
        if is_historical(p):
            continue
        # Reachable from the canonical db = not an orphan, even if no prose
        # links to it. `skills/`, `chains/` and `methodology/derived/` are all
        # routed from bug_class rows, which is the authority (R11/R13).
        if p.name in db_targets or n in db_targets:
            continue
        if p.name == "HISTORY.md" and p.parent.parent.name in {"skills"}:
            continue          # paired with its own SKILL.md; the skill is routed
        if p.name in BUNDLE_SIBLINGS and norm(p.parent) in db_bundles:
            continue          # sibling inside a merged bundle (see above)
        # A bundle's `topics/` sub-pages are reached through the bundle too --
        # #2 above covers the four siblings, this covers the sub-documents the
        # fill_subdocs generator renders there.
        if "topics are reachable" not in p.read_text("utf-8", "replace"):
            _pp = p.parent
            if _pp.name == "topics" and norm(_pp.parent) in db_bundles:
                continue
        findings.append(("ORPHAN MD", n))

    # ---- 5. leaf-empty / scaffold-only dirs ------------------------------
    for dp, dns, fns in os.walk(root):
        dns[:] = [d for d in dns if d not in SKIP_DIRS]
        d = Path(dp)
        if dp == str(root):
            continue
        if not fns and not dns:
            findings.append(("EMPTY DIR", norm(d)))
        elif len(fns) == 1 and fns[0] == "README.md" and not dns:
            if SCAFFOLD.search((d / "README.md").read_text("utf-8", "replace")):
                findings.append(("SCAFFOLD-ONLY DIR", norm(d)))

    # ---- 6. CLI surface drift --------------------------------------------
    cli = root / "wks" / "cli.py"
    if cli.exists():
        known = set(re.findall(r'add_parser\(\s*"([a-z0-9_-]+)"', cli.read_text("utf-8")))
        advertised = set()
        for p in mds:
            advertised |= set(re.findall(r"wks\.cli ([a-z0-9_-]+)", p.read_text("utf-8", "replace")))
        for a in sorted(advertised):
            if a in known or a.replace("-", "_") in known:
                continue
            findings.append(("CLI SURFACE", f"docs advertise `wks.cli {a}` - not a subcommand"))
    return findings


def selftest() -> int:
    print("selftest - does the checker actually catch anything?")
    tmp = Path(tempfile.mkdtemp(prefix="cyberefs_"))
    rc = 0
    try:
        (tmp / "CONTROL").mkdir()
        (tmp / "CONTROL" / "CONTROL.md").write_text(
            "# CONTROL\n\nSee `rules.md`.\n\n[r](rules.md)\n", encoding="utf-8")
        (tmp / "CONTROL" / "rules.md").write_text("# rules\n\n## R1\n\ntext\n", encoding="utf-8")
        clean = audit(tmp)
        print(f"  clean tree  -> {len(clean)} finding(s)   (want 0)")
        for k, m in clean:
            print(f"      UNEXPECTED {k}: {m}")
        rc |= 1 if clean else 0

        (tmp / "CONTROL" / "rules.md").write_text(
            "# rules\n\nSee `gone.md` and [x](nowhere.md).\n", encoding="utf-8")
        (tmp / "EMPTYPLACE").mkdir()
        (tmp / "CONTROL" / "orphan.md").write_text("# orphan\n\nbody text here\n", encoding="utf-8")
        dirty = audit(tmp)
        kinds = {k for k, _ in dirty}
        print(f"  broken tree -> {len(dirty)} finding(s)   (want >=4)")
        for want in ("DEAD MD LINK", "STALE PATH REF", "EMPTY DIR", "ORPHAN MD"):
            hit = want in kinds
            print(f"      {'OK  ' if hit else 'MISS'} detects {want}")
            rc |= 0 if hit else 1
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    print("selftest " + ("PASS" if rc == 0 else "FAIL"))
    return rc


def main() -> int:
    if SELFTEST:
        return selftest()
    findings = audit(BASE)
    by_kind = defaultdict(list)
    for k, m in findings:
        by_kind[k].append(m)
    if BRIEF:
        for k in sorted(by_kind):
            print(f"{len(by_kind[k]):5d}  {k}")
        print(f"{len(findings):5d}  TOTAL")
        return 1 if findings else 0
    print(f"# Reference audit - {BASE}")
    for k in sorted(by_kind):
        print(f"\n## {k} ({len(by_kind[k])})")
        for m in sorted(by_kind[k]):
            print("  " + m)
    print(f"\nTOTAL {len(findings)} finding(s)")
    return 1 if findings else 0


if __name__ == "__main__":
    sys.exit(main())