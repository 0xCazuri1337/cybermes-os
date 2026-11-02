"""Rule 9 audit: no vulnerability class may have two canonical homes.

    python tools/taxonomy/audit_taxonomy.py

Checks, in order of how badly they break the map:

  1. NON-CANONICAL CLASS CONTENT — only `*/knowledge/CLASS.md` is a class
     page. A topic page whose filename resolves to a researched class must be
     a pointer, never a second full copy of the corpus.
  2. DUPLICATE CANONICAL PAGES — two class pages claim the same class.
     This is the failure the whole canonical-home rule exists to prevent.
  3. DEAD POINTER — a stub whose canonical target does not exist. A pointer
     that points nowhere is worse than no pointer: it looks navigable.
  4. ORPHANED EVIDENCE — a db class with items but no canonical page.
  5. SECTION DRIFT — a canonical class page missing a schema section, or
     carrying one in the wrong order. Rule 5 is a consistency claim.
  6. SUBDOC DRIFT — every taxonomy_spec.SUBDOCS entry exists and is non-empty.
  7. CHAIN DRIFT — family narratives carry CHAIN_SECTIONS; DB-backed chain
     digests carry CHAIN_DIGEST_SECTIONS. Every db.chain row has a digest.
  8. UNMARKED CONTENT — a section that is neither empty, nor `Not yet
     researched.`, nor gated prose. Invented technical content must not be
     able to sit in the tree looking researched.

Only canonical class pages are checked against BUG_SECTIONS. DIGEST,
COMPETENCY, HUNT, session notes, methodology, assessment and skill pages have
their own schemas and are deliberately excluded from the class-page schema
check. Both WEB and NETWORK are scanned.

Exit 0 = clean. Exit 1 = at least one finding, each printed with its path.
"""
from __future__ import annotations

import os
import pathlib
import sys
from collections import defaultdict

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent.parent))

from build_taxonomy import (  # noqa: E402
    BUG_SECTIONS, CHAIN_SECTIONS, CLASS_HOME, STEM_TO_CLASS, db,
    researched_classes,
)
from taxonomy_spec import CHAINS, SUBDOCS  # noqa: E402
from wks.chains import CHAIN_DIGEST_SECTIONS  # noqa: E402

ROOT = pathlib.Path(__file__).resolve().parent.parent.parent
from wks import config, domains as _domains  # noqa: E402

# WKS_ROOT may be a Windows 8.3 short path (C:\\Users\\ADMINI~1\\...), but
# config resolves symlinks/aliases to the long form, so `relative_to(ROOT)`
# raised ValueError. Compare against the RESOLVED root.
ROOT = config.root().resolve()   # WKS_ROOT may be an 8.3 path
BC = _domains.domain_dir(_domains.WEB)
AC = _domains.domain_dir(_domains.NETWORK)
DOMAIN_DIRS = (BC, AC)
NR = "Not yet researched."

# Declared sub-documents. They are rendered by `tools/fill_subdocs.py` from
# the same gated corpus and live in a class bundle's `topics/`, so they carry
# no BUG_SECTIONS schema and own no `bug_class` row. Matching is by UNIQUE
# FILENAME: the old code compared a path relative to `domains/web` against a
# path relative to the retired `bug-classes/` root, so it could never see a
# sub-doc that was actually present — and could not report one that was absent.
_SUBDOC_NAMES = {f for files in SUBDOCS.values() for f in files}
_CHAIN_FAMILIES = {c[0] for c in CHAINS}
_APPENDIX = ("Narrative (authored)", "Full digest (authored)")

# rank for the order check; unknown sections must NOT raise. A schema check
# that crashes on unexpected input cannot report the unexpected input.
_SECTION_RANK = {s: i for i, s in enumerate(BUG_SECTIONS)}


def is_stub(txt: str) -> bool:
    return "Pointer — not the canonical page" in txt[:400]


def _rel(p: pathlib.Path) -> str:
    """Repo-relative path, tolerant of a Windows 8.3 short-path WKS_ROOT.

    `Path.relative_to` raises when the two spellings differ
    (`C:\\Users\\ADMINI~1\\...` vs `C:\\Users\\Administrator\\...`) and
    realpath does NOT expand the 8.3 form, so fall back to os.path.relpath,
    which compares by identity.
    """
    try:
        return p.relative_to(ROOT).as_posix()
    except ValueError:
        return pathlib.PurePath(
            os.path.relpath(str(p), str(ROOT))).as_posix()


def main() -> int:
    findings: list[str] = []
    canon: dict[str, list[str]] = defaultdict(list)
    con = db()
    researched = researched_classes(con)

    # Every markdown file is scanned for POINTER STUBS (a dead stub is a dead
    # stub wherever it lives). Only `knowledge/CLASS.md` is a canonical class
    # page: DIGEST.md, COMPETENCY.md, HUNT.md, session notes, methodology pages
    # and topic skeletons are different document types with their own schemas.
    # The old list-of-names filter read every one of those as a class page,
    # producing 40 false "duplicate canonical" and ~144 false section drifts.
    pages: list[pathlib.Path] = []
    for dom_dir in DOMAIN_DIRS:
        pages += [p for p in dom_dir.rglob("*.md")
                  if p.name != "README.md" and "chains" not in p.parts]

    class_pages: list[pathlib.Path] = []
    subdoc_pages: list[pathlib.Path] = []

    for p in pages:
        txt = p.read_text(encoding="utf-8")

        # A migrated file opens with a provenance banner, so line 1 is a
        # comment shared by every bundle.
        _tl = [x for x in txt.splitlines()
               if not x.lstrip().startswith("<!--")]
        title = (_tl[0] if _tl else "").lstrip("# ").strip()

        if is_stub(txt):
            # 2. dead pointer. The stub renders its canonical home in TWO
            # forms on one line -- a markdown link target and a bare
            # backticked path. Reading the first backtick span took the PROSE
            # form (`web/authorization/`) and called 7 healthy pointers dead.
            import re as _re
            target = ""
            for line in txt.splitlines():
                if line.startswith("**Canonical home:**"):
                    m = _re.search(r"\]\(([^)]+)\)", line)
                    target = m.group(1) if m else (
                        line.split("`")[1] if "`" in line else "")
                    break
            if not target:
                findings.append(f"STUB HAS NO TARGET  {_rel(p)}")
            elif not (p.parent / target).resolve().exists():
                findings.append(f"DEAD POINTER  {_rel(p)} -> {target}")
            continue

        if p.name == "CLASS.md" and p.parent.name == "knowledge":
            class_pages.append(p)
            canon[title].append(_rel(p))

            secs = [ln[3:].strip() for ln in txt.splitlines()
                    if ln.startswith("## ")]
            if secs != list(BUG_SECTIONS):
                missing = [s for s in BUG_SECTIONS if s not in secs]
                extra = [s for s in secs if s not in BUG_SECTIONS]
                order_ok = secs == sorted(
                    secs, key=lambda s: _SECTION_RANK.get(s, 99))
                findings.append(
                    f"SECTION DRIFT  {_rel(p)}  "
                    f"missing={missing} unexpected={extra} order_ok={order_ok}")

            # 5. every section must be empty, NR, or substantive
            cur = None
            body: dict[str, list[str]] = defaultdict(list)
            for ln in txt.splitlines():
                if ln.startswith("## "):
                    cur = ln[3:].strip()
                elif cur:
                    body[cur].append(ln)
            for s, lines in body.items():
                content = "\n".join(lines).strip()
                if not content or content == NR:
                    continue
                if len(content) < 40:
                    findings.append(
                        f"THIN SECTION  {_rel(p)} :: {s} "
                        f"({len(content)} chars — too short to be gated prose)")
            continue

        # A sub-document has its OWN schema. The contract is only that it is
        # non-empty and carries at least one section; applying BUG_SECTIONS to
        # it is the mistake that made the audit look like a tree-wide failure.
        if p.name in _SUBDOC_NAMES:
            subdoc_pages.append(p)
            secs = [ln[3:].strip() for ln in txt.splitlines()
                    if ln.startswith("## ")]
            if not txt.strip():
                findings.append(f"EMPTY SUBDOC  {_rel(p)}")
            elif not secs:
                findings.append(f"SUBDOC HAS NO SECTIONS  {_rel(p)}")
            if NR in txt and "item" not in txt.lower():
                findings.append(
                    f"SUBDOC UNMARKED CONTENT  {_rel(p)}  "
                    f"reads 'Not yet researched' but claims no gated item")
            continue

        # A topic directory is a routing surface. A non-stub page there whose
        # filename resolves to a researched class is a second copy of that
        # class, even when it is not named CLASS.md. This is what caught the
        # 23 KB `topics/authentication/rate-limit.md` duplicate that the old
        # title-only duplicate check missed.
        if "topics" in p.parts:
            _stem = p.name[:-3]
            _cid = STEM_TO_CLASS.get(_stem, _stem)
            if _cid in researched and CLASS_HOME.get(_cid):
                findings.append(
                    f"NON-CANONICAL CLASS CONTENT  {_rel(p)}  "
                    f"duplicates {_cid} (canonical: {CLASS_HOME[_cid]})")

    for title, ps in sorted(canon.items()):
        if len(ps) > 1:
            findings.append(f"DUPLICATE CANONICAL  {title}: {ps}")

    # 3. orphaned evidence
    for (cid,) in con.execute("select id from bug_class"):
        n = con.execute("select count(*) from item where class_id=?",
                        (cid,)).fetchone()[0]
        if n and cid not in CLASS_HOME:
            findings.append(
                f"ORPHANED EVIDENCE  class {cid}: {n} items, no CLASS_HOME")

    # R14 resolves each entry through the ONE layout owner. The old form
    # `domain_dir(domain) / cid / CLASS.md` omitted both the specialization
    # directory and `knowledge/`, so it reported all 70 healthy pages missing.
    for cid, home in sorted(CLASS_HOME.items()):
        try:
            hp = _domains.class_subdir(cid, "knowledge", con) / "CLASS.md"
        except Exception as e:  # unmapped class / specialization
            findings.append(f"CLASS_HOME UNRESOLVABLE  {cid} -> {home}: {e}")
            continue
        if not hp.exists():
            findings.append(f"CLASS_HOME MISSING FILE  {cid} -> {home}")

    # 4. declared sub-documents must exist. Matching by unique filename is
    # deliberate: a path comparison against the retired bug-classes/ root can
    # neither find a present sub-doc nor report an absent one.
    by_name: dict[str, list[pathlib.Path]] = defaultdict(list)
    for p in pages:
        if p.name in _SUBDOC_NAMES:
            by_name[p.name].append(p)
    for name in sorted(_SUBDOC_NAMES):
        found = by_name.get(name, [])
        if not found:
            findings.append(
                f"MISSING SUBDOC  {name}  declared in taxonomy_spec.SUBDOCS")
        elif len(found) > 1:
            findings.append(
                f"DUPLICATE SUBDOC  {name}: {[_rel(p) for p in found]}")

    # 5. chains, in BOTH domains. There are TWO chain document types:
    #   * the seven family narratives declared in taxonomy_spec.CHAINS, which
    #     carry the full CHAIN_SECTIONS schema; and
    #   * DB-backed chain digests written by wks.chains, whose contract is the
    #     evidence sequence itself (CHAIN_DIGEST_SECTIONS).
    # Applying one schema to both reported 71 healthy digests as drifted.
    db_keys = {r["chain_key"] for r in
               con.execute("select chain_key from chain")}
    chain_files: list[pathlib.Path] = []
    for dom_dir in DOMAIN_DIRS:
        cdir = dom_dir / "chains"
        if not cdir.is_dir():
            continue
        for q in sorted(cdir.glob("*.md")):
            if q.name == "README.md" or q.parent != cdir:
                continue
            if is_stub(q.read_text(encoding="utf-8")):
                continue
            chain_files.append(q)

    for fname in sorted(_CHAIN_FAMILIES):
        if not any((d / "chains" / fname).exists() for d in DOMAIN_DIRS):
            findings.append(f"MISSING CHAIN FAMILY  {fname}")

    for p in chain_files:
        # Scan the GENERATED section only. An authored appendix contributes
        # its own `## ` headings and is not schema.
        _gen = p.read_text(encoding="utf-8")
        for marker in _APPENDIX:
            _gen = _gen.split(f"## {marker}")[0]
        secs = [ln[3:].strip() for ln in _gen.splitlines()
                if ln.startswith("## ")]
        if p.name in _CHAIN_FAMILIES:
            _order = [x for x in secs if x in CHAIN_SECTIONS]
            _extra = [x for x in secs if x not in CHAIN_SECTIONS]
            if _order != list(CHAIN_SECTIONS) or _extra:
                findings.append(
                    f"CHAIN SCHEMA DRIFT  {_rel(p)}  "
                    f"{len(_order)}/{len(CHAIN_SECTIONS)} sections"
                    + (f"  extra={_extra}" if _extra else ""))
        elif p.stem in db_keys:
            if secs != list(CHAIN_DIGEST_SECTIONS):
                findings.append(
                    f"CHAIN DIGEST DRIFT  {_rel(p)}  "
                    f"expected={list(CHAIN_DIGEST_SECTIONS)} got={secs}")
        else:
            findings.append(
                f"UNKNOWN CHAIN FILE  {_rel(p)}  "
                f"not in taxonomy_spec.CHAINS or db.chain")

    present_keys = {p.stem for p in chain_files}
    for key in sorted(db_keys - present_keys):
        findings.append(f"MISSING CHAIN DIGEST  {key}.md")

    con.close()

    print(f"audited {len(class_pages)} canonical CLASS pages, "
          f"{len(subdoc_pages)}/{len(_SUBDOC_NAMES)} declared sub-docs, "
          f"{len(chain_files)} chain files ({len(db_keys)} db chains)")
    if findings:
        print(f"\n{len(findings)} finding(s):")
        for f in findings:
            print("  " + f)
        return 1
    print("OK — one canonical home per class, no dead pointers, no orphaned "
          "evidence, schemas uniform")
    return 0


if __name__ == "__main__":
    sys.exit(main())