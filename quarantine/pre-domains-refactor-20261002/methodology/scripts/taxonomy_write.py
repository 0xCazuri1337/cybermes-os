"""Write the taxonomy from the spec + the canonical db. `--check` verifies only.

    python methodology/scripts/taxonomy_write.py           # write
    python methodology/scripts/taxonomy_write.py --check   # verify, exit 1 on drift

WHAT IT WRITES
    domains/<domain>/<class_id>/knowledge/   canonical class page
    domains/<domain>/<class_id>/topics/      pointer stubs + sub-topic pages
    domains/<domain>/chains/                 one file per chain family
    domains/web/areas/                       the area indexes
    learning/**, validation/**, reporting/** the non-taxonomy READMEs

    Every path is derived from `wks.domains.class_rel`, which is the single
    owner of the layout. This script never spells a class directory itself: a
    second spelling is a second answer, and the two will eventually disagree.

WHAT IT NEVER TOUCHES
    The per-class evidence digests under each class's `knowledge/` and the chain
    digests under each domain's `chains/` — those are GENERATED projections of
    db/wks.db produced by wks/pipeline.py. CONTROL/rules.md R11 forbids
    hand-editing a generated document, so this script leaves them entirely
    alone. The db class id -> canonical file mapping is CLASS_HOME.
"""
from __future__ import annotations

import argparse
import re
import posixpath
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))

DOMAINS = "domains"


def _cdir(class_id: str) -> str:
    """Repo-relative path of a class's own directory, via the one owner.

    Delegates to wks.domains so the generator, the skill writer, the pipeline
    and the merger cannot disagree about where a class lives. Raises for a
    network class with no specialization rather than guessing a folder.
    """
    from wks import domains as _d
    return _d.class_rel(class_id, _CON)

from build_taxonomy import (  # noqa: E402
    BUG_SECTIONS, CHAIN_SECTIONS, NR, STEM_TO_CLASS, CHAIN_HOME,
    CLASS_HOME, db, bug_file, chain_file, render, researched_classes,
)
from taxonomy_spec import (  # noqa: E402
    CHAINS, CLASSES, README_FOR, R, STUBS, SUBDOCS,
)

ROOT = Path(__file__).resolve().parent.parent.parent
# MERGED TREE (2026-10-02). The canonical class page and the chain narrative
# are emitted INTO the merged bundles instead of two top-level trees:
#
#   skills/<Web|Network + AD>/<class_id>/CLASS.md   <- was bug-classes/**/<name>.md
#   skills/<Web|Network + AD>/chains/<family>.md    <- was attack-chains/<family>.md
#
# The domain is derived per class from the db on every run, so a class
# registered later lands in the correct half with no edit here.
from wks import domains as _domains   # noqa: E402

BC = _domains.domain_dir(_domains.WEB)
AC = _domains.domain_dir(_domains.NETWORK)

# Populated per-run from the canonical db. Never a literal here.
_CON = None
_RESEARCHED: set[str] = set()


def _rel_to(target_rel: str, dest_dir: str) -> str:
    """Path of `target_rel` relative to the directory the file is written into.

    A generated README lives several directories deep
    (`skills/Web/areas/web/authentication/`), so a repo-relative path is wrong by
    depth -- MEASURED: 46 links that LOOKED rewritten and resolved nowhere.
    """
    import posixpath
    if not dest_dir:
        return target_rel
    return posixpath.relpath(target_rel, dest_dir)


def _retarget(body: str, dest_dir: str = "") -> str:
    """Rewrite references to the retired tree inside a GENERATED body.

    R11 forbids editing a generated file after the fact, and the spec's README
    bodies name pages by their pre-merge paths. Every generator run re-emits
    those dead links, so a post-hoc retargeter loses on the next run -- rewriting
    them HERE makes the fix part of generation.
    """
    for cid, rel in CLASS_HOME.items():
        dom = _domains.domain_of(_CON, cid)
        lab = _domains.DOMAIN_LABEL[dom]
        for old, new in ((f"bug-classes/{rel}", f"../../{lab}/{cid}/CLASS.md"),
                         (f"classes/{cid}.md", f"../../{lab}/{cid}/EVIDENCE.md"),
                         (f"skills/{cid}-hunting/SKILL.md", f"{_cdir(cid)}/skills/SKILL.md")):
            body = body.replace(old, new)
        # NB: the BARE `stem.md` form is handled once, by the
        # CLASS-PAGE loop below. It used to be rewritten here too, and
        # because that pass replaced only the label it ran AFTER the
        # correct one and undid it -- `[`../../smb/CLASS.md`](smb.md)`
        # (MEASURED: 6 Network-AD area READMEs, permanent drift).

        area = rel.rsplit("/", 1)[0]
        for key, files in SUBDOCS.items():
            karea = key[len("bug-classes/"):] if key.startswith("bug-classes/") else key
            if karea != area:
                continue
            for sub in files:
                body = body.replace(
                    f"bug-classes/{area}/{sub}",
                    _rel_to(f"{_cdir(cid)}/topics/{sub}", dest_dir))
                # and the BARE form, which is how the spec's xss area README
                # names its sub-docs. Without this the name survived the
                # pipeline and resolved to a sibling that never existed
                # (MEASURED: `framework-xss.md` as a dead link).
                body = body.replace(f"`{sub}`", f"`{_rel_to(f'{_cdir(cid)}/topics/{sub}', dest_dir)}`")
    # NON-SUBDOCS topic pages. `web/authorization/privilege-escalation.md` is a
    # CLASSES row with no db class, so it renders under the domain's topics/
    # instead of a class bundle -- and the authorization area README names it
    # as a bare filename. Without this the generator emitted the bare name
    # (MEASURED: 14 files drifting on every `--check`).
    for _path, _t, _c, _o, _n in CLASSES:
        if _path_to_class(_path):
            continue                      # handled as a canonical class page
        _stem2 = _path.rsplit("/", 1)[-1]
        _root2 = _path.split("/", 1)[0]
        _dom2 = _domains.NETWORK if _root2 == "network" else _domains.WEB
        _tgt2 = f"domains/{_domains.DOMAIN_SLUG[_dom2]}/topics/{_path[len(_root2) + 1:]}"
        _l2 = _rel_to(_tgt2, dest_dir)
        # BOTH forms: the bare filename, the full bug-classes-relative path, and
        # each as a markdown link whose label and target must move together.
        for _a in (f"[`{_stem2}`]({_stem2})", f"[`{_path}`]({_path})",
                   f"`{_stem2}`", f"`{_path}`"):
            body = body.replace(_a, f"[`{_l2}`]({_l2})" if _a.startswith("[")
                                else f"`{_l2}`")
    # CLASS-PAGE PATHS named in a README body. `web/authorization/idor.md` is a
    # canonical CLASS page (CLASS_HOME['idor']), and it now renders as the
    # bundle's `topics/idor.md` -- a different name and a different directory,
    # so a body that still names the old path resolves to nothing
    # (MEASURED: 10 dead links across skills/README.md and two bundles).
    for _cid3, _rel3 in CLASS_HOME.items():
        _stem3 = _rel3.rsplit("/", 1)[-1]
        try:
            _lab4 = _domains.DOMAIN_LABEL[
                _domains.domain_of(_CON, _cid3)]
        except KeyError:
            _lab4 = "Network + AD" if _rel3.startswith("network") else "Web"
        # A CLASS page whose filename differs from its class id
        # (`network/infrastructure/exposed-services.md` -> class
        # `exposed_services`) is a SUB-page rendered into the bundle's
        # topics/, not the canonical CLASS.md. Comparing only the id missed it
        # (MEASURED: 6 Network-AD area READMEs drifting on every --check).
        # Every CLASS_HOME entry whose stem equals the id (in either the
        # underscore or hyphen spelling) is the CANONICAL page -> CLASS.md.
        # `exposed_services` and `exposed-services` are the same id; treating
        # the hyphen form as a sub-page sent the README's links to
        # `<bundle>/topics/`, which does not exist (MEASURED: 6 READMEs).
        _is_canon = _stem3 in (f"{_cid3}.md", f"{_cid3.replace('_', '-')}.md")
        if _is_canon:
            # the class's own page: CLASS.md in its bundle
            _tgt4 = f"{_cdir(_cid3)}/knowledge/CLASS.md"
        else:
            # a sub-page of the class: <bundle>/topics/<stem>
            _tgt4 = f"{_cdir(_cid3)}/topics/{_stem3}"
        _l4 = _rel_to(_tgt4, dest_dir)
        # ONE regex for the whole reference, so the label and the link move
        # together. Replacing them in sequence left a rewritten label beside a
        # stale link, because the second substitution matched inside the row the
        # first had just written (MEASURED: `../../smb/CLASS.md`](smb.md)` in
        # 6 Network-AD area READMEs, drifting on every --check).
        for _a2 in (_rel3, _stem3):
            body = re.sub(
                r"\[`" + re.escape(_a2) + r"`\]\([^)]+\)"
                r"|`" + re.escape(_a2) + "`",
                lambda _m: (f"[`{_l4}`]({_l4})"
                            if _m.group(0).startswith("[") else f"`{_l4}`"),
                body)


    # THE ROOT INDEX. `bug-classes/` (and bare `../bug-classes/`) is the tree
    # root, which is now `skills/`. One reference in R["reporting"] kept
    # pointing at the retired directory (MEASURED: 1 permanent R15 drift).
    # Match the LITERAL label the spec uses (`bug-classes/`, with its trailing
    # slash) rather than deriving it: deriving dropped the slash and the
    # substitution matched nothing (MEASURED: 1 permanent drift).
    for _lab in ("`bug-classes/`", "`skills/`"):
        for _old in ("../bug-classes/README.md", "bug-classes/README.md"):
            body = body.replace(
                f"[{_lab}]({_old})",
                f"[`domains/`]({_rel_to('domains/README.md', dest_dir)})")

    # CHAIN NARRATIVES named in a README body. `attack-chains/api-chains.md`
    # became `skills/<domain>/chains/api-chains.md`; the generator emitted the
    # retired prefix, so R15 --check drifted on every run (MEASURED: 8 READMEs).
    # The chain narratives are emitted under Web; a Network-only tree is not
    # where a spec body means them, so the Web location is the one to emit.
    for _cf in _chain_basenames():
        body = body.replace(
            f"`attack-chains/{_cf}`",
            f"`{_rel_to(f'domains/web/chains/{_cf}', dest_dir)}`")

    # STUB FILENAMES in a README body (`ssti.md`). The stub is now the owning
    # class's `topics/<name>.md`, so the bare filename resolves to nothing
    # (MEASURED: 8 READMEs drifting on every `--check`).
    for _skey2, (_st2, _sc2, _sw2) in STUBS.items():
        _srel2 = _skey2[len("bug-classes/"):] if _skey2.startswith("bug-classes/") else None
        if not _srel2:
            continue
        _stem5 = _srel2.rsplit("/", 1)[-1]
        _cid5 = _stub_class(_srel2, _sc2)
        _root5 = _srel2.rsplit("/", 1)[0]
        if _cid5:
            try:
                _lab5 = _domains.DOMAIN_LABEL[
                    _domains.domain_of(_CON, _cid5)]
            except KeyError:
                _lab5 = "Network + AD" if _root5.startswith("network") else "Web"
            _tgt5 = f"{_cdir(_cid5)}/topics/{_stem5}"
        else:
            _lab5 = "Network + AD" if _root5.startswith("network") else "Web"
            _tgt5 = f"domains/{DOMAINS}/{_root5}/topics/{_stem5}"
        _link5 = _rel_to(_tgt5, dest_dir)
        body = body.replace(f"[`{_stem5}`]({_stem5})",
                            f"[`{_link5}`]({_link5})")
        body = body.replace(f"`{_stem5}`", f"`{_link5}`")

    # STUB PATHS named in a README body (`api/rest/idor-bola.md`). The stub
    # itself is relocated into a bundle's topics/ or the domain's topics/, so a
    # path that was a sibling in `bug-classes/` no longer resolves. Resolve it
    # through the same STUBS table the writer uses (MEASURED: 13 dead links in
    # skills/README.md alone).
    for _skey, (_stitle, _scan, _swhy) in STUBS.items():
        _srel = _skey[len("bug-classes/"):] if _skey.startswith("bug-classes/") else None
        if not _srel:
            continue
        _cid2 = _stub_class(_srel, _scan)
        _root3 = _srel.rsplit("/", 1)[0]
        _lab3 = "Network + AD" if _root3.startswith("network") else "Web"
        if _cid2:
            try:
                _lab3 = _domains.DOMAIN_LABEL[
                    _domains.domain_of(_CON, _cid2)]
                _dest3 = f"{_cdir(_cid2)}/topics"
            except KeyError:
                _dest3 = f"domains/{DOMAINS}/{_root3}/topics"
        else:
            _dest3 = f"domains/{DOMAINS}/{_root3}/topics"
        body = body.replace(
            f"`{_srel}`",
            f"`{_rel_to(f'{_dest3}/{_srel.rsplit(chr(47), 1)[-1]}', dest_dir)}`")
    return body


def readme(parent: str, title: str, body: str) -> str:
    """A directory README.

    The spec bodies are written as complete documents and most of them open
    with their own `# Heading`. `readme()` also prepends one, so eight of the
    nine generated READMEs rendered a DOUBLED title ("# Attack chains" twice)
    that had been sitting in the tree looking like a formatting quirk. The
    rule is: trust the body when it declares its own title, otherwise supply
    the one passed in.
    """
    body = _retarget(body, parent).strip()
    if body.startswith("# "):
        return body + "\n"
    return f"# {title}\n\n{body}\n"


def stub(title: str, canonical: str, why: str, target: str | None = None,
         prose_path: str | None = None) -> str:
    """A pointer stub. Deliberately thin — it must never become a second copy.

    `canonical` is the LABEL (the old tree-relative path, so a reader can still
    recognise the page) and `target` is the LINK, which must resolve inside the
    merged tree. Reusing one value for both left every API area stub with a dead
    link (MEASURED: 14 files failing R15 --check on every generator run).
    """
    target = target if target is not None else canonical
    # When the canonical page sits in the SAME bundle, the label is that link.
    # Naming the retired path as the label left the stub pointing one way and
    # labelling the other (MEASURED: `../../web/authorization/idor.md` as the
    # label of a stub whose link is `../CLASS.md`).
    if target.startswith("..") and "topics/" not in target:
        canonical = target
    # The `why` prose opens with its own "Canonical home: `<old path>`." Naming
    # a path that no longer exists, and `retarget_refs` rewrote it after the
    # fact so R15 --check never settled (MEASURED: 8 files drifting every run).
    # The LABEL is the human-facing name; the prose must name the same one.
    # The prose names the page by its REPO path, because the link is stored
    # relative to the stub's own directory and is not followable as written.
    _prose = why
    if prose_path:
        import re as _re2
        _prose = _re2.sub(r"Canonical home: `[^`]+`",
                          f"Canonical home: `{prose_path}`", why)
    return (
        f"# {title}\n\n"
        f"> **Pointer — not the canonical page.**\n\n"
        f"**Canonical home:** [`{canonical}`]({target})\n\n"
        f"{_prose}\n\n"
        f"This file exists so the name is findable from this directory. It "
        f"deliberately contains no vulnerability content: a second copy is how "
        f"a taxonomy rots.\n"
    )


def class_page(path: str, title: str, cwe: str, owasp: str, one: str) -> str:
    """A skeleton for a class with no gated evidence — honest, not invented."""
    stem = path.split("/")[-1][:-3]
    # RESEARCHED is keyed by db class id; several classes have more than one
    # possible canonical filename (graphql-surface.md <-> class `graphql`).
    # An explicit stem->class map beats guessing, because guessing silently
    # renders a skeleton for a class that HAS gated evidence.
    cid = STEM_TO_CLASS.get(stem, stem)
    if cid in _RESEARCHED:
        return bug_file(_CON, cid)
    head = [
        f"- **CWE:** {cwe}",
        f"- **OWASP:** {owasp}",
        "",
        one,
        "",
        f"Canonical home for this class. Sections are filled only from gated "
        f"evidence in `db/wks.db`; every section below is unresearched until "
        f"a research wave clears the gate (`validation/validation-gates.md`).",
    ]
    body = {"Definition": "\n".join(head)}
    return render(title, BUG_SECTIONS, body)


def chain_page(fname: str, title: str, blurb: str) -> str:
    key = {v: k for k, v in CHAIN_HOME.items()}.get(fname)
    if key:
        return chain_file(_CON, key)
    return render(title, CHAIN_SECTIONS, {
        "Objective": blurb + "\n\nNo chain in this family has passed the "
                      "evidence gate yet. `wks/chains.py` refuses to build a "
                      "step on a missing or unpromoted item, so this file "
                      "stays a schema until the underlying classes are gated.",
    })


def supporting() -> dict[str, str]:
    """learning/, validation/ — the non-taxonomy responsibilities."""
    out: dict[str, str] = {}

    out["learning/README.md"] = readme("learning", "Learning workspace", R["learning"])
    for d, what in (
        # Brief §12: learning state is not knowledge. The five names below are
        # the LEARNING LOOP's own vocabulary (goal -> tasks -> evidence ->
        # proposals -> progress), and each is transient state about the next
        # wave, never a place canonical knowledge is filed. `knowledge` was the
        # old name for promoted findings; it is now `proposals`, because a
        # finding only becomes knowledge by passing the gate, and a folder named
        # "knowledge" invited exactly the confusion this refactor removes.
        ("plans", "the active Goal, its measurable criteria, and the current wave"),
        ("tasks", "one brief per delegated specialist, with status and output path"),
        ("sessions", "raw subagent output — staging only, never trusted"),
        ("proposals", "findings awaiting the gate; promoted into domains/ only after review"),
        ("gaps", "what the last wave failed to close, and why"),
        ("progress", "maturity and coverage over time, per class"),
    ):
        out[f"learning/{d}/README.md"] = readme(
            f"learning/{d}", d.title(),
            f"Holds {what}.\n\n"
            f"Part of the learning loop described in `../README.md`. Nothing "
            f"here is canonical vulnerability knowledge — that is "
            f"`domains/`, and it arrives only through the gate at "
            f"`validation/validation-gates.md`.")
    # NOTE: readme() retargets, so the `bug-classes/` and `../README.md`
    # references above are rewritten to their merged-tree homes at render time.

    out["validation/README.md"] = readme("validation", "Validation", R["validation"])

    # reporting/ — R["reporting"] existed in the spec but nothing rendered it,
    # so `reporting/README.md` was hand-written and would drift from the spec
    # with nothing to notice. Generating it closes that: the spec entry and the
    # file on disk can no longer disagree.
    #
    # The body in R["reporting"] carried no markdown links and named
    # REPORT_FORMAT.md without saying it was superseded. Corrected in
    # taxonomy_spec.py so the rendered page keeps the links a reader needs.
    out["reporting/README.md"] = readme("reporting", "Reporting", R["reporting"])

    out["validation/validation-gates.md"] = readme(
        "validation/validation-gates", "Validation Gates",
        """The hard gates a finding must clear before it is knowledge.

## The four hard gates

These are **necessary conditions, not inputs to a weighted score**. A weighted
mean can be passed by a short, fluent, confident claim; a gate cannot.

| Gate | Rejects | Implemented in |
|---|---|---|
| `NO_SOURCES` / `INSUFFICIENT_SOURCES` | a claim with no provenance | `wks/quality.py` |
| `INSUFFICIENT_PUBLISHER_HOSTS` | two pages on one host counted as corroboration | `wks/quality.py` |
| `DISCOVERY_ONLY_SOURCE` | social media as knowledge (a lead, not a source) | `wks/quality.py` |
| `FABRICATED_REFS` | invented cross-references (`Ref1`, `Source2`) — **reject**, never downgrade | `wks/quality.py` |

Plus one gate outside the database: **every cited quote must actually appear on
the cited page** (`wks/verify_quotes.py`). A subagent reporting that it read a
source is a self-report and carries no weight.

## Why publisher hosts and not citation counts

Two pages on `owasp.org` are one publisher. The metric that matters is the
number of distinct registrable hosts behind a claim — measured on the previous
system, where 37 of 54 competencies could never corroborate because every seed
sat on `cwe.mitre.org`.

## States

`discovered → under_review → supported → high_confidence`, with `disputed`,
`outdated`, `rejected` and `unresolved` as legitimate terminal-ish states.
Unresolved is never presented as established.

## Checking

```bash
python -m wks.cli selftest     # the gate regressions
python -m wks.cli gate         # re-assess every item
```

`quality.py` is the **only** writer of `validation_state`. Nothing else may set
it.""")

    out["validation/evidence-requirements.md"] = readme(
        "validation/evidence-requirements", "Evidence Requirements",
        """What a finding must carry before it can be reported.

## Required

1. **Two accounts you control**, fully separated, for any authorization claim.
   Reading your own second account proves the boundary is missing without
   involving anyone else.
2. **A disproof clause** — the condition that would prove the claim *wrong*.
   An item with no disproof is a checklist line, not knowledge.
3. **The request/response pair**, not a description of it.
4. **Downstream state evidence** for anything involving timing or a counter:
   the HTTP trace proves the attempt, the resulting state proves the effect.
5. **Quantified scope** limited to what was actually performed. Bulk extraction
   that was not carried out does not go in the report.

## Insufficient on its own

- A `200` without a comparison against a second identity.
- A tool's severity label with no stated basis.
- A screenshot with no reproducible request.
- Behaviour reproduced only on dev/staging, where the hostname is out of scope.

## Boundary

`wks/config.py` carries `RESEARCH_ONLY = True` and `CAN_AUTHORIZE = False`.
This system fetches published documentation; it does not scan, fuzz, or exploit
any target. Active testing requires explicit, user-provided authorization and
lives outside this pipeline.""")

    out["validation/false-positives.md"] = readme(
        "validation/false-positives", "False Positives",
        """Rejecting a hypothesis before it costs a report slot.

## The rule

A rejection must say **why the evidence is not a finding**, not "this looks
intended". Each per-class rule lives in `db/wks.db` (`fp_case`) and renders
into that class file's *Common False Positives* section — this file is the
discipline, not the list.

## Distinguish two rejections

| Verdict | Meaning | Action |
|---|---|---|
| *unpromotable pending better evidence* | the claim may hold; the evidence is thin | hold, find a second publisher |
| *evidence is fabricated* | the quote is not on the page, or a ref is invented | **reject and fix the producer** — do not retry the same brief |

Collapsing these two is how a broken acquisition step gets mistaken for a thin
item, and gets retried forever.

## Test the checker in both directions

A rejection rate computed from an unvalidated verifier is a number about your
own bugs, not about the producer. Before trusting any rejection:

- genuine artifact + genuine quote → must **PASS**
- genuine artifact + one substituted word → must **FAIL**

The first implementation of the quote checker rejected 11 of 56 **genuine**
quotes — a 19% false-positive rate, all of it extraction bugs (markdown
emphasis, table pipes, undecoded HTML entities) and none of it agent
misconduct. A verifier that cries wolf gets switched off, and then it protects
nothing. `eval/test_wks.py` T13 pins both directions.

## If a rejection looks wrong

Diff the raw artifact before blaming the source. Three false-negative sources
live in the extraction, not the quote: markdown emphasis, table pipes, and
undecoded entities (`&#x27;`, `&quot;`). Unescape before stripping tags and
again after.

## Record it

Every rejection carries its reason. That log is the audit trail and the input to
fixing the producer — `wks/fp.py` captures hypothesis → test → invalidated-by →
rejection rule.""")
    return out


# --------------------------------------------------------------------------

def _chain_basenames() -> set[str]:
    """Basenames of the chain NARRATIVES declared in the spec.

    Read from `CHAINS` rather than by scanning `attack-chains/`, because the
    generator's own destination is `skills/<domain>/chains/` and the retired
    directory may be gone by the time it runs.
    """
    return {c[0] for c in CHAINS} | {"cross-class-chains.md"}


def _stub_class(stub_rel: str, canonical: str) -> str | None:
    """Which class a pointer stub belongs to.

    The stub's own FILENAME is not a class id (`open-redirect.md` vs the
    registered `open_redirect`), so it resolves through the page it POINTS AT.
    """
    import posixpath
    joined = posixpath.normpath(
        posixpath.join(stub_rel.rsplit("/", 1)[0], canonical))
    for cid, rel in CLASS_HOME.items():
        if rel == joined or rel.endswith(joined.lstrip("./")):
            return cid
    return None


def _stub_target(stub_rel: str, canonical: str, _dest_dir: str) -> str:
    """Rebase a pointer stub's canonical path onto the merged tree.

    `canonical` is relative to the STUB's own directory in the old tree. Under
    the merged tree the stub sits in its own bundle's topics/, and its target is
    another bundle's CLASS.md, so the path must be rebuilt, not copied.
    """
    from build_taxonomy import CLASS_HOME
    # stub dir + canonical, normalised, is the old repo-relative page
    joined = posixpath.normpath(
        posixpath.join(stub_rel.rsplit("/", 1)[0], canonical))
    for cid, rel in CLASS_HOME.items():
        if rel == joined or rel.endswith(joined.lstrip("./")):
            try:
                dom = _domains.domain_of(_CON, cid)
            except KeyError:
                continue
            target = f"{_cdir(cid)}/knowledge/CLASS.md"
            # relative to the REAL destination of this stub, not a placeholder
            return posixpath.relpath(target, _dest_dir)
    # an area README
    if joined.endswith("README.md"):
        area = joined[: -len("/README.md")]
        dom = _domains.NETWORK if area.startswith("network") else _domains.WEB
        rel2 = area[len("network"):].lstrip("/") if area.startswith("network") else area
        target = f"domains/{_domains.DOMAIN_SLUG[dom]}/areas/{rel2}/README.md"
        return posixpath.relpath(target, _dest_dir)
    return canonical


def _path_to_class(path: str) -> str | None:
    """CLASSES key (e.g. `web/xss/xss.md`) -> db class id (e.g. `xss`).

    Derived by INVERTING CLASS_HOME, the one existing id -> path map. A second
    literal mapping would be a mirror that could silently disagree with it.
    """
    for cid, rel in CLASS_HOME.items():
        if rel == path:
            return cid
    return None


def build(check: bool) -> int:
    global _CON, _RESEARCHED
    _CON = db()
    # Read the researched set from the corpus, never from a literal in this
    # file: a background cycle can ingest new classes between runs, and a
    # hand-maintained mirror of db state goes stale silently.
    _RESEARCHED = researched_classes(_CON)
    files: dict[str, str] = {}

    # -- bug-classes -------------------------------------------------------
    files["domains/README.md"] = readme("domains", "Domains", R["bug-classes"])
    files["domains/web/README.md"] = readme("domains/web", "Web bug classes", R["web"])
    # The per-area indexes. MEASURED: these two were dropped when the
    # roots were repointed, so the area READMEs that 9 other files link to
    # had no target at all.
    files["domains/web/areas/web/README.md"] = readme(
        "domains/web/areas/web", "Web attack-surface areas", R["web"])
    files["domains/web/areas/api/README.md"] = readme(
        "domains/web/areas/api", "API attack-surface areas", R["api"])
    files["domains/network/README.md"] = readme("domains/network",
                                         "Network & Active Directory", R["api"])

    # README_FOR keys are ALREADY repo-relative (they begin with
    # `bug-classes/`). Prefixing again produced `bug-classes/bug-classes/`
    # and silently relocated the pointer stubs.
    # README_FOR keys are the OLD bug-classes/<area>/ paths. Under the merged
    # tree each area README belongs to the domain that owns the area, so the key
    # is rewritten rather than emitted at a path the writer would never revisit.
    # `network/**` is the only non-web root, matching the class split.
    for parent, (title, body) in README_FOR.items():
        _rel = parent
        if _rel.startswith("bug-classes/"):
            _rel = _rel[len("bug-classes/"):]
        elif _rel == "bug-classes":
            files["domains/README.md"] = readme("domains", title, body)
            continue
        elif _rel == "attack-chains":
            files["domains/web/chains/README.md"] = readme(
                "domains/web/chains", title, body)
            continue
        elif _rel.startswith("attack-chains/"):
            files[f"domains/web/chains/{_rel[len('attack-chains/'):]}"] = \
                readme(f"domains/web/chains/{_rel[len('attack-chains/'):]}",
                       title, body)
            continue
        _dom = _domains.NETWORK if _rel.startswith("network") else _domains.WEB
        _rel = _rel[len("network"):].lstrip("/") if _rel.startswith("network") else _rel
        # The domain ROOT itself ("bug-classes/network" strips to "") is the
        # domain README, not an area README. Without this branch it rendered
        # `domains/network/areas//README.md` — a path with an empty segment,
        # which no filesystem tool and no link can address.
        if not _rel:
            files[f"domains/{_domains.DOMAIN_SLUG[_dom]}/README.md"] = readme(
                f"domains/{_domains.DOMAIN_SLUG[_dom]}", title, body)
            continue
        _new = f"domains/{_domains.DOMAIN_SLUG[_dom]}/areas/{_rel}"
        files[f"{_new}/README.md"] = readme(_new, title, body)

    for path, title, cwe, owasp, one in CLASSES:
        # `path` stays the CLASSES key (what CLASS_HOME maps) so the spec
        # remains the registry; only the OUTPUT location moves, into the
        # bundle the db assigns this class to.
        # Two kinds of CLASSES row, and conflating them loses 23 real pages:
        #   * a CANONICAL class page -- has a db class and a CLASS_HOME entry.
        #     It renders into that class's bundle as CLASS.md.
        #   * a SUB-TOPIC page (`graphql/batching.md`, `coupon-abuse.md`) -- a
        #     technique or variant with no db class of its own. It still exists
        #     and is still generated, so it keeps its own file under the domain
        #     folder's `topics/` rather than being silently dropped or forced
        #     into a fake class id.
        _cid = _path_to_class(path)
        if _cid:
            _dom = _domains.domain_of(_CON, _cid)
            files[f"{_cdir(_cid)}/knowledge/CLASS.md"] = \
                class_page(path, title, cwe, owasp, one)
        else:
            # The directory's first segment decides the half. `network/**` is
            # the only non-web root, so this is derived from the same vocabulary
            # the class split uses rather than a list of page names.
            _root = path.split("/", 1)[0]
            _dom = _domains.NETWORK if _root == "network" else _domains.WEB
            _rel = path[len(_root) + 1:]
            files[f"domains/{_domains.DOMAIN_SLUG[_dom]}/topics/{_rel}"] = \
                class_page(path, title, cwe, owasp, one)

    # STUBS keys are ALREADY repo-relative. Prefixing them again produced
    # `bug-classes/bug-classes/**` and left the pointer stubs unreachable
    # from the directory whose README promises them.
    for path, (title, canonical, why) in STUBS.items():
        # STUBS keys are ALREADY repo-relative (bug-classes/**, attack-chains/**);
        # under the merged tree they move under skills/.
        # STUBS keys are repo-relative (`bug-classes/web/server-side/ssti.md`).
        # Under the merged tree a stub moves beside the pages it points AT, so a
        # reader who follows the pointer lands in the tree that owns the concept.
        _rel = path[len("bug-classes/"):] if path.startswith("bug-classes/") else None
        if _rel:
            _cid = None
            for _c, _h in CLASS_HOME.items():
                if _h == _rel:
                    _cid = _c
                    break
            if _cid is None:
                # The stub's own filename is NOT a class id (`open-redirect.md`
                # vs the registered `open_redirect`). Resolve through the page it
                # POINTS AT, which is a real CLASSES/CLASS_HOME key, and fall
                # back to the AREA the stub lives in.
                _joined = posixpath.normpath(
                    posixpath.join(_rel.rsplit("/", 1)[0], canonical))
                _cid = next((c for c, h in CLASS_HOME.items()
                             if h == _joined
                             or h.endswith(_joined.lstrip("./"))), None)
            if _cid is None:
                # No class page: the stub belongs to the DOMAIN of its area.
                _area = _rel.rsplit("/", 1)[0]
                _dom = (_domains.NETWORK if _area.startswith("network")
                        else _domains.WEB)
                    # The stub itself lives at that path, so its target must be
                # relative to the DIRECTORY it is written into.
                # The DIRECTORY the stub is written into, not the stub's own
                # filename: `skills/<dom>/topics/api/rest/` for `api/rest/x.md`.
                _here = f"domains/{_domains.DOMAIN_SLUG[_dom]}/topics/{_rel.rsplit('/', 1)[0]}".rstrip("/")
                # `_stub_target` already returns a path relative to `_here`;
                # wrapping it in `_rel_to` re-relativised it and produced 8
                # leading `../` (MEASURED: 7 dead links).
                _canon2 = _stub_target(_rel, canonical, _here)
                files[f"domains/{_domains.DOMAIN_SLUG[_dom]}/topics/{_rel}"] = stub(
                    title, canonical, why, target=_canon2,
                    prose_path=posixpath.normpath(
                        posixpath.join(_here, _canon2)))
                continue
            _dom = _domains.domain_of(_CON, _cid)
            _new = f"{_cdir(_cid)}/topics/{_rel.rsplit('/', 1)[-1]}"
            _dest = f"{_cdir(_cid)}/topics"
            _canon = _stub_target(_rel, canonical, _dest)
            # the prose names the page by its REPO path, so a reader sees
            # something they can look up; the link stays relative.
            _prose3 = posixpath.normpath(
                posixpath.join(_dest, _canon))
            files[_new] = stub(title, canonical, why, target=_canon,
                               prose_path=_prose3)
        else:
            files[f"domains/web/{path.replace('attack-chains/', 'chains/')}"] = \
                stub(title, canonical, why)

    # -- attack-chains -----------------------------------------------------
    files["domains/web/chains/README.md"] = readme("domains/web/chains",
                                                 "Web attack chains", R["chains"])
    for fname, title, blurb in CHAINS:
        files[f"domains/web/chains/{fname}"] = chain_page(fname, title, blurb)

    # -- methodology / reporting additions ---------------------------------
    files["domains/web/chains/cross-class-chains.md"] = chain_page(
        "cross-class-chains.md", "Cross-Class Chains",
        "Chains whose steps belong to different domains — for example an "
        "injection that yields a credential, which then yields an object.")

    files.update(supporting())

    # -- guard: one path, one owning generator ---------------------------
    # `taxonomy_write.py` renders CLASSES; `tools/fill_subdocs.py` renders
    # SUBDOCS. A path in both is claimed twice, and the second writer wins —
    # measured: running this script replaced six evidence-backed XSS
    # sub-documents with "Not yet researched." skeletons and `--check` still
    # reported clean, because the overwrite WAS the spec. The spec listed 57
    # canonical classes while only 51 ever existed on disk. Declaring a path
    # in both lists is a spec bug; refuse to write rather than pick a winner.
    # SUBDOCS keys are `bug-classes/web/xss` and the values are BARE filenames,
    # so `_path_to_class(_f)` never matched and every path came out as
    # `topics/None/<file>` -- which is why `--check` reported MISSING for pages
    # that the fill_subdocs generator had written correctly.
    subdoc_paths = set()
    for _d, _fs in SUBDOCS.items():
        _area = _d[len("bug-classes/"):] if _d.startswith("bug-classes/") else _d
        for _f in _fs:
            _cid = next((c for c, h in CLASS_HOME.items()
                         if h.rsplit("/", 1)[-1] == _area.rsplit("/", 1)[-1]
                         or h.endswith(_area)), None)
            # A SUBDOCS area with no CLASS_HOME entry resolves to no class. The
            # old code silently defaulted those to WEB, which produced a
            # `topics/None/<file>` path that matched nothing and made the guard
            # below vacuous for them. Skip instead: an unmapped subdoc cannot
            # clash with a rendered page, and the MISSING report from
            # fill_subdocs --check is what should surface it.
            if not _cid:
                continue
            subdoc_paths.add(f"{_cdir(_cid)}/topics/{_f}")
    clashes = sorted(subdoc_paths & set(files))
    if clashes:
        print("REFUSING TO WRITE — paths claimed by both generators:", file=sys.stderr)
        for c in clashes:
            print(f"  {c}", file=sys.stderr)
        print("\nFix: remove the path from CLASSES in taxonomy_spec.py. SUBDOCS is "
              "the owning declaration for anything tools/fill_subdocs.py renders.",
              file=sys.stderr)
        return 2

    # -- guard: every researched class must have a canonical file ----------
    # The first version of this script resolved a class id from the filename
    # stem, so `race-condition.md` rendered an empty skeleton while 12 gated
    # items sat in the db, and `oauth-oidc-misconfiguration.md` was missing
    # entirely with 14 items orphaned. Both were invisible: the run reported
    # success. A renderer that can silently drop gated evidence must assert
    # its own coverage.
    #
    # STEM_TO_CLASS is keyed by FILENAME STEM, so the assertion has to
    # invert it to ask "does a CLASSES row exist at the path CLASS_HOME
    # claims?". Comparing CLASS_HOME's stem back against STEM_TO_CLASS's key
    # is circular and rejects every correctly-wired class.
    declared = {c[0] for c in CLASSES}
    orphaned = [f"{cid}: CLASS_HOME={CLASS_HOME.get(cid)!r} is not a CLASSES row"
                for cid in _RESEARCHED if CLASS_HOME.get(cid) not in declared]
    if orphaned:
        print("REFUSING TO WRITE — researched classes without a canonical page:",
              file=sys.stderr)
        for o in orphaned:
            print("  " + o, file=sys.stderr)
        print("\nFix: add the CLASSES row for that path in taxonomy_spec.py, or "
              "correct CLASS_HOME.", file=sys.stderr)
        return 2

    # -- write / check -----------------------------------------------------
    # The area READMEs for `network/*` are HAND-AUTHORED, not in the spec, so
    # `retarget_refs` edits them in place after the merge. R15 compared them
    # against generator output that does not exist and reported DRIFT forever
    # (MEASURED: 4 files, on every run). `--check` therefore only asserts the
    # files this generator actually emits.
    drift = []
    for rel, text in sorted(files.items()):
        p = ROOT / rel
        if check:
            if not p.exists():
                drift.append(f"MISSING  {rel}")
            elif p.read_text(encoding="utf-8") != text:
                drift.append(f"DRIFT    {rel}")
            continue
        p.parent.mkdir(parents=True, exist_ok=True)
        if not p.exists() or p.read_text(encoding="utf-8") != text:
            p.write_text(text, encoding="utf-8")

    if check:
        if drift:
            print(f"{len(drift)} file(s) differ from the spec:")
            for d in drift:
                print("  " + d)
            return 1
        print(f"OK — {len(files)} files match the spec and the canonical db")
        return 0

    n_stub = len(STUBS)
    print(f"wrote {len(files)} files")
    print(f"  canonical class pages : {len(CLASSES)}")
    print(f"  pointer stubs         : {n_stub} (no duplicated knowledge)")
    print(f"  chain files           : {len(CHAINS)}")
    print(f"  from gated db rows    : {len(_RESEARCHED)} classes, "
          f"{len(CHAIN_HOME)} chains")
    return 0


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--check", action="store_true")
    sys.exit(build(ap.parse_args().check))