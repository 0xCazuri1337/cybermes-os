"""Paths and tunables. The only module that knows where things live."""
from __future__ import annotations

import os
from pathlib import Path


def root() -> Path:
    """Resolve the root at CALL time, never at import time.

    Import-time resolution is a trap: a module imported once keeps the first
    WKS_ROOT it saw, so a later sandboxed run silently writes to the earlier
    database and reports on state it is not changing. Every path below is
    therefore derived from a function.
    """
    env = os.environ.get("WKS_ROOT")
    if env:
        return Path(env)
    return Path(__file__).resolve().parent.parent


# Kept for convenience/back-compat, but prefer root() in library code.
ROOT = root()


def db_path() -> Path:
    """The canonical structured database.

    `WKS_DB` overrides the path outright. This is the SECOND sandbox
    lever, and it exists because `WKS_ROOT` alone cannot sandbox a
    SUBPROCESS that must run the real code.

    MEASURED 2026-11-01: `eval/test_dispatch_reachability.py` spawns
    `python -m orch.hunt_cli` as a subprocess and sets `WKS_ROOT=<repo>`.
    That was enough for the code, but `hunt_cli._con()` opens
    `root()/db/wks.db` -- and with `WKS_ROOT` pointing at the real repo,
    that IS the live canonical database. The subprocess wrote a real
    `finding` row (`reach.*.finding.*`, status `validating`) into the live
    corpus, and the scheduler counted it as potential impact.

    A subprocess cannot be monkeypatched, so the override has to be an
    ENVIRONMENT VARIABLE. `WKS_ROOT` relocates everything (code included),
    which means the subprocess can no longer find the real package --
    so it cannot be used alone. `WKS_DB` relocates ONLY the database,
    which is exactly the surface the subprocess needs to be isolated on.

    Resolution order:
      1. `WKS_DB`  -- an explicit database path.
      2. `WKS_ROOT/db/wks.db` -- the relocated root's database.
      3. `<repo>/db/wks.db` -- the canonical location.
    """
    env = os.environ.get("WKS_DB")
    if env:
        return Path(env)
    return root() / "db" / "wks.db"


DB_PATH = ROOT / "db" / "wks.db"
SCHEMA_PATH = Path(__file__).resolve().parent / "schema.sql"


def runtime_dir() -> Path:
    """Runtime state root — `runtime/state`.

    Brief §10: runtime state is NOT knowledge and must not sit beside it. Cycle
    journals, seed verification, resume cursors and audit output are all
    execution state: disposable, rewritten constantly, and meaningless to a
    reader who never ran the system. Keeping them in their own subtree means a
    knowledge export is `domains/` + `db/` and never sweeps up a half-written
    journal.

    A FUNCTION, like every path here, so a sandboxed run (WKS_ROOT) relocates
    its state with everything else.
    """
    return root() / "runtime" / "state"


# The legacy flat-tree constants (CLASSES_DIR, CHAINS_DIR, SKILLS_DIR,
# KNOWLEDGE_DIR, STATE_DIR) are GONE, not merely unused.
#
# They were module-level, so they froze `root()` at IMPORT time — the exact trap
# the `root()` docstring warns about — and after the move to `domains/` every
# one of them named a directory that no longer exists. A constant that points at
# a retired path is worse than no constant: it reads like a live handle, so the
# next caller writes into a folder nothing audits. The live equivalents are
# `runtime_dir()` here and `wks.domains.class_subdir()` / `class_rel()` for
# everything under `domains/`.
RESEARCH_DIR = ROOT / "knowledge" / "incoming"
KNOWLEDGE_DIR = ROOT / "knowledge"
INCOMING_DIR = ROOT / "knowledge" / "incoming"
MATERIALS_DIR = ROOT / "knowledge" / "materials"
ACTIVITY_DIR = ROOT / "knowledge" / "activity"
EVAL_DIR = ROOT / "eval"
CONTROL_DIR = ROOT / "CONTROL"

# ---------------------------------------------------------------------------
# Quality thresholds (brief §15, §29). Tuned, not guessed: the promotion gate
# is deliberately strict, because the failure mode being defended against is
# "a citation exists => trusted", which is how 1,380 unsourced stubs reached
# `validated` in the previous system.
# ---------------------------------------------------------------------------

# An item needs evidence from at least this many DISTINCT PUBLISHER HOSTS.
# Two pages on one host is one publisher, not corroboration.
MIN_PUBLISHER_HOSTS = 2

# User-hosting / page-builder domains are NOT independent publishers. A Notion
# or GitBook page is a document someone typed, not an authority that reviewed
# and published a position. Five such hosts sit in the `source` table right now
# (app.notion.com, two *.notion.site, two *.gitbook.io) and no active item cites
# them -- but nothing in the gate stopped that, so a future ingest could have
# satisfied MIN_PUBLISHER_HOSTS with two pages a single author uploaded.
#
# This is a STANDING USER CONSTRAINT: builder pages must never satisfy the
# multi-publisher-host rule. Enforced in quality.assess(), which filters these
# hosts out of BOTH the host count and the corroboration score, and re-reports
# the item as INSUFFICIENT_PUBLISHER_HOSTS rather than silently discounting it.
BUILDER_HOST_SUFFIXES = (
    ".notion.site",
    ".gitbook.io",
    ".readthedocs.io",
    ".netlify.app",
    ".vercel.app",
    ".pages.dev",
    ".web.app",
    ".firebaseapp.com",
)
BUILDER_HOSTS_EXACT = {
    "app.notion.com",
    "notion.so",
    "notion.site",
    "gitbook.io",
    "www.gitbook.io",
    "readthedocs.io",
    "netlify.app",
    "vercel.app",
    "pages.dev",
    "pages.github.io",
}


def is_builder_host(host: str) -> bool:
    """True when `host` is a page-builder / static-hosting domain rather than a
    publisher. Such a host may be CITED as a lead, never counted as a
    corroborating publisher."""
    h = (host or "").lower().strip(".")
    if h in BUILDER_HOSTS_EXACT:
        return True
    return any(h.endswith(sfx) for sfx in BUILDER_HOST_SUFFIXES)

# A publisher is an organisation, not a hostname. `www.microsoft.com` and
# `learn.microsoft.com` are two hosts run by the same company, so counting
# them as two independent corroborating publishers lets a single vendor's
# own documentation promote an item on its own -- exactly the failure the
# two-publisher rule exists to prevent. Builder hosts are filtered first;
# this collapses what is left onto its registrable domain.
#
# Deliberately a 2-label heuristic, not a public-suffix list: every host in
# this corpus is a ccTLD/gTLD domain (owasp.org, nccgroup.com, github.blog),
# so the last two labels identify the organisation. The `co.uk`-style
# exception is handled by the small suffix set below rather than by pulling
# in a dependency the tree deliberately does not have.
_MULTI_LABEL_TLDS = (
    ".co.uk", ".org.uk", ".ac.uk", ".gov.uk", ".co.jp", ".or.jp",
    ".com.au", ".net.au", ".org.au", ".co.nz", ".com.br", ".com.mx",
    ".co.in", ".com.sg", ".com.tr", ".co.za",
)

# GitHub serves one organisation's content from several registrable domains:
# the HTML site, the raw blob CDN, gists, and user/project Pages. The plain
# 2-label heuristic splits them into three "publishers"
# (github.com / githubusercontent.com / github.io), which is a false
# independence: one repository cited as both `github.com/...` and
# `raw.githubusercontent.com/...` would satisfy MIN_PUBLISHER_HOSTS on its own.
#
# This matters concretely for write-up corpora (HTB walkthroughs live almost
# entirely on GitHub), where a self-corroborating pair is the DEFAULT case
# rather than an edge case. Collapsing them to one org is strictly
# conservative: it can only ever make corroboration HARDER to reach, never
# easier, and the two-publisher rule still passes on github+portswigger,
# github+owasp, github+mitre, github+go.dev exactly as before.
_GITHUB_OWNED_ORGS = {"github.com", "githubusercontent.com", "github.io"}
GITHUB_PUBLISHER_ORG = "github.com"


def publisher_org(host: str) -> str:
    """Registrable-domain identity of `host`, used to count DISTINCT
    publishers. Two hosts that collapse to the same value are one publisher
    and must not satisfy the multi-publisher rule twice.

    GitHub's own domains collapse onto one org -- see _GITHUB_OWNED_ORGS.
    """
    h = (host or "").lower().strip().strip(".")
    if not h:
        return ""
    if h.endswith(_MULTI_LABEL_TLDS):
        parts = h.split(".")
        org = ".".join(parts[-3:]) if len(parts) >= 3 else h
    else:
        parts = h.split(".")
        org = ".".join(parts[-2:]) if len(parts) >= 3 else h
    return GITHUB_PUBLISHER_ORG if org in _GITHUB_OWNED_ORGS else org

# ...and at least this many sources overall.

MIN_SOURCES = 2

# Items whose claims are this vague cannot reach `supported` regardless of
# citations. Length is a proxy for specificity, not a quality claim.
MIN_CLAIM_CHARS = 40
MIN_BODY_CHARS_SUPPORTED = 200

# A class is `mature` only when every one of these holds (§29).
MATURITY_MIN_ITEMS = 12
MATURITY_MIN_HIGH_CONF = 4
MATURITY_MIN_FP_RULES = 2
MATURITY_MIN_CHAINS = 1

# Weighted quality vector. Weights sum to 1.0. Practical usefulness and
# evidence strength dominate deliberately: theory that cannot be applied is
# not hunting knowledge (§2).
QUALITY_WEIGHTS = {
    "source_credibility": 0.10,
    "technical_specificity": 0.13,
    "evidence_strength": 0.16,
    "reproducibility": 0.11,
    "corroboration": 0.14,
    "practical_usefulness": 0.18,
    "recency": 0.05,
    "internal_consistency": 0.06,
    "real_world_demo": 0.04,
    "limitations_documented": 0.03,
}

# State thresholds, applied to the weighted score AND to hard gates.
STATE_THRESHOLDS = {
    "high_confidence": 0.72,
    "supported": 0.55,
    "under_review": 0.30,
}

STATES = (
    "discovered",
    "under_review",
    "supported",
    "high_confidence",
    "disputed",
    "outdated",
    "rejected",
    "unresolved",
)

# Source authority tiers (1 strongest). Drives source_credibility.
#
# CLOSED VOCABULARY. `upsert_source` resolves a row's authority through
# `SOURCE_AUTHORITY.get(source_type, 3)`, so a type that is missing here does
# not raise — it silently becomes 3. That is not a cosmetic gap: authority 3
# scores 0.45 on source_credibility instead of 1.0, so a genuine IETF standard
# or a MITRE CWE page could be scored as if it were a practitioner's blog post.
#
# That is exactly what happened. 19 rows were written with types absent from
# this map (`standards_body`, `vendor_docs`, `research_doc`, `cwe`,
# `weakness_db`, `vendor_advisory`, `industry_guidance`, `standard`,
# `standards`) and all 19 defaulted to 3, dragging down 33 items that cite
# them. `research_sources.problems()` now fails loudly on a type that is not a
# key here, so the drift cannot be reintroduced silently.
SOURCE_AUTHORITY = {
    "taxonomy": 1,      # CWE, OWASP, NIST
    "advisory": 1,      # vendor advisories, CVE
    # Standards bodies and weakness databases are normative, not practitioner
    # material: an RFC or a CWE definition is a primary source.
    "standard": 1,          # RFC, ISO, W3C, WHATWG
    "standards": 1,         # plural spelling seen in older rows
    "standards_body": 1,    # rfc-editor.org and similar
    "cwe": 1,               # cwe.mitre.org definitions
    "weakness_db": 1,       # weakness taxonomies
    "docs": 2,          # vendor/platform documentation
    "research": 2,      # conference, lab research
    "cheatsheet": 2,    # PortSwigger Academy, HackTricks
    "vendor": 2,
    "research_doc": 2,      # lab / conference writeups with a DOI or venue
    "industry_guidance": 2, # recognised industry body guidance
    "vendor_docs": 2,       # vendor product documentation
    "vendor_advisory": 1,   # vendor security advisory: normative for that product
    "report": 3,        # disclosed bug reports
    "writeup": 3,       # practitioner writeups
    "blog": 4,
    "dataset": 3,
    "social": 5,        # discovery leads only — never trusted knowledge
}

# Source types that may only ever produce a lead, never a promotion on their own.
DISCOVERY_ONLY = {"social"}

# The research boundary (brief §4). This package has no target-testing code by
# design; the orch/ layer performs active testing when explicitly authorized.
# These flags make the boundary explicit and greppable.
#
# MEASURED DEFECT (fixed): these were `RESEARCH_ONLY = False` and
# `CAN_AUTHORIZE = True`, which contradicted the project's own constitution
# (`AGENTS.md` §5: "The system performs no active testing against any
# target (`config.RESEARCH_ONLY` is `True`); active testing requires explicit
# user-provided authorization") and the quarantine-era copy of the same
# statement at `quarantine/pre-domains-refactor-20261002/.../taxonomy_write.py`.
# The flag had been flipped to describe the ORCH layer's capability while
# living in the WKS package, so a grep for the research boundary reported
# the opposite of what the boundary actually is.
#
# The distinction that matters: `orch/` CAN authorize a hunt (it owns
# `scope_grant`, `AuthorizationContext` and the target-contacting
# executors). `wks/` has no target-contacting code at all — it fetches
# published documents and curates knowledge. So the WKS layer's flags are
# True/False, and the orchestrator's authorization authority is expressed by
# `orch/`'s own scope grants, which is where it belongs.
#
# MEASURED: no runtime code in `wks/`, `orch/`, `scripts/` or
# `learning_engine/` reads either flag. They are a declaration of the layer
# boundary, which is exactly why they must state it correctly.
RESEARCH_ONLY = True
CAN_AUTHORIZE = False
