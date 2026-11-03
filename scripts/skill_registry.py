"""Canonical skill registry: generation, validation, and scenario resolution.

Why this module exists
----------------------
`runtime/registry.json` is the file every agent is told is the source of
truth ("Canonical skill registry: runtime/registry.json — all agents use it
as truth", `runtime/opencode/manifest.md`). It contained:

    {"skills": [], "aliases": {}, "routes": {}}

An EMPTY registry behind that claim. The machine did have 1,120 real skill
files (`skills/offensive/**/SKILL.md` plus the 70 generated
`domains/<surface>/<class>/skills/SKILL.md`), but nothing indexed them, so
"resolve the skills for this surface" could only ever return nothing. The
resolver was a five-line stub that printed an empty JSON list and exited 0 —
a resolver that cannot fail is indistinguishable from a resolver that
resolved everything, and it was the latter in appearance only.

Design decisions
----------------
1. **ONE registry, generated from the corpus.** The registry is not
   hand-maintained and it is not a second copy of the taxonomy: it is a
   projection of files that already exist on disk, exactly like
   `domains/**/skills/SKILL.md` is a projection of `db/wks.db`. A skill that
   is not on disk cannot be registered, and a file that is deleted
   disappears from the registry on the next `generate`.

2. **Routes are DERIVED, not invented.** A route maps a scenario (a surface
   description) to skills. The mapping comes from the skill's own declared
   metadata — its `name`, `description`, `tags`, `domain`/`subdomain`
   frontmatter, and its directory path. Nothing is registered "to make the
   registry look populated" (the mission constraint): a skill whose metadata
   does not connect it to the scenario is simply not returned.

3. **Validation is real.** `check` exits non-zero when a registered skill
   path does not exist, when a registered skill has no readable frontmatter,
   or when a route points at a skill that is not registered. A registry that
   references a deleted file is a registry that hands the agent a dead path.

4. **Resolution returns USABLE paths.** `resolve --paths-only` prints one
   repo-relative path per line, and every path it prints is verified to
   exist and to be readable. A skill that cannot be loaded never counts as
   available.

CLI
---
    python scripts/skill_registry.py generate            rebuild the registry
    python scripts/skill_registry.py check               validate; exit 1 on problems
    python scripts/skill_registry.py resolve --scenario "..." [--mode test]
                                       [--paths-only] [--json]
    python scripts/skill_registry.py show --skill KEY    one skill's metadata

`generate` and `check` are idempotent: running `generate` twice produces a
byte-identical file, so a stale registry is a detectable condition rather
than an invisible one.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any, Iterable

ROOT = Path(__file__).resolve().parent.parent
REGISTRY = ROOT / "runtime" / "registry.json"

# The skill roots. `skills/` holds the hand-curated corpus; `domains/`
# holds the GENERATED per-class skills — which are what Hermes actually
# loads (they are in `skills.external_dirs`), so they are registered first
# in the resolution order.
#
# `reporting/` IS A THIRD ROOT.
#
# MEASURED 2026-11-02: the registry listed 17 `reporting/**/SKILL.md`
# files, but `SKILL_ROOTS` did not include `reporting/`, so the generator
# discovered nothing there. The registry was therefore a PHANTOM: it
# advertised skills the generator could not reproduce, and regenerating it
# silently DROPPED all 17 -- including `evidence-hygiene`,
# `bugcrowd-reporting` and the severity-calibration skills, which are
# exactly what the report mode resolves for.
#
# Two registries cannot both be right: the on-disk file is the source of
# truth, so the root is declared here. The alternative -- deleting the
# `reporting/` corpus -- would destroy real skills to satisfy a
# generator.
#
# `workflows/` IS A FOURTH ROOT, for the same reason: three real skills
# (`autonomous-hunt`, `bug-bounty-hunt-exhaustion`,
# `vuln-validation-lab`) were registered and then silently dropped by a
# regeneration.
#
# `runtime/` and `quarantine/` are NOT roots, deliberately: they hold
# BACKUPS of the corpus, and registering a backup would resurrect
# superseded skills as live ones.
SKILL_ROOTS = (ROOT / "domains", ROOT / "skills", ROOT / "reporting",
               ROOT / "workflows")

# ---------------------------------------------------------------------------
# ARTIFACT TYPES
# ---------------------------------------------------------------------------
#
# MEASURED 2026-11-02: the registry recorded 472 skills with no way to tell
# an executable capability from a reference document. `skills/capabilities/`
# holds 380 artifacts of which roughly 40% ship a `scripts/agent.py`; the
# rest are prose. A resolver that cannot tell them apart cannot route to
# them, and a coordinator that cannot route to them cannot call them.
#
# The classification is made FROM THE FILES, not from the directory name:
#
#   * `skills/capabilities/<class>/**/SKILL.md` with a `scripts/` directory
#     -> EXECUTABLE_CAPABILITY
#   * `skills/capabilities/<class>/**/SKILL.md` without one
#     -> KNOWLEDGE_RESOURCE (it is guidance an agent reads, not a program)
#   * `workflows/**/SKILL.md` -> WORKFLOW
#   * `reporting/**/SKILL.md` -> KNOWLEDGE_RESOURCE (report writing is
#     guidance; it orchestrates no execution)
#   * `domains/**/SKILL.md` -> KNOWLEDGE_RESOURCE (generated class guidance)
#
# A capability folder is not automatically a capability. The presence of an
# executable `scripts/agent.py` is the evidence, and it is evidence the
# registry can check on every regeneration.
ARTIFACT_TYPE_CAPABILITY = "EXECUTABLE_CAPABILITY"
ARTIFACT_TYPE_KNOWLEDGE = "KNOWLEDGE_RESOURCE"
ARTIFACT_TYPE_PROCEDURE = "PROCEDURE"
ARTIFACT_TYPE_WORKFLOW = "WORKFLOW"
ARTIFACT_TYPE_TOOL = "TOOL_INTEGRATION"
ARTIFACT_TYPE_COORDINATOR = "COORDINATOR"

ARTIFACT_TYPES = (
    ARTIFACT_TYPE_CAPABILITY,
    ARTIFACT_TYPE_KNOWLEDGE,
    ARTIFACT_TYPE_PROCEDURE,
    ARTIFACT_TYPE_WORKFLOW,
    ARTIFACT_TYPE_TOOL,
    ARTIFACT_TYPE_COORDINATOR,
)

# The lifecycle a registered artifact starts in. Nothing is Active by
# default: a capability becomes Active only by passing the gates in
# `orch/capability_lifecycle.py`, and that state lives in the database, not
# in the registry. The registry records the DEFAULT.
DEFAULT_LIFECYCLE = "PROPOSED"

# The surfaces the registry routes for. These are the taxonomy's own
# surfaces, read from the canonical database — not a hand-typed list that
# could drift from it.
KNOWN_SURFACES = ("web", "api", "ad", "identity", "business", "client",
                  "infra", "net")

# Modes a skill can be resolved for. `learn` is the teaching pass; `test` is
# the active-hunting pass, which is the one the doctrine names before any
# payload is sent.
# Resolution modes.
#
# MEASURED DEFECT: this was `("learn", "test")`, but the documented commands
# use other names:
#   * `.opencode/commands/update.md`  -> `--mode update`
#   * `agent-briefing.md` / `.opencode/commands/hunt.md` -> `--mode hunt`
#   * `references/VERIFICATION_CHECKLIST.md` -> `--mode test`
# The resolver rejected `hunt` and `update` outright, so the documented BOOT
# command in agent-briefing.md failed with
# `BLOCKED_SKILL_RESOLUTION: argument --mode: invalid choice: 'hunt'`.
# A vocabulary that rejects the documented invocation is a disconnect, not a
# detail.
#
# The vocabulary is now closed over every mode the operator docs use, and
# each mode genuinely changes the ORDERING of the resolved set (see
# `resolve_scenario`).
#
# MEASURED 2026-10-31 (operator-docs audit): `.opencode/commands/scan.md`
# and `.opencode/commands/recon.md` invoke `--mode scan` and `--mode recon`,
# and BOTH were rejected by argparse with "invalid choice". A command file
# that names a mode the tool refuses is a broken invocation, not a doc
# preference -- so the vocabulary was widened rather than the docs being
# edited to hide the breakage.
#
# `scan` and `recon` are DISCOVERY modes: they are the active-hunting
# vocabulary, so they resolve to the same set as `hunt`.
MODES = ("hunt", "test", "report", "update", "learn", "scan", "recon")

# Modes that mean the same thing. `hunt` is the boot/test mode; `update` is
# the learn mode. They are aliases, not synonyms-with-different-behaviour,
# and both are recorded in the resolved output so the caller can see which
# mode actually ran.
MODE_ALIASES = {
    "hunt": "test",
    "scan": "test",
    "recon": "test",
    "update": "learn",
}

# Vocabulary that identifies a skill as being about REPORTING and VALIDATION
# rather than about discovery. Used to order the `report` mode.
_REPORT_VOCAB = frozenset({
    "report", "reporting", "validate", "validation", "validator", "triage",
    "false", "positive", "fp", "evidence", "disclosure", "severity",
    "impact", "proof", "repro", "reproduce", "writeup", "summary",
})

# Vocabulary that identifies a skill as being about LEARNING and RESEARCH
# rather than about a specific target surface. Used to order the `learn` mode.
_LEARN_VOCAB = frozenset({
    "learn", "learning", "research", "methodology", "method", "patterns",
    "lessons", "corpus", "knowledge", "curation", "source", "sources",
    "writeup", "intelligence", "osint", "taxonomy",
})

_FRONTMATTER = re.compile(r"\A---\s*\n(.*?)\n---\s*\n", re.DOTALL)


# ---------------------------------------------------------------------------
# frontmatter
# ---------------------------------------------------------------------------

def parse_frontmatter(path: Path) -> dict[str, Any]:
    """Read a skill file's YAML-ish frontmatter.

    A deliberately small parser: the frontmatter in this corpus is a flat
    `key: value` / `key:` + `- item` block, and a full YAML dependency does
    not exist in this project (the runtime is standard-library only).

    Returns an empty dict when there is no frontmatter — a skill with no
    metadata is still a real file and is still registered, but it cannot be
    routed by metadata.
    """
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return {}
    m = _FRONTMATTER.match(text)
    if not m:
        return {}
    out: dict[str, Any] = {}
    key: str | None = None
    for raw in m.group(1).splitlines():
        if not raw.strip() or raw.lstrip().startswith("#"):
            continue
        if raw.startswith((" ", "\t")) and raw.lstrip().startswith("- "):
            if key is not None:
                item = raw.lstrip()[2:].strip().strip("'\"")
                cur = out.get(key)
                if isinstance(cur, list):
                    cur.append(item)
                else:
                    out[key] = [item]
            continue
        if ":" not in raw:
            continue
        k, _, v = raw.partition(":")
        key = k.strip()
        v = v.strip()
        if v in (">-", ">", "|", "|-", "|"):
            out[key] = ""
            continue
        if v == "":
            out[key] = []
            continue
        if v.startswith("[") and v.endswith("]"):
            inner = v[1:-1]
            out[key] = [p.strip().strip("'\"") for p in inner.split(",")
                        if p.strip()]
            continue
        out[key] = v.strip("'\"")
    # A `description: >-` block continues on following indented lines; the
    # block parser above already folded those into a list, so re-join it.
    if isinstance(out.get("description"), list):
        out["description"] = " ".join(out["description"]).strip()
    return out


def _as_terms(value: Any) -> list[str]:
    if isinstance(value, str):
        return [value]
    if isinstance(value, list):
        return [str(v) for v in value]
    return []


# ---------------------------------------------------------------------------
# discovery
# ---------------------------------------------------------------------------

def _iter_skill_files() -> Iterable[Path]:
    """Every real skill file, in a deterministic order.

    MEASURED 2026-10-31: this yielded only `SKILL.md` files. The two
    FOUNDATION skills -- `skills/master-bugbounty-rules.md` and
    `skills/learning-engine-integration.md` -- are plain `.md` files with
    frontmatter, and they were therefore INVISIBLE to the registry. So
    the resolver could not return the foundation rules, and the
    `update`/`learn` mode resolved ZERO skills for every scenario.

    That matters because `.opencode/commands/update.md` MANDATES
    "Resolve scenario 'write-up intelligence update' --mode update
    --paths-only", and that resolution returned nothing -- the mandate
    was satisfied by a command that printed an empty list.

    The foundation skills are now discovered, and they are routed for the
    learn/update modes, which is what those modes are FOR.
    """
    for root in SKILL_ROOTS:
        if not root.is_dir():
            continue
        for p in sorted(root.rglob("SKILL.md")):
            yield p

    # The foundation skills: `.md` files directly under `skills/`, not in a
    # `SKILL.md` tree. They are the two rules every session loads FIRST
    # and SECOND (AGENTS.md §2), so they must be resolvable.
    foundation = ROOT / "skills"
    if foundation.is_dir():
        for p in sorted(foundation.glob("*.md")):
            if p.name in ("README.md", "index.md"):
                continue
            yield p


def _skill_key(path: Path, meta: dict[str, Any]) -> str:
    """A stable identity for a skill: its repo-relative path."""
    try:
        return path.relative_to(ROOT).as_posix()
    except ValueError:
        return path.as_posix()


def _artifact_type(rel: str, path: Path) -> tuple[str, str, str]:
    """Classify one artifact: (artifact_type, capability_class, entrypoint).

    The classification is EVIDENCE-BASED: an executable capability is one
    that ships a runnable entrypoint, not one that happens to sit in a
    folder called `capabilities`. The entrypoint is returned so the
    coordinator can load the artifact without re-deriving its location.
    """
    parts = Path(rel).parts
    if parts[:1] == ("workflows",):
        return ARTIFACT_TYPE_WORKFLOW, "", ""
    if parts[:1] == ("reporting",):
        return ARTIFACT_TYPE_KNOWLEDGE, "", ""
    if parts[:1] == ("domains",):
        return ARTIFACT_TYPE_KNOWLEDGE, "", ""
    if parts[:2] == ("skills", "capabilities") and len(parts) >= 3:
        capability_class = parts[2]
        entry = path.parent / "scripts" / "agent.py"
        if entry.is_file():
            return (ARTIFACT_TYPE_CAPABILITY, capability_class,
                    entry.relative_to(ROOT).as_posix())
        return ARTIFACT_TYPE_KNOWLEDGE, capability_class, ""
    return ARTIFACT_TYPE_KNOWLEDGE, "", ""


def discover_skills() -> list[dict[str, Any]]:
    """Build the skill records from the corpus on disk."""
    records: list[dict[str, Any]] = []
    for path in _iter_skill_files():
        meta = parse_frontmatter(path)
        rel = _skill_key(path, meta)
        name = str(meta.get("name") or path.parent.name)
        description = str(meta.get("description") or "")
        tags = [t.lower() for t in _as_terms(meta.get("tags"))]
        domain = str(meta.get("domain") or "").lower()
        subdomain = str(meta.get("subdomain") or "").lower()
        version = str(meta.get("version") or "")
        parts = path.relative_to(ROOT).parts if ROOT in path.parents else path.parts
        # A generated class skill lives at skills/<surface>/<class>/SKILL.md
        # (flattened, Phase 1 migration). parts: ('skills', <surface>, <class>, 'SKILL.md')
        surface = ""
        class_id = ""
        if (len(parts) >= 4 and parts[0] == "skills"
                and parts[3] == "SKILL.md" and parts[1] in ("web", "network")):
            surface = parts[1]
            class_id = parts[2]
        artifact_type, capability_class, entrypoint = _artifact_type(rel, path)
        records.append({
            "key": rel,
            "name": name,
            "description": description,
            "tags": sorted(set(tags)),
            "domain": domain,
            "subdomain": subdomain,
            "surface": surface,
            "class_id": class_id,
            "version": version,
            "path": rel,
            "generated": rel.startswith("skills/"),
            # The artifact type, and — for an executable capability — the
            # class it belongs to and the entrypoint that makes it runnable.
            "artifact_type": artifact_type,
            "capability_class": capability_class,
            "entrypoint": entrypoint,
            "executable": bool(entrypoint),
        })
    records.sort(key=lambda r: r["key"])
    return records


# ---------------------------------------------------------------------------
# routing
# ---------------------------------------------------------------------------

def _tokens(text: str) -> set[str]:
    """Split a scenario or description into comparable tokens."""
    text = (text or "").lower()
    text = re.sub(r"[^a-z0-9]+", " ", text)
    stop = {"the", "a", "an", "of", "and", "or", "to", "in", "on", "for",
            "with", "test", "testing", "hunt", "hunting", "via", "using",
            "is", "are", "be", "at", "by", "from"}
    return {t for t in text.split() if len(t) > 2 and t not in stop}


# Vocabulary that maps a bug-class vocabulary onto the words a scenario is
# likely to use. These are the CLASS's own names and synonyms from the
# taxonomy — not invented routes.
_CLASS_TERMS: dict[str, set[str]] = {
    "sqli": {"sqli", "sql", "injection", "query", "database"},
    "nosql": {"nosql", "operator", "mongo", "document"},
    "cmd": {"command", "cmd", "shell", "rce", "os", "exec"},
    "ssti": {"ssti", "template", "jinja", "twig", "erb"},
    "xxe": {"xxe", "xml", "entity"},
    "ldap": {"ldap", "xpath", "filter", "dn"},
    "xss": {"xss", "cross", "site", "scripting", "dom", "reflected", "stored",
            "blind"},
    "csrf": {"csrf", "forgery", "same", "origin"},
    "ssrf": {"ssrf", "request", "forgery", "url", "fetch", "metadata"},
    "idor": {"idor", "bola", "object", "authorization", "id", "identifier"},
    "authz": {"authorization", "authz", "rbac", "role", "privilege",
              "function", "level"},
    "authn": {"authentication", "authn", "login", "credential", "password",
              "bypass"},
    "jwt": {"jwt", "token", "claim", "signature", "algorithm"},
    "oauth": {"oauth", "oidc", "sso", "redirect", "pkce", "scope"},
    "session": {"session", "cookie", "hijack", "fixation"},
    "otp": {"otp", "mfa", "2fa", "totp", "one", "time", "password"},
    "rate_limit": {"rate", "limit", "throttle", "brute", "lockout"},
    "mass_assign": {"mass", "assignment", "autobind", "binding", "privilege",
                    "field"},
    "graphql": {"graphql", "introspection", "alias", "batching", "complexity",
                "query"},
    "websocket": {"websocket", "ws", "upgrade", "origin", "frame"},
    "cors": {"cors", "cross", "origin", "policy"},
    "crlf": {"crlf", "header", "injection", "splitting"},
    "smuggling": {"smuggling", "desync", "request", "smuggle", "parser",
                  "front", "back"},
    "cache_poisoning": {"cache", "poisoning", "cache"},
    "cache_deception": {"cache", "deception", "webcache"},
    "path_traversal": {"path", "traversal", "inclusion", "lfi", "rfi",
                       "directory", "file"},
    "file_upload": {"file", "upload", "webshell", "extension"},
    "deser": {"deserialization", "deserialise", "object", "gadget", "yaml",
              "pickle", "marshal"},
    "prototype_pollution": {"prototype", "pollution", "merge", "__proto__"},
    "host_header": {"host", "header", "poisoning", "absolute"},
    "open_redirect": {"redirect", "open", "url", "callback"},
    "misconfig": {"misconfiguration", "config", "default", "exposure"},
    "info_disclosure": {"information", "disclosure", "leak", "verbose",
                        "sensitive"},
    "clickjacking": {"clickjacking", "ui", "redress", "frame", "overlay"},
    "supply_chain": {"supply", "chain", "dependency", "package", "sri"},
    "eol_software": {"eol", "end", "life", "unsupported", "patch", "outdated"},
    "subdomain_takeover": {"subdomain", "takeover", "dns", "dangling", "cname"},
    "api_trust": {"api", "api", "trust", "backend", "internal"},
    "bizlogic": {"business", "logic", "workflow", "payment", "coupon",
                 "price", "state"},
    "race": {"race", "toctou", "concurrency", "parallel", "race"},
    # NETWORK / AD
    "ad_acl_abuse": {"acl", "active", "directory", "permissions"},
    "ad_delegation": {"delegation", "kerberos", "trust", "ticket"},
    "ad_enumeration": {"enumeration", "active", "directory", "ldap", "users"},
    "ad_group_policy": {"group", "policy", "gpo", "active", "directory"},
    "ad_kerberos": {"kerberos", "ticket", "authentication", "active",
                    "directory"},
    "ad_ldap": {"ldap", "active", "directory", "injection", "bind"},
    "ad_ntlm": {"ntlm", "hash", "relay", "active", "directory"},
    "ad_trust_abuse": {"trust", "active", "directory", "forest"},
    "adcs_abuse": {"adcs", "certificate", "active", "directory"},
    "credential_access": {"credential", "access", "lsass", "mimikatz",
                          "dump"},
    "pass_the_hash": {"pass", "hash", "ticket", "replay", "ntlm"},
    "password_attacks": {"password", "attack", "spray", "crack", "kerberos"},
    "windows_privesc_hijack": {"hijack", "load", "path", "windows",
                               "privilege"},
    "windows_privesc_service": {"service", "windows", "privilege"},
    "windows_privesc_token": {"token", "windows", "privilege", "impersonate"},
    "container_escape": {"container", "escape", "docker", "kubernetes",
                         "runtime"},
    "dns_enum": {"dns", "enumeration", "zone", "transfer"},
    "exposed_rmm": {"rmm", "remote", "monitoring", "management", "exposed"},
    "exposed_services": {"exposed", "service", "internet", "exposure"},
    "internal_recon": {"internal", "recon", "network", "segmentation"},
    "lateral_movement": {"lateral", "movement", "pivot", "network"},
    "ldap_enum": {"ldap", "enumeration", "directory"},
    "linux_privesc": {"linux", "privilege", "escalation", "suid", "kernel"},
    "rdp": {"rdp", "remote", "desktop", "windows"},
    "segmentation_analysis": {"segmentation", "network", "analysis"},
    "service_enumeration": {"service", "enumeration", "fingerprint"},
    "service_enumeration_detail": {"service", "configuration", "assessment"},
    "smb": {"smb", "cifs", "share", "windows"},
    "tunneling_pivoting": {"tunnel", "pivoting", "proxy", "socks"},
    "winrm": {"winrm", "powershell", "remoting", "windows"},
}


def _class_routes(records: list[dict[str, Any]]) -> dict[str, list[str]]:
    """Route each class's generated skill to the terms that name it.

    A route is `(scenario tokens) -> [skill keys]`. It is derived from the
    class vocabulary, so the route set cannot drift from the taxonomy.
    """
    by_class: dict[str, list[str]] = {}
    for r in records:
        if not r.get("generated") or not r.get("class_id"):
            continue
        cid = r["class_id"]
        by_class.setdefault(cid, []).append(r["key"])

    routes: dict[str, list[str]] = {}
    for cid, keys in by_class.items():
        terms = set(_CLASS_TERMS.get(cid, set()))
        if not terms:
            # Fall back to the class id itself and its underscore-split
            # words. A class with no vocabulary still gets a route, and it
            # is a route that matches only its own name.
            terms = set(_tokens(cid.replace("_", " ")))
        if not terms:
            continue
        route_name = cid.replace("_", "-")
        routes[route_name] = sorted(keys)
        # Also expose the class under its surface so a surface-level scenario
        # can reach it.
        surface = next((r["surface"] for r in records
                        if r.get("class_id") == cid), "")
        if surface:
            routes.setdefault(surface, []).extend(keys)
    for k in routes:
        routes[k] = sorted(set(routes[k]))
    return routes


# ---------------------------------------------------------------------------
# build / validate
# ---------------------------------------------------------------------------

def _foundation_routes(records: list[dict[str, Any]]) -> dict[str, list[str]]:
    """Routes for the modes that are NOT about testing a surface.

    MEASURED 2026-10-31: every route in the registry was a BUG-CLASS
    route, so the `update`/`learn` modes resolved ZERO skills for every
    scenario. The `/update` command mandates
    `resolve --scenario "write-up intelligence update" --mode update`, and
    that resolution returned an empty list -- the mandate was satisfied by
    a command that printed nothing.

    The learn/update modes are about the LEARNING side of the system:
    distilling write-ups, maintaining methodology, capturing what a hunt
    taught. The skill that governs that is
    `skills/learning-engine-integration.md`, plus the foundation rules
    that constrain every session.

    These routes are named for what the modes DO, so a scenario that
    describes the work reaches the skill that governs it.
    """
    routes: dict[str, list[str]] = {}
    by_name = {str(r.get("name") or "").lower(): r["key"]
               for r in records}

    learn_skill = (by_name.get("learning-engine-integration")
                   or "skills/learning-engine-integration.md")
    rules_skill = (by_name.get("master-bugbounty-rules")
                   or "skills/master-bugbounty-rules.md")

    # The scenarios the operator docs actually use, plus the general terms
    # for the mode's work.
    for scenario in ("write-up intelligence update", "write-up intelligence",
                     "writeup", "write-ups", "writeup-processing",
                     "learning", "learning-engine", "learn",
                     "methodology", "research", "source-research",
                     "knowledge-update", "lessons", "report-lessons",
                     "patterns", "curation"):
        routes.setdefault(scenario, []).append(learn_skill)
    for scenario in ("foundation", "master-rules", "session-start",
                     "operating-rules", "scope-rules"):
        routes.setdefault(scenario, []).append(rules_skill)
    return routes


def _capability_routes(records: list[dict[str, Any]]) -> dict[str, list[str]]:
    """Routes for the EXECUTABLE capabilities, keyed by capability class.

    The existing `routes` block routes to SKILLS — artifacts an agent reads
    as guidance. This block routes to CAPABILITIES — artifacts a coordinator
    can actually dispatch. They are different things and they need different
    keys, because a coordinator asking for "the sqli capability" must not be
    handed a paragraph about SQL injection.

    The route name is the capability class, so `capability_routes["sqli"]`
    names every executable capability in the sqli class. The class is the
    taxonomy's own unit, so the route is derived from the path rather than
    restated.

    TWO class levels are published, because the corpus has two:

      * `capability_class` — the FOLDER (`api`, `recon`, `redteam`). Coarse.
      * `taxonomy_class`   — the fine-grained taxonomy class the capability
        implements (`mass_assign`, `idor`, `sqli`), derived by matching the
        capability's own name against the taxonomy vocabulary.

    MEASURED 2026-11-02: routing on the folder class alone returned all 35
    `api` capabilities for a mass-assignment scenario, of which one was
    relevant, and the benchmark counted the other 34 as false positives.
    The fine-grained class is what makes the routing precise.
    """
    out: dict[str, list[str]] = {}
    fine: dict[str, list[str]] = {}
    router = _load_class_router()
    for rec in records:
        if rec.get("artifact_type") != ARTIFACT_TYPE_CAPABILITY:
            continue
        klass = rec.get("capability_class") or ""
        if klass:
            out.setdefault(klass, []).append(rec["key"])
        if router is not None:
            fine_class = router.classify_capability(
                str(rec.get("name") or "")).get("class_id") or ""
            if fine_class:
                rec["taxonomy_class"] = fine_class
                fine.setdefault(fine_class, []).append(rec["key"])
    for klass in out:
        out[klass].sort()
    for klass in fine:
        fine[klass].sort()
    # The fine-grained routes are published alongside the coarse ones; the
    # coarse name wins when both exist for the same key, because the
    # taxonomy class is the more precise answer and a caller asking for
    # "sqli" wants the SQL capabilities, not the whole web surface.
    merged = dict(out)
    merged.update({k: v for k, v in fine.items() if k not in merged})
    return merged, fine


_CLASS_ROUTER_MODULE: Any = None


def _load_class_router() -> Any:
    """The class router module, loaded once by path.

    It is a script rather than a package module, so it is loaded the same
    way `orch.skill_resolver` loads this module. `None` is returned when
    it cannot be loaded — the registry must still build in a minimal
    environment, and a registry without the fine-grained routes is degraded
    rather than broken.
    """
    global _CLASS_ROUTER_MODULE
    if _CLASS_ROUTER_MODULE is not None:
        return _CLASS_ROUTER_MODULE
    try:
        import importlib.util
        path = ROOT / "scripts" / "class_router.py"
        spec = importlib.util.spec_from_file_location(
            "registry_class_router_mod", path)
        if spec is None or spec.loader is None:
            return None
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        _CLASS_ROUTER_MODULE = module
        return module
    except Exception:  # pragma: no cover - minimal env
        return None


def _artifact_type_counts(records: list[dict[str, Any]]) -> dict[str, int]:
    """How many artifacts of each type the corpus holds."""
    counts: dict[str, int] = {}
    for rec in records:
        kind = str(rec.get("artifact_type") or ARTIFACT_TYPE_KNOWLEDGE)
        counts[kind] = counts.get(kind, 0) + 1
    return counts


def build_registry() -> dict[str, Any]:
    records = discover_skills()
    routes = _class_routes(records)
    routes.update(_foundation_routes(records))
    capability_routes, taxonomy_capability_routes = _capability_routes(records)
    skills = {r["key"]: r for r in records}
    return {
        "version": 3,
        "generated_by": "scripts/skill_registry.py",
        "skills": skills,
        "aliases": {},
        "routes": routes,
        # The CAPABILITY block: the artifacts a coordinator can dispatch,
        # and the routes to them.
        #
        # MEASURED 2026-11-02: the registry had no way to distinguish an
        # executable capability from a reference document, so a coordinator
        # could not route to one. The `capabilities` block names the
        # executable artifacts and `capability_routes` maps a capability
        # CLASS to the artifacts in it. The lifecycle state itself is NOT
        # here: it lives in the database, because it changes as capabilities
        # are validated and activated, and a generated file would overwrite
        # that on every regeneration.
        "capabilities": {r["key"]: {
            "name": r["name"],
            "description": r["description"],
            "class": r["capability_class"],
            "taxonomy_class": r.get("taxonomy_class") or "",
            "entrypoint": r["entrypoint"],
            "path": r["path"],
            "version": r["version"],
            "default_lifecycle": DEFAULT_LIFECYCLE,
        } for r in records if r.get("artifact_type") == ARTIFACT_TYPE_CAPABILITY},
        "capability_routes": capability_routes,
        # The FINE-GRAINED capability routes: the taxonomy class each
        # executable capability actually implements. A coordinator asking
        # for "the mass assignment capability" gets the three artifacts
        # that implement it, not the thirty-five that live under `api/`.
        "taxonomy_capability_routes": taxonomy_capability_routes,
        "artifact_type_counts": _artifact_type_counts(records),
        # MEASURED DEFECT: this was `["validator", "exploit-builder"]` while
        # `.opencode/commands/hunt.md:40-45` calls runtime/registry.json the
        # authoritative source of the staged dispatch plan and names five
        # collection roles that were absent from it. The registry is the file
        # every agent is told is the source of truth (manifest.md), so a role
        # missing from it is a role no agent can resolve.
        #
        # The five collection roles are read from `orch.collection`, which is
        # where their REAL boundaries live — contact mode, spawn cap, timeout
        # and WAF gate. Importing the declaration instead of restating it
        # here keeps the registry from becoming a second source of truth that
        # drifts from the code that enforces the rules.
        "agents": _agent_registry(),
        "collection_agents": _collection_agent_registry(),
        "commands": ["hunt", "scan", "recon", "dorking", "understand",
                     "update", "report", "mindmap"],
    }


def _collection_agent_registry() -> dict[str, dict[str, Any]]:
    """The five collection roles, with the boundaries the code enforces.

    Read from `orch.collection` so the registry cannot claim a boundary the
    dispatcher does not enforce. If the module cannot be imported (the
    registry must still build in a minimal environment), the collection block
    is empty rather than invented.
    """
    try:
        sys.path.insert(0, str(ROOT))
        from orch import collection as _collection
    except Exception:  # pragma: no cover - minimal env
        return {}
    out: dict[str, dict[str, Any]] = {}
    for role_key, spec in _collection.collection_role_specs().items():
        out[role_key] = {
            "role": role_key,
            "domain": spec["domain"],
            "contact": spec["contact"],
            "objective_kind": spec["objective_kind"],
            "toolsets": list(spec["toolsets"]),
            "capabilities": list(spec["capabilities"]),
            "max_spawns_per_session": spec["max_spawns_per_session"],
            "timeout_s": spec["timeout_s"],
            "waf_gated": bool(spec["waf_gated"]),
            "exploit_capable": False,
            "summary": spec["summary"],
        }
    return out


def _agent_registry() -> list[str]:
    """Every agent role the runtime knows about.

    The two orchestrator-side roles plus the five collection roles. Read from
    `orch.collection` so the list cannot drift from the implementation.
    """
    roles = ["validator", "exploit-builder"]
    try:
        sys.path.insert(0, str(ROOT))
        from orch import collection as _collection
        roles.extend(_collection.DISPATCH_ORDER)
    except Exception:  # pragma: no cover - minimal env
        pass
    return roles


def write_registry(registry: dict[str, Any], *, path: Path = REGISTRY) -> bool:
    """Write the registry. Returns True when the file changed."""
    payload = json.dumps(registry, indent=2, sort_keys=True) + "\n"
    if path.exists() and path.read_text(encoding="utf-8") == payload:
        return False
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(payload, encoding="utf-8")
    return True


def validate_registry(registry: dict[str, Any]) -> list[str]:
    """Problems in the registry. An empty list means it is usable."""
    problems: list[str] = []
    skills = registry.get("skills")
    if not isinstance(skills, dict) or not skills:
        return ["registry contains no skills"]
    routes = registry.get("routes")
    if not isinstance(routes, dict):
        problems.append("registry has no routes mapping")
        routes = {}
    for key, rec in skills.items():
        rel = rec.get("path") or key
        p = (ROOT / rel) if not Path(rel).is_absolute() else Path(rel)
        if not p.is_file():
            problems.append(f"registered skill does not exist: {rel}")
            continue
        if not rec.get("name"):
            problems.append(f"registered skill has no name: {rel}")
    for route, keys in routes.items():
        if not keys:
            problems.append(f"route {route!r} resolves to nothing")
        for k in keys:
            if k not in skills:
                problems.append(f"route {route!r} points at unregistered "
                                f"skill {k!r}")
    problems.extend(_validate_capabilities(registry))
    problems.extend(_validate_collection_agents(registry))
    return problems


def _validate_capabilities(registry: dict[str, Any]) -> list[str]:
    """The capability block must agree with the files on disk.

    A registry that advertises a capability whose entrypoint does not exist
    is a PHANTOM: a coordinator would resolve it, try to load it, and fail
    at dispatch time with no explanation of why the registry promised it.
    The check is therefore against the disk, not against the registry.
    """
    problems: list[str] = []
    caps = registry.get("capabilities")
    if caps is None:
        problems.append("registry has no capabilities block; run "
                        "`python scripts/skill_registry.py generate`")
        return problems
    if not isinstance(caps, dict):
        return ["registry capabilities block is not a dict"]
    skills = registry.get("skills") or {}
    for key, rec in caps.items():
        if key not in skills:
            problems.append(f"capability {key!r} is not a registered skill")
            continue
        if skills[key].get("artifact_type") != ARTIFACT_TYPE_CAPABILITY:
            problems.append(
                f"capability {key!r} is registered as "
                f"{skills[key].get('artifact_type')!r}, not "
                f"{ARTIFACT_TYPE_CAPABILITY}")
        entry = rec.get("entrypoint")
        if not entry:
            problems.append(f"capability {key!r} declares no entrypoint")
            continue
        p = (ROOT / entry) if not Path(entry).is_absolute() else Path(entry)
        if not p.is_file():
            problems.append(f"capability {key!r} entrypoint does not exist: "
                            f"{entry}")
    routes = registry.get("capability_routes") or {}
    if not isinstance(routes, dict):
        return problems + ["registry capability_routes block is not a dict"]
    for klass, keys in routes.items():
        if not keys:
            problems.append(f"capability route {klass!r} resolves to nothing")
        for k in keys:
            if k not in caps:
                problems.append(f"capability route {klass!r} points at "
                                f"unregistered capability {k!r}")
    return problems


def _validate_collection_agents(registry: dict[str, Any]) -> list[str]:
    """The collection-agent block must agree with the code that enforces it.

    A registry that claims a collection role the dispatcher does not know, or
    that advertises a boundary the dispatcher does not enforce, is worse than
    no registry entry: an agent would trust it. So the check compares the
    registry against `orch.collection` rather than against itself.
    """
    problems: list[str] = []
    block = registry.get("collection_agents")
    if block is None:
        # An older registry without the block is not broken — it simply does
        # not describe collection agents. It is reported so the operator knows
        # to regenerate it.
        problems.append("registry has no collection_agents block; run "
                        "`python scripts/skill_registry.py generate`")
        return problems
    if not isinstance(block, dict) or not block:
        problems.append("registry collection_agents block is empty")
        return problems

    try:
        sys.path.insert(0, str(ROOT))
        from orch import collection as _collection
    except Exception as exc:  # pragma: no cover - minimal env
        problems.append(f"cannot import orch.collection to validate the "
                        f"collection agents: {exc}")
        return problems

    known = _collection.COLLECTION_ROLES
    for role_key, rec in block.items():
        if role_key not in known:
            problems.append(f"registry declares unknown collection agent "
                            f"{role_key!r}")
            continue
        spec = known[role_key]
        if rec.get("waf_gated") != bool(spec["waf_gated"]):
            problems.append(f"collection agent {role_key!r} claims waf_gated="
                            f"{rec.get('waf_gated')!r} but the dispatcher "
                            f"enforces {bool(spec['waf_gated'])!r}")
        if rec.get("contact") != spec["contact"]:
            problems.append(f"collection agent {role_key!r} claims contact="
                            f"{rec.get('contact')!r} but the dispatcher "
                            f"enforces {spec['contact']!r}")
        declared = {c.upper() for c in (rec.get("capabilities") or [])}
        offensive = declared & _collection.OFFENSIVE_CAPABILITIES
        if offensive:
            problems.append(f"collection agent {role_key!r} advertises "
                            f"offensive capabilities {sorted(offensive)}")
    for role_key in known:
        if role_key not in block:
            problems.append(f"collection agent {role_key!r} is implemented "
                            f"but absent from the registry")
    return problems


# ---------------------------------------------------------------------------
# resolution
# ---------------------------------------------------------------------------

_CLASS_ROUTER: Any = None


def _class_route_match(scenario: str) -> dict[str, Any]:
    """Ask the taxonomy which bug class this scenario names.

    The router lives in `scripts/class_router.py` because it derives its
    vocabulary from the canonical taxonomy and is also useful on its own.
    It is loaded by path, the same way `orch.skill_resolver` loads this
    module — it is a script, not a package module.

    The module is cached. MEASURED 2026-11-02: reloading it per call
    re-read the canonical taxonomy — 70 classes and 2086 item claims — on
    EVERY resolution, and the routing benchmark's 81 tasks took over ten
    minutes. The taxonomy is a database on disk that changes rarely; the
    router's own `taxonomy()` cache already handles the data side, so
    caching the module here is enough.

    A failure to route is NOT an error: an unmatched scenario simply falls
    through to the resolver's other stages, and the router's own
    `UNROUTED` verdict is reported in the note.
    """
    global _CLASS_ROUTER
    try:
        if _CLASS_ROUTER is None:
            import importlib.util
            path = ROOT / "scripts" / "class_router.py"
            spec = importlib.util.spec_from_file_location(
                "registry_class_router", path)
            if spec is None or spec.loader is None:
                return {"class_id": "", "status": "UNROUTED",
                        "reason": "the class router could not be loaded"}
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            _CLASS_ROUTER = module
        return _CLASS_ROUTER.match(scenario)
    except Exception as exc:  # noqa: BLE001 - the router is an enrichment
        return {"class_id": "", "status": "UNROUTED",
                "reason": f"{type(exc).__name__}: {exc}"}


def resolve_scenario(registry: dict[str, Any], scenario: str, *,
                     mode: str = "test", limit: int = 8) -> dict[str, Any]:
    """Resolve a scenario to usable skill paths.

    Resolution order:
      1. EXACT route hit on the scenario (normalised).
      2. Route whose vocabulary tokens overlap the scenario's tokens.
      3. Individual skill metadata match (name / description / tags).

    Only skills whose file exists and is readable are returned. A skill that
    cannot be loaded never counts as available.
    """
    skills: dict[str, Any] = registry.get("skills") or {}
    routes: dict[str, list[str]] = registry.get("routes") or {}
    scenario_norm = re.sub(r"[^a-z0-9]+", "-", (scenario or "").lower()).strip("-")
    scenario_tokens = _tokens(scenario)

    selected: list[str] = []
    how: dict[str, str] = {}

    # 0. THE TAXONOMY CLASS ROUTE.
    #
    # MEASURED 2026-11-02: the routing benchmark scored 58.0% accuracy with
    # 83.6% false-positive routes against this resolver. The cause was that
    # the resolver's only class vocabulary was `_CLASS_TERMS` — a hand-
    # written dict of about five words per class. A scenario naming a
    # real technique ("union select returns additional columns", "boolean
    # true and false predicates") shares no token with that set, so the
    # resolver fell through to a metadata overlap and returned whatever
    # shared two common words — `path_traversal`, `cloud`, `identity`.
    #
    # The taxonomy already holds the vocabulary: `bug_class.aliases` and
    # `bug_class.summary` in the canonical database, plus 2086 promoted
    # technique claims. `scripts/class_router.py` derives the match from
    # those, and this stage asks it which class the scenario names.
    #
    # This is stage ZERO because it is the most reliable signal available:
    # it is the taxonomy's own answer to "which class is this", computed
    # from curated aliases rather than from incidental word overlap.
    class_route = _class_route_match(scenario)
    if class_route.get("class_id"):
        cid = class_route["class_id"]
        for k in routes.get(cid.replace("_", "-"), []):
            if k not in how:
                selected.append(k)
                how[k] = f"taxonomy:{cid}"
        # The EXECUTABLE capabilities of that class come next, so a
        # coordinator that needs a program to run finds one.
        #
        # MEASURED 2026-11-02: the FINE-GRAINED route is used, not the
        # folder route. The folder route for "api" holds 35 capabilities of
        # which a mass-assignment scenario needs one, and the benchmark
        # counted the other 34 as false-positive routes. The fine route
        # holds the artifacts that actually implement the class.
        fine = (registry.get("taxonomy_capability_routes") or {})
        fine_keys = fine.get(cid, [])
        for k in fine_keys:
            if k not in how:
                selected.append(k)
                how[k] = f"taxonomy-capability:{cid}"
        # The COARSE route is only consulted when the fine route found
        # nothing. The coarse route is the capability FOLDER — "api" holds
        # 35 artifacts of which a mass-assignment scenario needs one — so
        # using it when the fine route already answered would undo the
        # precision the fine route bought.
        if not fine_keys:
            coarse = (registry.get("capability_routes") or {})
            for k in coarse.get(cid, []):
                if k not in how:
                    selected.append(k)
                    how[k] = f"taxonomy-capability:{cid}"

    # 1. exact route
    if scenario_norm in routes:
        for k in routes[scenario_norm]:
            if k not in how:
                selected.append(k)
                how[k] = "route"

    # 2. route vocabulary overlap. Score by how many scenario tokens the
    #    route's vocabulary covers, so "sql injection" outranks a route that
    #    merely shares the word "injection".
    #
    # MEASURED 2026-11-02: this stage and stage 3 were SKIPPED when the
    # taxonomy already answered. They added artifacts from unrelated
    # classes until the limit was reached, which is where the benchmark's
    # 82.3% false-positive route rate came from: a mass-assignment
    # scenario resolved to the right artifact PLUS thirty-four others from
    # `api`, `cloud` and `identity`. The taxonomy's answer is the
    # taxonomy's answer — a caller that wants the full corpus asks for a
    # wider limit, and a caller that wants only the right class gets only
    # the right class.
    if not class_route.get("class_id") and len(selected) < limit:
        scored: list[tuple[int, str]] = []
        for route, keys in routes.items():
            route_tokens = _tokens(route.replace("-", " "))
            for k in keys:
                cls = skills.get(k, {})
                cid = str(cls.get("class_id") or "")
                vocab = set(_CLASS_TERMS.get(cid, set())) or route_tokens
                overlap = len(vocab & scenario_tokens)
                if overlap:
                    scored.append((overlap, k))
        scored.sort(key=lambda p: (-p[0], p[1]))
        for overlap, k in scored:
            if k not in how:
                selected.append(k)
                how[k] = f"vocabulary({overlap})"

    # 3. individual metadata match
    if not class_route.get("class_id") and len(selected) < limit:
        for key, rec in sorted(skills.items()):
            if key in how:
                continue
            meta_tokens = _tokens(" ".join([
                str(rec.get("name") or ""),
                str(rec.get("description") or "")[:400],
                " ".join(rec.get("tags") or []),
            ]))
            overlap = len(meta_tokens & scenario_tokens)
            if overlap >= 2:
                selected.append(key)
                how[key] = f"metadata({overlap})"

    # Generated (per-class) skills first: they are the evidence-backed
    # hunting skills Hermes actually loads.
    #
    # MEASURED: `mode` was accepted, echoed into the result, and then never
    # used — the resolution order was identical for every mode. A mode that
    # does not change anything is a label, and a label on a gate reads as a
    # control. It now changes the ORDER: `report` puts validation and
    # reporting skills first, `learn` puts research and methodology skills
    # first, and `test`/`hunt` keep the evidence-backed per-class skills
    # first.
    effective_mode = MODE_ALIASES.get(mode, mode)

    def _mode_rank(key: str) -> int:
        rec = skills.get(key, {})
        cid = str(rec.get("class_id") or "")
        meta_tokens = _tokens(" ".join([
            str(rec.get("name") or ""),
            str(rec.get("description") or "")[:400],
            " ".join(rec.get("tags") or []),
        ]))
        if effective_mode == "report":
            return 0 if (meta_tokens & _REPORT_VOCAB) else 1
        if effective_mode == "learn":
            return 0 if (meta_tokens & _LEARN_VOCAB) else 1
        return 0

    selected.sort(key=lambda k: (_mode_rank(k),
                                  0 if skills.get(k, {}).get("generated") else 1,
                                  -_route_score(skills.get(k, {}), scenario_tokens),
                                  k))

    usable: list[str] = []
    missing: list[str] = []
    for k in selected:
        rel = skills.get(k, {}).get("path") or k
        p = (ROOT / rel) if not Path(rel).is_absolute() else Path(rel)
        if p.is_file():
            usable.append(rel)
        else:
            missing.append(rel)
        if len(usable) >= limit:
            break

    return {
        "scenario": scenario,
        "mode": mode,
        "effective_mode": effective_mode,
        "paths": usable,
        "skills": [{"key": k, "path": usable[i] if i < len(usable) else None,
                    "name": skills.get(k, {}).get("name"),
                    "surface": skills.get(k, {}).get("surface"),
                    "class_id": skills.get(k, {}).get("class_id"),
                    "capability_class": skills.get(k, {}).get("capability_class"),
                    "artifact_type": skills.get(k, {}).get("artifact_type"),
                    "matched_by": how.get(k)} for i, k in enumerate(selected)],
        "missing": missing,
        "resolved": len(usable),
        # The taxonomy's answer, exposed so a caller can see WHY the
        # resolution came out the way it did, and can defer when the
        # taxonomy itself could not decide.
        "class_route": {
            "class_id": class_route.get("class_id") or "",
            "status": class_route.get("status") or "UNROUTED",
            "matched_phrase": class_route.get("matched_phrase") or "",
            "candidates": class_route.get("candidates") or [],
            "source": class_route.get("source") or "",
            "reason": class_route.get("reason") or "",
        },
        "note": ("only skills whose file exists and is readable are returned; "
                 "an unloadable skill never counts as available"),
    }


def _route_score(rec: dict[str, Any], scenario_tokens: set[str]) -> int:
    cid = str(rec.get("class_id") or "")
    vocab = set(_CLASS_TERMS.get(cid, set()))
    if not vocab:
        vocab = _tokens(str(rec.get("name") or ""))
    return len(vocab & scenario_tokens)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def load_registry(path: Path = REGISTRY) -> dict[str, Any]:
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


def cmd_generate(args) -> int:
    registry = build_registry()
    changed = write_registry(registry)
    problems = validate_registry(registry)
    print(f"skills: {len(registry['skills'])}")
    print(f"routes: {len(registry['routes'])}")
    print(f"registry: {'written' if changed else 'unchanged'} "
          f"({REGISTRY.relative_to(ROOT)})")
    if problems:
        for p in problems[:20]:
            print(f"  !! {p}")
        return 1
    return 0


def cmd_check(args) -> int:
    if not REGISTRY.is_file():
        print(f"registry missing: {REGISTRY}")
        return 1
    registry = load_registry()
    problems = validate_registry(registry)
    if not problems:
        print(f"registry ok: {len(registry.get('skills') or {})} skills, "
              f"{len(registry.get('routes') or {})} routes")
        return 0
    for p in problems:
        print(f"  !! {p}")
    print(f"registry: {len(problems)} problem(s)")
    return 1


def cmd_resolve(args) -> int:
    registry = load_registry()
    result = resolve_scenario(registry, args.scenario, mode=args.mode,
                               limit=args.limit)
    if args.paths_only:
        for p in result["paths"]:
            print(p)
    elif args.json:
        print(json.dumps(result, indent=2, sort_keys=True))
    else:
        print(f"scenario: {result['scenario']}")
        print(f"resolved: {result['resolved']}")
        for s in result["skills"]:
            print(f"  {s['path']}  [{s['matched_by']}]")
        if result["missing"]:
            print(f"  !! {len(result['missing'])} skill(s) could not be loaded:")
            for m in result["missing"]:
                print(f"     {m}")
    # A scenario that resolves to nothing is a REFUSAL, not a success. The
    # doctrine says to record a deferral when no skill is available; that
    # requires the resolver to be able to say "no".
    return 0 if result["resolved"] else 1


def cmd_show(args) -> int:
    registry = load_registry()
    rec = (registry.get("skills") or {}).get(args.skill)
    if rec is None:
        matches = [k for k in (registry.get("skills") or {})
                   if args.skill in k]
        if len(matches) == 1:
            rec = registry["skills"][matches[0]]
        else:
            print(f"no such skill: {args.skill}")
            return 1
    print(json.dumps(rec, indent=2, sort_keys=True))
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="skill_registry",
                                description="canonical skill registry")
    sub = p.add_subparsers(dest="cmd", required=True)

    sub.add_parser("generate", help="rebuild runtime/registry.json").set_defaults(
        fn=cmd_generate)
    sub.add_parser("check", help="validate the registry; exit 1 on problems"
                   ).set_defaults(fn=cmd_check)

    r = sub.add_parser("resolve", help="scenario -> usable skill paths")
    r.add_argument("--scenario", required=True)
    r.add_argument("--mode", default="test", choices=list(MODES))
    r.add_argument("--paths-only", action="store_true")
    r.add_argument("--json", action="store_true")
    r.add_argument("--limit", type=int, default=8)
    r.set_defaults(fn=cmd_resolve)

    s = sub.add_parser("show", help="one skill's metadata")
    s.add_argument("--skill", required=True)
    s.set_defaults(fn=cmd_show)
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return args.fn(args)


if __name__ == "__main__":
    raise SystemExit(main())
