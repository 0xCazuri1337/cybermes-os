"""SKILL RESOLUTION FOR A LIVE HUNT — the missing link to the registry.

THE DEFECT THIS EXISTS TO CLOSE (measured 2026-11-01)
-----------------------------------------------------
`runtime/registry.json` is populated and correct: MEASURED 474 registered
skills, 62 routes, 474 valid skill paths, 0 broken routes. The resolver
(`scripts/skill_registry.py`) resolves real scenarios to real files.

But nothing in the HUNT ever asked it for anything. Grepping every caller of
the registry across the tree returned exactly ONE caller:

    scripts/runtime_preflight.py:159   (resolve)
    scripts/runtime_preflight.py:305   (record in the session)

`orch/` never mentions the registry. The hunt's `surface.build` step resolves
a tool inventory; `hypotheses.generate` classifies observed signals; `recon.*`
probes. None of them resolves a skill. So:

  * the SKILL GATE in AGENTS.md ("Before ANY test: what skills does this
    surface trigger? -> run scripts/skill_registry.py resolve") was a rule
    the orchestrator could not obey, because the orchestrator never asked;
  * the corpus's 474 evidence-backed per-class skills were documentation the
    agent loaded by reading, not knowledge the hunt APPLIED;
  * a newly discovered surface — the exact case the rule exists for — got no
    skill at all.

This module is the missing link. It:

  1. derives a SCENARIO from a newly discovered surface node (its kind, its
     attributes, the technology and the parameters observed);
  2. resolves that scenario through the REAL registry;
  3. LOADS the skill CONTENT, so the applied guidance is the file's text and
     not its path;
  4. persists the resolution in the hunt's own database, so the record of
     "which skill governed this test" is auditable after the fact;
  5. reports a DEFERRAL when no skill can be resolved — an unavailable skill
     is recorded as a deferral with a reason, never silently counted as
     available.

It does not decide what to test. It decides what the test is GUIDED BY.
"""
from __future__ import annotations

import json
import re
import sqlite3
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from orch import store  # noqa: E402

# The hunt's own record of what guidance applied where. This is the table
# that makes the skill gate AUDITABLE after the fact — without it, "the
# orchestrator resolved a skill before testing" is an unfalsifiable claim.
SKILL_RESOLUTION_SCHEMA = """
CREATE TABLE IF NOT EXISTS hunt_skill_resolution (
  hunt_id       TEXT NOT NULL,
  scenario      TEXT NOT NULL,
  surface_node  TEXT,
  skill_path    TEXT NOT NULL,
  skill_name    TEXT,
  class_id      TEXT,
  matched_by    TEXT,
  content_sha256 TEXT,
  content_bytes INTEGER,
  applied       INTEGER NOT NULL DEFAULT 0,
  recorded_at   TEXT NOT NULL,
  PRIMARY KEY (hunt_id, scenario, skill_path)
);
CREATE INDEX IF NOT EXISTS ix_hunt_skill_resolution_hunt
  ON hunt_skill_resolution(hunt_id);
CREATE INDEX IF NOT EXISTS ix_hunt_skill_resolution_class
  ON hunt_skill_resolution(class_id);
"""

# A surface node's kind implies the class of attack it invites. This is the
# vocabulary the resolver already knows, expressed as surface kinds.
_KIND_SCENARIOS = {
    "endpoint": "authenticated API with object identifiers",
    "service": "service enumeration",
    "identity": "authentication and session handling",
    "boundary": "trust boundary crossing",
    "datastore": "injection into a datastore",
    "technology": "known technology attack surface",
    "host": "host and service reconnaissance",
}

# The route vocabulary the registry actually publishes. The registry's routes
# are CLASS names (`idor`, `cors`, `sqli`, ...), so a scenario only reaches a
# class skill when it NAMES that class. The hunt already derives a class from
# the observed signals (`orch.hypothesis.classify_behaviour`), so the
# scenario is built from that class when it is known.
#
# MEASURED 2026-11-01: without this, an endpoint scenario resolved to 12
# skills including `ios-redteam-pipeline` and `cloud-iam-deep`, because the
# resolver's metadata fallback fires on a two-token overlap. Naming the
# observed class turns the resolution back into a lookup.
_CLASS_ROUTE_BY_ID = {
    "api_trust": "api-trust",
    "authn": "authn",
    "authz": "authz",
    "bizlogic": "bizlogic",
    "cache_deception": "cache-deception",
    "cache_poisoning": "cache-poisoning",
    "clickjacking": "clickjacking",
    "cmd": "cmd",
    "cors": "cors",
    "crlf": "crlf",
    "csrf": "csrf",
    "deser": "deser",
    "eol_software": "eol-software",
    "file_upload": "file-upload",
    "graphql": "graphql",
    "host_header": "host-header",
    "idor": "idor",
    "info_disclosure": "info-disclosure",
    "jwt": "jwt",
    "ldap": "ldap",
    "mass_assign": "mass-assign",
    "misconfig": "misconfig",
    "nosql": "nosql",
    "oauth": "oauth",
    "open_redirect": "open-redirect",
    "otp": "otp",
    "path_traversal": "path-traversal",
    "prototype_pollution": "prototype-pollution",
    "race": "race",
    "rate_limit": "rate-limit",
    "ssti": "ssti",
    "sqli": "sqli",
    "ssrf": "ssrf",
    "xss": "xss",
    "xxe": "xxe",
}

# Attributes that name the specific behaviour a node exhibits. These make
# the scenario specific enough to resolve, which is the point: "an endpoint"
# is not a scenario, but "an endpoint with an id parameter and a JSON body" is.
_ATTR_TERMS = {
    "method": ("read", "write", "state change"),
    "params": ("object identifier", "parameter"),
    "body": ("request body", "content type"),
    "tech": ("technology", "known technology"),
    "auth": ("authentication", "authorization"),
    "content_type": ("content type", "parsing"),
    "port": ("service enumeration",),
    "protocol": ("protocol",),
}


def ensure_schema(con: sqlite3.Connection) -> None:
    con.executescript(SKILL_RESOLUTION_SCHEMA)
    con.commit()


def _domain_of(node: dict[str, Any], attrs: dict[str, Any]) -> str:
    """Which knowledge domain does this surface belong to?

    The hunt's own context names the kind of hunt (`web`, `network`, ...),
    and the surface's technology often names it too. An HTTP(S) endpoint is
    a web surface unless the hunt says otherwise; a host with a port and a
    protocol that is not HTTP is a network surface.
    """
    explicit = str(attrs.get("domain") or "").strip().lower()
    if explicit in _DOMAIN_ROUTES:
        return explicit
    kind = str(node.get("kind") or "").lower()
    name = str(node.get("name") or "").lower()
    scheme = str(attrs.get("scheme") or "").lower()
    protocol = str(attrs.get("protocol") or "").lower()
    if scheme in ("http", "https") or protocol in ("http", "https"):
        return "web"
    if kind == "endpoint":
        return "web"
    if kind in ("service", "datastore", "boundary"):
        return "network"
    if name.startswith(("http://", "https://")):
        return "web"
    return "network"


def scenario_for(node: dict[str, Any]) -> str:
    """Derive a resolution scenario from a surface node.

    The scenario names the CLASS the hunt observed (when it knows one), the
    KIND of surface, and the OBSERVED attributes. The class comes first
    because the registry's routes ARE class names: a scenario that names
    `idor` reaches the idor route exactly, and a scenario that does not
    falls through to the resolver's loose metadata matching.
    """
    kind = str(node.get("kind") or "").lower()
    base = _KIND_SCENARIOS.get(kind, "attack surface reconnaissance")
    attrs = node.get("attributes") or {}
    if isinstance(attrs, str):
        try:
            attrs = json.loads(attrs or "{}")
        except json.JSONDecodeError:
            attrs = {}
    if not isinstance(attrs, dict):
        attrs = {}

    parts: list[str] = []
    # 1. The observed class, if the hunt derived one.
    observed_class = str(attrs.get("class_id") or attrs.get("class") or "").strip()
    route = _CLASS_ROUTE_BY_ID.get(observed_class.lower())
    if route:
        parts.append(route.replace("-", " "))

    # 2. The DOMAIN, so a surface with no observed class still reaches the
    # registry's domain route rather than the resolver's loose metadata
    # fallback.
    domain = _domain_of(node, attrs)
    if domain:
        parts.append(domain)

    # 3. The kind of surface.
    parts.append(base)

    # 4. The technology, when the surface announces one.
    for key in ("tech", "protocol"):
        value = attrs.get(key)
        if isinstance(value, str) and value.strip():
            parts.append(value.strip())
            break

    # 5. The observed attributes, which say what the endpoint does.
    for key in ("method", "params", "body", "content_type", "auth"):
        value = attrs.get(key)
        if not value:
            continue
        if isinstance(value, (list, tuple)):
            names = [str(v) for v in value if v]
            if names:
                parts.append(" ".join(_ATTR_TERMS.get(key, (key,))[:1]))
                parts.append(" ".join(names[:6]))
        else:
            parts.append(" ".join(_ATTR_TERMS.get(key, (key,))[:1]))
            parts.append(str(value))

    # 6. The OBSERVED SIGNALS. These are the words that name a class: the
    # registry's class vocabulary is built from them, so a node carrying
    # "reflected" or "cors" resolves to `xss` or `cors` rather than to the
    # first four classes of its domain.
    signals = attrs.get("signals") or []
    if isinstance(signals, str):
        try:
            signals = json.loads(signals)
        except json.JSONDecodeError:
            signals = [signals]
    if isinstance(signals, (list, tuple)):
        parts.append(" ".join(str(s) for s in signals[:12] if s))

    # De-duplicate while keeping order, so the scenario stays readable.
    seen: set[str] = set()
    words: list[str] = []
    for part in parts:
        key = part.lower()
        if key and key not in seen:
            seen.add(key)
            words.append(part)
    return " ".join(words).strip()


def _load_resolver():
    """Import the REAL registry resolver.

    It is a script under `scripts/`, not a package module, so it is loaded
    by path. A duplicate implementation of route resolution here would be a
    second source of truth about which skill governs a test — the exact
    defect this module exists to close.
    """
    import importlib.util
    path = ROOT / "scripts" / "skill_registry.py"
    spec = importlib.util.spec_from_file_location("hunt_skill_registry", path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load the skill registry from {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _rank_against_scenario(entries: list[dict[str, Any]], scenario: str,
                           limit: int, *, class_terms: dict[str, set[str]] | None = None
                           ) -> list[dict[str, Any]]:
    """Rank a domain route's members by how well they fit the scenario.

    A domain route is a POOL. `web` holds every web class, and taking the
    first four alphabetically would resolve an endpoint to
    `api_trust`/`authn`/`authz` regardless of what the endpoint is.

    The vocabulary is the registry's OWN class vocabulary — the one that
    produces a "vocabulary(N)" match — read from the registry module rather
    than restated here. A second, weaker copy of that vocabulary is exactly
    the kind of second source of truth this project exists to prevent: it
    would drift from the registry, and the drift would be silent.

    The class vocabulary is enriched with the OBSERVED signals, because the
    scenario's own words ("object identifiers", "cors", "reflected") are the
    terms that name a class. A scenario that says "object identifiers" puts
    `idor` first; one that says "cors" puts `cors` first.
    """
    scenario_tokens = _tokens(scenario)
    if not scenario_tokens:
        return entries[:limit]

    scored: list[tuple[int, str, dict[str, Any]]] = []
    for e in entries:
        cid = str(e.get("class_id") or "")
        vocab = set()
        if class_terms:
            vocab |= set(class_terms.get(cid, set()))
        vocab |= _tokens(f"{cid.replace('_', ' ')} {e.get('name') or ''} "
                         f"{e.get('surface') or ''}")
        overlap = len(vocab & scenario_tokens)
        scored.append((overlap, e["path"], e))
    scored.sort(key=lambda t: (-t[0], t[1]))
    ranked = []
    for overlap, path, e in scored:
        if overlap:
            e = dict(e)
            e["matched_by"] = f"route-pool:{overlap}"
        ranked.append(e)
    return ranked[:limit]


def _resolve_scored(registry_mod, registry: dict[str, Any], scenario: str,
                    *, mode: str, limit: int) -> dict[str, Any]:
    """Resolve a scenario to the skills that genuinely govern it.

    MEASURED 2026-11-01: the stock resolver's metadata fallback fires on a
    TWO-token overlap. For the scenario "service enumeration http" that
    returned 12 skills for one local HTTP endpoint — among them
    `ios-redteam-pipeline`, `cloud-iam-deep` and `okta-attack`. A gate that
    hands back the attack skill for an iOS pipeline when the surface is a
    plain HTTP service is not a gate; it is a list.

    The fix uses the registry's ROUTES as the primary mechanism, because
    the routes ARE the authoritative class-to-skill mapping and they are
    derived from the taxonomy, not from a text overlap:

      1. if the scenario names a class the registry routes, that route's
         skills are the answer;
      2. otherwise the resolver's own answers are ranked, and only the
         strong ones are kept.

    Nothing is invented here: the candidates and the match reasons come
    from the real resolver and the real registry. This only decides which
    of THEIR answers are strong enough to govern a test.
    """
    routes = registry.get("routes") or {}
    skills_meta = registry.get("skills") or {}

    # --- 1. an exact route for the class the scenario names ---------------
    scenario_norm = re.sub(r"[^a-z0-9]+", "-", (scenario or "").lower()).strip("-")
    route_key = None
    for candidate in (scenario_norm, scenario_norm.split(" ")[0]):
        if candidate and candidate in routes:
            route_key = candidate
            break
    if route_key is None:
        # The scenario may contain a class name among other words.
        for token in scenario_norm.split("-"):
            if token in routes:
                route_key = token
                break

    # --- 1b. a DOMAIN route for the kind of surface ----------------------
    #
    # MEASURED 2026-11-01: when the hunt has NOT derived a class, there is
    # no class route to hit, and the resolver's metadata fallback returns
    # whatever shares two common words — for a plain HTTP service that was
    # `ios-redteam-pipeline` and `cloud-iam-deep`. The registry publishes a
    # DOMAIN route (`web`, `network`, ...) whose members are exactly the
    # classes of that domain. A surface with no observed class is governed
    # by its domain's classes, which is a defensible answer; "the iOS
    # attack pipeline" is not.
    if route_key is None:
        for domain in _DOMAIN_ROUTES:
            if domain in scenario_norm:
                if domain in routes:
                    route_key = domain
                    break

    if route_key is not None:
        paths = [p for p in (routes.get(route_key) or []) if p]
        entries = []
        for p in paths:
            meta = skills_meta.get(p) or {}
            entries.append({"key": p, "path": p, "name": meta.get("name"),
                            "surface": meta.get("surface"),
                            "class_id": meta.get("class_id"),
                            "matched_by": f"route:{route_key}"})
        # A DOMAIN route is a POOL, not an answer. `web` holds every web
        # class, and taking the first four alphabetically would resolve an
        # endpoint to api_trust/authn/authz regardless of what the endpoint
        # actually is. So when the route is a domain, the members are RANKED
        # against the scenario's own terms, and only the best are returned.
        if route_key in _DOMAIN_ROUTES and len(entries) > limit:
            entries = _rank_against_scenario(
                entries, scenario, limit,
                class_terms=getattr(registry_mod, "_CLASS_TERMS", None))
        return {
            "scenario": scenario, "mode": mode,
            "effective_mode": mode,
            "paths": [e["path"] for e in entries[:limit]],
            "skills": entries[:limit],
            "missing": [],
            "weak": [],
            "resolved": min(len(entries), limit),
            "note": (f"resolved through the registry's own route for "
                     f"'{route_key}'; the route is derived from the "
                     f"taxonomy, not from a text overlap"),
        }

    # --- 2. otherwise rank the resolver's answers --------------------------
    result = registry_mod.resolve_scenario(registry, scenario, mode=mode,
                                           limit=max(limit * 6, 24))
    scenario_tokens = set(_tokens(scenario))
    n = len(scenario_tokens) or 1

    strong: list[dict[str, Any]] = []
    weak: list[dict[str, Any]] = []
    for skill in result.get("skills") or []:
        path = skill.get("path")
        if not path:
            continue
        matched_by = str(skill.get("matched_by") or "")
        if matched_by == "route":
            strong.append(skill)
            continue
        # The resolver encodes the overlap in the match reason:
        # "vocabulary(N)" / "metadata(N)".
        digits = "".join(ch for ch in matched_by if ch.isdigit())
        overlap = int(digits) if digits else 0
        if matched_by.startswith("vocabulary"):
            # A vocabulary match must cover a real share of the scenario.
            threshold = max(2, -(-n // 3))
        else:
            # A metadata match is weaker evidence, so it must cover more.
            threshold = max(3, -(-n // 2))
        if overlap >= threshold:
            strong.append(skill)
        else:
            weak.append(skill)

    strong = strong[:limit]
    result["paths"] = [s["path"] for s in strong if s.get("path")]
    result["skills"] = strong
    result["weak"] = [{"path": s.get("path"), "name": s.get("name"),
                       "class_id": s.get("class_id"),
                       "matched_by": s.get("matched_by")} for s in weak]
    result["resolved"] = len(result["paths"])
    result["note"] = (
        "no registry route named this scenario, so the resolver's own "
        "matches were ranked: a class route, or a vocabulary match covering "
        "at least a third of the scenario's terms, or a metadata match "
        "covering at least half. A weak match is recorded as a deferral "
        "with its reason, never applied as guidance.")
    return result


def _tokens(text: str) -> set[str]:
    """Content tokens of a scenario string."""
    out: set[str] = set()
    for raw in re.split(r"[^a-z0-9]+", (text or "").lower()):
        if len(raw) >= 3 and raw not in _STOP:
            out.add(raw)
    return out


_STOP = {
    "the", "and", "for", "with", "that", "this", "from", "are", "was",
    "not", "but", "you", "your", "its", "his", "her", "their", "them",
    "then", "than", "into", "over", "under", "about", "after", "before",
    "when", "where", "while", "each", "any", "all", "can", "may", "must",
    "should", "would", "could", "will", "does", "has", "have", "had",
    "been", "being", "there", "these", "those", "such", "also", "per",
    "via", "use", "used", "using",
}

# The registry's DOMAIN routes. A surface with no observed class is governed
# by the classes of its domain, because the domain route is the registry's
# own statement of which classes apply to that kind of surface.
_DOMAIN_ROUTES = ("web", "network", "mobile", "cloud", "api")


def resolve_for_surface(con: sqlite3.Connection, hunt_id: str, node: dict[str, Any],
                        *, mode: str = "hunt", limit: int = 4) -> dict[str, Any]:
    """Resolve, LOAD and RECORD the skills for one newly discovered surface.

    Returns a verdict dict. `applied` lists the skills whose CONTENT was
    loaded; `deferred` lists the ones that could not be loaded, with the
    reason. A skill that cannot be loaded never counts as available.
    """
    ensure_schema(con)
    scenario = scenario_for(node)
    node_key = str(node.get("node_key") or node.get("name") or "")

    registry_mod = _load_resolver()
    try:
        registry = registry_mod.load_registry()
    except Exception as exc:  # noqa: BLE001 - a missing registry is a deferral
        return {"ok": False, "scenario": scenario, "applied": [],
                "deferred": [{"reason": f"registry unavailable: "
                                       f"{type(exc).__name__}: {exc}"}],
                "error": "registry unavailable"}

    result = _resolve_scored(registry_mod, registry, scenario,
                              mode=mode, limit=limit)
    paths = list(result.get("paths") or [])
    matched = {s.get("path"): s for s in (result.get("skills") or [])
               if s.get("path")}

    applied: list[dict[str, Any]] = []
    deferred: list[dict[str, Any]] = []
    now = store.now()

    for rel in paths:
        abs_path = Path(rel) if Path(rel).is_absolute() else ROOT / rel
        try:
            text = abs_path.read_text(encoding="utf-8")
        except OSError as exc:
            deferred.append({"path": rel,
                             "reason": f"unreadable: {type(exc).__name__}: {exc}"})
            continue
        import hashlib
        digest = hashlib.sha256(text.encode("utf-8")).hexdigest()
        meta = matched.get(rel) or {}
        class_id = meta.get("class_id") or ""
        try:
            con.execute(
                "INSERT OR REPLACE INTO hunt_skill_resolution(hunt_id, scenario,"
                " surface_node, skill_path, skill_name, class_id, matched_by,"
                " content_sha256, content_bytes, applied, recorded_at)"
                " VALUES (?,?,?,?,?,?,?,?,?,1,?)",
                (hunt_id, scenario, node_key, rel, meta.get("name"),
                 class_id, meta.get("matched_by"), digest, len(text.encode()),
                 now))
            con.commit()
        except sqlite3.Error as exc:
            deferred.append({"path": rel,
                             "reason": f"could not record: {exc}"})
            continue
        applied.append({
            "path": rel,
            "name": meta.get("name"),
            "class_id": class_id,
            "matched_by": meta.get("matched_by"),
            "bytes": len(text.encode("utf-8")),
            "sha256": digest,
            # The first lines of the skill are the guidance an agent reads
            # first. They are carried so the caller does not have to re-read
            # the file, and so the record shows WHAT was applied.
            "head": "\n".join(text.splitlines()[:12]),
        })

    for missing in result.get("missing") or []:
        deferred.append({"path": missing, "reason": "not present on disk"})

    # A weak match is NOT applied, but it is not hidden either: it is
    # recorded with the reason it was rejected, so the deferral is
    # auditable and an operator can see what was considered and why.
    for weak in result.get("weak") or []:
        deferred.append({"path": weak.get("path"),
                         "reason": (f"weak match ({weak.get('matched_by')}) — "
                                    f"did not cover enough of the scenario to "
                                    f"govern a test"),
                         "weak": True})

    if not applied:
        deferred.append({"reason": "no skill could be resolved for this surface"})

    return {"ok": bool(applied), "scenario": scenario,
            "surface_node": node_key, "applied": applied,
            "deferred": deferred,
            "resolved": len(applied),
            "note": ("a skill that cannot be loaded is recorded as a deferral "
                     "and never counts as available")}


def resolve_for_hunt(con: sqlite3.Connection, hunt_id: str, *,
                     mode: str = "hunt", limit: int = 4) -> dict[str, Any]:
    """Resolve skills for EVERY newly discovered surface of the hunt.

    This is the step a hunt runs after the surface is built and before it
    tests anything: each discovered node gets its skills resolved, loaded and
    recorded.
    """
    ensure_schema(con)
    rows = con.execute(
        "SELECT node_key, kind, name, attributes FROM surface_node"
        " WHERE hunt_id=? ORDER BY observed DESC, kind, name",
        (hunt_id,)).fetchall()
    nodes = []
    for r in rows:
        nodes.append({"node_key": r["node_key"], "kind": r["kind"],
                      "name": r["name"], "attributes": r["attributes"]})
    results = [resolve_for_surface(con, hunt_id, n, mode=mode, limit=limit)
               for n in nodes]
    applied = [a for r in results for a in r["applied"]]
    deferred = [d for r in results for d in r["deferred"]]
    classes = sorted({a["class_id"] for a in applied if a.get("class_id")})
    return {
        "ok": True,
        "hunt_id": hunt_id,
        "surfaces": len(nodes),
        "resolved": len(applied),
        "classes": classes,
        "applied": applied,
        "deferred": deferred,
        "results": results,
    }


def recorded_for(con: sqlite3.Connection, hunt_id: str) -> list[dict[str, Any]]:
    """What the hunt actually applied. This is the audit view."""
    ensure_schema(con)
    rows = con.execute(
        "SELECT scenario, surface_node, skill_path, skill_name, class_id,"
        " matched_by, content_sha256, content_bytes, applied, recorded_at"
        " FROM hunt_skill_resolution WHERE hunt_id=? ORDER BY recorded_at",
        (hunt_id,)).fetchall()
    return [dict(r) for r in rows]
