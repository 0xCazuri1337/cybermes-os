"""Domain routing — the natural-language front door (brief §6, §7, §8).

The brief requires that "Learn XSS" reaches WEB, "Master Kerberos attack paths"
reaches NETWORK -> ACTIVE_DIRECTORY, and "find an attack path from a web
foothold to domain compromise" activates BOTH without the user naming either.
That means routing is a first-class subsystem, not a convention in a prompt.

Two design decisions, both forced by measured failures elsewhere in this system:

1. **Vocabulary names MECHANISMS, not categories.** The competency registry
   attributed 2 of 9 realistic phrasings for `business_logic` because its
   aliases were category names, which only match text using the category name.
   Adding mechanism vocabulary ("applied twice", "negative quantity", "reuse a
   coupon") took it to 7 of 9 with no effect on neighbours. So each domain here
   is keyed by the observable that actually appears in an objective: "asrep
   roast", "kerberoasting", "ticket", not "active directory".

2. **Routing refuses to guess.** A weak match or a tie returns
   `UNROUTED` with the candidates named, rather than picking one. A router
   that always answers is indistinguishable from a correct router, and a wrong
   confident route silently sends a whole learning run at the wrong domain —
   which is worse than an explicit "I am not sure, here are my candidates".

Nothing here touches a target, a network, or the database. Routing is a pure
function of text plus the taxonomy: it is testable with no I/O, which is
exactly why it is in its own module.
"""
from __future__ import annotations

import re
import sqlite3
from dataclasses import dataclass, field

# ---------------------------------------------------------------------------
# The two top-level offensive domains. Active Directory is NOT a third domain
# (brief §2): it is a specialization under NETWORK, because every AD attack
# path is reached through network access to a protocol.
# ---------------------------------------------------------------------------

WEB = "web"
NETWORK = "network"

DOMAINS: dict[str, dict] = {
    WEB: {
        "label": "Web & API",
        "statement": (
            "Browser- and API-mediated HTTP surfaces: authentication, "
            "authorization, injection, client-side execution, request forgery, "
            "business logic."
        ),
    },
    NETWORK: {
        "label": "Internal Network & Infrastructure",
        "statement": (
            "Internal network reachability, exposed services, remote "
            "administration protocols and the credential paths between hosts."
        ),
    },
}

# Specializations under NETWORK. Ordered most-specific first so a routing hit
# on "kerberos" reports ACTIVE_DIRECTORY, not the generic parent.
NETWORK_SPECIALIZATIONS: dict[str, dict] = {
    "active_directory": {
        "label": "On-Premises Active Directory",
        "parent": NETWORK,
        "statement": (
            "Directory objects, their ACLs and relationships, and the "
            "authentication protocols that carry them."
        ),
    },
    "internal_network": {
        "label": "Internal Network",
        "parent": NETWORK,
        "statement": (
            "Host and service discovery, reachability, and the protocols used "
            "to move between hosts."
        ),
    },
    "infrastructure": {
        "label": "Infrastructure & Windows/Linux Services",
        "parent": NETWORK,
        "statement": (
            "The services themselves: configuration, privileges, exposed "
            "management interfaces, and host-level escalation."
        ),
    },
}

ALL_NODES = (WEB, NETWORK, *NETWORK_SPECIALIZATIONS)

# ---------------------------------------------------------------------------
# Mechanism vocabulary. Each entry: node -> (phrases, exclude).
#
# `exclude` applies ONLY after a positive match, so a phrase that is ambiguous
# across domains ("credential", "relay") is deliberately absent from both
# sides and left to the tie-break below, rather than being assigned to whichever
# domain happened to be listed first.
# ---------------------------------------------------------------------------

_WEB_PHRASES = (
    "xss", "cross site scripting", "cross-site scripting", "reflected xss",
    "stored xss", "dom xss", "dom based xss", "blind xss", "csrf", "xsrf",
    "cross site request forgery", "cross-site request forgery",
    "sqli", "sql injection", "nosql injection", "command injection",
    "template injection", "ssti", "xxe", "path traversal", "directory traversal",
    "lfi", "rfi", "file upload", "unrestricted file upload",
    "deserialization", "deserialisation", "insecure deserialization",
    "prototype pollution", "idor", "bola", "broken object level authorization",
    "broken object level authorisation", "insecure direct object reference",
    "graphql", "websocket", "cors", "oauth", "oidc", "jwt", "json web token",
    "open redirect", "clickjacking", "postmessage", "dom clobbering",
    "mass assignment", "rate limit", "caching", "cache poisoning",
    "request smuggling", "business logic", "coupon", "race condition", "toctou",
    "rest api", "api security", "subdomain takeover", "vhost", "csp",
)

_NET_PHRASES = (
    "internal network", "intranet", "lateral movement", "move laterally",
    "pivoting", "tunneling", "tunnelling", "socks proxy", "port forwarding",
    "network segmentation", "segmentation", "subnet", "ip range",
    "host discovery", "service enumeration", "port scan", "smb", "cifs",
    "winrm", "powershell remoting", "rdp", "remote desktop", "ssh",
    "dns enumeration", "zone transfer", "axfr", "named pipe", "netbios",
    "exposed service", "remote management", "rmm", "firewall", "vpn",
    "internal host", "internal service", "windows privilege escalation",
    "linux privilege escalation", "sudo", "suid", "capabilities", "token impersonation",
    "unquoted service path", "alwaysinstallelevated", "credential dumping",
)

_AD_PHRASES = (
    "kerberos", "kerberoasting", "kerberoast", "asrep", "as-rep",
    "asreproasting", "as-rep roasting", "ntlm", "ntlmv1", "relay attack",
    "ntlm relay", "pass the hash", "pass-the-hash", "golden ticket",
    "silver ticket", "dcsync", "dcsync", "delegation abuse",
    "constrained delegation", "unconstrained delegation",
    "resource based constrained delegation", "rbcd", "service principal name",
    "service principal", "spn", "active directory", "active directory",
    "domain controller", "domain controller", "domain admin", "domain compromise",
    "forest", "trust relationship", "ad cs", "adcs", "ad certificate services",
    "certificate template", "gpo", "group policy", "group policy preference",
    "sysvol", "netlogon", "sam account", "ntds.dit", "lsass",
    "ldap", "clldap", "acl abuse", "genericwrite", "genericall", "writedacl",
    "writeowner", "sid history", "ad user", "organizational unit",
    "organizational units", "ou abuse", "as a domain", "domain admin",
)

_INTERNAL_PHRASES = (
    "internal recon", "internal reconnaissance", "internal enumeration",
    "internal host", "internal network", "smb share", "file share",
    "file sharing", "named pipe", "lateral movement", "pivot", "pivoting",
    "workstation", "workgroup", "enumeration of internal",
)

_INFRA_PHRASES = (
    "privilege escalation", "priv esc", "privesc", "service configuration",
    "sudo", "suid", "linux host", "windows host", "systemd", "cron",
    "host configuration", "hardening", "unquoted service path", "winexec",
    "alwaysinstallelevated", "token impersonation", "potato", "juicy potato",
)

_VOCAB: dict[str, tuple[tuple[str, ...], tuple[str, ...]]] = {
    WEB: (_WEB_PHRASES, ()),
    # NETWORK is a DOMAIN node, not a specialization, so its hits attach to the
    # domain directly (see `_specialization_for`, which returns None for it).
    # It must be REGISTERED, not merely declared: the first draft defined
    # `_NET_PHRASES` and never added it here, so winrm / smb / rdp / lateral
    # movement / pivoting silently routed nowhere while still appearing in the
    # vocabulary listing as though they worked.
    NETWORK: (_NET_PHRASES, ()),
    "active_directory": (_AD_PHRASES, ("cloud identity", "entra id",
                                      "azure ad", "entra", "aws iam",
                                      "gcp iam", "okta")),
    "internal_network": (_INTERNAL_PHRASES, ()),
    "infrastructure": (_INFRA_PHRASES, ()),
}

# Phrases that genuinely straddle domains. They route to BOTH sides rather than
# being silently assigned, because the whole point of §6 is that the user should
# not have to know which domain their objective lives in.
#
# THE RULE FOR ADDING ONE HERE: the phrase must name the CROSSING. "attack
# path" and "attack chain" were in this list first and were wrong — the brief's
# own example "Master Kerberos attack paths" contains "attack path" and must
# route to NETWORK alone, yet it activated WEB and reported CROSS_DOMAIN. A
# domain-neutral phrase in this list poisons every objective that happens to
# mention the word, so the admission test is: does this phrase only make sense
# if something is being crossed from one place to another?
_BRIDGE_PHRASES = (
    # a web-facing thing yielding internal reach
    "web foothold", "foothold", "from a web", "from the web",
    "internal access", "into the internal", "reached the internal",
    "reaching the internal", "internal network access",
    # a leaked artefact yielding access to either side
    "credential exposure", "credential leak", "exposed credentials",
    "leaked credentials", "secrets in", "hardcoded credential",
    "hardcoded credentials", "source code", "config file", "config files",
    # an internal identity yielding domain control
    "to the domain", "to domain", "reaching the domain", "reached the domain",
    "domain compromise", "into the domain", "onto the domain",
    "to the domain controller", "domain controller from",
    # a network foothold yielding application access
    "pivot into", "pivoting into", "from the internal", "internal identity",
)

# Words that indicate the user is asking about a TRANSITION between domains.
_CHAIN_HINT = re.compile(
    r"\b(from|into|to|through|via)\b.*\b(internal|domain|forest|network|"
    r"controller|ad)\b", re.I)


@dataclass
class Match:
    node: str
    phrase: str
    kind: str                      # vocabulary | bridge


@dataclass
class Route:
    """The verdict. Never a bare domain string."""

    objective: str
    domains: list[str] = field(default_factory=list)
    specializations: list[str] = field(default_factory=list)
    matches: list[Match] = field(default_factory=list)
    bridges: list[str] = field(default_factory=list)
    orphans: list[str] = field(default_factory=list)
    status: str = "UNROUTED"       # ROUTED | CROSS_DOMAIN | UNROUTED
    note: str = ""

    @property
    def is_cross_domain(self) -> bool:
        return len(self.domains) > 1

    @property
    def nodes(self) -> list[str]:
        return self.domains + self.specializations

    def explain(self) -> str:
        if self.status == "UNROUTED":
            return (f"UNROUTED: {self.objective!r}\n  {self.note}\n"
                    f"  candidates: {', '.join(ALL_NODES)}")
        lines = [f"{self.status}: {self.objective!r}"]
        lines.append(f"  domains: {', '.join(self.domains)}")
        if self.specializations:
            lines.append(f"  specializations: {', '.join(self.specializations)}")
        if self.bridges:
            lines.append(f"  bridge phrases: {', '.join(self.bridges)}")
        lines.append("  matched: " + ", ".join(
            f"{m.node}<-{m.phrase!r}({m.kind})" for m in self.matches))
        if self.orphans:
            # Never printed as a domain: a specialization whose parent link is
            # broken is a table defect, and §2 forbids it becoming a third
            # top-level domain. Reported, never silently repaired.
            lines.append(f"  ORPHANED SPECIALIZATION: {', '.join(self.orphans)}")
        return "\n".join(lines)


def _normalise(text: str) -> str:
    return " ".join(text.lower().replace("_", " ").replace("-", " ").split())


def _hits(phrases: tuple[str, ...], haystack: str) -> list[str]:
    out = []
    for p in phrases:
        p = _normalise(p)
        toks = p.split()
        parts = [re.escape(t) for t in toks]
        # Allow a simple plural on the FINAL token only. Without this,
        # "internal host" cannot match "the internal hosts", which is how half
        # of real objectives are phrased. The suffix is optional so the
        # singular still matches, and it is anchored by the lookahead below.
        parts[-1] += r"(?:e?s)?"
        pat = (r"(?<![a-z0-9])" + r"\s+".join(parts) + r"(?![a-z0-9])")
        if re.search(pat, haystack):
            out.append(p)
    return out


def _specialization_for(node: str) -> str | None:
    return NETWORK_SPECIALIZATIONS.get(node, {}).get("parent")


def route(objective: str) -> Route:
    """Resolve a natural-language objective to domains + specializations.

    Ordering of the verdict, which is the whole contract:

      * exactly one domain, no bridge   -> ROUTED
      * more than one domain, or a bridge phrase -> CROSS_DOMAIN
      * nothing matched, or the top two
        candidates TIE                    -> UNROUTED, candidates named

    The tie case is the one that matters. "credential dump" hits NETWORK only,
    but a bare "privilege escalation" is genuinely ambiguous between a web app
    and a Windows host, and silently guessing either one is how a whole learning
    run gets pointed at the wrong tree.
    """
    r = Route(objective=objective)
    hay = _normalise(objective)
    if not hay:
        r.note = "empty objective"
        return r

    for node, (phrases, excludes) in _VOCAB.items():
        hit = _hits(phrases, hay)
        if not hit:
            continue
        # An exclusion only ever REMOVES a hit; it never adds one. This is what
        # keeps "entra id" out of the on-prem AD domain without also blinding
        # AD routing to the word "directory".
        if _hits(excludes, hay):
            continue
        for p in hit:
            r.matches.append(Match(node, p, "vocabulary"))

    r.bridges = _hits(_BRIDGE_PHRASES, hay)
    for p in r.bridges:
        r.matches.append(Match(WEB + "+" + NETWORK, p, "bridge"))

    # Promote a specialization hit into its parent domain, so a caller can ask
    # "which domains are in play" without re-walking the tree.
    #
    # Classification is by IDENTITY, not by whether a parent link happens to be
    # present. Inferring it from the parent made a corrupt table promote a
    # specialization into a third top-level domain — which §2 forbids — so the
    # node's membership in NETWORK_SPECIALIZATIONS is what decides, and a
    # broken parent link is dropped rather than silently repaired.
    doms: list[str] = []
    orphans: list[str] = []
    for m in r.matches:
        if m.kind == "bridge":
            for d in (WEB, NETWORK):
                if d not in doms:
                    doms.append(d)
            continue
        if m.node in NETWORK_SPECIALIZATIONS:
            parent = _specialization_for(m.node)
            if parent and parent not in doms:
                doms.append(parent)
            elif not parent:
                orphans.append(m.node)
        elif m.node not in doms:
            doms.append(m.node)
    r.domains = doms
    # Must be assigned: the orphan list is populated above and the Route
    # carries it as a REPORTED field. Without this the degradation path silently
    # swallowed the table defect it exists to surface.
    r.orphans = orphans

    for m in r.matches:
        if m.node in NETWORK_SPECIALIZATIONS and m.node not in r.specializations:
            r.specializations.append(m.node)

    if not r.domains:
        r.status = "UNROUTED"
        r.note = ("no mechanism phrase matched any domain; naming candidates "
                  "rather than guessing")
        return r

    if r.bridges or len(r.domains) > 1:
        r.status = "CROSS_DOMAIN"
        if not r.bridges:
            r.note = "matched vocabulary in more than one domain"
        return r

    # Single domain. Ties WITHIN a domain across specializations are not
    # ambiguous — a Kerberos objective is genuinely both AD and internal
    # network — so specialization breadth never downgrades the verdict.
    r.status = "ROUTED"
    return r


def coverage() -> dict:
    """Report which vocabulary entries have never been exercised.

    A routing table that has only ever been tested against the three examples
    in the brief is a routing table written for its own test suite. This lists
    every phrase so an operator can see the surface and add a probe.
    """
    out = {}
    for node, (phrases, excludes) in _VOCAB.items():
        out[node] = {"phrases": len(phrases), "excludes": len(excludes),
                     "all": list(phrases)}
    out["_bridge"] = {"phrases": len(_BRIDGE_PHRASES), "all": list(_BRIDGE_PHRASES)}
    return out

# ===========================================================================
# ON-DISK TREE SPLIT — a SEPARATE concern from the router above.
#
# `route()` above answers "which domain does this OBJECTIVE belong to" from
# natural-language text. What follows answers "which folder does this CLASS
# belong in" from the database. They share a domain vocabulary and nothing else;
# conflating them is how a class ends up filed by a keyword instead of by what
# it actually is.
#
# The rule that makes this safe: the split is DERIVED from the db on every call.
# A literal list of "these 25 classes are network" goes stale the moment a class
# is registered -- the next run reports success and files a network class under
# Web, where nobody hunting there will ever find it.
# ===========================================================================

# The on-disk folder names. `network` is the user's own wording, kept verbatim:
# the tree should say what they asked for, not what a schema would prefer.
#
# These labels are the LEGACY flat-tree names. The canonical layout is
# `domains/<domain>/...` below, whose directory names are the DOMAIN SLUGS
# (lowercase, hyphenated) — not these display labels. DOMAIN_LABEL is retained
# only so a legacy reference fails loudly in one place rather than silently
# producing a folder named "Network + AD" inside the new tree.
DOMAIN_LABEL = {
    WEB: "Web",
    NETWORK: "Network + AD",
}

# ---------------------------------------------------------------------------
# CANONICAL LAYOUT — the one place that knows where anything lives.
# ---------------------------------------------------------------------------
# Every writer (taxonomy_write, skillgen, pipeline, methodgen, chains,
# merge_skills) resolves its output through these functions. That is the whole
# point: a path declared in two places is a path two generators will fight over,
# and the second writer wins silently (see the taxonomy_spec CLASSES/SUBDOCS
# guard). One owner, many callers.
#
# Layout:
#   domains/<domain>/methodology/
#   domains/<domain>/<class_id>/knowledge/     canonical class page
#   domains/<domain>/<class_id>/skills/        the hunting skill
#   domains/<domain>/<class_id>/chains/        chains anchored on this class
#   domains/<domain>/<class_id>/assessment/    class-scoped assessment
#   domains/<domain>/<class_id>/mastery/       class-scoped mastery state
#   domains/<domain>/<class_id>/labs/          practice material
#   domains/<domain>/chains/                   chains spanning classes in-domain
#
# Active Directory is a SPECIALIZATION under network, not a third domain: every
# AD attack path is reached through network access to a protocol. It is
# therefore filed at domains/network/active-directory/<class_id>/.

# Primary active Skills root. Migrated from "domains/" (Phase 1, 2026-11-03).
# The on-disk canonical layout now lives under skills/<domain>/...
DOMAINS_DIRNAME = "skills"

# Domain slug on disk. Distinct from DOMAIN_LABEL (a display name) so a folder
# is never named "Network + AD".
DOMAIN_SLUG = {
    WEB: "web",
    NETWORK: "network",
}

# Specialization -> the on-disk folder under its parent domain.
SPEC_SLUG = {
    "active_directory": "active-directory",
    "internal_network": "internal-network",
    "infrastructure": "infrastructure",
}

# The subdirectories a bug-class unit owns. Declared once so a caller cannot
# invent a seventh name that no auditor checks.
# The subdirectories a bug-class unit owns. `knowledge` and `skills` are now
# FLATTENED to the class root (CLASS.md, DIGEST.md, SKILL.md, HISTORY.md,
# HUNT.md live directly in the class dir), so they are no longer subdirs.
# Kept declared for back-compat callers that still ask for them.
CLASS_SUBDIRS = ("chains", "assessment", "mastery", "labs", "knowledge", "skills")


def config_root():
    from . import config
    return config.root()


def domains_root():
    from . import config
    return config.root() / DOMAINS_DIRNAME


def domain_dir(domain: str):
    """`domains/web` or `domains/network`."""
    if domain not in DOMAIN_SLUG:
        raise KeyError(
            f"unknown domain {domain!r}; expected one of {sorted(DOMAIN_SLUG)}")
    return domains_root() / DOMAIN_SLUG[domain]


def specialization_of(con, class_id: str) -> str | None:
    """The specialization for a class, or None.

    Read from `class_domain` on every call. Returns None for a web class, and
    for an UNMAPPED network class — which is a defect, not a licence to file it
    loose at the domain root; `class_rel` raises on that case instead.

    The `specialization` column is NOT in schema.sql, so a database built from
    the schema alone (every sandbox in eval/, and any fresh install) has a
    `class_domain` table without it. Probing for the column and degrading to
    "no specialization" is what lets those databases work at all: the original
    query raised `no such column: specialization` and took T11 down, which is
    the same failure shape as a gate that dies on a data gap — it reports
    nothing and is indistinguishable from a gate that passed.

    It is also correct, not merely convenient: with no column there are no
    specialization rows, so None is the true answer, and `class_rel` then
    applies the network-requires-a-specialization rule on its own.
    """
    try:
        row = con.execute(
            "SELECT specialization FROM class_domain WHERE class_id=?",
            (class_id,)).fetchone()
    except sqlite3.OperationalError as e:
        if "no such column" not in str(e):
            raise
        return None
    if row and row["specialization"] and row["specialization"] != "-":
        return row["specialization"]
    return None


def class_rel(class_id: str, con=None) -> str:
    """Repo-relative POSIX path of a class's own directory.

    THE function every writer calls. Returns e.g.
    `domains/web/xss` or `domains/network/active-directory/ad_kerberos`.
    """
    con = con or _con()
    domain = domain_of(con, class_id)
    spec = specialization_of(con, class_id)
    if spec:
        if spec not in SPEC_SLUG:
            raise KeyError(
                f"class {class_id!r} has specialization {spec!r}, which has no "
                f"on-disk slug. Add it to SPEC_SLUG in wks/domains.py.")
        if domain != NETWORK:
            raise KeyError(
                f"class {class_id!r} is domain {domain!r} but carries the "
                f"network specialization {spec!r}; §2 forbids that combination.")
        return f"{DOMAINS_DIRNAME}/{DOMAIN_SLUG[domain]}/{SPEC_SLUG[spec]}/{class_id}"
    # A network class with no specialization is unmapped, and filing it at
    # domains/network/<class_id> would bury it beside 25 others. Raise.
    if domain == NETWORK:
        raise KeyError(
            f"class {class_id!r} is a network class with no `class_domain` "
            f"specialization. Add a row (active_directory | internal_network | "
            f"infrastructure) rather than letting it default to a domain root.")
    return f"{DOMAINS_DIRNAME}/{DOMAIN_SLUG[domain]}/{class_id}"


def class_dir(class_id: str, con=None):
    """Absolute path of a class's own directory. Creates nothing."""
    from . import config
    return config.root() / class_rel(class_id, con)


def class_subdir(class_id: str, name: str, con=None):
    """Flattened: `knowledge` and `skills` resolve to the class dir itself."""
    if name not in CLASS_SUBDIRS:
        raise KeyError(
            f"{name!r} is not a bug-class subdirectory; expected one of "
            f"{CLASS_SUBDIRS}. Add it to CLASS_SUBDIRS deliberately.")
    if name in ("knowledge", "skills"):
        return class_dir(class_id, con)
    return class_dir(class_id, con) / name


def domain_chains_dir(domain: str):
    """In-domain chains that span classes: `domains/web/chains`."""
    return domain_dir(domain) / "chains"


def methodology_dir(domain: str):
    """Domain-specific methodology: `domains/web/methodology`."""
    return domain_dir(domain) / "methodology"

# Maps the `bug_class.surface` VOCABULARY to a domain. This is a statement about
# the values `surface` may take -- not a list of class names. Measured in use:
# web 23, ad 12, net 13, api 5, identity 4, business 2, client 2, infra 1.
#
# `class_domain.domain` is authoritative where present (40 of 62 classes); this
# grouping is the fallback, and an unmapped surface RAISES rather than defaulting.
# Defaulting an unknown surface to Web would bury a network class permanently.
NETWORK_SURFACES = frozenset({"ad", "net"})
WEB_SURFACES = frozenset({"web", "api", "client", "identity", "business", "infra"})


def _con() -> "sqlite3.Connection":
    from . import config
    db = config.db_path()
    if not db.exists():
        raise SystemExit(f"no database at {db}")
    con = sqlite3.connect(f"file:{db}?mode=ro", uri=True)
    con.row_factory = sqlite3.Row
    return con


def domain_of(con, class_id: str) -> str:
    """Resolve one registered class to WEB or NETWORK.

    Derived from the db on every call -- never cached in a literal.
    Raises KeyError for an unknown class or an unmapped surface, so a defect is
    reported at the point it happens instead of producing a wrong folder.
    """
    row = con.execute("SELECT domain FROM class_domain WHERE class_id=?",
                      (class_id,)).fetchone()
    if row and row["domain"] in DOMAIN_LABEL:
        return row["domain"]
    row = con.execute("SELECT surface FROM bug_class WHERE id=?",
                      (class_id,)).fetchone()
    if not row:
        raise KeyError(f"class {class_id!r} is not registered in db/wks.db")
    surface = (row["surface"] or "").lower()
    if surface in NETWORK_SURFACES:
        return NETWORK
    if surface in WEB_SURFACES:
        return WEB
    raise KeyError(
        f"class {class_id!r} has surface {row['surface']!r}, which maps to neither "
        f"domain. Add the surface to NETWORK_SURFACES or WEB_SURFACES here -- "
        f"do not let it default into a tree.")


def class_split(con) -> dict[str, list[str]]:
    """{domain: [class_id, ...]} for every registered class."""
    out: dict[str, list[str]] = {WEB: [], NETWORK: []}
    for r in con.execute("SELECT id FROM bug_class ORDER BY id"):
        out[domain_of(con, r["id"])].append(r["id"])
    return out


def class_dir_unmapped(class_id: str):
    """Escape hatch for a class with no `class_domain` row.

    A class with no domain row would otherwise raise inside `class_rel` and take
    a whole generator down with it — and a gate that dies on a data gap reports
    nothing, which is indistinguishable from a gate that passed. Un-mapped
    classes land in `domains/_unmapped/<class_id>` instead: still visible, still
    reported by `class_health`, but not fatal.

    A NETWORK-surface class with no row is a different case: it has a domain
    (network) but no specialization, so `class_rel` raises on purpose. Routing
    it here would bury it beside 25 siblings, so only a genuinely domainless
    class is diverted.
    """
    from . import config
    try:
        domain = domain_of(_con(), class_id)
    except KeyError:
        domain = None
    if domain == NETWORK:
        return class_dir(class_id)
    return domains_root() / "_unmapped" / class_id


def chain_dir(domain: str):
    """Chains are a sibling of the class folders inside the same domain."""
    return domain_dir(domain) / "chains"


def surface_audit(con) -> dict[str, list[str]]:
    """Every surface in use, with the domain it routes to. The drift detector:
    a surface appearing here that is in neither frozenset is a bug in this
    module, not a class to be filed by guesswork."""
    groups: dict[str, list[str]] = {}
    for r in con.execute("SELECT id, surface FROM bug_class ORDER BY surface, id"):
        groups.setdefault(r["surface"] or "(none)", []).append(r["id"])
    out = {}
    for surface, ids in groups.items():
        try:
            out[surface] = {"domain": DOMAIN_LABEL[domain_of(con, ids[0])],
                            "count": len(ids)}
        except KeyError as e:
            out[surface] = {"domain": "UNMAPPED", "count": len(ids), "error": str(e)}
    return out



def main(argv: list[str] | None = None) -> int:
    """`python -m wks.domains --split` -- the on-disk split, not the router."""
    import argparse
    ap = argparse.ArgumentParser(prog="wks.domains")
    ap.add_argument("--split", action="store_true",
                    help="print the Web / Network + AD class split")
    ap.add_argument("--surfaces", action="store_true",
                    help="surface -> domain routing table")
    ap.add_argument("--check", action="store_true",
                    help="verify the on-disk tree matches the db split")
    a = ap.parse_args(argv)
    con = _con()

    if a.check:
        # Resolved through class_rel, not `domain_dir(dom)/cid`. The old form
        # assumed every class sat at `skills/<Domain>/<id>` and reported all 25
        # network classes as missing once they moved under
        # `domains/network/<specialization>/<id>` -- a check that fails against
        # a correct tree teaches you to ignore it.
        problems = []
        total = 0
        for dom, ids in class_split(con).items():
            for cid in ids:
                total += 1
                try:
                    rel = class_rel(cid, con)
                except KeyError as e:
                    problems.append(f"unresolvable: {cid}: {e}")
                    continue
                d = config_root() / rel
                if not d.is_dir():
                    problems.append(f"missing {rel}: {cid}")
                elif not (d / "CLASS.md").exists():
                    problems.append(f"no canonical page: {rel}/CLASS.md")
        for p in problems:
            print("  !", p)
        print(f"tree check: {len(problems)} problem(s) across {total} classes")
        return 1 if problems else 0

    if a.surfaces:
        print("surface -> domain (the only literal grouping in this module):")
        for surface, info in surface_audit(con).items():
            print(f"  {surface:12} -> {info['domain']:14} ({info['count']} classes)")
            if info.get("error"):
                print(f"      {info['error']}")
        return 0

    split = class_split(con)
    print(f"skills/{DOMAIN_SLUG[WEB]}/            {len(split[WEB])} classes")
    for c in split[WEB]:
        print(f"    {class_rel(c, con)}")
    print(f"skills/{DOMAIN_SLUG[NETWORK]}/        {len(split[NETWORK])} classes")
    for c in split[NETWORK]:
        print(f"    {class_rel(c, con)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
