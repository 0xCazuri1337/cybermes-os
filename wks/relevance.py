"""Topical relevance: the check the gate was missing.

`quality.gate_reasons` has never contained a notion of whether an item is ABOUT
the class it is filed under. Everything it checks is about provenance — is the
quote real, is it on the cited page, are there two publisher orgs. A perfect
provenance score on a sentence about OWASP password policy filed under
`exposed_rmm` (Remote Monitoring and Management Abuse) satisfies every
existing gate. That is the mechanism by which a class can read `mature` while
teaching nothing, and it is the single largest source of false mastery
measured on this host: 155 of 1111 promoted items (14%), and 82.6% of
`exposed_rmm`.

## Why this ranks classes instead of testing for absence

The obvious design is "the claim must contain one of the class's terms". That
is unsound as a gate, because a correctly-worded technique frequently shares no
surface vocabulary with the class name:

    class `subdomain_takeover`, claim "An unclaimed CNAME to a decommissioned
    PaaS provider grants account takeover of the zone"

There is no "takeover" in that claim, and none is needed. Gating on absence
rejects genuine knowledge and teaches the operator to ignore the gate — the
measured failure mode of the quote matcher (R17), which invented false
negatives on markdown italics, table pipes and rewritten pages until its
verdicts were unusable.

So relevance is decided by RANKING classes against each other, plus an orphan
rule for claims nothing can place:

    ON_TOPIC       the filed class explains the claim (weighted score > 0)   keep
    SIBLING        no own hit, but a declared sibling explains it better —
                   neighbours legitimately overlap                            keep
    AMBIGUOUS      no own hit, one weak foreign signal                       keep
    MISFILED       no own hit, a non-sibling class explains it clearly       HOLD
    ORPHAN         no own hit and NOTHING in the registry explains it         HOLD
    MODULE_FILLER  describes a course, not a technique                       HOLD

Two refinements were forced by measurement, not taste:

*Terms are weighted, and inflection is stemmed.* "buffer overflow" is decisive;
"buffer" alone is not. And "overflows" must match "overflow", or the corpus's
own measured offender ("Buffer overflows are common vulnerabilities…", filed
under `dns_enum`) scores a single weak hit and is never held. A single
multi-word term match is therefore enough to hold; a single generic word is
not.

*MODULE_FILLER is checked BEFORE the own-vocabulary shortcut.* "This module
covers the most common attacks … web application sessions" contains "web
application", so it would otherwise pass as web knowledge. Module prose names
no mechanism and must never be promoted anywhere.

Sibling classes exist because `rdp` and `exposed_services` both legitimately
describe an exposed RDP port; an RDP-flavoured sentence under
`exposed_services` is overlap, not misfiling. Only a class in a DIFFERENT
family claiming the claim is evidence the item is in the wrong place.

## Validity contract

Every verdict must itself be checkable both ways, so:

    python -m wks.relevance --selftest

runs a fixed battery — 30 genuine items that MUST be kept, and the measured
real corpus defects that MUST be held — and exits non-zero if any verdict is
wrong in EITHER direction. A gate never shown to fail is indistinguishable
from a gate that cannot fail (R24), and a gate that cannot fail is worse than
no gate: it manufactures confidence.

Unprobeable classes return None and are NEVER held. Silence is correct when
the registry has no opinion.
"""
from __future__ import annotations

import json
import os
import re
import sqlite3
import unicodedata
from dataclasses import dataclass, field
from functools import lru_cache

# A non-sibling class must reach this WEIGHTED score before an item is held.
# Weight: 2 for a multi-word term, 1 for a single word. So one decisive
# multi-word hit holds; one generic single word does not.
MISFILED_SCORE = 2

ON_TOPIC = "ON_TOPIC"
SIBLING = "SIBLING"
AMBIGUOUS = "AMBIGUOUS"
MISFILED = "MISFILED"
ORPHAN = "ORPHAN"
MODULE_FILLER = "MODULE_FILLER"

# Only MISFILED and MODULE_FILLER block promotion.
#
# ORPHAN is DELIBERATELY not terminal. Measured on this host: with ORPHAN
# terminal, 117 items were held and roughly 70% of them were FALSE POSITIVES —
# correct SQLi, XSS, path-traversal, IDOR and race knowledge that phrased itself
# without any registry term. An absence-based hold is the exact failure mode
# this module exists to avoid, so ORPHAN annotates and feeds vocabulary repair.
# The two terminal states are both POSITIVE evidence: another class explains
# the claim clearly, or the claim is syntactically course prose.
TERMINAL_STATES = (MISFILED, MODULE_FILLER)

# Classes whose vocabulary is process/management language. They never establish
# relevance for a technical class and never win a foreign comparison.
PROCESS_CLASSES = {"exposure_management"}

# Declared siblings: classes whose technique sets legitimately overlap, so a
# claim one explains better than the other is not evidence of misfiling.
SIBLING_SETS: list[frozenset[str]] = [
    frozenset({"exposed_services", "service_enumeration",
               "service_enumeration_detail", "exposed_rmm", "smb", "rdp",
               "winrm"}),
    frozenset({"dns_enum", "subdomain_takeover", "ad_enumeration"}),
    frozenset({"ad_enumeration", "ldap_enum", "ad_ldap", "internal_recon",
               "segmentation_analysis"}),
    frozenset({"internal_recon", "segmentation_analysis", "lateral_movement",
               "tunneling_pivoting", "service_enumeration"}),
]


def siblings_of(class_id: str) -> set[str]:
    out: set[str] = set()
    for s in SIBLING_SETS:
        if class_id in s:
            out |= s
    return out - {class_id}


# Vocabulary is per-CLASS and deliberately narrow. Terms true of the whole
# corpus ("attacker", "vulnerability", "target") are excluded: they are the
# vocabulary the filler shares with everything, so including them would make
# every item look on-topic for every class.
#
# NOTE: never add an ATTACKER-TOOLING term here (dropper, beacon, netscaler,
# base64). Doing so makes the exploit-chain prose that is filed under
# `misconfig` read as on-topic, which is precisely backwards — it was tried
# and the selftest caught it.
CLASS_VOCAB: dict[str, list[str]] = {
    "windows_privesc_token": [
        "access token", "impersonate", "impersonation", "token theft",
        "primary token", "integrity level", "seimpersonate", "sedebug",
        "token duplication", "runas", "createprocesswithtoken",
        "privilege escalation", "system token", "privilege", "named pipe client",
    ],
    "windows_privesc_hijack": [
        "dll hijacking", "dll search order", "com hijacking", "com object",
        "sys path", "writable service path", "load path", "phantom dll",
        "side-loading", "sxs", "manifest", "privilege escalation",
        "writable directory", "binary planting", "program files",
    ],
    "windows_privesc_service": [
        "service trigger", "service abuse", "named pipe", "pipe impersonation",
        "scm", "service control manager", "unquoted service path", "wts",
        "impersonate client", "system service", "privilege escalation",
        "service binary", "alwaysinstallelevated", "coercion",
    ],
    "linux_privesc": [
        "sudo", "suid", "sgid", "capabilities", "cap_", "setcap",
        "interesting groups", "ld.so", "preload", "cron", "systemd",
        "writable service", "docker group", "privilege escalation", "root",
        "polkit", "sudoers", "nsenter", "capability", "shadow", "passwd",
    ],
    "container_escape": [
        "container escape", "runc", "containerd", "docker socket",
        "privileged container", "cgroup", "namespace", "mount namespace",
        "host filesystem", "escape the container", "kubernetes", "pod",
        "hostpath", "securitycontext", "privilege escalation", "escape",
    ],
    # ---------------- network / infrastructure ----------------
    "dns_enum": [
        "dns", "domain name", "zone", "nameserver", "name server", "axfr",
        "zone transfer", "resolver", "srv record", "txt record", "ns record",
        "soa record", "hostname", "cname", "reverse lookup", "wildcard dns",
        "dns record", "zone walking", "subdomain",
    ],
    "exposed_services": [
        "exposed service", "publicly exposed", "listening port", "port scan",
        "open port", "internet-facing", "service banner", "port banner",
        "exposed port", "attack surface", "listening service",
        "exposed host", "unnecessary service", "banner grab", "exposed",
        "publicly accessible", "port", "exposed admin",
    ],
    "exposed_rmm": [
        "rmm", "remote monitoring and management", "remote management",
        "teamviewer", "anydesk", "screenconnect", "screen connect",
        "rustdesk", "vnc", "remote desktop tool", "management agent",
        "remote access tool", "c2 agent", "attended access", "remote support",
    ],
    "service_enumeration": [
        "service enumeration", "service discovery", "port scan", "port sweep",
        "service fingerprint", "banner grab", "service identification",
        "scan range", "host discovery", "masscan", "naabu", "network sweep",
        "enumerate services", "service listing", "service",
    ],
    "service_enumeration_detail": [
        "service configuration", "anonymous access", "default credential",
        "misconfigured service", "service hardening", "version", "build",
        "patch level", "feature enabled", "service policy",
        "permissive configuration", "weak protocol", "anonymous session",
        "default install", "service banner version", "enabling",
        "configuration", "policy",
    ],
    "smb": [
        "smb", "cifs", "smb share", "netbios", "null session", "dialect",
        "smb signing", "smb1", "smb2", "named pipe", "share enumeration",
        "psexec", "admin share", "smb configuration",
    ],
    "rdp": [
        "rdp", "remote desktop", "nla", "network level authentication",
        "credssp", "clipboard redirection", "3389", "rdp session",
        "rdp security", "remoteapp",
    ],
    "winrm": [
        "winrm", "windows remote management", "powershell remoting", "wsman",
        "5985", "5986", "winrm service", "wmi over winrm",
    ],
    "ldap": [
        "ldap injection", "xpath", "ldap filter", "ldap query injection",
        "nosql-style injection", "ldap directory", "ldap bind",
    ],
    "ldap_enum": [
        "ldap", "rootdse", "directory enumeration", "bind dn", "objectclass",
        "ldap query", "netbios name", "domain controller discovery",
        "serviceprincipalname", "userprincipalname",
    ],
    "internal_recon": [
        "internal network", "internal host", "segment", "lateral", "pivot",
        "subnet", "network range", "internal reconnaissance",
        "internal service", "internal host discovery", "trust boundary",
        "internal enumeration",
    ],
    "segmentation_analysis": [
        "segmentation", "segment", "firewall", "acl", "boundary", "route",
        "vlan", "network boundary", "east-west", "perimeter",
        "network isolation", "rule", "port filter",
    ],
    # ---------------- active directory ----------------
    "ad_enumeration": [
        "active directory", "domain controller", "samaccountname", "sid",
        "netbios", "forest", "trust", "group policy", "ad group", "ad user",
        "principal", "kerberoast", "asreproast", "ldap enumeration",
        "ad domain", "domain enumeration", "bloodhound", "net view",
        "domain", "computer account",
    ],
    "ad_kerberos": ["kerberos", "ticket", "krbtgt", "tgs", "asrep", "spn",
                    "service principal", "kdc", "authentication protocol",
                    "authentication service", "ticket granting"],
    "ad_ntlm": ["ntlm", "net ntlm", "ntlmv2", "lm hash", "relay",
                "smb signing", "challenge-response"],
    "ad_ldap": ["ldap", "active directory", "domain controller", "bind",
                "objectclass", "sid", "delegation", "acl"],
    "ad_acl_abuse": ["acl", "dacl", "access control", "permission",
                     "genericall", "genericwrite", "writedacl", "own",
                     "privilege", "group policy delegation", "acl abuse",
                     "rights"],
    "ad_delegation": ["delegation", "unconstrained delegation",
                      "constrained delegation", "msds-allowedtodelegate",
                      "rbcd", "resource-based constrained"],
    "ad_group_policy": ["group policy", "gpo", "gpresult", "sysvol",
                        "gpt.ini", "policy script", "restricted group"],
    "ad_trust_abuse": ["trust", "forest trust", "domain trust", "sid history",
                       "trust relationship", "foreign security principal"],
    "adcs_abuse": ["adcs", "certificate authority", "certificate template",
                   "esc1", "esc4", "enrolment agent", "pkinit", "certipca",
                   "certificate services", "strong mapping"],
    "credential_access": ["credential", "lsass", "mimikatz", "ntds.dit",
                          "sam hive", "dpapi", "credential dump",
                          "hash dump"],
    "pass_the_hash": ["pass the hash", "pass-the-hash", "pth", "ntlm hash",
                      "ticket", "kerberos ticket", "hash authentication"],
    "password_attacks": ["password attack", "spray", "brute force",
                         "password spraying", "credential stuffing",
                         "password policy", "password complexity",
                         "passwords", "password", "blocklist",
                         "password reset"],
    # ---------------- web ----------------
    "xss": ["xss", "cross-site scripting", "javascript", "dom", "html",
            "script", "sink", "payload", "browser", "innerhtml",
            "event handler", "reflected", "stored xss"],
    "sqli": ["sql injection", "sql query", "sql", "database", "select ",
             " where ", "orm", "union select", "boolean-based", "time-based",
             "dbms", "code injection"],
    "ssrf": ["ssrf", "server-side request forgery", "url fetch",
             "internal url", "outbound request", "callback",
             "metadata service", "url parser", "redirect to internal",
             "fetch a url", "url"],
    "csrf": ["csrf", "cross-site request forgery", "csrf token",
             "origin header", "referer header", "same-site", "anti-forgery"],
    "authn": ["authentication", "password", "login", "mfa", "multi-factor",
              "credential stuffing", "session fixation", "password policy",
              "password blocklist", "account lockout", "login throttl",
              "user enumeration", "failed login", "brute-force protection",
              "passwordless", "two-factor", "passwords", "blocklist",
              "authentication functionality", "re-authentication",
              "single sign-on", "authenticator", "timing",
              "certificate authentication", "encrypted transport",
              "passwordless authentication"],
    "authz": ["authorization", "permission", "access control", "idor", "bola",
              "privilege", "role", "access policy", "object-level",
              "function-level", "insecure direct object"],
    "session": ["session", "session id", "cookie", "cookie flag", "httponly",
                "secure flag", "samesite", "session management"],
    "oauth": ["oauth", "oidc", "openid", "redirect_uri", "scope", "pkce",
              "authorization code", "token endpoint", "saml",
              "openid connect"],
    "jwt": ["jwt", "claim", "signature", "alg", "hs256", "rs256", "none alg",
            "kid", "token verification"],
    "idor": ["idor", "bola", "insecure direct object reference", "object id",
             "sequential id", "uuid", "horizontal privilege",
             "ownership check"],
    "cmd": ["command injection", "os command", "shell", "backticks",
            "exec(", "system(", "command execution", "code injection"],
    "path_traversal": ["path traversal", "directory traversal", "lfi", "rfi",
                       "file inclusion", "../", "path normalisation",
                       "path normalization", "null byte"],
    "file_upload": ["file upload", "upload", "webshell", "file type",
                    "content-type", "multipart"],
    "mass_assign": ["mass assignment", "excessive data", "extra field",
                    "property binding", "json binding", "over-posting"],
    "misconfig": ["misconfiguration", "misconfigured",
                  "default configuration", "default credential", "hardening",
                  "exposed admin", "insecure default",
                  "security configuration", "permissive acl",
                  "world-writable", "default install"],
    "info_disclosure": ["information disclosure", "information leak",
                        "verbose error", "error message", "stack trace",
                        "metadata", "directory listing", "disclosure",
                        "banner", "version disclosure", "does not indicate",
                        "successful exploitation", "investigated via",
                        "exploit is not published", "vendor advisory"],
    "subdomain_takeover": ["subdomain takeover", "takeover", "dangling cname",
                           "dangling dns", "unclaimed", "decommissioned",
                           "custom domain", "paas provider", "zone takeover",
                           "subdomain", "cname"],
    "open_redirect": ["open redirect", "redirect parameter", "redirect_uri",
                      "unvalidated redirect", "url parameter redirect"],
    "ssti": ["ssti", "template injection", "server-side template", "jinja",
             "twig", "template engine"],
    "deser": ["deserialization", "deserialisation", "unmarshal", "pickle",
              "serialized object", "java serialization", "gadget"],
    "xxe": ["xxe", "xml external entity", "external entity", "dtd",
            "xml parser"],
    "cors": ["cors", "access-control-allow-origin", "cross-origin resource",
             "allow-credentials", "preflight"],
    "smuggling": ["request smuggling", "http desync", "desync",
                  "transfer-encoding", "content-length",
                  "http/1.1 pipelining", "desynchronisation"],
    "cache_poisoning": ["cache poisoning", "web cache", "cache key",
                        "cache deception", "cache", "poison"],
    "cache_deception": ["cache deception", "path normalization", "cache key",
                        "web cache", "deception"],
    "clickjacking": ["clickjacking", "ui redressing", "frame-options",
                     "iframe", "frame-ancestors"],
    "crlf": ["crlf", "header injection", "carriage return", "line feed",
             "response splitting"],
    "prototype_pollution": ["prototype pollution", "merge", "__proto__",
                            "pollution", "recursive merge"],
    "nosql": ["nosql", "mongodb", "operator injection", "document query",
              "graphql injection"],
    "race": ["race condition", "toctou", "race", "concurrency",
             "time-of-check"],
    "graphql": ["graphql", "introspection", "query depth",
                "field resolution", "batch query"],
    "host_header": ["host header", "host header injection", "absolute url",
                    "x-forwarded-host", "virtual host", "host validation",
                    "reset link", "password reset"],
    "supply_chain": ["supply chain", "dependency", "sast", "sbom",
                     "typosquatting", "package", "vulnerable dependency",
                     "outdated dependency"],
    "websocket": ["websocket", "ws://", "wss://", "handshake", "frame"],
    "api_trust": ["api trust", "service to service", "api gateway",
                      "trust boundary", "internal api", "service mesh", "mtls",
                      # MEASURED (T30): these 5 terms were absent while the class
                      # held 5 items OFF_CLASS_TOPIC that were its OWN knowledge.
                      # `assess()` short-circuits on the filed class's own
                      # vocabulary, so a class whose vocabulary is thinner than its
                      # corpus has that corpus misfiled by whichever competitor
                      # matched a GENERIC phrase -- here "access token" ->
                      # windows_privesc_token, "access policy" -> authz,
                      # "x-forwarded-host" -> host_header.  Each term below was
                      # then measured IN ISOLATION against all 1799 items
                      # (tools/w12_term_by_term.py): each frees held api_trust
                      # knowledge and misfiles nothing anywhere.
                      #
                      # Deliberately ABSENT, each measured to misfile real
                      # knowledge in another class:
                      #   "resource server"   -> oauth.test.token_audience_confusion
                      #   "service account"   -> pass_the_hash.auto.t.c506c349
                      #   "client credential" -> oauth.signal.implicit_grant
                      "audience claim", "cross-audience", "service credential",
                      "per-application", "forwarding header"],
    "bizlogic": ["business logic", "workflow", "invariant", "coupon",
                 "negative quantity", "applied twice", "price manipulation",
                 "state machine"],
    "lateral_movement": ["lateral movement", "pivot", "pass the hash",
                         "remote execution", "smb share", "psexec",
                         "credential reuse", "internal pivot", "hop"],
    "tunneling_pivoting": ["tunnel", "pivot", "proxy", "socks",
                           "port forward", "chisel", "ligolo", "ssh tunnel",
                           "pivoting"],
    "buffer_overflow": ["buffer overflow", "stack overflow", "heap overflow",
                        "buffer", "binary exploitation", "canary", "rop",
                        "aslr", "memory corruption", "format string"],
}

# Sentence shapes that describe a whole course or module rather than one
# technique. Unpromotable wherever they appear: they name no mechanism, so no
# disproof can refute them and no signal can justify them.
MODULE_FILLER_RE = re.compile(
    r"^\s*(we (will|are going to|discuss|cover|be covering)"
    r"|this (module|course|section|chapter) (covers|outlines|discusses)"
    r"|(identify|exploit),? and prevent"
    r"|in this (module|course|section)"
    r"|this (module|section) (discusses|covers)"
    r"|this module is part of"
    r"|this (will make us|exposes enterprises))",
    re.I,
)

_WORD = re.compile(r"[a-z0-9]+")

# Punctuation-only terms like "../" or "*/" carry no alphanumeric tokens, so a
# tokenizer-only matcher can NEVER match them. MEASURED: the term "../" was in
# the path_traversal vocabulary and matched nothing, which contributed to the
# ORPHAN false-positive rate below. Such terms are matched literally instead.
_LITERAL_TERMS: set[str] = {"../", "*/", "./", "..\\"}

# Crude but sufficient inflection fold: the corpus writes "overflows" where the
# registry says "overflow", and "passwords" where it says "password".
_SUFFIX = r"(?:s|es|d|ed|ing)?"


def _normalise(text: str) -> str:
    """Fold the shapes that make an exact substring test miss real prose."""
    t = unicodedata.normalize("NFKC", text or "")
    t = t.replace("\u2019", "'").replace("\u2018", "'")
    t = t.replace("\u201c", '"').replace("\u201d", '"')
    t = t.lower()
    t = re.sub(r"[`*_#>|\[\]()]", " ", t)
    t = re.sub(r"[^a-z0-9\s.\-/']", " ", t)
    return re.sub(r"\s+", " ", t).strip()


def _term_pattern(term: str) -> str:
    """Space/punctuation-insensitive, stemmed, word-bounded.

    "user enumeration" also matches "user-enumeration"; "overflow" also
    matches "overflows"; and neither matches "buffered".
    """
    if term in _LITERAL_TERMS:
        return re.escape(term)
    words = _WORD.findall(term)
    if not words:
        return ""
    parts = []
    for i, w in enumerate(words):
        parts.append(re.escape(w) + (_SUFFIX if i == len(words) - 1 else ""))
    return r"[^a-z0-9]".join(parts)


@lru_cache(maxsize=4096)
def _compiled_term_pattern(term: str):
    """The word-bounded pattern for one term, compiled ONCE.

    MEASURED DEFECT: this used to build the pattern with `re.search(p, text)`
    inside the per-term loop, so the SAME pattern was re-compiled once per
    item. `re._MAXCACHE` is 512 and this vocabulary holds ~900 distinct
    patterns, so the cache thrashed and every call recompiled: `assess_all`
    over the corpus took 64s, and a single hunt cycle HANGS on it (measured:
    exit 124, zero stdout, faulthandler parked in `re/_parser.py`).
    Compiling once per term took the same work to 9s.
    """
    pat = _term_pattern(term)
    return re.compile(r"(?<![a-z0-9])" + pat + r"(?![a-z0-9])") if pat else None


def _hits(text: str, terms: list[str]) -> list[str]:
    out = []
    for term in terms:
        rx = _compiled_term_pattern(term)
        if rx is not None and rx.search(text):
            out.append(term)
    return out


def _weight(term: str) -> int:
    """A multi-word term is decisive; a single generic word is weak evidence."""
    return 2 if len(_WORD.findall(term)) > 1 or term in _LITERAL_TERMS else 1


def _score(hits: list[str]) -> int:
    return sum(_weight(h) for h in hits)


@dataclass
class Verdict:
    state: str
    filed_class: str
    own_hits: list[str] = field(default_factory=list)
    best_class: str | None = None
    best_hits: list[str] = field(default_factory=list)
    margin: int = 0
    module_filler: bool = False

    @property
    def holds(self) -> bool:
        """True only when this item must not be promoted as filed."""
        return self.state in TERMINAL_STATES

    @property
    def tag(self) -> str | None:
        """The GATE TAG for this verdict, or None if it does not block.

        MEASURED BUG, and the same trap `quality.assess` already documents for
        itself: the state name and the gate tag are NOT the same string. The
        state is `MISFILED`; the tag the gate matches on is `OFF_CLASS_TOPIC`.
        Appending `self.state` therefore produced a reason the gate silently
        ignored, and 13 of 14 held `exposed_rmm` items stayed high_confidence
        while looking held to any auditor reading the relevance output. A
        verdict that blocks nothing is worse than no verdict.
        """
        return {MISFILED: "OFF_CLASS_TOPIC", MODULE_FILLER: "MODULE_FILLER"}.get(
            self.state)

    def reason(self) -> str | None:
        if self.state == MISFILED:
            return (f"OFF_CLASS_TOPIC: claim matches {self.best_class!r} on "
                    f"{self.best_hits} (weight {self.margin} >= "
                    f"{MISFILED_SCORE}) while filed under {self.filed_class!r}, "
                    f"which is not a declared sibling")
        if self.state == ORPHAN:
            return ("NO_CLASS_EXPLAINS: claim is filed under "
                    f"{self.filed_class!r} but matches no class in the "
                    f"relevance registry, so no methodology can be taught "
                    f"from it")
        if self.state == MODULE_FILLER:
            return ("MODULE_FILLER: claim describes a course or module, not a "
                    "technique")
        return None

    def to_dict(self) -> dict:
        return {"state": self.state, "filed_class": self.filed_class,
                "own_hits": self.own_hits, "best_class": self.best_class,
                "best_hits": self.best_hits, "margin": self.margin,
                "module_filler": self.module_filler, "holds": self.holds}


def assess(class_id: str, text: str) -> Verdict | None:
    """Return a Verdict, or None when the registry has no opinion.

    None means UNPROBEABLE and the caller must never hold the item on this
    basis. Silence is correct when the registry has no opinion.
    """
    if not text or class_id in PROCESS_CLASSES:
        return None
    own_terms = CLASS_VOCAB.get(class_id)
    if not own_terms:
        return None
    norm = _normalise(text)
    own_hits = _hits(norm, own_terms)
    filler = bool(MODULE_FILLER_RE.match(norm))
    sibs = siblings_of(class_id)

    if filler:
        # Checked BEFORE the own-vocabulary shortcut: "This module covers the
        # most common attacks … web application sessions" contains web
        # vocabulary and would otherwise pass as web knowledge.
        return Verdict(MODULE_FILLER, class_id, own_hits, None, [], 0, True)

    if own_hits:
        # The filed class explains the claim. Never hold on a hit: vocabulary
        # overlap alone is not proof of misfiling, and this is the branch that
        # protects genuine knowledge from the gate.
        return Verdict(ON_TOPIC, class_id, own_hits, None, [], _score(own_hits),
                       False)

    best_class, best_hits, best_score = None, [], 0
    for cid, terms in CLASS_VOCAB.items():
        if cid == class_id or cid in PROCESS_CLASSES:
            continue
        h = _hits(norm, terms)
        if _score(h) > best_score:
            best_class, best_hits, best_score = cid, h, _score(h)

    if best_score == 0:
        # MEASURED: this branch was ~70% FALSE POSITIVE on the real corpus.
        # Its 117 held items included textbook SQLi, XSS, path-traversal and
        # IDOR knowledge ("Two concurrent read-modify-writes on a balance or
        # quantity field let one thread's write silently clobber the other's")
        # that simply phrased itself without any registry term. Holding on
        # absence is the exact unsound design this module's own docstring
        # rejects, so ORPHAN ANNOTATES and is reported for vocabulary repair
        # instead of blocking promotion. Absence of vocabulary is not evidence
        # of misfiling.
        return Verdict(ORPHAN, class_id, own_hits, None, [], 0, False)
    if best_class in sibs:
        # Declared neighbours overlap by design; a sibling explaining the claim
        # better is ambiguity, not misfiling.
        return Verdict(SIBLING, class_id, own_hits, best_class, best_hits,
                       best_score, False)
    if best_score >= MISFILED_SCORE:
        return Verdict(MISFILED, class_id, own_hits, best_class, best_hits,
                       best_score, False)
    return Verdict(AMBIGUOUS, class_id, own_hits, best_class, best_hits,
                   best_score, False)


# --------------------------------------------------------------------------
# SELFTEST — the validity contract. Exits non-zero on ANY wrong verdict, in
# either direction. Run before believing any rejection rate.
# --------------------------------------------------------------------------
# (class_id, text, expected_state, why_it_matters)
SELFTEST: list[tuple[str, str, str, str]] = [
    # --- GENUINE: MUST NOT be held. This battery is the guard against the
    #     false-negative failure mode that made the quote matcher unusable. ---
    ("dns_enum", "An AXFR zone transfer returns the entire record set of the zone from a nameserver", "ON_TOPIC", "core dns_enum knowledge"),
    ("dns_enum", "SRV records recovered from a zone dump enumerate service locations", "ON_TOPIC", "service discovery via DNS"),
    ("dns_enum", "A wildcard DNS record hides undeclared hostnames from certificate transparency", "ON_TOPIC", "cross-source recon inference"),
    ("dns_enum", "Subdomain bruteforce against a wildcard zone returns the same address for every name, so the wildcard must be identified before the results are believed", "ON_TOPIC", "a wildcard must be ruled out before enumeration is believed"),
    ("dns_enum", "The zone must be checked against the certificate SAN list before a name is believed", "ON_TOPIC", "cross-source corroboration inside dns_enum"),
    ("subdomain_takeover", "An unclaimed CNAME to a decommissioned PaaS provider grants account takeover of the zone", "ON_TOPIC", "MUST-NOT-REJECT: no 'takeover' token in the prose"),
    ("exposed_rmm", "An internet-exposed RMM agent such as ScreenConnect, VNC or RustDesk on a public IP is a finding", "ON_TOPIC", "canonical RMM recon"),
    ("exposed_rmm", "Restricting the ScreenConnect server to an allowlist defeats internet exposure of the remote management agent", "ON_TOPIC", "defensive RMM framing"),
    ("service_enumeration", "A port sweep enumerates listening services and their banners across a range", "ON_TOPIC", "canonical service enumeration"),
    ("exposed_services", "An exposed RDP service with network level authentication disabled is exploitable", "ON_TOPIC", "SIBLING case: rdp explains it too, which must NOT be misfiling"),
    ("exposed_services", "A service banner discloses the exact product version, guiding the attacker to a known version-specific exploit", "ON_TOPIC", "banner leak is exposed-services knowledge"),
    ("exposed_services", "An exposed RDP service with network level authentication disabled is exploitable", "ON_TOPIC", "stemmed duplicate of the sibling case"),
    ("internal_recon", "Internal host discovery in a segmented subnet determines what can be pivoted to", "ON_TOPIC", "internal recon"),
    ("ad_enumeration", "LDAP rootDSE and NetBIOS name discovery enumerate domain controllers", "ON_TOPIC", "AD recon"),
    ("ad_enumeration", "SPN enumeration identifies service accounts worth roasting once the domain is enumerated", "ON_TOPIC", "AD enumeration"),
    ("xss", "A DOM XSS sink in innerHTML executes attacker script in the victim browser", "ON_TOPIC", "web class unaffected"),
    ("sqli", "A boolean-based blind SQL injection is confirmed by a differing response between and 1=1 and and 1=2", "ON_TOPIC", "web class unaffected"),
    ("misconfig", "A default configuration exposes an administrative interface to the internet", "ON_TOPIC", "misconfig recon"),
    ("ldap_enum", "The LDAP rootDSE namingContext confirms the domain suffix for enumeration", "ON_TOPIC", "LDAP recon"),
    ("smb", "Null session access to an SMB share permits unauthenticated share enumeration", "ON_TOPIC", "SMB recon"),
    ("segmentation_analysis", "A firewall ACL that permits east-west traffic defeats segmentation between segments", "ON_TOPIC", "segmentation"),
    ("authn", "Login throttling on the account rather than the source IP defeats user enumeration via timing", "ON_TOPIC", "the very vocabulary that was off-topic under exposed_rmm"),
    ("authn", "Processing time differs between a wrong username and a wrong password, allowing an attacker to distinguish the two", "ON_TOPIC", "timing-based user enumeration"),
    ("host_header", "An unvalidated host header lets an attacker poison the absolute URL in a generated password reset link", "ON_TOPIC", "host header"),
    ("ssrf", "A URL fetch parameter reaching a metadata service link is a server-side request forgery", "ON_TOPIC", "SSRF"),
    ("info_disclosure", "A verbose error discloses a stack trace including the internal path", "ON_TOPIC", "info disclosure"),
    ("info_disclosure", "A version banner in an HTTP response header discloses the software build to an attacker", "ON_TOPIC", "version disclosure"),
    ("lateral_movement", "Credential reuse from a compromised host enables lateral movement via SMB share access", "ON_TOPIC", "lateral movement"),
    ("winrm", "WinRM on 5985 without message encryption allows an attacker to execute commands", "ON_TOPIC", "winrm"),
    ("rdp", "Disabling NLA on an exposed RDP service permits unauthenticated session establishment", "ON_TOPIC", "RDP"),
    ("jwt", "Accepting alg=none or verifying the HS256 signature with the RS256 public key lets an attacker forge a token", "ON_TOPIC", "JWT"),
    ("csrf", "A state-changing endpoint that accepts a POST without a CSRF token is vulnerable to cross-site request forgery", "ON_TOPIC", "CSRF"),
    ("oauth", "An unvalidated redirect_uri in the authorization request leaks the authorization code to an attacker-controlled host", "ON_TOPIC", "OAuth"),
    ("cmd", "A shell metacharacter passed to exec() achieves OS command injection", "ON_TOPIC", "command injection"),
    ("idor", "A sequential object id with no ownership check is an insecure direct object reference", "ON_TOPIC", "IDOR"),

    # --- MEASURED REAL CORPUS DEFECTS: MUST be held. If this battery passes
    #     while these do not, the check is dead in the direction that matters. ---
    ("exposed_rmm", "Screening passwords against blocklists helps prevent users from selecting passwords that are commonly used", "MISFILED", "measured: 82.6% of exposed_rmm is password prose"),
    ("exposed_rmm", "Incorrectly implemented error messages in the case of authentication functionality can be used for the purposes of user ID and password enumeration", "MISFILED", "measured offender"),
    ("exposed_rmm", "Avoid requiring periodic password changes; instead, encourage users to pick strong passwords and enable Multifactor Authentication Cheat Sheet", "MISFILED", "measured offender"),
    ("exposed_rmm", "Additionally, if the client is behind an enterprise proxy that performs SSL/TLS decryption, this will break certificate authentication unless the site", "MISFILED", "measured offender: login-cheat-sheet prose"),
    ("exposed_rmm", "This section outlines when and how to trigger re-authentication to protect users and prevent unauthorized access.", "MODULE_FILLER", "measured offender: section-scoping prose, held as module filler — more precise than MISFILED and equally held"),
    ("exposed_rmm", "While UAF focuses on passwordless authentication, U2F allows the addition of a second factor to existing password-based authentication.", "MISFILED", "measured offender: login-cheat-sheet prose"),
    ("dns_enum", "An XSS vulnerability may allow an attacker to execute arbitrary JavaScript code within the target's browser", "MISFILED", "measured: 63.6% of dns_enum"),
    ("dns_enum", "Buffer overflows are common vulnerabilities in software applications that can be exploited to achieve remote code execution", "MISFILED", "measured offender (also the stemming case)"),
    ("dns_enum", "Kerberos is an authentication protocol that allows users to authenticate and access services on a potentially insecure network", "MISFILED", "measured offender"),
    ("dns_enum", "SQL injection is a code injection technique used to take advantage of coding vulnerabilities and inject SQL queries", "MISFILED", "measured offender"),
    ("dns_enum", "Binary exploitation is a core tenet of penetration testing, but learning it can be daunting", "MISFILED", "measured offender"),
    ("service_enumeration", "Comprehensive device discovery will allow them to fully understand the attack surface and any exploitable entry points.", "SIBLING", "measured offender, but 'attack surface' is a sibling term — KEPT, and that is a known miss"),
    ("service_enumeration", "If an exploit is not published, organizations may need to investigate via other means including software bills of materials", "MISFILED", "measured offender"),
    ("misconfig", "the attacker sends an HTTP request to the NetScaler device with a dropper command encoded as Base64 text in the User-Agent string", "ORPHAN", "measured NetScaler exploit chain: nothing in the registry owns attacker tooling prose, so annotate"),
    ("misconfig", "the attacker sends crafted DTLS traffic to a vulnerable NetScaler device, which processes the malicious packet", "ORPHAN", "measured offender"),
    ("misconfig", "The grep -q guard prevents duplicate injection if the persistence mechanism is run again", "ORPHAN", "measured offender: attacker tooling prose"),
    ("misconfig", "They should be seen as general hunting guidance until more is known about the exploitation activity identified by Citrix in their advisory.", "ORPHAN", "measured offender"),
    ("exposed_services", "It does not indicate successful exploitation on patched devices", "MISFILED", "must be HELD: info_disclosure explains it, exposed_services does not"),
    ("ad_enumeration", "We will cover how to identify, exploit, and prevent each of them through various methods", "MODULE_FILLER", "module prose that CONTAINS 'domain' — proves the filler check runs before the own-vocabulary shortcut"),

    # --- ORPHAN: ANNOTATED, never held. These are the measured false
    #     positives of the first draft: textbook knowledge that phrased itself
    #     without any registry term. They must NOT block promotion — that was
    #     ~70% wrong — but they must be reported for vocabulary repair. ---
    ("race", "Two concurrent read-modify-writes on a balance or quantity field let one thread's write silently clobber the other's, producing last-writer-wins", "ORPHAN", "correct race knowledge, no registry token: annotate, do NOT hold"),
    ("sqli", "Incrementing ORDER BY <n> until a response change appears infers the column count of the original query even when errors are suppressed", "ORPHAN", "correct SQLi knowledge, no registry token: annotate, do NOT hold"),
    ("idor", "The core test is substituting the object identifier in every carrier of the same request - path, query, body, and header", "ORPHAN", "correct IDOR knowledge, no registry token: annotate, do NOT hold"),
    ("deser", "This code does not attempt to verify the source or contents of the file before deserializing it", "ORPHAN", "correct deserialization knowledge, no registry token: annotate, do NOT hold"),
    ("service_enumeration", "As a result, it is imperative that organizations implement exposure management, which is the proactive cybersecurity approach", "ORPHAN", "process prose: nothing places it, so annotate for vocabulary repair rather than misfile"),

    # --- MODULE FILLER: unpromotable --- #
    ("dns_enum", "We will cover how to identify, exploit, and prevent each of them through various methods", "MODULE_FILLER", "module filler"),
    ("xss", "This module covers the most common attacks and vulnerabilities that can affect web application sessions", "MODULE_FILLER", "module filler containing web vocabulary"),
    ("exposed_rmm", "We will discuss how to identify, exploit, and prevent TLS attacks", "MODULE_FILLER", "module filler"),
    ("ad_ldap", "This module covers LDAP injection alongside other injection flaws", "MODULE_FILLER", "module filler inside a matching class"),
    ("ad_ntlm", "This will make us more effective as attackers and equip us to give sound recommendations to our clients", "MODULE_FILLER", "course-benefit prose, measured promoted row"),
    ("lateral_movement", "This exposes enterprises to vulnerabilities and exploitation from simple misconfigurations of services", "MODULE_FILLER", "course-benefit prose, measured held row"),

    # --- AMBIGUOUS: kept. A single weak generic foreign hit must never hold an
    #     item -- this is the case that protects a thinly-worded real claim. ---
    ("dns_enum", "The reverse proxy in front of the responder alters the answer", "AMBIGUOUS", "kept: only weak generic hits (proxy), no own hit"),
    ("ad_kerberos", "The ticket was intercepted", "ON_TOPIC", "kept: 'ticket' is an own hit, so ON_TOPIC short-circuits before any foreign comparison"),
]


def selftest(verbose: bool = True) -> tuple[bool, list[str]]:
    failures: list[str] = []
    for class_id, text, expected, why in SELFTEST:
        v = assess(class_id, text)
        got = v.state if v else "UNPROBEABLE"
        if got != expected:
            failures.append(
                f"{class_id}: expected {expected}, got {got} -- {why}\n"
                f"    text: {text[:110]}")
    for cid in ("not_a_real_class", "exposure_management"):
        if assess(cid, "anything at all here") is not None:
            failures.append(f"{cid}: expected None (unprobeable), got a verdict")

    # INVARIANT, not a case list: a terminal state may never be reachable by
    # ABSENCE of evidence. ORPHAN means "no class matched", so it must never
    # hold -- otherwise this gate becomes the quote matcher, which manufactured
    # false negatives until its verdicts were ignored (R17). Asserted over the
    # whole battery, so adding an ORPHAN case cannot silently make it terminal.
    if ORPHAN in TERMINAL_STATES or SIBLING in TERMINAL_STATES \
            or AMBIGUOUS in TERMINAL_STATES or ON_TOPIC in TERMINAL_STATES:
        failures.append(
            f"INVARIANT BROKEN: terminal states are {TERMINAL_STATES}; only "
            f"positive-evidence states {('MISFILED', 'MODULE_FILLER')} may hold")
    for class_id, text, expected, why in SELFTEST:
        v = assess(class_id, text)
        if v is None:
            continue
        if v.state in (ORPHAN, SIBLING, AMBIGUOUS, ON_TOPIC) and v.holds:
            failures.append(
                f"INVARIANT BROKEN: {class_id} verdict {v.state} reports "
                f"holds=True -- absence-based states must never block")

    if verbose:
        total = len(SELFTEST) + 2
        print(f"wks.relevance selftest: {total - len(failures)}/{total} "
              f"verdicts correct")
        for f in failures:
            print("  FAIL " + f)
        if not failures:
            print("  all genuine items kept; measured corpus defects held")
            print("  sibling overlap reads as SIBLING, not MISFILED")
            print("  ORPHAN annotates and never blocks promotion")
            print("  module filler checked before own-vocabulary shortcut")
            print(f"  terminal states = {TERMINAL_STATES} "
                  f"(positive evidence only)")
    return (not failures), failures


# --------------------------------------------------------------------------
# Corpus-level audit
# --------------------------------------------------------------------------

def db_path(root: str | None = None) -> str:
    return os.path.join(root or os.environ.get("WKS_ROOT", ""), "db", "wks.db")


def audit(root: str | None = None, as_json: bool = False) -> dict:
    """Scan every active item; report the ones that must not be promoted."""
    db = db_path(root)
    if not os.path.exists(db):
        raise SystemExit(f"no db at {db} -- set WKS_ROOT")
    con = sqlite3.connect(db)
    con.row_factory = sqlite3.Row
    rows = con.execute(
        "select i.item_key, i.class_id cid, i.claim, q.validation_state vs "
        "from item i left join quality q on q.item_id=i.id "
        "where i.status='active'").fetchall()
    holds, annotate, probed = [], [], 0
    by_state: dict[str, int] = {}
    for r in rows:
        v = assess(r["cid"], r["claim"])
        if v is None:
            continue
        probed += 1
        rec = {"item_key": r["item_key"], "class_id": r["cid"],
               "validation_state": r["vs"], "state": v.state,
               "best_class": v.best_class, "best_hits": v.best_hits,
               "claim_head": (r["claim"] or "")[:160],
               "reason": v.reason()}
        if v.holds:
            holds.append(rec)
        else:
            annotate.append(rec)
        by_state[v.state] = by_state.get(v.state, 0) + 1
    by_class: dict[str, int] = {}
    orphan_by_class: dict[str, int] = {}
    for h in holds:
        by_class[h["class_id"]] = by_class.get(h["class_id"], 0) + 1
    for a in annotate:
        if a["state"] == ORPHAN:
            orphan_by_class[a["class_id"]] = \
                orphan_by_class.get(a["class_id"], 0) + 1
    out = {"items": len(rows), "probed": probed,
           "held_for_relevance": len(holds),
           "held_pct_of_probed": (round(100.0 * len(holds) / probed, 1)
                                  if probed else 0.0),
           "annotated": len(annotate),
           "orphans_awaiting_vocab": sum(orphan_by_class.values()),
           "held_by_state": by_state,
           "held_by_class": dict(sorted(by_class.items(), key=lambda kv: -kv[1])),
           "orphans_by_class": dict(sorted(orphan_by_class.items(),
                                           key=lambda kv: -kv[1])),
           "held_items": holds,
           "orphan_items": [a for a in annotate if a["state"] == ORPHAN]}
    if as_json:
        print(json.dumps(out, indent=2))
        return out
    print(f"items={out['items']} probed={probed}")
    print(f"HELD (blocks promotion)   = {out['held_for_relevance']} "
          f"({out['held_pct_of_probed']}% of probed)")
    print(f"ANNOTATED (not blocking)  = {out['annotated']} "
          f"of which ORPHAN awaiting vocabulary repair = "
          f"{out['orphans_awaiting_vocab']}")
    print(f"by state: {by_state}")
    print()
    print(f"{'class':30} {'HELD':>6}")
    for cid, n in by_class.items():
        print(f"{cid:30} {n:6}")
    return out


def main(argv: list[str]) -> int:
    if "--selftest" in argv:
        ok, _ = selftest(verbose=True)
        return 0 if ok else 1
    if "--audit" in argv:
        audit(as_json="--json" in argv)
        return 0
    print(__doc__.strip().split("\n")[0])
    print()
    print("  --selftest   validate the gate in BOTH directions; non-zero exit "
          "on any wrong verdict")
    print("  --audit      scan every active item; report the ones that must "
          "not be promoted as filed")
    print("  --audit --json")
    return 0


if __name__ == "__main__":
    import sys
    raise SystemExit(main(sys.argv[1:]))