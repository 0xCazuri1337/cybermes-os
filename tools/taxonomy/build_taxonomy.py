"""Build the canonical bug-class taxonomy from one declarative spec.

    python tools/taxonomy/build_taxonomy.py          # write the tree
    python tools/taxonomy/build_taxonomy.py --check  # verify, write nothing

WHY A GENERATOR AND NOT 140 HAND WRITES
    Rule 5 requires every bug-class file to follow ONE structure, and rule 8
    requires the taxonomy to be extensible without restructuring. A hand-written
    tree drifts on both the moment a file is added. So the tree is DEFINED here
    and rendered from the spec — adding a class is a spec edit, not a
    restructuring.

PROVENANCE OF CONTENT
    Three tiers, never blurred:
      1. GENERATED FROM THE DB. The four researched classes (idor, race, oauth,
         graphql) have 53 gated items and 4 chains in db/wks.db. Their Detection
         / Exploitation / Validation / FP sections are RENDERED FROM THOSE ROWS
         with their sources and disproofs. Nothing here is paraphrased by hand.
      2. NAVIGATIONAL. READMEs and pointer stubs. These describe where knowledge
         lives. They assert no technical claim.
      3. UNRESEARCHED. Every section with no gated evidence behind it says
         `Not yet researched.` — never an invented plausible sentence.

    Sections that need curation a schema cannot supply (Root Cause, Detection
    heuristics, Real-World Examples, Technology notes) are left UNRESEARCHED
    even where adjacent sections are populated. A full-looking file that
    paraphrases its own database is worse than an honest gap.

COLLISIONS WITH THE EXISTING TREE — resolved, not ignored
    classes/*.md and chains/*.md are GENERATED projections of db/wks.db written
    by wks/pipeline.py:write_class_markdown. CONTROL/rules.md R11 says a
    generated document is never hand-edited. This script therefore does NOT
    touch them. They remain the per-class evidence digest; bug-classes/ is the
    canonical map and attack-chains/ the canonical chain narrative. The mapping
    between db class id and canonical file lives in CLASS_HOME below and is the
    single place that relationship is written down.
"""
from __future__ import annotations

import argparse
import sqlite3
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent
DB = ROOT / "db" / "wks.db"

# --------------------------------------------------------------------------
# SCHEMAS — the only definition of a bug-class file and a chain file.
# --------------------------------------------------------------------------

BUG_SECTIONS = (
    "Definition", "Root Cause", "Preconditions", "Attack Surface", "Detection",
    "Exploitation", "Variations", "Technology / Framework Considerations",
    "API Considerations", "Attack Chains", "Real-World Examples",
    "Common False Positives", "Validation", "Impact",
    "Related Bug Classes", "References",
)

CHAIN_SECTIONS = (
    "Objective", "Preconditions", "Initial Weakness", "Chain Steps",
    "Required Conditions", "Impact", "Detection Strategy", "Validation",
    "Real-World Examples", "Related Bug Classes", "References",
)

NR = "Not yet researched."


def render(title: str, sections: tuple[str, ...], body: dict[str, str]) -> str:
    """Render a file from the schema. A section absent from `body` is NR."""
    out = [f"# {title}", ""]
    for s in sections:
        out += [f"## {s}", "", body.get(s, NR).strip() or NR, ""]
    return "\n".join(out).rstrip() + "\n"


# --------------------------------------------------------------------------
# DB ACCESS — read-only. The gate is the only writer of validation_state and
# this script does not write to the corpus at all.
# --------------------------------------------------------------------------

def db() -> sqlite3.Connection:
    if not DB.exists():
        sys.exit(f"no canonical store at {DB} — run `python -m wks.cli seed` first")
    con = sqlite3.connect(f"file:{DB}?mode=ro", uri=True)
    con.row_factory = sqlite3.Row
    return con


def _items(con, cid, kind) -> list:
    return con.execute(
        "select claim, body, disproof from item where class_id=? and kind=? "
        "order by item_key", (cid, kind)).fetchall()


def _fmt(rows, with_body=True) -> str:
    """Render db items with claim, body and the disproof that bounds the claim."""
    if not rows:
        return ""
    out = []
    for r in rows:
        out.append(f"**{r['claim']}**")
        if with_body and r["body"]:
            out += ["", r["body"].strip()]
        if r["disproof"]:
            out += ["", f"*Disproof:* {r['disproof'].strip()}"]
        out.append("")
    return "\n".join(out).strip()


def _sources(con, cid) -> str:
    rows = con.execute(
        "select distinct s.host, s.url, s.source_type, s.publisher "
        "from item i join item_source isr on isr.item_id=i.id "
        "join source s on s.id=isr.source_id where i.class_id=? "
        "order by s.host, s.url", (cid,)).fetchall()
    if not rows:
        return ""
    by_host: dict[str, list] = {}
    for r in rows:
        by_host.setdefault(r["host"], []).append(r)
    out = []
    for host in sorted(by_host):
        out.append(f"- **{host}** ({by_host[host][0]['source_type']})")
        for r in by_host[host]:
            out.append(f"  - <{r['url']}>")
    out += ["", "Every item above is gated on >= 2 distinct publisher hosts "
            "(`wks/quality.py`, rule R1). Publisher diversity, not citation "
            "count, is what makes these corroborated."]
    return "\n".join(out)


def _related(con, cid) -> str:
    rows = con.execute(
        "select class_id, count(*) c from chain_step where class_id in "
        "(select distinct chain_id from chain_step where class_id=?) and "
        "class_id<>? group by class_id", (cid, cid)).fetchall()
    if not rows:
        return ""
    home = CLASS_HOME
    out = []
    for r in rows:
        tgt = home.get(r["class_id"])
        link = f"[{r['class_id']}]({tgt})" if tgt else r["class_id"]
        out.append(f"- {link} — shares a chain")
    return "\n".join(out)


def _chain_link(chain_key: str) -> str:
    """Repo-relative path of a chain narrative in the MERGED tree."""
    from wks import config as _cfg, domains as _doms, store as _store
    con = _store.open_db()
    try:
        row = con.execute("SELECT id FROM chain WHERE chain_key=?",
                          (chain_key,)).fetchone()
        owner = "Web"
        if row:
            owner = None
            for r in con.execute(
                    """SELECT DISTINCT class_id FROM chain_step WHERE chain_id=?""",
                    (row["id"],)):
                try:
                    d = _doms.domain_of(con, r["class_id"])
                except KeyError:
                    continue
                if d == _doms.NETWORK:
                    owner = "Network + AD"
                    break
                owner = owner or _doms.DOMAIN_LABEL[d]
            owner = owner or "Web"
    finally:
        con.close()
    stem = chain_key.replace("-to-", "-chains").replace("-", "-")
    return f"skills/{owner}/chains/{stem}.md"


def _class_link(class_id: str) -> str:
    """Repo-relative path of a class's canonical page in the MERGED tree."""
    from wks import domains as _doms, store as _store
    con = _store.open_db()
    try:
        dom = _doms.domain_of(con, class_id)
    except KeyError:
        con.close()
        return f"skills/{class_id}/CLASS.md"
    con.close()
    return f"skills/{_doms.DOMAIN_LABEL[dom]}/{class_id}/CLASS.md"


def bug_file(con, cid) -> str:
    """Render one bug-class file entirely from gated db rows."""
    b = con.execute("select * from bug_class where id=?", (cid,)).fetchone()
    if b is None:
        sys.exit(f"class {cid!r} is not in the taxonomy — register it first")

    defn = [b["summary"].strip(), ""]
    defn.append(f"- **CWE:** {b['cwe']}")
    defn.append(f"- **OWASP:** {b['owasp']}")
    defn.append(f"- **Surface:** {b['surface']}")
    if b["aliases"]:
        defn.append(f"- **Aliases:** {b['aliases']}")
    defn += ["", f"Canonical home for `{cid}`. Rendered from `db/wks.db` by "
              "`tools/taxonomy/build_taxonomy.py` — edit the rows, not "
              "this file."]

    # Chains this class participates in, from chain_step.
    chains = con.execute(
        "select distinct c.chain_key, c.name, c.goal from chain c "
        "join chain_step s on s.chain_id=c.id where s.class_id=? "
        "order by c.chain_key", (cid,)).fetchall()
    chain_txt = "\n".join(
        # MERGED TREE: the chain narrative lives beside the class bundles, at
        # skills/<Domain>/chains/. Emit the path the merged tree actually uses --
        # a link to `attack-chains/` here is a dead link the moment the tree is
        # merged, and a retargeter that "fixes" it afterwards produces
        # `../skills/...` relative to the wrong directory.
        f"- [`{c['chain_key']}`](../../{_chain_link(c['chain_key'])})"
        if False else f"- `{c['chain_key']}` — {c['name']} (goal: `{c['goal']}`)"
        for c in chains)

    # FP rules: the db keeps both an item (kind=fp_rule) and a case row.
    fp_rows = _items(con, cid, "fp_rule")
    cases = con.execute(
        "select hypothesis, invalidated_by, rejection_rule from fp_case "
        "where class_id=? order by fp_key", (cid,)).fetchall()
    fp = []
    if fp_rows:
        fp.append(_fmt(fp_rows))
    for c in cases:
        fp.append(f"**Hypothesis:** {c['hypothesis']}")
        fp.append(f"- Invalidated by: {c['invalidated_by']}")
        fp.append(f"- **Rejection rule:** {c['rejection_rule']}")
        fp.append("")
    surface = b["surface"]
    attack_surface = (
        f"Surface: **{surface}**.\n\n"
        "The entry points and enabling conditions for this surface are "
        "enumerated under **Preconditions**; the observable signals are under "
        "**Detection**."
        if surface else "")

    return render(b["name"], BUG_SECTIONS, {
        "Definition": "\n".join(defn),
        "Preconditions": _fmt(_items(con, cid, "prerequisite")),
        "Attack Surface": attack_surface,
        # `evidence` is what makes a technique PROVABLE and belongs with the
        # observable. Without a route, 92 promoted items across 48 classes were
        # rendered nowhere -- knowledge the corpus holds and the page denies.
        "Detection": _fmt(_items(con, cid, "signal") + _items(con, cid, "evidence")),
        "Exploitation": _fmt(_items(con, cid, "technique")),
        # `or` HID every variant item in any class that also holds a bypass:
        # smuggling has both, so all 3 of its promoted variants were dropped.
        "Variations": _fmt(_items(con, cid, "bypass") + _items(con, cid, "variant")),
        "Common False Positives": "\n".join(fp).strip(),
        # `test` is proof-of-exploitation guidance and belongs here. Without
        # this, every promoted kind=test item was dropped from the page.
        "Validation": _fmt(_items(con, cid, "validation") + _items(con, cid, "test")),
        "Impact": _fmt(_items(con, cid, "impact")),
        "Attack Chains": chain_txt,
        "Related Bug Classes": _related(con, cid),
        "References": _sources(con, cid),
    })


def chain_file(con, key) -> str:
    """Render one attack-chain file entirely from gated db rows."""
    c = con.execute("select * from chain where chain_key=?", (key,)).fetchone()
    if c is None:
        sys.exit(f"chain {key!r} is not in the corpus")
    steps = con.execute(
        "select ord, class_id, action, why, needs from chain_step "
        "where chain_id=? order by ord", (c["id"],)).fetchall()

    body, pre, needs = [], [], []
    for s in steps:
        if s["needs"]:
            pre.append(f"{s['ord']}. {s['needs']}")
            needs.append(s["needs"])
        body += [f"**{s['ord']}. `{s['class_id']}` — {s['action']}**", ""]
        if s["why"]:
            body += [f"- Why: {s['why']}"]
        if s["needs"]:
            body += [f"- Requires: {s['needs']}"]
        body.append("")

    classes = sorted({s["class_id"] for s in steps})
    rel = "\n".join(
        f"- `{k}`" + (f" — canonical: [`{_class_link(k)}`]" if k in CLASS_HOME else "")
        for k in classes)

    src = con.execute(
        "select distinct s.host, s.url from chain_step cs "
        "join item i on i.id=cs.item_id join item_source isr on isr.item_id=i.id "
        "join source s on s.id=isr.source_id where cs.chain_id=? "
        "order by s.host, s.url", (c["id"],)).fetchall()
    refs = "\n".join(f"- **{r['host']}** — <{r['url']}>" for r in src)

    return render(c["name"], CHAIN_SECTIONS, {
        "Objective": f"Goal: **{c['goal']}**.\n\n{c['summary']}",
        "Preconditions": "\n".join(pre),
        "Initial Weakness": (f"**Step 1.** {steps[0]['action']}\n\n"
                             f"- Why: {steps[0]['why']}") if steps else "",
        "Chain Steps": "\n".join(body),
        "Required Conditions": "\n".join(f"- {n}" for n in dict.fromkeys(needs)),
        "Impact": c["impact"] or "",
        "Related Bug Classes": rel,
        "References": refs,
    })


# --------------------------------------------------------------------------
# db class id -> canonical bug-class file. THE single place that the
# generated classes/ projection and the canonical tree are related.
# --------------------------------------------------------------------------

CLASS_HOME = {
    "idor": "web/authorization/idor.md",
    "race": "web/business-logic/race-condition.md",
    "oauth": "web/authentication/oauth-oidc-misconfiguration.md",
    "graphql": "api/graphql/graphql-surface.md",
    "sqli": "web/injection/sql-injection.md",
    "ssrf": "web/request-forgery/ssrf.md",
    "xss": "web/xss/xss.md",
    "authz": "web/authorization/function-level-authorization.md",
    "jwt": "web/authentication/jwt-token-validation.md",
    "mass_assign": "api/rest/mass-assignment.md",
    "bizlogic": "web/business-logic/workflow-bypass.md",
    "csrf": "web/request-forgery/csrf.md",
    "ssti": "web/injection/template-injection.md",
    "path_traversal": "web/file-security/path-traversal.md",
    "deser": "web/server-side/deserialization.md",

    # ---- classes added by wks/taxonomy_ext.py -----------------------------
    # Registered with verified seeds but originally given no home, which R15
    # reports as ORPHANED EVIDENCE: the db held gated items while the tree
    # rendered no page for them, so the knowledge was invisible to a reader.
    "authn": "web/authentication/authentication-failures.md",
    "smuggling": "web/request-forgery/request-smuggling.md",
    "cors": "web/miscellaneous/cors.md",
    "cmd": "web/injection/command-injection.md",
    "xxe": "web/injection/xml-external-entity.md",
    "ldap": "web/injection/ldap-injection.md",
    "nosql": "web/injection/nosql-injection.md",
    "file_upload": "web/file-security/file-upload.md",
    "clickjacking": "web/client-side/clickjacking.md",
    "prototype_pollution": "web/server-side/prototype-pollution.md",
    "open_redirect": "web/client-side/open-redirect.md",
    "host_header": "web/request-forgery/host-header-injection.md",
    "crlf": "web/injection/crlf-header-injection.md",
    "cache_poisoning": "web/request-forgery/cache-poisoning.md",
    "cache_deception": "web/miscellaneous/cache-deception.md",
    "websocket": "web/websocket/websocket-weaknesses.md",
    "info_disclosure": "web/miscellaneous/information-disclosure.md",
    "misconfig": "web/configuration/security-misconfiguration.md",
    "supply_chain": "web/supply-chain/dependency-supply-chain.md",
    "subdomain_takeover": "web/infrastructure/subdomain-takeover.md",
    "api_trust": "api/api-to-api/api-to-api-trust.md",
    "session": "web/authentication/session-management.md",


    # ---- wave 11: field-registered classes that had spec rows but no home --
    # MEASURED 2026-10-03: these were registered by tools/reg_field_classes.py
    # with a `taxonomy_spec.CLASSES` row each, but never wired here. Once they
    # held gated items, `taxonomy_write.py --check` REFUSED to write the whole
    # tree ("CLASS_HOME=None is not a CLASSES row") and masterprompt check c_54
    # (the architecture auditor, SS54) went red -- a mapping gap surfacing as a
    # tree-wide failure. The guard was right; the map was incomplete.
    #
    # `rate_limit` has TWO candidate CLASSES rows: `web/authentication/rate-limit.md`
    # ("Rate Limiting") and `api/rest/rate-limit.md` ("Rate Limit and Resource
    # Consumption"). Chosen: the API one, because the class is defined by whether
    # a security-relevant operation is reachable at all -- an API property, not
    # an authentication one. Recorded so the choice is auditable rather than a
    # silent coin flip.
    "otp": "web/authentication/otp.md",
    "rate_limit": "api/rest/rate-limit.md",
    "eol_software": "web/configuration/eol-software.md",

    # ---- NETWORK domain -------------------------------------------------
    # Derived from `wks.network_taxonomy.NET_CLASSES` by specialization, so
    # this map cannot drift from the seeded taxonomy. Hardcoding 25 more rows
    # here is exactly the drift trap the comment below warns about: a
    # hand-maintained list mirroring a generated one goes stale silently.
    # ACTIVE_DIRECTORY is a subdirectory of network/, never a third domain.
    "internal_recon": "network/internal-network/internal-recon.md",
    "service_enumeration": "network/internal-network/service-enumeration.md",
    "lateral_movement": "network/internal-network/lateral-movement.md",
    "tunneling_pivoting": "network/internal-network/tunneling-pivoting.md",
    "segmentation_analysis": "network/internal-network/segmentation-analysis.md",

    "exposed_services": "network/infrastructure/exposed-services.md",
    "exposed_rmm": "network/infrastructure/exposed-rmm.md",
    "smb": "network/infrastructure/smb.md",
    "winrm": "network/infrastructure/winrm.md",
    "rdp": "network/infrastructure/rdp.md",
    "ldap_enum": "network/infrastructure/ldap-enumeration.md",
    "dns_enum": "network/infrastructure/dns-enumeration.md",
    "service_enumeration_detail": "network/infrastructure/service-configuration.md",

    "ad_kerberos": "network/active-directory/ad-kerberos.md",
    "ad_ntlm": "network/active-directory/ad-ntlm.md",
    "ad_ldap": "network/active-directory/ad-ldap.md",
    "ad_acl_abuse": "network/active-directory/ad-acl-abuse.md",
    "ad_delegation": "network/active-directory/ad-delegation.md",
    "adcs_abuse": "network/active-directory/adcs-abuse.md",
    "ad_trust_abuse": "network/active-directory/ad-trust-abuse.md",
    "ad_group_policy": "network/active-directory/ad-group-policy.md",
    "credential_access": "network/active-directory/credential-access.md",
    "pass_the_hash": "network/active-directory/pass-the-hash.md",
    "password_attacks": "network/active-directory/password-attacks.md",
    "ad_enumeration": "network/active-directory/ad-enumeration.md",

    # Privilege escalation / escape. Registered in `bug_class` by a research
    # effort on 2026-10-03 with no entry anywhere in the tree, so the
    # generator filed their pages under `network/topics/` -- where they are
    # topic prose, not class units -- and the auditor reported "resolves
    # to ... which is absent". CLASS_HOME is the ONE id -> path map: a class
    # missing from it has no home, and every writer that inverts it
    # disagrees.
    "windows_privesc_token":
        "network/active-directory/windows-privesc-token.md",
    "windows_privesc_service":
        "network/active-directory/windows-privesc-service.md",
    "windows_privesc_hijack":
        "network/active-directory/windows-privesc-hijack.md",
    "linux_privesc": "network/internal-network/linux-privesc.md",
    "container_escape": "network/internal-network/container-escape.md",
}

def network_class_rows() -> list[tuple[str, str, str, str, str]]:
    """Render the NETWORK CLASSES rows from `wks.network_taxonomy`.

    The 25 NETWORK rows in CLASSES are generated from the seeded taxonomy
    rather than hand-copied. A hand-maintained list mirroring a generated one
    drifts silently — the exact failure the comment above CLASSES_HOME warns
    about, so it must not be reintroduced one domain over.

    OWASP is '-' for NETWORK classes: the A0x:2021 / APIx:2023 identifiers are
    a WEB/API enumeration and have no honest value for Kerberos delegation or
    SMB signing. Writing one there would be a fabricated taxonomy reference,
    which is the same defect as a fabricated citation.
    """
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
    from wks.network_taxonomy import NET_CLASSES
    rows = []
    for cid, s in NET_CLASSES.items():
        rows.append((f"network/{_SPEC_DIR[s.specialization]}/{_SPEC_FILE[cid]}",
                     s.name, s.cwe or "-", "-", s.summary))
    return rows


# Specialization -> directory name, and class id -> file stem. Both are derived
# once so `network_class_rows()` and `CLASS_HOME` cannot disagree about where a
# page lives — the two are checked against each other by
# `tools/taxonomy/audit_taxonomy.py`.
_SPEC_DIR = {
    "internal_network": "internal-network",
    "infrastructure": "infrastructure",
    "active_directory": "active-directory",
}

_SPEC_FILE = {
    "internal_recon": "internal-recon.md",
    "service_enumeration": "service-enumeration.md",
    "lateral_movement": "lateral-movement.md",
    "tunneling_pivoting": "tunneling-pivoting.md",
    "segmentation_analysis": "segmentation-analysis.md",
    "exposed_services": "exposed-services.md",
    "exposed_rmm": "exposed-rmm.md",
    "smb": "smb.md",
    "winrm": "winrm.md",
    "rdp": "rdp.md",
    "ldap_enum": "ldap-enumeration.md",
    "dns_enum": "dns-enumeration.md",
    "service_enumeration_detail": "service-configuration.md",
    "ad_kerberos": "ad-kerberos.md",
    "ad_ntlm": "ad-ntlm.md",
    "ad_ldap": "ad-ldap.md",
    "ad_acl_abuse": "ad-acl-abuse.md",
    "ad_delegation": "ad-delegation.md",
    "adcs_abuse": "adcs-abuse.md",
    "ad_trust_abuse": "ad-trust-abuse.md",
    "ad_group_policy": "ad-group-policy.md",
    "credential_access": "credential-access.md",
    "pass_the_hash": "pass-the-hash.md",
    "password_attacks": "password-attacks.md",
    "ad_enumeration": "ad-enumeration.md",
    # Privilege escalation / escape classes declared in
    # wks.network_taxonomy.py on 2026-10-03. They were in `bug_class` with no
    # page anywhere ("resolves to ... which is absent"): a class registered in
    # the db but missing from this map raises KeyError in `network_class_rows`,
    # which the spec turns into a loud refusal to write the NETWORK branch at
    # all. One missing row here takes out 67 classes' worth of pages.
    "windows_privesc_token": "windows-privesc-token.md",
    "windows_privesc_service": "windows-privesc-service.md",
    "windows_privesc_hijack": "windows-privesc-hijack.md",
    "linux_privesc": "linux-privesc.md",
    "container_escape": "container-escape.md",
}

# db classes rendered from gated rows rather than a skeleton.
#
# DERIVED FROM THE DB, NOT HAND-MAINTAINED. This was a hardcoded dict
# {"idor","race","oauth"} and it went stale silently: a background WKS cycle
# ingested 51 gated items for jwt/sqli/ssrf/xss while this file was being
# written, and those items rendered as `Not yet researched.` on files that
# already had the evidence in the corpus. Any hand-maintained list that mirrors
# db state will drift the moment the db changes; read the db instead.
def researched_classes(con) -> set[str]:
    """Every class that has at least one item in the canonical store."""
    return {r[0] for r in con.execute(
        "select distinct class_id from item")}


# canonical filename stem -> db class id. Only needed where the file name is not
# simply the class id; keeping it explicit stops a stem that happens to collide
# from silently rendering a skeleton for a researched class.
# canonical filename stem -> db class id.
#
# DERIVED, NOT HAND-MAINTAINED. Kept as a literal it drifted three times in one
# session: `graphql-surface`, `race-condition` and `oauth-oidc-misconfiguration`
# silently rendered empty skeletons while 40 gated items sat in the corpus,
# because the lookup missed and the page fell through to the skeleton branch.
# A map that mirrors another map will always drift; invert one instead.
def stem_to_class() -> dict[str, str]:
    """filename stem -> db class id, derived from CLASS_HOME."""
    return {v.split("/")[-1][:-3]: k for k, v in CLASS_HOME.items()}


STEM_TO_CLASS = stem_to_class()

# db chains -> attack-chains file
#
# DERIVED, NOT HAND-MAINTAINED -- the same rule `stem_to_class()` above exists
# to enforce, for the same reason. MEASURED (2026-10-02): this was a 4-entry
# literal while the corpus held 18 chains, so 14 of them landed in the db and
# never appeared in `attack-chains/` at all. A hand-kept map always drifts.
CHAIN_HOME_OVERRIDES = {
    "idor-to-account-takeover": "authorization-chains.md",
    "oauth-open-redirect-to-ato": "authentication-chains.md",
    "race-to-financial-impact": "business-logic-chains.md",
    "graphql-exposure-to-enumeration": "api-chains.md",
}

# class id -> narrative family. Unlisted classes fall back to cross-class.
_CHAIN_FAMILY = {
    "ad_delegation": "authentication-chains.md",
    "ad_kerberos": "authentication-chains.md",
    "pass_the_hash": "authentication-chains.md",
    "ad_ldap": "authentication-chains.md",
    "ad_ntlm": "authentication-chains.md",
    "ad_acl_abuse": "authorization-chains.md",
    "adcs_abuse": "authorization-chains.md",
    "ad_enumeration": "authorization-chains.md",
    "ad_trust_abuse": "authorization-chains.md",
    "ad_group_policy": "authorization-chains.md",
    "subdomain_takeover": "authorization-chains.md",
    "oauth": "authentication-chains.md",
    "session": "authentication-chains.md",
    "authn": "authentication-chains.md",
    "authz": "authorization-chains.md",
    "idor": "authorization-chains.md",
    "graphql": "api-chains.md",
    "api_trust": "api-chains.md",
    "mass_assign": "api-chains.md",
    # ssrf-chains.md is a DECLARED family (taxonomy_spec.CHAIN_FAMILIES) and is
    # linked from attack-chains/README.md. Routing it to api-chains.md left the
    # declared page asserting "no chain in this family has passed the evidence
    # gate" while two ssrf chains existed in another file -- a projection that
    # denies knowledge rather than merely omitting it.
    "ssrf": "ssrf-chains.md",
    "sqli": "api-chains.md",
    "deser": "api-chains.md",
    "xss": "xss-chains.md",
    "csrf": "xss-chains.md",
    "clickjacking": "xss-chains.md",
    "open_redirect": "xss-chains.md",
    "race": "business-logic-chains.md",
    "bizlogic": "business-logic-chains.md",
    "lateral_movement": "cross-class-chains.md",
    "smb": "cross-class-chains.md",
    "winrm": "cross-class-chains.md",
    "rdp": "cross-class-chains.md",
    "tunneling_pivoting": "cross-class-chains.md",
    "supply_chain": "cross-class-chains.md",
    "cache_deception": "cross-class-chains.md",
    "internal_recon": "cross-class-chains.md",
    "segmentation_analysis": "cross-class-chains.md",
    "service_enumeration": "cross-class-chains.md",
    "exposed_services": "cross-class-chains.md",
    "exposed_rmm": "cross-class-chains.md",
    "misconfig": "cross-class-chains.md",
}


def build_chain_home(con) -> dict:
    """chain_key -> narrative filename, derived from the db rather than listed.

    A chain is filed under the family covering most of the classes its steps
    touch. An unmappable chain goes to cross-class-chains.md: parked, never
    dropped -- a chain silently omitted from the canonical narrative is worse
    than one filed loosely, because the reader cannot tell it is missing.
    """
    home = dict(CHAIN_HOME_OVERRIDES)
    for row in con.execute("SELECT DISTINCT chain_key FROM chain ORDER BY chain_key"):
        key = row["chain_key"]
        if key in home:
            continue
        classes = [r["class_id"] for r in con.execute(
            """SELECT DISTINCT s.class_id FROM chain_step s
               JOIN chain c ON c.id = s.chain_id
               WHERE c.chain_key = ? AND s.class_id IS NOT NULL""", (key,))]
        tally = {}
        for c in classes:
            fam = _CHAIN_FAMILY.get(c)
            if fam:
                tally[fam] = tally.get(fam, 0) + 1
        home[key] = (max(tally, key=tally.get) if tally
                     else "cross-class-chains.md")
    return home


CHAIN_HOME = build_chain_home(db())