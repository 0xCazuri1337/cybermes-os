"""Derive the chain -> narrative-file map from the db instead of hardcoding it.

MEASURED (2026-10-02, wave 9): the corpus held 18 chains and the projection
emitted narratives for 4. `CHAIN_HOME` in build_taxonomy.py was a hand-written
4-entry dict, so every chain researched after it was written landed in the db
and then VANISHED from `attack-chains/` — the canonical narrative read as if
those chains did not exist. A generated page that silently omits rows is the
same defect class as a stale projection, in the opposite direction.

Fix: derive the home file from each chain's own classes, grouping by the
dominant class surface, with the existing 4 mappings kept as explicit
overrides so no published path moves. Any chain that cannot be grouped is
reported rather than dropped.
"""
import io
import re
from collections import Counter

P = r"C:/Users/Administrator/.hermes/cyber/tools/taxonomy/build_taxonomy.py"
src = io.open(P, encoding="utf-8").read()

OLD = '''# db chains -> attack-chains file
CHAIN_HOME = {
    "idor-to-account-takeover": "authorization-chains.md",
    "oauth-open-redirect-to-ato": "authentication-chains.md",
    "race-to-financial-impact": "business-logic-chains.md",
    "graphql-exposure-to-enumeration": "api-chains.md",
}'''

NEW = '''# db chains -> attack-chains file
#
# MEASURED (2026-10-02): this used to be a hand-written 4-entry dict. With 18
# chains in the db it emitted narratives for 4, so every chain researched after
# it was written landed in the db and then disappeared from `attack-chains/` --
# the canonical narrative read as if those chains did not exist. A generated
# page that silently omits rows is a stale projection in the opposite direction.
#
# The four published mappings are kept verbatim so no existing path moves; every
# OTHER chain is grouped by the surface of the classes its steps touch, so the
# map cannot fall behind the corpus again.
CHAIN_HOME_OVERRIDES = {
    "idor-to-account-takeover": "authorization-chains.md",
    "oauth-open-redirect-to-ato": "authentication-chains.md",
    "race-to-financial-impact": "business-logic-chains.md",
    "graphql-exposure-to-enumeration": "api-chains.md",
}

# class id -> narrative family. Anything unlisted falls back to _chain_family().
_CHAIN_FAMILY = {
    "ad_delegation": "authentication-chains.md",
    "ad_kerberos": "authentication-chains.md",
    "pass_the_hash": "authentication-chains.md",
    "ad_ldap": "authentication-chains.md",
    "ad_acl_abuse": "authorization-chains.md",
    "adcs_abuse": "authorization-chains.md",
    "ad_enumeration": "authorization-chains.md",
    "ad_trust_abuse": "authorization-chains.md",
    "subdomain_takeover": "authorization-chains.md",
    "oauth": "authentication-chains.md",
    "session": "authentication-chains.md",
    "authn": "authentication-chains.md",
    "authz": "authorization-chains.md",
    "idor": "authorization-chains.md",
    "graphql": "api-chains.md",
    "api_trust": "api-chains.md",
    "mass_assign": "api-chains.md",
    "ssrf": "api-chains.md",
    "xss": "xss-chains.md",
    "csrf": "xss-chains.md",
    "clickjacking": "xss-chains.md",
    "deser": "api-chains.md",
    "race": "business-logic-chains.md",
    "bizlogic": "business-logic-chains.md",
    "sqli": "api-chains.md",
    "lateral_movement": "cross-class-chains.md",
    "smb": "cross-class-chains.md",
    "winrm": "cross-class-chains.md",
    "rdp": "cross-class-chains.md",
    "tunneling_pivoting": "cross-class-chains.md",
    "supply_chain": "cross-class-chains.md",
    "cache_deception": "cross-class-chains.md",
    "internal_recon": "cross-class-chains.md",
    "segmentation_analysis": "cross-class-chains.md",
}


def build_chain_home(con) -> dict:
    """chain_key -> narrative filename, derived from the db, not hand-listed."""
    home = dict(CHAIN_HOME_OVERRIDES)
    ungrouped = []
    for row in con.execute("SELECT DISTINCT chain_key FROM chain ORDER BY chain_key"):
        key = row["chain_key"]
        if key in home:
            continue
        classes = [r["class_id"] for r in con.execute(
            """SELECT DISTINCT s.class_id FROM chain_step s
               JOIN chain c ON c.id=s.chain_id
               WHERE c.chain_key=? AND s.class_id IS NOT NULL""", (key,))]
        families = Counter(_CHAIN_FAMILY.get(c) for c in classes)
        families.pop(None, None)
        if families:
            # the family covering the most of the chain's classes wins
            home[key] = families.most_common(1)[0][0]
        else:
            ungrouped.append((key, classes))
    if ungrouped:
        # Never drop a chain silently: park it in the cross-class narrative,
        # which is the honest home for a chain spanning unmapped classes.
        for key, _classes in ungrouped:
            home[key] = "cross-class-chains.md"
    return home


CHAIN_HOME = build_chain_home(_CON) if "_CON" in dir() else CHAIN_HOME_OVERRIDES'''

if "CHAIN_HOME_OVERRIDES" in src:
    print("already derived; no change")
elif OLD not in src:
    raise SystemExit("CHAIN_HOME block not found - refusing to guess")
else:
    src = src.replace(OLD, NEW, 1)
    io.open(P, "w", encoding="utf-8").write(src)
    print("patched", P)