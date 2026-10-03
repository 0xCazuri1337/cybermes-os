"""Derive the chain -> narrative-file map from the db instead of hardcoding it.

MEASURED (2026-10-02, wave 9): the corpus held 18 chains and the projection
emitted narratives for 4. `CHAIN_HOME` in build_taxonomy.py was a hand-written
4-entry dict, so every chain researched after it was written landed in the db
and then VANISHED from `attack-chains/` -- the canonical narrative read as if
those chains did not exist. That is a stale projection in the OPPOSITE
direction: the db grew and the docs did not.

The same file already learned this lesson for class pages: `stem_to_class()`
derives a map by INVERTING another map precisely because a hand-kept literal
drifted three times in one session. This applies the same rule to chains.

The four published mappings are kept as explicit overrides so no existing path
moves; every other chain is grouped by the family of the classes its steps
touch, and anything unmapped is parked in cross-class-chains.md rather than
dropped.
"""
import io

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
    "ssrf": "api-chains.md",
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


CHAIN_HOME = build_chain_home(db())'''

if "CHAIN_HOME_OVERRIDES" in src:
    print("already derived; no change")
elif OLD not in src:
    raise SystemExit("CHAIN_HOME literal not found - refusing to guess")
else:
    src = src.replace(OLD, NEW, 1)
    io.open(P, "w", encoding="utf-8").write(src)
    print("patched", P)