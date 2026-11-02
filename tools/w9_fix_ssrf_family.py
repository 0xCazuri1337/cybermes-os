"""Route the SSRF family to its DECLARED narrative file.

`taxonomy_spec.py` declares seven chain families, one of which is
`ssrf-chains.md`, and `attack-chains/README.md` plus
`bug-classes/web/file-security/README.md` link to it. My derived `_CHAIN_FAMILY`
map sent `ssrf` to `api-chains.md`, which left `ssrf-chains.md` as an empty
skeleton claiming "No chain in this family has passed the evidence gate yet"
while TWO ssrf chains sat in api-chains.md.

That is the worst kind of projection failure: not a stale file but a file that
actively asserts the absence of knowledge that exists. The declared family is
the correct home for those chains, so the map is corrected rather than the spec.
"""
import io

P = r"C:/Users/Administrator/.hermes/cyber/tools/taxonomy/build_taxonomy.py"
src = io.open(P, encoding="utf-8").read()

OLD = '    "ssrf": "api-chains.md",'
NEW = ('    # ssrf-chains.md is a DECLARED family (taxonomy_spec.CHAIN_FAMILIES) and is\n'
       '    # linked from attack-chains/README.md. Routing it to api-chains.md left the\n'
       '    # declared page asserting "no chain in this family has passed the evidence\n'
       '    # gate" while two ssrf chains existed in another file -- a projection that\n'
       '    # denies knowledge rather than merely omitting it.\n'
       '    "ssrf": "ssrf-chains.md",')

if '"ssrf": "ssrf-chains.md"' in src:
    print("already routed to ssrf-chains.md; no change")
elif OLD not in src:
    raise SystemExit("ssrf family entry not found - refusing to guess")
else:
    src = src.replace(OLD, NEW, 1)
    io.open(P, "w", encoding="utf-8").write(src)
    print("patched ssrf family routing in", P)