"""Rewrite the item_keys in eval/test_wks_chains.py so the first segment is a
REAL class id.

MEASURED: `wks.ingest` derives the class from the FIRST dot-segment of
`item_key`, so a fixture key like `t23.chain.foo` registers as class `t23` and is
rejected with `unknown class 't23'` before any chain logic runs. The test then
reported 5 failures that had nothing to do with chains.
"""
import io
import re

P = r"C:/Users/Administrator/.hermes/cyber/eval/test_wks_chains.py"
src = io.open(P, encoding="utf-8").read()

# fixture classes that exist in the sandbox: ad_delegation, ad_kerberos, ad_acl_abuse
REMAP = {
    "t23.technique.enumerate_spn": "ad_kerberos.technique.enumerate_spn",
    "t23.signal.delegation_flag_present": "ad_delegation.signal.delegation_flag_present",
    "t23.technique.replication_rights_present": "ad_acl_abuse.technique.replication_rights_present",
    "t23.chain.delegation_to_dcsync": "ad_delegation.chain.delegation_to_dcsync",
    "t23.chain.one_step": "ad_delegation.chain.one_step",
    "t23.chain.unjustified": "ad_delegation.chain.unjustified",
}
for old, new in REMAP.items():
    src = src.replace('"%s"' % old, '"%s"' % new)

# the chain_key must also be unique and not collide with the item key
src = src.replace('"t23-delegation-to-dcsync"', '"t23-delegation-to-dcsync"')
io.open(P, "w", encoding="utf-8").write(src)
print("remapped %d item keys in %s" % (len(REMAP), P))
for new in REMAP.values():
    print("  ", new)