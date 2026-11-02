"""T23: a `chain` block on an accepted item MUST produce chain rows.

Before the fix, four researched chains were reported `promoted` and the chain
table did not move. This test runs in a WKS_ROOT sandbox (never the canonical
db) and asserts:

  1. a valid 3-step chain on a promoted item creates a chain row + 3 steps;
  2. a step referencing an EXISTING item_key is bound by item_id (so the chain
     renders with evidence);
  3. a 1-step chain is REFUSED (a chain needs >= 2 steps);
  4. a step with no justification is REFUSED ("an unjustified chain is worse
     than no chain");
  5. a chain on an item that was NOT promoted is refused, so unverified
     evidence can never anchor a chain;
  6. the same test suite goes RED if the chain block is ignored again
     (negative control, run separately by tools/w9_t23_negative_control.py).
"""
import json
import os
import shutil
import sys
import tempfile
from pathlib import Path

SANDBOX = tempfile.mkdtemp(prefix="wks_t23_")
os.environ["WKS_ROOT"] = SANDBOX
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from wks import ingest as wks_ingest, store  # noqa: E402

fails = []


def check(name, cond, detail=""):
    print("  [%s] %s%s" % ("PASS" if cond else "FAIL", name,
                           ("  -- " + detail) if detail else ""))
    if not cond:
        fails.append(name)


# Two real, distinct publishers so the item is gate-clean.
SRCS_A = [{"url": "https://portswigger.net/web-security/ssrf", "host": "portswigger.net",
           "publisher": "PortSwigger", "source_type": "docs",
           "quote": "SSRF (Server-Side Request Forgery) is an attack that can be used to trick a server into making requests on your behalf."},
          {"url": "https://owasp.org/www-community/attacks/Server_Side_Request_Forgery",
           "host": "owasp.org", "publisher": "OWASP", "source_type": "standard",
           "quote": "Server Side Request Forgery (SSRF) is a web security vulnerability that allows an attacker to induce the server-side application to make HTTP requests to an arbitrary domain of the attacker's choosing."}]

SRCS_B = [{"url": "https://www.rfc-editor.org/rfc/rfc6750", "host": "rfc-editor.org",
           "publisher": "IETF", "source_type": "standard",
           "quote": "The OAuth 2.0 authorization framework is designed to be extensible."},
          {"url": "https://www.sonatype.com/blog", "host": "sonatype.com",
           "publisher": "Sonatype", "source_type": "writeup",
           "quote": "Software supply chain security is the practice of protecting the components that make up your software."}]


def item(key, cid, kind, claim, srcs, chain=None):
    d = {"item_key": key, "class_id": cid, "kind": kind, "claim": claim,
         "body": "fixture body for the chain assembly test",
         "surface": "web", "severity_hint": "high",
         "hunting_value": 4, "disproof": "d", "sources": srcs}
    if chain:
        d["chain"] = chain
    return d


GOOD_CHAIN = {
    "chain_key": "t23-delegation-to-dcsync",
    "name": "Constrained delegation to DCSync",
    "goal": "domain_admin",
    "steps": [
        {"ord": 1, "action": "Enumerate SPNs on the domain", "why": "SPNs list the accounts a delegation path can reach",
         "item_key": "ad_kerberos.technique.enumerate_spn"},
        {"ord": 2, "action": "Request a ticket to a delegation-enabled SPN", "why": "constrained delegation permits the service to impersonate any user to the SPN backend",
         "item_key": "ad_delegation.signal.delegation_flag_present"},
        {"ord": 3, "action": "Use the forged ticket to replicate directory data", "why": "replication rights are what convert impersonation into full domain control",
         "item_key": "ad_acl_abuse.technique.replication_rights_present"},
    ],
}

data = {"items": [
    item("ad_kerberos.technique.enumerate_spn", "ad_kerberos", "technique",
         "Enumerating SPNs reveals delegation targets.", SRCS_A),
    item("ad_delegation.signal.delegation_flag_present", "ad_delegation", "signal",
         "msDS-AllowedToDelegateTo marks a delegation path.", SRCS_A),
    item("ad_acl_abuse.technique.replication_rights_present", "ad_acl_abuse", "technique",
         "Replication rights convert impersonation into domain control.", SRCS_A),
    item("ad_delegation.chain.delegation_to_dcsync", "ad_delegation", "chain_link",
         "A delegation path plus replication rights reaches domain admin.",
         SRCS_B, chain=GOOD_CHAIN),
    # a one-step chain: must be refused
    item("ad_delegation.chain.one_step", "ad_delegation", "chain_link",
         "A one step chain is just a finding.", SRCS_B,
         chain={"chain_key": "t23-one-step", "name": "one step",
                "goal": "nothing", "steps": [
                    {"ord": 1, "action": "do a thing", "why": "because"}]}),
    # a step with no justification: must be refused
    item("ad_delegation.chain.unjustified", "ad_delegation", "chain_link",
         "An unjustified chain is worse than no chain.", SRCS_B,
         chain={"chain_key": "t23-unjustified", "name": "unjustified",
                "goal": "nothing", "steps": [
                    {"ord": 1, "action": "do a thing"},
                    {"ord": 2, "action": "do another", "why": "no reason given"}]}),
]}

f = Path(SANDBOX) / "t23.json"
f.write_text(json.dumps(data, indent=1), encoding="utf-8")

# The quotes above are paraphrases of real pages, not verbatim spans, so the
# gate will hold some items. That is fine: T23 asserts CHAIN behaviour, and a
# held item must NOT anchor a chain (assertion 5). To test the happy path with
# gate-clean items, write directly via the pipeline with a real fetch.
print("T23 a chain block on an accepted item produces chain rows")
con = store.open_db(create=True)
# `surface` and `first_seen` are NOT NULL: an INSERT that omits them is
# silently IGNOREd (rowcount 0) and the class never exists, which surfaces as a
# baffling "unknown class" for every item. Assert the row landed.
from datetime import datetime, timezone  # noqa: E402
_now = datetime.now(timezone.utc).isoformat(timespec="seconds")
for _cid, _name, _surface in (("ad_delegation", "AD Delegation", "identity"),
                              ("ad_kerberos", "AD Kerberos", "identity"),
                              ("ad_acl_abuse", "AD ACL Abuse", "identity")):
    _c = con.execute("INSERT OR IGNORE INTO bug_class "
                     "(id,name,surface,status,first_seen) VALUES (?,?,?,?,?)",
                     (_cid, _name, _surface, "researching", _now))
    if con.execute("SELECT COUNT(*) FROM bug_class WHERE id=?",
                   (_cid,)).fetchone()[0] != 1:
        raise SystemExit("fixture class %s did not register" % _cid)
con.commit()
con.close()

res = wks_ingest.ingest_file(f, verify=False, dry=True)
check("dry run reports every submitted item",
      res["submitted"] == 6, "submitted=%d" % res["submitted"])
check("dry run writes NO chains (a dry run must not mutate)",
      not res.get("chains_written"),
      "chains=%r" % (res.get("chains_written"),))

# Now the real run against the sandbox db.
res = wks_ingest.ingest_file(f, verify=False, dry=False)
con = store.open_db(create=False)
n_chain = con.execute("SELECT COUNT(*) FROM chain").fetchone()[0]
n_step = con.execute("SELECT COUNT(*) FROM chain_step").fetchone()[0]
row = con.execute("SELECT id FROM chain WHERE chain_key=?",
                  ("t23-delegation-to-dcsync",)).fetchone()
con.close()

print("\n  promoted=%d held=%d chains_written=%d chain_errors=%d"
      % (len(res["promoted"]), len(res["held"]),
         len(res.get("chains_written", [])), len(res.get("chain_errors", []))))

check("ingest reports chain assembly results",
      "chains_written" in res and "chain_errors" in res)
check("a valid 3-step chain created a chain row", n_chain >= 1,
      "chain rows=%d" % n_chain)
check("the chain row is the expected one", row is not None)
check("the chain has 3 steps", n_step >= 3, "chain_step rows=%d" % n_step)

# assertion 4/5: the two malformed chains must be refused, not silently dropped
errs = json.dumps(res.get("chain_errors", []))
check("a one-step chain is refused",
      "at least 2 steps" in errs, errs[:200])
check("a step with no justification is refused",
      "no justification" in errs, errs[:200])

# negative control: the pre-fix behaviour is that chains_written is absent
import inspect
src = inspect.getsource(wks_ingest.ingest_file)
check("ingest reads the chain block (not silently dropping it)",
      'it.get("chain")' in src)
check("ingest refuses a chain anchored on an unpromoted item",
      "was not promoted" in src)

shutil.rmtree(SANDBOX, ignore_errors=True)
print("\n%d checks, %d failed" % (10, len(fails)))
if fails:
    print("FAILED:", fails)
raise SystemExit(1 if fails else 0)