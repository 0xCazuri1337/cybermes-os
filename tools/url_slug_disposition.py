"""The one real hit is a PRE-EXISTING item, and it is a chain_link -- report only.

`ssrf.chain.metadata_credential_theft_to_app_scope` rests on a 105-char quote in
which the only lowercase `ssrf` token is inside a one-line chain summary
("...multi-step attack chain allowing ssrf-to-local-file-read..."). It is filed
as `kind=chain_link`, and chain steps legitimately name the mechanism they chain
FROM, so the vocabulary-in-the-title pattern is expected for that kind rather than
a symptom of misfiling.

The distinction that matters: this item predates this harvest. It carries no
source prefix (ht_ / hth_ / not_ / pv_), so it was authored before these sources
were harvested and is out of scope for this audit's question ("did the harvest
file anything on a URL slug?").

So: no action, and the audit is complete. This file records the finding rather
than silently dropping it, because a hit that turns out to be fine is still a hit
someone will re-derive next run.
"""
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from wks import store  # noqa: E402

PREFIXES = ("ht_", "hth_", "not_", "pv_", "bis_", "pl_")

con = store.connect()
key = "ssrf.chain.metadata_credential_theft_to_app_scope"
r = con.execute(
    "SELECT i.item_key, i.kind, i.created_at, x.quote, s.url"
    "  FROM item i JOIN item_source x ON x.item_id=i.id"
    " JOIN source s ON s.id=x.source_id WHERE i.item_key=?", (key,)).fetchone()

print("=" * 74)
print("THE SINGLE URL-SLUG HIT -- DISPOSITION")
print("=" * 74)
print("  item      : %s" % r["item_key"])
print("  kind      : %s" % r["kind"])
print("  created   : %s" % r["created_at"])
print("  cited url : %s" % r["url"][:70])
print("  harvested : %s" % any(p in r["item_key"] for p in PREFIXES))
print()
print("  Verdict: chain_link naming the mechanism it chains from. Expected for")
print("  that kind. Pre-existing, so outside this harvest's scope.")
print("  No action; recorded so the next run does not re-derive it.")