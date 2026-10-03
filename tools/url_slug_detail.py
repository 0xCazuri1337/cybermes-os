"""Are those 9 items really misfiled, or is my URL-stripper over-aggressive?

A second pass, because the first audit's finding can be a FALSE POSITIVE in
either direction:

  * Too aggressive -> the stripper eats a legitimate technical term. `redirect_uri`
    and `openid` and `scope` are PROTOCOL TERMS that appear in prose and in
    endpoints alike; deleting `oauth/authorize` also deletes the `oauth` that a
    quote legitimately used. Refiling those on that evidence would be WRONG.
  * Too lax -> a quote whose only class signal is `boolean-based-sqli` in an
    outbound link really is misfiled, and the class would be padding.

So for each of the 9, this prints the quote with URLs marked, so the judgement is
made on the actual text and not on a regex's opinion.
"""
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from wks import store  # noqa: E402

TARGETS = ["cross-site scripting", "tunnel", "ssrf", "frame-ancestors",
           "redirect_uri", "openid", "scope", "namespace", "writable directory"]

con = store.connect()
for term in TARGETS:
    rows = list(con.execute(
        "SELECT i.id, i.class_id, i.claim, x.quote, s.url"
        "  FROM item i"
        "  JOIN quality q ON q.item_id=i.id"
        "  JOIN item_source x ON x.item_id=i.id"
        "  JOIN source s ON s.id=x.source_id"
        " WHERE q.validation_state='high_confidence' AND i.status='active'"
        "   AND x.quote LIKE ?", ("%" + term + "%",)))
    for r in rows:
        q = r["quote"] or ""
        # where does the term actually occur?
        hits = [m.start() for m in re.finditer(re.escape(term), q, re.I)]
        ctx = []
        for h in hits[:3]:
            ctx.append(q[max(0, h - 45):h + len(term) + 25].replace("\n", " "))
        print("=" * 78)
        print("%s   class=%s" % (term, r["class_id"]))
        print("  claim: %s" % (r["claim"] or "")[:120])
        for c in ctx:
            looks_url = bool(re.search(r"https?://|www\.|\.com|\.org|\.net|/"
                                       r"[a-z]+-[a-z]+-[a-z]+", c))
            print("   %s  %s" % ("[URL?]" if looks_url else "[PROSE]", c))
        break